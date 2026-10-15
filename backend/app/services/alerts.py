"""Security alert pipeline.

create_security_event() is the single funnel through which every security
event flows. It:

  1. persists the event
  2. scores it with the ML model when applicable
  3. indexes it into Elasticsearch (when available)
  4. broadcasts a real-time alert over WebSockets
  5. auto-creates an Incident when the risk is high
  6. refreshes the trust score of the affected asset
"""

import asyncio
import logging
import threading

from sqlalchemy.orm import Session

from app.ml.service import model_status
from app.models.device import Device, Server
from app.models.security import Incident, SecurityEvent
from app.services import elastic
from app.services.anomaly import risk_from_anomaly
from app.services.trust import recalculate_trust
from app.services.websocket import manager

logger = logging.getLogger(__name__)

INCIDENT_THRESHOLD = 65.0

# Main application event loop, bound at startup. Used to schedule WebSocket
# broadcasts from sync code (endpoints run in worker threads and have no
# event loop of their own).
_main_loop = None


def bind_main_loop(loop):
    global _main_loop
    _main_loop = loop


def _fire(coro):
    """Schedule a coroutine from sync code, regardless of the calling context.

    Works from async endpoints, sync endpoints (worker threads), and plain
    scripts where no event loop exists at all.
    """
    loop = _main_loop
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, loop)
        return
    threading.Thread(target=asyncio.run, args=(coro,), daemon=True).start()

SEVERITY_BY_RISK = [
    (75.0, "CRITICAL"),
    (55.0, "HIGH"),
    (35.0, "MEDIUM"),
    (0.0, "LOW"),
]


def severity_for_risk(risk: float) -> str:
    for threshold, severity in SEVERITY_BY_RISK:
        if risk >= threshold:
            return severity
    return "LOW"


def create_security_event(
    db: Session,
    *,
    event_type: str,
    description: str,
    severity: str = "LOW",
    user_id=None,
    device_id=None,
    server_id=None,
    source_ip=None,
    destination_ip=None,
    anomaly_score=None,
    risk_score=None,
    event_metadata=None,
    broadcast: bool = True,
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        user_id=user_id,
        device_id=device_id,
        server_id=server_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        anomaly_score=anomaly_score,
        risk_score=risk_score,
        event_metadata=event_metadata or {},
    )

    if anomaly_score is not None:
        event.is_anomalous = anomaly_score >= 0.6

    if risk_score is None:
        risk_score = risk_from_anomaly(anomaly_score)
        event.risk_score = risk_score
    if event.severity == "LOW" and risk_score:
        event.severity = severity_for_risk(risk_score)

    db.add(event)
    db.flush()
    db.commit()
    db.refresh(event)

    # Elasticsearch indexing (best effort)
    try:
        elastic.index_event(_event_dict(event))
    except Exception:
        pass

    # Real-time WebSocket alert
    if broadcast:
        _fire(manager.broadcast({
            "type": "security_alert",
            "event": _event_dict(event),
        }))

    # Trust refresh for the affected asset
    try:
        if device_id:
            asset = db.query(Device).get(device_id)
            if asset:
                recalculate_trust(db, asset)
        elif server_id:
            asset = db.query(Server).get(server_id)
            if asset:
                recalculate_trust(db, asset)
    except Exception:
        db.rollback()

    # Auto-create incident for high-risk events
    if (event.risk_score or 0) >= INCIDENT_THRESHOLD:
        _auto_create_incident(db, event)

    return event


def _auto_create_incident(db: Session, event: SecurityEvent):
    # Don't stack duplicate incidents for the same signature within 30 min
    from datetime import datetime, timedelta

    since = datetime.utcnow() - timedelta(minutes=30)
    duplicate = (
        db.query(Incident)
        .filter(
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.created_at >= since,
        )
        .all()
    )
    for incident in duplicate:
        if event.event_type in (incident.event_ids or []):
            return

    incident = Incident(
        title=f"High-risk event: {event.event_type}",
        description=(
            f"Automatically opened by the anomaly detection pipeline. "
            f"Event #{event.id}: {event.description}"
        ),
        severity=event.severity,
        status="OPEN",
        risk_score=event.risk_score,
        user_id=event.user_id,
        device_id=event.device_id,
        server_id=event.server_id,
        event_ids=[event.id],
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    _fire(manager.broadcast({
        "type": "incident_created",
        "incident": _incident_dict(incident),
    }))
    logger.info("Auto-created incident #%d from event #%d", incident.id, event.id)


def _event_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "severity": event.severity,
        "user_id": event.user_id,
        "device_id": event.device_id,
        "server_id": event.server_id,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "description": event.description,
        "anomaly_score": event.anomaly_score,
        "risk_score": event.risk_score,
        "is_anomalous": event.is_anomalous,
        "event_metadata": event.event_metadata,
        "created_at": event.created_at.isoformat(),
    }


def _incident_dict(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "created_at": incident.created_at.isoformat(),
    }