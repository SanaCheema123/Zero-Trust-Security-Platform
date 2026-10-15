from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import SecurityEvent
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    require_read,
    require_write,
)
from app.services.alerts import create_security_event

router = APIRouter(
    prefix="/events",
    tags=["Security Events"],
)

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class EventCreate(BaseModel):
    event_type: str
    description: str
    severity: str = "LOW"
    source_ip: str | None = None
    destination_ip: str | None = None
    anomaly_score: float | None = None
    risk_score: float | None = None
    event_metadata: dict | None = None


def _event_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "description": event.description,
        "anomaly_score": event.anomaly_score,
        "risk_score": event.risk_score,
        "is_anomalous": event.is_anomalous,
        "is_alerted": event.is_alerted,
        "user_id": event.user_id,
        "device_id": event.device_id,
        "server_id": event.server_id,
        "event_metadata": event.event_metadata,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }


@router.get("")
def list_events(
    current_user: User = Depends(require_read("dashboard")),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    event_type: str | None = None,
    anomalous_only: bool = False,
    minutes: int | None = Query(None, ge=1, le=10080),
):
    query = db.query(SecurityEvent)
    if severity:
        if severity.upper() not in SEVERITIES:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
        query = query.filter(SecurityEvent.severity == severity.upper())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if anomalous_only:
        query = query.filter(SecurityEvent.is_anomalous.is_(True))
    if minutes:
        query = query.filter(
            SecurityEvent.created_at >= datetime.utcnow() - timedelta(minutes=minutes)
        )

    total = query.count()
    rows = query.order_by(SecurityEvent.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [_event_dict(e) for e in rows]}


@router.get("/summary")
def events_summary(
    current_user: User = Depends(require_read("dashboard")),
    db: Session = Depends(get_db),
    minutes: int = Query(1440, ge=1, le=10080),
):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.created_at >= since)
        .all()
    )

    by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    by_type: dict[str, int] = {}
    for event in rows:
        by_severity[event.severity] = by_severity.get(event.severity, 0) + 1
        by_type[event.event_type] = by_type.get(event.event_type, 0) + 1

    return {
        "window_minutes": minutes,
        "total": len(rows),
        "anomalous": sum(1 for e in rows if e.is_anomalous),
        "by_severity": by_severity,
        "by_type": dict(
            sorted(by_type.items(), key=lambda kv: kv[1], reverse=True)[:10]
        ),
        "recent": [_event_dict(e) for e in sorted(
            rows, key=lambda e: e.created_at, reverse=True
        )[:10]],
    }


@router.post("", status_code=201)
def create_event(
    request: Request,
    payload: EventCreate,
    current_user: User = Depends(require_write("incidents")),
    db: Session = Depends(get_db),
):
    if payload.severity.upper() not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {payload.severity}")

    event = create_security_event(
        db,
        event_type=payload.event_type,
        description=payload.description,
        severity=payload.severity.upper(),
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        anomaly_score=payload.anomaly_score,
        risk_score=payload.risk_score,
        event_metadata=payload.event_metadata,
    )

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="event.create", resource_type="security_event", resource_id=event.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details={"event_type": event.event_type, "severity": event.severity},
    )
    return _event_dict(event)