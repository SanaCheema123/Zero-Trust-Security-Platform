from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.ml.service import model_status
from app.models.device import Device, Server
from app.models.security import (
    Incident,
    LoginAttempt,
    NetworkTraffic,
    SecurityEvent,
)
from app.models.user import User
from app.security.dependencies import require_read

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def dashboard_summary(
    current_user: User = Depends(require_read("dashboard")),
    db: Session = Depends(get_db),
    minutes: int = Query(60, ge=1, le=10080),
):
    since = datetime.utcnow() - timedelta(minutes=minutes)

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.created_at >= since)
        .all()
    )
    traffic = (
        db.query(NetworkTraffic)
        .filter(NetworkTraffic.created_at >= since)
        .all()
    )

    open_incidents = (
        db.query(Incident)
        .filter(Incident.status.in_(["OPEN", "INVESTIGATING"]))
        .count()
    )
    recent_incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(5)
        .all()
    )

    failed_logins = (
        db.query(LoginAttempt)
        .filter(
            LoginAttempt.created_at >= since,
            LoginAttempt.success.is_(False),
        )
        .count()
    )

    devices = db.query(Device).all()
    servers = db.query(Server).all()

    high_risk_events = [e for e in events if (e.risk_score or 0) >= 55]
    anomalous_traffic = [t for t in traffic if t.is_anomalous]

    return {
        "window_minutes": minutes,
        "counts": {
            "devices": len(devices),
            "servers": len(servers),
            "online_assets": sum(1 for d in devices if d.is_online)
            + sum(1 for s in servers if s.is_online),
            "open_incidents": open_incidents,
            "security_events": len(events),
            "high_risk_events": len(high_risk_events),
            "traffic_flows": len(traffic),
            "anomalous_traffic": len(anomalous_traffic),
            "failed_logins": failed_logins,
        },
        "severity_breakdown": {
            severity: sum(1 for e in events if e.severity == severity)
            for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        },
        "trust": {
            "devices_avg": round(
                sum(d.trust_score or 0 for d in devices) / len(devices), 2
            ) if devices else 0,
            "servers_avg": round(
                sum(s.trust_score or 0 for s in servers) / len(servers), 2
            ) if servers else 0,
            "low_trust": sum(
                1 for a in list(devices) + list(servers) if (a.trust_score or 0) < 40
            ),
            # Keep the dashboard trust payload compatible with /trust/overview
            # so the frontend can render trust bars without assuming missing fields.
            "devices": {
                "count": len(devices),
                "avg": round(
                    sum(d.trust_score or 0 for d in devices) / len(devices), 2
                ) if devices else 0,
                "buckets": {
                    "low": sum(1 for d in devices if (d.trust_score or 0) < 40),
                    "medium": sum(1 for d in devices if 40 <= (d.trust_score or 0) < 70),
                    "high": sum(1 for d in devices if (d.trust_score or 0) >= 70),
                },
                "trusted": sum(1 for d in devices if d.is_trusted),
            },
            "servers": {
                "count": len(servers),
                "avg": round(
                    sum(s.trust_score or 0 for s in servers) / len(servers), 2
                ) if servers else 0,
                "buckets": {
                    "low": sum(1 for s in servers if (s.trust_score or 0) < 40),
                    "medium": sum(1 for s in servers if 40 <= (s.trust_score or 0) < 70),
                    "high": sum(1 for s in servers if (s.trust_score or 0) >= 70),
                },
            },
        },
        "recent_incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "risk_score": i.risk_score,
                "created_at": i.created_at.isoformat() if i.created_at else None,
            }
            for i in recent_incidents
        ],
        "recent_events": [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "description": e.description,
                "source_ip": e.source_ip,
                "anomaly_score": e.anomaly_score,
                "risk_score": e.risk_score,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in sorted(events, key=lambda e: e.created_at, reverse=True)[:8]
        ],
        "ml": model_status(),
    }