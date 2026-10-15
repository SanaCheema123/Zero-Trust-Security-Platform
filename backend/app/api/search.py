from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import NetworkTraffic, SecurityEvent
from app.models.user import User
from app.security.dependencies import require_read
from app.services import elastic

router = APIRouter(
    prefix="/search",
    tags=["Search"],
)


@router.get("")
def search(
    current_user: User = Depends(require_read("search")),
    db: Session = Depends(get_db),
    q: str = Query(..., min_length=1, max_length=200),
    limit: int = Query(50, ge=1, le=100),
):
    results = {"engine": "elasticsearch", "hits": []}

    es_hits = elastic.search(q, size=limit)

    if es_hits:
        results["hits"] = es_hits
        return results

    # PostgreSQL fallback
    results["engine"] = "postgresql"
    pattern = f"%{q}%"

    events = (
        db.query(SecurityEvent)
        .filter(or_(
            SecurityEvent.description.ilike(pattern),
            SecurityEvent.source_ip.ilike(pattern),
            SecurityEvent.destination_ip.ilike(pattern),
            SecurityEvent.event_type.ilike(pattern),
        ))
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    traffic = (
        db.query(NetworkTraffic)
        .filter(or_(
            NetworkTraffic.source_ip.ilike(pattern),
            NetworkTraffic.destination_ip.ilike(pattern),
            NetworkTraffic.protocol.ilike(pattern),
        ))
        .order_by(NetworkTraffic.created_at.desc())
        .limit(limit)
        .all()
    )

    for event in events:
        results["hits"].append({
            "kind": "security_event",
            "id": event.id,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "anomaly_score": event.anomaly_score,
            "risk_score": event.risk_score,
            "is_anomalous": event.is_anomalous,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        })
    for flow in traffic:
        results["hits"].append({
            "kind": "network_traffic",
            "id": flow.id,
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
            "protocol": flow.protocol,
            "direction": flow.direction,
            "bytes_transferred": flow.bytes_transferred,
            "anomaly_score": flow.anomaly_score,
            "is_anomalous": flow.is_anomalous,
            "created_at": flow.created_at.isoformat() if flow.created_at else None,
        })

    return results