from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import NetworkTraffic
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    require_read,
    require_write,
)
from app.services.anomaly import risk_from_anomaly, score_traffic
from app.services import elastic
from app.services.scheduler import ingest_flow
from app.services.websocket import manager

router = APIRouter(
    prefix="/network",
    tags=["Network Monitoring"],
)


class TrafficIngest(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=0, le=65535)
    destination_port: int = Field(ge=0, le=65535)
    protocol: str
    direction: str = "inbound"
    bytes_transferred: int = 0
    packet_count: int = 0
    duration_ms: int = 0
    traffic_metadata: dict | None = None


def _traffic_dict(traffic: NetworkTraffic) -> dict:
    return {
        "id": traffic.id,
        "source_ip": traffic.source_ip,
        "destination_ip": traffic.destination_ip,
        "source_port": traffic.source_port,
        "destination_port": traffic.destination_port,
        "protocol": traffic.protocol,
        "direction": traffic.direction,
        "bytes_transferred": traffic.bytes_transferred,
        "packet_count": traffic.packet_count,
        "duration_ms": traffic.duration_ms,
        "anomaly_score": traffic.anomaly_score,
        "is_anomalous": traffic.is_anomalous,
        "created_at": traffic.created_at.isoformat() if traffic.created_at else None,
    }


@router.get("/traffic")
def list_traffic(
    current_user: User = Depends(require_read("network")),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    anomalous_only: bool = False,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    minutes: int | None = Query(None, ge=1, le=10080),
):
    query = db.query(NetworkTraffic)
    if anomalous_only:
        query = query.filter(NetworkTraffic.is_anomalous.is_(True))
    if source_ip:
        query = query.filter(NetworkTraffic.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NetworkTraffic.destination_ip == destination_ip)
    if minutes:
        query = query.filter(
            NetworkTraffic.created_at >= datetime.utcnow() - timedelta(minutes=minutes)
        )

    total = query.count()
    rows = query.order_by(NetworkTraffic.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [_traffic_dict(t) for t in rows]}


@router.post("/traffic/ingest", status_code=201)
async def ingest_traffic(
    request: Request,
    payload: TrafficIngest,
    current_user: User = Depends(require_write("network")),
    db: Session = Depends(get_db),
):
    """Ingest a flow record from an external sensor; it is ML-scored inline."""
    traffic = ingest_flow(db, payload.model_dump())

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="network.ingest", resource_type="network_traffic", resource_id=traffic.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details={"source_ip": traffic.source_ip, "is_anomalous": traffic.is_anomalous},
    )
    return _traffic_dict(traffic)


@router.get("/stats")
def traffic_stats(
    current_user: User = Depends(require_read("network")),
    db: Session = Depends(get_db),
    minutes: int = Query(60, ge=1, le=10080),
):
    since = datetime.utcnow() - timedelta(minutes=minutes)

    rows = (
        db.query(NetworkTraffic)
        .filter(NetworkTraffic.created_at >= since)
        .all()
    )

    total_bytes = sum(r.bytes_transferred or 0 for r in rows)
    anomalous = [r for r in rows if r.is_anomalous]

    # per-protocol breakdown
    protocols: dict[str, int] = {}
    for r in rows:
        protocols[r.protocol] = protocols.get(r.protocol, 0) + 1

    # per-direction
    inbound = sum(1 for r in rows if r.direction == "inbound")
    outbound = sum(1 for r in rows if r.direction == "outbound")

    # top source IPs by volume
    by_src: dict[str, int] = {}
    for r in rows:
        by_src[r.source_ip] = by_src.get(r.source_ip, 0) + (r.bytes_transferred or 0)
    top_sources = sorted(by_src.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        "window_minutes": minutes,
        "total_flows": len(rows),
        "total_bytes": total_bytes,
        "anomalous_flows": len(anomalous),
        "anomaly_rate": round(len(anomalous) / len(rows), 4) if rows else 0.0,
        "inbound": inbound,
        "outbound": outbound,
        "protocols": protocols,
        "top_sources": [{"ip": ip, "bytes": b} for ip, b in top_sources],
        "avg_anomaly_score": (
            round(sum(r.anomaly_score or 0 for r in rows) / len(rows), 4) if rows else 0.0
        ),
    }