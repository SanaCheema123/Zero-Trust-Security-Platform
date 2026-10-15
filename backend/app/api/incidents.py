from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.device import Device, Server
from app.models.security import Incident, SecurityEvent
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    require_read,
    require_write,
)

router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)

STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}


class IncidentUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    assignee_id: int | None = None
    description: str | None = None


def _incident_dict(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "user_id": incident.user_id,
        "device_id": incident.device_id,
        "server_id": incident.server_id,
        "assignee_id": incident.assignee_id,
        "event_ids": incident.event_ids or [],
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
    }


@router.get("")
def list_incidents(
    current_user: User = Depends(require_read("incidents")),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    query = db.query(Incident)
    if status:
        if status.upper() not in STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
        query = query.filter(Incident.status == status.upper())
    if severity:
        query = query.filter(Incident.severity == severity.upper())

    total = query.count()
    rows = query.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [_incident_dict(i) for i in rows]}


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    current_user: User = Depends(require_read("incidents")),
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    result = _incident_dict(incident)

    # Investigation timeline: related events plus asset context
    events = []
    event_ids = set(incident.event_ids or [])
    for event in db.query(SecurityEvent).order_by(SecurityEvent.created_at.asc()).all():
        related = (
            event.id in event_ids
            or (incident.device_id and event.device_id == incident.device_id)
            or (incident.server_id and event.server_id == incident.server_id)
            or (
                incident.user_id
                and event.user_id == incident.user_id
            )
        )
        if related:
            events.append({
                "id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "description": event.description,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "anomaly_score": event.anomaly_score,
                "risk_score": event.risk_score,
                "is_anomalous": event.is_anomalous,
                "created_at": event.created_at.isoformat() if event.created_at else None,
            })

    result["timeline"] = events

    if incident.device_id:
        device = db.query(Device).filter(Device.id == incident.device_id).first()
        if device:
            result["device"] = {
                "id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "trust_score": device.trust_score,
            }
    if incident.server_id:
        server = db.query(Server).filter(Server.id == incident.server_id).first()
        if server:
            result["server"] = {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address,
                "trust_score": server.trust_score,
            }

    return result


@router.patch("/{incident_id}")
def update_incident(
    request: Request,
    incident_id: int,
    payload: IncidentUpdate,
    current_user: User = Depends(require_write("incidents")),
    db: Session = Depends(get_db),
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if payload.status is not None:
        if payload.status.upper() not in STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {payload.status}")
        incident.status = payload.status.upper()
        if incident.status in ("RESOLVED", "CLOSED") and not incident.resolved_at:
            incident.resolved_at = datetime.utcnow()
        elif incident.status in ("OPEN", "INVESTIGATING"):
            incident.resolved_at = None

    if payload.severity is not None:
        incident.severity = payload.severity.upper()
    if payload.assignee_id is not None:
        incident.assignee_id = payload.assignee_id
    if payload.description is not None:
        incident.description = payload.description

    db.commit()
    db.refresh(incident)

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="incident.update", resource_type="incident", resource_id=incident.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details=payload.model_dump(exclude_none=True),
    )
    return _incident_dict(incident)