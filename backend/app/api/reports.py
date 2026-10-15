import csv
import io
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.device import Device, Server
from app.models.security import (
    AuditLog,
    Incident,
    LoginAttempt,
    NetworkTraffic,
    SecurityEvent,
)
from app.models.user import User
from app.security.dependencies import require_read

router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


def _csv_response(filename: str, columns: list[str], rows: list[list]) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    writer.writerows(rows)
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/summary")
def report_summary(
    current_user: User = Depends(require_read("reports")),
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=24 * 30),
):
    since = datetime.utcnow() - timedelta(hours=hours)

    events = db.query(SecurityEvent).filter(SecurityEvent.created_at >= since).all()
    traffic = db.query(NetworkTraffic).filter(NetworkTraffic.created_at >= since).all()
    incidents = db.query(Incident).filter(Incident.created_at >= since).all()
    logins = db.query(LoginAttempt).filter(LoginAttempt.created_at >= since).all()
    audit = db.query(AuditLog).filter(AuditLog.created_at >= since).all()

    failed_logins = [l for l in logins if not l.success]

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "window_hours": hours,
        "events": {
            "total": len(events),
            "by_severity": {
                severity: sum(1 for e in events if e.severity == severity)
                for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            },
            "anomalous": sum(1 for e in events if e.is_anomalous),
        },
        "traffic": {
            "total_flows": len(traffic),
            "total_bytes": sum(t.bytes_transferred or 0 for t in traffic),
            "anomalous": sum(1 for t in traffic if t.is_anomalous),
        },
        "incidents": {
            "total": len(incidents),
            "open": sum(1 for i in incidents if i.status == "OPEN"),
            "investigating": sum(1 for i in incidents if i.status == "INVESTIGATING"),
            "resolved": sum(1 for i in incidents if i.status in ("RESOLVED", "CLOSED")),
        },
        "logins": {
            "total": len(logins),
            "success": sum(1 for l in logins if l.success),
            "failed": len(failed_logins),
            "mfa_required": sum(1 for l in logins if l.mfa_required),
        },
        "audit_entries": len(audit),
        "assets": {
            "devices": db.query(Device).count(),
            "servers": db.query(Server).count(),
        },
    }


@router.get("/export/events")
def export_events(
    current_user: User = Depends(require_read("reports")),
    db: Session = Depends(get_db),
    hours: int = Query(168, ge=1, le=24 * 30),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.created_at >= since)
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )
    return _csv_response(
        "security_events.csv",
        ["id", "created_at", "event_type", "severity", "source_ip", "destination_ip",
         "description", "anomaly_score", "risk_score", "is_anomalous"],
        [
            [
                e.id, e.created_at.isoformat(), e.event_type, e.severity,
                e.source_ip or "", e.destination_ip or "", e.description or "",
                e.anomaly_score or "", e.risk_score or "", e.is_anomalous,
            ]
            for e in rows
        ],
    )


@router.get("/export/traffic")
def export_traffic(
    current_user: User = Depends(require_read("reports")),
    db: Session = Depends(get_db),
    hours: int = Query(24, ge=1, le=24 * 30),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(NetworkTraffic)
        .filter(NetworkTraffic.created_at >= since)
        .order_by(NetworkTraffic.created_at.desc())
        .all()
    )
    return _csv_response(
        "network_traffic.csv",
        ["id", "created_at", "source_ip", "destination_ip", "source_port",
         "destination_port", "protocol", "direction", "bytes_transferred",
         "packet_count", "anomaly_score", "is_anomalous"],
        [
            [
                t.id, t.created_at.isoformat(), t.source_ip, t.destination_ip,
                t.source_port, t.destination_port, t.protocol, t.direction,
                t.bytes_transferred, t.packet_count,
                t.anomaly_score or "", t.is_anomalous,
            ]
            for t in rows
        ],
    )


@router.get("/export/audit")
def export_audit(
    current_user: User = Depends(require_read("reports")),
    db: Session = Depends(get_db),
    hours: int = Query(168, ge=1, le=24 * 30),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.created_at >= since)
        .order_by(AuditLog.created_at.desc())
        .all()
    )
    return _csv_response(
        "audit_logs.csv",
        ["id", "created_at", "username", "action", "resource_type",
         "resource_id", "ip_address", "details"],
        [
            [
                a.id, a.created_at.isoformat(), a.username or "", a.action,
                a.resource_type or "", a.resource_id or "", a.ip_address or "",
                a.details or {},
            ]
            for a in rows
        ],
    )


@router.get("/export/incidents")
def export_incidents(
    current_user: User = Depends(require_read("reports")),
    db: Session = Depends(get_db),
):
    rows = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return _csv_response(
        "incidents.csv",
        ["id", "created_at", "resolved_at", "title", "severity", "status",
         "risk_score", "device_id", "server_id"],
        [
            [
                i.id, i.created_at.isoformat() if i.created_at else "",
                i.resolved_at.isoformat() if i.resolved_at else "",
                i.title, i.severity, i.status, i.risk_score,
                i.device_id or "", i.server_id or "",
            ]
            for i in rows
        ],
    )