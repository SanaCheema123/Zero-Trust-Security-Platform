from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.security import AuditLog
from app.models.user import User
from app.security.dependencies import require_read

router = APIRouter(
    prefix="/audit",
    tags=["Audit Logs"],
)


def _audit_dict(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "user_id": entry.user_id,
        "username": entry.username,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "details": entry.details,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.get("")
def list_audit_logs(
    current_user: User = Depends(require_read("audit")),
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = None,
    username: str | None = None,
    minutes: int | None = Query(None, ge=1, le=10080),
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.contains(action))
    if username:
        query = query.filter(AuditLog.username == username)
    if minutes:
        query = query.filter(
            AuditLog.created_at >= datetime.utcnow() - timedelta(minutes=minutes)
        )

    total = query.count()
    rows = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [_audit_dict(e) for e in rows]}


@router.get("/summary")
def audit_summary(
    current_user: User = Depends(require_read("audit")),
    db: Session = Depends(get_db),
    minutes: int = Query(1440, ge=1, le=10080),
):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.created_at >= since)
        .all()
    )

    by_action: dict[str, int] = {}
    by_user: dict[str, int] = {}
    for entry in rows:
        by_action[entry.action] = by_action.get(entry.action, 0) + 1
        by_user[entry.username or "system"] = by_user.get(entry.username or "system", 0) + 1

    return {
        "window_minutes": minutes,
        "total": len(rows),
        "by_action": dict(sorted(by_action.items(), key=lambda kv: kv[1], reverse=True)[:12]),
        "by_user": dict(sorted(by_user.items(), key=lambda kv: kv[1], reverse=True)[:12]),
    }