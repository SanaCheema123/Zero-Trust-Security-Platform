from sqlalchemy.orm import Session

from app.models.security import AuditLog


def write_audit_log(
    db: Session,
    *,
    user_id=None,
    username=None,
    action: str,
    resource_type=None,
    resource_id=None,
    ip_address=None,
    user_agent=None,
    details=None,
) -> AuditLog:
    """Write an audit log entry (never raises)."""
    try:
        entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
        db.add(entry)
        db.commit()
        return entry
    except Exception:
        db.rollback()
        return None