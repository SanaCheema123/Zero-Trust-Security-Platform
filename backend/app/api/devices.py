from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.device import Device
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.dependencies import (
    get_client_ip,
    get_client_user_agent,
    require_read,
    require_write,
)
from app.services.trust import recalculate_trust

router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
)


class DeviceUpdate(BaseModel):
    is_trusted: bool | None = None
    is_online: bool | None = None
    risk_factors: list[str] | None = None
    owner_user_id: int | None = None


def _device_dict(device: Device) -> dict:
    return {
        "id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "device_type": device.device_type,
        "operating_system": device.operating_system,
        "is_trusted": device.is_trusted,
        "trust_score": device.trust_score,
        "is_online": device.is_online,
        "risk_factors": device.risk_factors or [],
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
        "created_at": device.created_at.isoformat() if device.created_at else None,
    }


@router.get("")
def list_devices(
    current_user: User = Depends(require_read("devices")),
    db: Session = Depends(get_db),
    trust_min: float = Query(0.0, ge=0.0, le=100.0),
    trusted_only: bool = False,
):
    query = db.query(Device)
    if trust_min > 0:
        query = query.filter(Device.trust_score >= trust_min)
    if trusted_only:
        query = query.filter(Device.is_trusted.is_(True))
    devices = query.order_by(Device.trust_score.asc()).all()
    return [_device_dict(d) for d in devices]


@router.get("/{device_id}")
def get_device(
    device_id: int,
    current_user: User = Depends(require_read("devices")),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_dict(device)


@router.patch("/{device_id}")
def update_device(
    request: Request,
    device_id: int,
    payload: DeviceUpdate,
    current_user: User = Depends(require_write("devices")),
    db: Session = Depends(get_db),
):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    for field in ("is_trusted", "is_online", "risk_factors", "owner_user_id"):
        value = getattr(payload, field)
        if value is not None:
            setattr(device, field, value)

    db.commit()
    recalculate_trust(db, device)

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="device.update", resource_type="device", resource_id=device.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details=payload.model_dump(exclude_none=True),
    )
    return _device_dict(device)