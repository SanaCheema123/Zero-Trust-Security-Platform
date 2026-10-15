from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.device import Server
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
    prefix="/servers",
    tags=["Servers"],
)


class ServerUpdate(BaseModel):
    is_online: bool | None = None
    risk_factors: list[str] | None = None
    zone: str | None = None


def _server_dict(server: Server) -> dict:
    return {
        "id": server.id,
        "hostname": server.hostname,
        "ip_address": server.ip_address,
        "server_type": server.server_type,
        "operating_system": server.operating_system,
        "zone": server.zone,
        "services": server.services or [],
        "is_online": server.is_online,
        "trust_score": server.trust_score,
        "risk_factors": server.risk_factors or [],
        "last_seen": server.last_seen.isoformat() if server.last_seen else None,
        "created_at": server.created_at.isoformat() if server.created_at else None,
    }


@router.get("")
def list_servers(
    current_user: User = Depends(require_read("servers")),
    db: Session = Depends(get_db),
    trust_min: float = Query(0.0, ge=0.0, le=100.0),
    zone: str | None = None,
):
    query = db.query(Server)
    if trust_min > 0:
        query = query.filter(Server.trust_score >= trust_min)
    if zone:
        query = query.filter(Server.zone == zone)
    servers = query.order_by(Server.trust_score.asc()).all()
    return [_server_dict(s) for s in servers]


@router.get("/{server_id}")
def get_server(
    server_id: int,
    current_user: User = Depends(require_read("servers")),
    db: Session = Depends(get_db),
):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return _server_dict(server)


@router.patch("/{server_id}")
def update_server(
    request: Request,
    server_id: int,
    payload: ServerUpdate,
    current_user: User = Depends(require_write("servers")),
    db: Session = Depends(get_db),
):
    server = db.query(Server).filter(Server.id == server_id).first()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    for field in ("is_online", "risk_factors", "zone"):
        value = getattr(payload, field)
        if value is not None:
            setattr(server, field, value)

    db.commit()
    recalculate_trust(db, server)

    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="server.update", resource_type="server", resource_id=server.id,
        ip_address=get_client_ip(request), user_agent=get_client_user_agent(request),
        details=payload.model_dump(exclude_none=True),
    )
    return _server_dict(server)