from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.device import Device, Server
from app.models.security import TrustScore
from app.models.user import User
from app.security.dependencies import require_read
from app.services.trust import recalculate_all

router = APIRouter(
    prefix="/trust",
    tags=["Trust Scores"],
)


def _trust_dict(record: TrustScore) -> dict:
    return {
        "id": record.id,
        "user_id": record.user_id,
        "device_id": record.device_id,
        "server_id": record.server_id,
        "score": record.score,
        "user_score": record.user_score,
        "device_score": record.device_score,
        "network_score": record.network_score,
        "behavior_score": record.behavior_score,
        "reason": record.reason,
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


@router.get("/overview")
def trust_overview(
    current_user: User = Depends(require_read("dashboard")),
    db: Session = Depends(get_db),
):
    """Current trust posture of all assets."""
    devices = db.query(Device).all()
    servers = db.query(Server).all()

    device_scores = [d.trust_score or 0 for d in devices]
    server_scores = [s.trust_score or 0 for s in servers]
    all_scores = device_scores + server_scores

    def bucket(scores):
        low = sum(1 for s in scores if s < 40)
        medium = sum(1 for s in scores if 40 <= s < 70)
        high = sum(1 for s in scores if s >= 70)
        return {"low": low, "medium": medium, "high": high}

    return {
        "devices": {
            "count": len(devices),
            "avg": round(sum(device_scores) / len(device_scores), 2) if device_scores else 0,
            "buckets": bucket(device_scores),
            "trusted": sum(1 for d in devices if d.is_trusted),
        },
        "servers": {
            "count": len(servers),
            "avg": round(sum(server_scores) / len(server_scores), 2) if server_scores else 0,
            "buckets": bucket(server_scores),
        },
        "overall_avg": (
            round(sum(all_scores) / len(all_scores), 2) if all_scores else 0
        ),
        "low_trust_assets": [
            {
                "type": "device" if isinstance(a, Device) else "server",
                "id": a.id,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "trust_score": a.trust_score,
            }
            for a in sorted(
                list(devices) + list(servers),
                key=lambda a: a.trust_score or 0,
            )[:5]
            if (a.trust_score or 0) < 40
        ],
    }


@router.get("/history")
def trust_history(
    current_user: User = Depends(require_read("dashboard")),
    db: Session = Depends(get_db),
    asset_id: int | None = None,
    asset_type: str | None = Query(None, pattern="^(device|server)$"),
    hours: int = Query(48, ge=1, le=24 * 30),
):
    since = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(TrustScore).filter(TrustScore.created_at >= since)

    if asset_type == "device" and asset_id:
        query = query.filter(TrustScore.device_id == asset_id)
    elif asset_type == "server" and asset_id:
        query = query.filter(TrustScore.server_id == asset_id)
    elif asset_type:
        query = query.filter(
            TrustScore.device_id.isnot(None) if asset_type == "device"
            else TrustScore.server_id.isnot(None)
        )

    rows = query.order_by(TrustScore.created_at.asc()).all()
    return [_trust_dict(r) for r in rows]


@router.post("/recalculate")
def recalculate(
    current_user: User = Depends(require_read("devices")),
    db: Session = Depends(get_db),
):
    """Trigger a full trust recalculation across all assets."""
    return recalculate_all(db)