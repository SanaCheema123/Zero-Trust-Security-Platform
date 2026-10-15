"""Trust score engine.

Implements a zero-trust scoring model: every device and server starts at
a neutral 50 and its score is continuously adjusted by:

  * baseline posture (trusted flag, online status, age)
  * recent security events weighted by severity
  * ML anomaly activity on that asset
  * explicit risk factors (e.g. missing updates, open ports)

Scores are clamped to [0, 100].
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models.device import Device, Server
from app.models.security import SecurityEvent, TrustScore

logger = logging.getLogger(__name__)

SEVERITY_WEIGHT = {"LOW": 3.0, "MEDIUM": 7.0, "HIGH": 15.0, "CRITICAL": 25.0}


def _age_days(created_at: datetime) -> float:
    if not created_at:
        return 0.0
    return max(0.0, (datetime.utcnow() - created_at).total_seconds() / 86400.0)


def _event_penalty(db: Session, asset_id: int, asset_type: str, hours: int = 24) -> float:
    since = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(SecurityEvent).filter(SecurityEvent.created_at >= since)

    if asset_type == "device":
        query = query.filter(SecurityEvent.device_id == asset_id)
    else:
        query = query.filter(SecurityEvent.server_id == asset_id)

    total = 0.0
    for event in query.all():
        total += SEVERITY_WEIGHT.get(event.severity, 3.0)
        if event.is_anomalous:
            total += 5.0
    return total


def _recent_anomaly_count(db: Session, asset_id: int, asset_type: str, hours: int = 24) -> int:
    since = datetime.utcnow() - timedelta(hours=hours)
    query = db.query(SecurityEvent).filter(
        SecurityEvent.created_at >= since,
        SecurityEvent.is_anomalous.is_(True),
    )
    if asset_type == "device":
        query = query.filter(SecurityEvent.device_id == asset_id)
    else:
        query = query.filter(SecurityEvent.server_id == asset_id)
    return query.count()


def _compute_score(asset, db: Session, asset_type: str) -> dict:
    score = 50.0
    reasons = []

    # --- baseline posture ------------------------------------------------
    if getattr(asset, "is_trusted", False):
        score += 15.0
        reasons.append("Marked as trusted")
    if getattr(asset, "is_online", True):
        score += 5.0
        reasons.append("Currently online")

    age_days = _age_days(asset.created_at)
    if age_days >= 30:
        score += 5.0
        reasons.append("Established asset (30+ days old)")

    risk_factors = asset.risk_factors or []
    if risk_factors:
        score -= 5.0 * len(risk_factors)
        reasons.append(f"Active risk factors: {', '.join(str(r) for r in risk_factors)}")

    # --- recent security posture ----------------------------------------
    penalty = _event_penalty(db, asset.id, asset_type)
    anomaly_count = _recent_anomaly_count(db, asset.id, asset_type)
    score -= penalty
    score -= anomaly_count * 3.0
    if penalty > 0:
        reasons.append(f"Security events in last 24h (penalty {penalty:.0f})")
    if anomaly_count > 0:
        reasons.append(f"{anomaly_count} ML-flagged anomalies in last 24h")

    score = max(0.0, min(100.0, score))

    return {
        "score": round(score, 2),
        "user_score": None,
        "device_score": round(score, 2) if asset_type == "device" else None,
        "server_score": round(score, 2) if asset_type == "server" else None,
        "network_score": None,
        "behavior_score": None,
        "reason": "; ".join(reasons) if reasons else "No significant factors",
    }


def recalculate_trust(db: Session, asset) -> dict:
    """Recalculate and persist the trust score for one device or server."""
    asset_type = "device" if isinstance(asset, Device) else "server"
    result = _compute_score(asset, db, asset_type)

    asset.trust_score = result["score"]
    db.add(asset)

    record = TrustScore(
        device_id=asset.id if asset_type == "device" else None,
        server_id=asset.id if asset_type == "server" else None,
        score=result["score"],
        user_score=result["user_score"],
        device_score=result["device_score"],
        network_score=result["network_score"],
        behavior_score=result["behavior_score"],
        reason=result["reason"],
    )
    db.add(record)
    db.commit()
    return result


def recalculate_all(db: Session) -> dict:
    devices = db.query(Device).all()
    servers = db.query(Server).all()

    for device in devices:
        recalculate_trust(db, device)
    for server in servers:
        recalculate_trust(db, server)

    logger.info("Recalculated trust for %d devices and %d servers", len(devices), len(servers))
    return {"devices": len(devices), "servers": len(servers)}