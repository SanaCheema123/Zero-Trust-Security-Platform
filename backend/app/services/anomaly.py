"""Anomaly scoring orchestration.

Builds features for a flow (with context such as recent flows from the
same source) and asks the ML service for a score.
"""

from sqlalchemy.orm import Session

from app.ml.features import build_flow_features
from app.ml.service import score_features
from app.models.security import NetworkTraffic


def recent_flows_from_source(db: Session, source_ip: str, minutes: int = 5) -> int:
    from datetime import datetime, timedelta

    since = datetime.utcnow() - timedelta(minutes=minutes)
    return (
        db.query(NetworkTraffic)
        .filter(
            NetworkTraffic.source_ip == source_ip,
            NetworkTraffic.created_at >= since,
        )
        .count()
    )


def score_traffic(db: Session, traffic: NetworkTraffic) -> dict:
    """Score an existing (unscored) traffic row using the ML model."""
    features = build_flow_features(
        source_port=traffic.source_port,
        destination_port=traffic.destination_port,
        protocol=traffic.protocol,
        direction=traffic.direction,
        bytes_transferred=traffic.bytes_transferred,
        packet_count=traffic.packet_count,
        duration_ms=traffic.duration_ms,
        recent_flows_from_src=recent_flows_from_source(db, traffic.source_ip),
    )
    return score_features(features)


def risk_from_anomaly(anomaly_score) -> float:
    """Map an ML anomaly score to a 0..100 risk score."""
    if anomaly_score is None:
        return 0.0
    return round(min(100.0, anomaly_score * 100.0), 2)