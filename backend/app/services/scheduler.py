"""Background tasks run from the FastAPI lifespan.

  * live traffic simulation: generate + score + persist flows and push
    them to WebSocket clients (once per interval)
  * periodic trust recalculation
"""

import asyncio
import logging
import random

from sqlalchemy.orm import Session

from app.database.connection import SessionLocal
from app.ml.service import is_ready
from app.models.security import NetworkTraffic
from app.services.anomaly import risk_from_anomaly, score_traffic
from app.services import elastic
from app.services.traffic import generate_flow, bulk_history
from app.services.trust import recalculate_all
from app.services.websocket import manager

logger = logging.getLogger(__name__)

TRAFFIC_INTERVAL_SECONDS = float(__import__("os").getenv("TRAFFIC_INTERVAL_SECONDS", "3"))
TRUST_INTERVAL_SECONDS = float(__import__("os").getenv("TRUST_INTERVAL_SECONDS", "60"))


def ingest_flow(db: Session, flow: dict) -> NetworkTraffic:
    """Score + persist one flow. Returns the stored row (or None)."""
    traffic = NetworkTraffic(**flow)
    db.add(traffic)
    db.flush()

    result = score_traffic(db, traffic)
    traffic.anomaly_score = result["anomaly_score"]
    traffic.is_anomalous = result["is_anomalous"]
    db.commit()
    db.refresh(traffic)

    try:
        elastic.index_traffic(_traffic_dict(traffic))
    except Exception:
        pass

    return traffic


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
        "created_at": traffic.created_at.isoformat(),
    }


async def traffic_loop():
    rng = random.Random()
    while True:
        try:
            db: Session = SessionLocal()
            try:
                flow = generate_flow(db, rng)
                traffic = ingest_flow(db, flow)
                if traffic:
                    await manager.broadcast({
                        "type": "traffic",
                        "traffic": _traffic_dict(traffic),
                    })
            finally:
                db.close()
        except Exception as exc:
            logger.exception("Traffic loop iteration failed: %s", exc)
        await asyncio.sleep(TRAFFIC_INTERVAL_SECONDS)


async def trust_loop():
    while True:
        await asyncio.sleep(TRUST_INTERVAL_SECONDS)
        try:
            db: Session = SessionLocal()
            try:
                result = recalculate_all(db)
                await manager.broadcast({
                    "type": "trust_refresh",
                    "result": result,
                })
            finally:
                db.close()
        except Exception as exc:
            logger.exception("Trust loop iteration failed: %s", exc)


async def warmup():
    """Called on startup: backfill historical data, load the ML model."""
    # Load the trained model (if any)
    is_ready()

    db: Session = SessionLocal()
    try:
        bulk_history(db)
    finally:
        db.close()