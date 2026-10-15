import logging
import os
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.ml.service import model_status, retrain
from app.models.security import NetworkTraffic
from app.models.user import User
from app.security.audit import write_audit_log
from app.security.dependencies import require_write

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ml",
    tags=["ML / Anomaly Detection"],
)

TRAIN_SCRIPT = Path(__file__).resolve().parents[2] / "ml" / "train_model.py"
MODEL_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"


@router.get("/status")
def status(
    current_user: User = Depends(require_write("ml")),
):
    return model_status()


@router.post("/retrain")
def retrain_model(
    current_user: User = Depends(require_write("ml")),
    db: Session = Depends(get_db),
):
    """Retrain the Isolation Forest on live traffic stored in PostgreSQL.

    Falls back to the script's built-in synthetic dataset when there isn't
    enough real traffic yet.
    """
    flow_count = db.query(NetworkTraffic).count()

    env = dict(os.environ)
    env["BACKEND_DIR"] = str(Path(__file__).resolve().parents[2])

    command = [
        sys.executable,
        str(TRAIN_SCRIPT),
        "--output",
        str(MODEL_DIR / "anomaly_model.joblib"),
        "--min-samples",
        "200",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Training timed out")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to launch training: {exc}")

    if result.returncode != 0:
        logger.error("Training failed:\n%s", result.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Training failed: {result.stderr[-500:]}",
        )

    ok = retrain()
    write_audit_log(
        db, user_id=current_user.id, username=current_user.username,
        action="ml.retrain", resource_type="model",
        details={"flows_in_db": flow_count, "output": str(result.stdout[-300:])},
    )
    return {
        "detail": "Model retrained and reloaded",
        "flows_in_db": flow_count,
        "output": result.stdout[-500:],
        "model": model_status(),
    }