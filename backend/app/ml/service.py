"""Anomaly detection service.

Loads the trained Isolation Forest artifact (model + scaler + threshold)
and exposes a scoring API used by the traffic / event ingestion paths.
"""

import logging
import os
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = str(
    Path(__file__).resolve().parents[2] / "ml" / "models" / "anomaly_model.joblib"
)

MODEL_PATH = os.getenv("MODEL_PATH", DEFAULT_MODEL_PATH)

_model = None
_scaler = None
_threshold = None
_load_error = None


def load_model(force: bool = False):
    """Load (or reload) the trained anomaly detection artifacts."""
    global _model, _scaler, _threshold, _load_error

    if _model is not None and not force:
        return True

    _model = _scaler = _threshold = None
    _load_error = None

    try:
        artifact = joblib.load(MODEL_PATH)
        _model = artifact["model"]
        _scaler = artifact["scaler"]
        _threshold = artifact["threshold"]
        logger.info("Loaded anomaly detection model from %s", MODEL_PATH)
        return True
    except FileNotFoundError:
        _load_error = f"Model artifact not found at {MODEL_PATH}. Run ml/train_model.py first."
        logger.warning(_load_error)
        return False
    except Exception as exc:  # pragma: no cover - defensive
        _load_error = f"Failed to load model: {exc}"
        logger.warning(_load_error)
        return False


def is_ready() -> bool:
    return _model is not None


def model_status() -> dict:
    load_model()
    if _model is None:
        return {
            "ready": False,
            "error": _load_error,
        }
    return {
        "ready": True,
        "path": MODEL_PATH,
        "algorithm": "IsolationForest",
        "features": int(getattr(_model, "n_features_in_", 0)),
        "threshold": float(_threshold) if _threshold is not None else None,
    }


def score_features(features: list) -> dict:
    """Return {'anomaly_score': 0..1, 'is_anomalous': bool}.

    The Isolation Forest scores each sample; the more negative the score,
    the more anomalous. We normalize using the training threshold so that
    a score of ~0.5 corresponds to the decision boundary.
    """
    if _model is None:
        if not load_model():
            return {"anomaly_score": None, "is_anomalous": False}

    try:
        x = np.array([features], dtype=float)
        if _scaler is not None:
            x = _scaler.transform(x)

        raw = float(_model.score_samples(x)[0])
        threshold = float(_threshold) if _threshold is not None else 0.0

        # Normalize: threshold maps to 0.5, higher raw -> lower anomaly score
        shift = raw - threshold
        # scale so that a 10% shift from the threshold is a 0.05 score change
        score = 0.5 - (shift * 5.0)
        score = min(1.0, max(0.0, score))

        return {
            "anomaly_score": round(score, 4),
            "is_anomalous": score >= 0.6,
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Scoring failed: %s", exc)
        return {"anomaly_score": None, "is_anomalous": False}


def retrain() -> bool:
    """Force a reload from disk (used by the retrain API endpoint)."""
    return load_model(force=True)