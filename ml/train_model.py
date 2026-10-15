#!/usr/bin/env python3
"""Train the network-flow anomaly detection model.

Generates a labeled dataset of realistic flows (normal + attack patterns),
trains an Isolation Forest, and saves the artifacts (model, scaler,
decision threshold) to a single joblib file consumed by the backend.

Usage:
    python ml/train_model.py                       # default output location
    python ml/train_model.py --output /tmp/model.joblib
    python ml/train_model.py --db-url postgresql+psycopg://...  # mix live data

The Isolation Forest is unsupervised, so the labels are only used to pick
a decision threshold at the desired false-positive rate.
"""

import argparse
import os
import random
import sys
from pathlib import Path

# Allow importing feature builders from the backend package
BACKEND_DIR = os.getenv("BACKEND_DIR", str(Path(__file__).resolve().parents[1] / "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from app.ml.features import build_flow_features

DEFAULT_OUTPUT = (
    Path(__file__).resolve().parents[1] / "backend" / "ml" / "models" / "anomaly_model.joblib"
)

NORMAL_FLOW = {
    "protocols": ["HTTPS", "HTTPS", "HTTP", "DNS", "TCP", "SSH", "UDP"],
    "dports": [443, 443, 80, 53, 5432, 22, 53],
    "direction": "inbound",
}


def random_normal_flow(rng: random.Random) -> dict:
    idx = rng.randrange(len(NORMAL_FLOW["protocols"]))
    packets = rng.randint(1, 300)
    return {
        "source_port": rng.randint(1024, 65535),
        "destination_port": NORMAL_FLOW["dports"][idx],
        "protocol": NORMAL_FLOW["protocols"][idx],
        "direction": "inbound" if rng.random() < 0.65 else "outbound",
        "bytes_transferred": packets * rng.randint(60, 1400),
        "packet_count": packets,
        "duration_ms": rng.randint(1, 6000),
        "recent_flows_from_src": rng.randint(0, 30),
    }


def random_anomalous_flow(rng: random.Random, kind: str = None) -> dict:
    kind = kind or rng.choice(["port_scan", "exfiltration", "brute_force", "icmp_flood"])

    if kind == "port_scan":
        return {
            "source_port": rng.randint(1024, 65535),
            "destination_port": rng.choice([21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 9200, 27017, 3389]),
            "protocol": rng.choice(["TCP", "UDP"]),
            "direction": "inbound",
            "bytes_transferred": rng.randint(0, 400),
            "packet_count": rng.randint(1, 10),
            "duration_ms": rng.randint(1, 250),
            "recent_flows_from_src": rng.randint(50, 500),
        }
    if kind == "exfiltration":
        return {
            "source_port": rng.randint(1024, 65535),
            "destination_port": rng.choice([443, 53, 22]),
            "protocol": rng.choice(["TCP", "UDP"]),
            "direction": "outbound",
            "bytes_transferred": rng.randint(300000, 10000000),
            "packet_count": rng.randint(800, 40000),
            "duration_ms": rng.randint(8000, 150000),
            "recent_flows_from_src": rng.randint(0, 20),
        }
    if kind == "brute_force":
        return {
            "source_port": rng.randint(1024, 65535),
            "destination_port": 22,
            "protocol": "TCP",
            "direction": "inbound",
            "bytes_transferred": rng.randint(2000, 30000),
            "packet_count": rng.randint(15, 500),
            "duration_ms": rng.randint(3000, 50000),
            "recent_flows_from_src": rng.randint(30, 300),
        }
    return {  # icmp_flood
        "source_port": 0,
        "destination_port": 0,
        "protocol": "ICMP",
        "direction": "inbound",
        "bytes_transferred": rng.randint(8000, 600000),
        "packet_count": rng.randint(600, 25000),
        "duration_ms": rng.randint(1500, 40000),
        "recent_flows_from_src": rng.randint(5, 60),
    }


def synthetic_dataset(n_normal: int = 4000, n_anomalous: int = 600, seed: int = 7):
    rng = random.Random(seed)
    features, labels = [], []

    for _ in range(n_normal):
        features.append(build_flow_features(**random_normal_flow(rng)))
        labels.append(0)
    for _ in range(n_anomalous):
        features.append(build_flow_features(**random_anomalous_flow(rng)))
        labels.append(1)

    return np.array(features, dtype=float), np.array(labels)


def live_dataset(db_url: str, limit: int = 5000):
    """Pull real flows from PostgreSQL and reuse their ML scores as labels."""
    from sqlalchemy import create_engine, text

    engine = create_engine(db_url)
    with engine.connect() as conn:
        rows = conn.execute(text(
            """
            SELECT source_port, destination_port, protocol, direction,
                   bytes_transferred, packet_count, duration_ms, is_anomalous
            FROM network_traffic
            ORDER BY created_at DESC
            LIMIT :limit
            """
        ), {"limit": limit}).fetchall()

    features, labels = [], []
    for row in rows:
        features.append(build_flow_features(
            source_port=row[0],
            destination_port=row[1],
            protocol=row[2],
            direction=row[3],
            bytes_transferred=row[4],
            packet_count=row[5],
            duration_ms=row[6],
        ))
        labels.append(1 if row[7] else 0)
    return np.array(features, dtype=float), np.array(labels)


def train(features: np.ndarray, labels: np.ndarray, contamination: float = 0.15, seed: int = 7):
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(features)

    model = IsolationForest(
        n_estimators=200,
        max_samples=256,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(x_scaled)

    raw_scores = model.score_samples(x_scaled)
    # Threshold at the contamination quantile of the TRAINING distribution
    threshold = float(np.percentile(raw_scores, contamination * 100))

    return model, scaler, threshold


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--db-url", default=os.getenv("DATABASE_URL", ""))
    parser.add_argument("--min-samples", type=int, default=0,
                        help="Minimum DB samples before using live data")
    parser.add_argument("--synthetic-normal", type=int, default=4000)
    parser.add_argument("--synthetic-anomalous", type=int, default=600)
    args = parser.parse_args()

    features_list, labels_list = [], []

    # 1) Live data from PostgreSQL when enough is available
    if args.db_url and args.min_samples:
        from sqlalchemy import create_engine, text
        engine = create_engine(args.db_url)
        with engine.connect() as conn:
            count = conn.execute(text("SELECT count(*) FROM network_traffic")).scalar()
        if count >= args.min_samples:
            live_x, live_y = live_dataset(args.db_url)
            features_list.append(live_x)
            labels_list.append(live_y)
            print(f"Using {len(live_x)} live flows from PostgreSQL")
        else:
            print(f"Only {count} live flows (< {args.min_samples}) - skipping live data")

    # 2) Synthetic baseline so the model always has broad coverage
    syn_x, syn_y = synthetic_dataset(args.synthetic_normal, args.synthetic_anomalous)
    features_list.append(syn_x)
    labels_list.append(syn_y)
    print(f"Using {len(syn_x)} synthetic flows")

    features = np.vstack(features_list)
    labels = np.concatenate(labels_list)

    model, scaler, threshold = train(features, labels)
    anomaly_rate = labels.mean()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "scaler": scaler,
            "threshold": threshold,
            "n_features": features.shape[1],
            "trained_on": len(features),
            "anomaly_rate": anomaly_rate,
        },
        output,
    )

    print(f"Model saved to {output}")
    print(f"  features: {features.shape[1]}, samples: {len(features)}")
    print(f"  contamination/label rate: {anomaly_rate:.3f}")
    print(f"  decision threshold: {threshold:.4f}")
    print("Done.")


if __name__ == "__main__":
    main()