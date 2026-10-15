"""Simulated network traffic generator.

Produces realistic flow records between known internal assets and external
hosts. Most flows are normal; a configurable share are suspicious patterns
(port scans, exfiltration, brute force, ICMP flood) so the ML anomaly
detector has something to find.
"""

import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address, ip_address

from sqlalchemy.orm import Session

from app.models.device import Device, Server
from app.models.security import NetworkTraffic

INTERNAL_PREFIXES = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "192.168."]

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTPS", "SSH", "HTTP"]

SERVICE_PORTS = {
    "HTTPS": 443,
    "HTTP": 80,
    "SSH": 22,
    "DNS": 53,
    "TCP": 3306,
    "UDP": 53,
}

EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "104.16.132.229", "151.101.1.69",
    "185.199.108.153", "52.84.12.44", "34.117.59.81", "140.82.112.3",
]

# Well-known malicious-ish actors for simulations
ATTACKER_IPS = [
    "45.155.205.233", "185.220.101.34", "103.75.190.24",
    "198.98.51.13", "91.219.236.105", "194.26.135.178",
]


def is_internal(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def generate_external_ip(rng: random.Random) -> str:
    if rng.random() < 0.35:
        return rng.choice(ATTACKER_IPS)
    return rng.choice(EXTERNAL_IPS)


def _internal_assets(db: Session):
    devices = db.query(Device).all()
    servers = db.query(Server).all()
    return devices, servers


def generate_flow(db: Session, rng: random.Random = None) -> dict:
    """Generate one simulated flow record (not yet persisted/scored)."""
    rng = rng or random.Random()
    devices, servers = _internal_assets(db)
    if not servers and not devices:
        return _generic_flow(rng)

    roll = rng.random()

    # 12% of flows are deliberately suspicious
    if roll < 0.12:
        return _anomalous_flow(rng, devices, servers)

    # normal flow: internal -> server/external or external -> server
    if servers and rng.random() < 0.7:
        server = rng.choice(servers)
        dst = server.ip_address
    elif devices:
        device = rng.choice(devices)
        dst = device.ip_address
    else:
        dst = "10.0.0.1"

    if rng.random() < 0.3:
        src = generate_external_ip(rng)
        direction = "inbound"
        protocol = rng.choice(["HTTPS", "HTTP", "SSH"])
    else:
        if devices:
            src = rng.choice(devices).ip_address
        else:
            src = "10.0.0.10"
        direction = "outbound"
        protocol = rng.choice(["HTTPS", "HTTPS", "DNS", "TCP"])

    dest_port = SERVICE_PORTS.get(protocol, rng.choice([443, 80, 22, 5432, 3306]))
    src_port = rng.randint(1024, 65535)

    packet_count = rng.randint(1, 200)
    bytes_transferred = packet_count * rng.randint(60, 1400)
    duration_ms = rng.randint(1, 5000)

    return {
        "source_ip": src,
        "destination_ip": dst,
        "source_port": src_port,
        "destination_port": dest_port,
        "protocol": protocol,
        "direction": direction,
        "bytes_transferred": bytes_transferred,
        "packet_count": packet_count,
        "duration_ms": duration_ms,
        "traffic_metadata": {"simulated": True, "kind": "normal"},
    }


def _generic_flow(rng: random.Random) -> dict:
    return {
        "source_ip": generate_external_ip(rng),
        "destination_ip": "10.0.0.5",
        "source_port": rng.randint(1024, 65535),
        "destination_port": 443,
        "protocol": "HTTPS",
        "direction": "inbound",
        "bytes_transferred": rng.randint(100, 20000),
        "packet_count": rng.randint(1, 60),
        "duration_ms": rng.randint(1, 3000),
        "traffic_metadata": {"simulated": True, "kind": "normal"},
    }


def _anomalous_flow(rng: random.Random, devices, servers) -> dict:
    kind = rng.choice(["port_scan", "exfiltration", "brute_force", "icmp_flood"])
    attacker = generate_external_ip(rng)
    victim = rng.choice(servers).ip_address if servers else "10.0.0.5"

    if kind == "port_scan":
        return {
            "source_ip": attacker,
            "destination_ip": victim,
            "source_port": rng.randint(1024, 65535),
            "destination_port": rng.choice([21, 22, 23, 25, 53, 80, 443, 3306, 5432, 8080, 9200, 27017]),
            "protocol": rng.choice(["TCP", "UDP"]),
            "direction": "inbound",
            "bytes_transferred": rng.randint(0, 300),
            "packet_count": rng.randint(1, 8),
            "duration_ms": rng.randint(1, 200),
            "traffic_metadata": {"simulated": True, "kind": "port_scan"},
        }
    if kind == "exfiltration":
        return {
            "source_ip": victim,
            "destination_ip": attacker,
            "source_port": rng.randint(1024, 65535),
            "destination_port": rng.choice([443, 53, 22]),
            "protocol": rng.choice(["TCP", "UDP"]),
            "direction": "outbound",
            "bytes_transferred": rng.randint(200000, 9000000),
            "packet_count": rng.randint(500, 30000),
            "duration_ms": rng.randint(5000, 120000),
            "traffic_metadata": {"simulated": True, "kind": "exfiltration"},
        }
    if kind == "brute_force":
        return {
            "source_ip": attacker,
            "destination_ip": victim,
            "source_port": rng.randint(1024, 65535),
            "destination_port": 22,
            "protocol": "TCP",
            "direction": "inbound",
            "bytes_transferred": rng.randint(1000, 20000),
            "packet_count": rng.randint(10, 400),
            "duration_ms": rng.randint(2000, 40000),
            "traffic_metadata": {"simulated": True, "kind": "brute_force"},
        }
    # icmp_flood
    return {
        "source_ip": attacker,
        "destination_ip": victim,
        "source_port": 0,
        "destination_port": 0,
        "protocol": "ICMP",
        "direction": "inbound",
        "bytes_transferred": rng.randint(5000, 500000),
        "packet_count": rng.randint(500, 20000),
        "duration_ms": rng.randint(1000, 30000),
        "traffic_metadata": {"simulated": True, "kind": "icmp_flood"},
    }


def bulk_history(db: Session, minutes_back: int = 240, target: int = 800) -> None:
    """Generate historical traffic so dashboards / model have data."""
    rng = random.Random(42)
    now = datetime.utcnow()

    existing = db.query(NetworkTraffic).count()
    if existing >= target:
        return

    needed = target - existing
    for _ in range(needed):
        flow = generate_flow(db, rng)
        flow["created_at"] = now - timedelta(
            minutes=rng.uniform(0, minutes_back),
            seconds=rng.uniform(0, 59),
        )
        db.add(NetworkTraffic(**flow))

    db.commit()