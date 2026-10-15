#!/usr/bin/env python3
"""Seed the zero-trust platform database with demo data.

Creates:
  * roles + users (admin / security_analyst / operator / viewer)
  * devices and servers with initial posture
  * network traffic history (ML-scored)
  * security events (including ML-flagged anomalies)
  * open incidents
  * trust score records
  * audit log entries
  * an OAuth 2.0 demo client for the frontend SSO button

It also trains the anomaly detection model when it is missing.

Usage:
    DATABASE_URL=postgresql+psycopg://... python scripts/seed_database.py
"""

import os
import random
import sys
from datetime import datetime, timedelta

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "backend")
    )
)

from app.database.connection import SessionLocal
from app.models import (
    AuditLog,
    Device,
    Incident,
    NetworkTraffic,
    OAuthClient,
    Role,
    SecurityEvent,
    Server,
    TrustScore,
    User,
)
from app.security.auth import hash_password

ROLE_DESCRIPTIONS = {
    "admin": "Full platform administration",
    "security_analyst": "Investigate incidents, manage ML, generate reports",
    "operator": "Operate network/assets and respond to incidents",
    "viewer": "Read-only access to dashboards",
}

USERS = [
    {"username": "admin", "email": "admin@zerotrust.local",
     "password": "Admin@123", "role": "admin"},
    {"username": "security_analyst", "email": "analyst@zerotrust.local",
     "password": "Analyst@123", "role": "security_analyst"},
    {"username": "operator", "email": "operator@zerotrust.local",
     "password": "Operator@123", "role": "operator"},
    {"username": "viewer", "email": "viewer@zerotrust.local",
     "password": "Viewer@123", "role": "viewer"},
]

DEVICES = [
    {"hostname": "analyst-laptop-01", "ip_address": "10.0.1.21",
     "mac_address": "3C:52:82:11:AA:01", "device_type": "laptop",
     "operating_system": "Windows 11", "owner_user_id": 2,
     "is_trusted": True, "trust_score": 78.5, "is_online": True},
    {"hostname": "ops-workstation-02", "ip_address": "10.0.1.32",
     "mac_address": "3C:52:82:11:AA:02", "device_type": "workstation",
     "operating_system": "Ubuntu 24.04", "owner_user_id": 3,
     "is_trusted": True, "trust_score": 81.0, "is_online": True},
    {"hostname": "admin-mobile-01", "ip_address": "10.0.1.44",
     "mac_address": "A4:83:E7:11:AA:03", "device_type": "mobile",
     "operating_system": "iOS 17", "owner_user_id": 1,
     "is_trusted": True, "trust_score": 74.2, "is_online": True},
    {"hostname": "lab-laptop-07", "ip_address": "10.0.1.57",
     "mac_address": "F0:2F:74:11:AA:04", "device_type": "laptop",
     "operating_system": "macOS 14", "owner_user_id": None,
     "is_trusted": False, "trust_score": 35.0, "is_online": True,
     "risk_factors": ["missing_os_updates", "unknown_owner"]},
    {"hostname": "guest-wifi-tablet-03", "ip_address": "10.0.2.15",
     "mac_address": "D8:3A:DD:11:AA:05", "device_type": "tablet",
     "operating_system": "Android 14", "owner_user_id": None,
     "is_trusted": False, "trust_score": 22.5, "is_online": True,
     "risk_factors": ["guest_network", "no_mdm"]},
]

SERVERS = [
    {"hostname": "web-prod-01", "ip_address": "10.0.10.11",
     "server_type": "web", "operating_system": "Ubuntu 22.04",
     "zone": "dmz", "services": ["nginx", "node-app"],
     "is_online": True, "trust_score": 88.0},
    {"hostname": "db-prod-01", "ip_address": "10.0.10.21",
     "server_type": "database", "operating_system": "Debian 12",
     "zone": "internal", "services": ["postgresql"],
     "is_online": True, "trust_score": 90.5},
    {"hostname": "auth-prod-01", "ip_address": "10.0.10.31",
     "server_type": "identity", "operating_system": "Ubuntu 22.04",
     "zone": "internal", "services": ["keycloak"],
     "is_online": True, "trust_score": 92.0},
    {"hostname": "file-staging-01", "ip_address": "10.0.20.41",
     "server_type": "file", "operating_system": "CentOS Stream 9",
     "zone": "staging", "services": ["samba", "nfs"],
     "is_online": True, "trust_score": 55.0,
     "risk_factors": ["legacy_os", "open_smb_shares"]},
]

ATTACKER_IPS = [
    "45.155.205.233", "185.220.101.34", "103.75.190.24",
    "198.98.51.13", "91.219.236.105", "194.26.135.178",
]

EVENT_TEMPLATES = [
    # (event_type, severity, description, anomaly_score, risk_score, ip)
    ("suspicious_login", "MEDIUM",
     "Suspicious login from a new geographic location", 0.61, 55.0, None),
    ("port_scan_detected", "HIGH",
     "Port scan detected against internal assets (22, 443, 3389)", 0.88, 78.0, None),
    ("brute_force_ssh", "HIGH",
     "Repeated SSH authentication failures against auth-prod-01", 0.82, 72.0, None),
    ("data_exfiltration_suspect", "CRITICAL",
     "Unusually large outbound transfer detected", 0.95, 91.0, None),
    ("mfa_failure", "MEDIUM",
     "Multiple invalid TOTP codes submitted", 0.58, 52.0, None),
    ("malware_signature", "HIGH",
     "Endpoint flagged by EDR signature match", 0.79, 74.0, None),
    ("unauthorized_device", "MEDIUM",
     "Unknown device joined the network", 0.55, 48.0, None),
    ("ics_protocol_anomaly", "LOW",
     "Unexpected protocol observed on OT segment", 0.45, 30.0, None),
]


def ensure_schema():
    """Create tables if missing; rebuild them if the schema is out of date.

    SQLAlchemy's create_all() never alters existing tables, so a database
    volume created by an older version of the models keeps its old columns
    and every query against the new columns fails (e.g. roles.description).
    Since all data here is demo/seed data, a detected mismatch is repaired
    by dropping and recreating the schema before seeding.
    """
    from sqlalchemy import inspect

    from app.database.connection import Base, engine

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    missing_tables = [
        name for name in Base.metadata.tables if name not in existing_tables
    ]
    if missing_tables:
        print(f"Creating missing tables: {', '.join(sorted(missing_tables))}")
        Base.metadata.create_all(bind=engine)

    # Also check pre-existing tables for column drift: create_all() never
    # alters existing tables, so old volumes keep missing new columns.
    needs_rebuild = False
    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            continue
        existing_columns = {c["name"] for c in inspector.get_columns(table_name)}
        expected_columns = set(table.columns.keys())
        missing_columns = expected_columns - existing_columns
        if missing_columns:
            print(
                f"Schema out of date: {table_name} is missing "
                f"{', '.join(sorted(missing_columns))}"
            )
            needs_rebuild = True
            break

    if needs_rebuild:
        print("Rebuilding schema...")
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)


def seed_database():
    ensure_schema()
    db = SessionLocal()

    try:
        # ---------------------------------------------------------- roles
        roles = {}
        for role_name, description in ROLE_DESCRIPTIONS.items():
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(name=role_name, description=description)
                db.add(role)
                db.flush()
            roles[role_name] = role

        # ---------------------------------------------------------- users
        user_ids = {}
        for user_data in USERS:
            user = db.query(User).filter(User.username == user_data["username"]).first()
            if not user:
                user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    password_hash=hash_password(user_data["password"]),
                    is_active=True,
                    mfa_enabled=False,
                    last_login=datetime.utcnow() - timedelta(hours=random.randint(2, 30)),
                    last_login_ip=random.choice(["10.0.1.21", "10.0.1.32", "10.0.1.44"]),
                )
                user.roles.append(roles[user_data["role"]])
                db.add(user)
                db.flush()
                print(f"Created user: {user_data['username']}")
            user_ids[user_data["username"]] = user.id

        # -------------------------------------------------------- devices
        device_ids = {}
        for dev in DEVICES:
            existing = db.query(Device).filter(Device.hostname == dev["hostname"]).first()
            if not existing:
                owner = dev.pop("owner_user_id", None)
                record = Device(
                    **dev,
                    owner_user_id=user_ids.get("security_analyst") if owner == 2
                    else (user_ids.get("operator") if owner == 3
                          else (user_ids.get("admin") if owner == 1 else None)),
                    created_at=datetime.utcnow() - timedelta(days=random.randint(30, 200)),
                    last_seen=datetime.utcnow() - timedelta(minutes=random.randint(1, 300)),
                )
                db.add(record)
                db.flush()
                device_ids[dev["hostname"]] = record.id
                print(f"Created device: {dev['hostname']}")
            else:
                device_ids[dev["hostname"]] = existing.id

        # --------------------------------------------------------- servers
        server_ids = {}
        for srv in SERVERS:
            existing = db.query(Server).filter(Server.hostname == srv["hostname"]).first()
            if not existing:
                record = Server(
                    **srv,
                    created_at=datetime.utcnow() - timedelta(days=random.randint(90, 400)),
                    last_seen=datetime.utcnow() - timedelta(minutes=random.randint(1, 60)),
                )
                db.add(record)
                db.flush()
                server_ids[srv["hostname"]] = record.id
                print(f"Created server: {srv['hostname']}")
            else:
                server_ids[srv["hostname"]] = existing.id

        # -------------------------------------------------- network traffic
        traffic_count = db.query(NetworkTraffic).count()
        if traffic_count < 400:
            print("Seeding network traffic history (this may take a moment)...")
            from app.services.scheduler import ingest_flow
            from app.services.traffic import generate_flow

            rng = random.Random(1234)
            needed = 500 - traffic_count
            for _ in range(needed):
                flow = generate_flow(db, rng)
                flow["created_at"] = datetime.utcnow() - timedelta(
                    minutes=rng.uniform(1, 240),
                    seconds=rng.uniform(0, 59),
                )
                # persist with a backdated timestamp
                row = NetworkTraffic(**flow)
                db.add(row)
                db.flush()
                from app.services.anomaly import score_traffic
                result = score_traffic(db, row)
                row.anomaly_score = result["anomaly_score"]
                row.is_anomalous = result["is_anomalous"]
            db.commit()
            print(f"Seeded {needed} traffic flows")
        else:
            print(f"Traffic history already present ({traffic_count} flows)")

        # ------------------------------------------------- security events
        existing_events = db.query(SecurityEvent).count()
        if existing_events == 0:
            print("Seeding security events...")
            rng = random.Random(99)
            server_hostnames = list(server_ids.keys())
            device_hostnames = list(device_ids.keys())
            for event_type, severity, description, anomaly, risk, _ip in EVENT_TEMPLATES:
                for i in range(rng.randint(2, 5)):
                    use_server = rng.random() < 0.6
                    asset_name = rng.choice(server_hostnames if use_server else device_hostnames)
                    event = SecurityEvent(
                        event_type=event_type,
                        severity=severity,
                        server_id=server_ids.get(asset_name) if use_server else None,
                        device_id=device_ids.get(asset_name) if not use_server else None,
                        source_ip=(
                            rng.choice(ATTACKER_IPS) if event_type in
                            ("port_scan_detected", "brute_force_ssh", "data_exfiltration_suspect")
                            else "10.0.1.21"
                        ),
                        destination_ip="10.0.10.11",
                        description=description,
                        anomaly_score=anomaly,
                        risk_score=risk,
                        is_anomalous=anomaly >= 0.6,
                        is_alerted=True,
                        event_metadata={"seeded": True, "template": event_type},
                        created_at=datetime.utcnow() - timedelta(
                            hours=rng.uniform(0.2, 24 * 6),
                        ),
                    )
                    db.add(event)
            db.commit()

            # sync trust scores with seeded events for realism
            print("Recalculating trust scores...")
            from app.services.trust import recalculate_all
            recalculate_all(db)
            print("Seeded security events")
        else:
            print(f"Security events already present ({existing_events})")

        # ------------------------------------------------------- incidents
        if db.query(Incident).count() == 0:
            print("Seeding incidents...")
            incidents = [
                {
                    "title": "SSH brute force against auth-prod-01",
                    "description": "Multiple SSH authentication failures from external IP 45.155.205.233 targeting the identity zone. Investigate source and review firewall rules.",
                    "severity": "HIGH", "status": "INVESTIGATING",
                    "risk_score": 72.0, "server_id": server_ids.get("auth-prod-01"),
                },
                {
                    "title": "Suspicious outbound data transfer",
                    "description": "ML flagged an unusually large outbound transfer from file-staging-01. Possible data exfiltration; verify against approved transfers.",
                    "severity": "CRITICAL", "status": "OPEN",
                    "risk_score": 91.0, "server_id": server_ids.get("file-staging-01"),
                },
                {
                    "title": "Unknown device on corporate network",
                    "description": "An unrecognized MAC address was observed on the internal segment. Device has been quarantined pending review.",
                    "severity": "MEDIUM", "status": "OPEN",
                    "risk_score": 48.0, "device_id": device_ids.get("guest-wifi-tablet-03"),
                },
            ]
            for inc in incidents:
                db.add(Incident(
                    title=inc["title"], description=inc["description"],
                    severity=inc["severity"], status=inc["status"],
                    risk_score=inc["risk_score"],
                    server_id=inc.get("server_id"), device_id=inc.get("device_id"),
                    assignee_id=user_ids.get("security_analyst"),
                    event_ids=[],
                    created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 48)),
                ))
            db.commit()
            print("Seeded incidents")

        # ----------------------------------------------------- trust history
        if db.query(TrustScore).count() < 20:
            print("Seeding trust score history...")
            rng = random.Random(5)
            devices = db.query(Device).all()
            servers = db.query(Server).all()
            for asset in list(devices) + list(servers):
                base = asset.trust_score or 50.0
                for i in range(6):
                    delta = (i - 5) * rng.uniform(1.5, 4.0)
                    db.add(TrustScore(
                        device_id=asset.id if isinstance(asset, Device) else None,
                        server_id=asset.id if isinstance(asset, Server) else None,
                        score=round(max(0, min(100, base + delta)), 2),
                        reason="Seeded history",
                        created_at=datetime.utcnow() - timedelta(hours=(5 - i) * 8),
                    ))
            db.commit()
            print("Seeded trust score history")

        # ------------------------------------------------------ audit logs
        if db.query(AuditLog).count() < 50:
            print("Seeding audit logs...")
            rng = random.Random(11)
            actions = [
                ("login.success", "user"), ("login.failure", "user"),
                ("incident.update", "incident"), ("device.update", "device"),
                ("network.ingest", "network_traffic"), ("report.export", "report"),
            ]
            usernames = [u["username"] for u in USERS]
            for _ in range(120):
                action, resource = rng.choice(actions)
                username = rng.choice(usernames)
                db.add(AuditLog(
                    user_id=user_ids.get(username),
                    username=username,
                    action=action,
                    resource_type=resource,
                    resource_id=rng.randint(1, 60),
                    ip_address=rng.choice(["10.0.1.21", "10.0.1.32", "10.0.1.44"]),
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    details={"seeded": True},
                    created_at=datetime.utcnow() - timedelta(
                        hours=rng.uniform(0.1, 24 * 7),
                    ),
                ))
            db.commit()
            print("Seeded audit logs")

        # ----------------------------------------------------- oauth client
        demo_client = db.query(OAuthClient).filter(
            OAuthClient.client_id == "zerotrust-frontend"
        ).first()
        if not demo_client:
            db.add(OAuthClient(
                client_id="zerotrust-frontend",
                client_secret="demo-client-secret-change-me",
                name="ZeroTrust Platform UI",
                redirect_uris=[
                    "http://localhost:5173/oauth/callback",
                    "http://localhost:8080/oauth/callback",
                    "http://localhost/oauth/callback",
                ],
                is_active=True,
            ))
            db.commit()
            print("Created OAuth demo client 'zerotrust-frontend'")

        db.commit()
        print("\nDatabase seeding completed successfully.")
        print("Demo users:")
        for u in USERS:
            print(f"  {u['username']:16s} / {u['password']}  ({u['role']})")

    except Exception as e:
        db.rollback()
        print(f"\nDatabase seeding failed: {e}")
        raise

    finally:
        db.close()


def ensure_model():
    """Train the anomaly model if the artifact is missing."""
    from app.ml.service import model_status
    status = model_status()
    if status.get("ready"):
        print(f"Model already present: {status['path']}")
        return

    print("Training anomaly detection model...")
    import subprocess
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml", "train_model.py"))
    env = dict(os.environ)
    env["BACKEND_DIR"] = backend_dir
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
    )
    if result.returncode == 0:
        print(result.stdout)
    else:
        print("Model training failed (continuing):", result.stderr[-800:])


if __name__ == "__main__":
    # Train the model first so seeded traffic flows are scored by real ML
    ensure_model()
    seed_database()