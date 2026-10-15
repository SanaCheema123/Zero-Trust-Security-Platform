from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)

from app.database.connection import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), default="LOW", index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=True)

    source_ip = Column(String(45), nullable=True)
    destination_ip = Column(String(45), nullable=True)

    description = Column(Text, nullable=True)

    anomaly_score = Column(Float, nullable=True)
    risk_score = Column(Float, nullable=True)

    is_anomalous = Column(Boolean, default=False, index=True)
    is_alerted = Column(Boolean, default=False)

    event_metadata = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class NetworkTraffic(Base):
    __tablename__ = "network_traffic"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)

    protocol = Column(String(20), nullable=False)
    direction = Column(String(10), default="inbound")

    bytes_transferred = Column(Integer, default=0)
    packet_count = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)

    anomaly_score = Column(Float, nullable=True)
    is_anomalous = Column(Boolean, default=False, index=True)

    traffic_metadata = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String(100), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    success = Column(Boolean, default=False, index=True)
    mfa_required = Column(Boolean, default=False)
    mfa_success = Column(Boolean, nullable=True)

    reason = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(String(20), default="MEDIUM", index=True)
    status = Column(String(30), default="OPEN", index=True)

    risk_score = Column(Float, default=0.0)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=True)

    assignee_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    event_ids = Column(JSON, default=list)

    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class TrustScore(Base):
    __tablename__ = "trust_scores"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    server_id = Column(Integer, ForeignKey("servers.id"), nullable=True)

    score = Column(Float, nullable=False)

    user_score = Column(Float, nullable=True)
    device_score = Column(Float, nullable=True)
    network_score = Column(Float, nullable=True)
    behavior_score = Column(Float, nullable=True)

    reason = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(100), nullable=True)

    action = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(Integer, nullable=True)

    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    details = Column(JSON, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id = Column(Integer, primary_key=True, index=True)

    client_id = Column(String(64), unique=True, nullable=False, index=True)
    client_secret = Column(String(128), nullable=False)

    name = Column(String(100), nullable=False)

    redirect_uris = Column(JSON, default=list)

    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.utcnow)


class OAuthAuthorizationCode(Base):
    __tablename__ = "oauth_authorization_codes"

    id = Column(Integer, primary_key=True, index=True)

    code = Column(String(128), unique=True, nullable=False, index=True)

    client_id = Column(String(64), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    redirect_uri = Column(String(255), nullable=False)
    scope = Column(String(255), nullable=True)

    code_challenge = Column(String(128), nullable=True)
    code_challenge_method = Column(String(10), nullable=True)

    is_used = Column(Boolean, default=False)

    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)