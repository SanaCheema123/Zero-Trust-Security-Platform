from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, JSON, String

from app.database.connection import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String(150), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)
    mac_address = Column(String(17), nullable=True)

    device_type = Column(String(50), nullable=False)
    operating_system = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)

    owner_user_id = Column(Integer, nullable=True)

    is_trusted = Column(Boolean, default=False)
    trust_score = Column(Float, default=50.0)

    is_online = Column(Boolean, default=True)

    risk_factors = Column(JSON, default=list)

    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class Server(Base):
    __tablename__ = "servers"

    id = Column(Integer, primary_key=True, index=True)

    hostname = Column(String(150), nullable=False)
    ip_address = Column(String(45), nullable=False, index=True)

    server_type = Column(String(100), nullable=False)
    operating_system = Column(String(100), nullable=True)

    zone = Column(String(50), default="production")

    services = Column(JSON, default=list)

    is_online = Column(Boolean, default=True)
    trust_score = Column(Float, default=50.0)

    risk_factors = Column(JSON, default=list)

    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)