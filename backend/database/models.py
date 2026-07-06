"""SQLAlchemy database models for CloudSync."""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, Integer, DateTime, Text, Index
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    """Database model for registered system accounts."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # admin, analyst, viewer
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))


class SecurityEvent(Base):
    """Database model for normalized security logs."""
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_id = Column(String(36), unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(100), nullable=False)
    username = Column(String(100), nullable=True)
    source_ip = Column(String(45), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False, index=True)
    process = Column(String(50), nullable=True)
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=False)
    hash = Column(String(64), unique=True, nullable=False, index=True)


# Compound indexes for fast telemetry queries
Index("ix_events_user_time", SecurityEvent.username, SecurityEvent.timestamp)
Index("ix_events_severity_time", SecurityEvent.severity, SecurityEvent.timestamp)