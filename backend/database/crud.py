"""CRUD operations for CloudSync security event persistence."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable, Mapping

from sqlalchemy import desc, select, func, delete
from sqlalchemy.orm import Session

from backend.database.models import SecurityEvent, User


def insert_event(session: Session, event: Mapping[str, Any]) -> SecurityEvent:
    """Persist a single security event."""
    record = _to_model(event)
    session.add(record)
    session.flush()
    session.refresh(record)
    return record


def insert_many(session: Session, events: Iterable[Mapping[str, Any]]) -> list[SecurityEvent]:
    """Persist multiple security events in one transaction."""
    records = [_to_model(event) for event in events]
    if not records:
        return []

    session.add_all(records)
    session.flush()
    for record in records:
        session.refresh(record)
    return records


def get_recent_events(session: Session, *, limit: int = 100) -> list[SecurityEvent]:
    """Return the most recent events ordered by event timestamp."""
    stmt = (
        select(SecurityEvent)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def get_high_risk_events(
    session: Session,
    *,
    min_score: int = 70,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Return events at or above the configured risk score threshold."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.risk_score >= min_score)
        .order_by(desc(SecurityEvent.risk_score), desc(SecurityEvent.timestamp))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def get_events_by_username(
    session: Session,
    username: str,
    *,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Return events associated with a specific username."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.username == username)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())



def get_event_by_id(session: Session, event_id: str) -> SecurityEvent | None:
    """Return a security event by its unique event_id."""
    stmt = select(SecurityEvent).where(SecurityEvent.event_id == event_id)
    return session.scalar(stmt)


def get_events_by_ip(
    session: Session,
    ip: str,
    *,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Return events originating from the given IP address."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.source_ip == ip)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def get_events_by_type(
    session: Session,
    event_type: str,
    *,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Return events of a specific event type."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.event_type == event_type)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def get_events_by_hostname(
    session: Session,
    hostname: str,
    *,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Return events for a specific hostname."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.hostname == hostname)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def count_events(session: Session) -> int:
    """Return total number of security events."""
    stmt = select(func.count()).select_from(SecurityEvent)
    return session.scalar(stmt) or 0


def count_high_risk_events(
    session: Session,
    min_score: int = 70,
) -> int:
    """Return number of high-risk security events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.risk_score >= min_score)
    )
    return session.scalar(stmt) or 0


def count_failed_logins(session: Session) -> int:
    """Return number of failed login events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.event_type == "Failed Login")
    )
    return session.scalar(stmt) or 0


def count_successful_logins(session: Session) -> int:
    """Return number of successful login events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.event_type == "Successful Login")
    )
    return session.scalar(stmt) or 0


def count_unique_users(session: Session) -> int:
    """Return number of unique usernames."""
    stmt = select(func.count(func.distinct(SecurityEvent.username)))
    return session.scalar(stmt) or 0


def count_unique_ips(session: Session) -> int:
    """Return number of unique source IPs."""
    stmt = select(func.count(func.distinct(SecurityEvent.source_ip)))
    return session.scalar(stmt) or 0


def dashboard_summary(session: Session) -> dict[str, int]:
    """Return summary statistics for the dashboard."""
    return {
        "total_events": count_events(session),
        "high_risk": count_high_risk_events(session),
        "failed_logins": count_failed_logins(session),
        "successful_logins": count_successful_logins(session),
        "unique_users": count_unique_users(session),
        "unique_ips": count_unique_ips(session),
    }


def delete_old_events(session: Session, days: int) -> int:
    """Delete events older than the specified number of days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    stmt = delete(SecurityEvent).where(SecurityEvent.timestamp < cutoff)

    result = session.execute(stmt)
    session.commit()

    return result.rowcount or 0


# =============================================================================
# User CRUD Operations
# =============================================================================

def create_user(
    session: Session,
    *,
    username: str,
    email: str,
    password_hash: str,
    role: str = "analyst",
) -> User:
    """
    Create a new application user.
    """

    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role=role,
    )

    try:
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    except Exception:
        session.rollback()
        raise


def get_user_by_username(
    session: Session,
    username: str,
) -> User | None:
    """
    Retrieve a user by username.
    """

    stmt = (
        select(User)
        .where(User.username == username)
    )

    return session.scalar(stmt)


def get_user_by_email(
    session: Session,
    email: str,
) -> User | None:
    """
    Retrieve a user by email.
    """

    stmt = (
        select(User)
        .where(User.email == email)
    )

    return session.scalar(stmt)


def get_user_by_id(
    session: Session,
    user_id: int,
) -> User | None:
    """
    Retrieve a user by primary key.
    """

    stmt = (
        select(User)
        .where(User.id == user_id)
    )

    return session.scalar(stmt)


def list_users(
    session: Session,
) -> list[User]:
    """
    Return all users.
    """

    stmt = (
        select(User)
        .order_by(User.username)
    )

    return list(session.scalars(stmt).all())


def delete_user(
    session: Session,
    user_id: int,
) -> bool:
    """
    Delete a user.
    """

    user = get_user_by_id(session, user_id)

    if user is None:
        return False

    try:
        session.delete(user)
        session.commit()
        return True

    except Exception:
        session.rollback()
        raise


def _to_model(event: Mapping[str, Any]) -> SecurityEvent:
    """Convert an event mapping into a SecurityEvent ORM instance."""
    payload = _normalize_payload(event)
    return SecurityEvent(
        event_id=str(payload["event_id"]),
        timestamp=_parse_timestamp(payload["timestamp"]),
        hostname=str(payload["hostname"]),
        username=payload.get("username"),
        source_ip=payload.get("source_ip"),
        event_type=str(payload["event_type"]),
        category=str(payload["category"]),
        severity=str(payload["severity"]),
        risk_score=int(payload["risk_score"]),
        process=payload.get("process"),
        message=str(payload["message"]),
        raw_log=str(payload["raw_log"]),
    )


def _normalize_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize parser or normalizer payloads into database-ready fields."""
    if hasattr(event, "to_dict"):
        payload = event.to_dict()
    else:
        payload = dict(event)

    metadata = payload.get("metadata") or {}

    return {
        "event_id": payload.get("event_id") or str(uuid.uuid4()),
        "timestamp": payload["timestamp"],
        "hostname": payload.get("hostname") or "unknown",
        "username": payload.get("username"),
        "source_ip": payload.get("source_ip"),
        "event_type": payload["event_type"],
        "category": payload.get("category") or metadata.get("category") or "unknown",
        "severity": payload.get("severity") or metadata.get("severity") or "info",
        "risk_score": payload.get("risk_score", metadata.get("risk_score", 0)),
        "process": payload.get("process") or metadata.get("process"),
        "message": payload.get("message") or metadata.get("message") or payload.get("raw_log", ""),
        "raw_log": payload.get("raw_log") or payload.get("raw") or "",
    }


def _parse_timestamp(value: str | datetime) -> datetime:
    """Parse ISO-8601 or datetime values into timezone-aware datetimes."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    normalized = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed
