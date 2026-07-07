"""CRUD operations for DefenSync security event persistence."""

from __future__ import annotations

import json
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable, Mapping

from sqlalchemy import ColumnElement, case, desc, or_, select, func, delete
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

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


def get_recent_events(
    session: Session,
    *,
    limit: int = 100,
    owner_id: str | None = None,
    server_id: str | None = None,
) -> list[SecurityEvent]:
    """Return the most recent events ordered by event timestamp."""
    stmt = (
        select(SecurityEvent)
        .order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))
        .limit(limit)
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    if server_id:
        stmt = stmt.where(SecurityEvent.server_id == server_id)
    return list(session.scalars(stmt).all())


def get_high_risk_events(
    session: Session,
    *,
    min_score: int = 70,
    limit: int = 100,
    owner_id: str | None = None,
    server_id: str | None = None,
) -> list[SecurityEvent]:
    """Return events at or above the configured risk score threshold."""
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.risk_score >= min_score)
        .order_by(desc(SecurityEvent.risk_score), desc(SecurityEvent.timestamp))
        .limit(limit)
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    if server_id:
        stmt = stmt.where(SecurityEvent.server_id == server_id)
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


def get_existing_event_ids(session: Session, event_ids: list[str]) -> set[str]:
    """Retrieve the set of event_ids that already exist in the database from the given list."""
    if not event_ids:
        return set()
    stmt = select(SecurityEvent.event_id).where(SecurityEvent.event_id.in_(event_ids))
    return set(session.scalars(stmt).all())


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


def count_events(session: Session, *, owner_id: str | None = None) -> int:
    """Return total number of security events."""
    stmt = select(func.count()).select_from(SecurityEvent)
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def count_high_risk_events(
    session: Session,
    min_score: int = 70,
    owner_id: str | None = None,
) -> int:
    """Return number of high-risk security events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.risk_score >= min_score)
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def count_failed_logins(session: Session, *, owner_id: str | None = None) -> int:
    """Return number of failed login events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.event_type == "Failed Login")
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def count_successful_logins(session: Session, *, owner_id: str | None = None) -> int:
    """Return number of successful login events."""
    stmt = (
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.event_type == "Successful Login")
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def count_unique_users(session: Session, *, owner_id: str | None = None) -> int:
    """Return number of unique usernames."""
    stmt = select(func.count(func.distinct(SecurityEvent.username)))
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def count_unique_ips(session: Session, *, owner_id: str | None = None) -> int:
    """Return number of unique source IPs."""
    stmt = select(func.count(func.distinct(SecurityEvent.source_ip)))
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    return session.scalar(stmt) or 0


def dashboard_summary(
    session: Session,
    *,
    owner_id: str | None = None,
    server_id: str | None = None,
) -> dict[str, int]:
    """Return summary statistics for the dashboard."""
    stmt = select(
        func.count(SecurityEvent.id),
        func.sum(case((SecurityEvent.risk_score >= 70, 1), else_=0)),
        func.sum(case((SecurityEvent.event_type == "Failed Login", 1), else_=0)),
        func.sum(case((SecurityEvent.event_type == "Successful Login", 1), else_=0)),
        func.count(func.distinct(SecurityEvent.username)),
        func.count(func.distinct(SecurityEvent.source_ip)),
        func.avg(SecurityEvent.risk_score),
    )
    if owner_id:
        stmt = stmt.where(SecurityEvent.owner_id == owner_id)
    if server_id:
        stmt = stmt.where(SecurityEvent.server_id == server_id)
    row = session.execute(stmt).one()
    avg_risk = row[6] or 0
    return {
        "total_events": int(row[0] or 0),
        "high_risk": int(row[1] or 0),
        "failed_logins": int(row[2] or 0),
        "successful_logins": int(row[3] or 0),
        "unique_users": int(row[4] or 0),
        "unique_ips": int(row[5] or 0),
        "average_risk_score": int(round(avg_risk)),
    }


def delete_old_events(session: Session, days: int) -> int:
    """Delete events older than the specified number of days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    stmt = delete(SecurityEvent).where(SecurityEvent.timestamp < cutoff)

    result = session.execute(stmt)
    session.commit()

    return result.rowcount or 0


def _event_filter_clauses(
    *,
    event_type: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    server_id: str | None = None,
    owner_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    min_risk_score: int | None = None,
    max_risk_score: int | None = None,
) -> list[ColumnElement[bool]]:
    """Build shared WHERE clauses for SecurityEvent queries."""
    clauses: list[ColumnElement[bool]] = []

    if event_type:
        clauses.append(SecurityEvent.event_type == event_type)
    if severity:
        clauses.append(SecurityEvent.severity == severity)
    if category:
        clauses.append(SecurityEvent.category == category)
    if username:
        clauses.append(SecurityEvent.username == username)
    if source_ip:
        clauses.append(SecurityEvent.source_ip == source_ip)
    if hostname:
        clauses.append(SecurityEvent.hostname == hostname)
    if server_id:
        clauses.append(SecurityEvent.server_id == server_id)
    if owner_id:
        clauses.append(SecurityEvent.owner_id == owner_id)
    if start_time:
        clauses.append(SecurityEvent.timestamp >= start_time)
    if end_time:
        clauses.append(SecurityEvent.timestamp <= end_time)
    if min_risk_score is not None:
        clauses.append(SecurityEvent.risk_score >= min_risk_score)
    if max_risk_score is not None:
        clauses.append(SecurityEvent.risk_score <= max_risk_score)
    if search:
        pattern = f"%{search.strip()}%"
        clauses.append(
            or_(
                SecurityEvent.message.ilike(pattern),
                SecurityEvent.username.ilike(pattern),
                SecurityEvent.hostname.ilike(pattern),
                SecurityEvent.source_ip.ilike(pattern),
                SecurityEvent.process.ilike(pattern),
                SecurityEvent.event_type.ilike(pattern),
                SecurityEvent.raw_log.ilike(pattern),
            )
        )

    return clauses


def _apply_event_filters(stmt: Select[Any], filters: list[ColumnElement[bool]]) -> Select[Any]:
    """Apply filter clauses to a select statement."""
    for clause in filters:
        stmt = stmt.where(clause)
    return stmt
def _apply_event_sort(stmt: Select[Any], *, sort_order: str = "newest") -> Select[Any]:
    """Apply timestamp sort order to a SecurityEvent select statement."""
    if sort_order == "oldest":
        return stmt.order_by(SecurityEvent.timestamp.asc(), SecurityEvent.id.asc())
    return stmt.order_by(desc(SecurityEvent.timestamp), desc(SecurityEvent.id))


def query_events(
    session: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    event_type: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    server_id: str | None = None,
    owner_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    min_risk_score: int | None = None,
    max_risk_score: int | None = None,
    sort_order: str = "newest",
) -> list[SecurityEvent]:
    """Query, filter, search, and paginate security events."""
    filters = _event_filter_clauses(
        event_type=event_type,
        severity=severity,
        category=category,
        username=username,
        source_ip=source_ip,
        hostname=hostname,
        server_id=server_id,
        owner_id=owner_id,
        start_time=start_time,
        end_time=end_time,
        search=search,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
    )
    stmt = _apply_event_filters(select(SecurityEvent), filters)
    stmt = _apply_event_sort(stmt, sort_order=sort_order)
    stmt = stmt.offset(offset).limit(limit)
    return list(session.scalars(stmt).all())


def count_query_events(
    session: Session,
    *,
    event_type: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    hostname: str | None = None,
    server_id: str | None = None,
    owner_id: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    search: str | None = None,
    min_risk_score: int | None = None,
    max_risk_score: int | None = None,
) -> int:
    """Return the total number of security events matching filter criteria."""
    filters = _event_filter_clauses(
        event_type=event_type,
        severity=severity,
        category=category,
        username=username,
        source_ip=source_ip,
        hostname=hostname,
        server_id=server_id,
        owner_id=owner_id,
        start_time=start_time,
        end_time=end_time,
        search=search,
        min_risk_score=min_risk_score,
        max_risk_score=max_risk_score,
    )
    stmt = _apply_event_filters(select(func.count()).select_from(SecurityEvent), filters)
    return session.scalar(stmt) or 0


def update_event(
    session: Session,
    event_id: str,
    updates: Mapping[str, Any],
) -> SecurityEvent | None:
    """Update mutable fields on an existing security event."""
    record = get_event_by_id(session, event_id)
    if record is None:
        return None

    allowed_fields = {
        "severity",
        "risk_score",
        "category",
        "message",
        "username",
        "source_ip",
        "process",
        "hostname",
    }
    for field, value in updates.items():
        if field in allowed_fields:
            setattr(record, field, value)

    session.flush()
    session.refresh(record)
    return record


def delete_event_by_id(session: Session, event_id: str) -> bool:
    """Delete a single security event by its unique event_id."""
    record = get_event_by_id(session, event_id)
    if record is None:
        return False
    session.delete(record)
    return True


def delete_events(
    session: Session,
    *,
    event_type: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_ip: str | None = None,
) -> int:
    """Delete security events matching specified criteria."""
    stmt = delete(SecurityEvent)
    
    has_criteria = False
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
        has_criteria = True
    if start_time:
        stmt = stmt.where(SecurityEvent.timestamp >= start_time)
        has_criteria = True
    if end_time:
        stmt = stmt.where(SecurityEvent.timestamp <= end_time)
        has_criteria = True
    if source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == source_ip)
        has_criteria = True

    if not has_criteria:
        raise ValueError("At least one delete criterion must be provided.")

    result = session.execute(stmt)
    return result.rowcount or 0


def calculate_event_hash(raw_log: str, timestamp: datetime) -> str:
    """Generate SHA-256 hash of raw log and timestamp for deduplication."""
    ts_str = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp)
    data = f"{raw_log}_{ts_str}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def get_existing_event_hashes(session: Session, hashes: list[str]) -> set[str]:
    """Retrieve the set of event hashes that already exist in the database from the given list."""
    if not hashes:
        return set()
    try:
        stmt = select(SecurityEvent.hash).where(SecurityEvent.hash.in_(hashes))
        return set(session.scalars(stmt).all())
    except Exception:
        session.rollback()
        return set()


def get_event_by_hash(session: Session, hash_val: str) -> SecurityEvent | None:
    """Retrieve a security event by its calculated hash."""
    try:
        stmt = select(SecurityEvent).where(SecurityEvent.hash == hash_val)
        return session.scalar(stmt)
    except Exception:
        session.rollback()
        return None


def _to_model(event: Mapping[str, Any]) -> SecurityEvent:
    """Convert an event mapping into a SecurityEvent ORM instance."""
    payload = _normalize_payload(event)
    ts = _parse_timestamp(payload["timestamp"])
    raw_log = str(payload["raw_log"])
    h_val = payload.get("hash") or calculate_event_hash(raw_log, ts)
    return SecurityEvent(
        event_id=str(payload["event_id"]),
        server_id=payload.get("server_id"),
        owner_id=payload.get("owner_id"),
        timestamp=ts,
        hostname=str(payload["hostname"]),
        username=payload.get("username"),
        source_ip=payload.get("source_ip"),
        event_type=str(payload["event_type"]),
        category=str(payload["category"]),
        severity=str(payload["severity"]),
        risk_score=int(payload["risk_score"]),
        risk_level=payload.get("risk_level"),
        command=payload.get("command"),
        process=payload.get("process"),
        message=str(payload["message"]),
        raw_log=raw_log,
        normalized_data=payload.get("normalized_data"),
        hash=h_val,
        cpu_usage=payload.get("cpu_usage"),
        memory_usage=payload.get("memory_usage"),
        disk_usage=payload.get("disk_usage"),
        login_time=_parse_timestamp(payload["login_time"]) if payload.get("login_time") else None,
        logout_time=_parse_timestamp(payload["logout_time"]) if payload.get("logout_time") else None,
        failed_login_count=payload.get("failed_login_count"),
        session_duration=payload.get("session_duration"),
        commands_executed=payload.get("commands_executed"),
        network_connections=payload.get("network_connections"),
    )


def _normalize_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize parser or normalizer payloads into database-ready fields."""
    if hasattr(event, "to_dict"):
        payload = event.to_dict()
    else:
        payload = dict(event)

    metadata = payload.get("metadata") or {}

    risk_score = int(payload.get("risk_score", metadata.get("risk_score", 0)))
    from backend.risk.levels import risk_level_from_score

    return {
        "event_id": payload.get("event_id") or str(uuid.uuid4()),
        "server_id": payload.get("server_id"),
        "owner_id": payload.get("owner_id"),
        "timestamp": payload["timestamp"],
        "hostname": payload.get("hostname") or "unknown",
        "username": payload.get("username"),
        "source_ip": payload.get("source_ip"),
        "event_type": payload["event_type"],
        "category": payload.get("category") or metadata.get("category") or "unknown",
        "severity": payload.get("severity") or metadata.get("severity") or "info",
        "risk_score": risk_score,
        "risk_level": payload.get("risk_level") or metadata.get("risk_level") or risk_level_from_score(risk_score),
        "command": payload.get("command") or metadata.get("command"),
        "process": payload.get("process") or metadata.get("process"),
        "message": payload.get("message") or metadata.get("message") or payload.get("raw_log", ""),
        "raw_log": payload.get("raw_log") or payload.get("raw") or "",
        "normalized_data": payload.get("normalized_data") or json.dumps(metadata, default=str),
        "cpu_usage": payload.get("cpu_usage"),
        "memory_usage": payload.get("memory_usage"),
        "disk_usage": payload.get("disk_usage"),
        "login_time": payload.get("login_time"),
        "logout_time": payload.get("logout_time"),
        "failed_login_count": payload.get("failed_login_count"),
        "session_duration": payload.get("session_duration"),
        "commands_executed": payload.get("commands_executed"),
        "network_connections": payload.get("network_connections"),
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


def get_user_by_username(session: Session, username: str) -> User | None:
    """Retrieve a user by their unique username."""
    stmt = select(User).where(User.username == username)
    return session.scalar(stmt)


def get_user_by_email(session: Session, email: str) -> User | None:
    """Retrieve a user by their unique email."""
    stmt = select(User).where(User.email == email)
    return session.scalar(stmt)


def list_users(session: Session) -> list[User]:
    """Return all users ordered by creation time."""
    return list(session.scalars(select(User).order_by(desc(User.created_at))).all())


def delete_user(session: Session, user_id: str) -> bool:
    """Delete a user by ID."""
    user = session.get(User, user_id)
    if user is None:
        return False
    session.delete(user)
    session.flush()
    return True


def create_user(
    session: Session,
    username: str,
    email: str,
    password: str,
    role: str = "analyst",
) -> User:
    """Create and persist a new user."""
    user = User(
        name=username,
        username=username,
        email=email,
        password_hash=password,
        hashed_password=password,
        role=role.upper(),
    )
    session.add(user)
    session.flush()
    session.refresh(user)
    return user