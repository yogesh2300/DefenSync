"""CRUD operations for DefenSync server registry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from sqlalchemy import and_, case, desc, func, or_, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.database.models import CollectionRun, SecurityEvent, Server
from backend.health.status import ERROR_STATUSES, HealthStatus, OFFLINE_STATUSES, is_online
from backend.health.types import HealthCheckResult

MONITORED_STATUSES = ("active", "online", "offline", "error")


def create_server(session: Session, data: Mapping[str, Any]) -> Server:
    server = Server(**dict(data))
    session.add(server)
    session.flush()
    session.refresh(server)
    return server


def get_server(session: Session, server_id: str) -> Server | None:
    return session.get(Server, server_id)


def _owner_clause(owner_id: str):
    return or_(Server.owner_id == owner_id, Server.created_by == owner_id)


def _server_scope(*, owner_id: str | None = None, account_id: str | None = None):
    if account_id:
        return Server.account_id == account_id
    if owner_id:
        return _owner_clause(owner_id)
    return None


def list_servers(
    session: Session,
    *,
    active_only: bool = False,
    owner_id: str | None = None,
    account_id: str | None = None,
) -> list[Server]:
    stmt = select(Server).order_by(desc(Server.created_at))
    if active_only:
        stmt = stmt.where(Server.status != "inactive")
    scoped = _server_scope(owner_id=owner_id, account_id=account_id)
    if scoped is not None:
        stmt = stmt.where(scoped)
    return list(session.scalars(stmt).all())


def list_monitored_servers(session: Session, *, owner_id: str | None = None) -> list[Server]:
    """Return servers eligible for health monitoring (not manually disabled)."""
    return list_servers(session, active_only=True, owner_id=owner_id)


def update_server(session: Session, server: Server, updates: Mapping[str, Any]) -> Server:
    for key, value in updates.items():
        if value is not None and hasattr(server, key):
            setattr(server, key, value)
    server.updated_at = datetime.now(timezone.utc)
    session.flush()
    session.refresh(server)
    return server


def delete_server(session: Session, server: Server) -> None:
    from backend.database.models import LinuxCollectionState

    session.query(LinuxCollectionState).filter(LinuxCollectionState.server_id == server.id).delete()
    session.delete(server)


def mark_health_connecting(session: Session, server: Server) -> Server:
    server.health_status = HealthStatus.CONNECTING
    server.last_health_check = datetime.now(timezone.utc)
    server.updated_at = datetime.now(timezone.utc)
    session.flush()
    session.refresh(server)
    return server


def apply_health_result(session: Session, server: Server, result: HealthCheckResult) -> Server:
    """Atomically persist the outcome of a health probe."""
    now = result.checked_at or datetime.now(timezone.utc)
    server.health_status = result.health_status
    server.last_health_check = now
    server.connection_latency_ms = result.latency_ms
    server.health_error_message = result.error_message
    server.updated_at = now

    if is_online(result.health_status):
        server.last_seen = now
        server.last_connected = now
        server.consecutive_failures = 0
    else:
        server.consecutive_failures = int(server.consecutive_failures or 0) + 1

    session.flush()
    session.refresh(server)
    return server


def set_server_status(
    session: Session,
    server: Server,
    *,
    status: str,
    connected: bool = False,
) -> Server:
    """Legacy enrollment/connectivity helper — prefer apply_health_result for probes."""
    server.status = status
    if connected:
        server.last_seen = datetime.now(timezone.utc)
        server.last_connected = datetime.now(timezone.utc)
        server.health_status = HealthStatus.ONLINE
        server.consecutive_failures = 0
    elif status == "inactive":
        server.health_status = HealthStatus.UNKNOWN
    server.updated_at = datetime.now(timezone.utc)
    session.flush()
    session.refresh(server)
    return server


def create_collection_run(session: Session, server_id: str) -> CollectionRun:
    run = CollectionRun(server_id=server_id, status="running")
    session.add(run)
    session.flush()
    session.refresh(run)
    return run


def complete_collection_run(
    session: Session,
    run: CollectionRun,
    *,
    status: str,
    stats: Mapping[str, Any],
    error_message: str | None = None,
) -> CollectionRun:
    run.status = status
    run.processed = int(stats.get("processed", 0))
    run.inserted = int(stats.get("inserted", 0))
    run.duplicates = int(stats.get("duplicates", 0))
    run.failed = int(stats.get("failed", 0))
    run.skipped = int(stats.get("skipped", 0))
    run.duration_ms = stats.get("duration_ms")
    run.error_message = error_message
    run.completed_at = datetime.now(timezone.utc)
    session.flush()
    session.refresh(run)
    return run


def list_collection_runs(session: Session, server_id: str, *, limit: int = 20) -> list[CollectionRun]:
    stmt = (
        select(CollectionRun)
        .where(CollectionRun.server_id == server_id)
        .order_by(desc(CollectionRun.started_at))
        .limit(limit)
    )
    return list(session.scalars(stmt).all())


def latest_collection_run(session: Session, server_id: str) -> CollectionRun | None:
    stmt = (
        select(CollectionRun)
        .where(CollectionRun.server_id == server_id)
        .order_by(desc(CollectionRun.started_at))
        .limit(1)
    )
    return session.scalar(stmt)


def average_risk_for_server(session: Session, server_id: str) -> int:
    value = session.scalar(
        select(func.avg(SecurityEvent.risk_score)).where(SecurityEvent.server_id == server_id)
    )
    return int(round(value or 0))


def high_risk_count_for_server(session: Session, server_id: str) -> int:
    return session.scalar(
        select(func.count(SecurityEvent.id)).where(
            SecurityEvent.server_id == server_id,
            SecurityEvent.risk_score >= 70,
        )
    ) or 0


def _empty_health_summary() -> dict[str, int]:
    return {
        "total_servers": 0,
        "active_servers": 0,
        "online_servers": 0,
        "offline_servers": 0,
        "healthy_servers": 0,
        "servers_with_errors": 0,
        "average_ssh_latency_ms": 0,
        "recently_connected": 0,
        "recently_disconnected": 0,
    }


def health_summary(
    session: Session,
    *,
    owner_id: str | None = None,
    server_id: str | None = None,
    account_id: str | None = None,
) -> dict[str, int]:
    """Aggregate fleet health metrics from persisted probe results (no live SSH)."""
    settings = get_settings()
    recent_cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.HEALTH_RECENT_WINDOW_SECONDS)

    if server_id:
        server = session.get(Server, server_id)
        if server is None:
            return _empty_health_summary()
        if account_id and server.account_id != account_id:
            return _empty_health_summary()
        if owner_id and not account_id and (server.owner_id or server.created_by) != owner_id:
            return _empty_health_summary()
        if server.status == "inactive":
            return {
                **_empty_health_summary(),
                "total_servers": 1,
            }

        health = (server.health_status or HealthStatus.UNKNOWN).lower()
        online = 1 if is_online(health) else 0
        offline = 1 if health in OFFLINE_STATUSES else 0
        errors = 1 if health in ERROR_STATUSES else 0
        healthy = online
        recent_connected = 1 if server.last_seen and server.last_seen >= recent_cutoff and online else 0
        recent_disconnected = (
            1 if not is_online(health) and server.last_health_check and server.last_health_check >= recent_cutoff else 0
        )
        return {
            "total_servers": 1,
            "active_servers": 1,
            "online_servers": online,
            "offline_servers": offline if not errors else 0,
            "healthy_servers": healthy,
            "servers_with_errors": errors if errors else offline,
            "average_ssh_latency_ms": int(server.connection_latency_ms or 0),
            "recently_connected": recent_connected,
            "recently_disconnected": recent_disconnected,
        }

    base = select(Server)
    scoped = _server_scope(owner_id=owner_id, account_id=account_id)
    if scoped is not None:
        base = base.where(scoped)

    stmt = select(
        func.count(Server.id),
        func.sum(case((Server.status == "inactive", 1), else_=0)),
        func.sum(case((Server.health_status == HealthStatus.ONLINE, 1), else_=0)),
        func.sum(case((Server.health_status.in_(tuple(OFFLINE_STATUSES)), 1), else_=0)),
        func.sum(case((Server.health_status.in_(tuple(ERROR_STATUSES)), 1), else_=0)),
        func.avg(case((Server.health_status == HealthStatus.ONLINE, Server.connection_latency_ms), else_=None)),
        func.sum(case((
            and_(Server.health_status == HealthStatus.ONLINE, Server.last_seen >= recent_cutoff),
            1,
        ), else_=0)),
        func.sum(case((
            and_(
                Server.health_status != HealthStatus.ONLINE,
                Server.health_status != HealthStatus.UNKNOWN,
                Server.health_status != HealthStatus.CONNECTING,
                Server.last_health_check >= recent_cutoff,
            ),
            1,
        ), else_=0)),
    )
    scoped = _server_scope(owner_id=owner_id, account_id=account_id)
    if scoped is not None:
        stmt = stmt.where(scoped)

    row = session.execute(stmt).one()
    total = int(row[0] or 0)
    inactive = int(row[1] or 0)
    online = int(row[2] or 0)
    offline = int(row[3] or 0)
    errors = int(row[4] or 0)
    avg_latency = int(round(row[5] or 0))
    recent_connected = int(row[6] or 0)
    recent_disconnected = int(row[7] or 0)
    active = max(0, total - inactive)

    return {
        "total_servers": total,
        "active_servers": active,
        "online_servers": online,
        "offline_servers": offline + errors,
        "healthy_servers": online,
        "servers_with_errors": errors,
        "average_ssh_latency_ms": avg_latency,
        "recently_connected": recent_connected,
        "recently_disconnected": recent_disconnected,
    }


def server_summary(
    session: Session,
    *,
    owner_id: str | None = None,
    server_id: str | None = None,
) -> dict[str, int]:
    """Backward-compatible wrapper around health_summary."""
    summary = health_summary(session, owner_id=owner_id, server_id=server_id)
    return {
        "total_servers": summary["total_servers"],
        "active_servers": summary["active_servers"],
        "online_servers": summary["online_servers"],
        "offline_servers": summary["offline_servers"],
    }


def count_events_for_server(session: Session, server_id: str) -> int:
    return session.scalar(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.server_id == server_id)
    ) or 0
