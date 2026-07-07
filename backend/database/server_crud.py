"""CRUD operations for DefenSync server registry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.orm import Session

from backend.database.models import CollectionRun, SecurityEvent, Server

ACTIVE_STATUSES = ("active", "online")


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


def list_servers(session: Session, *, active_only: bool = False, owner_id: str | None = None) -> list[Server]:
    stmt = select(Server).order_by(desc(Server.created_at))
    if active_only:
        stmt = stmt.where(Server.status.in_(ACTIVE_STATUSES))
    if owner_id:
        stmt = stmt.where(_owner_clause(owner_id))
    return list(session.scalars(stmt).all())


def update_server(session: Session, server: Server, updates: Mapping[str, Any]) -> Server:
    for key, value in updates.items():
        if value is not None and hasattr(server, key):
            setattr(server, key, value)
    server.updated_at = datetime.now(timezone.utc)
    session.flush()
    session.refresh(server)
    return server


def delete_server(session: Session, server: Server) -> None:
    session.delete(server)


def set_server_status(
    session: Session,
    server: Server,
    *,
    status: str,
    connected: bool = False,
) -> Server:
    server.status = status
    if connected:
        server.last_seen = datetime.now(timezone.utc)
        server.last_connected = datetime.now(timezone.utc)
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


def server_summary(
    session: Session,
    *,
    owner_id: str | None = None,
    server_id: str | None = None,
) -> dict[str, int]:
    if server_id:
        server = session.get(Server, server_id)
        if server is None:
            return {
                "total_servers": 0,
                "active_servers": 0,
                "online_servers": 0,
                "offline_servers": 0,
            }
        if owner_id and (server.owner_id or server.created_by) != owner_id:
            return {
                "total_servers": 0,
                "active_servers": 0,
                "online_servers": 0,
                "offline_servers": 0,
            }
        is_active = server.status in ACTIVE_STATUSES
        is_online = server.status == "online"
        return {
            "total_servers": 1,
            "active_servers": 1 if is_active else 0,
            "online_servers": 1 if is_online else 0,
            "offline_servers": 1 if is_active and not is_online else 0,
        }

    stmt = select(
        func.count(Server.id),
        func.sum(case((Server.status.in_(ACTIVE_STATUSES), 1), else_=0)),
        func.sum(case((Server.status == "online", 1), else_=0)),
    )
    if owner_id:
        stmt = stmt.where(_owner_clause(owner_id))
    row = session.execute(stmt).one()
    total = int(row[0] or 0)
    active = int(row[1] or 0)
    online = int(row[2] or 0)
    return {
        "total_servers": total,
        "active_servers": active,
        "online_servers": online,
        "offline_servers": max(0, active - online),
    }


def count_events_for_server(session: Session, server_id: str) -> int:
    return session.scalar(
        select(func.count(SecurityEvent.id)).where(SecurityEvent.server_id == server_id)
    ) or 0
