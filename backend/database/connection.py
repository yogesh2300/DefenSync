"""PostgreSQL connection and session management for DefenSync."""

from __future__ import annotations

import os
from datetime import timezone, tzinfo
from functools import lru_cache
from typing import Iterator
from zoneinfo import ZoneInfo

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import get_settings


def get_database_url() -> str:
    """Return the PostgreSQL connection URL from application settings."""
    return get_settings().DATABASE_URL


@lru_cache(maxsize=1)
def get_engine(*, echo: bool | None = None) -> Engine:
    """Return a cached SQLAlchemy 2.x engine configured for PostgreSQL."""
    if echo is None:
        echo = os.getenv("DB_ECHO", "false").lower() in {"1", "true", "yes"}

    return create_engine(
        get_database_url(),
        echo=echo,
        pool_pre_ping=True,
    )


def get_session_factory(*, echo: bool | None = None) -> sessionmaker[Session]:
    """Return a session factory bound to the application engine."""
    return sessionmaker(
        bind=get_engine(echo=echo),
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


def get_session(*, echo: bool | None = None) -> Session:
    """Create a new database session."""
    return get_session_factory(echo=echo)()


_STORAGE_TIMEZONES: dict[int, tzinfo] = {}


def storage_timezone(session: Session) -> tzinfo:
    """Zone of naive DateTime column values.

    Columns are `timestamp without time zone`; PostgreSQL stores aware datetimes as wall
    clock in the session TimeZone. SQLite keeps the UTC values written by the pipeline.
    """
    engine = session.get_bind()
    engine = getattr(engine, "engine", engine)
    key = id(engine)
    if key not in _STORAGE_TIMEZONES:
        zone: tzinfo = timezone.utc
        if engine.dialect.name == "postgresql":
            zone = ZoneInfo(str(session.execute(text("SHOW TimeZone")).scalar()))
        _STORAGE_TIMEZONES[key] = zone
    return _STORAGE_TIMEZONES[key]


def session_scope(*, echo: bool | None = None) -> Iterator[Session]:
    """Provide a transactional scope that commits on success and rolls back on failure."""
    session = get_session(echo=echo)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
