#!/usr/bin/env python3
"""Clean-skeleton reset: delete all mutable application data and keep exactly one admin.

The admin comes from ADMIN_USERNAME / ADMIN_EMAIL / ADMIN_PASSWORD in the local .env. Everything
runs in one transaction with plain DELETE statements (no DROP / TRUNCATE): the schema, code,
dataset source files under datasets/ and model artifacts under models/ are untouched. The
configured admin is kept if it already exists, otherwise it is created inside the same
transaction, so the old accounts disappear only together with the replacement being committed.

    python scripts/reset_skeleton.py          # dry run: show row counts, change nothing
    python scripts/reset_skeleton.py --yes    # perform the reset

Refuses to run when ENVIRONMENT is production. Never prints the admin password.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, func, inspect, select, text

from backend.bootstrap.default_admin import admin_config
from backend.core.config import get_settings
from backend.core.security import hash_password
from backend.database.connection import get_engine, get_session
from backend.database.crud import create_user, get_user_by_email
from backend.database.models import (
    Account, Alert, BehaviorProfile, CollectionRun, DatasetImport, Detection, Event, Incident, RiskHistory, Server, User,
)

# Dependents first. The schema declares no foreign keys, but this order keeps every
# intermediate state consistent for the application's logical references.
DELETE_ORDER = [RiskHistory, Incident, Alert, Detection, BehaviorProfile, CollectionRun, DatasetImport, Event, Server, Account]
LEGACY_TABLES = ["monitored_servers"]


def row_counts(session) -> dict[str, int]:
    tables = set(inspect(session.connection()).get_table_names())
    counts = {model.__tablename__: session.scalar(select(func.count()).select_from(model)) for model in [User, *DELETE_ORDER]}
    for table in LEGACY_TABLES:
        if table in tables:
            counts[table] = session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()
    return counts


def print_counts(title: str, counts: dict[str, int]) -> None:
    print(title)
    for table, count in counts.items():
        print(f"  {table:<18} {count}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DefenSync clean-skeleton database reset")
    parser.add_argument("--yes", action="store_true", help="actually delete (default is a dry run)")
    args = parser.parse_args(argv)

    settings = get_settings()
    if settings.ENVIRONMENT.strip().lower() in {"production", "prod"}:
        print("Refusing to reset: ENVIRONMENT is production.", file=sys.stderr)
        return 2
    config, problem = admin_config(settings)
    if config is None:
        print(f"Refusing to reset: {problem}. The replacement admin must be configured first.", file=sys.stderr)
        return 2

    print(f"Database: {settings.DB_NAME} on {settings.DB_HOST}:{settings.DB_PORT}")
    session = get_session()
    try:
        before = row_counts(session)
        print_counts("Rows before:", before)
        if not args.yes:
            print("Dry run only. Re-run with --yes to delete these rows and keep one admin.")
            return 0

        existing = get_user_by_email(session, config.email)
        keep = existing if existing is not None and (existing.role or "").upper() == "ADMIN" and existing.username == config.username else None

        for model in DELETE_ORDER:
            session.execute(delete(model))
        for table in LEGACY_TABLES:
            if table in before:
                session.execute(text(f'DELETE FROM "{table}"'))
        users = delete(User) if keep is None else delete(User).where(User.id != keep.id)
        session.execute(users)

        if keep is None:
            digest = hash_password(config.password)
            admin = create_user(session, username=config.username, email=config.email, password=digest, role="ADMIN")
        else:
            admin = keep
        session.flush()

        after = row_counts(session)
        remaining = session.execute(select(User.username, User.email, User.role)).all()
        expected = [(config.username, config.email, "ADMIN")]
        leftovers = {table: count for table, count in after.items() if table != User.__tablename__ and count}
        if [(u, e.lower(), r.upper()) for u, e, r in remaining] != expected or leftovers:
            session.rollback()
            print(f"Verification failed (users={len(remaining)}, leftovers={leftovers}); rolled back.", file=sys.stderr)
            return 1

        session.commit()
        print_counts("Rows after:", after)
        print(f"Admin '{admin.username}' {'kept' if keep is not None else 'created'} (role ADMIN, password stored as hash).")
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        get_engine().dispose()


if __name__ == "__main__":
    raise SystemExit(main())
