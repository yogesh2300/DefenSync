#!/usr/bin/env python3
"""Remove analyst accounts left behind by the old register-then-fail-MFA behaviour (development/test only).

Before pending registrations existed, /register committed a User row even when the verification
code could never be delivered. The schema has no "verified" flag, so a candidate must match all of:

  * role is not ADMIN and the email is not ADMIN_EMAIL (the bootstrap admin is never touched)
  * created at or after --created-after (required; pick the window of the failed attempts)
  * no account membership
  * owns nothing: no servers, events, alerts, detections, incidents, risk history,
    behaviour profiles or dataset imports

    python scripts/cleanup_unverified_users.py --created-after 2026-10-04T18:32         # dry run
    python scripts/cleanup_unverified_users.py --created-after 2026-10-04T18:32 --yes   # delete

Deletes in one transaction with plain DELETE statements and re-checks the count before commit.
Refuses to run when ENVIRONMENT is production.
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import delete, func, or_, select

from backend.core.config import get_settings
from backend.database.connection import get_engine, get_session
from backend.database.models import (
    Alert, BehaviorProfile, DatasetImport, Detection, Event, Incident, RiskHistory, Server, User,
)

OWNED_BY_USER = [Event, Alert, Detection, Incident, RiskHistory, BehaviorProfile, DatasetImport]


def owns_anything(session, user_id: str) -> bool:
    if session.scalar(select(func.count(Server.id)).where(or_(Server.owner_id == user_id, Server.created_by == user_id))):
        return True
    return any(session.scalar(select(func.count()).select_from(model).where(model.owner_id == user_id)) for model in OWNED_BY_USER)


def find_candidates(session, created_after: datetime, admin_email: str) -> list[User]:
    stmt = (
        select(User)
        .where(func.upper(User.role) != "ADMIN")
        .where(User.created_at >= created_after)
        .where(or_(User.account_id.is_(None), User.account_id == ""))
        .order_by(User.created_at)
    )
    if admin_email:
        stmt = stmt.where(func.lower(User.email) != admin_email.strip().lower())
    return [user for user in session.scalars(stmt).all() if not owns_anything(session, user.id)]


def mask_email(email: str) -> str:
    local, _, domain = (email or "").partition("@")
    return f"{local[:1]}***@{domain}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remove orphaned, never-verified analyst accounts (dev/test)")
    parser.add_argument("--created-after", required=True, type=datetime.fromisoformat, help="ISO timestamp, e.g. 2026-10-04T18:32")
    parser.add_argument("--yes", action="store_true", help="actually delete (default is a dry run)")
    args = parser.parse_args(argv)

    settings = get_settings()
    if (settings.ENVIRONMENT or "").lower() == "production":
        print("Refusing to run: ENVIRONMENT is production.", file=sys.stderr)
        return 2

    session = get_session()
    try:
        candidates = find_candidates(session, args.created_after, settings.ADMIN_EMAIL)
        total = session.scalar(select(func.count(User.id)))
        print(f"Users in database: {total}. Orphaned, never-verified candidates: {len(candidates)}")
        for user in candidates:
            print(f"  {user.username:<24} {mask_email(user.email):<28} created {user.created_at:%Y-%m-%d %H:%M}")
        if not args.yes:
            print("Dry run only. Re-run with --yes to delete these users.")
            return 0
        ids = [user.id for user in candidates]
        if ids:
            deleted = session.execute(delete(User).where(User.id.in_(ids))).rowcount
            if deleted != len(ids):
                session.rollback()
                print(f"Expected to delete {len(ids)} users but matched {deleted}; rolled back.", file=sys.stderr)
                return 1
        session.commit()
        print(f"Deleted {len(ids)} users. Users remaining: {session.scalar(select(func.count(User.id)))}")
        return 0
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
        get_engine().dispose()


if __name__ == "__main__":
    raise SystemExit(main())
