#!/usr/bin/env python3
"""Prepare / inspect an isolated local QA target for Trusted Devices browser testing.

Defaults to dry-run. Never starts the mailbox, backend, or frontend. Never prints
passwords, OTPs, or tokens. Refuses to write unless the database is positively a
local *_qa target and the operator passes --apply with the confirm phrase.

Examples (PowerShell, repo root, venv active):

  # Inspect what this process would use (DB from env/.env; SMTP should be overridden later)
  $env:DB_NAME = "defensync_qa"
  python scripts/qa_trusted_devices_setup.py --status

  # Print start commands (does not execute them)
  python scripts/qa_trusted_devices_setup.py --print-commands

  # Create QA accounts only after confirming the local QA DB (passwords via env or prompt)
  $env:DB_NAME = "defensync_qa"
  $env:QA_TRUSTED_DEVICES_CONFIRM = "I_UNDERSTAND_LOCAL_QA"
  python scripts/qa_trusted_devices_setup.py --apply
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.core.config import get_settings
from backend.database.connection import get_engine, get_session
from backend.database.crud import get_user_by_email, get_user_by_username
from backend.database.models import Base
from backend.services.auth_service import AuthService
from backend.testing.qa_trusted_devices_env import (
    CONFIRM_PHRASE,
    QA_ADMIN_EMAIL,
    QA_ADMIN_USERNAME,
    QA_ANALYST_EMAIL,
    QA_ANALYST_USERNAME,
    SMTP_QA_FROM,
    SMTP_QA_HOST,
    SMTP_QA_PORT,
    SMTP_QA_SECURITY,
    assess_database_only,
    assess_qa_target,
    confirm_phrase_accepted,
)


def _reload_settings():
    get_settings.cache_clear()
    try:
        from backend.database.connection import get_engine as _ge
        _ge.cache_clear()
    except Exception:
        pass
    return get_settings()


def _print_status(settings, *, include_smtp: bool) -> int:
    view = assess_qa_target(settings) if include_smtp else assess_database_only(settings)
    print("DefenSync Trusted Devices QA target")
    print(f"  ENVIRONMENT : {view.environment}")
    print(f"  DB_HOST     : {view.db_host}")
    print(f"  DB_PORT     : {view.db_port}")
    print(f"  DB_NAME     : {view.db_name}")
    print(f"  DB_USER     : {view.db_user}")
    print(f"  SMTP_HOST   : {view.smtp_host}")
    print(f"  SMTP_PORT   : {view.smtp_port or '(unset)'}")
    print(f"  SMTP_SECURITY: {view.smtp_security}")
    print(f"  SMTP_FROM   : {view.smtp_from}")
    print(f"  Analyst     : {QA_ANALYST_USERNAME} <{QA_ANALYST_EMAIL}>")
    print(f"  Admin       : {QA_ADMIN_USERNAME} <{QA_ADMIN_EMAIL}>")
    if view.blockers:
        print("BLOCKERS:")
        for item in view.blockers:
            print(f"  - {item}")
        return 2
    print("OK: local QA database identity accepted.")
    if not include_smtp:
        print("NOTE: start the backend with process-env SMTP overrides to 127.0.0.1:2525 so OTPs stay local.")
    return 0


def _print_commands() -> None:
    print(
        f"""# === DefenSync Trusted Devices QA — PowerShell (copy/paste; does not auto-start) ===
# 0) Create the disposable QA database once (PostgreSQL local only):
#    psql -h 127.0.0.1 -U postgres -c "CREATE DATABASE defensync_qa;"

# 1) Terminal A — local OTP mailbox (127.0.0.1 only; optional --print-codes on a trusted machine)
$env:QA_SMTP_PORT = "{SMTP_QA_PORT}"
python scripts/qa_otp_mailbox.py --print-codes

# 2) Terminal B — backend forced onto QA DB + local SMTP (process env overrides .env)
$env:DB_HOST = "127.0.0.1"
$env:DB_NAME = "defensync_qa"
$env:ENVIRONMENT = "development"
$env:SMTP_HOST = "{SMTP_QA_HOST}"
$env:SMTP_PORT = "{SMTP_QA_PORT}"
$env:SMTP_SECURITY = "{SMTP_QA_SECURITY}"
$env:SMTP_FROM = "{SMTP_QA_FROM}"
$env:SMTP_USERNAME = " "
$env:SMTP_PASSWORD = " "
python scripts/migrate_schema.py
python -m backend.main

# Confirm SMTP/DB: GET /health should be healthy; startup must not log delivery to a non-local host.
# With SMTP_SECURITY=none the backend refuses non-loopback SMTP_HOST.

# 3) Terminal C — frontend (proxies /api to the backend)
npm --prefix frontend run dev

# 4) Provision throwaway accounts (after steps 0–2 DB exists). Passwords via prompt or env; never logged.
$env:DB_NAME = "defensync_qa"
$env:QA_TRUSTED_DEVICES_CONFIRM = "{CONFIRM_PHRASE}"
python scripts/qa_trusted_devices_setup.py --apply

# 5) Browser: http://localhost:5173/login as {QA_ANALYST_EMAIL} (analyst) or {QA_ADMIN_EMAIL} (admin)
#    OTP appears in Terminal A when --print-codes is set.
"""
    )


def _print_checklist() -> None:
    print(
        f"""# Trusted Devices browser checklist (after QA setup)
1. Mailbox running on 127.0.0.1:{SMTP_QA_PORT}; backend started with DB_NAME=defensync_qa and SMTP overrides above.
2. Sign in as analyst {QA_ANALYST_EMAIL} → OTP from local mailbox → environment → dashboard.
3. Account menu → Trusted Devices. Confirm count (N / limit), empty or listed devices, session-revocation notice.
4. Enroll this browser with a display name. Confirm success mentions device-bound session token; count increments.
5. DevTools/Application → localStorage defensync_token replaced (do not paste the token anywhere).
6. Optional: Refresh device-bound session; confirm success without exposing secrets.
7. Start revoke → cancel confirmation → device still active.
8. Revoke the test device → status REVOKED, count decreases; success text does not claim global logout.
9. Protected call with the revoked device-bound token should 401 (use a second browser profile or API client holding the old bound token if testing isolation).
10. Enroll a second device (or second browser profile). Confirm independent sessions; MFA-only token (pre-enroll) still works until expiry per policy.
11. Fill all slots (default 3) → further enroll shows TRUSTED_DEVICE_LIMIT_EXCEEDED guidance.
12. Sign in as admin {QA_ADMIN_EMAIL} → Admin → Users → QA analyst → Trusted devices limit/list visible.
13. As analyst, confirm admin device-limit API/UI is unavailable; you only see your own devices.
"""
    )


def _password(env_name: str, label: str) -> str:
    from_env = os.getenv(env_name, "")
    if from_env:
        return from_env
    first = getpass.getpass(f"{label} password (min 8 chars, not echoed): ")
    second = getpass.getpass(f"Confirm {label} password: ")
    if first != second:
        raise SystemExit(f"{label} passwords did not match.")
    return first


def _ensure_user(*, username: str, email: str, password: str, role: str, reset_passwords: bool) -> str:
    session = get_session()
    try:
        existing = get_user_by_email(session, email) or get_user_by_username(session, username)
        if existing is not None:
            if (existing.email or "").lower() != email.lower() or existing.username != username:
                return f"SKIP conflict for {username}/{email}: another account already owns that identity."
            if (existing.role or "").upper() != role.upper():
                return f"SKIP {username}: exists with role={(existing.role or '').upper()} (expected {role})."
            if reset_passwords:
                AuthService(session).set_password(existing, password)
                return f"UPDATED password hash for existing {role} {username}."
            return f"EXISTS {role} {username} <{email}> (unchanged)."
        AuthService(session).register_user(username=username, email=email, password=password, role=role)
        return f"CREATED {role} {username} <{email}>."
    finally:
        session.close()


def _ensure_database(settings) -> int:
    """Create the configured *_qa database if missing. Never drops. Connects via maintenance DB 'postgres'."""
    view = assess_database_only(settings)
    if view.blockers:
        print("Refusing --ensure-db; target is not an accepted local QA database:")
        for item in view.blockers:
            print(f"  - {item}")
        return 2
    if not confirm_phrase_accepted(os.getenv("QA_TRUSTED_DEVICES_CONFIRM")):
        print(f"Set QA_TRUSTED_DEVICES_CONFIRM={CONFIRM_PHRASE} for --ensure-db.")
        return 2

    import psycopg
    from urllib.parse import quote_plus

    raw_password = settings.DB_PASSWORD
    password = raw_password.get_secret_value() if hasattr(raw_password, "get_secret_value") else str(raw_password)
    target = view.db_name
    users = []
    if os.getenv("QA_PG_SUPERUSER", "").strip():
        users.append(os.getenv("QA_PG_SUPERUSER", "").strip())
    users.extend(["postgres", settings.DB_USER])
    last_err = "unknown"
    for user in users:
        maint = (
            f"postgresql://{quote_plus(user)}:{quote_plus(password)}"
            f"@{settings.DB_HOST}:{int(settings.DB_PORT)}/postgres"
        )
        try:
            with psycopg.connect(maint, autocommit=True) as conn:
                row = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target,)).fetchone()
                if row:
                    print(f"EXISTS database {target} (unchanged).")
                    return 0
                can = conn.execute(
                    "SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user"
                ).fetchone()
                if not can or not can[0]:
                    last_err = f"{user} lacks CREATEDB/SUPERUSER"
                    continue
                # Identifier validated as local *_qa by assess_database_only.
                conn.execute(f'CREATE DATABASE "{target}"')
                print(f"CREATED database {target}.")
                return 0
        except Exception as exc:
            last_err = f"{user}:{type(exc).__name__}"
            continue
    print(f"Failed to ensure QA database ({last_err}).")
    print("OPERATOR_ACTION: as a local PostgreSQL superuser run:")
    print(f'  psql -h 127.0.0.1 -U postgres -c "CREATE DATABASE {target};"')
    print(f'  psql -h 127.0.0.1 -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE {target} TO {settings.DB_USER};"')
    print("Or set QA_PG_SUPERUSER to a privileged role whose password matches DB_PASSWORD in this process, then re-run --ensure-db.")
    return 1


def _apply(settings, *, reset_passwords: bool) -> int:
    view = assess_database_only(settings)
    if view.blockers:
        print("Refusing --apply; database is not an accepted local QA target:")
        for item in view.blockers:
            print(f"  - {item}")
        return 2
    if not confirm_phrase_accepted(os.getenv("QA_TRUSTED_DEVICES_CONFIRM")):
        print(f"Set QA_TRUSTED_DEVICES_CONFIRM={CONFIRM_PHRASE} to apply account changes.")
        return 2

    analyst_password = _password("QA_ANALYST_PASSWORD", "QA analyst")
    admin_password = _password("QA_ADMIN_PASSWORD", "QA admin")
    AuthService.validate_password(analyst_password)
    AuthService.validate_password(admin_password)

    # Ensure schema exists on the QA database (idempotent create_all; migrate_schema is still recommended).
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    messages = [
        _ensure_user(
            username=QA_ANALYST_USERNAME,
            email=QA_ANALYST_EMAIL,
            password=analyst_password,
            role="ANALYST",
            reset_passwords=reset_passwords,
        ),
        _ensure_user(
            username=QA_ADMIN_USERNAME,
            email=QA_ADMIN_EMAIL,
            password=admin_password,
            role="ADMIN",
            reset_passwords=reset_passwords,
        ),
    ]
    for line in messages:
        print(line)
    print("Done. Passwords were not printed. Use the local QA mailbox for OTP codes.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Isolated local QA prep for Trusted Devices (dry-run by default).")
    parser.add_argument("--status", action="store_true", help="Show redacted DB/SMTP target and blockers.")
    parser.add_argument("--print-commands", action="store_true", help="Print PowerShell start commands; do not run them.")
    parser.add_argument("--print-checklist", action="store_true", help="Print the browser verification checklist.")
    parser.add_argument("--apply", action="store_true", help="Create/update QA accounts after safety checks.")
    parser.add_argument(
        "--ensure-db",
        action="store_true",
        help="Create the local *_qa database if missing (never drops). Requires confirm phrase.",
    )
    parser.add_argument(
        "--reset-passwords",
        action="store_true",
        help="With --apply, reset passwords for existing QA accounts (hashes only).",
    )
    parser.add_argument(
        "--require-smtp-overrides",
        action="store_true",
        help="With --status, also require loopback SMTP already set in this process.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not any([args.status, args.print_commands, args.print_checklist, args.apply, args.ensure_db]):
        build_parser().print_help()
        print("\nHint: start with --print-commands or --status (set DB_NAME=defensync_qa in the process env).")
        return 0

    if args.print_commands:
        _print_commands()
    if args.print_checklist:
        _print_checklist()

    settings = None
    if args.status or args.apply or args.ensure_db:
        settings = _reload_settings()

    code = 0
    if args.status and settings is not None:
        code = max(code, _print_status(settings, include_smtp=bool(args.require_smtp_overrides)))
    if args.ensure_db and settings is not None:
        code = max(code, _ensure_database(settings))
    if args.apply and settings is not None:
        code = max(code, _apply(settings, reset_passwords=bool(args.reset_passwords)))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
