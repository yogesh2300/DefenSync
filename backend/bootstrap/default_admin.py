"""Admin bootstrap from ADMIN_USERNAME / ADMIN_EMAIL / ADMIN_PASSWORD in the local .env.

Startup (`ensure_default_admin`) is idempotent: it creates the configured admin only when
no ADMIN account exists yet and nobody already holds ADMIN_EMAIL or ADMIN_USERNAME. It never
creates a second admin and never changes an existing password. To apply a deliberately
changed ADMIN_PASSWORD to the configured admin:

    python -m backend.bootstrap.default_admin --reset-password

The password is only ever stored as a hash and is never logged or printed.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

from backend.core.config import Settings, get_settings
from backend.core.exceptions import ValidationException
from backend.core.logging import get_logger
from backend.core.security import hash_password
from backend.database.connection import get_session
from backend.database.crud import admin_user_exists, get_user_by_email, get_user_by_username
from backend.services.auth_service import EMAIL_PATTERN, MIN_PASSWORD_LENGTH, AuthService

logger = get_logger(__name__)


@dataclass(frozen=True)
class AdminConfig:
    username: str
    email: str
    password: str

    def __repr__(self) -> str:
        return f"AdminConfig(username={self.username!r}, email=<configured>, password=<redacted>)"


def admin_config(settings: Settings | None = None) -> tuple[AdminConfig | None, str | None]:
    """Return the configured admin, or None and a reason that never contains the password."""
    settings = settings or get_settings()
    username = (settings.ADMIN_USERNAME or "").strip()
    email = (settings.ADMIN_EMAIL or "").strip().lower()
    password = settings.ADMIN_PASSWORD.get_secret_value() if settings.ADMIN_PASSWORD is not None else ""
    if not username or not email or not password:
        return None, "ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD must all be set in .env"
    if len(username) < 3:
        return None, "ADMIN_USERNAME must be at least 3 characters"
    if not EMAIL_PATTERN.fullmatch(email):
        return None, "ADMIN_EMAIL is not a valid email address"
    if len(password) < MIN_PASSWORD_LENGTH:
        return None, f"ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters"
    return AdminConfig(username, email, password), None


def ensure_default_admin() -> None:
    """Create the configured ADMIN account when no ADMIN user exists yet."""
    config, problem = admin_config()
    session = get_session()
    try:
        if config is not None:
            holder = get_user_by_email(session, config.email)
            if holder is not None:
                if (holder.role or "").upper() == "ADMIN":
                    logger.info("Configured admin already exists (username=%s).", holder.username)
                else:
                    logger.warning("ADMIN_EMAIL belongs to a non-admin account; it is not promoted automatically.")
                return

        if admin_user_exists(session):
            if config is not None:
                logger.warning("An admin exists but none uses ADMIN_EMAIL; no second admin was created.")
            else:
                logger.info("Admin already exists.")
            return

        if config is None:
            logger.warning("No ADMIN user found and admin bootstrap is not configured (%s).", problem)
            return

        if get_user_by_username(session, config.username):
            logger.warning("No ADMIN user found, but ADMIN_USERNAME is taken by another account; bootstrap skipped.")
            return

        AuthService(session).register_user(
            username=config.username,
            email=config.email,
            password=config.password,
            role="ADMIN",
        )
        logger.info("Bootstrap admin created (username=%s).", config.username)
    except ValidationException as exc:
        logger.warning("Could not create bootstrap ADMIN user: %s", exc.message)
    except Exception:
        logger.exception("Failed to bootstrap ADMIN user.")
        session.rollback()
    finally:
        session.close()


def reset_admin_password() -> int:
    """Explicitly re-hash ADMIN_PASSWORD onto the admin that owns ADMIN_EMAIL."""
    config, problem = admin_config()
    if config is None:
        print(f"Admin bootstrap is not configured: {problem}.", file=sys.stderr)
        return 1
    session = get_session()
    try:
        user = get_user_by_email(session, config.email)
        if user is None or (user.role or "").upper() != "ADMIN":
            print("No ADMIN account uses ADMIN_EMAIL; start the backend to create it.", file=sys.stderr)
            return 1
        digest = hash_password(config.password)
        user.password_hash = digest
        user.hashed_password = digest
        session.commit()
        print(f"Password for admin '{user.username}' updated from ADMIN_PASSWORD.")
        return 0
    finally:
        session.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DefenSync admin bootstrap")
    parser.add_argument("--reset-password", action="store_true", help="apply ADMIN_PASSWORD to the configured admin")
    args = parser.parse_args(argv)
    if args.reset_password:
        return reset_admin_password()
    ensure_default_admin()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
