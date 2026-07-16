"""Bootstrap tasks run during application startup."""

from __future__ import annotations

from backend.core.config import get_settings
from backend.core.exceptions import ValidationException
from backend.core.logging import get_logger
from backend.database.connection import get_session
from backend.database.crud import admin_user_exists
from backend.services.auth_service import AuthService

logger = get_logger(__name__)


def ensure_default_admin() -> None:
    """Create the default ADMIN account when no ADMIN user exists yet."""
    settings = get_settings()
    session = get_session()
    try:
        if admin_user_exists(session):
            logger.info("Default admin already exists.")
            return

        password = settings.DEFAULT_ADMIN_PASSWORD.get_secret_value()
        if not password:
            logger.warning(
                "No ADMIN user found and DEFAULT_ADMIN_PASSWORD is empty; skipping bootstrap.",
            )
            return

        username = settings.DEFAULT_ADMIN_USERNAME.strip()
        email = settings.DEFAULT_ADMIN_EMAIL.strip().lower()
        if not username or not email:
            logger.warning(
                "No ADMIN user found and default admin username/email are not configured; skipping bootstrap.",
            )
            return

        AuthService(session).register_user(
            username=username,
            email=email,
            password=password,
            role="ADMIN",
        )
        logger.info("Default admin created successfully (username=%s).", username)
    except ValidationException as exc:
        logger.warning("Could not create default ADMIN user: %s", exc.message)
    except Exception:
        logger.exception("Failed to bootstrap default ADMIN user.")
        session.rollback()
    finally:
        session.close()
