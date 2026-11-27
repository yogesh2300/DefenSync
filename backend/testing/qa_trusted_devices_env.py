"""Safety helpers for an isolated local QA environment for Trusted Devices.

This module never starts services, never sends email, and never prints passwords,
OTPs, or tokens. Operators must explicitly opt into database writes via the setup CLI.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

LOCAL_DB_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
# Database names that are explicitly treated as disposable local QA targets.
ALLOWED_QA_DB_NAMES = frozenset({"defensync_qa", "cloudsync_qa"})
QA_DB_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]*_qa$")
CONFIRM_PHRASE = "I_UNDERSTAND_LOCAL_QA"
BLOCKED_ENVIRONMENTS = frozenset({"production", "prod"})

# Dedicated throwaway identities for Trusted Devices browser QA (emails stay on the local mailbox).
QA_ANALYST_USERNAME = "qa_td_analyst"
QA_ANALYST_EMAIL = "qa.td.analyst@localhost"
QA_ADMIN_USERNAME = "qa_td_admin"
QA_ADMIN_EMAIL = "qa.td.admin@localhost"

SMTP_QA_HOST = "127.0.0.1"
SMTP_QA_PORT = "2525"
SMTP_QA_SECURITY = "none"
SMTP_QA_FROM = "defensync-qa@localhost"


@dataclass(frozen=True)
class QaTargetView:
    """Redacted view of the configured database/SMTP target for operator confirmation."""

    environment: str
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    smtp_host: str
    smtp_port: int
    smtp_security: str
    smtp_from: str
    blockers: tuple[str, ...]

    @property
    def is_safe(self) -> bool:
        return not self.blockers


def _str(settings: Any, name: str, default: str = "") -> str:
    value = getattr(settings, name, default)
    if hasattr(value, "get_secret_value"):
        return ""
    return str(value or default).strip()


def assess_qa_target(settings: Any) -> QaTargetView:
    """Return whether `settings` points at an acceptable local QA database and SMTP profile.

    Process environment variables override `.env` for pydantic-settings. SMTP must still be
    forced to the loopback QA mailbox at runtime so OTPs cannot reach an external relay.
    """
    environment = _str(settings, "ENVIRONMENT", "development").lower()
    db_host = _str(settings, "DB_HOST", "127.0.0.1").lower()
    db_name = _str(settings, "DB_NAME")
    db_port = int(getattr(settings, "DB_PORT", 5432) or 5432)
    db_user = _str(settings, "DB_USER", "postgres")
    smtp_host = _str(settings, "SMTP_HOST")
    smtp_port = int(getattr(settings, "SMTP_PORT", 0) or 0)
    smtp_security = _str(settings, "SMTP_SECURITY", "starttls").lower()
    smtp_from = _str(settings, "SMTP_FROM")

    blockers: list[str] = []
    if environment in BLOCKED_ENVIRONMENTS:
        blockers.append(f"ENVIRONMENT={environment!r} is blocked for Trusted Devices QA.")
    if db_host not in LOCAL_DB_HOSTS:
        blockers.append(f"DB_HOST={db_host!r} is not a loopback host; refusing non-local databases.")
    if not db_name:
        blockers.append("DB_NAME is empty.")
    elif db_name not in ALLOWED_QA_DB_NAMES and not QA_DB_NAME_PATTERN.fullmatch(db_name):
        blockers.append(
            f"DB_NAME={db_name!r} is not a local QA database. "
            f"Use one of {sorted(ALLOWED_QA_DB_NAMES)} or a name ending in '_qa'."
        )

    # SMTP in .env may still point at Gmail; that is a warning for status, and a hard
    # requirement when printing run commands / applying accounts for Trusted Devices QA.
    smtp_blockers: list[str] = []
    if smtp_host.lower() not in LOCAL_DB_HOSTS:
        smtp_blockers.append(
            f"SMTP_HOST={(smtp_host or '(empty)')!r} is not loopback. "
            "Start the backend with process-env SMTP overrides to 127.0.0.1:2525."
        )
    if smtp_security != SMTP_QA_SECURITY:
        smtp_blockers.append(
            f"SMTP_SECURITY={smtp_security!r} must be 'none' for the local QA mailbox "
            "(accepted by the backend only for localhost relays)."
        )
    if smtp_port and int(smtp_port) != int(SMTP_QA_PORT):
        smtp_blockers.append(f"SMTP_PORT={smtp_port} should be {SMTP_QA_PORT} for the QA mailbox.")

    return QaTargetView(
        environment=environment or "development",
        db_host=db_host or "127.0.0.1",
        db_port=db_port,
        db_name=db_name,
        db_user=db_user,
        smtp_host=smtp_host or "(unset)",
        smtp_port=smtp_port,
        smtp_security=smtp_security or "(unset)",
        smtp_from=smtp_from or "(unset)",
        blockers=tuple(blockers + smtp_blockers),
    )


def assess_database_only(settings: Any) -> QaTargetView:
    """Like assess_qa_target but only enforces database locality (SMTP may still need overrides)."""
    view = assess_qa_target(settings)
    db_blockers = tuple(
        item for item in view.blockers if not item.startswith("SMTP_")
    )
    return QaTargetView(
        environment=view.environment,
        db_host=view.db_host,
        db_port=view.db_port,
        db_name=view.db_name,
        db_user=view.db_user,
        smtp_host=view.smtp_host,
        smtp_port=view.smtp_port,
        smtp_security=view.smtp_security,
        smtp_from=view.smtp_from,
        blockers=db_blockers,
    )


def confirm_phrase_accepted(value: str | None) -> bool:
    return (value or "").strip() == CONFIRM_PHRASE
