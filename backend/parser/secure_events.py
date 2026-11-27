"""Per-event parsers for /var/log/secure entries."""

from __future__ import annotations

from typing import Any, Callable

from backend.parser.event_types import EventType
from backend.parser.patterns import (
    SECURE_FAILED_INVALID_USER,
    SECURE_FAILED_LOGIN,
    SECURE_INVALID_USER,
    SECURE_INVALID_USER_AUTH,
    SECURE_PAM_AUTH_FAILURE,
    SECURE_PAM_SESSION,
    SECURE_SU_SWITCH,
    SECURE_SUCCESSFUL_LOGIN,
    SECURE_SUDO_COMMAND,
    SECURE_SUDO_SESSION,
)
from backend.parser.schemas import build_event
from backend.parser.utils import parse_secure_header

SecureParser = Callable[[str, dict[str, Any]], dict[str, Any] | None]


def parse_invalid_user(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Detect invalid user authentication attempts."""
    message = header["message"]

    match = SECURE_FAILED_INVALID_USER.search(message)
    if match:
        return build_event(
            event_type=EventType.INVALID_USER,
            message=message,
            raw_log=raw_line,
            timestamp=header["timestamp"],
            hostname=header["hostname"],
            username=match.group("user"),
            source_ip=match.group("ip"),
            process=header["process"],
        )

    match = SECURE_INVALID_USER.search(message)
    if match:
        return build_event(
            event_type=EventType.INVALID_USER,
            message=message,
            raw_log=raw_line,
            timestamp=header["timestamp"],
            hostname=header["hostname"],
            username=match.group("user"),
            source_ip=match.group("ip"),
            process=header["process"],
        )

    match = SECURE_INVALID_USER_AUTH.search(message)
    if match:
        return build_event(
            event_type=EventType.INVALID_USER,
            message=message,
            raw_log=raw_line,
            timestamp=header["timestamp"],
            hostname=header["hostname"],
            username=match.group("user"),
            source_ip=None,
            process=header["process"],
        )

    return None


def parse_failed_login(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Detect failed login attempts for valid users."""
    message = header["message"]
    match = SECURE_FAILED_LOGIN.search(message)
    if not match:
        return None

    return build_event(
        event_type=EventType.FAILED_LOGIN,
        message=message,
        raw_log=raw_line,
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        username=match.group("user"),
        source_ip=match.group("ip"),
        process=header["process"],
    )


def parse_successful_login(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Detect successful SSH or PAM logins."""
    message = header["message"]
    match = SECURE_SUCCESSFUL_LOGIN.search(message)
    if not match:
        return None

    return build_event(
        event_type=EventType.SUCCESSFUL_LOGIN,
        message=message,
        raw_log=raw_line,
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        username=match.group("user"),
        source_ip=match.group("ip"),
        process=header["process"],
    )


def parse_sudo_command(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Detect sudo command execution from secure.log."""
    message = header["message"]

    match = SECURE_SUDO_COMMAND.search(message)
    if match:
        return build_event(
            event_type=EventType.SUDO_COMMAND,
            message=message,
            raw_log=raw_line,
            timestamp=header["timestamp"],
            hostname=header["hostname"],
            username=match.group("user"),
            source_ip=None,
            process=header["process"] or "sudo",
        )

    match = SECURE_SUDO_SESSION.search(message)
    if match:
        return build_event(
            event_type=EventType.SUDO_COMMAND,
            message=message,
            raw_log=raw_line,
            timestamp=header["timestamp"],
            hostname=header["hostname"],
            username=header.get("process", "sudo"),
            source_ip=None,
            process="sudo",
        )

    return None


def parse_su_switch(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Detect su's own success/failure record; only lines written by the su program."""
    if header["process"] != "su":
        return None
    match = SECURE_SU_SWITCH.match(header["message"])
    if not match:
        return None
    return build_event(
        event_type=EventType.FAILED_PRIVILEGE_ESCALATION if match.group("failed") else EventType.PRIVILEGE_ESCALATION,
        message=header["message"],
        raw_log=raw_line,
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        username=match.group("user"),
        source_ip=None,
        process=header["process"],
    )


def parse_pam_auth_failure(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Accept pam_unix authentication failures; the normalizer decides by PAM service."""
    if not SECURE_PAM_AUTH_FAILURE.match(header["message"]):
        return None
    return build_event(
        event_type=EventType.FAILED_LOGIN,
        message=header["message"],
        raw_log=raw_line,
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        process=header["process"],
    )


def parse_pam_session(raw_line: str, header: dict[str, Any]) -> dict[str, Any] | None:
    """Accept pam_unix session open/close; the normalizer keeps only login services."""
    match = SECURE_PAM_SESSION.match(header["message"])
    if not match:
        return None
    return build_event(
        event_type=EventType.SESSION_OPENED if match.group("action") == "opened" else EventType.SESSION_CLOSED,
        message=header["message"],
        raw_log=raw_line,
        timestamp=header["timestamp"],
        hostname=header["hostname"],
        username=match.group("user"),
        process=header["process"],
    )


SECURE_EVENT_PARSERS: tuple[SecureParser, ...] = (
    parse_invalid_user,
    parse_failed_login,
    parse_successful_login,
    parse_sudo_command,
    parse_su_switch,
    parse_pam_auth_failure,
    parse_pam_session,
)


def parse_secure_event(raw_line: str) -> dict[str, Any] | None:
    """Classify a secure.log line into a structured security event."""
    stripped = raw_line.strip()
    if not stripped:
        return None

    header = parse_secure_header(stripped)
    if header is None:
        return None

    for parser in SECURE_EVENT_PARSERS:
        event = parser(stripped, header)
        if event is not None:
            event.setdefault("program", header["process"])
            event.setdefault("pid", header["pid"])
            return event

    return None
