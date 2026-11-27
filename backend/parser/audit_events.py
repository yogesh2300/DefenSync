"""Per-event parsers for /var/log/audit/audit.log entries."""

from __future__ import annotations

from typing import Any, Callable

from backend.parser.event_types import EventType
from backend.parser.patterns import (
    FILE_CREATE_SYSCALLS,
    FILE_DELETE_SYSCALLS,
    MKDIR_SYSCALLS,
    PERM_SYSCALLS,
)
from backend.parser.schemas import build_event
from backend.parser.utils import (
    extract_audit_hostname,
    extract_audit_message,
    extract_audit_process,
    extract_audit_username,
    is_sudo_context,
    parse_audit_fields,
    parse_audit_timestamp,
    resolve_syscall_name,
)

AuditParser = Callable[[str, dict[str, str], str], dict[str, Any] | None]


def _base_audit_event(
    raw_line: str,
    fields: dict[str, str],
    audit_type: str,
    *,
    event_type: EventType,
    username: str | None = None,
    message: str | None = None,
) -> dict[str, Any]:
    """Build a structured audit event with common field extraction."""
    return build_event(
        event_type=event_type,
        message=message or extract_audit_message(fields, audit_type),
        raw_log=raw_line,
        timestamp=parse_audit_timestamp(raw_line),
        hostname=extract_audit_hostname(fields),
        username=username if username is not None else extract_audit_username(fields),
        source_ip=fields.get("addr") or None,
        process=extract_audit_process(fields),
    )


def parse_user_auth(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect authentication and session start/end from audit records."""
    if audit_type not in {"USER_AUTH", "USER_LOGIN", "USER_START", "USER_END", "USER_ACCT"}:
        return None
    op = (fields.get("op") or "").lower()
    if audit_type == "USER_ACCT" and ("add" in op or "delet" in op):
        return None
    res = (fields.get("res") or fields.get("success") or "").lower()
    failed = res in {"failed", "no", "0"} or "fail" in op
    event_type = EventType.FAILED_LOGIN if failed else EventType.SUCCESSFUL_LOGIN
    return _base_audit_event(
        raw_line,
        fields,
        audit_type,
        event_type=event_type,
        username=fields.get("acct") or extract_audit_username(fields),
    )


def parse_user_creation(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect user account creation events."""
    if audit_type == "ADD_USER":
        return _base_audit_event(
            raw_line,
            fields,
            audit_type,
            event_type=EventType.USER_CREATION,
            username=fields.get("acct") or extract_audit_username(fields),
        )

    if audit_type == "USER_ACCT":
        op = (fields.get("op") or "").lower()
        if "add" in op:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.USER_CREATION,
                username=fields.get("acct") or extract_audit_username(fields),
            )

    return None


def parse_user_deletion(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect user account deletion events."""
    if audit_type == "DEL_USER":
        return _base_audit_event(
            raw_line,
            fields,
            audit_type,
            event_type=EventType.USER_DELETION,
            username=fields.get("acct") or extract_audit_username(fields),
        )

    if audit_type == "USER_ACCT":
        op = (fields.get("op") or "").lower()
        if "delet" in op:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.USER_DELETION,
                username=fields.get("acct") or extract_audit_username(fields),
            )

    return None


def parse_sudo_command(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect sudo command execution from audit records."""
    if not is_sudo_context(fields):
        return None

    if audit_type in {"USER_CMD", "EXECVE", "CRED_REFR", "SYSCALL", "PROCTITLE"}:
        return _base_audit_event(
            raw_line,
            fields,
            audit_type,
            event_type=EventType.SUDO_COMMAND,
        )

    return None


def parse_directory_creation(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect directory creation via mkdir syscalls or CREATE path records."""
    if audit_type == "SYSCALL":
        syscall = resolve_syscall_name(fields)
        if syscall in MKDIR_SYSCALLS:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.DIRECTORY_CREATION,
            )

    if audit_type == "PATH":
        nametype = (fields.get("nametype") or "").upper()
        comm = (fields.get("comm") or "").lower()
        if nametype == "CREATE" and comm in MKDIR_SYSCALLS:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.DIRECTORY_CREATION,
            )

    return None


def parse_file_creation(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect file creation via creat/open syscalls or CREATE path records."""
    if audit_type == "SYSCALL":
        syscall = resolve_syscall_name(fields)
        if syscall in FILE_CREATE_SYSCALLS:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.FILE_CREATION,
            )

    if audit_type == "PATH":
        nametype = (fields.get("nametype") or "").upper()
        if nametype == "CREATE":
            comm = (fields.get("comm") or "").lower()
            if comm not in MKDIR_SYSCALLS:
                return _base_audit_event(
                    raw_line,
                    fields,
                    audit_type,
                    event_type=EventType.FILE_CREATION,
                )

    return None


def parse_file_deletion(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect file or directory deletion events."""
    if audit_type == "SYSCALL":
        syscall = resolve_syscall_name(fields)
        if syscall in FILE_DELETE_SYSCALLS:
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.FILE_DELETION,
            )

    if audit_type == "PATH":
        nametype = (fields.get("nametype") or "").upper()
        if nametype == "DELETE":
            return _base_audit_event(
                raw_line,
                fields,
                audit_type,
                event_type=EventType.FILE_DELETION,
            )

    return None


def parse_permission_change(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect chmod/chown permission changes."""
    if audit_type != "SYSCALL":
        return None

    syscall = resolve_syscall_name(fields)
    if syscall in PERM_SYSCALLS:
        return _base_audit_event(
            raw_line,
            fields,
            audit_type,
            event_type=EventType.PERMISSION_CHANGE,
        )

    return None


def parse_command_execution(raw_line: str, fields: dict[str, str], audit_type: str) -> dict[str, Any] | None:
    """Detect general command execution (non-sudo)."""
    if audit_type not in {"USER_CMD", "EXECVE", "PROCTITLE"}:
        return None

    if is_sudo_context(fields):
        return None

    return _base_audit_event(
        raw_line,
        fields,
        audit_type,
        event_type=EventType.COMMAND_EXECUTION,
    )


AUDIT_EVENT_PARSERS: tuple[AuditParser, ...] = (
    parse_user_auth,
    parse_user_creation,
    parse_user_deletion,
    parse_sudo_command,
    parse_directory_creation,
    parse_file_creation,
    parse_file_deletion,
    parse_permission_change,
    parse_command_execution,
)


def parse_audit_event(raw_line: str) -> dict[str, Any] | None:
    """Classify an audit.log line into a structured security event."""
    stripped = raw_line.strip()
    if not stripped:
        return None

    fields = parse_audit_fields(stripped)
    if not fields:
        return None

    audit_type = fields.get("type", "")
    if not audit_type:
        return None

    for parser in AUDIT_EVENT_PARSERS:
        event = parser(stripped, fields, audit_type)
        if event is not None:
            return event

    return None
