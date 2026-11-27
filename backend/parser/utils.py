"""Shared parsing utilities for secure and audit log lines."""

from __future__ import annotations

from typing import Any

from backend.parser.patterns import AUDIT_KV, AUDIT_TIMESTAMP, AUDIT_SYSCALL_NAMES, ISO_SECURE_HEADER, SECURE_HEADER

_UNSET_VALUES = frozenset({"unset", "4294967295", "-1", ""})


def parse_secure_header(raw_line: str) -> dict[str, Any] | None:
    """Extract syslog header fields from a secure.log line."""
    match = SECURE_HEADER.match(raw_line.strip()) or ISO_SECURE_HEADER.match(raw_line.strip())
    if not match:
        return None
    return {
        "timestamp": match.group("timestamp"),
        "hostname": match.group("hostname"),
        "process": match.group("process").strip(),
        "pid": int(match.group("pid")) if match.group("pid") else None,
        "message": match.group("message"),
    }


def parse_audit_fields(raw_line: str) -> dict[str, str]:
    """Extract key=value fields from an audit.log line."""
    fields: dict[str, str] = {}
    for key, value in AUDIT_KV.findall(raw_line):
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value
    return fields


def parse_audit_timestamp(raw_line: str) -> str | None:
    """Extract the audit epoch timestamp from msg=audit(...)."""
    match = AUDIT_TIMESTAMP.search(raw_line)
    if not match:
        return None
    return match.group(1)


def resolve_syscall_name(fields: dict[str, str]) -> str:
    """Resolve a syscall name from audit fields, preferring the syscall number."""
    syscall = fields.get("syscall", "")
    if syscall.isdigit():
        mapped = AUDIT_SYSCALL_NAMES.get(syscall)
        if mapped:
            return mapped

    comm = (fields.get("comm") or "").strip('"').lower()
    if comm:
        return comm

    return syscall.lower()


def extract_audit_username(fields: dict[str, str]) -> str | None:
    """Best-effort username from audit key=value fields."""
    for key in ("acct", "suser", "user"):
        value = fields.get(key)
        if value and value not in _UNSET_VALUES:
            return value.strip('"')

    auid = fields.get("auid")
    if auid == "0":
        return "root"
    if auid and auid not in _UNSET_VALUES and not auid.isdigit():
        return auid

    uid = fields.get("uid")
    if uid == "0":
        return "root"

    return None


def extract_audit_hostname(fields: dict[str, str]) -> str | None:
    """Hostname from audit fields when present."""
    for key in ("hostname", "node"):
        value = fields.get(key)
        if value and value not in _UNSET_VALUES:
            return value.strip('"')
    return None


def extract_audit_process(fields: dict[str, str]) -> str | None:
    """Process or executable name from audit fields."""
    for key in ("exe", "comm", "proctitle"):
        value = fields.get(key)
        if value and value not in _UNSET_VALUES:
            return value.strip('"')
    return None


def extract_audit_message(fields: dict[str, str], audit_type: str) -> str:
    """Build a human-readable message from audit fields."""
    parts = [f"type={audit_type}"]

    for key in ("op", "acct", "cmd", "name", "nametype", "syscall", "comm", "exe"):
        value = fields.get(key)
        if value:
            parts.append(f"{key}={value}")

    return " ".join(parts)


def is_sudo_context(fields: dict[str, str]) -> bool:
    """Return True when audit fields indicate a sudo-related event."""
    for key in ("exe", "comm", "cmd", "proctitle"):
        value = (fields.get(key) or "").lower()
        if "sudo" in value:
            return True
    return False
