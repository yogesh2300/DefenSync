"""Catalog of Linux log sources and remote diagnostic commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


SourceType = Literal["file", "command"]


@dataclass(frozen=True)
class LogSourceDefinition:
    """Definition of a collectable log or command output source."""

    key: str
    label: str
    source_type: SourceType
    path: str | None = None
    command: str | None = None
    category: str = "system"


def _cmd(name: str) -> str:
    """Return a sanitized read-only shell command."""
    allowed = {
        "journalctl": "journalctl -n {tail} --output=short-iso --no-pager 2>/dev/null || true",
        "last": "last -F 2>/dev/null || last 2>/dev/null || true",
        "lastb": "lastb -F 2>/dev/null || lastb 2>/dev/null || true",
        "who": "who 2>/dev/null || true",
        "w": "w 2>/dev/null || true",
        "uptime": "uptime 2>/dev/null || true",
        "free": "free -m 2>/dev/null || true",
        "df": "df -h 2>/dev/null || true",
        "ps": "ps aux 2>/dev/null || true",
        "ss": "ss -tuln 2>/dev/null || true",
        "hostnamectl": "hostnamectl 2>/dev/null || true",
        "uname": "uname -a 2>/dev/null || true",
        "top": "COLUMNS=512 top -b -n 1 2>/dev/null | head -n {tail} || true",
    }
    return allowed[name]


LOG_SOURCE_CATALOG: dict[str, LogSourceDefinition] = {
    "secure": LogSourceDefinition("secure", "Secure Log", "file", path="/var/log/secure", category="auth"),
    "audit": LogSourceDefinition("audit", "Audit Log", "file", path="/var/log/audit/audit.log", category="audit"),
    "auth": LogSourceDefinition("auth", "Auth Log", "file", path="/var/log/auth.log", category="auth"),
    "syslog": LogSourceDefinition("syslog", "Syslog", "file", path="/var/log/syslog", category="system"),
    "journalctl": LogSourceDefinition("journalctl", "Journalctl", "command", command=_cmd("journalctl"), category="system"),
    "last": LogSourceDefinition("last", "Last Logins", "command", command=_cmd("last"), category="auth"),
    "lastb": LogSourceDefinition("lastb", "Failed Logins (lastb)", "command", command=_cmd("lastb"), category="auth"),
    "who": LogSourceDefinition("who", "Active Sessions", "command", command=_cmd("who"), category="auth"),
    "w": LogSourceDefinition("w", "Logged-in Users Detail", "command", command=_cmd("w"), category="auth"),
    "uptime": LogSourceDefinition("uptime", "Uptime", "command", command=_cmd("uptime"), category="metrics"),
    "free": LogSourceDefinition("free", "Memory Usage", "command", command=_cmd("free"), category="metrics"),
    "df": LogSourceDefinition("df", "Disk Usage", "command", command=_cmd("df"), category="metrics"),
    "ps": LogSourceDefinition("ps", "Processes", "command", command=_cmd("ps"), category="metrics"),
    "ss": LogSourceDefinition("ss", "Network Connections", "command", command=_cmd("ss"), category="network"),
    "hostnamectl": LogSourceDefinition("hostnamectl", "Host Info", "command", command=_cmd("hostnamectl"), category="system"),
    "uname": LogSourceDefinition("uname", "Kernel Info", "command", command=_cmd("uname"), category="system"),
    "top": LogSourceDefinition("top", "CPU Snapshot", "command", command=_cmd("top"), category="metrics"),
}

DEFAULT_LOG_SOURCES = frozenset({
    "secure", "auth", "audit", "journalctl",
    "last", "lastb", "who", "w", "uptime",
    "free", "df", "ps", "ss", "hostnamectl", "uname",
})

# Read-only, no root: how the host sees this SSH session and the host's clock zone.
HOST_CONTEXT_COMMAND = (
    "printf 'ssh_connection=%s\\n' \"$SSH_CONNECTION\"; "
    "printf 'utc_offset=%s\\n' \"$(date +%z)\"; "
    "printf 'timezone=%s\\n' \"$(timedatectl show -p Timezone --value 2>/dev/null"
    " || readlink /etc/localtime 2>/dev/null || cat /etc/timezone 2>/dev/null)\""
)

# Legacy aliases used by existing collection API
LEGACY_SOURCE_ALIASES = {
    "secure": "secure",
    "audit": "audit",
}
