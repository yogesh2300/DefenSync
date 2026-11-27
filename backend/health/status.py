"""Health status constants and helpers."""

from __future__ import annotations

from enum import StrEnum


class HealthStatus(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"
    UNREACHABLE = "unreachable"
    AUTHENTICATION_FAILED = "authentication_failed"
    CREDENTIAL_ERROR = "credential_error"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


ONLINE_STATUSES = frozenset({HealthStatus.ONLINE})
OFFLINE_STATUSES = frozenset({
    HealthStatus.OFFLINE,
    HealthStatus.UNREACHABLE,
    HealthStatus.TIMEOUT,
})
ERROR_STATUSES = frozenset({
    HealthStatus.ERROR,
    HealthStatus.AUTHENTICATION_FAILED,
    HealthStatus.CREDENTIAL_ERROR,
})
TRANSIENT_STATUSES = frozenset({HealthStatus.CONNECTING})


def is_online(status: str | None) -> bool:
    return (status or "").lower() == HealthStatus.ONLINE


def is_error_state(status: str | None) -> bool:
    return (status or "").lower() in ERROR_STATUSES


def health_label(status: str | None) -> str:
    labels = {
        HealthStatus.ONLINE: "Online",
        HealthStatus.OFFLINE: "Offline",
        HealthStatus.CONNECTING: "Checking",
        HealthStatus.ERROR: "Connection Lost",
        HealthStatus.UNREACHABLE: "Unreachable",
        HealthStatus.AUTHENTICATION_FAILED: "Authentication Failed",
        HealthStatus.CREDENTIAL_ERROR: "Credential Error",
        HealthStatus.TIMEOUT: "Timeout",
        HealthStatus.UNKNOWN: "Unknown",
    }
    return labels.get((status or "").lower(), "Unknown")
