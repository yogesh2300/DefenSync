"""Shared behavioral telemetry constants and validators."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

DATASET_NAME = "DEFENSYNC_BEHAVIORAL_TELEMETRY"
SOURCE_TYPE = "BEHAVIORAL"
PROVIDER = "LOCAL"
SYNTHETIC_ORIGIN = "SYNTHETIC"
EVENT_TYPE = "USER_BEHAVIOR_TELEMETRY"

REQUIRED_COLUMNS = {
    "timestamp",
    "user_id",
    "linux_username",
    "session_id",
    "server_id",
    "typing_speed_cpm",
    "command_rate_per_minute",
    "command_error_rate",
    "idle_time_seconds",
    "repeated_command_ratio",
    "session_duration_minutes",
    "login_hour",
    "is_anomaly",
    "behavior_class",
    "data_origin",
}

ALLOWED_CLASSES = {
    "NORMAL",
    "OVER_EFFICIENCY",
    "AUTOMATED_ACTIVITY",
    "UNUSUAL_SESSION",
    "SUSPICIOUS_BEHAVIOR",
}
ALLOWED_ORIGINS = {"SYNTHETIC", "IMPORTED"}


def identity_key(user_id: str | None, linux_username: str | None) -> str:
    if user_id:
        return user_id.strip()
    return (linux_username or "unknown").strip()


def parse_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def validate_row(row: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    missing = sorted(REQUIRED_COLUMNS - set(row.keys()))
    if missing:
        return None, f"Missing required columns: {', '.join(missing)}"
    try:
        parsed = {
            "timestamp": parse_timestamp(row["timestamp"]),
            "user_id": str(row["user_id"]).strip(),
            "linux_username": str(row["linux_username"]).strip(),
            "session_id": str(row["session_id"]).strip(),
            "server_id": str(row["server_id"]).strip() or None,
            "typing_speed_cpm": float(row["typing_speed_cpm"]),
            "command_rate_per_minute": float(row["command_rate_per_minute"]),
            "command_error_rate": float(row["command_error_rate"]),
            "idle_time_seconds": float(row["idle_time_seconds"]),
            "repeated_command_ratio": float(row["repeated_command_ratio"]),
            "session_duration_minutes": float(row["session_duration_minutes"]),
            "login_hour": int(float(row["login_hour"])),
            "is_anomaly": parse_bool(row["is_anomaly"]),
            "behavior_class": str(row["behavior_class"]).strip().upper(),
            "data_origin": str(row["data_origin"]).strip().upper(),
        }
    except Exception as exc:
        return None, f"Invalid field value: {exc}"

    if not 0 <= parsed["command_error_rate"] <= 1:
        return None, "command_error_rate must be between 0 and 1"
    if not 0 <= parsed["repeated_command_ratio"] <= 1:
        return None, "repeated_command_ratio must be between 0 and 1"
    if not 0 <= parsed["typing_speed_cpm"] <= 900:
        return None, "typing_speed_cpm outside reasonable range"
    if parsed["command_rate_per_minute"] < 0:
        return None, "command_rate_per_minute must be non-negative"
    if parsed["idle_time_seconds"] < 0:
        return None, "idle_time_seconds must be non-negative"
    if parsed["session_duration_minutes"] <= 0:
        return None, "session_duration_minutes must be positive"
    if not 0 <= parsed["login_hour"] <= 23:
        return None, "login_hour must be between 0 and 23"
    if parsed["behavior_class"] not in ALLOWED_CLASSES:
        return None, "behavior_class is not supported"
    if parsed["data_origin"] not in ALLOWED_ORIGINS:
        return None, "data_origin must be SYNTHETIC or IMPORTED"
    return parsed, None
