"""Explainable over-efficiency and automation detector."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from backend.database.models import BehaviorProfile, SecurityEvent

EPSILON = 1e-6


@dataclass(slots=True)
class DetectorResult:
    risk_score: int
    classification: str
    triggered_signals: list[str]
    reasons: list[str]
    baseline_values: dict[str, Any]
    observed_values: dict[str, Any]
    deviations: dict[str, float | bool]


class OverEfficiencyDetector:
    """Weighted rules with concrete human-readable reasons."""

    def evaluate(self, event: SecurityEvent, profile: BehaviorProfile) -> DetectorResult:
        observed = _observed(event)
        baseline = _baseline(profile)
        deviations = calculate_deviations(event, profile)
        risk = 0
        signals: list[str] = []
        reasons: list[str] = []

        def add(signal: str, weight: int, reason: str) -> None:
            nonlocal risk
            risk += weight
            signals.append(signal)
            reasons.append(reason)

        if profile.average_typing_speed and event.typing_speed_cpm and event.typing_speed_cpm > profile.average_typing_speed * 1.8:
            add("typing_speed", 20, f"Typing speed is {event.typing_speed_cpm / profile.average_typing_speed:.1f} times higher than the user's normal baseline.")
        if profile.average_command_rate and event.command_rate_per_minute and event.command_rate_per_minute > profile.average_command_rate * 2.0:
            add("command_rate", 25, f"Command rate is {event.command_rate_per_minute / profile.average_command_rate:.1f} times higher than the user's normal baseline.")
        if profile.average_command_rate and event.command_rate_per_minute and event.command_rate_per_minute > profile.average_command_rate * 3.0:
            add("extreme_command_rate", 10, "Command rate is more than three times higher than the user's normal baseline, consistent with automation.")
        if profile.average_command_error_rate is not None and event.command_error_rate is not None and event.command_error_rate < max(profile.average_command_error_rate * 0.25, EPSILON):
            add("low_error_rate", 5, "Command error rate is far lower than the user's normal baseline.")
        if profile.average_idle_time and event.idle_time_seconds is not None and event.idle_time_seconds < profile.average_idle_time * 0.20:
            add("low_idle_time", 15, "Idle time is less than 20% of the user's normal baseline.")
        if event.repeated_command_ratio is not None and event.repeated_command_ratio > 0.70:
            add("repetition_ratio", 15, "Repeated command ratio is above 0.70, indicating highly repetitive activity.")
        unusual_login = _unusual_login(event.login_hour, profile.usual_login_start, profile.usual_login_end)
        session_deviation = float(deviations.get("session_duration_deviation", 0) or 0)
        if unusual_login:
            add("unusual_login_time", 5, f"Login hour {event.login_hour} is outside the user's usual login window.")
        if session_deviation >= 2.5:
            add("session_duration", 5, "Session duration deviates strongly from the user's normal baseline.")
        if unusual_login and session_deviation >= 2.5:
            add("unusual_session_pattern", 25, "Login time and session duration are both outside the user's usual pattern.")
        moderate_deviations = sum(
            1
            for key in (
                "typing_speed_deviation",
                "command_rate_deviation",
                "error_rate_deviation",
                "idle_time_deviation",
                "repetition_deviation",
            )
            if float(deviations.get(key, 0) or 0) >= 1.5
        )
        if risk < 50 and moderate_deviations >= 3:
            add("combined_moderate_deviations", 50, "Several behavior metrics moderately deviate from the user's normal baseline at the same time.")

        risk = max(0, min(100, risk))
        return DetectorResult(
            risk_score=risk,
            classification=classification_for(risk),
            triggered_signals=signals,
            reasons=reasons or ["Observed behavior is within the user's learned baseline."],
            baseline_values=baseline,
            observed_values=observed,
            deviations=deviations,
        )


def calculate_deviations(event: SecurityEvent, profile: BehaviorProfile) -> dict[str, float | bool]:
    return {
        "typing_speed_deviation": _z(event.typing_speed_cpm, profile.average_typing_speed, profile.std_typing_speed),
        "command_rate_deviation": _z(event.command_rate_per_minute, profile.average_command_rate, profile.std_command_rate),
        "error_rate_deviation": _z(event.command_error_rate, profile.average_command_error_rate, profile.std_command_error_rate),
        "idle_time_deviation": _z(event.idle_time_seconds, profile.average_idle_time, profile.std_idle_time),
        "repetition_deviation": _z(event.repeated_command_ratio, profile.average_repeated_command_ratio, profile.std_repeated_command_ratio),
        "session_duration_deviation": _z(event.session_duration_minutes, profile.average_session_duration, profile.std_session_duration),
        "unusual_login_time": _unusual_login(event.login_hour, profile.usual_login_start, profile.usual_login_end),
    }


def classification_for(score: int) -> str:
    if score >= 85:
        return "AUTOMATED_ACTIVITY"
    if score >= 70:
        return "OVER_EFFICIENCY"
    if score >= 50:
        return "SUSPICIOUS_BEHAVIOR"
    if score >= 30:
        return "UNUSUAL_SESSION"
    return "NORMAL"


def _z(value: float | int | None, mean: float | None, std: float | None) -> float:
    if value is None or mean is None:
        return 0.0
    denominator = max(abs(std or 0), EPSILON)
    return round(abs(float(value) - float(mean)) / denominator, 3)


def _unusual_login(hour: int | None, start: int | None, end: int | None) -> bool:
    if hour is None or start is None or end is None:
        return False
    if start <= end:
        return not (start <= hour <= end)
    return not (hour >= start or hour <= end)


def _observed(event: SecurityEvent) -> dict[str, Any]:
    return {
        "typing_speed_cpm": event.typing_speed_cpm,
        "command_rate_per_minute": event.command_rate_per_minute,
        "command_error_rate": event.command_error_rate,
        "idle_time_seconds": event.idle_time_seconds,
        "repeated_command_ratio": event.repeated_command_ratio,
        "session_duration_minutes": event.session_duration_minutes,
        "login_hour": event.login_hour,
    }


def _baseline(profile: BehaviorProfile) -> dict[str, Any]:
    return {
        "average_typing_speed": profile.average_typing_speed,
        "average_command_rate": profile.average_command_rate,
        "average_command_error_rate": profile.average_command_error_rate,
        "average_idle_time": profile.average_idle_time,
        "average_repeated_command_ratio": profile.average_repeated_command_ratio,
        "average_session_duration": profile.average_session_duration,
        "usual_login_start": profile.usual_login_start,
        "usual_login_end": profile.usual_login_end,
        "baseline_version": profile.baseline_version,
    }
