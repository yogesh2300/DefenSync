"""Severity levels and risk scoring for normalized security events."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from typing import Mapping

from backend.normalizer.event_types import EventType


class SeverityLevel(StrEnum):
    """Ordered severity labels for security events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class _SeverityRank(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_RANK: Mapping[SeverityLevel, _SeverityRank] = {
    SeverityLevel.LOW: _SeverityRank.LOW,
    SeverityLevel.MEDIUM: _SeverityRank.MEDIUM,
    SeverityLevel.HIGH: _SeverityRank.HIGH,
    SeverityLevel.CRITICAL: _SeverityRank.CRITICAL,
}

DEFAULT_SEVERITY: Mapping[EventType, SeverityLevel] = {
    EventType.FAILED_LOGIN: SeverityLevel.HIGH,
    EventType.SUCCESSFUL_LOGIN: SeverityLevel.LOW,
    EventType.INVALID_USER: SeverityLevel.HIGH,
    EventType.USER_CREATION: SeverityLevel.HIGH,
    EventType.USER_DELETION: SeverityLevel.CRITICAL,
    EventType.SUDO_COMMAND: SeverityLevel.MEDIUM,
    EventType.FILE_MODIFICATION: SeverityLevel.MEDIUM,
    EventType.DIRECTORY_CREATION: SeverityLevel.LOW,
    EventType.PERMISSION_CHANGE: SeverityLevel.HIGH,
    EventType.COMMAND_EXECUTION: SeverityLevel.LOW,
    EventType.PRIVILEGE_ESCALATION: SeverityLevel.MEDIUM,
    EventType.FAILED_PRIVILEGE_ESCALATION: SeverityLevel.HIGH,
    EventType.SESSION_OPENED: SeverityLevel.LOW,
    EventType.SESSION_CLOSED: SeverityLevel.LOW,
    EventType.SYSTEM_SNAPSHOT: SeverityLevel.LOW,
    EventType.SYSTEM_EVENT: SeverityLevel.LOW,
}

BASE_RISK_SCORE: Mapping[EventType, int] = {
    EventType.FAILED_LOGIN: 65,
    EventType.SUCCESSFUL_LOGIN: 20,
    EventType.INVALID_USER: 70,
    EventType.USER_CREATION: 70,
    EventType.USER_DELETION: 85,
    EventType.SUDO_COMMAND: 55,
    EventType.FILE_MODIFICATION: 45,
    EventType.DIRECTORY_CREATION: 30,
    EventType.PERMISSION_CHANGE: 60,
    EventType.COMMAND_EXECUTION: 40,
    EventType.PRIVILEGE_ESCALATION: 50,
    EventType.FAILED_PRIVILEGE_ESCALATION: 60,
    EventType.SESSION_OPENED: 10,
    EventType.SESSION_CLOSED: 5,
    EventType.SYSTEM_SNAPSHOT: 0,
    EventType.SYSTEM_EVENT: 10,
}


class RiskScoreCalculator:
    """Compute risk scores (0-100) from event type and optional context."""

    MIN_SCORE = 0
    MAX_SCORE = 100

    def __init__(
        self,
        base_scores: Mapping[EventType, int] | None = None,
        severity_by_type: Mapping[EventType, SeverityLevel] | None = None,
    ) -> None:
        self._base_scores = dict(base_scores or BASE_RISK_SCORE)
        self._severity_by_type = dict(severity_by_type or DEFAULT_SEVERITY)

    def severity_for(self, event_type: EventType) -> SeverityLevel:
        """Return the default severity for an event type."""
        return self._severity_by_type.get(event_type, SeverityLevel.MEDIUM)

    def calculate(
        self,
        event_type: EventType,
        *,
        is_root: bool = False,
        is_privileged_user: bool = False,
        is_remote: bool = False,
    ) -> int:
        """
        Calculate a bounded risk score for the given event.

        Context flags allow downstream enrichment without changing base mappings.
        """
        score = self._base_scores.get(event_type, 50)

        if is_root:
            score += 10
        if is_privileged_user:
            score += 5
        if is_remote and event_type in {
            EventType.FAILED_LOGIN,
            EventType.SUCCESSFUL_LOGIN,
            EventType.INVALID_USER,
            EventType.SUDO_COMMAND,
            EventType.COMMAND_EXECUTION,
        }:
            score += 5

        return max(self.MIN_SCORE, min(self.MAX_SCORE, score))
