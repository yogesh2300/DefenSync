"""Cloud suspicious activity sequence detection v0 (rule-based, read-time).

Findings are heuristic observations over ordered CLOUD events for one actor_id.
They do not confirm account compromise and never trigger remediation.

Rules use only explicit normalized fields (see RULE_SPECS). CLOUD_AUTHENTICATION is
never treated as success or failure. "Unusual IP vs historical baseline" is omitted
until a prior baseline comparison exists.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from backend.core.environments import CLOUD
from backend.core.exceptions import ValidationException
from backend.core.timestamps import ensure_aware
from backend.database.models import SecurityEvent, User
from backend.database.scope import environment_clause, event_visibility_clause, with_environment
from backend.services.cloud.azure_normalizer import DATA_ORIGIN as AZURE_LOG_ANALYTICS_ORIGIN
from backend.services.cloud.identity_baseline_service import (
    ALLOWED_DATA_ORIGINS,
    DEFAULT_DATA_ORIGINS,
    MAX_WINDOW,
    MIN_WINDOW,
    _parse_cloud_identity,
)
from backend.services.datasets.azure_import_service import (
    CLOUD_LOGIN_FAILURE,
    CLOUD_LOGIN_SUCCESS,
    CLOUD_PRIVILEGE_CHANGE,
    CLOUD_RESOURCE_OPERATION,
)

DISCLAIMER = (
    "Heuristic sequence observation only. Matched patterns describe ordered events that "
    "were present in authorized telemetry; they do not confirm account compromise and "
    "do not authorize automatic remediation."
)

# Sequence span within the query window (bounded independently of the lookback).
DEFAULT_SEQUENCE_MINUTES = 60
MAX_SEQUENCE_MINUTES = 24 * 60
MIN_SEQUENCE_MINUTES = 1
MAX_FINDINGS = 100

RULE_SPECS: dict[str, dict[str, Any]] = {
    "auth_failures_then_success": {
        "title": "Repeated authentication failures followed by a successful login",
        "required_fields": ["actor_id", "event_type", "timestamp", "event_id"],
        "severity": "high",
        "rationale": (
            "Two or more CLOUD_LOGIN_FAILURE events for the same actor_id are followed "
            "later by a CLOUD_LOGIN_SUCCESS within the sequence window. "
            "CLOUD_AUTHENTICATION rows are ignored because outcome is unknown."
        ),
    },
    "privilege_then_resource": {
        "title": "Privilege change followed by a resource operation",
        "required_fields": ["actor_id", "event_type", "timestamp", "event_id"],
        "severity": "high",
        "rationale": (
            "A CLOUD_PRIVILEGE_CHANGE is followed later by a CLOUD_RESOURCE_OPERATION "
            "for the same actor_id within the sequence window."
        ),
    },
    "login_success_then_privilege_ip_change": {
        "title": "Successful login then privilege change from a different source IP",
        "required_fields": ["actor_id", "event_type", "timestamp", "event_id", "source_ip"],
        "severity": "medium",
        "rationale": (
            "A CLOUD_LOGIN_SUCCESS with a non-empty source_ip is followed by a "
            "CLOUD_PRIVILEGE_CHANGE with a different non-empty source_ip. "
            "This is an IP change within the window, not a claim of historical rarity."
        ),
    },
}


def _origins(requested: list[str] | None) -> frozenset[str]:
    if not requested:
        return frozenset(DEFAULT_DATA_ORIGINS)
    cleaned = {(value or "").strip() for value in requested if (value or "").strip()}
    if not cleaned:
        raise ValidationException("data_origins cannot be empty.")
    unknown = sorted(cleaned - ALLOWED_DATA_ORIGINS)
    if unknown:
        raise ValidationException(
            "Unsupported data_origins for cloud sequence detection: "
            + ", ".join(unknown)
            + f". Allowed: {', '.join(sorted(ALLOWED_DATA_ORIGINS))}."
        )
    return frozenset(cleaned)


def _event_ref(event: SecurityEvent) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp": ensure_aware(event.timestamp).isoformat() if event.timestamp is not None else None,
        "event_type": event.event_type,
        "source_ip": (event.source_ip or None),
        "operation": (event.operation or None),
        "resource_id": (event.resource_id or None),
    }


def _ordered(events: list[SecurityEvent]) -> list[SecurityEvent]:
    usable = [event for event in events if event.timestamp is not None and (event.actor_id or "").strip()]
    return sorted(usable, key=lambda event: (ensure_aware(event.timestamp), event.event_id or ""))


class CloudSequenceDetectionService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def detect(
        self,
        *,
        user: User,
        start_time: datetime,
        end_time: datetime,
        actor_id: str | None = None,
        data_origins: list[str] | None = None,
        sequence_minutes: int = DEFAULT_SEQUENCE_MINUTES,
    ) -> dict[str, Any]:
        if start_time is None or end_time is None:
            raise ValidationException("start_time and end_time are required.")
        start = ensure_aware(start_time)
        end = ensure_aware(end_time)
        if end <= start:
            raise ValidationException("end_time must be after start_time.")
        duration = end - start
        if duration < MIN_WINDOW:
            raise ValidationException("Time window is too short.")
        if duration > MAX_WINDOW:
            raise ValidationException(
                f"Time window must be at most {int(MAX_WINDOW.total_seconds() // 3600)} hours."
            )
        if sequence_minutes < MIN_SEQUENCE_MINUTES or sequence_minutes > MAX_SEQUENCE_MINUTES:
            raise ValidationException(
                f"sequence_minutes must be between {MIN_SEQUENCE_MINUTES} and {MAX_SEQUENCE_MINUTES}."
            )
        sequence_delta = timedelta(minutes=int(sequence_minutes))
        origins = _origins(data_origins)

        visibility = with_environment(event_visibility_clause(scope="private", user=user), CLOUD)
        clauses = [
            environment_clause(CLOUD),
            SecurityEvent.data_origin.in_(tuple(origins)),
            SecurityEvent.timestamp >= start,
            SecurityEvent.timestamp < end,
        ]
        if visibility is not None:
            clauses.insert(0, visibility)
        wanted = (actor_id or "").strip() or None
        if wanted:
            clauses.append(SecurityEvent.actor_id == wanted)

        rows = list(
            self._session.scalars(
                select(SecurityEvent).where(and_(*clauses)).order_by(SecurityEvent.timestamp.asc())
            ).all()
        )

        by_actor: dict[str, list[SecurityEvent]] = defaultdict(list)
        skipped_missing_identity = 0
        skipped_missing_timestamp = 0
        for event in rows:
            if not (event.actor_id or "").strip():
                skipped_missing_identity += 1
                continue
            if event.timestamp is None:
                skipped_missing_timestamp += 1
                continue
            by_actor[event.actor_id.strip()].append(event)

        findings: list[dict[str, Any]] = []
        for actor, events in sorted(by_actor.items()):
            ordered = _ordered(events)
            for matcher in _RULE_MATCHERS.values():
                findings.extend(matcher(actor, ordered, sequence_delta))

        findings.sort(
            key=lambda item: (
                {"high": 0, "medium": 1, "low": 2}.get(item["severity"], 9),
                item["end_time"] or "",
                item["pattern_id"],
            )
        )
        truncated = len(findings) > MAX_FINDINGS
        capped = findings[:MAX_FINDINGS]
        return {
            "environment": CLOUD,
            "data_origins": sorted(origins),
            "window": {
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "sequence_minutes": int(sequence_minutes),
            },
            "disclaimer": DISCLAIMER,
            "rules": [
                {
                    "pattern_id": pattern_id,
                    "title": spec["title"],
                    "required_fields": list(spec["required_fields"]),
                    "severity": spec["severity"],
                    "rationale": spec["rationale"],
                }
                for pattern_id, spec in RULE_SPECS.items()
            ],
            "findings": capped,
            "summary": {
                "finding_count": len(capped),
                "identity_count": len(by_actor),
                "event_count": sum(len(group) for group in by_actor.values()),
                "events_skipped_missing_identity": skipped_missing_identity,
                "events_skipped_missing_timestamp": skipped_missing_timestamp,
                "truncated": truncated,
            },
        }


def _within(earlier: SecurityEvent, later: SecurityEvent, sequence_delta: timedelta) -> bool:
    return ensure_aware(later.timestamp) - ensure_aware(earlier.timestamp) <= sequence_delta


def _finding(
    *,
    pattern_id: str,
    actor: str,
    events: list[SecurityEvent],
    evidence: list[str],
) -> dict[str, Any]:
    spec = RULE_SPECS[pattern_id]
    first, last = events[0], events[-1]
    identity = None
    for event in events:
        identity = _parse_cloud_identity(event.normalized_data)
        if identity:
            break
    return {
        "pattern_id": pattern_id,
        "title": spec["title"],
        "severity": spec["severity"],
        "severity_rationale": spec["rationale"],
        "actor_id": actor,
        "cloud_identity": identity,
        "start_time": ensure_aware(first.timestamp).isoformat(),
        "end_time": ensure_aware(last.timestamp).isoformat(),
        "event_refs": [_event_ref(event) for event in events],
        "evidence_summary": evidence,
        "interpretation": "heuristic",
        "limitations": [
            "Does not confirm compromised credentials or malicious intent.",
            "CLOUD_AUTHENTICATION events are never used as login success or failure.",
            "No automatic remediation is triggered.",
        ],
    }


def _match_auth_failures_then_success(
    actor: str, events: list[SecurityEvent], sequence_delta: timedelta
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    failures = [event for event in events if event.event_type == CLOUD_LOGIN_FAILURE]
    successes = [event for event in events if event.event_type == CLOUD_LOGIN_SUCCESS]
    for success in successes:
        prior = [event for event in failures if ensure_aware(event.timestamp) < ensure_aware(success.timestamp)]
        prior = [event for event in prior if _within(event, success, sequence_delta)]
        if len(prior) < 2:
            continue
        selected = prior[-2:] + [success]
        findings.append(
            _finding(
                pattern_id="auth_failures_then_success",
                actor=actor,
                events=selected,
                evidence=[
                    f"{len(prior)} CLOUD_LOGIN_FAILURE event(s) observed before CLOUD_LOGIN_SUCCESS "
                    f"within {int(sequence_delta.total_seconds() // 60)} minutes "
                    f"(evidence uses the two failures immediately preceding success).",
                    f"Failure times: {ensure_aware(selected[0].timestamp).isoformat()}, "
                    f"{ensure_aware(selected[1].timestamp).isoformat()}.",
                    f"Success time: {ensure_aware(success.timestamp).isoformat()}.",
                ],
            )
        )
    return findings


def _match_privilege_then_resource(
    actor: str, events: list[SecurityEvent], sequence_delta: timedelta
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    privileges = [event for event in events if event.event_type == CLOUD_PRIVILEGE_CHANGE]
    resources = [event for event in events if event.event_type == CLOUD_RESOURCE_OPERATION]
    for privilege in privileges:
        for resource in resources:
            if ensure_aware(resource.timestamp) <= ensure_aware(privilege.timestamp):
                continue
            if not _within(privilege, resource, sequence_delta):
                continue
            evidence = [
                f"CLOUD_PRIVILEGE_CHANGE at {ensure_aware(privilege.timestamp).isoformat()}"
                + (f" operation={privilege.operation}" if privilege.operation else "")
                + ".",
                f"CLOUD_RESOURCE_OPERATION at {ensure_aware(resource.timestamp).isoformat()}"
                + (f" operation={resource.operation}" if resource.operation else "")
                + (f" resource_id={resource.resource_id}" if resource.resource_id else "")
                + ".",
            ]
            findings.append(
                _finding(
                    pattern_id="privilege_then_resource",
                    actor=actor,
                    events=[privilege, resource],
                    evidence=evidence,
                )
            )
            break  # one resource follow-up per privilege event is enough for v0
    return findings


def _match_login_success_then_privilege_ip_change(
    actor: str, events: list[SecurityEvent], sequence_delta: timedelta
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    logins = [
        event
        for event in events
        if event.event_type == CLOUD_LOGIN_SUCCESS and (event.source_ip or "").strip()
    ]
    privileges = [
        event
        for event in events
        if event.event_type == CLOUD_PRIVILEGE_CHANGE and (event.source_ip or "").strip()
    ]
    for login in logins:
        login_ip = login.source_ip.strip()
        for privilege in privileges:
            if ensure_aware(privilege.timestamp) <= ensure_aware(login.timestamp):
                continue
            if not _within(login, privilege, sequence_delta):
                continue
            privilege_ip = privilege.source_ip.strip()
            if privilege_ip == login_ip:
                continue
            findings.append(
                _finding(
                    pattern_id="login_success_then_privilege_ip_change",
                    actor=actor,
                    events=[login, privilege],
                    evidence=[
                        f"CLOUD_LOGIN_SUCCESS from source_ip={login_ip} at "
                        f"{ensure_aware(login.timestamp).isoformat()}.",
                        f"CLOUD_PRIVILEGE_CHANGE from source_ip={privilege_ip} at "
                        f"{ensure_aware(privilege.timestamp).isoformat()}.",
                        "Both source_ip values were present and differed; no historical baseline was used.",
                    ],
                )
            )
            break
    return findings


_RULE_MATCHERS: dict[str, Callable[[str, list[SecurityEvent], timedelta], list[dict[str, Any]]]] = {
    "auth_failures_then_success": _match_auth_failures_then_success,
    "privilege_then_resource": _match_privilege_then_resource,
    "login_success_then_privilege_ip_change": _match_login_success_then_privilege_ip_change,
}
