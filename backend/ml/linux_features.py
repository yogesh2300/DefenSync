"""Linux behavioral features for the Linux Isolation Forest.

Only genuine, source-observed Linux security events are eligible. History features look
strictly backwards in event time on the same host, so a row never depends on a later
event or on another event recorded in the same instant.

Deliberately never read: rule and model output (risk_score, risk_level, severity, alerts,
anomaly scores, behavioral scores), collection metadata (collection_timestamp, created_at),
snapshot metrics copied onto every row of a collection batch (cpu/memory/disk usage,
network_connections, commands_executed, failed_login_count), fields known only after a
session ends (session_duration, logout_time), source-identity fields (provider,
dataset_name) and identifiers (event_id, hash). raw_log and message are read only to
recognise the sshd authentication method. Literal usernames, IP addresses and server ids
are used only to group and compare events, never as values.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np

from backend.core.timestamps import SOURCE_EVENT, UTC_OFFSET
from backend.normalizer.event_types import (
    NON_SECURITY_EVENT_TYPES,
    RECORD_ORIGIN_COLLECTOR,
    RECORD_SECURITY_EVENT,
    EventType,
)

FEATURE_VERSION = "linux-v1"

PER_EVENT_FEATURES: tuple[str, ...] = (
    "hour_sin",
    "hour_cos",
    "is_weekend",
    "is_failure",
    "is_privilege_escalation",
    "is_root_target",
    "auth_password",
    "auth_publickey",
    "is_remote",
)
HISTORY_FEATURES: tuple[str, ...] = (
    "ip_new_for_user",
    "user_new_on_host",
    "failures_from_ip_10m",
    "failures_for_user_10m",
    "distinct_users_from_ip_1h",
    "success_after_failures_10m",
    "log_secs_since_user_prev_event",
    "priv_esc_in_session",
)
FEATURE_NAMES: tuple[str, ...] = PER_EVENT_FEATURES + HISTORY_FEATURES

LINUX_SOURCE_TYPE = "LINUX"
LIVE_LINUX_ORIGIN = "LIVE_LINUX"

INELIGIBLE_SOURCE_TYPE = "wrong_source_type"
INELIGIBLE_DATA_ORIGIN = "wrong_data_origin"
INELIGIBLE_RECORD_KIND = "not_security_event"
INELIGIBLE_EVENT_TIME = "no_source_event_time"
INELIGIBLE_COLLECTOR = "collector_generated"

# Window ends are inclusive: an event exactly 10 minutes earlier is inside the 10-minute window.
FAILURE_WINDOW = timedelta(minutes=10)
IP_USERS_WINDOW = timedelta(hours=1)
# Journal session ids are attached only to login/session lines, not to su/sudo, so a
# privilege escalation's session is the user's latest earlier login, at most 12 hours back.
SESSION_CONTEXT_WINDOW = timedelta(hours=12)
PREV_EVENT_CAP_SECONDS = 30 * 24 * 3600

LOGIN_FAILURE_TYPES = frozenset({EventType.FAILED_LOGIN.value, EventType.INVALID_USER.value})
FAILURE_TYPES = LOGIN_FAILURE_TYPES | {EventType.FAILED_PRIVILEGE_ESCALATION.value}
PRIVILEGE_TYPES = frozenset({
    EventType.PRIVILEGE_ESCALATION.value,
    EventType.FAILED_PRIVILEGE_ESCALATION.value,
    EventType.SUDO_COMMAND.value,
})
SESSION_START_TYPES = frozenset({EventType.SUCCESSFUL_LOGIN.value, EventType.SESSION_OPENED.value})
SUCCESS_LOGIN_TYPES = frozenset({EventType.SUCCESSFUL_LOGIN.value})

AUTH_PASSWORD = "password"
AUTH_PUBLICKEY = "publickey"
_AUTH_METHOD = re.compile(
    r"\b(?:Accepted|Failed)\s+(?P<method>password|keyboard-interactive/pam|publickey)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class LinuxEventRecord:
    """The only event attributes the Linux feature layer reads.

    host_key, username and source_ip group and compare events; they are never feature values.
    auth_method is derived from the source line; the line itself is not kept.
    """

    event_id: str
    host_key: str
    source_type: str | None
    data_origin: str | None
    record_kind: str | None
    record_origin: str | None
    timestamp_source: str | None
    event_type: str
    event_time: datetime | None
    host_utc_offset: timedelta | None
    username: str | None
    source_ip: str | None
    target_user: str | None
    auth_method: str | None

    @classmethod
    def from_event(cls, event: Any) -> LinuxEventRecord:
        """Build from an Event ORM row or a mapping with the same column names."""
        if isinstance(event, LinuxEventRecord):
            return event
        nd = _normalized_data(_get(event, "normalized_data"))
        # message is the pipeline's summary ("Successful Login for ..."); the sshd wording is in raw_log.
        source_line = f"{_get(event, 'raw_log') or ''}\n{_get(event, 'message') or ''}"
        return cls(
            event_id=str(_get(event, "event_id") or ""),
            host_key=str(_get(event, "server_id") or _get(event, "hostname") or ""),
            source_type=_get(event, "source_type"),
            data_origin=_get(event, "data_origin"),
            record_kind=nd.get("record_kind"),
            record_origin=nd.get("record_origin"),
            timestamp_source=_get(event, "timestamp_source"),
            event_type=str(_get(event, "event_type") or ""),
            event_time=_event_time(nd.get("event_time_utc"), _get(event, "timestamp")),
            host_utc_offset=_utc_offset(nd.get("host_utc_offset")),
            username=_clean(_get(event, "username")),
            source_ip=_clean(_get(event, "source_ip")),
            target_user=_clean(nd.get("target_user")),
            auth_method=_auth_method(source_line),
        )


@dataclass(frozen=True)
class LinuxFeatureMatrix:
    """Chronological feature rows of eligible events; rows align with event_ids."""

    feature_names: tuple[str, ...]
    values: np.ndarray
    event_ids: tuple[str, ...]
    excluded: Mapping[str, int]


def ineligibility_reason(event: Any) -> str | None:
    """None when the event is eligible for Linux ML, otherwise the first failed requirement."""
    record = LinuxEventRecord.from_event(event)
    if (record.source_type or "").upper() != LINUX_SOURCE_TYPE:
        return INELIGIBLE_SOURCE_TYPE
    if (record.data_origin or "").upper() != LIVE_LINUX_ORIGIN:
        return INELIGIBLE_DATA_ORIGIN
    if record.record_kind != RECORD_SECURITY_EVENT or record.event_type in NON_SECURITY_EVENT_TYPES:
        return INELIGIBLE_RECORD_KIND
    if record.timestamp_source != SOURCE_EVENT or record.event_time is None:
        return INELIGIBLE_EVENT_TIME
    if record.record_origin == RECORD_ORIGIN_COLLECTOR:
        return INELIGIBLE_COLLECTOR
    return None


def is_linux_ml_eligible(event: Any) -> bool:
    return ineligibility_reason(event) is None


def per_event_features(event: Any) -> dict[str, float]:
    """Features of the event alone; local hour/weekday use the host offset, else UTC."""
    record = LinuxEventRecord.from_event(event)
    if record.event_time is None:
        raise ValueError("Event has no source event time.")
    local = record.event_time + (record.host_utc_offset or timedelta(0))
    hour = local.hour + local.minute / 60 + local.second / 3600
    angle = 2 * math.pi * hour / 24
    privileged = record.event_type in PRIVILEGE_TYPES
    root_subject = record.target_user if privileged else record.username
    return _rounded({
        "hour_sin": math.sin(angle),
        "hour_cos": math.cos(angle),
        "is_weekend": float(local.weekday() >= 5),
        "is_failure": float(record.event_type in FAILURE_TYPES),
        "is_privilege_escalation": float(privileged),
        "is_root_target": float(root_subject == "root"),
        "auth_password": float(record.auth_method == AUTH_PASSWORD),
        "auth_publickey": float(record.auth_method == AUTH_PUBLICKEY),
        "is_remote": float(_is_remote(record.source_ip)),
    })


class HostHistory:
    """Eligible events of one host strictly before the event being scored."""

    def __init__(self) -> None:
        self._records: list[LinuxEventRecord] = []
        self._users: set[str] = set()
        self._user_ips: set[tuple[str, str]] = set()
        self._last_seen: dict[str, datetime] = {}

    def add(self, record: LinuxEventRecord) -> None:
        if record.event_time is None:
            raise ValueError("History events need a source event time.")
        if self._records and record.event_time < self._records[-1].event_time:
            raise ValueError("History events must be added in event-time order.")
        self._records.append(record)
        if record.username:
            self._users.add(record.username)
            self._last_seen[record.username] = record.event_time
            if record.source_ip:
                self._user_ips.add((record.username, record.source_ip))

    def features_for(self, record: LinuxEventRecord) -> dict[str, float]:
        t = record.event_time
        if t is None:
            raise ValueError("Event has no source event time.")
        if self._records and self._records[-1].event_time >= t:
            raise ValueError("History contains events at or after the scored event.")
        user, ip = record.username, record.source_ip
        failures_ip = failures_user = 0
        failure_match = False
        users_from_ip: set[str] = set()
        priv_in_session = 0
        session_open = record.event_type not in SESSION_START_TYPES
        for prior in reversed(self._records):
            age = t - prior.event_time
            if age > SESSION_CONTEXT_WINDOW:
                break
            same_ip = bool(ip) and prior.source_ip == ip
            same_user = bool(user) and prior.username == user
            if age <= FAILURE_WINDOW and prior.event_type in LOGIN_FAILURE_TYPES:
                failures_ip += same_ip
                failures_user += same_user
                failure_match = failure_match or same_ip or same_user
            if age <= IP_USERS_WINDOW and same_ip and prior.username:
                users_from_ip.add(prior.username)
            if same_user and session_open:
                if prior.event_type in PRIVILEGE_TYPES:
                    priv_in_session += 1
                if prior.event_type in SESSION_START_TYPES:
                    session_open = False
        last = self._last_seen.get(user) if user else None
        gap = PREV_EVENT_CAP_SECONDS if last is None else min((t - last).total_seconds(), PREV_EVENT_CAP_SECONDS)
        return _rounded({
            "ip_new_for_user": float(bool(user and ip) and (user, ip) not in self._user_ips),
            "user_new_on_host": float(bool(user) and user not in self._users),
            "failures_from_ip_10m": float(failures_ip),
            "failures_for_user_10m": float(failures_user),
            "distinct_users_from_ip_1h": float(len(users_from_ip)),
            "success_after_failures_10m": float(record.event_type in SUCCESS_LOGIN_TYPES and failure_match),
            "log_secs_since_user_prev_event": math.log1p(gap),
            "priv_esc_in_session": float(priv_in_session),
        })


def history_features(event: Any, prior_events: Iterable[Any]) -> dict[str, float]:
    """History features from prior_events that are eligible, on the same host and strictly earlier.

    Anything else passed in, including later events, is ignored.
    """
    record = LinuxEventRecord.from_event(event)
    if record.event_time is None:
        raise ValueError("Event has no source event time.")
    history = HostHistory()
    for prior in sorted(
        (
            candidate
            for candidate in (LinuxEventRecord.from_event(item) for item in prior_events)
            if candidate.host_key == record.host_key
            and ineligibility_reason(candidate) is None
            and candidate.event_time < record.event_time
        ),
        key=_chronological_key,
    ):
        history.add(prior)
    return history.features_for(record)


def extract_event_features(event: Any, prior_events: Iterable[Any] = ()) -> dict[str, float]:
    """All features of one eligible event, keyed and ordered by FEATURE_NAMES."""
    record = LinuxEventRecord.from_event(event)
    reason = ineligibility_reason(record)
    if reason is not None:
        raise ValueError(f"Event is not eligible for Linux ML: {reason}")
    features = {**per_event_features(record), **history_features(record, prior_events)}
    return {name: features[name] for name in FEATURE_NAMES}


def feature_vector(features: Mapping[str, float]) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]


def split_eligible(events: Iterable[Any]) -> tuple[list[LinuxEventRecord], dict[str, int]]:
    eligible: list[LinuxEventRecord] = []
    excluded: dict[str, int] = {}
    for event in events:
        record = LinuxEventRecord.from_event(event)
        reason = ineligibility_reason(record)
        if reason is None:
            eligible.append(record)
        else:
            excluded[reason] = excluded.get(reason, 0) + 1
    return eligible, dict(sorted(excluded.items()))


def build_feature_matrix(events: Iterable[Any]) -> LinuxFeatureMatrix:
    """Feature rows of the eligible events in chronological order.

    Events sharing a timestamp are scored before any of them enters the history,
    so simultaneous events never see each other.
    """
    eligible, excluded = split_eligible(events)
    ordered = sorted(eligible, key=_chronological_key)
    histories: dict[str, HostHistory] = {}
    rows: list[list[float]] = []
    index = 0
    while index < len(ordered):
        end = index
        while end < len(ordered) and ordered[end].event_time == ordered[index].event_time:
            end += 1
        group = ordered[index:end]
        for record in group:
            history = histories.setdefault(record.host_key, HostHistory())
            features = {**per_event_features(record), **history.features_for(record)}
            rows.append(feature_vector(features))
        for record in group:
            histories[record.host_key].add(record)
        index = end
    values = np.array(rows, dtype=float) if rows else np.zeros((0, len(FEATURE_NAMES)), dtype=float)
    return LinuxFeatureMatrix(
        feature_names=FEATURE_NAMES,
        values=values,
        event_ids=tuple(record.event_id for record in ordered),
        excluded=excluded,
    )


def _chronological_key(record: LinuxEventRecord) -> tuple[datetime, str, str]:
    return (record.event_time, record.host_key, record.event_id)


def _get(event: Any, name: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(name)
    return getattr(event, name, None)


def _normalized_data(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _event_time(canonical: Any, column: Any) -> datetime | None:
    """UTC occurrence time: the canonical event_time_utc copy first, else the timestamp column.

    A naive value is read as UTC.
    """
    for value in (canonical, column):
        if value in (None, ""):
            continue
        if isinstance(value, datetime):
            parsed = value
        else:
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError:
                continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _utc_offset(value: Any) -> timedelta | None:
    match = UTC_OFFSET.fullmatch(str(value or "").strip())
    if not match:
        return None
    sign, hours, minutes = match.groups()
    offset = timedelta(hours=int(hours), minutes=int(minutes))
    return -offset if sign == "-" else offset


def _clean(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _auth_method(message: str) -> str | None:
    match = _AUTH_METHOD.search(message)
    if not match:
        return None
    return AUTH_PUBLICKEY if match.group("method").lower() == AUTH_PUBLICKEY else AUTH_PASSWORD


def _is_remote(source_ip: str | None) -> bool:
    """Only a literal, non-loopback IP address counts; hostnames and display names do not."""
    if not source_ip:
        return False
    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified)


def _rounded(features: dict[str, float]) -> dict[str, float]:
    return {name: round(float(value), 6) + 0.0 for name, value in features.items()}
