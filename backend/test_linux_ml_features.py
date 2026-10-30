"""Linux ML eligibility and behavioral feature extraction (no model training)."""

from __future__ import annotations

import dataclasses
import json
import math
import random
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import numpy as np
import pytest

from backend.ml.linux_features import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    INELIGIBLE_COLLECTOR,
    INELIGIBLE_DATA_ORIGIN,
    INELIGIBLE_EVENT_TIME,
    INELIGIBLE_RECORD_KIND,
    INELIGIBLE_SOURCE_TYPE,
    PREV_EVENT_CAP_SECONDS,
    HostHistory,
    LinuxEventRecord,
    build_feature_matrix,
    extract_event_features,
    history_features,
    ineligibility_reason,
    is_linux_ml_eligible,
    per_event_features,
)

BASE = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)  # Monday; 15:30 at the host's +0530
CAP = math.log1p(PREV_EVENT_CAP_SECONDS)


def linux_event(
    event_id: str,
    minutes: float | None,
    event_type: str,
    *,
    username: str | None = None,
    source_ip: str | None = None,
    message: str = "",
    target_user: str | None = None,
    record_kind: str = "SECURITY_EVENT",
    record_origin: str = "SOURCE_OBSERVED",
    timestamp_source: str = "SOURCE_EVENT",
    source_type: str = "LINUX",
    data_origin: str = "LIVE_LINUX",
    server_id: str = "srv-1",
    offset: str | None = "+0530",
    session_id: str | None = None,
    base: datetime = BASE,
) -> SimpleNamespace:
    """An Event-shaped row as stored by the Linux pipeline, including fields ML must ignore.

    `message` is the source line and goes to raw_log; the stored message column is the
    pipeline's summary, as in real rows.
    """
    ts = None if minutes is None else base + timedelta(minutes=minutes)
    nd: dict = {"record_kind": record_kind, "record_origin": record_origin}
    if ts is not None:
        nd["event_time_utc"] = ts.isoformat()
    if offset is not None:
        nd["host_utc_offset"] = offset
    if target_user is not None:
        nd["target_user"] = target_user
    return SimpleNamespace(
        event_id=event_id,
        server_id=server_id,
        hostname="yogeshos",
        timestamp=ts.replace(tzinfo=None) if ts else None,
        timestamp_source=timestamp_source,
        source_type=source_type,
        data_origin=data_origin,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        message=" ".join(part for part in (event_type, "for", username, "from", source_ip) if part)
        if username else event_type,
        raw_log=message,
        session_id=session_id,
        normalized_data=json.dumps(nd),
        hash=f"hash-{event_id}",
        risk_score=10,
        risk_level="low",
        severity="low",
        collection_timestamp=datetime(2026, 10, 6, 15, 6, 19),
        created_at=datetime(2026, 10, 6, 15, 6, 20),
        cpu_usage=None,
        memory_usage=55.0,
        disk_usage=40.0,
        network_connections=12,
        commands_executed=300,
        failed_login_count=1,
        session_duration=None,
        logout_time=None,
        provider=None,
        dataset_name=None,
        original_label=None,
        behavioral_risk_score=None,
        behavioral_classification=None,
    )


def fixture_events() -> list[SimpleNamespace]:
    """Eight eligible human events on one host, in chronological order."""
    return [
        linux_event("e01", 0, "Successful Login", username="alice", source_ip="10.0.0.5",
                    message="Accepted publickey for alice from 10.0.0.5 port 50000 ssh2"),
        linux_event("e02", 2, "Failed Login", username="bob", source_ip="203.0.113.9",
                    message="Failed password for bob from 203.0.113.9 port 40000 ssh2"),
        linux_event("e03", 3, "Failed Login", username="root", source_ip="203.0.113.9",
                    message="Failed password for root from 203.0.113.9 port 40001 ssh2"),
        linux_event("e04", 5, "Failed Login", username="bob", source_ip="203.0.113.9",
                    message="Failed password for bob from 203.0.113.9 port 40002 ssh2"),
        linux_event("e05", 6, "Successful Login", username="bob", source_ip="203.0.113.9",
                    message="Accepted password for bob from 203.0.113.9 port 40003 ssh2",
                    session_id="boot-1:sshd-session:4242"),
        linux_event("e06", 20, "Privilege Escalation", username="bob", target_user="root",
                    message="(to root) bob on pts/0"),
        linux_event("e07", 25, "Failed Privilege Escalation", username="bob", target_user="root",
                    message="pam_unix(sudo:auth): authentication failure; logname=bob uid=1000"),
        linux_event("e08", 90, "Successful Login", username="alice", source_ip="198.51.100.7",
                    message="Accepted publickey for alice from 198.51.100.7 port 50111 ssh2"),
    ]


def noise_events() -> list[SimpleNamespace]:
    """Ineligible rows interleaved with the fixture; none may affect any feature."""
    return [
        linux_event("n01", 4, "System Snapshot", username="root", record_kind="SYSTEM_SNAPSHOT",
                    timestamp_source="SNAPSHOT_COLLECTION_TIME",
                    message="root  88  0.0  0.0  0  0 ?  S  02:12  0:00 [irq/41-pciehp]"),
        linux_event("n02", 4, "System Event", record_kind="SYSTEM_EVENT", message="kernel: usb 1-1: new device"),
        linux_event("n03", 1, "Successful Login", username="ysalve", source_ip="192.168.195.1",
                    record_origin="COLLECTOR_GENERATED",
                    message="Accepted password for ysalve from 192.168.195.1 port 51000 ssh2"),
        linux_event("n04", 4.5, "Failed Login", username="bob", source_ip="203.0.113.9",
                    record_origin="COLLECTOR_GENERATED",
                    message="Failed password for bob from 203.0.113.9 port 40009 ssh2"),
        linux_event("n05", 5.5, "Failed Login", username="bob", source_ip="203.0.113.9",
                    timestamp_source="COLLECTION_TIME_FALLBACK",
                    message="Failed password for bob from 203.0.113.9 port 40010 ssh2"),
        linux_event("n06", 5.75, "Failed Login", username="bob", source_ip="203.0.113.9",
                    data_origin="PUBLIC_DATASET",
                    message="Failed password for bob from 203.0.113.9 port 40011 ssh2"),
        linux_event("n07", 5.8, "CLOUD_LOGIN_FAILURE", username="bob", source_ip="203.0.113.9",
                    source_type="CLOUD", data_origin="AZURE_LOG_ANALYTICS"),
    ]


def hour_angle(minutes_after_base: float) -> tuple[float, float]:
    hour = 15.5 + minutes_after_base / 60  # BASE is 15:30 local at +0530
    angle = 2 * math.pi * hour / 24
    return round(math.sin(angle), 6), round(math.cos(angle), 6)


# Per event: weekend, failure, privilege, root target, password, publickey, remote.
EXPECTED_PER_EVENT = {
    "e01": (0, 0, 0, 0, 0, 1, 1),
    "e02": (0, 1, 0, 0, 1, 0, 1),
    "e03": (0, 1, 0, 1, 1, 0, 1),
    "e04": (0, 1, 0, 0, 1, 0, 1),
    "e05": (0, 0, 0, 0, 1, 0, 1),
    "e06": (0, 0, 1, 1, 0, 0, 0),
    "e07": (0, 1, 1, 1, 0, 0, 0),
    "e08": (0, 0, 0, 0, 0, 1, 1),
}
# History: ip_new, user_new, failures_ip, failures_user, users_from_ip, success_after, log_gap, priv_in_session.
EXPECTED_HISTORY = {
    "e01": (1, 1, 0, 0, 0, 0, CAP, 0),
    "e02": (1, 1, 0, 0, 0, 0, CAP, 0),
    "e03": (1, 1, 1, 0, 1, 0, CAP, 0),
    "e04": (0, 0, 2, 1, 2, 0, math.log1p(180), 0),
    "e05": (0, 0, 3, 2, 2, 1, math.log1p(60), 0),
    "e06": (0, 0, 0, 0, 0, 0, math.log1p(840), 0),
    "e07": (0, 0, 0, 0, 0, 0, math.log1p(300), 1),
    "e08": (1, 0, 0, 0, 0, 0, math.log1p(5400), 0),
}
MINUTES = {"e01": 0, "e02": 2, "e03": 3, "e04": 5, "e05": 6, "e06": 20, "e07": 25, "e08": 90}


def expected_row(event_id: str) -> list[float]:
    sin, cos = hour_angle(MINUTES[event_id])
    return [sin, cos, *map(float, EXPECTED_PER_EVENT[event_id]), *map(float, EXPECTED_HISTORY[event_id])]


def row_of(matrix, event_id: str) -> dict[str, float]:
    return dict(zip(matrix.feature_names, matrix.values[matrix.event_ids.index(event_id)], strict=True))


# 1. Snapshot exclusion
def test_system_snapshot_is_excluded():
    snapshot = noise_events()[0]
    assert ineligibility_reason(snapshot) == INELIGIBLE_RECORD_KIND
    mislabeled = linux_event("s2", 1, "System Snapshot", record_kind="SECURITY_EVENT")
    assert ineligibility_reason(mislabeled) == INELIGIBLE_RECORD_KIND
    assert build_feature_matrix([snapshot]).values.shape == (0, len(FEATURE_NAMES))


# 2. System-event exclusion
def test_system_event_is_excluded():
    assert ineligibility_reason(noise_events()[1]) == INELIGIBLE_RECORD_KIND
    missing_kind = linux_event("k1", 1, "Failed Login", record_kind="")
    assert ineligibility_reason(missing_kind) == INELIGIBLE_RECORD_KIND


# 3. Collector-generated exclusion, including from every history window
def test_collector_generated_events_are_excluded_and_not_in_history():
    collector_login, collector_failure = noise_events()[2], noise_events()[3]
    assert ineligibility_reason(collector_login) == INELIGIBLE_COLLECTOR
    assert ineligibility_reason(collector_failure) == INELIGIBLE_COLLECTOR
    with_noise = build_feature_matrix(fixture_events() + [collector_login, collector_failure])
    assert "n03" not in with_noise.event_ids and "n04" not in with_noise.event_ids
    assert row_of(with_noise, "e05")["failures_from_ip_10m"] == 3.0
    assert with_noise.excluded == {INELIGIBLE_COLLECTOR: 2}


# 4. Wrong source / data origin
def test_wrong_source_or_data_origin_is_excluded():
    assert ineligibility_reason(noise_events()[5]) == INELIGIBLE_DATA_ORIGIN
    assert ineligibility_reason(noise_events()[6]) == INELIGIBLE_SOURCE_TYPE
    for origin in ("SYNTHETIC", "SYNTHETIC_CLOUD_DEMO", "AZURE_LOG_ANALYTICS", None):
        event = linux_event("o1", 1, "Failed Login", data_origin=origin)
        assert ineligibility_reason(event) == INELIGIBLE_DATA_ORIGIN
    for source in ("CLOUD", "HPC", "BEHAVIORAL"):
        assert ineligibility_reason(linux_event("o2", 1, "Failed Login", source_type=source)) == INELIGIBLE_SOURCE_TYPE


# 5. Missing genuine source event time
def test_rows_without_source_event_time_are_excluded():
    assert ineligibility_reason(noise_events()[4]) == INELIGIBLE_EVENT_TIME
    assert ineligibility_reason(linux_event("t1", 1, "Failed Login", timestamp_source="")) == INELIGIBLE_EVENT_TIME
    assert ineligibility_reason(linux_event("t2", None, "Failed Login")) == INELIGIBLE_EVENT_TIME
    with pytest.raises(ValueError, match=INELIGIBLE_EVENT_TIME):
        extract_event_features(linux_event("t3", None, "Failed Login"))


def test_noise_never_changes_the_fixture_features():
    clean = build_feature_matrix(fixture_events())
    noisy = build_feature_matrix(fixture_events() + noise_events())
    assert noisy.event_ids == clean.event_ids
    assert np.array_equal(noisy.values, clean.values)
    assert noisy.excluded == {
        INELIGIBLE_COLLECTOR: 2,
        INELIGIBLE_DATA_ORIGIN: 1,
        INELIGIBLE_EVENT_TIME: 1,
        INELIGIBLE_RECORD_KIND: 2,
        INELIGIBLE_SOURCE_TYPE: 1,
    }
    assert all(is_linux_ml_eligible(event) for event in fixture_events())


# 6. All required features, with exact values on the fixture
def test_feature_names_are_exactly_the_required_set():
    assert FEATURE_VERSION == "linux-v1"
    assert FEATURE_NAMES == (
        "hour_sin", "hour_cos", "is_weekend", "is_failure", "is_privilege_escalation",
        "is_root_target", "auth_password", "auth_publickey", "is_remote",
        "ip_new_for_user", "user_new_on_host", "failures_from_ip_10m", "failures_for_user_10m",
        "distinct_users_from_ip_1h", "success_after_failures_10m", "log_secs_since_user_prev_event",
        "priv_esc_in_session",
    )
    events = fixture_events()
    assert tuple(extract_event_features(events[4], events[:4])) == FEATURE_NAMES


def test_fixture_feature_matrix_matches_hand_computed_values():
    matrix = build_feature_matrix(fixture_events())
    assert matrix.values.shape == (8, len(FEATURE_NAMES))
    assert matrix.event_ids == tuple(MINUTES)
    for event_id in MINUTES:
        assert list(matrix.values[matrix.event_ids.index(event_id)]) == pytest.approx(expected_row(event_id), abs=1e-6), event_id


def test_local_hour_and_weekend_use_host_offset_else_utc():
    friday_evening_utc = datetime(2026, 10, 9, 20, 0, tzinfo=timezone.utc)
    local = per_event_features(linux_event("w1", 0, "Failed Login", base=friday_evening_utc))
    assert local["is_weekend"] == 1.0  # Saturday 01:30 at +0530
    assert local["hour_sin"] == pytest.approx(round(math.sin(2 * math.pi * 1.5 / 24), 6))
    utc = per_event_features(linux_event("w2", 0, "Failed Login", base=friday_evening_utc, offset=None))
    assert utc["is_weekend"] == 0.0
    assert utc["hour_cos"] == pytest.approx(round(math.cos(2 * math.pi * 20 / 24), 6))


def test_auth_method_and_remote_parsing():
    kbd = per_event_features(linux_event("a1", 0, "Successful Login", username="bob", source_ip="10.1.1.1",
                                         message="Accepted keyboard-interactive/pam for bob from 10.1.1.1 port 1 ssh2"))
    assert (kbd["auth_password"], kbd["auth_publickey"], kbd["is_remote"]) == (1.0, 0.0, 1.0)
    console = per_event_features(linux_event("a2", 0, "Successful Login", username="bob", source_ip=":0"))
    assert (console["auth_password"], console["auth_publickey"], console["is_remote"]) == (0.0, 0.0, 0.0)
    loopback = per_event_features(linux_event("a3", 0, "Successful Login", username="bob", source_ip="127.0.0.1"))
    assert loopback["is_remote"] == 0.0


def test_auth_method_is_read_from_raw_log_not_the_summary_message():
    stored = SimpleNamespace(**vars(linux_event("a4", 0, "Successful Login", username="bob", source_ip="10.2.2.2")))
    stored.message = "Successful Login for bob from 10.2.2.2"
    stored.raw_log = (
        "2026-10-05T05:30:00-04:00 host sshd-session[11039]: "
        "Accepted password for bob from 10.2.2.2 port 51027 ssh2"
    )
    assert per_event_features(stored)["auth_password"] == 1.0
    stored.raw_log = stored.raw_log.replace("Accepted password", "Accepted publickey")
    features = per_event_features(stored)
    assert (features["auth_password"], features["auth_publickey"]) == (0.0, 1.0)


# 7. No future-event leakage
def test_history_never_uses_future_events():
    events = fixture_events()
    for k, event in enumerate(events):
        assert extract_event_features(event, events) == extract_event_features(event, events[:k]), event.event_id
    full = build_feature_matrix(events)
    for k in range(1, len(events) + 1):
        prefix = build_feature_matrix(events[:k])
        assert np.array_equal(prefix.values, full.values[:k])


def test_host_history_rejects_events_at_or_after_the_scored_event():
    events = [LinuxEventRecord.from_event(event) for event in fixture_events()]
    history = HostHistory()
    history.add(events[4])
    with pytest.raises(ValueError):
        history.features_for(events[3])
    with pytest.raises(ValueError):
        history.features_for(events[4])
    with pytest.raises(ValueError):
        history.add(events[0])


def test_simultaneous_events_do_not_see_each_other():
    burst = [
        linux_event("b1", 0, "Failed Login", username="u1", source_ip="203.0.113.50"),
        linux_event("b2", 0, "Failed Login", username="u2", source_ip="203.0.113.50"),
        linux_event("b3", 1, "Failed Login", username="u3", source_ip="203.0.113.50"),
    ]
    matrix = build_feature_matrix(burst)
    assert row_of(matrix, "b1")["failures_from_ip_10m"] == 0.0
    assert row_of(matrix, "b2")["failures_from_ip_10m"] == 0.0
    assert row_of(matrix, "b3")["failures_from_ip_10m"] == 2.0
    assert row_of(matrix, "b3")["distinct_users_from_ip_1h"] == 2.0


def test_history_is_per_host():
    other_host = linux_event("h1", 4, "Failed Login", username="bob", source_ip="203.0.113.9", server_id="srv-2")
    matrix = build_feature_matrix(fixture_events() + [other_host])
    assert row_of(matrix, "e05")["failures_from_ip_10m"] == 3.0
    assert row_of(matrix, "h1")["user_new_on_host"] == 1.0


# 8. New-IP calculation
def test_new_ip_for_user_and_new_user_on_host():
    matrix = build_feature_matrix(fixture_events())
    assert [row_of(matrix, e)["ip_new_for_user"] for e in ("e01", "e02", "e04", "e05", "e06", "e08")] == [1, 1, 0, 0, 0, 1]
    assert [row_of(matrix, e)["user_new_on_host"] for e in ("e01", "e02", "e03", "e04", "e08")] == [1, 1, 1, 0, 0]


# 9. Failed-login window calculation
def test_failed_login_windows():
    matrix = build_feature_matrix(fixture_events())
    assert [row_of(matrix, e)["failures_from_ip_10m"] for e in ("e02", "e03", "e04", "e05")] == [0, 1, 2, 3]
    assert [row_of(matrix, e)["failures_for_user_10m"] for e in ("e02", "e04", "e05", "e06")] == [0, 1, 2, 0]
    assert row_of(matrix, "e05")["success_after_failures_10m"] == 1.0
    assert row_of(matrix, "e08")["success_after_failures_10m"] == 0.0


def test_failure_window_boundary_is_inclusive_at_ten_minutes():
    login = linux_event("x9", 20, "Successful Login", username="eve", source_ip="203.0.113.77")
    at_edge = linux_event("x1", 10, "Failed Login", username="eve", source_ip="203.0.113.77")
    past_edge = linux_event("x0", 10 - 1 / 60, "Failed Login", username="eve", source_ip="203.0.113.77")
    assert history_features(login, [at_edge])["failures_from_ip_10m"] == 1.0
    assert history_features(login, [past_edge])["failures_from_ip_10m"] == 0.0
    assert history_features(login, [past_edge])["success_after_failures_10m"] == 0.0


# 10. Previous-user-event timing
def test_seconds_since_user_previous_event():
    matrix = build_feature_matrix(fixture_events())
    assert row_of(matrix, "e01")["log_secs_since_user_prev_event"] == pytest.approx(CAP, abs=1e-6)
    assert row_of(matrix, "e04")["log_secs_since_user_prev_event"] == pytest.approx(math.log1p(180), abs=1e-6)
    assert row_of(matrix, "e05")["log_secs_since_user_prev_event"] == pytest.approx(math.log1p(60), abs=1e-6)
    assert row_of(matrix, "e08")["log_secs_since_user_prev_event"] == pytest.approx(math.log1p(5400), abs=1e-6)


# 11. Privilege escalation / session context
def test_privilege_escalation_session_context():
    events = fixture_events() + [
        linux_event("e09", 40, "Successful Login", username="bob", source_ip="203.0.113.9",
                    message="Accepted password for bob from 203.0.113.9 port 40100 ssh2"),
        linux_event("e10", 45, "Privilege Escalation", username="bob", target_user="alice",
                    message="(to alice) bob on pts/1"),
        linux_event("e11", 46, "Sudo Command", username="bob", target_user="root",
                    message="bob : TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id"),
    ]
    matrix = build_feature_matrix(events)
    assert row_of(matrix, "e06")["priv_esc_in_session"] == 0.0
    assert row_of(matrix, "e07")["priv_esc_in_session"] == 1.0
    assert row_of(matrix, "e09")["priv_esc_in_session"] == 0.0  # a login starts a new session
    assert row_of(matrix, "e10")["priv_esc_in_session"] == 0.0  # earlier session's escalations do not carry over
    assert row_of(matrix, "e10")["is_root_target"] == 0.0
    assert row_of(matrix, "e11")["priv_esc_in_session"] == 1.0
    assert row_of(matrix, "e11")["is_root_target"] == 1.0
    assert row_of(matrix, "e11")["is_privilege_escalation"] == 1.0


# 12. Literal username / IP are not model features
def test_literal_username_and_ip_are_not_feature_values():
    forbidden = {"username", "source_ip", "user", "ip", "hostname", "server_id", "actor_id"}
    assert not forbidden & set(FEATURE_NAMES)
    names = {"alice": "carol", "bob": "dave"}
    ips = {"10.0.0.5": "10.9.9.9", "203.0.113.9": "198.18.0.4", "198.51.100.7": "192.0.2.200"}
    renamed = []
    for event in fixture_events():
        clone = SimpleNamespace(**vars(event))
        clone.username = names.get(event.username, event.username)
        clone.source_ip = ips.get(event.source_ip, event.source_ip)
        clone.server_id = "another-server-id"
        for old, new in [*names.items(), *ips.items()]:
            clone.message = clone.message.replace(old, new)
            clone.raw_log = clone.raw_log.replace(old, new)
        renamed.append(clone)
    assert np.array_equal(build_feature_matrix(renamed).values, build_feature_matrix(fixture_events()).values)


# 13. Collection metadata, rule/model output and batch snapshot metrics are not used
def test_collection_metadata_and_rule_output_are_ignored():
    record_fields = {f.name for f in dataclasses.fields(LinuxEventRecord)}
    never_read = {
        "risk_score", "risk_level", "severity", "collection_timestamp", "created_at", "cpu_usage",
        "memory_usage", "disk_usage", "network_connections", "commands_executed", "failed_login_count",
        "session_duration", "logout_time", "hash", "raw_log", "message", "provider", "dataset_name",
        "original_label", "behavioral_risk_score", "behavioral_classification",
    }
    assert not never_read & record_fields
    assert not never_read & set(FEATURE_NAMES)
    mutated = []
    for index, event in enumerate(fixture_events()):
        clone = SimpleNamespace(**vars(event))
        clone.risk_score, clone.risk_level, clone.severity = 99, "critical", "critical"
        clone.collection_timestamp = datetime(2030, 1, 1) + timedelta(hours=index)
        clone.created_at = datetime(2031, 1, 1)
        clone.cpu_usage, clone.memory_usage, clone.disk_usage = 99.0, 99.0, 99.0
        clone.network_connections, clone.commands_executed, clone.failed_login_count = 999, 999, 50
        clone.session_duration, clone.logout_time = 9999.0, datetime(2031, 1, 1)
        clone.hash, clone.original_label = f"other-{index}", "ANOMALOUS"
        clone.behavioral_risk_score, clone.behavioral_classification = 100, "OVER_EFFICIENCY"
        mutated.append(clone)
    assert np.array_equal(build_feature_matrix(mutated).values, build_feature_matrix(fixture_events()).values)


# 14. Deterministic output
def test_feature_output_is_deterministic_and_order_independent():
    events = fixture_events() + noise_events()
    first = build_feature_matrix(events)
    shuffled = list(events)
    random.Random(7).shuffle(shuffled)
    second = build_feature_matrix(shuffled)
    assert first.event_ids == second.event_ids
    assert np.array_equal(first.values, second.values)
    assert np.array_equal(build_feature_matrix(events).values, first.values)
    assert all(isinstance(value, float) for value in extract_event_features(events[3], events).values())


def test_mapping_rows_are_accepted_like_orm_rows():
    events = fixture_events()
    as_dicts = [vars(event) for event in events]
    assert np.array_equal(build_feature_matrix(as_dicts).values, build_feature_matrix(events).values)
    assert np.array_equal(build_feature_matrix([]).values, np.zeros((0, len(FEATURE_NAMES))))
