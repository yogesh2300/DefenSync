"""Linux Isolation Forest integration: eligibility, baseline gate, threshold, model separation.

Synthetic rows live only in an in-memory SQLite database created per test.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import joblib
import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from backend.database.models import Alert, Base, Detection, Event
from backend.ml import linux_isolation_forest as linux_if
from backend.ml.linux_features import FEATURE_NAMES as LINUX_FEATURE_NAMES
from backend.ml.linux_features import build_feature_matrix
from backend.services.detection_service import FEATURE_NAMES, FEATURE_VERSION, DetectionService

BASE = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
OWNER = "owner-1"


class RecordingForest:
    """Stand-in hybrid Random Forest that records every row it is asked to classify."""

    calls: list[int] = []

    def predict(self, x):
        RecordingForest.calls.append(len(x))
        return np.zeros(len(x), dtype=int)


class ExplodingModel:
    """Stand-in stale Linux model; any use fails the test."""

    def predict(self, x):
        raise AssertionError("stale Linux model was used")

    def score_samples(self, x):
        raise AssertionError("stale Linux model was used")


class Env:
    def __init__(self, tmp_path: Path) -> None:
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session = sessionmaker(bind=self.engine, expire_on_commit=False)()
        self.model_dir = tmp_path / "models"
        self.settings = MagicMock()
        self.settings.MODEL_DIR = str(self.model_dir)

    def service(self) -> DetectionService:
        with patch("backend.services.detection_service.get_settings", return_value=self.settings):
            return DetectionService(self.session)

    @property
    def linux_model(self) -> Path:
        return self.model_dir / "linux" / OWNER / "linux_detection.joblib"

    def close(self) -> None:
        self.session.close()
        self.engine.dispose()


@pytest.fixture
def env(tmp_path):
    environment = Env(tmp_path)
    RecordingForest.calls = []
    yield environment
    environment.close()


def add_linux(
    session,
    event_id: str,
    minutes: float,
    event_type: str = "Successful Login",
    *,
    username: str | None = "alice",
    source_ip: str | None = "10.0.0.5",
    raw: str | None = None,
    target_user: str | None = None,
    record_kind: str = "SECURITY_EVENT",
    record_origin: str = "SOURCE_OBSERVED",
    timestamp_source: str = "SOURCE_EVENT",
    source_type: str = "LINUX",
    data_origin: str = "LIVE_LINUX",
    risk_score: int = 10,
    severity: str = "low",
    original_label: str | None = None,
    server_id: str = "srv-1",
) -> None:
    ts = BASE + timedelta(minutes=minutes)
    nd = {"record_kind": record_kind, "record_origin": record_origin, "host_utc_offset": "+0530"}
    if timestamp_source == "SOURCE_EVENT":
        nd["event_time_utc"] = ts.isoformat()
    if target_user:
        nd["target_user"] = target_user
    session.add(Event(
        event_id=event_id,
        timestamp=ts.replace(tzinfo=None),
        timestamp_source=timestamp_source,
        hostname="linux-host",
        username=username,
        source_ip=source_ip,
        event_type=event_type,
        category="authentication",
        severity=severity,
        risk_score=risk_score,
        message=f"{event_type} for {username}",
        raw_log=raw or f"{event_type} {event_id}",
        hash=f"hash-{event_id}",
        owner_id=OWNER,
        server_id=server_id,
        source_type=source_type,
        data_origin=data_origin,
        normalized_data=json.dumps(nd),
        original_label=original_label,
    ))


def seed_eligible(session, count: int, *, prefix: str = "ev", start: int = 0, risk_score: int = 10,
                  severity: str = "low", labels: tuple[str, ...] = (), server_id: str = "srv-1",
                  order: str = "forward") -> list[str]:
    """Deterministic, varied human Linux activity: logins, failures, su and sudo."""
    users = ("alice", "bob", "carol")
    indexes = list(range(start, start + count))
    if order == "reverse":
        indexes.reverse()
    ids = []
    for i in indexes:
        user, ip = users[i % 3], f"10.0.0.{i % 4 + 1}"
        kind = i % 10
        event_id = f"{prefix}-{i:04d}"
        label = labels[i % len(labels)] if labels else None
        common = dict(risk_score=risk_score, severity=severity, original_label=label, server_id=server_id)
        if kind <= 6:
            add_linux(session, event_id, i * 53, "Successful Login", username=user, source_ip=ip,
                      raw=f"sshd-session[{i}]: Accepted publickey for {user} from {ip} port {40000 + i} ssh2", **common)
        elif kind == 7:
            add_linux(session, event_id, i * 53, "Failed Login", username=user, source_ip=ip,
                      raw=f"sshd-session[{i}]: Failed password for {user} from {ip} port {40000 + i} ssh2", **common)
        elif kind == 8:
            add_linux(session, event_id, i * 53, "Privilege Escalation", username=user, source_ip=None,
                      target_user="root", raw=f"su[{i}]: (to root) {user} on pts/0", **common)
        else:
            add_linux(session, event_id, i * 53, "Sudo Command", username=user, source_ip=None, target_user="root",
                      raw=f"sudo[{i}]: {user} : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id", **common)
        ids.append(event_id)
    session.commit()
    return ids


def seed_noise(session) -> None:
    add_linux(session, "snap-1", 5, "System Snapshot", username="root", source_ip=None,
              record_kind="SYSTEM_SNAPSHOT", timestamp_source="SNAPSHOT_COLLECTION_TIME")
    add_linux(session, "sys-1", 6, "System Event", username=None, source_ip=None, record_kind="SYSTEM_EVENT")
    add_linux(session, "col-1", 7, "Successful Login", username="ysalve", source_ip="192.168.195.1",
              record_origin="COLLECTOR_GENERATED", raw="Accepted password for ysalve from 192.168.195.1 port 1 ssh2")
    session.commit()


def linux_predictions(env) -> list[Detection]:
    return list(env.session.scalars(select(Detection)).all())


# 1. 42 eligible events do not train
def test_42_eligible_events_do_not_train_or_detect(env):
    seed_eligible(env.session, 42)
    seed_noise(env.session)
    result = env.service().run_detection(owner_id=OWNER)
    linux = result["linux"]
    assert linux["isolation_forest_status"] == "insufficient_baseline"
    assert linux["training_status"] == "not_trained"
    assert linux["model_action"] == "skipped"
    assert (linux["eligible_count"], linux["minimum_required"]) == (42, 100)
    assert (linux["scored_count"], linux["anomaly_count"], result["ml_anomalies"]) == (0, 0, 0)
    assert not env.linux_model.exists()
    assert linux_predictions(env) == []
    assert env.session.scalar(select(func.count(Alert.id))) == 0


# 2. insufficient_baseline status
def test_status_reports_insufficient_baseline_without_training(env):
    seed_eligible(env.session, 42)
    linux = env.service().status(owner_id=OWNER)["linux"]
    assert linux["isolation_forest_status"] == "insufficient_baseline"
    assert linux["eligible_count"] == 42
    assert linux["minimum_required"] == 100
    assert linux["training_status"] == "not_trained"
    assert linux["random_forest_status"] == "no_valid_linux_labels"
    assert linux["model_present"] is False
    assert not env.linux_model.exists()


# 3. Minimum baseline is 100
def test_minimum_baseline_is_100(env):
    assert linux_if.MIN_IF_BASELINE == 100
    seed_eligible(env.session, 99)
    assert env.service().run_detection(owner_id=OWNER)["linux"]["isolation_forest_status"] == "insufficient_baseline"
    seed_eligible(env.session, 1, start=99)
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    assert linux["isolation_forest_status"] == "trained"
    assert linux["model_action"] == "trained"
    assert linux["training_metadata"]["training_count"] == 100


# 4-8. Ineligible rows never count toward the baseline
INELIGIBLE = {
    "snapshot": (dict(event_type="System Snapshot", record_kind="SYSTEM_SNAPSHOT",
                      timestamp_source="SNAPSHOT_COLLECTION_TIME"), "not_security_event"),
    "system_event": (dict(event_type="System Event", record_kind="SYSTEM_EVENT"), "not_security_event"),
    "collector": (dict(record_origin="COLLECTOR_GENERATED"), "collector_generated"),
    "wrong_origin": (dict(data_origin="PUBLIC_DATASET"), "wrong_data_origin"),
    "wrong_source": (dict(source_type="CLOUD", data_origin="AZURE_LOG_ANALYTICS"), "wrong_source_type"),
    "missing_source_time": (dict(timestamp_source="COLLECTION_TIME_FALLBACK"), "no_source_event_time"),
}


@pytest.mark.parametrize("kind", sorted(INELIGIBLE))
def test_ineligible_rows_are_excluded_from_baseline(env, kind):
    overrides, reason = INELIGIBLE[kind]
    overrides = dict(overrides)
    event_type = overrides.pop("event_type", "Successful Login")
    for i in range(120):
        add_linux(env.session, f"{kind}-{i}", i, event_type, **overrides)
    env.session.commit()
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    assert linux["eligible_count"] == 0
    if kind != "wrong_source":  # CLOUD rows are not Linux rows at all
        assert linux["excluded"] == {reason: 120}
    assert linux["isolation_forest_status"] == "insufficient_baseline"
    assert not env.linux_model.exists()


def test_trained_model_scores_only_eligible_events(env):
    eligible_ids = seed_eligible(env.session, 120)
    seed_noise(env.session)
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    predictions = linux_predictions(env)
    assert linux["scored_count"] == 120
    assert {p.event_id for p in predictions} == set(eligible_ids)
    assert {p.detection_type for p in predictions} <= set(linux_if.DETECTION_TYPES)
    assert all(p.random_forest_label == "not_applicable" and p.confidence is None for p in predictions)


# 9. risk_score / severity are not used for baseline selection or the threshold
def test_risk_score_and_severity_do_not_affect_baseline_or_threshold(tmp_path):
    results = []
    for name, risk, severity in (("low", 5, "low"), ("high", 95, "critical")):
        environment = Env(tmp_path / name)
        seed_eligible(environment.session, 120, risk_score=risk, severity=severity)
        linux = environment.service().run_detection(owner_id=OWNER)["linux"]
        scores = sorted(p.isolation_score for p in linux_predictions(environment))
        results.append((linux["training_metadata"]["training_count"], linux["threshold"], scores))
        environment.close()
    assert results[0][0] == results[1][0] == 120
    assert results[0][1] == results[1][1]
    assert results[0][2] == results[1][2]


# 10. Linux feature version
def test_linux_feature_version_is_linux_v1(env):
    seed_eligible(env.session, 120)
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    bundle = joblib.load(env.linux_model)
    assert linux["feature_version"] == bundle["feature_version"] == "linux-v1"
    assert bundle["feature_names"] == list(LINUX_FEATURE_NAMES)
    assert FEATURE_VERSION == "v3"  # hybrid feature version is unchanged


# 11. Linux model path is separate
def test_linux_model_path_is_separate_from_hybrid_bundles(env):
    seed_eligible(env.session, 120)
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    assert env.linux_model.exists()
    assert Path(linux["model_path"]) == env.linux_model
    assert linux["training_metadata"]["model_path"] == str(env.linux_model)
    assert not (env.model_dir / OWNER / "hybrid_detection.joblib").exists()
    assert not (env.model_dir / "global").exists()
    assert linux_if.model_path(env.model_dir, None) == env.model_dir / "linux" / "global" / "linux_detection.joblib"


# 12. Global / hybrid Random Forest is never applied to Linux events
def test_hybrid_random_forest_never_sees_linux_events(env):
    service = env.service()
    for i in range(12):
        env.session.add(Event(
            event_id=f"cloud-{i}", timestamp=(BASE + timedelta(minutes=i)).replace(tzinfo=None), hostname="azure",
            username="user@contoso", source_ip="198.51.100.1", event_type="CLOUD_LOGIN_FAILURE", category="cloud",
            severity="medium", risk_score=10, message="cloud", raw_log=f"cloud-{i}", hash=f"cloud-hash-{i}",
            owner_id=OWNER, source_type="CLOUD", data_origin="AZURE_LOG_ANALYTICS",
        ))
    seed_eligible(env.session, 120)
    cloud_events = service._load_events(owner_id=OWNER, exclude_linux=True)
    cloud_if = IsolationForest(n_estimators=10, random_state=0).fit(service._features(cloud_events))
    hybrid = {
        "isolation_forests": {"CLOUD": cloud_if, "LINUX": ExplodingModel()},
        "random_forest": RecordingForest(),
        "rf_status": "trained",
        "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
        "trained_at": "earlier",
    }
    service._save_bundle(OWNER, hybrid)
    service._save_bundle(None, hybrid)
    result = service.run_detection(owner_id=OWNER)
    assert RecordingForest.calls == [12]
    assert result["linux"]["random_forest_status"] == "no_valid_linux_labels"
    assert "random_forest" not in joblib.load(env.linux_model)
    linux_ids = {p.event_id for p in linux_predictions(env) if p.detection_type in linux_if.DETECTION_TYPES}
    assert len(linux_ids) == 120 and not any(event_id.startswith("cloud-") for event_id in linux_ids)


# 13. Linux RF status, even when Linux rows carry original_label values
def test_linux_random_forest_stays_disabled(env):
    seed_eligible(env.session, 120, labels=("ANOMALOUS", "NORMAL"))
    with patch("backend.services.detection_service.RandomForestClassifier") as forest:
        result = env.service().run_detection(owner_id=OWNER)
    forest.assert_not_called()
    linux = result["linux"]
    assert linux["random_forest_status"] == "no_valid_linux_labels"
    assert linux["valid_label_count"] == 0
    assert linux["training_metadata"]["random_forest_status"] == "no_valid_linux_labels"
    assert env.service().status(owner_id=OWNER)["linux"]["random_forest_status"] == "no_valid_linux_labels"


# 14. Threshold is derived from the baseline score distribution; higher score = more anomalous
def test_threshold_is_baseline_percentile_and_score_direction_is_consistent(env):
    seed_eligible(env.session, 150)
    service = env.service()
    service.run_detection(owner_id=OWNER)
    bundle = joblib.load(env.linux_model)
    metadata = bundle["training_metadata"]
    baseline = build_feature_matrix(service._load_linux_rows(owner_id=OWNER)).values
    expected = float(np.percentile(-bundle["model"].score_samples(baseline), 99.0))
    assert bundle["threshold"] == pytest.approx(expected)
    assert metadata["threshold_method"] == "baseline_percentile"
    assert metadata["threshold_percentile"] == 99.0
    assert metadata["threshold_value"] == bundle["threshold"]
    assert "contamination" in metadata["model_params"] and "not used" in metadata["model_params"]["contamination"]

    burst_start = 150 * 53 + 600
    for j in range(6):
        add_linux(env.session, f"burst-{j}", burst_start + j * 0.5, "Failed Login", username="root",
                  source_ip="203.0.113.66", raw="Failed password for root from 203.0.113.66 port 1 ssh2")
    add_linux(env.session, "burst-ok", burst_start + 4, "Successful Login", username="root", source_ip="203.0.113.66",
              raw="Accepted password for root from 203.0.113.66 port 2 ssh2")
    env.session.commit()
    rerun = env.service().run_detection(owner_id=OWNER)["linux"]
    assert rerun["model_action"] == "reused"
    predictions = {p.event_id: p for p in linux_predictions(env)}
    assert predictions["burst-ok"].isolation_score > metadata["baseline_score_median"]
    for prediction in predictions.values():
        assert prediction.is_anomaly == (prediction.isolation_score > bundle["threshold"])
        assert prediction.classification == ("Suspicious" if prediction.is_anomaly else "Normal")


# 15. Stale models and stale detections cannot act as the Linux model
def test_stale_hybrid_linux_forest_and_stale_rows_are_ignored(env):
    seed_eligible(env.session, 42)
    add_linux(env.session, "snap-old", 3, "System Snapshot", username="root", source_ip=None,
              record_kind="SYSTEM_SNAPSHOT", timestamp_source="SNAPSHOT_COLLECTION_TIME")
    env.session.add(Detection(server_id="srv-1", owner_id=OWNER, event_id="snap-old", isolation_score=0.7,
                              classification="Suspicious", detection_type="isolation_forest", is_anomaly=True))
    env.session.commit()
    service = env.service()
    service._save_bundle(OWNER, {
        "isolation_forests": {"LINUX": ExplodingModel()},
        "random_forest": None,
        "rf_status": "no_valid_labels",
        "feature_names": FEATURE_NAMES,
        "feature_version": FEATURE_VERSION,
    })
    result = service.run_detection(owner_id=OWNER)
    assert result["linux"]["isolation_forest_status"] == "insufficient_baseline"
    status = service.status(owner_id=OWNER)
    assert status["isolation_forest"] == "not_trained" and status["ready"] is False
    assert status["linux"]["model_present"] is False
    anomalies = service.get_anomalies(owner_id=OWNER)
    assert anomalies["items"] == [] and anomalies["total"] == 0
    assert env.session.scalar(select(func.count(Detection.id))) == 1  # left in place, not deleted


def test_incompatible_file_at_linux_path_is_not_reused(env):
    seed_eligible(env.session, 120)
    env.linux_model.parent.mkdir(parents=True)
    joblib.dump({"kind": linux_if.MODEL_KIND, "environment": "LINUX", "feature_version": "linux-v0",
                 "feature_names": list(LINUX_FEATURE_NAMES), "model": ExplodingModel(), "threshold": 0.5},
                env.linux_model)
    assert linux_if.load_bundle(env.linux_model) is None
    linux = env.service().run_detection(owner_id=OWNER)["linux"]
    assert linux["model_action"] == "trained"
    assert linux_if.load_bundle(env.linux_model) is not None


def test_compatibility_rejects_non_linux_bundles():
    matrix = build_feature_matrix([])
    assert not linux_if.is_compatible(None)
    assert not linux_if.is_compatible({"isolation_forests": {}, "feature_version": "v3"})
    model = IsolationForest(n_estimators=5, random_state=0).fit(np.zeros((5, len(LINUX_FEATURE_NAMES))))
    good = {"kind": linux_if.MODEL_KIND, "environment": "LINUX", "feature_version": "linux-v1",
            "feature_names": list(LINUX_FEATURE_NAMES), "model": model, "threshold": 0.4}
    assert linux_if.is_compatible(good)
    for key, value in (("environment", "CLOUD"), ("kind", "hybrid"), ("feature_names", list(reversed(LINUX_FEATURE_NAMES))),
                       ("threshold", float("nan"))):
        assert not linux_if.is_compatible({**good, key: value})
    wrong_width = IsolationForest(n_estimators=5, random_state=0).fit(np.zeros((5, 3)))
    assert not linux_if.is_compatible({**good, "model": wrong_width})
    with pytest.raises(ValueError):
        linux_if.train_bundle(matrix, path=Path("unused"))


# 16. Metadata
def test_training_metadata_is_complete(env):
    seed_eligible(env.session, 120)
    seed_noise(env.session)
    env.service().run_detection(owner_id=OWNER)
    metadata = joblib.load(env.linux_model)["training_metadata"]
    assert metadata["environment"] == "LINUX"
    assert metadata["feature_version"] == "linux-v1"
    assert metadata["eligible_count"] == 120
    assert metadata["training_count"] == 120
    datetime.fromisoformat(metadata["training_time"])
    assert metadata["model_type"] == "sklearn.ensemble.IsolationForest"
    assert metadata["threshold_method"] == "baseline_percentile"
    assert metadata["excluded"] == {"collector_generated": 1, "not_security_event": 2}
    assert metadata["minimum_baseline"] == 100
    assert metadata["model_path"] == str(env.linux_model)
    assert "risk_score" not in json.dumps(metadata["baseline_selection"]).replace("No risk_score", "")


# 17. Deterministic feature ordering and training
def test_training_is_deterministic_regardless_of_insert_order(tmp_path):
    thresholds = []
    for order in ("forward", "reverse"):
        environment = Env(tmp_path / order)
        seed_eligible(environment.session, 120, order=order)
        environment.service().run_detection(owner_id=OWNER)
        bundle = joblib.load(environment.linux_model)
        assert bundle["feature_names"] == list(LINUX_FEATURE_NAMES)
        thresholds.append(bundle["threshold"])
        environment.close()
    assert thresholds[0] == thresholds[1]


def test_reuse_does_not_retrain_and_server_scope_limits_scoring(env):
    seed_eligible(env.session, 110)
    seed_eligible(env.session, 20, prefix="s2", start=500, server_id="srv-2")
    service = env.service()
    first = service.run_detection(owner_id=OWNER)["linux"]
    second = service.run_detection(owner_id=OWNER, server_id="srv-2")["linux"]
    assert first["model_action"] == "trained" and second["model_action"] == "reused"
    assert first["trained_at"] == second["trained_at"]
    assert second["scored_count"] == 20
