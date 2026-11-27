"""Synthetic behavioral-pattern Random Forest demonstration: loading, features, split, model, leakage."""

from __future__ import annotations

import csv
import random
from pathlib import Path

import numpy as np
import pytest
from pydantic import ValidationError

from backend.api.ml_demo import BehavioralSession
from backend.core.config import PROJECT_ROOT, get_settings
from backend.ml import behavioral_random_forest as brf
from backend.services.ml_demo_service import (
    STATUS_DATASET_MISSING,
    STATUS_NOT_TRAINED,
    STATUS_STALE,
    STATUS_TRAINED,
    BehavioralRfDemoService,
)

COLUMNS = [
    "timestamp", "user_id", "linux_username", "session_id", "server_id",
    "typing_speed_cpm", "command_rate_per_minute", "command_error_rate", "idle_time_seconds",
    "repeated_command_ratio", "session_duration_minutes", "login_hour",
    "is_anomaly", "behavior_class", "data_origin",
]

PROFILES = {
    "NORMAL": (180, 3, 0.10, 90, 0.10, 60, 11),
    "OVER_EFFICIENCY": (420, 9, 0.01, 20, 0.15, 30, 14),
    "AUTOMATED_ACTIVITY": (600, 40, 0.00, 1, 0.85, 8, 3),
    "SUSPICIOUS_BEHAVIOR": (150, 6, 0.40, 40, 0.30, 25, 2),
    "UNUSUAL_SESSION": (170, 2, 0.12, 400, 0.10, 400, 4),
}
COUNTS = {"NORMAL": 80, "OVER_EFFICIENCY": 20, "AUTOMATED_ACTIVITY": 16, "SUSPICIOUS_BEHAVIOR": 12, "UNUSUAL_SESSION": 12}


def session_row(label: str, index: int, rng: random.Random) -> dict[str, str]:
    base = PROFILES[label]
    values = [max(0.0, value * rng.uniform(0.9, 1.1)) for value in base[:-1]]
    return {
        "timestamp": f"2026-07-15T{index % 24:02d}:00:00Z",
        "user_id": f"user-{index % 6:03d}",
        "linux_username": f"u{index % 6}",
        "session_id": f"sess-{index:05d}",
        "server_id": f"server-{index % 4:02d}",
        "typing_speed_cpm": f"{values[0]:.2f}",
        "command_rate_per_minute": f"{values[1]:.3f}",
        "command_error_rate": f"{min(values[2], 1.0):.4f}",
        "idle_time_seconds": f"{values[3]:.2f}",
        "repeated_command_ratio": f"{min(values[4], 1.0):.4f}",
        "session_duration_minutes": f"{values[5]:.2f}",
        "login_hour": str(base[6]),
        "is_anomaly": str(label != "NORMAL"),
        "behavior_class": label,
        "data_origin": "SYNTHETIC",
    }


def generated_rows(seed: int = 7) -> list[dict[str, str]]:
    rng = random.Random(seed)
    rows, index = [], 0
    for label, count in COUNTS.items():
        for _ in range(count):
            rows.append(session_row(label, index, rng))
            index += 1
    rng.shuffle(rows)
    return rows


def write_csv(path: Path, rows: list[dict[str, str]], columns: list[str] = COLUMNS) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def dataset(tmp_path):
    return brf.load_dataset(write_csv(tmp_path / "b.csv", generated_rows()))


# ---------------------------------------------------------------- loading and features


def test_load_dataset_reads_features_and_labels(dataset):
    assert len(dataset) == sum(COUNTS.values()) == dataset.rows_total
    assert dataset.features.shape == (len(dataset), len(brf.FEATURE_NAMES))
    assert set(dataset.labels) == set(brf.CLASSES)
    assert dataset.skipped == {}


def test_load_dataset_skips_invalid_rows(tmp_path):
    rows = generated_rows()
    rows[0] = {**rows[0], "typing_speed_cpm": ""}
    rows[1] = {**rows[1], "idle_time_seconds": "nan"}
    rows[2] = {**rows[2], "behavior_class": "ATTACK"}
    rows[3] = {**rows[3], "data_origin": "LIVE_LINUX"}
    rows[4] = {**rows[4], "behavior_class": "normal"}
    loaded = brf.load_dataset(write_csv(tmp_path / "b.csv", rows))
    assert loaded.skipped == {"invalid_feature": 2, "unknown_label": 1, "non_synthetic_origin": 1}
    assert len(loaded) == len(rows) - 4
    assert loaded.rows_total == len(rows)


def test_load_dataset_requires_feature_and_label_columns(tmp_path):
    columns = [name for name in COLUMNS if name != "login_hour"]
    with pytest.raises(ValueError, match="login_hour"):
        brf.load_dataset(write_csv(tmp_path / "b.csv", generated_rows(), columns))


def test_feature_selection_is_exactly_the_seven_numeric_features():
    assert brf.FEATURE_NAMES == (
        "typing_speed_cpm", "command_rate_per_minute", "command_error_rate", "idle_time_seconds",
        "repeated_command_ratio", "session_duration_minutes", "login_hour",
    )
    assert brf.LABEL_COLUMN == "behavior_class"
    assert brf.CLASSES == ("NORMAL", "OVER_EFFICIENCY", "AUTOMATED_ACTIVITY", "SUSPICIOUS_BEHAVIOR", "UNUSUAL_SESSION")


# ---------------------------------------------------------------- leakage


LEAKAGE_COLUMNS = ("is_anomaly", "behavior_class", "data_origin", "user_id", "session_id", "server_id")


def test_leakage_columns_are_never_features():
    for column in LEAKAGE_COLUMNS + ("linux_username", "timestamp"):
        assert column not in brf.FEATURE_NAMES
        assert column in brf.EXCLUDED_COLUMNS


def test_features_do_not_change_with_excluded_columns(tmp_path, dataset):
    scrambled = [
        {**row, "user_id": "x", "session_id": "y", "server_id": "server-demo", "linux_username": "z",
         "is_anomaly": "False", "timestamp": "2030-01-01T00:00:00Z"}
        for row in generated_rows()
    ]
    other = brf.load_dataset(write_csv(tmp_path / "s.csv", scrambled))
    assert np.array_equal(dataset.features, other.features) and dataset.labels == other.labels


def test_predict_ignores_label_and_identifier_keys(dataset):
    bundle = brf.train_and_evaluate(dataset)
    session = dict(zip(brf.FEATURE_NAMES, PROFILES["AUTOMATED_ACTIVITY"]))
    plain = brf.predict(bundle, session)
    noisy = brf.predict(bundle, {**session, "is_anomaly": False, "behavior_class": "NORMAL", "user_id": "user-001", "server_id": "server-demo"})
    assert plain["probabilities"] == noisy["probabilities"]
    assert set(plain["features"]) == set(brf.FEATURE_NAMES)


def test_api_session_schema_rejects_leakage_fields():
    valid = dict(zip(brf.FEATURE_NAMES, (180.0, 3.0, 0.1, 90.0, 0.1, 60.0, 11)))
    assert BehavioralSession(**valid).model_dump() == valid
    with pytest.raises(ValidationError):
        BehavioralSession(**valid, is_anomaly=True)
    with pytest.raises(ValidationError):
        BehavioralSession(**{**valid, "login_hour": 24})


# ---------------------------------------------------------------- split, training, metrics


def test_train_test_split_is_stratified_and_complete(dataset):
    meta = brf.train_and_evaluate(dataset)["training_metadata"]
    dist = meta["class_distribution"]
    assert meta["train_rows"] + meta["test_rows"] == len(dataset)
    assert meta["test_rows"] == round(len(dataset) * brf.TEST_SIZE) or abs(meta["test_rows"] - len(dataset) * brf.TEST_SIZE) < 1
    for name in brf.CLASSES:
        assert dist["train"][name] + dist["test"][name] == dist["all"][name] == COUNTS[name]
        assert dist["test"][name] >= 1
    assert meta["split"] == {"method": "stratified train_test_split", "test_size": brf.TEST_SIZE, "random_state": brf.RANDOM_STATE}


def test_training_metadata_and_model(dataset):
    bundle = brf.train_and_evaluate(dataset)
    model = bundle["model"]
    assert brf.is_compatible(bundle)
    assert model.n_features_in_ == len(brf.FEATURE_NAMES)
    assert model.random_state == brf.RANDOM_STATE
    assert sorted(model.classes_) == sorted(brf.CLASSES)
    assert bundle["data_source"] == "SYNTHETIC_BEHAVIORAL_DATASET"
    importance = bundle["training_metadata"]["feature_importance"]
    assert [item["feature"] for item in importance] != [] and {item["feature"] for item in importance} == set(brf.FEATURE_NAMES)
    assert sum(item["importance"] for item in importance) == pytest.approx(1.0, abs=1e-3)


def test_training_is_deterministic(dataset):
    a = brf.train_and_evaluate(dataset)
    b = brf.train_and_evaluate(dataset)
    assert a["training_metadata"]["evaluation"] == b["training_metadata"]["evaluation"]
    assert a["training_metadata"]["feature_importance"] == b["training_metadata"]["feature_importance"]
    assert np.array_equal(a["model"].predict_proba(dataset.features), b["model"].predict_proba(dataset.features))


def test_metrics_cover_every_class(dataset):
    evaluation = brf.train_and_evaluate(dataset)["training_metadata"]["evaluation"]
    assert set(evaluation["per_class"]) == set(brf.CLASSES)
    for metrics in evaluation["per_class"].values():
        assert {"precision", "recall", "f1", "support"} == set(metrics)
        assert 0.0 <= metrics["f1"] <= 1.0
    matrix = np.asarray(evaluation["confusion_matrix"]["matrix"])
    assert matrix.shape == (5, 5)
    assert matrix.sum() == sum(m["support"] for m in evaluation["per_class"].values())
    assert evaluation["confusion_matrix"]["labels"] == list(brf.CLASSES)
    assert 0.0 <= evaluation["macro_f1"] <= 1.0 and 0.0 <= evaluation["accuracy"] <= 1.0


def test_training_requires_every_class(tmp_path):
    rows = [row for row in generated_rows() if row["behavior_class"] != "UNUSUAL_SESSION"]
    with pytest.raises(ValueError, match="every class"):
        brf.train_and_evaluate(brf.load_dataset(write_csv(tmp_path / "b.csv", rows)))


def test_prediction_output(dataset):
    bundle = brf.train_and_evaluate(dataset)
    result = brf.predict(bundle, dict(zip(brf.FEATURE_NAMES, PROFILES["AUTOMATED_ACTIVITY"])))
    assert result["predicted_pattern"] == "AUTOMATED_ACTIVITY"
    assert sum(result["probabilities"].values()) == pytest.approx(1.0, abs=1e-3)
    assert result["confidence"] == max(result["probabilities"].values())
    assert result["demonstration"] == "Synthetic behavioral-pattern classification demonstration."
    assert "does not prove malicious activity" in result["disclaimer"]
    with pytest.raises(ValueError, match="login_hour"):
        brf.predict(bundle, dict(zip(brf.FEATURE_NAMES[:-1], PROFILES["NORMAL"])))
    with pytest.raises(ValueError):
        brf.predict(bundle, {**dict(zip(brf.FEATURE_NAMES, PROFILES["NORMAL"])), "idle_time_seconds": float("inf")})


def test_bundle_roundtrip_and_incompatible_bundles(tmp_path, dataset):
    bundle = brf.train_and_evaluate(dataset)
    path = tmp_path / "rf.joblib"
    brf.save_bundle(bundle, path)
    assert brf.load_bundle(path) is not None
    assert not brf.is_compatible({**bundle, "feature_names": [*brf.FEATURE_NAMES, "is_anomaly"]})
    assert not brf.is_compatible({**bundle, "kind": "openstack_isolation_forest"})


# ---------------------------------------------------------------- service


def _settings(tmp_path: Path):
    settings = get_settings().model_copy()
    settings.DATASET_ROOT = str(tmp_path / "datasets")
    settings.BEHAVIORAL_DATASET_PATH = "behavioral"
    settings.MODEL_DIR = str(tmp_path / "models")
    return settings


def test_service_train_report_predict_and_staleness(tmp_path):
    service = BehavioralRfDemoService(_settings(tmp_path))
    assert service.report()["status"] == STATUS_DATASET_MISSING
    path = write_csv(tmp_path / "datasets" / "behavioral" / brf.DATASET_FILENAME, generated_rows())
    assert service.report()["status"] == STATUS_NOT_TRAINED
    with pytest.raises(LookupError):
        service.predict(dict(zip(brf.FEATURE_NAMES, PROFILES["NORMAL"])))
    trained = service.train()
    assert trained["status"] == STATUS_TRAINED
    assert trained["is_synthetic"] is True and trained["is_live"] is False
    assert trained["demonstration"] == "Synthetic behavioral-pattern classification demonstration."
    assert trained["model"]["evaluation"]["confusion_matrix"]["labels"] == list(brf.CLASSES)
    assert service.model_file.is_relative_to(tmp_path / "models" / "demo" / "behavioral")
    assert service.predict(dict(zip(brf.FEATURE_NAMES, PROFILES["NORMAL"])))["predicted_pattern"] in brf.CLASSES
    assert service.report()["status"] == STATUS_TRAINED
    write_csv(path, generated_rows(seed=8)[:-1])
    assert service.report()["status"] == STATUS_STALE


REAL_DATASET = PROJECT_ROOT / "datasets" / "behavioral" / brf.DATASET_FILENAME


@pytest.mark.skipif(not REAL_DATASET.is_file(), reason="Generated behavioral dataset not present")
def test_real_generated_dataset_trains():
    loaded = brf.load_dataset(REAL_DATASET)
    assert len(loaded) == loaded.rows_total and loaded.skipped == {}
    meta = brf.train_and_evaluate(loaded)["training_metadata"]
    assert set(meta["class_distribution"]["all"]) == set(brf.CLASSES)
    assert meta["evaluation"]["macro_f1"] > 0.5
