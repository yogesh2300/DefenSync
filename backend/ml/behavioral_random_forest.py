"""Random Forest behavioral-pattern classifier (model version behavioral-rf-v1).

Synthetic behavioral-pattern classification demonstration. The training data is the generated
dataset datasets/behavioral/generated_behavioral_telemetry.csv (data_origin SYNTHETIC). Its
behavior_class values are generator categories, not real attack labels, so a prediction only says
which known synthetic pattern a session most closely resembles; it never proves malicious activity.

Only the seven numeric session features are model inputs. Labels, identifiers, timestamps and the
data origin are never features. This model shares no data or files with the Linux, Azure,
OpenStack, HPC or hybrid models.
"""

from __future__ import annotations

import csv
import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

logger = logging.getLogger(__name__)

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None

MODEL_KIND = "behavioral_random_forest"
MODEL_VERSION = "behavioral-rf-v1"
MODEL_TYPE = "sklearn.ensemble.RandomForestClassifier"
DATA_SOURCE = "SYNTHETIC_BEHAVIORAL_DATASET"
DEMONSTRATION = "Synthetic behavioral-pattern classification demonstration."
DISCLAIMER = (
    "Trained on synthetic generated sessions. Classes are generator patterns, not real attack labels; "
    "a prediction shows the closest known synthetic pattern and does not prove malicious activity."
)
MODEL_SUBDIR = "demo/behavioral"
MODEL_FILENAME = "behavioral_random_forest.joblib"
DATASET_FILENAME = "generated_behavioral_telemetry.csv"
EXPECTED_ORIGIN = "SYNTHETIC"

FEATURE_NAMES: tuple[str, ...] = (
    "typing_speed_cpm",
    "command_rate_per_minute",
    "command_error_rate",
    "idle_time_seconds",
    "repeated_command_ratio",
    "session_duration_minutes",
    "login_hour",
)
LABEL_COLUMN = "behavior_class"
CLASSES: tuple[str, ...] = (
    "NORMAL",
    "OVER_EFFICIENCY",
    "AUTOMATED_ACTIVITY",
    "SUSPICIOUS_BEHAVIOR",
    "UNUSUAL_SESSION",
)
EXCLUDED_COLUMNS: dict[str, str] = {
    "behavior_class": "Target label.",
    "is_anomaly": "Derived from the target label (NORMAL vs not NORMAL).",
    "data_origin": "Constant SYNTHETIC provenance marker; used only to verify the dataset.",
    "user_id": "Identifier.",
    "linux_username": "Identifier.",
    "session_id": "Identifier.",
    "server_id": "Identifier.",
    "timestamp": "Generation time, not session behaviour.",
}

TEST_SIZE = 0.25
RANDOM_STATE = 42
N_ESTIMATORS = 200
CLASS_WEIGHT = "balanced"


@dataclass
class BehavioralDataset:
    features: np.ndarray
    labels: list[str]
    columns: list[str]
    rows_total: int
    skipped: dict[str, int] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.labels)


def _number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def load_dataset(path: Path) -> BehavioralDataset:
    """Feature rows and labels; rows with a missing feature, unknown label or non-synthetic origin are skipped."""
    skipped: Counter = Counter()
    rows, labels, total = [], [], 0
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = list(reader.fieldnames or [])
        missing = [name for name in (*FEATURE_NAMES, LABEL_COLUMN) if name not in columns]
        if missing:
            raise ValueError(f"Behavioral dataset is missing columns: {', '.join(missing)}")
        for record in reader:
            total += 1
            if "data_origin" in columns and (record.get("data_origin") or "").strip().upper() != EXPECTED_ORIGIN:
                skipped["non_synthetic_origin"] += 1
                continue
            label = (record.get(LABEL_COLUMN) or "").strip().upper()
            if label not in CLASSES:
                skipped["unknown_label"] += 1
                continue
            values = [_number(record.get(name)) for name in FEATURE_NAMES]
            if any(value is None for value in values):
                skipped["invalid_feature"] += 1
                continue
            rows.append(values)
            labels.append(label)
    features = np.asarray(rows, dtype=float).reshape(len(rows), len(FEATURE_NAMES))
    return BehavioralDataset(features=features, labels=labels, columns=columns, rows_total=total, skipped=dict(skipped))


def _distribution(labels: list[str]) -> dict[str, int]:
    counts = Counter(labels)
    return {name: int(counts.get(name, 0)) for name in CLASSES}


def train_and_evaluate(dataset: BehavioralDataset, *, trained_at: datetime | None = None) -> dict[str, Any]:
    """Stratified hold-out split, fit on the training part, metrics on the untouched test part."""
    counts = Counter(dataset.labels)
    if len(dataset) < 20 or any(counts.get(name, 0) < 2 for name in CLASSES):
        raise ValueError("Behavioral dataset needs at least 20 rows and 2 rows for every class.")
    labels = np.asarray(dataset.labels)
    x_train, x_test, y_train, y_test = train_test_split(
        dataset.features, labels, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=labels,
    )
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS, class_weight=CLASS_WEIGHT, random_state=RANDOM_STATE, n_jobs=1,
    )
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)
    report = classification_report(y_test, predicted, labels=list(CLASSES), output_dict=True, zero_division=0)
    importance = sorted(
        ((name, float(value)) for name, value in zip(FEATURE_NAMES, model.feature_importances_)),
        key=lambda item: -item[1],
    )
    trained_at = trained_at or datetime.now(timezone.utc)
    evaluation = {
        "accuracy": round(float(accuracy_score(y_test, predicted)), 4),
        "macro_f1": round(float(f1_score(y_test, predicted, labels=list(CLASSES), average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y_test, predicted, labels=list(CLASSES), average="weighted", zero_division=0)), 4),
        "per_class": {
            name: {
                "precision": round(float(report[name]["precision"]), 4),
                "recall": round(float(report[name]["recall"]), 4),
                "f1": round(float(report[name]["f1-score"]), 4),
                "support": int(report[name]["support"]),
            }
            for name in CLASSES
        },
        "confusion_matrix": {
            "labels": list(CLASSES),
            "rows_are": "true class",
            "columns_are": "predicted class",
            "matrix": confusion_matrix(y_test, predicted, labels=list(CLASSES)).tolist(),
        },
    }
    return {
        "kind": MODEL_KIND,
        "model_version": MODEL_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "classes": list(CLASSES),
        "data_source": DATA_SOURCE,
        "model": model,
        "trained_at": trained_at.isoformat(),
        "training_metadata": {
            "model_type": MODEL_TYPE,
            "model_params": {
                "n_estimators": N_ESTIMATORS,
                "class_weight": CLASS_WEIGHT,
                "random_state": RANDOM_STATE,
            },
            "split": {"method": "stratified train_test_split", "test_size": TEST_SIZE, "random_state": RANDOM_STATE},
            "rows_total": dataset.rows_total,
            "rows_used": len(dataset),
            "rows_skipped": dict(dataset.skipped),
            "train_rows": int(len(y_train)),
            "test_rows": int(len(y_test)),
            "class_distribution": {
                "all": _distribution(dataset.labels),
                "train": _distribution(list(y_train)),
                "test": _distribution(list(y_test)),
            },
            "label_column": LABEL_COLUMN,
            "excluded_columns": dict(EXCLUDED_COLUMNS),
            "feature_importance": [{"feature": name, "importance": round(value, 4)} for name, value in importance],
            "evaluation": evaluation,
        },
    }


def is_compatible(bundle: Any) -> bool:
    if not isinstance(bundle, dict):
        return False
    if bundle.get("kind") != MODEL_KIND or bundle.get("model_version") != MODEL_VERSION:
        return False
    if list(bundle.get("feature_names") or []) != list(FEATURE_NAMES):
        return False
    model = bundle.get("model")
    if not isinstance(model, RandomForestClassifier) or getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        return False
    return sorted(str(name) for name in model.classes_) == sorted(CLASSES)


def feature_vector(session: Mapping[str, Any]) -> np.ndarray:
    values = []
    for name in FEATURE_NAMES:
        value = _number(session.get(name))
        if value is None:
            raise ValueError(f"Session feature '{name}' must be a finite number.")
        values.append(value)
    return np.asarray([values], dtype=float)


def predict(bundle: dict[str, Any], session: Mapping[str, Any]) -> dict[str, Any]:
    """Closest synthetic pattern for one session. Keys outside FEATURE_NAMES are ignored."""
    if not is_compatible(bundle):
        raise ValueError("Incompatible behavioral Random Forest bundle.")
    model: RandomForestClassifier = bundle["model"]
    vector = feature_vector(session)
    probabilities = model.predict_proba(vector)[0]
    ranked = sorted(zip((str(name) for name in model.classes_), probabilities), key=lambda item: -item[1])
    return {
        "predicted_pattern": ranked[0][0],
        "confidence": round(float(ranked[0][1]), 4),
        "probabilities": {name: round(float(value), 4) for name, value in ranked},
        "features": {name: float(vector[0][i]) for i, name in enumerate(FEATURE_NAMES)},
        "model_version": MODEL_VERSION,
        "data_source": DATA_SOURCE,
        "demonstration": DEMONSTRATION,
        "disclaimer": DISCLAIMER,
    }


def model_path(model_dir: str | Path) -> Path:
    return Path(model_dir) / MODEL_SUBDIR / MODEL_FILENAME


def save_bundle(bundle: dict[str, Any], path: Path) -> None:
    if joblib is None:  # pragma: no cover
        raise RuntimeError("joblib is required to persist the behavioral model.")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path: Path) -> dict[str, Any] | None:
    if joblib is None or not path.exists():
        return None
    try:
        bundle = joblib.load(path)
    except Exception:
        logger.exception("Failed to load the behavioral demonstration model")
        return None
    if not is_compatible(bundle):
        logger.warning("Ignoring incompatible behavioral demonstration model at %s", path)
        return None
    return bundle
