"""OpenStack Isolation Forest for the OpenStack ML demonstration (model version openstack-if-v1).

Input rows come only from backend.ml.openstack_features (feature version openstack-v1). The model
answers "is this cloud API behaviour unusual compared with the learned baseline?" for one time
window. It is unsupervised: it is fitted on every complete window from every capture, without
the abnormal-instance labels and without knowing which capture a window came from. It never
shares data or files with the Azure, Linux, HPC, behavioral or hybrid models, and its findings
are operational anomalies in OpenStack infrastructure, not evidence of account compromise.

Score direction: anomaly_score = -IsolationForest.score_samples(x); higher is more anomalous.
A window is anomalous when its score is strictly above the THRESHOLD_PERCENTILE of the training
scores. `contamination` stays "auto" and is never used for flagging.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.ml.openstack_features import (
    AGGREGATION_UNIT,
    EXCLUDED_FIELDS,
    FEATURE_NAMES,
    FEATURE_VERSION,
    OpenStackWindowMatrix,
)

logger = logging.getLogger(__name__)

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None

MODEL_KIND = "openstack_isolation_forest"
MODEL_VERSION = "openstack-if-v1"
MODEL_TYPE = "sklearn.ensemble.IsolationForest"
DATA_SOURCE = "OPENSTACK_PUBLIC_DATASET"
DEMONSTRATION = "OpenStack ML demonstration"
DISCLAIMER = (
    "OpenStack cloud-infrastructure/API telemetry from a public dataset. Not Azure telemetry and not "
    "live data. Anomalous windows indicate unusual API/VM behaviour, not account compromise."
)
MODEL_SUBDIR = "demo/openstack"
MODEL_FILENAME = "openstack_isolation_forest.joblib"

MIN_TRAINING_WINDOWS = 50
N_ESTIMATORS = 200
RANDOM_STATE = 42
THRESHOLD_PERCENTILE = 95.0
EVIDENCE_FEATURES = 5
SCORE_DIRECTION = "anomaly_score = -IsolationForest.score_samples(x); higher is more anomalous"
TRAINING_SELECTION = (
    "Every complete window from all three raw captures, unlabelled. No label, file, date, risk_score, "
    "severity, alert or detection filter."
)

RESULT_ANOMALOUS = "anomalous"
RESULT_NORMAL = "normal"


def model_path(model_dir: str | Path) -> Path:
    return Path(model_dir) / MODEL_SUBDIR / MODEL_FILENAME


def anomaly_scores(model: IsolationForest, values: np.ndarray) -> np.ndarray:
    return -model.score_samples(values)


def _robust_scale(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    median = np.median(values, axis=0)
    q75, q25 = np.percentile(values, [75, 25], axis=0)
    scale = (q75 - q25) / 1.349
    std = values.std(axis=0)
    scale = np.where(scale > 0, scale, np.where(std > 0, std, 1.0))
    return median, scale


def train_bundle(matrix: OpenStackWindowMatrix, *, trained_at: datetime | None = None) -> dict[str, Any]:
    if tuple(matrix.feature_names) != FEATURE_NAMES:
        raise ValueError("Feature matrix does not use the openstack-v1 feature ordering.")
    if len(matrix) < MIN_TRAINING_WINDOWS:
        raise ValueError(f"OpenStack baseline needs at least {MIN_TRAINING_WINDOWS} windows (have {len(matrix)}).")
    model = IsolationForest(n_estimators=N_ESTIMATORS, contamination="auto", random_state=RANDOM_STATE)
    model.fit(matrix.values)
    scores = anomaly_scores(model, matrix.values)
    threshold = float(np.percentile(scores, THRESHOLD_PERCENTILE))
    median, scale = _robust_scale(matrix.values)
    trained_at = trained_at or datetime.now(timezone.utc)
    return {
        "kind": MODEL_KIND,
        "model_version": MODEL_VERSION,
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "data_source": DATA_SOURCE,
        "model": model,
        "threshold": threshold,
        "baseline_median": median.tolist(),
        "baseline_scale": scale.tolist(),
        "trained_at": trained_at.isoformat(),
        "training_metadata": {
            "model_type": MODEL_TYPE,
            "model_params": {
                "n_estimators": N_ESTIMATORS,
                "random_state": RANDOM_STATE,
                "contamination": "auto (not used for flagging)",
            },
            "training_windows": len(matrix),
            "window_minutes": matrix.window_minutes,
            "excluded_partial_windows": matrix.excluded_partial,
            "aggregation_unit": AGGREGATION_UNIT,
            "training_selection": TRAINING_SELECTION,
            "threshold_method": "training_score_percentile",
            "threshold_percentile": THRESHOLD_PERCENTILE,
            "threshold_value": threshold,
            "score_direction": SCORE_DIRECTION,
            "training_score_min": float(scores.min()),
            "training_score_median": float(np.median(scores)),
            "training_score_max": float(scores.max()),
            "training_above_threshold": int((scores > threshold).sum()),
            "excluded_fields": dict(EXCLUDED_FIELDS),
        },
    }


def is_compatible(bundle: Any) -> bool:
    if not isinstance(bundle, dict):
        return False
    if bundle.get("kind") != MODEL_KIND or bundle.get("model_version") != MODEL_VERSION:
        return False
    if bundle.get("feature_version") != FEATURE_VERSION or list(bundle.get("feature_names") or []) != list(FEATURE_NAMES):
        return False
    model = bundle.get("model")
    if not isinstance(model, IsolationForest) or getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        return False
    threshold = bundle.get("threshold")
    return isinstance(threshold, float) and math.isfinite(threshold)


def _evidence(row: np.ndarray, median: np.ndarray, scale: np.ndarray) -> list[dict[str, Any]]:
    deviation = (row - median) / scale
    order = np.argsort(-np.abs(deviation))[:EVIDENCE_FEATURES]
    return [
        {
            "feature": FEATURE_NAMES[index],
            "value": round(float(row[index]), 4),
            "baseline_median": round(float(median[index]), 4),
            "robust_z": round(float(deviation[index]), 2),
            "direction": "above" if deviation[index] > 0 else "below",
        }
        for index in order
        if deviation[index] != 0
    ]


def score_windows(bundle: dict[str, Any], matrix: OpenStackWindowMatrix) -> list[dict[str, Any]]:
    """One result per window: score, normal/anomalous result, feature values and evidence."""
    if not is_compatible(bundle):
        raise ValueError("Incompatible OpenStack Isolation Forest bundle.")
    if len(matrix) == 0:
        return []
    scores = anomaly_scores(bundle["model"], matrix.values)
    threshold = bundle["threshold"]
    median = np.asarray(bundle["baseline_median"], dtype=float)
    scale = np.asarray(bundle["baseline_scale"], dtype=float)
    span = timedelta(minutes=matrix.window_minutes)
    results = []
    for index, start in enumerate(matrix.window_starts):
        row = matrix.values[index]
        anomalous = bool(scores[index] > threshold)
        results.append({
            "window_start": start.isoformat(),
            "window_end": (start + span).isoformat(),
            "anomaly_score": round(float(scores[index]), 6),
            "threshold": round(threshold, 6),
            "result": RESULT_ANOMALOUS if anomalous else RESULT_NORMAL,
            "features": {name: round(float(row[i]), 4) for i, name in enumerate(FEATURE_NAMES)},
            "evidence": _evidence(row, median, scale) if anomalous else [],
            "model_version": MODEL_VERSION,
            "feature_version": FEATURE_VERSION,
            "data_source": DATA_SOURCE,
        })
    return results


def evaluate(
    results: list[dict[str, Any]],
    matrix: OpenStackWindowMatrix,
    labelled_instances: Iterable[str],
) -> dict[str, Any]:
    """Post-hoc comparison with the dataset's abnormal-instance list. Never feeds training."""
    labelled = {value.lower() for value in labelled_instances}
    is_labelled = np.array([bool(instances & labelled) for instances in matrix.window_instances], dtype=bool)
    flagged = np.array([item["result"] == RESULT_ANOMALOUS for item in results], dtype=bool)
    scores = np.array([item["anomaly_score"] for item in results], dtype=float)
    labelled_count = int(is_labelled.sum())
    flagged_labelled = int((flagged & is_labelled).sum())
    flagged_total = int(flagged.sum())
    percentiles = [
        round(float((scores < scores[index]).mean() * 100), 1) for index in np.flatnonzero(is_labelled)
    ]
    return {
        "purpose": "Post-hoc check only. Labels were not used for features, training or the threshold.",
        "labelled_instances": len(labelled),
        "windows_total": len(results),
        "windows_with_labelled_instances": labelled_count,
        "flagged_windows": flagged_total,
        "flagged_with_labelled_instances": flagged_labelled,
        "labelled_window_recall": round(flagged_labelled / labelled_count, 4) if labelled_count else None,
        "flagged_window_precision": round(flagged_labelled / flagged_total, 4) if flagged_total else None,
        "labelled_window_score_percentiles": percentiles,
    }


def save_bundle(bundle: dict[str, Any], path: Path) -> None:
    if joblib is None:  # pragma: no cover
        raise RuntimeError("joblib is required to persist the OpenStack model.")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path: Path) -> dict[str, Any] | None:
    if joblib is None or not path.exists():
        return None
    try:
        bundle = joblib.load(path)
    except Exception:
        logger.exception("Failed to load the OpenStack demonstration model")
        return None
    if not is_compatible(bundle):
        logger.warning("Ignoring incompatible OpenStack demonstration model at %s", path)
        return None
    return bundle
