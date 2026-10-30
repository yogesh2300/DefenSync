"""Linux Isolation Forest: training, baseline-derived threshold and a Linux-only model file.

Input rows come only from backend.ml.linux_features (feature version linux-v1). The model
file lives under MODEL_DIR/linux/ and is never shared with Cloud, HPC or behavioral models,
nor with the hybrid bundle (MODEL_DIR/<owner>/hybrid_detection.joblib).

Score direction: anomaly_score = -IsolationForest.score_samples(x), so a higher score is
always more anomalous. An event is flagged when its anomaly score is strictly above the
99th percentile of the anomaly scores of the baseline the model was trained on. The
IsolationForest `contamination` parameter is left at "auto" and never used for flagging.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from backend.ml.linux_features import FEATURE_NAMES, FEATURE_VERSION, LinuxFeatureMatrix

logger = logging.getLogger(__name__)

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None

ENVIRONMENT = "LINUX"
MODEL_KIND = "linux_isolation_forest"
MODEL_TYPE = "sklearn.ensemble.IsolationForest"
MODEL_SUBDIR = "linux"
MODEL_FILENAME = "linux_detection.joblib"

MIN_IF_BASELINE = 100
MAX_BASELINE = 5000
N_ESTIMATORS = 200
RANDOM_STATE = 42
THRESHOLD_METHOD = "baseline_percentile"
THRESHOLD_PERCENTILE = 99.0
SCORE_DIRECTION = "anomaly_score = -IsolationForest.score_samples(x); higher is more anomalous"
BASELINE_SELECTION = (
    "All Linux-ML-eligible security events in the owner scope, chronological, most recent "
    f"{MAX_BASELINE}. No risk_score, severity, alert, detection or label filter."
)

STATUS_INSUFFICIENT = "insufficient_baseline"
STATUS_NOT_TRAINED = "not_trained"
STATUS_TRAINED = "trained"
STATUS_REUSED = "reused"
RF_STATUS = "no_valid_linux_labels"

DETECTION_ANOMALY = "linux_isolation_forest"
DETECTION_NORMAL = "linux_normal"
DETECTION_TYPES = (DETECTION_ANOMALY, DETECTION_NORMAL)


def model_path(model_dir: str | Path, owner_id: str | None) -> Path:
    return Path(model_dir) / MODEL_SUBDIR / (owner_id or "global") / MODEL_FILENAME


def anomaly_scores(model: IsolationForest, values: np.ndarray) -> np.ndarray:
    return -model.score_samples(values)


def train_bundle(
    matrix: LinuxFeatureMatrix,
    *,
    path: Path,
    trained_at: datetime | None = None,
) -> dict[str, Any]:
    """Fit on the most recent eligible rows and derive the flagging threshold from them."""
    if tuple(matrix.feature_names) != FEATURE_NAMES:
        raise ValueError("Feature matrix does not use the linux-v1 feature ordering.")
    eligible_count = int(matrix.values.shape[0])
    if eligible_count < MIN_IF_BASELINE:
        raise ValueError(f"Linux baseline needs at least {MIN_IF_BASELINE} eligible events (have {eligible_count}).")
    baseline = matrix.values[-MAX_BASELINE:]
    model = IsolationForest(n_estimators=N_ESTIMATORS, contamination="auto", random_state=RANDOM_STATE)
    model.fit(baseline)
    scores = anomaly_scores(model, baseline)
    threshold = float(np.percentile(scores, THRESHOLD_PERCENTILE))
    trained_at = trained_at or datetime.now(timezone.utc)
    metadata = {
        "environment": ENVIRONMENT,
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "eligible_count": eligible_count,
        "training_count": int(baseline.shape[0]),
        "training_time": trained_at.isoformat(),
        "model_type": MODEL_TYPE,
        "model_params": {
            "n_estimators": N_ESTIMATORS,
            "random_state": RANDOM_STATE,
            "contamination": "auto (not used for flagging)",
        },
        "threshold_method": THRESHOLD_METHOD,
        "threshold_percentile": THRESHOLD_PERCENTILE,
        "threshold_value": threshold,
        "score_direction": SCORE_DIRECTION,
        "baseline_score_min": float(scores.min()),
        "baseline_score_median": float(np.median(scores)),
        "baseline_score_max": float(scores.max()),
        "baseline_above_threshold": int((scores > threshold).sum()),
        "baseline_selection": BASELINE_SELECTION,
        "baseline_first_event_id": matrix.event_ids[-baseline.shape[0]],
        "baseline_last_event_id": matrix.event_ids[-1],
        "excluded": dict(matrix.excluded),
        "minimum_baseline": MIN_IF_BASELINE,
        "model_path": str(path),
        "random_forest_status": RF_STATUS,
    }
    return {
        "kind": MODEL_KIND,
        "environment": ENVIRONMENT,
        "feature_version": FEATURE_VERSION,
        "feature_names": list(FEATURE_NAMES),
        "model": model,
        "threshold": threshold,
        "trained_at": trained_at.isoformat(),
        "training_metadata": metadata,
    }


def is_compatible(bundle: Any) -> bool:
    """Only a Linux Isolation Forest bundle built from linux-v1 features is usable."""
    if not isinstance(bundle, dict):
        return False
    if bundle.get("kind") != MODEL_KIND or bundle.get("environment") != ENVIRONMENT:
        return False
    if bundle.get("feature_version") != FEATURE_VERSION or list(bundle.get("feature_names") or []) != list(FEATURE_NAMES):
        return False
    model = bundle.get("model")
    if not isinstance(model, IsolationForest) or getattr(model, "n_features_in_", None) != len(FEATURE_NAMES):
        return False
    threshold = bundle.get("threshold")
    return isinstance(threshold, float) and math.isfinite(threshold)


def save_bundle(bundle: dict[str, Any], path: Path) -> None:
    if joblib is None:  # pragma: no cover
        raise RuntimeError("joblib is required to persist the Linux model.")
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_bundle(path: Path) -> dict[str, Any] | None:
    """The stored Linux bundle, or None when it is missing, unreadable or incompatible."""
    if joblib is None or not path.exists():
        return None
    try:
        bundle = joblib.load(path)
    except Exception:
        logger.exception("Failed to load the Linux detection model")
        return None
    if not is_compatible(bundle):
        logger.warning("Ignoring incompatible Linux detection model at %s", path)
        return None
    return bundle
