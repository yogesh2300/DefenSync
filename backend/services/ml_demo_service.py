"""Dataset-only ML demonstrations: OpenStack Isolation Forest and synthetic behavioral Random Forest.

Both demonstrations read static files under DATASET_ROOT and persist their models under
MODEL_DIR/demo/. They never read or write the database, never touch the Azure, Linux or hybrid
detection models, and never share training data with each other.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Any, Mapping

from backend.core.config import PROJECT_ROOT, Settings, get_settings
from backend.core.logging import get_logger
from backend.ml import behavioral_random_forest as behavioral_rf
from backend.ml import openstack_features
from backend.ml import openstack_isolation_forest as openstack_if

logger = get_logger(__name__)

STATUS_NOT_TRAINED = "not_trained"
STATUS_TRAINED = "trained"
STATUS_STALE = "stale"
STATUS_DATASET_MISSING = "dataset_missing"

OPENSTACK_FILES = ("openstack_normal1.log", "openstack_normal2.log", "openstack_abnormal.log")
OPENSTACK_LABEL_FILE = "anomaly_labels.txt"
TOP_ANOMALIES = 10

_TRAIN_LOCK = threading.Lock()


class DemoDatasetMissing(FileNotFoundError):
    pass


def _resolve(path: str | Path) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else PROJECT_ROOT / candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_stamp(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {"name": path.name, "size_bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def _stamps_match(recorded: list[dict[str, Any]] | None, paths: list[Path]) -> bool:
    if not recorded or len(recorded) != len(paths):
        return False
    current = {item["name"]: item for item in (_file_stamp(path) for path in paths)}
    return all(
        current.get(item.get("name"), {}).get("size_bytes") == item.get("size_bytes")
        and current.get(item.get("name"), {}).get("mtime_ns") == item.get("mtime_ns")
        for item in recorded
    )


class OpenStackDemoService:
    """OpenStack cloud-API Isolation Forest demonstration (public dataset, not Azure, not live)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def raw_dir(self) -> Path:
        return _resolve(self._settings.DATASET_ROOT) / self._settings.OPENSTACK_DATASET_PATH / "raw"

    @property
    def model_file(self) -> Path:
        return openstack_if.model_path(_resolve(self._settings.MODEL_DIR))

    def _paths(self) -> list[Path]:
        paths = [self.raw_dir / name for name in OPENSTACK_FILES]
        missing = [path.name for path in paths if not path.is_file()]
        if missing:
            raise DemoDatasetMissing(f"OpenStack raw files not found: {', '.join(missing)}")
        return paths

    def _labelled_instances(self) -> list[str]:
        path = self.raw_dir / OPENSTACK_LABEL_FILE
        if not path.is_file():
            return []
        lines = (line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines())
        return [line.lower() for line in lines if len(line) == 36 and line.count("-") == 4]

    def _build_matrix(self, paths: list[Path]) -> tuple[openstack_features.OpenStackWindowMatrix, list[dict[str, Any]]]:
        records: list[openstack_features.OpenStackRecord] = []
        files = []
        for path in paths:
            stats = openstack_features.ParseStats()
            records.extend(openstack_features.iter_file(path, stats))
            files.append({**_file_stamp(path), "sha256": _sha256(path), **vars(stats)})
        return openstack_features.build_windows(records), files

    def train(self) -> dict[str, Any]:
        paths = self._paths()
        with _TRAIN_LOCK:
            matrix, files = self._build_matrix(paths)
            bundle = openstack_if.train_bundle(matrix)
            results = openstack_if.score_windows(bundle, matrix)
            evaluation = openstack_if.evaluate(results, matrix, self._labelled_instances())
            bundle["report"] = self._report_body(bundle, matrix, files, results, evaluation)
            openstack_if.save_bundle(bundle, self.model_file)
        logger.info(
            "OpenStack demo model trained: %d windows, %d anomalous",
            len(matrix), bundle["report"]["summary"]["anomalous_windows"],
        )
        return self._view(bundle, STATUS_TRAINED)

    def report(self) -> dict[str, Any]:
        try:
            paths = self._paths()
        except DemoDatasetMissing as exc:
            return self._empty(STATUS_DATASET_MISSING, str(exc))
        bundle = openstack_if.load_bundle(self.model_file)
        if bundle is None or "report" not in bundle:
            return self._empty(STATUS_NOT_TRAINED, "Train the OpenStack demonstration to see results.")
        stale = not _stamps_match(bundle["report"]["dataset"]["files"], paths)
        return self._view(bundle, STATUS_STALE if stale else STATUS_TRAINED)

    def _report_body(self, bundle, matrix, files, results, evaluation) -> dict[str, Any]:
        anomalous = [item for item in results if item["result"] == openstack_if.RESULT_ANOMALOUS]
        return {
            "dataset": {
                "path": f"{self._settings.OPENSTACK_DATASET_PATH}/raw",
                "files": files,
                "records_parsed": matrix.records,
                "windows_scored": len(matrix),
                "windows_excluded_partial": matrix.excluded_partial,
            },
            "summary": {
                "windows_scored": len(results),
                "anomalous_windows": len(anomalous),
                "normal_windows": len(results) - len(anomalous),
                "threshold": round(bundle["threshold"], 6),
            },
            "top_anomalies": sorted(anomalous, key=lambda item: -item["anomaly_score"])[:TOP_ANOMALIES],
            "window_scores": [
                {"window_start": item["window_start"], "anomaly_score": item["anomaly_score"], "result": item["result"]}
                for item in results
            ],
            "evaluation": evaluation,
        }

    def _base(self, status: str) -> dict[str, Any]:
        return {
            "demonstration": openstack_if.DEMONSTRATION,
            "data_source": openstack_if.DATA_SOURCE,
            "is_live": False,
            "is_azure": False,
            "disclaimer": openstack_if.DISCLAIMER,
            "question": "Is this cloud API behaviour unusual compared with the learned baseline?",
            "status": status,
            "model_version": openstack_if.MODEL_VERSION,
            "feature_version": openstack_features.FEATURE_VERSION,
            "aggregation_unit": openstack_features.AGGREGATION_UNIT,
            "feature_names": list(openstack_features.FEATURE_NAMES),
            "excluded_fields": dict(openstack_features.EXCLUDED_FIELDS),
        }

    def _empty(self, status: str, message: str) -> dict[str, Any]:
        return {**self._base(status), "message": message}

    def _view(self, bundle: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            **self._base(status),
            "trained_at": bundle["trained_at"],
            "model": bundle["training_metadata"],
            **bundle["report"],
        }


class BehavioralRfDemoService:
    """Synthetic behavioral-pattern Random Forest demonstration (generated data, not real telemetry)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    @property
    def dataset_file(self) -> Path:
        return (
            _resolve(self._settings.DATASET_ROOT)
            / self._settings.BEHAVIORAL_DATASET_PATH
            / behavioral_rf.DATASET_FILENAME
        )

    @property
    def model_file(self) -> Path:
        return behavioral_rf.model_path(_resolve(self._settings.MODEL_DIR))

    def _path(self) -> Path:
        path = self.dataset_file
        if not path.is_file():
            raise DemoDatasetMissing(f"Behavioral dataset not found: {path.name}")
        return path

    def train(self) -> dict[str, Any]:
        path = self._path()
        with _TRAIN_LOCK:
            dataset = behavioral_rf.load_dataset(path)
            bundle = behavioral_rf.train_and_evaluate(dataset)
            bundle["dataset"] = {
                "path": f"{self._settings.BEHAVIORAL_DATASET_PATH}/{path.name}",
                "files": [{**_file_stamp(path), "sha256": _sha256(path)}],
            }
            behavioral_rf.save_bundle(bundle, self.model_file)
        logger.info("Behavioral RF demo model trained on %d synthetic sessions", len(dataset))
        return self._view(bundle, STATUS_TRAINED)

    def _load(self) -> dict[str, Any] | None:
        bundle = behavioral_rf.load_bundle(self.model_file)
        return bundle if bundle is not None and "dataset" in bundle else None

    def report(self) -> dict[str, Any]:
        try:
            path = self._path()
        except DemoDatasetMissing as exc:
            return self._empty(STATUS_DATASET_MISSING, str(exc))
        bundle = self._load()
        if bundle is None:
            return self._empty(STATUS_NOT_TRAINED, "Train the behavioral demonstration to see results.")
        stale = not _stamps_match(bundle["dataset"]["files"], [path])
        return self._view(bundle, STATUS_STALE if stale else STATUS_TRAINED)

    def predict(self, session: Mapping[str, Any]) -> dict[str, Any]:
        bundle = self._load()
        if bundle is None:
            raise LookupError("The behavioral Random Forest demonstration has not been trained.")
        return behavioral_rf.predict(bundle, session)

    def _base(self, status: str) -> dict[str, Any]:
        return {
            "demonstration": behavioral_rf.DEMONSTRATION,
            "data_source": behavioral_rf.DATA_SOURCE,
            "is_live": False,
            "is_synthetic": True,
            "disclaimer": behavioral_rf.DISCLAIMER,
            "question": "What known behavioral pattern does this session most closely resemble?",
            "status": status,
            "model_version": behavioral_rf.MODEL_VERSION,
            "feature_names": list(behavioral_rf.FEATURE_NAMES),
            "classes": list(behavioral_rf.CLASSES),
            "excluded_columns": dict(behavioral_rf.EXCLUDED_COLUMNS),
        }

    def _empty(self, status: str, message: str) -> dict[str, Any]:
        return {**self._base(status), "message": message}

    def _view(self, bundle: dict[str, Any], status: str) -> dict[str, Any]:
        return {**self._base(status), "trained_at": bundle["trained_at"], "dataset": bundle["dataset"], "model": bundle["training_metadata"]}
