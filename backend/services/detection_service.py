"""Hybrid Isolation Forest + Random Forest detection with persisted models."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.environments import BEHAVIORAL, CLOUD, HPC, LINUX, SOURCE_FAMILIES, source_family, source_types_for_family
from backend.database.models import DATA_SCOPE_PRIVATE, PRESENTATION_DATA_ORIGIN, MLPrediction, SecurityEvent
from backend.ml import linux_isolation_forest as linux_if
from backend.ml.linux_features import FEATURE_NAMES as LINUX_FEATURE_NAMES
from backend.ml.linux_features import FEATURE_VERSION as LINUX_FEATURE_VERSION
from backend.ml.linux_features import LinuxFeatureMatrix, build_feature_matrix
from backend.services.alert_service import AlertService

logger = logging.getLogger(__name__)

try:
    import joblib
except ImportError:  # pragma: no cover
    joblib = None

# v3: source-family one-hot; no server identity in the feature vector.
# New Linux servers must not change RF ground truth or inject unseen server hashes.
FEATURE_VERSION = "v3"
MIN_IF_BASELINE = 100
MIN_ISO_BASELINE = MIN_IF_BASELINE
MAX_IF_BASELINE = 2000
MIN_SCORED_EVENTS = 10
MIN_RF_LABELED = 10
RF_MAX_POSITIVE = 400
RF_MAX_NEGATIVE = 1600
EXCLUDED_RF_ORIGINS = {"SYNTHETIC_CLOUD_DEMO", "SYNTHETIC"}
# Linux has its own pipeline (backend.ml.linux_features / linux_isolation_forest). The hybrid
# path below never scores Linux events, never fits a Linux model and never applies its
# Random Forest to Linux events.
HYBRID_FAMILIES = tuple(family for family in SOURCE_FAMILIES if family != LINUX)
LINUX_SOURCE_TYPES = source_types_for_family(LINUX)
LINUX_SCORING_WINDOW = 2000
LINUX_ROW_COLUMNS = (
    SecurityEvent.event_id,
    SecurityEvent.server_id,
    SecurityEvent.hostname,
    SecurityEvent.source_type,
    SecurityEvent.data_origin,
    SecurityEvent.timestamp_source,
    SecurityEvent.event_type,
    SecurityEvent.timestamp,
    SecurityEvent.username,
    SecurityEvent.source_ip,
    SecurityEvent.raw_log,
    SecurityEvent.message,
    SecurityEvent.normalized_data,
)

FEATURE_NAMES = [
    "login_hour",
    "session_duration",
    "failed_login_count",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "commands_executed",
    "network_connections",
    "severity",
    "suspicious_type",
    "failed_login_flag",
    "root_flag",
    "remote_ip",
    "failure_flag",
    "source_linux",
    "source_cloud",
    "source_hpc",
    "source_behavioral",
    "event_type_code",
    "has_resource",
    "has_actor",
]
SUSPICIOUS_TYPES = {
    "Failed Login",
    "Invalid User",
    "User Creation",
    "Sudo Command",
    "CLOUD_AUTHORIZATION_FAILURE",
    "CLOUD_LOGIN_FAILURE",
    "CLOUD_API_FAILURE",
    "HDFS_EXCEPTION",
    "HDFS_ERROR",
    "HPC_KERNEL_FAILURE",
    "HPC_APP_FAILURE",
    "HPC_ERROR",
    "HPC_FAILURE",
}
POSITIVE_LABELS = {"ANOMALOUS", "ABNORMAL", "MALICIOUS", "SUSPICIOUS", "ATTACK"}
NEGATIVE_LABELS = {"NORMAL", "BENIGN"}
SEVERITY_MAP = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "error": 3, "warning": 2}


class DetectionService:
    """Hybrid detection: rule alerts + Isolation Forest + optional labeled Random Forest."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._alert_service = AlertService(session)
        self._settings = get_settings()

    def _load_events(
        self,
        limit: int = 2000,
        server_id: str | None = None,
        owner_id: str | None = None,
        account_id: str | None = None,
        *,
        exclude_linux: bool = False,
    ) -> list[SecurityEvent]:
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.data_scope == DATA_SCOPE_PRIVATE, SecurityEvent.data_origin != PRESENTATION_DATA_ORIGIN)
            .order_by(SecurityEvent.timestamp.desc())
            .limit(limit)
        )
        if exclude_linux:
            stmt = stmt.where(func.upper(SecurityEvent.source_type).notin_(LINUX_SOURCE_TYPES))
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        if account_id:
            stmt = stmt.where(SecurityEvent.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        elif not server_id:
            return []
        events = list(reversed(self._session.scalars(stmt).all()))
        if exclude_linux:
            events = [event for event in events if self._source_family_name(event.source_type) != LINUX]
        return events

    def _load_labeled_training_rows(
        self,
        *,
        owner_id: str | None = None,
        max_positive: int = RF_MAX_POSITIVE,
        max_negative: int = RF_MAX_NEGATIVE,
    ) -> list[SecurityEvent]:
        """Deterministic labeled pool for RF from original_label only.

        RF ground truth is the stable PUBLIC_DATASET repository (OpenStack,
        HDFS, and BGL only when native labels are in POSITIVE_LABELS /
        NEGATIVE_LABELS). Synthetic demo/behavioral origins are excluded.

        Ordering is timestamp ASC, event_id ASC so the capped pool is stable
        across application runs (not a random subsample).

        New LIVE_LINUX servers do not invalidate or retrain RF. server_id is
        not used to select RF rows: a Linux host is application context, not
        supervised class membership. risk_score, Isolation Forest output,
        rule alerts, and behavioral labels are never RF targets.

        Identical 21-feature vectors are retained as separate observations.
        Only genuine event_id / source-hash duplicates are dropped.
        """
        def _fetch(labels: set[str], limit: int) -> list[SecurityEvent]:
            clauses = [
                func.upper(SecurityEvent.original_label).in_(tuple(labels)),
                or_(SecurityEvent.data_origin.is_(None), SecurityEvent.data_origin.notin_(tuple(EXCLUDED_RF_ORIGINS))),
            ]
            origin_ok = SecurityEvent.data_origin == "PUBLIC_DATASET"
            if owner_id:
                clauses.append(or_(SecurityEvent.owner_id == owner_id, origin_ok))
            else:
                clauses.append(origin_ok)
            stmt = (
                select(SecurityEvent)
                .where(*clauses)
                .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.event_id.asc())
                .limit(limit)
            )
            return list(self._session.scalars(stmt).all())

        positives = _fetch(POSITIVE_LABELS, max_positive)
        negatives = _fetch(NEGATIVE_LABELS, max_negative)
        return self._dedupe_labeled(positives + negatives)

    @staticmethod
    def _dedupe_labeled(events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Drop genuine duplicate source records, not identical feature vectors.

        Two labeled events may share the same 21-feature vector and remain
        separate RF observations. event_id and the stored event hash identify
        the same imported record appearing twice.
        """
        seen_ids: set[str] = set()
        seen_hashes: set[str] = set()
        unique: list[SecurityEvent] = []
        for event in events:
            event_id = getattr(event, "event_id", None)
            if event_id and event_id in seen_ids:
                continue
            event_hash = getattr(event, "hash", None)
            if event_hash and event_hash in seen_hashes:
                continue
            if event_id:
                seen_ids.add(event_id)
            if event_hash:
                seen_hashes.add(event_hash)
            unique.append(event)
        return unique

    @staticmethod
    def _source_onehot(source_type: str | None) -> list[float]:
        """Categorical one-hot source family. Values are not ordinal."""
        family = source_family(source_type)
        return [
            1.0 if family == LINUX else 0.0,
            1.0 if family == CLOUD else 0.0,
            1.0 if family == HPC else 0.0,
            1.0 if family == BEHAVIORAL else 0.0,
        ]

    @staticmethod
    def _source_family_name(source_type: str | None) -> str:
        return source_family(source_type)

    @classmethod
    def _row(cls, event: SecurityEvent) -> list[float]:
        ts = event.timestamp
        if ts is not None and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        login_hour = float(getattr(event, "login_hour", None) if getattr(event, "login_hour", None) is not None else (ts.hour if ts else 0))
        event_type = event.event_type or ""
        severity_key = (event.severity or "").lower()
        source_type = getattr(event, "source_type", None) or "LINUX"
        failure_tokens = ("FAIL", "ERROR", "EXCEPTION", "FATAL")
        linux_login_fail = event_type == "Failed Login"
        return [
            login_hour,
            float(getattr(event, "session_duration", 0) or getattr(event, "session_duration_minutes", 0) or 0),
            float(getattr(event, "failed_login_count", 0) or 0),
            float(getattr(event, "cpu_usage", 0) or 0),
            float(getattr(event, "memory_usage", 0) or 0),
            float(getattr(event, "disk_usage", 0) or 0),
            float(getattr(event, "commands_executed", 0) or 0),
            float(getattr(event, "network_connections", 0) or 0),
            float(SEVERITY_MAP.get(severity_key, 0)),
            1.0 if event_type in SUSPICIOUS_TYPES else 0.0,
            1.0 if linux_login_fail or event_type == "CLOUD_LOGIN_FAILURE" else 0.0,
            1.0 if event.username and event.username.lower() == "root" else 0.0,
            1.0 if event.source_ip and not str(event.source_ip).startswith("127.") else 0.0,
            1.0 if severity_key in {"high", "critical", "error"} or any(token in event_type.upper() for token in failure_tokens) else 0.0,
            *cls._source_onehot(source_type),
            cls._event_type_code(event_type),
            1.0 if getattr(event, "resource_id", None) else 0.0,
            1.0 if (getattr(event, "actor_id", None) or event.username) else 0.0,
        ]

    @staticmethod
    def _event_type_code(value: str | None) -> float:
        """Deterministic categorical encoding of event_type.

        This is a hashed category token, not an ordinal ranking of event types.
        Nearby numeric values do not imply similar event semantics.
        """
        if not value:
            return 0.0
        digest = hashlib.md5(value.encode("utf-8"), usedforsecurity=False).digest()
        return int.from_bytes(digest[:2], "big") / 65535.0

    @classmethod
    def _features(cls, events: list[SecurityEvent]) -> np.ndarray:
        return np.array([cls._row(event) for event in events], dtype=float)

    @staticmethod
    def _supervised_label(event: SecurityEvent) -> int | None:
        label = (event.original_label or "").strip().upper()
        if label in POSITIVE_LABELS:
            return 1
        if label in NEGATIVE_LABELS:
            return 0
        return None

    def _load_if_baseline_events(
        self,
        *,
        source_type: str,
        owner_id: str | None = None,
        max_events: int = MAX_IF_BASELINE,
    ) -> list[SecurityEvent]:
        """Load a source-family Isolation Forest baseline, independent of scoring.

        Scoring uses `_load_events()` (typically the latest 2000 mixed events).
        This query pulls eligible normal observations for one source family from
        the current database and is not limited to that scoring window.

        LINUX is not served here: its baseline is the eligible Linux security
        events of backend.ml.linux_features, selected without risk_score.

        Priority: original_label NORMAL/BENIGN, then unlabeled risk_score < 40.
        Known positive original_label values never enter the baseline.
        Isolation Forest predictions and rule-derived labels are not used.
        Ordering is timestamp ASC, event_id ASC (deterministic).
        """
        family = self._source_family_name(source_type)
        if family == LINUX:
            return []
        labeled_clauses = [
            func.upper(SecurityEvent.original_label).in_(tuple(NEGATIVE_LABELS)),
            func.upper(SecurityEvent.source_type).in_(source_types_for_family(family)),
        ]
        if owner_id:
            labeled_clauses.append(
                or_(SecurityEvent.owner_id == owner_id, SecurityEvent.data_origin == "PUBLIC_DATASET")
            )
        labeled_stmt = (
            select(SecurityEvent)
            .where(*labeled_clauses)
            .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.event_id.asc())
            .limit(max_events)
        )
        labeled_normal = list(self._session.scalars(labeled_stmt).all())
        labeled_normal = [event for event in labeled_normal if self._source_family_name(event.source_type) == family]
        if len(labeled_normal) >= max_events:
            return labeled_normal

        loaded_ids = {event.event_id for event in labeled_normal if getattr(event, "event_id", None)}
        unlabeled_clauses = [
            SecurityEvent.original_label.is_(None),
            SecurityEvent.risk_score < 40,
            func.upper(SecurityEvent.source_type).in_(source_types_for_family(family)),
            SecurityEvent.data_origin != PRESENTATION_DATA_ORIGIN,
        ]
        if owner_id:
            unlabeled_clauses.append(SecurityEvent.owner_id == owner_id)
        unlabeled_stmt = (
            select(SecurityEvent)
            .where(*unlabeled_clauses)
            .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.event_id.asc())
            .limit(max_events)
        )
        unlabeled: list[SecurityEvent] = []
        for event in self._session.scalars(unlabeled_stmt).all():
            if event.event_id in loaded_ids:
                continue
            if self._source_family_name(event.source_type) != family:
                continue
            if self._supervised_label(event) == 1:
                continue
            unlabeled.append(event)
            if len(labeled_normal) + len(unlabeled) >= max_events:
                break
        return labeled_normal + unlabeled

    def _fit_isolation_forests_by_source(self, *, owner_id: str | None = None) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
        """Fit one Isolation Forest per non-Linux source family with a sufficient baseline.

        Families below MIN_IF_BASELINE are recorded as insufficient_baseline and
        are not fitted. No cross-family substitution is performed. LINUX is
        recorded as separate_linux_pipeline and never fitted here.
        """
        models: dict[str, Any] = {}
        meta: dict[str, dict[str, Any]] = {
            LINUX: {
                "baseline_events": 0,
                "status": "separate_linux_pipeline",
                "iso_normal_labeled_count": 0,
                "iso_low_risk_unlabeled_count": 0,
                "source_families": [],
            }
        }
        for family in HYBRID_FAMILIES:
            baseline = self._load_if_baseline_events(source_type=family, owner_id=owner_id)
            labeled_n, unlabeled_n = self._if_baseline_composition(baseline)
            families_present = sorted({self._source_family_name(event.source_type) for event in baseline})
            if len(baseline) < MIN_IF_BASELINE:
                meta[family] = {
                    "baseline_events": len(baseline),
                    "status": "insufficient_baseline",
                    "iso_normal_labeled_count": labeled_n,
                    "iso_low_risk_unlabeled_count": unlabeled_n,
                    "source_families": families_present,
                }
                continue
            iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
            iso.fit(self._features(baseline))
            models[family] = iso
            meta[family] = {
                "baseline_events": len(baseline),
                "status": "trained",
                "iso_normal_labeled_count": labeled_n,
                "iso_low_risk_unlabeled_count": unlabeled_n,
                "source_families": families_present,
            }
        return models, meta

    @classmethod
    def _score_with_source_if(
        cls,
        events: list[SecurityEvent],
        iso_by_source: dict[str, Any] | None,
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Score each event with the Isolation Forest trained on the same source family.

        If that family has no model, no anomaly is fabricated; the event is marked
        isolation_forest unavailable and left to rules / Random Forest.
        """
        n = len(events)
        flags = np.zeros(n, dtype=bool)
        scores = np.zeros(n, dtype=float)
        availability = ["insufficient_baseline"] * n
        models = iso_by_source or {}
        for family, iso in models.items():
            if iso is None or family == LINUX:
                continue
            indexes = [i for i, event in enumerate(events) if cls._source_family_name(event.source_type) == family]
            if not indexes:
                continue
            subset = [events[i] for i in indexes]
            predicted = iso.predict(cls._features(subset)) == -1
            sampled = -iso.score_samples(cls._features(subset))
            for offset, idx in enumerate(indexes):
                flags[idx] = bool(predicted[offset])
                scores[idx] = float(sampled[offset])
                availability[idx] = "trained"
        return flags, scores, availability

    @staticmethod
    def _iso_models_from_bundle(bundle: dict[str, Any] | None) -> dict[str, Any]:
        if not bundle:
            return {}
        forests = bundle.get("isolation_forests")
        if not isinstance(forests, dict):
            return {}
        # A Linux forest in a hybrid bundle comes from the retired generic Linux path and is never used.
        return {family: model for family, model in forests.items() if model is not None and family != LINUX}

    @staticmethod
    def _if_baseline_composition(events: list[SecurityEvent]) -> tuple[int, int]:
        labeled = sum(1 for event in events if DetectionService._supervised_label(event) == 0)
        unlabeled = sum(1 for event in events if DetectionService._supervised_label(event) is None)
        return labeled, unlabeled

    def _model_dir(self, owner_id: str | None) -> Path:
        root = Path(self._settings.MODEL_DIR)
        path = root / (owner_id or "global")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _save_bundle(self, owner_id: str | None, bundle: dict[str, Any]) -> None:
        if joblib is None:
            return
        joblib.dump(bundle, self._model_dir(owner_id) / "hybrid_detection.joblib")

    def _load_bundle(self, owner_id: str | None) -> dict[str, Any] | None:
        if joblib is None:
            return None
        path = self._model_dir(owner_id) / "hybrid_detection.joblib"
        if not path.exists():
            return None
        try:
            return joblib.load(path)
        except Exception:
            logger.exception("Failed to load persisted detection models")
            return None

    def _compatible_bundle(self, bundle: dict[str, Any] | None) -> dict[str, Any] | None:
        if not bundle:
            return None
        names = list(bundle.get("feature_names") or [])
        if names != FEATURE_NAMES:
            logger.warning("Ignoring persisted detection bundle: feature_names mismatch")
            return None
        if bundle.get("feature_version") != FEATURE_VERSION:
            logger.warning("Ignoring persisted detection bundle: feature_version mismatch")
            return None
        forests = DetectionService._iso_models_from_bundle(bundle)
        if not forests:
            logger.warning("Ignoring persisted detection bundle: no source-family Isolation Forest models")
            return None
        return bundle

    def _train_random_forest(
        self,
        labeled_events: list[SecurityEvent],
        score_features: np.ndarray,
    ) -> tuple[Any, np.ndarray, str, dict[str, Any] | None, dict[str, float] | None, int, int]:
        rf_suspicious = np.zeros(len(score_features), dtype=bool)
        labeled = [
            (event, self._supervised_label(event))
            for event in labeled_events
            if self._supervised_label(event) is not None
        ]
        unique_labels = {label for _, label in labeled}
        if len(labeled) < MIN_RF_LABELED or unique_labels != {0, 1}:
            return None, rf_suspicious, "no_valid_labels", None, None, 0, 0

        y = np.array([label for _, label in labeled], dtype=int)
        x = self._features([event for event, _ in labeled])
        positive_count = int(y.sum())
        negative_count = int(len(y) - positive_count)
        rf = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=6)
        evaluation: dict[str, Any]
        can_holdout = positive_count >= 2 and negative_count >= 2
        if can_holdout:
            try:
                x_train, x_test, y_train, y_test = train_test_split(
                    x, y, test_size=0.3, random_state=42, stratify=y,
                )
            except ValueError:
                x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3, random_state=42)
            rf.fit(x_train, y_train)
            test_classes = set(int(value) for value in np.unique(y_test))
            if test_classes == {0, 1}:
                y_pred = rf.predict(x_test)
                evaluation = {
                    "dataset": "original_label stratified hold-out (30%) from PUBLIC_DATASET + owner labeled rows",
                    "rf_training_source": "PUBLIC_DATASET",
                    "samples_labeled": int(len(y)),
                    "train_size": int(len(y_train)),
                    "test_size": int(len(y_test)),
                    "positive_count": positive_count,
                    "negative_count": negative_count,
                    "positive_samples": positive_count,
                    "negative_samples": negative_count,
                    "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
                    "precision": round(float(precision_score(y_test, y_pred, zero_division=0)), 4),
                    "recall": round(float(recall_score(y_test, y_pred, zero_division=0)), 4),
                    "f1": round(float(f1_score(y_test, y_pred, zero_division=0)), 4),
                    "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
                    "note": "Metrics are computed only on the labeled hold-out split. original_label is the sole RF target; risk_score, ISO output, and behavioral labels are not used as ground truth.",
                }
            else:
                evaluation = {
                    "dataset": "original_label stratified hold-out (30%) from PUBLIC_DATASET + owner labeled rows",
                    "rf_training_source": "PUBLIC_DATASET",
                    "samples_labeled": int(len(y)),
                    "train_size": int(len(y_train)),
                    "test_size": int(len(y_test)),
                    "positive_count": positive_count,
                    "negative_count": negative_count,
                    "positive_samples": positive_count,
                    "negative_samples": negative_count,
                    "limitation": "Hold-out test set did not contain both classes; classification metrics are omitted.",
                }
        else:
            rf.fit(x, y)
            evaluation = {
                "dataset": "original_label pool without hold-out",
                "rf_training_source": "PUBLIC_DATASET",
                "samples_labeled": int(len(y)),
                "train_size": int(len(y)),
                "test_size": 0,
                "positive_count": positive_count,
                "negative_count": negative_count,
                "positive_samples": positive_count,
                "negative_samples": negative_count,
                "limitation": "Not enough samples in both classes for a 70/30 stratified hold-out. Metrics omitted to avoid training-set leakage.",
            }
        rf_suspicious = rf.predict(score_features) == 1
        feature_importance = {
            name: round(float(value), 4)
            for name, value in zip(FEATURE_NAMES, rf.feature_importances_)
        }
        return rf, rf_suspicious, "trained", evaluation, feature_importance, positive_count, negative_count

    def run_detection(self, *, owner_id: str | None = None, server_id: str | None = None, account_id: str | None = None) -> dict[str, Any]:
        rule_created = self._alert_service.sync_from_events(owner_id=owner_id)
        linux = self._run_linux_detection(owner_id=owner_id, server_id=server_id, account_id=account_id)
        events = self._load_events(owner_id=owner_id, server_id=server_id, account_id=account_id, exclude_linux=True)
        result = self._run_hybrid_detection(
            events, rule_created=rule_created, owner_id=owner_id, server_id=server_id, account_id=account_id,
        )
        result["linux"] = linux
        result["events_analyzed"] = int(result.get("events_analyzed") or 0) + linux["scored_count"]
        result["ml_anomalies"] = int(result.get("ml_anomalies") or 0) + linux["anomaly_count"]
        result["predictions_stored"] = int(result.get("predictions_stored") or 0) + linux["scored_count"]
        if "total_flagged" in result:
            result["total_flagged"] = int(result.get("total_flagged") or 0) + linux["anomaly_count"]
        result["message"] = f"{linux['message']} Cloud/HPC/behavioral: {result.get('message', '')}".strip()
        return result

    def _run_hybrid_detection(
        self,
        events: list[SecurityEvent],
        *,
        rule_created: int,
        owner_id: str | None = None,
        server_id: str | None = None,
        account_id: str | None = None,
    ) -> dict[str, Any]:
        """Cloud / HPC / behavioral detection with the hybrid bundle; never receives Linux events."""
        trained_at = datetime.now(timezone.utc).isoformat()
        if len(events) < MIN_SCORED_EVENTS:
            return {
                "success": True,
                "events_analyzed": len(events),
                "rule_alerts_created": rule_created,
                "ml_anomalies": 0,
                "ml_classified_suspicious": 0,
                "normal": len([e for e in events if e.risk_score < 70]),
                "suspicious": len([e for e in events if 70 <= e.risk_score < 85]),
                "malicious": len([e for e in events if e.risk_score >= 85]),
                "predictions_stored": 0,
                "isolation_forest": "insufficient_events",
                "random_forest": "unavailable",
                "evaluation": None,
                "trained_at": trained_at,
                "model_action": "skipped",
                "feature_version": FEATURE_VERSION,
                "message": f"Detection skipped: need at least {MIN_SCORED_EVENTS} events (current: {len(events)}). Rule-based alerts synced.",
            }

        features = self._features(events)
        existing = self._compatible_bundle(self._load_bundle(owner_id))
        model_action = "reused" if existing else "trained"
        iso_by_source: dict[str, Any] = {}
        iso_availability: list[str] = []
        iso_status = "not_trained"
        iso_eval = None
        evaluation: dict[str, Any] | None = None
        feature_importance: dict[str, float] | None = None
        rf = None
        rf_status = "unavailable"
        training_metadata: dict[str, Any]

        if existing:
            iso_by_source = self._iso_models_from_bundle(existing)
            iso_status = "trained"
            anomaly_flags, anomaly_scores, iso_availability = self._score_with_source_if(events, iso_by_source)
            rf = existing.get("random_forest")
            rf_status = existing.get("rf_status") or ("trained" if rf is not None else "no_valid_labels")
            evaluation = (existing.get("evaluation") or {}).get("random_forest")
            iso_eval = (existing.get("evaluation") or {}).get("isolation_forest")
            feature_importance = existing.get("feature_importance")
            trained_at = existing.get("trained_at") or trained_at
            training_metadata = existing.get("training_metadata") or {"feature_version": FEATURE_VERSION}
            if rf is not None and rf_status == "trained":
                rf_suspicious = rf.predict(features) == 1
            else:
                rf_suspicious = np.zeros(len(events), dtype=bool)
                rf = None
        else:
            iso_by_source, iso_models_by_source = self._fit_isolation_forests_by_source(owner_id=owner_id)
            if not iso_by_source:
                total_baseline = sum(int(row.get("baseline_events") or 0) for row in iso_models_by_source.values())
                return {
                    "success": True,
                    "events_analyzed": len(events),
                    "rule_alerts_created": rule_created,
                    "ml_anomalies": 0,
                    "ml_classified_suspicious": 0,
                    "normal": len([e for e in events if e.risk_score < 70]),
                    "suspicious": len([e for e in events if 70 <= e.risk_score < 85]),
                    "malicious": len([e for e in events if e.risk_score >= 85]),
                    "predictions_stored": 0,
                    "isolation_forest": "insufficient_baseline",
                    "random_forest": "unavailable",
                    "evaluation": None,
                    "trained_at": trained_at,
                    "model_action": "skipped",
                    "feature_version": FEATURE_VERSION,
                    "training_metadata": {
                        "feature_version": FEATURE_VERSION,
                        "feature_count": len(FEATURE_NAMES),
                        "iso_baseline_events": total_baseline,
                        "iso_training_scope": "source_family_baseline",
                        "iso_models_by_source": iso_models_by_source,
                    },
                    "message": (
                        f"Isolation Forest baseline needs at least {MIN_IF_BASELINE} "
                        "source-compatible NORMAL/BENIGN or low-risk unlabeled events per source family."
                    ),
                }
            iso_status = "trained"
            anomaly_flags, anomaly_scores, iso_availability = self._score_with_source_if(events, iso_by_source)
            labeled_events = self._load_labeled_training_rows(owner_id=owner_id)
            rf, rf_suspicious, rf_status, evaluation, feature_importance, pos_count, neg_count = self._train_random_forest(
                labeled_events, features
            )
            scoring_labeled = [(i, self._supervised_label(event)) for i, event in enumerate(events) if self._supervised_label(event) is not None]
            if scoring_labeled:
                y_true = np.array([label for _, label in scoring_labeled], dtype=int)
                y_iso = np.array([1 if anomaly_flags[i] else 0 for i, _ in scoring_labeled], dtype=int)
                iso_eval = {
                    "mapping": "IsolationForest -1 compared to original_label where labels exist on the scoring window",
                    "note": "This is an unsupervised comparison, not Isolation Forest training. original_label is never an ISO target. Each event is scored only by its source-family model.",
                    "accuracy": round(float(accuracy_score(y_true, y_iso)), 4),
                    "precision": round(float(precision_score(y_true, y_iso, zero_division=0)), 4),
                    "recall": round(float(recall_score(y_true, y_iso, zero_division=0)), 4),
                    "f1": round(float(f1_score(y_true, y_iso, zero_division=0)), 4),
                }
            trained_baselines = [row["baseline_events"] for row in iso_models_by_source.values() if row.get("status") == "trained"]
            labeled_total = sum(int(row.get("iso_normal_labeled_count") or 0) for row in iso_models_by_source.values())
            unlabeled_total = sum(int(row.get("iso_low_risk_unlabeled_count") or 0) for row in iso_models_by_source.values())
            training_metadata = {
                "feature_version": FEATURE_VERSION,
                "feature_count": len(FEATURE_NAMES),
                "rf_training_source": "PUBLIC_DATASET",
                "rf_training_events": 0 if rf is None else int((evaluation or {}).get("samples_labeled") or 0),
                "rf_positive_samples": pos_count,
                "rf_negative_samples": neg_count,
                "iso_baseline_events": int(sum(trained_baselines)),
                "iso_training_scope": "source_family_baseline",
                "iso_normal_labeled_count": labeled_total,
                "iso_low_risk_unlabeled_count": unlabeled_total,
                "iso_models_by_source": iso_models_by_source,
            }
            bundle = {
                "isolation_forests": {family: iso_by_source.get(family) for family in SOURCE_FAMILIES},
                "random_forest": rf,
                "feature_names": FEATURE_NAMES,
                "feature_version": FEATURE_VERSION,
                "trained_at": trained_at,
                "evaluation": {"random_forest": evaluation, "isolation_forest": iso_eval},
                "feature_importance": feature_importance,
                "rf_status": rf_status,
                "training_metadata": training_metadata,
            }
            self._save_bundle(owner_id, bundle)

        ml_count = 0
        rf_count = int(rf_suspicious.sum())
        normal_count = suspicious_count = malicious_count = 0
        prediction_rows: list[MLPrediction] = []
        for idx, event in enumerate(events):
            score = float(anomaly_scores[idx])
            is_anomaly = bool(anomaly_flags[idx])
            is_rf = bool(rf_suspicious[idx])
            if event.risk_score >= 85 or (is_anomaly and is_rf):
                classification = "Malicious"
                malicious_count += 1
            elif event.risk_score >= 70 or is_anomaly or is_rf:
                classification = "Suspicious"
                suspicious_count += 1
            else:
                classification = "Normal"
                normal_count += 1
            detection_type = "normal"
            if is_anomaly and is_rf:
                detection_type = "hybrid"
            elif is_anomaly:
                detection_type = "isolation_forest"
            elif is_rf:
                detection_type = "random_forest"
            elif event.risk_score >= 70:
                detection_type = "rule_based"
            reasons = self._explanation(event, is_anomaly, is_rf, iso_availability[idx] if idx < len(iso_availability) else "trained")
            # Heuristic anomaly strength mapped into the existing confidence column.
            # This is NOT a calibrated probability.
            heuristic_confidence = round(min(0.99, max(0.5, score / (score + 1.0))), 3)
            prediction_rows.append(
                MLPrediction(
                    server_id=getattr(event, "server_id", None) or "unassigned",
                    owner_id=getattr(event, "owner_id", None),
                    account_id=getattr(event, "account_id", None),
                    event_id=event.event_id,
                    isolation_score=score,
                    random_forest_label="suspicious" if is_rf else "normal",
                    classification=classification,
                    confidence=heuristic_confidence,
                    detection_type=detection_type,
                    message="; ".join(reasons),
                    is_anomaly=is_anomaly,
                    risk_score=event.risk_score,
                )
            )
            if is_anomaly or is_rf:
                self._alert_service.create_ml_alert(event, score=score, explanation="; ".join(reasons), detection_type=detection_type)
                ml_count += 1

        # Only this run's own (non-Linux) events are replaced; Linux prediction rows are never touched here.
        delete_stmt = delete(MLPrediction).where(MLPrediction.event_id.in_([event.event_id for event in events]))
        if account_id:
            delete_stmt = delete_stmt.where(MLPrediction.account_id == account_id)
        elif owner_id:
            delete_stmt = delete_stmt.where(MLPrediction.owner_id == owner_id)
        if server_id:
            delete_stmt = delete_stmt.where(MLPrediction.server_id == server_id)
        self._session.execute(delete_stmt)
        self._session.add_all(prediction_rows)
        self._session.commit()

        return {
            "success": True,
            "events_analyzed": len(events),
            "rule_alerts_created": rule_created,
            "ml_anomalies": int(anomaly_flags.sum()),
            "ml_classified_suspicious": rf_count,
            "total_flagged": ml_count,
            "normal": normal_count,
            "suspicious": suspicious_count,
            "malicious": malicious_count,
            "predictions_stored": len(prediction_rows),
            "isolation_forest": iso_status,
            "random_forest": rf_status,
            "evaluation": {"random_forest": evaluation, "isolation_forest": iso_eval},
            "feature_importance": feature_importance,
            "trained_at": trained_at,
            "model_action": model_action,
            "feature_version": FEATURE_VERSION,
            "training_metadata": training_metadata,
            "message": (
                "Hybrid detection complete. Isolation Forest is unsupervised; "
                "Random Forest trains only on original_label. "
                "Reported confidence is a heuristic Isolation Forest strength score, not a calibrated probability."
            ),
        }

    @staticmethod
    def _explanation(event: SecurityEvent, is_anomaly: bool, is_rf: bool, iso_status: str = "trained") -> list[str]:
        reasons = [
            f"Event type {event.event_type or 'unknown'}",
            f"Source family {DetectionService._source_family_name(getattr(event, 'source_type', None))}",
            f"Severity {event.severity or 'unknown'}",
        ]
        if event.event_type == "Failed Login":
            reasons.append("Repeated or failed authentication activity")
        if event.username and event.username.lower() == "root":
            reasons.append("Privileged account activity")
        hour = getattr(event, "login_hour", None)
        if hour is not None and (hour < 6 or hour > 22):
            reasons.append(f"Unusual login hour {hour}")
        if (event.failed_login_count or 0) >= 3:
            reasons.append("Elevated failed-login count in collection batch")
        if iso_status != "trained":
            reasons.append("Isolation Forest unavailable for this source family (insufficient_baseline)")
        elif is_anomaly:
            reasons.append("Isolation Forest flagged unusual feature combination")
        else:
            reasons.append("Isolation Forest did not flag this event")
        if is_rf:
            reasons.append("Random Forest classified the labeled threat pattern")
        else:
            reasons.append("Random Forest did not classify this event as suspicious")
        if (event.risk_score or 0) >= 70:
            reasons.append("Rule engine risk score is elevated")
        else:
            reasons.append(f"Rule engine risk score is {event.risk_score or 0}")
        reasons.append("Isolation Forest strength is a heuristic score, not a calibrated probability")
        return reasons

    def get_anomalies(self, *, limit: int = 20, server_id: str | None = None, owner_id: str | None = None, account_id: str | None = None) -> dict[str, Any]:
        scope = "server" if server_id else "account" if account_id else "owner" if owner_id else "unscoped"
        stored = self._stored_anomalies(limit=limit, server_id=server_id, owner_id=owner_id, account_id=account_id)
        total_stmt = (
            select(func.count(MLPrediction.id))
            .join(SecurityEvent, SecurityEvent.event_id == MLPrediction.event_id)
            .where(MLPrediction.is_anomaly.is_(True), self._current_prediction_filter())
        )
        if account_id:
            total_stmt = total_stmt.where(MLPrediction.account_id == account_id)
        elif owner_id:
            total_stmt = total_stmt.where(MLPrediction.owner_id == owner_id)
        if server_id:
            total_stmt = total_stmt.where(MLPrediction.server_id == server_id)
        total = int(self._session.scalar(total_stmt) or 0)
        items = stored
        if not items:
            events = self._load_events(
                limit=max(limit * 5, 50), server_id=server_id, owner_id=owner_id, account_id=account_id, exclude_linux=True,
            )
            bundle = self._compatible_bundle(self._load_bundle(owner_id))
            if bundle and events:
                iso_by_source = self._iso_models_from_bundle(bundle)
                flags, scores, _availability = self._score_with_source_if(events, iso_by_source)
                rf = bundle.get("random_forest") if bundle.get("rf_status") == "trained" else None
                rf_flags = rf.predict(self._features(events)) == 1 if rf is not None else np.zeros(len(events), dtype=bool)
                rows = []
                for event, flagged, score, is_rf in zip(events, flags, scores, rf_flags, strict=True):
                    if not (flagged or is_rf):
                        continue
                    detection_type = "hybrid" if flagged and is_rf else "isolation_forest" if flagged else "random_forest"
                    rows.append({
                        **self._event_summary(event, detection_type),
                        "classification": "Suspicious",
                        "anomaly_score": round(float(score), 3),
                    })
                items = rows[:limit]
        return {
            "scope": scope,
            "windowed": True,
            "scoring_window": 2000,
            "total": total or len(items),
            "items": items,
            "note": "Detections are windowed scores on PRIVATE telemetry, not a full-population census. Global datasets are not account detections.",
        }

    def _stored_anomalies(self, *, limit: int, server_id: str | None = None, owner_id: str | None = None, account_id: str | None = None) -> list[dict[str, Any]]:
        stmt = (
            select(MLPrediction, SecurityEvent)
            .join(SecurityEvent, SecurityEvent.event_id == MLPrediction.event_id)
            .where(MLPrediction.classification.in_(("Suspicious", "Malicious")), self._current_prediction_filter())
            .order_by(MLPrediction.created_at.desc())
            .limit(limit)
        )
        if server_id:
            stmt = stmt.where(MLPrediction.server_id == server_id)
        if account_id:
            stmt = stmt.where(MLPrediction.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(MLPrediction.owner_id == owner_id)
        rows = self._session.execute(stmt).all()
        return [
            {
                **self._event_summary(event, prediction.detection_type or "ml_anomaly"),
                "classification": prediction.classification,
                "anomaly_score": round(float(prediction.isolation_score or 0), 3),
                "confidence": prediction.confidence,
                "message": prediction.message or event.message,
            }
            for prediction, event in rows
        ]

    @staticmethod
    def _current_prediction_filter():
        """Linux predictions count only when written by the Linux pipeline.

        Rows the retired generic path stored for Linux events (snapshots included) stay in
        the table but are not reported.
        """
        return or_(
            func.upper(SecurityEvent.source_type).notin_(LINUX_SOURCE_TYPES),
            MLPrediction.detection_type.in_(linux_if.DETECTION_TYPES),
        )

    @staticmethod
    def _event_summary(event: SecurityEvent, detection_type: str) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "collection_timestamp": event.collection_timestamp.isoformat() if getattr(event, "collection_timestamp", None) else None,
            "hostname": event.hostname,
            "username": event.username,
            "source_ip": event.source_ip,
            "event_type": event.event_type,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "risk_level": getattr(event, "risk_level", None),
            "source_type": getattr(event, "source_type", None),
            "source_family": DetectionService._source_family_name(getattr(event, "source_type", None)),
            "server_id": getattr(event, "server_id", None),
            "message": event.message,
            "detection_type": detection_type,
            "classification": "Malicious" if event.risk_score >= 85 else "Suspicious" if event.risk_score >= 70 else "Normal",
        }

    def status(self, *, owner_id: str | None = None, server_id: str | None = None, account_id: str | None = None) -> dict[str, Any]:
        stmt = select(func.count(SecurityEvent.id)).where(SecurityEvent.data_scope == DATA_SCOPE_PRIVATE)
        if account_id:
            stmt = stmt.where(SecurityEvent.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        if server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        event_count = self._session.scalar(stmt) or 0
        bundle = self._compatible_bundle(self._load_bundle(owner_id))
        alert_summary = self._alert_service.summary(owner_id=owner_id, server_id=server_id)
        iso_trained = bool(self._iso_models_from_bundle(bundle))
        rf_status = (bundle or {}).get("rf_status") or "not_trained"
        detection_scope = "server" if server_id else "account" if account_id else "owner" if owner_id else "unscoped"
        return {
            "engine": "DefenSync Hybrid Detection",
            "detection_scope": detection_scope,
            "account_id": account_id,
            "server_id": server_id,
            "windowed": True,
            "scoring_window": 2000,
            "models": ["Isolation Forest", "Random Forest", "Rule Engine"],
            "events_in_db": event_count,
            "ready": bool(iso_trained),
            "model_bundle": bool(bundle),
            "model_action": "reused" if bundle else "none",
            "alerts": alert_summary,
            "isolation_forest": "trained" if iso_trained else "not_trained",
            "random_forest": rf_status if bundle else "not_trained",
            "trained_at": (bundle or {}).get("trained_at"),
            "feature_version": (bundle or {}).get("feature_version"),
            "evaluation": (bundle or {}).get("evaluation"),
            "feature_importance": (bundle or {}).get("feature_importance"),
            "training_metadata": (bundle or {}).get("training_metadata"),
            "feature_names": FEATURE_NAMES,
            "linux": self._linux_status(owner_id=owner_id, server_id=server_id, account_id=account_id),
            "limitations": [
                "Isolation Forest is unsupervised and is not trained on original_label or rule-derived labels.",
                "Random Forest trains only when original_label ground truth exists for both classes.",
                "Behavioral labels such as OVER_EFFICIENCY are not RF ground truth.",
                "Opening this page does not retrain models.",
                "ready reflects a compatible persisted Isolation Forest bundle, not event count.",
                "confidence on detections is a heuristic Isolation Forest strength score, not a calibrated probability.",
                "Linux uses its own Isolation Forest on eligible Linux security events only (feature version linux-v1).",
                "Linux Random Forest is disabled: there are no valid Linux labels.",
            ],
        }

    def _linux_model_path(self, owner_id: str | None) -> Path:
        return linux_if.model_path(self._settings.MODEL_DIR, owner_id)

    def _load_linux_rows(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        account_id: str | None = None,
    ) -> list[Any]:
        """Linux rows of the whole account/owner scope; history features need every host's full timeline."""
        stmt = (
            select(*LINUX_ROW_COLUMNS)
            .where(
                SecurityEvent.data_scope == DATA_SCOPE_PRIVATE,
                func.upper(SecurityEvent.source_type).in_(LINUX_SOURCE_TYPES),
            )
            .order_by(SecurityEvent.timestamp.asc(), SecurityEvent.event_id.asc())
        )
        if account_id:
            stmt = stmt.where(SecurityEvent.account_id == account_id)
        elif owner_id:
            stmt = stmt.where(SecurityEvent.owner_id == owner_id)
        elif server_id:
            stmt = stmt.where(SecurityEvent.server_id == server_id)
        else:
            return []
        return list(self._session.execute(stmt).mappings().all())

    def _linux_matrix(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        account_id: str | None = None,
    ) -> tuple[LinuxFeatureMatrix, dict[str, str | None]]:
        rows = self._load_linux_rows(owner_id=owner_id, server_id=server_id, account_id=account_id)
        hosts = {str(row["event_id"]): row["server_id"] for row in rows}
        return build_feature_matrix(rows), hosts

    @staticmethod
    def _linux_summary(
        matrix: LinuxFeatureMatrix,
        *,
        path: Path,
        bundle: dict[str, Any] | None,
        status: str,
        model_action: str,
        message: str,
        scored: int = 0,
        anomalies: int = 0,
    ) -> dict[str, Any]:
        metadata = (bundle or {}).get("training_metadata")
        return {
            "environment": linux_if.ENVIRONMENT,
            "feature_version": LINUX_FEATURE_VERSION,
            "feature_names": list(LINUX_FEATURE_NAMES),
            "isolation_forest_status": status,
            "training_status": linux_if.STATUS_TRAINED if bundle else linux_if.STATUS_NOT_TRAINED,
            "model_action": model_action,
            "eligible_count": len(matrix.event_ids),
            "minimum_required": linux_if.MIN_IF_BASELINE,
            "excluded": dict(matrix.excluded),
            "scored_count": scored,
            "anomaly_count": anomalies,
            "random_forest_status": linux_if.RF_STATUS,
            "valid_label_count": 0,
            "label_basis": (
                "No analyst-verified Linux label source exists. Public-dataset labels, risk_score, severity, "
                "alerts, Isolation Forest output and event type are not Linux ground truth."
            ),
            "model_path": str(path),
            "model_present": bundle is not None,
            "threshold_method": (metadata or {}).get("threshold_method"),
            "threshold": (bundle or {}).get("threshold"),
            "trained_at": (bundle or {}).get("trained_at"),
            "training_metadata": metadata,
            "message": message,
        }

    @staticmethod
    def _insufficient_linux_message(eligible: int) -> str:
        return (
            f"Linux Isolation Forest not trained: {eligible} eligible Linux security events, "
            f"{linux_if.MIN_IF_BASELINE} required. No Linux anomalies are reported."
        )

    def _linux_status(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        account_id: str | None = None,
    ) -> dict[str, Any]:
        """Linux model state without training or scoring."""
        matrix, _hosts = self._linux_matrix(owner_id=owner_id, server_id=server_id, account_id=account_id)
        path = self._linux_model_path(owner_id)
        bundle = linux_if.load_bundle(path)
        eligible = len(matrix.event_ids)
        if bundle is not None:
            return self._linux_summary(
                matrix, path=path, bundle=bundle, status=linux_if.STATUS_TRAINED, model_action="none",
                message="Linux Isolation Forest trained (linux-v1).",
            )
        if eligible < linux_if.MIN_IF_BASELINE:
            return self._linux_summary(
                matrix, path=path, bundle=None, status=linux_if.STATUS_INSUFFICIENT, model_action="none",
                message=self._insufficient_linux_message(eligible),
            )
        return self._linux_summary(
            matrix, path=path, bundle=None, status=linux_if.STATUS_NOT_TRAINED, model_action="none",
            message="Linux baseline is sufficient; Run Detection trains the Linux Isolation Forest.",
        )

    def _run_linux_detection(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
        account_id: str | None = None,
    ) -> dict[str, Any]:
        """Train (once the baseline is sufficient) or reuse the Linux model, then score eligible events.

        Nothing is written when the baseline is insufficient. Only eligible Linux security
        events are scored; prediction rows of the retired generic path are left untouched.
        """
        matrix, hosts = self._linux_matrix(owner_id=owner_id, server_id=server_id, account_id=account_id)
        path = self._linux_model_path(owner_id)
        bundle = linux_if.load_bundle(path)
        eligible = len(matrix.event_ids)
        if bundle is None:
            if eligible < linux_if.MIN_IF_BASELINE:
                return self._linux_summary(
                    matrix, path=path, bundle=None, status=linux_if.STATUS_INSUFFICIENT, model_action="skipped",
                    message=self._insufficient_linux_message(eligible),
                )
            bundle = linux_if.train_bundle(matrix, path=path)
            linux_if.save_bundle(bundle, path)
            model_action = "trained"
        else:
            model_action = "reused"

        indexes = [i for i, event_id in enumerate(matrix.event_ids) if not server_id or hosts.get(event_id) == server_id]
        indexes = indexes[-LINUX_SCORING_WINDOW:]
        if not indexes:
            return self._linux_summary(
                matrix, path=path, bundle=bundle, status=linux_if.STATUS_TRAINED, model_action=model_action,
                message="Linux Isolation Forest trained; no eligible Linux events in this scope to score.",
            )
        values = matrix.values[indexes]
        event_ids = [matrix.event_ids[i] for i in indexes]
        scores = linux_if.anomaly_scores(bundle["model"], values)
        threshold = float(bundle["threshold"])
        flags = scores > threshold
        events = {
            event.event_id: event
            for event in self._session.scalars(select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids)))
        }
        self._session.execute(
            delete(MLPrediction).where(
                MLPrediction.event_id.in_(event_ids),
                MLPrediction.detection_type.in_(linux_if.DETECTION_TYPES),
            )
        )
        training_count = int((bundle.get("training_metadata") or {}).get("training_count") or 0)
        rows: list[MLPrediction] = []
        flagged_events: list[tuple[SecurityEvent, float, str]] = []
        for event_id, vector, score, flagged in zip(event_ids, values, scores, flags, strict=True):
            event = events.get(event_id)
            if event is None:
                continue
            message = self._linux_explanation(vector, float(score), threshold, bool(flagged), training_count)
            rows.append(
                MLPrediction(
                    server_id=event.server_id or "unassigned",
                    owner_id=event.owner_id,
                    account_id=event.account_id,
                    event_id=event_id,
                    isolation_score=float(score),
                    random_forest_label="not_applicable",
                    classification="Suspicious" if flagged else "Normal",
                    confidence=None,
                    detection_type=linux_if.DETECTION_ANOMALY if flagged else linux_if.DETECTION_NORMAL,
                    message=message,
                    is_anomaly=bool(flagged),
                    risk_score=event.risk_score or 0,
                )
            )
            if flagged:
                flagged_events.append((event, float(score), message))
        self._session.add_all(rows)
        self._session.commit()
        for event, score, message in flagged_events:
            self._alert_service.create_ml_alert(event, score=score, explanation=message, detection_type=linux_if.DETECTION_ANOMALY)
        return self._linux_summary(
            matrix, path=path, bundle=bundle, status=linux_if.STATUS_TRAINED, model_action=model_action,
            scored=len(rows), anomalies=len(flagged_events),
            message=f"Linux Isolation Forest scored {len(rows)} eligible events; {len(flagged_events)} above the baseline threshold.",
        )

    @staticmethod
    def _linux_explanation(vector: np.ndarray, score: float, threshold: float, flagged: bool, training_count: int) -> str:
        features = dict(zip(LINUX_FEATURE_NAMES, (float(value) for value in vector), strict=True))
        notable = [
            name for name in LINUX_FEATURE_NAMES
            if name not in {"hour_sin", "hour_cos", "log_secs_since_user_prev_event"} and features[name] > 0
        ]
        relation = "above" if flagged else "at or below"
        text = (
            f"Linux Isolation Forest anomaly score {score:.4f} {relation} the baseline threshold {threshold:.4f} "
            f"({linux_if.THRESHOLD_PERCENTILE:g}th percentile of {training_count} baseline events)"
        )
        return f"{text}; active features: {', '.join(notable)}" if notable else text
