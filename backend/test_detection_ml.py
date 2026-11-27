"""Hybrid detection encoding, labels, persistence, and reuse tests."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, Event
from backend.services.detection_service import (
    FEATURE_NAMES,
    FEATURE_VERSION,
    MIN_IF_BASELINE,
    POSITIVE_LABELS,
    RF_MAX_NEGATIVE,
    RF_MAX_POSITIVE,
    DetectionService,
)


def _event(**kwargs):
    payload = {
        "event_id": kwargs.get("event_id", "e1"),
        "timestamp": datetime(2026, 8, 17, 10, 15, tzinfo=timezone.utc),
        "hostname": "web01",
        "username": "yogesh",
        "source_ip": "10.0.0.8",
        "event_type": "Successful Login",
        "severity": "low",
        "risk_score": 20,
        "message": "login",
        "raw_log": "login",
        "source_type": "LINUX",
    }
    payload.update(kwargs)
    event = Event()
    for key, value in payload.items():
        setattr(event, key, value)
    return event


def _persist_event(session, **kwargs):
    index = kwargs.pop("index", 0)
    payload = {
        "event_id": kwargs.get("event_id", f"evt-{index}"),
        "timestamp": kwargs.get("timestamp", datetime(2026, 8, 17, 10, 15, tzinfo=timezone.utc)),
        "hostname": "web01",
        "username": kwargs.get("username", "yogesh"),
        "source_ip": "10.0.0.8",
        "event_type": kwargs.get("event_type", "Successful Login"),
        "category": "auth",
        "severity": kwargs.get("severity", "low"),
        "risk_score": kwargs.get("risk_score", 20),
        "message": "login",
        "raw_log": kwargs.get("raw_log", f"login-{index}"),
        "hash": kwargs.get("hash", f"hash-{index}"),
        "owner_id": kwargs.get("owner_id", "owner-1"),
        "server_id": kwargs.get("server_id", "server-A"),
        "source_type": kwargs.get("source_type", "LINUX"),
        "data_origin": kwargs.get("data_origin", "LIVE_LINUX"),
        "original_label": kwargs.get("original_label"),
        "dataset_name": kwargs.get("dataset_name"),
        "login_hour": kwargs.get("login_hour"),
        "cpu_usage": kwargs.get("cpu_usage"),
        "resource_id": kwargs.get("resource_id"),
    }
    event = Event(**{key: value for key, value in payload.items() if value is not None or key == "original_label"})
    session.add(event)
    return event


class DetectionFeatureTests(unittest.TestCase):
    def test_features_do_not_include_risk_score(self):
        self.assertNotIn("risk_score", FEATURE_NAMES)
        row = DetectionService._row(_event(risk_score=99))
        self.assertEqual(len(row), len(FEATURE_NAMES))

    def test_feature_length_matches_names(self):
        row = DetectionService._row(_event())
        self.assertEqual(len(row), len(FEATURE_NAMES))
        self.assertEqual(len(FEATURE_NAMES), 21)
        self.assertNotIn("server_hash", FEATURE_NAMES)
        self.assertEqual(FEATURE_VERSION, "v3")

    def test_server_id_does_not_change_feature_vector(self):
        shared = dict(
            event_type="Successful Login",
            source_type="LINUX",
            username="yogesh",
            source_ip="10.0.0.8",
            severity="low",
            risk_score=20,
            login_hour=10,
        )
        row_a = DetectionService._row(_event(server_id="server-A", **shared))
        row_b = DetectionService._row(_event(server_id="server-B", **shared))
        self.assertEqual(row_a, row_b)

    def test_identical_feature_vectors_are_retained(self):
        shared = dict(
            event_type="HDFS_EXCEPTION",
            source_type="CLOUD",
            username="nova",
            source_ip="10.0.0.8",
            severity="high",
            login_hour=3,
            original_label="ANOMALOUS",
        )
        events = [
            _event(event_id="dup-1", hash="hash-1", **shared),
            _event(event_id="dup-2", hash="hash-2", **shared),
            _event(event_id="dup-3", hash="hash-3", **shared),
        ]
        self.assertEqual(DetectionService._row(events[0]), DetectionService._row(events[1]))
        self.assertEqual(DetectionService._row(events[1]), DetectionService._row(events[2]))
        unique = DetectionService._dedupe_labeled(events)
        self.assertEqual(len(unique), 3)

    def test_genuine_hash_duplicates_are_excluded(self):
        shared = dict(
            event_type="HDFS_EXCEPTION",
            source_type="CLOUD",
            original_label="ANOMALOUS",
            login_hour=3,
        )
        events = [
            _event(event_id="id-1", hash="same-source-hash", **shared),
            _event(event_id="id-2", hash="same-source-hash", **shared),
        ]
        unique = DetectionService._dedupe_labeled(events)
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0].event_id, "id-1")

    def test_source_encoding_is_one_hot(self):
        linux = DetectionService._row(_event(source_type="LINUX"))
        cloud = DetectionService._row(_event(source_type="CLOUD"))
        hpc = DetectionService._row(_event(source_type="HPC"))
        behavioral = DetectionService._row(_event(source_type="BEHAVIORAL"))
        names = FEATURE_NAMES
        self.assertEqual(
            [linux[names.index(name)] for name in ("source_linux", "source_cloud", "source_hpc", "source_behavioral")],
            [1.0, 0.0, 0.0, 0.0],
        )
        self.assertEqual(
            [cloud[names.index(name)] for name in ("source_linux", "source_cloud", "source_hpc", "source_behavioral")],
            [0.0, 1.0, 0.0, 0.0],
        )
        self.assertEqual(
            [hpc[names.index(name)] for name in ("source_linux", "source_cloud", "source_hpc", "source_behavioral")],
            [0.0, 0.0, 1.0, 0.0],
        )
        self.assertEqual(
            [behavioral[names.index(name)] for name in ("source_linux", "source_cloud", "source_hpc", "source_behavioral")],
            [0.0, 0.0, 0.0, 1.0],
        )

    def test_supervised_label_uses_original_label_only(self):
        self.assertEqual(DetectionService._supervised_label(_event(original_label="NORMAL", risk_score=90)), 0)
        self.assertEqual(DetectionService._supervised_label(_event(original_label="BENIGN")), 0)
        self.assertEqual(DetectionService._supervised_label(_event(original_label="ANOMALOUS", risk_score=10)), 1)
        self.assertEqual(DetectionService._supervised_label(_event(original_label="ATTACK")), 1)
        self.assertIsNone(DetectionService._supervised_label(_event(original_label="OVER_EFFICIENCY")))
        self.assertIsNone(DetectionService._supervised_label(_event(original_label="AUTOMATED_ACTIVITY")))
        self.assertIsNone(DetectionService._supervised_label(_event(original_label="SUSPICIOUS_BEHAVIOR")))
        self.assertIsNone(DetectionService._supervised_label(_event(original_label="UNUSUAL_SESSION")))
        self.assertIsNone(DetectionService._supervised_label(_event(original_label=None, risk_score=90)))

    def test_cloud_and_hpc_features_keep_vector_length(self):
        cloud = _event(event_type="HDFS_EXCEPTION", source_type="CLOUD", resource_id="blk_1", cpu_usage=None)
        hpc = _event(event_type="HPC_KERNEL_FAILURE", source_type="HPC", resource_id="R01", username=None)
        linux = _event(event_type="Failed Login", source_type="LINUX", username="root")
        for event in (cloud, hpc, linux):
            row = DetectionService._row(event)
            self.assertEqual(len(row), len(FEATURE_NAMES))

    def test_model_bundle_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            mock = MagicMock()
            mock.MODEL_DIR = tmp
            with patch("backend.services.detection_service.get_settings", return_value=mock):
                service = DetectionService(session=None)  # type: ignore[arg-type]
                service._save_bundle("owner", {
                    "rf_status": "trained",
                    "trained_at": "t",
                    "feature_names": FEATURE_NAMES,
                    "feature_version": FEATURE_VERSION,
                    "isolation_forest": object(),
                })
                loaded = service._load_bundle("owner")
                self.assertEqual(loaded["rf_status"], "trained")
                self.assertEqual(loaded["feature_version"], FEATURE_VERSION)
                self.assertTrue((Path(tmp) / "owner" / "hybrid_detection.joblib").exists())


class DetectionPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.session = self.Session()
        self.settings = MagicMock()
        self.settings.MODEL_DIR = self.tmp.name

    def tearDown(self) -> None:
        self.session.close()
        self.engine.dispose()
        self.tmp.cleanup()

    def _service(self) -> DetectionService:
        with patch("backend.services.detection_service.get_settings", return_value=self.settings):
            return DetectionService(self.session)

    def _seed(self, *, normals: int = 0, anomalies: int = 0, unlabeled: int = 0, origin: str = "PUBLIC_DATASET") -> None:
        index = 0
        for _ in range(normals):
            _persist_event(
                self.session,
                index=index,
                original_label="NORMAL",
                data_origin=origin,
                source_type="CLOUD",
                dataset_name="LOGHUB_HDFS",
                risk_score=10,
                login_hour=index % 24,
                cpu_usage=float(index),
                resource_id=f"blk-n-{index}",
                raw_log=f"normal-{index}",
            )
            index += 1
        for _ in range(anomalies):
            _persist_event(
                self.session,
                index=index,
                original_label="ANOMALOUS",
                data_origin=origin,
                source_type="CLOUD",
                dataset_name="LOGHUB_HDFS",
                event_type="HDFS_EXCEPTION",
                risk_score=20,
                login_hour=(index * 3) % 24,
                cpu_usage=float(50 + index),
                resource_id=f"blk-a-{index}",
                raw_log=f"anomaly-{index}",
            )
            index += 1
        for _ in range(unlabeled):
            _persist_event(
                self.session,
                index=index,
                original_label=None,
                data_origin="LIVE_LINUX",
                source_type="LINUX",
                risk_score=15,
            )
            index += 1
        self.session.commit()

    def test_status_not_ready_without_bundle(self):
        self._seed(unlabeled=12)
        status = self._service().status(owner_id="owner-1")
        self.assertGreaterEqual(status["events_in_db"], 10)
        self.assertFalse(status["ready"])
        self.assertFalse(status["model_bundle"])
        self.assertEqual(status["isolation_forest"], "not_trained")
        self.assertEqual(status["random_forest"], "not_trained")

    def test_rf_does_not_train_without_both_classes(self):
        self._seed(normals=MIN_IF_BASELINE, anomalies=0)
        result = self._service().run_detection(owner_id="owner-1")
        self.assertEqual(result["isolation_forest"], "trained")
        self.assertEqual(result["random_forest"], "no_valid_labels")
        self.assertEqual(result["model_action"], "trained")

    def test_rf_evaluation_is_holdout_only(self):
        self._seed(normals=MIN_IF_BASELINE, anomalies=40)
        result = self._service().run_detection(owner_id="owner-1")
        evaluation = result["evaluation"]["random_forest"]
        self.assertEqual(result["random_forest"], "trained")
        self.assertGreater(evaluation["train_size"], 0)
        self.assertGreater(evaluation["test_size"], 6)
        self.assertEqual(evaluation["train_size"] + evaluation["test_size"], evaluation["samples_labeled"])
        ratio = evaluation["test_size"] / evaluation["samples_labeled"]
        self.assertGreater(ratio, 0.2)
        self.assertLess(ratio, 0.4)
        self.assertIn("accuracy", evaluation)
        self.assertIn("confusion_matrix", evaluation)
        self.assertGreaterEqual(evaluation["positive_samples"], 2)
        self.assertGreaterEqual(evaluation["negative_samples"], 2)
        self.assertEqual(evaluation["rf_training_source"], "PUBLIC_DATASET")

    def test_model_persistence_contains_versioned_bundle(self):
        self._seed(normals=MIN_IF_BASELINE, anomalies=40)
        service = self._service()
        result = service.run_detection(owner_id="owner-1")
        bundle = service._load_bundle("owner-1")
        self.assertEqual(bundle["feature_names"], FEATURE_NAMES)
        self.assertEqual(bundle["feature_version"], FEATURE_VERSION)
        self.assertIsNotNone(bundle["isolation_forests"]["CLOUD"])
        self.assertIsNotNone(bundle["random_forest"])
        self.assertEqual(bundle["rf_status"], "trained")
        self.assertEqual(result["feature_version"], FEATURE_VERSION)
        self.assertEqual(bundle["training_metadata"]["feature_count"], 21)
        self.assertEqual(bundle["training_metadata"]["rf_training_source"], "PUBLIC_DATASET")
        self.assertEqual(bundle["training_metadata"]["iso_training_scope"], "source_family_baseline")
        self.assertIn("iso_models_by_source", bundle["training_metadata"])
        self.assertEqual(bundle["training_metadata"]["iso_models_by_source"]["CLOUD"]["status"], "trained")
        self.assertIsNotNone(bundle["isolation_forests"]["CLOUD"])
        self.assertIsNone(bundle["isolation_forests"].get("HPC"))

    def test_model_reuse_does_not_retrain(self):
        self._seed(normals=MIN_IF_BASELINE, anomalies=40)
        service = self._service()
        first = service.run_detection(owner_id="owner-1")
        second = service.run_detection(owner_id="owner-1")
        self.assertEqual(first["model_action"], "trained")
        self.assertEqual(second["model_action"], "reused")
        self.assertEqual(first["trained_at"], second["trained_at"])
        status = service.status(owner_id="owner-1")
        self.assertTrue(status["ready"])
        self.assertTrue(status["model_bundle"])
        self.assertEqual(status["isolation_forest"], "trained")
        self.assertEqual(status["feature_version"], FEATURE_VERSION)

    def test_incompatible_bundle_is_rejected(self):
        self._seed(unlabeled=12)
        service = self._service()
        service._save_bundle("owner-1", {
            "isolation_forest": object(),
            "feature_names": FEATURE_NAMES,
            "feature_version": "v2",
            "rf_status": "trained",
        })
        status = service.status(owner_id="owner-1")
        self.assertFalse(status["ready"])
        self.assertFalse(status["model_bundle"])
        self.assertNotEqual(FEATURE_VERSION, "v2")

    def test_rf_pool_retains_identical_vectors_from_database(self):
        for index in range(30):
            _persist_event(
                self.session,
                index=index,
                original_label="ANOMALOUS" if index < 15 else "NORMAL",
                data_origin="PUBLIC_DATASET",
                source_type="CLOUD",
                event_type="HDFS_EXCEPTION",
                login_hour=4,
                cpu_usage=1.0,
                resource_id="blk-same",
                hash=f"unique-hash-{index}",
            )
        self.session.commit()
        pool = self._service()._load_labeled_training_rows(owner_id="owner-1")
        self.assertGreater(len(pool), 17)
        self.assertEqual(len(pool), 30)
        self.assertEqual(len({tuple(DetectionService._row(event)) for event in pool}), 1)

    def test_rf_pool_respects_class_caps(self):
        self._seed(normals=12, anomalies=10)
        pool = self._service()._load_labeled_training_rows(
            owner_id="owner-1",
            max_positive=5,
            max_negative=8,
        )
        positives = [event for event in pool if DetectionService._supervised_label(event) == 1]
        negatives = [event for event in pool if DetectionService._supervised_label(event) == 0]
        self.assertEqual(len(positives), 5)
        self.assertEqual(len(negatives), 8)
        self.assertLessEqual(len(positives), RF_MAX_POSITIVE)
        self.assertLessEqual(len(negatives), RF_MAX_NEGATIVE)

    def test_if_insufficient_baseline_does_not_fit(self):
        self._seed(unlabeled=20)
        result = self._service().run_detection(owner_id="owner-1")
        # Linux rows never reach the hybrid path; the Linux pipeline reports its own baseline.
        self.assertEqual(result["isolation_forest"], "insufficient_events")
        self.assertEqual(result["linux"]["isolation_forest_status"], "insufficient_baseline")
        self.assertEqual(result["model_action"], "skipped")
        self.assertIsNone(self._service()._load_bundle("owner-1"))

    def test_generic_baseline_never_serves_linux_and_excludes_positive_labels(self):
        index = 0
        for label in POSITIVE_LABELS:
            for _ in range(8):
                _persist_event(
                    self.session,
                    index=index,
                    original_label=label,
                    data_origin="PUBLIC_DATASET",
                    source_type="CLOUD",
                    risk_score=10,
                )
                index += 1
        for _ in range(MIN_IF_BASELINE + 5):
            _persist_event(
                self.session,
                index=index,
                original_label=None,
                data_origin="LIVE_LINUX",
                source_type="LINUX",
                risk_score=15,
            )
            index += 1
        self.session.commit()
        service = self._service()
        self.assertEqual(service._load_if_baseline_events(source_type="LINUX", owner_id="owner-1"), [])
        for event in service._load_if_baseline_events(source_type="CLOUD", owner_id="owner-1"):
            self.assertNotIn((event.original_label or "").upper(), POSITIVE_LABELS)
            self.assertNotEqual(DetectionService._supervised_label(event), 1)

    def test_if_baseline_query_is_separate_from_scoring_window(self):
        for index in range(8):
            _persist_event(
                self.session,
                index=index,
                original_label=None,
                data_origin="LIVE_LINUX",
                source_type="LINUX",
                risk_score=15,
                timestamp=datetime(2026, 9, 27, 12, index, tzinfo=timezone.utc),
            )
        for extra in range(MIN_IF_BASELINE):
            _persist_event(
                self.session,
                index=100 + extra,
                original_label="NORMAL",
                data_origin="PUBLIC_DATASET",
                source_type="CLOUD",
                risk_score=10,
                timestamp=datetime(2024, 1, 1, 0, 0, tzinfo=timezone.utc),
            )
        self.session.commit()
        service = self._service()
        scored = service._load_events(limit=8, owner_id="owner-1")
        baseline = service._load_if_baseline_events(source_type="CLOUD", owner_id="owner-1")
        self.assertEqual(len(scored), 8)
        self.assertTrue(all(event.data_origin == "LIVE_LINUX" for event in scored))
        self.assertGreaterEqual(len(baseline), MIN_IF_BASELINE)
        self.assertGreater(len(baseline), len(scored))
        self.assertTrue(any(event.data_origin == "PUBLIC_DATASET" for event in baseline))
        scored_ids = {event.event_id for event in scored}
        baseline_ids = {event.event_id for event in baseline}
        self.assertFalse(baseline_ids <= scored_ids)

    def test_linux_event_does_not_use_hpc_if(self):
        from sklearn.ensemble import IsolationForest

        hpc_events = [
            _event(event_id=f"hpc-{index}", source_type="HPC", event_type="HPC_KERNEL_FAILURE", resource_id="R01", username=None)
            for index in range(MIN_IF_BASELINE)
        ]
        hpc_iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=20)
        hpc_iso.fit(DetectionService._features(hpc_events))
        linux_event = _event(event_id="linux-1", source_type="LINUX", event_type="Successful Login", memory_usage=88.0)
        flags, _scores, availability = DetectionService._score_with_source_if([linux_event], {"HPC": hpc_iso})
        self.assertEqual(availability[0], "insufficient_baseline")
        self.assertFalse(flags[0])

    def test_cloud_event_does_not_use_hpc_if(self):
        from sklearn.ensemble import IsolationForest

        hpc_events = [
            _event(event_id=f"hpc-{index}", source_type="HPC", event_type="HPC_KERNEL_FAILURE", resource_id="R01", username=None)
            for index in range(MIN_IF_BASELINE)
        ]
        hpc_iso = IsolationForest(contamination=0.1, random_state=42, n_estimators=20)
        hpc_iso.fit(DetectionService._features(hpc_events))
        cloud_event = _event(event_id="cloud-1", source_type="CLOUD", event_type="HDFS_EXCEPTION", resource_id="blk_1")
        flags, _scores, availability = DetectionService._score_with_source_if([cloud_event], {"HPC": hpc_iso})
        self.assertEqual(availability[0], "insufficient_baseline")
        self.assertFalse(flags[0])

    def test_linux_insufficient_baseline_does_not_fit_linux_if(self):
        self._seed(unlabeled=20)
        service = self._service()
        models, meta = service._fit_isolation_forests_by_source(owner_id="owner-1")
        self.assertEqual(meta["LINUX"]["status"], "separate_linux_pipeline")
        self.assertNotIn("LINUX", models)
        result = service.run_detection(owner_id="owner-1")
        self.assertEqual(result["linux"]["isolation_forest_status"], "insufficient_baseline")
        self.assertEqual(result["linux"]["eligible_count"], 0)

    def test_source_with_enough_normals_gets_own_if_baseline(self):
        self._seed(normals=MIN_IF_BASELINE, unlabeled=20)
        service = self._service()
        models, meta = service._fit_isolation_forests_by_source(owner_id="owner-1")
        self.assertEqual(meta["CLOUD"]["status"], "trained")
        self.assertGreaterEqual(meta["CLOUD"]["baseline_events"], MIN_IF_BASELINE)
        self.assertIn("CLOUD", models)
        self.assertEqual(meta["LINUX"]["status"], "separate_linux_pipeline")
        self.assertNotIn("LINUX", models)
        linux_event = _event(event_id="live-linux", source_type="LINUX")
        flags, _scores, availability = DetectionService._score_with_source_if([linux_event], models)
        self.assertEqual(availability[0], "insufficient_baseline")
        self.assertFalse(flags[0])

    def test_positive_labels_never_enter_source_baselines(self):
        index = 0
        for family, origin in (("LINUX", "LIVE_LINUX"), ("CLOUD", "PUBLIC_DATASET"), ("HPC", "PUBLIC_DATASET"), ("BEHAVIORAL", "SYNTHETIC")):
            for label in POSITIVE_LABELS:
                _persist_event(
                    self.session,
                    index=index,
                    original_label=label,
                    data_origin=origin,
                    source_type=family,
                    risk_score=10,
                )
                index += 1
            for _ in range(MIN_IF_BASELINE):
                _persist_event(
                    self.session,
                    index=index,
                    original_label="NORMAL" if family != "LINUX" else None,
                    data_origin=origin if family != "LINUX" else "LIVE_LINUX",
                    source_type=family,
                    risk_score=15,
                )
                index += 1
        self.session.commit()
        service = self._service()
        for family in ("LINUX", "CLOUD", "HPC", "BEHAVIORAL"):
            baseline = service._load_if_baseline_events(source_type=family, owner_id="owner-1")
            self.assertTrue(all(DetectionService._source_family_name(event.source_type) == family for event in baseline))
            for event in baseline:
                self.assertNotIn((event.original_label or "").upper(), POSITIVE_LABELS)
                self.assertNotEqual(DetectionService._supervised_label(event), 1)


if __name__ == "__main__":
    unittest.main()
