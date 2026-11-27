"""Step 1 Cloud/Linux isolation and Azure file-importer hardening regression tests.

No live Azure, SSH, or PostgreSQL: SQLite in-memory sessions and temp directories only.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import numpy as np
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.core.environments import CLOUD, LINUX, UNKNOWN, source_family, source_types_for_family
from backend.core.timestamps import SOURCE_EVENT, SOURCE_FALLBACK
from backend.database.models import DATA_SCOPE_PRIVATE, Base, DatasetImport, Event, Incident, RiskHistory, User
from backend.database.scope import event_visibility_clause
from backend.services.behavioral.baseline_service import BehavioralBaselineService
from backend.services.correlation_service import CorrelationService, environment_from_source
from backend.services.datasets.azure_import_service import (
    CLOUD_ACTIVITY,
    CLOUD_AUTHENTICATION,
    CLOUD_LOGIN_FAILURE,
    CLOUD_LOGIN_SUCCESS,
    CLOUD_PRIVILEGE_CHANGE,
    CLOUD_RESOURCE_OPERATION,
    AzureActivityLogImportService,
    AzureImportPathError,
)
from backend.services.detection_service import MIN_IF_BASELINE, DetectionService

T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
COLLECTED = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)


def _event(actor, source_type, event_type, minute, risk=20, provider=None, **extra):
    event = Event()
    event.event_id = f"{source_type}-{actor}-{event_type}-{minute}"
    event.timestamp = T0 + timedelta(minutes=minute)
    event.username = actor
    event.actor_id = actor
    event.source_type = source_type
    event.provider = provider
    event.event_type = event_type
    event.message = event_type
    event.severity = "high" if risk >= 70 else "info"
    event.risk_score = risk
    event.behavioral_risk_score = None
    event.hostname = "host"
    for key, value in extra.items():
        setattr(event, key, value)
    return event


def _sqlite_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _persist(session, index, *, source_type, event_type, actor="testuser", minute=0, risk=20, provider=None, **extra):
    fields = {
        "event_id": f"evt-{index}",
        "timestamp": T0 + timedelta(minutes=minute),
        "hostname": "host",
        "username": actor,
        "actor_id": actor,
        "event_type": event_type,
        "category": "test",
        "severity": "high" if risk >= 70 else "info",
        "risk_score": risk,
        "message": event_type,
        "raw_log": f"raw-{index}",
        "hash": f"hash-{index}",
        "owner_id": extra.pop("owner_id", "owner-1"),
        "account_id": extra.pop("account_id", None),
        "data_scope": DATA_SCOPE_PRIVATE,
        "source_type": source_type,
        "provider": provider,
        "data_origin": "LIVE_LINUX" if source_type == "LINUX" else "AZURE_ACTIVITY_LOG_FILE",
        **extra,
    }
    session.add(Event(**fields))


class CloudDetectionFamilyTests(unittest.TestCase):
    def test_a_cloud_dataset_maps_to_cloud_not_linux(self):
        for value in ("CLOUD_DATASET", "cloud_dataset", "AZURE", "CLOUD"):
            self.assertEqual(DetectionService._source_family_name(value), CLOUD)
            self.assertEqual(DetectionService._source_onehot(value), [0.0, 1.0, 0.0, 0.0])
        self.assertIn("CLOUD_DATASET", source_types_for_family(CLOUD))
        self.assertNotIn("CLOUD_DATASET", source_types_for_family(LINUX))

    def test_b_linux_remains_linux(self):
        self.assertEqual(DetectionService._source_family_name("LINUX"), LINUX)
        self.assertEqual(DetectionService._source_family_name(None), LINUX)
        self.assertEqual(DetectionService._source_onehot("LINUX"), [1.0, 0.0, 0.0, 0.0])
        self.assertEqual(DetectionService._source_family_name("HPC"), "HPC")
        self.assertEqual(DetectionService._source_family_name("BEHAVIORAL"), "BEHAVIORAL")

    def test_unknown_source_type_is_never_linux(self):
        self.assertEqual(source_family("SOMETHING_NEW"), UNKNOWN)
        self.assertEqual(DetectionService._source_onehot("SOMETHING_NEW"), [0.0, 0.0, 0.0, 0.0])

    def test_cloud_dataset_event_is_never_scored_by_linux_forest(self):
        linux_model = MagicMock()
        linux_model.predict.side_effect = lambda X: np.full(len(X), -1)
        linux_model.score_samples.side_effect = lambda X: np.zeros(len(X))
        azure = _event("alice@example.com", "CLOUD_DATASET", "CLOUD_ACTIVITY", 0, provider="AZURE")
        flags, _scores, availability = DetectionService._score_with_source_if([azure], {LINUX: linux_model})
        linux_model.predict.assert_not_called()
        self.assertEqual(availability, ["insufficient_baseline"])
        self.assertFalse(flags[0])

        cloud_model = MagicMock()
        cloud_model.predict.side_effect = lambda X: np.full(len(X), 1)
        cloud_model.score_samples.side_effect = lambda X: np.zeros(len(X))
        linux = _event("yogesh", "LINUX", "Successful Login", 0)
        _flags, _scores, availability = DetectionService._score_with_source_if([azure, linux], {LINUX: linux_model, CLOUD: cloud_model})
        # Linux events are scored only by the separate Linux pipeline, never by a hybrid-bundle forest.
        self.assertEqual(availability, ["trained", "insufficient_baseline"])
        self.assertEqual(len(cloud_model.predict.call_args[0][0]), 1)
        linux_model.predict.assert_not_called()

    def test_legacy_cloud_rows_join_cloud_baseline_never_linux(self):
        session = _sqlite_session()
        for index in range(MIN_IF_BASELINE):
            _persist(session, index, source_type="CLOUD_DATASET", event_type="CLOUD_ACTIVITY", provider="AZURE")
        for index in range(MIN_IF_BASELINE, MIN_IF_BASELINE + 5):
            _persist(session, index, source_type="LINUX", event_type="Successful Login")
        session.commit()
        service = DetectionService(session)
        cloud = service._load_if_baseline_events(source_type=CLOUD, owner_id="owner-1")
        linux = service._load_if_baseline_events(source_type=LINUX, owner_id="owner-1")
        self.assertEqual(len(cloud), MIN_IF_BASELINE)
        self.assertTrue(all(event.source_type == "CLOUD_DATASET" for event in cloud))
        # The Linux baseline comes from backend.ml.linux_features, not the generic risk_score loader.
        self.assertEqual(linux, [])


class CorrelationIsolationTests(unittest.TestCase):
    def _build(self, events):
        return CorrelationService(session=None)._build(events)  # type: ignore[arg-type]

    def test_c_linux_and_cloud_same_actor_never_one_incident(self):
        events = [
            _event("testuser", "LINUX", "Failed Login", 0, risk=75),
            _event("testuser", "CLOUD", CLOUD_LOGIN_FAILURE, 1, risk=70, provider="AZURE"),
        ]
        incidents = self._build(events)
        self.assertEqual({item["environment"] for item in incidents}, {LINUX, CLOUD})
        linux = next(item for item in incidents if item["environment"] == LINUX)
        cloud = next(item for item in incidents if item["environment"] == CLOUD)
        self.assertEqual(linux["event_ids"], [events[0].event_id])
        self.assertEqual(cloud["event_ids"], [events[1].event_id])
        self.assertEqual(linux["source"], "Linux")
        self.assertEqual(cloud["source"], "Azure")
        self.assertNotEqual(linux["incident_id"], cloud["incident_id"])

    def test_c_cross_environment_evidence_is_not_combined(self):
        events = [
            _event("testuser", "LINUX", "Successful Login", 0),
            _event("testuser", "CLOUD", CLOUD_RESOURCE_OPERATION, 1, provider="AZURE"),
        ]
        self.assertEqual(self._build(events), [])

    def test_d_linux_to_linux_correlation_unchanged(self):
        events = [
            _event("testuser", "LINUX", "Successful Login", 0),
            _event("testuser", "LINUX", "Sudo Command", 1, risk=60),
        ]
        incidents = self._build(events)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["environment"], LINUX)
        self.assertEqual(incident["title"], "Correlated activity for testuser")
        self.assertEqual(incident["incident_id"], f"testuser-{int(events[1].timestamp.timestamp())}")
        self.assertEqual(incident["evidence"], ["Linux login/authentication activity", "Privilege-related Linux activity"])
        self.assertEqual(incident["event_ids"], [e.event_id for e in events])

    def test_d_cloud_to_cloud_correlation(self):
        events = [
            _event("alice@example.com", "CLOUD", CLOUD_LOGIN_SUCCESS, 0, provider="AZURE"),
            _event("alice@example.com", "CLOUD", CLOUD_PRIVILEGE_CHANGE, 1, provider="AZURE"),
        ]
        incidents = self._build(events)
        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident["environment"], CLOUD)
        self.assertTrue(incident["incident_id"].startswith("cloud:"))
        self.assertEqual(incident["title"], "Correlated Cloud activity for alice@example.com")
        self.assertEqual(incident["evidence"], ["Cloud sign-in/authentication activity", "Cloud privilege/role change"])
        self.assertNotIn("Linux", incident["explanation"])

    def test_same_actor_in_different_tenants_is_not_merged(self):
        events = [
            _event("root", "LINUX", "Successful Login", 0, account_id="acct-a"),
            _event("root", "LINUX", "Sudo Command", 1, account_id="acct-b"),
        ]
        self.assertEqual(self._build(events), [])

    def test_long_cloud_actor_incident_id_fits_column(self):
        actor = "a" * 200 + "@example.com"
        events = [
            _event(actor, "CLOUD", CLOUD_LOGIN_SUCCESS, 0, provider="AZURE"),
            _event(actor, "CLOUD", CLOUD_PRIVILEGE_CHANGE, 1, provider="AZURE"),
        ]
        incident = self._build(events)[0]
        self.assertLessEqual(len(incident["incident_id"]), 80)

    def test_environment_from_stored_source(self):
        self.assertEqual(environment_from_source("Linux"), LINUX)
        self.assertEqual(environment_from_source("Azure"), CLOUD)
        self.assertEqual(environment_from_source("OpenStack"), CLOUD)
        self.assertEqual(environment_from_source("Behavioral,Linux,OpenStack"), "MIXED_LEGACY")


class AdminCorrelationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.session = _sqlite_session()
        _persist(self.session, 1, source_type="LINUX", event_type="Failed Login", minute=0, risk=75, account_id="acct-1")
        _persist(self.session, 2, source_type="LINUX", event_type="Sudo Command", minute=1, risk=60, account_id="acct-1")
        _persist(self.session, 3, source_type="CLOUD", event_type=CLOUD_LOGIN_FAILURE, minute=1, risk=70, provider="AZURE", account_id="acct-1")
        _persist(self.session, 4, source_type="CLOUD", event_type=CLOUD_PRIVILEGE_CHANGE, minute=2, provider="AZURE", account_id="acct-1")
        self.session.commit()

    def _assert_isolated(self, stored):
        self.assertEqual({row["environment"] for row in stored}, {LINUX, CLOUD})
        by_id = {row.event_id: row.source_type for row in self.session.scalars(select(Event)).all()}
        for row in stored:
            families = {source_family(by_id[event_id]) for event_id in row["event_ids"]}
            self.assertEqual(families, {row["environment"]})
        cloud = next(row for row in stored if row["environment"] == CLOUD)
        self.assertNotIn("Linux", cloud["explanation"])
        self.assertEqual(cloud["intelligence_refs"], [])

    def test_admin_global_run_keeps_environments_apart(self):
        stored = CorrelationService(self.session).correlate_and_store(owner_id=None, account_id=None)
        self._assert_isolated(stored)
        entity_types = {row.entity_type for row in self.session.scalars(select(RiskHistory)).all()}
        self.assertEqual(entity_types, {"identity", "cloud_identity"})
        for incident in self.session.scalars(select(Incident)).all():
            self.assertEqual(len(incident.source.split(",")), 1)

    def test_account_run_writes_separate_linux_and_cloud_risk_series(self):
        stored = CorrelationService(self.session).correlate_and_store(owner_id=None, account_id="acct-1")
        self._assert_isolated(stored)
        account_rows = {
            row.entity_type: row.risk_score
            for row in self.session.scalars(select(RiskHistory).where(RiskHistory.entity_key == "account:acct-1")).all()
        }
        self.assertEqual(set(account_rows), {"account", "cloud_account"})
        linux = next(row for row in stored if row["environment"] == LINUX)
        self.assertEqual(account_rows["account"], linux["risk_score"])

    def test_behavior_history_defaults_to_linux_only(self):
        history = CorrelationService(self.session).behavior_history(account_id="acct-1")
        self.assertEqual(history["environment"], LINUX)
        self.assertEqual(history["totals"]["activity"], 2)
        cloud = CorrelationService(self.session).behavior_history(account_id="acct-1", environment=CLOUD)
        self.assertEqual(cloud["totals"]["activity"], 2)


class LinuxBaselineIsolationTests(unittest.TestCase):
    def test_cloud_events_never_enter_linux_behavioral_baseline(self):
        session = _sqlite_session()
        for index in range(3):
            _persist(session, index, source_type="LINUX", event_type="Successful Login", actor="yogesh", minute=index, login_hour=10)
        for index in range(3, 30):
            _persist(session, index, source_type="CLOUD", event_type=CLOUD_LOGIN_SUCCESS, actor="yogesh", minute=index, provider="AZURE", login_hour=3)
        session.commit()
        profile = BehavioralBaselineService(session).build_linux(identity_key="yogesh", owner_id="owner-1")
        self.assertEqual(profile.profile_sample_count, 3)


AZURE_ROW = {
    "eventTimestamp": "2026-03-01T10:15:00.1234567Z",
    "caller": "alice@example.com",
    "operationName": {"value": "Microsoft.Compute/virtualMachines/write"},
    "status": {"value": "Succeeded"},
    "category": {"value": "Administrative"},
    "resourceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
    "resourceType": {"value": "Microsoft.Compute/virtualMachines"},
    "httpRequest": {"clientIpAddress": "203.0.113.7"},
    "correlationId": "c-1",
}


class AzureImporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.azure = self.root / "Azure"
        self.azure.mkdir()
        (self.azure / "activity.json").write_text(json.dumps({"value": [AZURE_ROW]}), encoding="utf-8")
        (self.azure / "notes.txt").write_text("x", encoding="utf-8")
        (self.root / "secret.txt").write_text("do-not-read", encoding="utf-8")
        (self.root / "outside.json").write_text("[]", encoding="utf-8")
        self.session = _sqlite_session()
        self.service = AzureActivityLogImportService(self.session, dataset_root=self.root)

    def tearDown(self):
        self.session.close()
        self.tmp.cleanup()

    def _normalize(self, row, **kwargs):
        return self.service._normalize(row, owner_id="owner-1", source="activity.json", collected_at=COLLECTED, **kwargs)

    def test_e_path_traversal_and_escape_rejected(self):
        for bad in ("../secret.txt", "../outside.json", "..\\outside.json", str(self.root / "outside.json"), str(self.root / "secret.txt")):
            with self.assertRaises(AzureImportPathError, msg=bad):
                self.service.resolve_path(bad)
        with self.assertRaises(AzureImportPathError):
            self.service.resolve_path("notes.txt")
        with self.assertRaises(FileNotFoundError):
            self.service.resolve_path("missing.json")
        self.assertEqual(self.service.resolve_path("activity.json"), (self.azure / "activity.json").resolve())

    def test_e_symlink_escape_rejected(self):
        link = self.azure / "link.json"
        try:
            os.symlink(self.root / "outside.json", link)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is not permitted on this machine.")
        with self.assertRaises(AzureImportPathError):
            self.service.resolve_path("link.json")

    @unittest.skipUnless(os.name == "nt", "NTFS junctions are Windows-only.")
    def test_e_junction_escape_rejected(self):
        import _winapi

        _winapi.CreateJunction(str(self.root), str(self.azure / "escape"))
        with self.assertRaises(AzureImportPathError):
            self.service.resolve_path("escape/outside.json")
        with self.assertRaises(AzureImportPathError):
            self.service.resolve_path("escape/secret.txt")

    def test_f_timestamp_present_is_source_event(self):
        event = self._normalize(AZURE_ROW)
        self.assertEqual(event["timestamp_source"], SOURCE_EVENT)
        self.assertEqual(event["timestamp"], datetime(2026, 3, 1, 10, 15, 0, 123456, tzinfo=timezone.utc))
        self.assertEqual(event["collection_timestamp"], COLLECTED)

    def test_f_timestamp_missing_or_invalid_is_collection_fallback(self):
        for row in ({k: v for k, v in AZURE_ROW.items() if k != "eventTimestamp"}, {**AZURE_ROW, "eventTimestamp": "not-a-date"}):
            event = self._normalize(row)
            self.assertEqual(event["timestamp_source"], SOURCE_FALLBACK)
            self.assertEqual(event["timestamp"], COLLECTED)
            self.assertEqual(event["collection_timestamp"], COLLECTED)

    def test_g_event_taxonomy(self):
        cases = [
            (AZURE_ROW, CLOUD_RESOURCE_OPERATION),
            ({**AZURE_ROW, "operationName": {"value": "Microsoft.Authorization/roleAssignments/write"}}, CLOUD_PRIVILEGE_CHANGE),
            ({"time": "2026-03-01T10:00:00Z", "category": "AuditLogs", "operationName": "Add member to role"}, CLOUD_PRIVILEGE_CHANGE),
            ({"time": "2026-03-01T10:00:00Z", "category": "SignInLogs", "operationName": "Sign-in activity", "resultType": "0",
              "properties": {"userPrincipalName": "bob@example.com", "ipAddress": "198.51.100.4"}}, CLOUD_LOGIN_SUCCESS),
            ({"time": "2026-03-01T10:00:00Z", "category": "SignInLogs", "resultType": "50126"}, CLOUD_LOGIN_FAILURE),
            ({"createdDateTime": "2026-03-01T10:00:00Z", "userPrincipalName": "bob@example.com", "status": {"errorCode": 0}}, CLOUD_LOGIN_SUCCESS),
            ({"time": "2026-03-01T10:00:00Z", "category": "SignInLogs", "operationName": "Sign-in activity"}, CLOUD_AUTHENTICATION),
            ({"time": "2026-03-01T10:00:00Z", "category": "ServiceHealth", "operationName": "Incident"}, CLOUD_ACTIVITY),
            ({"time": "2026-03-01T10:00:00Z"}, CLOUD_ACTIVITY),
        ]
        for row, expected in cases:
            self.assertEqual(self._normalize(row)["event_type"], expected, msg=row)
        sign_in = self._normalize(cases[3][0])
        self.assertEqual(sign_in["actor_id"], "bob@example.com")
        self.assertEqual(sign_in["source_ip"], "198.51.100.4")
        failure = self._normalize(cases[4][0])
        self.assertEqual(failure["severity"], "medium")
        resource = self._normalize(AZURE_ROW)
        self.assertEqual(resource["resource_type"], "Microsoft.Compute/virtualMachines")
        self.assertEqual(json.loads(resource["raw_log"]), AZURE_ROW)

    def test_h_normalized_event_is_private_cloud_of_account(self):
        event = self._normalize(AZURE_ROW, account_id="acct-1")
        self.assertEqual(event["source_type"], CLOUD)
        self.assertEqual(event["provider"], "AZURE")
        self.assertEqual(event["data_scope"], DATA_SCOPE_PRIVATE)
        self.assertEqual(event["account_id"], "acct-1")
        self.assertEqual(event["owner_id"], "owner-1")

    def test_h_import_scopes_rows_and_tracks_dataset_import(self):
        result = self.service.import_file("activity.json", owner_id="owner-1", account_id="acct-1")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(result["source_file"], "activity.json")
        self.assertFalse(result["live_monitoring"])
        stored = self.session.scalars(select(Event)).all()
        self.assertEqual(len(stored), 1)
        row = stored[0]
        self.assertEqual((row.source_type, row.provider, row.data_scope, row.account_id, row.owner_id), (CLOUD, "AZURE", DATA_SCOPE_PRIVATE, "acct-1", "owner-1"))
        self.assertEqual(row.timestamp_source, SOURCE_EVENT)
        run = self.session.scalars(select(DatasetImport)).one()
        self.assertEqual((run.dataset_name, run.status, run.records_imported, run.total_records_discovered), ("AZURE_ACTIVITY_LOG", "COMPLETED", 1, 1))
        self.assertEqual(run.source_file, "activity.json")

        analyst = User(id="owner-1", username="u", email="u@example.com", hashed_password="x", role="ANALYST", account_id="acct-1")
        visible = self.session.scalars(select(Event).where(event_visibility_clause(scope="private", user=analyst))).all()
        self.assertEqual(len(visible), 1)

        again = self.service.import_file("activity.json", owner_id="owner-1", account_id="acct-1")
        self.assertTrue(again["already_imported"])
        self.assertEqual(len(self.session.scalars(select(Event)).all()), 1)

    def test_h_cross_account_duplicate_does_not_touch_existing_rows(self):
        self.service.import_file("activity.json", owner_id="owner-1", account_id="acct-1")
        before = self.session.scalars(select(Event)).one()
        original_collection = before.collection_timestamp
        result = self.service.import_file("activity.json", owner_id="owner-2", account_id="acct-2")
        self.assertEqual(result["inserted"], 0)
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(result["dedup_scope"], "GLOBAL_EVENT_HASH")
        after = self.session.scalars(select(Event)).one()
        self.assertEqual(after.account_id, "acct-1")
        self.assertEqual(after.collection_timestamp, original_collection)

    def test_invalid_json_marks_import_failed(self):
        (self.azure / "broken.json").write_text("{not json", encoding="utf-8")
        from backend.core.exceptions import ValidationException

        with self.assertRaises(ValidationException):
            self.service.import_file("broken.json", owner_id="owner-1")
        run = self.session.scalars(select(DatasetImport)).one()
        self.assertEqual(run.status, "FAILED")


if __name__ == "__main__":
    unittest.main()
