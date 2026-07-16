"""Focused tests for Module 2 behavioral telemetry."""

from __future__ import annotations

import csv
import random
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.core.exceptions import ValidationException
from backend.database import crud
from backend.database.models import Base, BehaviorProfile, SecurityEvent
from backend.services.behavioral.baseline_service import BehavioralBaselineService
from backend.services.behavioral.behavior_analysis_service import BehavioralAnalysisService
from backend.services.behavioral.over_efficiency_detector import OverEfficiencyDetector
from backend.services.behavioral.schemas import DATASET_NAME, REQUIRED_COLUMNS, validate_row
from backend.services.behavioral.telemetry_import_service import BehavioralTelemetryImportService, file_id_for
from scripts.generate_behavioral_telemetry import FIELDS, SEED, make_record


class BehavioralModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.behavioral = self.root / "behavioral"
        self.behavioral.mkdir()
        self.csv_path = self.behavioral / "generated_behavioral_telemetry.csv"
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def write_rows(self, rows: list[dict[str, object]]) -> str:
        with self.csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        return file_id_for(self.csv_path.name)

    def test_generator_is_reproducible_and_users_distinct(self) -> None:
        first = [make_record(random.Random(SEED), idx, "NORMAL") for idx in range(5)]
        second = [make_record(random.Random(SEED), idx, "NORMAL") for idx in range(5)]
        self.assertEqual(first, second)
        self.assertEqual(len({row["typing_speed_cpm"] for row in first}), 5)

    def test_csv_validation_rejects_invalid_ratios(self) -> None:
        row = {column: "1" for column in REQUIRED_COLUMNS}
        row.update({"timestamp": "2026-07-15T00:00:00+00:00", "behavior_class": "NORMAL", "data_origin": "SYNTHETIC", "command_error_rate": "1.5"})
        parsed, error = validate_row(row)
        self.assertIsNone(parsed)
        self.assertIn("between 0 and 1", error or "")

    def test_import_limit_duplicate_and_privacy_marking(self) -> None:
        rows = [make_record(random.Random(SEED + idx), idx, "NORMAL") for idx in range(5)]
        file_id = self.write_rows(rows)
        session = self.Session()
        try:
            service = BehavioralTelemetryImportService(session, dataset_root=self.root)
            run = service.import_file(file_id=file_id, owner_id="owner-1", max_records=3, batch_size=2)
            self.assertEqual(run.records_processed, 3)
            self.assertEqual(run.records_imported, 3)
            event = session.query(SecurityEvent).first()
            self.assertEqual(event.source_type, "BEHAVIORAL")
            self.assertEqual(event.data_origin, "SYNTHETIC")
            self.assertNotIn("password", event.raw_log.lower())
            with self.assertRaises(ValidationException):
                service.import_file(file_id=file_id, owner_id="owner-1", max_records=1)
        finally:
            session.close()

    def test_baseline_excludes_anomalous_and_handles_insufficient(self) -> None:
        rng = random.Random(SEED)
        normal_rows = [make_record(rng, idx, "NORMAL") for idx in range(12)]
        anomaly_rows = [make_record(rng, idx + 100, "OVER_EFFICIENCY") for idx in range(3)]
        file_id = self.write_rows(normal_rows + anomaly_rows)
        session = self.Session()
        try:
            BehavioralTelemetryImportService(session, dataset_root=self.root).import_file(file_id=file_id, owner_id="owner-1", max_records=20)
            first = session.query(SecurityEvent).filter(SecurityEvent.original_label == "NORMAL").first()
            profile = BehavioralBaselineService(session).build(identity_key=first.actor_id, server_id=first.server_id, owner_id="owner-1")
            self.assertEqual(profile.status, "INSUFFICIENT_DATA")
            self.assertLess(profile.profile_sample_count, 10)
        finally:
            session.close()

    def test_normal_records_create_active_baseline(self) -> None:
        rows = []
        for idx in range(12):
            row = make_record(random.Random(SEED + idx), 0, "NORMAL")
            row["session_id"] = f"sess-active-{idx}"
            rows.append(row)
        file_id = self.write_rows(rows)
        session = self.Session()
        try:
            BehavioralTelemetryImportService(session, dataset_root=self.root).import_file(file_id=file_id, owner_id="owner-1")
            event = session.query(SecurityEvent).first()
            profile = BehavioralBaselineService(session).build(identity_key=event.actor_id, server_id=event.server_id, owner_id="owner-1")
            self.assertEqual(profile.status, "ACTIVE")
            self.assertEqual(profile.profile_sample_count, 12)
        finally:
            session.close()

    def test_detector_normal_over_efficiency_and_automated_reasons(self) -> None:
        profile = BehaviorProfile(
            owner_id="owner-1",
            identity_key="user-1",
            server_id="server-1",
            average_typing_speed=100,
            std_typing_speed=0,
            average_command_rate=2,
            std_command_rate=0,
            average_command_error_rate=0.1,
            std_command_error_rate=0,
            average_idle_time=100,
            std_idle_time=0,
            average_repeated_command_ratio=0.1,
            std_repeated_command_ratio=0,
            average_session_duration=50,
            std_session_duration=0,
            usual_login_start=8,
            usual_login_end=18,
            status="ACTIVE",
            baseline_version=1,
        )
        normal = SecurityEvent(typing_speed_cpm=100, command_rate_per_minute=2, command_error_rate=0.1, idle_time_seconds=100, repeated_command_ratio=0.1, session_duration_minutes=50, login_hour=10)
        over = SecurityEvent(typing_speed_cpm=210, command_rate_per_minute=4.5, command_error_rate=0.05, idle_time_seconds=10, repeated_command_ratio=0.75, session_duration_minutes=55, login_hour=10)
        auto = SecurityEvent(typing_speed_cpm=260, command_rate_per_minute=8, command_error_rate=0.0, idle_time_seconds=2, repeated_command_ratio=0.9, session_duration_minutes=160, login_hour=23)
        detector = OverEfficiencyDetector()
        self.assertEqual(detector.evaluate(normal, profile).classification, "NORMAL")
        self.assertEqual(detector.evaluate(over, profile).classification, "OVER_EFFICIENCY")
        auto_result = detector.evaluate(auto, profile)
        self.assertEqual(auto_result.classification, "AUTOMATED_ACTIVITY")
        self.assertTrue(auto_result.reasons)

    def test_zero_standard_deviation_does_not_crash_analysis(self) -> None:
        session = self.Session()
        try:
            profile = BehaviorProfile(owner_id="owner-1", identity_key="user-1", server_id="server-1", average_typing_speed=100, std_typing_speed=0, average_command_rate=2, std_command_rate=0, average_command_error_rate=0.1, std_command_error_rate=0, average_idle_time=100, std_idle_time=0, average_repeated_command_ratio=0.1, std_repeated_command_ratio=0, average_session_duration=50, std_session_duration=0, usual_login_start=8, usual_login_end=18, status="ACTIVE", baseline_version=1)
            session.add(profile)
            crud.insert_event(session, {"event_id": "behavior-event", "owner_id": "owner-1", "server_id": "server-1", "timestamp": datetime.now(timezone.utc), "hostname": "behavioral", "event_type": "USER_BEHAVIOR_TELEMETRY", "category": "behavioral", "severity": "info", "risk_score": 0, "message": "m", "raw_log": "{}", "source_type": "BEHAVIORAL", "provider": "LOCAL", "data_origin": "SYNTHETIC", "dataset_name": DATASET_NAME, "actor_id": "user-1", "session_id": "s1", "typing_speed_cpm": 120, "command_rate_per_minute": 2.2, "command_error_rate": 0.1, "idle_time_seconds": 80, "repeated_command_ratio": 0.1, "session_duration_minutes": 55, "login_hour": 9})
            session.commit()
            result = BehavioralAnalysisService(session).analyze_event("behavior-event", owner_id="owner-1")
            self.assertEqual(result["status"], "ANALYZED")
        finally:
            session.close()

    def test_existing_linux_and_openstack_events_still_work_and_filters_summary(self) -> None:
        session = self.Session()
        try:
            crud.insert_event(session, {"event_id": "linux-1", "timestamp": "2026-07-15T00:00:00+00:00", "hostname": "linux", "event_type": "Failed Login", "category": "authentication", "severity": "medium", "risk_score": 45, "message": "Failed password", "raw_log": "Failed password"})
            crud.insert_event(session, {"event_id": "openstack-1", "timestamp": "2026-07-15T00:00:00+00:00", "hostname": "openstack", "event_type": "CLOUD_ACTIVITY", "category": "cloud", "severity": "info", "risk_score": 0, "message": "cloud", "raw_log": "cloud", "source_type": "CLOUD", "provider": "OPENSTACK", "data_origin": "PUBLIC_DATASET", "dataset_name": "LOGHUB_OPENSTACK"})
            rows = [make_record(random.Random(SEED + idx), idx, "NORMAL") for idx in range(3)]
            file_id = self.write_rows(rows)
            BehavioralTelemetryImportService(session, dataset_root=self.root).import_file(file_id=file_id, owner_id="owner-1", max_records=3)
            self.assertEqual(len(crud.query_events(session, source_type="LINUX")), 1)
            self.assertEqual(len(crud.query_events(session, source_type="CLOUD", provider="OPENSTACK")), 1)
            self.assertEqual(len(crud.query_events(session, source_type="BEHAVIORAL", dataset_name=DATASET_NAME)), 3)
            summary = BehavioralAnalysisService(session).summary()
            self.assertEqual(summary["total_behavioral_events"], 3)
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
