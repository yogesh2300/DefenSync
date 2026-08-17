"""Focused tests for the OpenStack public dataset importer module."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import crud
from backend.database.models import Base, SecurityEvent
from backend.parser.openstack_parser import (
    DATA_ORIGIN,
    PROVIDER,
    infer_label_from_path,
    map_openstack_event_type,
    parse_openstack_line,
)
from backend.services.datasets.openstack_discovery import OpenStackDiscoveryService
from backend.services.datasets.openstack_import_service import OpenStackImportService


NORMAL_LINE = (
    '2017-05-14 20:16:02.865 2931 INFO nova.osapi_compute.wsgi.server '
    '[req-12345678-1234-1234-1234-123456789abc '
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb] '
    '10.11.10.1 "GET /v2/servers/detail HTTP/1.1" status: 200 len: 123 time: 0.10'
)

ABNORMAL_LINE = (
    '2017-05-14 20:17:02.865 2931 ERROR nova.compute.manager '
    '[req-22345678-1234-1234-1234-123456789abc] '
    'Unauthorized exception while deleting instance cccccccc-cccc-cccc-cccc-cccccccccccc'
)


class OpenStackDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.openstack = self.root / "OpenStack"
        (self.openstack / "normal").mkdir(parents=True)
        (self.openstack / "abnormal").mkdir(parents=True)
        self.normal_file = self.openstack / "normal" / "openstack_normal.log"
        self.abnormal_file = self.openstack / "abnormal" / "openstack_abnormal.log"
        self.normal_file.write_text(f"{NORMAL_LINE}\nnot a standard openstack line\n", encoding="utf-8")
        self.abnormal_file.write_text(f"{ABNORMAL_LINE}\n", encoding="utf-8")

        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def discovery(self) -> OpenStackDiscoveryService:
        return OpenStackDiscoveryService(dataset_root=self.root, openstack_path="OpenStack")

    def test_file_discovery_returns_safe_metadata(self) -> None:
        files = self.discovery().discover_files()
        self.assertEqual(len(files), 2)
        self.assertTrue(all(not Path(item.relative_path).is_absolute() for item in files))
        self.assertEqual({item.label for item in files}, {"NORMAL", "ANOMALOUS"})

    def test_safe_path_validation_rejects_escape(self) -> None:
        service = OpenStackDiscoveryService(dataset_root=self.root, openstack_path="../outside")
        with self.assertRaises(ValueError):
            _ = service.dataset_dir

    def test_parser_for_representative_normal_line(self) -> None:
        parsed = parse_openstack_line(NORMAL_LINE)
        self.assertEqual(parsed.parse_status, "PARSED")
        self.assertEqual(parsed.normalized_service, "COMPUTE")
        self.assertEqual(parsed.http_method, "GET")
        self.assertEqual(parsed.response_code, 200)
        self.assertEqual(map_openstack_event_type(parsed), "CLOUD_ACTIVITY")

    def test_parser_for_representative_abnormal_line(self) -> None:
        parsed = parse_openstack_line(ABNORMAL_LINE)
        self.assertEqual(parsed.parse_status, "PARSED")
        self.assertEqual(parsed.severity, "ERROR")
        self.assertEqual(map_openstack_event_type(parsed), "CLOUD_AUTHORIZATION_FAILURE")

    def test_parser_failure_does_not_crash_import(self) -> None:
        parsed = parse_openstack_line("this is not parseable")
        self.assertEqual(parsed.parse_status, "PARTIAL")
        self.assertEqual(parsed.raw_line, "this is not parseable")

    def test_labels_are_derived_from_path_only(self) -> None:
        self.assertEqual(infer_label_from_path("normal/openstack.log")["original_label"], "NORMAL")
        self.assertEqual(infer_label_from_path("abnormal/openstack.log")["original_label"], "ANOMALOUS")
        self.assertFalse(infer_label_from_path("mixed/openstack.log")["is_labelled"])

    def test_import_limit_batch_counters_and_raw_retention(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = next(item.file_id for item in discovery.discover_files() if item.label == "NORMAL")
            run = OpenStackImportService(session, discovery=discovery).import_file(
                file_id=file_id,
                owner_id="owner-1",
                max_records=2,
                batch_size=1,
            )
            self.assertEqual(run.records_processed, 2)
            self.assertEqual(run.records_imported, 2)
            rows = session.query(SecurityEvent).all()
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row.raw_log for row in rows))
            self.assertTrue(all(row.provider == PROVIDER for row in rows))
            self.assertTrue(all(row.data_origin == DATA_ORIGIN for row in rows))
            self.assertTrue(all(row.provider != "AZURE" for row in rows))
        finally:
            session.close()

    def test_parser_extracts_request_context_user(self) -> None:
        parsed = parse_openstack_line(NORMAL_LINE)
        self.assertEqual(parsed.user_id, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        self.assertEqual(parsed.tenant_id, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")

    def test_duplicate_import_protection(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = discovery.discover_files()[0].file_id
            service = OpenStackImportService(session, discovery=discovery)
            first = service.import_file(file_id=file_id, owner_id="owner-1", max_records=1, batch_size=1)
            count = session.query(SecurityEvent).count()
            second = service.import_file(file_id=file_id, owner_id="owner-1", max_records=1, batch_size=1)
            self.assertEqual(second.id, first.id)
            self.assertEqual(session.query(SecurityEvent).count(), count)
        finally:
            session.close()

    def test_existing_linux_event_creation_still_works(self) -> None:
        session = self.Session()
        try:
            record = crud.insert_event(
                session,
                {
                    "event_id": "linux-event-1",
                    "timestamp": "2026-07-15T00:00:00+00:00",
                    "hostname": "linux-host",
                    "event_type": "Failed Login",
                    "category": "authentication",
                    "severity": "medium",
                    "risk_score": 45,
                    "message": "Failed password for root",
                    "raw_log": "Failed password for root",
                },
            )
            session.commit()
            self.assertEqual(record.source_type, "LINUX")
            self.assertEqual(record.data_origin, "LIVE_LINUX")
        finally:
            session.close()

    def test_event_filters_return_matching_openstack_records(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = next(item.file_id for item in discovery.discover_files() if item.label == "ANOMALOUS")
            OpenStackImportService(session, discovery=discovery).import_file(
                file_id=file_id,
                owner_id="owner-1",
                max_records=1,
                batch_size=1,
            )
            rows = crud.query_events(
                session,
                owner_id="owner-1",
                source_type="CLOUD",
                provider="OPENSTACK",
                data_origin="PUBLIC_DATASET",
                dataset_name="LOGHUB_OPENSTACK",
                original_label="ANOMALOUS",
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0].original_label, "ANOMALOUS")
        finally:
            session.close()

    def test_synthetic_demo_import_sets_honest_origin_and_yogesh_actor(self) -> None:
        from scripts.generate_openstack_demo import DEMO_USER, OUTPUT, build_lines, generate

        demo_root = self.root / "OpenStack" / "demo"
        demo_root.mkdir(parents=True, exist_ok=True)
        (demo_root / OUTPUT.name).write_text("\n".join(build_lines()) + "\n", encoding="utf-8")
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = next(item.file_id for item in discovery.discover_files() if "demo" in item.relative_path)
            service = OpenStackImportService(session, discovery=discovery)
            result = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            self.assertEqual(result["data_origin"], "SYNTHETIC_CLOUD_DEMO")
            self.assertEqual(result["status"], "COMPLETED")
            rows = session.query(SecurityEvent).all()
            self.assertGreaterEqual(len(rows), 100)
            self.assertLessEqual(len(rows), 300)
            self.assertTrue(all(row.data_origin == "SYNTHETIC_CLOUD_DEMO" for row in rows))
            self.assertTrue(all(row.provider == "OPENSTACK" for row in rows))
            filtered = crud.query_events(session, owner_id="owner-1", source_type="CLOUD", provider="OPENSTACK", limit=500)
            self.assertEqual(len(filtered), len(rows))
            yogesh = [row for row in rows if row.actor_id == DEMO_USER]
            self.assertGreaterEqual(len(yogesh), 3)
            self.assertLess(len(yogesh), len(rows) / 2)
            self.assertTrue(any(row.severity in {"high", "critical"} for row in yogesh))
            self.assertTrue(any(row.severity == "info" for row in rows))
            second = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            self.assertTrue(second["already_imported"])
            self.assertEqual(session.query(SecurityEvent).count(), len(rows))
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
