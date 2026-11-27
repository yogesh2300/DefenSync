"""BGL parser and importer tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, SecurityEvent
from backend.parser.bgl_parser import (
    DATA_ORIGIN,
    PROVIDER,
    SOURCE_TYPE,
    map_bgl_event_type,
    map_bgl_original_label,
    parse_bgl_line,
)
from backend.services.datasets.bgl_import_service import BGLImportService
from backend.services.datasets.log_dataset_discovery import LogDatasetDiscoveryService
from backend.services.detection_service import FEATURE_NAMES, DetectionService


NORMAL_LINE = (
    "- 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 2005-06-03-15.42.50.363779 "
    "R02-M1-N0-C:J12-U11 RAS KERNEL INFO instruction cache parity error corrected"
)
ALERT_LINE = (
    "KERNDTLB 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 2005-06-03-15.42.50.363779 "
    "R02-M1-N0-C:J12-U11 RAS KERNEL FATAL instruction cache parity error corrected"
)


class BGLDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.bgl = self.root / "BGL"
        self.bgl.mkdir()
        (self.bgl / "BGL.log").write_text(f"{NORMAL_LINE}\n{ALERT_LINE}\nnot-a-bgl-line\n", encoding="utf-8")
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def discovery(self) -> LogDatasetDiscoveryService:
        return LogDatasetDiscoveryService(relative_dir="BGL", dataset_name="LOGHUB_BGL", dataset_root=self.root)

    def test_parser_normal_line(self) -> None:
        parsed = parse_bgl_line(NORMAL_LINE)
        self.assertEqual(parsed.parse_status, "PARSED")
        self.assertEqual(parsed.native_label, "-")
        self.assertEqual(parsed.timestamp.year, 2005)
        self.assertEqual(parsed.timestamp.hour, 15)
        self.assertIn("instruction cache", parsed.message)
        self.assertEqual(map_bgl_original_label(parsed.native_label)["original_label"], "NORMAL")
        self.assertEqual(map_bgl_event_type(parsed), "HPC_ACTIVITY")

    def test_parser_alert_line_preserves_native_label(self) -> None:
        parsed = parse_bgl_line(ALERT_LINE)
        label = map_bgl_original_label(parsed.native_label)
        self.assertEqual(label["original_label"], "KERNDTLB")
        self.assertNotEqual(label["original_label"], "ANOMALOUS")
        self.assertEqual(map_bgl_event_type(parsed), "HPC_KERNEL_FAILURE")

    def test_import_unified_schema_and_origin(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = discovery.discover_files()[0].file_id
            run = BGLImportService(session, discovery=discovery).import_file(
                file_id=file_id, owner_id="owner-1", max_records=10, batch_size=2
            )
            self.assertEqual(run.status, "COMPLETED")
            rows = session.query(SecurityEvent).all()
            self.assertEqual(len(rows), 3)
            self.assertTrue(all(row.provider == PROVIDER for row in rows))
            self.assertTrue(all(row.source_type == SOURCE_TYPE for row in rows))
            self.assertTrue(all(row.data_origin == DATA_ORIGIN for row in rows))
            self.assertTrue(all(row.raw_log for row in rows))
            self.assertTrue(all(row.dataset_name == "LOGHUB_BGL" for row in rows))
            self.assertNotEqual(rows[0].source_type, "LINUX")
            normals = [row for row in rows if row.original_label == "NORMAL"]
            alerts = [row for row in rows if row.original_label == "KERNDTLB"]
            self.assertEqual(len(normals), 1)
            self.assertEqual(len(alerts), 1)
        finally:
            session.close()

    def test_deduplication(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = discovery.discover_files()[0].file_id
            service = BGLImportService(session, discovery=discovery)
            first = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            second = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            self.assertFalse(first["already_imported"])
            self.assertTrue(second["already_imported"])
            self.assertEqual(session.query(SecurityEvent).count(), first["records_imported"])
        finally:
            session.close()

    def test_feature_vector_does_not_require_linux_metrics(self) -> None:
        parsed = parse_bgl_line(ALERT_LINE)
        event = SecurityEvent()
        event.timestamp = parsed.timestamp
        event.event_type = map_bgl_event_type(parsed)
        event.severity = "critical"
        event.source_type = SOURCE_TYPE
        event.resource_id = parsed.node
        event.username = None
        event.source_ip = None
        row = DetectionService._row(event)
        self.assertEqual(len(row), len(FEATURE_NAMES))
        self.assertTrue(all(isinstance(value, float) for value in row))
        self.assertEqual(row[FEATURE_NAMES.index("cpu_usage")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("source_hpc")], 1.0)
        self.assertEqual(row[FEATURE_NAMES.index("source_cloud")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("source_linux")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("has_resource")], 1.0)
        self.assertEqual(row[FEATURE_NAMES.index("failure_flag")], 1.0)


if __name__ == "__main__":
    unittest.main()
