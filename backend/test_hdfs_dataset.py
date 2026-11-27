"""HDFS parser and importer tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, SecurityEvent
from backend.parser.hdfs_parser import (
    DATA_ORIGIN,
    PROVIDER,
    SOURCE_TYPE,
    map_hdfs_event_type,
    map_hdfs_original_label,
    parse_hdfs_line,
)
from backend.services.datasets.hdfs_import_service import HDFSImportService
from backend.services.datasets.log_dataset_discovery import LogDatasetDiscoveryService
from backend.services.detection_service import FEATURE_NAMES, DetectionService


NORMAL_LINE = (
    "081109 203518 143 INFO dfs.DataNode$DataXceiver: "
    "Receiving block blk_-1608999687919862906 src: /10.250.19.102:54106 dest: /10.250.19.102:50010"
)
ANOMALY_LINE = (
    "081109 203519 29 ERROR dfs.DataNode$DataXceiver: "
    "writeBlock blk_-3544583377289625738 received exception java.io.IOException"
)


class HDFSDatasetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.hdfs = self.root / "HDFS"
        self.hdfs.mkdir()
        (self.hdfs / "HDFS.log").write_text(f"{NORMAL_LINE}\n{ANOMALY_LINE}\n", encoding="utf-8")
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self) -> None:
        self.engine.dispose()
        self.tmp.cleanup()

    def discovery(self) -> LogDatasetDiscoveryService:
        return LogDatasetDiscoveryService(relative_dir="HDFS", dataset_name="LOGHUB_HDFS", dataset_root=self.root)

    def test_parser_extracts_block_timestamp_and_ip(self) -> None:
        parsed = parse_hdfs_line(NORMAL_LINE)
        self.assertEqual(parsed.parse_status, "PARSED")
        self.assertEqual(parsed.timestamp.year, 2008)
        self.assertEqual(parsed.timestamp.month, 11)
        self.assertEqual(parsed.timestamp.day, 9)
        self.assertEqual(parsed.block_id, "blk_-1608999687919862906")
        self.assertEqual(parsed.source_ip, "10.250.19.102")
        self.assertEqual(map_hdfs_event_type(parsed), "HDFS_BLOCK_TRANSFER")

    def test_label_mapping(self) -> None:
        self.assertEqual(map_hdfs_original_label("Normal")["original_label"], "NORMAL")
        self.assertEqual(map_hdfs_original_label("Anomaly")["original_label"], "ANOMALOUS")
        self.assertEqual(map_hdfs_original_label("other")["original_label"], "other")

    def test_import_applies_block_labels(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = discovery.discover_files()[0].file_id
            labels = {
                "blk_-1608999687919862906": "Normal",
                "blk_-3544583377289625738": "Anomaly",
            }
            run = HDFSImportService(session, discovery=discovery, label_map=labels).import_file(
                file_id=file_id, owner_id="owner-1", max_records=10, batch_size=1
            )
            self.assertEqual(run.records_imported, 2)
            rows = {row.resource_id: row for row in session.query(SecurityEvent).all()}
            self.assertEqual(rows["blk_-1608999687919862906"].original_label, "NORMAL")
            self.assertEqual(rows["blk_-3544583377289625738"].original_label, "ANOMALOUS")
            self.assertTrue(all(row.provider == PROVIDER for row in rows.values()))
            self.assertTrue(all(row.source_type == SOURCE_TYPE for row in rows.values()))
            self.assertTrue(all(row.data_origin == DATA_ORIGIN for row in rows.values()))
            self.assertTrue(all(row.raw_log for row in rows.values()))
        finally:
            session.close()

    def test_deduplication(self) -> None:
        session = self.Session()
        try:
            discovery = self.discovery()
            file_id = discovery.discover_files()[0].file_id
            service = HDFSImportService(session, discovery=discovery, label_map={})
            first = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            second = service.import_and_prepare(file_id=file_id, owner_id="owner-1")
            self.assertTrue(second["already_imported"])
            self.assertEqual(session.query(SecurityEvent).count(), first["records_imported"])
        finally:
            session.close()

    def test_feature_vector_uses_cloud_family(self) -> None:
        parsed = parse_hdfs_line(ANOMALY_LINE)
        event = SecurityEvent()
        event.timestamp = parsed.timestamp
        event.event_type = map_hdfs_event_type(parsed)
        event.severity = "high"
        event.source_type = SOURCE_TYPE
        event.resource_id = parsed.block_id
        event.source_ip = parsed.source_ip
        row = DetectionService._row(event)
        self.assertEqual(len(row), len(FEATURE_NAMES))
        self.assertEqual(row[FEATURE_NAMES.index("source_cloud")], 1.0)
        self.assertEqual(row[FEATURE_NAMES.index("source_hpc")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("source_linux")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("cpu_usage")], 0.0)
        self.assertEqual(row[FEATURE_NAMES.index("has_resource")], 1.0)
        self.assertEqual(row[FEATURE_NAMES.index("failure_flag")], 1.0)
        parsed_with_ip = parse_hdfs_line(NORMAL_LINE)
        event_with_ip = SecurityEvent()
        event_with_ip.timestamp = parsed_with_ip.timestamp
        event_with_ip.event_type = map_hdfs_event_type(parsed_with_ip)
        event_with_ip.severity = "info"
        event_with_ip.source_type = SOURCE_TYPE
        event_with_ip.source_ip = parsed_with_ip.source_ip
        ip_row = DetectionService._row(event_with_ip)
        self.assertEqual(ip_row[FEATURE_NAMES.index("remote_ip")], 1.0)


if __name__ == "__main__":
    unittest.main()
