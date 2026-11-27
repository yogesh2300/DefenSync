"""Streaming importer for the repository HDFS_v1 private-cloud Hadoop log."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.parser.hdfs_parser import (
    CATEGORY,
    DATASET_NAME,
    DATA_ORIGIN,
    PROVIDER,
    SOURCE_TYPE,
    map_hdfs_event_type,
    map_hdfs_original_label,
    normalize_hdfs_severity,
    parse_hdfs_line,
)
from backend.services.datasets.log_dataset_discovery import LogDatasetDiscoveryService
from backend.services.datasets.streaming_import import StreamingLogImportService, event_id_for, risk_score_for


class HDFSImportService(StreamingLogImportService):
    dataset_names = (DATASET_NAME,)
    provider = PROVIDER
    source_type = SOURCE_TYPE

    def __init__(
        self,
        session: Session,
        *,
        discovery: LogDatasetDiscoveryService | None = None,
        label_map: dict[str, str] | None = None,
    ) -> None:
        settings = get_settings()
        super().__init__(
            session,
            discovery=discovery
            or LogDatasetDiscoveryService(
                relative_dir=settings.HDFS_DATASET_PATH,
                dataset_name=DATASET_NAME,
            ),
        )
        self._label_map = label_map

    def _load_block_labels(self) -> dict[str, str]:
        root = Path(self._settings.DATASET_ROOT)
        if not root.is_absolute():
            root = Path.cwd() / root
        path = (root / self._settings.HDFS_DATASET_PATH / "preprocessed" / "anomaly_label.csv").resolve()
        if not path.is_file():
            return {}
        labels: dict[str, str] = {}
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                block_id = (row.get("BlockId") or row.get("block_id") or "").strip()
                label = (row.get("Label") or row.get("label") or "").strip()
                if block_id and label:
                    labels[block_id] = label
        return labels

    def _event_payload(
        self,
        *,
        line: str,
        owner_id: str,
        relative_path: str,
        line_number: int,
        file_hash: str,
    ) -> dict[str, Any] | None:
        parsed = parse_hdfs_line(line)
        if self._label_map is None:
            self._label_map = self._load_block_labels()
        native = self._label_map.get(parsed.block_id or "")
        label = map_hdfs_original_label(native)
        severity = normalize_hdfs_severity(parsed)
        event_type = map_hdfs_event_type(parsed)
        metadata = {
            **parsed.to_metadata(),
            "source_file": relative_path,
            "source_file_hash": file_hash,
            "source_line": line_number,
            "label_source": label["label_source"],
            "label_confidence": label["label_confidence"],
            "original_label": label["original_label"],
            "native_label": label["native_label"],
            "is_labelled": label["is_labelled"],
            "classification_note": "HDFS_v1 is a private-cloud Hadoop DFS log with block-level Normal/Anomaly labels.",
        }
        timestamp = parsed.timestamp or datetime.now(timezone.utc)
        raw_line = parsed.raw_line
        return {
            "event_id": event_id_for("hdfs", file_hash, line_number, raw_line),
            "server_id": None,
            "owner_id": owner_id,
            "timestamp": timestamp,
            "collection_timestamp": datetime.now(timezone.utc),
            "timestamp_source": "SOURCE_EVENT",
            "hostname": parsed.component or "hdfs-public-dataset",
            "username": None,
            "source_ip": parsed.source_ip,
            "event_type": event_type,
            "category": CATEGORY,
            "severity": severity,
            "risk_score": risk_score_for(severity, event_type),
            "message": parsed.message or raw_line,
            "raw_log": raw_line,
            "normalized_data": json.dumps(metadata, default=str),
            "metadata": metadata,
            "process": parsed.component,
            "source_type": SOURCE_TYPE,
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "dataset_name": DATASET_NAME,
            "is_labelled": label["is_labelled"],
            "original_label": label["original_label"],
            "actor_id": None,
            "resource_id": parsed.block_id,
            "resource_type": "HDFS_BLOCK" if parsed.block_id else None,
            "operation": parsed.component,
            "parser_status": parsed.parse_status,
            "login_hour": timestamp.hour if timestamp else None,
        }
