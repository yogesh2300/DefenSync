"""Streaming importer for the repository BGL (Blue Gene/L) log."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.parser.bgl_parser import (
    CATEGORY,
    DATASET_NAME,
    DATA_ORIGIN,
    PROVIDER,
    SOURCE_TYPE,
    map_bgl_event_type,
    map_bgl_original_label,
    normalize_bgl_severity,
    parse_bgl_line,
)
from backend.services.datasets.log_dataset_discovery import LogDatasetDiscoveryService
from backend.services.datasets.streaming_import import StreamingLogImportService, event_id_for, risk_score_for


class BGLImportService(StreamingLogImportService):
    dataset_names = (DATASET_NAME,)
    provider = PROVIDER
    source_type = SOURCE_TYPE

    def __init__(self, session: Session, *, discovery: LogDatasetDiscoveryService | None = None) -> None:
        settings = get_settings()
        super().__init__(
            session,
            discovery=discovery
            or LogDatasetDiscoveryService(
                relative_dir=settings.BGL_DATASET_PATH,
                dataset_name=DATASET_NAME,
            ),
        )

    def _event_payload(
        self,
        *,
        line: str,
        owner_id: str,
        relative_path: str,
        line_number: int,
        file_hash: str,
    ) -> dict[str, Any] | None:
        parsed = parse_bgl_line(line)
        label = map_bgl_original_label(parsed.native_label)
        severity = normalize_bgl_severity(parsed)
        event_type = map_bgl_event_type(parsed)
        origin = DATA_ORIGIN
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
            "classification_note": "BGL is an HPC supercomputer log, not a cloud control-plane dataset.",
        }
        timestamp = parsed.timestamp or datetime.now(timezone.utc)
        raw_line = parsed.raw_line
        return {
            "event_id": event_id_for("bgl", file_hash, line_number, raw_line),
            "server_id": None,
            "owner_id": owner_id,
            "timestamp": timestamp,
            "collection_timestamp": datetime.now(timezone.utc),
            "timestamp_source": "SOURCE_EVENT",
            "hostname": parsed.node or "bgl-public-dataset",
            "username": None,
            "source_ip": None,
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
            "data_origin": origin,
            "dataset_name": DATASET_NAME,
            "is_labelled": label["is_labelled"],
            "original_label": label["original_label"],
            "actor_id": None,
            "resource_id": parsed.node,
            "resource_type": "HPC_NODE",
            "operation": parsed.component,
            "parser_status": parsed.parse_status,
            "login_hour": timestamp.hour if timestamp else None,
        }
