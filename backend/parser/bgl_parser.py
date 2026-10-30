"""Fault-tolerant parser for the Loghub Blue Gene/L (BGL) supercomputer log.

BGL is an HPC / supercomputer dataset (LLNL BlueGene/L). It is not an OpenStack,
Azure, or AWS cloud control-plane log. Records are stored as operational HPC logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


DATASET_NAME = "LOGHUB_BGL"
PROVIDER = "BGL"
DATA_ORIGIN = "PUBLIC_DATASET"
SOURCE_TYPE = "HPC"
CATEGORY = "hpc"

_LINE = re.compile(
    r"^(?P<label>\S+)\s+(?P<unix>\d+)\s+(?P<date>\d{4}\.\d{2}\.\d{2})\s+(?P<node>\S+)\s+"
    r"(?P<time>\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+)\s+(?P<node_repeat>\S+)\s+"
    r"(?P<kind>\S+)\s+(?P<component>\S+)\s+(?P<level>\S+)\s+(?P<content>.*)$"
)


@dataclass(slots=True)
class BGLParsedLog:
    raw_line: str
    parse_status: str
    timestamp: datetime | None = None
    native_label: str | None = None
    node: str | None = None
    facility: str | None = None
    component: str | None = None
    level: str | None = None
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_type": SOURCE_TYPE,
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "dataset_name": DATASET_NAME,
            "parse_status": self.parse_status,
            "native_label": self.native_label,
            "node": self.node,
            "facility": self.facility,
            "component": self.component,
            "level": self.level,
            **self.metadata,
        }


def parse_bgl_line(line: str) -> BGLParsedLog:
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return BGLParsedLog(raw_line=raw, parse_status="FAILED", message="", metadata={"error": "empty line"})

    match = _LINE.match(raw)
    if not match:
        return BGLParsedLog(
            raw_line=raw,
            parse_status="PARTIAL",
            message=raw,
            metadata={"error": "line did not match BGL Loghub columns"},
        )

    timestamp = _parse_bgl_time(match.group("time")) or _parse_unix(match.group("unix"))
    return BGLParsedLog(
        raw_line=raw,
        parse_status="PARSED" if timestamp else "PARTIAL",
        timestamp=timestamp,
        native_label=match.group("label"),
        node=match.group("node"),
        facility=match.group("kind"),
        component=match.group("component"),
        level=match.group("level"),
        message=match.group("content").strip(),
        metadata={
            "unix_timestamp": match.group("unix"),
            "date_field": match.group("date"),
            "node_repeat": match.group("node_repeat"),
        },
    )


def map_bgl_event_type(parsed: BGLParsedLog) -> str:
    component = (parsed.component or "").upper()
    level = (parsed.level or "").upper()
    if component == "KERNEL" and level in {"FATAL", "FAILURE", "SEVERE"}:
        return "HPC_KERNEL_FAILURE"
    if component in {"APP", "APPLICATION"} and level in {"FATAL", "FAILURE", "SEVERE"}:
        return "HPC_APP_FAILURE"
    if level in {"FATAL", "FAILURE", "SEVERE"}:
        return "HPC_FAILURE"
    if level == "ERROR":
        return "HPC_ERROR"
    if level in {"WARNING", "WARN"}:
        return "HPC_WARNING"
    return "HPC_ACTIVITY"


def normalize_bgl_severity(parsed: BGLParsedLog) -> str:
    level = (parsed.level or "").upper()
    if level in {"FATAL", "FAILURE", "SEVERE", "CRITICAL"}:
        return "critical"
    if level == "ERROR":
        return "high"
    if level in {"WARNING", "WARN"}:
        return "medium"
    return "info"


def map_bgl_original_label(native_label: str | None) -> dict[str, Any]:
    """Preserve the BGL alert-category column.

    '-' is the dataset's non-alert marker and maps to NORMAL.
    Any other token is kept as the native alert category. Those categories are
    reliability/alert tags, not proven security attacks, so they are NOT mapped
    to ANOMALOUS.
    """
    token = (native_label or "").strip()
    if not token:
        return {
            "original_label": None,
            "is_labelled": False,
            "label_source": "bgl_column",
            "label_confidence": 0.0,
            "native_label": token,
        }
    if token == "-":
        return {
            "original_label": "NORMAL",
            "is_labelled": True,
            "label_source": "bgl_column",
            "label_confidence": 1.0,
            "native_label": token,
        }
    return {
        "original_label": token[:30],
        "is_labelled": True,
        "label_source": "bgl_column",
        "label_confidence": 1.0,
        "native_label": token,
    }


def _parse_bgl_time(value: str) -> datetime | None:
    """Parse Loghub BGL time field ``YYYY-MM-DD-HH.MM.SS.ffffff``."""
    try:
        date_s, time_s = value[:10], value[11:]
        year, month, day = (int(part) for part in date_s.split("-"))
        bits = time_s.split(".")
        hour, minute, second = int(bits[0]), int(bits[1]), int(bits[2])
        micros = int((bits[3] + "000000")[:6]) if len(bits) > 3 else 0
        return datetime(year, month, day, hour, minute, second, micros, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _parse_unix(value: str) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None
