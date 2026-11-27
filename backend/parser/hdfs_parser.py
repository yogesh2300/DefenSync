"""Fault-tolerant parser for the Loghub HDFS_v1 private-cloud Hadoop log.

HDFS_v1 was generated in a private cloud using benchmark workloads. It is a
distributed-storage / cloud-infrastructure log, not a Linux SSH security log
and not an OpenStack control-plane dump.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


DATASET_NAME = "LOGHUB_HDFS"
PROVIDER = "HDFS"
DATA_ORIGIN = "PUBLIC_DATASET"
SOURCE_TYPE = "CLOUD"
CATEGORY = "cloud"

_LINE = re.compile(
    r"^(?P<date>\d{6})\s+(?P<time>\d{6})\s+(?P<pid>\d+)\s+(?P<level>[A-Z]+)\s+"
    r"(?P<component>[^:]+):\s*(?P<message>.*)$"
)
_BLOCK = re.compile(r"blk_-?\d+")
_IP = re.compile(r"/((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?")


@dataclass(slots=True)
class HDFSParsedLog:
    raw_line: str
    parse_status: str
    timestamp: datetime | None = None
    pid: str | None = None
    level: str | None = None
    component: str | None = None
    message: str = ""
    block_id: str | None = None
    source_ip: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_type": SOURCE_TYPE,
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "dataset_name": DATASET_NAME,
            "parse_status": self.parse_status,
            "pid": self.pid,
            "level": self.level,
            "component": self.component,
            "block_id": self.block_id,
            **self.metadata,
        }


def parse_hdfs_line(line: str) -> HDFSParsedLog:
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return HDFSParsedLog(raw_line=raw, parse_status="FAILED", message="", metadata={"error": "empty line"})

    match = _LINE.match(raw)
    if not match:
        return HDFSParsedLog(
            raw_line=raw,
            parse_status="PARTIAL",
            message=raw,
            metadata={"error": "line did not match HDFS Loghub prefix"},
        )

    message = match.group("message").strip()
    block_match = _BLOCK.search(raw)
    ip_match = _IP.search(raw)
    timestamp = _parse_hdfs_timestamp(match.group("date"), match.group("time"))
    return HDFSParsedLog(
        raw_line=raw,
        parse_status="PARSED" if timestamp else "PARTIAL",
        timestamp=timestamp,
        pid=match.group("pid"),
        level=match.group("level"),
        component=match.group("component").strip(),
        message=message,
        block_id=block_match.group(0) if block_match else None,
        source_ip=ip_match.group(1) if ip_match else None,
    )


def map_hdfs_event_type(parsed: HDFSParsedLog) -> str:
    text = f"{parsed.component or ''} {parsed.message or ''}".lower()
    if "exception" in text:
        return "HDFS_EXCEPTION"
    if "interrupted" in text:
        return "HDFS_INTERRUPT"
    if "verification succeeded" in text:
        return "HDFS_VERIFICATION"
    if "terminating" in text:
        return "HDFS_PACKET_COMPLETE"
    if "receiving block" in text or "received block" in text or "allocateblock" in text:
        return "HDFS_BLOCK_TRANSFER"
    if (parsed.level or "").upper() in {"WARN", "WARNING"}:
        return "HDFS_WARNING"
    if (parsed.level or "").upper() in {"ERROR", "FATAL"}:
        return "HDFS_ERROR"
    return "HDFS_ACTIVITY"


def normalize_hdfs_severity(parsed: HDFSParsedLog) -> str:
    level = (parsed.level or "").upper()
    if level in {"FATAL", "CRITICAL"}:
        return "critical"
    if level == "ERROR":
        return "high"
    if level in {"WARN", "WARNING"}:
        return "medium"
    return "info"


def map_hdfs_original_label(native_label: str | None) -> dict[str, Any]:
    """Map HDFS_v1 block ground-truth labels from anomaly_label.csv.

    Normal -> NORMAL, Anomaly -> ANOMALOUS. Other tokens are preserved as-is
    and are not coerced into ANOMALOUS.
    """
    token = (native_label or "").strip()
    if not token:
        return {
            "original_label": None,
            "is_labelled": False,
            "label_source": "hdfs_anomaly_label",
            "label_confidence": 0.0,
            "native_label": token,
        }
    lowered = token.lower()
    if lowered == "normal":
        mapped = "NORMAL"
    elif lowered == "anomaly":
        mapped = "ANOMALOUS"
    else:
        mapped = token[:30]
    return {
        "original_label": mapped,
        "is_labelled": True,
        "label_source": "hdfs_anomaly_label",
        "label_confidence": 1.0,
        "native_label": token,
    }


def _parse_hdfs_timestamp(date_s: str, time_s: str) -> datetime | None:
    """HDFS_v1 uses YYMMDD HHMMSS (example: 081109 203518 -> 2008-11-09 20:35:18 UTC)."""
    try:
        year = 2000 + int(date_s[0:2])
        month = int(date_s[2:4])
        day = int(date_s[4:6])
        hour = int(time_s[0:2])
        minute = int(time_s[2:4])
        second = int(time_s[4:6])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None
