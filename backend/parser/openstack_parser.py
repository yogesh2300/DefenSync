"""Fault-tolerant parser and mapper for Loghub OpenStack public logs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


DATASET_NAME = "LOGHUB_OPENSTACK"
PROVIDER = "OPENSTACK"
DATA_ORIGIN = "PUBLIC_DATASET"

SERVICE_MAP = {
    "nova": "COMPUTE",
    "neutron": "NETWORK",
    "keystone": "IDENTITY",
    "cinder": "BLOCK_STORAGE",
    "glance": "IMAGE",
    "swift": "OBJECT_STORAGE",
    "heat": "ORCHESTRATION",
}

_LOG_PREFIX = re.compile(
    r"^(?:(?P<source_log>\S+)\s+)?"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+"
    r"(?:(?P<pid>\d+)\s+)?(?P<severity>[A-Z]+)\s+"
    r"(?P<logger>[A-Za-z0-9_.:-]+)\s+(?P<message>.*)$"
)
_REQ_ID = re.compile(r"\b(?P<request_id>req-[A-Za-z0-9-]+)\b")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_INSTANCE_ID = re.compile(r"\[instance:\s*(?P<instance_id>[0-9a-fA-F-]{36})\]")
_HTTP = re.compile(
    r'"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(?P<path>[^"\s]+)[^"]*"\s+'
    r"(?:status:\s*)?(?P<code>\d{3})?",
    re.IGNORECASE,
)
_BRACKET_BLOCK = re.compile(r"\[(?P<body>[^\]]+)\]")


@dataclass(slots=True)
class OpenStackParsedLog:
    """Structured parser result; raw line is always retained."""

    raw_line: str
    parse_status: str
    timestamp: datetime | None = None
    date: str | None = None
    time: str | None = None
    host: str | None = None
    process: str | None = None
    pid: str | None = None
    request_id: str | None = None
    instance_id: str | None = None
    tenant_id: str | None = None
    user_id: str | None = None
    severity: str | None = None
    message: str = ""
    operation: str | None = None
    resource_id: str | None = None
    resource_type: str | None = None
    source_ip: str | None = None
    http_method: str | None = None
    response_code: int | None = None
    error_info: str | None = None
    service: str | None = None
    normalized_service: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_type": "CLOUD",
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "dataset_name": DATASET_NAME,
            "parse_status": self.parse_status,
            "date": self.date,
            "time": self.time,
            "host": self.host,
            "service": self.service,
            "normalized_service": self.normalized_service,
            "pid": self.pid,
            "request_id": self.request_id,
            "instance_id": self.instance_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "operation": self.operation,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "http_method": self.http_method,
            "response_code": self.response_code,
            "error_info": self.error_info,
            **self.metadata,
        }


def parse_openstack_line(line: str) -> OpenStackParsedLog:
    """Parse one OpenStack log line without raising on malformed input."""
    raw = line.rstrip("\r\n")
    if not raw.strip():
        return OpenStackParsedLog(raw_line=raw, parse_status="FAILED", message="", error_info="empty line")

    match = _LOG_PREFIX.match(raw)
    if match:
        timestamp = _parse_timestamp(match.group("timestamp"))
        logger_name = match.group("logger")
        message = match.group("message").strip()
        service = _service_from_logger(logger_name)
        parsed = OpenStackParsedLog(
            raw_line=raw,
            parse_status="PARSED" if timestamp else "PARTIAL",
            timestamp=timestamp,
            date=timestamp.date().isoformat() if timestamp else None,
            time=timestamp.time().isoformat() if timestamp else None,
            process=logger_name,
            pid=match.group("pid"),
            severity=match.group("severity"),
            message=message,
            service=service,
            normalized_service=SERVICE_MAP.get(service or ""),
            metadata={"logger": logger_name, "source_log": match.group("source_log")},
        )
    else:
        parsed = OpenStackParsedLog(
            raw_line=raw,
            parse_status="PARTIAL",
            message=raw,
            error_info="line did not match common OpenStack prefix",
        )

    _enrich(parsed)
    return parsed


def map_openstack_event_type(parsed: OpenStackParsedLog) -> str:
    """Map parsed message text to a conservative normalized cloud event type."""
    text = f"{parsed.message} {parsed.operation or ''}".lower()

    if _contains_any(text, "unauthorized", "forbidden", "not authorized", "policy doesn't allow"):
        return "CLOUD_AUTHORIZATION_FAILURE"
    if parsed.response_code == 401 or _contains_any(text, "authentication failed", "invalid credentials", "failed auth"):
        return "CLOUD_LOGIN_FAILURE"
    if _contains_any(text, "authenticated", "auth success", "token issued"):
        return "CLOUD_LOGIN_SUCCESS"
    if _contains_any(text, " create ", " created", "booting instance", "build_and_run_instance"):
        if _contains_any(text, "instance", "server", "vm"):
            return "VM_CREATED"
        if "network" in text:
            return "NETWORK_CREATED"
    if _contains_any(text, " delete ", " deleted", "destroy"):
        if _contains_any(text, "instance", "server", "vm"):
            return "VM_DELETED"
        if "network" in text:
            return "NETWORK_DELETED"
    if _contains_any(text, "start instance", "vm started", "powering-on", "resume instance"):
        return "VM_STARTED"
    if _contains_any(text, "stop instance", "vm stopped", "vm paused", "powering-off", "suspend instance"):
        return "VM_STOPPED"
    if _contains_any(text, "attach", "volume attached"):
        return "VOLUME_ATTACHED"
    if _contains_any(text, "detach", "volume detached"):
        return "VOLUME_DETACHED"
    if _contains_any(text, "image") and _contains_any(text, "get", "download", "access"):
        return "IMAGE_ACCESSED"
    if _contains_any(text, "role", "permission") and _contains_any(text, "add", "remove", "update", "changed"):
        return "ROLE_ASSIGNMENT_CHANGED"
    if parsed.response_code and parsed.response_code >= 400:
        return "CLOUD_API_FAILURE"
    if (parsed.severity or "").upper() in {"ERROR", "CRITICAL", "FATAL"}:
        return "CLOUD_ERROR"
    if (parsed.severity or "").upper() in {"WARNING", "WARN"}:
        return "CLOUD_WARNING"
    return "CLOUD_ACTIVITY"


def normalize_openstack_severity(parsed: OpenStackParsedLog) -> str:
    """Normalize OpenStack logger severity to DefenSync severity values."""
    severity = (parsed.severity or "").upper()
    if severity in {"CRITICAL", "FATAL"}:
        return "critical"
    if severity == "ERROR":
        return "high"
    if severity in {"WARNING", "WARN"}:
        return "medium"
    if severity == "DEBUG":
        return "low"
    return "info"


def infer_label_from_path(relative_path: str) -> dict[str, Any]:
    """Infer dataset labels only from clear file/folder naming evidence."""
    lowered = relative_path.replace("\\", "/").lower()
    parts = [part for part in lowered.split("/") if part]
    text = " ".join(parts)

    if any(part in {"abnormal", "anomaly", "anomalous"} for part in parts) or "abnormal" in text:
        return {"original_label": "ANOMALOUS", "is_labelled": True, "label_source": "path", "label_confidence": 0.9}
    if any(part in {"normal"} for part in parts) or "normal" in text:
        return {"original_label": "NORMAL", "is_labelled": True, "label_source": "path", "label_confidence": 0.9}
    return {"original_label": None, "is_labelled": False, "label_source": "unknown", "label_confidence": 0.0}


def _parse_timestamp(value: str) -> datetime | None:
    normalized = value.replace(",", ".").replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _service_from_logger(logger_name: str | None) -> str | None:
    if not logger_name:
        return None
    first = logger_name.split(".", 1)[0].lower()
    return first if first in SERVICE_MAP else None


def _enrich(parsed: OpenStackParsedLog) -> None:
    request = _REQ_ID.search(parsed.raw_line)
    if request:
        parsed.request_id = request.group("request_id")

    instance = _INSTANCE_ID.search(parsed.raw_line)
    if instance:
        parsed.instance_id = instance.group("instance_id")
        parsed.resource_id = parsed.instance_id

    ip_match = _IP.search(parsed.raw_line)
    if ip_match:
        parsed.source_ip = ip_match.group(0)

    http = _HTTP.search(parsed.raw_line)
    if http:
        parsed.http_method = http.group("method").upper()
        path = http.group("path")
        parsed.operation = f"{parsed.http_method} {path}"
        parsed.resource_id = parsed.resource_id or _resource_from_http_path(path)
        if http.group("code"):
            parsed.response_code = int(http.group("code"))

    uuids = [value for value in _UUID.findall(parsed.raw_line) if parsed.request_id != f"req-{value}"]
    if not parsed.resource_id and uuids:
        parsed.resource_id = uuids[0]

    if not parsed.operation:
        parsed.operation = _operation_from_message(parsed.message)
    if not parsed.resource_type:
        parsed.resource_type = parsed.normalized_service

    if (parsed.severity or "").upper() in {"ERROR", "CRITICAL", "FATAL"}:
        parsed.error_info = parsed.message[:500]

    block = _BRACKET_BLOCK.search(parsed.raw_line)
    if block:
        body = block.group("body")
        parsed.metadata["context_block"] = body
        tokens = body.split()
        if tokens and tokens[0].startswith("req-"):
            if len(tokens) > 1 and not parsed.user_id:
                parsed.user_id = tokens[1]
            if len(tokens) > 2 and not parsed.tenant_id:
                parsed.tenant_id = tokens[2]


def _operation_from_message(message: str) -> str | None:
    lowered = message.lower()
    for op in ("create", "delete", "update", "start", "stop", "attach", "detach", "resize", "reboot", "authenticate"):
        if op in lowered:
            return op.upper()
    return None


def _looks_instance_related(message: str) -> bool:
    lowered = message.lower()
    return any(word in lowered for word in ("instance", "server", "vm", "compute"))


def _resource_from_http_path(path: str) -> str | None:
    parts = [part for part in path.split("/") if part]
    for index, part in enumerate(parts):
        if part in {"servers", "instances", "images", "volumes", "networks"} and index + 1 < len(parts):
            candidate = parts[index + 1]
            if _UUID.fullmatch(candidate):
                return candidate
    return None


def _contains_any(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)
