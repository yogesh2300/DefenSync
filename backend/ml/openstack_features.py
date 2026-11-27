"""OpenStack (Nova) log parser and time-window feature layer (feature version openstack-v1).

OpenStack is public cloud-infrastructure/API telemetry from the Loghub OpenStack dataset. It is
not Azure telemetry: rows, features and models built here are never mixed with Azure, Linux,
HPC or behavioral data, and nothing here reads from or writes to the database.

Aggregation unit: fixed, non-overlapping WINDOW_MINUTES windows over the time-ordered log lines.
A line belongs to the window that contains its logged timestamp; the source file plays no part.
Windows whose observed activity spans less than MIN_WINDOW_COVERAGE of the window length (the
first/last minutes of a capture) are excluded as partial instead of being scored.

Features describe behaviour inside a window only. Calendar date, time of day, source file name,
request IDs, instance IDs, user/project/IP values, log level and any label are never features;
identities contribute only as distinct counts.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Iterator

import numpy as np

FEATURE_VERSION = "openstack-v1"
WINDOW_MINUTES = 5
MIN_WINDOW_COVERAGE = 0.5
AGGREGATION_UNIT = (
    f"Fixed {WINDOW_MINUTES}-minute windows over all parsed lines, assigned by logged timestamp only; "
    f"windows with activity spanning < {int(MIN_WINDOW_COVERAGE * 100)}% of the window are excluded as partial."
)

FEATURE_NAMES: tuple[str, ...] = (
    "events_total",
    "api_requests",
    "requests_per_minute",
    "get_requests",
    "post_requests",
    "delete_requests",
    "other_method_requests",
    "post_ratio",
    "delete_ratio",
    "status_2xx_ratio",
    "status_4xx_ratio",
    "status_5xx_ratio",
    "latency_mean",
    "latency_p95",
    "latency_max",
    "response_length_mean",
    "response_length_max",
    "compute_api_requests",
    "metadata_api_requests",
    "external_event_requests",
    "compute_manager_events",
    "libvirt_events",
    "claims_events",
    "scheduler_events",
    "vm_started",
    "vm_paused",
    "vm_resumed",
    "vm_stopped",
    "spawn_seconds_mean",
    "spawn_seconds_max",
    "build_seconds_max",
    "destroy_seconds_max",
    "distinct_users",
    "distinct_projects",
    "distinct_active_instances",
    "distinct_client_ips",
)

EXCLUDED_FIELDS: dict[str, str] = {
    "anomaly_label": "Known abnormal instances are used only for post-hoc evaluation, never for training or features.",
    "source_file": "File name separates the abnormal capture from the normal captures.",
    "date": "Each capture covers a different date, so the date would reveal the capture.",
    "time_of_day": "Captures cover different hours; clock time is not behaviour.",
    "line_number": "Position in a file is not behaviour.",
    "request_id": "Unique per request; acts as an identifier.",
    "instance_id": "The anomaly label key; only the number of distinct active instances is used.",
    "user_id / project_id / client_ip values": "Identifiers; only distinct counts per window are used.",
    "log_level": "Severity proxy; excluded with risk_score, severity, alerts and detections.",
}

_LINE_RE = re.compile(
    r"^(?:(?P<source>\S+)\s+)?(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
    r"(?P<pid>\d+)\s+(?P<level>[A-Z]+)\s+(?P<component>\S+)\s*(?P<rest>.*)$"
)
_CONTEXT_RE = re.compile(r"^\[(?P<context>[^\]]*)\]\s*")
_INSTANCE_RE = re.compile(r"\[instance:\s*(?P<instance>[0-9a-fA-F-]{36})\]")
_HTTP_RE = re.compile(
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+\"\s+"
    r"status:\s*(?P<status>\d{3})\s+len:\s*(?P<length>\d+)\s+time:\s*(?P<latency>[\d.]+)"
)
_LIFECYCLE_RE = re.compile(r"VM (?P<state>Started|Paused|Resumed|Stopped) \(Lifecycle Event\)")
_TOOK_RE = re.compile(r"Took (?P<seconds>[\d.]+) seconds to (?P<action>spawn|build|destroy)")


@dataclass(frozen=True)
class OpenStackRecord:
    timestamp: datetime
    level: str
    component: str
    message: str
    request_id: str | None = None
    user_id: str | None = None
    project_id: str | None = None
    instance_id: str | None = None
    client_ip: str | None = None
    method: str | None = None
    path: str | None = None
    status: int | None = None
    response_length: int | None = None
    latency: float | None = None
    source_file: str | None = None
    line_number: int = 0


def _identity(value: str) -> str | None:
    return None if not value or value == "-" else value


def parse_line(line: str, *, source_file: str | None = None, line_number: int = 0) -> OpenStackRecord | None:
    """One Nova log line as a record, or None when the line does not follow the Nova format."""
    match = _LINE_RE.match(line.strip())
    if not match:
        return None
    try:
        timestamp = datetime.fromisoformat(f"{match['date']} {match['time']}")
    except ValueError:
        return None
    rest = match["rest"]
    request_id = user_id = project_id = None
    context = _CONTEXT_RE.match(rest)
    if context:
        parts = context["context"].split()
        if parts and parts[0].startswith("req-"):
            request_id = parts[0]
            user_id = _identity(parts[1]) if len(parts) > 1 else None
            project_id = _identity(parts[2]) if len(parts) > 2 else None
        rest = rest[context.end():]
    instance = _INSTANCE_RE.search(rest)
    http = _HTTP_RE.search(rest)
    return OpenStackRecord(
        timestamp=timestamp,
        level=match["level"],
        component=match["component"],
        message=rest,
        request_id=request_id,
        user_id=user_id,
        project_id=project_id,
        instance_id=instance["instance"].lower() if instance else None,
        client_ip=http["ip"] if http else None,
        method=http["method"] if http else None,
        path=http["path"] if http else None,
        status=int(http["status"]) if http else None,
        response_length=int(http["length"]) if http else None,
        latency=float(http["latency"]) if http else None,
        source_file=source_file if source_file is not None else match["source"],
        line_number=line_number,
    )


@dataclass
class ParseStats:
    lines: int = 0
    parsed: int = 0
    unparsed: int = 0


def iter_file(path: Path, stats: ParseStats | None = None) -> Iterator[OpenStackRecord]:
    stats = stats if stats is not None else ParseStats()
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            stats.lines += 1
            record = parse_line(line, source_file=Path(path).name, line_number=number)
            if record is None:
                stats.unparsed += 1
                continue
            stats.parsed += 1
            yield record


def window_start(timestamp: datetime, minutes: int = WINDOW_MINUTES) -> datetime:
    floored = timestamp.replace(second=0, microsecond=0)
    return floored - timedelta(minutes=floored.minute % minutes)


@dataclass
class _Window:
    first: datetime
    last: datetime
    events: int = 0
    methods: Counter = field(default_factory=Counter)
    statuses: list[int] = field(default_factory=list)
    latencies: list[float] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    components: Counter = field(default_factory=Counter)
    lifecycle: Counter = field(default_factory=Counter)
    took: dict[str, list[float]] = field(default_factory=lambda: {"spawn": [], "build": [], "destroy": []})
    users: set = field(default_factory=set)
    projects: set = field(default_factory=set)
    instances: set = field(default_factory=set)
    ips: set = field(default_factory=set)

    def add(self, record: OpenStackRecord) -> None:
        self.first = min(self.first, record.timestamp)
        self.last = max(self.last, record.timestamp)
        self.events += 1
        component = record.component
        if "osapi_compute" in component:
            self.components["compute_api"] += 1
        elif "metadata" in component:
            self.components["metadata_api"] += 1
        elif "server_external_events" in component:
            self.components["external_events"] += 1
        elif "compute.manager" in component:
            self.components["compute_manager"] += 1
        elif "libvirt" in component:
            self.components["libvirt"] += 1
        elif "compute.claims" in component:
            self.components["claims"] += 1
        elif "scheduler" in component:
            self.components["scheduler"] += 1
        if record.method:
            self.methods[record.method] += 1
            self.statuses.append(record.status or 0)
            self.latencies.append(record.latency or 0.0)
            self.lengths.append(record.response_length or 0)
        lifecycle = _LIFECYCLE_RE.search(record.message)
        if lifecycle:
            self.lifecycle[lifecycle["state"]] += 1
        took = _TOOK_RE.search(record.message)
        if took:
            self.took[took["action"]].append(float(took["seconds"]))
        for target, value in (
            (self.users, record.user_id),
            (self.projects, record.project_id),
            (self.instances, record.instance_id),
            (self.ips, record.client_ip),
        ):
            if value:
                target.add(value)

    def vector(self, minutes: int) -> list[float]:
        requests = len(self.statuses)
        statuses = np.asarray(self.statuses, dtype=float)
        latencies = np.asarray(self.latencies, dtype=float)
        lengths = np.asarray(self.lengths, dtype=float)

        def ratio(count: float) -> float:
            return float(count) / requests if requests else 0.0

        def stat(values: list[float], fn) -> float:
            return float(fn(values)) if values else 0.0

        get, post, delete = self.methods["GET"], self.methods["POST"], self.methods["DELETE"]
        values = {
            "events_total": self.events,
            "api_requests": requests,
            "requests_per_minute": requests / minutes,
            "get_requests": get,
            "post_requests": post,
            "delete_requests": delete,
            "other_method_requests": requests - get - post - delete,
            "post_ratio": ratio(post),
            "delete_ratio": ratio(delete),
            "status_2xx_ratio": ratio(((statuses >= 200) & (statuses < 300)).sum()),
            "status_4xx_ratio": ratio(((statuses >= 400) & (statuses < 500)).sum()),
            "status_5xx_ratio": ratio((statuses >= 500).sum()),
            "latency_mean": float(latencies.mean()) if requests else 0.0,
            "latency_p95": float(np.percentile(latencies, 95)) if requests else 0.0,
            "latency_max": float(latencies.max()) if requests else 0.0,
            "response_length_mean": float(lengths.mean()) if requests else 0.0,
            "response_length_max": float(lengths.max()) if requests else 0.0,
            "compute_api_requests": self.components["compute_api"],
            "metadata_api_requests": self.components["metadata_api"],
            "external_event_requests": self.components["external_events"],
            "compute_manager_events": self.components["compute_manager"],
            "libvirt_events": self.components["libvirt"],
            "claims_events": self.components["claims"],
            "scheduler_events": self.components["scheduler"],
            "vm_started": self.lifecycle["Started"],
            "vm_paused": self.lifecycle["Paused"],
            "vm_resumed": self.lifecycle["Resumed"],
            "vm_stopped": self.lifecycle["Stopped"],
            "spawn_seconds_mean": stat(self.took["spawn"], np.mean),
            "spawn_seconds_max": stat(self.took["spawn"], np.max),
            "build_seconds_max": stat(self.took["build"], np.max),
            "destroy_seconds_max": stat(self.took["destroy"], np.max),
            "distinct_users": len(self.users),
            "distinct_projects": len(self.projects),
            "distinct_active_instances": len(self.instances),
            "distinct_client_ips": len(self.ips),
        }
        return [float(values[name]) for name in FEATURE_NAMES]


@dataclass
class OpenStackWindowMatrix:
    feature_names: tuple[str, ...]
    values: np.ndarray
    window_starts: list[datetime]
    window_minutes: int
    window_instances: list[frozenset[str]]
    excluded_partial: int = 0
    records: int = 0

    def __len__(self) -> int:
        return int(self.values.shape[0])


def build_windows(
    records: Iterable[OpenStackRecord],
    *,
    window_minutes: int = WINDOW_MINUTES,
    min_coverage: float = MIN_WINDOW_COVERAGE,
) -> OpenStackWindowMatrix:
    """Aggregate records into per-window feature vectors ordered by window start.

    `window_instances` holds the instance IDs seen in each window. It exists only so a caller can
    evaluate results against an external label list afterwards; it is never part of `values`.
    """
    windows: dict[datetime, _Window] = {}
    total = 0
    for record in records:
        total += 1
        key = window_start(record.timestamp, window_minutes)
        window = windows.get(key)
        if window is None:
            window = windows[key] = _Window(first=record.timestamp, last=record.timestamp)
        window.add(record)
    min_span = timedelta(minutes=window_minutes) * min_coverage
    starts, rows, instances, partial = [], [], [], 0
    for key in sorted(windows):
        window = windows[key]
        if window.last - window.first < min_span:
            partial += 1
            continue
        starts.append(key)
        rows.append(window.vector(window_minutes))
        instances.append(frozenset(window.instances))
    values = np.asarray(rows, dtype=float).reshape(len(rows), len(FEATURE_NAMES))
    return OpenStackWindowMatrix(
        feature_names=FEATURE_NAMES,
        values=values,
        window_starts=starts,
        window_minutes=window_minutes,
        window_instances=instances,
        excluded_partial=partial,
        records=total,
    )
