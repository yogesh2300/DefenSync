"""Parse source event timestamps separately from DefenSync collection time.

Event occurrence time comes from the Linux/cloud log when present and is always
returned as an aware UTC datetime. Collection time is when DefenSync retrieved
the line (the DefenSync clock, UTC).

Timezone rules (recorded per event as ParsedOccurrence.tz_basis):
- Text carrying Z or a numeric offset (journalctl short-iso, cloud ISO) keeps
  that offset (TZ_SOURCE_OFFSET).
- Audit epoch seconds are UTC by definition (TZ_EPOCH).
- Wall-clock text without a zone (syslog, last -F, lastb -F) is local time of
  the Linux host. When the host timezone captured during collection is passed
  as host_tz it is converted with that zone, DST included (TZ_HOST). Without it
  the wall clock is labelled UTC (TZ_ASSUMED_UTC); the DefenSync server zone is
  never substituted.
Syslog lines without a year infer the year from collection time in the host
zone, rolling back one year if the result would be more than one day ahead.
Epoch seconds are read only from audit record headers (msg=audit(EPOCH:SERIAL))
or from a value that is itself an epoch; numbers inside other text are never dates.
System-state snapshots (ps, df, ...) have no event time: they carry the
collection time marked SOURCE_SNAPSHOT.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

SYSLOG = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
ISO = re.compile(
    r"(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
AUDIT_RECORD_EPOCH = re.compile(r"audit\((\d{9,11}(?:\.\d+)?):\d+\)")
BARE_EPOCH = re.compile(r"\s*(\d{9,11}(?:\.\d+)?)\s*")
LAST_FULL = re.compile(
    r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+"
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<year>\d{4})"
)
UTC_OFFSET = re.compile(r"([+-])(\d{2}):?(\d{2})")
SOURCE_EVENT = "SOURCE_EVENT"
SOURCE_FALLBACK = "COLLECTION_TIME_FALLBACK"
SOURCE_SNAPSHOT = "SNAPSHOT_COLLECTION_TIME"

TZ_SOURCE_OFFSET = "SOURCE_OFFSET"
TZ_EPOCH = "EPOCH_UTC"
TZ_HOST = "HOST_TIMEZONE"
TZ_ASSUMED_UTC = "ASSUMED_UTC"
TZ_COLLECTION_CLOCK = "COLLECTION_CLOCK"


@dataclass(frozen=True, slots=True)
class ParsedOccurrence:
    event_time: datetime
    source: str
    tz_basis: str = TZ_COLLECTION_CLOCK


def collection_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def resolve_host_timezone(name: str | None, utc_offset: str | None = None) -> tzinfo | None:
    """Return the Linux host zone from an IANA name (preferred) or a +HHMM offset, else None."""
    zone_name = (name or "").strip()
    if "zoneinfo/" in zone_name:
        zone_name = zone_name.split("zoneinfo/", 1)[1]
    for prefix in ("posix/", "right/"):
        if zone_name.startswith(prefix):
            zone_name = zone_name[len(prefix):]
    if zone_name:
        try:
            return ZoneInfo(zone_name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    match = UTC_OFFSET.fullmatch((utc_offset or "").strip())
    if match:
        sign = -1 if match.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))
    return None


def _wall_clock(year: int, month: int, day: int, hour: int, minute: int, second: int,
                host_tz: tzinfo | None) -> tuple[datetime, str]:
    if host_tz is None:
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc), TZ_ASSUMED_UTC
    local = datetime(year, month, day, hour, minute, second, tzinfo=host_tz)
    return local.astimezone(timezone.utc), TZ_HOST


def infer_year(month: int, day: int, collected_at: datetime, host_tz: tzinfo | None = None) -> int:
    collected_at = ensure_aware(collected_at)
    local_now = collected_at.astimezone(host_tz) if host_tz else collected_at
    year = local_now.year
    try:
        candidate = datetime(year, month, day, tzinfo=local_now.tzinfo)
    except ValueError:
        return year
    if candidate - local_now > timedelta(days=1):
        return year - 1
    return year


def _parse_iso(raw: str, host_tz: tzinfo | None = None) -> tuple[datetime, str] | None:
    text = raw.strip().replace("Z", "+00:00")
    if " " in text and "T" not in text[:19]:
        text = text.replace(" ", "T", 1)
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-5] + text[-5:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text.split()[0] if " " in text[19:] else text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc), TZ_SOURCE_OFFSET
    if host_tz is not None:
        return parsed.replace(tzinfo=host_tz).astimezone(timezone.utc), TZ_HOST
    return parsed.replace(tzinfo=timezone.utc), TZ_ASSUMED_UTC


def parse_iso(raw: str, *, host_tz: tzinfo | None = None) -> datetime | None:
    parsed = _parse_iso(raw, host_tz)
    return parsed[0] if parsed else None


def _parse_syslog(raw: str, collected_at: datetime, host_tz: tzinfo | None) -> tuple[datetime, str] | None:
    match = SYSLOG.search(raw.strip())
    if not match:
        return None
    month = MONTHS.get(match.group("month"))
    if month is None:
        return None
    day = int(match.group("day"))
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    year = infer_year(month, day, collected_at, host_tz)
    try:
        return _wall_clock(year, month, day, hour, minute, second, host_tz)
    except ValueError:
        return None


def parse_syslog(raw: str, *, collected_at: datetime, host_tz: tzinfo | None = None) -> datetime | None:
    parsed = _parse_syslog(raw, collected_at, host_tz)
    return parsed[0] if parsed else None


def parse_audit_epoch(raw: str) -> datetime | None:
    match = AUDIT_RECORD_EPOCH.search(raw) or BARE_EPOCH.fullmatch(raw)
    if not match:
        return None
    try:
        return datetime.fromtimestamp(float(match.group(1)), tz=timezone.utc)
    except (ValueError, OSError, OverflowError):
        return None


def _parse_last_line(raw: str, collected_at: datetime, host_tz: tzinfo | None) -> tuple[datetime, str] | None:
    match = LAST_FULL.search(raw)
    if match:
        month = MONTHS[match.group("month")]
        day = int(match.group("day"))
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        year = int(match.group("year"))
        try:
            return _wall_clock(year, month, day, hour, minute, second, host_tz)
        except ValueError:
            return None
    return _parse_syslog(raw, collected_at, host_tz)


def parse_last_line(raw: str, *, collected_at: datetime, host_tz: tzinfo | None = None) -> datetime | None:
    parsed = _parse_last_line(raw, collected_at, host_tz)
    return parsed[0] if parsed else None


def parse_occurrence(
    raw: str | None,
    *,
    collected_at: datetime | None = None,
    source_hint: str | None = None,
    explicit: Any = None,
    host_tz: tzinfo | None = None,
) -> ParsedOccurrence:
    collected = ensure_aware(collected_at or collection_now())
    if explicit not in (None, ""):
        if isinstance(explicit, datetime):
            basis = TZ_SOURCE_OFFSET if explicit.tzinfo is not None else TZ_ASSUMED_UTC
            return ParsedOccurrence(ensure_aware(explicit), SOURCE_EVENT, basis)
        for parsed in (_parse_iso(str(explicit), host_tz), _parse_syslog(str(explicit), collected, host_tz)):
            if parsed:
                return ParsedOccurrence(parsed[0], SOURCE_EVENT, parsed[1])
        audit = parse_audit_epoch(str(explicit))
        if audit:
            return ParsedOccurrence(audit, SOURCE_EVENT, TZ_EPOCH)

    text = str(raw or "")
    hint = (source_hint or "").lower()
    if hint == "audit":
        audit = parse_audit_epoch(text)
        if audit:
            return ParsedOccurrence(audit, SOURCE_EVENT, TZ_EPOCH)
    if hint in {"last", "lastb", "who", "w"}:
        last = _parse_last_line(text, collected, host_tz)
        if last:
            return ParsedOccurrence(last[0], SOURCE_EVENT, last[1])
    iso = ISO.search(text)
    if iso:
        parsed = _parse_iso(iso.group("iso"), host_tz)
        if parsed:
            return ParsedOccurrence(parsed[0], SOURCE_EVENT, parsed[1])
    syslog = _parse_syslog(text, collected, host_tz)
    if syslog:
        return ParsedOccurrence(syslog[0], SOURCE_EVENT, syslog[1])
    audit = parse_audit_epoch(text)
    if audit:
        return ParsedOccurrence(audit, SOURCE_EVENT, TZ_EPOCH)
    return ParsedOccurrence(collected, SOURCE_FALLBACK, TZ_COLLECTION_CLOCK)


def login_hour_from(event_time: datetime) -> int:
    """UTC hour of the normalized source event time (the canonical ML convention)."""
    return ensure_aware(event_time).hour


TIME_LABEL_EVENT = "EVENT_TIME"
TIME_LABEL_OBSERVED = "OBSERVED_AT"
TIME_LABEL_COLLECTED = "COLLECTED_AT"


def _utc_or_none(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return ensure_aware(datetime.fromisoformat(str(value).replace("Z", "+00:00"))).astimezone(timezone.utc)
    except ValueError:
        return None


def event_time_view(
    *,
    timestamp: datetime | None,
    collection_timestamp: datetime | None,
    timestamp_source: str | None,
    normalized_data: Any,
    storage_tz: tzinfo,
) -> dict[str, Any]:
    """Explicit UTC event/collection times for presentation; stored values are never altered.

    Naive DB columns are wall-clock in `storage_tz` (PostgreSQL renders aware values in
    its session TimeZone). The canonical UTC copies in normalized_data are preferred.
    `collection_time` is the first collection; the collection_timestamp column is refreshed
    whenever the same occurrence is seen again and is returned as `last_collection_time`.
    `collection_delay_seconds` (collection - event) is reported as is: a negative value
    means the source clock and the DefenSync clock disagree, and nothing is corrected.
    """
    nd = normalized_data
    if isinstance(nd, str):
        try:
            nd = json.loads(nd)
        except ValueError:
            nd = {}
    nd = nd if isinstance(nd, dict) else {}

    def stored(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        aware = value if value.tzinfo else value.replace(tzinfo=storage_tz)
        return aware.astimezone(timezone.utc)

    event_time = _utc_or_none(nd.get("event_time_utc")) or stored(timestamp)
    last_collection = stored(collection_timestamp)
    collection_time = _utc_or_none(nd.get("first_collection_time_utc")) or last_collection
    record_kind = nd.get("record_kind")
    if record_kind == "SYSTEM_SNAPSHOT" or timestamp_source == SOURCE_SNAPSHOT:
        label = TIME_LABEL_OBSERVED
    elif timestamp_source == SOURCE_FALLBACK:
        label = TIME_LABEL_COLLECTED
    else:
        label = TIME_LABEL_EVENT
    delay = None
    if label == TIME_LABEL_EVENT and event_time and collection_time:
        delay = round((collection_time - event_time).total_seconds(), 3)
    return {
        "event_time": event_time,
        "collection_time": collection_time,
        "last_collection_time": last_collection,
        "record_kind": record_kind,
        "record_origin": nd.get("record_origin"),
        "time_label": label,
        "collection_delay_seconds": delay,
        "source_time_after_collection": delay is not None and delay < 0,
    }
