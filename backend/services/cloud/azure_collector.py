"""Read-only Azure telemetry collector: Log Analytics -> cloud normalizer -> events table.

Sources: Microsoft Entra sign-in logs (`SigninLogs`) and the Azure Activity Log
(`AzureActivity`), both read from one Log Analytics workspace. Collection is manual
(API-triggered) over a bounded window: a recent lookback (at most MAX_WINDOW_MINUTES)
or an explicit historical start/end bounded by CollectionLimits. Repeating or
overlapping a window is safe because rows are deduplicated by the account-scoped
Azure hash. Nothing in this module writes to Azure.
"""

from __future__ import annotations

import logging
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.core.environments import CLOUD
from backend.core.timestamps import collection_now, ensure_aware
from backend.database import crud
from backend.database.models import DATA_SCOPE_PRIVATE
from backend.services.cloud.azure_client import (
    NOT_CONFIGURED,
    QUERY_FAILED,
    SOURCE_NOT_AVAILABLE,
    AzureCollectorError,
    LogAnalyticsClient,
    Transport,
)
from backend.services.cloud.azure_normalizer import (
    AZURE_ACTIVITY,
    DATA_ORIGIN,
    DEDUP_SCHEME,
    ENTRA_SIGNIN,
    PROVIDER,
    SOURCE_TABLES,
    MalformedAzureRecord,
    normalize_record,
)

logger = logging.getLogger(__name__)

STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_CONFIGURED = "CONFIGURED"
STATUS_COLLECTION_OK = "COLLECTION_OK"
STATUS_COLLECTION_FAILED = "COLLECTION_FAILED"

# Overall outcome of one collection, independent of the legacy status above.
OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_PARTIAL = "PARTIAL"
OUTCOME_FAILED = "FAILED"
SOURCE_OK = "OK"
NOT_QUERIED = "NOT_QUERIED"
TRUNCATED = "TRUNCATED"
ROWS_FAILED = "ROWS_FAILED"
PARTIAL_RESULT = "PARTIAL_RESULT"

SOURCES = (ENTRA_SIGNIN, AZURE_ACTIVITY)
DEFAULT_LOOKBACK_MINUTES = 15
# Upper bound of lookback_minutes (a recent window ending now).
MAX_WINDOW_MINUTES = 1440
DEFAULT_MAX_WINDOW_HOURS = 168
DEFAULT_MAX_HISTORY_DAYS = 90
DEFAULT_MAX_RECORDS = 500
MAX_RECORDS_LIMIT = 5000
MAX_FUTURE_SKEW = timedelta(minutes=5)
INSERT_BATCH_SIZE = 500
MAX_REPORTED_ERRORS = 20
REQUIRED_SETTINGS = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_LOG_ANALYTICS_WORKSPACE_ID")

_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_TENANT_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$", re.IGNORECASE)
_SOURCE_FATAL_CONTINUE = {SOURCE_NOT_AVAILABLE, QUERY_FAILED}


class _LastRun:
    """Process-local summary of the latest collection (no secrets); not persisted."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: dict[str, Any] | None = None

    def get(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._value) if self._value else None

    def set(self, value: dict[str, Any]) -> None:
        with self._lock:
            self._value = dict(value)

    def clear(self) -> None:
        with self._lock:
            self._value = None


LAST_RUN = _LastRun()


@dataclass(frozen=True)
class AzureConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    workspace_id: str

    @classmethod
    def from_settings(cls, settings: Settings) -> "AzureConfig":
        secret = settings.AZURE_CLIENT_SECRET
        return cls(
            tenant_id=(settings.AZURE_TENANT_ID or "").strip(),
            client_id=(settings.AZURE_CLIENT_ID or "").strip(),
            client_secret=(secret.get_secret_value() if secret is not None else "").strip(),
            workspace_id=(settings.AZURE_LOG_ANALYTICS_WORKSPACE_ID or "").strip(),
        )

    def __repr__(self) -> str:
        return "AzureConfig(<redacted>)"

    def missing(self) -> list[str]:
        values = (self.tenant_id, self.client_id, self.client_secret, self.workspace_id)
        return [name for name, value in zip(REQUIRED_SETTINGS, values, strict=True) if not value]

    def invalid(self) -> list[str]:
        problems = []
        if self.tenant_id and not (_GUID.match(self.tenant_id) or _TENANT_DOMAIN.match(self.tenant_id)):
            problems.append("AZURE_TENANT_ID")
        if self.client_id and not _GUID.match(self.client_id):
            problems.append("AZURE_CLIENT_ID")
        if self.workspace_id and not _GUID.match(self.workspace_id):
            problems.append("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
        return problems


@dataclass(frozen=True)
class CollectionLimits:
    """Bounds for explicit start/end (historical) windows. Every Azure query stays bounded."""
    max_window_hours: int = DEFAULT_MAX_WINDOW_HOURS
    max_history_days: int = DEFAULT_MAX_HISTORY_DAYS

    @classmethod
    def from_settings(cls, settings: Settings) -> "CollectionLimits":
        hours = getattr(settings, "CLOUD_COLLECTION_MAX_WINDOW_HOURS", None) or DEFAULT_MAX_WINDOW_HOURS
        days = getattr(settings, "CLOUD_COLLECTION_MAX_HISTORY_DAYS", None) or DEFAULT_MAX_HISTORY_DAYS
        return cls(max_window_hours=max(1, int(hours)), max_history_days=max(1, int(days)))

    def view(self) -> dict[str, int]:
        return {
            "max_lookback_minutes": MAX_WINDOW_MINUTES,
            "max_window_hours": self.max_window_hours,
            "max_history_days": self.max_history_days,
            "default_max_records_per_source": DEFAULT_MAX_RECORDS,
            "max_records_per_source": MAX_RECORDS_LIMIT,
        }


def resolve_window(
    *,
    lookback_minutes: int | None,
    start: datetime | None,
    end: datetime | None,
    now: datetime,
    limits: CollectionLimits | None = None,
) -> tuple[datetime, datetime]:
    """Bounded query window. Raises ValueError for unbounded, inverted, too-old, or oversized windows."""
    limits = limits or CollectionLimits()
    if (start is None) != (end is None):
        raise ValueError("start_time and end_time must be provided together.")
    if start is not None and end is not None:
        if lookback_minutes is not None:
            raise ValueError("Use either lookback_minutes or start_time/end_time, not both.")
        start, end = ensure_aware(start), ensure_aware(end)
        if start >= end:
            raise ValueError("start_time must be before end_time.")
        if end > now + MAX_FUTURE_SKEW:
            raise ValueError("end_time cannot be in the future.")
        if end - start > timedelta(hours=limits.max_window_hours):
            raise ValueError(f"A historical collection window cannot exceed {limits.max_window_hours} hours.")
        if start < now - timedelta(days=limits.max_history_days):
            raise ValueError(f"start_time cannot be more than {limits.max_history_days} days ago.")
        return start, end
    minutes = DEFAULT_LOOKBACK_MINUTES if lookback_minutes is None else int(lookback_minutes)
    if minutes < 1:
        raise ValueError("lookback_minutes must be at least 1.")
    if minutes > MAX_WINDOW_MINUTES:
        raise ValueError(f"The collection window cannot exceed {MAX_WINDOW_MINUTES} minutes; use start_time/end_time for older data.")
    return now - timedelta(minutes=minutes), now


def validate_collection_request(sources: list[str] | None, max_records: int | None) -> tuple[list[str], int]:
    """Selected Azure sources (default: all) and the per-source row cap. Raises ValueError."""
    selected = list(dict.fromkeys(sources or SOURCES))
    unknown = [source for source in selected if source not in SOURCES]
    if unknown:
        raise ValueError(f"Unsupported Azure sources: {', '.join(unknown)}")
    limit = DEFAULT_MAX_RECORDS if max_records is None else int(max_records)
    if not 1 <= limit <= MAX_RECORDS_LIMIT:
        raise ValueError(f"max_records must be between 1 and {MAX_RECORDS_LIMIT}.")
    return selected, limit


def build_query(source: str, start: datetime, end: datetime, max_records: int) -> str:
    table = SOURCE_TABLES[source]
    return (
        f"{table}\n"
        f"| where TimeGenerated between (datetime({_kql_time(start)}) .. datetime({_kql_time(end)}))\n"
        f"| sort by TimeGenerated asc\n"
        f"| take {int(max_records)}"
    )


class AzureCollector:
    def __init__(self, session: Session, *, settings: Settings | None = None, transport: Transport | None = None) -> None:
        settings = settings or get_settings()
        self._session = session
        self._config = AzureConfig.from_settings(settings)
        self._limits = CollectionLimits.from_settings(settings)
        self._transport = transport

    def configuration(self) -> dict[str, Any]:
        missing, invalid = self._config.missing(), self._config.invalid()
        return {"configured": not missing and not invalid, "missing_settings": missing, "invalid_settings": invalid}

    def status(self) -> dict[str, Any]:
        config = self.configuration()
        last = LAST_RUN.get()
        if not config["configured"]:
            state = STATUS_NOT_CONFIGURED
        elif last is None:
            state = STATUS_CONFIGURED
        else:
            state = last["status"]
        return {
            "collector": "AZURE",
            "status": state,
            **config,
            "sources": [{"source": source, "table": SOURCE_TABLES[source]} for source in SOURCES],
            "read_only": True,
            "acquisition": "AZURE_LOG_ANALYTICS_QUERY_API",
            "last_collection": last,
        }

    def collect(
        self,
        *,
        owner_id: str,
        account_id: str | None,
        lookback_minutes: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        sources: list[str] | None = None,
        max_records: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """`now` is the reference time for lookback and age limits (defaults to the collection start)."""
        started_at = collection_now()
        window_start, window_end = resolve_window(
            lookback_minutes=lookback_minutes, start=start, end=end, now=now or started_at, limits=self._limits,
        )
        selected, limit = validate_collection_request(sources, max_records)

        collection_id = str(uuid.uuid4())
        result: dict[str, Any] = {
            "collection_id": collection_id,
            "collector": "AZURE",
            "status": STATUS_NOT_CONFIGURED,
            "outcome": OUTCOME_FAILED,
            "configured": False,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "max_records_per_source": limit,
            "records_retrieved": 0,
            "records_normalized": 0,
            "records_failed": 0,
            "records_inserted": 0,
            "records_deduplicated": 0,
            "sources": [],
            "errors": [],
            "error": None,
            "account_id": account_id,
            "source_type": CLOUD,
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "data_scope": DATA_SCOPE_PRIVATE,
            "dedup_scheme": DEDUP_SCHEME,
            "collection_started_at": started_at.isoformat(),
            "collection_completed_at": None,
        }
        config = self.configuration()
        if not config["configured"]:
            result.update(config)
            result["error"] = {"code": NOT_CONFIGURED, "message": "Azure collection is not configured; set " + ", ".join(config["missing_settings"] + config["invalid_settings"]) + "."}
            return self._finish(result)

        result.update(configured=True, status=STATUS_COLLECTION_OK)
        client = LogAnalyticsClient(
            tenant_id=self._config.tenant_id,
            client_id=self._config.client_id,
            client_secret=self._config.client_secret,
            workspace_id=self._config.workspace_id,
            transport=self._transport,
        )
        payloads: list[dict[str, Any]] = []
        for position, source in enumerate(selected):
            source_result = {
                "source": source, "table": SOURCE_TABLES[source], "status": SOURCE_OK,
                "retrieved": 0, "normalized": 0, "failed": 0, "truncated": False, "resume_from": None,
            }
            result["sources"].append(source_result)
            try:
                query = client.query(build_query(source, window_start, window_end, limit), start=window_start, end=window_end)
            except AzureCollectorError as exc:
                source_result.update(status=exc.code, message=exc.message)
                if exc.code in _SOURCE_FATAL_CONTINUE:
                    continue
                result.update(status=STATUS_COLLECTION_FAILED, error={"code": exc.code, "message": exc.message, "retry_after": exc.retry_after})
                result["sources"].extend(
                    {
                        "source": skipped, "table": SOURCE_TABLES[skipped], "status": NOT_QUERIED,
                        "message": "Not queried because an earlier source failed.",
                        "retrieved": 0, "normalized": 0, "failed": 0, "truncated": False, "resume_from": None,
                    }
                    for skipped in selected[position + 1:]
                )
                break
            if query.partial_error:
                source_result["warning"] = f"Partial Log Analytics result ({query.partial_error})."
            columns = [str(column.get("name")) if isinstance(column, dict) else "" for column in query.columns]
            source_result["retrieved"] = len(query.rows)
            source_result["truncated"] = len(query.rows) >= limit
            last_generated = None
            for index, row in enumerate(query.rows):
                try:
                    record = _row_to_record(columns, row)
                    last_generated = record.get("TimeGenerated") or last_generated
                    payloads.append(normalize_record(source, record, owner_id=owner_id, account_id=account_id, collected_at=started_at, collection_id=collection_id))
                    source_result["normalized"] += 1
                except MalformedAzureRecord as exc:
                    source_result["failed"] += 1
                    if len(result["errors"]) < MAX_REPORTED_ERRORS:
                        result["errors"].append({"source": source, "index": index, "error": str(exc)})
            if source_result["truncated"] and last_generated:
                # Rows are sorted by TimeGenerated ascending, so the rest of the window starts here.
                source_result["resume_from"] = str(last_generated)

        for source_result in result["sources"]:
            result["records_retrieved"] += source_result["retrieved"]
            result["records_normalized"] += source_result["normalized"]
            result["records_failed"] += source_result["failed"]
        if result["sources"] and all(item["status"] != SOURCE_OK for item in result["sources"]):
            result["status"] = STATUS_COLLECTION_FAILED
            result["error"] = result["error"] or {"code": result["sources"][0]["status"], "message": "No requested Azure source could be queried."}

        inserted, deduplicated = self._store(payloads)
        result["records_inserted"] = inserted
        result["records_deduplicated"] = deduplicated
        return self._finish(result)

    def _store(self, payloads: list[dict[str, Any]]) -> tuple[int, int]:
        inserted = deduplicated = 0
        for begin in range(0, len(payloads), INSERT_BATCH_SIZE):
            batch = payloads[begin:begin + INSERT_BATCH_SIZE]
            existing = crud.get_existing_event_hashes(self._session, [item["hash"] for item in batch])
            fresh: list[dict[str, Any]] = []
            seen: set[str] = set()
            for item in batch:
                if item["hash"] in existing or item["hash"] in seen:
                    deduplicated += 1
                    continue
                seen.add(item["hash"])
                fresh.append(item)
            if not fresh:
                continue
            try:
                crud.insert_events_with_hash(self._session, fresh)
                self._session.commit()
                inserted += len(fresh)
            except IntegrityError:
                self._session.rollback()
                for item in fresh:
                    try:
                        crud.insert_events_with_hash(self._session, [item])
                        self._session.commit()
                        inserted += 1
                    except IntegrityError:
                        self._session.rollback()
                        deduplicated += 1
        return inserted, deduplicated

    @staticmethod
    def _finish(result: dict[str, Any]) -> dict[str, Any]:
        result["collection_completed_at"] = collection_now().isoformat()
        result["outcome"], result["issues"] = collection_outcome(result)
        summary = {key: result[key] for key in (
            "collection_id", "status", "outcome", "account_id", "window_start", "window_end", "records_retrieved",
            "records_normalized", "records_failed", "records_inserted", "records_deduplicated",
            "collection_started_at", "collection_completed_at", "error",
        )}
        if result["configured"]:
            LAST_RUN.set(summary)
        error = result.get("error") or {}
        if result["status"] == STATUS_COLLECTION_FAILED:
            logger.warning("Azure collection %s failed: %s - %s", result["collection_id"], error.get("code"), error.get("message"))
        logger.info(
            "Azure collection %s status=%s outcome=%s retrieved=%d normalized=%d failed=%d inserted=%d deduplicated=%d",
            result["collection_id"], result["status"], result["outcome"], result["records_retrieved"], result["records_normalized"],
            result["records_failed"], result["records_inserted"], result["records_deduplicated"],
        )
        return result


def collection_outcome(result: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """SUCCESS only when every requested source was queried completely and every row was normalized.

    A source that is missing or failed, a truncated source, rows that could not be normalized and
    partial Log Analytics results each make the run PARTIAL. A run that failed before retrieving
    any row is FAILED. Issues carry safe codes and fixed messages only.
    """
    issues: list[dict[str, Any]] = []
    for item in result.get("sources") or []:
        source = item["source"]
        if item["status"] != SOURCE_OK:
            issues.append({"source": source, "code": item["status"], "message": item.get("message") or "The source could not be queried."})
        if item.get("truncated"):
            resume = f" Collect again from {item['resume_from']} to get the rest of the window." if item.get("resume_from") else ""
            issues.append({"source": source, "code": TRUNCATED, "message": f"Stopped at the {result.get('max_records_per_source')}-row limit.{resume}"})
        if item.get("failed"):
            issues.append({"source": source, "code": ROWS_FAILED, "message": f"{item['failed']} row(s) could not be normalized and were skipped."})
        if item.get("warning"):
            issues.append({"source": source, "code": PARTIAL_RESULT, "message": item["warning"]})
    if result.get("status") != STATUS_COLLECTION_OK:
        return (OUTCOME_PARTIAL if result.get("records_retrieved") else OUTCOME_FAILED), issues
    return (OUTCOME_PARTIAL if issues else OUTCOME_SUCCESS), issues


def _row_to_record(columns: list[str], row: Any) -> dict[str, Any]:
    if not isinstance(row, list) or len(row) != len(columns):
        raise MalformedAzureRecord("Row does not match the result columns.")
    return dict(zip(columns, row, strict=True))


def _kql_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
