"""Azure Activity Log / Entra sign-in *file* importer. Offline import only; this is not live Azure monitoring.

Files must live inside DATASET_ROOT/Azure. Imported rows are CLOUD-family,
PRIVATE telemetry of the importing user's account; they never use the Linux
model, Linux baselines, or Linux correlation.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.environments import CLOUD
from backend.core.exceptions import ValidationException
from backend.core.privacy import redact_secrets
from backend.core.timestamps import collection_now, parse_occurrence
from backend.database import crud
from backend.database.models import DATA_SCOPE_PRIVATE, DatasetImport
from backend.services.ingestion_service import IngestionService

AZURE_SUBDIR = "Azure"
DATASET_NAME = "AZURE_ACTIVITY_LOG"
DATASET_VERSION = "azure-export-file"
DATA_ORIGIN = "AZURE_ACTIVITY_LOG_FILE"
PROVIDER = "AZURE"
SUPPORTED_SUFFIXES = {".json", ".csv"}
MAX_REPORTED_ERRORS = 20
COLUMN_LIMIT = 255
SOURCE_IP_LIMIT = 45

CLOUD_LOGIN_SUCCESS = "CLOUD_LOGIN_SUCCESS"
CLOUD_LOGIN_FAILURE = "CLOUD_LOGIN_FAILURE"
CLOUD_AUTHENTICATION = "CLOUD_AUTHENTICATION"
CLOUD_PRIVILEGE_CHANGE = "CLOUD_PRIVILEGE_CHANGE"
CLOUD_RESOURCE_OPERATION = "CLOUD_RESOURCE_OPERATION"
CLOUD_ACTIVITY = "CLOUD_ACTIVITY"
CLOUD_EVENT_TYPES = (
    CLOUD_LOGIN_SUCCESS,
    CLOUD_LOGIN_FAILURE,
    CLOUD_AUTHENTICATION,
    CLOUD_PRIVILEGE_CHANGE,
    CLOUD_RESOURCE_OPERATION,
    CLOUD_ACTIVITY,
)

SIGN_IN_CATEGORIES = {
    "signinlogs",
    "noninteractiveusersigninlogs",
    "serviceprincipalsigninlogs",
    "managedidentitysigninlogs",
}
SIGN_IN_OPERATIONS = {"sign-in activity"}
PRIVILEGE_OPERATION_PREFIXES = ("microsoft.authorization/roleassignments/", "microsoft.authorization/roledefinitions/")
PRIVILEGE_OPERATIONS = {
    "microsoft.authorization/elevateaccess/action",
    "add member to role",
    "remove member from role",
}
ARM_OPERATION = re.compile(r"^microsoft\.[a-z0-9.]+/.+/(write|delete|action)$", re.I)
UPN_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"


class AzureImportPathError(ValueError):
    """The requested file is outside the approved Azure dataset directory or unsupported."""


class AzureActivityLogImportService:
    def __init__(self, session: Session, *, dataset_root: str | Path | None = None) -> None:
        self._session = session
        self._settings = get_settings()
        self._ingestion = IngestionService(session)
        self._dataset_root = Path(dataset_root or self._settings.DATASET_ROOT)

    @property
    def azure_dir(self) -> Path:
        root = self._dataset_root
        if not root.is_absolute():
            root = Path.cwd() / root
        return (root.resolve() / AZURE_SUBDIR).resolve()

    def resolve_path(self, path: str) -> Path:
        """Resolve a user-supplied path strictly inside DATASET_ROOT/Azure (symlinks resolved first)."""
        if not path or "\x00" in path:
            raise AzureImportPathError("Azure import path is empty or invalid.")
        base = self.azure_dir
        candidate = (base / Path(path)).resolve()
        if not candidate.is_relative_to(base):
            raise AzureImportPathError(
                f"Azure import files must be inside the {AZURE_SUBDIR} dataset directory; '{path}' is outside it."
            )
        if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise AzureImportPathError("Azure import files must be .json or .csv exports.")
        if not candidate.is_file():
            raise FileNotFoundError(path)
        return candidate

    def import_file(
        self,
        path: str,
        *,
        owner_id: str,
        account_id: str | None = None,
        max_records: int = 2000,
        allow_reimport: bool = False,
    ) -> dict[str, Any]:
        if not self._settings.DATASET_IMPORT_ENABLED:
            raise ValidationException("Dataset import is disabled by DATASET_IMPORT_ENABLED=false.")
        file_path = self.resolve_path(path)
        relative = file_path.relative_to(self.azure_dir).as_posix()
        file_hash = _sha256_file(file_path)
        limit = max(1, min(int(max_records), int(self._settings.DATASET_IMPORT_MAX_RECORDS)))

        run = self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.owner_id == owner_id,
                DatasetImport.dataset_name == DATASET_NAME,
                DatasetImport.source_file_hash == file_hash,
            )
        )
        if run is not None and run.status in {"COMPLETED", "PARTIAL"} and not allow_reimport:
            return self._result(run, relative=relative, account_id=account_id, already_imported=True)

        run = run or DatasetImport(owner_id=owner_id, dataset_name=DATASET_NAME, source_file_hash=file_hash)
        now = datetime.now(timezone.utc)
        run.dataset_version = DATASET_VERSION
        run.source_file = relative
        run.status = "RUNNING"
        run.total_records_discovered = 0
        run.records_processed = 0
        run.records_imported = 0
        run.records_skipped = 0
        run.records_failed = 0
        run.batch_size = int(self._settings.DATASET_IMPORT_BATCH_SIZE)
        run.import_limit = limit
        run.started_at = now
        run.completed_at = None
        run.error_message = None
        run.updated_at = now
        self._session.add(run)
        self._session.commit()

        errors: list[dict[str, Any]] = []
        counters = {"imported": 0, "skipped": 0, "failed": 0}
        try:
            records = self._read(file_path)
            run.total_records_discovered = len(records)
            selected = records[:limit]
            collected_at = collection_now()
            payloads: list[dict[str, Any]] = []
            for index, row in enumerate(selected):
                if not isinstance(row, dict):
                    counters["failed"] += 1
                    errors.append({"index": index, "error": "Record is not a JSON object / CSV row."})
                    continue
                payloads.append(
                    self._normalize(
                        row,
                        owner_id=owner_id,
                        source=relative,
                        account_id=account_id,
                        collected_at=collected_at,
                        import_id=run.id,
                    )
                )
            run.records_processed = len(selected)
            self._ingest(payloads, counters, errors)
        except Exception as exc:
            self._session.rollback()
            run.status = "FAILED"
            run.error_message = f"{type(exc).__name__}: {exc}"[:1000]
            run.completed_at = datetime.now(timezone.utc)
            run.updated_at = run.completed_at
            self._session.add(run)
            self._session.commit()
            if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError, csv.Error)):
                raise ValidationException(f"Azure export file could not be parsed: {type(exc).__name__}.") from exc
            raise

        run.records_imported = counters["imported"]
        run.records_skipped = counters["skipped"]
        run.records_failed = counters["failed"]
        if counters["failed"] and counters["imported"]:
            run.status = "PARTIAL"
        elif counters["failed"] and not counters["imported"]:
            run.status = "FAILED"
        else:
            run.status = "COMPLETED"
        failures = [item for item in errors if item.get("error") != "Duplicate event ignored"]
        run.error_message = "; ".join(f"#{item.get('index')}: {item.get('error')}" for item in failures[:5])[:1000] or None
        run.completed_at = datetime.now(timezone.utc)
        run.updated_at = run.completed_at
        self._session.add(run)
        self._session.commit()
        return self._result(run, relative=relative, account_id=account_id, errors=failures[:MAX_REPORTED_ERRORS])

    def _ingest(self, payloads: list[dict[str, Any]], counters: dict[str, int], errors: list[dict[str, Any]]) -> None:
        """Insert in batches. Rows whose global hash already exists are skipped without touching
        the stored row, so an import never rewrites another account's events."""
        batch_size = max(1, int(self._settings.DATASET_IMPORT_BATCH_SIZE))
        for start in range(0, len(payloads), batch_size):
            batch = payloads[start:start + batch_size]
            hashes = [
                crud.calculate_event_hash(
                    item["raw_log"],
                    item["timestamp"],
                    server_id=None,
                    event_type=item["event_type"],
                    username=item.get("username"),
                    source_ip=item.get("source_ip"),
                )
                for item in batch
            ]
            existing = crud.get_existing_event_hashes(self._session, hashes)
            fresh = [item for item, value in zip(batch, hashes, strict=True) if value not in existing]
            counters["skipped"] += len(batch) - len(fresh)
            if not fresh:
                continue
            result = self._ingestion.ingest_bulk_events(fresh)
            counters["imported"] += int(result.get("inserted") or 0)
            counters["skipped"] += int(result.get("duplicates") or 0)
            counters["failed"] += int(result.get("failed") or 0)
            for item in result.get("errors") or []:
                errors.append({**item, "index": start + int(item.get("index") or 0)})

    @staticmethod
    def _result(
        run: DatasetImport,
        *,
        relative: str,
        account_id: str | None,
        already_imported: bool = False,
        errors: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "import_id": run.id,
            "status": run.status,
            "dataset": DATASET_NAME,
            "source_file": relative,
            "provider": PROVIDER,
            "source_type": CLOUD,
            "data_origin": DATA_ORIGIN,
            "data_scope": DATA_SCOPE_PRIVATE,
            "account_id": account_id,
            "label": "Azure Activity Log Import",
            "live_monitoring": False,
            "already_imported": already_imported,
            "total_records_discovered": run.total_records_discovered,
            "records_processed": run.records_processed,
            "inserted": run.records_imported,
            "duplicates": run.records_skipped,
            "failed": run.records_failed,
            "errors": errors or [],
            "dedup_scope": "GLOBAL_EVENT_HASH",
        }

    def _read(self, path: Path) -> list[Any]:
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() == ".csv":
            return list(csv.DictReader(io.StringIO(text)))
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("value", "records", "events"):
                if isinstance(data.get(key), list):
                    return data[key]
            return [data]
        return data if isinstance(data, list) else []

    def _normalize(
        self,
        row: dict[str, Any],
        *,
        owner_id: str | None,
        source: str,
        account_id: str | None = None,
        collected_at: datetime | None = None,
        import_id: str | None = None,
    ) -> dict[str, Any]:
        collected = collected_at or collection_now()
        properties = _properties(row)
        source_time = row.get("eventTimestamp") or row.get("time") or row.get("timestamp") or row.get("createdDateTime")
        occurrence = parse_occurrence(None, collected_at=collected, explicit=source_time)
        caller = _caller(row, properties)
        operation = _value(row.get("operationName")) or _value(row.get("operation")) or "AzureActivity"
        status = _value(row.get("status"))
        if isinstance(row.get("status"), dict) and status is None:
            status = row["status"].get("errorCode")
        sign_in = _is_sign_in(row)
        sign_in_failed = _sign_in_failed(row, properties) if sign_in else None
        event_type = classify_azure_event(row, operation=str(operation), sign_in=sign_in, sign_in_failed=sign_in_failed)
        failed = str(status).lower() in {"failed", "failure"} or sign_in_failed is True
        severity = "medium" if failed else "info"
        risk = 70 if failed else 20
        resource = row.get("resourceId") or row.get("resource")
        metadata = {
            "azure_category": _value(row.get("category")),
            "operation": str(operation),
            "status": None if status is None else str(status),
            "result_type": row.get("resultType"),
            "correlation_id": row.get("correlationId"),
            "event_data_id": row.get("eventDataId"),
            "source_file": source,
            "import_id": import_id,
            "timestamp_source": occurrence.source,
            "source_timestamp_raw": None if source_time is None else str(source_time),
        }
        return {
            "timestamp": occurrence.event_time,
            "collection_timestamp": collected,
            "timestamp_source": occurrence.source,
            "hostname": str(row.get("resourceGroupName") or row.get("resourceGroup") or "azure"),
            "username": _clip(caller),
            "actor_id": _clip(caller),
            "source_ip": _source_ip(row, properties),
            "event_type": event_type,
            "category": "cloud",
            "severity": severity,
            "risk_score": risk,
            "message": f"{operation} status={status}",
            "raw_log": redact_secrets(json.dumps(row, default=str)),
            "normalized_data": json.dumps(metadata, default=str),
            "source_type": CLOUD,
            "provider": PROVIDER,
            "data_origin": DATA_ORIGIN,
            "data_scope": DATA_SCOPE_PRIVATE,
            "dataset_name": DATASET_NAME,
            "resource_id": _clip(resource),
            "resource_type": _clip(_value(row.get("resourceType"))) or "",
            "operation": str(operation),
            "owner_id": owner_id,
            "account_id": account_id,
            "parser_status": "PARSED",
        }


def classify_azure_event(row: dict[str, Any], *, operation: str, sign_in: bool, sign_in_failed: bool | None) -> str:
    """Small cloud taxonomy. Only fields present in the record are used; otherwise CLOUD_ACTIVITY."""
    if sign_in:
        if sign_in_failed is None:
            return CLOUD_AUTHENTICATION
        return CLOUD_LOGIN_FAILURE if sign_in_failed else CLOUD_LOGIN_SUCCESS
    op = operation.strip().lower()
    if op in PRIVILEGE_OPERATIONS or op.startswith(PRIVILEGE_OPERATION_PREFIXES):
        return CLOUD_PRIVILEGE_CHANGE
    if ARM_OPERATION.match(op):
        return CLOUD_RESOURCE_OPERATION
    return CLOUD_ACTIVITY


def _value(item: Any) -> Any:
    if isinstance(item, dict):
        return item.get("value") or item.get("localizedValue")
    return item if item not in ("", None) else None


def _properties(row: dict[str, Any]) -> dict[str, Any]:
    props = row.get("properties")
    if isinstance(props, str) and props.strip().startswith("{"):
        try:
            props = json.loads(props)
        except json.JSONDecodeError:
            return {}
    return props if isinstance(props, dict) else {}


def _is_sign_in(row: dict[str, Any]) -> bool:
    category = str(_value(row.get("category")) or "").lower()
    operation = str(_value(row.get("operationName")) or "").lower()
    if category in SIGN_IN_CATEGORIES or operation in SIGN_IN_OPERATIONS:
        return True
    status = row.get("status")
    return "createdDateTime" in row and isinstance(status, dict) and "errorCode" in status


def _sign_in_failed(row: dict[str, Any], properties: dict[str, Any]) -> bool | None:
    """None when the record does not state the sign-in outcome."""
    for candidate in (
        row.get("resultType"),
        (properties.get("status") or {}).get("errorCode") if isinstance(properties.get("status"), dict) else None,
        row["status"].get("errorCode") if isinstance(row.get("status"), dict) else None,
    ):
        if candidate in (None, ""):
            continue
        return str(candidate).strip() != "0"
    return None


def _caller(row: dict[str, Any], properties: dict[str, Any]) -> str | None:
    for candidate in (
        row.get("caller"),
        row.get("userPrincipalName"),
        properties.get("userPrincipalName"),
        row.get("identity"),
        row.get("actor"),
    ):
        if isinstance(candidate, dict):
            candidate = (candidate.get("claims") or {}).get(UPN_CLAIM) or (
                (candidate.get("authorization") or {}).get("evidence") or {}
            ).get("principalId")
        if candidate:
            return str(candidate)
    return None


def _source_ip(row: dict[str, Any], properties: dict[str, Any]) -> str | None:
    http = row.get("httpRequest") if isinstance(row.get("httpRequest"), dict) else {}
    for candidate in (http.get("clientIpAddress"), row.get("callerIpAddress"), row.get("ipAddress"), properties.get("ipAddress")):
        if candidate and len(str(candidate)) <= SOURCE_IP_LIMIT:
            return str(candidate)
    return None


def _clip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)[:COLUMN_LIMIT]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
