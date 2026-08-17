"""Streaming OpenStack public dataset import service."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.exceptions import ValidationException
from backend.database import crud
from backend.database.models import DatasetImport, SecurityEvent
from backend.parser.openstack_parser import (
    DATASET_NAME,
    DATA_ORIGIN,
    PROVIDER,
    infer_label_from_path,
    map_openstack_event_type,
    normalize_openstack_severity,
    parse_openstack_line,
)

DEMO_DATA_ORIGIN = "SYNTHETIC_CLOUD_DEMO"
DEMO_DATASET_NAME = "DEFENSYNC_OPENSTACK_DEMO"
from backend.services.datasets.openstack_discovery import DatasetFile, OpenStackDiscoveryService

logger = logging.getLogger(__name__)


class OpenStackImportService:
    """Import OpenStack public dataset rows into the existing events table."""

    def __init__(
        self,
        session: Session,
        *,
        discovery: OpenStackDiscoveryService | None = None,
    ) -> None:
        self._session = session
        self._settings = get_settings()
        self._discovery = discovery or OpenStackDiscoveryService()

    def import_file(
        self,
        *,
        file_id: str,
        owner_id: str,
        max_records: int | None = None,
        batch_size: int | None = None,
        allow_reimport: bool = False,
        line_offset: int = 0,
    ) -> DatasetImport:
        """Synchronously import a bounded number of OpenStack log records."""
        if not self._settings.DATASET_IMPORT_ENABLED:
            raise ValidationException("Dataset import is disabled by DATASET_IMPORT_ENABLED=false.")

        selected = self._get_discovered_file(file_id)
        path = self._discovery.resolve_file_id(file_id)
        file_hash = self._sha256_file(path)

        limit = self._normalize_limit(max_records)
        effective_batch = self._normalize_batch_size(batch_size)
        existing = self._find_completed_import(owner_id=owner_id, file_hash=file_hash)
        if existing and not allow_reimport:
            return existing
        run = self._prepare_import_run(
            owner_id=owner_id,
            file_info=selected,
            file_hash=file_hash,
            limit=limit,
            batch_size=effective_batch,
            allow_reimport=allow_reimport,
        )

        counters = {
            "processed": 0,
            "imported": 0,
            "skipped": 0,
            "failed": 0,
        }
        batch: list[dict[str, Any]] = []
        label = infer_label_from_path(selected.relative_path)

        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if line_number <= line_offset:
                        continue
                    if counters["processed"] >= limit:
                        break

                    counters["processed"] += 1
                    if not line.strip():
                        counters["skipped"] += 1
                        continue

                    try:
                        batch.append(
                            self._event_payload(
                                line=line,
                                owner_id=owner_id,
                                relative_path=selected.relative_path,
                                line_number=line_number,
                                file_hash=file_hash,
                                label=label,
                            )
                        )
                    except Exception as exc:
                        counters["failed"] += 1
                        logger.warning("OpenStack parser failed line=%s file=%s: %s", line_number, selected.relative_path, exc)

                    if len(batch) >= effective_batch:
                        self._flush_batch(batch, counters)
                        self._update_run(run, counters)
                        batch = []

            if batch:
                self._flush_batch(batch, counters)

            self._finish_run(run, counters)
            return run
        except Exception as exc:
            self._session.rollback()
            run.status = "FAILED"
            run.error_message = str(exc)
            run.completed_at = datetime.now(timezone.utc)
            run.updated_at = datetime.now(timezone.utc)
            self._session.commit()
            raise

    def list_imports(self, *, owner_id: str | None = None, limit: int = 50) -> list[DatasetImport]:
        stmt = (
            select(DatasetImport)
            .where(DatasetImport.dataset_name.in_((DATASET_NAME, DEMO_DATASET_NAME)))
            .order_by(desc(DatasetImport.created_at))
            .limit(limit)
        )
        if owner_id:
            stmt = stmt.where(DatasetImport.owner_id == owner_id)
        return list(self._session.scalars(stmt).all())

    def get_import(self, import_id: str, *, owner_id: str | None = None) -> DatasetImport | None:
        stmt = select(DatasetImport).where(DatasetImport.id == import_id)
        if owner_id:
            stmt = stmt.where(DatasetImport.owner_id == owner_id)
        return self._session.scalar(stmt)

    def summary(self, *, owner_id: str | None = None) -> dict[str, Any]:
        total = self._session.scalar(
            select(func.count(SecurityEvent.id)).where(
                *self._openstack_clauses(owner_id=owner_id),
            )
        ) or 0
        normal = self._count_events(owner_id=owner_id, original_label="NORMAL")
        anomalous = self._count_events(owner_id=owner_id, original_label="ANOMALOUS")
        partial = self._count_events(owner_id=owner_id, parser_status="PARTIAL")
        failed = self._count_events(owner_id=owner_id, parser_status="FAILED")
        services = [
            row[0]
            for row in self._session.execute(
                self._event_distinct_stmt(SecurityEvent.resource_type, owner_id=owner_id)
            ).all()
            if row[0]
        ]
        event_types = [
            row[0]
            for row in self._session.execute(
                self._event_distinct_stmt(SecurityEvent.event_type, owner_id=owner_id)
            ).all()
            if row[0]
        ]
        latest_import = self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.dataset_name.in_((DATASET_NAME, DEMO_DATASET_NAME)),
                *( [DatasetImport.owner_id == owner_id] if owner_id else [] ),
            ).order_by(desc(DatasetImport.created_at)).limit(1)
        )
        return {
            "dataset": DATASET_NAME,
            "provider": PROVIDER,
            "total_openstack_events": int(total),
            "normal_labelled_events": int(normal),
            "anomalous_labelled_events": int(anomalous),
            "partially_parsed_events": int(partial),
            "failed_records": int(failed),
            "services_represented": services,
            "event_types_represented": event_types,
            "most_recent_import": self.import_to_dict(latest_import) if latest_import else None,
        }

    def import_and_prepare(
        self,
        *,
        file_id: str,
        owner_id: str,
        max_records: int | None = None,
        batch_size: int | None = None,
        allow_reimport: bool = False,
        line_offset: int = 0,
    ) -> dict[str, Any]:
        selected = self._get_discovered_file(file_id)
        path = self._discovery.resolve_file_id(file_id)
        file_hash = self._sha256_file(path)
        existing = self._find_completed_import(owner_id=owner_id, file_hash=file_hash)
        run = self.import_file(
            file_id=file_id,
            owner_id=owner_id,
            max_records=max_records,
            batch_size=batch_size,
            allow_reimport=allow_reimport,
            line_offset=line_offset,
        )
        payload = self.import_to_dict(run)
        payload["already_imported"] = bool(existing) and not allow_reimport
        payload["provider"] = PROVIDER
        origin, dataset = origin_fields_for_path(selected.relative_path)
        payload["data_origin"] = origin
        payload["dataset"] = dataset
        return payload

    @staticmethod
    def import_to_dict(run: DatasetImport) -> dict[str, Any]:
        return {
            "import_id": run.id,
            "owner_id": run.owner_id,
            "dataset": run.dataset_name,
            "dataset_version": run.dataset_version,
            "source_file": run.source_file,
            "status": run.status,
            "total_records_discovered": run.total_records_discovered,
            "records_processed": run.records_processed,
            "records_imported": run.records_imported,
            "records_skipped": run.records_skipped,
            "records_failed": run.records_failed,
            "batch_size": run.batch_size,
            "import_limit": run.import_limit,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "error_message": run.error_message,
            "created_at": run.created_at,
            "updated_at": run.updated_at,
        }

    def _find_completed_import(self, *, owner_id: str, file_hash: str) -> DatasetImport | None:
        return self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.owner_id == owner_id,
                DatasetImport.source_file_hash == file_hash,
                DatasetImport.dataset_name.in_((DATASET_NAME, DEMO_DATASET_NAME)),
                DatasetImport.status.in_(("COMPLETED", "PARTIAL")),
            )
        )

    def _get_discovered_file(self, file_id: str) -> DatasetFile:
        for item in self._discovery.discover_files():
            if item.file_id == file_id:
                return item
        raise ValidationException("OpenStack dataset file_id was not found.")

    def _prepare_import_run(
        self,
        *,
        owner_id: str,
        file_info: DatasetFile,
        file_hash: str,
        limit: int,
        batch_size: int,
        allow_reimport: bool,
    ) -> DatasetImport:
        existing = self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.owner_id == owner_id,
                DatasetImport.source_file_hash == file_hash,
                DatasetImport.dataset_name.in_((DATASET_NAME, DEMO_DATASET_NAME)),
            )
        )
        if existing and existing.status in {"COMPLETED", "PARTIAL"} and not allow_reimport:
            return existing
        if existing and not allow_reimport and existing.status not in {"FAILED", "RUNNING"}:
            return existing
        run = existing if existing else DatasetImport()
        origin, dataset_name = origin_fields_for_path(file_info.relative_path)
        run.owner_id = owner_id
        run.dataset_name = dataset_name
        run.dataset_version = "synthetic-demo" if origin == DEMO_DATA_ORIGIN else "public-loghub"
        run.source_file = file_info.relative_path
        run.source_file_hash = file_hash
        run.status = "RUNNING"
        run.total_records_discovered = file_info.estimated_line_count or 0
        run.records_processed = 0
        run.records_imported = 0
        run.records_skipped = 0
        run.records_failed = 0
        run.batch_size = batch_size
        run.import_limit = limit
        run.started_at = datetime.now(timezone.utc)
        run.completed_at = None
        run.error_message = None
        run.updated_at = datetime.now(timezone.utc)
        self._session.add(run)
        self._session.commit()
        return run

    def _event_payload(
        self,
        *,
        line: str,
        owner_id: str,
        relative_path: str,
        line_number: int,
        file_hash: str,
        label: dict[str, Any],
    ) -> dict[str, Any]:
        parsed = parse_openstack_line(line)
        severity = normalize_openstack_severity(parsed)
        event_type = map_openstack_event_type(parsed)
        origin, dataset_name = origin_fields_for_path(relative_path)
        metadata = {
            **parsed.to_metadata(),
            "source_type": "CLOUD",
            "provider": PROVIDER,
            "data_origin": origin,
            "dataset_name": dataset_name,
            "source_file": relative_path,
            "source_file_hash": file_hash,
            "source_line": line_number,
            "label_source": label["label_source"],
            "label_confidence": label["label_confidence"],
            "original_label": label["original_label"],
            "is_labelled": label["is_labelled"],
        }
        timestamp = parsed.timestamp or datetime.now(timezone.utc)
        raw_line = parsed.raw_line
        hostname = "openstack-synthetic-demo" if origin == DEMO_DATA_ORIGIN else (parsed.host or "openstack-public-dataset")
        return {
            "event_id": self._event_id(file_hash, line_number, raw_line),
            "server_id": None,
            "owner_id": owner_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "username": parsed.user_id,
            "source_ip": parsed.source_ip,
            "event_type": event_type,
            "category": "cloud",
            "severity": severity,
            "risk_score": _risk_score_for(severity, event_type),
            "message": parsed.message or raw_line,
            "raw_log": raw_line,
            "normalized_data": json.dumps(metadata, default=str),
            "metadata": metadata,
            "process": parsed.process,
            "source_type": "CLOUD",
            "provider": PROVIDER,
            "data_origin": origin,
            "dataset_name": dataset_name,
            "is_labelled": label["is_labelled"],
            "original_label": label["original_label"],
            "actor_id": parsed.user_id,
            "resource_id": parsed.resource_id,
            "resource_type": parsed.resource_type,
            "operation": parsed.operation,
            "parser_status": parsed.parse_status,
        }

    def _flush_batch(self, batch: list[dict[str, Any]], counters: dict[str, int]) -> None:
        if not batch:
            return
        hashes = [crud.calculate_event_hash(str(item["raw_log"]), item["timestamp"]) for item in batch]
        existing_hashes = crud.get_existing_event_hashes(self._session, hashes)
        to_insert: list[dict[str, Any]] = []
        for item, hash_value in zip(batch, hashes, strict=True):
            if hash_value in existing_hashes:
                counters["skipped"] += 1
                continue
            item["hash"] = hash_value
            to_insert.append(item)
        if not to_insert:
            self._session.commit()
            return
        try:
            crud.insert_many(self._session, to_insert)
            self._session.commit()
            counters["imported"] += len(to_insert)
        except Exception as exc:
            self._session.rollback()
            counters["failed"] += len(to_insert)
            logger.exception("OpenStack import batch failed: %s", exc)

    def _update_run(self, run: DatasetImport, counters: dict[str, int]) -> None:
        run.records_processed = counters["processed"]
        run.records_imported = counters["imported"]
        run.records_skipped = counters["skipped"]
        run.records_failed = counters["failed"]
        run.updated_at = datetime.now(timezone.utc)
        self._session.add(run)
        self._session.commit()

    def _finish_run(self, run: DatasetImport, counters: dict[str, int]) -> None:
        self._update_run(run, counters)
        if counters["failed"] and counters["imported"]:
            run.status = "PARTIAL"
        elif counters["failed"] and not counters["imported"]:
            run.status = "FAILED"
        else:
            run.status = "COMPLETED"
        run.completed_at = datetime.now(timezone.utc)
        run.updated_at = datetime.now(timezone.utc)
        self._session.add(run)
        self._session.commit()

    def _normalize_limit(self, requested: int | None) -> int:
        max_allowed = int(self._settings.DATASET_IMPORT_MAX_RECORDS)
        if requested is None:
            return max_allowed
        if requested < 1:
            raise ValidationException("max_records must be greater than zero.")
        return min(requested, max_allowed)

    def _normalize_batch_size(self, requested: int | None) -> int:
        value = requested or int(self._settings.DATASET_IMPORT_BATCH_SIZE)
        if value < 1:
            raise ValidationException("batch_size must be greater than zero.")
        return min(value, int(self._settings.DATASET_IMPORT_BATCH_SIZE))

    def _count_events(
        self,
        *,
        owner_id: str | None = None,
        original_label: str | None = None,
        parser_status: str | None = None,
    ) -> int:
        clauses = self._openstack_clauses(owner_id=owner_id)
        if original_label:
            clauses.append(SecurityEvent.original_label == original_label)
        if parser_status:
            clauses.append(SecurityEvent.parser_status == parser_status)
        return self._session.scalar(select(func.count(SecurityEvent.id)).where(*clauses)) or 0

    @staticmethod
    def _openstack_clauses(*, owner_id: str | None = None) -> list[Any]:
        clauses = [
            SecurityEvent.source_type == "CLOUD",
            SecurityEvent.provider == PROVIDER,
        ]
        if owner_id:
            clauses.append(SecurityEvent.owner_id == owner_id)
        return clauses

    @staticmethod
    def _event_distinct_stmt(column: Any, *, owner_id: str | None = None) -> Any:
        clauses = OpenStackImportService._openstack_clauses(owner_id=owner_id)
        return select(column).where(*clauses).distinct().order_by(column)

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _event_id(file_hash: str, line_number: int, raw_line: str) -> str:
        digest = hashlib.sha256(f"{file_hash}:{line_number}:{raw_line}".encode("utf-8")).hexdigest()
        return f"openstack-{digest[:24]}"


def origin_fields_for_path(relative_path: str) -> tuple[str, str]:
    lowered = relative_path.replace("\\", "/").lower()
    if "demo" in lowered or "synthetic" in lowered:
        return DEMO_DATA_ORIGIN, DEMO_DATASET_NAME
    return DATA_ORIGIN, DATASET_NAME


def _risk_score_for(severity: str, event_type: str) -> int:
    if event_type in {"CLOUD_AUTHORIZATION_FAILURE", "CLOUD_LOGIN_FAILURE", "CLOUD_API_FAILURE"}:
        return 70
    return {
        "critical": 85,
        "high": 70,
        "medium": 45,
        "low": 20,
        "info": 5,
    }.get(severity, 5)
