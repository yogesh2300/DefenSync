"""Shared streaming import helpers for public log datasets."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.exceptions import ValidationException
from backend.database import crud
from backend.database.models import DATA_SCOPE_GLOBAL, DatasetImport, SecurityEvent
from backend.services.datasets.openstack_discovery import DatasetFile

logger = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def event_id_for(prefix: str, file_hash: str, line_number: int, raw_line: str) -> str:
    digest = hashlib.sha256(f"{file_hash}:{line_number}:{raw_line}".encode("utf-8")).hexdigest()
    return f"{prefix}-{digest[:24]}"


def risk_score_for(severity: str, event_type: str) -> int:
    if any(token in event_type for token in ("FAILURE", "EXCEPTION", "AUTHORIZATION", "LOGIN_FAILURE")):
        return 70
    return {
        "critical": 85,
        "high": 70,
        "medium": 45,
        "low": 20,
        "info": 5,
    }.get(severity, 5)


class StreamingLogImportService:
    """Bounded, hashed, restartable importer into the unified events table."""

    dataset_names: tuple[str, ...] = ()
    provider: str = ""
    source_type: str = ""

    def __init__(self, session: Session, *, discovery: Any) -> None:
        self._session = session
        self._settings = get_settings()
        self._discovery = discovery

    def list_imports(self, *, owner_id: str | None = None, limit: int = 50) -> list[DatasetImport]:
        stmt = (
            select(DatasetImport)
            .where(DatasetImport.dataset_name.in_(self.dataset_names))
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
        file_hash = sha256_file(path)
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
        payload["provider"] = self.provider
        payload["data_origin"] = "PUBLIC_DATASET"
        payload["dataset"] = run.dataset_name
        payload["source_file"] = selected.relative_path
        return payload

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
        if not self._settings.DATASET_IMPORT_ENABLED:
            raise ValidationException("Dataset import is disabled by DATASET_IMPORT_ENABLED=false.")

        selected = self._get_discovered_file(file_id)
        path = self._discovery.resolve_file_id(file_id)
        file_hash = sha256_file(path)
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
        counters = {"processed": 0, "imported": 0, "skipped": 0, "failed": 0}
        batch: list[dict[str, Any]] = []
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
                        payload = self._event_payload(
                            line=line,
                            owner_id=owner_id,
                            relative_path=selected.relative_path,
                            line_number=line_number,
                            file_hash=file_hash,
                        )
                        if payload is None:
                            counters["skipped"] += 1
                            continue
                        batch.append(payload)
                    except Exception as exc:
                        counters["failed"] += 1
                        logger.warning(
                            "Dataset parser failed line=%s file=%s: %s",
                            line_number,
                            selected.relative_path,
                            exc,
                        )
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

    def _event_payload(self, **kwargs: Any) -> dict[str, Any] | None:
        raise NotImplementedError

    def summary(self, *, owner_id: str | None = None) -> dict[str, Any]:
        clauses = self._event_clauses(owner_id=owner_id)
        total = self._session.scalar(select(func.count(SecurityEvent.id)).where(*clauses)) or 0
        labels = [
            {"label": row[0], "count": int(row[1])}
            for row in self._session.execute(
                select(SecurityEvent.original_label, func.count(SecurityEvent.id))
                .where(*clauses)
                .group_by(SecurityEvent.original_label)
                .order_by(func.count(SecurityEvent.id).desc())
            ).all()
        ]
        event_types = [
            row[0]
            for row in self._session.execute(
                select(SecurityEvent.event_type).where(*clauses).distinct().order_by(SecurityEvent.event_type)
            ).all()
            if row[0]
        ]
        latest_import = self._session.scalar(
            select(DatasetImport)
            .where(
                DatasetImport.dataset_name.in_(self.dataset_names),
                *([DatasetImport.owner_id == owner_id] if owner_id else []),
            )
            .order_by(desc(DatasetImport.created_at))
            .limit(1)
        )
        return {
            "dataset": self.dataset_names[0] if self.dataset_names else "",
            "provider": self.provider,
            "source_type": self.source_type,
            "data_origin": "PUBLIC_DATASET",
            "total_events": int(total),
            "labels": labels,
            "event_types_represented": event_types,
            "most_recent_import": self.import_to_dict(latest_import) if latest_import else None,
        }

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

    def _event_clauses(self, *, owner_id: str | None = None) -> list[Any]:
        del owner_id
        return [
            SecurityEvent.data_scope == DATA_SCOPE_GLOBAL,
            SecurityEvent.provider == self.provider,
            SecurityEvent.dataset_name.in_(self.dataset_names),
        ]

    def _find_completed_import(self, *, owner_id: str, file_hash: str) -> DatasetImport | None:
        return self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.owner_id == owner_id,
                DatasetImport.source_file_hash == file_hash,
                DatasetImport.dataset_name.in_(self.dataset_names),
                DatasetImport.status.in_(("COMPLETED", "PARTIAL")),
            )
        )

    def _get_discovered_file(self, file_id: str) -> DatasetFile:
        for item in self._discovery.discover_files():
            if item.file_id == file_id:
                return item
        raise ValidationException("Dataset file_id was not found.")

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
                DatasetImport.dataset_name.in_(self.dataset_names),
            )
        )
        if existing and existing.status in {"COMPLETED", "PARTIAL"} and not allow_reimport:
            return existing
        if existing and not allow_reimport and existing.status not in {"FAILED", "RUNNING"}:
            return existing
        run = existing if existing else DatasetImport()
        run.owner_id = owner_id
        run.dataset_name = self.dataset_names[0]
        run.dataset_version = "public-loghub"
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

    def _flush_batch(self, batch: list[dict[str, Any]], counters: dict[str, int]) -> None:
        if not batch:
            return
        hashes = [crud.calculate_event_hash(str(item["raw_log"]), item["timestamp"], event_type=item.get("event_type")) for item in batch]
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
            logger.exception("Dataset import batch failed: %s", exc)

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
