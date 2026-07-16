"""Streaming import of aggregate behavioral telemetry CSV records."""

from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.exceptions import ValidationException
from backend.database import crud
from backend.database.models import DatasetImport
from backend.services.behavioral.schemas import (
    DATASET_NAME,
    EVENT_TYPE,
    PROVIDER,
    SOURCE_TYPE,
    SYNTHETIC_ORIGIN,
    identity_key,
    validate_row,
)


class BehavioralTelemetryImportService:
    """Import privacy-preserving behavioral telemetry into the events table."""

    def __init__(self, session: Session, *, dataset_root: str | Path | None = None) -> None:
        self._session = session
        self._settings = get_settings()
        self._dataset_root = Path(dataset_root or self._settings.DATASET_ROOT)

    @property
    def dataset_dir(self) -> Path:
        root = self._dataset_root if self._dataset_root.is_absolute() else Path.cwd() / self._dataset_root
        base = root.resolve()
        candidate = (base / self._settings.BEHAVIORAL_DATASET_PATH).resolve()
        if not _is_relative_to(candidate, base):
            raise ValueError("BEHAVIORAL_DATASET_PATH must resolve inside DATASET_ROOT.")
        return candidate

    def discover_files(self) -> list[dict[str, Any]]:
        base = self.dataset_dir
        if not base.exists():
            return []
        files = []
        for path in sorted(base.glob("*.csv")):
            rel = path.relative_to(base).as_posix()
            files.append(
                {
                    "file_id": file_id_for(rel),
                    "filename": path.name,
                    "relative_path": rel,
                    "size_bytes": path.stat().st_size,
                    "dataset": DATASET_NAME,
                }
            )
        return files

    def import_file(
        self,
        *,
        file_id: str,
        owner_id: str,
        max_records: int | None = None,
        batch_size: int | None = None,
        allow_reimport: bool = False,
    ) -> DatasetImport:
        file_info = self._file_by_id(file_id)
        path = (self.dataset_dir / file_info["relative_path"]).resolve()
        file_hash = _sha256_file(path)
        limit = min(max_records or self._settings.BEHAVIORAL_IMPORT_MAX_RECORDS, self._settings.BEHAVIORAL_IMPORT_MAX_RECORDS)
        batch = min(batch_size or self._settings.BEHAVIORAL_IMPORT_BATCH_SIZE, self._settings.BEHAVIORAL_IMPORT_BATCH_SIZE)

        existing = self._session.scalar(
            select(DatasetImport).where(
                DatasetImport.owner_id == owner_id,
                DatasetImport.dataset_name == DATASET_NAME,
                DatasetImport.source_file_hash == file_hash,
            )
        )
        if existing and not allow_reimport:
            raise ValidationException("This behavioral telemetry file was already imported for this user.")
        run = existing if existing and allow_reimport else DatasetImport()
        run.owner_id = owner_id
        run.dataset_name = DATASET_NAME
        run.dataset_version = "synthetic-v1"
        run.source_file = file_info["relative_path"]
        run.source_file_hash = file_hash
        run.status = "RUNNING"
        run.records_processed = 0
        run.records_imported = 0
        run.records_skipped = 0
        run.records_failed = 0
        run.batch_size = batch
        run.import_limit = limit
        run.started_at = datetime.now(timezone.utc)
        run.completed_at = None
        run.error_message = None
        run.updated_at = datetime.now(timezone.utc)
        self._session.add(run)
        self._session.commit()

        pending: list[dict[str, Any]] = []
        try:
            with path.open("r", newline="", encoding="utf-8") as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader, start=1):
                    if run.records_processed >= limit:
                        break
                    run.records_processed += 1
                    parsed, error = validate_row(row)
                    if error or parsed is None:
                        run.records_failed += 1
                        continue
                    pending.append(self._event_payload(parsed, owner_id=owner_id, row_number=index, file_hash=file_hash))
                    if len(pending) >= batch:
                        self._flush(pending, run)
                        pending = []
            if pending:
                self._flush(pending, run)
            run.status = "PARTIAL" if run.records_failed else "COMPLETED"
            run.completed_at = datetime.now(timezone.utc)
            run.updated_at = datetime.now(timezone.utc)
            self._session.add(run)
            self._session.commit()
            return run
        except Exception as exc:
            self._session.rollback()
            run.status = "FAILED"
            run.error_message = str(exc)
            run.completed_at = datetime.now(timezone.utc)
            run.updated_at = datetime.now(timezone.utc)
            self._session.add(run)
            self._session.commit()
            raise

    def list_imports(self, *, owner_id: str | None = None, limit: int = 50) -> list[DatasetImport]:
        stmt = select(DatasetImport).where(DatasetImport.dataset_name == DATASET_NAME).order_by(desc(DatasetImport.created_at)).limit(limit)
        if owner_id:
            stmt = stmt.where(DatasetImport.owner_id == owner_id)
        return list(self._session.scalars(stmt).all())

    def get_import(self, import_id: str, *, owner_id: str | None = None) -> DatasetImport | None:
        stmt = select(DatasetImport).where(DatasetImport.id == import_id, DatasetImport.dataset_name == DATASET_NAME)
        if owner_id:
            stmt = stmt.where(DatasetImport.owner_id == owner_id)
        return self._session.scalar(stmt)

    @staticmethod
    def import_to_dict(run: DatasetImport) -> dict[str, Any]:
        return {
            "import_id": run.id,
            "dataset": run.dataset_name,
            "source_file": run.source_file,
            "status": run.status,
            "processed": run.records_processed,
            "imported": run.records_imported,
            "skipped": run.records_skipped,
            "failed": run.records_failed,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "error_message": run.error_message,
        }

    def _file_by_id(self, file_id: str) -> dict[str, Any]:
        for file_info in self.discover_files():
            if file_info["file_id"] == file_id:
                return file_info
        raise ValidationException("Behavioral telemetry file_id was not found.")

    def _event_payload(self, row: dict[str, Any], *, owner_id: str, row_number: int, file_hash: str) -> dict[str, Any]:
        metadata = {
            **row,
            "source_file_hash": file_hash,
            "source_row": row_number,
            "privacy": "aggregate timing/statistical metrics only; no keystroke text stored",
        }
        actor = identity_key(row["user_id"], row["linux_username"])
        raw_log = json.dumps(
            {
                "user_id": row["user_id"],
                "session_id": row["session_id"],
                "behavior_class": row["behavior_class"],
                "data_origin": row["data_origin"],
                "row_number": row_number,
            },
            sort_keys=True,
        )
        return {
            "event_id": f"behavior-{hashlib.sha256(f'{file_hash}:{row_number}:{raw_log}'.encode()).hexdigest()[:24]}",
            "owner_id": owner_id,
            "server_id": row["server_id"],
            "timestamp": row["timestamp"],
            "hostname": "behavioral-telemetry-dataset",
            "username": row["linux_username"],
            "event_type": EVENT_TYPE,
            "category": "behavioral",
            "severity": "info",
            "risk_score": 0,
            "message": f"Synthetic aggregate behavioral telemetry for {actor}",
            "raw_log": raw_log,
            "normalized_data": json.dumps(metadata, default=str),
            "metadata": metadata,
            "source_type": SOURCE_TYPE,
            "provider": PROVIDER,
            "data_origin": row["data_origin"],
            "dataset_name": DATASET_NAME,
            "is_labelled": True,
            "original_label": row["behavior_class"],
            "actor_id": actor,
            "session_id": row["session_id"],
            "typing_speed_cpm": row["typing_speed_cpm"],
            "command_rate_per_minute": row["command_rate_per_minute"],
            "command_error_rate": row["command_error_rate"],
            "idle_time_seconds": row["idle_time_seconds"],
            "repeated_command_ratio": row["repeated_command_ratio"],
            "session_duration_minutes": row["session_duration_minutes"],
            "login_hour": row["login_hour"],
            "behavioral_classification": row["behavior_class"],
            "behavioral_risk_score": 0,
            "parser_status": "PARSED",
        }

    def _flush(self, events: list[dict[str, Any]], run: DatasetImport) -> None:
        hashes = [crud.calculate_event_hash(item["raw_log"], item["timestamp"]) for item in events]
        existing = crud.get_existing_event_hashes(self._session, hashes)
        to_insert = []
        for event, hash_value in zip(events, hashes, strict=True):
            if hash_value in existing:
                run.records_skipped += 1
                continue
            event["hash"] = hash_value
            to_insert.append(event)
        if to_insert:
            crud.insert_many(self._session, to_insert)
            run.records_imported += len(to_insert)
        run.updated_at = datetime.now(timezone.utc)
        self._session.add(run)
        self._session.commit()


def file_id_for(relative_path: str) -> str:
    return hashlib.sha256(relative_path.replace("\\", "/").encode()).hexdigest()[:24]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False
