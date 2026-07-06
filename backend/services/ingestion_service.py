"""Ingestion service for validation, deduplication, and parsing of incoming events."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Mapping
from sqlalchemy.orm import Session

from backend.core.exceptions import DuplicateResourceError, DatabaseException
from backend.database import crud
from backend.database.models import SecurityEvent

logger = logging.getLogger(__name__)


class IngestionService:
    """Service layer coordinating validation, deduplication, and ingestion logic."""

    def __init__(self, session: Session) -> None:
        """Initialize the ingestion service with a database session."""
        self._session = session

    def ingest_single_event(self, event_data: Mapping[str, Any]) -> SecurityEvent:
        """Ingest a single security event after ensuring it is not a duplicate."""
        event_id = event_data.get("event_id")
        if event_id:
            if crud.get_event_by_id(self._session, str(event_id)) is not None:
                raise DuplicateResourceError(f"Security event with ID '{event_id}' already exists.")

        raw_log = event_data.get("raw_log") or event_data.get("message") or ""
        ts_val = event_data.get("timestamp")
        
        if ts_val:
            parsed_ts = crud._parse_timestamp(ts_val)
        else:
            parsed_ts = datetime.now(timezone.utc)

        h_val = crud.calculate_event_hash(raw_log, parsed_ts)
        if crud.get_event_by_hash(self._session, h_val) is not None:
            raise DuplicateResourceError(f"Duplicate security event detected with hash '{h_val}'.")

        full_data = dict(event_data)
        full_data["timestamp"] = parsed_ts
        full_data["hash"] = h_val

        try:
            record = crud.insert_event(self._session, full_data)
            self._session.commit()
            return record
        except Exception as e:
            self._session.rollback()
            logger.error("Failed to commit single event ingestion: %s", str(e))
            raise DatabaseException(f"Failed to commit security event: {str(e)}")

    def ingest_bulk_events(self, events_data: list[dict[str, Any]]) -> dict[str, Any]:
        """Ingest a batch of security events, performing bulk validation and hashing."""
        inserted = 0
        duplicates = 0
        failed = 0
        errors: list[dict[str, Any]] = []

        if not events_data:
            return {
                "inserted": inserted,
                "duplicates": duplicates,
                "failed": failed,
                "errors": errors,
            }

        valid_payloads = []
        incoming_hashes = []
        incoming_ids = []

        for index, event in enumerate(events_data):
            eid = event.get("event_id")
            raw_log = event.get("raw_log") or event.get("message") or ""
            ts_val = event.get("timestamp")

            if ts_val:
                try:
                    parsed_ts = crud._parse_timestamp(ts_val)
                except Exception as exc:
                    failed += 1
                    errors.append({"index": index, "error": f"Invalid timestamp format: {str(exc)}"})
                    continue
            else:
                parsed_ts = datetime.now(timezone.utc)

            etype = event.get("event_type")
            if not etype:
                failed += 1
                errors.append({"index": index, "error": "Missing event_type"})
                continue

            h_val = crud.calculate_event_hash(raw_log, parsed_ts)
            
            norm_event = dict(event)
            norm_event["timestamp"] = parsed_ts
            norm_event["hash"] = h_val
            
            valid_payloads.append((index, norm_event, h_val, eid))
            incoming_hashes.append(h_val)
            if eid:
                incoming_ids.append(str(eid))

        existing_hashes = set()
        existing_ids = set()
        
        if incoming_hashes:
            try:
                existing_hashes = crud.get_existing_event_hashes(self._session, incoming_hashes)
            except Exception as e:
                logger.error("Failed to query existing event hashes: %s", str(e))
                raise DatabaseException(f"Database error during hash deduplication: {str(e)}")

        if incoming_ids:
            try:
                existing_ids = crud.get_existing_event_ids(self._session, incoming_ids)
            except Exception as e:
                logger.error("Failed to query existing event IDs: %s", str(e))
                raise DatabaseException(f"Database error during ID deduplication: {str(e)}")

        records_to_insert = []
        seen_hashes = set()
        seen_ids = set()

        for index, payload, h_val, eid in valid_payloads:
            eid_str = str(eid) if eid else None
            
            is_dup = False
            if h_val in existing_hashes or h_val in seen_hashes:
                is_dup = True
            elif eid_str and (eid_str in existing_ids or eid_str in seen_ids):
                is_dup = True

            if is_dup:
                duplicates += 1
                errors.append({"index": index, "error": "Duplicate event ignored"})
            else:
                seen_hashes.add(h_val)
                if eid_str:
                    seen_ids.add(eid_str)
                records_to_insert.append(payload)

        if records_to_insert:
            try:
                crud.insert_many(self._session, records_to_insert)
                self._session.commit()
                inserted = len(records_to_insert)
                logger.info("Successfully ingested %d security events in bulk", inserted)
            except Exception as e:
                self._session.rollback()
                logger.error("Failed to commit bulk event ingestion transaction: %s", str(e))
                raise DatabaseException(f"Failed to commit bulk event ingestion transaction: {str(e)}")

        return {
            "inserted": inserted,
            "duplicates": duplicates,
            "failed": failed,
            "errors": errors,
        }