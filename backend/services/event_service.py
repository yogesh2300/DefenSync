"""Business logic service layer for security event querying and persistence."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Iterable, Literal, Mapping

from sqlalchemy.orm import Session

from backend.core.exceptions import DatabaseException, ResourceNotFoundError
from backend.database import crud
from backend.database.models import SecurityEvent

logger = logging.getLogger(__name__)


class EventService:
    """Service layer coordinating business logic and database CRUD operations for security events."""

    def __init__(self, session: Session) -> None:
        """Initialize the event service with a database session."""
        self._session = session

    # -------------------------------------------------------------------------
    # Read
    # -------------------------------------------------------------------------

    def get_event_by_id(self, event_id: str) -> SecurityEvent | None:
        """Retrieve a specific security event by its unique event_id."""
        logger.debug("Retrieving event by ID: %s", event_id)
        return crud.get_event_by_id(self._session, event_id)

    def require_event_by_id(self, event_id: str) -> SecurityEvent:
        """Retrieve an event by event_id or raise ResourceNotFoundError."""
        event = self.get_event_by_id(event_id)
        if event is None:
            raise ResourceNotFoundError(f"Security event '{event_id}' not found.")
        return event

    def get_recent_events(
        self,
        limit: int = 100,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve recent security events ordered by timestamp."""
        logger.debug("Retrieving recent events with limit=%d server_id=%s", limit, server_id)
        return crud.get_recent_events(
            self._session,
            limit=limit,
            owner_id=owner_id,
            server_id=server_id,
        )

    def get_high_risk_events(
        self,
        min_score: int = 70,
        limit: int = 100,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> list[SecurityEvent]:
        """Retrieve events at or above the minimum risk score threshold."""
        logger.debug(
            "Retrieving high-risk events with min_score=%d limit=%d server_id=%s",
            min_score,
            limit,
            server_id,
        )
        return crud.get_high_risk_events(
            self._session,
            min_score=min_score,
            limit=limit,
            owner_id=owner_id,
            server_id=server_id,
        )

    def get_events_by_username(self, username: str, limit: int = 100) -> list[SecurityEvent]:
        """Retrieve security events associated with a specific username."""
        logger.debug("Retrieving events for username=%s with limit=%d", username, limit)
        return crud.get_events_by_username(self._session, username, limit=limit)

    def get_events_by_ip(self, ip: str, limit: int = 100) -> list[SecurityEvent]:
        """Retrieve security events originating from a specific source IP address."""
        logger.debug("Retrieving events for source_ip=%s with limit=%d", ip, limit)
        return crud.get_events_by_ip(self._session, ip, limit=limit)

    def get_events_by_type(self, event_type: str, limit: int = 100) -> list[SecurityEvent]:
        """Retrieve security events matching a specific event type."""
        logger.debug("Retrieving events for event_type=%s with limit=%d", event_type, limit)
        return crud.get_events_by_type(self._session, event_type, limit=limit)

    def get_events_by_hostname(self, hostname: str, limit: int = 100) -> list[SecurityEvent]:
        """Retrieve security events for a specific hostname."""
        logger.debug("Retrieving events for hostname=%s with limit=%d", hostname, limit)
        return crud.get_events_by_hostname(self._session, hostname, limit=limit)

    def query_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        event_type: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        hostname: str | None = None,
        server_id: str | None = None,
        owner_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        search: str | None = None,
        min_risk_score: int | None = None,
        max_risk_score: int | None = None,
        sort_order: Literal["newest", "oldest"] = "newest",
    ) -> list[SecurityEvent]:
        """Query, filter, search, and paginate security events."""
        logger.debug(
            "Querying events limit=%d offset=%d search=%r event_type=%r",
            limit,
            offset,
            search,
            event_type,
        )
        return crud.query_events(
            self._session,
            limit=limit,
            offset=offset,
            event_type=event_type,
            severity=severity,
            category=category,
            username=username,
            source_ip=source_ip,
            hostname=hostname,
            server_id=server_id,
            owner_id=owner_id,
            start_time=start_time,
            end_time=end_time,
            search=search,
            min_risk_score=min_risk_score,
            max_risk_score=max_risk_score,
            sort_order=sort_order,
        )

    def count_events(
        self,
        *,
        event_type: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        username: str | None = None,
        source_ip: str | None = None,
        hostname: str | None = None,
        server_id: str | None = None,
        owner_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        search: str | None = None,
        min_risk_score: int | None = None,
        max_risk_score: int | None = None,
    ) -> int:
        """Return the total number of events matching the given filter criteria."""
        return crud.count_query_events(
            self._session,
            event_type=event_type,
            severity=severity,
            category=category,
            username=username,
            source_ip=source_ip,
            hostname=hostname,
            server_id=server_id,
            owner_id=owner_id,
            start_time=start_time,
            end_time=end_time,
            search=search,
            min_risk_score=min_risk_score,
            max_risk_score=max_risk_score,
        )

    def search_events(
        self,
        search: str,
        *,
        limit: int = 100,
        offset: int = 0,
        sort_order: Literal["newest", "oldest"] = "newest",
        **filters: Any,
    ) -> list[SecurityEvent]:
        """Search events by keyword across message, user, host, IP, and log fields."""
        return self.query_events(
            limit=limit,
            offset=offset,
            search=search,
            sort_order=sort_order,
            **filters,
        )

    def paginate_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        **filters: Any,
    ) -> dict[str, Any]:
        """Return a paginated result set with total count metadata."""
        items = self.query_events(limit=limit, offset=offset, **filters)
        total = self.count_events(**{k: v for k, v in filters.items() if k != "sort_order"})
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # -------------------------------------------------------------------------
    # Create
    # -------------------------------------------------------------------------

    def create_event(self, event: Mapping[str, Any]) -> SecurityEvent:
        """Persist a single security event and commit the transaction."""
        logger.info("Creating security event: %s", event.get("event_type", "Unknown"))
        try:
            record = crud.insert_event(self._session, event)
            self._session.commit()
            return record
        except Exception as exc:
            self._session.rollback()
            logger.exception("Failed to create security event")
            raise DatabaseException("Failed to create security event.") from exc

    def create_events(self, events: Iterable[Mapping[str, Any]]) -> list[SecurityEvent]:
        """Persist multiple security events and commit the transaction."""
        event_list = list(events)
        logger.info("Creating batch of %d security events", len(event_list))
        if not event_list:
            return []
        try:
            records = crud.insert_many(self._session, event_list)
            self._session.commit()
            return records
        except Exception as exc:
            self._session.rollback()
            logger.exception("Failed to create security events batch")
            raise DatabaseException("Failed to create security events batch.") from exc

    def insert_event(self, event: Mapping[str, Any]) -> SecurityEvent:
        """Persist a single event without committing (for use within a larger transaction)."""
        logger.info("Inserting security event: %s", event.get("event_type", "Unknown"))
        return crud.insert_event(self._session, event)

    def insert_many(self, events: Iterable[Mapping[str, Any]]) -> list[SecurityEvent]:
        """Persist multiple events without committing (for use within a larger transaction)."""
        event_list = list(events)
        logger.info("Inserting batch of %d security events", len(event_list))
        return crud.insert_many(self._session, event_list)

    # -------------------------------------------------------------------------
    # Update
    # -------------------------------------------------------------------------

    def update_event(self, event_id: str, updates: Mapping[str, Any]) -> SecurityEvent:
        """Update mutable fields on an existing security event."""
        logger.info("Updating security event: %s", event_id)
        try:
            record = crud.update_event(self._session, event_id, updates)
            if record is None:
                raise ResourceNotFoundError(f"Security event '{event_id}' not found.")
            self._session.commit()
            return record
        except ResourceNotFoundError:
            raise
        except Exception as exc:
            self._session.rollback()
            logger.exception("Failed to update security event: %s", event_id)
            raise DatabaseException("Failed to update security event.") from exc

    # -------------------------------------------------------------------------
    # Delete
    # -------------------------------------------------------------------------

    def delete_event(self, event_id: str) -> None:
        """Delete a single security event by event_id."""
        logger.info("Deleting security event: %s", event_id)
        try:
            deleted = crud.delete_event_by_id(self._session, event_id)
            if not deleted:
                raise ResourceNotFoundError(f"Security event '{event_id}' not found.")
            self._session.commit()
        except ResourceNotFoundError:
            raise
        except Exception as exc:
            self._session.rollback()
            logger.exception("Failed to delete security event: %s", event_id)
            raise DatabaseException("Failed to delete security event.") from exc

    def delete_events(
        self,
        *,
        event_type: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        source_ip: str | None = None,
    ) -> int:
        """Delete security events matching the given criteria."""
        logger.info(
            "Deleting events event_type=%r source_ip=%r start_time=%r end_time=%r",
            event_type,
            source_ip,
            start_time,
            end_time,
        )
        try:
            deleted_count = crud.delete_events(
                self._session,
                event_type=event_type,
                start_time=start_time,
                end_time=end_time,
                source_ip=source_ip,
            )
            self._session.commit()
            return deleted_count
        except ValueError:
            self._session.rollback()
            raise
        except Exception as exc:
            self._session.rollback()
            logger.exception("Failed to delete security events")
            raise DatabaseException("Failed to delete security events.") from exc
