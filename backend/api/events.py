"""REST API endpoints for querying and managing security events."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db, get_current_user, get_current_admin
from backend.database.models import User
from backend.services.event_service import EventService
from backend.services.analytics_service import AnalyticsService
from backend.services.ingestion_service import IngestionService

logger = logging.getLogger(__name__)
router = APIRouter()


# =============================================================================
# Pydantic Schemas (Pydantic v2)
# =============================================================================

class SecurityEventResponse(BaseModel):
    """Pydantic schema representing a serialized security event."""

    id: int = Field(..., description="Internal primary key identifier")
    event_id: str = Field(..., description="Unique UUID for the security event")
    timestamp: datetime = Field(..., description="Timestamp of the event in UTC")
    hostname: str = Field(..., description="Originating host machine name")
    username: str | None = Field(None, description="Username associated with the event")
    source_ip: str | None = Field(None, description="Source IP address if network-related")
    event_type: str = Field(..., description="Normalized classification of the event")
    category: str = Field(..., description="Event category (e.g., authentication, system)")
    severity: str = Field(..., description="Severity rating (info, low, medium, high, critical)")
    risk_score: int = Field(..., description="Calculated behavioral risk score (0-100)")
    process: str | None = Field(None, description="Process or daemon name generating the log")
    message: str = Field(..., description="Human-readable event summary or log text")

    model_config = {"from_attributes": True}


class SecurityEventCreate(BaseModel):
    """Pydantic schema for validating incoming security event payload."""

    event_id: str | None = Field(None, description="Unique UUID for the security event")
    timestamp: datetime | None = Field(None, description="Timestamp of the event in UTC")
    hostname: str = Field("unknown", min_length=1, max_length=255, description="Originating host machine name")
    event_type: str = Field(..., min_length=1, max_length=64, description="Normalized classification of the event")
    category: str | None = Field(None, max_length=32, description="Event category")
    severity: Literal["info", "low", "medium", "high", "critical"] = Field("info", description="Severity rating")
    risk_score: int = Field(0, ge=0, le=100, description="Calculated behavioral risk score (0-100)")
    message: str = Field(..., description="Human-readable event summary or log text")
    raw_log: str = Field(..., description="Raw log text")

    username: str | None = Field(None, max_length=255, description="Username associated with the event")
    source_ip: str | None = Field(None, max_length=45, description="Source IP address if network-related")
    process: str | None = Field(None, max_length=255, description="Process or daemon name generating the log")

    @field_validator("event_type")
    @classmethod
    def validate_event_type(cls, v: str) -> str:
        """Validate that the event type belongs to recognized log classifications."""
        valid_types = {
            "Failed Login", "Successful Login", "Invalid User", "Sudo Command",
            "User Creation", "User Deletion", "Directory Creation", "File Creation",
            "File Deletion", "Permission Change", "Command Execution", "File Modification"
        }
        matched = None
        for vt in valid_types:
            if vt.lower() == v.lower():
                matched = vt
                break
        if not matched:
            raise ValueError(f"Invalid event type '{v}'. Allowed types: {', '.join(sorted(valid_types))}")
        return matched


class IngestionResponse(BaseModel):
    """Response schema for single security event ingestion."""

    success: bool = Field(True, description="Indicates if the operation was successful")
    message: str = Field("Event stored successfully.", description="Operation status message")
    event: SecurityEventResponse = Field(..., description="The persisted security event record")


class BulkErrorDetail(BaseModel):
    """Details of a validation or insertion failure in bulk payload."""

    index: int = Field(..., description="The list position of the failed event")
    error: str = Field(..., description="The reason for rejection or failure")


class BulkIngestionResponse(BaseModel):
    """Response schema for bulk security event ingestion."""

    success: bool = Field(True, description="Indicates if the operation was successful")
    inserted: int = Field(..., description="Number of successfully inserted event records")
    duplicates: int = Field(..., description="Number of ignored duplicate records")
    failed: int = Field(..., description="Number of invalid payload records that failed validation")
    errors: list[BulkErrorDetail] = Field([], description="List of individual event errors with row index")


# =============================================================================
# Dependencies
# =============================================================================

def get_event_service(db: Session = Depends(get_db)) -> EventService:
    return EventService(db)


def get_analytics_service(db: Session = Depends(get_db)) -> AnalyticsService:
    return AnalyticsService(db)


def get_ingestion_service(db: Session = Depends(get_db)) -> IngestionService:
    return IngestionService(db)


# =============================================================================
# Endpoints
# =============================================================================

@router.get("", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="Query Security Events")
def query_events(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    offset: int = Query(0, ge=0, description="Number of events to skip"),
    event_type: str | None = Query(None, description="Filter by event classification type"),
    severity: str | None = Query(None, description="Filter by severity level"),
    category: str | None = Query(None, description="Filter by high-level category"),
    username: str | None = Query(None, description="Filter by associated username"),
    source_ip: str | None = Query(None, description="Filter by originating source IP"),
    start_time: datetime | None = Query(None, description="Filter events after this UTC timestamp"),
    end_time: datetime | None = Query(None, description="Filter events before this UTC timestamp"),
    sort_order: Literal["newest", "oldest"] = Query("newest", description="Sorting by timestamp"),
    current_user: User = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Query, filter, and paginate security events."""
    logger.info("API request by %s: GET /events", current_user.username)
    return service.query_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        severity=severity,
        category=category,
        username=username,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        sort_order=sort_order,
    )


@router.get("/stats", status_code=status.HTTP_200_OK, summary="Get Security Analytics and Statistics")
def get_event_stats(
    current_user: User = Depends(get_current_user),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> Any:
    """Retrieve aggregated SIEM metrics, severity distributions, attacker IP ranks, and hourly trends."""
    logger.info("API request by %s: GET /events/stats", current_user.username)
    return analytics_service.get_event_stats()


@router.get("/recent", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="List Recent Events")
def get_recent_events(
    limit: int = Query(20, ge=1, le=1000, description="Number of recent events to return"),
    current_user: User = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve the absolute latest security events, optimized for live SIEM dashboards."""
    logger.info("API request by %s: GET /events/recent (limit=%d)", current_user.username, limit)
    return service.get_recent_events(limit=limit)


@router.get("/high-risk", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="List High-Risk Events")
def get_high_risk_events(
    min_score: int = Query(70, ge=0, le=100, description="Minimum risk score threshold"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    current_user: User = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve high-risk security events meeting or exceeding risk score (>= 70), sorted descending."""
    logger.info("API request by %s: GET /events/high-risk (min_score=%d)", current_user.username, min_score)
    return service.get_high_risk_events(min_score=min_score, limit=limit)


@router.post("", response_model=IngestionResponse, status_code=status.HTTP_201_CREATED, summary="Ingest a Single Event")
def ingest_single_event(
    event_data: SecurityEventCreate,
    current_user: User = Depends(get_current_user),
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> Any:
    """Ingest, validate, and persist a single security event."""
    logger.info("API request by %s: POST /events (event_id=%s)", current_user.username, event_data.event_id)
    inserted_event = ingestion_service.ingest_single_event(event_data.model_dump())
    return IngestionResponse(
        success=True,
        message="Event stored successfully.",
        event=SecurityEventResponse.model_validate(inserted_event),
    )


@router.post("/bulk", response_model=BulkIngestionResponse, status_code=status.HTTP_201_CREATED, summary="Bulk Ingest Security Events")
def ingest_bulk_events(
    events_data: list[dict[str, Any]],
    current_user: User = Depends(get_current_user),
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> Any:
    """Ingest multiple security events in bulk, returning execution summaries and errors."""
    logger.info("API request by %s: POST /events/bulk (count=%d)", current_user.username, len(events_data))
    stats = ingestion_service.ingest_bulk_events(events_data)
    return BulkIngestionResponse(
        success=True,
        inserted=stats["inserted"],
        duplicates=stats["duplicates"],
        failed=stats["failed"],
        errors=[BulkErrorDetail(**err) for err in stats["errors"]],
    )


@router.delete("", status_code=status.HTTP_200_OK, summary="Delete Events (Admin Only)")
def delete_events(
    event_type: str | None = Query(None, description="Delete only events matching this classification"),
    start_time: datetime | None = Query(None, description="Delete events after this UTC timestamp"),
    end_time: datetime | None = Query(None, description="Delete events before this UTC timestamp"),
    source_ip: str | None = Query(None, description="Delete events matching this source IP"),
    current_admin: User = Depends(get_current_admin),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Delete security events matching criteria. Admin-only operation."""
    logger.info("ADMIN DELETE request by %s: DELETE /events", current_admin.username)
    try:
        deleted_count = service.delete_events(
            event_type=event_type,
            start_time=start_time,
            end_time=end_time,
            source_ip=source_ip,
        )
        return {
            "success": True,
            "message": f"Successfully deleted {deleted_count} security events.",
            "deleted_count": deleted_count,
        }
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )