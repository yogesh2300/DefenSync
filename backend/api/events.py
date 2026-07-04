"""REST API endpoints for querying and managing security events."""
from __future__ import annotations

from backend.core.logging import get_logger
from datetime import datetime
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.services.event_service import EventService

logger = get_logger(__name__)

router = APIRouter()


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


def get_event_service(db: Session = Depends(get_db)) -> EventService:
    """Dependency injection provider yielding an EventService bound to the current database session."""
    return EventService(db)


@router.get("", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="List Recent Events")
def get_recent_events(
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve the most recent security events ordered by timestamp descending."""
    logger.info("API request: GET /events (limit=%d)", limit)
    return service.get_recent_events(limit=limit)


@router.get("/high-risk", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="List High-Risk Events")
def get_high_risk_events(
    min_score: int = Query(70, ge=0, le=100, description="Minimum risk score threshold"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve high-risk security events meeting or exceeding the minimum risk threshold."""
    logger.info("API request: GET /events/high-risk (min_score=%d, limit=%d)", min_score, limit)
    return service.get_high_risk_events(min_score=min_score, limit=limit)


@router.get("/user/{username}", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="Get Events by Username")
def get_events_by_username(
    username: str,
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve security events associated with a specific username."""
    logger.info("API request: GET /events/user/%s (limit=%d)", username, limit)
    return service.get_events_by_username(username=username, limit=limit)


@router.get("/ip/{ip}", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="Get Events by IP")
def get_events_by_ip(
    ip: str,
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve security events originating from a specific source IP address."""
    logger.info("API request: GET /events/ip/%s (limit=%d)", ip, limit)
    return service.get_events_by_ip(ip=ip, limit=limit)


@router.get("/type/{event_type}", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="Get Events by Type")
def get_events_by_type(
    event_type: str,
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of events to return"),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve security events matching a specific event classification type."""
    logger.info("API request: GET /events/type/%s (limit=%d)", event_type, limit)
    return service.get_events_by_type(event_type=event_type, limit=limit)


@router.get("/{event_id}", response_model=SecurityEventResponse, status_code=status.HTTP_200_OK, summary="Get Event by ID")
def get_event_by_id(
    event_id: str,
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve a single security event by its unique UUID."""
    logger.info("API request: GET /events/%s", event_id)
    event = service.get_event_by_id(event_id)
    if not event:
        logger.warning("Event not found: %s", event_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' was not found.",
        )
    return event