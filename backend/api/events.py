"""REST API endpoints for querying and managing security events."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from sqlalchemy.orm import Session, object_session

from backend.api.dependencies import (
    get_db,
    get_current_user,
    get_current_admin,
    resolve_account_id,
    resolve_owner_id,
    validate_server_scope,
    visibility_for,
    is_admin,
)
from backend.core.environments import ENVIRONMENT_PATTERN, LINUX
from backend.core.timestamps import TIME_LABEL_EVENT, event_time_view
from backend.database.connection import storage_timezone
from backend.database.models import DATA_SCOPE_PRIVATE, User
from backend.database.scope import infer_data_scope, with_environment
from backend.services.event_service import (
    EventService,
    normalize_event_ids,
    resolve_cloud_event_ids_data_origin,
)
from backend.services.analytics_service import AnalyticsService
from backend.services.ingestion_service import IngestionService

logger = logging.getLogger(__name__)
router = APIRouter()


# =============================================================================
# Pydantic Schemas (Pydantic v2)
# =============================================================================

class SecurityEventResponse(BaseModel):
    """Pydantic schema representing a serialized security event."""

    id: str = Field(..., description="Internal primary key identifier (UUID)")
    event_id: str = Field(..., description="Unique UUID for the security event")
    server_id: str | None = Field(None, description="Registered server ID for this event")
    owner_id: str | None = Field(None, description="Collector / actor user ID")
    account_id: str | None = Field(None, description="Owning account for PRIVATE telemetry")
    data_scope: str = Field("PRIVATE", description="PRIVATE account telemetry or GLOBAL intelligence")
    timestamp: datetime = Field(..., description="Stored column value (database wall clock, no offset); use event_time")
    collection_timestamp: datetime | None = Field(None, description="Stored column value (database wall clock, no offset); use collection_time")
    event_time: datetime | None = Field(None, description="UTC. Source occurrence time, or the observation time when time_label is OBSERVED_AT")
    collection_time: datetime | None = Field(None, description="UTC time DefenSync first collected this record")
    last_collection_time: datetime | None = Field(None, description="UTC time DefenSync last re-observed this record")
    time_label: str = Field(TIME_LABEL_EVENT, description="EVENT_TIME, OBSERVED_AT (snapshot) or COLLECTED_AT (no source time)")
    collection_delay_seconds: float | None = Field(None, description="collection_time - event_time; negative means the clocks disagree")
    source_time_after_collection: bool = Field(False, description="Source time is later than DefenSync's collection time")
    record_kind: str | None = Field(None, description="SECURITY_EVENT, SYSTEM_EVENT or SYSTEM_SNAPSHOT (Linux)")
    record_origin: str | None = Field(None, description="SOURCE_OBSERVED or COLLECTOR_GENERATED (Linux)")
    timestamp_source: str | None = Field(None, description="SOURCE_EVENT, COLLECTION_TIME_FALLBACK, or SNAPSHOT_COLLECTION_TIME")
    created_at: datetime | None = Field(None, description="Time the normalized record was stored")
    hostname: str = Field(..., description="Originating host machine name")
    username: str | None = Field(None, description="Username associated with the event")
    source_ip: str | None = Field(None, description="Source IP address if network-related")
    event_type: str = Field(..., description="Normalized classification of the event")
    category: str = Field(..., description="Event category (e.g., authentication, system)")
    severity: str = Field(..., description="Severity rating (info, low, medium, high, critical)")
    risk_score: int = Field(..., description="Calculated behavioral risk score (0-100)")
    risk_level: str | None = Field(None, description="Risk level derived from score")
    command: str | None = Field(None, description="Command observed in the event")
    process: str | None = Field(None, description="Process or daemon name generating the log")
    message: str = Field(..., description="Human-readable event summary or log text")
    raw_log: str | None = Field(None, description="Original collected log line")
    normalized_data: str | None = Field(None, description="JSON normalized metadata for this event")
    source_type: str = Field("LINUX", description="Event source type, e.g. LINUX or CLOUD")
    provider: str | None = Field(None, description="Cloud provider when source_type is CLOUD")
    data_origin: str = Field("LIVE_LINUX", description="Origin of the record, e.g. LIVE_LINUX or PUBLIC_DATASET")
    dataset_name: str | None = Field(None, description="Public dataset name for dataset records")
    is_labelled: bool = Field(False, description="Whether a trusted dataset label is available")
    original_label: str | None = Field(None, description="Original dataset label, when available")
    actor_id: str | None = Field(None, description="Cloud actor/user identifier when available")
    resource_id: str | None = Field(None, description="Cloud resource identifier when available")
    resource_type: str | None = Field(None, description="Cloud resource/service type when available")
    operation: str | None = Field(None, description="Cloud operation or API action when available")
    parser_status: str = Field("PARSED", description="Parser status: PARSED, PARTIAL, or FAILED")
    session_id: str | None = None
    typing_speed_cpm: float | None = None
    command_rate_per_minute: float | None = None
    command_error_rate: float | None = None
    idle_time_seconds: float | None = None
    repeated_command_ratio: float | None = None
    session_duration_minutes: float | None = None
    login_hour: int | None = None
    behavioral_risk_score: int | None = None
    behavioral_classification: str | None = None
    risk_reasons: str | None = None
    baseline_version: int | None = None

    model_config = {"from_attributes": True}

    @model_validator(mode="before")
    @classmethod
    def _explicit_times(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return data
        session = object_session(data)
        values = {name: getattr(data, name) for name in cls.model_fields if hasattr(data, name)}
        values.update(event_time_view(
            timestamp=getattr(data, "timestamp", None),
            collection_timestamp=getattr(data, "collection_timestamp", None),
            timestamp_source=getattr(data, "timestamp_source", None),
            normalized_data=getattr(data, "normalized_data", None),
            storage_tz=storage_timezone(session) if session is not None else timezone.utc,
        ))
        return values


class SecurityEventCreate(BaseModel):
    """Pydantic schema for validating incoming security event payload."""

    event_id: str | None = Field(None, description="Unique UUID for the security event")
    server_id: str | None = Field(None, description="Registered server ID")
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
    command: str | None = Field(None, description="Command observed in the event")
    normalized_data: str | None = Field(None, description="JSON normalized metadata for this event")

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
    limit: int = Query(100, ge=1, le=2000, description="Maximum number of events to return"),
    offset: int = Query(0, ge=0, description="Number of events to skip"),
    event_type: str | None = Query(None, description="Filter by event classification type"),
    severity: str | None = Query(None, description="Filter by severity level"),
    category: str | None = Query(None, description="Filter by high-level category"),
    username: str | None = Query(None, description="Filter by associated username"),
    source_ip: str | None = Query(None, description="Filter by originating source IP"),
    hostname: str | None = Query(None, description="Filter by originating hostname"),
    server_id: str | None = Query(None, description="Filter by monitored server ID"),
    source_type: str | None = Query(None, description="Filter by source type, e.g. CLOUD"),
    provider: str | None = Query(None, description="Filter by provider, e.g. OPENSTACK"),
    data_origin: str | None = Query(None, description="Filter by data origin, e.g. PUBLIC_DATASET"),
    dataset_name: str | None = Query(None, description="Filter by dataset name"),
    original_label: str | None = Query(None, description="Filter by original dataset label"),
    parser_status: str | None = Query(None, description="Filter by parser status"),
    behavioral_classification: str | None = Query(None, description="Filter by behavioral classification"),
    minimum_behavioral_risk: int | None = Query(None, ge=0, le=100, description="Minimum behavioral risk"),
    actor_id: str | None = Query(None, description="Filter by behavioral actor/user ID"),
    session_id: str | None = Query(None, description="Filter by behavioral session ID"),
    event_ids: list[str] | None = Query(
        None,
        description="Optional explicit event_id filter (repeatable or comma-separated). Still subject to account/environment visibility.",
    ),
    search: str | None = Query(None, description="Search message, username, hostname, IP, and log text"),
    start_time: datetime | None = Query(None, description="Filter events after this UTC timestamp"),
    end_time: datetime | None = Query(None, description="Filter events before this UTC timestamp"),
    record_kind: Literal["SECURITY_EVENT", "SYSTEM_EVENT", "SYSTEM_SNAPSHOT", "NOT_SNAPSHOT"] | None = Query(
        None, description="Only security events, system events, snapshots, or everything except snapshots"),
    sort_order: Literal["newest", "oldest"] = Query("newest", description="Sort by event time (source occurrence; observation time for snapshots)"),
    scope: Literal["private", "global", "both"] = Query("private", description="private telemetry, global intelligence, or both"),
    account_id: str | None = Query(None, description="Admin-only account filter for private telemetry"),
    environment: str | None = Query(None, pattern=ENVIRONMENT_PATTERN, description="Optional environment filter"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Query, filter, and paginate security events."""
    logger.info(
        "API request by %s: GET /events server_id=%s scope=%s environment=%s event_ids=%s",
        current_user.username,
        server_id,
        scope,
        environment,
        None if event_ids is None else len(event_ids),
    )
    selected = account_id if is_admin(current_user) else None
    visibility = with_environment(visibility_for(current_user, scope=scope, selected_account_id=selected), environment)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    normalized_ids = normalize_event_ids(event_ids)
    effective_origin = resolve_cloud_event_ids_data_origin(
        event_ids=normalized_ids,
        environment=environment,
        requested_data_origin=data_origin,
    )
    return service.query_events(
        limit=limit,
        offset=offset,
        event_type=event_type,
        severity=severity,
        category=category,
        username=username,
        source_ip=source_ip,
        hostname=hostname,
        server_id=scoped_server_id,
        visibility=visibility,
        source_type=source_type,
        provider=provider,
        data_origin=effective_origin,
        dataset_name=dataset_name,
        original_label=original_label,
        parser_status=parser_status,
        behavioral_classification=behavioral_classification,
        minimum_behavioral_risk=minimum_behavioral_risk,
        actor_id=actor_id,
        session_id=session_id,
        event_ids=normalized_ids,
        search=search,
        start_time=start_time,
        end_time=end_time,
        record_kind=record_kind,
        sort_order=sort_order,
    )


@router.get("/stats", status_code=status.HTTP_200_OK, summary="Get Security Analytics and Statistics")
def get_event_stats(
    server_id: str | None = Query(None, description="Filter analytics to one server"),
    environment: str = Query(LINUX, pattern=ENVIRONMENT_PATTERN, description="Environment for the statistics"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    analytics_service: AnalyticsService = Depends(get_analytics_service),
) -> Any:
    """Retrieve aggregated SIEM metrics, severity distributions, attacker IP ranks, and hourly trends."""
    logger.info("API request by %s: GET /events/stats server_id=%s environment=%s", current_user.username, server_id, environment)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    visibility = with_environment(visibility_for(current_user, scope="private"), environment)
    return {**analytics_service.get_event_stats(visibility=visibility, server_id=scoped_server_id), "environment": environment}


@router.get("/recent", response_model=list[SecurityEventResponse], status_code=status.HTTP_200_OK, summary="List Recent Events")
def get_recent_events(
    limit: int = Query(20, ge=1, le=2000, description="Number of recent events to return"),
    server_id: str | None = Query(None, description="Filter recent events to one server"),
    environment: str | None = Query(None, pattern=ENVIRONMENT_PATTERN, description="Optional environment filter"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve the absolute latest security events, optimized for live SIEM dashboards."""
    logger.info("API request by %s: GET /events/recent (limit=%d, server_id=%s, environment=%s)", current_user.username, limit, server_id, environment)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    visibility = with_environment(visibility_for(current_user, scope="private"), environment)
    return service.get_recent_events(limit=limit, owner_id=None, server_id=scoped_server_id, visibility=visibility)


@router.get("/high-risk", status_code=status.HTTP_200_OK, summary="List High-Risk Events")
def get_high_risk_events(
    min_score: int = Query(70, ge=0, le=100, description="Minimum risk score threshold"),
    limit: int = Query(100, ge=1, le=2000, description="Maximum number of events to return"),
    offset: int = Query(0, ge=0, description="Number of high-risk events to skip"),
    server_id: str | None = Query(None, description="Filter high-risk events to one server"),
    environment: str | None = Query(None, pattern=ENVIRONMENT_PATTERN, description="Optional environment filter"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: EventService = Depends(get_event_service),
) -> Any:
    """Retrieve high-risk security events meeting or exceeding risk score (>= 70), sorted descending."""
    logger.info(
        "API request by %s: GET /events/high-risk (min_score=%d, server_id=%s, environment=%s)",
        current_user.username,
        min_score,
        server_id,
        environment,
    )
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    visibility = with_environment(visibility_for(current_user, scope="private"), environment)
    items = service.get_high_risk_events(
        min_score=min_score,
        limit=limit,
        visibility=visibility,
        server_id=scoped_server_id,
        offset=offset,
    )
    total = service.count_high_risk_events(
        min_score=min_score,
        visibility=visibility,
        server_id=scoped_server_id,
    )
    return {
        "total": total,
        "items": [SecurityEventResponse.model_validate(item) for item in items],
        "limit": limit,
        "offset": offset,
        "scope": "private",
        "note": "total is a database COUNT; items are the current page.",
    }


@router.post("", response_model=IngestionResponse, status_code=status.HTTP_201_CREATED, summary="Ingest a Single Event")
def ingest_single_event(
    event_data: SecurityEventCreate,
    current_user: User = Depends(get_current_user),
    ingestion_service: IngestionService = Depends(get_ingestion_service),
) -> Any:
    """Ingest, validate, and persist a single security event."""
    logger.info("API request by %s: POST /events (event_id=%s)", current_user.username, event_data.event_id)
    payload = event_data.model_dump()
    payload["owner_id"] = current_user.id
    payload["account_id"] = resolve_account_id(current_user)
    payload["data_scope"] = DATA_SCOPE_PRIVATE
    payload["data_origin"] = payload.get("data_origin") or "LIVE_LINUX"
    inserted_event = ingestion_service.ingest_single_event(payload)
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
    payloads = []
    failed = 0
    errors: list[dict[str, Any]] = []
    for index, item in enumerate(events_data):
        try:
            validated = SecurityEventCreate.model_validate(item)
        except ValidationError as exc:
            failed += 1
            errors.append({"index": index, "error": str(exc.errors())})
            continue
        payload = validated.model_dump()
        payload["owner_id"] = current_user.id
        payload["account_id"] = resolve_account_id(current_user)
        payload["data_scope"] = DATA_SCOPE_PRIVATE
        payloads.append(payload)
    stats = ingestion_service.ingest_bulk_events(payloads)
    return BulkIngestionResponse(
        success=True,
        inserted=stats["inserted"],
        duplicates=stats["duplicates"],
        failed=failed + stats["failed"],
        errors=[BulkErrorDetail(**err) for err in errors + stats["errors"]],
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