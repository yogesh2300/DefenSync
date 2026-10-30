"""REST API endpoints for on-demand log collection and pipeline processing."""

from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db
from backend.core.exceptions import AuthorizationError, ValidationException
from backend.database.scope import user_can_access_server
from backend.core.logging import get_logger
from backend.collector.log_sources import DEFAULT_LOG_SOURCES
from backend.database.models import User
from backend.services.server_service import ServerService

logger = get_logger(__name__)
router = APIRouter()

LogSourceName = Literal["secure", "audit", "auth", "syslog", "journalctl", "last", "lastb", "who", "w", "uptime", "free", "df", "ps", "ss", "hostnamectl", "uname", "top"]


class CollectionRunRequest(BaseModel):
    """Collection requires a registered server — credentials come from the database."""

    server_id: str = Field(..., description="Monitored server ID from Server Management.")
    tail_lines: int | None = Field(None, ge=1, le=10000)
    log_sources: list[LogSourceName] | None = None

    @field_validator("log_sources")
    @classmethod
    def validate_log_sources(cls, value: list[LogSourceName] | None) -> list[LogSourceName] | None:
        if value is None:
            return None
        normalized = list(dict.fromkeys(source.lower() for source in value))
        if not normalized:
            raise ValueError("log_sources must include at least one source.")
        return normalized  # type: ignore[return-value]


class CollectionRunResponse(BaseModel):
    success: bool
    processed: int
    inserted: int
    collected_events: int
    duplicates: int
    failed: int
    skipped: int
    duration_ms: int
    server_id: str
    errors: list[dict[str, Any]] = Field(default_factory=list)
    skipped_sources: dict[str, str] = Field(default_factory=dict)
    detection: dict[str, Any] | None = Field(
        None,
        description="Present after a successful collection when post-collection detection was queued",
    )


def get_server_service(db: Session = Depends(get_db)) -> ServerService:
    return ServerService(db)


@router.post(
    "/run",
    response_model=CollectionRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Run log collection pipeline for an accessible server",
)
def run_collection(
    request: CollectionRunRequest,
    current_user: User = Depends(get_current_user),
    servers: ServerService = Depends(get_server_service),
) -> CollectionRunResponse:
    """
    Collect Linux security logs using credentials stored in the database.

    Register servers via POST /api/v1/servers — do not use .env SSH settings.
    """
    log_sources = frozenset(request.log_sources) if request.log_sources else DEFAULT_LOG_SOURCES
    server = servers.get_server(request.server_id)
    if not user_can_access_server(current_user, server):
        raise AuthorizationError("You do not have access to this server.")
    logger.info("User %s collection run server_id=%s", current_user.username, request.server_id)
    try:
        stats = servers.collect_for_server(
            request.server_id,
            tail_lines=request.tail_lines,
            log_sources=log_sources,
        )
    except Exception as exc:
        raise ValidationException(str(exc)) from exc

    return CollectionRunResponse(
        success=bool(stats.get("success")),
        processed=stats.get("processed", 0),
        inserted=stats.get("inserted", 0),
        collected_events=stats.get("collected_events", stats.get("inserted", 0)),
        duplicates=stats.get("duplicates", 0),
        failed=stats.get("failed", 0),
        skipped=stats.get("skipped", 0),
        duration_ms=stats.get("duration_ms", 0),
        server_id=request.server_id,
        errors=stats.get("errors", []),
        skipped_sources=stats.get("skipped_sources") or {},
        detection=stats.get("detection"),
    )
