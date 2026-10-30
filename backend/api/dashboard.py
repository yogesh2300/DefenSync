"""REST API endpoints for dashboard analytics and SIEM metric summaries."""
from __future__ import annotations

from backend.core.logging import get_logger
from typing import Any
from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_account_id, resolve_owner_id, validate_server_scope, visibility_for
from backend.core.environments import ENVIRONMENT_PATTERN, LINUX
from backend.database.models import User
from backend.services.dashboard_service import DashboardService

logger = get_logger(__name__)

router = APIRouter()


class DashboardSummaryResponse(BaseModel):
    """Pydantic schema representing aggregated dashboard telemetry summary metrics."""

    total_events: int = Field(..., description="Security events (excludes System Snapshot / System Event rows)")
    high_risk: int = Field(..., description="Count of high-risk security events (score >= 70)")
    successful_logins: int = Field(..., description="Count of successful authentication events")
    failed_logins: int = Field(..., description="Count of failed authentication events")
    unique_users: int = Field(..., description="Number of distinct usernames observed")
    unique_ips: int = Field(..., description="Number of distinct source IP addresses observed")
    average_risk_score: int = Field(0, description="Average risk score across the environment's security events")
    max_risk_score: int = Field(0, description="Highest risk score across the environment's security events")
    system_snapshots: int = Field(0, description="Point-in-time system-state observations (not security events)")
    system_events: int = Field(0, description="System boot/shutdown records (not user logins)")
    collector_generated_events: int = Field(0, description="SSH events caused by DefenSync's own probes and collections")
    environment: str | None = Field(LINUX, description="Environment the event metrics were computed for")
    total_servers: int = Field(0, description="Total registered Linux servers")
    active_servers: int = Field(0, description="Active monitored servers")
    online_servers: int = Field(0, description="Servers with online SSH status")
    offline_servers: int = Field(0, description="Active servers currently offline")
    healthy_servers: int = Field(0, description="Servers passing health checks")
    servers_with_errors: int = Field(0, description="Servers with authentication or connection errors")
    average_ssh_latency_ms: int = Field(0, description="Average SSH probe latency for online servers")
    recently_connected: int = Field(0, description="Servers connected within the recent health window")
    recently_disconnected: int = Field(0, description="Servers that failed health checks recently")


def get_dashboard_service(db: Session = Depends(get_db)) -> DashboardService:
    """Dependency injection provider yielding a DashboardService bound to the current database session."""
    return DashboardService(db)


@router.get("/summary", response_model=DashboardSummaryResponse, status_code=status.HTTP_200_OK, summary="Get Dashboard Summary")
def get_dashboard_summary(
    server_id: str | None = Query(None, description="Filter dashboard metrics to one server"),
    environment: str = Query(LINUX, pattern=ENVIRONMENT_PATTERN, description="Environment for event metrics"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
) -> Any:
    """Retrieve aggregated SIEM telemetry summary metrics for dashboard visualization."""
    logger.info("API request by %s: GET /dashboard/summary server_id=%s environment=%s", current_user.username, server_id, environment)
    visibility = visibility_for(current_user, scope="private")
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    try:
        return service.dashboard_summary(
            visibility=visibility,
            server_id=scoped_server_id,
            account_id=resolve_account_id(current_user),
            environment=environment,
            server_owner_id=resolve_owner_id(current_user),
        )
    except Exception:
        logger.exception("Unhandled dashboard summary error; returning zero JSON response")
        return DashboardService.empty_summary(environment)


@router.get("", response_model=DashboardSummaryResponse, status_code=status.HTTP_200_OK, summary="Get Dashboard Summary")
def get_dashboard_root(
    server_id: str | None = Query(None, description="Filter dashboard metrics to one server"),
    environment: str = Query(LINUX, pattern=ENVIRONMENT_PATTERN, description="Environment for event metrics"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DashboardService = Depends(get_dashboard_service),
) -> Any:
    """Retrieve dashboard metrics at /api/v1/dashboard."""
    logger.info("API request by %s: GET /dashboard server_id=%s environment=%s", current_user.username, server_id, environment)
    visibility = visibility_for(current_user, scope="private")
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    try:
        return service.dashboard_summary(
            visibility=visibility,
            server_id=scoped_server_id,
            account_id=resolve_account_id(current_user),
            environment=environment,
            server_owner_id=resolve_owner_id(current_user),
        )
    except Exception:
        logger.exception("Unhandled dashboard root error; returning zero JSON response")
        return DashboardService.empty_summary(environment)
