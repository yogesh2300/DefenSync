"""REST API endpoints for dashboard analytics and SIEM metric summaries."""
from __future__ import annotations

from backend.core.logging import get_logger
from typing import Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db
from backend.services.dashboard_service import DashboardService

logger = get_logger(__name__)

router = APIRouter()


class DashboardSummaryResponse(BaseModel):
    """Pydantic schema representing aggregated dashboard telemetry summary metrics."""

    total_events: int = Field(..., description="Total number of recorded security events")
    high_risk: int = Field(..., description="Count of high-risk security events (score >= 70)")
    successful_logins: int = Field(..., description="Count of successful authentication events")
    failed_logins: int = Field(..., description="Count of failed authentication events")
    unique_users: int = Field(..., description="Number of distinct usernames observed")
    unique_ips: int = Field(..., description="Number of distinct source IP addresses observed")


def get_dashboard_service(db: Session = Depends(get_db)) -> DashboardService:
    """Dependency injection provider yielding a DashboardService bound to the current database session."""
    return DashboardService(db)


@router.get("/summary", response_model=DashboardSummaryResponse, status_code=status.HTTP_200_OK, summary="Get Dashboard Summary")
def get_dashboard_summary(
    service: DashboardService = Depends(get_dashboard_service),
) -> Any:
    """Retrieve aggregated SIEM telemetry summary metrics for dashboard visualization."""
    logger.info("API request: GET /dashboard/summary")
    return service.dashboard_summary()