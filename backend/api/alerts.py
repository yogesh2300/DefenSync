"""REST API endpoints for security alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_owner_id, validate_server_scope, visibility_for
from backend.core.environments import ENVIRONMENT_PATTERN, LINUX
from backend.core.exceptions import ValidationException
from backend.core.logging import get_logger
from backend.database.models import User
from backend.services.alert_service import AlertService

logger = get_logger(__name__)
router = APIRouter()


class AlertResponse(BaseModel):
    id: str
    event_id: str
    server_id: str | None = None
    owner_id: str | None = None
    account_id: str | None = None
    title: str
    message: str
    severity: str
    risk_score: int = Field(..., description="Stored alert risk_score (may be legacy-inflated for old ML rows)")
    detection_type: str
    acknowledged: bool
    created_at: datetime
    explanation: str | None = None
    recommendation: str | None = None
    risk_factors: str | None = None
    incident_id: str | None = None
    event_timestamp: datetime | None = None
    confidence: float | None = None
    risk_level: str | None = None
    event_risk_score: int | None = Field(None, description="Linked event.risk_score; prefer this for Event Risk display")
    event_severity: str | None = Field(None, description="Linked event severity")
    anomaly_score: float | None = Field(None, description="Isolation Forest anomaly strength when available")
    alert_priority: str = Field("low", description="Priority-board severity after correcting ML inflation")
    demo_label: str | None = Field(None, description="DEMO when presentation/simulated telemetry")
    is_demo: bool = False
    collection_id: str | None = None
    collection_run_id: str | None = None
    notification_status: str | None = Field(None, description="n8n outbox PENDING|SENT|FAILED|NOT_CONFIGURED")
    notification_http_status: int | None = None
    email_delivery: str | None = Field(None, description="unknown unless an external delivery receipt exists")

    model_config = {"from_attributes": True}


class AlertSummaryResponse(BaseModel):
    total: int
    unacknowledged: int
    rule_based: int
    ml_anomaly: int
    critical: int
    priority: int = 0
    environment: str | None = None


def get_alert_service(db: Session = Depends(get_db)) -> AlertService:
    return AlertService(db)


@router.get("", response_model=list[AlertResponse], summary="List security alerts")
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    acknowledged: bool | None = Query(None),
    server_id: str | None = Query(None, description="Filter alerts to one server"),
    environment: str | None = Query(None, pattern=ENVIRONMENT_PATTERN, description="Only alerts whose event is in this environment"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: AlertService = Depends(get_alert_service),
) -> Any:
    logger.info("API request by %s: GET /alerts server_id=%s environment=%s", current_user.username, server_id, environment)
    owner_id = resolve_owner_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.list_alerts(
        limit=limit,
        acknowledged=acknowledged,
        owner_id=owner_id,
        server_id=scoped_server_id,
        environment=environment,
    )


@router.get("/summary", response_model=AlertSummaryResponse, summary="Alert summary counts")
def alert_summary(
    server_id: str | None = Query(None, description="Filter alert summary to one server"),
    environment: str = Query(LINUX, pattern=ENVIRONMENT_PATTERN, description="Environment of the alerted events"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: AlertService = Depends(get_alert_service),
) -> Any:
    owner_id = resolve_owner_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    summary = service.summary(
        owner_id=owner_id,
        server_id=scoped_server_id,
        environment=environment,
        visibility=visibility_for(current_user, scope="private"),
    )
    return {**summary, "environment": environment}


@router.post("/{alert_id}/ack", response_model=AlertResponse, summary="Acknowledge alert")
def acknowledge_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> Any:
    logger.info("API request by %s: POST /alerts/%s/ack", current_user.username, alert_id)
    try:
        owner_id = resolve_owner_id(current_user)
        return service.acknowledge(alert_id, owner_id=owner_id)
    except ValueError as exc:
        raise ValidationException(str(exc)) from exc
