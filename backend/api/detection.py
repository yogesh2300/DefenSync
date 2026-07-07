"""REST API endpoints for ML behavioral detection."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_owner_id, validate_server_scope
from backend.core.logging import get_logger
from backend.database.models import User
from backend.services.detection_service import DetectionService

logger = get_logger(__name__)
router = APIRouter()


class DetectionRunResponse(BaseModel):
    success: bool
    events_analyzed: int
    rule_alerts_created: int = 0
    ml_anomalies: int = 0
    ml_classified_suspicious: int = 0
    total_flagged: int | None = None
    normal: int = 0
    suspicious: int = 0
    malicious: int = 0
    predictions_stored: int = 0
    message: str


class AnomalyItem(BaseModel):
    event_id: str
    timestamp: str | None
    hostname: str
    username: str | None
    source_ip: str | None
    server_id: str | None = None
    event_type: str
    severity: str
    risk_score: int
    message: str
    detection_type: str
    classification: str | None = None
    anomaly_score: float | None = None


def get_detection_service(db: Session = Depends(get_db)) -> DetectionService:
    return DetectionService(db)


@router.get("/status", summary="Detection engine status")
def detection_status(
    server_id: str | None = Query(None, description="Filter detection status to one server"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DetectionService = Depends(get_detection_service),
) -> Any:
    logger.info("API request by %s: GET /detection/status server_id=%s", current_user.username, server_id)
    owner_id = resolve_owner_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.status(owner_id=owner_id, server_id=scoped_server_id)


@router.post("/run", response_model=DetectionRunResponse, summary="Run hybrid detection")
def run_detection(
    server_id: str | None = Query(None, description="Run detection for one server only"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DetectionService = Depends(get_detection_service),
) -> Any:
    logger.info("API request by %s: POST /detection/run server_id=%s", current_user.username, server_id)
    owner_id = resolve_owner_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.run_detection(owner_id=owner_id, server_id=scoped_server_id)


@router.get("/anomalies", response_model=list[AnomalyItem], summary="List detected anomalies")
def list_anomalies(
    limit: int = Query(20, ge=1, le=100),
    server_id: str | None = Query(None, description="Filter anomalies to one server"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DetectionService = Depends(get_detection_service),
) -> Any:
    logger.info("API request by %s: GET /detection/anomalies server_id=%s", current_user.username, server_id)
    owner_id = resolve_owner_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.get_anomalies(limit=limit, owner_id=owner_id, server_id=scoped_server_id)
