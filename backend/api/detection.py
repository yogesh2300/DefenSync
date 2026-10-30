"""REST API endpoints for ML behavioral detection."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_account_id, resolve_owner_id, validate_server_scope
from backend.core.exceptions import AuthorizationError, ResourceNotFoundError, ValidationException
from backend.core.logging import get_logger
from backend.database import server_crud
from backend.database.models import User
from backend.database.scope import is_admin
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
    isolation_forest: str | None = None
    random_forest: str | None = None
    evaluation: dict[str, Any] | None = None
    feature_importance: dict[str, float] | None = None
    trained_at: str | None = None
    message: str
    linux: dict[str, Any] | None = Field(
        None, description="Linux Isolation Forest / Random Forest state, separate from the Cloud/HPC/behavioral models",
    )

    model_config = {"extra": "allow"}


class AnomalyItem(BaseModel):
    event_id: str
    timestamp: str | None
    collection_timestamp: str | None = None
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
    account_id = resolve_account_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.status(owner_id=owner_id, server_id=scoped_server_id, account_id=account_id)


@router.post("/run", response_model=DetectionRunResponse, summary="Run hybrid detection")
def run_detection(
    server_id: str | None = Query(None, description="Run detection for one server only"),
    owner_id: str | None = Query(None, max_length=36, description="ADMIN only: run detection in this user's scope"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DetectionService = Depends(get_detection_service),
) -> Any:
    logger.info("API request by %s: POST /detection/run server_id=%s", current_user.username, server_id)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    scope_owner, scope_account = _run_scope(db, current_user, scoped_server_id, owner_id)
    return service.run_detection(owner_id=scope_owner, server_id=scoped_server_id, account_id=scope_account)


def _run_scope(db: Session, user: User, server_id: str | None, owner_id: str | None) -> tuple[str, str | None]:
    """(owner_id, account_id) a detection run writes under.

    A run deletes and rebuilds the stored predictions of its scope, so ADMIN must name one
    tenant (a server or a user) instead of rebuilding every tenant's detections at once.
    """
    if not is_admin(user):
        if owner_id and owner_id != user.id:
            raise AuthorizationError("Only administrators can run detection for another user.")
        return user.id, resolve_account_id(user)
    if server_id:
        server = server_crud.get_server(db, server_id)
        server_owner = server.owner_id or server.created_by
        if not server_owner:
            raise ValidationException(f"Server '{server_id}' has no owner; detection cannot be scoped to a tenant.")
        if owner_id and owner_id != server_owner:
            raise ValidationException("owner_id does not own the selected server.")
        return server_owner, server.account_id
    if owner_id:
        target = db.get(User, owner_id)
        if target is None:
            raise ResourceNotFoundError(f"User '{owner_id}' not found.")
        return target.id, None if is_admin(target) else target.account_id
    raise ValidationException(
        "Administrators must select a server or pass owner_id: a platform-wide run would rebuild every tenant's detections."
    )


@router.get("/anomalies", summary="List detected anomalies")
def list_anomalies(
    limit: int = Query(20, ge=1, le=100),
    server_id: str | None = Query(None, description="Filter anomalies to one server"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: DetectionService = Depends(get_detection_service),
) -> Any:
    logger.info("API request by %s: GET /detection/anomalies server_id=%s", current_user.username, server_id)
    owner_id = resolve_owner_id(current_user)
    account_id = resolve_account_id(current_user)
    scoped_server_id = validate_server_scope(server_id, current_user, db)
    return service.get_anomalies(limit=limit, owner_id=owner_id, server_id=scoped_server_id, account_id=account_id)
