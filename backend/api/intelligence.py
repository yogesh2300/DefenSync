"""Investigation APIs: correlation, incidents, behavior history, export."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.api.dependencies import (
    get_current_admin,
    get_current_user,
    get_db,
    resolve_account_id,
    resolve_owner_id,
    visibility_for,
)
from backend.core.environments import ENVIRONMENT_PATTERN, LINUX, normalize_environment
from backend.core.exceptions import ResourceNotFoundError, ValidationException
from backend.core.logging import get_logger
from backend.database.models import DATA_SCOPE_GLOBAL, DATA_SCOPE_PRIVATE, Incident, User
from backend.database.scope import is_admin
from backend.services import n8n_notifier
from backend.services.global_intelligence_service import GlobalIntelligenceService
from backend.services.alert_service import AlertService
from backend.services.correlation_service import CorrelationService
from backend.services.detection_service import DetectionService
from backend.services.event_service import EventService

router = APIRouter()
logger = get_logger(__name__)


def get_n8n_notifier() -> n8n_notifier.N8nNotifier:
    return n8n_notifier.N8nNotifier.from_settings()


@router.get("/global/summary", status_code=200)
def global_intelligence_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del current_user
    return GlobalIntelligenceService(db).summary()


@router.post("/correlate", status_code=200)
def run_correlation(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    account_id = resolve_account_id(current_user)
    incidents = CorrelationService(db).correlate_and_store(owner_id=resolve_owner_id(current_user), account_id=account_id)
    return {"count": len(incidents), "incidents": incidents}


@router.get("/incidents", status_code=200)
def list_incidents(
    limit: int = Query(20, ge=1, le=100),
    environment: str | None = Query(None, pattern=ENVIRONMENT_PATTERN, description="Only incidents of this environment"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    account_id = resolve_account_id(current_user)
    service = CorrelationService(db)
    fetch = 100 if environment else limit
    rows = service.list_incidents(owner_id=resolve_owner_id(current_user), account_id=account_id, limit=fetch)
    if not rows:
        rows = service.correlate_and_store(owner_id=resolve_owner_id(current_user), account_id=account_id)
    if environment:
        family = normalize_environment(environment)
        rows = [row for row in rows if (row.get("environment") or LINUX) == family]
    return rows[:limit]


@router.get("/n8n/status", status_code=200, summary="n8n incident notification configuration")
def n8n_status(
    current_user: User = Depends(get_current_user),
    notifier: n8n_notifier.N8nNotifier = Depends(get_n8n_notifier),
) -> dict[str, Any]:
    return notifier.status(include_last_delivery=is_admin(current_user))


@router.post(
    "/incidents/{incident_ref:path}/n8n-test",
    status_code=200,
    summary="TEST/DEMO: send one existing incident to the n8n webhook (admin only)",
)
def n8n_test_notification(
    incident_ref: str,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
    notifier: n8n_notifier.N8nNotifier = Depends(get_n8n_notifier),
) -> dict[str, Any]:
    """Demo operation: re-sends a stored incident (by row id or incident_id) with event incident.test.

    Creates nothing, changes nothing and works for any severity so the n8n workflow can be tested.
    """
    row = db.scalar(select(Incident).where(or_(Incident.id == incident_ref, Incident.incident_id == incident_ref)))
    if row is None:
        raise ResourceNotFoundError("Incident not found.")
    recipients = n8n_notifier.resolve_owner_recipient_emails(
        db, owner_id=row.owner_id, account_id=row.account_id
    )
    if not recipients:
        raise ValidationException("Incident has no verified owner recipient for notification.")
    logger.info("API request by %s: n8n test notification for incident %s", current_user.username, row.incident_id)
    payload = n8n_notifier.build_payload(
        CorrelationService._to_dict(row),
        event=n8n_notifier.EVENT_TEST,
        test=True,
        recipient_emails=recipients,
    )
    result = notifier.send(payload)
    return {"operation": "n8n_test_notification", "test": True, "schema_version": n8n_notifier.SCHEMA_VERSION, **result.as_dict()}


@router.get("/behavior-history", status_code=200)
def behavior_history(
    actor: str | None = Query(None),
    limit: int = Query(48, ge=1, le=200),
    environment: str = Query("LINUX", pattern="^(LINUX|CLOUD|HPC|BEHAVIORAL)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    account_id = resolve_account_id(current_user)
    return CorrelationService(db).behavior_history(
        owner_id=resolve_owner_id(current_user),
        account_id=account_id,
        actor=actor,
        limit=limit,
        environment=environment,
    )


@router.get("/export", status_code=200)
def export_investigation(
    fmt: str = Query("json", pattern="^(json|csv)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    account_id = resolve_account_id(current_user)
    visibility = visibility_for(current_user, scope="private")
    events = EventService(db).get_recent_events(limit=200, visibility=visibility)
    alerts = AlertService(db).list_alerts(limit=200, owner_id=resolve_owner_id(current_user), account_id=account_id)
    incidents = CorrelationService(db).list_incidents(owner_id=resolve_owner_id(current_user), account_id=account_id, limit=50)
    metrics = DetectionService(db).status(owner_id=resolve_owner_id(current_user), account_id=account_id)
    payload = {
        "report_timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "collection_timestamp": e.collection_timestamp.isoformat() if getattr(e, "collection_timestamp", None) else None,
                "event_type": e.event_type,
                "risk_score": e.risk_score,
                "message": e.message,
            }
            for e in events
        ],
        "alerts": [
            {"id": a.id, "title": a.title, "severity": a.severity, "risk_score": a.risk_score, "created_at": a.created_at.isoformat() if a.created_at else None}
            for a in alerts
        ],
        "incidents": incidents,
        "ml": {
            "isolation_forest": metrics.get("isolation_forest"),
            "random_forest": metrics.get("random_forest"),
            "evaluation": metrics.get("evaluation"),
        },
    }
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=["event_id", "timestamp", "event_type", "risk_score", "message"])
        writer.writeheader()
        writer.writerows(payload["events"])
        return Response(content=buffer.getvalue(), media_type="text/csv")
    return Response(content=json.dumps(payload, default=str), media_type="application/json")
