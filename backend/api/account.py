"""Account-scoped dashboard APIs."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_admin, get_current_user, get_db, is_admin, resolve_account_id, validate_server_scope
from backend.core.environments import CLOUD, ENVIRONMENT_PATTERN, LINUX
from backend.core.exceptions import AuthorizationError
from backend.database.models import User
from backend.services import collection_n8n_trigger, presentation_trigger
from backend.services.account_service import AccountService
from backend.services.cloud.presentation_telemetry import allowed_emails

router = APIRouter()


@router.get("/summary", status_code=status.HTTP_200_OK)
def account_summary(
    account_id: str | None = Query(None, description="Admin-only account selector"),
    server_id: str | None = Query(None),
    environment: str = Query(LINUX, pattern=ENVIRONMENT_PATTERN, description="Environment the aggregates are computed for"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    selected = None
    if account_id:
        if not is_admin(current_user):
            raise AuthorizationError("Account selection is limited to platform administrators.")
        selected = account_id
    scoped_server = validate_server_scope(server_id, current_user, db)
    return AccountService(db).summary(current_user, selected_account_id=selected, server_id=scoped_server, environment=environment)


@router.get("/presentation-trigger", status_code=status.HTTP_200_OK, summary="Presentation demo trigger progress (read-only)")
def presentation_trigger_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if is_admin(current_user) or (current_user.email or "").strip().lower() not in allowed_emails():
        return {"enabled": False}
    account_id = resolve_account_id(current_user)
    return {
        "enabled": True,
        "interval_range": [presentation_trigger.MIN_INTERVAL, presentation_trigger.MAX_INTERVAL],
        "environments": {
            environment: presentation_trigger.status(db, owner_id=current_user.id, account_id=account_id, environment=environment)
            for environment in (LINUX, CLOUD)
        },
    }


@router.get(
    "/collection-n8n",
    status_code=status.HTTP_200_OK,
    summary="Alternate-success collection n8n trigger progress (read-only)",
)
def collection_n8n_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """LINUX and CLOUD success counters and last dispatch status for the caller's tenant scope."""
    account_id = resolve_account_id(current_user)
    return collection_n8n_trigger.status_for_scope(
        db, owner_id=current_user.id, account_id=account_id,
    )


@router.get("/list", status_code=status.HTTP_200_OK)
def list_accounts(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    del current_admin
    return {"accounts": AccountService(db).list_accounts()}
