"""Real cloud telemetry collection APIs (Azure). Read-only toward Azure; no secrets in responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field, SecretStr
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_admin, get_current_user, get_db, is_admin, resolve_account_id
from backend.core.config import Settings, get_settings
from backend.core.exceptions import ResourceNotFoundError, ValidationException
from backend.core.logging import get_logger
from backend.database.models import Account, CloudCollectionRun, CloudSource, User
from backend.database.scope import user_can_access_cloud_source
from backend.services.cloud.azure_client import Transport
from backend.services.cloud.azure_collector import (
    MAX_RECORDS_LIMIT,
    MAX_WINDOW_MINUTES,
    STATUS_COLLECTION_FAILED,
    STATUS_COLLECTION_OK,
    STATUS_CONFIGURED,
    AzureCollector,
)
from backend.services.cloud.cloud_source_service import CloudSourceService, azure_config, run_view, source_view
from backend.services.cloud.identity_baseline_service import (
    ALLOWED_DATA_ORIGINS,
    CloudIdentityBaselineService,
)
from backend.services.cloud.sequence_detection_service import (
    DEFAULT_SEQUENCE_MINUTES,
    MAX_SEQUENCE_MINUTES,
    CloudSequenceDetectionService,
)

logger = get_logger(__name__)
router = APIRouter()


class AzureCollectRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=36, description="DefenSync account that owns this Azure tenant's telemetry")
    lookback_minutes: int | None = Field(None, ge=1, le=MAX_WINDOW_MINUTES)
    start_time: datetime | None = None
    end_time: datetime | None = None
    sources: list[Literal["ENTRA_SIGNIN", "AZURE_ACTIVITY"]] | None = None
    max_records: int | None = Field(None, ge=1, le=MAX_RECORDS_LIMIT, description="Per-source row cap")


# Every field has a default so a validation error never echoes the whole body (and the secret);
# missing values are rejected by the service with field names only.
class AzureSourceCredentials(BaseModel):
    provider: Literal["AZURE"] = "AZURE"
    source_type: Literal["AZURE_LOG_ANALYTICS"] = "AZURE_LOG_ANALYTICS"
    tenant_id: str = Field("", max_length=255)
    client_id: str = Field("", max_length=64)
    client_secret: SecretStr = SecretStr("")
    workspace_id: str = Field("", max_length=64)

    def config(self):
        return azure_config(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret.get_secret_value(),
            workspace_id=self.workspace_id,
        )


class CloudSourceCreateRequest(AzureSourceCredentials):
    account_id: str | None = Field(None, max_length=36, description="ADMIN only: account that owns the source")


class CloudSourceCollectRequest(BaseModel):
    lookback_minutes: int | None = Field(None, ge=1, le=MAX_WINDOW_MINUTES, description="Recent window ending now")
    start_time: datetime | None = Field(None, description="Historical window start (with end_time); bounded by the configured limits")
    end_time: datetime | None = None
    sources: list[Literal["ENTRA_SIGNIN", "AZURE_ACTIVITY"]] | None = None
    max_records: int | None = Field(None, ge=1, le=MAX_RECORDS_LIMIT, description="Per-source row cap")


def get_azure_settings() -> Settings:
    return get_settings()


def get_azure_transport() -> Transport | None:
    """None selects the standard HTTPS transport; tests override this dependency."""
    return None


def get_cloud_source_service(
    db: Session = Depends(get_db),
    transport: Transport | None = Depends(get_azure_transport),
) -> CloudSourceService:
    return CloudSourceService(db, transport=transport)


@router.get("/sources", status_code=status.HTTP_200_OK, summary="Cloud sources accessible to the current user")
def list_cloud_sources(
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    sources = [service.view(source) for source in service.list_sources(current_user)]
    return {"sources": sources, "count": len(sources), "collection_limits": service.collection_limits()}


@router.post("/sources/test-connection", status_code=status.HTTP_200_OK, summary="Test Azure credentials before saving (read-only)")
def test_cloud_credentials(
    body: AzureSourceCredentials,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    del current_user
    return service.test_credentials(body.config())


@router.post("/sources", status_code=status.HTTP_201_CREATED, summary="Add a cloud source (connection is verified first)")
def create_cloud_source(
    body: CloudSourceCreateRequest,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    return source_view(service.create(current_user, body.config(), account_id=body.account_id))


@router.get("/sources/{source_id}", status_code=status.HTTP_200_OK, summary="Cloud source status")
def get_cloud_source(
    source_id: str,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    return service.view(service.get_source(current_user, source_id))


@router.post("/sources/{source_id}/test-connection", status_code=status.HTTP_200_OK, summary="Re-test a saved cloud source (read-only)")
def test_cloud_source(
    source_id: str,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    return service.test_saved(current_user, source_id)


@router.post("/sources/{source_id}/collect", status_code=status.HTTP_200_OK, summary="Collect now from a cloud source (read-only)")
def collect_cloud_source(
    source_id: str,
    body: CloudSourceCollectRequest | None = None,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    logger.info("API request by %s: POST /cloud/sources/%s/collect", current_user.username, source_id)
    body = body or CloudSourceCollectRequest()
    return service.collect(
        current_user,
        source_id,
        lookback_minutes=body.lookback_minutes,
        start=body.start_time,
        end=body.end_time,
        max_records=body.max_records,
        sources=body.sources,
    )


@router.get("/sources/{source_id}/collections", status_code=status.HTTP_200_OK, summary="Collection runs of a cloud source (newest first)")
def list_cloud_source_collections(
    source_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    storage_tz = service.storage_tz()
    runs = [run_view(run, storage_tz) for run in service.list_runs(current_user, source_id, limit=limit)]
    return {"cloud_source_id": source_id, "runs": runs, "count": len(runs), "collection_limits": service.collection_limits()}


@router.get("/sources/{source_id}/collections/{run_id}", status_code=status.HTTP_200_OK, summary="One collection run of a cloud source")
def get_cloud_source_collection(
    source_id: str,
    run_id: str,
    current_user: User = Depends(get_current_user),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    return run_view(service.get_run(current_user, source_id, run_id), service.storage_tz())


@router.delete("/sources/{source_id}", status_code=status.HTTP_200_OK, summary="Remove a cloud source")
def delete_cloud_source(
    source_id: str,
    current_admin: User = Depends(get_current_admin),
    service: CloudSourceService = Depends(get_cloud_source_service),
) -> dict[str, Any]:
    service.delete(current_admin, source_id)
    return {"success": True, "id": source_id}


@router.get(
    "/identity-baselines",
    status_code=status.HTTP_200_OK,
    summary="Cloud identity behavioral baselines (observed activity aggregates)",
)
def cloud_identity_baselines(
    start_time: datetime = Query(..., description="Inclusive window start (UTC recommended)"),
    end_time: datetime = Query(..., description="Exclusive window end (UTC recommended)"),
    actor_id: str | None = Query(None, max_length=255, description="Optional cloud identity filter (actor_id)"),
    data_origin: list[str] | None = Query(
        None,
        description=f"Optional origin filter; default and allowlist: {', '.join(sorted(ALLOWED_DATA_ORIGINS))}",
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Aggregate PRIVATE CLOUD events by cloud actor_id for the caller's account scope.

    Does not detect compromise. Real Azure telemetry only unless an allowlisted data_origin is passed.
    """
    logger.info(
        "API request by %s: GET /cloud/identity-baselines actor_id=%s",
        current_user.username,
        (actor_id or "")[:64] or None,
    )
    return CloudIdentityBaselineService(db).build(
        user=current_user,
        start_time=start_time,
        end_time=end_time,
        actor_id=actor_id,
        data_origins=data_origin,
    )


@router.get(
    "/sequence-findings",
    status_code=status.HTTP_200_OK,
    summary="Cloud suspicious activity sequence findings (rule-based heuristics)",
)
def cloud_sequence_findings(
    start_time: datetime = Query(..., description="Inclusive lookback window start (UTC recommended)"),
    end_time: datetime = Query(..., description="Exclusive lookback window end (UTC recommended)"),
    actor_id: str | None = Query(None, max_length=255, description="Optional cloud identity filter (actor_id)"),
    sequence_minutes: int = Query(
        DEFAULT_SEQUENCE_MINUTES,
        ge=1,
        le=MAX_SEQUENCE_MINUTES,
        description="Max minutes between steps of a matched sequence",
    ),
    data_origin: list[str] | None = Query(
        None,
        description=f"Optional origin filter; default and allowlist: {', '.join(sorted(ALLOWED_DATA_ORIGINS))}",
    ),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Detect transparent event sequences for cloud identities in the caller's account scope.

    Heuristic only — does not confirm compromise and does not trigger remediation.
    """
    logger.info(
        "API request by %s: GET /cloud/sequence-findings actor_id=%s sequence_minutes=%s",
        current_user.username,
        (actor_id or "")[:64] or None,
        sequence_minutes,
    )
    return CloudSequenceDetectionService(db).detect(
        user=current_user,
        start_time=start_time,
        end_time=end_time,
        actor_id=actor_id,
        data_origins=data_origin,
        sequence_minutes=sequence_minutes,
    )


@router.get("/azure/status", status_code=status.HTTP_200_OK, summary="Azure collector configuration and last collection")
def azure_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_azure_settings),
) -> dict[str, Any]:
    status_payload = AzureCollector(db, settings=settings).status()
    last = status_payload.get("last_collection")
    if last and not _can_see_collection(db, current_user, last):
        status_payload["last_collection"] = None
        if status_payload["status"] in {STATUS_COLLECTION_OK, STATUS_COLLECTION_FAILED}:
            status_payload["status"] = STATUS_CONFIGURED
    return status_payload


def _can_see_collection(db: Session, user: User, last: dict[str, Any]) -> bool:
    """ADMIN sees every collection; an analyst only one from a CloudSource they can access,
    or an account-level collection of their own (non-empty) account. A missing account never matches."""
    if is_admin(user):
        return True
    collection_id = last.get("collection_id")
    if collection_id:
        run = db.scalar(select(CloudCollectionRun).where(CloudCollectionRun.collection_id == collection_id).limit(1))
        if run is not None:
            source = db.get(CloudSource, run.cloud_source_id)
            return source is not None and user_can_access_cloud_source(user, source)
    account_id = resolve_account_id(user)
    return bool(account_id) and last.get("account_id") == account_id


@router.post("/azure/collect", status_code=status.HTTP_200_OK, summary="Collect Entra sign-ins and Azure Activity Log (read-only)")
def azure_collect(
    request: AzureCollectRequest,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_azure_settings),
    transport: Transport | None = Depends(get_azure_transport),
) -> dict[str, Any]:
    if db.get(Account, request.account_id) is None:
        raise ResourceNotFoundError(f"Account '{request.account_id}' not found.")
    logger.info("API request by %s: POST /cloud/azure/collect account_id=%s", current_admin.username, request.account_id)
    try:
        return AzureCollector(db, settings=settings, transport=transport).collect(
            owner_id=current_admin.id,
            account_id=request.account_id,
            lookback_minutes=request.lookback_minutes,
            start=request.start_time,
            end=request.end_time,
            sources=request.sources,
            max_records=request.max_records,
        )
    except ValueError as exc:
        raise ValidationException(str(exc)) from exc
