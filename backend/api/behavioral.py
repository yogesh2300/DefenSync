"""Behavioral telemetry import, baseline, and analysis APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_owner_id
from backend.core.exceptions import ResourceNotFoundError
from backend.database.models import User
from backend.services.behavioral.baseline_service import BehavioralBaselineService, profile_to_dict
from backend.services.behavioral.behavior_analysis_service import BehavioralAnalysisService
from backend.services.behavioral.telemetry_import_service import BehavioralTelemetryImportService

router = APIRouter()


class BehavioralImportRequest(BaseModel):
    file_id: str = Field(..., min_length=8)
    max_records: int | None = Field(None, ge=1)
    batch_size: int | None = Field(None, ge=1)
    allow_reimport: bool = False


class BehavioralImportResponse(BaseModel):
    import_id: str
    dataset: str
    source_file: str
    status: str
    processed: int
    imported: int
    skipped: int
    failed: int
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None


@router.get("/files", status_code=status.HTTP_200_OK)
def behavioral_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    del current_user
    return {"files": BehavioralTelemetryImportService(db).discover_files()}


@router.post("/import", response_model=BehavioralImportResponse, status_code=status.HTTP_201_CREATED)
def import_behavioral_telemetry(
    request: BehavioralImportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    service = BehavioralTelemetryImportService(db)
    run = service.import_file(
        file_id=request.file_id,
        owner_id=current_user.id,
        max_records=request.max_records,
        batch_size=request.batch_size,
        allow_reimport=request.allow_reimport,
    )
    return service.import_to_dict(run)


@router.get("/imports", response_model=list[BehavioralImportResponse], status_code=status.HTTP_200_OK)
def list_behavioral_imports(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    owner_id = resolve_owner_id(current_user)
    service = BehavioralTelemetryImportService(db)
    return [service.import_to_dict(run) for run in service.list_imports(owner_id=owner_id, limit=limit)]


@router.get("/imports/{import_id}", response_model=BehavioralImportResponse, status_code=status.HTTP_200_OK)
def get_behavioral_import(
    import_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    service = BehavioralTelemetryImportService(db)
    run = service.get_import(import_id, owner_id=owner_id)
    if run is None:
        raise ResourceNotFoundError(f"Behavioral import '{import_id}' not found.")
    return service.import_to_dict(run)


@router.post("/baselines/build", status_code=status.HTTP_200_OK)
def build_behavioral_baselines(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return BehavioralBaselineService(db).build_all(owner_id=owner_id)


@router.post("/baselines/build/{identity_key}", status_code=status.HTTP_200_OK)
def build_behavioral_baseline(
    identity_key: str,
    server_id: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    profile = BehavioralBaselineService(db).build(identity_key=identity_key, server_id=server_id, owner_id=owner_id)
    return profile_to_dict(profile)


@router.get("/profiles", status_code=status.HTTP_200_OK)
def list_behavioral_profiles(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    owner_id = resolve_owner_id(current_user)
    return [profile_to_dict(profile) for profile in BehavioralBaselineService(db).list_profiles(owner_id=owner_id)]


@router.get("/profiles/{identity_key}", status_code=status.HTTP_200_OK)
def get_behavioral_profile(
    identity_key: str,
    server_id: str | None = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    profile = BehavioralBaselineService(db).get_profile(identity_key=identity_key, server_id=server_id, owner_id=owner_id)
    if profile is None:
        raise ResourceNotFoundError(f"Behavioral profile '{identity_key}' not found.")
    return profile_to_dict(profile)


@router.post("/analyze", status_code=status.HTTP_200_OK)
def analyze_behavioral_events(
    limit: int | None = Query(None, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return BehavioralAnalysisService(db).analyze_all(owner_id=owner_id, limit=limit)


@router.post("/analyze/{event_id}", status_code=status.HTTP_200_OK)
def analyze_behavioral_event(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return BehavioralAnalysisService(db).analyze_event(event_id, owner_id=owner_id)


@router.get("/summary", status_code=status.HTTP_200_OK)
def behavioral_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return BehavioralAnalysisService(db).summary(owner_id=owner_id)


@router.get("/anomalies", status_code=status.HTTP_200_OK)
def behavioral_anomalies(
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    owner_id = resolve_owner_id(current_user)
    return BehavioralAnalysisService(db).anomalies(owner_id=owner_id, limit=limit)
