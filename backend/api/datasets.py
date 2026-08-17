"""Authenticated public dataset discovery and import APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_owner_id
from backend.core.exceptions import ResourceNotFoundError, ValidationException
from backend.database.models import User
from backend.parser.openstack_parser import DATASET_NAME
from backend.services.datasets.openstack_discovery import OpenStackDiscoveryService
from backend.services.datasets.openstack_import_service import OpenStackImportService

router = APIRouter()


class OpenStackImportRequest(BaseModel):
    file_id: str = Field(..., min_length=8, max_length=128)
    max_records: int | None = Field(None, ge=1)
    batch_size: int | None = Field(None, ge=1)
    allow_reimport: bool = False
    line_offset: int = Field(0, ge=0)


class DatasetImportResponse(BaseModel):
    import_id: str
    owner_id: str
    dataset: str
    dataset_version: str | None = None
    source_file: str
    status: str
    total_records_discovered: int
    records_processed: int
    records_imported: int
    records_skipped: int
    records_failed: int
    batch_size: int
    import_limit: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime
    updated_at: datetime
    already_imported: bool = False
    provider: str | None = None
    data_origin: str | None = None


def get_import_service(db: Session = Depends(get_db)) -> OpenStackImportService:
    return OpenStackImportService(db)


@router.get("/openstack/status", status_code=status.HTTP_200_OK)
def openstack_status(
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    discovery = OpenStackDiscoveryService()
    return {
        **discovery.status(),
        "summary": service.summary(owner_id=owner_id),
    }


@router.get("/openstack/files", status_code=status.HTTP_200_OK)
def openstack_files(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    del current_user
    discovery = OpenStackDiscoveryService()
    return {
        "dataset": DATASET_NAME,
        "files": [item.to_dict() for item in discovery.discover_files()],
    }


@router.post("/openstack/import", response_model=DatasetImportResponse, status_code=status.HTTP_201_CREATED)
def import_openstack_file(
    request: OpenStackImportRequest,
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> dict[str, Any]:
    run = service.import_file(
        file_id=request.file_id,
        owner_id=current_user.id,
        max_records=request.max_records,
        batch_size=request.batch_size,
        allow_reimport=request.allow_reimport,
        line_offset=request.line_offset,
    )
    payload = service.import_to_dict(run)
    selected = next((item for item in OpenStackDiscoveryService().discover_files() if item.file_id == request.file_id), None)
    if selected:
        from backend.services.datasets.openstack_import_service import origin_fields_for_path
        origin, dataset = origin_fields_for_path(selected.relative_path)
        payload["data_origin"] = origin
        payload["dataset"] = dataset
        payload["provider"] = "OPENSTACK"
    return payload


@router.post("/openstack/demo", response_model=DatasetImportResponse, status_code=status.HTTP_201_CREATED)
def load_openstack_demo(
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> dict[str, Any]:
    """Generate the synthetic OpenStack demo log if needed, then import it."""
    from scripts.generate_openstack_demo import OUTPUT, generate

    generate()
    discovery = OpenStackDiscoveryService()
    files = discovery.discover_files()
    target = next((item for item in files if item.filename == OUTPUT.name), None)
    if target is None:
        raise ValidationException("OpenStack demo log was not generated.")
    return service.import_and_prepare(file_id=target.file_id, owner_id=current_user.id)


@router.get("/imports", response_model=list[DatasetImportResponse], status_code=status.HTTP_200_OK)
def list_dataset_imports(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> list[dict[str, Any]]:
    owner_id = resolve_owner_id(current_user)
    return [service.import_to_dict(run) for run in service.list_imports(owner_id=owner_id, limit=limit)]


@router.get("/imports/{import_id}", response_model=DatasetImportResponse, status_code=status.HTTP_200_OK)
def get_dataset_import(
    import_id: str,
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> dict[str, Any]:
    from backend.core.exceptions import ResourceNotFoundError

    owner_id = resolve_owner_id(current_user)
    run = service.get_import(import_id, owner_id=owner_id)
    if run is None:
        raise ResourceNotFoundError(f"Dataset import '{import_id}' not found.")
    return service.import_to_dict(run)
