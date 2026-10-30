"""Authenticated public dataset discovery and import APIs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_user, get_db, resolve_owner_id
from backend.services.global_intelligence_service import GlobalIntelligenceService
from backend.core.exceptions import ResourceNotFoundError, ValidationException
from backend.database.models import User
from backend.database.scope import resolve_account_id
from backend.core.config import get_settings
from backend.parser.bgl_parser import DATASET_NAME as BGL_DATASET_NAME
from backend.parser.hdfs_parser import DATASET_NAME as HDFS_DATASET_NAME
from backend.parser.openstack_parser import DATASET_NAME
from backend.services.datasets.azure_import_service import AzureActivityLogImportService, AzureImportPathError
from backend.services.datasets.bgl_import_service import BGLImportService
from backend.services.datasets.hdfs_import_service import HDFSImportService
from backend.services.datasets.log_dataset_discovery import LogDatasetDiscoveryService
from backend.services.datasets.openstack_discovery import OpenStackDiscoveryService
from backend.services.datasets.openstack_import_service import OpenStackImportService

router = APIRouter()


class OpenStackImportRequest(BaseModel):
    file_id: str = Field(..., min_length=8, max_length=128)
    max_records: int | None = Field(None, ge=1)
    batch_size: int | None = Field(None, ge=1)
    allow_reimport: bool = False
    line_offset: int = Field(0, ge=0)


class LogDatasetImportRequest(BaseModel):
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


def get_bgl_service(db: Session = Depends(get_db)) -> BGLImportService:
    return BGLImportService(db)


def get_hdfs_service(db: Session = Depends(get_db)) -> HDFSImportService:
    return HDFSImportService(db)


def _bgl_discovery() -> LogDatasetDiscoveryService:
    return LogDatasetDiscoveryService(relative_dir=get_settings().BGL_DATASET_PATH, dataset_name=BGL_DATASET_NAME)


def _hdfs_discovery() -> LogDatasetDiscoveryService:
    return LogDatasetDiscoveryService(relative_dir=get_settings().HDFS_DATASET_PATH, dataset_name=HDFS_DATASET_NAME)


@router.get("/status", status_code=status.HTTP_200_OK)
def dataset_hub_status(
    current_user: User = Depends(get_current_user),
    openstack: OpenStackImportService = Depends(get_import_service),
    bgl: BGLImportService = Depends(get_bgl_service),
    hdfs: HDFSImportService = Depends(get_hdfs_service),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    global_counts = GlobalIntelligenceService(openstack._session).summary()
    return {
        "openstack": {**OpenStackDiscoveryService().status(), "summary": openstack.summary(owner_id=owner_id), "public_openstack_events": global_counts["public_openstack_events"], "synthetic_openstack_demo_events": global_counts["synthetic_openstack_demo_events"]},
        "bgl": {**_bgl_discovery().status(), "summary": bgl.summary(owner_id=owner_id), "classification": "HPC supercomputer log (not cloud control-plane)", "bgl_hpc_events": global_counts["bgl_hpc_events"]},
        "hdfs": {**_hdfs_discovery().status(), "summary": hdfs.summary(owner_id=owner_id), "classification": "Private-cloud Hadoop DFS log", "hdfs_events": global_counts["hdfs_events"]},
        "azure": {
            "available": False,
            "live_monitoring": False,
            "file_import": True,
            "note": "Live Azure integration is not implemented. Offline Azure export files can be imported from DATASET_ROOT/Azure.",
        },
        "aws": {"available": False, "note": "AWS is not implemented."},
        "global_intelligence": global_counts,
    }


@router.get("/openstack/status", status_code=status.HTTP_200_OK)
def openstack_status(
    current_user: User = Depends(get_current_user),
    service: OpenStackImportService = Depends(get_import_service),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    discovery = OpenStackDiscoveryService()
    summary = service.summary(owner_id=owner_id)
    global_counts = GlobalIntelligenceService(service._session).summary()
    return {
        **discovery.status(),
        "summary": {**summary, "public_openstack_events": global_counts["public_openstack_events"], "synthetic_openstack_demo_events": global_counts["synthetic_openstack_demo_events"]},
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


@router.get("/bgl/status", status_code=status.HTTP_200_OK)
def bgl_status(
    current_user: User = Depends(get_current_user),
    service: BGLImportService = Depends(get_bgl_service),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return {
        **_bgl_discovery().status(),
        "summary": service.summary(owner_id=owner_id),
        "classification": "HPC supercomputer log (not cloud control-plane)",
        "data_origin": "PUBLIC_DATASET",
        "type": "HPC",
        "scope": "GLOBAL",
    }


@router.get("/bgl/files", status_code=status.HTTP_200_OK)
def bgl_files(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    del current_user
    discovery = _bgl_discovery()
    return {"dataset": BGL_DATASET_NAME, "files": [item.to_dict() for item in discovery.discover_files()]}


@router.post("/bgl/import", response_model=DatasetImportResponse, status_code=status.HTTP_201_CREATED)
def import_bgl_file(
    request: LogDatasetImportRequest,
    current_user: User = Depends(get_current_user),
    service: BGLImportService = Depends(get_bgl_service),
) -> dict[str, Any]:
    return service.import_and_prepare(
        file_id=request.file_id,
        owner_id=current_user.id,
        max_records=request.max_records,
        batch_size=request.batch_size,
        allow_reimport=request.allow_reimport,
        line_offset=request.line_offset,
    )


@router.get("/hdfs/status", status_code=status.HTTP_200_OK)
def hdfs_status(
    current_user: User = Depends(get_current_user),
    service: HDFSImportService = Depends(get_hdfs_service),
) -> dict[str, Any]:
    owner_id = resolve_owner_id(current_user)
    return {
        **_hdfs_discovery().status(),
        "summary": service.summary(owner_id=owner_id),
        "classification": "Private-cloud Hadoop DFS log",
        "data_origin": "PUBLIC_DATASET",
        "type": "CLOUD",
        "scope": "GLOBAL",
    }


@router.get("/hdfs/files", status_code=status.HTTP_200_OK)
def hdfs_files(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    del current_user
    discovery = _hdfs_discovery()
    return {"dataset": HDFS_DATASET_NAME, "files": [item.to_dict() for item in discovery.discover_files()]}


@router.post("/hdfs/import", response_model=DatasetImportResponse, status_code=status.HTTP_201_CREATED)
def import_hdfs_file(
    request: LogDatasetImportRequest,
    current_user: User = Depends(get_current_user),
    service: HDFSImportService = Depends(get_hdfs_service),
) -> dict[str, Any]:
    return service.import_and_prepare(
        file_id=request.file_id,
        owner_id=current_user.id,
        max_records=request.max_records,
        batch_size=request.batch_size,
        allow_reimport=request.allow_reimport,
        line_offset=request.line_offset,
    )


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


class AzureImportRequest(BaseModel):
    path: str = Field(
        ...,
        min_length=3,
        max_length=500,
        description="Path of an exported Azure Activity Log / sign-in JSON or CSV file, relative to DATASET_ROOT/Azure",
    )
    max_records: int = Field(2000, ge=1, le=10000)
    allow_reimport: bool = False


@router.post("/azure/import", status_code=status.HTTP_201_CREATED)
def import_azure_activity_log(
    request: AzureImportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Ingest an exported Azure log file from DATASET_ROOT/Azure. This is not live Azure monitoring.

    Rows are PRIVATE cloud telemetry owned by the caller and scoped to the caller's
    account (ADMIN is platform-level, so ADMIN imports carry no account_id).
    """
    try:
        return AzureActivityLogImportService(db).import_file(
            request.path,
            owner_id=current_user.id,
            account_id=resolve_account_id(current_user),
            max_records=request.max_records,
            allow_reimport=request.allow_reimport,
        )
    except AzureImportPathError as exc:
        raise ValidationException(str(exc)) from exc
    except FileNotFoundError as exc:
        raise ValidationException(f"Azure export file not found in the Azure dataset directory: {exc}") from exc

