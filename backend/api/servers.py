"""REST API for DefenSync server management."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field, computed_field, model_validator
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_admin, get_current_user, get_db
from backend.core.exceptions import AuthorizationError
from backend.collector.log_sources import LOG_SOURCE_CATALOG
from backend.core.logging import get_logger
from backend.database.models import Server, User
from backend.services.detection_service import DetectionService
from backend.services.event_service import EventService
from backend.services.server_service import ServerService

logger = get_logger(__name__)
router = APIRouter()

AuthType = Literal["password", "ssh_key", "private_key"]
ServerStatus = Literal["active", "inactive", "online", "offline", "error"]


class ServerCreateRequest(BaseModel):
    server_name: str = Field(..., min_length=1, max_length=100)
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(22, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=100)
    authentication_type: AuthType = "password"
    password: str | None = Field(None, min_length=1)
    private_key: str | None = Field(None, min_length=10)
    operating_system: str | None = "linux"
    environment: Literal["production", "development", "testing"] = "production"
    description: str | None = None

    @model_validator(mode="after")
    def validate_credentials(self) -> "ServerCreateRequest":
        auth = self.authentication_type.lower()
        if auth in {"ssh_key", "private_key"} and not self.private_key:
            raise ValueError("private_key is required for ssh_key authentication.")
        if auth == "password" and not self.password:
            raise ValueError("password is required for password authentication.")
        return self


class ServerUpdateRequest(BaseModel):
    server_name: str | None = Field(None, min_length=1, max_length=100)
    host: str | None = None
    port: int | None = Field(None, ge=1, le=65535)
    username: str | None = None
    authentication_type: AuthType | None = None
    password: str | None = Field(None, min_length=1)
    private_key: str | None = Field(None, min_length=10)
    operating_system: str | None = None
    environment: Literal["production", "development", "testing"] | None = None
    description: str | None = None
    status: ServerStatus | None = None


class ServerTestRequest(BaseModel):
    """Test SSH connection before saving server credentials."""

    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(22, ge=1, le=65535)
    username: str = Field(..., min_length=1, max_length=100)
    authentication_type: AuthType = "password"
    password: str | None = None
    private_key: str | None = None

    @model_validator(mode="after")
    def validate_credentials(self) -> "ServerTestRequest":
        auth = self.authentication_type.lower()
        if auth in {"ssh_key", "private_key"} and not self.private_key:
            raise ValueError("private_key is required for ssh_key authentication.")
        if auth == "password" and not self.password:
            raise ValueError("password is required for password authentication.")
        return self


class ServerResponse(BaseModel):
    id: str
    server_name: str
    host: str
    port: int
    username: str
    authentication_type: str
    operating_system: str | None
    environment: str = "production"
    description: str | None
    status: str
    connection_state: str | None = None
    last_seen: datetime | None = None
    last_connected: datetime | None
    last_collection: datetime | None = None
    last_collection_status: str | None = None
    risk_score: int = 0
    high_risk_count: int = 0
    owner_id: str | None = None
    created_by: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resolved_connection_state(self) -> str:
        if self.connection_state:
            return self.connection_state
        if self.status == "online":
            return "Online"
        if self.status == "inactive":
            return "Inactive"
        return "Offline"


class ServerCollectRequest(BaseModel):
    tail_lines: int | None = Field(None, ge=1, le=10000)
    log_sources: list[str] | None = None


def get_server_service(db: Session = Depends(get_db)) -> ServerService:
    return ServerService(db)


def get_event_service(db: Session = Depends(get_db)) -> EventService:
    return EventService(db)


def get_detection_service(db: Session = Depends(get_db)) -> DetectionService:
    return DetectionService(db)


def is_admin(user: User) -> bool:
    return user.role.upper() == "ADMIN"


def require_server_access(service: ServerService, server_id: str, user: User) -> Any:
    server = service.get_server(server_id)
    if not is_admin(user) and (server.owner_id or server.created_by) != user.id:
        raise AuthorizationError("You do not have access to this server.")
    return server


@router.get("", response_model=list[ServerResponse], summary="List servers")
def list_servers(
    active_only: bool = Query(False),
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    owner_id = None if is_admin(current_user) else current_user.id
    return service.list_server_rows(active_only=active_only, owner_id=owner_id)


@router.post("/test", summary="Test SSH before saving server")
def test_connection_preview(
    body: ServerTestRequest,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    del current_user
    return service.test_credentials(
        host=body.host,
        port=body.port,
        username=body.username,
        authentication_type=body.authentication_type,
        password=body.password,
        private_key=body.private_key,
    )


@router.post("/test-connection", summary="Test SSH before saving server")
def test_connection_preview_legacy(
    body: ServerTestRequest,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    return test_connection_preview(body, current_user, service)


@router.post("", response_model=ServerResponse, status_code=status.HTTP_201_CREATED, summary="Register server")
def create_server(
    body: ServerCreateRequest,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    return service.create_server(created_by=current_user.id, **body.model_dump())


@router.get("/sources", summary="Available log source catalog")
def list_log_sources(current_user: User = Depends(get_current_user)) -> Any:
    return [
        {"key": d.key, "label": d.label, "type": d.source_type, "category": d.category}
        for d in LOG_SOURCE_CATALOG.values()
    ]


@router.get("/{server_id}", response_model=ServerResponse, summary="Get server")
def get_server(
    server_id: str,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    return service.server_row(server_id)


@router.put("/{server_id}", response_model=ServerResponse, summary="Update server")
def update_server(
    server_id: str,
    body: ServerUpdateRequest,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    return service.update_server(server_id, body.model_dump(exclude_unset=True))


@router.delete("/{server_id}", status_code=status.HTTP_200_OK, summary="Delete server")
def delete_server(
    server_id: str,
    current_admin: User = Depends(get_current_admin),
    service: ServerService = Depends(get_server_service),
) -> dict[str, Any]:
    require_server_access(service, server_id, current_admin)
    service.delete_server(server_id)
    return {"success": True, "message": "Server deleted."}


@router.post("/{server_id}/test", summary="Test SSH connection")
def test_server(
    server_id: str,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    return service.test_connection(server_id)


@router.post("/{server_id}/connect", summary="Connect and update server status")
def connect_server(
    server_id: str,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    return service.test_connection(server_id)


@router.post("/{server_id}/collect", summary="Collect logs from server")
def collect_server(
    server_id: str,
    body: ServerCollectRequest,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    sources = frozenset(body.log_sources) if body.log_sources else None
    return service.collect_for_server(server_id, tail_lines=body.tail_lines, log_sources=sources)


@router.get("/{server_id}/logs", summary="Logs for a server")
def server_logs(
    server_id: str,
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    events: EventService = Depends(get_event_service),
) -> Any:
    require_server_access(ServerService(events._session), server_id, current_user)
    owner_id = None if is_admin(current_user) else current_user.id
    return events.query_events(limit=limit, server_id=server_id, owner_id=owner_id)


@router.get("/{server_id}/predictions", summary="ML predictions for a server")
def server_predictions(
    server_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    detection: DetectionService = Depends(get_detection_service),
) -> Any:
    require_server_access(ServerService(detection._session), server_id, current_user)
    owner_id = None if is_admin(current_user) else current_user.id
    return detection.get_anomalies(limit=limit, server_id=server_id, owner_id=owner_id)


@router.get("/{server_id}/risk", summary="Risk summary for a server")
def server_risk(
    server_id: str,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
    events: EventService = Depends(get_event_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    stats = service.server_stats(server_id)
    owner_id = None if is_admin(current_user) else current_user.id
    high_risk = events.get_high_risk_events(min_score=70, limit=100, owner_id=owner_id)
    server_high_risk = [
        {
            "event_id": e.event_id,
            "event_type": e.event_type,
            "risk_score": e.risk_score,
            "message": e.message,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in high_risk
        if getattr(e, "server_id", None) == server_id
    ]
    return {
        **stats,
        "high_risk_count": len(server_high_risk),
        "high_risk_events": server_high_risk[:10],
    }


@router.get("/{server_id}/stats", summary="Server overview statistics")
def server_stats(
    server_id: str,
    current_user: User = Depends(get_current_user),
    service: ServerService = Depends(get_server_service),
) -> Any:
    require_server_access(service, server_id, current_user)
    return service.server_stats(server_id)
