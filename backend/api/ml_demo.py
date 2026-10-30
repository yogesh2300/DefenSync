"""REST API for the dataset-only ML demonstrations.

OpenStack Isolation Forest: public OpenStack cloud-infrastructure dataset, not Azure, not live.
Behavioral Random Forest: synthetic generated sessions, not real telemetry.
Neither endpoint reads or writes database telemetry or the live detection models.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from backend.api.dependencies import get_current_user
from backend.core.exceptions import ResourceNotFoundError, ValidationException
from backend.core.logging import get_logger
from backend.database.models import User
from backend.services.ml_demo_service import BehavioralRfDemoService, DemoDatasetMissing, OpenStackDemoService

logger = get_logger(__name__)
router = APIRouter()


class BehavioralSession(BaseModel):
    typing_speed_cpm: float = Field(..., ge=0)
    command_rate_per_minute: float = Field(..., ge=0)
    command_error_rate: float = Field(..., ge=0, le=1)
    idle_time_seconds: float = Field(..., ge=0)
    repeated_command_ratio: float = Field(..., ge=0, le=1)
    session_duration_minutes: float = Field(..., ge=0)
    login_hour: int = Field(..., ge=0, le=23)

    model_config = {"extra": "forbid"}


def get_openstack_demo() -> OpenStackDemoService:
    return OpenStackDemoService()


def get_behavioral_demo() -> BehavioralRfDemoService:
    return BehavioralRfDemoService()


@router.get("/openstack", summary="OpenStack Isolation Forest demonstration results")
def openstack_report(
    current_user: User = Depends(get_current_user),
    service: OpenStackDemoService = Depends(get_openstack_demo),
) -> Any:
    return service.report()


@router.post("/openstack/train", summary="Train the OpenStack Isolation Forest demonstration")
def openstack_train(
    current_user: User = Depends(get_current_user),
    service: OpenStackDemoService = Depends(get_openstack_demo),
) -> Any:
    logger.info("API request by %s: POST /ml-demo/openstack/train", current_user.username)
    try:
        return service.train()
    except DemoDatasetMissing as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    except ValueError as exc:
        raise ValidationException(str(exc)) from exc


@router.get("/behavioral", summary="Synthetic behavioral Random Forest demonstration results")
def behavioral_report(
    current_user: User = Depends(get_current_user),
    service: BehavioralRfDemoService = Depends(get_behavioral_demo),
) -> Any:
    return service.report()


@router.post("/behavioral/train", summary="Train the synthetic behavioral Random Forest demonstration")
def behavioral_train(
    current_user: User = Depends(get_current_user),
    service: BehavioralRfDemoService = Depends(get_behavioral_demo),
) -> Any:
    logger.info("API request by %s: POST /ml-demo/behavioral/train", current_user.username)
    try:
        return service.train()
    except DemoDatasetMissing as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    except ValueError as exc:
        raise ValidationException(str(exc)) from exc


@router.post("/behavioral/predict", summary="Closest synthetic behavioral pattern for one session")
def behavioral_predict(
    session: BehavioralSession,
    current_user: User = Depends(get_current_user),
    service: BehavioralRfDemoService = Depends(get_behavioral_demo),
) -> Any:
    try:
        return service.predict(session.model_dump())
    except LookupError as exc:
        raise ResourceNotFoundError(str(exc)) from exc
    except ValueError as exc:
        raise ValidationException(str(exc)) from exc
