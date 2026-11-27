"""Trusted browser device management API (per-user limits, challenge proof, revoke)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_current_admin, get_current_user, get_db
from backend.database.models import User
from backend.services.auth_service import AuthService
from backend.services.trusted_device_service import TrustedDeviceService


def _with_device_bound_token(db, user: User, payload: dict) -> dict:
    """Re-issue an access JWT bound to the verified device so revoke can kill this session only."""
    device_id = payload.get("id")
    if device_id and payload.get("status") == "VERIFIED":
        payload = {
            **payload,
            "access_token": AuthService(db).create_token(user, device_id=device_id),
            "token_type": "bearer",
        }
    return payload

router = APIRouter(tags=["Trusted Devices"])


class DevicePublicKey(BaseModel):
    kty: str
    crv: str
    x: str
    y: str
    ext: bool | None = True


class BeginEnrollRequest(BaseModel):
    public_key_jwk: DevicePublicKey
    display_name: str | None = Field(default=None, max_length=120)


class CompleteProofRequest(BaseModel):
    device_id: str = Field(..., min_length=8, max_length=64)
    challenge_id: str = Field(..., min_length=8, max_length=64)
    nonce: str = Field(..., min_length=16, max_length=128)
    signature: str = Field(..., min_length=16, max_length=512)


class RenameDeviceRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=120)


class BeginVerifyRequest(BaseModel):
    device_id: str = Field(..., min_length=8, max_length=64)


class AdminDeviceLimitRequest(BaseModel):
    device_limit: int = Field(..., ge=0, le=50)


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    forwarded = request.headers.get("x-forwarded-for")
    source_ip = (forwarded.split(",")[0].strip() if forwarded else None) or (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")
    return source_ip, user_agent


@router.get("", summary="List the current user's trusted devices and per-user limit")
def list_my_devices(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).summary_for(current_user)


@router.post(
    "/enroll/begin",
    status_code=status.HTTP_200_OK,
    summary="Start enrollment after MFA: stores public key only and issues a one-time challenge",
)
def begin_enroll(
    body: BeginEnrollRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    source_ip, user_agent = _client_meta(request)
    return TrustedDeviceService(db).begin_enrollment(
        current_user,
        public_key_jwk=body.public_key_jwk.model_dump(),
        display_name=body.display_name,
        source_ip=source_ip,
        user_agent=user_agent,
    )


@router.post(
    "/enroll/complete",
    status_code=status.HTTP_200_OK,
    summary="Complete enrollment by signing the challenge with the device private key",
)
def complete_enroll(
    body: CompleteProofRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    source_ip, user_agent = _client_meta(request)
    result = TrustedDeviceService(db).complete_enrollment(
        current_user,
        device_id=body.device_id,
        challenge_id=body.challenge_id,
        nonce=body.nonce,
        signature=body.signature,
        source_ip=source_ip,
        user_agent=user_agent,
    )
    return _with_device_bound_token(db, current_user, result)


@router.post("/verify/begin", summary="Issue a return-device challenge for an already trusted device")
def begin_verify(
    body: BeginVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).begin_verify(current_user, device_id=body.device_id)


@router.post("/verify/complete", summary="Prove possession of a trusted device without consuming another slot")
def complete_verify(
    body: CompleteProofRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    source_ip, user_agent = _client_meta(request)
    result = TrustedDeviceService(db).complete_verify(
        current_user,
        device_id=body.device_id,
        challenge_id=body.challenge_id,
        nonce=body.nonce,
        signature=body.signature,
        source_ip=source_ip,
        user_agent=user_agent,
    )
    return _with_device_bound_token(db, current_user, result)


@router.get("/admin/users/{user_id}", summary="Admin: list another user's trusted devices")
def admin_list_devices(
    user_id: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).admin_list_for_user(actor=current_admin, target_user_id=user_id)


@router.put("/admin/users/{user_id}/limit", summary="Admin: set another user's per-user device limit")
def admin_set_limit(
    user_id: str,
    body: AdminDeviceLimitRequest,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).set_device_limit(
        actor=current_admin,
        target_user_id=user_id,
        device_limit=body.device_limit,
    )


@router.patch("/{device_id}", summary="Rename one of the current user's trusted devices")
def rename_device(
    device_id: str,
    body: RenameDeviceRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).rename(current_user, device_id=device_id, display_name=body.display_name)


@router.delete("/{device_id}", summary="Revoke a trusted device and free its slot")
def revoke_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return TrustedDeviceService(db).revoke(current_user, device_id=device_id)
