"""Authentication and registration HTTP API layer for DefenSync."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Form, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.api.dependencies import get_db, get_current_admin, get_current_user
from backend.core.exceptions import AuthenticationError, ResourceNotFoundError, ValidationException
from backend.database import crud
from backend.database.models import User
from backend.services.auth_service import AuthService
from backend.services.mfa.otp_service import OTPService
from backend.services.password_reset_service import PASSWORD_RESETS, PasswordResetService, PasswordResetStore
from backend.services.registration_service import PENDING_REGISTRATIONS, PendingRegistrationStore, RegistrationService

router = APIRouter(tags=["Authentication"])


# =============================================================================
# Request/Response Schemas (Pydantic v2)
# =============================================================================

class RegisterRequest(BaseModel):
    """Schema for user registration request."""

    username: str = Field(..., min_length=3, max_length=50, description="Unique username (display identity)")
    email: str = Field(..., min_length=3, max_length=100, description="Unique email address (used to sign in)")
    password: str = Field(..., min_length=8, description="User password")


class LoginRequest(BaseModel):
    """Schema for user authentication request."""

    email: str = Field(..., description="Registered email")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    """Schema for JWT token response."""

    access_token: str
    token_type: str = "bearer"


class OTPChannel(BaseModel):
    channel: str
    destination: str


class OTPChallengeResponse(BaseModel):
    """Password accepted; the second factor is still required. Contains no token and no code."""

    otp_required: bool = True
    challenge_id: str
    delivery: str | None = None
    destination: str | None = None
    channels: list[OTPChannel] = []
    expires_in: int | None = None
    resend_available_in: int = 0
    attempts_remaining: int
    sends_remaining: int


class OTPSendRequest(BaseModel):
    challenge_id: str = Field(..., min_length=16, max_length=128)
    channel: Literal["EMAIL", "SMS"] | None = None


class OTPVerifyRequest(BaseModel):
    challenge_id: str = Field(..., min_length=16, max_length=128)
    otp: str = Field(..., min_length=1, max_length=12)


class PasswordResetRequestBody(BaseModel):
    email: str = Field(..., min_length=3, max_length=100)


class PasswordResetResendBody(BaseModel):
    challenge_id: str = Field(..., min_length=16, max_length=128)


class PasswordResetCompleteBody(BaseModel):
    reset_token: str = Field(..., min_length=16, max_length=128)
    new_password: str = Field(..., max_length=256)
    confirm_password: str = Field(..., max_length=256)


class PasswordResetChallengeResponse(BaseModel):
    """Identical for registered and unknown emails. Contains no code, no destination and no account details."""

    message: str
    challenge_id: str
    expires_in: int | None = None
    resend_available_in: int = 0
    attempts_remaining: int
    sends_remaining: int


class PasswordResetTokenResponse(BaseModel):
    """Authorizes setting a new password only. It is not an access token and signs nobody in."""

    reset_token: str
    expires_in: int


class PasswordResetCompleteResponse(BaseModel):
    success: bool
    message: str


def get_otp_service() -> OTPService:
    return OTPService()


def get_pending_registrations() -> PendingRegistrationStore:
    return PENDING_REGISTRATIONS


def get_password_resets() -> PasswordResetStore:
    return PASSWORD_RESETS


class UserMeResponse(BaseModel):
    """Schema for returning the currently authenticated user's profile."""

    id: str
    name: str
    username: str
    email: str
    role: str
    account_id: str | None = None
    device_limit: int = 3
    created_at: datetime


class UserResponse(BaseModel):
    id: str
    name: str | None = None
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "/register",
    response_model=OTPChallengeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start registration: validate, then email a verification code (no account exists yet)",
)
def register_user(
    request_data: RegisterRequest,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    pending: PendingRegistrationStore = Depends(get_pending_registrations),
) -> OTPChallengeResponse:
    """The account is created by /register/verify; a registration whose code cannot be sent leaves nothing behind."""
    view = RegistrationService(db, otp_service, store=pending).start(
        username=request_data.username,
        email=request_data.email,
        password=request_data.password,
    )
    return OTPChallengeResponse(**view)


@router.post(
    "/register/verify",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Verify the registration code: creates the analyst account and returns its access token",
)
def verify_registration(
    request_data: OTPVerifyRequest,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    pending: PendingRegistrationStore = Depends(get_pending_registrations),
) -> TokenResponse:
    user = RegistrationService(db, otp_service, store=pending).verify(request_data.challenge_id, request_data.otp)
    return TokenResponse(access_token=AuthService(db).create_token(user), token_type="bearer")


@router.post(
    "/token",
    response_model=OTPChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify email + password and start the OTP challenge (no token is issued here)",
)
def login(
    email: str = Form(..., max_length=100),
    password: str = Form(...),
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
) -> OTPChallengeResponse:
    """Check the password for the registered email, then require a one-time code before any token exists."""

    user = AuthService(db).authenticate_user(email=email, password=password)
    return OTPChallengeResponse(**otp_service.start(user))


@router.post(
    "/otp/send",
    response_model=OTPChallengeResponse,
    status_code=status.HTTP_200_OK,
    summary="Send or resend the one-time code for a pending challenge",
)
def send_otp(
    request_data: OTPSendRequest,
    otp_service: OTPService = Depends(get_otp_service),
) -> OTPChallengeResponse:
    return OTPChallengeResponse(**otp_service.send(request_data.challenge_id, request_data.channel))


@router.post(
    "/otp/verify",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify the one-time code and obtain the JWT access token",
)
def verify_otp(
    request_data: OTPVerifyRequest,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
) -> TokenResponse:
    user_id = otp_service.verify(request_data.challenge_id, request_data.otp)
    user = db.get(User, user_id)
    if user is None:
        raise AuthenticationError("Invalid email or password.")
    return TokenResponse(access_token=AuthService(db).create_token(user), token_type="bearer")


@router.post(
    "/password-reset/request",
    response_model=PasswordResetChallengeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a password reset code (same answer whether or not the email is registered)",
)
def request_password_reset(
    request_data: PasswordResetRequestBody,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    resets: PasswordResetStore = Depends(get_password_resets),
) -> PasswordResetChallengeResponse:
    service = PasswordResetService(db, otp_service, store=resets, defer=background_tasks.add_task)
    return PasswordResetChallengeResponse(**service.request(request_data.email))


@router.post(
    "/password-reset/resend",
    response_model=PasswordResetChallengeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Resend the password reset code (120-second cooldown; replaces the previous code)",
)
def resend_password_reset(
    request_data: PasswordResetResendBody,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    resets: PasswordResetStore = Depends(get_password_resets),
) -> PasswordResetChallengeResponse:
    service = PasswordResetService(db, otp_service, store=resets, defer=background_tasks.add_task)
    return PasswordResetChallengeResponse(**service.resend(request_data.challenge_id))


@router.post(
    "/password-reset/verify",
    response_model=PasswordResetTokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify the password reset code; returns a short-lived reset token, never an access token",
)
def verify_password_reset(
    request_data: OTPVerifyRequest,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    resets: PasswordResetStore = Depends(get_password_resets),
) -> PasswordResetTokenResponse:
    service = PasswordResetService(db, otp_service, store=resets)
    return PasswordResetTokenResponse(**service.verify(request_data.challenge_id, request_data.otp))


@router.post(
    "/password-reset/complete",
    response_model=PasswordResetCompleteResponse,
    status_code=status.HTTP_200_OK,
    summary="Set a new password with the reset token; the user then signs in normally (with login MFA)",
)
def complete_password_reset(
    request_data: PasswordResetCompleteBody,
    db: Session = Depends(get_db),
    otp_service: OTPService = Depends(get_otp_service),
    resets: PasswordResetStore = Depends(get_password_resets),
) -> PasswordResetCompleteResponse:
    service = PasswordResetService(db, otp_service, store=resets)
    return PasswordResetCompleteResponse(
        **service.complete(request_data.reset_token, request_data.new_password, request_data.confirm_password),
    )


@router.get(
    "/me",
    response_model=UserMeResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve current user profile",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserMeResponse:
    """Retrieve details of the currently authenticated active user session."""
    return UserMeResponse(
        id=current_user.id,
        name=current_user.name or current_user.username,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role.upper(),
        account_id=getattr(current_user, "account_id", None),
        device_limit=int(getattr(current_user, "device_limit", None) or 3),
        created_at=current_user.created_at,
    )


@router.get("/users", response_model=list[UserResponse], summary="List users (Admin Only)")
def list_users(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> list[UserResponse]:
    del current_admin
    return [
        UserResponse(
            id=user.id,
            name=user.name or user.username,
            username=user.username,
            email=user.email,
            role=user.role.upper(),
            created_at=user.created_at,
        )
        for user in crud.list_users(db)
    ]


@router.delete("/users/{user_id}", summary="Delete user (Admin Only)")
def delete_user(
    user_id: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if user_id == current_admin.id:
        raise ValidationException("You cannot delete your own account.")
    deleted = crud.delete_user(db, user_id)
    if not deleted:
        raise ResourceNotFoundError(f"User '{user_id}' not found.")
    db.commit()
    return {"success": True, "message": "User deleted."}
