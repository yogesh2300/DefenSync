"""Authentication and registration HTTP API layer for CloudSync."""

from datetime import datetime
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm

from backend.api.dependencies import get_db, get_current_user
from backend.database.models import User
from backend.services.auth_service import AuthService

router = APIRouter(tags=["Authentication"])


# =============================================================================
# Request/Response Schemas (Pydantic v2)
# =============================================================================

class RegisterRequest(BaseModel):
    """Schema for user registration request."""

    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., description="Unique email address")
    password: str = Field(..., min_length=8, description="User password")


class RegisterResponse(BaseModel):
    """Schema for user registration response."""

    success: bool = True
    message: str = "User registered successfully."
    username: str


class LoginRequest(BaseModel):
    """Schema for user authentication request."""

    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponse(BaseModel):
    """Schema for JWT token response."""

    access_token: str
    token_type: str = "bearer"


class UserMeResponse(BaseModel):
    """Schema for returning the currently authenticated user's profile."""

    username: str
    email: str
    role: str
    created_at: datetime


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
def register_user(
    request_data: RegisterRequest,
    db: Session = Depends(get_db),
) -> RegisterResponse:
    """Create a new user account with default analyst privileges."""
    auth_service = AuthService(db)
    user = auth_service.register_user(
        username=request_data.username,
        email=request_data.email,
        password=request_data.password,
    )
    return RegisterResponse(username=user.username)


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and obtain JWT token",
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate credentials and generate a signed access token."""

    auth_service = AuthService(db)

    user = auth_service.authenticate_user(
        username=form_data.username,
        password=form_data.password,
    )

    token = auth_service.create_token(user)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
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
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        created_at=current_user.created_at,
    )
