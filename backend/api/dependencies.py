"""
FastAPI dependency providers for CloudSync.

Provides:

- Database session dependency
- Authenticated user dependency
- Administrator dependency
"""

from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
)
from backend.core.security import decode_access_token
from backend.database.connection import get_session
from backend.database.crud import get_user_by_username
from backend.database.models import User

settings = get_settings()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_PREFIX}/auth/token"
)


def get_db() -> Generator[Session, None, None]:
    """
    Provide a database session for each request.
    """
    db = get_session()

    try:
        yield db
    finally:
        db.close()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    Return the authenticated user associated with the JWT.
    """
    try:
        payload = decode_access_token(token)

        username = payload.get("sub")

        if username is None:
            raise AuthenticationError(
                "Invalid authentication credentials."
            )

    except JWTError:
        raise AuthenticationError(
            "Invalid or expired access token."
        )

    user = get_user_by_username(
        db,
        username=username,
    )

    if user is None:
        raise AuthenticationError(
            "User not found."
        )

    return user


def get_current_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Ensure the authenticated user has administrator privileges.
    """
    if current_user.role != "admin":
        raise AuthorizationError(
            "Administrator privileges required."
        )

    return current_user