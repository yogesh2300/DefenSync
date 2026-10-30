"""FastAPI dependencies for database sessions and authentication."""

from typing import Generator

from fastapi import Depends, Query
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from backend.core.exceptions import AuthenticationError, AuthorizationError, ResourceNotFoundError
from backend.core.security import decode_access_token
from backend.database import server_crud
from backend.database.connection import get_session
from backend.database.crud import get_user_by_username
from backend.database.models import TrustedDevice, User
from backend.services.auth_service import MFA_AMR
from backend.database.scope import (
    event_visibility_clause,
    is_admin,
    resolve_account_id,
    user_can_access_server,
)

# OAuth2 scheme for extracting bearer tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/token")


def get_db() -> Generator[Session, None, None]:
    """Dependency to provide a thread-safe database session."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()


def assert_device_bound_token_active(db: Session, user: User, device_id: str | None) -> None:
    """If the JWT carries a device_id, require that trusted device to still be VERIFIED for this user.

    Tokens without device_id are MFA-only sessions and are not selectively revoked by device.
    """
    if not device_id:
        return
    device = db.get(TrustedDevice, device_id)
    if (
        device is None
        or device.user_id != user.id
        or device.status != "VERIFIED"
    ):
        raise AuthenticationError("Trusted device session is no longer valid.")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to authenticate the current user using JWT."""
    try:
        payload = decode_access_token(token)
        username: str | None = payload.get("sub")
        if not username:
            raise AuthenticationError("Could not validate credentials, subject missing.")
    except JWTError as e:
        raise AuthenticationError(f"Could not validate credentials: {str(e)}")
    if not set(MFA_AMR).issubset(payload.get("amr") or []):
        raise AuthenticationError("Two-factor verification required.")

    user = get_user_by_username(db, username=username)
    if not user:
        raise AuthenticationError("User not found.")

    assert_device_bound_token_active(db, user, payload.get("device_id"))
    return user


def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Dependency to ensure the current authenticated user has administrative privileges."""
    if getattr(current_user, "role", "").upper() != "ADMIN":
        raise AuthorizationError("Administrative privileges required.")
        
    return current_user


def resolve_owner_id(current_user: User) -> str | None:
    """Collector identity for writes and legacy owner filters. ADMIN is unscoped."""
    return None if is_admin(current_user) else current_user.id


def validate_server_scope(
    server_id: str | None,
    current_user: User,
    db: Session,
) -> str | None:
    """Ensure the requested server belongs to the authenticated account/user."""
    if not server_id:
        return None
    server = server_crud.get_server(db, server_id)
    if server is None:
        raise ResourceNotFoundError(f"Server '{server_id}' not found.")
    if not user_can_access_server(current_user, server):
        raise AuthorizationError("You do not have access to this server.")
    return server_id


def visibility_for(
    current_user: User,
    *,
    scope: str = "private",
    selected_account_id: str | None = None,
):
    """Event visibility clause for PRIVATE / GLOBAL / BOTH."""
    account_id = selected_account_id if is_admin(current_user) else resolve_account_id(current_user)
    return event_visibility_clause(scope=scope, user=current_user, selected_account_id=account_id)