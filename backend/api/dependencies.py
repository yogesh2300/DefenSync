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
from backend.database.models import User

# OAuth2 scheme for extracting bearer tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/token")


def get_db() -> Generator[Session, None, None]:
    """Dependency to provide a thread-safe database session."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()


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

    user = get_user_by_username(db, username=username)
    if not user:
        raise AuthenticationError("User not found.")
        
    return user


def get_current_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """Dependency to ensure the current authenticated user has administrative privileges."""
    if getattr(current_user, "role", "").upper() != "ADMIN":
        raise AuthorizationError("Administrative privileges required.")
        
    return current_user


def resolve_owner_id(current_user: User) -> str | None:
    """Return owner scope for non-admin users."""
    return None if current_user.role.upper() == "ADMIN" else current_user.id


def validate_server_scope(
    server_id: str | None,
    current_user: User,
    db: Session,
) -> str | None:
    """Ensure the requested server belongs to the authenticated user."""
    if not server_id:
        return None
    server = server_crud.get_server(db, server_id)
    if server is None:
        raise ResourceNotFoundError(f"Server '{server_id}' not found.")
    if current_user.role.upper() != "ADMIN" and (server.owner_id or server.created_by) != current_user.id:
        raise AuthorizationError("You do not have access to this server.")
    return server_id