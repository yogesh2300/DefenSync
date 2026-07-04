"""
CloudSync Security Utilities.

Provides:
- Password hashing and verification
- JWT access token generation
- JWT access token validation

This module centralizes all authentication-related security logic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from backend.core.config import get_settings

# ==============================================================================
# Password Hashing Configuration
# ==============================================================================

PASSWORD_CONTEXT = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# ==============================================================================
# Password Utilities
# ==============================================================================

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Args:
        password: Plaintext password.

    Returns:
        Secure bcrypt hash.
    """
    return PASSWORD_CONTEXT.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against its bcrypt hash.

    Args:
        plain_password: User supplied password.
        hashed_password: Stored bcrypt hash.

    Returns:
        True if password matches.
    """
    return PASSWORD_CONTEXT.verify(
        plain_password,
        hashed_password,
    )


# ==============================================================================
# JWT Utilities
# ==============================================================================

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Payload to encode.
        expires_delta: Optional custom expiration time.

    Returns:
        Encoded JWT token.
    """
    settings = get_settings()

    now = datetime.now(timezone.utc)

    expire = (
        now + expires_delta
        if expires_delta
        else now + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload = data.copy()

    payload.update(
        {
            "iat": now,
            "exp": expire,
        }
    )

    encoded_jwt = jwt.encode(
        payload,
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.ALGORITHM,
    )

    return encoded_jwt


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Args:
        token: Encoded JWT token.

    Returns:
        Decoded JWT payload.

    Raises:
        JWTError:
            If the token is invalid, malformed,
            or has expired.
    """
    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY.get_secret_value(),
            algorithms=[settings.ALGORITHM],
        )

        return payload

    except JWTError:
        raise