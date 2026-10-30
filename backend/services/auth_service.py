"""
Authentication business logic service for DefenSync.
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from backend.core.exceptions import (
    AuthenticationError,
    DatabaseException,
    ValidationException,
)
from backend.core.logging import get_logger
from backend.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from backend.database.crud import (
    create_user,
    get_user_by_email,
    get_user_by_username,
)
from backend.database.models import User

logger = get_logger(__name__)

MFA_AMR = ("pwd", "otp")
MIN_PASSWORD_LENGTH = 8
EMAIL_PATTERN = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")


class AuthService:
    """
    Business logic for authentication and user registration.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    @staticmethod
    def validate_registration(username: str, email: str, password: str) -> tuple[str, str]:
        """Return the normalized (username, email) or raise ValidationException."""

        username = (username or "").strip()
        email = (email or "").strip().lower()

        if not username:
            raise ValidationException("Username cannot be empty.")

        if not email:
            raise ValidationException("Email cannot be empty.")

        if not EMAIL_PATTERN.fullmatch(email):
            raise ValidationException("Enter a valid email address.")

        AuthService.validate_password(password)
        return username, email

    @staticmethod
    def validate_password(password: str) -> None:
        """The password policy shared by registration and password reset."""

        if not password:
            raise ValidationException("Password cannot be empty.")

        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationException(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    def set_password(self, user: User, password: str) -> None:
        """Store a new password hash for an existing user (password reset). Never logs or stores the plaintext."""

        self.validate_password(password)
        digest = hash_password(password)
        try:
            user.password_hash = digest
            user.hashed_password = digest
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            logger.exception("Failed to update password for user %s", user.id)
            raise DatabaseException("Failed to update password.") from exc

    def ensure_available(self, username: str, email: str) -> None:
        """Only existing (verified) users block a username or email; pending registrations never do."""

        if get_user_by_username(self.db, username=username):
            raise ValidationException("Username already exists.")

        if get_user_by_email(self.db, email=email):
            raise ValidationException("Email already exists.")

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "ANALYST",
    ) -> User:
        """Create a user directly (bootstrap/admin tooling). Self-service sign-up goes through RegistrationService."""

        username, email = self.validate_registration(username, email, password)
        return self.create_user_with_hash(username, email, hash_password(password), role=role)

    def create_user_with_hash(
        self,
        username: str,
        email: str,
        password_hash: str,
        role: str = "ANALYST",
    ) -> User:
        role = (role or "").strip().upper()
        if role not in {"ADMIN", "ANALYST"}:
            raise ValidationException("Invalid user role.")

        self.ensure_available(username, email)

        try:
            user = create_user(
                self.db,
                username=username,
                email=email,
                password=password_hash,
                role=role,
            )
            self.db.commit()
            return user
        except Exception as exc:
            self.db.rollback()
            logger.exception("Failed to register user: %s", username)
            raise DatabaseException("Failed to register user.") from exc

    def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> User:
        """Password check by registered email. Username is a display identity, not a login."""

        user = get_user_by_email(
            self.db,
            email=(email or "").strip().lower(),
        )

        if user is None or not verify_password(
            password,
            user.password_hash or user.hashed_password,
        ):
            raise AuthenticationError(
                "Invalid email or password."
            )

        return user

    def create_token(
        self,
        user: User,
        *,
        device_id: str | None = None,
    ) -> str:
        """Issue the application token. Call only after the second factor has been verified.

        Optional ``device_id`` binds the access token to a VERIFIED trusted device so that
        revoking that device invalidates this token on the next authenticated request.
        Tokens without ``device_id`` remain ordinary MFA sessions (not selectively
        device-revocable). There are no refresh tokens in this architecture.
        """

        payload: dict = {
            "sub": user.username,
            "role": user.role,
            "amr": list(MFA_AMR),
        }
        if device_id:
            payload["device_id"] = device_id
        return create_access_token(payload)
