"""
Authentication business logic service for CloudSync.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.core.exceptions import (
    AuthenticationError,
    DatabaseException,
    ValidationException,
)
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


class AuthService:
    """
    Business logic for authentication and user registration.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "analyst",
    ) -> User:

        username = username.strip()
        email = email.strip().lower()

        if not username:
            raise ValidationException("Username cannot be empty.")

        if not email:
            raise ValidationException("Email cannot be empty.")

        if not password:
            raise ValidationException("Password cannot be empty.")

        if role not in {"admin", "analyst"}:
            raise ValidationException("Invalid user role.")

        if get_user_by_username(self.db, username=username):
            raise ValidationException("Username already exists.")

        if get_user_by_email(self.db, email=email):
            raise ValidationException("Email already exists.")

        password_hash = hash_password(password)

        try:
            return create_user(
                self.db,
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                )
        except Exception as exc:
            import traceback
            print("\n================ REAL DATABASE ERROR ================\n")
            traceback.print_exc()
            print("\n=====================================================\n")
            raise

    def authenticate_user(
        self,
        username: str,
        password: str,
    ) -> User:

        user = get_user_by_username(
            self.db,
            username=username,
        )

        if user is None:
            raise AuthenticationError(
                "Invalid username or password."
            )

        if not verify_password(
            password,
            user.password_hash,
        ):
            raise AuthenticationError(
                "Invalid username or password."
            )

        return user

    def create_token(
        self,
        user: User,
    ) -> str:

        return create_access_token(
            {
                "sub": user.username,
                "role": user.role,
            }
        )