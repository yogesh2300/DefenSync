"""Self-service password reset: emailed code, then a single-use reset token, then a new password.

Requests for unknown emails get a decoy challenge that behaves exactly like a real one but never
sends mail, so responses (including cooldowns and limits) never reveal whether an account exists.
Delivery for real accounts runs after the response, so timing does not reveal it either.
Everything lives in memory next to the OTP challenge store; a backend restart discards it.
Verifying the code never signs anyone in: the user signs in normally, with login MFA, afterwards.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.core.exceptions import MFAError, ValidationException
from backend.database.crud import get_user_by_email
from backend.database.models import User
from backend.services.auth_service import EMAIL_PATTERN, AuthService
from backend.services.mfa.otp_service import (
    OTP_CHALLENGE_INVALID,
    OTP_RESEND_COOLDOWN,
    OTP_RESEND_LIMIT,
    PURPOSE_PASSWORD_RESET,
    OTPService,
)

logger = logging.getLogger(__name__)

MAX_PENDING_RESETS = 1000
RESET_TOKEN_TTL = timedelta(minutes=10)
PASSWORD_RESET_UNAVAILABLE = "PASSWORD_RESET_UNAVAILABLE"
PASSWORD_RESET_INVALID = "PASSWORD_RESET_INVALID"
REQUESTED_MESSAGE = "If the account exists, a verification code has been sent to the registered email."
COMPLETED_MESSAGE = "Password reset successfully. Please sign in with your new password."

Defer = Callable[[Callable[[], None]], None]


@dataclass
class PasswordResetRequest:
    id: str
    key: str
    email: str
    user_id: str | None
    created_at: datetime
    expires_at: datetime
    starts: int = 1
    token_hash: str | None = None

    def __repr__(self) -> str:
        return f"PasswordResetRequest(starts={self.starts}, expires_at={self.expires_at.isoformat()}, <redacted>)"


class PasswordResetStore:
    """Process-local, lock-protected, bounded store keyed by an opaque id that is never sent to clients."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._items: dict[str, PasswordResetRequest] = {}

    def get(self, request_id: str) -> PasswordResetRequest | None:
        with self.lock:
            return self._items.get(request_id)

    def for_key(self, key: str) -> PasswordResetRequest | None:
        with self.lock:
            return next((item for item in self._items.values() if item.key == key), None)

    def for_token(self, token_hash: str) -> PasswordResetRequest | None:
        with self.lock:
            return next(
                (item for item in self._items.values() if item.token_hash and hmac.compare_digest(item.token_hash, token_hash)),
                None,
            )

    def put(self, request: PasswordResetRequest) -> None:
        with self.lock:
            self._items[request.id] = request

    def discard(self, request_id: str) -> None:
        with self.lock:
            self._items.pop(request_id, None)

    def purge(self, now: datetime) -> None:
        with self.lock:
            for request_id in [key for key, item in self._items.items() if now >= item.expires_at]:
                self._items.pop(request_id, None)

    def clear(self) -> None:
        with self.lock:
            self._items.clear()

    def __len__(self) -> int:
        with self.lock:
            return len(self._items)


PASSWORD_RESETS = PasswordResetStore()


def _run_now(task: Callable[[], None]) -> None:
    task()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _challenge_view(view: dict[str, Any]) -> dict[str, Any]:
    """The same fields for real and decoy challenges; no destination, so nothing differs between them."""
    return {
        "message": REQUESTED_MESSAGE,
        "challenge_id": view["challenge_id"],
        "expires_in": view["expires_in"],
        "resend_available_in": view["resend_available_in"],
        "attempts_remaining": view["attempts_remaining"],
        "sends_remaining": view["sends_remaining"],
    }


class PasswordResetService:
    def __init__(
        self,
        db: Session,
        otp_service: OTPService,
        *,
        store: PasswordResetStore | None = None,
        defer: Defer | None = None,
        max_pending: int = MAX_PENDING_RESETS,
    ) -> None:
        self._db = db
        self._otp = otp_service
        self._store = store if store is not None else PASSWORD_RESETS
        self._defer = defer or _run_now
        self._max_pending = max_pending

    def request(self, email: str) -> dict[str, Any]:
        """Start a reset for any well-formed email; the answer is identical whether or not it is registered."""
        key = (email or "").strip().lower()
        if not EMAIL_PATTERN.fullmatch(key):
            raise ValidationException("Enter a valid email address.")
        user = get_user_by_email(self._db, email=key)

        now = self._otp.now()
        with self._store.lock:
            self._store.purge(now)
            previous = self._store.for_key(key)
            if previous is not None:
                retry = max(
                    math.ceil((previous.created_at + self._otp.resend_cooldown - now).total_seconds()),
                    self._otp.resend_available_in(previous.id),
                )
                if retry > 0:
                    raise MFAError(OTP_RESEND_COOLDOWN, "Please wait before requesting another code.", status_code=429, retry_after=retry)
                if previous.starts >= self._otp.max_sends:
                    raise MFAError(OTP_RESEND_LIMIT, "Too many codes requested for this email. Try again later.", status_code=429)
            elif len(self._store) >= self._max_pending:
                raise MFAError(PASSWORD_RESET_UNAVAILABLE, "Too many password resets are pending. Try again later.", status_code=503)

        reset = PasswordResetRequest(
            id=secrets.token_urlsafe(24),
            key=key,
            email=user.email if user is not None else key,
            user_id=user.id if user is not None else None,
            created_at=now,
            expires_at=now + self._otp.challenge_lifetime,
            starts=previous.starts + 1 if previous is not None else 1,
        )
        view = self._otp.start_quiet(reset, PURPOSE_PASSWORD_RESET, decoy=user is None, defer=self._defer)
        with self._store.lock:
            if previous is not None:
                self._store.discard(previous.id)
                self._otp.cancel(previous.id)
            self._store.put(reset)
        logger.info("Password reset requested (attempt %s for this email)", reset.starts)
        return _challenge_view(view)

    def resend(self, challenge_id: str) -> dict[str, Any]:
        return _challenge_view(self._otp.resend_quiet(challenge_id, PURPOSE_PASSWORD_RESET, defer=self._defer))

    def verify(self, challenge_id: str, otp: str) -> dict[str, Any]:
        """Exchange a correct reset code for a short-lived token that can only set a new password."""
        request_id = self._otp.verify(challenge_id, otp, purpose=PURPOSE_PASSWORD_RESET)
        now = self._otp.now()
        with self._store.lock:
            reset = self._store.get(request_id)
            if reset is None or reset.user_id is None or now >= reset.expires_at:
                if reset is not None:
                    self._store.discard(reset.id)
                raise MFAError(OTP_CHALLENGE_INVALID, "This password reset is no longer valid. Request a new code.")
            token = secrets.token_urlsafe(32)
            reset.token_hash = _token_hash(token)
            reset.expires_at = now + RESET_TOKEN_TTL
        logger.info("Password reset code verified for user %s", reset.user_id)
        return {"reset_token": token, "expires_in": int(RESET_TOKEN_TTL.total_seconds())}

    def complete(self, reset_token: str, new_password: str, confirm_password: str) -> dict[str, Any]:
        """Set the new password once; the token, the reset and any pending sign-in codes end here."""
        now = self._otp.now()
        with self._store.lock:
            self._store.purge(now)
            reset = self._store.for_token(_token_hash(reset_token or ""))
        if reset is None:
            raise MFAError(PASSWORD_RESET_INVALID, "This password reset is no longer valid. Request a new code.")
        if new_password != confirm_password:
            raise ValidationException("Passwords do not match.")
        AuthService.validate_password(new_password)

        with self._store.lock:
            if self._store.get(reset.id) is not reset:
                raise MFAError(PASSWORD_RESET_INVALID, "This password reset is no longer valid. Request a new code.")
            self._store.discard(reset.id)
        user = self._db.get(User, reset.user_id)
        if user is None:
            raise MFAError(PASSWORD_RESET_INVALID, "This password reset is no longer valid. Request a new code.")
        AuthService(self._db).set_password(user, new_password)
        self._otp.cancel(reset.id)
        self._otp.cancel(user.id)
        logger.info("Password reset completed for user %s", user.id)
        return {"success": True, "message": COMPLETED_MESSAGE}
