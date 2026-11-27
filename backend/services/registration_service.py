"""Self-service registration. No User row exists until the emailed verification code is verified.

A pending registration lives in memory next to its OTP challenge and expires with it, so a
registration whose code cannot be delivered, or is never verified, leaves nothing in the
database. A backend restart discards pending registrations; the user simply registers again.
Codes are resent through the shared /otp/send endpoint, which keeps the same pending registration.
"""

from __future__ import annotations

import logging
import math
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from sqlalchemy.orm import Session

from backend.core.exceptions import MFAError
from backend.core.security import hash_password
from backend.database.models import User
from backend.services.auth_service import AuthService
from backend.services.mfa.otp_service import (
    OTP_CHALLENGE_INVALID,
    OTP_RESEND_COOLDOWN,
    OTP_RESEND_LIMIT,
    PURPOSE_REGISTRATION,
    OTPService,
)

logger = logging.getLogger(__name__)

MAX_PENDING_REGISTRATIONS = 1000
REGISTRATION_UNAVAILABLE = "REGISTRATION_UNAVAILABLE"


@dataclass
class PendingRegistration:
    id: str
    username: str
    email: str
    created_at: datetime
    expires_at: datetime
    starts: int = 1
    password_hash: str = ""

    def __repr__(self) -> str:
        return f"PendingRegistration(starts={self.starts}, expires_at={self.expires_at.isoformat()}, <redacted>)"


class PendingRegistrationStore:
    """Process-local, lock-protected, bounded store keyed by an opaque id that is never sent to clients."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._items: dict[str, PendingRegistration] = {}

    def get(self, pending_id: str) -> PendingRegistration | None:
        with self.lock:
            return self._items.get(pending_id)

    def for_email(self, email: str) -> PendingRegistration | None:
        with self.lock:
            return next((item for item in self._items.values() if item.email == email), None)

    def put(self, pending: PendingRegistration) -> None:
        with self.lock:
            self._items[pending.id] = pending

    def discard(self, pending_id: str) -> None:
        with self.lock:
            self._items.pop(pending_id, None)

    def purge(self, now: datetime) -> None:
        with self.lock:
            for pending_id in [key for key, item in self._items.items() if now >= item.expires_at]:
                self._items.pop(pending_id, None)

    def clear(self) -> None:
        with self.lock:
            self._items.clear()

    def __len__(self) -> int:
        with self.lock:
            return len(self._items)


PENDING_REGISTRATIONS = PendingRegistrationStore()


class RegistrationService:
    def __init__(
        self,
        db: Session,
        otp_service: OTPService,
        *,
        store: PendingRegistrationStore | None = None,
        clock: Callable[[], datetime] | None = None,
        max_pending: int = MAX_PENDING_REGISTRATIONS,
    ) -> None:
        self._db = db
        self._otp = otp_service
        self._store = store if store is not None else PENDING_REGISTRATIONS
        self._clock = clock or otp_service.now
        self._max_pending = max_pending

    def start(self, username: str, email: str, password: str) -> dict[str, Any]:
        """Validate, check against existing users, then email a code. Nothing is stored unless delivery succeeds."""
        username, email = AuthService.validate_registration(username, email, password)
        AuthService(self._db).ensure_available(username, email)

        now = self._clock()
        with self._store.lock:
            self._store.purge(now)
            previous = self._store.for_email(email)
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
                raise MFAError(REGISTRATION_UNAVAILABLE, "Too many registrations are pending. Try again later.", status_code=503)

        pending = PendingRegistration(
            id=secrets.token_urlsafe(24),
            username=username,
            email=email,
            created_at=now,
            expires_at=now + self._otp.challenge_lifetime,
            starts=previous.starts + 1 if previous is not None else 1,
        )
        view = self._otp.start(pending, purpose=PURPOSE_REGISTRATION)
        pending.password_hash = hash_password(password)
        with self._store.lock:
            if previous is not None:
                self._store.discard(previous.id)
                self._otp.cancel(previous.id)
            self._store.put(pending)
        logger.info("Registration verification code sent (attempt %s for this email)", pending.starts)
        return view

    def verify(self, challenge_id: str, otp: str) -> User:
        """Create the account only after the emailed code is verified."""
        pending_id = self._otp.verify(challenge_id, otp, purpose=PURPOSE_REGISTRATION)
        now = self._clock()
        with self._store.lock:
            pending = self._store.get(pending_id)
            self._store.discard(pending_id)
        if pending is None or now >= pending.expires_at:
            raise MFAError(OTP_CHALLENGE_INVALID, "This registration is no longer pending. Register again.")
        user = AuthService(self._db).create_user_with_hash(pending.username, pending.email, pending.password_hash)
        logger.info("Registration completed for user %s", user.id)
        return user
