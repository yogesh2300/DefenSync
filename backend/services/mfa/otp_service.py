"""OTP challenge lifecycle for the second authentication factor.

A password-verified user receives an opaque challenge id, never an access token.
The access token is issued only after `verify` succeeds. Codes come from `secrets`,
are stored only as an HMAC (keyed with SECRET_KEY), expire, are single-use, and
are invalidated after too many wrong attempts. Nothing here logs or returns a code.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from backend.core.config import Settings, get_settings
from backend.core.exceptions import MFAError
from backend.services.mfa.providers import EmailOTPProvider, OTPDeliveryError, OTPProvider, SMSOTPProvider

logger = logging.getLogger(__name__)

OTP_DIGITS = 6

MFA_NOT_CONFIGURED = "MFA_NOT_CONFIGURED"
OTP_DELIVERY_FAILED = "OTP_DELIVERY_FAILED"
OTP_INVALID = "OTP_INVALID"
OTP_EXPIRED = "OTP_EXPIRED"
OTP_TOO_MANY_ATTEMPTS = "OTP_TOO_MANY_ATTEMPTS"
OTP_RESEND_COOLDOWN = "OTP_RESEND_COOLDOWN"
OTP_RESEND_LIMIT = "OTP_RESEND_LIMIT"
OTP_CHALLENGE_INVALID = "OTP_CHALLENGE_INVALID"
OTP_CHANNEL_UNAVAILABLE = "OTP_CHANNEL_UNAVAILABLE"
OTP_NOT_SENT = "OTP_NOT_SENT"

PURPOSE_LOGIN = "login"
PURPOSE_REGISTRATION = "registration"
PURPOSE_PASSWORD_RESET = "password_reset"


@dataclass
class OTPChallenge:
    challenge_id: str
    user_id: str
    destinations: dict[str, str]
    created_at: datetime
    purpose: str = PURPOSE_LOGIN
    channel: str | None = None
    code_hash: str | None = None
    expires_at: datetime | None = None
    attempts: int = 0
    sends: int = 0
    last_sent_at: datetime | None = None
    # Quiet challenges deliver after the response and never report the outcome; decoys never deliver at all.
    quiet: bool = False
    decoy: bool = False

    def __repr__(self) -> str:
        return f"OTPChallenge(user_id={self.user_id!r}, purpose={self.purpose!r}, channel={self.channel!r}, sends={self.sends})"


class OTPChallengeStore:
    """Process-local, lock-protected challenge store. A restart discards pending challenges."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._items: dict[str, OTPChallenge] = {}

    def get(self, challenge_id: str) -> OTPChallenge | None:
        with self.lock:
            return self._items.get(challenge_id)

    def put(self, challenge: OTPChallenge) -> None:
        with self.lock:
            self._items[challenge.challenge_id] = challenge

    def discard(self, challenge_id: str) -> None:
        with self.lock:
            self._items.pop(challenge_id, None)

    def for_user(self, user_id: str) -> list[OTPChallenge]:
        with self.lock:
            return [item for item in self._items.values() if item.user_id == user_id]

    def purge(self, now: datetime, lifetime: timedelta) -> None:
        with self.lock:
            for challenge_id in [key for key, item in self._items.items() if now - item.created_at >= lifetime]:
                self._items.pop(challenge_id, None)

    def clear(self) -> None:
        with self.lock:
            self._items.clear()

    def __len__(self) -> int:
        with self.lock:
            return len(self._items)


CHALLENGES = OTPChallengeStore()


def delivery_configuration_warning(settings: Settings | None = None) -> str | None:
    """Startup notice when no channel can deliver codes. Reasons name settings, never their values."""
    settings = settings or get_settings()
    statuses = [EmailOTPProvider(settings).status(), SMSOTPProvider(settings).status()]
    if any(item["configured"] for item in statuses):
        return None
    reasons = "; ".join(f"{item['channel']}: {item['reason']}" for item in statuses)
    return (
        f"No two-factor delivery channel is configured ({reasons}). Every sign-in will be refused with "
        "MFA_NOT_CONFIGURED until SMTP_HOST and SMTP_FROM (plus SMTP_USERNAME/SMTP_PASSWORD for an authenticated relay) are set."
    )


class OTPService:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        providers: list[OTPProvider] | None = None,
        store: OTPChallengeStore | None = None,
        clock: Callable[[], datetime] | None = None,
        smtp_factory: Callable[..., Any] | None = None,
    ) -> None:
        settings = settings or get_settings()
        self._providers = providers if providers is not None else [EmailOTPProvider(settings, smtp_factory), SMSOTPProvider(settings)]
        self._store = store if store is not None else CHALLENGES
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._expire = timedelta(minutes=max(1, int(settings.OTP_EXPIRE_MINUTES)))
        self._max_attempts = max(1, int(settings.OTP_MAX_ATTEMPTS))
        self._cooldown = timedelta(seconds=max(0, int(settings.OTP_RESEND_COOLDOWN_SECONDS)))
        self._max_sends = max(1, int(settings.OTP_MAX_SENDS))
        self._lifetime = self._expire * (self._max_sends + 1)
        self._key = settings.SECRET_KEY.get_secret_value().encode("utf-8")

    def __repr__(self) -> str:
        return "OTPService(<redacted>)"

    def now(self) -> datetime:
        return self._clock()

    @property
    def challenge_lifetime(self) -> timedelta:
        return self._lifetime

    @property
    def resend_cooldown(self) -> timedelta:
        return self._cooldown

    @property
    def max_sends(self) -> int:
        return self._max_sends

    def resend_available_in(self, subject_id: str) -> int:
        """Seconds until any challenge for this subject may send another code (0 when allowed)."""
        now = self._clock()
        with self._store.lock:
            return max((self._cooldown_remaining(item, now) for item in self._store.for_user(subject_id)), default=0)

    def cancel(self, subject_id: str) -> None:
        """Invalidate every pending challenge (and so every outstanding code) for one subject."""
        with self._store.lock:
            for item in self._store.for_user(subject_id):
                self._store.discard(item.challenge_id)

    def provider_status(self) -> list[dict[str, Any]]:
        return [provider.status() for provider in self._providers]

    def _unavailable_summary(self, user: Any) -> str:
        parts = []
        for provider in self._providers:
            reason = provider.unavailable_reason()
            if reason is None and not provider.destination_for(user):
                reason = "no destination on this user"
            parts.append(f"{provider.channel}: {reason}")
        return "; ".join(parts)

    def _destinations(self, user: Any) -> dict[str, str]:
        destinations = {
            provider.channel: destination
            for provider in self._providers
            if provider.unavailable_reason() is None and (destination := provider.destination_for(user))
        }
        if not destinations:
            logger.warning("MFA delivery unavailable for user %s (%s)", user.id, self._unavailable_summary(user))
            raise MFAError(
                MFA_NOT_CONFIGURED,
                "Two-factor verification is not configured: no verification code delivery method is available. Contact an administrator.",
                status_code=503,
            )
        return destinations

    def start(self, user: Any, purpose: str = PURPOSE_LOGIN) -> dict[str, Any]:
        """Open a challenge for a password-verified user (or pending registration); deliver when one channel exists."""
        destinations = self._destinations(user)
        now = self._clock()
        with self._store.lock:
            self._store.purge(now, self._lifetime)
            previous = self._store.for_user(user.id)
            retry = max((self._cooldown_remaining(item, now) for item in previous), default=0)
            if retry:
                raise MFAError(OTP_RESEND_COOLDOWN, "Please wait before requesting another code.", status_code=429, retry_after=retry)
            for item in previous:
                self._store.discard(item.challenge_id)
            challenge = OTPChallenge(
                challenge_id=secrets.token_urlsafe(32), user_id=user.id, destinations=destinations, created_at=now, purpose=purpose,
            )
            self._store.put(challenge)
            logger.info("OTP challenge created for user %s", user.id)
            code = self._issue(challenge, next(iter(destinations)), now) if len(destinations) == 1 else None
        if code is not None:
            try:
                self._deliver(challenge, code)
            except MFAError:
                self._store.discard(challenge.challenge_id)
                raise
        return self._view(challenge, now)

    def send(self, challenge_id: str, channel: str | None = None) -> dict[str, Any]:
        """Send (or resend) a code on the chosen channel, subject to cooldown and send limits.

        A new code replaces the previous one. If it cannot be delivered the challenge keeps its
        previous code, expiry, attempts and cooldown, so the user can retry; the send still counts.
        """
        now = self._clock()
        with self._store.lock:
            challenge = self._live(challenge_id, now)
            if challenge.quiet:
                raise MFAError(OTP_CHALLENGE_INVALID, "Verification session is no longer valid. Sign in again.")
            selected = (channel or challenge.channel or (next(iter(challenge.destinations)) if len(challenge.destinations) == 1 else "")).upper()
            if selected not in challenge.destinations:
                raise MFAError(OTP_CHANNEL_UNAVAILABLE, "That delivery method is not available.", status_code=400)
            self._check_resend(challenge, now)
            previous = (challenge.channel, challenge.code_hash, challenge.expires_at, challenge.attempts, challenge.last_sent_at)
            code = self._issue(challenge, selected, now)
        try:
            self._deliver(challenge, code)
        except MFAError:
            with self._store.lock:
                challenge.channel, challenge.code_hash, challenge.expires_at, challenge.attempts, challenge.last_sent_at = previous
            raise
        return self._view(challenge, now)

    def start_quiet(self, subject: Any, purpose: str, *, decoy: bool, defer: Callable[[Callable[[], None]], None]) -> dict[str, Any]:
        """Open a challenge whose delivery runs via `defer` (after the response) and is never reported.

        A decoy issues codes exactly the same way but never delivers them, so callers can answer
        identically whether or not the subject is a real account. Subject ids must be unique per request.
        """
        destinations = self._destinations(subject)
        now = self._clock()
        with self._store.lock:
            self._store.purge(now, self._lifetime)
            challenge = OTPChallenge(
                challenge_id=secrets.token_urlsafe(32), user_id=subject.id, destinations=destinations, created_at=now,
                purpose=purpose, quiet=True, decoy=decoy,
            )
            self._store.put(challenge)
            logger.info("OTP challenge created for user %s", subject.id)
            code = self._issue(challenge, next(iter(destinations)), now)
        self._dispatch_quiet(challenge, code, defer)
        return self._view(challenge, now)

    def resend_quiet(self, challenge_id: str, purpose: str, *, defer: Callable[[Callable[[], None]], None]) -> dict[str, Any]:
        """Resend for a quiet challenge: same cooldown and send limit; a new code replaces the previous one."""
        now = self._clock()
        with self._store.lock:
            challenge = self._live(challenge_id, now)
            if not challenge.quiet or challenge.purpose != purpose:
                raise MFAError(OTP_CHALLENGE_INVALID, "Verification session is no longer valid. Request a new code.")
            self._check_resend(challenge, now)
            code = self._issue(challenge, challenge.channel, now)
        self._dispatch_quiet(challenge, code, defer)
        return self._view(challenge, now)

    def _dispatch_quiet(self, challenge: OTPChallenge, code: str, defer: Callable[[Callable[[], None]], None]) -> None:
        if challenge.decoy:
            return

        def deliver() -> None:
            try:
                self._deliver(challenge, code)
            except MFAError:
                pass

        defer(deliver)

    def _check_resend(self, challenge: OTPChallenge, now: datetime) -> None:
        if challenge.sends >= self._max_sends:
            self._store.discard(challenge.challenge_id)
            raise MFAError(OTP_RESEND_LIMIT, "Too many codes requested. Sign in again.", status_code=429)
        retry = self._cooldown_remaining(challenge, now)
        if retry:
            raise MFAError(OTP_RESEND_COOLDOWN, "Please wait before requesting another code.", status_code=429, retry_after=retry)

    def verify(self, challenge_id: str, otp: str, purpose: str = PURPOSE_LOGIN) -> str:
        """Return the subject id when the code is correct; the challenge is consumed either way it ends."""
        now = self._clock()
        with self._store.lock:
            challenge = self._live(challenge_id, now)
            if challenge.purpose != purpose:
                raise MFAError(OTP_CHALLENGE_INVALID, "Verification session is no longer valid. Sign in again.")
            if challenge.code_hash is None or challenge.expires_at is None:
                raise MFAError(OTP_NOT_SENT, "No verification code has been sent yet.", status_code=400)
            if now >= challenge.expires_at:
                challenge.code_hash = None
                challenge.expires_at = None
                logger.info("OTP verification failed for user %s (expired)", challenge.user_id)
                raise MFAError(OTP_EXPIRED, "The verification code has expired. Request a new code.")
            candidate = (otp or "").strip()
            valid = (
                len(candidate) == OTP_DIGITS
                and candidate.isdigit()
                and hmac.compare_digest(self._hash(challenge.challenge_id, candidate), challenge.code_hash)
            )
            if not valid:
                challenge.attempts += 1
                remaining = self._max_attempts - challenge.attempts
                logger.info("OTP verification failed for user %s", challenge.user_id)
                if remaining <= 0:
                    self._store.discard(challenge.challenge_id)
                    raise MFAError(OTP_TOO_MANY_ATTEMPTS, "Too many attempts. Sign in again.", status_code=429)
                raise MFAError(OTP_INVALID, "Invalid verification code.", attempts_remaining=remaining)
            self._store.discard(challenge.challenge_id)
            logger.info("OTP verification successful for user %s", challenge.user_id)
            return challenge.user_id

    def _live(self, challenge_id: str, now: datetime) -> OTPChallenge:
        challenge = self._store.get(challenge_id or "")
        if challenge is None or now - challenge.created_at >= self._lifetime:
            if challenge is not None:
                self._store.discard(challenge.challenge_id)
            raise MFAError(OTP_CHALLENGE_INVALID, "Verification session is no longer valid. Sign in again.")
        return challenge

    def _issue(self, challenge: OTPChallenge, channel: str, now: datetime) -> str:
        code = f"{secrets.randbelow(10 ** OTP_DIGITS):0{OTP_DIGITS}d}"
        challenge.channel = channel
        challenge.code_hash = self._hash(challenge.challenge_id, code)
        challenge.expires_at = now + self._expire
        challenge.attempts = 0
        challenge.sends += 1
        challenge.last_sent_at = now
        return code

    def _deliver(self, challenge: OTPChallenge, code: str) -> None:
        provider = next(item for item in self._providers if item.channel == challenge.channel)
        logger.info("OTP delivery attempted for user %s via %s", challenge.user_id, challenge.channel)
        try:
            provider.send(challenge.destinations[challenge.channel], code, int(self._expire.total_seconds() // 60))
        except OTPDeliveryError as exc:
            logger.warning("OTP delivery failed for user %s via %s (%s)", challenge.user_id, challenge.channel, exc.code)
            raise MFAError(OTP_DELIVERY_FAILED, "The verification code could not be sent. Try again later.", status_code=503) from None

    def _hash(self, challenge_id: str, code: str) -> str:
        return hmac.new(self._key, f"{challenge_id}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()

    def _cooldown_remaining(self, challenge: OTPChallenge, now: datetime) -> int:
        if challenge.last_sent_at is None:
            return 0
        remaining = (challenge.last_sent_at + self._cooldown - now).total_seconds()
        return max(0, math.ceil(remaining))

    def _view(self, challenge: OTPChallenge, now: datetime) -> dict[str, Any]:
        masks = {provider.channel: provider for provider in self._providers}
        sent = challenge.code_hash is not None and challenge.expires_at is not None
        return {
            "otp_required": True,
            "challenge_id": challenge.challenge_id,
            "delivery": challenge.channel if sent else None,
            "destination": masks[challenge.channel].mask(challenge.destinations[challenge.channel]) if sent else None,
            "channels": [{"channel": channel, "destination": masks[channel].mask(value)} for channel, value in challenge.destinations.items()],
            "expires_in": max(0, int((challenge.expires_at - now).total_seconds())) if sent else None,
            "resend_available_in": self._cooldown_remaining(challenge, now),
            "attempts_remaining": self._max_attempts - challenge.attempts,
            "sends_remaining": self._max_sends - challenge.sends,
        }
