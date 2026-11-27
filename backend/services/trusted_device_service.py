"""Per-user trusted browser device enrollment, challenge proof, limits, and alerts.

Session policy (migration / enforcement):
- There are no refresh tokens. Access JWTs are issued after MFA (pwd+otp).
- Devices are never auto-enrolled from login alone; enrollment requires an authenticated
  MFA session plus cryptographic possession proof.
- On successful enroll/verify, the API re-issues an access token with a ``device_id`` claim.
  Those device-bound tokens are rejected immediately when that device is REVOKED.
- MFA-only tokens (no ``device_id``) are not associated with a device and remain valid until
  ordinary expiry; they cannot be selectively killed by device revoke without a broader
  server-side session store. Login recovery via MFA/password reset is unchanged.
- Revoking device A does not affect device-bound tokens for device B.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.core.exceptions import AuthorizationError, DeviceTrustError, ResourceNotFoundError, ValidationException
from backend.database.models import DeviceChallenge, TrustedDevice, User
from backend.services.alert_service import AlertService

logger = logging.getLogger(__name__)

DEFAULT_DEVICE_LIMIT = 3
ACTIVE_STATUSES = ("PENDING", "VERIFIED")
CHALLENGE_TTL_SECONDS = 300
LIMIT_ALERT_DEDUPE_SECONDS = 900
REASON_LIMIT_EXCEEDED = "TRUSTED_DEVICE_LIMIT_EXCEEDED"
OUTCOME_DENIED = "denied"
OUTCOME_ENROLLED = "enrolled"
OUTCOME_VERIFIED = "verified"
OUTCOME_REVOKED = "revoked"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def public_key_thumbprint(public_key_jwk: dict[str, Any] | str) -> str:
    """RFC 7638-style SHA-256 thumbprint over required EC JWK members (safe device reference)."""
    data = json.loads(public_key_jwk) if isinstance(public_key_jwk, str) else public_key_jwk
    required = {"crv": data["crv"], "kty": data["kty"], "x": data["x"], "y": data["y"]}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _parse_public_jwk(public_key_jwk: dict[str, Any] | str) -> dict[str, Any]:
    data = json.loads(public_key_jwk) if isinstance(public_key_jwk, str) else dict(public_key_jwk)
    if data.get("kty") != "EC" or data.get("crv") != "P-256":
        raise ValidationException("Only ECDSA P-256 (ES256) device keys are supported.")
    if "d" in data:
        raise ValidationException("Private key material must not be sent to the server.")
    for field in ("x", "y"):
        if not data.get(field):
            raise ValidationException(f"Device public key is missing '{field}'.")
    return {"kty": "EC", "crv": "P-256", "x": data["x"], "y": data["y"], "ext": True}


def _pad_b64(value: str) -> str:
    return value + ("=" * (-len(value) % 4))


def _jwk_to_ec_public_key(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    x = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["x"])), "big")
    y = int.from_bytes(base64.urlsafe_b64decode(_pad_b64(jwk["y"])), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def _verify_es256(public_key_jwk: str, message: bytes, signature_b64: str) -> bool:
    try:
        jwk = _parse_public_jwk(public_key_jwk)
        key = _jwk_to_ec_public_key(jwk)
        raw = base64.urlsafe_b64decode(_pad_b64(signature_b64))
        if len(raw) == 64:
            der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        else:
            der = raw
            decode_dss_signature(der)
        key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False


def device_limit_for(user: User) -> int:
    limit = getattr(user, "device_limit", None)
    if limit is None:
        return DEFAULT_DEVICE_LIMIT
    return max(0, int(limit))


class TrustedDeviceService:
    def __init__(
        self,
        session: Session,
        *,
        clock: Callable[[], datetime] | None = None,
        alert_service_factory: Callable[[Session], AlertService] | None = None,
    ) -> None:
        self._session = session
        self._clock = clock or _utcnow
        self._alert_factory = alert_service_factory or AlertService

    def summary_for(self, user: User) -> dict[str, Any]:
        devices = self.list_devices(user)
        active = [item for item in devices if item["status"] in ACTIVE_STATUSES]
        limit = device_limit_for(user)
        return {
            "device_limit": limit,
            "active_count": len(active),
            "available_slots": max(0, limit - len(active)),
            "devices": devices,
        }

    def list_devices(self, user: User, *, include_revoked: bool = True) -> list[dict[str, Any]]:
        stmt = select(TrustedDevice).where(TrustedDevice.user_id == user.id).order_by(TrustedDevice.created_at.desc())
        rows = list(self._session.scalars(stmt).all())
        if not include_revoked:
            rows = [row for row in rows if row.status != "REVOKED"]
        return [self._serialize(row) for row in rows]

    def begin_enrollment(
        self,
        user: User,
        *,
        public_key_jwk: dict[str, Any] | str,
        display_name: str | None = None,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        jwk = _parse_public_jwk(public_key_jwk)
        thumbprint = public_key_thumbprint(jwk)
        name = (display_name or "Trusted device").strip()[:120] or "Trusted device"
        now = self._clock()

        locked = self._session.get(User, user.id, with_for_update=True)
        if locked is None:
            raise ResourceNotFoundError("User not found.")

        existing = self._session.scalar(
            select(TrustedDevice).where(
                TrustedDevice.user_id == locked.id,
                TrustedDevice.public_key_thumbprint == thumbprint,
            )
        )
        if existing is not None:
            if existing.status == "REVOKED":
                raise DeviceTrustError(
                    "DEVICE_REVOKED",
                    "This device was revoked. Enroll with a new key pair after MFA; revoked devices are never silently reactivated.",
                    status_code=403,
                )
            if existing.status in ACTIVE_STATUSES:
                challenge, nonce = self._issue_challenge(locked.id, existing.id, "ENROLL", now)
                self._session.commit()
                return {
                    "device_id": existing.id,
                    "status": existing.status,
                    "challenge_id": challenge.id,
                    "challenge": nonce,
                    "expires_in": CHALLENGE_TTL_SECONDS,
                    "outcome": "reproof",
                }

        active_count = self._active_count(locked.id)
        limit = device_limit_for(locked)
        if active_count >= limit:
            self._record_limit_exceeded(
                locked,
                thumbprint=thumbprint,
                source_ip=source_ip,
                user_agent=user_agent,
            )
            raise DeviceTrustError(
                REASON_LIMIT_EXCEEDED,
                f"Trusted device limit reached ({active_count} of {limit}). Revoke a device before enrolling another.",
                status_code=403,
                device_limit=limit,
                active_count=active_count,
                outcome=OUTCOME_DENIED,
            )

        device = TrustedDevice(
            id=str(uuid.uuid4()),
            user_id=locked.id,
            account_id=getattr(locked, "account_id", None),
            display_name=name,
            public_key_jwk=json.dumps(jwk, separators=(",", ":"), sort_keys=True),
            public_key_thumbprint=thumbprint,
            key_algorithm="ES256",
            status="PENDING",
            created_at=now,
            enroll_source_ip=(source_ip or "")[:45] or None,
            enroll_user_agent=(user_agent or "")[:512] or None,
        )
        self._session.add(device)
        self._session.flush()
        challenge, nonce = self._issue_challenge(locked.id, device.id, "ENROLL", now)
        self._session.commit()
        return {
            "device_id": device.id,
            "status": device.status,
            "challenge_id": challenge.id,
            "challenge": nonce,
            "expires_in": CHALLENGE_TTL_SECONDS,
            "outcome": "pending_proof",
            "device_limit": limit,
            "active_count": active_count + 1,
            "available_slots": max(0, limit - (active_count + 1)),
        }

    def complete_enrollment(
        self,
        user: User,
        *,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature: str,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        device = self._consume_signed_challenge(
            user,
            device_id=device_id,
            challenge_id=challenge_id,
            nonce=nonce,
            signature=signature,
            purpose="ENROLL",
        )
        if device.status == "REVOKED":
            raise DeviceTrustError(
                "DEVICE_REVOKED",
                "Revoked devices cannot be enrolled again with the same key.",
                status_code=403,
            )
        now = self._clock()
        device.status = "VERIFIED"
        device.enrolled_at = now
        device.last_seen_at = now
        if source_ip:
            device.last_source_ip = source_ip[:45]
        if user_agent:
            device.last_user_agent = user_agent[:512]
        self._session.commit()
        return {**self._serialize(device), "outcome": OUTCOME_ENROLLED}

    def begin_verify(self, user: User, *, device_id: str) -> dict[str, Any]:
        device = self._owned_device(user, device_id)
        if device.status == "REVOKED":
            raise DeviceTrustError(
                "DEVICE_REVOKED",
                "This device was revoked. Complete MFA and enroll a new key; revoked devices are not trusted.",
                status_code=403,
            )
        if device.status != "VERIFIED":
            raise DeviceTrustError(
                "DEVICE_UNVERIFIED",
                "Device is not verified. Complete enrollment proof before treating it as trusted.",
                status_code=403,
            )
        challenge, nonce = self._issue_challenge(user.id, device.id, "VERIFY", self._clock())
        self._session.commit()
        return {
            "device_id": device.id,
            "challenge_id": challenge.id,
            "challenge": nonce,
            "expires_in": CHALLENGE_TTL_SECONDS,
        }

    def complete_verify(
        self,
        user: User,
        *,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature: str,
        source_ip: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        device = self._consume_signed_challenge(
            user,
            device_id=device_id,
            challenge_id=challenge_id,
            nonce=nonce,
            signature=signature,
            purpose="VERIFY",
        )
        if device.status != "VERIFIED":
            raise DeviceTrustError(
                "DEVICE_REVOKED" if device.status == "REVOKED" else "DEVICE_UNVERIFIED",
                "Device is not trusted.",
                status_code=403,
            )
        now = self._clock()
        device.last_seen_at = now
        if source_ip:
            device.last_source_ip = source_ip[:45]
        if user_agent:
            device.last_user_agent = user_agent[:512]
        self._session.commit()
        return {**self._serialize(device), "outcome": OUTCOME_VERIFIED, "slot_consumed": False}

    def revoke(self, user: User, *, device_id: str) -> dict[str, Any]:
        device = self._owned_device(user, device_id)
        if device.status == "REVOKED":
            return {**self._serialize(device), "outcome": OUTCOME_REVOKED}
        device.status = "REVOKED"
        device.revoked_at = self._clock()
        self._session.commit()
        return {**self._serialize(device), "outcome": OUTCOME_REVOKED}

    def rename(self, user: User, *, device_id: str, display_name: str) -> dict[str, Any]:
        device = self._owned_device(user, device_id)
        name = (display_name or "").strip()[:120]
        if not name:
            raise ValidationException("Display name is required.")
        device.display_name = name
        self._session.commit()
        return self._serialize(device)

    def set_device_limit(self, *, actor: User, target_user_id: str, device_limit: int) -> dict[str, Any]:
        if str(getattr(actor, "role", "")).upper() != "ADMIN":
            raise AuthorizationError("Only an administrator may change another user's device limit.")
        if int(device_limit) < 0 or int(device_limit) > 50:
            raise ValidationException("device_limit must be between 0 and 50.")
        target = self._session.get(User, target_user_id, with_for_update=True)
        if target is None:
            raise ResourceNotFoundError("User not found.")
        target.device_limit = int(device_limit)
        self._session.commit()
        return {
            "user_id": target.id,
            "device_limit": target.device_limit,
            "active_count": self._active_count(target.id),
        }

    def admin_list_for_user(self, *, actor: User, target_user_id: str) -> dict[str, Any]:
        if str(getattr(actor, "role", "")).upper() != "ADMIN":
            raise AuthorizationError("Only an administrator may list another user's devices.")
        target = self._session.get(User, target_user_id)
        if target is None:
            raise ResourceNotFoundError("User not found.")
        return self.summary_for(target)

    def _active_count(self, user_id: str) -> int:
        return int(
            self._session.scalar(
                select(func.count())
                .select_from(TrustedDevice)
                .where(
                    TrustedDevice.user_id == user_id,
                    TrustedDevice.status.in_(ACTIVE_STATUSES),
                )
            )
            or 0
        )

    def _owned_device(self, user: User, device_id: str) -> TrustedDevice:
        device = self._session.get(TrustedDevice, device_id)
        if device is None or device.user_id != user.id:
            raise ResourceNotFoundError("Trusted device not found.")
        return device

    def _issue_challenge(self, user_id: str, device_id: str, purpose: str, now: datetime) -> tuple[DeviceChallenge, str]:
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
        challenge = DeviceChallenge(
            id=str(uuid.uuid4()),
            user_id=user_id,
            device_id=device_id,
            purpose=purpose,
            nonce_hash=hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
            created_at=now,
        )
        self._session.add(challenge)
        self._session.flush()
        return challenge, nonce

    def _consume_signed_challenge(
        self,
        user: User,
        *,
        device_id: str,
        challenge_id: str,
        nonce: str,
        signature: str,
        purpose: str,
    ) -> TrustedDevice:
        device = self._owned_device(user, device_id)
        now = self._clock()
        challenge = self._session.get(DeviceChallenge, challenge_id, with_for_update=True)
        if (
            challenge is None
            or challenge.user_id != user.id
            or challenge.device_id != device.id
            or challenge.purpose != purpose
        ):
            raise DeviceTrustError("DEVICE_CHALLENGE_INVALID", "Device challenge is invalid.", status_code=401)
        if challenge.used_at is not None:
            raise DeviceTrustError("DEVICE_CHALLENGE_REPLAY", "Device challenge was already used.", status_code=401)
        expires = _as_utc(challenge.expires_at)
        if expires is None or now > expires:
            raise DeviceTrustError("DEVICE_CHALLENGE_EXPIRED", "Device challenge has expired.", status_code=401)
        expected_hash = hashlib.sha256((nonce or "").encode("ascii")).hexdigest()
        if not secrets.compare_digest(expected_hash, challenge.nonce_hash):
            raise DeviceTrustError("DEVICE_CHALLENGE_INVALID", "Device challenge nonce mismatch.", status_code=401)
        message = f"{challenge_id}.{nonce}".encode("utf-8")
        if not _verify_es256(device.public_key_jwk, message, signature or ""):
            raise DeviceTrustError("DEVICE_PROOF_INVALID", "Device possession proof failed.", status_code=401)
        challenge.used_at = now
        self._session.flush()
        return device

    def _record_limit_exceeded(
        self,
        user: User,
        *,
        thumbprint: str,
        source_ip: str | None,
        user_agent: str | None,
    ) -> None:
        try:
            alerts = self._alert_factory(self._session)
            alerts.create_auth_security_alert(
                owner_id=user.id,
                account_id=getattr(user, "account_id", None),
                reason_code=REASON_LIMIT_EXCEEDED,
                outcome=OUTCOME_DENIED,
                title="Trusted device limit exceeded",
                message=(
                    f"Enrollment denied for user {user.id}: active trusted-device limit reached. "
                    f"Device reference {thumbprint[:16]}. Source IP and user-agent are supporting evidence only."
                ),
                source_ip=source_ip,
                user_agent=user_agent,
                device_ref=thumbprint,
                dedupe_seconds=LIMIT_ALERT_DEDUPE_SECONDS,
            )
        except Exception:
            logger.exception(
                "Failed to create trusted-device limit alert for user_id=%s; enrollment still denied",
                user.id,
            )

    def _serialize(self, device: TrustedDevice) -> dict[str, Any]:
        return {
            "id": device.id,
            "display_name": device.display_name,
            "status": device.status,
            "verification_status": device.status,
            "key_algorithm": device.key_algorithm,
            "device_ref": device.public_key_thumbprint,
            "created_at": device.created_at,
            "enrolled_at": device.enrolled_at,
            "last_seen_at": device.last_seen_at,
            "revoked_at": device.revoked_at,
            "account_id": device.account_id,
        }
