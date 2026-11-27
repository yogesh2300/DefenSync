"""Per-user trusted device limits, ECDSA challenge proof, alerts, and isolation."""

from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from pydantic import SecretStr

from backend.api import auth as auth_api
from backend.api import trusted_devices as devices_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.config import Settings, get_settings
from backend.core.exceptions import DeviceTrustError, register_exception_handlers
from backend.core.security import hash_password
from backend.database.models import Alert, Base, TrustedDevice, User
from backend.services.alert_service import AlertService
from backend.services.auth_service import AuthService, MFA_AMR
from backend.services.trusted_device_service import (
    DEFAULT_DEVICE_LIMIT,
    REASON_LIMIT_EXCEEDED,
    TrustedDeviceService,
    public_key_thumbprint,
)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 29, 8, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **delta):
        self.now += timedelta(**delta)


def session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def make_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public = private_key.public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(public.x.to_bytes(32, "big")),
        "y": _b64url(public.y.to_bytes(32, "big")),
        "ext": True,
    }
    return private_key, jwk


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def sign_challenge(private_key, challenge_id: str, nonce: str) -> str:
    message = f"{challenge_id}.{nonce}".encode("utf-8")
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return _b64url(raw)


class TrustedDeviceServiceTests(unittest.TestCase):
    def setUp(self):
        self.Session = session_factory()
        self.session = self.Session()
        self.clock = Clock()
        self.user_a = User(
            id="user-a",
            username="alice",
            email="alice@example.test",
            hashed_password=hash_password("Password-1"),
            role="ANALYST",
            account_id="acct-a",
            device_limit=3,
        )
        self.user_b = User(
            id="user-b",
            username="bob",
            email="bob@example.test",
            hashed_password=hash_password("Password-1"),
            role="ANALYST",
            account_id="acct-b",
            device_limit=3,
        )
        self.admin = User(
            id="admin-1",
            username="admin",
            email="admin@example.test",
            hashed_password=hash_password("Password-1"),
            role="ADMIN",
            account_id=None,
            device_limit=3,
        )
        self.session.add_all([self.user_a, self.user_b, self.admin])
        self.session.commit()
        self.service = TrustedDeviceService(self.session, clock=self.clock)

    def tearDown(self):
        self.session.close()

    def _enroll(self, user, *, name="Device"):
        private_key, jwk = make_keypair()
        begin = self.service.begin_enrollment(user, public_key_jwk=jwk, display_name=name)
        done = self.service.complete_enrollment(
            user,
            device_id=begin["device_id"],
            challenge_id=begin["challenge_id"],
            nonce=begin["challenge"],
            signature=sign_challenge(private_key, begin["challenge_id"], begin["challenge"]),
        )
        return private_key, jwk, done

    def test_default_limit_is_three_and_independent_per_user(self):
        self.assertEqual(DEFAULT_DEVICE_LIMIT, 3)
        for _ in range(3):
            self._enroll(self.user_a)
        for _ in range(2):
            self._enroll(self.user_b)
        summary_a = self.service.summary_for(self.user_a)
        summary_b = self.service.summary_for(self.user_b)
        self.assertEqual(summary_a["active_count"], 3)
        self.assertEqual(summary_a["device_limit"], 3)
        self.assertEqual(summary_a["available_slots"], 0)
        self.assertEqual(summary_b["active_count"], 2)
        self.assertEqual(summary_b["available_slots"], 1)

    def test_fourth_enrollment_denied_and_creates_alert(self):
        for index in range(3):
            self._enroll(self.user_a, name=f"A{index}")
        private_key, jwk = make_keypair()
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.begin_enrollment(self.user_a, public_key_jwk=jwk, display_name="Fourth")
        self.assertEqual(raised.exception.code, REASON_LIMIT_EXCEEDED)
        alerts = list(self.session.scalars(select(Alert).where(Alert.owner_id == self.user_a.id)).all())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].detection_type, "auth_security")
        self.assertEqual(alerts[0].risk_factors, REASON_LIMIT_EXCEEDED)
        # User B still has capacity.
        self._enroll(self.user_b, name="Bob-1")

    def test_alert_failure_does_not_bypass_limit(self):
        for _ in range(3):
            self._enroll(self.user_a)
        failing = TrustedDeviceService(
            self.session,
            clock=self.clock,
            alert_service_factory=lambda session: MagicMock(
                create_auth_security_alert=MagicMock(side_effect=RuntimeError("alert store down")),
            ),
        )
        _, jwk = make_keypair()
        with self.assertRaises(DeviceTrustError) as raised:
            failing.begin_enrollment(self.user_a, public_key_jwk=jwk)
        self.assertEqual(raised.exception.code, REASON_LIMIT_EXCEEDED)
        self.assertEqual(failing.summary_for(self.user_a)["active_count"], 3)

    def test_returning_device_does_not_consume_another_slot(self):
        private_key, jwk, enrolled = self._enroll(self.user_a, name="Laptop")
        self.assertEqual(self.service.summary_for(self.user_a)["active_count"], 1)
        begin = self.service.begin_verify(self.user_a, device_id=enrolled["id"])
        verified = self.service.complete_verify(
            self.user_a,
            device_id=enrolled["id"],
            challenge_id=begin["challenge_id"],
            nonce=begin["challenge"],
            signature=sign_challenge(private_key, begin["challenge_id"], begin["challenge"]),
        )
        self.assertEqual(verified["outcome"], "verified")
        self.assertFalse(verified["slot_consumed"])
        self.assertEqual(self.service.summary_for(self.user_a)["active_count"], 1)

    def test_revoke_frees_slot_and_rejects_old_key(self):
        private_key, jwk, enrolled = self._enroll(self.user_a)
        self.service.revoke(self.user_a, device_id=enrolled["id"])
        self.assertEqual(self.service.summary_for(self.user_a)["active_count"], 0)
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.begin_enrollment(self.user_a, public_key_jwk=jwk)
        self.assertEqual(raised.exception.code, "DEVICE_REVOKED")
        # New key can enroll into the freed slot.
        self._enroll(self.user_a, name="Replacement")

    def test_unverified_pending_cannot_verify(self):
        _, jwk = make_keypair()
        begin = self.service.begin_enrollment(self.user_a, public_key_jwk=jwk)
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.begin_verify(self.user_a, device_id=begin["device_id"])
        self.assertEqual(raised.exception.code, "DEVICE_UNVERIFIED")

    def test_replay_and_expired_challenge_rejected(self):
        private_key, jwk = make_keypair()
        begin = self.service.begin_enrollment(self.user_a, public_key_jwk=jwk)
        signature = sign_challenge(private_key, begin["challenge_id"], begin["challenge"])
        self.service.complete_enrollment(
            self.user_a,
            device_id=begin["device_id"],
            challenge_id=begin["challenge_id"],
            nonce=begin["challenge"],
            signature=signature,
        )
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.complete_enrollment(
                self.user_a,
                device_id=begin["device_id"],
                challenge_id=begin["challenge_id"],
                nonce=begin["challenge"],
                signature=signature,
            )
        self.assertEqual(raised.exception.code, "DEVICE_CHALLENGE_REPLAY")

        begin2 = self.service.begin_verify(self.user_a, device_id=begin["device_id"])
        self.clock.advance(minutes=10)
        with self.assertRaises(DeviceTrustError) as raised2:
            self.service.complete_verify(
                self.user_a,
                device_id=begin["device_id"],
                challenge_id=begin2["challenge_id"],
                nonce=begin2["challenge"],
                signature=sign_challenge(private_key, begin2["challenge_id"], begin2["challenge"]),
            )
        self.assertEqual(raised2.exception.code, "DEVICE_CHALLENGE_EXPIRED")

    def test_invalid_signature_rejected(self):
        private_key, jwk = make_keypair()
        other, _ = make_keypair()
        begin = self.service.begin_enrollment(self.user_a, public_key_jwk=jwk)
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.complete_enrollment(
                self.user_a,
                device_id=begin["device_id"],
                challenge_id=begin["challenge_id"],
                nonce=begin["challenge"],
                signature=sign_challenge(other, begin["challenge_id"], begin["challenge"]),
            )
        self.assertEqual(raised.exception.code, "DEVICE_PROOF_INVALID")
        del private_key

    def test_rejects_private_key_material_in_jwk(self):
        _, jwk = make_keypair()
        jwk_with_d = {**jwk, "d": "should-never-be-accepted"}
        with self.assertRaises(Exception):
            self.service.begin_enrollment(self.user_a, public_key_jwk=jwk_with_d)

    def test_admin_can_change_limit_analyst_cannot(self):
        with self.assertRaises(Exception):
            self.service.set_device_limit(actor=self.user_a, target_user_id=self.user_b.id, device_limit=5)
        result = self.service.set_device_limit(actor=self.admin, target_user_id=self.user_b.id, device_limit=5)
        self.assertEqual(result["device_limit"], 5)
        self.session.refresh(self.user_b)
        self.assertEqual(self.user_b.device_limit, 5)

    def test_users_cannot_see_each_others_devices(self):
        _, _, enrolled = self._enroll(self.user_a, name="Secret")
        with self.assertRaises(Exception):
            self.service.revoke(self.user_b, device_id=enrolled["id"])
        listing = self.service.summary_for(self.user_b)
        self.assertEqual(listing["devices"], [])

    def test_concurrent_enrollment_never_exceeds_limit(self):
        self.user_a.device_limit = 1
        self.session.commit()
        session1 = self.Session()
        session2 = self.Session()
        try:
            u1 = session1.get(User, "user-a")
            u2 = session2.get(User, "user-a")
            s1 = TrustedDeviceService(session1, clock=self.clock)
            s2 = TrustedDeviceService(session2, clock=self.clock)
            _, jwk1 = make_keypair()
            _, jwk2 = make_keypair()
            first = s1.begin_enrollment(u1, public_key_jwk=jwk1, display_name="One")
            with self.assertRaises(DeviceTrustError) as raised:
                s2.begin_enrollment(u2, public_key_jwk=jwk2, display_name="Two")
            self.assertEqual(raised.exception.code, REASON_LIMIT_EXCEEDED)
            self.assertEqual(first["status"], "PENDING")
            active = list(
                session1.scalars(
                    select(TrustedDevice).where(
                        TrustedDevice.user_id == "user-a",
                        TrustedDevice.status.in_(("PENDING", "VERIFIED")),
                    )
                ).all()
            )
            self.assertEqual(len(active), 1)
        finally:
            session1.close()
            session2.close()


class TrustedDeviceApiTests(unittest.TestCase):
    def setUp(self):
        self.Session = session_factory()
        self.session = self.Session()
        self.clock = Clock()
        self.user = User(
            id="user-1",
            username="yogesh",
            email="yogesh@example.test",
            hashed_password=hash_password("Password-1"),
            role="ANALYST",
            account_id="acct-1",
            device_limit=3,
        )
        self.admin = User(
            id="admin-1",
            username="admin",
            email="admin@example.test",
            hashed_password=hash_password("Password-1"),
            role="ADMIN",
            device_limit=3,
        )
        self.session.add_all([self.user, self.admin])
        self.session.commit()
        self.client = self._client(self.user)

    def tearDown(self):
        self.session.close()

    def _client(self, current):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.include_router(devices_api.router, prefix="/api/v1/auth/trusted-devices")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: current
        return TestClient(app)

    def test_enroll_verify_revoke_via_http(self):
        private_key, jwk = make_keypair()
        begin = self.client.post(
            "/api/v1/auth/trusted-devices/enroll/begin",
            json={"public_key_jwk": jwk, "display_name": "Chrome"},
        )
        self.assertEqual(begin.status_code, 200, begin.text)
        payload = begin.json()
        complete = self.client.post(
            "/api/v1/auth/trusted-devices/enroll/complete",
            json={
                "device_id": payload["device_id"],
                "challenge_id": payload["challenge_id"],
                "nonce": payload["challenge"],
                "signature": sign_challenge(private_key, payload["challenge_id"], payload["challenge"]),
            },
        )
        self.assertEqual(complete.status_code, 200, complete.text)
        listed = self.client.get("/api/v1/auth/trusted-devices")
        self.assertEqual(listed.status_code, 200)
        body = listed.json()
        self.assertEqual(body["active_count"], 1)
        self.assertEqual(body["device_limit"], 3)
        device_id = body["devices"][0]["id"]
        verify_begin = self.client.post("/api/v1/auth/trusted-devices/verify/begin", json={"device_id": device_id})
        self.assertEqual(verify_begin.status_code, 200)
        vb = verify_begin.json()
        verify_complete = self.client.post(
            "/api/v1/auth/trusted-devices/verify/complete",
            json={
                "device_id": device_id,
                "challenge_id": vb["challenge_id"],
                "nonce": vb["challenge"],
                "signature": sign_challenge(private_key, vb["challenge_id"], vb["challenge"]),
            },
        )
        self.assertEqual(verify_complete.status_code, 200)
        self.assertFalse(verify_complete.json().get("slot_consumed", True))
        revoke = self.client.delete(f"/api/v1/auth/trusted-devices/{device_id}")
        self.assertEqual(revoke.status_code, 200)
        listed2 = self.client.get("/api/v1/auth/trusted-devices").json()
        self.assertEqual(listed2["active_count"], 0)

    def test_me_includes_device_limit(self):
        # get_me uses get_current_user override
        response = self.client.get("/api/v1/auth/me")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["device_limit"], 3)

    def test_admin_limit_endpoint(self):
        admin_client = self._client(self.admin)
        response = admin_client.put(
            f"/api/v1/auth/trusted-devices/admin/users/{self.user.id}/limit",
            json={"device_limit": 4},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["device_limit"], 4)
        denied = self.client.put(
            f"/api/v1/auth/trusted-devices/admin/users/{self.user.id}/limit",
            json={"device_limit": 9},
        )
        self.assertEqual(denied.status_code, 403)

    def test_thumbprint_stable(self):
        _, jwk = make_keypair()
        self.assertEqual(public_key_thumbprint(jwk), public_key_thumbprint(json.dumps(jwk)))


class DeviceBoundSessionRevocationTests(unittest.TestCase):
    """Device-bound JWTs die on revoke; other devices and MFA-only tokens stay valid."""

    def setUp(self):
        self.Session = session_factory()
        self.session = self.Session()
        self.clock = Clock()
        self.settings = Settings.model_construct(
            SECRET_KEY=SecretStr("trusted-device-session-test-key"),
            ALGORITHM="HS256",
            ACCESS_TOKEN_EXPIRE_MINUTES=30,
        )
        self.user = User(
            id="user-sess",
            username="sessuser",
            email="sess@example.test",
            hashed_password=hash_password("Password-1"),
            role="ANALYST",
            account_id="acct-sess",
            device_limit=3,
        )
        self.session.add(self.user)
        self.session.commit()
        self.service = TrustedDeviceService(self.session, clock=self.clock)
        self._settings_patch = patch(
            "backend.core.security.get_settings",
            return_value=self.settings,
        )
        self._settings_patch.start()
        get_settings.cache_clear()
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.include_router(devices_api.router, prefix="/api/v1/auth/trusted-devices")
        app.dependency_overrides[get_db] = lambda: self.session
        # Real JWT validation path (no get_current_user override).
        self.client = TestClient(app)

    def tearDown(self):
        self._settings_patch.stop()
        get_settings.cache_clear()
        self.session.close()

    def _enroll(self, name="Device"):
        private_key, jwk = make_keypair()
        begin = self.service.begin_enrollment(self.user, public_key_jwk=jwk, display_name=name)
        done = self.service.complete_enrollment(
            self.user,
            device_id=begin["device_id"],
            challenge_id=begin["challenge_id"],
            nonce=begin["challenge"],
            signature=sign_challenge(private_key, begin["challenge_id"], begin["challenge"]),
        )
        return private_key, done

    def _auth(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    def test_revoke_invalidates_device_bound_session_only(self):
        private_a, device_a = self._enroll("Laptop-A")
        private_b, device_b = self._enroll("Phone-B")
        token_a = AuthService(self.session).create_token(self.user, device_id=device_a["id"])
        token_b = AuthService(self.session).create_token(self.user, device_id=device_b["id"])
        mfa_only = AuthService(self.session).create_token(self.user)

        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self._auth(token_a)).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self._auth(token_b)).status_code, 200)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers=self._auth(mfa_only)).status_code, 200)

        # Revoke using MFA-only session so the call itself is not device-bound to A.
        app_override = FastAPI()
        register_exception_handlers(app_override)
        app_override.include_router(devices_api.router, prefix="/api/v1/auth/trusted-devices")
        app_override.dependency_overrides[get_db] = lambda: self.session
        app_override.dependency_overrides[get_current_user] = lambda: self.user
        revoker = TestClient(app_override)
        revoked = revoker.delete(f"/api/v1/auth/trusted-devices/{device_a['id']}")
        self.assertEqual(revoked.status_code, 200)

        dead = self.client.get("/api/v1/auth/me", headers=self._auth(token_a))
        self.assertEqual(dead.status_code, 401, dead.text)
        self.assertIn("Trusted device session is no longer valid", dead.json().get("error", ""))

        alive_b = self.client.get("/api/v1/auth/me", headers=self._auth(token_b))
        self.assertEqual(alive_b.status_code, 200, alive_b.text)
        alive_mfa = self.client.get("/api/v1/auth/me", headers=self._auth(mfa_only))
        self.assertEqual(alive_mfa.status_code, 200, alive_mfa.text)

        # Revoked device cannot reauthenticate via device proof.
        with self.assertRaises(DeviceTrustError) as raised:
            self.service.begin_verify(self.user, device_id=device_a["id"])
        self.assertEqual(raised.exception.code, "DEVICE_REVOKED")
        del private_a, private_b

    def test_enroll_complete_returns_device_bound_access_token(self):
        private_key, jwk = make_keypair()
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(devices_api.router, prefix="/api/v1/auth/trusted-devices")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.user
        client = TestClient(app)
        begin = client.post(
            "/api/v1/auth/trusted-devices/enroll/begin",
            json={"public_key_jwk": jwk, "display_name": "Bound"},
        )
        self.assertEqual(begin.status_code, 200, begin.text)
        payload = begin.json()
        complete = client.post(
            "/api/v1/auth/trusted-devices/enroll/complete",
            json={
                "device_id": payload["device_id"],
                "challenge_id": payload["challenge_id"],
                "nonce": payload["challenge"],
                "signature": sign_challenge(private_key, payload["challenge_id"], payload["challenge"]),
            },
        )
        self.assertEqual(complete.status_code, 200, complete.text)
        body = complete.json()
        self.assertIn("access_token", body)
        from jose import jwt as jose_jwt
        claims = jose_jwt.get_unverified_claims(body["access_token"])
        self.assertEqual(claims.get("device_id"), body["id"])
        self.assertTrue(set(MFA_AMR).issubset(claims.get("amr") or []))
        # Bound token works until revoke.
        live = self.client.get("/api/v1/auth/me", headers=self._auth(body["access_token"]))
        self.assertEqual(live.status_code, 200)


class AuthAlertDedupeTests(unittest.TestCase):
    def setUp(self):
        self.Session = session_factory()
        self.session = self.Session()

    def tearDown(self):
        self.session.close()

    def test_dedupe_limit_alerts(self):
        alerts = AlertService(self.session)
        first = alerts.create_auth_security_alert(
            owner_id="u1",
            account_id="a1",
            reason_code=REASON_LIMIT_EXCEEDED,
            outcome="denied",
            title="Trusted device limit exceeded",
            message="first",
            device_ref="abc",
        )
        second = alerts.create_auth_security_alert(
            owner_id="u1",
            account_id="a1",
            reason_code=REASON_LIMIT_EXCEEDED,
            outcome="denied",
            title="Trusted device limit exceeded",
            message="second",
            device_ref="def",
        )
        self.assertEqual(first.id, second.id)
        rows = list(self.session.scalars(select(Alert)).all())
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
