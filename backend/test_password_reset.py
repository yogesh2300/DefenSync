"""Forgot password: emailed reset code -> single-use reset token -> new password -> normal login with MFA.

In-memory SMTP double, controllable clock and SQLite only; nothing touches the real database or mailbox.
"""

from __future__ import annotations

import io
import logging
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.test_registration_flow as base
from backend.api import auth as auth_api
from backend.api.dependencies import get_db
from backend.core.exceptions import MFAError, register_exception_handlers
from backend.core.security import hash_password, verify_password
from backend.database.models import Base, User
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.services.password_reset_service import COMPLETED_MESSAGE, REQUESTED_MESSAGE, PasswordResetService, PasswordResetStore
from backend.services.registration_service import PendingRegistrationStore

EMAIL = "member@example.test"
OLD_PASSWORD = "Old-Password-1"
NEW_PASSWORD = "New-Password-2"
COOLDOWN = 120


class PasswordResetTests(unittest.TestCase):
    def setUp(self):
        base.FakeSMTP.outbox = []
        base.FakeSMTP.fail = None
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        digest = hash_password(OLD_PASSWORD)
        self.member = User(username="member", email=EMAIL, hashed_password=digest, password_hash=digest, role="ANALYST")
        self.session.add(self.member)
        self.session.commit()
        self.clock = base.Clock()
        self.challenges = OTPChallengeStore()
        self.pending = PendingRegistrationStore()
        self.resets = PasswordResetStore()
        self.settings = base.smtp_settings()
        self.responses: list[str] = []
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = self.otp_service
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: self.pending
        app.dependency_overrides[auth_api.get_password_resets] = lambda: self.resets
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def otp_service(self):
        return OTPService(self.settings, store=self.challenges, clock=self.clock, smtp_factory=base.FakeSMTP)

    def call(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        self.responses.append(response.text)
        return response

    def request_reset(self, email=EMAIL):
        return self.call("POST", "/api/v1/auth/password-reset/request", json={"email": email})

    def resend(self, challenge_id):
        return self.call("POST", "/api/v1/auth/password-reset/resend", json={"challenge_id": challenge_id})

    def verify(self, challenge_id, otp):
        return self.call("POST", "/api/v1/auth/password-reset/verify", json={"challenge_id": challenge_id, "otp": otp})

    def complete(self, token, password=NEW_PASSWORD, confirm=None):
        body = {"reset_token": token, "new_password": password, "confirm_password": password if confirm is None else confirm}
        return self.call("POST", "/api/v1/auth/password-reset/complete", json=body)

    def login(self, password, email=EMAIL):
        return self.call("POST", "/api/v1/auth/token", data={"email": email, "password": password})

    def verify_login(self, challenge_id, otp):
        return self.call("POST", "/api/v1/auth/otp/verify", json={"challenge_id": challenge_id, "otp": otp})

    def users(self):
        return self.session.scalar(select(func.count(User.id)))

    def sent(self):
        return len(base.FakeSMTP.outbox)

    code = staticmethod(base.RegistrationFlowTests.code)

    def wrong(self):
        return "000000" if self.code() != "000000" else "111111"

    def start(self):
        response = self.request_reset()
        self.assertEqual(response.status_code, 202, response.text)
        return response.json()["challenge_id"]

    def reset_token(self):
        challenge_id = self.start()
        verified = self.verify(challenge_id, self.code())
        self.assertEqual(verified.status_code, 200, verified.text)
        return verified.json()["reset_token"]

    def password_is(self, password):
        self.session.refresh(self.member)
        return verify_password(password, self.member.password_hash) and verify_password(password, self.member.hashed_password)

    def assert_cooldown(self, response, retry_after):
        self.assertEqual((response.status_code, response.json()["code"], response.json()["retry_after"]), (429, "OTP_RESEND_COOLDOWN", retry_after))

    # 2
    def test_existing_email_receives_a_reset_challenge(self):
        response = self.request_reset("  Member@Example.TEST ")
        body = response.json()
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(body["message"], REQUESTED_MESSAGE)
        self.assertEqual((body["expires_in"], body["resend_available_in"], body["attempts_remaining"], body["sends_remaining"]), (300, COOLDOWN, 5, 2))
        self.assertEqual((self.sent(), base.FakeSMTP.outbox[0]["To"]), (1, EMAIL))
        self.assertTrue(self.password_is(OLD_PASSWORD))

    # 3 (plus equivalent behaviour afterwards)
    def test_unknown_email_gets_the_same_response_and_behaviour(self):
        known = self.request_reset().json()
        unknown = self.request_reset("nobody@example.test").json()
        self.assertEqual(self.sent(), 1)
        strip = lambda body: {key: value for key, value in body.items() if key != "challenge_id"}
        self.assertEqual(strip(known), strip(unknown))
        self.assertEqual(set(unknown), {"message", "challenge_id", "expires_in", "resend_available_in", "attempts_remaining", "sends_remaining"})
        self.assertEqual(self.request_reset().json()["code"], self.request_reset("nobody@example.test").json()["code"])
        for challenge_id in (known["challenge_id"], unknown["challenge_id"]):
            self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
            self.assertEqual(self.verify(challenge_id, "000000" if self.code() != "000000" else "111111").json()["attempts_remaining"], 4)
        self.clock.advance(seconds=COOLDOWN)
        resent_known, resent_unknown = self.resend(known["challenge_id"]), self.resend(unknown["challenge_id"])
        self.assertEqual((resent_known.status_code, resent_unknown.status_code), (202, 202))
        self.assertEqual(strip(resent_known.json()), strip(resent_unknown.json()))
        self.assertEqual(self.sent(), 2)

    def test_delivery_runs_after_the_response_and_failures_look_the_same(self):
        deferred = []
        service = PasswordResetService(self.session, self.otp_service(), store=self.resets, defer=deferred.append)
        service.request(EMAIL)
        service.request("nobody@example.test")
        self.assertEqual((len(deferred), self.sent()), (1, 0))
        deferred[0]()
        self.assertEqual(self.sent(), 1)
        self.resets.clear()
        self.challenges.clear()
        base.FakeSMTP.fail = "down"
        failed = self.request_reset()
        self.assertEqual((failed.status_code, failed.json()["message"]), (202, REQUESTED_MESSAGE))

    def test_missing_email_configuration_is_reported_the_same_for_every_email(self):
        self.settings = base.smtp_settings(**base.NO_SMTP)
        for email in (EMAIL, "nobody@example.test"):
            response = self.request_reset(email)
            self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"))
        self.assertEqual(len(self.resets), 0)

    # 4
    def test_registration_code_cannot_reset_a_password(self):
        registration = self.call("POST", "/api/v1/auth/register", json={"username": "newbie", "email": "newbie@example.test", "password": OLD_PASSWORD})
        challenge_id = registration.json()["challenge_id"]
        attempt = self.verify(challenge_id, self.code())
        self.assertEqual((attempt.status_code, attempt.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual(self.resend(challenge_id).json()["code"], "OTP_CHALLENGE_INVALID")
        self.assertNotIn("reset_token", attempt.json())

    # 5 (and a reset code cannot sign in or complete registration)
    def test_login_and_reset_codes_are_not_interchangeable(self):
        login = self.login(OLD_PASSWORD).json()["challenge_id"]
        as_reset = self.verify(login, self.code())
        self.assertEqual((as_reset.status_code, as_reset.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.clock.advance(seconds=COOLDOWN)
        reset = self.start()
        reset_code = self.code()
        for path in ("/api/v1/auth/otp/verify", "/api/v1/auth/register/verify"):
            misuse = self.call("POST", path, json={"challenge_id": reset, "otp": reset_code})
            self.assertEqual((misuse.status_code, misuse.json()["code"]), (401, "OTP_CHALLENGE_INVALID"), path)
            self.assertNotIn("access_token", misuse.json())
        self.assertEqual(self.call("POST", "/api/v1/auth/otp/send", json={"challenge_id": reset}).json()["code"], "OTP_CHALLENGE_INVALID")
        self.assertEqual(self.verify(reset, reset_code).status_code, 200)

    # 6 + 19
    def test_correct_code_returns_only_a_reset_token(self):
        challenge_id = self.start()
        verified = self.verify(challenge_id, self.code())
        body = verified.json()
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertEqual(set(body), {"reset_token", "expires_in"})
        self.assertEqual(body["expires_in"], 600)
        self.assertEqual(self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['reset_token']}"}).status_code, 401)
        completed = self.complete(body["reset_token"])
        self.assertEqual(completed.json(), {"success": True, "message": COMPLETED_MESSAGE})
        self.assertNotIn("access_token", verified.text + completed.text)

    # 7
    def test_wrong_code_fails(self):
        challenge_id = self.start()
        wrong = self.verify(challenge_id, self.wrong())
        self.assertEqual((wrong.status_code, wrong.json()["code"], wrong.json()["attempts_remaining"]), (401, "OTP_INVALID", 4))
        for _ in range(4):
            last = self.verify(challenge_id, self.wrong())
        self.assertEqual(last.json()["code"], "OTP_TOO_MANY_ATTEMPTS")
        self.assertEqual(self.verify(challenge_id, self.code()).status_code, 401)
        self.assertTrue(self.password_is(OLD_PASSWORD))

    # 8
    def test_expired_code_fails(self):
        challenge_id = self.start()
        self.clock.advance(minutes=5, seconds=1)
        expired = self.verify(challenge_id, self.code())
        self.assertEqual((expired.status_code, expired.json()["code"]), (401, "OTP_EXPIRED"))

    # 9 (code and reset token are both single-use)
    def test_code_and_token_are_single_use(self):
        challenge_id = self.start()
        code = self.code()
        token = self.verify(challenge_id, code).json()["reset_token"]
        reused = self.verify(challenge_id, code)
        self.assertEqual((reused.status_code, reused.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual(self.complete(token).status_code, 200)
        again = self.complete(token, password="Third-Password-3")
        self.assertEqual((again.status_code, again.json()["code"]), (401, "PASSWORD_RESET_INVALID"))
        self.assertTrue(self.password_is(NEW_PASSWORD))

    def test_reset_token_expires(self):
        token = self.reset_token()
        self.clock.advance(minutes=10)
        self.assertEqual(self.complete(token).json()["code"], "PASSWORD_RESET_INVALID")
        self.assertTrue(self.password_is(OLD_PASSWORD))

    # 10 + 11
    def test_resend_cooldown_is_exactly_120_seconds(self):
        challenge_id = self.start()
        self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
        self.assert_cooldown(self.request_reset(), COOLDOWN)
        self.clock.advance(seconds=119)
        self.assert_cooldown(self.resend(challenge_id), 1)
        self.assertEqual(self.sent(), 1)
        self.clock.advance(seconds=1)
        resent = self.resend(challenge_id)
        self.assertEqual((resent.status_code, resent.json()["resend_available_in"], resent.json()["challenge_id"]), (202, COOLDOWN, challenge_id))
        self.assertEqual(self.sent(), 2)

    # 12 + 13
    def test_resend_invalidates_the_old_code_and_the_new_one_works(self):
        with patch("backend.services.mfa.otp_service.secrets.randbelow", side_effect=[111111, 222222]):
            challenge_id = self.start()
            self.clock.advance(seconds=COOLDOWN)
            self.assertEqual(self.resend(challenge_id).status_code, 202)
        old = self.verify(challenge_id, "111111")
        self.assertEqual((old.status_code, old.json()["code"]), (401, "OTP_INVALID"))
        self.assertEqual(self.verify(challenge_id, "222222").status_code, 200)

    # 14 + 15
    def test_weak_or_mismatched_passwords_are_rejected_and_the_token_stays_usable(self):
        token = self.reset_token()
        weak = self.complete(token, password="short")
        self.assertEqual((weak.status_code, weak.json()["error"]), (422, "Password must be at least 8 characters."))
        mismatch = self.complete(token, password=NEW_PASSWORD, confirm="Different-Password-9")
        self.assertEqual((mismatch.status_code, mismatch.json()["error"]), (422, "Passwords do not match."))
        self.assertTrue(self.password_is(OLD_PASSWORD))
        self.assertEqual(self.complete(token).status_code, 200)

    # 16 + 17 + 18 + 20 + 21
    def test_reset_changes_the_password_and_login_still_requires_mfa(self):
        users_before = self.users()
        pending_login = self.login(OLD_PASSWORD).json()["challenge_id"]
        pending_code = self.code()
        self.clock.advance(seconds=COOLDOWN)
        self.assertEqual(self.complete(self.reset_token()).status_code, 200)
        self.assertTrue(self.password_is(NEW_PASSWORD))
        self.assertTrue(self.member.password_hash.startswith("$2"))
        self.assertEqual(self.verify_login(pending_login, pending_code).json()["code"], "OTP_CHALLENGE_INVALID")
        self.assertEqual(self.login(OLD_PASSWORD).status_code, 401)
        started = self.login(NEW_PASSWORD)
        self.assertEqual(started.status_code, 200, started.text)
        self.assertTrue(started.json()["otp_required"])
        self.assertNotIn("access_token", started.json())
        token = self.verify_login(started.json()["challenge_id"], self.code()).json()["access_token"]
        self.assertEqual(jwt.get_unverified_claims(token)["amr"], ["pwd", "otp"])
        me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual((me.status_code, me.json()["email"]), (200, EMAIL))
        self.assertEqual(self.users(), users_before)
        self.assertEqual(len(self.resets), 0)

    def test_pending_resets_are_bounded(self):
        service = PasswordResetService(self.session, self.otp_service(), store=self.resets, max_pending=2)
        service.request(EMAIL)
        service.request("two@example.test")
        with self.assertRaises(MFAError) as raised:
            service.request("three@example.test")
        self.assertEqual((raised.exception.code, raised.exception.status_code), ("PASSWORD_RESET_UNAVAILABLE", 503))
        self.clock.advance(minutes=21)
        service.request("three@example.test")
        self.assertEqual(len(self.resets), 1)

    # 22
    def test_no_code_password_or_reset_secret_leaks(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            challenge_id = self.start()
            self.verify(challenge_id, self.wrong())
            self.clock.advance(seconds=COOLDOWN)
            self.resend(challenge_id)
            self.request_reset("nobody@example.test")
            verified = self.verify(challenge_id, self.code())
            token = verified.json()["reset_token"]
            self.complete(token, password="short")
            self.complete(token)
            self.login(NEW_PASSWORD)
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        logs = stream.getvalue()
        codes = {self.code(index) for index in range(self.sent())}
        self.session.refresh(self.member)
        secrets_ = codes | {OLD_PASSWORD, NEW_PASSWORD, self.member.password_hash, base.SMTP_SECRET}
        for surface in self.responses + [logs]:
            for secret in secrets_:
                self.assertNotIn(secret, surface)
        self.assertNotIn(token, logs)
        self.assertEqual([text for text in self.responses if token in text], [verified.text])
        for text in self.responses:
            self.assertNotIn(self.member.id, text)
        self.assertIn("Password reset completed for user", logs)


if __name__ == "__main__":
    unittest.main()
