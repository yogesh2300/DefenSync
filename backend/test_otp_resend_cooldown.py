"""OTP resend: a 120-second cooldown enforced by the server for registration and sign-in codes.

In-memory SMTP double, controllable clock and SQLite only; nothing persists outside the test.
"""

from __future__ import annotations

import io
import logging
import unittest
from datetime import timedelta
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
from backend.core.exceptions import register_exception_handlers
from backend.core.security import hash_password
from backend.database.models import Base, User
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.services.registration_service import PendingRegistrationStore

PASSWORD = base.PASSWORD
EMAIL = base.EMAIL
MEMBER_EMAIL = "member@example.test"
COOLDOWN = 120


class OTPResendCooldownTests(unittest.TestCase):
    def setUp(self):
        base.FakeSMTP.outbox = []
        base.FakeSMTP.fail = None
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.clock = base.Clock()
        self.challenges = OTPChallengeStore()
        self.pending = PendingRegistrationStore()
        self.settings = base.smtp_settings()
        self.responses: list[str] = []
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(
            self.settings, store=self.challenges, clock=self.clock, smtp_factory=base.FakeSMTP,
        )
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: self.pending
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def call(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        self.responses.append(response.text)
        return response

    def register(self, password=PASSWORD):
        return self.call("POST", "/api/v1/auth/register", json={"username": "tejas", "email": EMAIL, "password": password})

    def resend(self, challenge_id):
        return self.call("POST", "/api/v1/auth/otp/send", json={"challenge_id": challenge_id})

    def verify_registration(self, challenge_id, otp):
        return self.call("POST", "/api/v1/auth/register/verify", json={"challenge_id": challenge_id, "otp": otp})

    def login(self):
        return self.call("POST", "/api/v1/auth/token", data={"email": MEMBER_EMAIL, "password": PASSWORD})

    def verify_login(self, challenge_id, otp):
        return self.call("POST", "/api/v1/auth/otp/verify", json={"challenge_id": challenge_id, "otp": otp})

    def add_member(self):
        digest = hash_password(PASSWORD)
        self.session.add(User(username="member", email=MEMBER_EMAIL, hashed_password=digest, password_hash=digest, role="ANALYST"))
        self.session.commit()

    def users(self, email=EMAIL):
        return self.session.scalar(select(func.count(User.id)).where(User.email == email))

    def sent(self):
        return len(base.FakeSMTP.outbox)

    code = staticmethod(base.RegistrationFlowTests.code)

    def start_registration(self):
        started = self.register()
        self.assertEqual(started.status_code, 202, started.text)
        return started.json()["challenge_id"]

    def assert_cooldown(self, response, retry_after):
        self.assertEqual((response.status_code, response.json()["code"], response.json()["retry_after"]), (429, "OTP_RESEND_COOLDOWN", retry_after))

    # 1
    def test_initial_send_reports_the_full_cooldown_and_creates_no_account(self):
        started = self.register()
        body = started.json()
        self.assertEqual(started.status_code, 202, started.text)
        self.assertEqual((body["resend_available_in"], body["expires_in"], body["sends_remaining"]), (COOLDOWN, 300, 2))
        self.assertEqual((self.sent(), self.users(), len(self.pending)), (1, 0, 1))

    # 2 + 3 + 4
    def test_resend_is_rejected_until_exactly_120_seconds(self):
        challenge_id = self.start_registration()
        self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
        self.clock.advance(seconds=119)
        self.assert_cooldown(self.resend(challenge_id), 1)
        self.assertEqual(self.sent(), 1)
        self.clock.advance(seconds=1)
        resent = self.resend(challenge_id)
        self.assertEqual(resent.status_code, 200, resent.text)
        body = resent.json()
        self.assertEqual((body["challenge_id"], body["resend_available_in"], body["expires_in"]), (challenge_id, COOLDOWN, 300))
        self.assertEqual((self.sent(), len(self.pending), self.users()), (2, 1, 0))

    # 5 + 6 + 7
    def test_new_code_invalidates_the_old_one_and_completes_the_same_pending_registration(self):
        with patch("backend.services.mfa.otp_service.secrets.randbelow", side_effect=[111111, 222222]):
            challenge_id = self.start_registration()
            pending_before = set(self.pending._items)
            self.clock.advance(seconds=COOLDOWN)
            self.assertEqual(self.resend(challenge_id).status_code, 200)
        self.assertEqual((self.code(0), self.code(1)), ("111111", "222222"))
        self.assertEqual(set(self.pending._items), pending_before)
        old = self.verify_registration(challenge_id, "111111")
        self.assertEqual((old.status_code, old.json()["code"]), (401, "OTP_INVALID"))
        self.assertEqual(self.users(), 0)
        new = self.verify_registration(challenge_id, "222222")
        self.assertEqual(new.status_code, 201, new.text)
        self.assertEqual((self.users(), len(self.pending), len(self.challenges)), (1, 0, 0))

    # 8
    def test_expired_code_is_rejected_and_a_resend_recovers(self):
        challenge_id = self.start_registration()
        expired_code = self.code()
        self.clock.advance(minutes=5, seconds=1)
        expired = self.verify_registration(challenge_id, expired_code)
        self.assertEqual((expired.status_code, expired.json()["code"]), (401, "OTP_EXPIRED"))
        self.assertEqual(self.users(), 0)
        self.assertEqual(self.resend(challenge_id).status_code, 200)
        self.assertEqual(self.verify_registration(challenge_id, expired_code).status_code, 401)
        self.assertEqual(self.verify_registration(challenge_id, self.code()).status_code, 201)
        self.assertEqual(self.users(), 1)

    # 9
    def test_failed_first_delivery_creates_nothing(self):
        base.FakeSMTP.fail = "down"
        failed = self.register()
        self.assertEqual((failed.status_code, failed.json()["code"]), (503, "OTP_DELIVERY_FAILED"))
        self.assertEqual((self.users(), len(self.pending), len(self.challenges)), (0, 0, 0))

    def test_failed_resend_keeps_the_pending_registration_retryable(self):
        challenge_id = self.start_registration()
        self.clock.advance(seconds=COOLDOWN)
        base.FakeSMTP.fail = "down"
        failed = self.resend(challenge_id)
        self.assertEqual((failed.status_code, failed.json()["code"]), (503, "OTP_DELIVERY_FAILED"))
        self.assertEqual((self.users(), len(self.pending), len(self.challenges), self.sent()), (0, 1, 1, 1))
        base.FakeSMTP.fail = None
        retried = self.resend(challenge_id)
        self.assertEqual(retried.status_code, 200, retried.text)
        self.assertEqual((retried.json()["sends_remaining"], self.sent()), (0, 2))
        self.assertEqual(self.verify_registration(challenge_id, self.code()).status_code, 201)
        self.assertEqual(self.users(), 1)

    def test_failed_resend_leaves_the_delivered_code_usable(self):
        challenge_id = self.start_registration()
        delivered = self.code()
        self.clock.advance(seconds=COOLDOWN)
        base.FakeSMTP.fail = "auth"
        self.assertEqual(self.resend(challenge_id).json()["code"], "OTP_DELIVERY_FAILED")
        self.assertEqual(self.verify_registration(challenge_id, delivered).status_code, 201)
        self.assertEqual(self.users(), 1)

    # 10
    def test_repeated_requests_cannot_bypass_the_cooldown(self):
        challenge_id = self.start_registration()
        for _ in range(20):
            self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
        for elapsed in (30, 60, 90, 119):
            self.clock.now = base.Clock().now + timedelta(seconds=elapsed)
            self.assert_cooldown(self.resend(challenge_id), COOLDOWN - elapsed)
            self.assert_cooldown(self.register(), COOLDOWN - elapsed)
        self.assertEqual((self.sent(), len(self.pending), self.challenges.get(challenge_id).sends), (1, 1, 1))
        self.clock.advance(seconds=1)
        self.assertEqual(self.resend(challenge_id).status_code, 200)
        self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
        self.clock.advance(seconds=10)
        self.assert_cooldown(self.register(password="Another-Password-2"), COOLDOWN - 10)
        self.assertEqual((self.sent(), len(self.pending), self.users()), (2, 1, 0))

    # 11
    def test_login_resend_has_the_same_server_side_cooldown(self):
        self.add_member()
        started = self.login()
        self.assertEqual((started.status_code, started.json()["resend_available_in"]), (200, COOLDOWN))
        challenge_id = started.json()["challenge_id"]
        first = self.code()
        self.assert_cooldown(self.resend(challenge_id), COOLDOWN)
        self.clock.advance(seconds=119)
        self.assert_cooldown(self.resend(challenge_id), 1)
        self.assert_cooldown(self.login(), 1)
        self.clock.advance(seconds=1)
        resent = self.resend(challenge_id)
        self.assertEqual((resent.status_code, resent.json()["resend_available_in"]), (200, COOLDOWN))
        if self.code() != first:
            self.assertEqual(self.verify_login(challenge_id, first).json()["code"], "OTP_INVALID")
        token = self.verify_login(challenge_id, self.code()).json()["access_token"]
        self.assertEqual(jwt.get_unverified_claims(token)["amr"], ["pwd", "otp"])

    # 12
    def test_resent_registration_and_login_codes_stay_isolated(self):
        self.add_member()
        registration = self.start_registration()
        self.clock.advance(seconds=COOLDOWN)
        self.assertEqual(self.resend(registration).status_code, 200)
        registration_code = self.code()
        as_login = self.verify_login(registration, registration_code)
        self.assertEqual((as_login.status_code, as_login.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        login = self.login().json()["challenge_id"]
        self.clock.advance(seconds=COOLDOWN)
        self.assertEqual(self.resend(login).status_code, 200)
        login_code = self.code()
        as_registration = self.verify_registration(login, login_code)
        self.assertEqual((as_registration.status_code, as_registration.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertNotIn("access_token", as_login.json() | as_registration.json())
        self.assertEqual(self.users(), 0)
        self.assertEqual(self.verify_registration(registration, registration_code).status_code, 201)
        self.assertEqual(self.verify_login(login, login_code).status_code, 200)

    # 13
    def test_codes_never_appear_in_responses_or_logs(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            self.add_member()
            registration = self.start_registration()
            self.resend(registration)
            self.clock.advance(seconds=COOLDOWN)
            base.FakeSMTP.fail = "down"
            self.resend(registration)
            base.FakeSMTP.fail = None
            self.resend(registration)
            self.verify_registration(registration, self.code())
            login = self.login().json()["challenge_id"]
            self.clock.advance(seconds=COOLDOWN)
            self.resend(login)
            self.verify_login(login, self.code())
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        codes = {self.code(index) for index in range(self.sent())}
        self.assertEqual(len(base.FakeSMTP.outbox), 4)
        for surface in self.responses + [stream.getvalue()]:
            for secret in codes | {PASSWORD, base.SMTP_SECRET}:
                self.assertNotIn(secret, surface)


if __name__ == "__main__":
    unittest.main()
