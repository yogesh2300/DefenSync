"""MFA delivery configuration: registration works without SMTP, sign-in never does, and nothing bypasses OTP.

In-memory SMTP double and SQLite only; no network, no real mailbox.
"""

from __future__ import annotations

import io
import logging
import re
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import auth as auth_api
from backend.api.dependencies import get_db
from backend.core.config import Settings
from backend.core.exceptions import register_exception_handlers
from backend.core.security import create_access_token
from backend.database.models import Base, User
from backend.services.auth_service import AuthService
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService, delivery_configuration_warning
from backend.services.registration_service import PendingRegistrationStore

PASSWORD = "Strong-Password-1"
SMTP_SECRET = "smtp-app-password-never-shown"
EMAIL = "tejas@example.test"
CODE_PATTERN = re.compile(r"verification code is: (\d{6})")


class Outbox:
    messages: list = []

    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        return None

    def login(self, username, password):
        return None

    def send_message(self, message):
        Outbox.messages.append(message)


def smtp_settings(**overrides):
    values = {
        "SECRET_KEY": SecretStr("delivery-config-test-key"),
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": 587,
        "SMTP_USERNAME": "mailer@example.test",
        "SMTP_PASSWORD": SecretStr(SMTP_SECRET),
        "SMTP_FROM": "DefenSync <no-reply@example.test>",
        "SMTP_SECURITY": "starttls",
    }
    values.update(overrides)
    return Settings.model_construct(**values)


def no_smtp_settings():
    return smtp_settings(SMTP_HOST="", SMTP_USERNAME="", SMTP_PASSWORD=SecretStr(""), SMTP_FROM="")


class MFADeliveryConfigurationTests(unittest.TestCase):
    def setUp(self):
        Outbox.messages = []
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.store = OTPChallengeStore()
        self.settings = no_smtp_settings()
        self.responses: list[str] = []
        self.log = io.StringIO()
        self.handler = logging.StreamHandler(self.log)
        root = logging.getLogger()
        self.previous_level = root.level
        root.addHandler(self.handler)
        root.setLevel(logging.DEBUG)
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(self.settings, store=self.store, smtp_factory=Outbox)
        pending = PendingRegistrationStore()
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: pending
        self.client = TestClient(app)

    def tearDown(self):
        root = logging.getLogger()
        root.removeHandler(self.handler)
        root.setLevel(self.previous_level)
        self.session.close()

    def call(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        self.responses.append(response.text)
        return response

    def register(self):
        """An existing, verified user (created directly, as bootstrap/admin tooling does)."""
        return AuthService(self.session).register_user("tejas", EMAIL, PASSWORD)

    def login(self, email=EMAIL, password=PASSWORD):
        return self.call("POST", "/api/v1/auth/token", data={"email": email, "password": password})

    def test_self_service_registration_without_smtp_leaves_no_user(self):
        response = self.call("POST", "/api/v1/auth/register", json={"username": "tejas", "email": EMAIL, "password": PASSWORD})
        self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"))
        self.assertIsNone(self.session.scalar(select(User).where(User.email == EMAIL)))
        self.assertEqual(Outbox.messages, [])

    def test_login_without_a_delivery_channel_is_refused_with_mfa_not_configured(self):
        self.register()
        response = self.login()
        body = response.json()
        self.assertEqual((response.status_code, body["code"]), (503, "MFA_NOT_CONFIGURED"))
        for field in ("access_token", "challenge_id", "otp", "code_hash"):
            self.assertNotIn(field, body)
        self.assertEqual((len(self.store), Outbox.messages), (0, []))
        logs = self.log.getvalue()
        self.assertIn("EMAIL: Email provider not configured", logs)
        self.assertIn("SMS: SMS provider not configured", logs)
        self.assertNotIn(PASSWORD, logs)

    def test_wrong_password_is_rejected_before_mfa_delivery_is_considered(self):
        self.register()
        for email, password in ((EMAIL, "Wrong-Password-1"), ("nobody@example.test", PASSWORD)):
            response = self.login(email, password)
            self.assertEqual((response.status_code, response.json().get("code")), (401, None))
        self.assertNotIn("MFA delivery unavailable", self.log.getvalue())

    def test_misconfigured_smtp_is_reported_by_reason_and_still_refused(self):
        self.register()
        cases = {
            "SMTP_PASSWORD missing": smtp_settings(SMTP_PASSWORD=SecretStr("")),
            "SMTP_SECURITY": smtp_settings(SMTP_SECURITY="tls1.3"),
            "unencrypted SMTP is only allowed to a local relay": smtp_settings(SMTP_SECURITY="none"),
        }
        for reason, settings in cases.items():
            self.settings = settings
            response = self.login()
            self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"), reason)
            self.assertIn(reason, self.log.getvalue())
        self.assertEqual(Outbox.messages, [])

    def test_login_proceeds_to_otp_once_smtp_is_configured(self):
        self.register()
        self.assertEqual(self.login().status_code, 503)
        self.settings = smtp_settings()
        challenge = self.login()
        body = challenge.json()
        self.assertEqual(challenge.status_code, 200, challenge.text)
        self.assertNotIn("access_token", body)
        self.assertEqual((body["delivery"], body["destination"]), ("EMAIL", "t***@example.test"))
        code = CODE_PATTERN.search(Outbox.messages[-1].get_content()).group(1)
        verified = self.call("POST", "/api/v1/auth/otp/verify", json={"challenge_id": body["challenge_id"], "otp": code})
        token = verified.json()["access_token"]
        me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me.json()["username"], "tejas")
        for surface in self.responses + [self.log.getvalue()]:
            self.assertNotIn(code, surface)
            self.assertNotIn(SMTP_SECRET, surface)

    def test_mfa_cannot_be_bypassed_when_delivery_is_unavailable(self):
        self.register()
        self.assertEqual(self.login().status_code, 503)
        fake_challenge = "x" * 43
        verify = self.call("POST", "/api/v1/auth/otp/verify", json={"challenge_id": fake_challenge, "otp": "000000"})
        send = self.call("POST", "/api/v1/auth/otp/send", json={"challenge_id": fake_challenge})
        self.assertEqual((verify.status_code, verify.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual((send.status_code, send.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertNotIn("access_token", verify.json())
        password_only = create_access_token({"sub": "tejas", "role": "ANALYST"})
        partial = create_access_token({"sub": "tejas", "role": "ANALYST", "amr": ["pwd"]})
        for headers in ({}, {"Authorization": f"Bearer {password_only}"}, {"Authorization": f"Bearer {partial}"}):
            self.assertEqual(self.client.get("/api/v1/auth/me", headers=headers).status_code, 401)
        legacy = self.call("POST", "/api/v1/auth/token", data={"username": "tejas", "password": PASSWORD})
        self.assertEqual(legacy.status_code, 422)

    def test_startup_warning_names_missing_settings_without_values(self):
        warning = delivery_configuration_warning(smtp_settings(SMTP_HOST="", SMTP_FROM=""))
        self.assertIn("MFA_NOT_CONFIGURED", warning)
        self.assertIn("SMTP_HOST and SMTP_FROM", warning)
        self.assertIn("EMAIL: Email provider not configured", warning)
        self.assertNotIn(SMTP_SECRET, warning)
        self.assertIsNone(delivery_configuration_warning(smtp_settings()))


if __name__ == "__main__":
    unittest.main()
