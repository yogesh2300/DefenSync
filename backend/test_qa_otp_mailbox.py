"""Step 2A.1: the QA OTP helper completes the real sign-in flow without weakening it.

The real auth router, OTPService and EmailOTPProvider deliver over SMTP to the local
QA mailbox on an ephemeral 127.0.0.1 port. SQLite in-memory only.
"""

from __future__ import annotations

import smtplib
import socket
import time
import unittest
from email.message import EmailMessage

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import auth as auth_api
from backend.api.dependencies import get_db
from backend.core.config import Settings
from backend.core.exceptions import register_exception_handlers
from backend.core.security import hash_password
from backend.database.models import Base, User
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.testing.otp_mailbox import OTPMailbox, QALoginError, login_with_otp

PASSWORD = "Qa-Mailbox-Password-1"
EMAIL = "qa.analyst@example.test"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class QAMailboxLoginTests(unittest.TestCase):
    def setUp(self):
        self.mailbox = OTPMailbox(port=0).start()
        self.store = OTPChallengeStore()
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.session.add(User(id="qa-1", username="qa_analyst", email=EMAIL, hashed_password=hash_password(PASSWORD), role="ANALYST"))
        self.session.commit()
        self.use_smtp(host="127.0.0.1", port=self.mailbox.port)
        self.responses: list[str] = []

    def tearDown(self):
        self.mailbox.stop()
        self.session.close()

    def use_smtp(self, **overrides):
        values = {
            "SECRET_KEY": SecretStr("qa-mailbox-signing-key"),
            "SMTP_HOST": "127.0.0.1",
            "SMTP_PORT": self.mailbox.port,
            "SMTP_FROM": "defensync-qa@localhost",
            "SMTP_SECURITY": "none",
        }
        values.update(overrides)
        settings = Settings.model_construct(**values)
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(settings, store=self.store)
        self.client = TestClient(app)

    def request(self, method, path, data=None, form=False):
        response = self.client.request(method, path, data=data) if form else self.client.request(method, path, json=data)
        self.responses.append(response.text)
        return response.status_code, response.json()

    def test_full_flow_issues_token_only_after_emailed_code(self):
        result = login_with_otp(self.request, EMAIL, PASSWORD, mailbox=self.mailbox, recipient=EMAIL)
        self.assertEqual(result.challenge["delivery"], "EMAIL")
        self.assertEqual(result.challenge["destination"], "q***@example.test")
        self.assertNotIn("access_token", self.responses[0])
        me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {result.access_token}"})
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["username"], "qa_analyst")
        self.assertNotIn(result.access_token, repr(result))

    def test_code_is_single_use_through_the_helper(self):
        login_with_otp(self.request, EMAIL, PASSWORD, mailbox=self.mailbox, recipient=EMAIL)
        self.assertIsNone(self.mailbox.wait_for_code(since=0, recipient=EMAIL, timeout=0.2))

    def test_wrong_password_never_sends_a_code(self):
        with self.assertRaises(QALoginError) as caught:
            login_with_otp(self.request, EMAIL, "wrong-password", mailbox=self.mailbox, recipient=EMAIL, timeout=0.5)
        self.assertIn("HTTP 401", str(caught.exception))
        self.assertIsNone(self.mailbox.wait_for_code(since=0, timeout=0.2))

    def test_unconfigured_email_fails_with_setup_hint_and_no_token(self):
        self.use_smtp(SMTP_HOST="")
        with self.assertRaises(QALoginError) as caught:
            login_with_otp(self.request, EMAIL, PASSWORD, mailbox=self.mailbox)
        self.assertIn("MFA_NOT_CONFIGURED", str(caught.exception))
        self.assertIn("SMTP_HOST=127.0.0.1", str(caught.exception))
        self.assertTrue(all("access_token" not in body for body in self.responses))

    def test_unreachable_mailbox_reports_delivery_failure(self):
        self.use_smtp(SMTP_PORT=free_port())
        with self.assertRaises(QALoginError) as caught:
            login_with_otp(self.request, EMAIL, PASSWORD, mailbox=self.mailbox)
        self.assertIn("OTP_DELIVERY_FAILED", str(caught.exception))

    def test_pre_mfa_backend_is_rejected(self):
        def legacy(method, path, data=None, form=False):
            return 200, {"access_token": "legacy", "token_type": "bearer"}

        with self.assertRaises(QALoginError) as caught:
            login_with_otp(legacy, EMAIL, PASSWORD, mailbox=self.mailbox, timeout=0.2)
        self.assertIn("predates mandatory MFA", str(caught.exception))

    def test_typed_code_source_and_wrong_code(self):
        result = login_with_otp(
            self.request, EMAIL, PASSWORD,
            read_code=lambda challenge: self.mailbox.wait_for_code(since=0, recipient=EMAIL, timeout=5),
        )
        self.assertTrue(result.access_token)

        self.store.clear()
        with self.assertRaises(QALoginError) as caught:
            login_with_otp(self.request, EMAIL, PASSWORD, read_code=lambda challenge: "not-a-code")
        self.assertIn("OTP_INVALID", str(caught.exception))

    def test_mailbox_filters_by_recipient_and_time(self):
        message = EmailMessage()
        message["From"] = "defensync-qa@localhost"
        message["To"] = "someone.else@example.test"
        message.set_content("Your verification code is: 123456\n")
        with smtplib.SMTP("127.0.0.1", self.mailbox.port, timeout=5) as smtp:
            smtp.send_message(message)
        self.assertIsNone(self.mailbox.wait_for_code(since=0, recipient=EMAIL, timeout=0.3))
        self.assertIsNone(self.mailbox.wait_for_code(since=time.monotonic() + 60, timeout=0.1))
        self.assertEqual(self.mailbox.wait_for_code(since=0, recipient="Someone.Else@example.test", timeout=1), "123456")


if __name__ == "__main__":
    unittest.main()
