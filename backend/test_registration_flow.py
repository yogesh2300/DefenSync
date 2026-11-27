"""Registration is transactional with respect to email verification: no User row until the code is verified.

In-memory SMTP double, controllable clock and SQLite only; nothing persists outside the test.
"""

from __future__ import annotations

import io
import logging
import re
import smtplib
import time
import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import auth as auth_api
from backend.api.dependencies import get_db
from backend.core.config import Settings
from backend.core.exceptions import MFAError, register_exception_handlers
from backend.core.security import hash_password, verify_password
from backend.database.models import Base, User
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.services.registration_service import PendingRegistrationStore, RegistrationService

PASSWORD = "Strong-Password-1"
EMAIL = "tejas@example.test"
SMTP_SECRET = "smtp-app-password-never-shown"
CODE_PATTERN = re.compile(r"verification code is: (\d{6})")


class FakeSMTP:
    outbox: list = []
    fail: str | None = None

    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        return None

    def login(self, username, password):
        if FakeSMTP.fail == "auth":
            raise smtplib.SMTPAuthenticationError(535, b"rejected")

    def send_message(self, message):
        if FakeSMTP.fail == "down":
            raise smtplib.SMTPServerDisconnected("connection lost")
        FakeSMTP.outbox.append(message)


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **delta):
        self.now += timedelta(**delta)


def smtp_settings(**overrides):
    values = {
        "SECRET_KEY": SecretStr("registration-flow-test-key"),
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": 587,
        "SMTP_USERNAME": "mailer@example.test",
        "SMTP_PASSWORD": SecretStr(SMTP_SECRET),
        "SMTP_FROM": "DefenSync <no-reply@example.test>",
        "SMTP_SECURITY": "starttls",
    }
    values.update(overrides)
    return Settings.model_construct(**values)


NO_SMTP = {"SMTP_HOST": "", "SMTP_USERNAME": "", "SMTP_PASSWORD": SecretStr(""), "SMTP_FROM": ""}


class RegistrationFlowTests(unittest.TestCase):
    def setUp(self):
        FakeSMTP.outbox = []
        FakeSMTP.fail = None
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.clock = Clock()
        self.challenges = OTPChallengeStore()
        self.pending = PendingRegistrationStore()
        self.settings = smtp_settings()
        self.responses: list[str] = []
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = self.otp_service
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: self.pending
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def otp_service(self):
        return OTPService(self.settings, store=self.challenges, clock=self.clock, smtp_factory=FakeSMTP)

    def call(self, method, path, **kwargs):
        response = self.client.request(method, path, **kwargs)
        self.responses.append(response.text)
        return response

    def register(self, username="tejas", email=EMAIL, password=PASSWORD):
        return self.call("POST", "/api/v1/auth/register", json={"username": username, "email": email, "password": password})

    def verify(self, challenge_id, otp):
        return self.call("POST", "/api/v1/auth/register/verify", json={"challenge_id": challenge_id, "otp": otp})

    def users(self):
        return self.session.scalar(select(func.count(User.id)))

    @staticmethod
    def code(index=-1):
        return CODE_PATTERN.search(FakeSMTP.outbox[index].get_content()).group(1)

    def wrong(self):
        return "000000" if self.code() != "000000" else "111111"

    def complete(self, username="tejas", email=EMAIL):
        started = self.register(username, email)
        self.assertEqual(started.status_code, 202, started.text)
        verified = self.verify(started.json()["challenge_id"], self.code())
        self.assertEqual(verified.status_code, 201, verified.text)
        return verified.json()["access_token"]

    # 1. Working SMTP: verification state first, account only after the correct code.
    def test_valid_registration_enters_verification_then_creates_exactly_one_account(self):
        started = self.register()
        body = started.json()
        self.assertEqual(started.status_code, 202, started.text)
        self.assertTrue(body["otp_required"])
        self.assertNotIn("access_token", body)
        self.assertEqual((body["delivery"], body["destination"]), ("EMAIL", "t***@example.test"))
        self.assertEqual(len(FakeSMTP.outbox), 1)
        self.assertEqual((self.users(), len(self.pending)), (0, 1))
        not_yet = self.call("POST", "/api/v1/auth/token", data={"email": EMAIL, "password": PASSWORD})
        self.assertEqual(not_yet.status_code, 401)

        verified = self.verify(body["challenge_id"], self.code())
        self.assertEqual(verified.status_code, 201, verified.text)
        self.assertEqual((self.users(), len(self.pending), len(self.challenges)), (1, 0, 0))
        user = self.session.scalar(select(User))
        self.assertEqual((user.username, user.email, user.role), ("tejas", EMAIL, "ANALYST"))
        self.assertNotEqual(user.password_hash, PASSWORD)
        self.assertTrue(verify_password(PASSWORD, user.password_hash))
        me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {verified.json()['access_token']}"})
        self.assertEqual(me.json()["username"], "tejas")
        replay = self.verify(body["challenge_id"], self.code())
        self.assertEqual((replay.status_code, self.users()), (401, 1))

    # 2. SMTP unavailable: error, no user, and the same email can be retried.
    def test_smtp_unavailable_leaves_no_user_and_the_email_can_be_retried(self):
        self.settings = smtp_settings(**NO_SMTP)
        for _ in range(3):
            response = self.register()
            self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"))
            self.assertNotIn("challenge_id", response.json())
        self.assertEqual((self.users(), len(self.pending), len(self.challenges)), (0, 0, 0))
        self.settings = smtp_settings()
        self.complete()
        self.assertEqual(self.users(), 1)

    # 3. SMTP failure while sending.
    def test_smtp_delivery_failure_leaves_no_orphan(self):
        for mode in ("down", "auth"):
            FakeSMTP.fail = mode
            response = self.register()
            self.assertEqual((response.status_code, response.json()["code"]), (503, "OTP_DELIVERY_FAILED"), mode)
            self.assertEqual((self.users(), len(self.pending), len(self.challenges)), (0, 0, 0), mode)
        FakeSMTP.fail = None
        self.complete()
        self.assertEqual(self.users(), 1)

    # 4. Invalid SMTP configuration.
    def test_invalid_smtp_configuration_leaves_no_orphan(self):
        for overrides in ({"SMTP_PASSWORD": SecretStr("")}, {"SMTP_SECURITY": "tls1.3"}, {"SMTP_SECURITY": "none"}):
            self.settings = smtp_settings(**overrides)
            response = self.register()
            self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"), overrides)
        self.assertEqual((self.users(), len(self.pending), FakeSMTP.outbox), (0, 0, []))

    # 5. Existing verified account.
    def test_existing_active_email_or_username_is_rejected(self):
        self.complete()
        sent = len(FakeSMTP.outbox)
        same_email = self.register(username="someone", email="TEJAS@Example.test")
        same_name = self.register(username="tejas", email="other@example.test")
        self.assertEqual((same_email.status_code, same_email.json()["error"]), (422, "Email already exists."))
        self.assertEqual((same_name.status_code, same_name.json()["error"]), (422, "Username already exists."))
        self.assertEqual((len(FakeSMTP.outbox), self.users(), len(self.pending)), (sent, 1, 0))

    # 6. Expired pending registration can be restarted.
    def test_expired_pending_registration_can_be_restarted(self):
        stale = self.register().json()["challenge_id"]
        stale_code = self.code()
        self.clock.advance(minutes=21)
        expired = self.verify(stale, stale_code)
        self.assertEqual((expired.status_code, expired.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual(self.users(), 0)
        self.complete()
        self.assertEqual(self.users(), 1)

    def test_retry_replaces_the_pending_registration_and_invalidates_the_old_code(self):
        first = self.register(password="First-Password-1").json()["challenge_id"]
        first_code = self.code()
        too_soon = self.register(password="Second-Password-2")
        self.assertEqual((too_soon.status_code, too_soon.json()["code"]), (429, "OTP_RESEND_COOLDOWN"))
        self.assertGreater(too_soon.json()["retry_after"], 0)
        self.clock.advance(seconds=121)
        second = self.register(password="Second-Password-2").json()["challenge_id"]
        self.assertEqual(len(self.pending), 1)
        old = self.verify(first, first_code)
        self.assertEqual((old.status_code, old.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual(self.verify(second, self.code()).status_code, 201)
        user = self.session.scalar(select(User))
        self.assertTrue(verify_password("Second-Password-2", user.password_hash))
        self.assertFalse(verify_password("First-Password-1", user.password_hash))

    def test_restarts_per_email_are_limited(self):
        for _ in range(3):
            self.assertEqual(self.register().status_code, 202)
            self.clock.advance(seconds=121)
        limited = self.register()
        self.assertEqual((limited.status_code, limited.json()["code"]), (429, "OTP_RESEND_LIMIT"))
        self.clock.advance(minutes=21)
        self.assertEqual(self.register().status_code, 202)

    # 7. Wrong OTP.
    def test_wrong_otp_does_not_activate_the_account(self):
        challenge_id = self.register().json()["challenge_id"]
        wrong = self.verify(challenge_id, self.wrong())
        self.assertEqual((wrong.status_code, wrong.json()["code"], wrong.json()["attempts_remaining"]), (401, "OTP_INVALID", 4))
        for _ in range(4):
            last = self.verify(challenge_id, self.wrong())
        self.assertEqual((last.status_code, last.json()["code"]), (429, "OTP_TOO_MANY_ATTEMPTS"))
        self.assertEqual(self.verify(challenge_id, self.code()).status_code, 401)
        self.assertEqual(self.users(), 0)

    # 8. Expired OTP; a resent code still completes the registration.
    def test_expired_otp_does_not_activate_the_account(self):
        challenge_id = self.register().json()["challenge_id"]
        expired_code = self.code()
        self.clock.advance(minutes=6)
        expired = self.verify(challenge_id, expired_code)
        self.assertEqual((expired.status_code, expired.json()["code"]), (401, "OTP_EXPIRED"))
        self.assertEqual(self.users(), 0)
        resent = self.call("POST", "/api/v1/auth/otp/send", json={"challenge_id": challenge_id})
        self.assertEqual(resent.status_code, 200, resent.text)
        self.assertEqual(self.verify(challenge_id, expired_code).status_code, 401)
        self.assertEqual(self.verify(challenge_id, self.code()).status_code, 201)
        self.assertEqual(self.users(), 1)

    # 9 + 10. The code is never in an API response or a log line.
    def test_otp_password_and_hash_never_appear_in_responses_or_logs(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            challenge_id = self.register().json()["challenge_id"]
            codes = {self.code()}
            pending = next(iter(self.pending._items.values()))
            self.verify(challenge_id, self.wrong())
            self.clock.advance(seconds=121)
            self.call("POST", "/api/v1/auth/otp/send", json={"challenge_id": challenge_id})
            codes.add(self.code())
            self.verify(challenge_id, self.code())
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        self.assertEqual(self.users(), 1)
        for surface in self.responses + [stream.getvalue(), repr(pending)]:
            for secret in codes | {pending.password_hash, PASSWORD, SMTP_SECRET}:
                self.assertNotIn(secret, surface)
        for response in self.responses:
            self.assertNotIn(pending.id, response)
        self.assertIn("Registration completed for user", stream.getvalue())

    def test_pending_registration_stores_only_a_normalized_email_and_a_password_hash(self):
        self.register(username="  tejas  ", email="  Tejas@Example.TEST ")
        pending = next(iter(self.pending._items.values()))
        self.assertEqual((pending.username, pending.email), ("tejas", EMAIL))
        self.assertTrue(pending.password_hash.startswith("$2"))
        self.assertTrue(verify_password(PASSWORD, pending.password_hash))
        self.assertNotIn(PASSWORD, [str(value) for value in vars(pending).values()])
        self.assertNotIn(self.code(), [str(value) for value in vars(pending).values()])

    # MFA cannot be bypassed and login / registration codes are not interchangeable.
    def test_login_and_registration_challenges_cannot_complete_each_other(self):
        digest = hash_password(PASSWORD)
        self.session.add(User(username="existing", email="existing@example.test", hashed_password=digest, password_hash=digest, role="ANALYST"))
        self.session.commit()
        registration = self.register().json()["challenge_id"]
        registration_code = self.code()
        as_login = self.call("POST", "/api/v1/auth/otp/verify", json={"challenge_id": registration, "otp": registration_code})
        self.assertEqual((as_login.status_code, as_login.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        login = self.call("POST", "/api/v1/auth/token", data={"email": "existing@example.test", "password": PASSWORD}).json()["challenge_id"]
        as_registration = self.verify(login, self.code())
        self.assertEqual((as_registration.status_code, as_registration.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertNotIn("access_token", as_login.json() | as_registration.json())
        self.assertEqual(self.verify(registration, registration_code).status_code, 201)
        self.assertEqual(self.users(), 2)

    def test_pending_username_does_not_block_and_first_verified_wins(self):
        first = self.register(username="shared", email="one@example.test").json()["challenge_id"]
        first_code = self.code()
        second = self.register(username="shared", email="two@example.test").json()["challenge_id"]
        second_code = self.code()
        self.assertEqual(self.verify(first, first_code).status_code, 201)
        loser = self.verify(second, second_code)
        self.assertEqual((loser.status_code, loser.json()["error"]), (422, "Username already exists."))
        self.assertEqual(self.users(), 1)

    def test_pending_registrations_are_bounded(self):
        service = RegistrationService(self.session, self.otp_service(), store=self.pending, max_pending=3)
        for index in range(3):
            service.start(f"user{index}", f"user{index}@example.test", PASSWORD)
        with self.assertRaises(MFAError) as raised:
            service.start("user3", "user3@example.test", PASSWORD)
        self.assertEqual((raised.exception.code, raised.exception.status_code), ("REGISTRATION_UNAVAILABLE", 503))
        self.clock.advance(minutes=21)
        service.start("user3", "user3@example.test", PASSWORD)
        self.assertEqual((len(self.pending), self.users()), (1, 0))

    # Scale: 100 failed attempts create nothing; the system stays responsive.
    def test_one_hundred_failed_registrations_create_no_accounts(self):
        self.settings = smtp_settings(**NO_SMTP)
        began = time.monotonic()
        for index in range(100):
            response = self.register(username=f"user{index}", email=f"user{index}@example.test")
            self.assertEqual(response.json()["code"], "MFA_NOT_CONFIGURED")
        for _ in range(100):
            self.assertEqual(self.register().json()["code"], "MFA_NOT_CONFIGURED")
        elapsed = time.monotonic() - began
        self.assertEqual((self.users(), len(self.pending), len(self.challenges), FakeSMTP.outbox), (0, 0, 0, []))
        self.assertLess(elapsed, 30, "failed registrations should stay cheap")
        self.settings = smtp_settings()
        self.complete()
        self.complete(username="user42", email="user42@example.test")
        self.assertEqual(self.users(), 2)

    def test_successful_registration_loop_creates_one_account_each(self):
        for index in range(10):
            self.complete(username=f"member{index}", email=f"member{index}@example.test")
        emails = self.session.scalars(select(User.email)).all()
        self.assertEqual(sorted(emails), sorted(f"member{index}@example.test" for index in range(10)))
        self.assertEqual((len(self.pending), len(self.challenges)), (0, 0))


class CleanupUnverifiedUsersTests(unittest.TestCase):
    """scripts/cleanup_unverified_users.py removes only orphaned analysts, never the admin or users with data."""

    def setUp(self):
        import importlib.util
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        path = Path(__file__).resolve().parents[1] / "scripts" / "cleanup_unverified_users.py"
        spec = importlib.util.spec_from_file_location("cleanup_unverified_users_under_test", path)
        self.script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.script)
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.factory = sessionmaker(bind=engine, expire_on_commit=False)
        self.config = smtp_settings(ENVIRONMENT="development", ADMIN_EMAIL="Owner@Example.test")
        self.patches = [
            patch.object(self.script, "get_session", self.factory),
            patch.object(self.script, "get_engine", MagicMock()),
            patch.object(self.script, "get_settings", lambda: self.config),
        ]
        for item in self.patches:
            item.start()
        before, after = datetime(2026, 10, 4, 18, 0), datetime(2026, 10, 4, 20, 20)
        from backend.database.models import Server
        with self.factory() as session:
            session.add_all([
                User(id="admin", username="admin", email="owner@example.test", hashed_password="x", role="ADMIN", created_at=before),
                User(id="orphan-1", username="yogesh23", email="y@example.test", hashed_password="x", role="ANALYST", created_at=after),
                User(id="orphan-2", username="demo1", email="d@example.test", hashed_password="x", role="ANALYST", created_at=after),
                User(id="old", username="older", email="o@example.test", hashed_password="x", role="ANALYST", created_at=before),
                User(id="member", username="member", email="m@example.test", hashed_password="x", role="ANALYST", account_id="acct", created_at=after),
                User(id="owner", username="owner", email="s@example.test", hashed_password="x", role="ANALYST", created_at=after),
                Server(server_name="vm", host="192.0.2.1", username="u", owner_id="owner", created_by="owner"),
            ])
            session.commit()

    def tearDown(self):
        for item in self.patches:
            item.stop()

    def run_script(self, *args):
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            code = self.script.main(["--created-after", "2026-10-04T18:32", *args])
        return code, out.getvalue()

    def usernames(self):
        with self.factory() as session:
            return sorted(session.scalars(select(User.username)).all())

    def test_dry_run_reports_and_changes_nothing(self):
        code, output = self.run_script()
        self.assertEqual(code, 0)
        self.assertIn("candidates: 2", output)
        self.assertIn("Dry run only", output)
        self.assertEqual(len(self.usernames()), 6)

    def test_deletes_only_orphaned_analysts(self):
        code, output = self.run_script("--yes")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.usernames(), ["admin", "member", "older", "owner"])

    def test_refuses_in_production(self):
        self.config = smtp_settings(ENVIRONMENT="production", ADMIN_EMAIL="owner@example.test")
        self.assertEqual(self.run_script("--yes")[0], 2)
        self.assertEqual(len(self.usernames()), 6)


if __name__ == "__main__":
    unittest.main()
