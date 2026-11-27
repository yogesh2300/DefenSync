"""Email sign-in, registration rules, admin bootstrap and the clean-skeleton reset.

SQLite in-memory only; the reset script and bootstrap are pointed at it with patches,
so the real PostgreSQL database is never touched.
"""

from __future__ import annotations

import importlib.util
import io
import logging
import re
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import auth as auth_api
from backend.api import events as events_api
from backend.api.dependencies import get_db
from backend.bootstrap import default_admin
from backend.core.config import Settings
from backend.core.exceptions import register_exception_handlers
from backend.core.security import hash_password, verify_password
from backend.database.models import Account, Alert, Base, Event, Incident, Server, User
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.services.registration_service import PendingRegistrationStore

ADMIN_PASSWORD = "Bootstrap-Admin-Secret-9"
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


def settings(**overrides):
    values = {
        "SECRET_KEY": SecretStr("email-login-test-key"),
        "ENVIRONMENT": "development",
        "SMTP_HOST": "smtp.example.test",
        "SMTP_FROM": "DefenSync <no-reply@example.test>",
        "SMTP_SECURITY": "starttls",
        "ADMIN_USERNAME": "admin",
        "ADMIN_EMAIL": "Owner@Example.test",
        "ADMIN_PASSWORD": SecretStr(ADMIN_PASSWORD),
        "DB_NAME": "sqlite-test",
        "DB_HOST": "memory",
        "DB_PORT": 0,
    }
    values.update(overrides)
    return Settings.model_construct(**values)


def new_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return engine


class RegistrationAndEmailLoginTests(unittest.TestCase):
    def setUp(self):
        Outbox.messages = []
        self.session = sessionmaker(bind=new_engine(), expire_on_commit=False)()
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        store = OTPChallengeStore()
        pending = PendingRegistrationStore()
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(settings(), store=store, smtp_factory=Outbox)
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: pending
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def register(self, **body):
        payload = {"username": "tejas", "email": "tejas@example.test", "password": "Strong-Password-1"}
        payload.update(body)
        return self.client.post("/api/v1/auth/register", json={k: v for k, v in payload.items() if v is not None})

    def complete_registration(self, **body):
        started = self.register(**body)
        self.assertEqual(started.status_code, 202, started.text)
        code = CODE_PATTERN.search(Outbox.messages[-1].get_content()).group(1)
        verified = self.client.post("/api/v1/auth/register/verify", json={"challenge_id": started.json()["challenge_id"], "otp": code})
        self.assertEqual(verified.status_code, 201, verified.text)
        return verified

    def login(self, email, password="Strong-Password-1"):
        return self.client.post("/api/v1/auth/token", data={"email": email, "password": password})

    def test_registration_requires_username_email_and_password(self):
        for missing in ("username", "email", "password"):
            self.assertEqual(self.register(**{missing: None}).status_code, 422, missing)
        self.assertEqual(self.session.scalar(select(func.count(User.id))), 0)

    def test_registration_validates_email_and_password_length(self):
        self.assertEqual(self.register(email="not-an-email").status_code, 422)
        self.assertEqual(self.register(password="short").status_code, 422)
        self.assertEqual(self.register(username="ab").status_code, 422)
        self.assertEqual(Outbox.messages, [])

    def test_username_and_email_are_unique(self):
        self.complete_registration()
        taken_name = self.register(email="other@example.test")
        taken_email = self.register(username="someone", email="TEJAS@example.test")
        self.assertEqual((taken_name.status_code, taken_name.json()["error"]), (422, "Username already exists."))
        self.assertEqual((taken_email.status_code, taken_email.json()["error"]), (422, "Email already exists."))

    def test_password_is_stored_only_as_a_hash(self):
        self.complete_registration()
        user = self.session.scalar(select(User))
        self.assertEqual((user.username, user.email, user.role), ("tejas", "tejas@example.test", "ANALYST"))
        for stored in (user.password_hash, user.hashed_password):
            self.assertNotEqual(stored, "Strong-Password-1")
            self.assertTrue(verify_password("Strong-Password-1", stored))

    def test_login_uses_email_not_username(self):
        self.complete_registration()
        sent = len(Outbox.messages)
        by_name = self.login("tejas")
        wrong = self.login("tejas@example.test", password="Wrong-Password-1")
        for response in (by_name, wrong):
            self.assertEqual((response.status_code, response.json()["error"]), (401, "Invalid email or password."))
            self.assertNotIn("challenge_id", response.json())
        self.assertEqual(len(Outbox.messages), sent)
        self.assertEqual(self.client.post("/api/v1/auth/token", data={"username": "tejas", "password": "Strong-Password-1"}).status_code, 422)

    def test_email_login_then_otp_yields_username_profile(self):
        self.complete_registration()
        challenge = self.login("  Tejas@Example.TEST ")
        self.assertEqual(challenge.status_code, 200, challenge.text)
        self.assertNotIn("access_token", challenge.json())
        self.assertEqual(challenge.json()["destination"], "t***@example.test")
        code = CODE_PATTERN.search(Outbox.messages[-1].get_content()).group(1)
        verified = self.client.post("/api/v1/auth/otp/verify", json={"challenge_id": challenge.json()["challenge_id"], "otp": code})
        token = verified.json()["access_token"]
        me = self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual((me.json()["username"], me.json()["email"]), ("tejas", "tejas@example.test"))


class AdminBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.engine = new_engine()
        self.factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.config = settings()
        self.patches = [
            patch.object(default_admin, "get_session", self.factory),
            patch.object(default_admin, "get_settings", lambda: self.config),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()

    def admins(self):
        with self.factory() as session:
            return session.execute(select(User.username, User.email, User.password_hash).where(User.role == "ADMIN")).all()

    def test_creates_configured_admin_once_with_hashed_password(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            default_admin.ensure_default_admin()
            default_admin.ensure_default_admin()
        finally:
            logging.getLogger().removeHandler(handler)
        admins = self.admins()
        self.assertEqual(len(admins), 1)
        username, email, digest = admins[0]
        self.assertEqual((username, email), ("admin", "owner@example.test"))
        self.assertNotEqual(digest, ADMIN_PASSWORD)
        self.assertTrue(verify_password(ADMIN_PASSWORD, digest))
        self.assertNotIn(ADMIN_PASSWORD, stream.getvalue())
        self.assertNotIn(ADMIN_PASSWORD, repr(default_admin.admin_config(self.config)))

    def test_does_not_create_a_second_admin_or_promote_users(self):
        with self.factory() as session:
            session.add(User(username="existing", email="existing@example.test", hashed_password="x", role="ADMIN"))
            session.add(User(username="analyst", email="owner@example.test", hashed_password="x", role="ANALYST"))
            session.commit()
        default_admin.ensure_default_admin()
        self.assertEqual([row[0] for row in self.admins()], ["existing"])

    def test_unconfigured_bootstrap_creates_nothing(self):
        self.config = settings(ADMIN_PASSWORD=SecretStr(""))
        default_admin.ensure_default_admin()
        self.assertEqual(self.admins(), [])
        self.config = settings(ADMIN_PASSWORD=SecretStr("short"))
        default_admin.ensure_default_admin()
        self.assertEqual(self.admins(), [])

    def test_password_changes_only_through_explicit_reset(self):
        default_admin.ensure_default_admin()
        self.config = settings(ADMIN_PASSWORD=SecretStr("Rotated-Admin-Secret-10"))
        default_admin.ensure_default_admin()
        self.assertTrue(verify_password(ADMIN_PASSWORD, self.admins()[0][2]))
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(default_admin.main(["--reset-password"]), 0)
        self.assertTrue(verify_password("Rotated-Admin-Secret-10", self.admins()[0][2]))
        self.assertNotIn("Rotated-Admin-Secret-10", out.getvalue())


class AdminPostMfaWorkspaceTests(unittest.TestCase):
    """Bootstrap admin: email + password -> OTP -> token that works in both workspaces and the admin API."""

    def setUp(self):
        Outbox.messages = []
        engine = new_engine()
        factory = sessionmaker(bind=engine, expire_on_commit=False)
        self.config = settings()
        with patch.object(default_admin, "get_session", factory), patch.object(default_admin, "get_settings", lambda: self.config):
            default_admin.ensure_default_admin()
        self.session = factory()
        now = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
        for index, source in enumerate(("LINUX", "CLOUD")):
            self.session.add(Event(
                event_id=f"evt-{source}", timestamp=now, hostname="h", event_type="Activity", category="auth",
                severity="low", risk_score=1, message="m", raw_log="r", hash=f"hash-{index}",
                source_type=source, data_scope="PRIVATE",
            ))
        self.session.commit()
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.include_router(events_api.router, prefix="/api/v1/events")
        app.dependency_overrides[get_db] = lambda: self.session
        store = OTPChallengeStore()
        pending = PendingRegistrationStore()
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(self.config, store=store, smtp_factory=Outbox)
        app.dependency_overrides[auth_api.get_pending_registrations] = lambda: pending
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def sign_in(self, email, password):
        challenge = self.client.post("/api/v1/auth/token", data={"email": email, "password": password})
        self.assertEqual(challenge.status_code, 200, challenge.text)
        self.assertNotIn("access_token", challenge.json())
        code = CODE_PATTERN.search(Outbox.messages[-1].get_content()).group(1)
        verified = self.client.post("/api/v1/auth/otp/verify", json={"challenge_id": challenge.json()["challenge_id"], "otp": code})
        self.assertEqual(verified.status_code, 200, verified.text)
        return {"Authorization": f"Bearer {verified.json()['access_token']}"}

    def test_admin_password_and_otp_yield_an_admin_session(self):
        headers = self.sign_in("owner@example.test", ADMIN_PASSWORD)
        me = self.client.get("/api/v1/auth/me", headers=headers).json()
        self.assertEqual((me["username"], me["role"]), ("admin", "ADMIN"))
        self.assertEqual(self.client.get("/api/v1/auth/me").status_code, 401)

    def test_admin_workspace_reads_follow_the_selected_environment(self):
        headers = self.sign_in("owner@example.test", ADMIN_PASSWORD)
        for environment in ("LINUX", "CLOUD"):
            rows = self.client.get("/api/v1/events/recent", params={"environment": environment, "limit": 50}, headers=headers)
            self.assertEqual(rows.status_code, 200, rows.text)
            self.assertEqual({row["source_type"] for row in rows.json()}, {environment})

    def test_admin_keeps_admin_only_api_and_analysts_are_refused(self):
        admin_headers = self.sign_in("owner@example.test", ADMIN_PASSWORD)
        users = self.client.get("/api/v1/auth/users", headers=admin_headers)
        self.assertEqual(users.status_code, 200, users.text)
        self.assertIn("admin", [row["username"] for row in users.json()])
        started = self.client.post("/api/v1/auth/register", json={"username": "tejas", "email": "tejas@example.test", "password": "Strong-Password-1"})
        code = CODE_PATTERN.search(Outbox.messages[-1].get_content()).group(1)
        self.client.post("/api/v1/auth/register/verify", json={"challenge_id": started.json()["challenge_id"], "otp": code})
        analyst_headers = self.sign_in("tejas@example.test", "Strong-Password-1")
        self.assertEqual(self.client.get("/api/v1/auth/users", headers=analyst_headers).status_code, 403)


def load_reset_script():
    path = Path(__file__).resolve().parents[1] / "scripts" / "reset_skeleton.py"
    spec = importlib.util.spec_from_file_location("reset_skeleton_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SkeletonResetTests(unittest.TestCase):
    def setUp(self):
        self.engine = new_engine()
        self.factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.reset = load_reset_script()
        self.config = settings()
        self.patches = [
            patch.object(self.reset, "get_session", self.factory),
            patch.object(self.reset, "get_engine", MagicMock()),
            patch.object(self.reset, "get_settings", lambda: self.config),
        ]
        for item in self.patches:
            item.start()
        now = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
        with self.factory() as session:
            session.add_all([
                Account(id="acct", name="Old"),
                User(id="old-admin", username="admin", email="admin@defensync.local", hashed_password="x", role="ADMIN"),
                User(id="old-analyst", username="analyst_1234", email="a@example.test", hashed_password="x", role="ANALYST"),
                Server(server_name="vm", host="10.0.0.1", username="u"),
                Event(event_id="e1", timestamp=now, hostname="h", event_type="Failed Login", category="auth", severity="low",
                      risk_score=1, message="m", raw_log="r", hash="h1"),
                Alert(event_id="e1", title="t", message="m", severity="low", risk_score=1),
                Incident(incident_id="INC-1", title="t"),
            ])
            session.commit()

    def tearDown(self):
        for item in self.patches:
            item.stop()

    def run_reset(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = self.reset.main(list(args))
        return code, out.getvalue() + err.getvalue()

    def count(self, model):
        with self.factory() as session:
            return session.scalar(select(func.count()).select_from(model))

    def test_dry_run_changes_nothing(self):
        code, output = self.run_reset()
        self.assertEqual(code, 0)
        self.assertIn("Dry run only", output)
        self.assertEqual((self.count(User), self.count(Event), self.count(Server)), (2, 1, 1))

    def test_reset_leaves_exactly_the_configured_admin(self):
        code, output = self.run_reset("--yes")
        self.assertEqual(code, 0, output)
        for model in (Account, Server, Event, Alert, Incident):
            self.assertEqual(self.count(model), 0, model.__tablename__)
        with self.factory() as session:
            users = session.execute(select(User.username, User.email, User.role, User.password_hash)).all()
        self.assertEqual([(u, e, r) for u, e, r, _ in users], [("admin", "owner@example.test", "ADMIN")])
        self.assertTrue(verify_password(ADMIN_PASSWORD, users[0][3]))
        self.assertNotIn(ADMIN_PASSWORD, output)

    def test_second_reset_keeps_the_same_admin_row(self):
        self.run_reset("--yes")
        with self.factory() as session:
            first = session.scalar(select(User.id))
        code, output = self.run_reset("--yes")
        self.assertEqual(code, 0, output)
        self.assertIn("kept", output)
        with self.factory() as session:
            self.assertEqual(session.scalars(select(User.id)).all(), [first])

    def test_refuses_without_replacement_admin_or_in_production(self):
        self.config = settings(ADMIN_EMAIL="")
        self.assertEqual(self.run_reset("--yes")[0], 2)
        self.config = settings(ENVIRONMENT="production")
        self.assertEqual(self.run_reset("--yes")[0], 2)
        self.assertEqual((self.count(User), self.count(Event)), (2, 1))


if __name__ == "__main__":
    unittest.main()
