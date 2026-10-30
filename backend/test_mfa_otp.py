"""Step 2A: OTP second factor after password login, plus environment-scoped authorization.

Email delivery uses an in-memory SMTP double; no network, no real mailbox. SQLite in-memory only.
"""

from __future__ import annotations

import io
import logging
import re
import smtplib
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import account as account_api
from backend.api import alerts as alerts_api
from backend.api import auth as auth_api
from backend.api import cloud as cloud_api
from backend.api import dashboard as dashboard_api
from backend.api import events as events_api
from backend.api import intelligence as intelligence_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.config import Settings, get_settings
from backend.core.exceptions import register_exception_handlers
from backend.core.security import create_access_token, hash_password
from backend.database.models import DATA_SCOPE_GLOBAL, DATA_SCOPE_PRIVATE, Account, Alert, Base, Event, Server, User
from backend.services.cloud.azure_collector import LAST_RUN, STATUS_COLLECTION_OK, STATUS_CONFIGURED
from backend.services.correlation_service import CorrelationService
from backend.services.mfa.otp_service import OTPChallengeStore, OTPService
from backend.services.mfa.providers import EmailOTPProvider, SMSOTPProvider

PASSWORD = "Correct-Horse-Battery-1"
SMTP_SECRET = "smtp-app-password-do-not-leak"
EMAIL = "yogesh@example.test"
CODE_PATTERN = re.compile(r"verification code is: (\d{6})")


class FakeSMTP:
    """Stands in for smtplib.SMTP; keeps delivered messages in memory."""

    outbox: list = []
    fail: str | None = None

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        return None

    def login(self, username, password):
        if FakeSMTP.fail == "auth":
            raise smtplib.SMTPAuthenticationError(535, f"rejected {username}:{password}".encode())

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


def mfa_settings(**overrides):
    values = {
        "SECRET_KEY": SecretStr("unit-test-signing-key"),
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": 587,
        "SMTP_USERNAME": "mailer@example.test",
        "SMTP_PASSWORD": SecretStr(SMTP_SECRET),
        "SMTP_FROM": "DefenSync <no-reply@example.test>",
        "SMTP_SECURITY": "starttls",
    }
    values.update(overrides)
    return Settings.model_construct(**values)


def session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


class OTPAuthTests(unittest.TestCase):
    def setUp(self):
        FakeSMTP.outbox = []
        FakeSMTP.fail = None
        self.clock = Clock()
        self.store = OTPChallengeStore()
        self.settings = mfa_settings()
        self.session = session_factory()
        self.session.add(User(id="user-1", username="yogesh", email=EMAIL, hashed_password=hash_password(PASSWORD), role="ANALYST", account_id="acct-a"))
        self.session.commit()
        self.responses: list[str] = []
        self.client = self._client()

    def tearDown(self):
        self.session.close()

    def _client(self):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(auth_api.router, prefix="/api/v1/auth")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[auth_api.get_otp_service] = lambda: OTPService(
            self.settings, store=self.store, clock=self.clock, smtp_factory=FakeSMTP,
        )
        return TestClient(app)

    def _record(self, response):
        self.responses.append(response.text)
        return response

    def login(self, password=PASSWORD, email=EMAIL):
        return self._record(self.client.post("/api/v1/auth/token", data={"email": email, "password": password}))

    def verify(self, challenge_id, otp):
        return self._record(self.client.post("/api/v1/auth/otp/verify", json={"challenge_id": challenge_id, "otp": otp}))

    def resend(self, challenge_id):
        return self._record(self.client.post("/api/v1/auth/otp/send", json={"challenge_id": challenge_id}))

    def me(self, token):
        return self.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    @staticmethod
    def code(index=-1):
        return CODE_PATTERN.search(FakeSMTP.outbox[index].get_content()).group(1)

    def start(self):
        response = self.login()
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["challenge_id"]

    def wrong(self, challenge_id):
        real = self.code()
        return "000000" if real != "000000" else "111111"

    def test_a_correct_password_requires_otp_and_issues_no_token(self):
        response = self.login()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["otp_required"])
        self.assertNotIn("access_token", body)
        self.assertEqual((body["delivery"], body["destination"]), ("EMAIL", "y***@example.test"))
        self.assertEqual(body["channels"], [{"channel": "EMAIL", "destination": "y***@example.test"}])
        self.assertEqual((body["expires_in"], body["attempts_remaining"]), (300, 5))
        self.assertEqual(len(FakeSMTP.outbox), 1)
        self.assertEqual(FakeSMTP.outbox[0]["To"], EMAIL)
        self.assertEqual(self.me(body["challenge_id"]).status_code, 401)

    def test_b_incorrect_password_creates_no_challenge_or_session(self):
        for email, password in ((EMAIL, "wrong-password-123"), ("nobody@example.test", PASSWORD), ("yogesh", PASSWORD)):
            response = self.login(password=password, email=email)
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("challenge_id", response.json())
            self.assertNotIn("access_token", response.json())
        self.assertEqual(FakeSMTP.outbox, [])
        self.assertEqual(len(self.store), 0)

    def test_c_correct_otp_completes_authentication(self):
        challenge_id = self.start()
        response = self.verify(challenge_id, self.code())
        self.assertEqual(response.status_code, 200)
        token = response.json()["access_token"]
        profile = self.me(token)
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.json()["username"], "yogesh")
        claims = jwt.get_unverified_claims(token)
        self.assertEqual(claims["amr"], ["pwd", "otp"])

    def test_d_incorrect_otp_fails(self):
        challenge_id = self.start()
        response = self.verify(challenge_id, self.wrong(challenge_id))
        self.assertEqual(response.status_code, 401)
        self.assertEqual((response.json()["code"], response.json()["attempts_remaining"]), ("OTP_INVALID", 4))
        self.assertNotIn("access_token", response.json())
        self.assertEqual(self.verify(challenge_id, "12ab56").json()["code"], "OTP_INVALID")

    def test_e_expired_otp_fails(self):
        challenge_id = self.start()
        code = self.code()
        self.clock.advance(minutes=5, seconds=1)
        expired = self.verify(challenge_id, code)
        self.assertEqual((expired.status_code, expired.json()["code"]), (401, "OTP_EXPIRED"))
        self.assertNotIn("access_token", expired.json())
        self.assertNotEqual(self.verify(challenge_id, code).status_code, 200)
        self.assertEqual(self.resend(challenge_id).status_code, 200)
        self.assertEqual(self.verify(challenge_id, self.code()).status_code, 200)

    def test_f_otp_cannot_be_reused(self):
        challenge_id = self.start()
        code = self.code()
        self.assertEqual(self.verify(challenge_id, code).status_code, 200)
        reused = self.verify(challenge_id, code)
        self.assertEqual((reused.status_code, reused.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))

    def test_g_too_many_attempts_invalidate_challenge(self):
        challenge_id = self.start()
        wrong = self.wrong(challenge_id)
        for remaining in (4, 3, 2, 1):
            self.assertEqual(self.verify(challenge_id, wrong).json()["attempts_remaining"], remaining)
        locked = self.verify(challenge_id, wrong)
        self.assertEqual((locked.status_code, locked.json()["code"]), (429, "OTP_TOO_MANY_ATTEMPTS"))
        after = self.verify(challenge_id, self.code())
        self.assertEqual((after.status_code, after.json()["code"]), (401, "OTP_CHALLENGE_INVALID"))
        self.assertEqual(len(self.store), 0)

    def test_h_resend_cooldown_and_send_limit(self):
        challenge_id = self.start()
        first = self.code()
        early = self.resend(challenge_id)
        self.assertEqual((early.status_code, early.json()["code"], early.json()["retry_after"]), (429, "OTP_RESEND_COOLDOWN", 120))
        self.assertEqual(self.login().json()["code"], "OTP_RESEND_COOLDOWN")
        self.assertEqual(len(FakeSMTP.outbox), 1)
        self.clock.advance(seconds=121)
        resent = self.resend(challenge_id)
        self.assertEqual(resent.status_code, 200)
        self.assertEqual((len(FakeSMTP.outbox), resent.json()["sends_remaining"]), (2, 1))
        second = self.code()
        if second != first:
            self.assertEqual(self.verify(challenge_id, first).json()["code"], "OTP_INVALID")
        self.clock.advance(seconds=121)
        self.assertEqual(self.resend(challenge_id).status_code, 200)
        self.clock.advance(seconds=121)
        limited = self.resend(challenge_id)
        self.assertEqual((limited.status_code, limited.json()["code"]), (429, "OTP_RESEND_LIMIT"))
        self.assertEqual(len(FakeSMTP.outbox), 3)

    def test_i_otp_is_never_returned_by_the_api(self):
        challenge_id = self.start()
        codes = {self.code()}
        hashes = {self.store.get(challenge_id).code_hash}
        self.verify(challenge_id, self.wrong(challenge_id))
        self.clock.advance(seconds=121)
        self.resend(challenge_id)
        codes.add(self.code())
        hashes.add(self.store.get(challenge_id).code_hash)
        self.verify(challenge_id, self.code())
        self.assertEqual(len(hashes), 2)
        for text in self.responses:
            for secret in codes | hashes:
                self.assertNotIn(secret, text)

    def test_j_otp_is_never_logged(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            challenge_id = self.start()
            self.verify(challenge_id, self.wrong(challenge_id))
            self.verify(challenge_id, self.code())
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        logs = stream.getvalue()
        self.assertIn("OTP challenge created for user user-1", logs)
        self.assertIn("OTP verification successful for user user-1", logs)
        self.assertNotIn(self.code(), logs)

    def test_k_secrets_are_not_exposed(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            challenge_id = self.start()
            code = self.code()
            token = self.verify(challenge_id, code).json()["access_token"]
            FakeSMTP.fail = "auth"
            self.clock.advance(minutes=1)
            failed = self.login()
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertEqual((failed.status_code, failed.json()["code"]), (503, "OTP_DELIVERY_FAILED"))
        signing_key = get_settings().SECRET_KEY.get_secret_value()
        provider = EmailOTPProvider(self.settings, FakeSMTP)
        surfaces = self.responses + [stream.getvalue(), repr(provider), repr(OTPService(self.settings, store=self.store))]
        for text in surfaces:
            self.assertNotIn(SMTP_SECRET, text)
            self.assertNotIn(signing_key, text)
        self.assertNotIn(code, str(jwt.get_unverified_claims(token)))
        self.assertEqual(len(self.store), 0)

    def test_password_only_token_is_rejected(self):
        legacy = create_access_token({"sub": "yogesh", "role": "ANALYST"})
        response = self.me(legacy)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Two-factor", response.json()["error"])

    def test_missing_delivery_configuration_refuses_login(self):
        self.settings = mfa_settings(SMTP_HOST="", SMTP_FROM="")
        response = self.login()
        self.assertEqual((response.status_code, response.json()["code"]), (503, "MFA_NOT_CONFIGURED"))
        self.assertNotIn("access_token", response.json())
        self.assertEqual(len(self.store), 0)

    def test_delivery_failure_creates_no_usable_challenge(self):
        FakeSMTP.fail = "down"
        response = self.login()
        self.assertEqual((response.status_code, response.json()["code"]), (503, "OTP_DELIVERY_FAILED"))
        self.assertEqual(len(self.store), 0)

    def test_challenge_stores_only_a_hash(self):
        challenge_id = self.start()
        challenge = self.store.get(challenge_id)
        code = self.code()
        self.assertNotIn(code, [str(value) for value in vars(challenge).values()])
        self.assertEqual(len(challenge.code_hash), 64)

    def test_email_message_content(self):
        self.start()
        message = FakeSMTP.outbox[0]
        body = message.get_content()
        self.assertEqual(message["Subject"], "DefenSync verification code")
        self.assertIn("This code expires in 5 minutes.", body)
        self.assertIn("If you did not attempt to sign in, ignore this email.", body)
        self.assertNotIn(PASSWORD, body)

    def test_sms_is_never_offered_without_a_provider(self):
        for provider_name in ("", "twilio"):
            sms = SMSOTPProvider(mfa_settings(SMS_PROVIDER=provider_name))
            self.assertEqual(sms.status(), {"channel": "SMS", "configured": False, "reason": "SMS provider not configured"})
        statuses = OTPService(self.settings, store=self.store).provider_status()
        self.assertEqual([item["channel"] for item in statuses if item["configured"]], ["EMAIL"])
        self.assertEqual(sms.mask("+91 9876541234"), "+91 ******1234")
        self.assertEqual(self.login().json()["channels"], [{"channel": "EMAIL", "destination": "y***@example.test"}])

    def test_unencrypted_smtp_only_to_local_relay(self):
        remote = EmailOTPProvider(mfa_settings(SMTP_SECURITY="none"))
        local = EmailOTPProvider(mfa_settings(SMTP_SECURITY="none", SMTP_HOST="127.0.0.1", SMTP_USERNAME=""))
        self.assertIsNotNone(remote.unavailable_reason())
        self.assertIsNone(local.unavailable_reason())


ACCOUNT_A, ACCOUNT_B = "acct-a", "acct-b"


class EnvironmentAuthorizationTests(unittest.TestCase):
    def setUp(self):
        LAST_RUN.clear()
        self.session = session_factory()
        self.users = {
            "a": User(id="analyst-a", username="analyst_a", email="a@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
            "b": User(id="analyst-b", username="analyst_b", email="b@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_B),
            "admin": User(id="admin-1", username="admin", email="admin@example.test", hashed_password="x", role="ADMIN"),
            "solo": User(id="analyst-solo", username="solo", email="solo@example.test", hashed_password="x", role="ANALYST"),
        }
        self.session.add_all([Account(id=ACCOUNT_A, name="A"), Account(id=ACCOUNT_B, name="B"), *self.users.values()])
        self.session.add_all([
            Server(id="server-a", server_name="vm-a", host="10.0.0.1", username="u", owner_id="analyst-a", account_id=ACCOUNT_A),
            Server(id="server-b", server_name="vm-b", host="10.0.0.2", username="u", owner_id="analyst-b", account_id=ACCOUNT_B),
        ])
        self._event("linux-a1", "LINUX", None, ACCOUNT_A, "analyst-a", server="server-a")
        self._event("linux-a2", "LINUX", None, ACCOUNT_A, "analyst-a", server="server-a")
        self._event("linux-b1", "LINUX", None, ACCOUNT_B, "analyst-b", server="server-b")
        self._event("azure-a1", "CLOUD", "AZURE", ACCOUNT_A, "admin-1", origin="AZURE_LOG_ANALYTICS")
        self._event("azure-b1", "CLOUD", "AZURE", ACCOUNT_B, "admin-1", origin="AZURE_LOG_ANALYTICS")
        self._event("openstack-g", "CLOUD", "OPENSTACK", None, None, origin="PUBLIC_DATASET", scope=DATA_SCOPE_GLOBAL)
        for event_id, owner, account, server in (
            ("linux-a1", "analyst-a", ACCOUNT_A, "server-a"),
            ("azure-a1", "analyst-a", ACCOUNT_A, None),
            ("azure-b1", "analyst-b", ACCOUNT_B, None),
        ):
            self.session.add(Alert(id=f"alert-{event_id}", event_id=event_id, owner_id=owner, account_id=account, server_id=server,
                                   title=event_id, message="m", severity="high", risk_score=80))
        self.session.commit()

    def tearDown(self):
        LAST_RUN.clear()
        self.session.close()

    def _event(self, event_id, source_type, provider, account, owner, *, server=None, origin="LIVE_LINUX", scope=DATA_SCOPE_PRIVATE):
        self.session.add(Event(
            event_id=event_id, timestamp=datetime(2026, 10, 4, 8, 0, tzinfo=timezone.utc), hostname="h", username="u",
            event_type="CLOUD_LOGIN_FAILURE" if source_type == "CLOUD" else "Failed Login", category="auth", severity="high",
            risk_score=80, message=event_id, raw_log=event_id, hash=f"hash-{event_id}", owner_id=owner, account_id=account,
            server_id=server, data_scope=scope, source_type=source_type, provider=provider, data_origin=origin,
        ))

    def client(self, who):
        app = FastAPI()
        register_exception_handlers(app)
        for router, prefix in ((events_api.router, "/api/v1/events"), (alerts_api.router, "/api/v1/alerts"),
                               (account_api.router, "/api/v1/account"), (intelligence_api.router, "/api/v1/intelligence"),
                               (cloud_api.router, "/api/v1/cloud"), (dashboard_api.router, "/api/v1/dashboard")):
            app.include_router(router, prefix=prefix)
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.users[who]
        app.dependency_overrides[cloud_api.get_azure_settings] = lambda: Settings.model_construct(
            SECRET_KEY=SecretStr("k"), AZURE_TENANT_ID="11111111-2222-3333-4444-555555555555",
            AZURE_CLIENT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AZURE_CLIENT_SECRET=SecretStr("s"),
            AZURE_LOG_ANALYTICS_WORKSPACE_ID="99999999-8888-7777-6666-555555555555",
        )
        return TestClient(app)

    @staticmethod
    def ids(response):
        assert response.status_code == 200, response.text
        return sorted(row.get("event_id") for row in response.json())

    def test_u_events_follow_environment(self):
        api = self.client("a")
        self.assertEqual(self.ids(api.get("/api/v1/events", params={"environment": "CLOUD"})), ["azure-a1"])
        self.assertEqual(self.ids(api.get("/api/v1/events", params={"environment": "LINUX"})), ["linux-a1", "linux-a2"])
        self.assertEqual(self.ids(api.get("/api/v1/events")), ["azure-a1", "linux-a1", "linux-a2"])
        self.assertEqual(api.get("/api/v1/events", params={"environment": "MARS"}).status_code, 422)

    def test_v_alerts_follow_environment(self):
        api = self.client("a")
        self.assertEqual(self.ids(api.get("/api/v1/alerts", params={"environment": "CLOUD"})), ["azure-a1"])
        self.assertEqual(self.ids(api.get("/api/v1/alerts", params={"environment": "LINUX"})), ["linux-a1"])
        self.assertEqual(self.ids(api.get("/api/v1/alerts")), ["azure-a1", "linux-a1"])

    def test_w_incidents_follow_environment(self):
        rows = [{"incident_id": "i-linux", "environment": "LINUX"}, {"incident_id": "i-cloud", "environment": "CLOUD"},
                {"incident_id": "i-legacy", "environment": None}]
        with patch.object(CorrelationService, "list_incidents", return_value=rows) as listed:
            api = self.client("a")
            cloud = api.get("/api/v1/intelligence/incidents", params={"environment": "CLOUD", "limit": 5}).json()
            linux = api.get("/api/v1/intelligence/incidents", params={"environment": "LINUX"}).json()
        self.assertEqual([row["incident_id"] for row in cloud], ["i-cloud"])
        self.assertEqual([row["incident_id"] for row in linux], ["i-linux", "i-legacy"])
        self.assertEqual(listed.call_args.kwargs["account_id"], ACCOUNT_A)

    def test_x_account_summary_follows_environment(self):
        api = self.client("a")
        self.assertEqual(api.get("/api/v1/account/summary", params={"environment": "CLOUD"}).json()["events"], 1)
        self.assertEqual(api.get("/api/v1/account/summary", params={"environment": "LINUX"}).json()["events"], 2)

    def test_y_environment_cannot_bypass_account_ownership(self):
        api = self.client("a")
        self.assertEqual(api.get("/api/v1/account/summary", params={"environment": "CLOUD", "account_id": ACCOUNT_B}).status_code, 403)
        self.assertEqual(self.ids(api.get("/api/v1/events", params={"environment": "CLOUD", "account_id": ACCOUNT_B})), ["azure-a1"])
        both = self.ids(api.get("/api/v1/events", params={"environment": "CLOUD", "scope": "both"}))
        self.assertEqual(both, ["azure-a1", "openstack-g"])

    def test_z_user_cannot_see_another_accounts_cloud_data(self):
        b = self.client("b")
        self.assertEqual(self.ids(b.get("/api/v1/events", params={"environment": "CLOUD"})), ["azure-b1"])
        self.assertEqual(self.ids(b.get("/api/v1/alerts", params={"environment": "CLOUD"})), ["azure-b1"])
        LAST_RUN.set({"status": STATUS_COLLECTION_OK, "account_id": ACCOUNT_A, "records_inserted": 7})
        hidden = b.get("/api/v1/cloud/azure/status").json()
        self.assertEqual((hidden["last_collection"], hidden["status"]), (None, STATUS_CONFIGURED))
        own = self.client("a").get("/api/v1/cloud/azure/status").json()
        self.assertEqual((own["last_collection"]["records_inserted"], own["status"]), (7, STATUS_COLLECTION_OK))
        self.assertEqual(self.client("admin").get("/api/v1/cloud/azure/status").json()["last_collection"]["account_id"], ACCOUNT_A)

    def test_aa_linux_authorization_unchanged(self):
        api = self.client("a")
        self.assertEqual(api.get("/api/v1/events", params={"server_id": "server-b"}).status_code, 403)
        self.assertEqual(api.get("/api/v1/alerts", params={"server_id": "server-b"}).status_code, 403)
        self.assertEqual(self.ids(api.get("/api/v1/events", params={"server_id": "server-a", "environment": "LINUX"})), ["linux-a1", "linux-a2"])
        self.assertEqual(self.ids(self.client("b").get("/api/v1/events", params={"environment": "LINUX"})), ["linux-b1"])

    def test_dashboard_fleet_counts_never_include_other_accounts(self):
        def servers(who, environment):
            body = self.client(who).get("/api/v1/dashboard", params={"environment": environment}).json()
            return body["total_servers"], body["total_events"]

        self.assertEqual(servers("solo", "LINUX"), (0, 0))
        self.assertEqual(servers("solo", "CLOUD"), (0, 0))
        self.assertEqual(servers("a", "LINUX"), (1, 2))
        self.assertEqual(servers("a", "CLOUD"), (1, 1))
        self.assertEqual(servers("admin", "LINUX")[0], 2)


if __name__ == "__main__":
    unittest.main()
