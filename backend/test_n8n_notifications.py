"""n8n incident notification: qualification, payload, failure isolation, idempotency, endpoint auth.

The HTTP call is always replaced by an in-process fake opener; no test contacts a real n8n.
"""

from __future__ import annotations

import io
import json
import logging
import socket
import threading
import time
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import intelligence as intelligence_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.config import Settings
from backend.core.exceptions import register_exception_handlers
from backend.database.models import DATA_SCOPE_PRIVATE, Base, Event, Incident, User
from backend.services import n8n_notifier
from backend.services.correlation_service import CorrelationService
from backend.services.n8n_notifier import (
    EVENT_CREATED,
    EVENT_ESCALATED,
    EVENT_TEST,
    REASON_NO_VERIFIED_RECIPIENT,
    SCHEMA_VERSION,
    STATUS_FAILED,
    STATUS_NOT_CONFIGURED,
    STATUS_SENT,
    STATUS_SKIPPED,
    N8nNotifier,
    build_payload,
    notification_event,
    resolve_owner_recipient_emails,
)

T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
WEBHOOK_URL = "https://n8n.example.test/webhook/secret-path-0f3c"
AUTH_TOKEN = "header-token-value-7d21"
SMTP_SECRET = "smtp-password-should-never-leak"
OWNER_EMAIL = "owner1@example.test"
OTHER_ACCOUNT_EMAIL = "other-account@example.test"
OWNER_ID = "owner-1"
ACCOUNT_A = "acct-a"
ACCOUNT_B = "acct-b"


class FakeOpener:
    """Stands in for the HTTP transport; records every request."""

    def __init__(self, *, status: int = 200, error: BaseException | None = None, gate: threading.Event | None = None):
        self.status = status
        self.error = error
        self.gate = gate
        self.requests: list[dict] = []
        self.done = threading.Event()

    def __call__(self, request, timeout):
        if self.gate is not None:
            self.gate.wait(5)
        self.requests.append({
            "url": request.full_url,
            "method": request.get_method(),
            "headers": {key.lower(): value for key, value in request.header_items()},
            "body": json.loads(request.data.decode("utf-8")),
            "raw": request.data.decode("utf-8"),
            "timeout": timeout,
        })
        self.done.set()
        if self.error is not None:
            raise self.error
        return self.status

    @property
    def payloads(self) -> list[dict]:
        return [item["body"] for item in self.requests]


def notifier(opener: FakeOpener | None = None, *, url: str = WEBHOOK_URL, background: bool = False, **kwargs) -> N8nNotifier:
    return N8nNotifier(url, opener=opener or FakeOpener(), background=background, **kwargs)


def new_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def ensure_owner(session, *, owner_id=OWNER_ID, email=OWNER_EMAIL, account_id=None):
    existing = session.get(User, owner_id)
    if existing is None:
        session.add(
            User(
                id=owner_id,
                username=f"user-{owner_id}",
                email=email,
                hashed_password="x",
                role="ANALYST",
                account_id=account_id,
            )
        )
        session.commit()
        return
    existing.email = email
    existing.account_id = account_id
    session.commit()


def persist(session, index, *, event_type, risk, actor="alice", minute=0, owner_id=OWNER_ID, account_id=None):
    session.add(Event(
        event_id=f"evt-{index}",
        timestamp=T0 + timedelta(minutes=minute),
        hostname="host",
        username=actor,
        actor_id=actor,
        event_type=event_type,
        category="test",
        severity="high" if risk >= 70 else "info",
        risk_score=risk,
        message=f"{event_type} raw-message-{index}",
        raw_log=f"RAW-LOG-LINE-{index} password=hunter2",
        hash=f"hash-{index}",
        owner_id=owner_id,
        account_id=account_id,
        data_scope=DATA_SCOPE_PRIVATE,
        source_type="LINUX",
        data_origin="LIVE_LINUX",
    ))
    session.commit()


def seed(session, severity: str, *, actor="alice", start=0, account_id=None):
    """Two Linux events forming one incident of the requested correlation severity."""
    ensure_owner(session, account_id=account_id)
    if severity == "critical":
        persist(session, f"{actor}-1", event_type="Failed Login", risk=90, actor=actor, minute=start, account_id=account_id)
        persist(session, f"{actor}-2", event_type="Failed Login", risk=40, actor=actor, minute=start + 1, account_id=account_id)
    elif severity == "high":
        persist(session, f"{actor}-1", event_type="Failed Login", risk=75, actor=actor, minute=start, account_id=account_id)
        persist(session, f"{actor}-2", event_type="Failed Login", risk=40, actor=actor, minute=start + 1, account_id=account_id)
    else:
        persist(session, f"{actor}-1", event_type="Failed Login", risk=30, actor=actor, minute=start, account_id=account_id)
        persist(session, f"{actor}-2", event_type="Sudo Command", risk=30, actor=actor, minute=start + 1, account_id=account_id)


def correlate(session, n8n: N8nNotifier, *, owner_id=OWNER_ID, account_id=None):
    return CorrelationService(session, notifier=n8n).correlate_and_store(owner_id=owner_id, account_id=account_id)


def incident_count(session) -> int:
    return session.scalar(select(func.count(Incident.id)))


# ---------------------------------------------------------------- qualification


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_high_and_critical_incidents_trigger_webhook(severity):
    session = new_session()
    seed(session, severity)
    opener = FakeOpener()
    stored = correlate(session, notifier(opener))
    assert [row["severity"] for row in stored] == [severity]
    assert len(opener.requests) == 1
    body = opener.payloads[0]
    assert body["event"] == EVENT_CREATED
    assert body["incident"]["severity"] == severity.upper()
    assert body["incident"]["incident_id"] == stored[0]["incident_id"]
    assert opener.requests[0]["method"] == "POST" and opener.requests[0]["url"] == WEBHOOK_URL


def test_medium_incident_does_not_trigger_webhook():
    session = new_session()
    seed(session, "medium")
    opener = FakeOpener()
    stored = correlate(session, notifier(opener))
    assert [row["severity"] for row in stored] == ["medium"]
    assert opener.requests == []


def test_events_without_an_incident_send_nothing():
    session = new_session()
    persist(session, 1, event_type="Service Restart", risk=20)
    persist(session, 2, event_type="Service Restart", risk=25, minute=1)
    opener = FakeOpener()
    assert correlate(session, notifier(opener)) == []
    assert opener.requests == []


@pytest.mark.parametrize(
    ("previous", "new", "is_new", "expected"),
    [
        (None, "high", True, EVENT_CREATED),
        (None, "CRITICAL", True, EVENT_CREATED),
        (None, "medium", True, None),
        ("medium", "high", False, EVENT_ESCALATED),
        ("high", "critical", False, None),
        ("high", "high", False, None),
        ("critical", "medium", False, None),
        (None, "low", True, None),
    ],
)
def test_notification_event_rules(previous, new, is_new, expected):
    assert notification_event(previous, new, is_new=is_new) == expected


def test_escalation_of_existing_incident_sends_once():
    session = new_session()
    seed(session, "medium")
    opener = FakeOpener()
    correlate(session, notifier(opener))
    assert opener.requests == []
    event = session.scalar(select(Event).where(Event.event_id == "evt-alice-1"))
    event.risk_score = 78
    session.commit()
    stored = correlate(session, notifier(opener))
    assert stored[0]["severity"] == "high"
    assert [p["event"] for p in opener.payloads] == [EVENT_ESCALATED]
    correlate(session, notifier(opener))
    assert len(opener.requests) == 1


# ---------------------------------------------------------------- payload


def test_payload_contains_required_fields():
    session = new_session()
    seed(session, "critical")
    opener = FakeOpener()
    correlate(session, notifier(opener))
    body = opener.payloads[0]
    assert body["schema_version"] == SCHEMA_VERSION == "defensync-incident-v1"
    assert body["test"] is False and body["sent_at"]
    assert "no automatic action" in body["notice"]
    incident = body["incident"]
    for key in ("id", "incident_id", "title", "environment", "severity", "risk_score", "actor", "event_count",
                "start_time", "end_time", "evidence_summary", "recommendation", "sources", "status"):
        assert key in incident, key
    assert incident["id"] and incident["environment"] == "LINUX" and incident["actor"] == "alice"
    assert incident["event_count"] == 2
    assert incident["sources"] == ["Linux"]
    assert incident["evidence_summary"] and incident["recommendation"]
    assert body["notification"]["recipient_emails"] == [OWNER_EMAIL]
    assert set(body) == {"schema_version", "event", "test", "sent_at", "incident", "notification", "notice"}


def test_payload_excludes_credentials_raw_logs_and_identifiers():
    session = new_session()
    seed(session, "high")
    opener = FakeOpener()
    n8n = N8nNotifier(WEBHOOK_URL, auth_header="X-DefenSync-Token", auth_token=AUTH_TOKEN, opener=opener, background=False)
    correlate(session, n8n)
    request = opener.requests[0]
    raw = request["raw"]
    for secret in (AUTH_TOKEN, WEBHOOK_URL, SMTP_SECRET, "hunter2", "RAW-LOG-LINE", "raw-message", "evt-alice", "owner-1"):
        assert secret not in raw, secret
    for key in ("event_ids", "owner_id", "account_id", "raw_log", "password", "token", "secret", "otp", "timeline"):
        assert f'"{key}"' not in raw.lower(), key
    assert request["headers"]["x-defensync-token"] == AUTH_TOKEN
    assert request["headers"]["content-type"] == "application/json"
    assert request["body"]["notification"]["recipient_emails"] == [OWNER_EMAIL]


def test_build_payload_truncates_and_whitelists_fields():
    incident = {
        "id": "row-1", "incident_id": "inc-1", "title": "t" * 400, "severity": "high", "risk_score": 80,
        "source": "Linux", "event_ids": ["a", "b", "c"], "evidence": json.dumps(["e"] * 30),
        "explanation": "x" * 2000, "client_secret": "nope", "raw_log": "nope", "account_id": "acct",
    }
    body = build_payload(incident, event=EVENT_TEST, test=True, recipient_emails=[OWNER_EMAIL])
    assert body["test"] is True and body["event"] == EVENT_TEST
    assert len(body["incident"]["title"]) == 240 and len(body["incident"]["explanation"]) == 500
    assert len(body["incident"]["evidence_summary"]) == 10 and body["incident"]["event_count"] == 3
    assert body["notification"]["recipient_emails"] == [OWNER_EMAIL]
    assert "nope" not in json.dumps(body) and "acct" not in json.dumps(body)


def test_resolve_owner_recipient_requires_registered_owner():
    session = new_session()
    assert resolve_owner_recipient_emails(session, owner_id=None, account_id=None) == []
    assert resolve_owner_recipient_emails(session, owner_id=OWNER_ID, account_id=None) == []
    ensure_owner(session)
    assert resolve_owner_recipient_emails(session, owner_id=OWNER_ID, account_id=None) == [OWNER_EMAIL]


def test_resolve_owner_recipient_rejects_account_mismatch():
    session = new_session()
    ensure_owner(session, account_id=ACCOUNT_A)
    assert resolve_owner_recipient_emails(session, owner_id=OWNER_ID, account_id=ACCOUNT_A) == [OWNER_EMAIL]
    assert resolve_owner_recipient_emails(session, owner_id=OWNER_ID, account_id=ACCOUNT_B) == []
    assert resolve_owner_recipient_emails(session, owner_id=OWNER_ID, account_id=None) == [OWNER_EMAIL]


def test_valid_owner_email_is_the_only_notification_recipient():
    session = new_session()
    seed(session, "high", account_id=ACCOUNT_A)
    session.add(
        User(
            id="other-owner",
            username="other_owner",
            email=OTHER_ACCOUNT_EMAIL,
            hashed_password="x",
            role="ANALYST",
            account_id=ACCOUNT_B,
        )
    )
    session.commit()
    opener = FakeOpener()
    correlate(session, notifier(opener), account_id=ACCOUNT_A)
    assert opener.payloads[0]["notification"]["recipient_emails"] == [OWNER_EMAIL]
    assert OTHER_ACCOUNT_EMAIL not in opener.requests[0]["raw"]


def test_missing_owner_user_skips_notification_without_failing_storage():
    session = new_session()
    persist(session, "solo-1", event_type="Failed Login", risk=75, actor="bob", minute=0)
    persist(session, "solo-2", event_type="Failed Login", risk=40, actor="bob", minute=1)
    opener = FakeOpener()
    stored = correlate(session, notifier(opener))
    assert len(stored) == 1 and incident_count(session) == 1
    assert opener.requests == []


def test_account_mismatch_skips_notification():
    session = new_session()
    ensure_owner(session, account_id=ACCOUNT_A)
    persist(session, "m1", event_type="Failed Login", risk=75, actor="carol", minute=0, account_id=ACCOUNT_B)
    persist(session, "m2", event_type="Failed Login", risk=40, actor="carol", minute=1, account_id=ACCOUNT_B)
    opener = FakeOpener()
    # Correlate under account B while the owner user belongs to account A.
    stored = correlate(session, notifier(opener), account_id=ACCOUNT_B)
    assert len(stored) == 1 and incident_count(session) == 1
    assert opener.requests == []


def test_send_without_recipient_is_skipped():
    opener = FakeOpener()
    result = notifier(opener).send(build_payload({"incident_id": "i"}, event=EVENT_TEST))
    assert result.status == STATUS_SKIPPED and result.reason == REASON_NO_VERIFIED_RECIPIENT
    assert opener.requests == []


# ---------------------------------------------------------------- failure isolation


@pytest.mark.parametrize(
    ("error", "reason", "http_status"),
    [
        (socket.timeout("timed out"), "timeout", None),
        (urllib.error.URLError(TimeoutError("timed out")), "timeout", None),
        (urllib.error.URLError(ConnectionRefusedError("refused")), "unreachable (ConnectionRefusedError)", None),
        (urllib.error.HTTPError(WEBHOOK_URL, 404, "Not Found", {}, io.BytesIO()), "HTTP 404", 404),
        (urllib.error.HTTPError(WEBHOOK_URL, 503, "Unavailable", {}, io.BytesIO()), "HTTP 503", 503),
    ],
)
def test_delivery_failures_do_not_fail_incident_creation(error, reason, http_status):
    session = new_session()
    seed(session, "high")
    opener = FakeOpener(error=error)
    stored = correlate(session, notifier(opener))
    assert len(stored) == 1 and incident_count(session) == 1
    assert len(opener.requests) == 1
    result = n8n_notifier.last_delivery()
    assert result["status"] == STATUS_FAILED and result["reason"] == reason and result["http_status"] == http_status


@pytest.mark.parametrize("status", [400, 500])
def test_non_2xx_status_codes_are_failures(status):
    result = notifier(FakeOpener(status=status)).send(
        build_payload({"incident_id": "i", "severity": "high"}, event=EVENT_TEST, recipient_emails=[OWNER_EMAIL])
    )
    assert result.status == STATUS_FAILED and result.http_status == status and not result.delivered


def test_unreachable_n8n_skips_rest_of_batch_without_waiting():
    opener = FakeOpener(error=socket.timeout("timed out"))
    items = [
        ({"incident_id": f"i{n}", "severity": "high", "risk_score": 90 - n}, EVENT_CREATED, [OWNER_EMAIL])
        for n in range(3)
    ]
    results = notifier(opener).notify_incidents(items)
    assert len(opener.requests) == 1
    assert [r.status for r in results] == [STATUS_FAILED, STATUS_SKIPPED, STATUS_SKIPPED]


def test_per_run_cap_sends_highest_risk_first():
    opener = FakeOpener()
    items = [
        ({"incident_id": f"i{n}", "severity": "high", "risk_score": n}, EVENT_CREATED, [OWNER_EMAIL])
        for n in range(15)
    ]
    results = notifier(opener).notify_incidents(items)
    assert len(results) == n8n_notifier.MAX_PER_RUN == len(opener.requests)
    assert opener.payloads[0]["incident"]["risk_score"] == 14


def test_missing_webhook_url_does_not_fail_incident_creation(caplog):
    session = new_session()
    seed(session, "critical")
    opener = FakeOpener()
    with caplog.at_level(logging.INFO, logger="backend.services.n8n_notifier"):
        stored = correlate(session, N8nNotifier("", opener=opener, background=False))
    assert len(stored) == 1 and incident_count(session) == 1
    assert opener.requests == []
    assert n8n_notifier.last_delivery()["status"] == STATUS_NOT_CONFIGURED
    assert "not configured" in caplog.text


def test_default_settings_leave_n8n_not_configured():
    settings = Settings.model_construct(
        N8N_WEBHOOK_URL=SecretStr(""), N8N_WEBHOOK_AUTH_HEADER="", N8N_WEBHOOK_AUTH_TOKEN=SecretStr(""), N8N_WEBHOOK_TIMEOUT_SECONDS=3.0,
    )
    n8n = N8nNotifier.from_settings(settings, opener=FakeOpener(), background=False)
    assert not n8n.configured and n8n.status()["reason"] == "N8N_WEBHOOK_URL is not set"
    assert Settings.model_fields["N8N_WEBHOOK_URL"].default.get_secret_value() == ""


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://n8n.example.test/hook", "not a url", "https://"])
def test_non_http_webhook_urls_are_refused(url):
    opener = FakeOpener()
    result = notifier(opener, url=url).send(
        build_payload({"incident_id": "i", "severity": "high"}, event=EVENT_TEST, recipient_emails=[OWNER_EMAIL])
    )
    assert result.status == STATUS_NOT_CONFIGURED and opener.requests == []


def test_notifier_exception_does_not_fail_correlation():
    class Broken(N8nNotifier):
        def notify_incidents(self, items):
            raise RuntimeError("boom")

    session = new_session()
    seed(session, "high")
    assert len(correlate(session, Broken(WEBHOOK_URL, background=False))) == 1
    assert incident_count(session) == 1


def test_background_delivery_does_not_block_incident_storage():
    session = new_session()
    seed(session, "high")
    gate = threading.Event()
    opener = FakeOpener(gate=gate)
    started = time.monotonic()
    stored = correlate(session, notifier(opener, background=True))
    assert time.monotonic() - started < 2
    assert len(stored) == 1 and incident_count(session) == 1
    assert opener.requests == []
    gate.set()
    assert opener.done.wait(5)
    assert opener.payloads[0]["incident"]["incident_id"] == stored[0]["incident_id"]


def test_timeout_is_short_and_bounded():
    assert notifier(timeout=3).status()["timeout_seconds"] == 3.0
    assert notifier(timeout=120).status()["timeout_seconds"] == 10.0
    opener = FakeOpener()
    notifier(opener, timeout=2).send(
        build_payload({"incident_id": "i"}, event=EVENT_TEST, recipient_emails=[OWNER_EMAIL])
    )
    assert opener.requests[0]["timeout"] == 2.0


def test_logs_never_contain_webhook_url_or_token(caplog):
    session = new_session()
    seed(session, "high")
    with caplog.at_level(logging.DEBUG):
        correlate(session, N8nNotifier(WEBHOOK_URL, auth_header="X-Token", auth_token=AUTH_TOKEN,
                                       opener=FakeOpener(error=urllib.error.HTTPError(WEBHOOK_URL, 500, "x", {}, io.BytesIO())),
                                       background=False))
    assert "n8n notification failed" in caplog.text
    assert WEBHOOK_URL not in caplog.text and AUTH_TOKEN not in caplog.text and "secret-path" not in caplog.text


# ---------------------------------------------------------------- idempotency


def test_recorrelation_does_not_resend():
    session = new_session()
    seed(session, "high")
    opener = FakeOpener()
    for _ in range(3):
        correlate(session, notifier(opener))
    assert len(opener.requests) == 1 and incident_count(session) == 1


# ---------------------------------------------------------------- API


ADMIN = User(id="admin-1", username="admin", email="admin@example.test", hashed_password="x", role="ADMIN")
ANALYST = User(id="owner-1", username="analyst", email="analyst@example.test", hashed_password="x", role="ANALYST")


def api(session, user, opener):
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(intelligence_api.router, prefix="/api/v1/intelligence")
    app.dependency_overrides[get_db] = lambda: session
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[intelligence_api.get_n8n_notifier] = lambda: notifier(opener)
    return TestClient(app)


def test_duplicate_incident_api_reads_do_not_resend(monkeypatch):
    session = new_session()
    seed(session, "critical")
    opener = FakeOpener()
    monkeypatch.setattr(n8n_notifier.N8nNotifier, "from_settings", classmethod(lambda cls, *a, **k: notifier(opener)))
    client = api(session, ADMIN, opener)
    first = client.get("/api/v1/intelligence/incidents")
    assert first.status_code == 200 and len(first.json()) == 1
    assert len(opener.requests) == 1
    for _ in range(3):
        assert client.get("/api/v1/intelligence/incidents").status_code == 200
    assert client.post("/api/v1/intelligence/correlate").status_code == 200
    assert len(opener.requests) == 1


def test_manual_test_endpoint_requires_authentication():
    session = new_session()
    response = api(session, None, FakeOpener()).post("/api/v1/intelligence/incidents/any/n8n-test")
    assert response.status_code == 401


def test_manual_test_endpoint_requires_admin():
    session = new_session()
    seed(session, "high")
    correlate(session, notifier(FakeOpener()))
    incident_id = session.scalar(select(Incident.incident_id))
    opener = FakeOpener()
    response = api(session, ANALYST, opener).post(f"/api/v1/intelligence/incidents/{incident_id}/n8n-test")
    assert response.status_code == 403
    assert opener.requests == []


def test_manual_test_endpoint_requires_existing_incident():
    session = new_session()
    opener = FakeOpener()
    response = api(session, ADMIN, opener).post("/api/v1/intelligence/incidents/does-not-exist/n8n-test")
    assert response.status_code == 404
    assert opener.requests == [] and incident_count(session) == 0


def test_manual_test_endpoint_sends_existing_incident_as_test():
    session = new_session()
    seed(session, "medium")
    correlate(session, notifier(FakeOpener()))
    row = session.scalar(select(Incident))
    opener = FakeOpener()
    client = api(session, ADMIN, opener)
    for ref in (row.incident_id, row.id):
        response = client.post(f"/api/v1/intelligence/incidents/{ref}/n8n-test")
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["test"] is True and data["status"] == STATUS_SENT and data["delivered"] is True
        assert data["operation"] == "n8n_test_notification"
    assert [p["event"] for p in opener.payloads] == [EVENT_TEST, EVENT_TEST]
    assert all(p["test"] is True and p["incident"]["incident_id"] == row.incident_id for p in opener.payloads)
    assert incident_count(session) == 1


def test_manual_test_endpoint_reports_not_configured():
    session = new_session()
    seed(session, "high")
    correlate(session, notifier(FakeOpener()))
    app_client = api(session, ADMIN, FakeOpener())
    app_client.app.dependency_overrides[intelligence_api.get_n8n_notifier] = lambda: N8nNotifier("", background=False)
    response = app_client.post(f"/api/v1/intelligence/incidents/{session.scalar(select(Incident.id))}/n8n-test")
    assert response.status_code == 200 and response.json()["status"] == STATUS_NOT_CONFIGURED


def test_status_endpoint_hides_url_and_limits_delivery_details_to_admin():
    session = new_session()
    analyst = api(session, ANALYST, FakeOpener()).get("/api/v1/intelligence/n8n/status")
    admin = api(session, ADMIN, FakeOpener()).get("/api/v1/intelligence/n8n/status")
    assert analyst.status_code == admin.status_code == 200
    assert analyst.json()["configured"] is True and "last_delivery" not in analyst.json()
    assert "last_delivery" in admin.json()
    assert analyst.json()["qualifying_severities"] == ["CRITICAL", "HIGH"]
    for response in (analyst, admin):
        assert WEBHOOK_URL not in response.text and "secret-path" not in response.text
