"""Core workflow: Azure collection -> storage -> API -> detection -> correlation -> incident -> n8n payload.

Azure is the real collector driven by a fake HTTPS transport (real-shaped Log Analytics responses);
n8n is a fake opener. SQLite in-memory only; no live Azure, PostgreSQL, webhook or email.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import alerts as alerts_api
from backend.api import events as events_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.environments import CLOUD
from backend.database.models import PRESENTATION_DATA_ORIGIN, Base, Detection, Event, Incident, User
from backend.services import n8n_notifier
from backend.services.cloud.azure_collector import LAST_RUN, AzureCollector
from backend.services.correlation_service import PRESENTATION_MARKER, CorrelationService
from backend.services.detection_service import DetectionService
from backend.test_azure_collector import ALICE_OID, SECRET, TOKEN, FakeAzure, activity_row, settings, signin_row
from backend.test_n8n_notifications import WEBHOOK_URL, FakeOpener

OWNER = "owner-1"
OTHER = "owner-2"
T0 = datetime(2026, 10, 4, 7, 0, tzinfo=timezone.utc)


def iso(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Env:
    def __init__(self, tmp_path):
        LAST_RUN.clear()
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.engine = engine
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.session.add_all([
            User(id=OWNER, username="analyst", email="analyst@example.test", hashed_password="x", role="ANALYST"),
            User(id=OTHER, username="other", email="other@example.test", hashed_password="x", role="ANALYST"),
        ])
        self.session.commit()
        self.model_settings = MagicMock()
        self.model_settings.MODEL_DIR = str(tmp_path / "models")
        self.opener = FakeOpener()

    def collect(self, *, signins=(), activity=(), owner=OWNER):
        fake = FakeAzure(signin_rows=list(signins), activity_rows=list(activity))
        return AzureCollector(self.session, settings=settings(), transport=fake).collect(
            owner_id=owner, account_id=None, lookback_minutes=15,
        )

    def detect(self, owner=OWNER):
        with patch("backend.services.detection_service.get_settings", return_value=self.model_settings):
            return DetectionService(self.session).run_detection(owner_id=owner)

    def correlate(self, opener=None, owner=OWNER):
        notifier = n8n_notifier.N8nNotifier(WEBHOOK_URL, opener=opener or self.opener, background=False)
        return CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id=owner)

    def api(self, user_id=OWNER):
        app = FastAPI()
        app.include_router(events_api.router, prefix="/api/v1/events")
        app.include_router(alerts_api.router, prefix="/api/v1/alerts")
        user = self.session.get(User, user_id)
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app)

    def close(self):
        LAST_RUN.clear()
        self.session.close()
        self.engine.dispose()


@pytest.fixture
def env(tmp_path):
    environment = Env(tmp_path)
    yield environment
    environment.close()


def seed_alice_incident(env):
    """Failed Entra sign-in followed by a role assignment: one high-severity Cloud incident."""
    return env.collect(
        signins=[signin_row("sig-1", result="50126", created=iso(0))],
        activity=[activity_row("act-1", time=iso(3))],
    )


# ---------------------------------------------------------------- B. Azure collection, storage, retrieval


def test_collected_azure_events_are_stored_and_retrievable_in_cloud_environment_only(env):
    result = seed_alice_incident(env)
    assert result["records_inserted"] == 2 and result["records_failed"] == 0

    owner = env.api(OWNER)
    cloud = owner.get("/api/v1/events/recent", params={"environment": "CLOUD", "limit": 50}).json()
    assert {row["source_type"] for row in cloud} == {"CLOUD"} and len(cloud) == 2
    assert owner.get("/api/v1/events/recent", params={"environment": "LINUX", "limit": 50}).json() == []
    assert env.api(OTHER).get("/api/v1/events/recent", params={"environment": "CLOUD", "limit": 50}).json() == []

    again = seed_alice_incident(env)
    assert again["records_inserted"] == 0 and again["records_deduplicated"] == 2
    assert env.session.scalar(select(func.count(Event.id))) == 2


def test_insufficient_cloud_events_skip_ml_scoring_without_predictions(env):
    seed_alice_incident(env)
    result = env.detect()
    assert result["events_analyzed"] == 2
    assert result["isolation_forest"] == "insufficient_events" and result["model_action"] == "skipped"
    assert result["predictions_stored"] == 0 and result["ml_anomalies"] == 0
    assert env.session.scalar(select(func.count(Detection.id))) == 0
    alerts = env.api(OWNER).get("/api/v1/alerts", params={"environment": "CLOUD"}).json()
    assert [alert["detection_type"] for alert in alerts] == ["rule_based"]


def test_sufficient_genuine_cloud_events_reach_cloud_isolation_forest(env):
    env.collect(signins=[signin_row(f"sig-{i:03d}", created=iso(i * 7)) for i in range(120)])
    for minute in range(9):
        env.session.add(Event(
            event_id=f"presentation-{minute}", timestamp=T0 + timedelta(minutes=minute), hostname="azure",
            username="presenter", actor_id="presenter", event_type="CLOUD_RESOURCE_OPERATION", category="cloud",
            severity="info", risk_score=20, message=f"presentation {PRESENTATION_MARKER}", raw_log="{}",
            hash=f"presentation-hash-{minute}", owner_id=OWNER, source_type="CLOUD", provider="AZURE",
            data_origin=PRESENTATION_DATA_ORIGIN,
        ))
    env.session.commit()

    result = env.detect()
    assert result["events_analyzed"] == 120
    assert result["isolation_forest"] == "trained" and result["model_action"] == "trained"
    assert result["random_forest"] == "no_valid_labels"
    assert result["predictions_stored"] == 120
    assert result["training_metadata"]["iso_models_by_source"][CLOUD]["status"] == "trained"
    scored = set(env.session.scalars(select(Detection.event_id)))
    assert len(scored) == 120 and not any(event_id.startswith("presentation-") for event_id in scored)


# ---------------------------------------------------------------- C/D. Correlation, incidents and n8n


def test_cloud_incident_has_evidence_and_recommendation_and_notifies_once(env):
    seed_alice_incident(env)
    stored = env.correlate()
    assert len(stored) == 1
    incident = stored[0]
    assert incident["environment"] == CLOUD and incident["severity"] == "high" and incident["actor"] == ALICE_OID
    assert "Cloud sign-in/authentication activity" in incident["evidence"]
    assert "Cloud privilege/role change" in incident["evidence"]
    assert incident["explanation"] and incident["recommendation"]
    assert PRESENTATION_MARKER not in incident["title"]

    assert [p["event"] for p in env.opener.payloads] == [n8n_notifier.EVENT_CREATED]
    payload = env.opener.payloads[0]
    assert payload["incident"]["environment"] == CLOUD and payload["incident"]["severity"] == "HIGH"
    raw = env.opener.requests[0]["raw"]
    for value in (SECRET, TOKEN, "203.0.113.10", "sig-1", "act-1", OWNER, '"raw_log"', '"event_ids"'):
        assert value not in raw, value

    for _ in range(2):
        env.correlate()
    assert env.session.scalar(select(func.count(Incident.id))) == 1
    assert len(env.opener.requests) == 1


def test_growing_incident_keeps_identity_and_does_not_notify_again(env):
    seed_alice_incident(env)
    first = env.correlate()[0]
    row_id = env.session.scalar(select(Incident.id))
    env.collect(signins=[signin_row("sig-2", result="50126", created=iso(9))])
    second = env.correlate()
    assert len(second) == 1
    assert second[0]["incident_id"] == first["incident_id"] and second[0]["id"] == row_id
    assert len(second[0]["event_ids"]) == 3 and second[0]["end_time"] != first["end_time"]
    assert env.session.scalar(select(func.count(Incident.id))) == 1
    assert len(env.opener.requests) == 1


def test_separate_activity_after_the_window_is_a_new_incident(env):
    seed_alice_incident(env)
    env.correlate()
    env.collect(
        signins=[signin_row("sig-9", result="50126", created=iso(180))],
        activity=[activity_row("act-9", time=iso(182))],
    )
    stored = env.correlate()
    assert env.session.scalar(select(func.count(Incident.id))) == 2 and len(stored) == 2
    assert [p["event"] for p in env.opener.payloads] == [n8n_notifier.EVENT_CREATED, n8n_notifier.EVENT_CREATED]


def test_webhook_failure_keeps_incident_stored(env):
    seed_alice_incident(env)
    failing = FakeOpener(status=500)
    assert len(env.correlate(failing)) == 1
    assert env.session.scalar(select(func.count(Incident.id))) == 1
    assert n8n_notifier.last_delivery()["status"] == n8n_notifier.STATUS_FAILED


def test_incidents_are_scoped_to_the_owner(env):
    seed_alice_incident(env)
    env.correlate()
    assert env.correlate(owner=OTHER) == []
    assert CorrelationService(env.session).list_incidents(owner_id=OTHER) == []


# ---------------------------------------------------------------- E. Presentation provenance


def test_presentation_incident_is_marked_in_title_evidence_and_payload(env):
    for minute, (event_type, risk) in enumerate((("CLOUD_LOGIN_SUCCESS", 20), ("CLOUD_PRIVILEGE_CHANGE", 80))):
        env.session.add(Event(
            event_id=f"presentation-{minute}", timestamp=T0 + timedelta(minutes=minute), hostname="azure",
            username="presenter@example.test", actor_id="presenter@example.test", event_type=event_type,
            category="cloud", severity="high" if risk >= 70 else "info", risk_score=risk,
            message=f"generated {PRESENTATION_MARKER}", raw_log="{}", hash=f"presentation-hash-{minute}",
            owner_id=OWNER, source_type="CLOUD", provider="AZURE", data_origin=PRESENTATION_DATA_ORIGIN,
        ))
    env.session.commit()
    seed_alice_incident(env)

    stored = {row["actor"]: row for row in env.correlate()}
    presentation, genuine = stored["presenter@example.test"], stored[ALICE_OID]
    assert presentation["title"].endswith(PRESENTATION_MARKER)
    assert any("generated by DefenSync for a presentation" in item for item in presentation["evidence"])
    assert "presentation" in presentation["explanation"]
    assert PRESENTATION_MARKER not in genuine["title"]
    assert not any("presentation" in item for item in genuine["evidence"])

    titles = {p["incident"]["actor"]: p["incident"]["title"] for p in env.opener.payloads}
    assert titles["presenter@example.test"].endswith(PRESENTATION_MARKER)
    assert PRESENTATION_MARKER not in titles[ALICE_OID]
