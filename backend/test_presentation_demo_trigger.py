"""Presentation demo trigger: one marked alert after every 1-3 successful manual collections.

SQLite in-memory, fake Azure transport, patched SSH retrieval and a fake n8n opener: no live
server, no PostgreSQL rows, no real webhook or email.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import account as account_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.environments import CLOUD, LINUX
from backend.database.models import (
    PRESENTATION_DATA_ORIGIN,
    Alert,
    Base,
    CloudCollectionRun,
    Event,
    Incident,
    PresentationTriggerState,
    User,
)
from backend.ml.linux_features import build_feature_matrix, is_linux_ml_eligible
from backend.services import n8n_notifier, presentation_trigger
from backend.services.cloud.presentation_telemetry import MARKER, SETUP_STEPS
from backend.services.collector_service import CollectorService
from backend.services.correlation_service import CorrelationService
from backend.services.linux_presentation_trigger import NOTE, record_linux_presentation_trigger
from backend.services.server_service import ServerService
from backend.test_azure_collector import FakeAzure, activity_row
from backend.test_cloud_sources import SOURCE_URL, token_failure
from backend.test_linux_collection_pipeline import ACCOUNT_A, LinuxCollectionTestBase, _ssh_auth_failure, retrieved
from backend.test_n8n_notifications import WEBHOOK_URL, FakeOpener
from backend.test_presentation_telemetry import PRESENTER, SETTINGS_PATH, PresentationTestBase, flag

INTERVAL_PATH = "backend.services.presentation_trigger.choose_interval"
STATUS_URL = "/api/v1/account/presentation-trigger"
NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def account_client(session, user):
    app = FastAPI()
    app.include_router(account_api.router, prefix="/api/v1/account")
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app)


class IntervalStateTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)

    def advance(self, session, run_id, *, owner_id="owner-a", account_id=ACCOUNT_A, environment=LINUX):
        result = presentation_trigger.advance(
            session, owner_id=owner_id, account_id=account_id, environment=environment, run_id=run_id, now=NOW,
        )
        session.commit()
        return result

    def test_1_selected_interval_is_between_one_and_three(self):
        draws = {presentation_trigger.choose_interval() for _ in range(300)}
        self.assertTrue(draws <= {1, 2, 3})
        self.assertEqual(draws, {1, 2, 3})

    def test_2_interval_and_progress_survive_a_restart(self):
        with patch(INTERVAL_PATH, side_effect=[3, 2]) as choose:
            with self.sessions() as first:
                self.assertEqual(self.advance(first, "run-1").triggered, False)
            with self.sessions() as restarted:
                view = presentation_trigger.status(restarted, owner_id="owner-a", account_id=ACCOUNT_A, environment=LINUX)
                self.assertEqual((view["trigger_interval"], view["progress"], view["collections_until_next_trigger"]), (3, 1, 2))
                self.assertFalse(self.advance(restarted, "run-2").triggered)
            with self.sessions() as again:
                result = self.advance(again, "run-3")
        self.assertTrue(result.triggered)
        self.assertEqual(choose.call_count, 2)
        with self.sessions() as session:
            state = session.scalars(select(PresentationTriggerState)).one()
            self.assertEqual((state.trigger_interval, state.progress, state.triggers_generated), (2, 0, 1))
            self.assertEqual(state.last_triggered_run_id, "run-3")

    def test_3_a_run_is_counted_once(self):
        with patch(INTERVAL_PATH, side_effect=[2, 3]), self.sessions() as session:
            self.assertTrue(self.advance(session, "run-1").counted)
            repeat = self.advance(session, "run-1")
            self.assertEqual((repeat.counted, repeat.triggered, repeat.state.progress), (False, False, 1))
            self.assertTrue(self.advance(session, "run-2").triggered)
            repeat = self.advance(session, "run-2")
            self.assertEqual((repeat.counted, repeat.triggered, repeat.state.triggers_generated), (False, False, 1))

    def test_4_accounts_and_environments_are_counted_separately(self):
        with patch(INTERVAL_PATH, return_value=2), self.sessions() as session:
            self.advance(session, "linux-1", environment=LINUX)
            self.advance(session, "cloud-1", environment=CLOUD)
            self.advance(session, "other-1", owner_id="owner-b", account_id="acct-b", environment=LINUX)
            self.assertTrue(self.advance(session, "linux-2", environment=LINUX).triggered)

            def view(environment, owner_id="owner-a", account_id=ACCOUNT_A):
                return presentation_trigger.status(session, owner_id=owner_id, account_id=account_id, environment=environment)

            self.assertEqual((view(LINUX)["triggers_generated"], view(LINUX)["progress"]), (1, 0))
            self.assertEqual((view(CLOUD)["triggers_generated"], view(CLOUD)["progress"]), (0, 1))
            other = view(LINUX, "owner-b", "acct-b")
            self.assertEqual((other["triggers_generated"], other["progress"]), (0, 1))
            self.assertEqual(view(LINUX, "solo", None), {"environment": LINUX, "started": False})


class LinuxDemoTriggerTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        self.session.add(User(id="admin-1", username="admin", email="admin@example.test", hashed_password="x", role="ADMIN"))
        self.session.commit()
        self.flag = patch(SETTINGS_PATH, return_value=SimpleNamespace(PRESENTATION_TELEMETRY_EMAILS="a@example.test"))
        self.flag.start()
        self.addCleanup(self.flag.stop)

    def interval(self, *values):
        choose = patch(INTERVAL_PATH, side_effect=list(values))
        choose.start()
        self.addCleanup(choose.stop)

    def post_collect(self, user_id="owner-a", **patch_kwargs):
        patch_kwargs = patch_kwargs or {"return_value": retrieved()}
        with patch.object(CollectorService, "collect_raw_lines", **patch_kwargs):
            response = self.api(user_id).post(f"/api/v1/servers/{self.server.id}/collect", json={"tail_lines": 500})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def presentation_events(self):
        return list(self.session.scalars(select(Event).where(Event.data_origin == PRESENTATION_DATA_ORIGIN)).all())

    def genuine_snapshot(self):
        rows = self.session.scalars(select(Event).where(Event.data_origin == "LIVE_LINUX")).all()
        return {e.id: (e.hash, e.message, e.risk_score, e.timestamp) for e in rows}

    def states(self):
        return self.session.scalar(select(func.count(PresentationTriggerState.id)))

    def test_5_triggers_once_on_the_selected_collection(self):
        self.interval(3, 2)
        bodies = [self.post_collect() for _ in range(2)]
        self.assertEqual([b["presentation_trigger"]["collections_until_next_trigger"] for b in bodies[:2]], [2, 1])
        self.assertEqual(self.presentation_events(), [])
        self.assertEqual(self.session.scalar(select(func.count(Alert.id))), 0)
        bodies.append(self.post_collect())
        (event,) = self.presentation_events()
        (alert,) = self.session.scalars(select(Alert)).all()
        third = bodies[2]["presentation_trigger"]
        self.assertEqual((third["triggers_generated"], third["progress"], third["trigger_interval"]), (1, 0, 2))
        self.assertEqual((event.source_type, event.server_id, event.owner_id, event.account_id), (LINUX, self.server.id, "owner-a", ACCOUNT_A))
        self.assertEqual((event.event_type, event.risk_score, event.severity), ("Sudo Command", 80, "high"))
        self.assertTrue(event.message.endswith(MARKER))
        metadata = json.loads(event.normalized_data)
        self.assertEqual((metadata["record_origin"], metadata["note"]), ("PRESENTATION_GENERATED", NOTE))
        self.assertEqual(alert.event_id, event.event_id)
        self.assertTrue(alert.title.endswith(MARKER))
        self.assertIn(NOTE, alert.explanation)
        genuine = self.session.scalars(select(Event).where(Event.data_origin == "LIVE_LINUX")).all()
        self.assertTrue(genuine)
        self.assertFalse([e for e in genuine if MARKER in (e.message or "")])

    def test_6_failed_admin_scheduled_and_unlisted_collections_do_not_count(self):
        self.interval(1, 1)
        failed = self.post_collect(side_effect=_ssh_auth_failure())
        self.assertFalse(failed["success"])
        admin = self.post_collect("admin-1")
        self.assertTrue(admin["success"])
        with patch.object(CollectorService, "collect_raw_lines", return_value=retrieved()):
            scheduled = ServerService(self.session).collect_for_server(self.server.id)
        self.assertTrue(scheduled["success"])
        with patch(SETTINGS_PATH, return_value=SimpleNamespace(PRESENTATION_TELEMETRY_EMAILS="")):
            unlisted = self.post_collect()
        for body in (failed, admin, scheduled, unlisted):
            self.assertNotIn("presentation_trigger", body)
        self.assertEqual((self.states(), self.presentation_events()), (0, []))
        self.assertEqual(self.session.scalar(select(func.count(Alert.id))), 0)
        self.assertEqual(self.post_collect()["presentation_trigger"]["triggers_generated"], 1)
        self.assertEqual(len(self.presentation_events()), 1)

    def test_7_repeating_a_run_does_not_duplicate_records(self):
        self.interval(1, 3)
        self.post_collect()
        run = self.last_run()
        user = self.session.get(User, "owner-a")
        again = record_linux_presentation_trigger(self.session, user=user, server=self.server, run=run)
        self.assertEqual((again["trigger_inserted"], again["alert_created"]), (False, False))
        self.assertEqual(again["trigger"]["triggers_generated"], 1)
        self.assertEqual(len(self.presentation_events()), 1)
        self.assertEqual(self.session.scalar(select(func.count(Alert.id))), 1)

    def test_8_markers_reach_the_incident_and_one_n8n_payload(self):
        self.interval(1, 3)
        self.post_collect()
        genuine_before = self.genuine_snapshot()
        opener = FakeOpener()
        notifier = n8n_notifier.N8nNotifier(WEBHOOK_URL, opener=opener, background=False)
        CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id="owner-a", account_id=ACCOUNT_A)
        (incident,) = [row for row in self.session.scalars(select(Incident)).all() if MARKER in row.title]
        (event,) = self.presentation_events()
        self.assertEqual(json.loads(incident.event_ids), [event.event_id])
        self.assertEqual(incident.severity, "high")
        evidence = json.loads(incident.evidence)
        self.assertTrue(any("generated by DefenSync for a presentation" in item for item in evidence))
        self.assertIn("generated by DefenSync for a presentation", incident.explanation)
        self.assertNotIn("resembles an anomaly pattern", incident.explanation)
        self.assertEqual(json.loads(incident.intelligence_refs or "[]"), [])
        marked = [p["incident"] for p in opener.payloads if MARKER in p["incident"]["title"]]
        genuine = [p["incident"] for p in opener.payloads if MARKER not in p["incident"]["title"]]
        (payload,) = marked
        self.assertEqual((payload["incident_id"], payload["environment"], payload["severity"]), (incident.incident_id, LINUX, "HIGH"))
        self.assertTrue(payload["title"].endswith(MARKER))
        self.assertTrue(any("generated by DefenSync for a presentation" in item for item in payload["evidence_summary"]))
        self.assertNotIn("attack", json.dumps(payload).lower())
        # The sample's genuine "invalid user admin" failure is still notified, without presentation wording.
        self.assertEqual([p["actor"] for p in genuine], ["admin"])
        self.assertNotIn("presentation", json.dumps(genuine).lower())
        incidents, sent = self.session.scalar(select(func.count(Incident.id))), len(opener.payloads)
        CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id="owner-a", account_id=ACCOUNT_A)
        self.assertEqual(self.session.scalar(select(func.count(Incident.id))), incidents)
        self.assertEqual(len(opener.payloads), sent)
        self.assertEqual(self.genuine_snapshot(), genuine_before)

    def test_9_presentation_record_is_excluded_from_linux_ml(self):
        self.interval(1, 3)
        self.post_collect()
        (event,) = self.presentation_events()
        self.assertFalse(is_linux_ml_eligible(event))
        events = self.session.scalars(select(Event)).all()
        matrix = build_feature_matrix(events)
        self.assertTrue(matrix.event_ids)
        self.assertNotIn(event.event_id, matrix.event_ids)

    def test_10_status_is_read_only_and_reveals_no_identifiers(self):
        self.interval(2, 3)
        self.post_collect()
        owner = self.session.get(User, "owner-a")
        before = self.states()
        response = account_client(self.session, owner).get(STATUS_URL)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["enabled"])
        self.assertEqual(body["interval_range"], [1, 3])
        linux = body["environments"][LINUX]
        self.assertEqual((linux["trigger_interval"], linux["progress"], linux["collections_until_next_trigger"]), (2, 1, 1))
        self.assertEqual(body["environments"][CLOUD], {"environment": CLOUD, "started": False})
        for secret_like in ("a@example.test", "owner-a", ACCOUNT_A, self.server.id, "PRESENTATION_TELEMETRY_EMAILS"):
            self.assertNotIn(secret_like, response.text)
        self.assertEqual(self.states(), before)
        for user_id in ("admin-1", "analyst-b"):
            other = account_client(self.session, self.session.get(User, user_id)).get(STATUS_URL)
            self.assertEqual(other.json(), {"enabled": False})


class CloudDemoTriggerTests(PresentationTestBase):
    def interval(self, *values):
        choose = patch(INTERVAL_PATH, side_effect=list(values))
        choose.start()
        self.addCleanup(choose.stop)

    def test_11_triggers_exactly_at_each_selected_interval(self):
        self.interval(1, 2, 3, 1)
        with flag():
            source = self.create_source(PRESENTER)
            counts = []
            for _ in range(6):
                body = self.collect(PRESENTER, source["id"])
                counts.append((len(self.triggers()), len(self.presentation_alerts())))
        self.assertEqual(counts, [(1, 1), (1, 1), (2, 2), (2, 2), (2, 2), (3, 3)])
        self.assertEqual(len(self.presentation_events()), len(SETUP_STEPS) + 3)
        status = body["presentation_trigger"]
        self.assertEqual((status["environment"], status["triggers_generated"], status["trigger_interval"]), (CLOUD, 3, 1))
        for alert in self.presentation_alerts():
            self.assertTrue(alert.title.endswith(MARKER))

    def test_12_failed_partial_and_admin_collections_do_not_advance(self):
        self.interval(2, 3)
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"], FakeAzure(token_response=token_failure(7000215)))
            self.collect(PRESENTER, source["id"], FakeAzure(query_status={"SigninLogs": 503, "AzureActivity": 503}))
            self.collect(PRESENTER, source["id"], FakeAzure(signin_rows=[], activity_rows=[activity_row("a1"), activity_row("a2")]), max_records=1)
            self.collect("admin-1", source["id"])
            self.assertEqual(self.session.scalar(select(func.count(PresentationTriggerState.id))), 0)
            first = self.collect(PRESENTER, source["id"])["presentation_trigger"]
            self.assertEqual((first["progress"], first["triggers_generated"]), (1, 0))
            self.assertEqual(self.triggers(), [])
            second = self.collect(PRESENTER, source["id"])["presentation_trigger"]
        self.assertEqual((second["progress"], second["triggers_generated"]), (0, 1))
        self.assertEqual((len(self.triggers()), len(self.presentation_alerts())), (1, 1))
        runs = self.session.scalar(select(func.count(CloudCollectionRun.id)))
        self.assertEqual(runs, 6)


if __name__ == "__main__":
    unittest.main()
