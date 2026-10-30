"""Presentation telemetry: allow-listed cloud source owner only, real Azure rows untouched.

SQLite in-memory, fake Azure transport, fake n8n opener: no live Azure, no PostgreSQL rows,
no real webhook.
"""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import func, select

from backend.api import alerts as alerts_api
from backend.api import events as events_api
from backend.core.environments import CLOUD
from backend.database.models import PRESENTATION_DATA_ORIGIN, Alert, CloudCollectionRun, CloudSource, Event, Incident, User
from backend.services import n8n_notifier
from backend.services.cloud.presentation_telemetry import (
    DETECTION_TYPE,
    MARKER,
    SETUP_STEPS,
    record_presentation_telemetry,
)
from backend.services.correlation_service import CorrelationService
from backend.services.detection_service import DetectionService
from backend.test_azure_collector import FakeAzure, activity_row, signin_row
from backend.test_cloud_sources import SOURCE_URL, CloudSourceTestBase, token_failure
from backend.test_linux_collection_pipeline import LinuxCollectionTestBase, _ssh_auth_failure
from backend.test_n8n_notifications import WEBHOOK_URL, FakeOpener

PRESENTER = "solo"
PRESENTER_EMAIL = "solo@example.test"
SETTINGS_PATH = "backend.services.cloud.presentation_telemetry.get_settings"


def flag(emails: str = PRESENTER_EMAIL, *, every_success: bool = True, n8n_every_success: bool = True):
    return patch(
        SETTINGS_PATH,
        return_value=SimpleNamespace(
            PRESENTATION_TELEMETRY_EMAILS=emails,
            CLOUD_DEMO_EVERY_SUCCESS=every_success,
            CLOUD_DEMO_N8N_EVERY_SUCCESS=n8n_every_success,
        ),
    )


def empty_azure() -> FakeAzure:
    return FakeAzure(signin_rows=[], activity_rows=[])


class PresentationTestBase(CloudSourceTestBase):
    """Interval fixed at 1, so every successful manual collection reaches the trigger."""

    def setUp(self):
        super().setUp()
        interval = patch("backend.services.presentation_trigger.choose_interval", return_value=1)
        interval.start()
        self.addCleanup(interval.stop)
        # Never hit a real n8n webhook from presentation collect tests (odd/even sequencing tested elsewhere).
        self._n8n_patch = patch(
            "backend.services.cloud.cloud_source_service.record_cloud_success",
            return_value={"counted": True, "sequence_number": 1, "dispatch_status": "SKIPPED", "trigger_every": 2},
        )
        self._n8n_patch.start()
        self.addCleanup(self._n8n_patch.stop)

    def api(self, user_id, fake=None):
        client = super().api(user_id, fake)
        client.app.include_router(events_api.router, prefix="/api/v1/events")
        client.app.include_router(alerts_api.router, prefix="/api/v1/alerts")
        return client

    def collect(self, user_id, source_id, fake=None, **body):
        response = self.api(user_id, fake or empty_azure()).post(f"{SOURCE_URL}/{source_id}/collect", json={"lookback_minutes": 15, **body})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def presentation_events(self, owner_id=None):
        stmt = select(Event).where(Event.data_origin == PRESENTATION_DATA_ORIGIN)
        if owner_id:
            stmt = stmt.where(Event.owner_id == owner_id)
        return list(self.session.scalars(stmt).all())

    def presentation_alerts(self):
        return list(self.session.scalars(select(Alert).where(Alert.detection_type == DETECTION_TYPE)).all())

    def triggers(self):
        return [e for e in self.presentation_events() if json.loads(e.normalized_data)["presentation_kind"] == "collect_trigger"]

    def backdate_source(self, source_id, days=2):
        source = self.session.get(CloudSource, source_id)
        source.created_at = source.created_at - timedelta(days=days)
        self.session.commit()


class AccountScopeTests(PresentationTestBase):
    def test_1_records_only_for_the_listed_owner(self):
        with flag():
            mine = self.create_source(PRESENTER)
            theirs = self.create_source("analyst-b")
            self.collect(PRESENTER, mine["id"])
            self.collect("analyst-b", theirs["id"])
        rows = self.presentation_events()
        self.assertEqual(len(rows), len(SETUP_STEPS) + 1)
        for event in rows:
            metadata = json.loads(event.normalized_data)
            self.assertEqual((event.owner_id, event.account_id, event.data_scope, event.source_type), (PRESENTER, None, "PRIVATE", CLOUD))
            expected_actor = "demo-suspicious-user" if metadata.get("presentation_kind") == "collect_trigger" else PRESENTER_EMAIL
            self.assertEqual((event.actor_id, event.server_id), (expected_actor, None))
            self.assertTrue(metadata["presentation_generated"])
            self.assertFalse(metadata["azure_record"])
            self.assertEqual((metadata["record_origin"], metadata["cloud_source_id"]), ("PRESENTATION_GENERATED", mine["id"]))
            self.assertTrue(event.message.endswith(MARKER))
        self.assertEqual(self.presentation_events("analyst-b"), [])

    def test_1b_admin_collect_or_unlisted_or_disabled_creates_nothing(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect("admin-1", source["id"])
            other = self.create_source("analyst-a")
            self.collect("analyst-a", other["id"])
        with flag(""):
            self.collect(PRESENTER, source["id"])
        self.assertEqual(self.presentation_events(), [])
        self.assertEqual(self.presentation_alerts(), [])

    def test_2_other_account_cannot_see_presentation_records(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"])
        own = self.api(PRESENTER).get("/api/v1/events", params={"environment": CLOUD, "limit": 100}).json()
        self.assertEqual({row["data_origin"] for row in own}, {PRESENTATION_DATA_ORIGIN})
        self.assertEqual(len(own), len(SETUP_STEPS) + 1)
        for user_id in ("analyst-a", "analyst-b"):
            client = self.api(user_id)
            self.assertEqual(client.get("/api/v1/events", params={"environment": CLOUD, "limit": 100}).json(), [])
            self.assertEqual(client.get("/api/v1/alerts").json(), [])
            self.assertEqual(client.get(f"{SOURCE_URL}/{source['id']}").status_code, 404)
        self.assertEqual(len(self.api(PRESENTER).get("/api/v1/alerts").json()), 1)


class RealTelemetryTests(PresentationTestBase):
    def test_3_real_azure_rows_and_run_counters_are_unchanged(self):
        fake = FakeAzure(signin_rows=[signin_row("s1")], activity_rows=[activity_row("a1")])
        with flag():
            source = self.create_source(PRESENTER)
            first = self.collect(PRESENTER, source["id"], fake)
        real = list(self.session.scalars(select(Event).where(Event.data_origin == "AZURE_LOG_ANALYTICS")).all())
        self.assertEqual(len(real), 2)
        snapshot = {e.id: (e.hash, e.event_id, e.message, e.raw_log, e.normalized_data, e.risk_score, e.timestamp) for e in real}
        self.assertEqual((first["records_inserted"], first["collection_run"]["rows_stored"]), (2, 2))
        with flag():
            second = self.collect(PRESENTER, source["id"], fake)
        self.assertEqual((second["records_inserted"], second["records_deduplicated"]), (0, 2))
        self.assertEqual((second["collection_run"]["rows_stored"], second["collection_run"]["rows_duplicate"]), (0, 2))
        self.session.expire_all()
        after = list(self.session.scalars(select(Event).where(Event.data_origin == "AZURE_LOG_ANALYTICS")).all())
        self.assertEqual({e.id: (e.hash, e.event_id, e.message, e.raw_log, e.normalized_data, e.risk_score, e.timestamp) for e in after}, snapshot)
        self.assertFalse({e.hash for e in after} & {e.hash for e in self.presentation_events()})

    def test_3b_presentation_rows_are_excluded_from_ml_inputs(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"])
        detection = DetectionService(self.session)
        self.assertEqual(detection._load_events(owner_id=PRESENTER, exclude_linux=True), [])
        self.assertEqual(detection._load_if_baseline_events(source_type=CLOUD, owner_id=PRESENTER), [])


class CollectTriggerTests(PresentationTestBase):
    def test_4_successful_collect_creates_one_alert(self):
        with flag():
            source = self.create_source(PRESENTER)
            body = self.collect(PRESENTER, source["id"])
        self.assertEqual(body["collection_run"]["status"], "SUCCESS")
        (trigger,) = self.triggers()
        (alert,) = self.presentation_alerts()
        self.assertEqual(alert.event_id, trigger.event_id)
        self.assertEqual((alert.owner_id, alert.severity, alert.risk_score), (PRESENTER, "high", 70))
        self.assertEqual(alert.risk_level, "high")
        self.assertTrue(alert.title.startswith("DEMO:"))
        self.assertEqual((trigger.event_type, trigger.severity, trigger.risk_score), ("CLOUD_PRIVILEGE_CHANGE", "medium", 70))
        self.assertEqual(trigger.actor_id, "demo-suspicious-user")
        self.assertEqual(trigger.hostname, "demo-resource-group")
        self.assertEqual(trigger.operation, "Microsoft.Authorization/roleAssignments/write")
        self.assertIn("Failed", trigger.message)
        self.assertIn("Owner", trigger.message)
        self.assertIn("DEMO", trigger.message)
        meta = json.loads(trigger.normalized_data)
        self.assertEqual(meta["collection_run_id"], body["collection_run"]["id"])
        self.assertEqual(meta["normalized_via"], "azure_normalizer")
        self.assertEqual(meta["scoring"], "live_failed_activity")
        self.assertEqual(body.get("presentation_trigger_risk_score"), 70)
        self.assertTrue(body.get("demo_feedback", {}).get("demo_incident_created"))
        self.assertTrue(body.get("security_demo", {}).get("simulated"))
        self.assertEqual(body["security_demo"]["email_subject"], "DefenSync Security Alert — Suspicious Cloud Activity")

    def test_5_same_run_never_duplicates_and_reads_create_nothing(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"])
            run = self.session.scalars(select(CloudCollectionRun)).one()
            user, cloud_source = self.session.get(User, PRESENTER), self.session.get(CloudSource, source["id"])
            again = record_presentation_telemetry(self.session, user=user, source=cloud_source, run=run)
        self.assertEqual((again["setup_inserted"], again["trigger_inserted"], again["alert_created"]), (0, False, False))
        client = self.api(PRESENTER)
        for _ in range(3):
            client.get("/api/v1/events", params={"environment": CLOUD})
            client.get("/api/v1/alerts")
            client.get(f"{SOURCE_URL}/{source['id']}")
        self.assertEqual((len(self.presentation_events()), len(self.presentation_alerts())), (len(SETUP_STEPS) + 1, 1))
        with flag():
            self.collect(PRESENTER, source["id"])
        self.assertEqual((len(self.triggers()), len(self.presentation_alerts())), (2, 2))
        self.assertEqual(len(self.presentation_events()), len(SETUP_STEPS) + 2)

    def test_6_failed_partial_or_connection_test_creates_nothing(self):
        with flag():
            source = self.create_source(PRESENTER)
            failed = self.collect(PRESENTER, source["id"], FakeAzure(token_response=token_failure(7000215)))
            self.assertEqual(failed["status"], "COLLECTION_FAILED")
            unavailable = self.collect(PRESENTER, source["id"], FakeAzure(query_status={"SigninLogs": 503, "AzureActivity": 503}))
            self.assertNotEqual(unavailable["collection_run"]["status"], "SUCCESS")
            truncated = self.collect(PRESENTER, source["id"], FakeAzure(signin_rows=[], activity_rows=[activity_row("a1"), activity_row("a2")]), max_records=1)
            self.assertEqual(truncated["collection_run"]["status"], "PARTIAL")
            self.assertEqual(self.api(PRESENTER).post(f"{SOURCE_URL}/{source['id']}/test-connection").status_code, 200)
        self.assertEqual(self.presentation_events(), [])
        self.assertEqual(self.presentation_alerts(), [])


class NotificationTests(PresentationTestBase):
    def test_9_n8n_receives_the_dynamic_payload_of_the_presentation_incident(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.backdate_source(source["id"])
            self.collect(PRESENTER, source["id"])
        opener = FakeOpener()
        notifier = n8n_notifier.N8nNotifier(WEBHOOK_URL, opener=opener, background=False)
        stored = CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id=PRESENTER)
        self.assertIn("high", {item["severity"] for item in stored})
        privilege_payloads = [p for p in opener.payloads if p.get("security_demo", {}).get("simulated")]
        self.assertEqual(len(privilege_payloads), 1)
        payload = privilege_payloads[0]
        high = next(i for i in stored if i.get("security_demo"))
        (trigger,) = self.triggers()
        stored_incident = self.session.scalars(select(Incident).where(Incident.incident_id == high["incident_id"])).one()
        self.assertEqual(json.loads(stored_incident.event_ids), [trigger.event_id])
        incident = payload["incident"]
        self.assertEqual(payload["event"], n8n_notifier.EVENT_CREATED)
        self.assertFalse(payload["test"])
        self.assertEqual(incident["incident_id"], high["incident_id"])
        self.assertEqual((incident["environment"], incident["severity"], incident["actor"]), (CLOUD, "HIGH", "demo-suspicious-user"))
        self.assertEqual(payload["notification"]["suggested_subject"], "DefenSync Security Alert — Suspicious Cloud Activity")
        self.assertEqual(payload["security_demo"]["risk_score"], 70)
        self.assertEqual(payload["security_demo"]["initiating_user"], "demo-suspicious-user")
        self.assertEqual(payload["security_demo"]["operation"], "Microsoft.Authorization/roleAssignments/write")
        self.assertEqual(payload["security_demo"]["target_resource"], "demo-resource-group")
        self.assertNotIn("event_ids", json.dumps(payload))
        before = len(opener.payloads)
        CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id=PRESENTER)
        self.assertEqual(len(opener.payloads), before)


class LinuxOfflineTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        self._flag = patch(SETTINGS_PATH, return_value=SimpleNamespace(PRESENTATION_TELEMETRY_EMAILS="a@example.test"))
        self._flag.start()
        self._notify = patch.object(n8n_notifier.N8nNotifier, "notify_incidents")
        self.notify = self._notify.start()

    def tearDown(self):
        self._notify.stop()
        self._flag.stop()
        super().tearDown()

    def test_7_offline_linux_collect_creates_nothing_and_notifies_nobody(self):
        stats = self.collect(side_effect=_ssh_auth_failure())
        self.assertFalse(stats["success"])
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(self.event_count(), 0)
        self.assertEqual(self.session.scalar(select(func.count(Alert.id))), 0)
        self.assertEqual(self.session.scalar(select(func.count(Incident.id))), 0)
        self.assertEqual(self.last_run().status, "failed")
        self.assertNotIn("detection", stats)
        self.notify.assert_not_called()

    def test_8_online_linux_collect_is_unchanged(self):
        stats = self.collect()
        self.assertTrue(stats["success"])
        events = self.linux_events()
        self.assertEqual(len(events), 4)
        self.assertEqual({e.data_origin for e in events}, {"LIVE_LINUX"})
        self.assertEqual(self.session.scalar(select(func.count(Event.id)).where(Event.data_origin == PRESENTATION_DATA_ORIGIN)), 0)
        self.assertEqual(stats["detection"]["status"], "queued")
        self.assertEqual(self.last_run().status, "completed")
