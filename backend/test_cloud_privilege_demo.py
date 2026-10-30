"""Controlled Cloud privilege demo: one DEMO incident + one n8n webhook per successful collect.

No live Azure tenant, no real webhook, no email delivery claims.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from backend.core.environments import CLOUD
from backend.database.models import PRESENTATION_DATA_ORIGIN
from backend.services import collection_n8n_trigger, n8n_notifier
from backend.services.cloud.azure_normalizer import AZURE_ACTIVITY, normalize_record
from backend.services.cloud.presentation_telemetry import (
    DEMO_ACTOR,
    DEMO_EMAIL_SUBJECT,
    DEMO_OPERATION,
    DEMO_RESOURCE_GROUP,
    EXPECTED_LIVE_RISK,
    MARKER,
    security_demo_from_event,
)
from backend.services.correlation_service import CorrelationService
from backend.test_n8n_notifications import WEBHOOK_URL, FakeOpener
from backend.test_presentation_telemetry import PRESENTER, PresentationTestBase, empty_azure, flag

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
SETTINGS = "backend.services.cloud.presentation_telemetry.get_settings"
CLOUD_SETTINGS = "backend.services.cloud.cloud_source_service.get_settings"


def demo_settings(**overrides):
    base = dict(
        PRESENTATION_TELEMETRY_EMAILS="solo@example.test",
        CLOUD_DEMO_EVERY_SUCCESS=True,
        CLOUD_DEMO_N8N_EVERY_SUCCESS=True,
        N8N_NOTIFICATION_RECIPIENT_EMAILS="solo@example.test",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class LiveFailedScoringTests(unittest.TestCase):
    def test_failed_role_assignment_scores_70_via_normalizer(self):
        record = {
            "TenantId": "00000000-0000-0000-0000-presentation01",
            "TimeGenerated": "2026-10-30T12:00:00.000Z",
            "OperationNameValue": DEMO_OPERATION,
            "OperationName": "Create role assignment",
            "Caller": DEMO_ACTOR,
            "ActivityStatusValue": "Failed",
            "EventDataId": "demo-failed-owner",
            "CorrelationId": "corr-demo",
            "ResourceGroup": DEMO_RESOURCE_GROUP,
            "_ResourceId": f"/subscriptions/x/resourceGroups/{DEMO_RESOURCE_GROUP}/providers/Microsoft.Authorization/roleAssignments/ra",
        }
        payload = normalize_record(
            AZURE_ACTIVITY,
            record,
            owner_id="owner-1",
            account_id=None,
            collected_at=NOW,
            collection_id="col-1",
        )
        self.assertEqual(payload["risk_score"], EXPECTED_LIVE_RISK)
        self.assertEqual(payload["severity"], "medium")
        self.assertEqual(payload["event_type"], "CLOUD_PRIVILEGE_CHANGE")


class PrivilegeDemoFlowTests(PresentationTestBase):
    def setUp(self):
        from backend.test_cloud_sources import CloudSourceTestBase

        CloudSourceTestBase.setUp(self)
        interval = patch("backend.services.presentation_trigger.choose_interval", return_value=1)
        interval.start()
        self.addCleanup(interval.stop)
        self.opener = FakeOpener(status=200)
        self.notifier = n8n_notifier.N8nNotifier(WEBHOOK_URL, opener=self.opener, background=False, timeout=1.0)
        self._settings = patch(SETTINGS, return_value=demo_settings())
        self._settings.start()
        self.addCleanup(self._settings.stop)
        self._cloud_settings = patch(CLOUD_SETTINGS, return_value=demo_settings())
        self._cloud_settings.start()
        self.addCleanup(self._cloud_settings.stop)
        self._cloud_n8n = patch(
            "backend.services.cloud.cloud_source_service.record_cloud_success",
            side_effect=self._record_cloud,
        )
        self._cloud_n8n.start()
        self.addCleanup(self._cloud_n8n.stop)
        self._recipients = patch(
            "backend.services.n8n_notifier.resolve_collection_recipient_emails",
            return_value=["solo@example.test"],
        )
        self._recipients.start()
        self.addCleanup(self._recipients.stop)

    def _record_cloud(self, session, **kwargs):
        return collection_n8n_trigger.record_successful_collection(
            session,
            source_type=CLOUD,
            collection_run_id=kwargs["collection_run_id"],
            owner_id=kwargs.get("owner_id"),
            account_id=kwargs.get("account_id"),
            outcome=collection_n8n_trigger.OUTCOME_CLOUD_SUCCESS,
            completed_at=kwargs.get("completed_at") or NOW,
            notifier=self.notifier,
            security_demo=kwargs.get("security_demo"),
            trigger_every=kwargs.get("trigger_every") or 1,
            policy=kwargs.get("policy") or "cloud_demo_every_success",
            now=NOW,
        )

    def test_zero_azure_rows_still_creates_one_demo_incident(self):
        with flag():
            source = self.create_source(PRESENTER)
            body = self.collect(PRESENTER, source["id"], empty_azure())
        self.assertEqual((body["records_retrieved"], body["records_inserted"]), (0, 0))
        self.assertTrue(body["demo_feedback"]["demo_incident_created"])
        self.assertEqual(body["presentation_trigger_risk_score"], 70)
        (trigger,) = self.triggers()
        self.assertEqual(trigger.data_origin, PRESENTATION_DATA_ORIGIN)
        self.assertEqual(trigger.risk_score, 70)
        self.assertEqual(trigger.actor_id, DEMO_ACTOR)
        self.assertIn("DEMO", trigger.message)
        self.assertTrue(trigger.message.endswith(MARKER))
        alerts = self.api(PRESENTER).get("/api/v1/alerts").json()
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["title"].startswith("DEMO:"))
        self.assertEqual(alerts[0]["risk_score"], 70)
        self.assertEqual((alerts[0].get("risk_level") or "").lower(), "high")
        self.assertTrue(alerts[0].get("is_demo"))
        self.assertEqual(alerts[0].get("demo_label"), "DEMO")

    def test_every_success_sends_one_n8n_and_retry_is_idempotent(self):
        with flag():
            source = self.create_source(PRESENTER)
            first = self.collect(PRESENTER, source["id"], empty_azure())
        self.assertEqual(first["collection_n8n"]["dispatch_status"], collection_n8n_trigger.STATUS_SENT)
        self.assertEqual(first["collection_n8n"]["sequence_number"], 1)
        self.assertEqual(first["collection_n8n"]["trigger_every"], 1)
        self.assertEqual(first["collection_n8n"]["policy"], "cloud_demo_every_success")
        self.assertEqual(first["collection_n8n"]["email_delivery"], "unknown")
        self.assertEqual(len(self.opener.payloads), 1)
        payload = self.opener.payloads[0]
        self.assertEqual(payload["security_demo"]["risk_score"], 70)
        self.assertEqual(payload["notification"]["suggested_subject"], DEMO_EMAIL_SUBJECT)
        self.assertEqual(payload["notification"]["recipient_emails"][0], "solo@example.test")
        html = payload["notification"].get("suggested_html") or ""
        fields = payload["notification"].get("email_fields") or {}
        self.assertIn("DEMO", html)
        self.assertIn("70/100", html)
        self.assertIn("demo-suspicious-user", html)
        self.assertIn("demo-resource-group", html)
        self.assertIn("Recommended Action", html)
        self.assertIn("Incident ID", html)
        self.assertEqual(fields.get("severity"), "High")
        self.assertEqual(fields.get("confidence"), "N/A")
        self.assertEqual(fields.get("event_count"), "1")
        self.assertEqual(fields.get("label"), "DEMO / SIMULATED")
        self.assertEqual(fields.get("detected_activity"), "Suspicious Cloud Privilege Change")
        self.assertTrue(fields.get("incident_id"))
        self.assertEqual(payload["security_demo"]["demo_label"], "DEMO")
        again = collection_n8n_trigger.record_successful_collection(
            self.session,
            source_type=CLOUD,
            collection_run_id=first["collection_run"]["id"],
            owner_id=PRESENTER,
            account_id=None,
            outcome=collection_n8n_trigger.OUTCOME_CLOUD_SUCCESS,
            completed_at=NOW,
            notifier=self.notifier,
            security_demo=first.get("security_demo"),
            trigger_every=1,
            policy="cloud_demo_every_success",
            now=NOW,
        )
        self.assertEqual(again["dispatch_status"], collection_n8n_trigger.STATUS_SENT)
        self.assertEqual(again.get("reason"), "duplicate_run")
        self.assertEqual(len(self.opener.payloads), 1)
        self.assertEqual(len(self.triggers()), 1)

    def test_second_success_creates_second_demo_and_second_notification(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"], empty_azure())
            second = self.collect(PRESENTER, source["id"], empty_azure())
        self.assertEqual(len(self.triggers()), 2)
        self.assertEqual(len(self.presentation_alerts()), 2)
        self.assertEqual(second["collection_n8n"]["sequence_number"], 2)
        self.assertEqual(second["collection_n8n"]["dispatch_status"], collection_n8n_trigger.STATUS_SENT)
        self.assertEqual(len(self.opener.payloads), 2)
        self.assertNotEqual(self.opener.payloads[0]["event_id"], self.opener.payloads[1]["event_id"])

    def test_failed_collection_creates_no_demo(self):
        from backend.test_azure_collector import FakeAzure
        from backend.test_cloud_sources import token_failure

        with flag():
            source = self.create_source(PRESENTER)
            failed = self.collect(PRESENTER, source["id"], FakeAzure(token_response=token_failure(7000215)))
        self.assertEqual(failed["status"], "COLLECTION_FAILED")
        self.assertEqual(self.triggers(), [])
        self.assertEqual(self.presentation_alerts(), [])
        self.assertEqual(len(self.opener.payloads), 0)

    def test_correlation_payload_once(self):
        with flag():
            source = self.create_source(PRESENTER)
            self.collect(PRESENTER, source["id"], empty_azure())
        self.opener.requests.clear()
        notifier = n8n_notifier.N8nNotifier(WEBHOOK_URL, opener=self.opener, background=False)
        CorrelationService(self.session, notifier=notifier).correlate_and_store(owner_id=PRESENTER)
        privilege = [
            p for p in self.opener.payloads
            if p.get("event") == n8n_notifier.EVENT_CREATED and p.get("security_demo", {}).get("simulated")
        ]
        self.assertEqual(len(privilege), 1)
        body = privilege[0]
        self.assertEqual(body["security_demo"]["initiating_user"], DEMO_ACTOR)
        self.assertEqual(body["security_demo"]["operation"], DEMO_OPERATION)
        secrets = json.dumps(body).lower()
        for banned in ("password", "client_secret", "otp", "bearer ", "access_token"):
            self.assertNotIn(banned, secrets)


if __name__ == "__main__":
    unittest.main()
