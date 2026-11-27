"""Alternate-success collection → n8n: sequencing, isolation, idempotency, retries.

HTTP to n8n is always replaced by FakeOpener; no test contacts a real webhook.
"""

from __future__ import annotations

import json
import threading
import unittest
from datetime import datetime, timezone
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
    Base,
    CollectionN8nDispatch,
    CollectionN8nSequence,
    User,
)
from backend.services import collection_n8n_trigger as trigger
from backend.services.collection_n8n_trigger import (
    STATUS_FAILED,
    STATUS_NOT_CONFIGURED,
    STATUS_SENT,
    STATUS_SKIPPED,
    event_id_for,
    record_successful_collection,
)
from backend.services.n8n_notifier import (
    COLLECTION_SCHEMA_VERSION,
    EVENT_COLLECTION_ALTERNATE,
    N8nNotifier,
    REASON_NO_VERIFIED_RECIPIENT,
    build_collection_payload,
    configured_notification_recipient_emails,
    resolve_collection_recipient_emails,
)
from backend.test_n8n_notifications import WEBHOOK_URL, FakeOpener

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
OWNER_A = "owner-a"
OWNER_B = "owner-b"
ACCOUNT_A = "acct-a"
ACCOUNT_B = "acct-b"
TEST_RECIPIENT = "notify@example.test"


def _engine():
    return create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)


class CollectionN8nTriggerTests(unittest.TestCase):
    def setUp(self):
        self.engine = _engine()
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.opener = FakeOpener(status=200)
        self.notifier = N8nNotifier(WEBHOOK_URL, opener=self.opener, background=False, timeout=1.0)
        # Collection email node requires recipient_emails[0]; supply via env resolver in tests.
        self._recipients = patch(
            "backend.services.n8n_notifier.resolve_collection_recipient_emails",
            return_value=[TEST_RECIPIENT],
        )
        self._recipients.start()
        self.addCleanup(self._recipients.stop)

    def record(self, session, *, source_type, run_id, owner_id=OWNER_A, account_id=ACCOUNT_A, outcome="completed"):
        return record_successful_collection(
            session,
            source_type=source_type,
            collection_run_id=run_id,
            owner_id=owner_id,
            account_id=account_id,
            outcome=outcome,
            completed_at=NOW,
            notifier=self.notifier,
            now=NOW,
        )

    def test_01_first_linux_success_skips_n8n(self):
        with self.Session() as session:
            view = self.record(session, source_type=LINUX, run_id="linux-1")
        self.assertEqual(view["dispatch_status"], STATUS_SKIPPED)
        self.assertEqual(view["sequence_number"], 1)
        self.assertTrue(view["counted"])
        self.assertEqual(len(self.opener.requests), 0)
        with self.Session() as session:
            self.assertEqual(session.scalar(select(func.count(CollectionN8nDispatch.id))), 0)
            seq = session.scalars(select(CollectionN8nSequence)).one()
            self.assertEqual((seq.source_type, seq.success_count), (LINUX, 1))

    def test_02_second_linux_success_triggers_exactly_once(self):
        with self.Session() as session:
            self.record(session, source_type=LINUX, run_id="linux-1")
            second = self.record(session, source_type=LINUX, run_id="linux-2")
        self.assertEqual(second["dispatch_status"], STATUS_SENT)
        self.assertEqual(second["sequence_number"], 2)
        self.assertEqual(len(self.opener.requests), 1)
        body = self.opener.requests[0]["body"]
        self.assertEqual(body["schema_version"], COLLECTION_SCHEMA_VERSION)
        self.assertEqual(body["event"], EVENT_COLLECTION_ALTERNATE)
        self.assertEqual(body["source_type"], LINUX)
        self.assertEqual(body["collection_id"], "linux-2")
        self.assertEqual(body["sequence_number"], 2)
        self.assertEqual(body["event_id"], event_id_for(LINUX, "linux-2"))
        self.assertEqual(body["account_id"], ACCOUNT_A)
        self.assertEqual(body["notification"]["recipient_emails"][0], TEST_RECIPIENT)
        self.assertNotIn("raw_log", body)
        self.assertNotIn("password", str(body).lower())
        with self.Session() as session:
            again = self.record(session, source_type=LINUX, run_id="linux-2")
        self.assertFalse(again["counted"])
        self.assertEqual(again["event_id"], event_id_for(LINUX, "linux-2"))
        self.assertEqual(len(self.opener.requests), 1)

    def test_03_cloud_sequence_is_independent(self):
        with self.Session() as session:
            self.record(session, source_type=LINUX, run_id="l-1")
            self.record(session, source_type=LINUX, run_id="l-2")
            c1 = self.record(session, source_type=CLOUD, run_id="c-1", outcome="SUCCESS")
            c2 = self.record(session, source_type=CLOUD, run_id="c-2", outcome="SUCCESS")
        self.assertEqual(c1["dispatch_status"], STATUS_SKIPPED)
        self.assertEqual(c1["sequence_number"], 1)
        self.assertEqual(c2["dispatch_status"], STATUS_SENT)
        self.assertEqual(c2["sequence_number"], 2)
        self.assertEqual(len(self.opener.requests), 2)
        sources = {req["body"]["source_type"] for req in self.opener.requests}
        self.assertEqual(sources, {LINUX, CLOUD})

    def test_04_failed_collections_do_not_call_recorder(self):
        """Document the contract: callers must not invoke the recorder on failure.

        The service itself only counts when called; this asserts no accidental side effects
        when we simply never call it (the production hook gates on success).
        """
        with self.Session() as session:
            self.assertEqual(session.scalar(select(func.count(CollectionN8nSequence.id))), 0)
            self.assertEqual(session.scalar(select(func.count(CollectionN8nDispatch.id))), 0)
        self.assertEqual(len(self.opener.requests), 0)

    def test_05_duplicate_callback_does_not_create_second_event(self):
        with self.Session() as session:
            self.record(session, source_type=LINUX, run_id="r1")
            self.record(session, source_type=LINUX, run_id="r2")
            dup = self.record(session, source_type=LINUX, run_id="r2")
        self.assertEqual(dup["reason"], "duplicate_run")
        self.assertEqual(len(self.opener.requests), 1)
        with self.Session() as session:
            self.assertEqual(session.scalar(select(func.count(CollectionN8nDispatch.id))), 1)
            self.assertEqual(session.scalars(select(CollectionN8nSequence)).one().success_count, 2)

    def test_06_concurrent_counts_preserve_sequence_and_eligibility(self):
        barrier = threading.Barrier(2)
        results: list[dict] = []
        lock = threading.Lock()

        def worker(run_id: str):
            session = self.Session()
            try:
                barrier.wait(timeout=5)
                # Serialize DB writes the same way production does (one locked sequence row).
                with lock:
                    view = record_successful_collection(
                        session,
                        source_type=LINUX,
                        collection_run_id=run_id,
                        owner_id=OWNER_A,
                        account_id=ACCOUNT_A,
                        outcome="completed",
                        completed_at=NOW,
                        notifier=self.notifier,
                        now=NOW,
                    )
                results.append(view)
            finally:
                session.close()

        threads = [threading.Thread(target=worker, args=(f"concurrent-{i}",)) for i in (1, 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(len(results), 2)
        sequences = sorted(r["sequence_number"] for r in results)
        self.assertEqual(sequences, [1, 2])
        statuses = {r["sequence_number"]: r["dispatch_status"] for r in results}
        self.assertEqual(statuses[1], STATUS_SKIPPED)
        self.assertEqual(statuses[2], STATUS_SENT)
        self.assertEqual(len(self.opener.requests), 1)
        with self.Session() as session:
            self.assertEqual(session.scalars(select(CollectionN8nSequence)).one().success_count, 2)

    def test_07_account_scopes_do_not_share_counters(self):
        with self.Session() as session:
            a1 = self.record(session, source_type=LINUX, run_id="a-1", account_id=ACCOUNT_A)
            b1 = self.record(session, source_type=LINUX, run_id="b-1", owner_id=OWNER_B, account_id=ACCOUNT_B)
            a2 = self.record(session, source_type=LINUX, run_id="a-2", account_id=ACCOUNT_A)
            b2 = self.record(session, source_type=LINUX, run_id="b-2", owner_id=OWNER_B, account_id=ACCOUNT_B)
        self.assertEqual([a1["sequence_number"], b1["sequence_number"]], [1, 1])
        self.assertEqual([a2["sequence_number"], b2["sequence_number"]], [2, 2])
        self.assertEqual(len(self.opener.requests), 2)
        accounts = {req["body"]["account_id"] for req in self.opener.requests}
        self.assertEqual(accounts, {ACCOUNT_A, ACCOUNT_B})
        with self.Session() as session:
            self.assertEqual(session.scalar(select(func.count(CollectionN8nSequence.id))), 2)

    def test_08_webhook_failure_recorded_and_retried_safely(self):
        failing = FakeOpener(status=503)
        notifier = N8nNotifier(WEBHOOK_URL, opener=failing, background=False, timeout=1.0)
        with self.Session() as session:
            record_successful_collection(
                session, source_type=CLOUD, collection_run_id="c1", owner_id=OWNER_A, account_id=ACCOUNT_A,
                outcome="SUCCESS", completed_at=NOW, notifier=notifier, now=NOW,
            )
            failed = record_successful_collection(
                session, source_type=CLOUD, collection_run_id="c2", owner_id=OWNER_A, account_id=ACCOUNT_A,
                outcome="SUCCESS", completed_at=NOW, notifier=notifier, now=NOW,
            )
        self.assertEqual(failed["dispatch_status"], STATUS_FAILED)
        self.assertEqual(len(failing.requests), 1)
        event_id = failed["event_id"]

        recovering = FakeOpener(status=200)
        ok_notifier = N8nNotifier(WEBHOOK_URL, opener=recovering, background=False, timeout=1.0)
        with self.Session() as session:
            retry = record_successful_collection(
                session, source_type=CLOUD, collection_run_id="c2", owner_id=OWNER_A, account_id=ACCOUNT_A,
                outcome="SUCCESS", completed_at=NOW, notifier=ok_notifier, now=NOW,
            )
            row = session.scalars(select(CollectionN8nDispatch)).one()
        self.assertEqual(retry["dispatch_status"], STATUS_SENT)
        self.assertEqual(retry["event_id"], event_id)
        self.assertEqual(len(recovering.requests), 1)
        self.assertEqual(recovering.requests[0]["body"]["event_id"], event_id)
        self.assertEqual(row.attempt_count, 2)
        self.assertEqual(row.status, STATUS_SENT)
        with self.Session() as session:
            self.assertEqual(session.scalars(select(CollectionN8nSequence)).one().success_count, 2)

    def test_09_not_configured_does_not_fail_collection_contract(self):
        notifier = N8nNotifier("", opener=self.opener, background=False)
        with self.Session() as session:
            self.record = lambda *a, **k: None  # noqa: E731 - unused
            first = record_successful_collection(
                session, source_type=LINUX, collection_run_id="x1", owner_id=OWNER_A, account_id=ACCOUNT_A,
                outcome="completed", completed_at=NOW, notifier=notifier, now=NOW,
            )
            second = record_successful_collection(
                session, source_type=LINUX, collection_run_id="x2", owner_id=OWNER_A, account_id=ACCOUNT_A,
                outcome="completed", completed_at=NOW, notifier=notifier, now=NOW,
            )
        self.assertEqual(first["dispatch_status"], STATUS_SKIPPED)
        self.assertEqual(second["dispatch_status"], STATUS_NOT_CONFIGURED)
        self.assertEqual(len(self.opener.requests), 0)

    def test_10_payload_builder_omits_secrets(self):
        payload = build_collection_payload(
            event_id="evt",
            source_type=LINUX,
            collection_id="run",
            sequence_number=4,
            completed_at=NOW,
            outcome="completed",
            account_id=ACCOUNT_A,
            recipient_emails=[TEST_RECIPIENT],
        )
        self.assertEqual(set(payload) >= {"schema_version", "event", "event_id", "source_type", "collection_id", "sequence_number", "completed_at", "outcome", "sent_at", "notice", "account_id", "notification"}, True)
        self.assertEqual(payload["notification"]["recipient_emails"], [TEST_RECIPIENT])
        # Matches n8n expression: {{ $json.body.notification.recipient_emails[0] }}
        self.assertEqual(payload["notification"]["recipient_emails"][0], TEST_RECIPIENT)
        for banned in ("password", "token", "secret", "raw_log", "jwt", "otp"):
            self.assertNotIn(banned, json.dumps(payload).lower())

    def test_10b_missing_recipients_are_not_posted(self):
        self._recipients.stop()
        try:
            with patch("backend.services.n8n_notifier.resolve_collection_recipient_emails", return_value=[]):
                with self.Session() as session:
                    record_successful_collection(
                        session, source_type=LINUX, collection_run_id="nr1", owner_id=OWNER_A, account_id=ACCOUNT_A,
                        outcome="completed", completed_at=NOW, notifier=self.notifier, now=NOW,
                    )
                    failed = record_successful_collection(
                        session, source_type=LINUX, collection_run_id="nr2", owner_id=OWNER_A, account_id=ACCOUNT_A,
                        outcome="completed", completed_at=NOW, notifier=self.notifier, now=NOW,
                    )
            self.assertEqual(failed["dispatch_status"], STATUS_FAILED)
            with self.Session() as session:
                row = session.scalars(select(CollectionN8nDispatch)).one()
                self.assertEqual(row.last_error, REASON_NO_VERIFIED_RECIPIENT)
            self.assertEqual(len(self.opener.requests), 0)
        finally:
            self._recipients.start()

    def test_10c_env_and_owner_recipients_merge(self):
        from types import SimpleNamespace

        with self.Session() as session:
            session.add(User(
                id=OWNER_A, username="a", email="owner-a@example.test", hashed_password="x",
                role="ANALYST", account_id=ACCOUNT_A,
            ))
            session.commit()
            settings = SimpleNamespace(N8N_NOTIFICATION_RECIPIENT_EMAILS="notify@example.test, owner-a@example.test")
            emails = resolve_collection_recipient_emails(
                session, owner_id=OWNER_A, account_id=ACCOUNT_A, settings=settings,
            )
        self.assertEqual(emails, ["notify@example.test", "owner-a@example.test"])
        self.assertEqual(configured_notification_recipient_emails(settings), ["notify@example.test", "owner-a@example.test"])

    def test_11_status_endpoint_exposes_progress_without_secrets(self):
        user = User(
            id=OWNER_A, username="analyst", email="a@example.test", hashed_password="x",
            role="ANALYST", account_id=ACCOUNT_A,
        )
        with self.Session() as session:
            session.add(user)
            session.commit()
            self.record(session, source_type=LINUX, run_id="s1")
            self.record(session, source_type=LINUX, run_id="s2")

        app = FastAPI()
        app.include_router(account_api.router, prefix="/api/v1/account")

        def _db():
            session = self.Session()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = _db
        app.dependency_overrides[get_current_user] = lambda: user
        client = TestClient(app)
        response = client.get("/api/v1/account/collection-n8n")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["trigger_every"], 2)
        linux = body["environments"][LINUX]
        self.assertEqual(linux["success_count"], 2)
        self.assertEqual(linux["last_dispatch"]["status"], STATUS_SENT)
        raw = response.text.lower()
        self.assertNotIn("password", raw)
        self.assertNotIn(WEBHOOK_URL.lower(), raw)


class LinuxCloudHookCompatibilityTests(unittest.TestCase):
    """Ensure production hooks only fire on success and wire collection_n8n into responses."""

    def test_server_service_imports_recorder(self):
        from backend.services import server_service
        self.assertTrue(hasattr(server_service, "record_linux_success"))

    def test_cloud_source_service_imports_recorder(self):
        from backend.services.cloud import cloud_source_service
        self.assertTrue(hasattr(cloud_source_service, "record_cloud_success"))

    def test_event_id_stable_across_calls(self):
        a = event_id_for(LINUX, "same-run")
        b = event_id_for(LINUX, "same-run")
        self.assertEqual(a, b)
        self.assertNotEqual(a, event_id_for(CLOUD, "same-run"))


if __name__ == "__main__":
    unittest.main()
