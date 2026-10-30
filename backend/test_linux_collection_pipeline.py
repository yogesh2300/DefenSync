"""Linux collection regression tests: real pipeline, parser, ingestion and health on SQLite.

Only the SSH retrieval (CollectorService.collect_raw_lines) and the background ML
detection thread are replaced. No live SSH, no PostgreSQL rows, no real credentials.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import paramiko
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.api import servers as servers_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.encryption import encrypt_secret
from backend.core.exceptions import CollectionProcessingError, register_exception_handlers
from backend.database.models import Account, CollectionRun, Event, Server, User
from backend.health.status import HealthStatus
from backend.services.collector_service import CollectorService
from backend.services.ingestion_service import IngestionService
from backend.services.pipeline_service import PipelineService
from backend.services.server_service import ServerService, _run_post_collection_detection
from backend.services.transform_service import TransformService
from backend.test_azure_collector import session_factory
from backend.test_linux_cloud_isolation import _azure_event

ACCOUNT_A, ACCOUNT_B = "acct-a", "acct-b"
SSH_PASSWORD = "unit-test-ssh-password"

SECURE_LINES = [
    "Oct  5 10:15:01 ubuntu sshd[1201]: Accepted password for ysalve from 192.0.2.50 port 50122 ssh2",
    "Oct  5 10:16:44 ubuntu sshd[1209]: Failed password for invalid user admin from 198.51.100.7 port 41000 ssh2",
    "2026-10-05T10:17:02+0000 ubuntu sshd[1215]: Accepted publickey for ysalve from 192.0.2.51 port 50200 ssh2",
]


def retrieved(*, with_fallback_source: bool = True) -> dict:
    sources = {"journalctl": list(SECURE_LINES)}
    if with_fallback_source:
        sources["uname"] = ["Linux ubuntu 6.8.0-45-generic x86_64 GNU/Linux"]
    return {
        "host": "192.0.2.10",
        "secure_lines": list(SECURE_LINES),
        "audit_lines": [],
        "extra_lines": [],
        "sources": sources,
        "summary": {key: len(lines) for key, lines in sources.items()},
        "metrics": {"memory_usage": 41.5, "disk_usage": 22.0, "process_count": 180},
    }


def _ssh_auth_failure() -> ConnectionError:
    try:
        raise ConnectionError("SSH connection failed after 1 attempts") from paramiko.AuthenticationException("Authentication failed.")
    except ConnectionError as exc:
        return exc


class LinuxCollectionTestBase(unittest.TestCase):
    def setUp(self):
        self.session = session_factory()
        self.session.add_all([
            Account(id=ACCOUNT_A, name="Account A"),
            Account(id=ACCOUNT_B, name="Account B"),
            User(id="owner-a", username="owner_a", email="a@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
            User(id="analyst-b", username="analyst_b", email="b@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_B),
        ])
        self.server = Server(
            server_name="ubuntu-web", host="192.0.2.10", port=22, username="defensync",
            authentication_type="password", encrypted_password=encrypt_secret(SSH_PASSWORD),
            status="active", health_status=HealthStatus.UNKNOWN, owner_id="owner-a",
            created_by="owner-a", account_id=ACCOUNT_A, environment="production",
        )
        self.session.add(self.server)
        self.session.commit()
        self._thread_patcher = patch("backend.services.server_service.threading.Thread")
        self.thread_mock = self._thread_patcher.start()

    def tearDown(self):
        self._thread_patcher.stop()
        self.session.close()

    def collect(self, payload=None, *, side_effect=None):
        with patch.object(CollectorService, "collect_raw_lines", return_value=payload or retrieved(), side_effect=side_effect):
            return ServerService(self.session).collect_for_server(self.server.id)

    def linux_events(self):
        return self.session.scalars(select(Event).where(Event.server_id == self.server.id)).all()

    def event_count(self):
        return self.session.scalar(select(func.count(Event.id)))

    def last_run(self):
        return self.session.scalars(select(CollectionRun).order_by(CollectionRun.started_at.desc())).first()

    def api(self, user_id):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(servers_api.router, prefix="/api/v1/servers")
        user = self.session.get(User, user_id)
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: user
        return TestClient(app, raise_server_exceptions=False)


class LinuxCollectionPipelineTests(LinuxCollectionTestBase):
    def test_1_store_with_server_id_persists_instead_of_crashing(self):
        stats = PipelineService(self.session).process_raw_logs(
            secure_lines=SECURE_LINES, hostname="ubuntu-web", server_id=self.server.id, owner_id="owner-a",
        )
        self.assertEqual(stats["inserted"], 3)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(len(self.linux_events()), 3)

    def test_2_events_are_linux_private_and_scoped_to_server_account(self):
        self.collect()
        events = self.linux_events()
        self.assertEqual(len(events), 4)
        for event in events:
            self.assertEqual(event.source_type, "LINUX")
            self.assertEqual(event.data_origin, "LIVE_LINUX")
            self.assertEqual(event.data_scope, "PRIVATE")
            self.assertEqual(event.account_id, ACCOUNT_A)
            self.assertEqual(event.owner_id, "owner-a")
            self.assertIsNone(event.provider)
        self.assertEqual(
            sorted(e.event_type for e in events),
            ["Failed Login", "Successful Login", "Successful Login", "System Snapshot"],
        )

    def test_3_source_timestamp_kept_separate_from_collection_timestamp(self):
        before = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=5)
        self.collect()
        failed = next(e for e in self.linux_events() if e.event_type == "Failed Login")
        self.assertEqual(failed.timestamp_source, "SOURCE_EVENT")
        self.assertEqual((failed.timestamp.month, failed.timestamp.day, failed.timestamp.hour, failed.timestamp.minute), (10, 5, 10, 16))
        self.assertGreaterEqual(failed.collection_timestamp.replace(tzinfo=None), before)
        self.assertNotEqual(failed.timestamp, failed.collection_timestamp)
        snapshot = next(e for e in self.linux_events() if e.event_type == "System Snapshot")
        self.assertEqual(snapshot.timestamp_source, "SNAPSHOT_COLLECTION_TIME")

    def test_4_second_identical_collect_is_deduplicated(self):
        payload = retrieved(with_fallback_source=False)
        first = self.collect(payload)
        second = self.collect(payload)
        self.assertEqual(first["inserted"], 3)
        self.assertEqual(second["inserted"], 0)
        self.assertEqual(second["duplicates"], 3)
        self.assertTrue(second["success"])
        self.assertEqual(len(self.linux_events()), 3)

    def test_5_success_marks_online_and_completes_run(self):
        stats = self.collect()
        self.assertTrue(stats["success"])
        self.assertEqual(stats["collected_events"], 4)
        self.session.refresh(self.server)
        self.assertEqual(self.server.health_status, HealthStatus.ONLINE)
        self.assertIsNotNone(self.server.last_successful_collection)
        run = self.last_run()
        self.assertEqual((run.status, run.inserted, run.error_message), ("completed", 4, None))

    def test_successful_collection_queues_detection_once_with_server_scope(self):
        self.thread_mock.reset_mock()
        stats = self.collect()
        self.assertTrue(stats["success"])
        self.assertEqual(stats["detection"]["status"], "queued")
        self.assertIn("background", stats["detection"]["message"].lower())
        self.thread_mock.assert_called_once()
        kwargs = self.thread_mock.call_args.kwargs
        self.assertIs(kwargs["target"], _run_post_collection_detection)
        self.assertEqual(kwargs["args"], ("owner-a", self.server.id, ACCOUNT_A))
        self.assertTrue(kwargs["daemon"])

    def test_failed_collection_does_not_queue_detection(self):
        self.thread_mock.reset_mock()
        stats = self.collect(side_effect=_ssh_auth_failure())
        self.assertFalse(stats["success"])
        self.assertNotIn("detection", stats)
        self.thread_mock.assert_not_called()


class LinuxCollectionFailureTests(LinuxCollectionTestBase):
    def test_6_processing_failure_is_coded_error_and_not_offline(self):
        with patch.object(TransformService, "enrich_events", side_effect=RuntimeError("enrichment exploded")):
            with self.assertRaises(CollectionProcessingError) as ctx:
                self.collect()
        self.assertEqual(ctx.exception.details["code"], "COLLECTION_PROCESSING_FAILED")
        self.assertIn("RuntimeError", str(ctx.exception))
        self.session.refresh(self.server)
        self.assertEqual(self.server.health_status, HealthStatus.ERROR)
        self.assertNotEqual(self.server.health_status, HealthStatus.OFFLINE)
        run = self.last_run()
        self.assertEqual(run.status, "failed")
        self.assertIn("enrichment exploded", run.error_message)
        self.assertEqual(ctx.exception.details["run_id"], run.id)
        self.assertEqual(self.linux_events(), [])

    def test_7_ssh_failure_keeps_precise_ssh_status_and_no_exception(self):
        stats = self.collect(side_effect=_ssh_auth_failure())
        self.assertFalse(stats["success"])
        self.assertEqual(stats["errors"][0]["stage"], "collect")
        self.session.refresh(self.server)
        self.assertEqual(self.server.health_status, HealthStatus.AUTHENTICATION_FAILED)
        self.assertEqual(self.last_run().status, "failed")
        self.assertEqual(self.linux_events(), [])


class LinuxCollectionApiTests(LinuxCollectionTestBase):
    def post_collect(self, user_id="owner-a"):
        return self.api(user_id).post(f"/api/v1/servers/{self.server.id}/collect", json={"tail_lines": 500})

    def test_8_collect_endpoint_returns_counts(self):
        with patch.object(CollectorService, "collect_raw_lines", return_value=retrieved()):
            response = self.post_collect()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertEqual((body["inserted"], body["collected_events"], body["failed"]), (4, 4, 0))
        self.assertEqual(len(self.linux_events()), 4)

    def test_9_processing_failure_returns_safe_coded_error(self):
        with patch.object(CollectorService, "collect_raw_lines", return_value=retrieved()), \
             patch.object(PipelineService, "_store_events", side_effect=AttributeError("simulated store bug")):
            response = self.post_collect()
        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertEqual(body["code"], "COLLECTION_PROCESSING_FAILED")
        self.assertEqual(body["type"], "CollectionProcessingError")
        self.assertEqual(body["server_id"], self.server.id)
        self.assertIn("processing failed", body["error"])
        self.assertNotEqual(body["error"], "Internal server error.")
        for secret in (SSH_PASSWORD, self.server.encrypted_password):
            self.assertNotIn(secret, response.text)

    def test_10_linux_collect_is_isolated_from_cloud_and_other_accounts(self):
        cloud = _azure_event()
        cloud.update(owner_id="owner-a", account_id=ACCOUNT_A)
        IngestionService(self.session).ingest_bulk_events([cloud])
        cloud_before = [(e.id, e.hash, e.source_type, e.collection_timestamp)
                        for e in self.session.scalars(select(Event).where(Event.source_type == "CLOUD"))]
        self.assertEqual(len(cloud_before), 1)

        with patch.object(CollectorService, "collect_raw_lines", return_value=retrieved()) as retrieve:
            denied = self.post_collect("analyst-b")
            self.assertIn(denied.status_code, (403, 404))
            retrieve.assert_not_called()
            self.assertEqual(self.post_collect().status_code, 200)

        cloud_after = [(e.id, e.hash, e.source_type, e.collection_timestamp)
                       for e in self.session.scalars(select(Event).where(Event.source_type == "CLOUD"))]
        self.assertEqual(cloud_after, cloud_before)
        self.assertEqual({e.source_type for e in self.linux_events()}, {"LINUX"})
        self.assertEqual(self.event_count(), 5)

    def test_collect_endpoint_includes_detection_queue_on_success(self):
        with patch.object(CollectorService, "collect_raw_lines", return_value=retrieved()):
            response = self.post_collect()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["detection"]["status"], "queued")
        self.assertIn("DefenSync Intelligence", body["detection"]["message"])


class PostCollectionDetectionHelperTests(unittest.TestCase):
    def test_detection_failure_is_swallowed_and_does_not_raise(self):
        class Boom(Exception):
            pass

        class FakeSession:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        session = FakeSession()
        with patch("backend.database.connection.get_session", return_value=session), \
             patch("backend.services.server_service.DetectionService") as detection_cls:
            detection_cls.return_value.run_detection.side_effect = Boom("model failed")
            _run_post_collection_detection("owner-a", "server-1", ACCOUNT_A)
            detection_cls.return_value.run_detection.assert_called_once_with(
                owner_id="owner-a",
                server_id="server-1",
                account_id=ACCOUNT_A,
            )
            self.assertTrue(session.closed)


if __name__ == "__main__":
    unittest.main()
