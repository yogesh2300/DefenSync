"""Cross-user isolation: analyst A, analyst B (both without an application account, as in the
live database) and a platform ADMIN, exercised through the real API routers.

SQLite in-memory only; n8n delivery, SSH health checks and detection model runs are replaced
with doubles, so nothing leaves the process and no production data is touched.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import account as account_api
from backend.api import alerts as alerts_api
from backend.api import cloud as cloud_api
from backend.api import datasets as datasets_api
from backend.api import detection as detection_api
from backend.api import events as events_api
from backend.api import intelligence as intelligence_api
from backend.api import servers as servers_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.config import Settings
from backend.core.exceptions import register_exception_handlers
from backend.database.models import (
    Account,
    Alert,
    Base,
    CloudCollectionRun,
    CloudSource,
    DatasetImport,
    Event,
    Incident,
    RiskHistory,
    Server,
    User,
)
from backend.parser.openstack_parser import DATASET_NAME as OPENSTACK_DATASET
from backend.services.cloud.azure_collector import LAST_RUN, STATUS_COLLECTION_OK, STATUS_CONFIGURED
from backend.services.correlation_service import (
    INCIDENT_ID_MAX,
    CorrelationService,
    _tenant_incident_id,
    account_entity_type,
)

A, B, ADMIN = "analyst-a", "analyst-b", "admin-1"
T0 = datetime(2026, 10, 5, 9, 0, tzinfo=timezone.utc)


def azure_settings() -> Settings:
    return Settings.model_construct(
        SECRET_KEY=SecretStr("k"), AZURE_TENANT_ID="11111111-2222-3333-4444-555555555555",
        AZURE_CLIENT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AZURE_CLIENT_SECRET=SecretStr("s"),
        AZURE_LOG_ANALYTICS_WORKSPACE_ID="99999999-8888-7777-6666-555555555555",
    )


class IsolationBase(unittest.TestCase):
    def setUp(self):
        LAST_RUN.clear()
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.users = {
            "a": User(id=A, username="analyst_a", email="a@example.test", hashed_password="x", role="ANALYST"),
            "b": User(id=B, username="analyst_b", email="b@example.test", hashed_password="x", role="ANALYST"),
            "admin": User(id=ADMIN, username="admin", email="admin@example.test", hashed_password="x", role="ADMIN"),
        }
        self.session.add_all(self.users.values())
        self.session.add_all([
            Server(id="server-a", server_name="vm-a", host="192.0.2.1", username="u", owner_id=A, created_by=A),
            Server(id="server-b", server_name="vm-b", host="192.0.2.2", username="u", owner_id=B, created_by=B),
            CloudSource(id="source-a", tenant_id="t-a", client_id="c-a", encrypted_client_secret="enc", workspace_id="w-a",
                        owner_id=A, created_by=A),
            CloudCollectionRun(id="run-a", cloud_source_id="source-a", requested_by=A, collection_id="coll-a",
                               status="COMPLETED", window_start=T0, window_end=T0 + timedelta(minutes=15), rows_stored=7),
        ])
        # Same actor ("root") and the same timestamp for both analysts: identical correlation ids.
        for owner, server in ((A, "server-a"), (B, "server-b")):
            self._event(f"{owner}-login", owner, server)
            self.session.add(Alert(id=f"alert-{owner}", event_id=f"{owner}-login", owner_id=owner, server_id=server,
                                   title="Failed login", message="m", severity="high", risk_score=95))
        self.session.commit()

        self.n8n = patch("backend.services.n8n_notifier.N8nNotifier.from_settings", return_value=MagicMock())
        self.n8n.start()
        self.health = patch("backend.services.server_service.get_health_engine", return_value=MagicMock())
        self.health.start()
        self.detection = MagicMock()
        self.detection.run_detection.return_value = {"success": True, "events_analyzed": 0, "message": "stub"}

    def tearDown(self):
        self.n8n.stop()
        self.health.stop()
        LAST_RUN.clear()
        self.session.close()

    def _event(self, event_id, owner, server, *, username="root", when=T0, risk=95):
        self.session.add(Event(
            event_id=event_id, timestamp=when, hostname=server, username=username, event_type="Failed Login",
            category="authentication", severity="high", risk_score=risk, message="ssh auth failure",
            raw_log=event_id, hash=f"hash-{event_id}", owner_id=owner, server_id=server, source_type="LINUX",
        ))

    def client(self, who):
        app = FastAPI()
        register_exception_handlers(app)
        for router, prefix in (
            (servers_api.router, "/api/v1/servers"), (cloud_api.router, "/api/v1/cloud"),
            (events_api.router, "/api/v1/events"), (alerts_api.router, "/api/v1/alerts"),
            (intelligence_api.router, "/api/v1/intelligence"), (account_api.router, "/api/v1/account"),
            (datasets_api.router, "/api/v1/datasets"), (detection_api.router, "/api/v1/detection"),
        ):
            app.include_router(router, prefix=prefix)
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.users[who]
        app.dependency_overrides[cloud_api.get_azure_settings] = azure_settings
        app.dependency_overrides[detection_api.get_detection_service] = lambda: self.detection
        return TestClient(app)

    def correlate(self, who):
        response = self.client(who).post("/api/v1/intelligence/correlate")
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def incidents(self):
        return {row.incident_id: (row.owner_id, row.account_id) for row in self.session.scalars(select(Incident))}

    @staticmethod
    def event_ids(response):
        assert response.status_code == 200, response.text
        return sorted(row["event_id"] for row in response.json())


class AnalystIsolationTests(IsolationBase):
    def test_1_b_cannot_access_a_server(self):
        b = self.client("b")
        self.assertEqual(b.get("/api/v1/servers/server-a").status_code, 403)
        self.assertEqual([row["id"] for row in b.get("/api/v1/servers").json()], ["server-b"])
        self.assertEqual(self.client("a").get("/api/v1/servers/server-a").status_code, 200)

    def test_2_b_cannot_access_a_cloud_source(self):
        b = self.client("b")
        self.assertEqual(b.get("/api/v1/cloud/sources/source-a").status_code, 404)
        self.assertEqual(b.get("/api/v1/cloud/sources/source-a/collections").status_code, 404)
        self.assertEqual(b.get("/api/v1/cloud/sources").json()["count"], 0)
        self.assertEqual(self.client("a").get("/api/v1/cloud/sources/source-a").status_code, 200)

    def test_3_b_cannot_see_a_events(self):
        b = self.client("b")
        self.assertEqual(self.event_ids(b.get("/api/v1/events")), [f"{B}-login"])
        self.assertEqual(b.get("/api/v1/events", params={"server_id": "server-a"}).status_code, 403)
        self.assertEqual(self.event_ids(self.client("a").get("/api/v1/events")), [f"{A}-login"])

    def test_4_b_cannot_see_a_alerts(self):
        self.assertEqual(self.event_ids(self.client("b").get("/api/v1/alerts")), [f"{B}-login"])
        self.assertEqual(self.client("b").get("/api/v1/alerts", params={"server_id": "server-a"}).status_code, 403)

    def test_5_b_cannot_acknowledge_a_alert(self):
        response = self.client("b").post(f"/api/v1/alerts/alert-{A}/ack")
        self.assertNotEqual(response.status_code, 200)
        self.session.expire_all()
        self.assertFalse(self.session.get(Alert, f"alert-{A}").acknowledged)
        self.assertEqual(self.client("a").post(f"/api/v1/alerts/alert-{A}/ack").status_code, 200)

    def test_6_b_cannot_see_a_incidents(self):
        self.correlate("a")
        b_rows = self.client("b").get("/api/v1/intelligence/incidents").json()
        a_rows = self.client("a").get("/api/v1/intelligence/incidents").json()
        self.assertEqual(len(a_rows), 1)
        self.assertEqual(len(b_rows), 1)
        self.assertNotEqual(a_rows[0]["incident_id"], b_rows[0]["incident_id"])
        self.assertEqual(sorted(owner for owner, _ in self.incidents().values()), [A, B])
        self.assertEqual(self.client("b").get("/api/v1/account/summary").json()["incidents"], 1)

    def test_7_b_cannot_see_a_risk_history(self):
        self.correlate("a")
        self.correlate("b")
        owners = sorted(row.owner_id for row in self.session.scalars(select(RiskHistory)))
        self.assertEqual(owners, [A, B])
        self.assertEqual(self.client("b").get("/api/v1/account/summary").json()["risk_trend"], [])

    def test_8_b_cannot_see_a_azure_collection_metadata(self):
        LAST_RUN.set({"collection_id": "coll-a", "status": STATUS_COLLECTION_OK, "account_id": None, "records_inserted": 7})
        hidden = self.client("b").get("/api/v1/cloud/azure/status").json()
        self.assertEqual((hidden["last_collection"], hidden["status"]), (None, STATUS_CONFIGURED))
        own = self.client("a").get("/api/v1/cloud/azure/status").json()
        self.assertEqual((own["last_collection"]["records_inserted"], own["status"]), (7, STATUS_COLLECTION_OK))

    def test_8b_missing_accounts_never_match_each_other(self):
        LAST_RUN.set({"collection_id": "unknown-run", "status": STATUS_COLLECTION_OK, "account_id": None, "records_inserted": 3})
        for who in ("a", "b"):
            self.assertIsNone(self.client(who).get("/api/v1/cloud/azure/status").json()["last_collection"], who)
        self.assertEqual(self.client("admin").get("/api/v1/cloud/azure/status").json()["last_collection"]["records_inserted"], 3)

    def test_9_b_correlation_cannot_change_a_incident_owner(self):
        self.correlate("a")
        before = self.incidents()
        self.assertEqual(list(before.values()), [(A, None)])
        self.correlate("b")
        after = self.incidents()
        for incident_id, owner in before.items():
            self.assertEqual(after[incident_id], owner)
        self.assertEqual(sorted(owner for owner, _ in after.values()), [A, B])

    def test_10_admin_correlation_cannot_change_a_incident_owner(self):
        self.correlate("a")
        self.correlate("b")
        before = self.incidents()
        self.correlate("admin")
        self.assertEqual(self.incidents(), before)
        self.assertEqual(self.session.scalar(select(func.count(Incident.id)).where(Incident.owner_id.is_(None))), 0)
        self.assertEqual(self.session.scalar(select(func.count(RiskHistory.id)).where(RiskHistory.owner_id.is_(None))), 0)

    def test_10b_admin_first_correlation_assigns_each_incident_to_its_tenant(self):
        stored = self.correlate("admin")
        self.assertEqual(stored["count"], 2)
        self.assertEqual(sorted(owner for owner, _ in self.incidents().values()), [A, B])
        self.assertEqual(len(self.client("a").get("/api/v1/intelligence/incidents").json()), 1)
        self.assertEqual(len(self.client("b").get("/api/v1/intelligence/incidents").json()), 1)

    def test_11_same_incident_id_does_not_take_over_the_other_tenant(self):
        a_id = self.correlate("a")["incidents"][0]["incident_id"]
        b_id = self.correlate("b")["incidents"][0]["incident_id"]
        self.assertEqual(b_id, _tenant_incident_id(a_id, B, None))
        self.assertTrue(b_id.startswith(f"{a_id}~"))
        self.correlate("a")
        self.correlate("b")
        self.correlate("admin")
        self.assertEqual(self.incidents(), {a_id: (A, None), b_id: (B, None)})
        self.assertEqual([row["incident_id"] for row in self.client("a").get("/api/v1/intelligence/incidents").json()], [a_id])
        self.assertEqual([row["incident_id"] for row in self.client("b").get("/api/v1/intelligence/incidents").json()], [b_id])

    def test_12_admin_keeps_platform_wide_visibility(self):
        self.correlate("a")
        self.correlate("b")
        admin = self.client("admin")
        self.assertEqual({row["id"] for row in admin.get("/api/v1/servers").json()}, {"server-a", "server-b"})
        self.assertEqual(admin.get("/api/v1/cloud/sources/source-a").status_code, 200)
        self.assertEqual(self.event_ids(admin.get("/api/v1/events")), [f"{A}-login", f"{B}-login"])
        self.assertEqual(self.event_ids(admin.get("/api/v1/alerts")), [f"{A}-login", f"{B}-login"])
        self.assertEqual(len(admin.get("/api/v1/intelligence/incidents").json()), 2)
        LAST_RUN.set({"collection_id": "coll-a", "status": STATUS_COLLECTION_OK, "account_id": None, "records_inserted": 7})
        self.assertEqual(admin.get("/api/v1/cloud/azure/status").json()["last_collection"]["collection_id"], "coll-a")


class DatasetStatusIsolationTests(IsolationBase):
    def setUp(self):
        super().setUp()
        for owner, created in ((A, T0), (B, T0 + timedelta(hours=1))):
            self.session.add(DatasetImport(owner_id=owner, dataset_name=OPENSTACK_DATASET, source_file=f"{owner}.log",
                                           source_file_hash=f"hash-{owner}", status="COMPLETED", created_at=created))
        self.session.commit()

    def latest_owner(self, who, path):
        response = self.client(who).get(path)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        summary = body["openstack"]["summary"] if "openstack" in body else body["summary"]
        latest = summary["most_recent_import"]
        return latest["owner_id"] if latest else None

    def test_analyst_sees_only_their_own_last_import(self):
        for path in ("/api/v1/datasets/status", "/api/v1/datasets/openstack/status"):
            self.assertEqual(self.latest_owner("a", path), A, path)
            self.assertEqual(self.latest_owner("b", path), B, path)

    def test_admin_sees_platform_wide_last_import(self):
        self.assertEqual(self.latest_owner("admin", "/api/v1/datasets/openstack/status"), B)

    def test_bgl_and_hdfs_last_import_is_scoped(self):
        for path in ("/api/v1/datasets/bgl/status", "/api/v1/datasets/hdfs/status"):
            self.assertIsNone(self.client("a").get(path).json()["summary"]["most_recent_import"], path)


class AdminDetectionScopeTests(IsolationBase):
    def run_detection(self, who, **params):
        return self.client(who).post("/api/v1/detection/run", params=params)

    def test_admin_without_a_scope_is_refused_and_nothing_runs(self):
        self.assertEqual(self.run_detection("admin").status_code, 422)
        self.detection.run_detection.assert_not_called()

    def test_admin_server_run_uses_the_server_tenant(self):
        self.assertEqual(self.run_detection("admin", server_id="server-b").status_code, 200)
        self.detection.run_detection.assert_called_once_with(owner_id=B, server_id="server-b", account_id=None)

    def test_admin_owner_run_uses_that_user(self):
        self.assertEqual(self.run_detection("admin", owner_id=A).status_code, 200)
        self.detection.run_detection.assert_called_once_with(owner_id=A, server_id=None, account_id=None)
        self.assertEqual(self.run_detection("admin", owner_id="missing").status_code, 404)
        self.assertEqual(self.run_detection("admin", owner_id=A, server_id="server-b").status_code, 422)

    def test_analyst_run_is_unchanged_and_cannot_target_another_user(self):
        self.assertEqual(self.run_detection("a").status_code, 200)
        self.detection.run_detection.assert_called_once_with(owner_id=A, server_id=None, account_id=None)
        self.assertEqual(self.run_detection("a", owner_id=B).status_code, 403)
        self.assertEqual(self.run_detection("a", server_id="server-b").status_code, 403)
        self.assertEqual(self.detection.run_detection.call_count, 1)


class AccountScopedRegressionTests(unittest.TestCase):
    """Existing account-based ownership keeps working alongside the owner_id fallback."""

    def setUp(self):
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.session.add_all([Account(id="acct-a", name="A"), Account(id="acct-b", name="B")])
        for index, account in enumerate(("acct-a", "acct-b")):
            self.session.add(Event(
                event_id=f"evt-{account}", timestamp=T0, hostname="h", username="root", event_type="Failed Login",
                category="authentication", severity="high", risk_score=95, message="ssh auth failure", raw_log="r",
                hash=f"hash-{index}", owner_id=f"owner-{account}", account_id=account, source_type="LINUX",
            ))
        self.session.commit()
        self.service = CorrelationService(self.session, notifier=MagicMock())

    def tearDown(self):
        self.session.close()

    def test_account_runs_keep_their_own_incident_and_account_risk(self):
        self.service.correlate_and_store(owner_id="member-a", account_id="acct-a")
        self.service.correlate_and_store(owner_id="member-b", account_id="acct-b")
        self.service.correlate_and_store()
        rows = {row.account_id: row.owner_id for row in self.session.scalars(select(Incident))}
        self.assertEqual(rows, {"acct-a": "member-a", "acct-b": "member-b"})
        self.assertEqual(len(self.service.list_incidents(account_id="acct-a")), 1)
        series = self.session.scalars(select(RiskHistory.account_id).where(RiskHistory.entity_type == account_entity_type("LINUX")))
        self.assertEqual(sorted(series), ["acct-a", "acct-b"])

    def test_rerun_updates_the_tenant_row_in_place(self):
        first = self.service.correlate_and_store(owner_id="member-a", account_id="acct-a")[0]
        row_id = self.session.scalar(select(Incident.id))
        second = self.service.correlate_and_store(owner_id="member-a", account_id="acct-a")[0]
        self.assertEqual(first["incident_id"], second["incident_id"])
        self.assertEqual((second["id"], self.session.scalar(select(func.count(Incident.id)))), (row_id, 1))

    def test_account_member_and_admin_resolve_the_same_qualified_row(self):
        self.session.add(Incident(incident_id="root-1791190800", owner_id="someone-else", title="other tenant"))
        self.session.commit()
        self.service.correlate_and_store(owner_id="member-a", account_id="acct-a")
        self.service.correlate_and_store()
        rows = sorted((row.account_id or "", row.owner_id) for row in self.session.scalars(select(Incident)))
        self.assertEqual(rows, [("", "someone-else"), ("acct-a", "member-a"), ("acct-b", "owner-acct-b")])


class TenantIncidentIdTests(unittest.TestCase):
    def test_qualified_id_is_deterministic_bounded_and_tenant_specific(self):
        base = "root-1791190800"
        self.assertEqual(_tenant_incident_id(base, B, None), _tenant_incident_id(base, B, None))
        self.assertNotEqual(_tenant_incident_id(base, A, None), _tenant_incident_id(base, B, None))
        long_base = "cloud:" + "x" * 60 + "-1791190800"
        for owner in (A, B):
            self.assertLessEqual(len(_tenant_incident_id(long_base, owner, None)), INCIDENT_ID_MAX)
        self.assertNotEqual(_tenant_incident_id(long_base, A, None), _tenant_incident_id(long_base, B, None))


if __name__ == "__main__":
    unittest.main()
