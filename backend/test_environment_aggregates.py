"""Step 1.5 environment-aware dashboard and account aggregates.

Linux and cloud aggregates are computed independently: no Linux row contributes
to a cloud aggregate, no cloud row to a Linux aggregate, unknown sources to
neither, and GLOBAL research corpora to no account aggregate.
SQLite in-memory only; no live Azure, SSH, or PostgreSQL.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import account as account_api
from backend.api import alerts as alerts_api
from backend.api import dashboard as dashboard_api
from backend.api import events as events_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.environments import CLOUD, LINUX, normalize_environment
from backend.database import crud
from backend.database.models import (
    DATA_SCOPE_GLOBAL,
    DATA_SCOPE_PRIVATE,
    Account,
    Alert,
    Base,
    Detection,
    Event,
    Incident,
    RiskHistory,
    User,
)
from backend.database.scope import event_visibility_clause, with_environment
from backend.services.account_service import AccountService
from backend.services.alert_service import AlertService
from backend.services.analytics_service import AnalyticsService
from backend.services.global_intelligence_service import GlobalIntelligenceService

ACCOUNT_ID = "acct-1"
OTHER_ACCOUNT_ID = "acct-2"
T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _user(user_id="user-1", account_id=ACCOUNT_ID, role="ANALYST"):
    return User(
        id=user_id,
        username=user_id,
        email=f"{user_id}@example.test",
        hashed_password="not-a-real-hash",
        role=role,
        account_id=account_id,
    )


class _Builder:
    def __init__(self, session):
        self.session = session
        self.index = 0

    def event(self, source_type, risk, *, event_type="Activity", account_id=ACCOUNT_ID, scope=DATA_SCOPE_PRIVATE,
              origin=None, provider=None, username="alice", alert=False, anomaly=False):
        self.index += 1
        event_id = f"evt-{self.index}"
        self.session.add(Event(
            event_id=event_id,
            timestamp=T0 + timedelta(minutes=self.index),
            hostname="host",
            username=username,
            actor_id=username,
            source_ip=f"10.0.0.{self.index}",
            event_type=event_type,
            category="test",
            severity="high" if risk >= 70 else "info",
            risk_score=risk,
            message=event_type,
            raw_log=f"raw-{self.index}",
            hash=f"hash-{self.index}",
            owner_id="owner-1",
            account_id=account_id,
            data_scope=scope,
            source_type=source_type,
            provider=provider,
            data_origin=origin or ("LIVE_LINUX" if source_type == "LINUX" else "AZURE_ACTIVITY_LOG_FILE"),
        ))
        if alert:
            self.session.add(Alert(
                event_id=event_id, owner_id="owner-1", account_id=account_id, title=event_type, message=event_type,
                severity="critical", risk_score=risk, detection_type="rule_based",
            ))
        if anomaly:
            self.session.add(Detection(
                server_id="unassigned", owner_id="owner-1", account_id=account_id, event_id=event_id,
                is_anomaly=True, risk_score=risk,
            ))
        return event_id

    def incident(self, source, *, account_id=ACCOUNT_ID, title="Correlated activity"):
        self.index += 1
        self.session.add(Incident(
            incident_id=f"inc-{self.index}", owner_id="owner-1", account_id=account_id, title=title,
            risk_score=50, confidence=50, actor="alice", source=source,
        ))

    def risk(self, entity_type, score, *, account_id=ACCOUNT_ID, minute=0):
        self.session.add(RiskHistory(
            owner_id="owner-1", account_id=account_id, entity_type=entity_type, entity_key=f"account:{account_id}",
            timestamp=T0 + timedelta(minutes=minute), risk_score=score, source="account_risk",
        ))

    def noise(self):
        """Rows that must never reach a Linux or Cloud account aggregate."""
        # GLOBAL research corpora (public datasets / synthetic), including cloud-typed rows.
        self.event("CLOUD", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="OPENSTACK", account_id=None, alert=True, anomaly=True)
        self.event("CLOUD", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="HDFS", account_id=None)
        self.event("HPC", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="BGL", account_id=None)
        self.event("BEHAVIORAL", 99, scope=DATA_SCOPE_GLOBAL, origin="SYNTHETIC", account_id=None)
        self.event("LINUX", 99, scope=DATA_SCOPE_GLOBAL, origin="SYNTHETIC_CLOUD_DEMO", account_id=None)
        # Private but unknown source type, and private HPC/behavioral rows in the same account.
        self.event("MYSTERY_SOURCE", 99, alert=True, anomaly=True)
        self.event("HPC", 99, origin="BGL_IMPORT", alert=True, anomaly=True)
        self.event("BEHAVIORAL", 99, origin="BEHAVIORAL_IMPORT")
        # Another account's Linux and Cloud telemetry.
        self.event("LINUX", 99, account_id=OTHER_ACCOUNT_ID, alert=True, anomaly=True)
        self.event("CLOUD", 99, account_id=OTHER_ACCOUNT_ID, alert=True, anomaly=True)
        self.incident("Linux", account_id=OTHER_ACCOUNT_ID)
        self.incident("Azure", account_id=OTHER_ACCOUNT_ID)
        # Incidents of other or unknown environments in this account.
        self.incident("BGL")
        self.incident("Behavioral")
        self.incident("")


def _seed_risk_scenario(session):
    """Linux risk 20 vs Cloud risk 95 (tests A and B)."""
    b = _Builder(session)
    session.add_all([Account(id=ACCOUNT_ID, name="Acct"), Account(id=OTHER_ACCOUNT_ID, name="Other")])
    for _ in range(4):
        b.event("LINUX", 20)
    for _ in range(2):
        b.event("CLOUD", 95, event_type="CLOUD_RESOURCE_OPERATION")
    b.risk("account", 20)
    b.risk("cloud_account", 95)
    b.noise()
    session.commit()


def _seed_count_scenario(session):
    """Linux 5 events / 1 high-risk / 2 incidents; Cloud 3 events / 2 high-risk / 4 incidents (tests C-E)."""
    b = _Builder(session)
    session.add_all([Account(id=ACCOUNT_ID, name="Acct"), Account(id=OTHER_ACCOUNT_ID, name="Other")])
    b.event("LINUX", 80, event_type="Failed Login", alert=True, anomaly=True)
    b.event("LINUX", 10, event_type="Successful Login")
    b.event("LINUX", 10, event_type="Failed Login")
    b.event("LINUX", 10)
    b.event("LINUX", 10)
    b.event("CLOUD", 90, event_type="CLOUD_LOGIN_FAILURE", alert=True, anomaly=True)
    b.event("CLOUD", 75, event_type="CLOUD_PRIVILEGE_CHANGE", alert=True, anomaly=True)
    b.event("CLOUD", 30, event_type="CLOUD_LOGIN_SUCCESS")
    b.incident("Linux")
    b.incident("Linux")
    b.incident("Azure")
    b.incident("Azure", title="Correlated Linux-looking title")
    b.incident("Cloud")
    b.incident("Azure")
    b.noise()
    session.commit()


class EnvironmentAggregateTests(unittest.TestCase):
    def setUp(self):
        self.session = _session()
        self.user = _user()
        self.session.add(self.user)
        self.session.commit()
        self.service = AccountService(self.session)

    def tearDown(self):
        self.session.close()

    def test_a_linux_summary_excludes_cloud(self):
        _seed_risk_scenario(self.session)
        linux = self.service.summary(self.user, environment=LINUX)
        self.assertEqual(linux["environment"], LINUX)
        self.assertEqual(linux["average_risk_score"], 20)
        self.assertEqual(linux["max_risk_score"], 20)
        self.assertEqual(linux["high_risk_events"], 0)
        self.assertEqual(linux["recent_risk"], 20)
        self.assertEqual([point["risk_score"] for point in linux["risk_trend"]], [20])
        self.assertEqual(linux["events"], 4)
        self.assertEqual(linux["linux_events"], 4)

    def test_b_cloud_summary_excludes_linux(self):
        _seed_risk_scenario(self.session)
        cloud = self.service.summary(self.user, environment=CLOUD)
        self.assertEqual(cloud["environment"], CLOUD)
        self.assertEqual(cloud["average_risk_score"], 95)
        self.assertEqual(cloud["max_risk_score"], 95)
        self.assertEqual(cloud["high_risk_events"], 2)
        self.assertEqual(cloud["recent_risk"], 95)
        self.assertEqual([point["risk_score"] for point in cloud["risk_trend"]], [95])
        self.assertEqual(cloud["events"], 2)
        self.assertIsNone(cloud["linux_events"])
        self.assertEqual(cloud["profiles"], 0)

    def test_default_environment_is_linux(self):
        _seed_risk_scenario(self.session)
        self.assertEqual(self.service.summary(self.user), self.service.summary(self.user, environment=LINUX))

    def test_c_event_counts_are_environment_specific(self):
        _seed_count_scenario(self.session)
        linux = self.service.summary(self.user, environment=LINUX)
        cloud = self.service.summary(self.user, environment=CLOUD)
        self.assertEqual((linux["events"], cloud["events"]), (5, 3))
        self.assertEqual((linux["failed_logins"], cloud["failed_logins"]), (2, 1))

    def test_d_high_risk_counts_are_environment_specific(self):
        _seed_count_scenario(self.session)
        linux = self.service.summary(self.user, environment=LINUX)
        cloud = self.service.summary(self.user, environment=CLOUD)
        self.assertEqual((linux["high_risk_events"], cloud["high_risk_events"]), (1, 2))
        self.assertEqual((linux["alerts"], cloud["alerts"]), (1, 2))
        self.assertEqual((linux["anomalies"], cloud["anomalies"]), (1, 2))

    def test_e_incident_counts_use_incident_environment(self):
        _seed_count_scenario(self.session)
        linux = self.service.summary(self.user, environment=LINUX)
        cloud = self.service.summary(self.user, environment=CLOUD)
        self.assertEqual((linux["incidents"], cloud["incidents"]), (2, 4))

    def test_g_public_datasets_remain_global(self):
        _seed_count_scenario(self.session)
        intel = GlobalIntelligenceService(self.session).summary()
        self.assertEqual(intel["scope"], "GLOBAL")
        self.assertEqual(intel["public_openstack_events"], 1)
        self.assertEqual(intel["hdfs_events"], 1)
        self.assertEqual(intel["bgl_hpc_events"], 1)
        self.assertEqual(intel["behavioral_events"], 1)
        self.assertEqual(intel["synthetic_openstack_demo_events"], 1)
        # The GLOBAL OpenStack/HDFS corpus is cloud-typed but never counted as account cloud telemetry.
        self.assertEqual(self.service.summary(self.user, environment=CLOUD)["events"], 3)

    def test_h_unknown_source_is_not_in_linux_aggregates(self):
        _seed_count_scenario(self.session)
        linux = self.service.summary(self.user, environment=LINUX)
        # The unknown-source row has risk 99 and an alert and anomaly; none of it reaches Linux.
        self.assertEqual(linux["max_risk_score"], 80)
        self.assertEqual((linux["high_risk_events"], linux["alerts"], linux["anomalies"]), (1, 1, 1))
        all_private = event_visibility_clause(scope="private", user=self.user)
        family_total = sum(
            crud.count_events(self.session, visibility=with_environment(all_private, env))
            for env in (LINUX, CLOUD, "HPC", "BEHAVIORAL")
        )
        self.assertEqual(crud.count_events(self.session, visibility=all_private), family_total + 1)

    def test_unknown_environment_is_not_requestable(self):
        for value in ("UNKNOWN", "PRIVATE", "AZURE", "linux;drop"):
            with self.assertRaises(ValueError):
                normalize_environment(value)
        self.assertEqual(normalize_environment(None), LINUX)

    def test_dashboard_stats_and_alert_summaries_are_environment_specific(self):
        _seed_count_scenario(self.session)
        private = event_visibility_clause(scope="private", user=self.user)
        linux = crud.dashboard_summary(self.session, visibility=private, environment=LINUX)
        cloud = crud.dashboard_summary(self.session, visibility=private, environment=CLOUD)
        self.assertEqual((linux["total_events"], cloud["total_events"]), (5, 3))
        self.assertEqual((linux["high_risk"], cloud["high_risk"]), (1, 2))
        self.assertEqual((linux["successful_logins"], cloud["successful_logins"]), (1, 1))
        analytics = AnalyticsService(self.session)
        linux_stats = analytics.get_event_stats(visibility=with_environment(private, LINUX))
        cloud_stats = analytics.get_event_stats(visibility=with_environment(private, CLOUD))
        self.assertEqual((linux_stats["total_events"], cloud_stats["total_events"]), (5, 3))
        self.assertNotIn("CLOUD_LOGIN_FAILURE", linux_stats["by_event_type"])
        self.assertNotIn("Failed Login", cloud_stats["by_event_type"])
        alerts = AlertService(self.session)
        self.assertEqual(alerts.summary(owner_id="owner-1", environment=LINUX, visibility=private)["total"], 1)
        self.assertEqual(alerts.summary(owner_id="owner-1", environment=CLOUD, visibility=private)["total"], 2)
        # Without a visibility clause the owner-only count keeps its legacy meaning.
        self.assertEqual(alerts.summary(owner_id="owner-1")["total"], 8)

    def test_list_accounts_counts_linux_only(self):
        _seed_count_scenario(self.session)
        rows = {row["id"]: row for row in self.service.list_accounts()}
        self.assertEqual(rows[ACCOUNT_ID]["linux_events"], 5)
        self.assertEqual(rows[OTHER_ACCOUNT_ID]["linux_events"], 1)


class EnvironmentAggregateApiTests(unittest.TestCase):
    def setUp(self):
        self.session = _session()
        self.user = _user("owner-1")
        self.session.add(self.user)
        self.session.commit()
        _seed_count_scenario(self.session)
        app = FastAPI()
        app.include_router(account_api.router, prefix="/api/v1/account")
        app.include_router(dashboard_api.router, prefix="/api/v1/dashboard")
        app.include_router(events_api.router, prefix="/api/v1/events")
        app.include_router(alerts_api.router, prefix="/api/v1/alerts")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.user
        self.client = TestClient(app)

    def tearDown(self):
        self.session.close()

    def test_account_summary_environment_parameter(self):
        default = self.client.get("/api/v1/account/summary").json()
        linux = self.client.get("/api/v1/account/summary", params={"environment": "LINUX"}).json()
        cloud = self.client.get("/api/v1/account/summary", params={"environment": "CLOUD"}).json()
        self.assertEqual(default, linux)
        self.assertEqual((linux["events"], cloud["events"]), (5, 3))
        self.assertEqual((linux["incidents"], cloud["incidents"]), (2, 4))

    def test_dashboard_events_and_alert_routes_accept_environment(self):
        linux = self.client.get("/api/v1/dashboard").json()
        cloud = self.client.get("/api/v1/dashboard", params={"environment": "CLOUD"}).json()
        self.assertEqual((linux["environment"], linux["total_events"]), (LINUX, 5))
        self.assertEqual((cloud["environment"], cloud["total_events"]), (CLOUD, 3))
        self.assertEqual(self.client.get("/api/v1/events/stats", params={"environment": "CLOUD"}).json()["total_events"], 3)
        recent = self.client.get("/api/v1/events/recent", params={"environment": "CLOUD", "limit": 50}).json()
        self.assertEqual({row["source_type"] for row in recent}, {"CLOUD"})
        high = self.client.get("/api/v1/events/high-risk", params={"environment": "LINUX"}).json()
        self.assertEqual(high["total"], 1)
        linux_alerts = self.client.get("/api/v1/alerts/summary").json()
        cloud_alerts = self.client.get("/api/v1/alerts/summary", params={"environment": "CLOUD"}).json()
        self.assertEqual((linux_alerts["environment"], linux_alerts["total"]), (LINUX, 1))
        self.assertEqual((cloud_alerts["environment"], cloud_alerts["total"]), (CLOUD, 2))

    def test_invalid_environment_is_rejected(self):
        for path in ("/api/v1/account/summary", "/api/v1/dashboard", "/api/v1/events/stats", "/api/v1/alerts/summary"):
            for value in ("UNKNOWN", "PRIVATE", "linux"):
                self.assertEqual(self.client.get(path, params={"environment": value}).status_code, 422, (path, value))


if __name__ == "__main__":
    unittest.main()
