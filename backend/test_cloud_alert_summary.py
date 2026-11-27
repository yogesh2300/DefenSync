"""Cloud alert summary exposes totals independent of the open-only list filter."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from backend.core.environments import CLOUD, LINUX
from backend.database.models import Alert, Event, User
from backend.services.alert_service import AlertService
from backend.test_azure_collector import session_factory


OWNER = "owner-cloud-alerts"


def _event(session, *, event_id: str, source_type: str, risk: int = 80) -> Event:
    row = Event(
        event_id=event_id,
        timestamp=datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc),
        hostname="azure",
        event_type="CLOUD_PRIVILEGE_CHANGE" if source_type != "LINUX" else "Failed Login",
        category="identity" if source_type != "LINUX" else "authentication",
        severity="high",
        risk_score=risk,
        message="test",
        raw_log=f"test-{event_id}",
        hash=f"hash-{event_id}",
        source_type=source_type,
        data_origin="AZURE_LOG_ANALYTICS" if source_type != "LINUX" else "LIVE_LINUX",
        data_scope="PRIVATE",
        owner_id=OWNER,
    )
    session.add(row)
    return row


def _alert(session, *, event_id: str, acknowledged: bool, severity: str = "high") -> Alert:
    row = Alert(
        event_id=event_id,
        owner_id=OWNER,
        title="t",
        message="m",
        severity=severity,
        risk_score=80,
        detection_type="rule_based",
        acknowledged=acknowledged,
        created_at=datetime(2026, 10, 28, 12, 1, tzinfo=timezone.utc),
    )
    session.add(row)
    return row


class CloudAlertSummaryTests(unittest.TestCase):
    def setUp(self):
        self.session = session_factory()
        self.session.add(User(id=OWNER, username="cloud_alerts", email="ca@example.test", hashed_password="x", role="ANALYST"))
        self.session.commit()

    def tearDown(self):
        self.session.close()

    def test_cloud_summary_counts_resolved_high_priority_without_mixing_linux(self):
        _event(self.session, event_id="c1", source_type="CLOUD")
        _event(self.session, event_id="c2", source_type="AZURE")
        _event(self.session, event_id="l1", source_type="LINUX")
        _alert(self.session, event_id="c1", acknowledged=True, severity="high")
        _alert(self.session, event_id="c2", acknowledged=False, severity="critical")
        _alert(self.session, event_id="l1", acknowledged=False, severity="high")
        self.session.commit()

        cloud = AlertService(self.session).summary(owner_id=OWNER, environment=CLOUD)
        linux = AlertService(self.session).summary(owner_id=OWNER, environment=LINUX)

        self.assertEqual(cloud["total"], 2)
        self.assertEqual(cloud["unacknowledged"], 1)
        self.assertEqual(cloud["priority"], 2)
        self.assertEqual(cloud["critical"], 1)
        self.assertEqual(linux["total"], 1)
        self.assertEqual(linux["priority"], 1)

        open_cloud = AlertService(self.session).list_alerts(owner_id=OWNER, environment=CLOUD, acknowledged=False)
        all_cloud = AlertService(self.session).list_alerts(owner_id=OWNER, environment=CLOUD)
        self.assertEqual(len(open_cloud), 1)
        self.assertEqual(len(all_cloud), 2)


if __name__ == "__main__":
    unittest.main()
