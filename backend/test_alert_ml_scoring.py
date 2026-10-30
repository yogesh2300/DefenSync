"""ML alert scoring must preserve event risk and keep anomaly strength separate."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import Alert, Base, Detection, SecurityEvent
from backend.services.alert_service import AlertService, alert_priority_for, serialize_alert


NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def _event(**kwargs) -> SecurityEvent:
    defaults = dict(
        event_id="evt-1",
        hostname="host-a",
        username="alice",
        event_type="System Snapshot",
        category="system",
        severity="low",
        risk_score=0,
        message="snapshot",
        raw_log="df -h",
        hash="hash-1",
        source_type="LINUX",
        data_origin="LIVE_LINUX",
        timestamp=NOW,
        owner_id="owner-1",
        account_id="acct-1",
    )
    defaults.update(kwargs)
    return SecurityEvent(**defaults)


class MlAlertScoringTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, expire_on_commit=False)
        self.session = self.Session()
        self.service = AlertService(self.session)

    def tearDown(self):
        self.session.close()

    def test_snapshot_risk_0_is_not_inflated_to_75(self):
        event = _event(risk_score=0, severity="low", event_type="System Snapshot")
        self.session.add(event)
        self.session.commit()
        alert = self.service.create_ml_alert(event, score=0.68, detection_type="linux_isolation_forest")
        self.assertEqual(alert.risk_score, 0)
        self.assertEqual(alert.severity, "low")
        self.assertAlmostEqual(alert.confidence, 0.68)
        self.assertNotEqual(alert.risk_score, 75)

    def test_normal_event_risk_20_retained(self):
        event = _event(event_id="e20", hash="h20", risk_score=20, severity="info", event_type="Successful Login")
        self.session.add(event)
        self.session.commit()
        alert = self.service.create_ml_alert(event, score=1.2, detection_type="ml_anomaly")
        self.assertEqual(alert.risk_score, 20)
        self.assertEqual(alert.severity, "info")

    def test_failed_login_65_retained(self):
        event = _event(event_id="e65", hash="h65", risk_score=65, severity="high", event_type="Failed Login")
        self.session.add(event)
        self.session.commit()
        alert = self.service.create_ml_alert(event, score=2.0, detection_type="ml_anomaly")
        self.assertEqual(alert.risk_score, 65)
        self.assertEqual(alert.severity, "high")

    def test_high_risk_85_retained(self):
        event = _event(event_id="e85", hash="h85", risk_score=85, severity="critical", event_type="User Deletion")
        self.session.add(event)
        self.session.commit()
        alert = self.service.create_ml_alert(event, score=3.0, detection_type="ml_anomaly")
        self.assertEqual(alert.risk_score, 85)
        self.assertEqual(alert.severity, "critical")

    def test_anomaly_strength_exposed_separately_in_serialize(self):
        event = _event(risk_score=0, severity="low")
        self.session.add(event)
        self.session.commit()
        alert = self.service.create_ml_alert(event, score=0.68, detection_type="linux_isolation_forest")
        self.session.add(
            Detection(
                server_id="srv-1",
                owner_id="owner-1",
                event_id=event.event_id,
                isolation_score=0.68,
                is_anomaly=True,
                risk_score=0,
                detection_type="linux_isolation_forest",
                classification="Suspicious",
            )
        )
        self.session.commit()
        view = serialize_alert(self.session, alert)
        self.assertEqual(view["event_risk_score"], 0)
        self.assertEqual(view["anomaly_score"], 0.68)
        self.assertEqual(view["alert_priority"], "low")
        self.assertEqual(view["event_severity"], "low")

    def test_ml_anomaly_does_not_force_priority_high(self):
        event = _event(risk_score=0, severity="low")
        alert = Alert(
            event_id=event.event_id,
            title="ML Anomaly: System Snapshot",
            message="x",
            severity="high",  # legacy inflated row
            risk_score=75,
            detection_type="linux_isolation_forest",
            confidence=0.55,
        )
        self.session.add_all([event, alert])
        self.session.commit()
        self.assertEqual(alert_priority_for(alert, event), "low")
        view = serialize_alert(self.session, alert, event=event)
        self.assertEqual(view["alert_priority"], "low")
        self.assertEqual(view["event_risk_score"], 0)
        self.assertEqual(view["risk_score"], 75)  # historical stored value untouched

    def test_missing_event_risk_is_null_not_fabricated(self):
        alert = Alert(
            event_id="orphan",
            title="orphan",
            message="m",
            severity="medium",
            risk_score=40,
            detection_type="rule_based",
        )
        self.session.add(alert)
        self.session.commit()
        view = serialize_alert(self.session, alert)
        self.assertIsNone(view["event_risk_score"])
        self.assertEqual(view["alert_priority"], "medium")

    def test_list_and_ack_still_work(self):
        event = _event(event_id="list-1", hash="hl", risk_score=20, severity="low", event_type="Successful Login")
        self.session.add(event)
        self.session.commit()
        created = self.service.create_ml_alert(event, score=0.9, detection_type="ml_anomaly")
        rows = self.service.list_alerts(owner_id="owner-1", limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_risk_score"], 20)
        self.assertEqual(rows[0]["anomaly_score"], 0.9)
        acked = self.service.acknowledge(created.id, owner_id="owner-1")
        self.assertTrue(acked["acknowledged"])
        self.assertEqual(acked["event_risk_score"], 20)


if __name__ == "__main__":
    unittest.main()
