"""Backend correlation uses event occurrence timestamps."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone, timedelta

from backend.database.models import Event
from backend.services.correlation_service import CorrelationService


def _event(actor, source_type, event_type, hour, risk=40, provider=None):
    event = Event()
    event.event_id = f"{actor}-{event_type}-{hour}"
    event.timestamp = datetime(2026, 8, 17, hour, 5, tzinfo=timezone.utc)
    event.collection_timestamp = datetime(2026, 8, 17, 18, 0, tzinfo=timezone.utc)
    event.username = actor
    event.actor_id = actor
    event.source_type = source_type
    event.provider = provider
    event.event_type = event_type
    event.message = event_type
    event.severity = "high" if risk >= 70 else "info"
    event.risk_score = risk
    event.behavioral_risk_score = risk if source_type == "BEHAVIORAL" else None
    event.hostname = "web01"
    return event


class CorrelationTests(unittest.TestCase):
    def test_incident_uses_event_time_and_stays_in_one_environment(self):
        events = [
            _event("yogesh", "LINUX", "Successful Login", 10, 30),
            _event("yogesh", "LINUX", "Sudo Command", 10, 60),
            _event("yogesh", "CLOUD", "CLOUD_ACTIVITY", 10, 40, provider="OPENSTACK"),
            _event("yogesh", "BEHAVIORAL", "USER_BEHAVIOR_TELEMETRY", 10, 70),
        ]
        incidents = CorrelationService(session=None)._build(events)  # type: ignore[arg-type]
        linux = [item for item in incidents if item["environment"] == "LINUX"]
        self.assertEqual(len(linux), 1)
        incident = linux[0]
        self.assertEqual(incident["actor"], "yogesh")
        self.assertEqual(incident["source"], "Linux")
        self.assertEqual(incident["start_time"].hour, 10)
        self.assertNotEqual(incident["start_time"].hour, 18)
        self.assertGreaterEqual(len(incident["evidence"]), 2)
        for item in incidents:
            self.assertEqual(len(item["source"].split(",")), 1)

    def test_events_outside_window_are_not_one_incident(self):
        events = [
            _event("yogesh", "LINUX", "Successful Login", 10, 30),
            _event("yogesh", "LINUX", "Sudo Command", 10, 60),
            _event("yogesh", "CLOUD", "CLOUD_ACTIVITY", 18, 40, provider="OPENSTACK"),
        ]
        incidents = CorrelationService(session=None)._build(events)  # type: ignore[arg-type]
        self.assertTrue(incidents)
        for incident in incidents:
            span = incident["end_time"] - incident["start_time"]
            self.assertLessEqual(span.total_seconds(), 15 * 60)

    def test_single_source_does_not_create_incident(self):
        events = [_event("alice", "LINUX", "Successful Login", 10, 20)]
        incidents = CorrelationService(session=None)._build(events)  # type: ignore[arg-type]
        self.assertEqual(incidents, [])


if __name__ == "__main__":
    unittest.main()
