"""Correlation reads the most recent events of each environment, not the oldest ones."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database.models import Base, Event
from backend.services.correlation_service import CorrelationService

OWNER = "owner-1"
T0 = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)


class RecentWindowTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()

    def tearDown(self):
        self.session.close()

    def add(self, event_id, actor, when, event_type="Failed Login", risk=70):
        self.session.add(Event(
            event_id=event_id, timestamp=when, hostname="vm", username=actor, event_type=event_type,
            category="authentication", severity="high" if risk >= 70 else "low", risk_score=risk,
            message="ssh auth failure" if event_type == "Failed Login" else event_type, raw_log=event_id,
            hash=f"hash-{event_id}", owner_id=OWNER, source_type="LINUX",
        ))

    def correlate(self, limit):
        return CorrelationService(self.session, notifier=MagicMock()).correlate_and_store(owner_id=OWNER, limit=limit)

    def test_newest_events_are_correlated_when_history_exceeds_the_limit(self):
        self.add("early-1", "early", T0)
        for day in range(1, 4):
            self.add(f"filler-{day}", "filler", T0 + timedelta(days=day), event_type="System Event", risk=10)
        self.add("late-1", "late", T0 + timedelta(days=5))
        self.add("late-2", "late", T0 + timedelta(days=5, minutes=3))
        self.session.commit()

        incidents = self.correlate(limit=3)

        self.assertEqual([item["actor"] for item in incidents], ["late"])
        incident = incidents[0]
        self.assertEqual(incident["event_ids"], ["late-1", "late-2"])
        self.assertLess(incident["start_time"], incident["end_time"])

    def test_all_events_within_the_limit_still_correlate(self):
        self.add("early-1", "early", T0)
        self.add("late-1", "late", T0 + timedelta(days=5))
        self.session.commit()
        self.assertEqual(sorted(item["actor"] for item in self.correlate(limit=1000)), ["early", "late"])


if __name__ == "__main__":
    unittest.main()
