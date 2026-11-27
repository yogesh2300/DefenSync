"""Event Explorer timestamp semantics: source occurrence vs collection vs observation time.

Real shapes from the RHEL VM (NTP-synced, America/New_York) collected by a DefenSync host
whose clock ran ~12 s slow, which is why a login can appear after its collection.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.api import events as events_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.timestamps import (
    SOURCE_EVENT,
    SOURCE_FALLBACK,
    SOURCE_SNAPSHOT,
    TIME_LABEL_COLLECTED,
    TIME_LABEL_EVENT,
    TIME_LABEL_OBSERVED,
    event_time_view,
)
from backend.database.models import Event
from backend.test_linux_cloud_isolation import _azure_event
from backend.test_linux_collection_pipeline import ACCOUNT_A, LinuxCollectionTestBase
from backend.services.ingestion_service import IngestionService

IST = ZoneInfo("Asia/Kolkata")
UTC = timezone.utc
LOGIN_LINE = "2026-10-06T03:47:12-04:00 YogeshOS sshd-session[15825]: Accepted password for ysalve from 192.168.195.1 port 55857 ssh2"
COLLECTED = datetime(2026, 10, 6, 7, 46, 59, 972796, tzinfo=UTC)


def login_nd(**extra):
    return {"record_kind": "SECURITY_EVENT", "record_origin": "COLLECTOR_GENERATED", "timestamp_source": SOURCE_EVENT,
            "event_time_utc": "2026-10-06T07:47:12+00:00", "first_collection_time_utc": COLLECTED.isoformat(), **extra}


class EventTimeViewTests(unittest.TestCase):
    def test_1_2_7_source_time_kept_and_collection_separate(self):
        view = event_time_view(timestamp=datetime(2026, 10, 6, 13, 17, 12), collection_timestamp=datetime(2026, 10, 6, 13, 16, 59, 972796),
                               timestamp_source=SOURCE_EVENT, normalized_data=json.dumps(login_nd()), storage_tz=IST)
        self.assertEqual(view["event_time"], datetime(2026, 10, 6, 7, 47, 12, tzinfo=UTC))
        self.assertEqual(view["collection_time"], COLLECTED)
        self.assertEqual(view["time_label"], TIME_LABEL_EVENT)
        self.assertEqual((view["record_kind"], view["record_origin"]), ("SECURITY_EVENT", "COLLECTOR_GENERATED"))

    def test_6_naive_columns_converted_with_storage_zone_only(self):
        view = event_time_view(timestamp=datetime(2026, 10, 6, 13, 17, 12), collection_timestamp=datetime(2026, 10, 6, 13, 16, 59),
                               timestamp_source=SOURCE_EVENT, normalized_data=None, storage_tz=IST)
        self.assertEqual(view["event_time"], datetime(2026, 10, 6, 7, 47, 12, tzinfo=UTC))
        self.assertEqual(view["collection_time"], datetime(2026, 10, 6, 7, 46, 59, tzinfo=UTC))
        self.assertEqual(view["last_collection_time"], view["collection_time"])

    def test_8_source_after_collection_reported_not_corrected(self):
        view = event_time_view(timestamp=None, collection_timestamp=None, timestamp_source=SOURCE_EVENT,
                               normalized_data=login_nd(), storage_tz=UTC)
        self.assertEqual(view["collection_delay_seconds"], -12.027)
        self.assertTrue(view["source_time_after_collection"])
        self.assertEqual(view["event_time"], datetime(2026, 10, 6, 7, 47, 12, tzinfo=UTC))

    def test_3_4_5_snapshot_and_fallback_labels(self):
        snap = event_time_view(timestamp=COLLECTED, collection_timestamp=COLLECTED, timestamp_source=SOURCE_SNAPSHOT,
                               normalized_data={"record_kind": "SYSTEM_SNAPSHOT"}, storage_tz=UTC)
        self.assertEqual((snap["time_label"], snap["event_time"], snap["collection_delay_seconds"]), (TIME_LABEL_OBSERVED, COLLECTED, None))
        fallback = event_time_view(timestamp=COLLECTED, collection_timestamp=COLLECTED, timestamp_source=SOURCE_FALLBACK,
                                   normalized_data={}, storage_tz=UTC)
        self.assertEqual(fallback["time_label"], TIME_LABEL_COLLECTED)
        system = event_time_view(timestamp=datetime(2026, 7, 1, 15, 55, 33, tzinfo=UTC), collection_timestamp=COLLECTED,
                                 timestamp_source=SOURCE_EVENT, normalized_data={"record_kind": "SYSTEM_EVENT"}, storage_tz=UTC)
        self.assertEqual(system["time_label"], TIME_LABEL_EVENT)


class EventApiTimeTests(LinuxCollectionTestBase):
    def api(self):
        app = FastAPI()
        app.include_router(events_api.router, prefix="/api/v1/events")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.users["owner-a"]
        return TestClient(app)

    def setUp(self):
        super().setUp()
        self.users = {u.id: u for u in self.session.scalars(select(events_api.User))}
        with patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED):
            self.collect({
                "host": "192.0.2.10", "secure_lines": [LOGIN_LINE], "audit_lines": [], "extra_lines": [], "summary": {}, "metrics": {},
                "sources": {"journalctl": [LOGIN_LINE], "ps": ["dbus  1063  0.1  0.2  8216  4348 ?  S  02:12  0:02 dbus-broker"],
                            "last": ["reboot   system boot  6.12.0-233.el10. Wed Jul  1 11:55:33 2026 - crash"]},
                "host_context": {"collector_ip": "192.168.195.1", "timezone": "America/New_York", "utc_offset": "-0400"},
            })
        body = self.api().get("/api/v1/events", params={"environment": "LINUX", "limit": 50}).json()
        self.by_kind = {e["record_kind"]: e for e in body}

    def test_api_exposes_explicit_semantics(self):
        login, snap, system = self.by_kind["SECURITY_EVENT"], self.by_kind["SYSTEM_SNAPSHOT"], self.by_kind["SYSTEM_EVENT"]
        self.assertEqual(datetime.fromisoformat(login["event_time"].replace("Z", "+00:00")), datetime(2026, 10, 6, 7, 47, 12, tzinfo=UTC))
        self.assertEqual(login["time_label"], TIME_LABEL_EVENT)
        self.assertIsNotNone(login["collection_time"])
        self.assertNotEqual(login["event_time"], login["collection_time"])
        self.assertEqual(snap["time_label"], TIME_LABEL_OBSERVED)
        self.assertEqual(snap["event_time"], snap["collection_time"])
        self.assertIsNone(snap["collection_delay_seconds"])
        self.assertEqual(system["time_label"], TIME_LABEL_EVENT)
        self.assertTrue(system["event_time"].startswith("2026-07-01T15:55:33"))
        self.assertTrue(login["event_time"].endswith(("Z", "+00:00")))

    def test_9_10_cloud_unchanged_and_dedup_unchanged(self):
        cloud = _azure_event()
        cloud.update(owner_id="owner-a", account_id=ACCOUNT_A)
        IngestionService(self.session).ingest_bulk_events([cloud])
        stored = self.session.scalar(select(Event).where(Event.source_type == "CLOUD"))
        before = (stored.hash, stored.timestamp, stored.normalized_data)
        body = self.api().get("/api/v1/events", params={"environment": "CLOUD", "limit": 50}).json()
        self.assertEqual([e["source_type"] for e in body], ["CLOUD"])
        self.assertIsNone(body[0]["record_kind"])
        self.session.refresh(stored)
        self.assertEqual((stored.hash, stored.timestamp, stored.normalized_data), before)
        count = len(self.linux_events())
        with patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED.replace(minute=55)):
            stats = self.collect({
                "host": "192.0.2.10", "secure_lines": [LOGIN_LINE], "audit_lines": [], "extra_lines": [], "summary": {}, "metrics": {},
                "sources": {"journalctl": [LOGIN_LINE]}, "host_context": {},
            })
        self.assertEqual((stats["inserted"], stats["duplicates"]), (0, 1))
        self.assertEqual(len(self.linux_events()), count)


if __name__ == "__main__":
    unittest.main()
