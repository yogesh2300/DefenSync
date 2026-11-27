"""Historical Linux events keep their own occurrence times when collected days later.

Covers the external review remark: events collected in one run must not share the
collection time as their event time. Line shapes follow the RHEL VM (journalctl
short-iso, /var/log/secure syslog, last -F); the host zone is America/New_York.
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
from backend.core.timestamps import SOURCE_EVENT, SOURCE_SNAPSHOT, TZ_HOST, TZ_SOURCE_OFFSET, parse_occurrence
from backend.database.models import Event
from backend.services.ingestion_service import IngestionService
from backend.test_linux_cloud_isolation import _azure_event
from backend.test_linux_collection_pipeline import ACCOUNT_A, LinuxCollectionTestBase

UTC = timezone.utc
FIRST_COLLECTION = datetime(2026, 10, 6, 13, 0, 0, tzinfo=UTC)
SECOND_COLLECTION = datetime(2026, 10, 8, 9, 30, 0, tzinfo=UTC)
HOST_CONTEXT = {"collector_ip": "192.168.195.1", "timezone": "America/New_York", "utc_offset": "-0400"}

# Deliberately out of chronological order, as a mixed journal/file read can be.
J_SUDO = ("2026-10-04T10:17:03-04:00 YogeshOS sudo[4410]:   ysalve : TTY=pts/0 ; PWD=/home/ysalve ; USER=root ; "
          "COMMAND=/usr/bin/systemctl restart sshd")
J_LOGIN = "2026-10-04T10:15:21-04:00 YogeshOS sshd-session[4402]: Accepted publickey for alice from 203.0.113.9 port 40000 ssh2"
J_FAILED = "2026-10-04T10:20:44-04:00 YogeshOS sshd-session[4500]: Failed password for invalid user admin from 198.51.100.7 port 41000 ssh2"
J_IST_OFFSET = "2026-10-05T09:00:00+05:30 YogeshOS sshd-session[4600]: Accepted password for bob from 203.0.113.20 port 40100 ssh2"
SECURE_SYSLOG = "Oct  3 22:05:10 YogeshOS sshd[3999]: Accepted password for carol from 203.0.113.30 port 40200 ssh2"
LAST_LOGIN = "alice    pts/3        203.0.113.9      Sun Oct  4 10:15:22 2026 - Sun Oct  4 11:02:40 2026  (00:47)"
SNAPSHOT = "root        1315  0.0  0.3 172420  6344 ?        Ssl  02:12   0:04 /usr/sbin/rsyslogd -n"

EXPECTED_UTC = {
    J_LOGIN: datetime(2026, 10, 4, 14, 15, 21, tzinfo=UTC),
    J_SUDO: datetime(2026, 10, 4, 14, 17, 3, tzinfo=UTC),
    J_FAILED: datetime(2026, 10, 4, 14, 20, 44, tzinfo=UTC),
    J_IST_OFFSET: datetime(2026, 10, 5, 3, 30, 0, tzinfo=UTC),
    SECURE_SYSLOG: datetime(2026, 10, 4, 2, 5, 10, tzinfo=UTC),
    LAST_LOGIN: datetime(2026, 10, 4, 14, 15, 22, tzinfo=UTC),
}


def payload(journal, secure=(), last=(), snapshots=(), host_context=HOST_CONTEXT):
    return {
        "host": "192.0.2.10", "secure_lines": [*secure, *journal], "audit_lines": [], "extra_lines": [],
        "sources": {"journalctl": list(journal), "secure": list(secure), "last": list(last), "ps": list(snapshots)},
        "summary": {}, "metrics": {}, "host_context": host_context,
    }


def naive_utc(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None)


class YearlessSyslogTests(unittest.TestCase):
    """secure/auth/syslog lines omit the year: inferred in the host zone from the collection time."""

    def test_year_boundary_in_host_zone(self):
        new_york = ZoneInfo("America/New_York")
        collected = datetime(2027, 1, 1, 6, 0, 0, tzinfo=UTC)  # 01:00 on Jan 1 in New York
        dec = parse_occurrence("Dec 31 23:59:50 YogeshOS sudo: x", collected_at=collected, source_hint="secure", host_tz=new_york)
        jan = parse_occurrence("Jan  1 00:00:05 YogeshOS sshd[1]: x", collected_at=collected, source_hint="secure", host_tz=new_york)
        self.assertEqual(dec.event_time, datetime(2027, 1, 1, 4, 59, 50, tzinfo=UTC))
        self.assertEqual(jan.event_time, datetime(2027, 1, 1, 5, 0, 5, tzinfo=UTC))
        self.assertLess(dec.event_time, jan.event_time)
        old = parse_occurrence("Oct  3 22:05:10 YogeshOS sshd[1]: x", collected_at=collected, source_hint="secure", host_tz=new_york)
        self.assertEqual(old.event_time, datetime(2026, 10, 4, 2, 5, 10, tzinfo=UTC))


class HistoricalEventTimeTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        with patch("backend.services.pipeline_service.collection_now", return_value=FIRST_COLLECTION):
            self.stats = self.collect(payload([J_SUDO, J_FAILED, J_LOGIN, J_IST_OFFSET], secure=[SECURE_SYSLOG],
                                              last=[LAST_LOGIN], snapshots=[SNAPSHOT]))

    def rows(self):
        return {e.raw_log: e for e in self.linux_events()}

    def nd(self, event):
        return json.loads(event.normalized_data)

    def api(self, **params):
        app = FastAPI()
        app.include_router(events_api.router, prefix="/api/v1/events")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.session.get(events_api.User, "owner-a")
        return TestClient(app).get("/api/v1/events", params={"environment": "LINUX", "limit": 100, **params}).json()

    def test_1_2_3_4_historical_events_keep_distinct_source_times(self):
        rows = self.rows()
        for line, expected in EXPECTED_UTC.items():
            event = rows[line]
            self.assertEqual(event.timestamp, naive_utc(expected), line)
            self.assertEqual(event.timestamp_source, SOURCE_EVENT)
            self.assertEqual(self.nd(event)["event_time_utc"], expected.isoformat())
            self.assertEqual(event.collection_timestamp, naive_utc(FIRST_COLLECTION))
            self.assertLess(event.timestamp, event.collection_timestamp)
        event_times = {rows[line].timestamp for line in EXPECTED_UTC}
        self.assertEqual(len(event_times), len(EXPECTED_UTC))
        self.assertEqual({rows[line].collection_timestamp for line in EXPECTED_UTC}, {naive_utc(FIRST_COLLECTION)})

    def test_7_command_event_uses_source_time(self):
        sudo = self.rows()[J_SUDO]
        nd = self.nd(sudo)
        self.assertEqual((sudo.event_type, sudo.username), ("Sudo Command", "ysalve"))
        self.assertEqual((nd["cmd"], nd["target_user"]), ("/usr/bin/systemctl restart sshd", "root"))
        self.assertEqual(sudo.timestamp, datetime(2026, 10, 4, 14, 17, 3))
        self.assertEqual(sudo.timestamp_source, SOURCE_EVENT)
        self.assertEqual(nd["record_kind"], "SECURITY_EVENT")

    def test_9_explicit_offset_and_host_zone(self):
        rows = self.rows()
        self.assertEqual(self.nd(rows[J_IST_OFFSET])["timestamp_tz_basis"], TZ_SOURCE_OFFSET)
        self.assertEqual(self.nd(rows[SECURE_SYSLOG])["timestamp_tz_basis"], TZ_HOST)
        self.assertEqual(self.nd(rows[LAST_LOGIN])["timestamp_tz_basis"], TZ_HOST)

    def test_6_snapshot_uses_observation_time(self):
        snap = self.rows()[SNAPSHOT]
        self.assertEqual((snap.timestamp_source, snap.timestamp), (SOURCE_SNAPSHOT, snap.collection_timestamp))
        self.assertEqual(snap.collection_timestamp, naive_utc(FIRST_COLLECTION))
        body = self.api(record_kind="SYSTEM_SNAPSHOT")
        self.assertEqual([(e["raw_log"], e["time_label"]) for e in body], [(SNAPSHOT, "OBSERVED_AT")])

    def test_5_timeline_sorted_by_occurrence_time(self):
        body = self.api(record_kind="NOT_SNAPSHOT")
        times = [datetime.fromisoformat(e["event_time"].replace("Z", "+00:00")) for e in body]
        self.assertEqual(times, sorted(times, reverse=True))
        self.assertEqual([e["raw_log"] for e in body], sorted(EXPECTED_UTC, key=EXPECTED_UTC.get, reverse=True))
        oldest = self.api(record_kind="NOT_SNAPSHOT", sort_order="oldest")
        self.assertEqual(oldest[0]["raw_log"], SECURE_SYSLOG)
        self.assertNotIn(SNAPSHOT, [e["raw_log"] for e in body])
        everything = self.api()
        self.assertEqual(everything[0]["raw_log"], SNAPSHOT)
        self.assertEqual({e["collection_time"] for e in body}, {"2026-10-06T13:00:00Z"})
        self.assertEqual(len({e["event_time"] for e in body}), len(body))

    def test_8_recollection_days_later_is_a_duplicate(self):
        before = {line: (e.id, e.timestamp, self.nd(e)["first_collection_time_utc"]) for line, e in self.rows().items()
                  if line != SNAPSHOT}
        with patch("backend.services.pipeline_service.collection_now", return_value=SECOND_COLLECTION):
            stats = self.collect(payload([J_LOGIN, J_SUDO, J_FAILED, J_IST_OFFSET], secure=[SECURE_SYSLOG], last=[LAST_LOGIN]))
        self.assertEqual((stats["inserted"], stats["duplicates"]), (0, len(before)))
        self.session.expire_all()
        after = self.rows()
        for line, (row_id, ts, first) in before.items():
            self.assertEqual((after[line].id, after[line].timestamp, self.nd(after[line])["first_collection_time_utc"]), (row_id, ts, first))
            self.assertEqual(after[line].collection_timestamp, naive_utc(SECOND_COLLECTION))

    def test_10_cloud_rows_untouched(self):
        cloud = _azure_event()
        cloud.update(owner_id="owner-a", account_id=ACCOUNT_A)
        IngestionService(self.session).ingest_bulk_events([cloud])
        stored = self.session.scalar(select(Event).where(Event.source_type == "CLOUD"))
        before = (stored.hash, stored.timestamp, stored.collection_timestamp, stored.normalized_data)
        with patch("backend.services.pipeline_service.collection_now", return_value=SECOND_COLLECTION):
            self.collect(payload([J_LOGIN]))
        self.session.refresh(stored)
        self.assertEqual((stored.hash, stored.timestamp, stored.collection_timestamp, stored.normalized_data), before)
        self.assertNotIn(cloud["raw_log"], [e["raw_log"] for e in self.api(record_kind="NOT_SNAPSHOT")])
