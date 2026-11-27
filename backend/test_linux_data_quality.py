"""Linux data quality: source event time vs collection time, security events vs system snapshots.

Input lines are taken from a real collection (RHEL 10 VM); only the SSH retrieval is faked.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy import select

from backend.core.timestamps import (
    SOURCE_EVENT,
    SOURCE_FALLBACK,
    SOURCE_SNAPSHOT,
    parse_audit_epoch,
    parse_occurrence,
)
from backend.database.models import Event
from backend.normalizer.event_normalizer import DefaultTimestampNormalizer
from backend.normalizer.event_types import RECORD_SECURITY_EVENT, RECORD_SYSTEM_EVENT, RECORD_SYSTEM_SNAPSHOT
from backend.parser.engine import parse_audit_line, parse_secure_line
from backend.services.ingestion_service import IngestionService
from backend.services.pipeline_service import PipelineService
from backend.test_linux_cloud_isolation import _azure_event
from backend.test_linux_collection_pipeline import ACCOUNT_A, LinuxCollectionTestBase

COLLECTED = datetime(2026, 10, 6, 6, 48, 37, tzinfo=timezone.utc)

PS_DBUS_SYSTEM = ("dbus        1063  0.1  0.2   8216  4348 ?        S    02:12   0:02 dbus-broker --log 4 --controller 9 "
                  "--machine-id f1b70a5948c84fc7aefe9b483b43c2d6 --max-bytes 536870912 --max-fds 4096 --max-matches 131072 --audit")
PS_DBUS_USER = ("ysalve      3059  0.0  0.2   6560  3768 ?        S    02:13   0:00 dbus-broker --log 4 --controller 9 "
                "--machine-id f1b70a5948c84fc7aefe9b483b43c2d6 --max-bytes 100000000000000 --max-fds 25000000000000 --max-matches 5000000000")
HOSTNAMECTL_CID = "    AF_VSOCK CID: 2877339630"
DF_ROOT = "/dev/mapper/rhel-root   17G  5.1G   12G  31% /"
FREE_MEM = "Mem:           1771        1062         233          17         689         709"
SNAPSHOT_SOURCES = {
    "ps": ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND", PS_DBUS_SYSTEM, PS_DBUS_USER],
    "hostnamectl": ["     Static hostname: rhel-vm", HOSTNAMECTL_CID],
    "df": ["Filesystem             Size  Used Avail Use% Mounted on", DF_ROOT],
    "free": ["               total        used        free      shared  buff/cache   available", FREE_MEM],
    "w": [
        " 02:48:48 up 36 min,  3 users,  load average: 0.09, 0.06, 0.24",
        "USER     TTY        LOGIN@   IDLE   JCPU   PCPU WHAT",
        "ysalve   tty2       02:13   36:01   0.04s  0.04s /usr/libexec/gnome-session-binary",
    ],
    "who": ["ysalve   seat0        2026-10-06 02:13 (login screen)"],
}
LAST_LOGIN = "ysalve   pts/1        192.168.195.1    Tue Oct  6 02:25:59 2026   still logged in"
LAST_REBOOT = "reboot   system boot  6.12.0-233.el10. Wed Jul  1 11:55:33 2026 - crash"
LAST_FOOTER = "wtmp begins Sat May 16 02:32:36 2026"
JOURNAL_LOGIN = "2026-10-06T02:25:59-0400 rhel-vm sshd[2412]: Accepted password for ysalve from 192.168.195.1 port 51544 ssh2"


def generic(sources, collected=COLLECTED):
    with patch("backend.services.pipeline_service.collection_now", return_value=collected):
        return PipelineService._generic_events_from_sources(sources, hostname="rhel-vm")


class TimestampParsingTests(unittest.TestCase):
    def test_1_syslog_security_event_keeps_source_time(self):
        parsed = parse_secure_line("Oct  6 02:25:59 rhel-vm sshd[2412]: Failed password for ysalve from 192.168.195.1 port 51544 ssh2")
        event_time = datetime.fromisoformat(DefaultTimestampNormalizer(COLLECTED).normalize(parsed))
        self.assertEqual((event_time.year, event_time.month, event_time.day, event_time.hour, event_time.minute), (2026, 10, 6, 2, 25))
        self.assertEqual(parsed["timestamp_source"], SOURCE_EVENT)

    def test_2_journal_and_audit_events_keep_source_time(self):
        journal = parse_occurrence(JOURNAL_LOGIN, collected_at=COLLECTED, source_hint="journalctl")
        self.assertEqual(journal.source, SOURCE_EVENT)
        self.assertEqual(journal.event_time, datetime(2026, 10, 6, 6, 25, 59, tzinfo=timezone.utc))

        epoch = datetime(2026, 10, 6, 6, 25, 59, tzinfo=timezone.utc).timestamp()
        audit = parse_audit_line(f'type=USER_LOGIN msg=audit({epoch}:812): pid=2412 uid=0 acct="ysalve" res=success')
        event_time = datetime.fromisoformat(DefaultTimestampNormalizer(COLLECTED).normalize(audit))
        self.assertEqual(event_time, datetime(2026, 10, 6, 6, 25, 59, tzinfo=timezone.utc))
        self.assertEqual(audit["timestamp_source"], SOURCE_EVENT)
        self.assertEqual(parse_audit_epoch(f"{epoch}"), event_time)

    def test_3_numeric_fields_in_diagnostic_output_are_not_dates(self):
        for line in (PS_DBUS_SYSTEM, PS_DBUS_USER, HOSTNAMECTL_CID, DF_ROOT, FREE_MEM):
            with self.subTest(line=line[:40]):
                self.assertIsNone(parse_audit_epoch(line))
                result = parse_occurrence(line, collected_at=COLLECTED)
                self.assertEqual(result.source, SOURCE_FALLBACK)
                self.assertEqual(result.event_time, COLLECTED)


class SnapshotClassificationTests(unittest.TestCase):
    def test_4_snapshots_get_collection_time_not_fabricated_history(self):
        events = generic(SNAPSHOT_SOURCES)
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event.metadata["record_kind"], RECORD_SYSTEM_SNAPSHOT)
            self.assertEqual(event.metadata["timestamp_source"], SOURCE_SNAPSHOT)
            self.assertEqual(datetime.fromisoformat(event.timestamp), COLLECTED)
            self.assertIsNone(event.metadata["login_hour"])
            self.assertEqual(event.metadata["normalized_data"]["record_kind"], RECORD_SYSTEM_SNAPSHOT)

    def test_header_and_footer_lines_are_not_logins(self):
        events = generic({"w": SNAPSHOT_SOURCES["w"], "last": [LAST_LOGIN, LAST_FOOTER]})
        self.assertEqual(sorted(e.username for e in events), ["ysalve", "ysalve"])

    def test_login_history_keeps_source_time_and_boot_records_are_system_events(self):
        login, reboot = generic({"last": [LAST_LOGIN, LAST_REBOOT]})
        self.assertEqual(login.metadata["record_kind"], RECORD_SECURITY_EVENT)
        self.assertEqual(login.metadata["timestamp_source"], SOURCE_EVENT)
        self.assertEqual(datetime.fromisoformat(login.timestamp), datetime(2026, 10, 6, 2, 25, 59, tzinfo=timezone.utc))
        self.assertEqual(login.metadata["login_hour"], 2)
        self.assertEqual(reboot.metadata["record_kind"], RECORD_SYSTEM_EVENT)
        self.assertEqual(reboot.metadata["timestamp_source"], SOURCE_EVENT)
        self.assertEqual(datetime.fromisoformat(reboot.timestamp), datetime(2026, 7, 1, 11, 55, 33, tzinfo=timezone.utc))
        self.assertIsNone(reboot.metadata["login_hour"])


def retrieved_live_shape() -> dict:
    sources = {"journalctl": [JOURNAL_LOGIN], "last": [LAST_LOGIN, LAST_REBOOT, LAST_FOOTER], **SNAPSHOT_SOURCES}
    return {
        "host": "192.0.2.10", "secure_lines": [JOURNAL_LOGIN], "audit_lines": [], "extra_lines": [],
        "sources": sources, "summary": {}, "metrics": {},
    }


class PersistedDataQualityTests(LinuxCollectionTestBase):
    def collect_at(self, collected):
        with patch("backend.services.pipeline_service.collection_now", return_value=collected):
            return self.collect(retrieved_live_shape())

    def kind(self, event):
        return json.loads(event.normalized_data)["record_kind"]

    def test_5_6_collection_time_is_kept_separate_from_event_time(self):
        self.collect_at(COLLECTED)
        events = self.linux_events()
        security = [e for e in events if self.kind(e) == RECORD_SECURITY_EVENT]
        snapshots = [e for e in events if self.kind(e) == RECORD_SYSTEM_SNAPSHOT]
        self.assertEqual(len(security), 2)
        self.assertEqual(len(snapshots), 11)
        collected_naive = COLLECTED.replace(tzinfo=None)
        for event in events:
            self.assertIsNotNone(event.collection_timestamp)
            if json.loads(event.normalized_data).get("source") != "secure":
                self.assertEqual(event.collection_timestamp.replace(tzinfo=None), collected_naive)
        for event in security:
            self.assertEqual(event.timestamp_source, SOURCE_EVENT)
            expected_hour = 6 if event.raw_log == JOURNAL_LOGIN else 2
            self.assertEqual((event.timestamp.hour, event.timestamp.minute), (expected_hour, 25))
            self.assertLess(event.timestamp.replace(tzinfo=None), event.collection_timestamp.replace(tzinfo=None))
        for event in snapshots:
            self.assertEqual(event.timestamp_source, SOURCE_SNAPSHOT)
            self.assertEqual(event.timestamp.replace(tzinfo=None), collected_naive)
            self.assertIsNone(event.login_hour)
        years = {e.timestamp.year for e in events}
        self.assertEqual(years, {2026})

    def test_7_8_events_deduplicate_and_snapshots_are_new_observations(self):
        first = self.collect_at(COLLECTED)
        second = self.collect_at(COLLECTED.replace(minute=50))
        self.assertEqual(first["inserted"], 14)
        self.assertEqual(second["duplicates"], 3)
        self.assertEqual(second["inserted"], 11)
        events = self.linux_events()
        by_kind = {}
        for event in events:
            by_kind.setdefault(self.kind(event), []).append(event)
        self.assertEqual(len(by_kind[RECORD_SECURITY_EVENT]), 2)
        self.assertEqual(len(by_kind[RECORD_SYSTEM_EVENT]), 1)
        self.assertEqual(len(by_kind[RECORD_SYSTEM_SNAPSHOT]), 22)
        observed = {e.collection_timestamp.replace(tzinfo=None).minute for e in by_kind[RECORD_SYSTEM_SNAPSHOT]}
        self.assertEqual(observed, {48, 50})

    def test_9_10_linux_rows_stay_linux_and_cloud_rows_are_untouched(self):
        cloud = _azure_event()
        cloud.update(owner_id="owner-a", account_id=ACCOUNT_A)
        IngestionService(self.session).ingest_bulk_events([cloud])
        cloud_rows = lambda: [(e.id, e.hash, e.timestamp, e.timestamp_source, e.collection_timestamp, e.normalized_data)
                              for e in self.session.scalars(select(Event).where(Event.source_type == "CLOUD"))]
        before = cloud_rows()
        self.assertEqual(before[0][3], SOURCE_EVENT)

        self.collect(retrieved_live_shape())

        self.assertEqual(cloud_rows(), before)
        linux = self.linux_events()
        self.assertEqual({(e.source_type, e.data_origin) for e in linux}, {("LINUX", "LIVE_LINUX")})
        self.assertTrue(all("record_kind" in json.loads(e.normalized_data) for e in linux))
        self.assertNotIn("record_kind", before[0][5] or "")


if __name__ == "__main__":
    unittest.main()
