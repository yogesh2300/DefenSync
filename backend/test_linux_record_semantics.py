"""Linux record semantics: System Snapshot taxonomy, collector-generated SSH activity,
host-timezone normalization to UTC, login_hour, and dashboard counting.

Real-shaped lines from a RHEL 10 VM (host zone America/New_York); only SSH retrieval is faked.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from zoneinfo import ZoneInfo

from sqlalchemy import select

from backend.core.environments import CLOUD, LINUX
from backend.core.timestamps import (
    SOURCE_EVENT,
    SOURCE_SNAPSHOT,
    TZ_ASSUMED_UTC,
    TZ_EPOCH,
    TZ_HOST,
    TZ_SOURCE_OFFSET,
    parse_occurrence,
    resolve_host_timezone,
)
from backend.database import crud
from backend.database.models import Event
from backend.normalizer.event_types import (
    RECORD_ORIGIN_COLLECTOR,
    RECORD_ORIGIN_SOURCE_OBSERVED,
    RECORD_SECURITY_EVENT,
    RECORD_SYSTEM_EVENT,
    RECORD_SYSTEM_SNAPSHOT,
)
from backend.services.collector_service import CollectorService
from backend.services.ingestion_service import IngestionService
from backend.test_linux_cloud_isolation import _azure_event
from backend.test_linux_collection_pipeline import ACCOUNT_A, LinuxCollectionTestBase

NEW_YORK = ZoneInfo("America/New_York")
COLLECTED = datetime(2026, 10, 6, 6, 48, 37, tzinfo=timezone.utc)
COLLECTOR_IP = "192.168.195.1"
HOST_CONTEXT = {"collector_ip": COLLECTOR_IP, "timezone": "America/New_York", "utc_offset": "-0400"}

J_COLLECTOR_OK = f"2026-10-06T02:25:59-0400 rhel-vm sshd[2412]: Accepted password for defensync from {COLLECTOR_IP} port 51544 ssh2"
J_USER_OK = "2026-10-06T02:30:10-0400 rhel-vm sshd[2500]: Accepted publickey for alice from 203.0.113.9 port 40000 ssh2"
J_COLLECTOR_FAIL = [
    f"2026-10-06T02:31:0{i}-0400 rhel-vm sshd[26{i}0]: Failed password for defensync from {COLLECTOR_IP} port 5160{i} ssh2"
    for i in range(3)
]
J_REAL_FAIL = "2026-10-06T02:40:00-0400 rhel-vm sshd[2700]: Failed password for invalid user admin from 198.51.100.7 port 41000 ssh2"
JOURNAL = [J_COLLECTOR_OK, J_USER_OK, *J_COLLECTOR_FAIL, J_REAL_FAIL]
LAST_LOGIN = f"defensync pts/1        {COLLECTOR_IP}    Tue Oct  6 02:25:59 2026   still logged in"
LAST_REBOOT = "reboot   system boot  6.12.0-233.el10. Wed Jul  1 11:55:33 2026 - crash"
SNAPSHOTS = {
    "ps": ["dbus        1063  0.1  0.2   8216  4348 ?        S    02:12   0:02 dbus-broker --max-bytes 536870912"],
    "hostnamectl": ["    AF_VSOCK CID: 2877339630"],
    "w": ["root     tty3       02:13   36:01   0.04s  0.04s -bash"],
    "who": ["alice    seat0        2026-10-06 02:13 (login screen)"],
}


def retrieved(host_context=HOST_CONTEXT) -> dict:
    sources = {"journalctl": list(JOURNAL), "last": [LAST_LOGIN, LAST_REBOOT], **SNAPSHOTS}
    return {"host": "192.0.2.10", "secure_lines": list(JOURNAL), "audit_lines": [], "extra_lines": [],
            "sources": sources, "summary": {}, "metrics": {}, "host_context": host_context}


class HostTimezoneTests(unittest.TestCase):
    def test_wall_clock_sources_use_host_zone_and_dst(self):
        summer = parse_occurrence("Tue Oct  6 02:25:59 2026", collected_at=COLLECTED, source_hint="last", host_tz=NEW_YORK)
        winter = parse_occurrence("Mon Jan  5 09:00:00 2026", collected_at=COLLECTED, source_hint="last", host_tz=NEW_YORK)
        syslog = parse_occurrence("Oct  6 02:25:59 rhel-vm sshd[1]: x", collected_at=COLLECTED, host_tz=NEW_YORK)
        self.assertEqual((summer.event_time, summer.tz_basis), (datetime(2026, 10, 6, 6, 25, 59, tzinfo=timezone.utc), TZ_HOST))
        self.assertEqual(winter.event_time, datetime(2026, 1, 5, 14, 0, tzinfo=timezone.utc))
        self.assertEqual(syslog.event_time, datetime(2026, 10, 6, 6, 25, 59, tzinfo=timezone.utc))

    def test_explicit_offsets_and_epochs_ignore_host_zone(self):
        journal = parse_occurrence(J_USER_OK, collected_at=COLLECTED, host_tz=ZoneInfo("Asia/Kolkata"))
        self.assertEqual((journal.event_time, journal.tz_basis), (datetime(2026, 10, 6, 6, 30, 10, tzinfo=timezone.utc), TZ_SOURCE_OFFSET))
        audit = parse_occurrence("type=USER_LOGIN msg=audit(1791267959.120:8): res=success", collected_at=COLLECTED,
                                 source_hint="audit", host_tz=NEW_YORK)
        self.assertEqual((audit.event_time, audit.tz_basis), (datetime.fromtimestamp(1791267959.12, tz=timezone.utc), TZ_EPOCH))

    def test_unknown_host_zone_is_labelled_not_guessed(self):
        result = parse_occurrence("Tue Oct  6 02:25:59 2026", collected_at=COLLECTED, source_hint="last")
        self.assertEqual((result.event_time.hour, result.tz_basis), (2, TZ_ASSUMED_UTC))

    def test_resolve_host_timezone(self):
        self.assertEqual(resolve_host_timezone("../usr/share/zoneinfo/America/New_York"), NEW_YORK)
        self.assertEqual(resolve_host_timezone("", "-0400").utcoffset(None).total_seconds(), -4 * 3600)
        self.assertIsNone(resolve_host_timezone("Not/AZone", "garbage"))

    def test_collector_reads_host_context_without_root(self):
        client = MagicMock()
        client.run_remote_command.return_value = [
            f"ssh_connection={COLLECTOR_IP} 51544 192.168.195.129 22", "utc_offset=-0400", "timezone=America/New_York",
        ]
        self.assertEqual(CollectorService._host_context(client, "h"), HOST_CONTEXT)
        command = client.run_remote_command.call_args.args[0]
        self.assertNotIn("sudo", command)
        client.run_remote_command.side_effect = RuntimeError("no shell")
        self.assertEqual(CollectorService._host_context(client, "h"), {})


class RecordSemanticsPersistedTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        with patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED):
            self.stats = self.collect(retrieved())
        self.rows = self.linux_events()
        self.nd = {e.id: json.loads(e.normalized_data) for e in self.rows}

    def by_line(self, line):
        return next(e for e in self.rows if e.raw_log == line)

    def kind(self, event):
        return self.nd[event.id]["record_kind"]

    def origin(self, event):
        return self.nd[event.id]["record_origin"]

    def test_invariants_1_to_3_record_kinds_and_taxonomy(self):
        for line in JOURNAL + [LAST_LOGIN]:
            self.assertEqual(self.kind(self.by_line(line)), RECORD_SECURITY_EVENT)
        reboot = self.by_line(LAST_REBOOT)
        self.assertEqual((self.kind(reboot), reboot.event_type, reboot.username), (RECORD_SYSTEM_EVENT, "System Event", None))
        self.assertEqual(self.nd[reboot.id]["system_action"], "reboot")
        snapshots = [e for e in self.rows if self.kind(e) == RECORD_SYSTEM_SNAPSHOT]
        self.assertEqual(len(snapshots), 4)
        self.assertEqual({e.event_type for e in snapshots}, {"System Snapshot"})
        self.assertEqual({e.category for e in snapshots}, {"system"})

    def test_invariants_4_5_snapshot_and_event_times(self):
        for event in self.rows:
            if self.kind(event) == RECORD_SYSTEM_SNAPSHOT:
                self.assertEqual(event.timestamp_source, SOURCE_SNAPSHOT)
                self.assertEqual(event.timestamp, event.collection_timestamp)
                self.assertEqual(event.timestamp.year, 2026)
            else:
                self.assertEqual(event.timestamp_source, SOURCE_EVENT)
                self.assertNotEqual(event.timestamp, event.collection_timestamp)
        self.assertEqual(self.by_line(LAST_REBOOT).timestamp, datetime(2026, 7, 1, 15, 55, 33))
        self.assertEqual(self.nd[self.by_line(LAST_LOGIN).id]["timestamp_tz_basis"], TZ_HOST)
        self.assertEqual(self.nd[self.by_line(J_USER_OK).id]["timestamp_tz_basis"], TZ_SOURCE_OFFSET)
        self.assertEqual(self.nd[self.by_line(J_USER_OK).id]["event_time_utc"], "2026-10-06T06:30:10+00:00")
        self.assertEqual(self.nd[self.by_line(J_USER_OK).id]["host_timezone"], "America/New_York")

    def test_invariant_6_login_hour_is_utc_hour_of_source_time(self):
        self.assertEqual(self.by_line(LAST_LOGIN).login_hour, 6)
        self.assertEqual(self.by_line(J_USER_OK).login_hour, 6)
        for event in self.rows:
            if self.kind(event) != RECORD_SECURITY_EVENT:
                self.assertIsNone(event.login_hour)

    def test_invariants_7_to_9_collector_events_tagged_retained_and_selectable(self):
        collector = [e for e in self.rows if self.origin(e) == RECORD_ORIGIN_COLLECTOR]
        self.assertEqual(sorted(e.raw_log for e in collector), sorted([J_COLLECTOR_OK, *J_COLLECTOR_FAIL]))
        self.assertEqual({self.nd[e.id]["record_origin_basis"] for e in collector}, {"configured_ssh_user+collector_source_ip"})
        self.assertEqual(self.origin(self.by_line(J_USER_OK)), RECORD_ORIGIN_SOURCE_OBSERVED)
        self.assertEqual(self.origin(self.by_line(LAST_LOGIN)), RECORD_ORIGIN_SOURCE_OBSERVED)
        user_behavior = [e for e in self.rows
                         if self.kind(e) == RECORD_SECURITY_EVENT and self.origin(e) == RECORD_ORIGIN_SOURCE_OBSERVED]
        self.assertEqual(sorted(e.raw_log for e in user_behavior), sorted([J_USER_OK, J_REAL_FAIL, LAST_LOGIN]))
        self.assertEqual(len(self.rows), 12)

    def test_collector_frequency_does_not_raise_risk(self):
        real_fail = self.by_line(J_REAL_FAIL)
        self.assertEqual(real_fail.failed_login_count, 1)
        for line in [J_COLLECTOR_OK, *J_COLLECTOR_FAIL]:
            self.assertNotIn("brute_force", self.by_line(line).normalized_data)
        self.assertLess(self.by_line(J_COLLECTOR_OK).risk_score, 70)

    def test_invariants_11_12_linux_scope_and_cloud_untouched(self):
        self.assertEqual({(e.source_type, e.data_origin, e.data_scope) for e in self.rows}, {("LINUX", "LIVE_LINUX", "PRIVATE")})
        cloud = _azure_event()
        cloud.update(owner_id="owner-a", account_id=ACCOUNT_A)
        IngestionService(self.session).ingest_bulk_events([cloud])
        snapshot = lambda: [(e.id, e.hash, e.event_type, e.timestamp, e.normalized_data)
                            for e in self.session.scalars(select(Event).where(Event.source_type == "CLOUD"))]
        before = snapshot()
        with patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED.replace(minute=55)):
            self.collect(retrieved())
        self.assertEqual(snapshot(), before)
        self.assertNotIn("record_origin", before[0][4] or "")

    def test_dashboard_counts_security_semantics(self):
        summary = crud.dashboard_summary(self.session, owner_id="owner-a", environment=LINUX)
        self.assertEqual(summary["successful_logins"], 3)
        self.assertEqual(summary["failed_logins"], 4)
        self.assertEqual(summary["total_events"], 7)
        self.assertEqual(summary["system_snapshots"], 4)
        self.assertEqual(summary["system_events"], 1)
        self.assertEqual(summary["collector_generated_events"], 4)
        self.assertEqual(crud.dashboard_summary(self.session, owner_id="owner-a", environment=CLOUD)["total_events"], 0)

    def test_without_host_context_nothing_is_tagged_or_guessed(self):
        self.session.query(Event).delete()
        self.session.commit()
        with patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED):
            self.collect(retrieved(host_context={}))
        rows = self.linux_events()
        nd = {e.id: json.loads(e.normalized_data) for e in rows}
        self.assertEqual({nd[e.id]["record_origin"] for e in rows}, {RECORD_ORIGIN_SOURCE_OBSERVED})
        last = next(e for e in rows if e.raw_log == LAST_LOGIN)
        self.assertEqual((last.timestamp.hour, nd[last.id]["timestamp_tz_basis"]), (2, TZ_ASSUMED_UTC))


def _load_backfill():
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "scripts" / "backfill_linux_record_semantics.py"
    spec = importlib.util.spec_from_file_location("backfill_linux_record_semantics", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HistoricalBackfillTests(LinuxCollectionTestBase):
    """Legacy rows as stored before the fix: wall-clock times labelled UTC, snapshots as logins."""

    LEGACY_COLLECTED = datetime(2026, 10, 6, 6, 50, 11)

    def seed(self, index, raw, source, event_type, ts, ts_source="SOURCE_EVENT", username=None, source_ip=None):
        self.session.add(Event(
            event_id=f"legacy-{index}", server_id=self.server.id, owner_id="owner-a", account_id=ACCOUNT_A,
            timestamp=ts, collection_timestamp=self.LEGACY_COLLECTED, timestamp_source=ts_source,
            hostname="rhel-vm", username=username, source_ip=source_ip, event_type=event_type, category="auth",
            severity="low", risk_score=15, message=raw, raw_log=raw, hash=f"legacy-hash-{index}",
            normalized_data=json.dumps({"source": source}), source_type="LINUX", data_origin="LIVE_LINUX",
            data_scope="PRIVATE", login_hour=ts.hour,
        ))

    def setUp(self):
        super().setUp()
        self.seed(1, LAST_LOGIN, "last", "Successful Login", datetime(2026, 10, 6, 2, 25, 59), username="defensync", source_ip=COLLECTOR_IP)
        self.seed(2, LAST_REBOOT, "last", "Successful Login", datetime(2026, 7, 1, 11, 55, 33), username="reboot", source_ip="6.12.0-233.el10.")
        self.seed(3, "    AF_VSOCK CID: 2877339630", "hostnamectl", "Command Execution", datetime(2061, 3, 6, 13, 0, 30))
        self.seed(4, " 02:48:37 up 35 min,  2 users,  load average: 0.00", "w", "Successful Login", self.LEGACY_COLLECTED,
                  ts_source="COLLECTION_TIME_FALLBACK", username="02:48:37")
        self.seed(5, "wtmp begins Sat May 16 02:32:36 2026", "last", "Successful Login", datetime(2026, 5, 16, 2, 32, 36), username="wtmp")
        self.seed(6, J_COLLECTOR_OK, "secure", "Successful Login", datetime(2026, 10, 6, 6, 25, 59), username="defensync", source_ip=COLLECTOR_IP)
        self.session.commit()
        self.backfill = _load_backfill()
        self.patcher = patch.object(self.backfill, "host_context_for", return_value=HOST_CONTEXT)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def run_backfill(self):
        job = self.backfill.Backfill(self.session)
        job.run(apply=True)
        return job

    def row(self, index):
        return self.session.scalar(select(Event).where(Event.event_id == f"legacy-{index}"))

    def test_backfill_corrects_semantics_without_deleting(self):
        job = self.run_backfill()
        self.assertEqual(len(self.linux_events()), 6)
        last, reboot, snap, header, footer, journal = (self.row(i) for i in range(1, 7))
        self.assertEqual((last.timestamp, last.login_hour, last.event_type), (datetime(2026, 10, 6, 6, 25, 59), 6, "Successful Login"))
        self.assertEqual((reboot.event_type, reboot.username, reboot.source_ip, reboot.login_hour), ("System Event", None, None, None))
        self.assertEqual(reboot.timestamp, datetime(2026, 7, 1, 15, 55, 33))
        self.assertEqual((snap.event_type, snap.timestamp, snap.timestamp_source), ("System Snapshot", self.LEGACY_COLLECTED, SOURCE_SNAPSHOT))
        self.assertEqual((header.event_type, header.username), ("System Snapshot", None))
        self.assertEqual(json.loads(header.normalized_data)["artifact"], "OUTPUT_HEADER")
        self.assertEqual((footer.event_type, json.loads(footer.normalized_data)["artifact"]), ("System Event", "OUTPUT_FOOTER"))
        self.assertEqual(journal.timestamp, datetime(2026, 10, 6, 6, 25, 59))
        self.assertEqual(json.loads(journal.normalized_data)["record_origin"], RECORD_ORIGIN_COLLECTOR)
        self.assertEqual(json.loads(last.normalized_data)["record_origin"], RECORD_ORIGIN_SOURCE_OBSERVED)
        self.assertEqual(job.counts["hashes recomputed"], 2)
        self.assertFalse(job.uncorrectable)

    def test_recollection_deduplicates_and_rerun_is_noop(self):
        self.run_backfill()
        payload = retrieved()
        payload["sources"] = {"last": [LAST_LOGIN, LAST_REBOOT]}
        payload["secure_lines"] = payload["sources"]["journalctl"] = []
        stats = self.collect(payload)
        self.assertEqual(stats["inserted"], 0)
        self.assertEqual(len(self.linux_events()), 6)
        second = self.run_backfill()
        self.assertEqual(second.counts["rows changed"], 0)


if __name__ == "__main__":
    unittest.main()
