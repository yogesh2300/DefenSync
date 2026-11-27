"""Linux telemetry expansion: incremental journald, privilege escalation, sessions, wtmp dedup.

Runs the real collector parsing, pipeline, ingestion and state storage on SQLite. Only SSH
is replaced, by a fake host that answers like journalctl (cursor, --since fallback, reboot).
Line shapes follow the RHEL VM; nothing is written to PostgreSQL.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from backend.collector.journal import (
    MODE_CURSOR,
    MODE_INITIAL,
    MODE_SINCE,
    JournalPosition,
    build_journal_command,
    parse_journal_output,
    short_iso_line,
)
from backend.core.encryption import encrypt_secret
from backend.core.timestamps import SOURCE_EVENT, SOURCE_SNAPSHOT
from backend.database import server_crud
from backend.database.models import Event, LinuxCollectionState, Server
from backend.health.status import HealthStatus
from backend.normalizer.event_types import EventType
from backend.parser.login_history import DURATION_FROM_LOGOUT, DURATION_REPORTED, parse_login_history_line
from backend.services.collector_service import CollectorService
from backend.services.ingestion_service import IngestionService
from backend.services.transform_service import TransformService
from backend.test_linux_collection_pipeline import ACCOUNT_A, SSH_PASSWORD, LinuxCollectionTestBase

UTC = timezone.utc
NEW_YORK = ZoneInfo("America/New_York")
COLLECTED = datetime(2026, 10, 6, 13, 0, 0, tzinfo=UTC)
HOST_CONTEXT = {"collector_ip": "192.168.195.1", "timezone": "America/New_York", "utc_offset": "-0400"}
BOOT_A, BOOT_B = "a" * 32, "b" * 32


def ny(hour, minute, second=0, micro=0, day=6):
    return datetime(2026, 10, day, hour, minute, second, micro, tzinfo=NEW_YORK)


def usec(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000_000)


class FakeJournalHost:
    """Answers the incremental journal command the way journalctl does on the VM."""

    def __init__(self, *, persistent=False, max_entries=10_000):
        self.entries: list[dict] = []
        self.boot = BOOT_A
        self.boots = 1
        self.persistent = persistent
        self.max_entries = max_entries
        self.positions: list[JournalPosition | None] = []
        self.extra_sources: dict[str, list[str]] = {}
        self._seq = 0

    def log(self, moment, identifier, pid, message):
        self._seq += 1
        self.entries.append({
            "__CURSOR": f"s=fake;i={self._seq:x};b={self.boot}",
            "__REALTIME_TIMESTAMP": str(usec(moment)),
            "_BOOT_ID": self.boot, "_HOSTNAME": "YogeshOS",
            "SYSLOG_IDENTIFIER": identifier, "_PID": str(pid), "MESSAGE": message,
        })

    def reboot(self, *, keep_history):
        self.boot = BOOT_B if self.boot == BOOT_A else BOOT_A
        if keep_history:
            self.boots += 1
        else:
            self.entries.clear()
            self.boots = 1

    def output(self, position):
        markers = [
            f"__DS_BOOT_ID={self.boot[:8]}-{self.boot[8:12]}-{self.boot[12:16]}-{self.boot[16:20]}-{self.boot[20:]}",
            f"__DS_VAR_LOG_JOURNAL={'yes' if self.persistent else 'no'}",
            "__DS_STORAGE=", f"__DS_BOOTS={self.boots}",
        ]
        cursors = [entry["__CURSOR"] for entry in self.entries]
        if position is None or not position.cursor:
            mode, selected = MODE_INITIAL, self.entries
        elif position.cursor in cursors:
            mode, selected = MODE_CURSOR, self.entries[cursors.index(position.cursor) + 1:]
        else:
            since = (position.realtime_usec or 0) // 1_000_000 * 1_000_000
            mode, selected = MODE_SINCE, [e for e in self.entries if int(e["__REALTIME_TIMESTAMP"]) >= since]
        return markers + [f"__DS_MODE={mode}"] + [json.dumps(e) for e in selected[: self.max_entries]]

    def collect_raw_lines(self, config, *, tail_lines=None, log_sources=None, journal_position=None):
        self.positions.append(journal_position)
        batch = parse_journal_output(self.output(journal_position), NEW_YORK, self.max_entries)
        sources = {"journalctl": batch.lines, **self.extra_sources}
        return {
            "host": "192.0.2.10", "secure_lines": list(batch.lines), "audit_lines": [], "extra_lines": [],
            "sources": sources, "summary": {}, "metrics": {}, "host_context": HOST_CONTEXT, "journal": batch,
        }


class TelemetryTestBase(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        self.host = FakeJournalHost()
        self._now = patch("backend.services.pipeline_service.collection_now", return_value=COLLECTED)
        self._now.start()

    def tearDown(self):
        self._now.stop()
        super().tearDown()

    def run_collection(self, server=None, host=None):
        host = host or self.host
        with patch.object(CollectorService, "collect_raw_lines", side_effect=host.collect_raw_lines):
            from backend.services.server_service import ServerService
            return ServerService(self.session).collect_for_server((server or self.server).id)

    def events(self, event_type=None, server=None):
        query = select(Event).where(Event.server_id == (server or self.server).id)
        if event_type is not None:
            query = query.where(Event.event_type == str(event_type))
        self.session.expire_all()
        return list(self.session.scalars(query.order_by(Event.timestamp)).all())

    def state(self, server=None):
        self.session.expire_all()
        return self.session.scalar(
            select(LinuxCollectionState).where(LinuxCollectionState.server_id == (server or self.server).id)
        )

    @staticmethod
    def nd(event):
        return json.loads(event.normalized_data)


# --- journal reader -----------------------------------------------------------------------------

class JournalReaderTests(unittest.TestCase):
    def test_initial_command_reads_auth_facilities_bounded(self):
        command = build_journal_command(JournalPosition(), 500)
        self.assertIn("__DS_MODE=initial", command)
        self.assertIn("SYSLOG_FACILITY=4 SYSLOG_FACILITY=10", command)
        self.assertIn("head -n 500", command)
        self.assertNotIn("--after-cursor", command)

    def test_cursor_command_checks_cursor_then_falls_back_to_since(self):
        position = JournalPosition("s=ab12;i=1f;b=" + BOOT_A + ";m=9;t=5f;x=c3", BOOT_A, 1_791_275_609_072_056)
        command = build_journal_command(position, 100)
        self.assertIn(f"--after-cursor='{position.cursor}'", command)
        self.assertIn("then echo __DS_MODE=cursor", command)
        self.assertIn("else echo __DS_MODE=since", command)
        self.assertIn("--since=@1791275609", command)

    def test_unsafe_cursor_is_never_sent_to_the_shell(self):
        command = build_journal_command(JournalPosition("s=1;i=2 $(reboot)", BOOT_A, 1), 100)
        self.assertNotIn("reboot)", command)
        self.assertIn("__DS_MODE=initial", command)

    def test_rebuilds_short_iso_line(self):
        entry = {
            "__REALTIME_TIMESTAMP": str(usec(ny(5, 0, 14, 20))),
            "_SOURCE_REALTIME_TIMESTAMP": str(usec(ny(5, 0, 13, 999_000))),
            "_HOSTNAME": "YogeshOS", "SYSLOG_IDENTIFIER": "sshd-session", "_PID": "6399", "SYSLOG_PID": "1",
            "MESSAGE": "pam_unix(sshd:session): session opened for user ysalve(uid=1000) by ysalve(uid=0)",
        }
        self.assertEqual(
            short_iso_line(entry, NEW_YORK),
            "2026-10-06T05:00:13-04:00 YogeshOS sshd-session[6399]: "
            "pam_unix(sshd:session): session opened for user ysalve(uid=1000) by ysalve(uid=0)",
        )
        entry.update(MESSAGE=list(b"line one\nline two"), _PID=None)
        self.assertTrue(short_iso_line(entry, NEW_YORK).endswith("sshd-session[1]: line one line two"))

    def test_output_markers_and_persistence(self):
        host = FakeJournalHost()
        host.log(ny(5, 0), "sshd-session", 10, "Accepted password for alice from 203.0.113.9 port 1 ssh2")
        batch = parse_journal_output(host.output(None), NEW_YORK, 10)
        self.assertEqual((batch.mode, batch.entries_read, batch.current_boot_id), (MODE_INITIAL, 1, BOOT_A))
        self.assertIs(batch.persistent, False)
        self.assertEqual(batch.last_position.cursor, host.entries[0]["__CURSOR"])
        persistent = parse_journal_output(["__DS_STORAGE=persistent", "__DS_VAR_LOG_JOURNAL=no"], None, 10)
        self.assertIs(persistent.persistent, True)
        auto_with_dir = parse_journal_output(["__DS_STORAGE=", "__DS_VAR_LOG_JOURNAL=yes"], None, 10)
        self.assertIs(auto_with_dir.persistent, True)
        self.assertIsNone(auto_with_dir.last_position)


# --- incremental collection ---------------------------------------------------------------------

class IncrementalJournalTests(TelemetryTestBase):
    def log_alice_login(self, moment, pid):
        self.host.log(moment, "sshd-session", pid, f"Accepted password for alice from 203.0.113.9 port {pid} ssh2")

    def test_repeated_collection_reads_only_new_entries(self):
        self.log_alice_login(ny(5, 0), 100)
        self.log_alice_login(ny(5, 1), 101)
        first = self.run_collection()
        self.assertEqual((first["inserted"], first["journal"]["mode"], first["journal"]["entries_read"]), (2, MODE_INITIAL, 2))
        self.assertTrue(first["journal"]["cursor_advanced"])

        second = self.run_collection()
        self.assertEqual((second["inserted"], second["journal"]["mode"], second["journal"]["entries_read"]), (0, MODE_CURSOR, 0))
        self.assertEqual(self.host.positions[-1].cursor, self.host.entries[-1]["__CURSOR"])

        self.log_alice_login(ny(5, 2), 102)
        third = self.run_collection()
        self.assertEqual((third["inserted"], third["duplicates"], third["journal"]["entries_read"]), (1, 0, 1))
        self.assertEqual(len(self.events(EventType.SUCCESSFUL_LOGIN)), 3)
        self.assertTrue(third["success"])

    def test_cursor_is_stored_per_server(self):
        self.log_alice_login(ny(5, 0), 100)
        self.run_collection()
        other = Server(
            server_name="rhel-db", host="192.0.2.11", port=22, username="defensync",
            authentication_type="password", encrypted_password=encrypt_secret(SSH_PASSWORD), status="active",
            health_status=HealthStatus.UNKNOWN, owner_id="owner-a", created_by="owner-a", account_id=ACCOUNT_A,
        )
        self.session.add(other)
        self.session.commit()
        other_host = FakeJournalHost()
        other_host.boot = BOOT_B
        other_host.log(ny(6, 0), "sshd-session", 7, "Accepted password for bob from 203.0.113.20 port 7 ssh2")
        self.run_collection(other, other_host)
        self.assertEqual(other_host.positions[0], JournalPosition())
        self.assertNotEqual(self.state(other).journal_cursor, self.state().journal_cursor)
        self.assertEqual(self.session.scalar(select(func.count()).select_from(LinuxCollectionState)), 2)
        server_crud.delete_server(self.session, other)
        self.session.commit()
        self.assertIsNone(self.state(other))
        self.assertIsNotNone(self.state())

    def test_cursor_not_advanced_when_storing_fails(self):
        self.log_alice_login(ny(5, 0), 100)
        with patch.object(IngestionService, "ingest_bulk_events", side_effect=RuntimeError("db down")):
            failed = self.run_collection()
        self.assertFalse(failed["journal"]["cursor_advanced"])
        self.assertIsNone(self.state().journal_cursor)
        retry = self.run_collection()
        self.assertEqual((retry["journal"]["mode"], retry["inserted"]), (MODE_INITIAL, 1))

    def test_bounded_read_continues_next_run(self):
        self.host.max_entries = 2
        for minute in range(5):
            self.log_alice_login(ny(5, minute), 100 + minute)
        first = self.run_collection()
        self.assertTrue(first["journal"]["backlog_pending"])
        self.run_collection()
        last = self.run_collection()
        self.assertFalse(last["journal"]["backlog_pending"])
        self.assertEqual(len(self.events(EventType.SUCCESSFUL_LOGIN)), 5)

    def test_reboot_with_volatile_journal_resumes_without_duplicates(self):
        self.log_alice_login(ny(5, 0), 100)
        self.run_collection()
        self.host.reboot(keep_history=False)
        self.log_alice_login(ny(5, 30), 200)
        after = self.run_collection()
        journal = after["journal"]
        self.assertEqual(journal["mode"], MODE_SINCE)
        self.assertTrue(journal["reboot_detected"])
        self.assertTrue(journal["gap_possible"])
        self.assertEqual(after["inserted"], 1)
        self.assertEqual(self.state().journal_boot_id, BOOT_B)
        self.assertIsNotNone(self.state().last_reboot_detected_at)

    def test_reboot_with_persistent_journal_keeps_cursor(self):
        self.host.persistent = True
        self.log_alice_login(ny(5, 0), 100)
        self.run_collection()
        self.host.reboot(keep_history=True)
        self.log_alice_login(ny(5, 30), 200)
        after = self.run_collection()
        self.assertEqual((after["journal"]["mode"], after["inserted"]), (MODE_CURSOR, 1))
        self.assertTrue(after["journal"]["reboot_detected"])
        self.assertFalse(after["journal"]["gap_possible"])
        self.assertEqual(after["journal"]["boots_available"], 2)

    def test_overlap_after_since_fallback_is_deduplicated(self):
        self.log_alice_login(ny(5, 0, 10), 100)
        self.run_collection()
        state = self.state()
        state.journal_cursor = "s=lost;i=1;b=" + BOOT_B
        self.session.commit()
        repeat = self.run_collection()
        self.assertEqual((repeat["journal"]["mode"], repeat["inserted"], repeat["duplicates"]), (MODE_SINCE, 0, 1))

    def test_first_incremental_run_matches_rows_from_tail_collection(self):
        self.log_alice_login(ny(5, 0), 100)
        legacy_line = parse_journal_output(self.host.output(None), NEW_YORK, 10).lines[0]
        self.collect({
            "host": "192.0.2.10", "secure_lines": [legacy_line], "audit_lines": [], "extra_lines": [],
            "sources": {"journalctl": [legacy_line]}, "summary": {}, "metrics": {}, "host_context": HOST_CONTEXT,
        })
        stats = self.run_collection()
        self.assertEqual((stats["inserted"], stats["duplicates"]), (0, 1))

    def test_event_time_is_source_time_not_collection_time(self):
        self.log_alice_login(ny(5, 0, 7), 100)
        self.run_collection()
        login = self.events(EventType.SUCCESSFUL_LOGIN)[0]
        nd = self.nd(login)
        self.assertEqual(nd["event_time_utc"], "2026-10-06T09:00:07+00:00")
        self.assertEqual(nd["first_collection_time_utc"], COLLECTED.isoformat())
        self.assertEqual(login.timestamp_source, SOURCE_EVENT)
        self.assertEqual((nd["log_source"], nd["boot_id"]), ("journalctl", BOOT_A))


# --- privilege escalation -----------------------------------------------------------------------

class PrivilegeEscalationTests(unittest.TestCase):
    def classify(self, *lines):
        events, errors = TransformService().normalize_log_lines(
            secure_lines=list(lines), audit_lines=[], hostname="YogeshOS", host_tz=NEW_YORK, collected_at=COLLECTED,
        )
        return events, errors

    def test_su_success(self):
        (event,), _ = self.classify("2026-10-06T05:10:01-04:00 YogeshOS su[4249]: (to root) ysalve on pts/0")
        self.assertEqual((event.event_type, event.username), (EventType.PRIVILEGE_ESCALATION, "ysalve"))
        self.assertEqual(
            {k: event.metadata[k] for k in ("target_user", "tty", "mechanism", "outcome", "pid", "program")},
            {"target_user": "root", "tty": "pts/0", "mechanism": "su", "outcome": "success", "pid": 4249, "program": "su"},
        )
        self.assertEqual(event.timestamp, "2026-10-06T09:10:01+00:00")
        self.assertIsNone(event.source_ip)

    def test_su_failure(self):
        (event,), _ = self.classify("2026-10-06T05:11:00-04:00 YogeshOS su[4300]: FAILED SU (to root) ysalve on pts/0")
        self.assertEqual((event.event_type, event.username, event.metadata["outcome"]),
                         (EventType.FAILED_PRIVILEGE_ESCALATION, "ysalve", "failure"))

    def test_sudo_denied(self):
        (event,), _ = self.classify(
            "2026-10-06T05:12:00-04:00 YogeshOS sudo[4400]:    mallory : user NOT in sudoers ; TTY=pts/1 ; "
            "PWD=/home/mallory ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        )
        self.assertEqual((event.event_type, event.username), (EventType.FAILED_PRIVILEGE_ESCALATION, "mallory"))
        self.assertEqual((event.metadata["target_user"], event.metadata["cmd"], event.metadata["reason"]),
                         ("root", "/usr/bin/cat /etc/shadow", "user NOT in sudoers"))

    def test_sudo_wrong_password_counted_once_per_attempt(self):
        events, errors = self.classify(
            "2026-10-06T05:13:00-04:00 YogeshOS sudo[4500]: pam_unix(sudo:auth): authentication failure; "
            "logname=ysalve uid=1000 euid=0 tty=/dev/pts/0 ruser=ysalve rhost=  user=ysalve",
            "2026-10-06T05:13:09-04:00 YogeshOS sudo[4500]:   ysalve : 1 incorrect password attempt ; TTY=pts/0 ; "
            "PWD=/home/ysalve ; USER=root ; COMMAND=/usr/bin/id",
        )
        self.assertEqual([(e.event_type, e.username, e.metadata["mechanism"]) for e in events],
                         [(EventType.FAILED_PRIVILEGE_ESCALATION, "ysalve", "sudo")])
        self.assertIsNone(events[0].metadata.get("target_user"))
        self.assertEqual(len(errors), 1)

    def test_successful_sudo_command_unchanged(self):
        (event,), _ = self.classify(
            "2026-10-06T05:14:00-04:00 YogeshOS sudo[4600]:   ysalve : TTY=pts/0 ; PWD=/home/ysalve ; USER=root ; COMMAND=/usr/bin/id"
        )
        self.assertEqual((event.event_type, event.metadata["target_user"]), (EventType.SUDO_COMMAND, "root"))

    def test_ordinary_system_messages_are_not_privilege_escalation(self):
        events, _ = self.classify(
            "2026-10-06T05:10:01-04:00 YogeshOS su[4249]: pam_unix(su-l:session): session opened for user root(uid=0) by ysalve(uid=1000)",
            "2026-10-06T05:15:00-04:00 YogeshOS sudo[4700]: pam_unix(sudo:session): session opened for user root(uid=0) by ysalve(uid=1000)",
            "2026-10-06T05:16:00-04:00 YogeshOS logger[4800]: (to root) ysalve on pts/0",
            "2026-10-06T05:17:00-04:00 YogeshOS systemd-logind[900]: New session 12 of user ysalve.",
            "2026-10-06T05:18:00-04:00 YogeshOS (systemd)[901]: pam_unix(systemd-user:session): session opened for user ysalve(uid=1000) by ysalve(uid=0)",
        )
        self.assertEqual(events, [])


# --- sessions -----------------------------------------------------------------------------------

class SessionTests(TelemetryTestBase):
    OPENED = "pam_unix(sshd:session): session opened for user alice(uid=1001) by alice(uid=0)"
    CLOSED = "pam_unix(sshd:session): session closed for user alice"

    def test_login_open_close_with_exact_duration(self):
        self.host.log(ny(5, 0, 1, 100_000), "sshd-session", 300, "Accepted password for alice from 203.0.113.9 port 5 ssh2")
        self.host.log(ny(5, 0, 1, 400_000), "sshd-session", 300, self.OPENED)
        self.host.log(ny(5, 47, 31, 900_000), "sshd-session", 300, self.CLOSED)
        stats = self.run_collection()
        self.assertTrue(stats["success"])
        login, = self.events(EventType.SUCCESSFUL_LOGIN)
        opened, = self.events(EventType.SESSION_OPENED)
        closed, = self.events(EventType.SESSION_CLOSED)
        self.assertEqual({login.session_id, opened.session_id, closed.session_id}, {f"{BOOT_A}:sshd-session:300"})
        self.assertEqual((opened.source_ip, self.nd(opened)["session_correlation"]), ("203.0.113.9", "login_matched"))
        self.assertEqual(closed.source_ip, "203.0.113.9")
        self.assertAlmostEqual(closed.session_duration, 47 * 60 + 30.5, places=3)
        nd = self.nd(closed)
        self.assertEqual((nd["session_correlation"], nd["session_duration_basis"]), ("opened_matched", "journal_session_open_close"))
        self.assertEqual(nd["event_time_utc"], "2026-10-06T09:47:31+00:00")
        self.assertEqual(nd["session_end_utc"], "2026-10-06T09:47:31.900000+00:00")
        self.assertEqual(nd["session_start_utc"], "2026-10-06T09:00:01.400000+00:00")
        self.assertEqual(closed.logout_time.replace(tzinfo=None), datetime(2026, 10, 6, 9, 47, 31, 900_000))
        self.assertEqual(closed.login_time.replace(tzinfo=None), datetime(2026, 10, 6, 9, 0, 1, 400_000))

    def test_close_in_later_collection_pairs_with_stored_open(self):
        self.host.log(ny(5, 0), "sshd-session", 301, "Accepted password for alice from 203.0.113.9 port 5 ssh2")
        self.host.log(ny(5, 0, 1), "sshd-session", 301, self.OPENED)
        self.run_collection()
        self.host.log(ny(6, 0, 1), "sshd-session", 301, self.CLOSED)
        self.run_collection()
        closed, = self.events(EventType.SESSION_CLOSED)
        self.assertEqual(closed.session_duration, 3600.0)
        self.assertEqual(closed.source_ip, "203.0.113.9")

    def test_close_without_open_has_no_duration(self):
        self.host.log(ny(6, 0), "sshd-session", 302, self.CLOSED)
        self.host.log(ny(6, 1), "sshd-session", 999, self.OPENED)
        self.run_collection()
        closed, = self.events(EventType.SESSION_CLOSED)
        self.assertIsNone(closed.session_duration)
        self.assertIsNone(closed.logout_time and closed.login_time)
        self.assertEqual(self.nd(closed)["session_correlation"], "no_open_record")
        opened, = self.events(EventType.SESSION_OPENED)
        self.assertEqual((opened.source_ip, self.nd(opened)["session_correlation"]), (None, "no_login_record"))

    def test_local_console_login_and_failure(self):
        self.host.log(ny(4, 35), "gdm-password]", 3066,
                      "pam_unix(gdm-password:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/tty1 ruser= rhost=  user=ysalve")
        self.host.log(ny(4, 35, 5), "gdm-password]", 3139,
                      "pam_unix(gdm-password:session): session opened for user ysalve(uid=1000) by ysalve(uid=0)")
        self.host.log(ny(4, 33, 50), "gdm-launch-environment]", 1290,
                      "pam_unix(gdm-launch-environment:session): session opened for user gdm(uid=42) by (uid=0)")
        stats = self.run_collection()
        failed, = self.events(EventType.FAILED_LOGIN)
        self.assertEqual((failed.username, failed.source_ip, self.nd(failed)["tty"]), ("ysalve", None, "/dev/tty1"))
        opened, = self.events(EventType.SESSION_OPENED)
        self.assertEqual((opened.username, self.nd(opened)["service"], opened.session_id),
                         ("ysalve", "gdm-password", f"{BOOT_A}:gdm-password:3139"))
        self.assertEqual((stats["failed"], stats["skipped"]), (0, 1))

    def test_collector_sessions_tagged_and_not_stored(self):
        self.host.log(ny(5, 0), "sshd-session", 400, "Accepted password for defensync from 192.168.195.1 port 6 ssh2")
        self.host.log(ny(5, 0, 1), "sshd-session", 400,
                      "pam_unix(sshd:session): session opened for user defensync(uid=1000) by defensync(uid=0)")
        self.host.log(ny(5, 0, 2), "sshd-session", 400, "pam_unix(sshd:session): session closed for user defensync")
        stats = self.run_collection()
        login, = self.events(EventType.SUCCESSFUL_LOGIN)
        self.assertEqual(self.nd(login)["record_origin"], "COLLECTOR_GENERATED")
        self.assertEqual(self.events(EventType.SESSION_OPENED) + self.events(EventType.SESSION_CLOSED), [])
        self.assertEqual(stats["collector_sessions_skipped"], 2)
        self.host.log(ny(5, 15), "sshd-session", 401, "Accepted password for defensync from 192.168.195.1 port 7 ssh2")
        self.run_collection()
        self.host.log(ny(5, 15, 2), "sshd-session", 401, "pam_unix(sshd:session): session closed for user defensync")
        later = self.run_collection()
        self.assertEqual((later["inserted"], later["collector_sessions_skipped"]), (0, 1))

    def test_existing_collector_rows_are_kept(self):
        self.host.log(ny(5, 0), "sshd-session", 400, "Accepted password for defensync from 192.168.195.1 port 6 ssh2")
        self.run_collection()
        before = [(e.id, e.hash) for e in self.events()]
        self.host.log(ny(5, 1), "sshd-session", 500, "Accepted password for alice from 203.0.113.9 port 8 ssh2")
        self.run_collection()
        self.assertTrue(set(before) <= {(e.id, e.hash) for e in self.events()})


# --- wtmp (last) sessions -----------------------------------------------------------------------

LAST_OPEN = "alice    pts/3        203.0.113.9      Tue Oct  6 05:00:00 2026   still logged in"
LAST_CLOSED = "alice    pts/3        203.0.113.9      Tue Oct  6 05:00:00 2026 - Tue Oct  6 05:47:30 2026  (00:47)"
LAST_CRASH = "ysalve   tty2         local            Mon Oct  5 14:02:23 2026 - crash                     (14:31)"
LAST_GONE = "ysalve   tty2         local            Mon Oct  5 14:02:23 2026   gone - no logout"
LAST_REBOOT_RUNNING = "reboot   system boot  6.12.0-233.el10. Tue Oct  6 04:33:39 2026   still running"
LAST_REBOOT_DONE = "reboot   system boot  6.12.0-233.el10. Tue Oct  6 04:33:39 2026 - Tue Oct  6 09:00:00 2026  (04:26)"
LAST_ROOT_DOWN = "root     pts/1                         Sun Jun 14 05:20:24 2026 - down                     (1+21:45)"


class LoginHistoryParserTests(unittest.TestCase):
    def parse(self, line):
        return parse_login_history_line(line, source="last", collected_at=COLLECTED, host_tz=NEW_YORK)

    def test_duration_only_from_wtmp(self):
        closed = self.parse(LAST_CLOSED)
        self.assertEqual((closed.duration_seconds, closed.duration_basis, closed.session_state),
                         (47 * 60 + 30.0, DURATION_FROM_LOGOUT, "closed"))
        self.assertEqual(closed.logout_time, datetime(2026, 10, 6, 9, 47, 30, tzinfo=UTC))
        crash = self.parse(LAST_CRASH)
        self.assertEqual((crash.duration_seconds, crash.duration_basis, crash.logout_time), (14 * 3600 + 31 * 60.0, DURATION_REPORTED, None))
        down = self.parse(LAST_ROOT_DOWN)
        self.assertEqual((down.remote_host, down.duration_seconds), (None, (45 * 60 + 21 * 3600 + 86400) * 1.0))
        for line in (LAST_OPEN, LAST_GONE):
            self.assertIsNone(self.parse(line).duration_seconds)

    def test_identity_ignores_state_and_collection_time(self):
        self.assertEqual(self.parse(LAST_OPEN).session_key, self.parse(LAST_CLOSED).session_key)
        self.assertEqual(self.parse(LAST_CRASH).session_key, self.parse(LAST_GONE).session_key)
        later = parse_login_history_line(LAST_OPEN, source="last", collected_at=COLLECTED + timedelta(days=3), host_tz=NEW_YORK)
        self.assertEqual(later.session_key, self.parse(LAST_OPEN).session_key)
        self.assertEqual(self.parse(LAST_OPEN).session_key, "last:alice:pts/3:203.0.113.9:2026-10-06T09:00:00Z")


class LoginHistoryDedupTests(TelemetryTestBase):
    def collect_last(self, *lines, journal=()):
        return self.collect({
            "host": "192.0.2.10", "secure_lines": list(journal), "audit_lines": [], "extra_lines": [],
            "sources": {"journalctl": list(journal), "last": list(lines), "uptime": [" 09:00:00 up 4:26,  1 user"]},
            "summary": {}, "metrics": {}, "host_context": HOST_CONTEXT,
        })

    def last_rows(self):
        self.session.expire_all()
        return list(self.session.scalars(select(Event).where(Event.command == "last -F")).all())

    def test_session_seen_open_then_closed_is_one_row(self):
        self.collect_last(LAST_OPEN)
        row, = self.last_rows()
        before = (row.id, row.hash, row.timestamp, row.raw_log, row.event_type)
        later = datetime(2026, 10, 6, 14, 0, tzinfo=UTC)
        with patch("backend.services.pipeline_service.collection_now", return_value=later):
            stats = self.collect_last(LAST_CLOSED)
        self.assertEqual((stats["inserted"], stats["login_history_duplicates"]), (1, 1))  # the uptime snapshot
        row, = self.last_rows()
        self.assertEqual((row.id, row.hash, row.timestamp, row.raw_log, row.event_type), before)
        self.assertEqual(row.session_duration, 47 * 60 + 30.0)
        self.assertEqual(row.logout_time.replace(tzinfo=None), datetime(2026, 10, 6, 9, 47, 30))
        self.assertEqual(row.collection_timestamp.replace(tzinfo=None), datetime(2026, 10, 6, 14, 0))
        nd = self.nd(row)
        self.assertEqual((nd["session_state"], nd["first_collection_time_utc"]), ("closed", COLLECTED.isoformat()))
        self.assertEqual(nd["event_time_utc"], "2026-10-06T09:00:00+00:00")

    def test_crash_and_gone_variants_and_reboot(self):
        self.collect_last(LAST_CRASH, LAST_REBOOT_RUNNING)
        self.collect_last(LAST_GONE, LAST_REBOOT_DONE, LAST_CRASH)
        rows = self.last_rows()
        self.assertEqual(len(rows), 2)
        reboot = next(r for r in rows if r.event_type == str(EventType.SYSTEM_EVENT))
        self.assertIsNone(reboot.login_time)
        self.assertEqual(self.nd(reboot)["record_kind"], "SYSTEM_EVENT")

    def test_legacy_duplicate_rows_are_kept_and_not_multiplied(self):
        for line in (LAST_CRASH, LAST_GONE):
            event = {
                "event_id": line[:20] + line[-8:], "timestamp": "2026-10-05T18:02:23+00:00", "hostname": "ubuntu-web",
                "username": "ysalve", "event_type": "Successful Login", "category": "authentication", "severity": "low",
                "risk_score": 15, "raw_log": line, "message": line, "command": "last -F", "server_id": self.server.id,
                "normalized_data": json.dumps({"record_kind": "SECURITY_EVENT"}),
            }
            IngestionService(self.session).ingest_bulk_events([event])
        self.assertEqual(len(self.last_rows()), 2)
        stats = self.collect_last(LAST_CRASH, LAST_GONE)
        self.assertEqual(len(self.last_rows()), 2)
        self.assertEqual(stats["login_history_duplicates"], 2)
        self.assertTrue(all(r.session_id == "last:ysalve:tty2:local:2026-10-05T18:02:23Z" for r in self.last_rows()))

    def test_different_login_time_is_a_new_session(self):
        self.collect_last(LAST_OPEN)
        self.collect_last(LAST_OPEN.replace("05:00:00", "06:10:00"))
        self.assertEqual(len(self.last_rows()), 2)

    def test_journal_hash_dedup_still_applies(self):
        line = "2026-10-06T05:00:00-04:00 YogeshOS sshd-session[1]: Accepted password for alice from 203.0.113.9 port 1 ssh2"
        self.collect_last(journal=[line, line])
        self.collect_last(journal=[line])
        self.assertEqual(len(self.events(EventType.SUCCESSFUL_LOGIN)), 1)

    def test_snapshots_stay_snapshots(self):
        self.collect_last(LAST_OPEN)
        snapshot, = self.events(EventType.SYSTEM_SNAPSHOT)
        self.assertEqual((snapshot.timestamp_source, self.nd(snapshot)["record_kind"]), (SOURCE_SNAPSHOT, "SYSTEM_SNAPSHOT"))
        self.assertEqual(snapshot.timestamp, snapshot.collection_timestamp)
        login, = self.events(EventType.SUCCESSFUL_LOGIN)
        self.assertEqual(self.nd(login)["record_kind"], "SECURITY_EVENT")


if __name__ == "__main__":
    unittest.main()
