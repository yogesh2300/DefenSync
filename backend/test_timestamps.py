"""Timestamp extraction vs collection-time regression tests."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from backend.core.timestamps import SOURCE_EVENT, SOURCE_FALLBACK, infer_year, parse_occurrence
from backend.database.crud import calculate_event_hash
from backend.normalizer.event_normalizer import DefaultTimestampNormalizer
from backend.parser.engine import parse_audit_line, parse_secure_line


class TimestampRegressionTests(unittest.TestCase):
    def test_secure_syslog_keeps_source_time_not_collection_time(self):
        collected = datetime(2026, 8, 17, 14, 30, tzinfo=timezone.utc)
        line = "Aug 17 10:15:32 web01 sshd[12]: Failed password for yogesh from 10.0.0.8"
        parsed = parse_secure_line(line)
        self.assertIsNotNone(parsed)
        iso = DefaultTimestampNormalizer(collected).normalize(parsed)
        event_time = datetime.fromisoformat(iso)
        self.assertEqual(event_time.hour, 10)
        self.assertEqual(event_time.minute, 15)
        self.assertNotEqual(event_time.hour, 14)

    def test_audit_epoch_preserved(self):
        collected = datetime(2026, 8, 17, 14, 30, tzinfo=timezone.utc)
        epoch = datetime(2026, 8, 17, 10, 15, 32, tzinfo=timezone.utc).timestamp()
        line = f'type=USER_AUTH msg=audit({epoch}:123): pid=1 uid=0 op=login acct="root" res=success'
        parsed = parse_audit_line(line)
        self.assertIsNotNone(parsed)
        iso = DefaultTimestampNormalizer(collected).normalize(parsed)
        event_time = datetime.fromisoformat(iso)
        self.assertEqual(event_time.hour, 10)
        self.assertEqual(event_time.minute, 15)
        self.assertEqual(parsed.get("timestamp_source"), SOURCE_EVENT)

    def test_repeated_collection_same_hash(self):
        ts = datetime(2026, 8, 17, 10, 15, tzinfo=timezone.utc)
        raw = "Aug 17 10:15:32 web01 sshd: Failed password for yogesh from 10.0.0.8"
        first = calculate_event_hash(raw, ts, server_id="s1", event_type="Failed Login", username="yogesh", source_ip="10.0.0.8")
        second = calculate_event_hash(raw, ts, server_id="s1", event_type="Failed Login", username="yogesh", source_ip="10.0.0.8")
        self.assertEqual(first, second)

    def test_missing_timestamp_falls_back_and_is_marked(self):
        collected = datetime(2026, 8, 17, 14, 30, tzinfo=timezone.utc)
        result = parse_occurrence("no time here at all", collected_at=collected)
        self.assertEqual(result.source, SOURCE_FALLBACK)
        self.assertEqual(result.event_time, collected)

    def test_year_inference_avoids_future_date(self):
        collected = datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc)
        year = infer_year(12, 31, collected)
        self.assertEqual(year, 2025)

    def test_iso_journal_line(self):
        collected = datetime(2026, 8, 17, 18, 0, tzinfo=timezone.utc)
        result = parse_occurrence(
            "2026-08-17T10:15:32+00:00 web01 sshd[1]: Accepted password for yogesh from 10.0.0.8",
            collected_at=collected,
            source_hint="journalctl",
        )
        self.assertEqual(result.source, SOURCE_EVENT)
        self.assertEqual(result.event_time.hour, 10)

    def test_malformed_timestamp_fallback(self):
        collected = datetime(2026, 8, 17, 14, 30, tzinfo=timezone.utc)
        result = parse_occurrence("Feb 31 99:99:99 host msg", collected_at=collected)
        self.assertIn(result.source, {SOURCE_EVENT, SOURCE_FALLBACK})


if __name__ == "__main__":
    unittest.main()
