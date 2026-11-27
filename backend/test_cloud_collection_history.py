"""Cloud data collection expansion: bounded historical windows and persisted collection runs.

Fake HTTPS transport (real-shaped Entra token + Log Analytics responses) and SQLite
in-memory only: no live Azure, no PostgreSQL rows, no real credentials.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from sqlalchemy import func, select

from backend.core.config import Settings
from backend.database.models import CloudCollectionRun, CloudSource, Event
from backend.services.cloud import cloud_source_service
from backend.services.cloud.azure_collector import (
    MAX_RECORDS_LIMIT,
    MAX_WINDOW_MINUTES,
    CollectionLimits,
    resolve_window,
)
from backend.services.cloud.azure_normalizer import ENTRA_SIGNIN, normalize_record
from backend.test_azure_collector import (
    ACCOUNT_A,
    ADMIN_ID,
    EVENT_TIME,
    SECRET,
    SIGNIN_COLUMNS,
    TOKEN,
    FakeAzure,
    activity_row,
    record,
    signin_row,
)
from backend.test_cloud_sources import SOURCE_URL, CloudSourceTestBase, token_failure

MISSING_TABLE = {"error": {"code": "BadArgumentError", "message": "invalid", "innererror": {
    "code": "SemanticError", "message": "'where' operator: Failed to resolve table or column expression named 'AzureActivity'"}}}


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def window(days_ago: float, hours: float) -> tuple[datetime, datetime]:
    end = (datetime.now(timezone.utc) - timedelta(days=days_ago)).replace(microsecond=0)
    return end - timedelta(hours=hours), end


def historical(start: datetime, end: datetime, **extra) -> dict:
    return {"start_time": start.isoformat(), "end_time": end.isoformat(), **extra}


class HistoryTestBase(CloudSourceTestBase):
    def setUp(self):
        super().setUp()
        self.source_id = self.create_source()["id"]
        self.fake.requests.clear()

    def collect(self, body=None, fake=None):
        return self.api("analyst-a", fake).post(f"{SOURCE_URL}/{self.source_id}/collect", json=body or {})

    def runs(self):
        return list(self.session.scalars(select(CloudCollectionRun).order_by(CloudCollectionRun.started_at)).all())

    def cloud_events(self):
        return list(self.session.scalars(select(Event).where(Event.provider == "AZURE")).all())


class HistoricalWindowTests(HistoryTestBase):
    def test_valid_historical_window(self):
        start, end = window(days_ago=10, hours=36)
        response = self.collect(historical(start, end))
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        run = body["collection_run"]
        self.assertEqual((body["outcome"], run["status"], run["mode"]), ("SUCCESS", "SUCCESS", "HISTORICAL"))
        self.assertEqual((parse(run["window_start"]), parse(run["window_end"])), (start, end))
        self.assertEqual((parse(body["window_start"]), parse(body["window_end"])), (start, end))
        queries = self.fake.queries()
        self.assertEqual(len(queries), 2)
        for query in queries:
            first, last = (parse(part) for part in query["timespan"].split("/"))
            self.assertEqual((first, last), (start, end))
            self.assertIn("| where TimeGenerated between (datetime(", query["query"])
            self.assertIn("| take 500", query["query"])

    def test_invalid_or_reversed_window_is_rejected_before_azure(self):
        start, end = window(days_ago=3, hours=2)
        for body in (
            historical(end, start),
            historical(start, start),
            {"start_time": start.isoformat()},
            {"end_time": end.isoformat()},
            {**historical(start, end), "lookback_minutes": 15},
            historical(start, datetime.now(timezone.utc) + timedelta(hours=1)),
        ):
            response = self.collect(body)
            self.assertEqual(response.status_code, 422, body)
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.runs(), [])
        self.assertEqual(self.event_count(), 0)

    def test_maximum_window_enforcement(self):
        limits = CollectionLimits()
        start, end = window(days_ago=20, hours=limits.max_window_hours + 1)
        self.assertEqual(self.collect(historical(start, end)).status_code, 422)
        too_old_start = datetime.now(timezone.utc) - timedelta(days=limits.max_history_days, hours=1)
        self.assertEqual(self.collect(historical(too_old_start, too_old_start + timedelta(hours=1))).status_code, 422)
        self.assertEqual(self.collect({"lookback_minutes": MAX_WINDOW_MINUTES + 1}).status_code, 422)
        self.assertEqual(self.collect({**historical(*window(5, 1)), "max_records": MAX_RECORDS_LIMIT + 1}).status_code, 422)
        self.assertEqual(self.runs(), [])
        start, end = window(days_ago=20, hours=limits.max_window_hours)
        self.assertEqual(self.collect(historical(start, end)).status_code, 200)

        configured = Settings.model_construct(CLOUD_COLLECTION_MAX_WINDOW_HOURS=48, CLOUD_COLLECTION_MAX_HISTORY_DAYS=30)
        with mock.patch.object(cloud_source_service, "get_settings", return_value=configured):
            self.assertEqual(self.collect(historical(*window(5, 49))).status_code, 422)
            self.assertEqual(self.collect(historical(*window(31, 1))).status_code, 422)
            self.assertEqual(self.collect(historical(*window(27, 48))).status_code, 200)
            limits_view = self.api("analyst-a").get(SOURCE_URL).json()["collection_limits"]
        self.assertEqual((limits_view["max_window_hours"], limits_view["max_history_days"]), (48, 30))
        self.assertEqual(limits_view["max_lookback_minutes"], MAX_WINDOW_MINUTES)

        now = datetime.now(timezone.utc)
        tight = CollectionLimits(max_window_hours=2, max_history_days=1)
        with self.assertRaises(ValueError):
            resolve_window(lookback_minutes=None, start=now - timedelta(hours=3), end=now, now=now, limits=tight)
        with self.assertRaises(ValueError):
            resolve_window(lookback_minutes=None, start=now - timedelta(days=2), end=now - timedelta(days=2) + timedelta(hours=1), now=now, limits=tight)
        self.assertEqual(resolve_window(lookback_minutes=60, start=None, end=None, now=now, limits=tight), (now - timedelta(hours=1), now))


class CollectionResultTests(HistoryTestBase):
    def test_successful_collection_result_is_persisted(self):
        fake = FakeAzure(signin_rows=[signin_row("s1"), signin_row("s2", result="50126")], activity_rows=[activity_row("a1")])
        start, end = window(days_ago=7, hours=24)
        body = self.collect(historical(start, end), fake).json()
        stored = self.runs()
        self.assertEqual(len(stored), 1)
        run = stored[0]
        self.assertEqual((run.cloud_source_id, run.account_id, run.requested_by), (self.source_id, ACCOUNT_A, "analyst-a"))
        self.assertEqual((run.status, run.mode, run.collection_id), ("SUCCESS", "HISTORICAL", body["collection_id"]))
        self.assertEqual((run.rows_retrieved, run.rows_normalized, run.rows_failed, run.rows_stored, run.rows_duplicate), (3, 3, 0, 3, 0))
        self.assertFalse(run.truncated)
        self.assertIsNone(run.error_code)
        self.assertIsNotNone(run.started_at)
        self.assertGreaterEqual(run.completed_at, run.started_at)
        self.assertEqual([(item["source"], item["status"], item["retrieved"]) for item in json.loads(run.source_results)],
                         [("ENTRA_SIGNIN", "OK", 2), ("AZURE_ACTIVITY", "OK", 1)])

        api = self.api("analyst-a")
        listed = api.get(f"{SOURCE_URL}/{self.source_id}/collections").json()
        self.assertEqual(listed["count"], 1)
        view = listed["runs"][0]
        self.assertEqual((view["id"], view["status"], view["rows_retrieved"], view["rows_stored"], view["rows_duplicate"]), (run.id, "SUCCESS", 3, 3, 0))
        self.assertEqual(api.get(f"{SOURCE_URL}/{self.source_id}/collections/{run.id}").json()["id"], run.id)
        self.assertEqual(api.get(f"{SOURCE_URL}/{self.source_id}").json()["last_collection_run"]["id"], run.id)
        self.assertEqual(api.get(f"{SOURCE_URL}/{self.source_id}/collections/missing").status_code, 404)
        self.assertEqual(self.api("analyst-b").get(f"{SOURCE_URL}/{self.source_id}/collections").status_code, 404)
        self.assertEqual(self.api("analyst-b").get(f"{SOURCE_URL}/{self.source_id}/collections/{run.id}").status_code, 404)

    def test_empty_activity_table_is_recorded_not_assumed(self):
        body = self.collect({}, FakeAzure(signin_rows=[signin_row("s1")], activity_rows=[])).json()
        run = body["collection_run"]
        self.assertEqual(run["status"], "SUCCESS")
        self.assertEqual({item["source"]: (item["status"], item["retrieved"]) for item in run["sources"]},
                         {"ENTRA_SIGNIN": ("OK", 1), "AZURE_ACTIVITY": ("OK", 0)})

    def test_partial_collection(self):
        missing = FakeAzure(query_status={"AzureActivity": 400}, query_error={"AzureActivity": MISSING_TABLE})
        body = self.collect({}, missing).json()
        run = body["collection_run"]
        self.assertEqual((body["status"], run["status"]), ("COLLECTION_OK", "PARTIAL"))
        self.assertEqual(run["error"]["code"], "SOURCE_NOT_AVAILABLE")
        self.assertEqual({item["source"]: item["status"] for item in run["sources"]}, {"ENTRA_SIGNIN": "OK", "AZURE_ACTIVITY": "SOURCE_NOT_AVAILABLE"})
        self.assertEqual((run["rows_retrieved"], run["rows_stored"]), (1, 1))

        rows = [signin_row("t1"), signin_row("t2"), signin_row("t3")]
        rows[-1][SIGNIN_COLUMNS.index(("TimeGenerated", "datetime"))] = "2026-10-04T09:30:00.000Z"
        truncated = self.collect({**historical(*window(4, 12)), "max_records": 3, "sources": ["ENTRA_SIGNIN"]},
                                 FakeAzure(signin_rows=rows)).json()["collection_run"]
        self.assertEqual((truncated["status"], truncated["truncated"], truncated["error"]["code"]), ("PARTIAL", True, "TRUNCATED"))
        self.assertEqual(truncated["max_records_per_source"], 3)
        self.assertEqual([item["source"] for item in truncated["sources"]], ["ENTRA_SIGNIN"])
        self.assertEqual(truncated["sources"][0]["resume_from"], "2026-10-04T09:30:00.000Z")
        self.assertIn("2026-10-04T09:30:00.000Z", truncated["error"]["message"])

        malformed = self.collect({}, FakeAzure(signin_rows=[signin_row("m1"), ["short"]], activity_rows=[])).json()["collection_run"]
        self.assertEqual((malformed["status"], malformed["error"]["code"], malformed["rows_failed"]), ("PARTIAL", "ROWS_FAILED", 1))
        self.assertEqual([run.status for run in self.runs()], ["PARTIAL", "PARTIAL", "PARTIAL"])

    def test_failed_collection(self):
        response = self.collect(historical(*window(6, 6)), FakeAzure(token_response=token_failure(7000215)))
        self.assertEqual(response.status_code, 200)
        run = response.json()["collection_run"]
        self.assertEqual((run["status"], run["error"]["code"], run["rows_retrieved"], run["rows_stored"]), ("FAILED", "INVALID_CREDENTIALS", 0, 0))
        self.assertEqual({item["source"]: item["status"] for item in run["sources"]},
                         {"ENTRA_SIGNIN": "INVALID_CREDENTIALS", "AZURE_ACTIVITY": "NOT_QUERIED"})
        self.assertEqual(response.json()["source"]["last_collection_run"]["status"], "FAILED")

        source = self.session.get(CloudSource, self.source_id)
        source.encrypted_client_secret = "not-a-fernet-token"
        self.session.commit()
        unreadable = self.collect({})
        self.assertEqual(unreadable.status_code, 422)
        self.assertEqual((self.runs()[-1].status, self.runs()[-1].error_code), ("FAILED", "CREDENTIAL_UNREADABLE"))

    def test_unexpected_error_marks_run_failed(self):
        with mock.patch("backend.services.cloud.azure_collector.AzureCollector._store", side_effect=RuntimeError("db down")):
            with self.assertRaises(RuntimeError):
                self.collect({})
        run = self.runs()[-1]
        self.assertEqual((run.status, run.error_code), ("FAILED", "COLLECTION_ERROR"))
        self.assertIsNotNone(run.completed_at)
        self.assertNotIn("db down", run.error_message)


class DeduplicationAndTimestampTests(HistoryTestBase):
    def test_duplicate_historical_collection(self):
        fake = FakeAzure(signin_rows=[signin_row("s1"), signin_row("s2")], activity_rows=[activity_row("a1")])
        start, end = window(days_ago=12, hours=24)
        first = self.collect(historical(start, end), fake).json()["collection_run"]
        ids = sorted(event.event_id for event in self.cloud_events())
        again = self.collect(historical(start, end), fake).json()["collection_run"]
        overlap = self.collect(historical(start + timedelta(hours=12), end + timedelta(hours=12)), fake).json()["collection_run"]
        recent = self.collect({"lookback_minutes": 60}, fake).json()["collection_run"]
        self.assertEqual((first["rows_stored"], first["rows_duplicate"]), (3, 0))
        for run in (again, overlap, recent):
            self.assertEqual((run["status"], run["rows_retrieved"], run["rows_stored"], run["rows_duplicate"]), ("SUCCESS", 3, 0, 3))
        self.assertEqual(sorted(event.event_id for event in self.cloud_events()), ids)
        self.assertEqual(len(self.runs()), 4)

    def test_event_time_and_collection_time_are_separate(self):
        start, end = window(days_ago=9, hours=24)
        run = self.collect(historical(start, end)).json()["collection_run"]
        events = {json.loads(event.normalized_data)["azure_source"]: event for event in self.cloud_events()}
        started = parse(run["started_at"])
        for event in events.values():
            collected = event.collection_timestamp.replace(tzinfo=timezone.utc)
            self.assertLess(abs(collected - started), timedelta(seconds=30))
            self.assertEqual(event.timestamp_source, "SOURCE_EVENT")
            self.assertNotEqual(event.timestamp, event.collection_timestamp)
        self.assertEqual(events["ENTRA_SIGNIN"].timestamp.replace(tzinfo=timezone.utc), parse(EVENT_TIME[:26] + "Z"))
        self.assertEqual(events["AZURE_ACTIVITY"].timestamp.replace(tzinfo=timezone.utc), datetime(2026, 10, 4, 8, 1, tzinfo=timezone.utc))

        row = record(SIGNIN_COLUMNS, signin_row("same-event"))
        earlier = normalize_record(ENTRA_SIGNIN, row, owner_id=ADMIN_ID, account_id=ACCOUNT_A,
                                   collected_at=datetime(2026, 10, 5, tzinfo=timezone.utc), collection_id="c-1")
        later = normalize_record(ENTRA_SIGNIN, row, owner_id=ADMIN_ID, account_id=ACCOUNT_A,
                                 collected_at=datetime(2026, 11, 5, tzinfo=timezone.utc), collection_id="c-2")
        self.assertEqual((earlier["hash"], earlier["event_id"], earlier["timestamp"]), (later["hash"], later["event_id"], later["timestamp"]))
        self.assertNotEqual(earlier["collection_timestamp"], later["collection_timestamp"])


class CollectionSecretTests(HistoryTestBase):
    def test_no_secret_leakage(self):
        leaky = FakeAzure(token_response=token_failure(7000215))
        responses = [
            self.collect(historical(*window(8, 4))),
            self.collect({}, leaky),
            self.collect(historical(*window(2, 1)), FakeAzure(query_status={"AzureActivity": 400}, query_error={"AzureActivity": MISSING_TABLE})),
        ]
        api = self.api("analyst-a")
        responses += [api.get(f"{SOURCE_URL}/{self.source_id}/collections"), api.get(SOURCE_URL), api.get(f"{SOURCE_URL}/{self.source_id}")]
        responses += [api.get(f"{SOURCE_URL}/{self.source_id}/collections/{run.id}") for run in self.runs()]
        for response in responses:
            self.assertNotIn(SECRET, response.text, response.request.url)
            self.assertNotIn(TOKEN, response.text, response.request.url)
        stored = " ".join(
            " ".join(str(value) for value in (run.error_code, run.error_message, run.source_results, run.collection_id))
            for run in self.runs()
        )
        self.assertNotIn(SECRET, stored)
        self.assertNotIn(TOKEN, stored)
        columns = set(CloudCollectionRun.__table__.columns.keys())
        self.assertFalse({name for name in columns if "secret" in name or "token" in name or "password" in name})
        logged = self.log.getvalue()
        self.assertIn("collection run", logged)
        self.assertNotIn(SECRET, logged)
        self.assertNotIn(TOKEN, logged)

    def test_deleting_source_removes_its_runs_but_keeps_events(self):
        self.collect({})
        self.assertEqual(len(self.runs()), 1)
        self.assertEqual(self.api("admin-1").delete(f"{SOURCE_URL}/{self.source_id}").status_code, 200)
        self.assertEqual(self.session.scalar(select(func.count(CloudCollectionRun.id))), 0)
        self.assertEqual(len(self.cloud_events()), 2)


if __name__ == "__main__":
    unittest.main()
