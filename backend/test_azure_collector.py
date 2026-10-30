"""Step 2: real Azure telemetry acquisition (collector + cloud normalizer).

These tests use a fake HTTPS transport that returns real-shaped Microsoft Entra
token and Log Analytics Query API responses. They prove the collector logic, not
live Azure connectivity. SQLite in-memory only.
"""

from __future__ import annotations

import io
import json
import logging
import unittest
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import cloud as cloud_api
from backend.api.dependencies import get_current_admin, get_current_user, get_db
from backend.core.config import Settings
from backend.core.environments import CLOUD, LINUX, source_family
from backend.core.exceptions import register_exception_handlers
from backend.core.timestamps import SOURCE_EVENT, SOURCE_FALLBACK
from backend.database import crud
from backend.database.models import DATA_SCOPE_GLOBAL, DATA_SCOPE_PRIVATE, Account, Base, Event, User
from backend.database.scope import event_visibility_clause
from backend.services.account_service import AccountService
from backend.services.cloud.azure_client import HttpResponse, LogAnalyticsClient
from backend.services.cloud.azure_collector import (
    LAST_RUN,
    MAX_WINDOW_MINUTES,
    STATUS_COLLECTION_FAILED,
    STATUS_COLLECTION_OK,
    STATUS_CONFIGURED,
    STATUS_NOT_CONFIGURED,
    AzureCollector,
)
from backend.services.cloud.azure_normalizer import AZURE_ACTIVITY, ENTRA_SIGNIN, normalize_record
from backend.services.global_intelligence_service import GlobalIntelligenceService

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
WORKSPACE = "99999999-8888-7777-6666-555555555555"
SECRET = "s3cr3t-CLIENT-value-do-not-leak"
TOKEN = "eyJ0eXAi.fake-access-token.do-not-leak"
ACCOUNT_A = "acct-a"
ACCOUNT_B = "acct-b"
ADMIN_ID = "admin-1"
ALICE_OID = "0f0e0d0c-0000-4000-8000-00000000a11c"
BOB_OID = "0f0e0d0c-0000-4000-8000-000000000b0b"
SUB = "12345678-aaaa-bbbb-cccc-1234567890ab"
EVENT_TIME = "2026-10-04T07:58:10.1234567Z"

SIGNIN_COLUMNS = [
    ("TenantId", "string"), ("TimeGenerated", "datetime"), ("CreatedDateTime", "datetime"), ("Id", "string"),
    ("OperationName", "string"), ("Category", "string"), ("UserPrincipalName", "string"), ("UserId", "string"),
    ("UserDisplayName", "string"), ("AppId", "string"), ("AppDisplayName", "string"), ("ClientAppUsed", "string"),
    ("IPAddress", "string"), ("Location", "string"), ("LocationDetails", "dynamic"), ("DeviceDetail", "dynamic"),
    ("ResultType", "string"), ("ResultDescription", "string"), ("Status", "dynamic"),
    ("AuthenticationRequirement", "string"), ("AuthenticationDetails", "dynamic"), ("ConditionalAccessStatus", "string"),
    ("CorrelationId", "string"), ("IsInteractive", "bool"),
]
ACTIVITY_COLUMNS = [
    ("TenantId", "string"), ("TimeGenerated", "datetime"), ("OperationNameValue", "string"), ("OperationName", "string"),
    ("Caller", "string"), ("CallerIpAddress", "string"), ("CategoryValue", "string"), ("ActivityStatusValue", "string"),
    ("ActivitySubstatusValue", "string"), ("CorrelationId", "string"), ("EventDataId", "string"), ("SubscriptionId", "string"),
    ("ResourceGroup", "string"), ("_ResourceId", "string"), ("ResourceProviderValue", "string"), ("Claims", "string"),
    ("Authorization", "string"), ("Level", "string"),
]


def signin_row(record_id="sig-1", *, upn="alice@contoso.com", oid=ALICE_OID, result="0", created=EVENT_TIME, ip="203.0.113.10"):
    values = {
        "TenantId": TENANT, "TimeGenerated": "2026-10-04T07:58:12.000Z", "CreatedDateTime": created, "Id": record_id,
        "OperationName": "Sign-in activity", "Category": "SignInLogs", "UserPrincipalName": upn, "UserId": oid,
        "UserDisplayName": upn.split("@")[0].title(), "AppId": "00000003-0000-0000-c000-000000000000",
        "AppDisplayName": "Azure Portal", "ClientAppUsed": "Browser", "IPAddress": ip, "Location": "IN",
        "LocationDetails": json.dumps({"city": "Pune", "countryOrRegion": "IN"}),
        "DeviceDetail": json.dumps({"operatingSystem": "Windows10", "browser": "Edge 120"}),
        "ResultType": result, "ResultDescription": "Invalid username or password" if result != "0" else "",
        "Status": json.dumps({"errorCode": int(result), "failureReason": "Invalid password" if result != "0" else None}),
        "AuthenticationRequirement": "multiFactorAuthentication",
        "AuthenticationDetails": json.dumps([{"authenticationMethod": "Password", "succeeded": result == "0"}]),
        "ConditionalAccessStatus": "success", "CorrelationId": f"corr-{record_id}", "IsInteractive": True,
    }
    return [values[name] for name, _ in SIGNIN_COLUMNS]


def activity_row(event_id="act-1", *, operation="MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", caller="alice@contoso.com",
                 oid=ALICE_OID, status="Success", resource=None, time="2026-10-04T08:01:00.000Z"):
    resource = resource or f"/subscriptions/{SUB}/resourceGroups/rg-prod/providers/Microsoft.Authorization/roleAssignments/ra-1"
    values = {
        "TenantId": TENANT, "TimeGenerated": time, "OperationNameValue": operation, "OperationName": "Create role assignment",
        "Caller": caller, "CallerIpAddress": "198.51.100.7", "CategoryValue": "Administrative", "ActivityStatusValue": status,
        "ActivitySubstatusValue": "Created", "CorrelationId": f"corr-{event_id}", "EventDataId": event_id, "SubscriptionId": SUB,
        "ResourceGroup": "rg-prod", "_ResourceId": resource, "ResourceProviderValue": operation.split("/")[0],
        "Claims": json.dumps({
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": caller,
            "http://schemas.microsoft.com/identity/claims/objectidentifier": oid,
            "appid": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
        }),
        "Authorization": json.dumps({"action": operation, "scope": resource}), "Level": "Informational",
    }
    return [values[name] for name, _ in ACTIVITY_COLUMNS]


def record(columns, row):
    return {name: value for (name, _), value in zip(columns, row, strict=True)}


def table(columns, rows):
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": n, "type": t} for n, t in columns], "rows": rows}]}


class FakeAzure:
    """Real-shaped Entra token + Log Analytics responses; records every request."""

    def __init__(self, *, signin_rows=None, activity_rows=None, token_response=None, query_status=None, query_error=None):
        self.signin_rows = signin_rows if signin_rows is not None else [signin_row()]
        self.activity_rows = activity_rows if activity_rows is not None else [activity_row()]
        self.token_response = token_response
        self.query_status = query_status or {}
        self.query_error = query_error or {}
        self.requests = []

    def __call__(self, url, body, headers, timeout):
        self.requests.append({"url": url, "body": body, "headers": headers, "timeout": timeout})
        if "oauth2/v2.0/token" in url:
            if self.token_response:
                return self.token_response
            return HttpResponse(200, json.dumps({"token_type": "Bearer", "expires_in": 3599, "access_token": TOKEN}).encode())
        query = json.loads(body)["query"]
        source = "SigninLogs" if query.startswith("SigninLogs") else "AzureActivity"
        if source in self.query_status:
            return HttpResponse(self.query_status[source], json.dumps(self.query_error.get(source, {})).encode())
        if source == "SigninLogs":
            return HttpResponse(200, json.dumps(table(SIGNIN_COLUMNS, self.signin_rows)).encode())
        return HttpResponse(200, json.dumps(table(ACTIVITY_COLUMNS, self.activity_rows)).encode())

    def queries(self):
        return [json.loads(item["body"]) for item in self.requests if "/query" in item["url"]]


def settings(**overrides):
    values = {
        "SECRET_KEY": SecretStr("test-only-jwt-key"),
        "AZURE_TENANT_ID": TENANT,
        "AZURE_CLIENT_ID": CLIENT,
        "AZURE_CLIENT_SECRET": SecretStr(SECRET),
        "AZURE_LOG_ANALYTICS_WORKSPACE_ID": WORKSPACE,
    }
    values.update(overrides)
    return Settings.model_construct(**values)


def session_factory():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


class AzureTestBase(unittest.TestCase):
    def setUp(self):
        LAST_RUN.clear()
        self.session = session_factory()
        self.session.add_all([
            Account(id=ACCOUNT_A, name="Account A"),
            Account(id=ACCOUNT_B, name="Account B"),
            User(id=ADMIN_ID, username="admin", email="admin@example.test", hashed_password="x", role="ADMIN"),
            User(id="analyst-a", username="analyst_a", email="a@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
        ])
        self.session.commit()
        self.analyst = self.session.get(User, "analyst-a")

    def tearDown(self):
        LAST_RUN.clear()
        self.session.close()

    def collect(self, fake=None, *, account_id=ACCOUNT_A, cfg=None, **kwargs):
        fake = fake or FakeAzure()
        kwargs.setdefault("lookback_minutes", 15)
        result = AzureCollector(self.session, settings=cfg or settings(), transport=fake).collect(owner_id=ADMIN_ID, account_id=account_id, **kwargs)
        return result, fake

    def cloud_events(self):
        return list(self.session.scalars(select(Event).where(Event.provider == "AZURE")).all())


class AzureNormalizationTests(AzureTestBase):
    COLLECTED = datetime(2026, 10, 4, 8, 15, tzinfo=timezone.utc)

    def normalize(self, source, columns, row, **kwargs):
        return normalize_record(source, record(columns, row), owner_id=ADMIN_ID, account_id=ACCOUNT_A,
                                collected_at=self.COLLECTED, collection_id="c-1", **kwargs)

    def test_a_entra_login_normalization(self):
        success = self.normalize(ENTRA_SIGNIN, SIGNIN_COLUMNS, signin_row())
        failure = self.normalize(ENTRA_SIGNIN, SIGNIN_COLUMNS, signin_row("sig-2", result="50126"))
        for event in (success, failure):
            self.assertEqual((event["source_type"], event["provider"]), (CLOUD, "AZURE"))
            self.assertEqual(source_family(event["source_type"]), CLOUD)
            self.assertNotEqual(source_family(event["source_type"]), LINUX)
            self.assertIsNone(event["dataset_name"])
            self.assertEqual(event["data_origin"], "AZURE_LOG_ANALYTICS")
        self.assertEqual(success["event_type"], "CLOUD_LOGIN_SUCCESS")
        self.assertEqual(failure["event_type"], "CLOUD_LOGIN_FAILURE")
        self.assertEqual(success["source_ip"], "203.0.113.10")
        meta = json.loads(success["normalized_data"])
        self.assertEqual(meta["original_operation"], "Sign-in activity")
        self.assertEqual(meta["client_app"], "Browser")
        self.assertEqual(meta["device"]["operatingSystem"], "Windows10")
        self.assertEqual(meta["location"]["city"], "Pune")
        self.assertEqual(meta["authentication_methods"], ["Password"])
        self.assertEqual(meta["authentication_result"]["result_type"], "0")
        self.assertEqual(json.loads(failure["normalized_data"])["authentication_result"]["failure_reason"], "Invalid password")

    def test_signin_without_outcome_is_not_forced_into_success_or_failure(self):
        row = record(SIGNIN_COLUMNS, signin_row("sig-3"))
        row["ResultType"], row["Status"] = "", "{}"
        event = normalize_record(ENTRA_SIGNIN, row, owner_id=ADMIN_ID, account_id=ACCOUNT_A, collected_at=self.COLLECTED, collection_id="c")
        self.assertEqual(event["event_type"], "CLOUD_AUTHENTICATION")

    def test_b_activity_log_normalization(self):
        privilege = self.normalize(AZURE_ACTIVITY, ACTIVITY_COLUMNS, activity_row())
        vm = f"/subscriptions/{SUB}/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-01"
        resource = self.normalize(AZURE_ACTIVITY, ACTIVITY_COLUMNS, activity_row("act-2", operation="MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", resource=vm, status="Failed"))
        other = self.normalize(AZURE_ACTIVITY, ACTIVITY_COLUMNS, activity_row("act-3", operation="Microsoft.Resources/checkPolicyCompliance"))
        for event in (privilege, resource, other):
            self.assertEqual((event["source_type"], event["provider"], event["data_scope"]), (CLOUD, "AZURE", DATA_SCOPE_PRIVATE))
        self.assertEqual(privilege["event_type"], "CLOUD_PRIVILEGE_CHANGE")
        self.assertEqual(resource["event_type"], "CLOUD_RESOURCE_OPERATION")
        self.assertEqual(other["event_type"], "CLOUD_ACTIVITY")
        self.assertEqual(privilege["actor_id"], ALICE_OID)
        self.assertEqual(privilege["username"], "alice@contoso.com")
        self.assertEqual(resource["resource_id"], vm)
        self.assertEqual(resource["resource_type"], "Microsoft.Compute/virtualMachines")
        self.assertEqual(resource["operation"], "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE")
        self.assertEqual((resource["severity"], resource["risk_score"]), ("medium", 70))
        meta = json.loads(resource["normalized_data"])
        self.assertEqual(meta["subscription_id"], SUB)
        self.assertEqual(meta["resource_group"], "rg-prod")
        self.assertEqual(meta["status"], "Failed")
        self.assertEqual(meta["correlation_id"], "corr-act-2")
        self.assertEqual(meta["original_operation"], "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE")

    def test_c_timestamp_preservation(self):
        event = self.normalize(ENTRA_SIGNIN, SIGNIN_COLUMNS, signin_row())
        self.assertEqual(event["timestamp"], datetime(2026, 10, 4, 7, 58, 10, 123456, tzinfo=timezone.utc))
        self.assertEqual(event["collection_timestamp"], self.COLLECTED)
        self.assertEqual(event["timestamp_source"], SOURCE_EVENT)
        activity = self.normalize(AZURE_ACTIVITY, ACTIVITY_COLUMNS, activity_row())
        self.assertEqual(activity["timestamp"], datetime(2026, 10, 4, 8, 1, tzinfo=timezone.utc))

    def test_d_fallback_timestamp_preserves_raw_record(self):
        row = record(SIGNIN_COLUMNS, signin_row("sig-bad-time", created="not-a-timestamp"))
        row["TimeGenerated"] = None
        event = normalize_record(ENTRA_SIGNIN, row, owner_id=ADMIN_ID, account_id=ACCOUNT_A, collected_at=self.COLLECTED, collection_id="c")
        self.assertEqual(event["timestamp_source"], SOURCE_FALLBACK)
        self.assertEqual(event["timestamp"], self.COLLECTED)
        raw = json.loads(event["raw_log"])
        self.assertEqual(raw["CreatedDateTime"], "not-a-timestamp")
        self.assertEqual(raw["Id"], "sig-bad-time")
        self.assertEqual(json.loads(event["normalized_data"])["source_timestamp_raw"], "not-a-timestamp")

    def test_f_azure_identity_is_not_defensync_owner_or_account(self):
        result, _ = self.collect()
        self.assertEqual(result["records_inserted"], 2)
        for event in self.cloud_events():
            self.assertEqual(event.owner_id, ADMIN_ID)
            self.assertEqual(event.account_id, ACCOUNT_A)
            self.assertEqual(event.actor_id, ALICE_OID)
            self.assertEqual(event.username, "alice@contoso.com")
            identity = json.loads(event.normalized_data)["cloud_identity"]
            self.assertEqual((identity["tenant_id"], identity["object_id"]), (TENANT, ALICE_OID))
            self.assertEqual(identity["user_principal_name"], "alice@contoso.com")
            self.assertNotIn(event.actor_id, {event.owner_id, event.account_id})


class AzureCollectionTests(AzureTestBase):
    def test_e_every_collected_event_is_private_cloud_azure(self):
        result, _ = self.collect(FakeAzure(signin_rows=[signin_row("s1"), signin_row("s2", result="50126")],
                                           activity_rows=[activity_row("a1"), activity_row("a2")]))
        self.assertEqual(result["status"], STATUS_COLLECTION_OK)
        self.assertEqual(result["records_inserted"], 4)
        events = self.cloud_events()
        self.assertEqual(len(events), 4)
        for event in events:
            self.assertEqual((event.data_scope, event.source_type, event.provider), (DATA_SCOPE_PRIVATE, CLOUD, "AZURE"))
            self.assertEqual(event.data_origin, "AZURE_LOG_ANALYTICS")
            self.assertIsNone(event.dataset_name)
            self.assertIsNone(event.server_id)

    def test_g_repeat_collection_deduplicates(self):
        fake = FakeAzure(signin_rows=[signin_row("s1"), signin_row("s1")], activity_rows=[activity_row("a1")])
        first, _ = self.collect(fake)
        second, _ = self.collect(fake)
        self.assertEqual((first["records_retrieved"], first["records_inserted"], first["records_deduplicated"]), (3, 2, 1))
        self.assertEqual((second["records_inserted"], second["records_deduplicated"]), (0, 3))
        self.assertEqual(len(self.cloud_events()), 2)

    def test_h_cross_account_and_cross_identity_isolation(self):
        same_shape = [signin_row("s-alice", upn="alice@contoso.com", oid=ALICE_OID), signin_row("s-bob", upn="bob@contoso.com", oid=BOB_OID)]
        result, _ = self.collect(FakeAzure(signin_rows=same_shape, activity_rows=[]))
        self.assertEqual(result["records_inserted"], 2)

        no_ids = [record(SIGNIN_COLUMNS, signin_row("x")), record(SIGNIN_COLUMNS, signin_row("x", upn="bob@contoso.com", oid=BOB_OID))]
        for item in no_ids:
            item["Id"] = None
        collected = datetime(2026, 10, 4, 8, 15, tzinfo=timezone.utc)
        hashes = {normalize_record(ENTRA_SIGNIN, item, owner_id=ADMIN_ID, account_id=ACCOUNT_A, collected_at=collected, collection_id="c")["hash"] for item in no_ids}
        self.assertEqual(len(hashes), 2)

        fake = FakeAzure(signin_rows=[signin_row("shared")], activity_rows=[])
        into_a, _ = self.collect(fake, account_id=ACCOUNT_A)
        into_b, _ = self.collect(fake, account_id=ACCOUNT_B)
        self.assertEqual((into_a["records_inserted"], into_b["records_inserted"]), (1, 1))
        shared = [event for event in self.cloud_events() if json.loads(event.raw_log)["Id"] == "shared"]
        self.assertEqual(sorted(event.account_id for event in shared), [ACCOUNT_A, ACCOUNT_B])
        analyst_view = self.session.scalars(select(Event).where(event_visibility_clause(scope="private", user=self.analyst))).all()
        self.assertTrue(all(event.account_id == ACCOUNT_A for event in analyst_view))

    def test_azure_hash_never_touches_global_hash(self):
        result, _ = self.collect()
        for event in self.cloud_events():
            global_hash = crud.calculate_event_hash(event.raw_log, event.timestamp, event_type=event.event_type,
                                                    username=event.username, source_ip=event.source_ip)
            self.assertNotEqual(event.hash, global_hash)
        self.assertEqual(result["dedup_scheme"], "AZURE_ACCOUNT_SCOPED_V1")

    def _seed_linux_and_global(self):
        def add(index, source_type, risk, *, scope=DATA_SCOPE_PRIVATE, origin="LIVE_LINUX", provider=None, account=ACCOUNT_A):
            self.session.add(Event(
                event_id=f"seed-{index}", timestamp=datetime(2026, 10, 4, 7, 0, tzinfo=timezone.utc), hostname="vm-1",
                username="yogesh", event_type="Failed Login", category="auth", severity="info", risk_score=risk,
                message="seed", raw_log=f"seed-{index}", hash=f"seed-hash-{index}", owner_id="analyst-a",
                account_id=account, data_scope=scope, source_type=source_type, provider=provider, data_origin=origin,
            ))
        for index in range(3):
            add(index, "LINUX", 10)
        add(10, "CLOUD", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="OPENSTACK", account=None)
        add(11, "CLOUD", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="HDFS", account=None)
        add(12, "HPC", 99, scope=DATA_SCOPE_GLOBAL, origin="PUBLIC_DATASET", provider="BGL", account=None)
        self.session.commit()

    def test_i_and_j_azure_events_reach_cloud_aggregates_only(self):
        self._seed_linux_and_global()
        self.collect(FakeAzure(signin_rows=[signin_row("s1"), signin_row("s2", result="50126")], activity_rows=[activity_row("a1")]))
        service = AccountService(self.session)
        linux = service.summary(self.analyst, environment=LINUX)
        cloud = service.summary(self.analyst, environment=CLOUD)
        self.assertEqual((linux["events"], linux["max_risk_score"], linux["high_risk_events"]), (3, 10, 0))
        self.assertEqual((cloud["events"], cloud["high_risk_events"], cloud["failed_logins"]), (3, 1, 1))
        private = event_visibility_clause(scope="private", user=self.analyst)
        self.assertEqual(crud.dashboard_summary(self.session, visibility=private, environment=CLOUD)["total_events"], 3)
        self.assertEqual(crud.dashboard_summary(self.session, visibility=private, environment=LINUX)["total_events"], 3)

    def test_k_global_datasets_remain_global(self):
        self._seed_linux_and_global()
        self.collect()
        intel = GlobalIntelligenceService(self.session).summary()
        self.assertEqual((intel["public_openstack_events"], intel["hdfs_events"], intel["bgl_hpc_events"]), (1, 1, 1))
        global_rows = self.session.scalars(select(Event).where(Event.data_scope == DATA_SCOPE_GLOBAL)).all()
        self.assertTrue(all(event.provider != "AZURE" and event.account_id is None for event in global_rows))
        self.assertEqual(AccountService(self.session).summary(self.analyst, environment=CLOUD)["events"], 2)

    def test_l_missing_configuration_is_not_configured(self):
        fake = FakeAzure()
        empty = settings(AZURE_TENANT_ID="", AZURE_CLIENT_ID="", AZURE_CLIENT_SECRET=SecretStr(""), AZURE_LOG_ANALYTICS_WORKSPACE_ID="")
        collector = AzureCollector(self.session, settings=empty, transport=fake)
        status = collector.status()
        self.assertEqual(status["status"], STATUS_NOT_CONFIGURED)
        self.assertEqual(len(status["missing_settings"]), 4)
        result = collector.collect(owner_id=ADMIN_ID, account_id=ACCOUNT_A)
        self.assertEqual((result["status"], result["records_inserted"]), (STATUS_NOT_CONFIGURED, 0))
        self.assertEqual(fake.requests, [])
        bad_format = AzureCollector(self.session, settings=settings(AZURE_LOG_ANALYTICS_WORKSPACE_ID="my-workspace-name"), transport=fake)
        self.assertEqual(bad_format.status()["invalid_settings"], ["AZURE_LOG_ANALYTICS_WORKSPACE_ID"])
        self.assertEqual(bad_format.status()["status"], STATUS_NOT_CONFIGURED)
        self.assertEqual(AzureCollector(self.session, settings=settings(), transport=fake).status()["status"], STATUS_CONFIGURED)

    def test_m_secrets_never_leak(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        root = logging.getLogger()
        previous = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            ok, fake = self.collect()
            leaky_error = HttpResponse(401, json.dumps({
                "error": "invalid_client", "error_codes": [7000215],
                "error_description": f"AADSTS7000215: Invalid client secret provided: {SECRET}",
            }).encode())
            failed, _ = self.collect(FakeAzure(token_response=leaky_error))
            status = AzureCollector(self.session, settings=settings()).status()
        finally:
            root.removeHandler(handler)
            root.setLevel(previous)
        self.assertEqual(failed["status"], STATUS_COLLECTION_FAILED)
        self.assertEqual(failed["error"]["code"], "INVALID_CREDENTIALS")
        token_request = next(item for item in fake.requests if "oauth2" in item["url"])
        self.assertIn(SECRET.encode(), token_request["body"])
        query_request = next(item for item in fake.requests if "/query" in item["url"])
        self.assertEqual(query_request["headers"]["Authorization"], f"Bearer {TOKEN}")
        surfaces = [json.dumps(ok, default=str), json.dumps(failed, default=str), json.dumps(status, default=str), stream.getvalue()]
        surfaces += [event.raw_log + (event.normalized_data or "") for event in self.cloud_events()]
        surfaces += [repr(LogAnalyticsClient(tenant_id=TENANT, client_id=CLIENT, client_secret=SECRET, workspace_id=WORKSPACE))]
        for text in surfaces:
            self.assertNotIn(SECRET, text)
            self.assertNotIn(TOKEN, text)

    def test_n_collection_is_bounded(self):
        _, fake = self.collect()
        for body in fake.queries():
            self.assertIn("| where TimeGenerated between (datetime(", body["query"])
            self.assertIn("| take 500", body["query"])
            start, end = (datetime.fromisoformat(part.replace("Z", "+00:00")) for part in body["timespan"].split("/"))
            self.assertEqual(end - start, timedelta(minutes=15))
        collector = AzureCollector(self.session, settings=settings(), transport=FakeAzure())
        now = datetime.now(timezone.utc)
        for kwargs in (
            {"lookback_minutes": MAX_WINDOW_MINUTES + 1},
            {"lookback_minutes": 0},
            {"start": now - timedelta(hours=1)},
            {"start": now - timedelta(days=30), "end": now},
            {"start": now, "end": now - timedelta(hours=1)},
            {"max_records": 100000},
        ):
            with self.assertRaises(ValueError, msg=kwargs):
                collector.collect(owner_id=ADMIN_ID, account_id=ACCOUNT_A, **kwargs)
        explicit, fake = self.collect(lookback_minutes=None, start=now - timedelta(hours=2), end=now - timedelta(hours=1))
        self.assertEqual(explicit["status"], STATUS_COLLECTION_OK)
        start, end = (datetime.fromisoformat(part.replace("Z", "+00:00")) for part in fake.queries()[0]["timespan"].split("/"))
        self.assertEqual(end - start, timedelta(hours=1))

    def test_o_malformed_record_does_not_abort_batch(self):
        empty_identity = [None] * len(SIGNIN_COLUMNS)
        short_row = ["only", "two"]
        result, _ = self.collect(FakeAzure(signin_rows=[signin_row("s1"), short_row, empty_identity, signin_row("s2")], activity_rows=[activity_row("a1")]))
        self.assertEqual(result["status"], STATUS_COLLECTION_OK)
        self.assertEqual((result["records_retrieved"], result["records_normalized"], result["records_failed"], result["records_inserted"]), (5, 3, 2, 3))
        self.assertEqual({item["index"] for item in result["errors"]}, {1, 2})
        self.assertNotIn("only", json.dumps(result["errors"]))


class AzureErrorHandlingTests(AzureTestBase):
    def assert_failure(self, fake, code, **kwargs):
        result, _ = self.collect(fake, **kwargs)
        self.assertEqual(result["status"], STATUS_COLLECTION_FAILED, result)
        self.assertEqual(result["error"]["code"], code)
        self.assertEqual(result["records_inserted"], 0)
        self.assertEqual(AzureCollector(self.session, settings=settings()).status()["status"], STATUS_COLLECTION_FAILED)
        return result

    def token_error(self, status, code):
        return HttpResponse(status, json.dumps({"error": "x", "error_codes": [code], "error_description": f"AADSTS{code}: detail"}).encode())

    def test_token_errors(self):
        self.assert_failure(FakeAzure(token_response=self.token_error(401, 7000215)), "INVALID_CREDENTIALS")
        self.assert_failure(FakeAzure(token_response=self.token_error(401, 7000222)), "EXPIRED_CREDENTIALS")
        self.assert_failure(FakeAzure(token_response=self.token_error(400, 90002)), "INVALID_TENANT")
        self.assert_failure(FakeAzure(token_response=self.token_error(400, 700016)), "INVALID_CREDENTIALS")
        self.assert_failure(FakeAzure(token_response=HttpResponse(503, b"")), "AZURE_UNAVAILABLE")

    def test_query_errors(self):
        both = lambda code: {"SigninLogs": code, "AzureActivity": code}
        self.assert_failure(FakeAzure(query_status=both(403)), "PERMISSION_DENIED")
        self.assert_failure(FakeAzure(query_status=both(404)), "INVALID_WORKSPACE")
        limited = self.assert_failure(FakeAzure(query_status=both(429)), "RATE_LIMITED")
        self.assertIn("retry later", limited["error"]["message"])
        self.assert_failure(FakeAzure(query_status=both(503)), "AZURE_UNAVAILABLE")
        self.assert_failure(FakeAzure(query_status=both(504)), "TIMEOUT")

    def test_missing_table_only_skips_that_source(self):
        missing = {"error": {"code": "BadArgumentError", "message": "The request had some invalid properties",
                             "innererror": {"code": "SemanticError", "message": "'where' operator: Failed to resolve table or column expression named 'SigninLogs'"}}}
        result, _ = self.collect(FakeAzure(query_status={"SigninLogs": 400}, query_error={"SigninLogs": missing}))
        self.assertEqual(result["status"], STATUS_COLLECTION_OK)
        self.assertEqual([item["status"] for item in result["sources"]], ["SOURCE_NOT_AVAILABLE", "OK"])
        self.assertEqual(result["records_inserted"], 1)

    def test_network_timeout(self):
        def timeout_transport(url, body, headers, timeout):
            raise TimeoutError("timed out")
        self.assert_failure(timeout_transport, "TIMEOUT")

    def test_malformed_response(self):
        def broken(url, body, headers, timeout):
            if "oauth2" in url:
                return HttpResponse(200, json.dumps({"access_token": TOKEN}).encode())
            return HttpResponse(200, b"<html>not json</html>")
        self.assert_failure(broken, "MALFORMED_RESPONSE")


class AzureApiTests(AzureTestBase):
    def client(self, user, cfg=None, fake=None):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(cloud_api.router, prefix="/api/v1/cloud")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[get_current_admin] = lambda: user
        app.dependency_overrides[cloud_api.get_azure_settings] = lambda: cfg or settings()
        app.dependency_overrides[cloud_api.get_azure_transport] = lambda: fake or FakeAzure()
        return TestClient(app)

    def test_status_and_collect_routes(self):
        admin = self.session.get(User, ADMIN_ID)
        not_configured = self.client(admin, cfg=settings(AZURE_CLIENT_SECRET=SecretStr("")))
        self.assertEqual(not_configured.get("/api/v1/cloud/azure/status").json()["status"], STATUS_NOT_CONFIGURED)
        api = self.client(admin)
        response = api.post("/api/v1/cloud/azure/collect", json={"account_id": ACCOUNT_A, "lookback_minutes": 15})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual((body["status"], body["records_inserted"]), (STATUS_COLLECTION_OK, 2))
        self.assertEqual(api.get("/api/v1/cloud/azure/status").json()["status"], STATUS_COLLECTION_OK)
        for text in (response.text, api.get("/api/v1/cloud/azure/status").text):
            self.assertNotIn(SECRET, text)
            self.assertNotIn(TOKEN, text)
        self.assertEqual(api.post("/api/v1/cloud/azure/collect", json={"account_id": "missing"}).status_code, 404)
        self.assertEqual(api.post("/api/v1/cloud/azure/collect", json={"account_id": ACCOUNT_A, "lookback_minutes": 100000}).status_code, 422)
        self.assertEqual(api.post("/api/v1/cloud/azure/collect", json={"lookback_minutes": 15}).status_code, 422)

    def test_analyst_cannot_trigger_collection(self):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(cloud_api.router, prefix="/api/v1/cloud")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.analyst
        response = TestClient(app).post("/api/v1/cloud/azure/collect", json={"account_id": ACCOUNT_A}, headers={"Authorization": "Bearer x"})
        self.assertIn(response.status_code, {401, 403})
        self.assertEqual(self.session.scalar(select(func.count(Event.id))), 0)


if __name__ == "__main__":
    unittest.main()
