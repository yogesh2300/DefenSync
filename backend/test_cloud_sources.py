"""Phase 1: environment onboarding — account-owned Azure cloud sources.

Fake HTTPS transport (real-shaped Entra token + Log Analytics responses) and
SQLite in-memory only: no live Azure, no PostgreSQL rows, no real credentials.
"""

from __future__ import annotations

import io
import json
import logging
import unittest
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.api import cloud as cloud_api
from backend.api import servers as servers_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.encryption import decrypt_secret
from backend.core.environments import CLOUD
from backend.core.exceptions import register_exception_handlers
from backend.database.models import Account, CloudSource, Event, Server, User
from backend.services.cloud.azure_client import HttpResponse
from backend.services.cloud.azure_collector import LAST_RUN
from backend.services.cloud.cloud_source_service import CONNECTION_TEST_QUERY
from backend.test_azure_collector import (
    CLIENT,
    SECRET,
    TENANT,
    TOKEN,
    WORKSPACE,
    FakeAzure,
    activity_row,
    session_factory,
    signin_row,
)

ACCOUNT_A, ACCOUNT_B = "acct-a", "acct-b"
OTHER_WORKSPACE = "12121212-3434-5656-7878-909090909090"
SOURCE_URL = "/api/v1/cloud/sources"


def credentials(**overrides):
    body = {
        "provider": "AZURE",
        "source_type": "AZURE_LOG_ANALYTICS",
        "tenant_id": TENANT,
        "client_id": CLIENT,
        "client_secret": SECRET,
        "workspace_id": WORKSPACE,
    }
    body.update(overrides)
    return body


def token_failure(code: int) -> HttpResponse:
    """Entra error whose description echoes the secret, to prove it is never relayed."""
    return HttpResponse(401, json.dumps({
        "error": "invalid_client", "error_codes": [code],
        "error_description": f"AADSTS{code}: Invalid client secret provided: {SECRET}",
    }).encode())


class CloudSourceTestBase(unittest.TestCase):
    def setUp(self):
        LAST_RUN.clear()
        self.session = session_factory()
        self.session.add_all([
            Account(id=ACCOUNT_A, name="Account A"),
            Account(id=ACCOUNT_B, name="Account B"),
            User(id="admin-1", username="admin", email="admin@example.test", hashed_password="x", role="ADMIN"),
            User(id="analyst-a", username="analyst_a", email="a@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
            User(id="analyst-a2", username="analyst_a2", email="a2@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_A),
            User(id="analyst-b", username="analyst_b", email="b@example.test", hashed_password="x", role="ANALYST", account_id=ACCOUNT_B),
            User(id="solo", username="solo", email="solo@example.test", hashed_password="x", role="ANALYST", account_id=None),
        ])
        self.session.commit()
        self.fake = FakeAzure()
        self.log = io.StringIO()
        self._handler = logging.StreamHandler(self.log)
        root = logging.getLogger()
        self._previous_level = root.level
        root.addHandler(self._handler)
        root.setLevel(logging.DEBUG)

    def tearDown(self):
        root = logging.getLogger()
        root.removeHandler(self._handler)
        root.setLevel(self._previous_level)
        LAST_RUN.clear()
        self.session.close()

    def user(self, user_id):
        return self.session.get(User, user_id)

    def api(self, user_id, fake=None):
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(cloud_api.router, prefix="/api/v1/cloud")
        app.include_router(servers_api.router, prefix="/api/v1/servers")
        user = self.user(user_id)
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: user
        app.dependency_overrides[cloud_api.get_azure_transport] = lambda: fake or self.fake
        return TestClient(app)

    def add_server(self, *, account_id=ACCOUNT_A, owner_id="analyst-a", name="ubuntu-web"):
        server = Server(server_name=name, host="192.0.2.10", username="defensync", owner_id=owner_id,
                        created_by=owner_id, account_id=account_id, environment="production")
        self.session.add(server)
        self.session.commit()
        return server

    def create_source(self, user_id="analyst-a", **overrides):
        response = self.api(user_id).post(SOURCE_URL, json=credentials(**overrides))
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def event_count(self):
        return self.session.scalar(select(func.count(Event.id)))


class OnboardingRoutingTests(CloudSourceTestBase):
    def test_1_zero_linux_servers_means_add_server(self):
        self.assertEqual(self.api("analyst-a").get("/api/v1/servers").json(), [])

    def test_2_registered_linux_server_means_linux_dashboard(self):
        self.add_server()
        rows = self.api("analyst-a").get("/api/v1/servers").json()
        self.assertEqual([row["server_name"] for row in rows], ["ubuntu-web"])

    def test_3_zero_cloud_sources_means_add_cloud_source(self):
        self.add_server()
        body = self.api("analyst-a").get(SOURCE_URL).json()
        self.assertEqual((body["count"], body["sources"]), (0, []))

    def test_4_cloud_source_means_cloud_dashboard(self):
        created = self.create_source()
        body = self.api("analyst-a").get(SOURCE_URL).json()
        self.assertEqual(body["count"], 1)
        source = body["sources"][0]
        self.assertEqual(source["id"], created["id"])
        self.assertEqual((source["environment"], source["provider"], source["source_type"]), (CLOUD, "AZURE", "AZURE_LOG_ANALYTICS"))
        self.assertEqual((source["provider_label"], source["source_type_label"]), ("Microsoft Azure", "Azure Log Analytics"))
        self.assertEqual(source["connection_status"], "CONNECTED")
        self.assertIsNone(source["last_successful_collection"])
        self.assertEqual(source["account_id"], ACCOUNT_A)


class EnvironmentIsolationTests(CloudSourceTestBase):
    def test_5_linux_server_never_appears_in_cloud_sources(self):
        server = self.add_server()
        sources = self.api("analyst-a").get(SOURCE_URL).json()["sources"]
        self.assertEqual(sources, [])
        self.create_source()
        sources = self.api("analyst-a").get(SOURCE_URL).json()["sources"]
        self.assertNotIn(server.id, [item["id"] for item in sources])
        self.assertTrue(all("server_name" not in item and "host" not in item for item in sources))

    def test_6_cloud_source_never_appears_in_linux_servers(self):
        self.add_server()
        created = self.create_source()
        for user_id in ("analyst-a", "admin-1"):
            rows = self.api(user_id).get("/api/v1/servers").json()
            self.assertEqual([row["server_name"] for row in rows], ["ubuntu-web"], user_id)
            self.assertNotIn(created["id"], [row["id"] for row in rows])
        self.assertEqual(self.session.scalar(select(func.count(Server.id))), 1)

    def test_7_user_cannot_access_another_accounts_cloud_source(self):
        created = self.create_source()
        source_id = created["id"]
        outsider = self.api("analyst-b")
        self.assertEqual(outsider.get(SOURCE_URL).json()["count"], 0)
        self.assertEqual(outsider.get(f"{SOURCE_URL}/{source_id}").status_code, 404)
        self.assertEqual(outsider.post(f"{SOURCE_URL}/{source_id}/test-connection").status_code, 404)
        self.assertEqual(outsider.post(f"{SOURCE_URL}/{source_id}/collect", json={}).status_code, 404)
        self.assertEqual(outsider.delete(f"{SOURCE_URL}/{source_id}").status_code, 403)
        self.assertEqual(self.api("solo").get(f"{SOURCE_URL}/{source_id}").status_code, 404)
        self.assertEqual(self.api("analyst-a2").get(f"{SOURCE_URL}/{source_id}").status_code, 200)
        self.assertEqual(self.event_count(), 0)

    def test_account_less_user_sees_only_their_own_source(self):
        own = self.create_source("solo", workspace_id=OTHER_WORKSPACE)
        self.create_source("analyst-a")
        listed = self.api("solo").get(SOURCE_URL).json()["sources"]
        self.assertEqual([item["id"] for item in listed], [own["id"]])
        self.assertIsNone(listed[0]["account_id"])

    def test_duplicate_workspace_in_same_account_is_rejected(self):
        self.create_source("analyst-a")
        duplicate = self.api("analyst-a2").post(SOURCE_URL, json=credentials())
        self.assertEqual(duplicate.status_code, 409)
        self.create_source("analyst-b")
        self.assertEqual(self.session.scalar(select(func.count(CloudSource.id))), 2)


class ConnectionTestTests(CloudSourceTestBase):
    def test_8_test_connection_does_not_collect_events(self):
        api = self.api("analyst-a")
        unsaved = api.post(f"{SOURCE_URL}/test-connection", json=credentials())
        self.assertEqual(unsaved.status_code, 200)
        self.assertEqual(self.session.scalar(select(func.count(CloudSource.id))), 0)
        created = self.create_source()
        self.fake.requests.clear()
        saved = api.post(f"{SOURCE_URL}/{created['id']}/test-connection")
        self.assertEqual(saved.status_code, 200)
        self.assertEqual([body["query"] for body in self.fake.queries()], [CONNECTION_TEST_QUERY])
        self.assertEqual(self.event_count(), 0)
        self.assertIsNone(self.session.get(CloudSource, created["id"]).last_collection_at)
        self.assertIsNone(LAST_RUN.get())

    def test_9_invalid_azure_credentials_fail_safely(self):
        api = self.api("analyst-a", FakeAzure(token_response=token_failure(7000215)))
        result = api.post(f"{SOURCE_URL}/test-connection", json=credentials()).json()
        self.assertEqual((result["success"], result["status"]), (False, "FAILED"))
        self.assertEqual(result["error"]["code"], "INVALID_CREDENTIALS")
        self.assertIn("Client Secret", result["error"]["message"])

        rejected = api.post(SOURCE_URL, json=credentials())
        self.assertEqual(rejected.status_code, 422)
        self.assertEqual(rejected.json()["code"], "CLOUD_CONNECTION_FAILED")
        self.assertEqual(rejected.json()["azure_error"]["code"], "INVALID_CREDENTIALS")
        self.assertEqual(self.session.scalar(select(func.count(CloudSource.id))), 0)

        for fake, code in (
            (FakeAzure(token_response=token_failure(90002)), "INVALID_TENANT"),
            (FakeAzure(query_status={"AzureActivity": 404}), "INVALID_WORKSPACE"),
            (FakeAzure(query_status={"AzureActivity": 403}), "PERMISSION_DENIED"),
        ):
            body = self.api("analyst-a", fake).post(f"{SOURCE_URL}/test-connection", json=credentials()).json()
            self.assertEqual((body["success"], body["error"]["code"]), (False, code))

        def offline(url, body, headers, timeout):
            raise TimeoutError("timed out")
        self.assertEqual(self.api("analyst-a", offline).post(f"{SOURCE_URL}/test-connection", json=credentials()).json()["error"]["code"], "TIMEOUT")

    def test_invalid_input_is_rejected_before_contacting_azure(self):
        api = self.api("analyst-a")
        for body, fragment in (
            (credentials(client_secret=""), "Client Secret"),
            ({"tenant_id": TENANT, "client_secret": SECRET}, "Client ID"),
            (credentials(workspace_id="my-workspace-name"), "Workspace ID"),
            (credentials(client_id="not-a-guid"), "Client ID"),
            (credentials(client_secret="x" * 2000), "too long"),
        ):
            for url in (f"{SOURCE_URL}/test-connection", SOURCE_URL):
                response = api.post(url, json=body)
                self.assertEqual(response.status_code, 422, (url, body.get("workspace_id")))
                self.assertIn(fragment, response.json()["error"])
        for body in (credentials(provider="AWS"), credentials(source_type="CLOUDTRAIL")):
            self.assertEqual(api.post(SOURCE_URL, json=body).status_code, 422)
        self.assertEqual(self.fake.requests, [])
        self.assertEqual(self.session.scalar(select(func.count(CloudSource.id))), 0)

    def test_10_valid_connection_returns_safe_success_status(self):
        result = self.api("analyst-a").post(f"{SOURCE_URL}/test-connection", json=credentials()).json()
        self.assertEqual(set(result), {"success", "status", "error", "tested_at"})
        self.assertEqual((result["success"], result["status"], result["error"]), (True, "CONNECTED", None))
        token_request, query_request = self.fake.requests
        self.assertIn("oauth2/v2.0/token", token_request["url"])
        self.assertIn(f"/workspaces/{WORKSPACE}/query", query_request["url"])

    def test_saved_source_retest_tracks_status(self):
        created = self.create_source()
        failed = self.api("analyst-a", FakeAzure(token_response=token_failure(7000222))).post(f"{SOURCE_URL}/{created['id']}/test-connection").json()
        self.assertEqual((failed["success"], failed["source"]["connection_status"]), (False, "FAILED"))
        self.assertEqual(failed["source"]["connection_error"]["code"], "EXPIRED_CREDENTIALS")
        transient = self.api("analyst-a", FakeAzure(token_response=HttpResponse(503, b""))).post(f"{SOURCE_URL}/{created['id']}/test-connection").json()
        self.assertEqual((transient["error"]["code"], transient["source"]["connection_status"]), ("AZURE_UNAVAILABLE", "FAILED"))
        healed = self.api("analyst-a").post(f"{SOURCE_URL}/{created['id']}/test-connection").json()
        self.assertEqual((healed["success"], healed["source"]["connection_status"], healed["source"]["connection_error"]), (True, "CONNECTED", None))


class CollectAndAdminTests(CloudSourceTestBase):
    def test_collect_now_reuses_collector_into_source_account(self):
        server = self.add_server()
        created = self.create_source()
        self.assertIsNone(created["last_collection_at"])
        fake = FakeAzure(signin_rows=[signin_row("s1"), signin_row("s2", result="50126")], activity_rows=[activity_row("a1")])
        result = self.api("analyst-a", fake).post(f"{SOURCE_URL}/{created['id']}/collect", json={"lookback_minutes": 15})
        self.assertEqual(result.status_code, 200, result.text)
        body = result.json()
        self.assertEqual((body["status"], body["records_inserted"], body["cloud_source_id"]), ("COLLECTION_OK", 3, created["id"]))
        self.assertEqual(body["source"]["last_collection_status"], "COLLECTION_OK")
        self.assertIsNotNone(body["source"]["last_successful_collection"])
        events = self.session.scalars(select(Event)).all()
        self.assertEqual(len(events), 3)
        for event in events:
            self.assertEqual((event.source_type, event.provider, event.account_id, event.server_id), (CLOUD, "AZURE", ACCOUNT_A, None))
        self.assertEqual([row["id"] for row in self.api("analyst-a").get("/api/v1/servers").json()], [server.id])
        self.assertEqual(self.api("analyst-a").post(f"{SOURCE_URL}/{created['id']}/collect", json={"lookback_minutes": 100000}).status_code, 422)

    def test_failed_collection_is_recorded_on_the_source(self):
        created = self.create_source()
        body = self.api("analyst-a", FakeAzure(token_response=token_failure(7000215))).post(f"{SOURCE_URL}/{created['id']}/collect", json={}).json()
        self.assertEqual(body["status"], "COLLECTION_FAILED")
        source = body["source"]
        self.assertEqual((source["last_collection_status"], source["connection_status"]), ("COLLECTION_FAILED", "FAILED"))
        self.assertIsNone(source["last_successful_collection"])
        self.assertEqual(self.event_count(), 0)

    def test_14_admin_is_platform_level(self):
        mine = self.create_source("analyst-a")
        theirs = self.create_source("analyst-b")
        admin = self.api("admin-1")
        self.assertEqual({item["id"] for item in admin.get(SOURCE_URL).json()["sources"]}, {mine["id"], theirs["id"]})
        self.assertEqual(admin.get(f"{SOURCE_URL}/{theirs['id']}").status_code, 200)
        assigned = admin.post(SOURCE_URL, json={**credentials(workspace_id=OTHER_WORKSPACE), "account_id": ACCOUNT_B})
        self.assertEqual((assigned.status_code, assigned.json()["account_id"]), (201, ACCOUNT_B))
        self.assertEqual(admin.post(SOURCE_URL, json={**credentials(), "account_id": "missing"}).status_code, 404)
        self.assertEqual(self.api("analyst-b").get(SOURCE_URL).json()["count"], 2)
        ignored = self.api("analyst-a").post(SOURCE_URL, json={**credentials(workspace_id=OTHER_WORKSPACE), "account_id": ACCOUNT_B})
        self.assertEqual(ignored.json()["account_id"], ACCOUNT_A)
        self.assertEqual(self.api("analyst-a").delete(f"{SOURCE_URL}/{mine['id']}").status_code, 403)
        self.assertEqual(admin.delete(f"{SOURCE_URL}/{mine['id']}").status_code, 200)
        self.assertIsNone(self.session.get(CloudSource, mine["id"]))


class SecretHandlingTests(CloudSourceTestBase):
    def test_11_client_secret_is_never_returned(self):
        api = self.api("analyst-a")
        responses = [api.post(f"{SOURCE_URL}/test-connection", json=credentials())]
        created = api.post(SOURCE_URL, json=credentials())
        responses.append(created)
        source_id = created.json()["id"]
        responses += [
            api.get(SOURCE_URL),
            api.get(f"{SOURCE_URL}/{source_id}"),
            api.post(f"{SOURCE_URL}/{source_id}/test-connection"),
            api.post(f"{SOURCE_URL}/{source_id}/collect", json={}),
            api.post(SOURCE_URL, json=credentials()),
            api.post(SOURCE_URL, json={"client_secret": SECRET}),
            api.post(SOURCE_URL, json=credentials(provider="AWS")),
            api.post(SOURCE_URL, json=credentials(workspace_id="bad")),
            self.api("analyst-a", FakeAzure(token_response=token_failure(7000215))).post(SOURCE_URL, json=credentials(workspace_id=OTHER_WORKSPACE)),
        ]
        for response in responses:
            self.assertNotIn(SECRET, response.text, response.request.url)
            self.assertNotIn(TOKEN, response.text, response.request.url)
        self.assertTrue(created.json()["client_secret_configured"])
        self.assertNotIn("client_secret", created.json())
        self.assertNotIn("encrypted_client_secret", created.json())
        stored = self.session.get(CloudSource, source_id)
        self.assertNotEqual(stored.encrypted_client_secret, SECRET)
        self.assertNotIn(SECRET, stored.encrypted_client_secret)
        self.assertEqual(decrypt_secret(stored.encrypted_client_secret), SECRET)

    def test_12_client_secret_is_never_logged(self):
        api = self.api("analyst-a")
        api.post(f"{SOURCE_URL}/test-connection", json=credentials())
        source_id = api.post(SOURCE_URL, json=credentials()).json()["id"]
        api.post(f"{SOURCE_URL}/{source_id}/test-connection")
        api.post(f"{SOURCE_URL}/{source_id}/collect", json={})
        failing = self.api("analyst-a", FakeAzure(token_response=token_failure(7000215)))
        failing.post(f"{SOURCE_URL}/test-connection", json=credentials())
        failing.post(SOURCE_URL, json=credentials(workspace_id=OTHER_WORKSPACE))
        failing.post(f"{SOURCE_URL}/{source_id}/test-connection")
        failing.post(f"{SOURCE_URL}/{source_id}/collect", json={})
        api.post(SOURCE_URL, json={"client_secret": SECRET})
        api.post(SOURCE_URL, json=credentials(provider="AWS"))
        api.post(SOURCE_URL, json=credentials(workspace_id="bad"))
        logged = self.log.getvalue()
        self.assertIn("Cloud source", logged)
        self.assertNotIn(SECRET, logged)
        self.assertNotIn(TOKEN, logged)

    def test_secret_is_not_part_of_any_url(self):
        api = self.api("analyst-a")
        created = api.post(SOURCE_URL, json=credentials())
        for item in self.fake.requests:
            self.assertNotIn(SECRET, item["url"])
        self.assertNotIn(SECRET, str(created.request.url))


if __name__ == "__main__":
    unittest.main()
