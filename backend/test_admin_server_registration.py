"""ADMIN (no application account) registering and managing a Linux server through the real servers router.

SQLite in-memory only; the background health check is patched so no SSH connection is attempted.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.api import servers as servers_api
from backend.api.dependencies import get_current_user, get_db
from backend.core.exceptions import register_exception_handlers
from backend.database.models import Account, Base, Server, User

SSH_PASSWORD = "ssh-test-password"


def server_body(name="admin-linux-01", host="192.0.2.10"):
    return {
        "server_name": name,
        "host": host,
        "port": 22,
        "username": "ubuntu",
        "authentication_type": "password",
        "password": SSH_PASSWORD,
        "operating_system": "linux",
    }


class AdminLinuxServerRegistrationTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine, expire_on_commit=False)()
        self.admin = User(id="admin-1", username="admin", email="owner@example.test", hashed_password="x", role="ADMIN")
        self.member = User(id="analyst-1", username="tejas", email="tejas@example.test", hashed_password="x", role="ANALYST", account_id="acct-1")
        self.solo = User(id="analyst-2", username="solo", email="solo@example.test", hashed_password="x", role="ANALYST")
        self.session.add_all([Account(id="acct-1", name="Tejas"), self.admin, self.member, self.solo])
        self.session.commit()

        self.health = patch("backend.services.server_service.get_health_engine", return_value=MagicMock())
        self.health.start()
        self.current = self.admin
        app = FastAPI()
        register_exception_handlers(app)
        app.include_router(servers_api.router, prefix="/api/v1/servers")
        app.dependency_overrides[get_db] = lambda: self.session
        app.dependency_overrides[get_current_user] = lambda: self.current
        self.client = TestClient(app)

    def tearDown(self):
        self.health.stop()
        self.session.close()

    def as_user(self, user):
        self.current = user
        return self.client

    def register_as_admin(self):
        response = self.as_user(self.admin).post("/api/v1/servers", json=server_body())
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_admin_without_account_registers_a_linux_server(self):
        self.assertIsNone(self.admin.account_id)
        created = self.register_as_admin()
        self.assertEqual((created["owner_id"], created["created_by"], created["account_id"]), ("admin-1", "admin-1", None))
        self.assertNotIn(SSH_PASSWORD, str(created))
        row = self.session.get(Server, created["id"])
        self.assertEqual((row.owner_id, row.account_id), ("admin-1", None))
        self.assertTrue(row.encrypted_password and row.encrypted_password != SSH_PASSWORD)
        self.assertEqual(self.session.scalar(select(func.count(Account.id))), 1)
        self.assertIsNone(self.session.get(User, "admin-1").account_id)

    def test_admin_sees_and_manages_the_server(self):
        created = self.register_as_admin()
        listed = self.as_user(self.admin).get("/api/v1/servers")
        self.assertEqual([row["id"] for row in listed.json()], [created["id"]])
        self.assertEqual(self.client.get(f"/api/v1/servers/{created['id']}").status_code, 200)
        renamed = self.client.put(f"/api/v1/servers/{created['id']}", json={"server_name": "admin-linux-renamed"})
        self.assertEqual((renamed.status_code, renamed.json()["server_name"]), (200, "admin-linux-renamed"))

    def test_analysts_cannot_see_or_touch_the_admin_server(self):
        created = self.register_as_admin()
        for analyst in (self.member, self.solo):
            client = self.as_user(analyst)
            self.assertEqual(client.get("/api/v1/servers").json(), [], analyst.username)
            self.assertEqual(client.get(f"/api/v1/servers/{created['id']}").status_code, 403, analyst.username)
            self.assertEqual(client.put(f"/api/v1/servers/{created['id']}", json={"server_name": "x"}).status_code, 403)
            self.assertEqual(client.delete(f"/api/v1/servers/{created['id']}").status_code, 403)
        self.assertEqual(self.session.get(Server, created["id"]).server_name, "admin-linux-01")

    def test_admin_list_is_platform_wide_and_analyst_scope_is_unchanged(self):
        admin_server = self.register_as_admin()
        member_server = self.as_user(self.member).post("/api/v1/servers", json=server_body("tejas-vm", "192.0.2.20")).json()
        self.assertEqual(member_server["account_id"], "acct-1")
        self.assertEqual({row["id"] for row in self.as_user(self.admin).get("/api/v1/servers").json()}, {admin_server["id"], member_server["id"]})
        self.assertEqual([row["id"] for row in self.as_user(self.member).get("/api/v1/servers").json()], [member_server["id"]])
        self.assertEqual(self.as_user(self.solo).get("/api/v1/servers").json(), [])

    def test_admin_deletes_the_test_server(self):
        created = self.register_as_admin()
        deleted = self.as_user(self.admin).delete(f"/api/v1/servers/{created['id']}")
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertIsNone(self.session.get(Server, created["id"]))
        self.assertEqual(self.client.get("/api/v1/servers").json(), [])


if __name__ == "__main__":
    unittest.main()
