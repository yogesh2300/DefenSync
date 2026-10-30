#!/usr/bin/env python3
"""
DefenSync Integration Test Suite.

By default this suite starts an ephemeral API process whose SMTP settings point at
a local QA mailbox (see backend/testing/otp_mailbox.py). No pre-running backend is
required. Set DEFENSYNC_SUITE_EXTERNAL=1 and API_URL to exercise an already-running
server instead (that server must deliver OTP email to the suite's QA mailbox).
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import time
import unittest
import urllib.parse
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.testing.otp_mailbox import QALoginError, OTPMailbox, login_with_otp, register_with_otp

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_API_URL = os.getenv("API_URL", "http://127.0.0.1:8000")
EXTERNAL_SUITE = os.getenv("DEFENSYNC_SUITE_EXTERNAL", "").strip().lower() in {"1", "true", "yes"}
HEALTH_TIMEOUT_SECONDS = 60


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class DefenSyncTestClient:
    """A lightweight, zero-dependency HTTP client to interact with the FastAPI server."""

    def __init__(self, base_url: str = DEFAULT_API_URL):
        self.base_url = base_url.rstrip("/")
        self.token = None

    def set_token(self, token: str):
        """Set the JWT Bearer token for authenticated requests."""
        self.token = token

    def clear_token(self):
        """Clear the current authenticated token."""
        self.token = None

    def _request(self, method: str, path: str, data: dict = None, params: dict = None, *, form: bool = False) -> tuple[int, dict]:
        """Send an HTTP request and return (status_code, response_json)."""
        url = f"{self.base_url}{path}"
        if params:
            query_string = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            if query_string:
                url = f"{url}?{query_string}"

        req_data = None
        headers = {}

        if data is not None:
            if form:
                req_data = "&".join(f"{k}={v}" for k, v in data.items()).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                req_data = json.dumps(data).encode("utf-8")
                headers["Content-Type"] = "application/json"

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = Request(url, data=req_data, headers=headers, method=method)

        try:
            with urlopen(req, timeout=30) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")
                return status_code, json.loads(response_body) if response_body else {}
        except HTTPError as e:
            status_code = e.getcode()
            try:
                response_body = e.read().decode("utf-8")
                return status_code, json.loads(response_body) if response_body else {}
            except Exception:
                return status_code, {"detail": str(e)}
        except (URLError, OSError, TimeoutError) as e:
            raise ConnectionError(
                f"Connection to API server at {self.base_url} failed: {e}. "
                "The suite starts its own API unless DEFENSYNC_SUITE_EXTERNAL=1."
            ) from e


class TestDefenSyncBackend(unittest.TestCase):
    """Test suite executing standard and behavioral endpoints on DefenSync."""

    _server: subprocess.Popen | None = None
    analyst_token: str | None = None
    account_ready: bool = False
    events_seeded: bool = False

    @classmethod
    def setUpClass(cls):
        cls.mailbox = OTPMailbox(port=0).start()
        suffix = random.randint(1000, 9999)
        cls.analyst_username = f"analyst_{suffix}"
        cls.analyst_password = "SecurePassword123!"
        cls.analyst_email = f"{cls.analyst_username}@DefenSync.local"
        cls.analyst_token = None
        cls.account_ready = False
        cls.events_seeded = False
        cls._server = None

        if EXTERNAL_SUITE:
            cls.client = DefenSyncTestClient(DEFAULT_API_URL)
            cls._wait_for_health(cls.client)
            return

        api_port = _free_port()
        env = os.environ.copy()
        env.update(
            {
                "SMTP_HOST": "127.0.0.1",
                "SMTP_PORT": str(cls.mailbox.port),
                "SMTP_SECURITY": "none",
                "SMTP_FROM": "defensync-qa@localhost",
                "SMTP_USERNAME": "",
                "SMTP_PASSWORD": "",
            }
        )
        # DEVNULL avoids a PIPE deadlock when the managed API logs heavily.
        cls._server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "backend.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
            ],
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.client = DefenSyncTestClient(f"http://127.0.0.1:{api_port}")
        try:
            cls._wait_for_health(cls.client)
        except Exception:
            cls._stop_server()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._stop_server()
        cls.mailbox.stop()

    @classmethod
    def _stop_server(cls) -> None:
        server = cls._server
        cls._server = None
        if server is None:
            return
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)

    @classmethod
    def _wait_for_health(cls, client: DefenSyncTestClient) -> None:
        deadline = time.monotonic() + HEALTH_TIMEOUT_SECONDS
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if cls._server is not None and cls._server.poll() is not None:
                raise RuntimeError(
                    f"Managed API process exited before becoming healthy (exit={cls._server.returncode})."
                )
            try:
                status_code, body = client._request("GET", "/health")
                if status_code == 200 and body.get("status") == "healthy":
                    return
            except Exception as exc:  # noqa: BLE001 - surface final error after retries
                last_error = exc
            time.sleep(0.25)
        raise RuntimeError(f"API at {client.base_url} did not become healthy within {HEALTH_TIMEOUT_SECONDS}s: {last_error}")

    def _ensure_account(self) -> None:
        """Create the suite analyst once (register), then mark the account ready."""
        if self.__class__.account_ready:
            return
        self.client.clear_token()
        try:
            login_with_otp(
                self.client._request,
                self.analyst_email,
                self.analyst_password,
                mailbox=self.mailbox,
                recipient=self.analyst_email,
            )
        except QALoginError:
            register_with_otp(
                self.client._request,
                self.analyst_username,
                self.analyst_email,
                self.analyst_password,
                mailbox=self.mailbox,
                recipient=self.analyst_email,
            )
        self.__class__.account_ready = True
        self.client.clear_token()

    def _ensure_analyst_token(self) -> str:
        """Return a real OTP-verified JWT without relying on earlier test methods."""
        token = self.__class__.analyst_token
        if token:
            self.client.set_token(token)
            return token
        self._ensure_account()
        self.client.clear_token()
        result = login_with_otp(
            self.client._request,
            self.analyst_email,
            self.analyst_password,
            mailbox=self.mailbox,
            recipient=self.analyst_email,
        )
        self.__class__.analyst_token = result.access_token
        self.client.set_token(result.access_token)
        return result.access_token

    def _ensure_seed_events(self) -> None:
        """Ingest the baseline events used by list/stats assertions when run in isolation."""
        if self.__class__.events_seeded:
            self._ensure_analyst_token()
            return
        self._ensure_analyst_token()
        singles = [
            {
                "hostname": "workstation-01",
                "event_type": "Failed Login",
                "severity": "medium",
                "risk_score": 45,
                "message": "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
                "raw_log": "Jul  6 02:00:00 workstation-01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
                "username": "admin",
                "source_ip": "192.168.1.100",
                "process": "sshd",
            }
        ]
        for payload in singles:
            status_code, body = self.client._request("POST", "/api/v1/events", payload)
            self.assertEqual(status_code, 201, body)
        bulk = [
            {
                "hostname": "web-server-01",
                "event_type": "Failed Login",
                "severity": "medium",
                "risk_score": 30,
                "message": "Failed password for root",
                "raw_log": "Failed password for root",
                "username": "root",
                "source_ip": "203.0.113.5",
                "process": "sshd",
            },
            {
                "hostname": "web-server-01",
                "event_type": "Sudo Command",
                "severity": "high",
                "risk_score": 85,
                "message": "root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get upgrade",
                "raw_log": "sudo upgrade executed",
                "username": "root",
                "source_ip": "127.0.0.1",
                "process": "sudo",
            },
            {
                "hostname": "db-server",
                "event_type": "Successful Login",
                "severity": "low",
                "risk_score": 10,
                "message": "Successful login for db_admin",
                "raw_log": "Successful login for db_admin",
                "username": "db_admin",
                "source_ip": "10.0.0.50",
                "process": "sshd",
            },
        ]
        status_code, body = self.client._request("POST", "/api/v1/events/bulk", bulk)
        self.assertEqual(status_code, 201, body)
        self.assertGreaterEqual(body.get("inserted", 0), 3)
        self.__class__.events_seeded = True

    def test_01_health_check(self):
        """Test GET /health endpoint."""
        status_code, body = self.client._request("GET", "/health")
        self.assertEqual(status_code, 200, "Health check failed")
        self.assertEqual(body.get("status"), "healthy")

    def test_02_register_users(self):
        """Register -> emailed code -> /register/verify creates the analyst account and returns its token."""
        if self.__class__.account_ready:
            self.skipTest("Suite analyst was already provisioned by another test in this run.")
        self.client.clear_token()
        result = register_with_otp(
            self.client._request,
            self.analyst_username,
            self.analyst_email,
            self.analyst_password,
            mailbox=self.mailbox,
            recipient=self.analyst_email,
        )
        self.assertNotIn("access_token", result.challenge)
        self.assertEqual(result.challenge.get("delivery"), "EMAIL")
        self.__class__.account_ready = True
        self.__class__.analyst_token = result.access_token
        self.client.set_token(result.access_token)
        status_code, body = self.client._request("GET", "/api/v1/auth/me")
        self.client.clear_token()
        self.assertEqual((status_code, body.get("username")), (200, self.analyst_username))

    def test_03_login_and_token_generation(self):
        """Email + password -> OTP challenge (no token) -> emailed code -> verified JWT for the analyst."""
        self._ensure_account()
        self.client.clear_token()
        result = login_with_otp(
            self.client._request,
            self.analyst_email,
            self.analyst_password,
            mailbox=self.mailbox,
            recipient=self.analyst_email,
        )
        self.assertNotIn("access_token", result.challenge)
        self.assertEqual(result.challenge.get("delivery"), "EMAIL")
        self.assertNotIn(self.analyst_email.split("@")[0], result.challenge.get("destination", ""))
        self.__class__.analyst_token = result.access_token

    def test_04_get_profile(self):
        """Test GET /auth/me profile endpoint with authentication."""
        self._ensure_analyst_token()
        status_code, body = self.client._request("GET", "/api/v1/auth/me")
        self.assertEqual(status_code, 200)
        self.assertEqual(body.get("username"), self.analyst_username)
        self.assertEqual(body.get("role", "").upper(), "ANALYST")

    def test_05_single_event_ingestion(self):
        """Test POST /events single ingestion with full validation."""
        self._ensure_analyst_token()
        payload = {
            "hostname": "workstation-01",
            "event_type": "Failed Login",
            "severity": "medium",
            "risk_score": 45,
            "message": "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
            "raw_log": f"Jul  6 02:00:00 workstation-01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2 suite={self.analyst_username}",
            "username": "admin",
            "source_ip": "192.168.1.100",
            "process": "sshd",
        }
        status_code, body = self.client._request("POST", "/api/v1/events", payload)
        self.assertEqual(status_code, 201, f"Failed single event ingestion: {body}")
        self.assertTrue(body.get("success"))
        self.assertIn("event", body)
        self.assertEqual(body["event"]["event_type"], "Failed Login")
        self.assertEqual(body["event"]["username"], "admin")
        self.assertEqual(body["event"]["risk_score"], 45)

    def test_06_reject_invalid_event_type(self):
        """Test validation error when providing an unsupported event type."""
        self._ensure_analyst_token()
        payload = {
            "hostname": "workstation-01",
            "event_type": "Super Dangerous Threat",  # Unsupported
            "severity": "critical",
            "risk_score": 100,
            "message": "Intrusion detected",
            "raw_log": "Threat Log here",
        }
        status_code, body = self.client._request("POST", "/api/v1/events", payload)
        self.assertEqual(status_code, 422, f"API accepted an invalid event type: {body}")

    def test_07_bulk_event_ingestion(self):
        """Test POST /events/bulk with multiple valid and invalid items."""
        self._ensure_analyst_token()
        marker = self.analyst_username
        payload = [
            {
                "hostname": "web-server-01",
                "event_type": "Failed Login",
                "severity": "medium",
                "risk_score": 30,
                "message": "Failed password for root",
                "raw_log": f"Failed password for root suite={marker}-bulk-1",
                "username": "root",
                "source_ip": "203.0.113.5",
                "process": "sshd",
            },
            {
                "hostname": "web-server-01",
                "event_type": "Sudo Command",
                "severity": "high",
                "risk_score": 85,
                "message": "root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt-get upgrade",
                "raw_log": f"sudo upgrade executed suite={marker}-bulk-2",
                "username": "root",
                "source_ip": "127.0.0.1",
                "process": "sudo",
            },
            {
                "hostname": "db-server",
                "event_type": "Successful Login",
                "severity": "low",
                "risk_score": 10,
                "message": "Successful login for db_admin",
                "raw_log": f"Successful login for db_admin suite={marker}-bulk-3",
                "username": "db_admin",
                "source_ip": "10.0.0.50",
                "process": "sshd",
            },
            {
                "hostname": "web-server-01",
                "event_type": "Invalid Action",  # Row error
                "severity": "critical",
                "risk_score": 95,
                "message": "Invalid logs",
                "raw_log": "Raw",
            },
        ]
        status_code, body = self.client._request("POST", "/api/v1/events/bulk", payload)
        self.assertEqual(status_code, 201)
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("inserted"), 3)
        self.assertEqual(body.get("failed"), 1)
        self.__class__.events_seeded = True

    def test_08_query_events_with_filters(self):
        """Test GET /events query filters and pagination."""
        self._ensure_seed_events()
        status_code, events = self.client._request("GET", "/api/v1/events", params={"limit": 10})
        self.assertEqual(status_code, 200)
        self.assertGreaterEqual(len(events), 4)

    def test_09_high_risk_events(self):
        """Test GET /events/high-risk endpoint."""
        self._ensure_seed_events()
        status_code, body = self.client._request("GET", "/api/v1/events/high-risk")
        self.assertEqual(status_code, 200)
        events = body.get("items") if isinstance(body, dict) else body
        self.assertGreaterEqual(len(events), 1)
        if isinstance(body, dict):
            self.assertGreaterEqual(body.get("total", 0), 1)

    def test_10_recent_events(self):
        """Test GET /events/recent endpoint."""
        self._ensure_seed_events()
        status_code, events = self.client._request("GET", "/api/v1/events/recent", params={"limit": 2})
        self.assertEqual(status_code, 200)
        self.assertEqual(len(events), 2)

    def test_11_event_statistics(self):
        """Test GET /events/stats for aggregated metrics."""
        self._ensure_seed_events()
        status_code, stats = self.client._request("GET", "/api/v1/events/stats")
        self.assertEqual(status_code, 200)
        self.assertIn("total_events", stats)
        self.assertIn("by_severity", stats)
        self.assertIn("by_event_type", stats)

    def test_12_rbac_delete_restriction_for_analyst(self):
        """Test that non-admin analysts are forbidden from deleting events."""
        self._ensure_analyst_token()
        status_code, body = self.client._request("DELETE", "/api/v1/events", params={"event_type": "Failed Login"})
        self.assertEqual(status_code, 403, body)


if __name__ == "__main__":
    print("======================================================================")
    print("DefenSync Integration Test Suite")
    print(f"External mode: {EXTERNAL_SUITE}  API_URL={DEFAULT_API_URL}")
    print("======================================================================")
    unittest.main()
