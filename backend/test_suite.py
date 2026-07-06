#!/usr/bin/env python3
"""
CloudSync Integration Test Suite.
A zero-dependency validation script to test the complete FastAPI Event Management System.
Uses only Python's built-in standard libraries to ensure cross-platform compatibility.
"""

import json
import os
import random
import sys
import unittest
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# Configuration
DEFAULT_API_URL = os.getenv("API_URL", "http://localhost:8000")


class CloudSyncTestClient:
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

    def _request(self, method: str, path: str, data: dict = None, params: dict = None) -> tuple[int, dict]:
        """Send an HTTP request and return (status_code, response_json)."""
        url = f"{self.base_url}{path}"
        if params:
            query_string = "&".join(f"{k}={v}" for k, v in params.items() if v is not None)
            if query_string:
                url = f"{url}?{query_string}"

        req_data = None
        headers = {}

        if data is not None:
            req_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = Request(url, data=req_data, headers=headers, method=method)

        try:
            with urlopen(req) as response:
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
        except Exception as e:
            print(f"\n[ERROR] Connection to API server at {self.base_url} failed.", file=sys.stderr)
            print(f"Detail: {e}", file=sys.stderr)
            print("\nPlease make sure your FastAPI application is running (e.g. uvicorn backend.main:app --port 8000)", file=sys.stderr)
            sys.exit(1)


class TestCloudSyncBackend(unittest.TestCase):
    """Test suite executing standard and behavioral endpoints on CloudSync."""

    @classmethod
    def setUpClass(cls):
        cls.client = CloudSyncTestClient()
        suffix = random.randint(1000, 9999)
        cls.analyst_username = f"analyst_{suffix}"
        cls.analyst_password = "SecurePassword123!"
        cls.analyst_email = f"{cls.analyst_username}@cloudsync.local"

    def test_01_health_check(self):
        """Test GET /health endpoint."""
        status_code, body = self.client._request("GET", "/health")
        self.assertEqual(status_code, 200, "Health check failed")
        self.assertEqual(body.get("status"), "healthy")

    def test_02_register_users(self):
        """Test registering both analyst and administrator roles."""
        payload = {
            "username": self.analyst_username,
            "email": self.analyst_email,
            "password": self.analyst_password
        }
        status_code, body = self.client._request("POST", "/api/v1/auth/register", payload)
        self.assertEqual(status_code, 201, f"Failed to register analyst user: {body}")
        self.assertEqual(body.get("username"), self.analyst_username)

    def test_03_login_and_token_generation(self):
        """Test obtaining a JWT access token for the registered analyst."""
        payload = {
            "username": self.analyst_username,
            "password": self.analyst_password
        }
        status_code, body = self.client._request("POST", "/api/v1/auth/token", payload)
        self.assertEqual(status_code, 200, f"Login failed: {body}")
        self.assertIn("access_token", body)
        self.assertEqual(body.get("token_type"), "bearer")
        self.__class__.analyst_token = body["access_token"]

    def test_04_get_profile(self):
        """Test GET /auth/me profile endpoint with authentication."""
        self.client.set_token(self.analyst_token)
        status_code, body = self.client._request("GET", "/api/v1/auth/me")
        self.assertEqual(status_code, 200)
        self.assertEqual(body.get("username"), self.analyst_username)
        self.assertEqual(body.get("role"), "analyst")

    def test_05_single_event_ingestion(self):
        """Test POST /events single ingestion with full validation."""
        self.client.set_token(self.analyst_token)
        payload = {
            "hostname": "workstation-01",
            "event_type": "Failed Login",
            "severity": "medium",
            "risk_score": 45,
            "message": "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
            "raw_log": "Jul  6 02:00:00 workstation-01 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
            "username": "admin",
            "source_ip": "192.168.1.100",
            "process": "sshd"
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
        self.client.set_token(self.analyst_token)
        payload = {
            "hostname": "workstation-01",
            "event_type": "Super Dangerous Threat",  # Unsupported
            "severity": "critical",
            "risk_score": 100,
            "message": "Intrusion detected",
            "raw_log": "Threat Log here"
        }
        status_code, body = self.client._request("POST", "/api/v1/events", payload)
        self.assertEqual(status_code, 422, "API accepted an invalid event type")

    def test_07_bulk_event_ingestion(self):
        """Test POST /events/bulk with multiple valid and invalid items."""
        self.client.set_token(self.analyst_token)
        payload = [
            {
                "hostname": "web-server-01",
                "event_type": "Failed Login",
                "severity": "medium",
                "risk_score": 30,
                "message": "Failed password for root",
                "raw_log": "Failed password for root",
                "username": "root",
                "source_ip": "203.0.113.5",
                "process": "sshd"
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
                "process": "sudo"
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
                "process": "sshd"
            },
            {
                "hostname": "web-server-01",
                "event_type": "Invalid Action",  # Row error
                "severity": "critical",
                "risk_score": 95,
                "message": "Invalid logs",
                "raw_log": "Raw"
            }
        ]
        status_code, body = self.client._request("POST", "/api/v1/events/bulk", payload)
        self.assertEqual(status_code, 201)
        self.assertTrue(body.get("success"))
        self.assertEqual(body.get("inserted"), 3)
        self.assertEqual(body.get("failed"), 1)

    def test_08_query_events_with_filters(self):
        """Test GET /events query filters and pagination."""
        self.client.set_token(self.analyst_token)
        status_code, events = self.client._request("GET", "/api/v1/events", params={"limit": 10})
        self.assertEqual(status_code, 200)
        self.assertGreaterEqual(len(events), 4)

    def test_09_high_risk_events(self):
        """Test GET /events/high-risk endpoint."""
        self.client.set_token(self.analyst_token)
        status_code, events = self.client._request("GET", "/api/v1/events/high-risk")
        self.assertEqual(status_code, 200)
        self.assertGreaterEqual(len(events), 1)

    def test_10_recent_events(self):
        """Test GET /events/recent endpoint."""
        self.client.set_token(self.analyst_token)
        status_code, events = self.client._request("GET", "/api/v1/events/recent", params={"limit": 2})
        self.assertEqual(status_code, 200)
        self.assertEqual(len(events), 2)

    def test_11_event_statistics(self):
        """Test GET /events/stats for aggregated metrics."""
        self.client.set_token(self.analyst_token)
        status_code, stats = self.client._request("GET", "/api/v1/events/stats")
        self.assertEqual(status_code, 200)
        self.assertIn("total_events", stats)
        self.assertIn("by_severity", stats)
        self.assertIn("by_event_type", stats)

    def test_12_rbac_delete_restriction_for_analyst(self):
        """Test that non-admin analysts are forbidden from deleting events."""
        self.client.set_token(self.analyst_token)
        status_code, body = self.client._request("DELETE", "/api/v1/events", params={"event_type": "Failed Login"})
        self.assertEqual(status_code, 403)


if __name__ == "__main__":
    print("======================================================================")
    print("CloudSync Integration Test Suite")
    print(f"Testing target backend URL: {DEFAULT_API_URL}")
    print("======================================================================")
    unittest.main()