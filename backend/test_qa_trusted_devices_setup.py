"""Safety guards for the Trusted Devices local QA environment helper."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from backend.testing.qa_trusted_devices_env import (
    CONFIRM_PHRASE,
    assess_database_only,
    assess_qa_target,
    confirm_phrase_accepted,
)


def settings(**overrides):
    values = {
        "ENVIRONMENT": "development",
        "DB_HOST": "127.0.0.1",
        "DB_PORT": 5432,
        "DB_NAME": "defensync_qa",
        "DB_USER": "postgres",
        "SMTP_HOST": "127.0.0.1",
        "SMTP_PORT": 2525,
        "SMTP_SECURITY": "none",
        "SMTP_FROM": "defensync-qa@localhost",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class QaTrustedDevicesEnvTests(unittest.TestCase):
    def test_accepts_local_qa_database_and_loopback_smtp(self):
        view = assess_qa_target(settings())
        self.assertTrue(view.is_safe)
        self.assertEqual(view.db_name, "defensync_qa")

    def test_rejects_default_non_qa_database_name(self):
        view = assess_database_only(settings(DB_NAME="cloudsync_db"))
        self.assertFalse(view.is_safe)
        self.assertTrue(any("cloudsync_db" in item for item in view.blockers))

    def test_rejects_remote_database_host(self):
        view = assess_database_only(settings(DB_HOST="db.example.com"))
        self.assertFalse(view.is_safe)
        self.assertTrue(any("loopback" in item for item in view.blockers))

    def test_rejects_production_environment(self):
        view = assess_database_only(settings(ENVIRONMENT="production"))
        self.assertFalse(view.is_safe)

    def test_rejects_external_smtp_when_full_assessment_required(self):
        view = assess_qa_target(settings(SMTP_HOST="smtp.gmail.com", SMTP_SECURITY="starttls", SMTP_PORT=587))
        self.assertFalse(view.is_safe)
        self.assertTrue(any("loopback" in item or "SMTP" in item for item in view.blockers))

    def test_database_only_ignores_external_smtp_so_operator_can_override_later(self):
        view = assess_database_only(settings(SMTP_HOST="smtp.gmail.com", SMTP_SECURITY="starttls"))
        self.assertTrue(view.is_safe)

    def test_confirm_phrase(self):
        self.assertTrue(confirm_phrase_accepted(CONFIRM_PHRASE))
        self.assertFalse(confirm_phrase_accepted("yes"))
        self.assertFalse(confirm_phrase_accepted(""))


if __name__ == "__main__":
    unittest.main()
