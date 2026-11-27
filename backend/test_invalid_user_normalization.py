"""Invalid-user SSH lines must normalize to stored security events (not DECLINED).

Redacted fixtures only — no live SSH, no secrets.
"""

from __future__ import annotations

import json
import unittest

from sqlalchemy import select

from backend.database.models import Event, Server, User, Account
from backend.ml.linux_features import ineligibility_reason, is_linux_ml_eligible
from backend.normalizer.event_types import EventType, RECORD_ORIGIN_SOURCE_OBSERVED, RECORD_SECURITY_EVENT
from backend.services.pipeline_service import PipelineService
from backend.services.transform_service import TransformService
from backend.test_azure_collector import session_factory
from backend.core.encryption import encrypt_secret
from backend.health.status import HealthStatus


INVALID_USER_LINES = [
    "2026-10-28T10:00:03-04:00 YogeshOS sshd[102]: Invalid user bob from 198.51.100.9 port 41002",
    "2026-10-28T10:00:04-04:00 YogeshOS sshd[103]: input_userauth_request: invalid user eve [preauth]",
    "2026-10-28T10:00:05-04:00 YogeshOS sshd-session[104]: Invalid user admin from 203.0.113.50 port 22",
]

# Already covered as Failed Login; must stay Failed Login (not reclassified as Invalid User).
FAILED_INVALID_PASSWORD = (
    "2026-10-28T10:00:01-04:00 YogeshOS sshd[100]: "
    "Failed password for invalid user admin from 198.51.100.7 port 41000 ssh2"
)


class InvalidUserNormalizationTests(unittest.TestCase):
    def test_transform_keeps_invalid_user_probes(self):
        ts = TransformService()
        events, errors = ts.normalize_log_lines(
            secure_lines=[*INVALID_USER_LINES, FAILED_INVALID_PASSWORD],
            hostname="YogeshOS",
        )
        self.assertEqual(errors, [])
        by_type = {}
        for event in events:
            by_type.setdefault(event.event_type, []).append(event)

        self.assertEqual(len(by_type[EventType.INVALID_USER]), 3)
        self.assertEqual(len(by_type[EventType.FAILED_LOGIN]), 1)

        with_ip = next(e for e in by_type[EventType.INVALID_USER] if e.source_ip)
        self.assertEqual(with_ip.username, "bob")
        self.assertEqual(with_ip.source_ip, "198.51.100.9")
        self.assertEqual(with_ip.category.value, "authentication")

        no_ip = next(e for e in by_type[EventType.INVALID_USER] if e.username == "eve")
        self.assertIsNone(no_ip.source_ip)

        failed = by_type[EventType.FAILED_LOGIN][0]
        self.assertEqual(failed.username, "admin")
        self.assertEqual(failed.source_ip, "198.51.100.7")

    def test_pipeline_persists_invalid_user_as_eligible_live_linux(self):
        session = session_factory()
        session.add_all([
            Account(id="acct-iu", name="IU"),
            User(id="owner-iu", username="owner_iu", email="iu@example.test", hashed_password="x",
                 role="ANALYST", account_id="acct-iu"),
        ])
        server = Server(
            server_name="yogesh-os", host="192.0.2.10", port=22, username="collector",
            authentication_type="password", encrypted_password=encrypt_secret("unit-test-ssh"),
            status="active", health_status=HealthStatus.UNKNOWN, owner_id="owner-iu",
            created_by="owner-iu", account_id="acct-iu", environment="lab",
        )
        session.add(server)
        session.commit()

        result = PipelineService(session).process_raw_logs(
            secure_lines=list(INVALID_USER_LINES),
            audit_lines=[],
            hostname="YogeshOS",
            server_id=server.id,
            owner_id="owner-iu",
            collector_user="collector",
            host_context={"collector_ip": "192.0.2.99", "timezone": "America/New_York", "utc_offset": "-0400"},
        )
        self.assertGreaterEqual(result.get("inserted", 0), 3)

        rows = list(session.scalars(select(Event).where(Event.server_id == server.id)).all())
        invalid = [row for row in rows if row.event_type == EventType.INVALID_USER.value]
        self.assertEqual(len(invalid), 3)

        for row in invalid:
            self.assertEqual(row.data_origin, "LIVE_LINUX")
            self.assertEqual(row.source_type, "LINUX")
            self.assertEqual(getattr(row, "data_scope", "PRIVATE"), "PRIVATE")
            self.assertEqual(row.timestamp_source, "SOURCE_EVENT")
            nd = json.loads(row.normalized_data) if isinstance(row.normalized_data, str) else row.normalized_data
            self.assertEqual(nd.get("record_kind"), RECORD_SECURITY_EVENT)
            self.assertEqual(nd.get("record_origin"), RECORD_ORIGIN_SOURCE_OBSERVED)
            self.assertIsNone(ineligibility_reason(row))
            self.assertTrue(is_linux_ml_eligible(row))

        session.close()


if __name__ == "__main__":
    unittest.main()
