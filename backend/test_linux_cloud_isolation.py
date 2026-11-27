"""Linux SSH health classification and Linux/cloud isolation regression tests.

No live SSH, PostgreSQL rows, or cloud APIs are touched: Paramiko, sockets,
sessions, and the collection pipeline are mocked.
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import paramiko
from cryptography.fernet import Fernet

from backend.collector.config import SSHConfig
from backend.core.encryption import CredentialDecryptionError, decrypt_secret, encrypt_secret
from backend.core.exceptions import ValidationException
from backend.database.models import Server
from backend.health.status import ERROR_STATUSES, HealthStatus, health_label
from backend.services.datasets.azure_import_service import AzureActivityLogImportService
from backend.services.health_service import HealthService
from backend.services.server_service import ServerService
from backend.services.ssh_service import (
    DIAG_AUTHENTICATION_FAILED,
    DIAG_COMMAND_EXECUTION_FAILED,
    DIAG_CREDENTIAL_ERROR,
    DIAG_NETWORK_ERROR,
    DIAG_SSH_TIMEOUT,
    DIAG_SUCCESS,
    SSHService,
    classify_ssh_exception,
)


def _foreign_ciphertext(value: str = "old-password") -> str:
    """Ciphertext produced under a different SECRET_KEY than the active one."""
    key = base64.urlsafe_b64encode(hashlib.sha256(b"a-previous-secret-key").digest())
    return Fernet(key).encrypt(value.encode()).decode()


def _wrapped(exc: Exception) -> ConnectionError:
    """Mirror SSHClient.connect, which wraps the last failure in ConnectionError."""
    try:
        raise ConnectionError(f"SSH connection failed after 1 attempts: {exc}") from exc
    except ConnectionError as wrapped:
        return wrapped


def _server(**overrides) -> Server:
    fields = {
        "id": "srv-1",
        "server_name": "Ubuntu-Web",
        "host": "192.0.2.10",
        "port": 22,
        "username": "defensync",
        "authentication_type": "password",
        "encrypted_password": encrypt_secret("correct-horse"),
        "status": "active",
        "health_status": HealthStatus.UNKNOWN,
        "consecutive_failures": 0,
        "owner_id": "owner-1",
        "created_by": "owner-1",
    }
    fields.update(overrides)
    return Server(**fields)


def _config() -> SSHConfig:
    return SSHConfig(host="192.0.2.10", username="defensync", password="x", timeout=1.0)


class SSHClassificationTests(unittest.TestCase):
    def test_wrapped_paramiko_auth_failure_is_authentication_failed(self):
        exc = _wrapped(paramiko.AuthenticationException("Authentication failed."))
        self.assertEqual(classify_ssh_exception(exc), HealthStatus.AUTHENTICATION_FAILED)

    def test_wrapped_socket_timeout_is_timeout(self):
        self.assertEqual(classify_ssh_exception(_wrapped(socket.timeout("timed out"))), HealthStatus.TIMEOUT)

    def test_connection_refused_is_unreachable(self):
        exc = _wrapped(ConnectionRefusedError(10061, "refused"))
        self.assertEqual(classify_ssh_exception(exc), HealthStatus.UNREACHABLE)

    def test_ssh_protocol_error_is_error_not_auth(self):
        exc = _wrapped(paramiko.SSHException("Error reading SSH protocol banner"))
        self.assertEqual(classify_ssh_exception(exc), HealthStatus.ERROR)

    def test_credential_decryption_error_is_credential_error(self):
        self.assertEqual(classify_ssh_exception(CredentialDecryptionError()), HealthStatus.CREDENTIAL_ERROR)

    def test_credential_error_is_error_state_with_label(self):
        self.assertIn(HealthStatus.CREDENTIAL_ERROR, ERROR_STATUSES)
        self.assertEqual(health_label("credential_error"), "Credential Error")


class CredentialStoreTests(unittest.TestCase):
    def test_round_trip_with_active_key(self):
        self.assertEqual(decrypt_secret(encrypt_secret("s3cret")), "s3cret")

    def test_foreign_key_raises_typed_error_that_is_still_value_error(self):
        with self.assertRaises(CredentialDecryptionError) as ctx:
            decrypt_secret(_foreign_ciphertext())
        self.assertIsInstance(ctx.exception, ValueError)
        self.assertIn("SECRET_KEY", str(ctx.exception))

    def test_health_probe_reports_credential_error_without_ssh(self):
        server = _server(encrypted_password=_foreign_ciphertext())
        with patch("backend.services.ssh_service.SSHClient") as client_cls:
            result = HealthService(MagicMock())._probe_server(server)
        client_cls.assert_not_called()
        self.assertEqual(result.health_status, HealthStatus.CREDENTIAL_ERROR)
        self.assertIn("re-enter", result.error_message)

    def test_test_connection_returns_structured_failure_not_exception(self):
        server = _server(encrypted_password=_foreign_ciphertext())
        result = SSHService.test_connection(server)
        self.assertFalse(result["success"])
        self.assertEqual(result["health_status"], HealthStatus.CREDENTIAL_ERROR)

    def test_service_test_connection_persists_precise_status(self):
        server = _server(encrypted_password=_foreign_ciphertext())
        service = ServerService(MagicMock())
        with patch("backend.services.server_service.server_crud.get_server", return_value=server):
            result = service.test_connection(server.id)
        self.assertEqual(result["health_status"], HealthStatus.CREDENTIAL_ERROR)
        self.assertEqual(result["connection_state"], "Credential Error")
        self.assertEqual(server.health_status, HealthStatus.CREDENTIAL_ERROR)

    def test_collect_with_undecryptable_credential_is_4xx_not_500(self):
        server = _server(encrypted_password=_foreign_ciphertext())
        service = ServerService(MagicMock())
        with patch("backend.services.server_service.server_crud.get_server", return_value=server), \
             patch("backend.services.server_service.server_crud.create_collection_run", return_value=MagicMock()), \
             patch("backend.services.server_service.server_crud.complete_collection_run"), \
             patch("backend.services.server_service.PipelineService") as pipeline_cls:
            with self.assertRaises(ValidationException):
                service.collect_for_server(server.id)
        pipeline_cls.return_value.collect_and_process.assert_not_called()
        self.assertEqual(server.health_status, HealthStatus.CREDENTIAL_ERROR)


class ProbeConnectivityTests(unittest.TestCase):
    def _probe(self, side_effect=None):
        with patch("backend.services.ssh_service.SSHClient") as client_cls:
            client_cls.return_value.connect.side_effect = side_effect
            return SSHService.probe_connectivity(_config())

    def test_success_is_online(self):
        self.assertEqual(self._probe()["health_status"], HealthStatus.ONLINE)

    def test_invalid_password_is_authentication_failed(self):
        probe = self._probe(_wrapped(paramiko.AuthenticationException("Authentication failed.")))
        self.assertEqual(probe["health_status"], HealthStatus.AUTHENTICATION_FAILED)
        self.assertIn("Authentication failed for host", probe["error_message"])

    def test_timeout_is_timeout(self):
        self.assertEqual(self._probe(_wrapped(socket.timeout("timed out")))["health_status"], HealthStatus.TIMEOUT)


class DiagnoseTests(unittest.TestCase):
    def test_tcp_timeout(self):
        with patch("backend.services.ssh_service.socket.create_connection", side_effect=socket.timeout("timed out")):
            self.assertEqual(SSHService.diagnose(_config())["result"], DIAG_SSH_TIMEOUT)

    def test_tcp_refused_is_network_error(self):
        with patch("backend.services.ssh_service.socket.create_connection", side_effect=ConnectionRefusedError(10061, "refused")):
            self.assertEqual(SSHService.diagnose(_config())["result"], DIAG_NETWORK_ERROR)

    def test_auth_failure(self):
        with patch("backend.services.ssh_service.socket.create_connection"), \
             patch("backend.services.ssh_service.SSHClient") as client_cls:
            client_cls.return_value.connect.side_effect = _wrapped(paramiko.AuthenticationException("Authentication failed."))
            self.assertEqual(SSHService.diagnose(_config())["result"], DIAG_AUTHENTICATION_FAILED)

    def test_exec_failure(self):
        with patch("backend.services.ssh_service.socket.create_connection"), \
             patch("backend.services.ssh_service.SSHClient") as client_cls:
            client_cls.return_value.run_remote_command_status.return_value = (127, [], "sh: not found")
            self.assertEqual(SSHService.diagnose(_config())["result"], DIAG_COMMAND_EXECUTION_FAILED)

    def test_success_reports_per_source_state(self):
        def run(command, timeout=30.0):
            if command == "echo defensync-ok":
                return 0, ["defensync-ok"], ""
            if "/var/log/auth.log" in command:
                return 0, ["missing"], ""
            if command.startswith("if [ -r"):
                return 0, ["readable"], ""
            return 0, ["line"], ""

        with patch("backend.services.ssh_service.socket.create_connection"), \
             patch("backend.services.ssh_service.SSHClient") as client_cls:
            client_cls.return_value.run_remote_command_status.side_effect = run
            report = SSHService.diagnose(_config())
        self.assertEqual(report["result"], DIAG_SUCCESS)
        self.assertIn("auth", report["message"])
        self.assertNotIn("x", [step.get("password") for step in report["steps"]])

    def test_diagnose_server_credential_error(self):
        report = SSHService.diagnose_server(_server(encrypted_password=_foreign_ciphertext()))
        self.assertEqual(report["result"], DIAG_CREDENTIAL_ERROR)


AZURE_ROW = {
    "eventTimestamp": "2026-03-01T10:15:00Z",
    "caller": "alice@example.com",
    "operationName": {"value": "Microsoft.Compute/virtualMachines/write"},
    "status": {"value": "Failed"},
    "resourceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
}


def _azure_event() -> dict:
    with patch("backend.services.datasets.azure_import_service.IngestionService"):
        service = AzureActivityLogImportService(MagicMock())
    return service._normalize(AZURE_ROW, owner_id=None, source="test.json")


class LinuxCloudIsolationTests(unittest.TestCase):
    def _linux_probe_online(self) -> str:
        with patch("backend.services.ssh_service.SSHClient"):
            return HealthService(MagicMock())._probe_server(_server()).health_status

    def test_a_cloud_disabled_settings_and_linux_work(self):
        from backend.core.config import Settings

        clean = {k: v for k, v in os.environ.items() if not k.startswith("AZURE_")}
        with patch.dict(os.environ, clean, clear=True):
            settings = Settings(_env_file=None, SECRET_KEY="unit-test-key")
        from backend.services.cloud.azure_collector import STATUS_NOT_CONFIGURED, AzureCollector

        azure_fields = [name for name in type(settings).model_fields if name.startswith("AZURE_")]
        for name in azure_fields:
            value = getattr(settings, name)
            self.assertEqual(value.get_secret_value() if hasattr(value, "get_secret_value") else value, "")
        self.assertEqual(AzureCollector(MagicMock(), settings=settings).status()["status"], STATUS_NOT_CONFIGURED)
        self.assertEqual(self._linux_probe_online(), HealthStatus.ONLINE)

    def test_b_invalid_cloud_credentials_do_not_affect_linux(self):
        from backend.core.config import Settings

        bogus = {"AZURE_TENANT_ID": "bad", "AZURE_CLIENT_ID": "bad", "AZURE_CLIENT_SECRET": "bad", "AZURE_SUBSCRIPTION_ID": "bad"}
        with patch.dict(os.environ, bogus):
            Settings(_env_file=None, SECRET_KEY="unit-test-key")
            self.assertEqual(self._linux_probe_online(), HealthStatus.ONLINE)

    def test_c_cloud_service_unavailable_does_not_affect_linux(self):
        import backend.api  # noqa: F401

        self.assertFalse(any(m == "azure" or m.startswith("azure.") for m in sys.modules))
        with patch.object(AzureActivityLogImportService, "import_file", side_effect=ConnectionError("cloud down")):
            self.assertEqual(self._linux_probe_online(), HealthStatus.ONLINE)

    def test_d_cloud_import_mode_and_linux_both_work(self):
        event = _azure_event()
        self.assertEqual(event["provider"], "AZURE")
        self.assertEqual(event["data_origin"], "AZURE_ACTIVITY_LOG_FILE")
        self.assertEqual(event["timestamp"], datetime(2026, 3, 1, 10, 15, tzinfo=timezone.utc))
        self.assertEqual(event["timestamp_source"], "SOURCE_EVENT")
        self.assertEqual(self._linux_probe_online(), HealthStatus.ONLINE)

    def test_e_invalid_linux_ssh_keeps_cloud_working_and_precise_error(self):
        with patch("backend.services.ssh_service.SSHClient") as client_cls:
            client_cls.return_value.connect.side_effect = _wrapped(paramiko.AuthenticationException("Authentication failed."))
            result = HealthService(MagicMock())._probe_server(_server())
        self.assertEqual(result.health_status, HealthStatus.AUTHENTICATION_FAILED)
        self.assertEqual(_azure_event()["source_type"], "CLOUD")

    def test_f_linux_restored_collection_resumes(self):
        server = _server()
        service = ServerService(MagicMock())
        failed_stats = {
            "processed": 0, "inserted": 0, "failed": 1, "duplicates": 0, "skipped": 0,
            "errors": [{"stage": "collect", "error": "Authentication failed.", "health_status": HealthStatus.AUTHENTICATION_FAILED}],
        }
        ok_stats = {"processed": 5, "inserted": 5, "failed": 0, "duplicates": 0, "skipped": 0, "errors": []}
        with patch("backend.services.server_service.server_crud.get_server", return_value=server), \
             patch("backend.services.server_service.server_crud.create_collection_run", return_value=MagicMock()), \
             patch("backend.services.server_service.server_crud.complete_collection_run"), \
             patch("backend.services.server_service.threading.Thread"), \
             patch("backend.services.server_service.PipelineService") as pipeline_cls:
            pipeline_cls.return_value.collect_and_process.return_value = failed_stats
            first = service.collect_for_server(server.id)
            self.assertFalse(first["success"])
            self.assertEqual(server.health_status, HealthStatus.AUTHENTICATION_FAILED)

            pipeline_cls.return_value.collect_and_process.return_value = ok_stats
            second = service.collect_for_server(server.id)
        self.assertTrue(second["success"])
        self.assertEqual(second["collected_events"], 5)
        self.assertEqual(server.health_status, HealthStatus.ONLINE)


if __name__ == "__main__":
    unittest.main()
