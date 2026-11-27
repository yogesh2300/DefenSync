"""SSH credential handling: in-memory private keys and safe username changes.

Keys are generated per test run; no real credentials, no network, no PostgreSQL.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from backend.collector.config import SSHConfig
from backend.collector.ssh_client import SSHClient, load_private_key
from backend.core.encryption import decrypt_secret, encrypt_secret
from backend.core.exceptions import ValidationException
from backend.health.status import HealthStatus
from backend.services.server_service import ServerService
from backend.services.ssh_service import SSHService
from backend.test_linux_collection_pipeline import SSH_PASSWORD, LinuxCollectionTestBase


def openssh_key(private_key, password: bytes | None = None) -> str:
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, encryption).decode()


ED25519 = openssh_key(ed25519.Ed25519PrivateKey.generate())


class PrivateKeyLoadingTests(unittest.TestCase):
    def test_supported_key_types_load_in_memory(self):
        cases = {
            paramiko.Ed25519Key: ED25519,
            paramiko.ECDSAKey: openssh_key(ec.generate_private_key(ec.SECP256R1())),
            paramiko.RSAKey: openssh_key(rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        }
        for key_type, content in cases.items():
            self.assertIsInstance(load_private_key(content), key_type)

    def test_unusable_keys_are_credential_errors(self):
        encrypted = openssh_key(ed25519.Ed25519PrivateKey.generate(), b"unit-test-passphrase")
        with self.assertRaisesRegex(ValueError, "Passphrase-protected"):
            load_private_key(encrypted)
        with self.assertRaisesRegex(ValueError, "could not be parsed"):
            load_private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----")

    def test_secrets_not_in_repr(self):
        text = repr(SSHConfig(host="192.0.2.10", username="defensync", private_key=ED25519)) + repr(
            SSHConfig(host="192.0.2.10", username="defensync", password=SSH_PASSWORD)
        )
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn(SSH_PASSWORD, text)


class KeyNeverWrittenToDiskTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        self.server.authentication_type = "ssh_key"
        self.server.encrypted_password = None
        self.server.encrypted_private_key = encrypt_secret(ED25519)
        self.session.commit()
        self._tmp = tempfile.TemporaryDirectory()
        self._tempdir = patch.object(tempfile, "tempdir", self._tmp.name)
        self._tempdir.start()

    def tearDown(self):
        self._tempdir.stop()
        self._tmp.cleanup()
        super().tearDown()

    def test_connect_passes_key_object_and_writes_no_file(self):
        captured = {}

        def fake_connect(_client, **kwargs):
            captured.update(kwargs)

        config = SSHService.config_from_server(self.server)
        with patch.object(paramiko.SSHClient, "connect", fake_connect), \
                patch.object(paramiko.SSHClient, "open_sftp", return_value=None):
            client = SSHClient(config)
            for _ in range(3):  # repeated health probes
                client._connect_once()
        self.assertIsNone(config.private_key_path)
        self.assertIsInstance(captured["pkey"], paramiko.Ed25519Key)
        self.assertNotIn("key_filename", captured)
        self.assertNotIn("password", captured)
        self.assertEqual(os.listdir(self._tmp.name), [])
        self.assertEqual(list(Path(tempfile.gettempdir()).glob("*.pem")), [])

    def test_stored_garbage_key_reports_credential_error(self):
        self.server.encrypted_private_key = encrypt_secret("-----BEGIN OPENSSH PRIVATE KEY-----\nbroken\n-----END OPENSSH PRIVATE KEY-----")
        self.session.commit()
        result = SSHService.test_connection(self.server)
        self.assertEqual((result["success"], result["health_status"]), (False, HealthStatus.CREDENTIAL_ERROR))

    def test_test_before_save_with_bad_key_does_not_raise(self):
        result = SSHService.test_credentials(
            host="192.0.2.10", port=22, username="defensync", authentication_type="ssh_key", private_key="x" * 40,
        )
        self.assertEqual((result["success"], result["health_status"]), (False, HealthStatus.CREDENTIAL_ERROR))
        self.assertEqual(os.listdir(self._tmp.name), [])


class UsernameChangeTests(LinuxCollectionTestBase):
    def setUp(self):
        super().setUp()
        self._health = patch("backend.services.server_service.get_health_engine")
        self._health.start()

    def tearDown(self):
        self._health.stop()
        super().tearDown()

    def stored(self):
        self.session.expire_all()
        return self.server.username, self.server.authentication_type, self.server.encrypted_password, self.server.encrypted_private_key

    def test_username_change_without_new_secret_is_rejected(self):
        before = self.stored()
        with self.assertRaisesRegex(ValidationException, "requires a new password or private key"):
            ServerService(self.session).update_server(self.server.id, {"username": "collector2"})
        self.assertEqual(self.stored(), before)

    def test_username_change_with_new_key_replaces_password(self):
        ServerService(self.session).update_server(
            self.server.id, {"username": " collector2 ", "authentication_type": "ssh_key", "private_key": ED25519},
        )
        username, auth, password, key = self.stored()
        self.assertEqual((username, auth, password), ("collector2", "ssh_key", None))
        self.assertEqual(decrypt_secret(key), ED25519)
        ServerService(self.session).update_server(self.server.id, {"authentication_type": "password", "password": "new-unit-test-pw"})
        _, auth, password, key = self.stored()
        self.assertEqual((auth, decrypt_secret(password), key), ("password", "new-unit-test-pw", None))

    def test_unchanged_username_needs_no_secret(self):
        ServerService(self.session).update_server(self.server.id, {"username": "defensync", "server_name": "renamed"})
        self.assertEqual(decrypt_secret(self.stored()[2]), SSH_PASSWORD)

    def test_blank_username_is_rejected(self):
        with self.assertRaisesRegex(ValidationException, "cannot be empty"):
            ServerService(self.session).update_server(self.server.id, {"username": "  ", "password": "new-unit-test-pw"})

    def test_api_returns_validation_error(self):
        response = self.api("owner-a").put(f"/api/v1/servers/{self.server.id}", json={"username": "collector2"})
        self.assertEqual(response.status_code, 422)
        self.assertIn("requires a new password or private key", response.json()["error"])
        self.assertEqual(self.stored()[0], "defensync")


if __name__ == "__main__":
    unittest.main()
