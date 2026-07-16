"""SSH connection service — credentials always from database, never from .env."""

from __future__ import annotations

import paramiko
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.collector.config import SSHConfig
from backend.collector.ssh_client import SSHClient, ssh_session
from backend.core.encryption import decrypt_secret
from backend.core.logging import get_logger
from backend.database.models import Server

logger = get_logger(__name__)


class SSHService:
    """Build SSH configs from server records and manage connection lifecycle."""

    @staticmethod
    def config_from_server(server: Server) -> SSHConfig:
        """Load decrypted credentials and build SSHConfig."""
        auth = server.authentication_type
        if auth in {"private_key", "ssh_key"}:
            if not server.encrypted_private_key:
                raise ValueError(f"Server '{server.server_name}' has no private key stored.")
            key_content = decrypt_secret(server.encrypted_private_key)
            key_path = SSHService._materialize_private_key(key_content)
            return SSHConfig(
                host=server.host,
                username=server.username,
                port=server.port,
                private_key_path=key_path,
            )
        if not server.encrypted_password:
            raise ValueError(f"Server '{server.server_name}' has no password stored.")
        password = decrypt_secret(server.encrypted_password)
        return SSHConfig(
            host=server.host,
            username=server.username,
            port=server.port,
            password=password,
        )

    @staticmethod
    def config_from_credentials(
        *,
        host: str,
        port: int,
        username: str,
        authentication_type: str,
        password: str | None = None,
        private_key: str | None = None,
    ) -> SSHConfig:
        """Build SSHConfig from plain credentials (test-before-save only)."""
        auth = SSHService._normalize_auth_type(authentication_type)
        if auth in {"private_key", "ssh_key"}:
            if not private_key:
                raise ValueError("Private key is required for ssh_key authentication.")
            key_path = SSHService._materialize_private_key(private_key)
            return SSHConfig(host=host, username=username, port=port, private_key_path=key_path)
        if not password:
            raise ValueError("Password is required for password authentication.")
        return SSHConfig(host=host, username=username, port=port, password=password)

    @staticmethod
    def _normalize_auth_type(auth_type: str) -> str:
        normalized = auth_type.strip().lower()
        if normalized in {"ssh_key", "private_key", "key"}:
            return "ssh_key"
        return "password"

    @staticmethod
    def _materialize_private_key(key_content: str) -> Path:
        """Write private key content to a temporary file for Paramiko."""
        temp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem")
        temp.write(key_content)
        temp.flush()
        temp.close()
        path = Path(temp.name)
        path.chmod(0o600)
        return path

    @staticmethod
    def probe_connectivity(config: SSHConfig) -> dict[str, Any]:
        """Lightweight SSH probe returning health status, latency, and error details."""
        from backend.health.status import HealthStatus

        started = datetime.now(timezone.utc)
        client = SSHClient(config)
        try:
            client.connect(max_retries=1)
            client.disconnect()
            latency_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            return {
                "health_status": HealthStatus.ONLINE,
                "latency_ms": latency_ms,
                "error_message": None,
            }
        except paramiko.AuthenticationException as exc:
            return {
                "health_status": HealthStatus.AUTHENTICATION_FAILED,
                "latency_ms": None,
                "error_message": str(exc),
            }
        except Exception as exc:
            import socket

            message = str(exc).lower()
            if isinstance(exc, (TimeoutError, socket.timeout)) or "timed out" in message:
                status = HealthStatus.TIMEOUT
            elif isinstance(exc, paramiko.SSHException) and (
                "authentication" in message or "auth" in message
            ):
                status = HealthStatus.AUTHENTICATION_FAILED
            elif isinstance(exc, (ConnectionRefusedError, ConnectionResetError, OSError)):
                status = HealthStatus.UNREACHABLE if "timed out" not in message else HealthStatus.TIMEOUT
            elif "authentication" in message or "auth failed" in message:
                status = HealthStatus.AUTHENTICATION_FAILED
            elif "connection" in message or "refused" in message or "unreachable" in message:
                status = HealthStatus.UNREACHABLE
            else:
                status = HealthStatus.OFFLINE
            logger.debug("SSH probe failed for host=%s: %s", config.host, exc)
            return {
                "health_status": status,
                "latency_ms": None,
                "error_message": str(exc),
            }

    @staticmethod
    def check_connectivity(config: SSHConfig) -> bool:
        """Lightweight SSH reachability check (connect/disconnect only, no remote commands)."""
        return SSHService.probe_connectivity(config)["health_status"] == "online"

    @staticmethod
    def _human_ssh_error(exc: Exception, host: str, port: int) -> str:
        """Translate a raw SSH/socket exception into a clear user-facing message."""
        import socket as _socket

        msg = str(exc).lower()

        if isinstance(exc, paramiko.AuthenticationException):
            return (
                f"Authentication failed for host {host}:{port}. "
                "Check the SSH username and password (or private key)."
            )
        if isinstance(exc, (TimeoutError, _socket.timeout)) or "timed out" in msg:
            return (
                f"Connection timed out while reaching {host}:{port}. "
                "The server may be unreachable or firewalled."
            )
        if isinstance(exc, ConnectionRefusedError) or "connection refused" in msg:
            return (
                f"Connection refused by {host}:{port}. "
                "SSH service may not be running or port {port} is blocked.".replace("{port}", str(port))
            )
        if isinstance(exc, _socket.gaierror) or "name or service not known" in msg or "nodename nor servname" in msg:
            return (
                f"Cannot resolve hostname '{host}'. "
                "Check that the IP address or hostname is correct."
            )
        if "no route to host" in msg or isinstance(exc, OSError) and "unreachable" in msg:
            return (
                f"Host {host} is unreachable. "
                "Verify the server is online and the network path is open."
            )
        if "authentication" in msg or "auth" in msg:
            return (
                f"Authentication failed for host {host}:{port}. "
                "Check the SSH username and credentials."
            )
        if "ssh" in msg and "not available" in msg:
            return f"SSH service unavailable on {host}:{port}."
        # Fallback: include the raw message but prefix it clearly
        return f"SSH connection to {host}:{port} failed: {exc}"

    @staticmethod
    def test_config(config: SSHConfig) -> dict[str, Any]:
        """Verify SSH connectivity via Paramiko and return latency, OS, and status."""
        started = datetime.now(timezone.utc)
        try:
            client = SSHClient(config)
            client.connect(max_retries=2)
            hostname_lines = client.run_remote_command("hostname")
            os_lines = client.run_remote_command("uname -s 2>/dev/null || cat /etc/os-release 2>/dev/null | head -1")
            client.disconnect()
            latency_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
            detected_os = SSHService._parse_os_hint(os_lines)
            return {
                "success": True,
                "connected": True,
                "message": "SSH connection successful.",
                "latency_ms": latency_ms,
                "hostname": hostname_lines[0] if hostname_lines else config.host,
                "operating_system": detected_os,
            }
        except Exception as exc:
            friendly = SSHService._human_ssh_error(exc, config.host, config.port)
            logger.warning("SSH test failed for host=%s port=%s: %s", config.host, config.port, exc)
            return {
                "success": False,
                "connected": False,
                "message": friendly,
                "latency_ms": None,
                "hostname": None,
                "operating_system": None,
            }

    @staticmethod
    def _parse_os_hint(lines: list[str]) -> str | None:
        if not lines:
            return None
        raw = lines[0].strip()
        if raw.startswith("NAME="):
            return raw.split("=", 1)[-1].strip('"').split()[0]
        return raw.lower() if raw else None

    @staticmethod
    def test_connection(server: Server) -> dict[str, Any]:
        """Test SSH using stored server credentials."""
        config = SSHService.config_from_server(server)
        return SSHService.test_config(config)

    @staticmethod
    def test_credentials(
        *,
        host: str,
        port: int,
        username: str,
        authentication_type: str,
        password: str | None = None,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        """Test SSH before persisting server credentials."""
        config = SSHService.config_from_credentials(
            host=host,
            port=port,
            username=username,
            authentication_type=authentication_type,
            password=password,
            private_key=private_key,
        )
        return SSHService.test_config(config)

    @staticmethod
    def session_for_server(server: Server):
        """Context manager yielding connected SSHClient for a server."""
        config = SSHService.config_from_server(server)
        return ssh_session(config)
