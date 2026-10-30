"""SSH connection service — credentials always from database, never from .env."""

from __future__ import annotations

import socket
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Iterable

import paramiko

from backend.collector.config import SSHConfig
from backend.collector.log_sources import DEFAULT_LOG_SOURCES, LOG_SOURCE_CATALOG
from backend.collector.ssh_client import SSHClient, load_private_key, ssh_session
from backend.core.encryption import CredentialDecryptionError, decrypt_secret
from backend.core.logging import get_logger
from backend.database.models import Server
from backend.health.status import HealthStatus

logger = get_logger(__name__)

DIAG_SUCCESS = "SUCCESS"
DIAG_NETWORK_ERROR = "NETWORK_ERROR"
DIAG_SSH_TIMEOUT = "SSH_TIMEOUT"
DIAG_AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
DIAG_COMMAND_EXECUTION_FAILED = "COMMAND_EXECUTION_FAILED"
DIAG_CREDENTIAL_ERROR = "CREDENTIAL_ERROR"
DIAG_SSH_PROTOCOL_ERROR = "SSH_PROTOCOL_ERROR"

_HEALTH_TO_DIAGNOSTIC = {
    HealthStatus.AUTHENTICATION_FAILED: DIAG_AUTHENTICATION_FAILED,
    HealthStatus.CREDENTIAL_ERROR: DIAG_CREDENTIAL_ERROR,
    HealthStatus.TIMEOUT: DIAG_SSH_TIMEOUT,
    HealthStatus.UNREACHABLE: DIAG_NETWORK_ERROR,
    HealthStatus.OFFLINE: DIAG_NETWORK_ERROR,
}


def root_cause(exc: BaseException) -> BaseException:
    """Unwrap the generic ConnectionError raised by SSHClient.connect retries."""
    current = exc
    seen: set[int] = set()
    while (
        type(current) is ConnectionError
        and current.__cause__ is not None
        and id(current) not in seen
    ):
        seen.add(id(current))
        current = current.__cause__
    return current


def classify_ssh_exception(exc: BaseException) -> str:
    """Map an SSH/credential exception to a precise HealthStatus value."""
    cause = root_cause(exc)
    message = str(cause).lower()
    if isinstance(cause, CredentialDecryptionError):
        return HealthStatus.CREDENTIAL_ERROR
    if isinstance(cause, paramiko.AuthenticationException):
        return HealthStatus.AUTHENTICATION_FAILED
    if isinstance(cause, (TimeoutError, socket.timeout)):
        return HealthStatus.TIMEOUT
    if isinstance(cause, paramiko.SSHException):
        if "authentication" in message or "auth failed" in message:
            return HealthStatus.AUTHENTICATION_FAILED
        if "timed out" in message or "timeout" in message:
            return HealthStatus.TIMEOUT
        return HealthStatus.ERROR
    if isinstance(cause, OSError):
        if "timed out" in message or "timeout" in message:
            return HealthStatus.TIMEOUT
        return HealthStatus.UNREACHABLE
    if isinstance(cause, ValueError):
        return HealthStatus.CREDENTIAL_ERROR
    if "timed out" in message or "timeout" in message:
        return HealthStatus.TIMEOUT
    if "authentication" in message or "auth failed" in message:
        return HealthStatus.AUTHENTICATION_FAILED
    if "connection" in message or "refused" in message or "unreachable" in message:
        return HealthStatus.UNREACHABLE
    return HealthStatus.OFFLINE


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
            load_private_key(key_content)
            return SSHConfig(
                host=server.host,
                username=server.username,
                port=server.port,
                private_key=key_content,
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
            load_private_key(private_key)
            return SSHConfig(host=host, username=username, port=port, private_key=private_key)
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
    def probe_connectivity(config: SSHConfig) -> dict[str, Any]:
        """Lightweight SSH probe returning health status, latency, and error details."""
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
        except Exception as exc:
            status = classify_ssh_exception(exc)
            logger.debug("SSH probe failed for host=%s status=%s: %s", config.host, status, root_cause(exc))
            return {
                "health_status": status,
                "latency_ms": None,
                "error_message": SSHService._human_ssh_error(exc, config.host, config.port),
            }

    @staticmethod
    def check_connectivity(config: SSHConfig) -> bool:
        """Lightweight SSH reachability check (connect/disconnect only, no remote commands)."""
        return SSHService.probe_connectivity(config)["health_status"] == "online"

    @staticmethod
    def _human_ssh_error(exc: Exception, host: str, port: int) -> str:
        """Translate a raw SSH/socket exception into a clear user-facing message."""
        import socket as _socket

        exc = root_cause(exc)
        msg = str(exc).lower()

        if isinstance(exc, CredentialDecryptionError):
            return str(exc)
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
            status = classify_ssh_exception(exc)
            logger.warning(
                "SSH test failed for host=%s port=%s status=%s: %s",
                config.host,
                config.port,
                status,
                root_cause(exc),
            )
            return {
                "success": False,
                "connected": False,
                "message": friendly,
                "health_status": status,
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
        try:
            config = SSHService.config_from_server(server)
        except ValueError as exc:
            logger.warning("Stored credentials unusable for server=%s: %s", server.server_name, exc)
            return {
                "success": False,
                "connected": False,
                "message": str(exc),
                "health_status": HealthStatus.CREDENTIAL_ERROR,
                "latency_ms": None,
                "hostname": None,
                "operating_system": None,
            }
        return SSHService.test_config(config)

    @staticmethod
    def diagnose(
        config: SSHConfig,
        *,
        log_sources: Iterable[str] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Stepwise SSH diagnostic: TCP reachability, SSH auth, exec, then collection sources."""
        if timeout is not None:
            config = replace(config, timeout=float(timeout))
        steps: list[dict[str, Any]] = []

        def finish(result: str, message: str) -> dict[str, Any]:
            return {
                "result": result,
                "success": result == DIAG_SUCCESS,
                "host": config.host,
                "port": config.port,
                "username": config.username,
                "message": message,
                "steps": steps,
            }

        started = time.perf_counter()
        try:
            with socket.create_connection((config.host, config.port), timeout=config.timeout):
                pass
            steps.append({"step": "tcp_connect", "ok": True, "latency_ms": int((time.perf_counter() - started) * 1000)})
        except (TimeoutError, socket.timeout) as exc:
            steps.append({"step": "tcp_connect", "ok": False, "error": str(exc) or "timed out"})
            return finish(DIAG_SSH_TIMEOUT, f"TCP connect to {config.host}:{config.port} timed out. The host is powered off, on a different IP, or firewalled.")
        except OSError as exc:
            steps.append({"step": "tcp_connect", "ok": False, "error": str(exc)})
            return finish(DIAG_NETWORK_ERROR, SSHService._human_ssh_error(exc, config.host, config.port))

        client = SSHClient(config)
        try:
            client.connect(max_retries=1)
            steps.append({"step": "ssh_authenticate", "ok": True})
        except Exception as exc:
            status = classify_ssh_exception(exc)
            steps.append({"step": "ssh_authenticate", "ok": False, "health_status": status, "error": str(root_cause(exc))})
            client.disconnect()
            return finish(
                _HEALTH_TO_DIAGNOSTIC.get(status, DIAG_SSH_PROTOCOL_ERROR),
                SSHService._human_ssh_error(exc, config.host, config.port),
            )

        try:
            try:
                exit_status, lines, error_text = client.run_remote_command_status("echo defensync-ok", timeout=config.timeout)
            except Exception as exc:
                steps.append({"step": "exec_probe", "ok": False, "error": str(exc)})
                return finish(DIAG_COMMAND_EXECUTION_FAILED, f"SSH authenticated but remote command execution failed: {exc}")
            if exit_status != 0 or "defensync-ok" not in lines:
                steps.append({"step": "exec_probe", "ok": False, "exit_status": exit_status, "error": error_text})
                return finish(DIAG_COMMAND_EXECUTION_FAILED, "SSH authenticated but the remote shell did not execute commands.")
            steps.append({"step": "exec_probe", "ok": True})

            sources_report: list[dict[str, Any]] = []
            for key in sorted(set(log_sources or DEFAULT_LOG_SOURCES)):
                definition = LOG_SOURCE_CATALOG.get(key)
                if definition is None:
                    continue
                entry: dict[str, Any] = {"source": key, "type": definition.source_type}
                try:
                    if definition.source_type == "file":
                        _, probe, _ = client.run_remote_command_status(
                            f"if [ -r {definition.path} ]; then echo readable; "
                            f"elif [ -e {definition.path} ]; then echo permission_denied; else echo missing; fi",
                            timeout=config.timeout,
                        )
                        state = probe[0] if probe else "unknown"
                        entry.update({"path": definition.path, "state": state, "ok": state == "readable"})
                    else:
                        command = (definition.command or "").replace("{tail}", "5")
                        _, output, _ = client.run_remote_command_status(command, timeout=config.timeout)
                        entry.update({"lines": len(output), "ok": bool(output)})
                except Exception as exc:
                    entry.update({"ok": False, "error": str(exc)})
                sources_report.append(entry)
            steps.append({"step": "collection_sources", "ok": any(item.get("ok") for item in sources_report), "sources": sources_report})
            if not any(item.get("ok") for item in sources_report):
                return finish(DIAG_COMMAND_EXECUTION_FAILED, "SSH works but no configured log source returned data or was readable.")
            unavailable = [item["source"] for item in sources_report if not item.get("ok")]
            message = "SSH connectivity, authentication, and log collection commands succeeded."
            if unavailable:
                message += f" Unavailable on this host: {', '.join(unavailable)}."
            return finish(DIAG_SUCCESS, message)
        finally:
            client.disconnect()

    @staticmethod
    def diagnose_server(server: Server, *, timeout: float | None = None) -> dict[str, Any]:
        """Run diagnose() with stored credentials; credential problems are reported, not raised."""
        try:
            config = SSHService.config_from_server(server)
        except ValueError as exc:
            return {
                "result": DIAG_CREDENTIAL_ERROR,
                "success": False,
                "host": server.host,
                "port": server.port,
                "username": server.username,
                "message": str(exc),
                "steps": [{"step": "load_credentials", "ok": False, "error": str(exc)}],
            }
        report = SSHService.diagnose(config, timeout=timeout)
        report["steps"].insert(0, {"step": "load_credentials", "ok": True})
        return report

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
        try:
            config = SSHService.config_from_credentials(
                host=host,
                port=port,
                username=username,
                authentication_type=authentication_type,
                password=password,
                private_key=private_key,
            )
        except ValueError as exc:
            return {
                "success": False,
                "connected": False,
                "message": str(exc),
                "health_status": HealthStatus.CREDENTIAL_ERROR,
                "latency_ms": None,
                "hostname": None,
                "operating_system": None,
            }
        return SSHService.test_config(config)

    @staticmethod
    def session_for_server(server: Server):
        """Context manager yielding connected SSHClient for a server."""
        config = SSHService.config_from_server(server)
        return ssh_session(config)
