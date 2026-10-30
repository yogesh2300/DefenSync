"""Paramiko SSH client wrapper for remote log file access."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Generator, List, Optional

import io
import paramiko
import time

from backend.collector.config import SSHConfig

_KEY_TYPES = (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey)


def load_private_key(content: str) -> paramiko.PKey:
    """Parse an unencrypted OpenSSH/PEM private key in memory; raises ValueError if unusable."""
    for key_type in _KEY_TYPES:
        try:
            return key_type.from_private_key(io.StringIO(content))
        except paramiko.PasswordRequiredException as exc:
            raise ValueError("Passphrase-protected private keys are not supported.") from exc
        except (paramiko.SSHException, ValueError, TypeError, IndexError):
            continue
    raise ValueError("Private key could not be parsed (supported: Ed25519, ECDSA, RSA).")


class SSHClient:
    """Manages Paramiko SSH and SFTP sessions to a CentOS Stream VM."""

    def __init__(self, config: SSHConfig) -> None:
        self._config = config
        self._client: Optional[paramiko.SSHClient] = None
        self._sftp: Optional[paramiko.SFTPClient] = None

    def connect(self, *, max_retries: int = 3, retry_delay: float = 1.5) -> None:
        """Open SSH and SFTP connections with optional retry."""
        last_error: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                self._connect_once()
                return
            except Exception as exc:
                last_error = exc
                self.disconnect()
                if attempt < max_retries:
                    time.sleep(retry_delay)
        raise ConnectionError(f"SSH connection failed after {max_retries} attempts: {last_error}") from last_error

    def _connect_once(self) -> None:
        """Single SSH connection attempt."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self._config.host,
            "port": self._config.port,
            "username": self._config.username,
            "timeout": self._config.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }

        if self._config.private_key:
            connect_kwargs["pkey"] = load_private_key(self._config.private_key)
        elif self._config.private_key_path:
            key_path = Path(self._config.private_key_path)
            connect_kwargs["key_filename"] = str(key_path)
        else:
            connect_kwargs["password"] = self._config.password

        client.connect(**connect_kwargs)
        self._client = client
        self._sftp = client.open_sftp()

    def disconnect(self) -> None:
        """Close SFTP and SSH sessions."""
        if self._sftp is not None:
            self._sftp.close()
            self._sftp = None
        if self._client is not None:
            self._client.close()
            self._client = None

    def read_remote_lines(self, remote_path: str, tail_lines: Optional[int] = None) -> List[str]:
        """
        Read a remote log file line by line.

        When tail_lines is set, only the last N non-empty lines are returned.
        This avoids loading very large audit logs entirely into memory.
        """
        if self._sftp is None:
            raise RuntimeError("SSH client is not connected. Call connect() first.")

        try:
            handle = self._sftp.open(remote_path, "r")
        except FileNotFoundError:
            return []
        except OSError:
            return []

        with handle as remote_file:
            text_lines = [
                line.rstrip("\r\n")
                for line in remote_file.readlines()
                if line.strip()
            ]

        if tail_lines is not None and tail_lines > 0:
            return text_lines[-tail_lines:]
        return text_lines

    def run_remote_command(self, command: str, *, timeout: float = 30.0) -> list[str]:
        """Execute a read-only remote command and return non-empty output lines."""
        if self._client is None:
            raise RuntimeError("SSH client is not connected. Call connect() first.")
        _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        del _stdin, stderr
        output = stdout.read().decode("utf-8", errors="replace")
        return [line.rstrip("\r\n") for line in output.splitlines() if line.strip()]

    def run_remote_command_status(self, command: str, *, timeout: float = 30.0) -> tuple[int, list[str], str]:
        """Execute a remote command and return (exit_status, stdout lines, stderr text)."""
        if self._client is None:
            raise RuntimeError("SSH client is not connected. Call connect() first.")
        _stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        del _stdin
        output = stdout.read().decode("utf-8", errors="replace")
        error_text = stderr.read().decode("utf-8", errors="replace").strip()
        exit_status = stdout.channel.recv_exit_status()
        lines = [line.rstrip("\r\n") for line in output.splitlines() if line.strip()]
        return exit_status, lines, error_text

    @contextmanager
    def session(self) -> Generator["SSHClient", None, None]:
        """Context manager that connects on entry and disconnects on exit."""
        self.connect()
        try:
            yield self
        finally:
            self.disconnect()


@contextmanager
def ssh_session(config: SSHConfig) -> Generator[SSHClient, None, None]:
    """Convenience context manager for a configured SSH session."""
    client = SSHClient(config)
    with client.session():
        yield client
