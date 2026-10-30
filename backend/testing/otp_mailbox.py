"""Local QA mailbox for completing the mandatory OTP sign-in against a running backend.

The backend under test delivers codes through its normal email channel; only its
SMTP settings point at this mailbox, supplied as process environment for the QA
run (never in .env, never in production):

    SMTP_HOST=127.0.0.1  SMTP_PORT=2525  SMTP_SECURITY=none  SMTP_FROM=defensync-qa@localhost

SMTP_SECURITY=none is accepted by the backend only for a localhost relay, and this
mailbox binds to 127.0.0.1 only. Captured codes stay in memory and are never printed.
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import threading
import time
from dataclasses import dataclass
from email import message_from_bytes
from email.policy import default as default_policy
from typing import Any, Callable

QA_SMTP_HOST = "127.0.0.1"
QA_SMTP_PORT = int(os.getenv("QA_SMTP_PORT", "2525"))
BACKEND_SMTP_HINT = (
    f"Start the backend under test with SMTP_HOST={QA_SMTP_HOST} SMTP_PORT={QA_SMTP_PORT} "
    "SMTP_SECURITY=none SMTP_FROM=defensync-qa@localhost (process environment for the QA run only)."
)

_CODE_PATTERN = re.compile(r"Your verification code is:\s*(\d{6})\b")
_ADDRESS_PATTERN = re.compile(r"<([^>]*)>")
_MAX_MESSAGE_BYTES = 256 * 1024

Request = Callable[..., tuple[int, Any]]


class QALoginError(AssertionError):
    """Sign-in could not be completed. Messages never contain a code or token."""


@dataclass
class _Delivery:
    received_at: float
    recipients: tuple[str, ...]
    code: str


class OTPMailbox:
    """Minimal SMTP receiver that keeps only the OTP extracted from each message."""

    def __init__(self, host: str = QA_SMTP_HOST, port: int = QA_SMTP_PORT) -> None:
        self.host = host
        self.port = port
        self._deliveries: list[_Delivery] = []
        self._ready = threading.Condition()
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    def __repr__(self) -> str:
        return f"OTPMailbox({self.host}:{self.port})"

    def __enter__(self) -> "OTPMailbox":
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def start(self) -> "OTPMailbox":
        mailbox = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                mailbox._session(self.rfile, self.wfile)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = False
            daemon_threads = True

        try:
            self._server = Server((self.host, self.port), Handler)
        except OSError as exc:
            raise QALoginError(f"QA mailbox could not listen on {self.host}:{self.port} ({exc.strerror or exc}). Set QA_SMTP_PORT to a free port.") from None
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, name="qa-otp-mailbox", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        with self._ready:
            self._deliveries.clear()

    def wait_for_code(self, *, since: float, recipient: str | None = None, timeout: float = 20.0) -> str | None:
        """Consume the newest code delivered after `since` (time.monotonic) to `recipient`, if any."""
        wanted = recipient.lower() if recipient else None
        deadline = time.monotonic() + timeout
        with self._ready:
            while True:
                for delivery in reversed(self._deliveries):
                    if delivery.received_at >= since and (wanted is None or wanted in delivery.recipients):
                        self._deliveries.remove(delivery)
                        return delivery.code
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._ready.wait(remaining)

    def _session(self, rfile, wfile) -> None:
        def reply(line: str) -> None:
            wfile.write(f"{line}\r\n".encode("ascii"))
            wfile.flush()

        recipients: list[str] = []
        reply("220 defensync-qa-mailbox ready")
        while True:
            raw = rfile.readline(4096)
            if not raw:
                return
            command = raw.decode("ascii", "replace").strip()
            verb = command[:4].upper()
            if verb in {"EHLO", "HELO"}:
                reply("250 defensync-qa-mailbox")
            elif verb == "MAIL":
                recipients = []
                reply("250 OK")
            elif verb == "RCPT":
                address = _ADDRESS_PATTERN.search(command)
                recipients.append(address.group(1).lower() if address else "")
                reply("250 OK")
            elif verb == "DATA":
                reply("354 End data with <CR><LF>.<CR><LF>")
                self._store(self._read_data(rfile), recipients)
                reply("250 OK")
            elif verb in {"RSET", "NOOP"}:
                if verb == "RSET":
                    recipients = []
                reply("250 OK")
            elif verb == "QUIT":
                reply("221 Bye")
                return
            else:
                reply("502 Command not implemented")

    @staticmethod
    def _read_data(rfile) -> bytes:
        lines: list[bytes] = []
        size = 0
        while True:
            line = rfile.readline(_MAX_MESSAGE_BYTES)
            if not line or line.rstrip(b"\r\n") == b".":
                return b"".join(lines)
            if line.startswith(b".."):
                line = line[1:]
            size += len(line)
            if size <= _MAX_MESSAGE_BYTES:
                lines.append(line)

    def _store(self, data: bytes, recipients: list[str]) -> None:
        message = message_from_bytes(data, policy=default_policy)
        part = message.get_body(preferencelist=("plain",))
        match = _CODE_PATTERN.search(part.get_content() if part is not None else "")
        if not match:
            return
        with self._ready:
            self._deliveries.append(_Delivery(time.monotonic(), tuple(recipients), match.group(1)))
            self._ready.notify_all()


@dataclass
class LoginResult:
    challenge: dict[str, Any]
    access_token: str

    def __repr__(self) -> str:
        return f"LoginResult(delivery={self.challenge.get('delivery')!r}, access_token=<redacted>)"


def _problem(body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    code = body.get("code") or body.get("type") or ""
    message = body.get("error") or body.get("detail") or ""
    return f"{code} {message}".strip()


def login_with_otp(
    request: Request,
    email: str,
    password: str,
    *,
    mailbox: OTPMailbox | None = None,
    recipient: str | None = None,
    read_code: Callable[[dict[str, Any]], str] | None = None,
    timeout: float = 20.0,
) -> LoginResult:
    """Email + password -> OTP challenge -> code from the QA mailbox (or `read_code`) -> verify -> token.

    `request(method, path, data, form=...)` must return `(status_code, json_body)`.
    """
    if mailbox is None and read_code is None:
        raise QALoginError("No OTP source: pass a QA mailbox or a code reader.")

    started = time.monotonic()
    status, challenge = request("POST", "/api/v1/auth/token", {"email": email, "password": password}, form=True)
    _require_challenge("Password step", status, 200, challenge)
    return _complete_with_code(request, challenge, "/api/v1/auth/otp/verify", 200, started, mailbox, recipient, read_code, timeout)


def register_with_otp(
    request: Request,
    username: str,
    email: str,
    password: str,
    *,
    mailbox: OTPMailbox | None = None,
    recipient: str | None = None,
    read_code: Callable[[dict[str, Any]], str] | None = None,
    timeout: float = 20.0,
) -> LoginResult:
    """Register -> verification challenge (no account yet) -> emailed code -> /register/verify -> account + token."""
    if mailbox is None and read_code is None:
        raise QALoginError("No OTP source: pass a QA mailbox or a code reader.")

    started = time.monotonic()
    status, challenge = request("POST", "/api/v1/auth/register", {"username": username, "email": email, "password": password})
    _require_challenge("Registration step", status, 202, challenge)
    return _complete_with_code(request, challenge, "/api/v1/auth/register/verify", 201, started, mailbox, recipient, read_code, timeout)


def _require_challenge(step: str, status: int, expected: int, challenge: Any) -> None:
    if status != expected:
        hint = f" {BACKEND_SMTP_HINT}" if isinstance(challenge, dict) and challenge.get("code") in {"MFA_NOT_CONFIGURED", "OTP_DELIVERY_FAILED"} else ""
        raise QALoginError(f"{step} failed: HTTP {status} {_problem(challenge)}.{hint}")
    if not isinstance(challenge, dict) or challenge.get("otp_required") is not True or "access_token" in challenge:
        raise QALoginError(f"{step} did not return an OTP challenge; the backend under test predates mandatory MFA. Restart it.")


def _complete_with_code(
    request: Request,
    challenge: dict[str, Any],
    verify_path: str,
    verify_status: int,
    started: float,
    mailbox: OTPMailbox | None,
    recipient: str | None,
    read_code: Callable[[dict[str, Any]], str] | None,
    timeout: float,
) -> LoginResult:
    if not challenge.get("delivery"):
        status, sent = request("POST", "/api/v1/auth/otp/send", {"challenge_id": challenge["challenge_id"], "channel": "EMAIL"})
        if status != 200:
            raise QALoginError(f"OTP send failed: HTTP {status} {_problem(sent)}")
        challenge = sent

    if mailbox is not None:
        code = mailbox.wait_for_code(since=started, recipient=recipient, timeout=timeout)
        if code is None:
            raise QALoginError(f"No verification email reached the QA mailbox on {mailbox.host}:{mailbox.port}. {BACKEND_SMTP_HINT}")
    else:
        code = (read_code(challenge) or "").strip()
        if not code:
            raise QALoginError("No verification code entered.")

    if code in json.dumps(challenge):
        raise QALoginError("OTP challenge response exposed the verification code.")

    status, verified = request("POST", verify_path, {"challenge_id": challenge["challenge_id"], "otp": code})
    token = verified.get("access_token") if status == verify_status and isinstance(verified, dict) else None
    if not token:
        raise QALoginError(f"OTP verification failed: HTTP {status} {_problem(verified)}")
    return LoginResult(challenge=challenge, access_token=token)
