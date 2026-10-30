"""OTP delivery providers. Providers never log or return the code they deliver."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Callable

from backend.core.config import Settings

CHANNEL_EMAIL = "EMAIL"
CHANNEL_SMS = "SMS"

SMTP_TIMEOUT_SECONDS = 15
SMTP_SECURITY_MODES = {"starttls", "ssl", "none"}
_LOCAL_SMTP_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OTPDeliveryError(Exception):
    """Delivery failed. `code` is safe to surface; provider error text is deliberately dropped."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class OTPProvider:
    channel: str = ""

    def status(self) -> dict[str, Any]:
        reason = self.unavailable_reason()
        return {"channel": self.channel, "configured": reason is None, "reason": reason}

    def unavailable_reason(self) -> str | None:
        raise NotImplementedError

    def destination_for(self, user: Any) -> str | None:
        raise NotImplementedError

    def mask(self, destination: str) -> str:
        raise NotImplementedError

    def send(self, destination: str, code: str, expires_minutes: int) -> None:
        raise NotImplementedError


class EmailOTPProvider(OTPProvider):
    channel = CHANNEL_EMAIL

    def __init__(self, settings: Settings, smtp_factory: Callable[..., Any] | None = None) -> None:
        self._host = (settings.SMTP_HOST or "").strip()
        self._port = int(settings.SMTP_PORT)
        self._username = (settings.SMTP_USERNAME or "").strip()
        secret = settings.SMTP_PASSWORD
        self._password = secret.get_secret_value() if secret is not None else ""
        self._sender = (settings.SMTP_FROM or "").strip()
        self._security = (settings.SMTP_SECURITY or "starttls").strip().lower()
        self._smtp_factory = smtp_factory

    def __repr__(self) -> str:
        return "EmailOTPProvider(<redacted>)"

    def unavailable_reason(self) -> str | None:
        if not self._host or not self._sender:
            return "Email provider not configured"
        if self._security not in SMTP_SECURITY_MODES:
            return "Email provider misconfigured (SMTP_SECURITY)"
        if self._security == "none" and self._host.lower() not in _LOCAL_SMTP_HOSTS:
            return "Email provider misconfigured (unencrypted SMTP is only allowed to a local relay)"
        if self._username and not self._password:
            return "Email provider misconfigured (SMTP_PASSWORD missing)"
        return None

    def destination_for(self, user: Any) -> str | None:
        email = (getattr(user, "email", None) or "").strip()
        return email if "@" in email else None

    def mask(self, destination: str) -> str:
        local, _, domain = destination.partition("@")
        return f"{local[:1]}***@{domain}" if local else f"***@{domain}"

    def send(self, destination: str, code: str, expires_minutes: int) -> None:
        message = EmailMessage()
        message["Subject"] = "DefenSync verification code"
        message["From"] = self._sender
        message["To"] = destination
        message.set_content(
            "DefenSync verification code\n\n"
            f"Your verification code is: {code}\n\n"
            f"This code expires in {expires_minutes} minutes.\n\n"
            "If you did not attempt to sign in, ignore this email.\n"
        )
        try:
            with self._connect() as client:
                if self._security == "starttls":
                    client.starttls(context=ssl.create_default_context())
                if self._username:
                    client.login(self._username, self._password)
                client.send_message(message)
        except smtplib.SMTPAuthenticationError:
            raise OTPDeliveryError("EMAIL_AUTH_FAILED") from None
        except (smtplib.SMTPException, OSError):
            raise OTPDeliveryError("EMAIL_UNAVAILABLE") from None

    def _connect(self):
        if self._smtp_factory is not None:
            return self._smtp_factory(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS)
        if self._security == "ssl":
            return smtplib.SMTP_SSL(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS, context=ssl.create_default_context())
        return smtplib.SMTP(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS)


class SMSOTPProvider(OTPProvider):
    """Configuration-driven SMS delivery. No SMS gateway is implemented yet, so it is never offered."""

    channel = CHANNEL_SMS
    IMPLEMENTATIONS: dict[str, Callable[[str, str], None]] = {}

    def __init__(self, settings: Settings) -> None:
        self._provider = (settings.SMS_PROVIDER or "").strip().lower()

    def unavailable_reason(self) -> str | None:
        if not self._provider or self._provider not in self.IMPLEMENTATIONS:
            return "SMS provider not configured"
        return None

    def destination_for(self, user: Any) -> str | None:
        phone = (getattr(user, "phone_number", None) or "").strip()
        return phone or None

    def mask(self, destination: str) -> str:
        digits = "".join(ch for ch in destination if ch.isdigit())
        prefix = destination.split()[0] if destination.startswith("+") and " " in destination else ""
        return f"{prefix} ******{digits[-4:]}".strip()

    def send(self, destination: str, code: str, expires_minutes: int) -> None:
        sender = self.IMPLEMENTATIONS.get(self._provider)
        if sender is None:
            raise OTPDeliveryError("SMS_NOT_CONFIGURED")
        sender(destination, f"DefenSync verification code: {code}. Expires in {expires_minutes} minutes.")
