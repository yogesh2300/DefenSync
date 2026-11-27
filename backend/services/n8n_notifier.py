"""Outbound n8n webhook for significant DefenSync incidents (notification only).

DefenSync detects, correlates and stores incidents; n8n only formats and delivers a notification
(for example an email). Nothing here blocks accounts, changes resources or takes any other
action, and a delivery problem never affects incident storage.

Qualification uses the incident severity already produced by CorrelationService ("high" or
"critical"). An incident is sent when it is first stored with a qualifying severity or when an
existing incident is escalated to one; re-correlating or reading an incident that already had a
qualifying severity sends nothing. Delivery is a single POST with a short timeout, run on a
background thread for automatic notifications, without retries or a queue.

The webhook URL and optional auth token are secrets: they are never logged or returned by the API.
"""

from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping, Sequence

from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.core.logging import get_logger
from backend.database.models import User

logger = get_logger(__name__)

SCHEMA_VERSION = "defensync-incident-v1"
COLLECTION_SCHEMA_VERSION = "defensync-collection-n8n-v1"
QUALIFYING_SEVERITIES = ("critical", "high")
EVENT_CREATED = "incident.created"
EVENT_ESCALATED = "incident.escalated"
EVENT_TEST = "incident.test"
EVENT_COLLECTION_ALTERNATE = "collection.alternate_success"
COLLECTION_NOTICE = (
    "Collection notification only. DefenSync reports a successful log collection milestone; "
    "this does not claim a threat was detected and takes no automatic action."
)

STATUS_SENT = "sent"
STATUS_FAILED = "failed"
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_SKIPPED = "skipped"

REASON_TIMEOUT = "timeout"
REASON_NO_VERIFIED_RECIPIENT = "no_verified_recipient"
MAX_PER_RUN = 10
MAX_TEXT = 500
MAX_EVIDENCE = 10
USER_AGENT = "DefenSync-n8n-notifier/1"
NOTICE = (
    "Notification only. DefenSync has taken no automatic action; review the incident in DefenSync "
    "before responding."
)

_STATE_LOCK = threading.Lock()
_LAST_DELIVERY: dict[str, Any] | None = None
_EXECUTOR: ThreadPoolExecutor | None = None


def qualifies(severity: str | None) -> bool:
    return (severity or "").strip().lower() in QUALIFYING_SEVERITIES


def notification_event(previous_severity: str | None, new_severity: str | None, *, is_new: bool) -> str | None:
    """Event to send for one upsert, or None when nothing should be sent."""
    if not qualifies(new_severity):
        return None
    if is_new:
        return EVENT_CREATED
    return None if qualifies(previous_severity) else EVENT_ESCALATED


def _text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _normalize_recipient_emails(emails: Sequence[str] | None) -> list[str]:
    """Deduplicate already-verified addresses. Does not look up users or trust inbound input beyond format."""
    verified: list[str] = []
    for raw in emails or ():
        email = str(raw or "").strip()
        if email and "@" in email and email not in verified:
            verified.append(email)
    return verified


def configured_notification_recipient_emails(settings: Settings | None = None) -> list[str]:
    """Addresses from N8N_NOTIFICATION_RECIPIENT_EMAILS (comma-separated). Empty when unset."""
    settings = settings or get_settings()
    raw = getattr(settings, "N8N_NOTIFICATION_RECIPIENT_EMAILS", "") or ""
    return _normalize_recipient_emails([item.strip() for item in str(raw).split(",") if item.strip()])


def resolve_owner_recipient_emails(
    session: Session,
    *,
    owner_id: str | None,
    account_id: str | None,
) -> list[str]:
    """Owner-only delivery: registered email for a valid incident owner.

    Looks up the DefenSync user by `owner_id` only. When the incident has an
    `account_id`, the owner must belong to that account. Ambiguous, missing, or
    inconsistent ownership yields an empty list (caller must skip send).
    Never uses monitored `actor` strings or caller-supplied addresses.
    """
    owner_key = (owner_id or "").strip()
    if not owner_key:
        return []
    user = session.get(User, owner_key)
    if user is None:
        return []
    email = (getattr(user, "email", None) or "").strip()
    if "@" not in email:
        return []
    incident_account = (account_id or "").strip() or None
    if incident_account is not None:
        user_account = (getattr(user, "account_id", None) or "").strip() or None
        if user_account != incident_account:
            return []
    return [email]


def resolve_collection_recipient_emails(
    session: Session | None = None,
    *,
    owner_id: str | None = None,
    account_id: str | None = None,
    settings: Settings | None = None,
) -> list[str]:
    """Recipients for collection/demo n8n emails (n8n expression recipient_emails[0]).

    Order: N8N_NOTIFICATION_RECIPIENT_EMAILS, then collecting owner's registered email.
    Never invents addresses; empty list means do not dispatch.
    """
    recipients = list(configured_notification_recipient_emails(settings))
    if session is not None:
        for email in resolve_owner_recipient_emails(session, owner_id=owner_id, account_id=account_id):
            if email not in recipients:
                recipients.append(email)
    return recipients


def _escape_html(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _display_or_na(value: Any) -> str:
    if value is None:
        return "N/A"
    text = " ".join(str(value).split())
    return text if text else "N/A"


def _risk_score_display(value: Any) -> str:
    if value is None or value == "":
        return "N/A"
    try:
        return f"{int(value)}/100"
    except (TypeError, ValueError):
        return _display_or_na(value)


def _severity_display(value: Any) -> str:
    text = _display_or_na(value)
    if text == "N/A":
        return text
    return text[:1].upper() + text[1:].lower() if text.isupper() or text.islower() else text


def _email_table(rows: Sequence[tuple[str, Any]], *, banner_html: str) -> str:
    """Render label/value rows; never omit a requested label (use N/A)."""
    cells = "".join(
        f"<tr><td style='padding:6px 12px;color:#555;vertical-align:top;white-space:nowrap'>"
        f"{_escape_html(label)}</td>"
        f"<td style='padding:6px 12px;color:#111'>{_escape_html(_display_or_na(value))}</td></tr>"
        for label, value in rows
    )
    return (
        "<div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.45;color:#111'>"
        f"{banner_html}"
        f"<table style='border-collapse:collapse;margin-top:8px'>{cells}</table>"
        "</div>"
    )


EMAIL_FIELD_KEYS = (
    "label",
    "title",
    "severity",
    "environment",
    "risk_score",
    "confidence",
    "actor",
    "event_count",
    "status",
    "detected_activity",
    "operation",
    "target_resource",
    "security_analysis",
    "recommended_action",
    "incident_id",
    "collection_id",
    "event_timestamp",
)


def security_demo_email_fields(demo: Mapping[str, Any]) -> dict[str, str]:
    """Flat fields for n8n expressions and HTML. Matches collection `security_demo` keys."""
    risk_level = demo.get("risk_level")
    severity = demo.get("severity") or risk_level
    actor = demo.get("initiating_user") or demo.get("actor")
    status = demo.get("operation_result") or demo.get("status")
    title = demo.get("title") or "Suspicious Cloud Privilege Change"
    # Detected activity = title only; operation is its own row.
    analysis = demo.get("security_analysis") or demo.get("note")
    # One DEMO privilege event per collection notification.
    event_count = demo.get("event_count")
    if event_count is None and demo.get("simulated"):
        event_count = 1
    incident_id = demo.get("incident_id") or demo.get("event_id")
    return {
        # Email label is always explicit for simulated demos (UI may still use demo_label=DEMO).
        "label": "DEMO / SIMULATED" if demo.get("simulated") else _display_or_na(demo.get("demo_label")),
        "title": _display_or_na(title),
        "severity": _severity_display(severity),
        "environment": _display_or_na(demo.get("environment")),
        "risk_score": _risk_score_display(demo.get("risk_score")),
        "confidence": _display_or_na(demo.get("confidence")),
        "actor": _display_or_na(actor),
        "event_count": _display_or_na(event_count),
        "status": _display_or_na(status),
        "detected_activity": _display_or_na(title),
        "operation": _display_or_na(demo.get("operation")),
        "target_resource": _display_or_na(demo.get("target_resource")),
        "security_analysis": _display_or_na(analysis),
        "recommended_action": _display_or_na(demo.get("recommended_action")),
        "incident_id": _display_or_na(incident_id),
        "collection_id": _display_or_na(demo.get("collection_id")),
        "event_timestamp": _display_or_na(demo.get("event_timestamp")),
    }


def _security_alert_rows(fields: Mapping[str, str]) -> list[tuple[str, Any]]:
    """Label order for Send Email HTML — never omit a row (use N/A)."""
    return [
        ("Label", fields.get("label")),
        ("Severity", fields.get("severity")),
        ("Environment", fields.get("environment")),
        ("Risk Score", fields.get("risk_score")),
        ("Confidence", fields.get("confidence")),
        ("Actor", fields.get("actor")),
        ("Event Count", fields.get("event_count")),
        ("Status", fields.get("status")),
        ("Detected Activity", fields.get("detected_activity")),
        ("Operation", fields.get("operation")),
        ("Target", fields.get("target_resource")),
        ("Security Analysis", fields.get("security_analysis")),
        ("Recommended Action", fields.get("recommended_action")),
        ("Incident ID", fields.get("incident_id")),
        ("Collection ID", fields.get("collection_id")),
        ("Timestamp", fields.get("event_timestamp")),
    ]


def build_security_demo_email_html(demo: Mapping[str, Any]) -> str:
    """HTML body for collection/demo n8n emails. Every label has a value (or N/A)."""
    fields = security_demo_email_fields(demo)
    banner = (
        "<h2 style='margin:0 0 8px;font-size:18px'>DefenSync Security Alert</h2>"
        "<p><strong>DEMO / SIMULATED</strong> — DefenSync presentation telemetry. "
        "Not a live Azure attack and no Azure permissions were changed.</p>"
    )
    return _email_table(_security_alert_rows(fields), banner_html=banner)


def incident_email_fields(incident: Mapping[str, Any], *, demo: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Flat fields for real incident emails; optional DEMO overlay when presentation_records apply."""
    evidence = incident.get("evidence_summary") or incident.get("evidence") or []
    if isinstance(evidence, str):
        evidence = [evidence]
    detected = "; ".join(str(item) for item in list(evidence)[:5] if item) or incident.get("title")
    if demo and demo.get("simulated") and demo.get("title"):
        detected = demo.get("title")
    analysis = incident.get("explanation")
    if demo and demo.get("simulated") and not analysis:
        analysis = demo.get("note")
    recommendation = incident.get("recommendation") or (demo or {}).get("recommended_action")
    label = "DEMO / SIMULATED" if demo and demo.get("simulated") else "Security incident"
    actor = (demo or {}).get("initiating_user") if demo else None
    actor = actor or incident.get("actor")
    operation = (demo or {}).get("operation")
    target = (demo or {}).get("target_resource")
    collection_id = (demo or {}).get("collection_id")
    return {
        "label": label,
        "title": _display_or_na(incident.get("title")),
        "severity": _severity_display(incident.get("severity")),
        "environment": _display_or_na(incident.get("environment")),
        "risk_score": _risk_score_display(incident.get("risk_score")),
        "confidence": _display_or_na(incident.get("confidence")),
        "actor": _display_or_na(actor),
        "event_count": _display_or_na(incident.get("event_count")),
        "status": _display_or_na(incident.get("status") or (demo or {}).get("operation_result")),
        "detected_activity": _display_or_na(detected),
        "operation": _display_or_na(operation),
        "target_resource": _display_or_na(target),
        "security_analysis": _display_or_na(analysis),
        "recommended_action": _display_or_na(recommendation),
        "incident_id": _display_or_na(incident.get("incident_id")),
        "collection_id": _display_or_na(collection_id),
        "event_timestamp": _display_or_na(incident.get("end_time") or incident.get("start_time")),
    }


def build_incident_email_html(incident: Mapping[str, Any], *, demo: Mapping[str, Any] | None = None) -> str:
    """HTML for real (and presentation-linked) incident notifications."""
    fields = incident_email_fields(incident, demo=demo)
    if demo and demo.get("simulated"):
        banner = (
            "<h2 style='margin:0 0 8px;font-size:18px'>DefenSync Security Alert</h2>"
            "<p><strong>DEMO / SIMULATED</strong> — correlated presentation telemetry. "
            "Not a live Azure attack.</p>"
        )
    else:
        banner = (
            "<h2 style='margin:0 0 8px;font-size:18px'>DefenSync Security Alert</h2>"
            "<p><strong>Security incident</strong> — notification only; "
            "no automatic action was taken.</p>"
        )
    return _email_table(_security_alert_rows(fields), banner_html=banner)


def validate_email_fields(fields: Mapping[str, Any]) -> list[str]:
    """Return missing/blank field keys. Empty list means the template can render safely."""
    problems: list[str] = []
    for key in EMAIL_FIELD_KEYS:
        value = fields.get(key)
        if value is None or (isinstance(value, str) and not str(value).strip()):
            problems.append(key)
    return problems


def _security_demo_view(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Whitelist presentation / privilege-demo fields for n8n email templates. Never includes secrets."""
    if not isinstance(raw, Mapping) or not raw.get("simulated"):
        return None
    subject = _text(raw.get("email_subject"), 200)
    risk = raw.get("risk_score")
    risk_level = _text(raw.get("risk_level"), 40)
    view = {
        "simulated": True,
        "demo_label": _text(raw.get("demo_label"), 20) or "DEMO",
        "title": _text(raw.get("title"), 200) or "Suspicious Cloud Privilege Change",
        "system_name": _text(raw.get("system_name"), 80) or "DefenSync",
        "environment": _text(raw.get("environment"), 40) or "CLOUD",
        "operation": _text(raw.get("operation"), 240),
        "operation_result": _text(raw.get("operation_result"), 40) or "Failed",
        "initiating_user": _text(raw.get("initiating_user"), 120),
        "actor": _text(raw.get("initiating_user") or raw.get("actor"), 120),
        "target_resource": _text(raw.get("target_resource"), 120),
        "event_timestamp": raw.get("event_timestamp"),
        "risk_score": risk,
        "risk_level": risk_level,
        "severity": _text(raw.get("severity") or risk_level, 40),
        "confidence": raw.get("confidence"),  # intentionally often absent → N/A in email
        "event_count": 1,
        "event_type": _text(raw.get("event_type"), 80),
        "collection_id": _text(raw.get("collection_id"), 80),
        "status": _text(raw.get("status") or raw.get("operation_result"), 40) or "Failed",
        "recommended_action": _text(raw.get("recommended_action")),
        "email_subject": subject,
        "data_origin": _text(raw.get("data_origin"), 80),
        "note": _text(raw.get("note")),
    }
    cleaned = {key: value for key, value in view.items() if value is not None}
    # Keep confidence key absent when unset so HTML shows N/A without inventing a score.
    fields = security_demo_email_fields(cleaned)
    cleaned["email_fields"] = fields
    cleaned["email_html"] = build_security_demo_email_html(cleaned)
    return cleaned


def build_collection_payload(
    *,
    event_id: str,
    source_type: str,
    collection_id: str,
    sequence_number: int,
    completed_at: datetime | None,
    outcome: str,
    account_id: str | None = None,
    sent_at: datetime | None = None,
    security_demo: Mapping[str, Any] | None = None,
    recipient_emails: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Collection/demo webhook body for n8n.

    Always includes `notification.recipient_emails` (possibly empty) so the existing
    Send Email expression `{{$json.body.notification.recipient_emails[0]}}` resolves.
    No credentials, tokens, or raw logs.
    """
    recipients = _normalize_recipient_emails(recipient_emails)
    notification: dict[str, Any] = {"recipient_emails": recipients}
    demo = _security_demo_view(security_demo)
    if demo:
        # Collection webhook incident id = outbound event_id (not a correlated incident row).
        demo = {**demo, "incident_id": event_id, "event_id": event_id}
        fields = security_demo_email_fields(demo)
        demo["email_fields"] = fields
        demo["email_html"] = build_security_demo_email_html(demo)
        if demo.get("email_subject"):
            notification["suggested_subject"] = demo["email_subject"]
        notification["suggested_html"] = demo["email_html"]
        notification["email_fields"] = fields
        notification["suggested_body_fields"] = list(EMAIL_FIELD_KEYS)
    body: dict[str, Any] = {
        "schema_version": COLLECTION_SCHEMA_VERSION,
        "event": EVENT_COLLECTION_ALTERNATE,
        "event_id": event_id,
        "source_type": (source_type or "").strip().upper(),
        "collection_id": collection_id,
        "sequence_number": int(sequence_number),
        "completed_at": completed_at.isoformat() if isinstance(completed_at, datetime) else completed_at,
        "outcome": outcome,
        "sent_at": (sent_at or datetime.now(timezone.utc)).isoformat(),
        "notice": COLLECTION_NOTICE,
        "notification": notification,
    }
    account = (account_id or "").strip()
    if account:
        body["account_id"] = account
    if demo:
        body["security_demo"] = demo
    return body


def build_payload(
    incident: Mapping[str, Any],
    *,
    event: str,
    test: bool = False,
    sent_at: datetime | None = None,
    recipient_emails: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Stable, whitelisted notification body. Event IDs, raw log lines and tenant IDs are never included."""
    sources = [name.strip() for name in str(incident.get("source") or "").split(",") if name.strip()]
    evidence = incident.get("evidence") or []
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            evidence = [evidence]
    event_ids = incident.get("event_ids") or []
    demo = _security_demo_view(incident.get("security_demo") if isinstance(incident.get("security_demo"), Mapping) else None)
    incident_view = {
        "id": incident.get("id"),
        "incident_id": incident.get("incident_id"),
        "title": _text(incident.get("title"), 240),
        "environment": incident.get("environment"),
        "severity": (incident.get("severity") or "").upper() or None,
        "risk_score": incident.get("risk_score"),
        "confidence": incident.get("confidence"),
        "actor": _text(incident.get("actor"), 255),
        "sources": sources,
        "event_count": len(event_ids) if isinstance(event_ids, (list, tuple)) else None,
        "start_time": incident.get("start_time"),
        "end_time": incident.get("end_time"),
        "status": incident.get("status"),
        "evidence_summary": [_text(item, 240) for item in list(evidence)[:MAX_EVIDENCE]],
        "explanation": _text(incident.get("explanation")),
        "recommendation": _text(incident.get("recommendation")),
    }
    email_fields = incident_email_fields(incident_view, demo=demo)
    notification: dict[str, Any] = {
        "recipient_emails": _normalize_recipient_emails(recipient_emails),
        "email_fields": email_fields,
        "suggested_html": build_incident_email_html(incident_view, demo=demo),
    }
    if demo and demo.get("email_subject"):
        notification["suggested_subject"] = demo["email_subject"]
    elif incident_view.get("severity") and incident_view.get("title"):
        notification["suggested_subject"] = _text(
            f"DefenSync Security Alert — {incident_view['severity']} — {incident_view['title']}",
            200,
        )
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "event": event,
        "test": bool(test),
        "sent_at": (sent_at or datetime.now(timezone.utc)).isoformat(),
        "incident": incident_view,
        "notification": notification,
        "notice": NOTICE,
    }
    if demo:
        body["security_demo"] = demo
    return body


@dataclass
class DeliveryResult:
    status: str
    event: str | None = None
    incident_id: str | None = None
    http_status: int | None = None
    reason: str | None = None
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def delivered(self) -> bool:
        return self.status == STATUS_SENT

    def as_dict(self) -> dict[str, Any]:
        return {**asdict(self), "delivered": self.delivered}


def _record(result: DeliveryResult) -> DeliveryResult:
    global _LAST_DELIVERY
    with _STATE_LOCK:
        _LAST_DELIVERY = result.as_dict()
    return result


def last_delivery() -> dict[str, Any] | None:
    with _STATE_LOCK:
        return dict(_LAST_DELIVERY) if _LAST_DELIVERY else None


def _executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    with _STATE_LOCK:
        if _EXECUTOR is None:
            _EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="n8n-notify")
        return _EXECUTOR


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_open(request: urllib.request.Request, timeout: float) -> int:
    with _OPENER.open(request, timeout=timeout) as response:
        return int(response.status)


def _failure_reason(exc: BaseException) -> tuple[str, int | None]:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}", int(exc.code)
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return REASON_TIMEOUT, None
    if isinstance(exc, urllib.error.URLError):
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            return REASON_TIMEOUT, None
        return f"unreachable ({type(exc.reason).__name__})", None
    if isinstance(exc, OSError):
        return f"unreachable ({type(exc).__name__})", None
    return f"error ({type(exc).__name__})", None


class N8nNotifier:
    def __init__(
        self,
        url: str = "",
        *,
        timeout: float = 3.0,
        auth_header: str = "",
        auth_token: str = "",
        opener: Callable[[urllib.request.Request, float], int] | None = None,
        background: bool = True,
    ) -> None:
        self._url = (url or "").strip()
        self._timeout = max(0.5, min(float(timeout or 3.0), 10.0))
        self._auth_header = (auth_header or "").strip()
        self._auth_token = auth_token or ""
        self._open = opener or _default_open
        self._background = background

    @classmethod
    def from_settings(cls, settings: Settings | None = None, **kwargs: Any) -> "N8nNotifier":
        settings = settings or get_settings()
        return cls(
            settings.N8N_WEBHOOK_URL.get_secret_value(),
            timeout=settings.N8N_WEBHOOK_TIMEOUT_SECONDS,
            auth_header=settings.N8N_WEBHOOK_AUTH_HEADER,
            auth_token=settings.N8N_WEBHOOK_AUTH_TOKEN.get_secret_value(),
            **kwargs,
        )

    @property
    def configuration_error(self) -> str | None:
        if not self._url:
            return "N8N_WEBHOOK_URL is not set"
        parsed = urllib.parse.urlsplit(self._url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return "N8N_WEBHOOK_URL must be an http(s) URL"
        return None

    @property
    def configured(self) -> bool:
        return self.configuration_error is None

    def status(self, *, include_last_delivery: bool = False) -> dict[str, Any]:
        view = {
            "configured": self.configured,
            "reason": self.configuration_error,
            "schema_version": SCHEMA_VERSION,
            "collection_schema_version": COLLECTION_SCHEMA_VERSION,
            "qualifying_severities": [name.upper() for name in QUALIFYING_SEVERITIES],
            "timeout_seconds": self._timeout,
            "auth_header_configured": bool(self._auth_header and self._auth_token),
            "max_notifications_per_correlation": MAX_PER_RUN,
            "mode": "notification_only",
            "collection_alternate_trigger": {
                "event": EVENT_COLLECTION_ALTERNATE,
                "every": 2,
                "rule": "Every alternate successful LINUX/CLOUD collection (2, 4, 6, …) per tenant scope.",
            },
        }
        if include_last_delivery:
            view["last_delivery"] = last_delivery()
        return view

    def _request(self, payload: dict[str, Any]) -> urllib.request.Request:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if self._auth_header and self._auth_token:
            headers[self._auth_header] = self._auth_token
        body = json.dumps(payload, default=str).encode("utf-8")
        return urllib.request.Request(self._url, data=body, headers=headers, method="POST")

    def _post(self, payload: dict[str, Any], *, log_key: str) -> DeliveryResult:
        """One POST attempt for a prepared payload. Never raises; never logs secrets."""
        event = payload.get("event")
        error = self.configuration_error
        if error:
            logger.info("n8n notification not configured (%s); %s not sent", error, log_key)
            return _record(DeliveryResult(STATUS_NOT_CONFIGURED, event, log_key, reason=error))
        try:
            code = self._open(self._request(payload), self._timeout)
        except Exception as exc:  # noqa: BLE001 - delivery must never propagate
            reason, code = _failure_reason(exc)
            logger.warning("n8n notification failed: %s event=%s reason=%s", log_key, event, reason)
            return _record(DeliveryResult(STATUS_FAILED, event, log_key, http_status=code, reason=reason))
        if 200 <= code < 300:
            logger.info("n8n notification sent: %s event=%s http=%s", log_key, event, code)
            return _record(DeliveryResult(STATUS_SENT, event, log_key, http_status=code))
        reason = f"HTTP {code}"
        logger.warning("n8n notification failed: %s event=%s reason=%s", log_key, event, reason)
        return _record(DeliveryResult(STATUS_FAILED, event, log_key, http_status=code, reason=reason))

    def send(self, payload: dict[str, Any]) -> DeliveryResult:
        """One POST attempt for an incident notification. Never raises; the outcome is returned and logged without secrets."""
        event = payload.get("event")
        incident_id = (payload.get("incident") or {}).get("incident_id")
        notification = dict(payload.get("notification") or {})
        recipients = _normalize_recipient_emails(notification.get("recipient_emails"))
        if not recipients:
            logger.info("n8n notification skipped for incident %s (%s)", incident_id, REASON_NO_VERIFIED_RECIPIENT)
            return _record(
                DeliveryResult(STATUS_SKIPPED, event, incident_id, reason=REASON_NO_VERIFIED_RECIPIENT)
            )
        # Re-embed only the normalized list so a caller cannot smuggle extra addresses via raw payload mutation.
        # Preserve whitelisted template hints from build_payload (subject/html/flat email_fields).
        cleaned = {"recipient_emails": recipients}
        subject = _text(notification.get("suggested_subject"), 200)
        if subject:
            cleaned["suggested_subject"] = subject
        html = notification.get("suggested_html")
        if isinstance(html, str) and html.strip():
            cleaned["suggested_html"] = html
        email_fields = notification.get("email_fields")
        if isinstance(email_fields, Mapping) and email_fields:
            cleaned["email_fields"] = {
                str(key): _display_or_na(value) for key, value in email_fields.items()
            }
        payload = {**payload, "notification": cleaned}
        return self._post(payload, log_key=f"incident={incident_id}")

    def send_collection(self, payload: dict[str, Any]) -> DeliveryResult:
        """One POST for a collection/demo event. Requires notification.recipient_emails for n8n email nodes."""
        event_id = payload.get("event_id")
        collection_id = payload.get("collection_id")
        notification = dict(payload.get("notification") or {})
        recipients = _normalize_recipient_emails(notification.get("recipient_emails"))
        if not recipients:
            logger.info(
                "n8n collection notification skipped for %s (%s)",
                collection_id,
                REASON_NO_VERIFIED_RECIPIENT,
            )
            return _record(
                DeliveryResult(
                    STATUS_SKIPPED,
                    payload.get("event"),
                    f"collection={collection_id} event_id={event_id}",
                    reason=REASON_NO_VERIFIED_RECIPIENT,
                )
            )
        cleaned = {**notification, "recipient_emails": recipients}
        payload = {**payload, "notification": cleaned}
        return self._post(payload, log_key=f"collection={collection_id} event_id={event_id}")

    def _send_batch(self, payloads: list[dict[str, Any]]) -> list[DeliveryResult]:
        results: list[DeliveryResult] = []
        for index, payload in enumerate(payloads):
            result = self.send(payload)
            results.append(result)
            if result.status == STATUS_FAILED and result.http_status is None:
                remaining = payloads[index + 1:]
                if remaining:
                    logger.warning("n8n unavailable (%s); %d further incident notification(s) skipped", result.reason, len(remaining))
                results.extend(
                    DeliveryResult(STATUS_SKIPPED, item.get("event"), item["incident"].get("incident_id"), reason="n8n unavailable")
                    for item in remaining
                )
                break
        return results

    def notify_incidents(
        self,
        items: Iterable[tuple[Mapping[str, Any], str] | tuple[Mapping[str, Any], str, Sequence[str]]],
    ) -> list[DeliveryResult] | None:
        """Queue qualifying incidents for delivery. Returns results only when running inline.

        Each item is `(incident, event)` or `(incident, event, recipient_emails)`. Recipient
        emails must already be resolved server-side from DefenSync user records; items without
        a verified recipient are skipped and never POSTed.
        """
        payloads: list[dict[str, Any]] = []
        skipped: list[DeliveryResult] = []
        for item in items:
            if len(item) == 3:
                incident, event, emails = item  # type: ignore[misc]
            else:
                incident, event = item  # type: ignore[misc]
                emails = ()
            recipients = _normalize_recipient_emails(emails)
            incident_id = incident.get("incident_id") if isinstance(incident, Mapping) else None
            if not recipients:
                skipped.append(
                    DeliveryResult(STATUS_SKIPPED, event, incident_id, reason=REASON_NO_VERIFIED_RECIPIENT)
                )
                continue
            payloads.append(build_payload(incident, event=event, recipient_emails=recipients))
        if not payloads:
            if skipped:
                _record(skipped[-1])
            return skipped
        error = self.configuration_error
        if error:
            logger.info("n8n notification not configured (%s); %d qualifying incident(s) not sent", error, len(payloads))
            _record(DeliveryResult(STATUS_NOT_CONFIGURED, payloads[0]["event"], payloads[0]["incident"]["incident_id"], reason=error))
            configured = [
                DeliveryResult(STATUS_NOT_CONFIGURED, p["event"], p["incident"]["incident_id"], reason=error)
                for p in payloads
            ]
            return skipped + configured
        if len(payloads) > MAX_PER_RUN:
            logger.info("n8n: %d qualifying incidents; sending the %d highest-risk", len(payloads), MAX_PER_RUN)
            payloads = sorted(payloads, key=lambda p: -(p["incident"].get("risk_score") or 0))[:MAX_PER_RUN]
        if not self._background:
            return skipped + self._send_batch(payloads)
        try:
            _executor().submit(self._send_batch, payloads)
        except RuntimeError:
            logger.warning("n8n notification executor unavailable; %d incident notification(s) not sent", len(payloads))
        return None
