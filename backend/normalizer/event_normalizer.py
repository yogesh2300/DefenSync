"""Convert parsed log dictionaries into standardized security events."""

from __future__ import annotations

import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, tzinfo
from typing import Any, Iterable, Iterator, Protocol, Sequence

from backend.core.timestamps import SOURCE_EVENT, SOURCE_FALLBACK, collection_now, parse_occurrence

from backend.normalizer.event_types import (
    EventType,
    NormalizedSecurityEvent,
    category_for,
)
from backend.normalizer.severity import RiskScoreCalculator, SeverityLevel
from backend.parser.patterns import (
    PAM_FIELD,
    SECURE_INVALID_USER,
    SECURE_INVALID_USER_AUTH,
    SECURE_PAM_AUTH_FAILURE,
    SECURE_PAM_SESSION,
    SECURE_SU_SWITCH,
)

ParsedLog = dict[str, Any]

# Placeholders used when score_risk=False; RiskEngine replaces these values.
_UNSCORED_SEVERITY = "info"
_UNSCORED_RISK_SCORE = 0

# --- Secure log (/var/log/secure) patterns ---

_SECURE_FAILED_LOGIN = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"(?:for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+)?from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
_SECURE_SUCCESS_LOGIN = re.compile(
    r"Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)
# sudo's own audit line; the accompanying pam_unix(sudo:session) line is the same command.
_SECURE_SUDO_COMMAND = re.compile(
    r"^\s*(?:sudo:\s*)?(?P<user>[^\s:]+)\s*:\s*(?P<details>.*\bCOMMAND=(?P<cmd>.+))$",
    re.IGNORECASE,
)
_SUDO_TARGET_USER = re.compile(r"\bUSER=(?P<target>[^\s;]+)")
_SUDO_TTY = re.compile(r"\bTTY=(?P<tty>[^\s;]+)")
# Denials sudo reports on its COMMAND line. Wrong passwords are counted from the per-attempt
# pam_unix(sudo:auth) lines, so the "N incorrect password attempts" summary is not a second event.
_SUDO_DENIALS = ("user NOT in sudoers", "command not allowed", "a password is required")
_SUDO_PASSWORD_SUMMARY = "incorrect password attempt"

# PAM services that represent an interactive login, as opposed to su/sudo/cron/systemd-user.
LOGIN_SERVICES = frozenset({
    "sshd", "login", "remote", "cockpit", "xrdp-sesman", "lightdm", "sddm",
    "gdm-password", "gdm-autologin", "gdm-fingerprint", "gdm-smartcard",
})
_SUDO_SERVICES = frozenset({"sudo", "sudo-i"})
_SECURE_TIMESTAMP = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})$"
)

_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

_ROOT_USERS = frozenset({"root", "0"})


class ClassificationResult:
    """Outcome of classifying a parsed log entry."""

    __slots__ = ("event_type", "username", "source_ip", "is_root", "is_remote", "metadata")

    def __init__(
        self,
        event_type: EventType,
        *,
        username: str | None = None,
        source_ip: str | None = None,
        is_root: bool = False,
        is_remote: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.event_type = event_type
        self.username = username
        self.source_ip = source_ip
        self.is_root = is_root
        self.is_remote = is_remote
        self.metadata = metadata or {}


class LogClassifier(Protocol):
    """Interface for source-specific event classifiers."""

    def supports(self, parsed: ParsedLog) -> bool:
        """Return True when this classifier handles the parsed log source."""

    def classify(self, parsed: ParsedLog) -> ClassificationResult | None:
        """Classify a parsed log entry, or return None if unmatched."""


class SecureLogClassifier:
    """Classify events from parsed /var/log/secure entries."""

    def supports(self, parsed: ParsedLog) -> bool:
        return parsed.get("source") == "secure" and "parse_error" not in parsed

    def classify(self, parsed: ParsedLog) -> ClassificationResult | None:
        message = parsed.get("message")
        if not isinstance(message, str):
            return None

        failed = _SECURE_FAILED_LOGIN.search(message)
        if failed:
            username = failed.group("user")
            return ClassificationResult(
                EventType.FAILED_LOGIN,
                username=username,
                source_ip=failed.group("ip"),
                is_root=_is_root_user(username),
                is_remote=True,
                metadata={"program": parsed.get("program"), "pid": parsed.get("pid")},
            )

        success = _SECURE_SUCCESS_LOGIN.search(message)
        if success:
            username = success.group("user")
            return ClassificationResult(
                EventType.SUCCESSFUL_LOGIN,
                username=username,
                source_ip=success.group("ip"),
                is_root=_is_root_user(username),
                is_remote=True,
                metadata={"program": parsed.get("program"), "pid": parsed.get("pid")},
            )

        # Parsed by secure_events.parse_invalid_user but previously declined here, so probes
        # like "Invalid user …" / input_userauth_request never became stored security events.
        # "Failed password for invalid user …" is already handled above as Failed Login.
        invalid = SECURE_INVALID_USER.search(message)
        if invalid:
            username = invalid.group("user")
            return ClassificationResult(
                EventType.INVALID_USER,
                username=username,
                source_ip=invalid.group("ip"),
                is_root=_is_root_user(username),
                is_remote=True,
                metadata={"program": parsed.get("program"), "pid": parsed.get("pid")},
            )
        invalid_auth = SECURE_INVALID_USER_AUTH.search(message)
        if invalid_auth:
            username = invalid_auth.group("user")
            return ClassificationResult(
                EventType.INVALID_USER,
                username=username,
                is_root=_is_root_user(username),
                is_remote=False,
                metadata={"program": parsed.get("program"), "pid": parsed.get("pid")},
            )

        sudo = _SECURE_SUDO_COMMAND.search(message)
        if sudo:
            details = sudo.group("details")
            if _SUDO_PASSWORD_SUMMARY in details:
                return None
            target = _SUDO_TARGET_USER.search(details)
            tty = _SUDO_TTY.search(details)
            denial = next((reason for reason in _SUDO_DENIALS if reason in details), None)
            if denial:
                return ClassificationResult(
                    EventType.FAILED_PRIVILEGE_ESCALATION,
                    username=sudo.group("user"),
                    is_root=bool(target) and _is_root_user(target.group("target")),
                    metadata={**self._process(parsed), "mechanism": "sudo", "outcome": "failure",
                              "reason": denial, "cmd": sudo.group("cmd").strip(),
                              "target_user": target.group("target") if target else None,
                              "tty": tty.group("tty") if tty else None},
                )
            target_user = target.group("target") if target else "root"
            return ClassificationResult(
                EventType.SUDO_COMMAND,
                username=sudo.group("user"),
                is_root=_is_root_user(target_user),
                metadata={"program": parsed.get("program"), "pid": parsed.get("pid"),
                          "cmd": sudo.group("cmd").strip(), "target_user": target_user},
            )

        su = SECURE_SU_SWITCH.match(message)
        if su and parsed.get("program") == "su":
            target_user = su.group("target")
            failed = bool(su.group("failed"))
            return ClassificationResult(
                EventType.FAILED_PRIVILEGE_ESCALATION if failed else EventType.PRIVILEGE_ESCALATION,
                username=su.group("user"),
                is_root=_is_root_user(target_user),
                metadata={**self._process(parsed), "mechanism": "su", "outcome": "failure" if failed else "success",
                          "target_user": target_user, "tty": su.group("tty")},
            )

        auth_failure = SECURE_PAM_AUTH_FAILURE.match(message)
        if auth_failure:
            return self._pam_auth_failure(parsed, auth_failure.group("service"), auth_failure.group("fields"))

        pam_session = SECURE_PAM_SESSION.match(message)
        if pam_session and pam_session.group("service") in LOGIN_SERVICES:
            username = pam_session.group("user")
            opened = pam_session.group("action") == "opened"
            uid = pam_session.group("uid")
            return ClassificationResult(
                EventType.SESSION_OPENED if opened else EventType.SESSION_CLOSED,
                username=username,
                is_root=_is_root_user(username),
                metadata={**self._process(parsed), "service": pam_session.group("service"),
                          "uid": int(uid) if uid else None},
            )

        return None

    @staticmethod
    def _process(parsed: ParsedLog) -> dict[str, Any]:
        return {"program": parsed.get("program"), "pid": parsed.get("pid")}

    def _pam_auth_failure(self, parsed: ParsedLog, service: str, raw_fields: str) -> ClassificationResult | None:
        """One failed attempt. sshd and su have their own canonical failure lines, so theirs are not counted."""
        fields = dict(PAM_FIELD.findall(raw_fields))
        user = fields.get("user") or None
        rhost = fields.get("rhost") or None
        tty = fields.get("tty") or None
        if service in _SUDO_SERVICES:
            initiator = fields.get("ruser") or fields.get("logname") or user
            return ClassificationResult(
                EventType.FAILED_PRIVILEGE_ESCALATION,
                username=initiator,
                metadata={**self._process(parsed), "mechanism": "sudo", "outcome": "failure",
                          "reason": "authentication failure", "service": service, "tty": tty},
            )
        if service in LOGIN_SERVICES and service != "sshd":
            return ClassificationResult(
                EventType.FAILED_LOGIN,
                username=user,
                source_ip=rhost,
                is_root=_is_root_user(user),
                is_remote=bool(rhost),
                metadata={**self._process(parsed), "service": service, "tty": tty},
            )
        return None


class AuditLogClassifier:
    """Classify events from parsed audit.log entries."""

    _WRITE_SYSCALLS = frozenset({"open", "openat", "write", "writev", "pwrite64"})
    _MKDIR_SYSCALLS = frozenset({"mkdir", "mkdirat"})
    _PERM_SYSCALLS = frozenset({"chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown"})

    def supports(self, parsed: ParsedLog) -> bool:
        return parsed.get("source") == "audit" and "parse_error" not in parsed

    def classify(self, parsed: ParsedLog) -> ClassificationResult | None:
        audit_type = parsed.get("type")
        fields = parsed.get("fields")
        if not isinstance(audit_type, str) or not isinstance(fields, dict):
            return None

        username = _extract_audit_username(fields)
        source_ip = fields.get("addr") or None
        is_root = _is_root_user(username) or fields.get("uid") in _ROOT_USERS
        metadata: dict[str, Any] = {
            "audit_type": audit_type,
            "pid": fields.get("pid"),
            "exe": fields.get("exe"),
        }

        if audit_type == "ADD_USER":
            return ClassificationResult(
                EventType.USER_CREATION,
                username=fields.get("acct") or username,
                source_ip=source_ip,
                is_root=is_root,
                is_remote=bool(source_ip),
                metadata={**metadata, "acct": fields.get("acct")},
            )

        if audit_type == "DEL_USER":
            return ClassificationResult(
                EventType.USER_DELETION,
                username=fields.get("acct") or username,
                source_ip=source_ip,
                is_root=is_root,
                is_remote=bool(source_ip),
                metadata={**metadata, "acct": fields.get("acct")},
            )

        if audit_type == "USER_ACCT":
            op = fields.get("op", "").lower()
            if "adding" in op or "add" in op:
                return ClassificationResult(
                    EventType.USER_CREATION,
                    username=fields.get("acct") or username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "op": fields.get("op")},
                )
            if "deleting" in op or "delete" in op:
                return ClassificationResult(
                    EventType.USER_DELETION,
                    username=fields.get("acct") or username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "op": fields.get("op")},
                )

        if self._is_sudo_event(audit_type, fields):
            return ClassificationResult(
                EventType.SUDO_COMMAND,
                username=username,
                source_ip=source_ip,
                is_root=is_root,
                metadata={**metadata, "cmd": fields.get("cmd") or fields.get("proctitle")},
            )

        if audit_type in {"USER_CMD", "EXECVE", "PROCTITLE"}:
            if self._is_sudo_event(audit_type, fields):
                return ClassificationResult(
                    EventType.SUDO_COMMAND,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "cmd": fields.get("cmd") or fields.get("proctitle")},
                )
            return ClassificationResult(
                EventType.COMMAND_EXECUTION,
                username=username,
                source_ip=source_ip,
                is_root=is_root,
                metadata={**metadata, "cmd": fields.get("cmd") or fields.get("proctitle")},
            )

        if audit_type == "PATH":
            nametype = fields.get("nametype", "").upper()
            if nametype == "CREATE":
                return ClassificationResult(
                    EventType.DIRECTORY_CREATION,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "name": fields.get("name"), "nametype": nametype},
                )
            if nametype in {"NORMAL", "DELETE"}:
                return ClassificationResult(
                    EventType.FILE_MODIFICATION,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "name": fields.get("name"), "nametype": nametype},
                )

        if audit_type == "SYSCALL":
            syscall = (fields.get("syscall") or fields.get("comm") or "").lower()
            nametype = fields.get("nametype", "").upper()

            if syscall in self._MKDIR_SYSCALLS or nametype == "CREATE":
                return ClassificationResult(
                    EventType.DIRECTORY_CREATION,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "syscall": syscall, "nametype": nametype},
                )

            if syscall in self._PERM_SYSCALLS:
                return ClassificationResult(
                    EventType.PERMISSION_CHANGE,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "syscall": syscall},
                )

            if syscall in self._WRITE_SYSCALLS or nametype == "NORMAL":
                return ClassificationResult(
                    EventType.FILE_MODIFICATION,
                    username=username,
                    source_ip=source_ip,
                    is_root=is_root,
                    metadata={**metadata, "syscall": syscall, "nametype": nametype},
                )

        return None

    @staticmethod
    def _is_sudo_event(audit_type: str, fields: dict[str, str]) -> bool:
        exe = (fields.get("exe") or "").lower()
        cmd = (fields.get("cmd") or fields.get("proctitle") or "").lower()
        comm = (fields.get("comm") or "").lower()
        return "sudo" in exe or "sudo" in cmd or comm == "sudo" or audit_type == "CRED_REFR"


class TimestampNormalizer(ABC):
    """Normalize timestamps from parsed logs to ISO-8601 UTC strings."""

    @abstractmethod
    def normalize(self, parsed: ParsedLog) -> str:
        """Return an ISO-8601 timestamp string."""


class DefaultTimestampNormalizer(TimestampNormalizer):
    """Normalize secure syslog and audit epoch timestamps to source occurrence time."""

    def __init__(self, collected_at: datetime | None = None, host_tz: tzinfo | None = None) -> None:
        self._collected_at = collected_at or collection_now()
        self._host_tz = host_tz

    def normalize(self, parsed: ParsedLog) -> str:
        occurrence = parse_occurrence(
            parsed.get("raw") or parsed.get("raw_log") or "",
            collected_at=self._collected_at,
            source_hint=str(parsed.get("source") or ""),
            explicit=parsed.get("timestamp"),
            host_tz=self._host_tz,
        )
        parsed["timestamp_source"] = occurrence.source
        parsed["timestamp_tz_basis"] = occurrence.tz_basis
        parsed["collection_timestamp"] = self._collected_at.isoformat()
        return occurrence.event_time.isoformat()


class EventNormalizer:
    """
    Convert parsed log dictionaries into NormalizedSecurityEvent instances.

    Classification and field normalization always run. Risk scoring is optional:
    set score_risk=False when a downstream RiskEngine owns scoring (pipeline path).

    Unrecognized or malformed entries are skipped (returns None per entry).
    """

    def __init__(
        self,
        classifiers: Sequence[LogClassifier] | None = None,
        risk_calculator: RiskScoreCalculator | None = None,
        timestamp_normalizer: TimestampNormalizer | None = None,
        default_hostname: str = "unknown",
        score_risk: bool = True,
    ) -> None:
        self._classifiers: tuple[LogClassifier, ...] = tuple(
            classifiers or (SecureLogClassifier(), AuditLogClassifier())
        )
        self._risk_calculator = risk_calculator or RiskScoreCalculator()
        self._timestamp_normalizer = timestamp_normalizer or DefaultTimestampNormalizer()
        self._default_hostname = default_hostname
        self._score_risk = score_risk

    def normalize(self, parsed: ParsedLog) -> NormalizedSecurityEvent | None:
        """Normalize a single parsed log dictionary."""
        if parsed.get("parse_error"):
            return None

        classification = self._classify(parsed)
        if classification is None:
            return None

        event_type = classification.event_type
        if self._score_risk:
            severity = self._risk_calculator.severity_for(event_type).value
            risk_score = self._risk_calculator.calculate(
                event_type,
                is_root=classification.is_root,
                is_remote=classification.is_remote,
            )
        else:
            severity = _UNSCORED_SEVERITY
            risk_score = _UNSCORED_RISK_SCORE

        hostname = str(parsed.get("hostname") or self._default_hostname)
        raw_log = str(parsed.get("raw", ""))

        return NormalizedSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._timestamp_normalizer.normalize(parsed),
            hostname=hostname,
            username=classification.username,
            source_ip=classification.source_ip,
            event_type=event_type,
            category=category_for(event_type),
            severity=severity,
            risk_score=risk_score,
            raw_log=raw_log,
            metadata={
                "source": parsed.get("source"),
                "path": parsed.get("path"),
                "line_number": parsed.get("line_number"),
                "is_root": classification.is_root,
                "is_remote": classification.is_remote,
                "timestamp_source": parsed.get("timestamp_source") or SOURCE_EVENT,
                "timestamp_tz_basis": parsed.get("timestamp_tz_basis"),
                "collection_timestamp": parsed.get("collection_timestamp"),
                **classification.metadata,
            },
        )

    def normalize_many(self, parsed_logs: Iterable[ParsedLog]) -> list[NormalizedSecurityEvent]:
        """Normalize a batch of parsed log dictionaries."""
        return [event for parsed in parsed_logs if (event := self.normalize(parsed)) is not None]

    def iter_normalize(self, parsed_logs: Iterable[ParsedLog]) -> Iterator[NormalizedSecurityEvent]:
        """Lazily normalize parsed logs, yielding only recognized events."""
        for parsed in parsed_logs:
            event = self.normalize(parsed)
            if event is not None:
                yield event

    def _classify(self, parsed: ParsedLog) -> ClassificationResult | None:
        for classifier in self._classifiers:
            if classifier.supports(parsed):
                return classifier.classify(parsed)
        return None


def _extract_audit_username(fields: dict[str, str]) -> str | None:
    for key in ("acct", "auid", "uid", "suser", "user"):
        value = fields.get(key)
        if value and value not in {"unset", "4294967295", "-1"}:
            if key in {"auid", "uid"} and value == "0":
                return "root"
            if key in {"auid", "uid"} and value.isdigit():
                continue
            return value
    return None


def _is_root_user(username: str | None) -> bool:
    return username is not None and username.lower() in _ROOT_USERS
