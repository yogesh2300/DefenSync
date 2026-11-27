"""End-to-end event processing pipeline orchestration."""

from __future__ import annotations

import re
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.collector.config import SSHConfig
from backend.collector.journal import JournalBatch, JournalPosition
from backend.collector.log_sources import DEFAULT_LOG_SOURCES
from backend.core.logging import get_logger
from backend.core.privacy import redact_secrets
from backend.core.timestamps import (
    SOURCE_EVENT,
    SOURCE_FALLBACK,
    SOURCE_SNAPSHOT,
    TZ_COLLECTION_CLOCK,
    ParsedOccurrence,
    collection_now,
    ensure_aware,
    login_hour_from,
    parse_occurrence,
    resolve_host_timezone,
)
from backend.normalizer.event_types import (
    RECORD_ORIGIN_COLLECTOR,
    RECORD_ORIGIN_SOURCE_OBSERVED,
    RECORD_SECURITY_EVENT,
    RECORD_SYSTEM_EVENT,
    RECORD_SYSTEM_SNAPSHOT,
    EventType,
    NormalizedSecurityEvent,
    category_for,
)
from backend.parser.login_history import parse_login_history_line
from backend.services.collector_service import CollectorService
from backend.services.ingestion_service import IngestionService
from backend.services.transform_service import DECLINED_BY_NORMALIZER, TransformService

logger = get_logger(__name__)

SNAPSHOT_SOURCES = frozenset({"uptime", "free", "df", "ps", "ss", "top", "hostnamectl", "uname", "who", "w"})
LOGIN_HISTORY_SOURCES = frozenset({"last", "lastb"})
# wtmp entries for these names are system boot/shutdown records, not user logins.
LOGIN_HISTORY_PSEUDO_USERS = frozenset({"reboot", "shutdown", "runlevel"})
# Header/footer lines that describe the output rather than a session or login.
NON_RECORD_LINES = {
    "w": re.compile(r"\s*(?:\d{1,2}:\d{2}:\d{2}\s+up\b|USER\s+TTY\b)"),
    "last": re.compile(r"\s*wtmp begins\b"),
    "lastb": re.compile(r"\s*btmp begins\b"),
}
COLLECTOR_AUTH_EVENT_TYPES = frozenset({EventType.SUCCESSFUL_LOGIN, EventType.FAILED_LOGIN})
COLLECTOR_ORIGIN_BASIS = "configured_ssh_user+collector_source_ip"
COLLECTOR_SESSION_BASIS = "same_journal_session_as_collector_login"
SESSION_EVENT_TYPES = frozenset({EventType.SUCCESSFUL_LOGIN, EventType.SESSION_OPENED, EventType.SESSION_CLOSED})
# PAM opens the session right after sshd/gdm accepts the login, in the same process.
LOGIN_TO_SESSION_MAX_USEC = 120 * 1_000_000
SESSION_DURATION_BASIS = "journal_session_open_close"
LOGIN_HISTORY_COMMANDS = {"last": "last -F", "lastb": "lastb -F"}
_SESSION_ORDER = {
    str(EventType.SUCCESSFUL_LOGIN): 0, str(EventType.SESSION_OPENED): 1, str(EventType.SESSION_CLOSED): 2,
}


def tag_record_origin(
    events: list[NormalizedSecurityEvent],
    *,
    collector_ip: str | None,
    collector_user: str | None,
) -> list[NormalizedSecurityEvent]:
    """Mark sshd authentication events caused by DefenSync's own SSH sessions.

    Health probes and collection sessions authenticate as the configured SSH user from
    the address the host reports in $SSH_CONNECTION. A person logging in as that same
    account from that same address is indistinguishable here and is tagged too.
    """
    if not collector_ip or not collector_user:
        return events
    tagged = []
    for event in events:
        if (
            event.event_type in COLLECTOR_AUTH_EVENT_TYPES
            and event.username == collector_user
            and event.source_ip == collector_ip
        ):
            event = replace(event, metadata={
                **event.metadata,
                "record_origin": RECORD_ORIGIN_COLLECTOR,
                "record_origin_basis": COLLECTOR_ORIGIN_BASIS,
            })
        tagged.append(event)
    return tagged


def annotate_journal_events(
    events: list[NormalizedSecurityEvent],
    entries: dict[str, dict[str, Any]] | None,
) -> list[NormalizedSecurityEvent]:
    """Attach journal boot/time to events read from journald, and a session id for login/session lines.

    The session id is boot + program + PID: sshd-session/gdm keep one process for the
    login, the PAM session open and its close, and the boot id rules out PID reuse.
    """
    if not entries:
        return events
    annotated = []
    for event in events:
        entry = entries.get(event.raw_log) or entries.get(event.raw_log.strip())
        if entry is None:
            annotated.append(event)
            continue
        metadata = {
            **event.metadata,
            "log_source": "journalctl",
            "boot_id": entry.get("boot_id"),
            "journal_realtime_usec": entry.get("realtime_usec"),
        }
        program = str(event.metadata.get("program") or entry.get("program") or "").rstrip("]")
        pid = event.metadata.get("pid") or entry.get("pid")
        if event.event_type in SESSION_EVENT_TYPES and entry.get("boot_id") and program and pid:
            metadata["session_id"] = f"{entry['boot_id']}:{program}:{pid}"
        annotated.append(replace(event, metadata=metadata))
    return annotated


def _journal_time(realtime_usec: int) -> str:
    """Session boundary at the journal's microsecond precision (event_time keeps the line's seconds)."""
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=realtime_usec)).isoformat()


def _utc_iso(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return ensure_aware(value).isoformat()
    try:
        return ensure_aware(datetime.fromisoformat(str(value).replace("Z", "+00:00"))).isoformat()
    except ValueError:
        return None


class PipelineService:
    """
    Orchestrate collection, transformation, and persistence of security events.

    Collect -> Parse -> Normalize -> Risk Score -> Store

    Persistence is delegated to IngestionService; this class does not
    perform direct database writes.
    """

    def __init__(
        self,
        session: Session,
        *,
        collector_service: CollectorService | None = None,
        transform_service: TransformService | None = None,
        ingestion_service: IngestionService | None = None,
    ) -> None:
        self._session = session
        self._collector = collector_service or CollectorService()
        self._transform = transform_service or TransformService()
        self._ingestion = ingestion_service or IngestionService(session)

    def process_raw_logs(
        self,
        *,
        secure_lines: list[str] | None = None,
        audit_lines: list[str] | None = None,
        hostname: str | None = None,
        server_id: str | None = None,
        owner_id: str | None = None,
        system_metrics: dict[str, float] | None = None,
        source_lines: dict[str, list[str]] | None = None,
        host_context: dict[str, str] | None = None,
        collector_user: str | None = None,
        journal_entries: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run the full pipeline on raw secure and audit log lines.

        host_context comes from the collection session: collector_ip (as seen by the
        host), timezone and utc_offset. collector_user is the configured SSH account.
        journal_entries maps journald lines to their boot id / journal time / PID.
        """
        host_context = host_context or {}
        host_tz = resolve_host_timezone(host_context.get("timezone"), host_context.get("utc_offset"))
        # One collection time for every record of this run, taken after retrieval.
        collected_at = collection_now()
        secure_count = len(secure_lines or [])
        audit_count = len(audit_lines or [])
        processed = secure_count + audit_count
        if source_lines:
            processed = max(processed, sum(len(lines or []) for lines in source_lines.values()))

        logger.info(
            "Pipeline processing raw logs host=%r secure_lines=%d audit_lines=%d",
            hostname,
            secure_count,
            audit_count,
        )

        normalized, transform_errors = self._transform.normalize_log_lines(
            secure_lines=secure_lines,
            audit_lines=audit_lines,
            hostname=hostname,
            host_tz=host_tz,
            collected_at=collected_at,
        )
        normalized = annotate_journal_events(normalized, journal_entries)
        normalized = tag_record_origin(
            normalized,
            collector_ip=host_context.get("collector_ip"),
            collector_user=collector_user,
        )
        normalized, collector_sessions = self._correlate_sessions(normalized, server_id)
        failed_login_count = self._count_failed_logins(normalized)
        generic = self._generic_events_from_sources(
            source_lines or {},
            hostname=hostname,
            host_tz=host_tz,
            collected_at=collected_at,
        )
        generic, history_duplicates = self._dedupe_login_history(
            generic, server_id=server_id, host_tz=host_tz, collected_at=collected_at,
        )
        normalized.extend(generic)
        events = self._transform.enrich_events(
            normalized,
            failed_login_count=failed_login_count,
        )

        stats = self._store_events(
            events,
            processed=processed,
            transform_errors=transform_errors,
            server_id=server_id,
            owner_id=owner_id,
            system_metrics=system_metrics,
            failed_login_count=failed_login_count,
            host_context=host_context,
            collected_at=collected_at,
            pre_duplicates=history_duplicates,
        )
        stats["collector_sessions_skipped"] = collector_sessions
        stats["login_history_duplicates"] = history_duplicates
        return stats

    def process_parsed_events(
        self,
        events: list[dict[str, Any] | str | None],
        *,
        source: str = "secure",
        hostname: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Run the pipeline on already parsed events or raw line strings."""
        processed = len(events)
        logger.info("Pipeline processing %d parsed/raw items", processed)

        if hostname:
            self._transform = TransformService(default_hostname=hostname)

        normalized, transform_errors = self._transform.normalize_batch(
            events,
            source="audit" if source == "audit" else "secure",
        )
        failed_login_count = self._count_failed_logins(normalized)
        scored = self._transform.enrich_events(
            normalized,
            failed_login_count=failed_login_count,
        )

        return self._store_events(
            scored,
            processed=processed,
            transform_errors=transform_errors,
            server_id=server_id,
        )

    def process_single_raw_line(
        self,
        raw_line: str,
        *,
        source: str = "secure",
        hostname: str | None = None,
    ) -> dict[str, Any]:
        """Run the pipeline for a single raw log line."""
        if hostname:
            self._transform = TransformService(default_hostname=hostname)

        processed = 1
        try:
            normalized = self._transform.normalize_raw_line(
                raw_line,
                source="audit" if source == "audit" else "secure",
            )
        except Exception as exc:
            logger.exception("Pipeline failed to normalize single raw line")
            return self._build_stats(
                processed=processed,
                failed=1,
                transform_errors=[{"index": 0, "error": str(exc)}],
            )

        if normalized is None:
            return self._build_stats(
                processed=processed,
                skipped=1,
                transform_errors=[{"index": 0, "error": "Unrecognized or unsupported log line"}],
            )

        scored = self._transform.enrich_events(normalized=[normalized], failed_login_count=0)
        return self._store_events(
            scored,
            processed=processed,
            transform_errors=[],
        )

    def process_single_parsed_event(
        self,
        parsed: dict[str, Any],
        *,
        hostname: str | None = None,
    ) -> dict[str, Any]:
        """Run the pipeline for a single already-parsed log event."""
        if hostname:
            self._transform = TransformService(default_hostname=hostname)

        processed = 1
        try:
            normalized = self._transform.normalize_parsed(parsed)
        except Exception as exc:
            logger.exception("Pipeline failed to normalize single parsed event")
            return self._build_stats(
                processed=processed,
                failed=1,
                transform_errors=[{"index": 0, "error": str(exc)}],
            )

        if normalized is None:
            return self._build_stats(
                processed=processed,
                skipped=1,
                transform_errors=[{"index": 0, "error": "Event type not supported by normalizer"}],
            )

        scored = self._transform.enrich_events(normalized=[normalized], failed_login_count=0)
        return self._store_events(
            scored,
            processed=processed,
            transform_errors=[],
        )

    def collect_and_process(
        self,
        config: SSHConfig,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
        server_id: str | None = None,
        owner_id: str | None = None,
        server_name: str | None = None,
    ) -> dict[str, Any]:
        """Collect raw logs from a Linux host and run the full pipeline."""
        logger.info("Pipeline collect_and_process host=%s server_id=%s", config.host, server_id)
        sources = log_sources or DEFAULT_LOG_SOURCES
        position = self._journal_position(server_id) if "journalctl" in sources else None
        try:
            payload = self._collector.collect_raw_lines(
                config,
                tail_lines=tail_lines,
                log_sources=log_sources,
                **({"journal_position": position} if position is not None else {}),
            )
        except Exception as exc:
            from backend.services.ssh_service import classify_ssh_exception, root_cause

            logger.exception("Log collection failed for host=%s", config.host)
            return self._build_stats(
                processed=0,
                transform_errors=[{
                    "stage": "collect",
                    "error": str(root_cause(exc)) or str(exc),
                    "health_status": classify_ssh_exception(exc),
                }],
                failed=1,
            )

        journal: JournalBatch | None = payload.get("journal")
        secure_keys = {"secure", "auth", "journalctl"}
        audit_keys = {"audit", "syslog"}
        secure_lines = payload.get("secure_lines") if sources & secure_keys else []
        audit_lines = payload.get("audit_lines") if sources & audit_keys else []
        if not log_sources:
            secure_lines = payload.get("secure_lines", [])
            audit_lines = payload.get("audit_lines", [])

        stats = self.process_raw_logs(
            secure_lines=secure_lines,
            audit_lines=audit_lines,
            hostname=server_name or payload.get("host"),
            server_id=server_id,
            owner_id=owner_id,
            system_metrics=payload.get("metrics"),
            source_lines=payload.get("sources"),
            host_context=payload.get("host_context"),
            collector_user=config.username,
            journal_entries=journal.entries if journal else None,
        )
        stats["skipped_sources"] = payload.get("skipped_sources") or {}
        if journal is not None and server_id:
            stored = not any(error.get("stage") == "store" for error in stats.get("errors", []))
            stats["journal"] = self._save_journal_state(server_id, journal, advance_cursor=stored)
        return stats

    def _journal_position(self, server_id: str | None) -> JournalPosition | None:
        if not server_id:
            return None
        from backend.database.collection_state import load_journal_position

        return load_journal_position(self._session, server_id)

    def _save_journal_state(self, server_id: str, journal: JournalBatch, *, advance_cursor: bool) -> dict[str, Any]:
        from backend.database.collection_state import save_journal_state

        try:
            return save_journal_state(self._session, server_id, journal, advance_cursor=advance_cursor)
        except SQLAlchemyError:
            self._session.rollback()
            logger.exception("Could not save journal collection state server_id=%s", server_id)
            return {"mode": journal.mode, "entries_read": journal.entries_read, "cursor_advanced": False}

    def collect_logs(
        self,
        server_id: str,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """Collect and process logs for a server ID (database credentials only)."""
        from backend.database import server_crud
        from backend.services.ssh_service import SSHService

        session = self._ingestion._session
        server = server_crud.get_server(session, server_id)
        if server is None:
            raise ValueError(f"Server '{server_id}' not found.")
        config = SSHService.config_from_server(server)
        return self.collect_and_process(
            config,
            tail_lines=tail_lines,
            log_sources=log_sources,
            server_id=server.id,
            owner_id=server.owner_id or server.created_by,
            server_name=server.server_name,
        )

    @staticmethod
    def _count_failed_logins(events: list[NormalizedSecurityEvent]) -> int:
        """Compute batch context passed into the stateless RiskEngine.

        DefenSync's own failed probes (e.g. a stale stored password) are frequent by
        construction and must not raise brute-force context.
        """
        return sum(
            1 for event in events
            if event.event_type == EventType.FAILED_LOGIN
            and event.metadata.get("record_origin") != RECORD_ORIGIN_COLLECTOR
        )

    def _prior_session_records(self, server_id: str | None, session_ids: set[str]) -> list[dict[str, Any]]:
        """Already stored login/session records of these journal sessions (earlier batches)."""
        if not server_id or not session_ids:
            return []
        import json

        from backend.database.models import Event

        try:
            rows = self._session.execute(
                select(Event.session_id, Event.event_type, Event.username, Event.source_ip, Event.normalized_data)
                .where(Event.server_id == server_id, Event.session_id.in_(sorted(session_ids)))
            ).all()
        except SQLAlchemyError:
            self._session.rollback()
            return []
        records = []
        for session_id, event_type, username, source_ip, normalized_data in rows:
            try:
                nd = json.loads(normalized_data) if normalized_data else {}
            except ValueError:
                nd = {}
            usec = nd.get("journal_realtime_usec")
            if usec is None:
                continue
            records.append({
                "session_id": session_id, "event_type": event_type, "username": username,
                "source_ip": source_ip, "usec": int(usec),
                "record_origin": nd.get("record_origin"), "record_origin_basis": nd.get("record_origin_basis"),
                "event": None,
            })
        return records

    def _correlate_sessions(
        self,
        events: list[NormalizedSecurityEvent],
        server_id: str | None,
    ) -> tuple[list[NormalizedSecurityEvent], int]:
        """Link login -> session opened -> session closed within one journal session.

        Duration is computed only from a matched open and close; a close without its open
        has no duration. Sessions of DefenSync's own SSH logins are not stored: they are
        probe noise and are returned as a count.
        """
        timelines: dict[str, list[dict[str, Any]]] = {}
        for index, event in enumerate(events):
            session_id = event.metadata.get("session_id")
            usec = event.metadata.get("journal_realtime_usec")
            if not session_id or usec is None or event.event_type not in SESSION_EVENT_TYPES:
                continue
            timelines.setdefault(session_id, []).append({
                "session_id": session_id, "event_type": str(event.event_type), "username": event.username,
                "source_ip": event.source_ip, "usec": int(usec),
                "record_origin": event.metadata.get("record_origin"),
                "record_origin_basis": event.metadata.get("record_origin_basis"),
                "event": index,
            })
        if not timelines:
            return events, 0
        for record in self._prior_session_records(server_id, set(timelines)):
            timelines[record["session_id"]].insert(0, record)

        updates: dict[int, dict[str, Any]] = {}
        for records in timelines.values():
            records.sort(key=lambda r: (r["usec"], _SESSION_ORDER.get(r["event_type"], 3)))
            login: dict[str, Any] | None = None
            opened: dict[str, Any] | None = None
            for record in records:
                kind = record["event_type"]
                if kind == str(EventType.SUCCESSFUL_LOGIN):
                    login = record
                    continue
                extra: dict[str, Any] = {}
                if kind == str(EventType.SESSION_OPENED):
                    matched = (
                        login is not None and login["username"] == record["username"]
                        and 0 <= record["usec"] - login["usec"] <= LOGIN_TO_SESSION_MAX_USEC
                    )
                    extra["session_correlation"] = "login_matched" if matched else "no_login_record"
                    extra["login_time"] = extra["session_start_utc"] = _journal_time(record["usec"])
                    if matched:
                        self._inherit_origin(record, login, extra)
                    opened = record
                else:
                    extra["logout_time"] = extra["session_end_utc"] = _journal_time(record["usec"])
                    if opened is not None and opened["username"] == record["username"]:
                        extra["session_correlation"] = "opened_matched"
                        extra["login_time"] = extra["session_start_utc"] = _journal_time(opened["usec"])
                        extra["session_duration_seconds"] = round((record["usec"] - opened["usec"]) / 1_000_000, 6)
                        extra["session_duration_basis"] = SESSION_DURATION_BASIS
                        self._inherit_origin(record, opened, extra)
                    elif login is not None and login["username"] == record["username"]:
                        extra["session_correlation"] = "login_only"
                        self._inherit_origin(record, login, extra)
                    else:
                        extra["session_correlation"] = "no_open_record"
                    opened = None
                if record["event"] is not None:
                    updates[record["event"]] = extra

        kept: list[NormalizedSecurityEvent] = []
        collector_sessions = 0
        for index, event in enumerate(events):
            extra = updates.get(index)
            if extra is None:
                kept.append(event)
                continue
            if extra.get("record_origin") == RECORD_ORIGIN_COLLECTOR:
                collector_sessions += 1
                continue
            source_ip = extra.pop("source_ip", None)
            kept.append(replace(
                event,
                source_ip=event.source_ip or source_ip,
                metadata={**event.metadata, **extra},
            ))
        return kept, collector_sessions

    @staticmethod
    def _inherit_origin(record: dict[str, Any], parent: dict[str, Any], extra: dict[str, Any]) -> None:
        """The session belongs to the login that started it: same origin and source address."""
        if parent.get("source_ip"):
            extra["source_ip"] = parent["source_ip"]
            record["source_ip"] = parent["source_ip"]
        if parent.get("record_origin") == RECORD_ORIGIN_COLLECTOR:
            extra["record_origin"] = RECORD_ORIGIN_COLLECTOR
            extra["record_origin_basis"] = COLLECTOR_SESSION_BASIS
            record["record_origin"] = RECORD_ORIGIN_COLLECTOR

    def _dedupe_login_history(
        self,
        events: list[NormalizedSecurityEvent],
        *,
        server_id: str | None,
        host_tz: tzinfo | None,
        collected_at: datetime,
    ) -> tuple[list[NormalizedSecurityEvent], int]:
        """Drop last/lastb lines for sessions already stored, matched by session identity.

        A matched stored row keeps its timestamp, raw_log, hash and type; only its
        collection time is refreshed and empty session fields are filled in.
        """
        keyed = [event for event in events if event.metadata.get("session_key")]
        if not keyed:
            return events, 0
        import json

        from backend.database.models import Event

        existing: dict[str, list[Any]] = {}
        if server_id:
            try:
                rows = self._session.scalars(
                    select(Event).where(
                        Event.server_id == server_id,
                        Event.command.in_(list(LOGIN_HISTORY_COMMANDS.values())),
                    )
                ).all()
            except SQLAlchemyError:
                self._session.rollback()
                logger.warning("Login history lookup failed server_id=%s; using hash deduplication", server_id)
                rows = []
            commands = {command: source for source, command in LOGIN_HISTORY_COMMANDS.items()}
            for row in rows:
                session = parse_login_history_line(
                    row.raw_log or "", source=commands[row.command], collected_at=collected_at, host_tz=host_tz,
                )
                if session is not None:
                    existing.setdefault(session.session_key, []).append(row)

        kept: list[NormalizedSecurityEvent] = []
        seen: set[str] = set()
        duplicates = 0
        touched = False
        for event in events:
            key = event.metadata.get("session_key")
            if not key:
                kept.append(event)
                continue
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            rows = existing.get(key)
            if not rows:
                kept.append(event)
                continue
            duplicates += 1
            touched = True
            for row in rows:
                self._enrich_login_history_row(row, event.metadata, collected_at, json)
        if touched:
            try:
                self._session.commit()
            except SQLAlchemyError:
                self._session.rollback()
                logger.exception("Could not update stored login history server_id=%s", server_id)
        return kept, duplicates

    @staticmethod
    def _enrich_login_history_row(row: Any, metadata: dict[str, Any], collected_at: datetime, json: Any) -> None:
        row.collection_timestamp = collected_at
        if not row.session_id:
            row.session_id = metadata.get("session_id")
        if row.login_time is None and metadata.get("login_time"):
            row.login_time = datetime.fromisoformat(metadata["login_time"])
        if row.logout_time is None and metadata.get("logout_time"):
            row.logout_time = datetime.fromisoformat(metadata["logout_time"])
        if row.session_duration is None and metadata.get("session_duration_seconds") is not None:
            row.session_duration = metadata["session_duration_seconds"]
        try:
            nd = json.loads(row.normalized_data) if row.normalized_data else {}
        except ValueError:
            nd = {}
        if not isinstance(nd, dict):
            return
        for field in ("session_key", "terminal", "remote_host", "login_time"):
            nd.setdefault(field, metadata.get(field))
        for field in ("logout_time", "session_duration_seconds", "session_duration_basis"):
            if nd.get(field) is None and metadata.get(field) is not None:
                nd[field] = metadata[field]
        nd["session_state"] = metadata.get("session_state")
        nd["session_last_observed_line"] = metadata.get("message")
        nd["session_last_observed_at"] = collected_at.isoformat()
        row.normalized_data = json.dumps(nd, default=str)

    @staticmethod
    def _generic_events_from_sources(
        source_lines: dict[str, list[str]],
        *,
        hostname: str | None = None,
        host_tz: tzinfo | None = None,
        collected_at: datetime | None = None,
    ) -> list[NormalizedSecurityEvent]:
        """Create normalized records for command outputs not covered by auth/audit parsers.

        last/lastb are login history with real timestamps. Every other source is a
        point-in-time snapshot of system state: it gets the collection time and is never
        parsed for a date, because its numbers (PIDs, sizes, IDs) are not timestamps.
        """
        generic_sources = SNAPSHOT_SOURCES | LOGIN_HISTORY_SOURCES
        collected_at = collected_at or collection_now()
        source_commands = {
            "journalctl": "journalctl --output=short-iso --no-pager",
            "last": "last -F",
            "lastb": "lastb -F",
            "who": "who",
            "w": "w",
            "uptime": "uptime",
            "free": "free -m",
            "df": "df -h",
            "ps": "ps aux",
            "ss": "ss -tuln",
            "hostnamectl": "hostnamectl",
            "uname": "uname -a",
            "top": "top",
        }
        events: list[NormalizedSecurityEvent] = []
        for source, lines in source_lines.items():
            if source not in generic_sources:
                continue
            non_record = NON_RECORD_LINES.get(source)
            for index, line in enumerate(lines or [], start=1):
                if not line.strip() or (non_record and non_record.match(line)):
                    continue
                parts = line.split()
                first = parts[0]
                source_ip = next((t for t in parts if t.count(".") == 3 and t[0].isdigit()), None)
                username = first if source in {"last", "lastb", "who", "w"} else None
                system_action = None
                if source in SNAPSHOT_SOURCES:
                    occurrence = ParsedOccurrence(collected_at, SOURCE_SNAPSHOT, TZ_COLLECTION_CLOCK)
                    record_kind = RECORD_SYSTEM_SNAPSHOT
                    event_type, severity, risk_score = EventType.SYSTEM_SNAPSHOT, "info", 0
                else:
                    occurrence = parse_occurrence(line, collected_at=collected_at, source_hint=source, host_tz=host_tz)
                    if first in LOGIN_HISTORY_PSEUDO_USERS:
                        record_kind = RECORD_SYSTEM_EVENT
                        event_type, severity, risk_score = EventType.SYSTEM_EVENT, "info", 10
                        system_action, username, source_ip = first, None, None
                    elif source == "lastb":
                        record_kind = RECORD_SECURITY_EVENT
                        event_type, severity, risk_score = EventType.FAILED_LOGIN, "medium", 55
                    else:
                        record_kind = RECORD_SECURITY_EVENT
                        event_type, severity, risk_score = EventType.SUCCESSFUL_LOGIN, "low", 15
                has_source_time = record_kind == RECORD_SECURITY_EVENT and occurrence.source == SOURCE_EVENT
                command = source_commands.get(source, source)
                session_fields: dict[str, Any] = {}
                if source in LOGIN_HISTORY_SOURCES:
                    session = parse_login_history_line(line, source=source, collected_at=collected_at, host_tz=host_tz)
                    if session is not None:
                        session_fields = {"session_key": session.session_key, "session_state": session.session_state}
                        if record_kind == RECORD_SECURITY_EVENT:
                            session_fields.update({
                                "session_id": session.session_id,
                                "terminal": session.terminal,
                                "remote_host": session.remote_host,
                                "login_time": session.login_time.isoformat(),
                                "logout_time": session.logout_time.isoformat() if session.logout_time else None,
                                "session_duration_seconds": session.duration_seconds,
                                "session_duration_basis": session.duration_basis,
                            })
                events.append(
                    NormalizedSecurityEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=occurrence.event_time.isoformat(),
                        hostname=hostname or "unknown",
                        username=username,
                        source_ip=source_ip,
                        event_type=event_type,
                        category=category_for(event_type),
                        severity=severity,
                        risk_score=risk_score,
                        raw_log=line,
                        metadata={
                            "source": source,
                            "line_number": index,
                            "timestamp_source": occurrence.source,
                            "timestamp_tz_basis": occurrence.tz_basis,
                            "collection_timestamp": collected_at.isoformat(),
                            "record_kind": record_kind,
                            "login_hour": login_hour_from(occurrence.event_time) if has_source_time else None,
                            "normalized_data": {
                                "source": source,
                                "line": line,
                                "command": command,
                                "timestamp_source": occurrence.source,
                                "timestamp_tz_basis": occurrence.tz_basis,
                                "record_kind": record_kind,
                                **({"system_action": system_action} if system_action else {}),
                                **session_fields,
                            },
                            "command": command,
                            "message": line,
                            **session_fields,
                        },
                    )
                )
        return events

    def _store_events(
        self,
        events: list[NormalizedSecurityEvent],
        *,
        processed: int,
        transform_errors: list[dict[str, Any]],
        server_id: str | None = None,
        owner_id: str | None = None,
        system_metrics: dict[str, float] | None = None,
        failed_login_count: int = 0,
        host_context: dict[str, str] | None = None,
        collected_at: datetime | None = None,
        pre_duplicates: int = 0,
    ) -> dict[str, Any]:
        """Delegate persistence to IngestionService.

        Lines the normalizer recognised but deliberately declined are skipped, not failed.
        pre_duplicates are records already matched to stored ones before ingestion.
        """
        host_context = host_context or {}
        transform_errors = [error for error in transform_errors if error.get("error") != DECLINED_BY_NORMALIZER]
        skipped = max(0, processed - len(events) - len(transform_errors) - pre_duplicates)

        if not events:
            return self._build_stats(
                processed=processed,
                duplicates=pre_duplicates,
                skipped=skipped,
                transform_errors=transform_errors,
            )

        collected_at = collected_at or collection_now()
        payloads = [event.to_persistence_dict() for event in events]
        if server_id:
            for payload in payloads:
                payload["server_id"] = server_id
        if owner_id:
            for payload in payloads:
                payload["owner_id"] = owner_id
        if server_id:
            from backend.database.models import Server
            server = self._session.get(Server, server_id)
            account_id = getattr(server, "account_id", None) if server else None
            for payload in payloads:
                payload["account_id"] = account_id
                payload["data_scope"] = "PRIVATE"
        if system_metrics:
            for payload in payloads:
                payload.setdefault("cpu_usage", system_metrics.get("cpu_usage"))
                payload.setdefault("memory_usage", system_metrics.get("memory_usage"))
                payload.setdefault("disk_usage", system_metrics.get("disk_usage"))
                payload.setdefault("network_connections", int(system_metrics.get("network_connections", 0)))
                payload.setdefault("commands_executed", int(system_metrics.get("process_count", 0) or 0) or None)
        if failed_login_count:
            for payload in payloads:
                payload.setdefault("failed_login_count", failed_login_count)
        for payload in payloads:
            metadata = payload.setdefault("metadata", {})
            metadata.setdefault("record_kind", RECORD_SECURITY_EVENT)
            metadata.setdefault("record_origin", RECORD_ORIGIN_SOURCE_OBSERVED)
            payload["collection_timestamp"] = metadata.get("collection_timestamp") or collected_at
            payload["timestamp_source"] = metadata.get("timestamp_source") or SOURCE_FALLBACK
            payload["raw_log"] = redact_secrets(payload.get("raw_log"))
            payload["message"] = redact_secrets(payload.get("message"))
            for column in ("login_time", "logout_time"):
                if metadata.get(column):
                    payload.setdefault(column, metadata[column])
            if metadata.get("session_duration_seconds") is not None:
                payload.setdefault("session_duration", metadata["session_duration_seconds"])
            canonical = {
                "record_kind": metadata["record_kind"],
                "record_origin": metadata["record_origin"],
                "event_time_utc": _utc_iso(payload.get("timestamp")),
                "first_collection_time_utc": _utc_iso(payload["collection_timestamp"]),
                "host_timezone": host_context.get("timezone"),
                "host_utc_offset": host_context.get("utc_offset"),
            }
            for key in ("record_origin_basis", "timestamp_tz_basis"):
                if metadata.get(key):
                    canonical[key] = metadata[key]
            canonical = {key: value for key, value in canonical.items() if value is not None}
            metadata.update(canonical)
            # login_hour is the UTC hour of a genuine source occurrence time, never of collection time.
            payload["login_hour"] = None
            if metadata["record_kind"] == RECORD_SECURITY_EVENT and payload["timestamp_source"] == SOURCE_EVENT:
                if metadata.get("login_hour") is not None:
                    payload["login_hour"] = metadata["login_hour"]
                elif payload.get("timestamp"):
                    payload["login_hour"] = login_hour_from(datetime.fromisoformat(canonical["event_time_utc"]))
            if metadata.get("normalized_data"):
                import json
                nd = metadata["normalized_data"]
                if isinstance(nd, dict):
                    nd.update(canonical)
                    nd.setdefault("feature_family", "LIVE_LINUX_FEATURES")
                    nd.setdefault("is_remote", bool(payload.get("source_ip")))
                    nd.setdefault(
                        "privileged_activity",
                        str(payload.get("event_type") or "") in {"Sudo Command", "User Creation", "Permission Change"}
                        or str(payload.get("username") or "").lower() == "root",
                    )
                payload["normalized_data"] = json.dumps(nd, default=str)
            payload.setdefault("actor_id", payload.get("username"))
            payload.setdefault("data_origin", "LIVE_LINUX")
            payload.setdefault("source_type", "LINUX")
        try:
            ingest_stats = self._ingestion.ingest_bulk_events(payloads)
        except Exception as exc:
            logger.exception("Pipeline bulk ingestion failed")
            return self._build_stats(
                processed=processed,
                duplicates=pre_duplicates,
                skipped=skipped,
                transform_errors=transform_errors + [{"stage": "store", "error": str(exc)}],
                failed=len(events),
            )

        return self._build_stats(
            processed=processed,
            inserted=ingest_stats.get("inserted", 0),
            duplicates=ingest_stats.get("duplicates", 0) + pre_duplicates,
            failed=len(transform_errors) + ingest_stats.get("failed", 0),
            skipped=skipped,
            transform_errors=transform_errors + ingest_stats.get("errors", []),
        )

    @staticmethod
    def _build_stats(
        *,
        processed: int,
        inserted: int = 0,
        failed: int = 0,
        duplicates: int = 0,
        skipped: int = 0,
        transform_errors: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "processed": processed,
            "inserted": inserted,
            "failed": failed,
            "duplicates": duplicates,
            "skipped": skipped,
            "errors": transform_errors or [],
        }
