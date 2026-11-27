"""Transform parsed log events through normalization and risk enrichment."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, tzinfo
from typing import Any, Literal

from backend.core.logging import get_logger
from backend.core.timestamps import collection_now
from backend.normalizer.event_normalizer import DefaultTimestampNormalizer, EventNormalizer
from backend.normalizer.event_types import NormalizedSecurityEvent
from backend.parser.engine import parse_audit_line, parse_logs, parse_secure_line
from backend.risk.engine import RiskEngine

logger = get_logger(__name__)

LogSource = Literal["secure", "audit"]
# A recognised log line the normalizer deliberately does not turn into an event.
DECLINED_BY_NORMALIZER = "Event type not supported by normalizer"


class TransformService:
    """
    Convert parsed or raw log data into risk-scored normalized events.

    Orchestrates Normalizer and RiskEngine without performing database I/O.
    """

    def __init__(
        self,
        *,
        normalizer: EventNormalizer | None = None,
        risk_engine: RiskEngine | None = None,
        default_hostname: str = "unknown",
    ) -> None:
        self._collected_at = collection_now()
        self._normalizer = normalizer or EventNormalizer(
            default_hostname=default_hostname,
            score_risk=False,
            timestamp_normalizer=DefaultTimestampNormalizer(self._collected_at),
        )
        self._risk_engine = risk_engine or RiskEngine()
        self._default_hostname = default_hostname

    def _normalizer_for(
        self,
        hostname: str | None = None,
        host_tz: tzinfo | None = None,
        collected_at: datetime | None = None,
    ) -> EventNormalizer:
        """Return a classification-only normalizer for the pipeline path."""
        return EventNormalizer(
            default_hostname=hostname or self._default_hostname,
            score_risk=False,
            timestamp_normalizer=DefaultTimestampNormalizer(collected_at or collection_now(), host_tz=host_tz),
        )

    def normalize_parsed(self, parsed: dict[str, Any]) -> NormalizedSecurityEvent | None:
        """Normalize a single parsed log dictionary without risk scoring."""
        prepared = self._prepare_parsed(parsed)
        if prepared is None:
            return None
        return self._normalizer.normalize(prepared)

    def normalize_raw_line(
        self,
        raw_line: str,
        *,
        source: LogSource = "secure",
        line_number: int | None = None,
    ) -> NormalizedSecurityEvent | None:
        """Parse and normalize a single raw log line without risk scoring."""
        parsed = self._parse_raw_line(raw_line, source=source, line_number=line_number)
        if parsed is None:
            return None
        return self.normalize_parsed(parsed)

    def normalize_batch(
        self,
        items: list[dict[str, Any] | str | None],
        *,
        source: LogSource = "secure",
    ) -> tuple[list[NormalizedSecurityEvent], list[dict[str, Any]]]:
        """Parse and normalize a batch of log entries."""
        normalized: list[NormalizedSecurityEvent] = []
        errors: list[dict[str, Any]] = []

        for index, item in enumerate(items):
            if item is None:
                errors.append({"index": index, "error": "Empty log entry"})
                continue
            try:
                parsed = self._coerce_to_parsed(item, source=source, line_number=index + 1)
                if parsed is None:
                    errors.append({"index": index, "error": "Unrecognized log line"})
                    continue
                event = self._normalizer.normalize(parsed)
                if event is None:
                    errors.append({"index": index, "error": DECLINED_BY_NORMALIZER})
                    continue
                normalized.append(event)
            except Exception as exc:
                logger.exception("Normalization failed at index %d", index)
                errors.append({"index": index, "error": str(exc)})

        return normalized, errors

    def normalize_log_lines(
        self,
        *,
        secure_lines: list[str] | None = None,
        audit_lines: list[str] | None = None,
        hostname: str | None = None,
        host_tz: tzinfo | None = None,
        collected_at: datetime | None = None,
    ) -> tuple[list[NormalizedSecurityEvent], list[dict[str, Any]]]:
        """Parse and normalize secure and audit log line lists.

        host_tz is the Linux host zone used for wall-clock times without an offset.
        collected_at is the collection time of this run (default: now).
        """
        if hostname or host_tz or collected_at:
            self._normalizer = self._normalizer_for(hostname, host_tz, collected_at)

        parsed_events = parse_logs(secure_lines or [], audit_lines or [])
        normalized, errors = self.normalize_batch(parsed_events)

        if hostname:
            normalized = [replace(event, hostname=hostname) for event in normalized]

        return normalized, errors

    def enrich_events(
        self,
        events: list[NormalizedSecurityEvent],
        *,
        failed_login_count: int = 0,
    ) -> list[NormalizedSecurityEvent]:
        """Apply risk scoring to already-normalized events."""
        enriched: list[NormalizedSecurityEvent] = []
        for event in events:
            context = RiskEngine.build_context(
                event,
                failed_login_count=failed_login_count,
            )
            enriched.append(self._risk_engine.enrich(event, context))
        return enriched

    def transform_parsed(
        self,
        parsed: dict[str, Any],
        *,
        failed_login_count: int = 0,
    ) -> NormalizedSecurityEvent | None:
        """Normalize and enrich a single parsed log dictionary."""
        normalized = self.normalize_parsed(parsed)
        if normalized is None:
            return None
        return self.enrich_events([normalized], failed_login_count=failed_login_count)[0]

    def transform_raw_line(
        self,
        raw_line: str,
        *,
        source: LogSource = "secure",
        line_number: int | None = None,
        failed_login_count: int = 0,
    ) -> NormalizedSecurityEvent | None:
        """Parse, normalize, and enrich a single raw log line."""
        normalized = self.normalize_raw_line(
            raw_line,
            source=source,
            line_number=line_number,
        )
        if normalized is None:
            return None
        return self.enrich_events([normalized], failed_login_count=failed_login_count)[0]

    def transform_batch(
        self,
        items: list[dict[str, Any] | str | None],
        *,
        source: LogSource = "secure",
        failed_login_count: int = 0,
    ) -> tuple[list[NormalizedSecurityEvent], list[dict[str, Any]]]:
        """Parse, normalize, and enrich a batch of log entries."""
        normalized, errors = self.normalize_batch(items, source=source)
        if not normalized:
            return [], errors
        enriched = self.enrich_events(normalized, failed_login_count=failed_login_count)
        return enriched, errors

    def transform_log_lines(
        self,
        *,
        secure_lines: list[str] | None = None,
        audit_lines: list[str] | None = None,
        hostname: str | None = None,
        failed_login_count: int = 0,
    ) -> tuple[list[NormalizedSecurityEvent], list[dict[str, Any]]]:
        """Parse, normalize, and enrich secure and audit log line lists."""
        normalized, errors = self.normalize_log_lines(
            secure_lines=secure_lines,
            audit_lines=audit_lines,
            hostname=hostname,
        )
        if not normalized:
            return [], errors
        enriched = self.enrich_events(normalized, failed_login_count=failed_login_count)
        return enriched, errors

    def _coerce_to_parsed(
        self,
        item: dict[str, Any] | str,
        *,
        source: LogSource,
        line_number: int | None,
    ) -> dict[str, Any] | None:
        if isinstance(item, str):
            return self._parse_raw_line(item, source=source, line_number=line_number)
        return self._prepare_parsed(item, default_source=source)

    @staticmethod
    def _parse_raw_line(
        raw_line: str,
        *,
        source: LogSource,
        line_number: int | None,
    ) -> dict[str, Any] | None:
        stripped = raw_line.strip()
        if not stripped:
            return None
        if source == "audit":
            return parse_audit_line(stripped, line_number=line_number)
        return parse_secure_line(stripped, line_number=line_number)

    @staticmethod
    def _prepare_parsed(
        parsed: dict[str, Any],
        default_source: LogSource | None = None,
    ) -> dict[str, Any] | None:
        if parsed.get("parse_error"):
            return None

        prepared = dict(parsed)
        if "source" not in prepared and default_source:
            prepared["source"] = default_source
        if "raw" not in prepared:
            prepared["raw"] = prepared.get("raw_log") or prepared.get("message") or ""
        return prepared
