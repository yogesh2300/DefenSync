"""Unified interface for multi-server Linux log collection."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from backend.collector.config import SSHConfig
from backend.collector.journal import JournalBatch, JournalPosition, build_journal_command, parse_journal_output
from backend.collector.log_sources import DEFAULT_LOG_SOURCES, HOST_CONTEXT_COMMAND, LOG_SOURCE_CATALOG
from backend.collector.ssh_client import ssh_session
from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.core.timestamps import resolve_host_timezone
from backend.database.models import Server
from backend.services.ssh_service import SSHService

logger = get_logger(__name__)


class CollectorService:
    """
    Collect raw Linux logs over SSH for a registered server.

    Does not parse, normalize, or persist events.
    """

    def collect_sources(
        self,
        config: SSHConfig,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
        journal_position: JournalPosition | None = None,
    ) -> dict[str, Any]:
        """Collect from multiple Linux log sources and diagnostic commands.

        With a journal_position, journald is read incrementally from that server's cursor
        instead of as the last `tail` lines.
        """
        sources = log_sources or DEFAULT_LOG_SOURCES
        collected: dict[str, list[str]] = {}
        skipped: dict[str, str] = {}
        tail = tail_lines or 200
        journal: JournalBatch | None = None

        logger.info("Collecting sources=%s from host=%s", sorted(sources), config.host)
        with ssh_session(config) as client:
            host_context = self._host_context(client, config.host)
            for key in sources:
                definition = LOG_SOURCE_CATALOG.get(key)
                if definition is None:
                    skipped[key] = "unknown source"
                    continue
                try:
                    if key == "journalctl" and journal_position is not None:
                        journal = self._read_journal(client, journal_position, host_context)
                        collected[key] = journal.lines
                    elif definition.source_type == "file" and definition.path:
                        collected[key] = client.read_remote_lines(definition.path, tail_lines=tail_lines)
                    elif definition.source_type == "command" and definition.command:
                        command = definition.command.format(tail=tail)
                        collected[key] = client.run_remote_command(command)
                    else:
                        collected[key] = []
                    if not collected.get(key):
                        skipped[key] = "unavailable or empty"
                except Exception as exc:
                    logger.warning("Failed collecting source=%s host=%s: %s", key, config.host, exc)
                    collected[key] = []
                    skipped[key] = str(exc)

        secure_lines: list[str] = []
        secure_lines.extend(collected.get("secure", []))
        secure_lines.extend(collected.get("auth", []))
        secure_lines.extend(collected.get("journalctl", []))

        audit_lines: list[str] = []
        audit_lines.extend(collected.get("audit", []))
        audit_lines.extend(collected.get("syslog", []))

        extra_lines: list[str] = []
        for metric_key in ("free", "df", "uptime", "ps", "ss", "top", "hostnamectl", "uname"):
            extra_lines.extend(collected.get(metric_key, []))

        metrics = self._parse_system_metrics(collected)

        return {
            "host": config.host,
            "secure_lines": secure_lines,
            "audit_lines": audit_lines,
            "extra_lines": extra_lines,
            "sources": collected,
            "skipped_sources": skipped,
            "summary": {key: len(lines) for key, lines in collected.items()},
            "metrics": metrics,
            "host_context": host_context,
            "journal": journal,
        }

    @staticmethod
    def _read_journal(client: Any, position: JournalPosition, host_context: dict[str, str]) -> JournalBatch:
        max_entries = get_settings().JOURNAL_MAX_ENTRIES_PER_RUN
        host_tz = resolve_host_timezone(host_context.get("timezone"), host_context.get("utc_offset"))
        lines = client.run_remote_command(build_journal_command(position, max_entries), timeout=120.0)
        return parse_journal_output(lines, host_tz, max_entries)

    @staticmethod
    def _host_context(client: Any, host: str) -> dict[str, str]:
        """Collector source IP as seen by the host, plus the host timezone; {} if unavailable."""
        try:
            lines = client.run_remote_command(HOST_CONTEXT_COMMAND)
        except Exception as exc:
            logger.warning("Host context unavailable host=%s: %s", host, exc)
            return {}
        values = dict(line.split("=", 1) for line in lines if "=" in line)
        context = {
            "collector_ip": (values.get("ssh_connection") or "").split(" ")[0],
            "utc_offset": (values.get("utc_offset") or "").strip(),
            "timezone": (values.get("timezone") or "").strip(),
        }
        return {key: value for key, value in context.items() if value}

    def collect_raw_lines(
        self,
        config: SSHConfig,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
        journal_position: JournalPosition | None = None,
    ) -> dict[str, Any]:
        """Collect raw log lines from configured sources."""
        payload = self.collect_sources(
            config, tail_lines=tail_lines, log_sources=log_sources, journal_position=journal_position,
        )
        return {
            "journal": payload.get("journal"),
            "host": payload["host"],
            "secure_lines": payload["secure_lines"],
            "audit_lines": payload["audit_lines"],
            "extra_lines": payload.get("extra_lines", []),
            "sources": payload.get("sources", {}),
            "summary": payload.get("summary", {}),
            "metrics": payload.get("metrics", {}),
            "host_context": payload.get("host_context", {}),
        }

    def collect_logs(
        self,
        server_id: str,
        session: Session,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
    ) -> dict[str, Any]:
        """
        Collect logs for a registered server by ID.

        Loads encrypted credentials from the database — never from .env.
        """
        from backend.database import server_crud

        server = server_crud.get_server(session, server_id)
        if server is None:
            raise ValueError(f"Server '{server_id}' not found.")
        config = SSHService.config_from_server(server)
        return self.collect_raw_lines(config, tail_lines=tail_lines, log_sources=log_sources)

    @staticmethod
    def _parse_system_metrics(collected: dict[str, list[str]]) -> dict[str, float]:
        """Extract CPU, memory, and disk usage from diagnostic command output."""
        metrics: dict[str, float] = {}

        free_lines = collected.get("free", [])
        for line in free_lines:
            if line.startswith("Mem:"):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        total = float(parts[1])
                        used = float(parts[2])
                        if total > 0:
                            metrics["memory_usage"] = round((used / total) * 100, 2)
                    except ValueError:
                        pass
                break

        df_lines = collected.get("df", [])
        for line in df_lines[1:]:
            if line.endswith("/") or " /$" in line or line.split()[-1] == "/":
                parts = line.split()
                if len(parts) >= 5:
                    pct = parts[4].replace("%", "")
                    try:
                        metrics["disk_usage"] = float(pct)
                    except ValueError:
                        pass
                break

        top_or_ps = list(collected.get("top", [])) + list(collected.get("ps", []))
        for line in top_or_ps:
            if "Cpu(s):" in line or "%Cpu" in line:
                parts = line.replace(",", "").split()
                for idx, part in enumerate(parts):
                    if part in {"id", "idle"} and idx > 0:
                        try:
                            idle = float(parts[idx - 1])
                            metrics["cpu_usage"] = round(100.0 - idle, 2)
                        except ValueError:
                            pass
                        break

        ss_lines = collected.get("ss", [])
        metrics["network_connections"] = float(len([l for l in ss_lines if l.strip()]))
        ps_lines = collected.get("ps", [])
        metrics["process_count"] = float(max(0, len(ps_lines) - 1))

        return metrics
