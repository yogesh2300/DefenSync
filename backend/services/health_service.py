"""Dedicated server health monitoring service with concurrent SSH probes."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.database import server_crud
from backend.database.connection import get_session
from backend.database.models import Server
from backend.health.status import ERROR_STATUSES, HealthStatus, OFFLINE_STATUSES, is_online
from backend.health.types import HealthCheckResult
from backend.services.ssh_service import SSHService, classify_ssh_exception

logger = get_logger(__name__)


class HealthService:
    """Check SSH connectivity, classify failures, and persist health metrics."""

    def __init__(self, session: Session | None = None) -> None:
        self._session = session
        self._settings = get_settings()

    def check_all_servers(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Run concurrent health checks for all monitored servers."""
        session = self._session or get_session()
        owns_session = self._session is None
        started = time.perf_counter()
        try:
            servers = server_crud.list_monitored_servers(session, owner_id=owner_id)
            if server_id:
                servers = [server for server in servers if server.id == server_id]

            if not servers:
                return {
                    "checked": 0,
                    "online": 0,
                    "offline": 0,
                    "errors": 0,
                    "duration_ms": 0,
                    "average_latency_ms": 0,
                }

            for server in servers:
                server_crud.mark_health_connecting(session, server)
            if servers:
                session.commit()

            results: list[HealthCheckResult] = []
            max_workers = min(
                self._settings.HEALTH_CHECK_MAX_WORKERS,
                max(1, len(servers)),
            )
            with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="health") as pool:
                futures = {
                    pool.submit(self._check_server_worker, server.id): server.id
                    for server in servers
                }
                for future in as_completed(futures):
                    server_id_value = futures[future]
                    try:
                        results.append(future.result())
                    except Exception:
                        logger.exception("Health check worker failed server_id=%s", server_id_value)
                        results.append(
                            HealthCheckResult(
                                server_id=server_id_value,
                                health_status=HealthStatus.ERROR,
                                error_message="Health check worker failed.",
                                checked_at=datetime.now(timezone.utc),
                            )
                        )

            online = sum(1 for result in results if is_online(result.health_status))
            offline = sum(
                1 for result in results
                if result.health_status in OFFLINE_STATUSES
            )
            errors = sum(
                1 for result in results
                if result.health_status in ERROR_STATUSES
            )
            latencies = [result.latency_ms for result in results if result.latency_ms is not None]
            average_latency = int(sum(latencies) / len(latencies)) if latencies else 0
            duration_ms = int((time.perf_counter() - started) * 1000)

            logger.info(
                "Health cycle complete checked=%d online=%d offline=%d errors=%d duration_ms=%d",
                len(results),
                online,
                offline,
                errors,
                duration_ms,
            )
            return {
                "checked": len(results),
                "online": online,
                "offline": offline,
                "errors": errors,
                "duration_ms": duration_ms,
                "average_latency_ms": average_latency,
            }
        finally:
            if owns_session:
                session.close()

    def check_server(self, server_id: str) -> HealthCheckResult:
        """Check a single server synchronously."""
        session = self._session or get_session()
        owns_session = self._session is None
        try:
            server = server_crud.get_server(session, server_id)
            if server is None:
                raise ValueError(f"Server '{server_id}' not found.")
            if server.status == "inactive":
                return HealthCheckResult(
                    server_id=server_id,
                    health_status=HealthStatus.UNKNOWN,
                    checked_at=datetime.now(timezone.utc),
                )
            server_crud.mark_health_connecting(session, server)
            session.commit()
            result = self._probe_server(server)
            server_crud.apply_health_result(session, server, result)
            session.commit()
            return result
        finally:
            if owns_session:
                session.close()

    def _check_server_worker(self, server_id: str) -> HealthCheckResult:
        session = get_session()
        try:
            server = server_crud.get_server(session, server_id)
            if server is None:
                return HealthCheckResult(
                    server_id=server_id,
                    health_status=HealthStatus.ERROR,
                    error_message="Server not found.",
                    checked_at=datetime.now(timezone.utc),
                )
            result = self._probe_server(server)
            server_crud.apply_health_result(session, server, result)
            session.commit()
            return result
        except Exception as exc:
            session.rollback()
            logger.exception("Health check failed server_id=%s", server_id)
            server = server_crud.get_server(session, server_id)
            if server is not None:
                result = HealthCheckResult(
                    server_id=server_id,
                    health_status=HealthStatus.ERROR,
                    error_message=str(exc),
                    checked_at=datetime.now(timezone.utc),
                )
                server_crud.apply_health_result(session, server, result)
                session.commit()
                return result
            return HealthCheckResult(
                server_id=server_id,
                health_status=HealthStatus.ERROR,
                error_message=str(exc),
                checked_at=datetime.now(timezone.utc),
            )
        finally:
            session.close()

    def _probe_server(self, server: Server) -> HealthCheckResult:
        checked_at = datetime.now(timezone.utc)
        try:
            config = replace(
                SSHService.config_from_server(server),
                timeout=float(self._settings.HEALTH_CHECK_TIMEOUT_SECONDS),
            )
            probe = SSHService.probe_connectivity(config)
            return HealthCheckResult(
                server_id=server.id,
                health_status=probe["health_status"],
                latency_ms=probe.get("latency_ms"),
                error_message=probe.get("error_message"),
                checked_at=checked_at,
            )
        except ValueError as exc:
            return HealthCheckResult(
                server_id=server.id,
                health_status=HealthStatus.CREDENTIAL_ERROR,
                error_message=str(exc),
                checked_at=checked_at,
            )
        except Exception as exc:
            return HealthCheckResult(
                server_id=server.id,
                health_status=self._classify_exception(exc),
                error_message=str(exc),
                checked_at=checked_at,
            )

    @staticmethod
    def _classify_exception(exc: Exception) -> str:
        return classify_ssh_exception(exc)

    def record_collection_success(self, server: Server) -> None:
        """Update health fields after a successful log collection."""
        session = self._session
        if session is None:
            raise RuntimeError("HealthService.record_collection_success requires a session.")
        now = datetime.now(timezone.utc)
        server.last_successful_collection = now
        server_crud.apply_health_result(
            session,
            server,
            HealthCheckResult(
                server_id=server.id,
                health_status=HealthStatus.ONLINE,
                latency_ms=server.connection_latency_ms,
                checked_at=now,
            ),
        )

    def record_collection_failure(
        self,
        server: Server,
        *,
        error_message: str,
        ssh_failed: bool = True,
        health_status: str | None = None,
    ) -> None:
        """Update health fields after a failed collection."""
        session = self._session
        if session is None:
            raise RuntimeError("HealthService.record_collection_failure requires a session.")
        status = health_status or (HealthStatus.OFFLINE if ssh_failed else HealthStatus.ERROR)
        server_crud.apply_health_result(
            session,
            server,
            HealthCheckResult(
                server_id=server.id,
                health_status=status,
                error_message=error_message,
                checked_at=datetime.now(timezone.utc),
            ),
        )
