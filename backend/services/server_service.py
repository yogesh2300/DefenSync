"""Business logic for DefenSync server management and per-server collection."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from backend.core.encryption import encrypt_secret
from backend.core.exceptions import CollectionProcessingError, ResourceNotFoundError, ValidationException
from backend.core.logging import get_logger
from backend.database import server_crud
from backend.database.models import Server, User
from backend.health.status import HealthStatus, health_label
from backend.health.types import HealthCheckResult
from backend.services.detection_service import DetectionService
from backend.services.health_engine import get_health_engine
from backend.services.health_service import HealthService
from backend.services.collection_n8n_trigger import record_linux_success
from backend.services.linux_presentation_trigger import record_linux_presentation_trigger
from backend.services.pipeline_service import PipelineService
from backend.services.ssh_service import SSHService

logger = get_logger(__name__)


def _run_post_collection_detection(
    owner_id: str | None,
    server_id: str,
    account_id: str | None = None,
) -> None:
    """Run existing detection for one server after a successful collection.

    Runs in a background thread so the collect API can return promptly. Failures are
    logged only — they must never rewrite the completed collection result.
    """
    from backend.database.connection import get_session

    session = get_session()
    try:
        DetectionService(session).run_detection(
            owner_id=owner_id,
            server_id=server_id,
            account_id=account_id,
        )
        logger.info("Background detection finished server_id=%s", server_id)
    except Exception:
        logger.exception("Background post-collection detection failed server_id=%s", server_id)
    finally:
        session.close()


class ServerService:
    """Manage servers, connections, and per-server log collection."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._health = HealthService(session)

    def list_servers(self, *, active_only: bool = False, owner_id: str | None = None, account_id: str | None = None) -> list[Server]:
        return server_crud.list_servers(self._session, active_only=active_only, owner_id=owner_id, account_id=account_id)

    def get_server(self, server_id: str) -> Server:
        server = server_crud.get_server(self._session, server_id)
        if server is None:
            raise ResourceNotFoundError(f"Server '{server_id}' not found.")
        return server

    def create_server(
        self,
        *,
        server_name: str,
        host: str,
        username: str,
        authentication_type: str,
        password: str | None = None,
        private_key: str | None = None,
        port: int = 22,
        operating_system: str | None = "linux",
        environment: str = "production",
        description: str | None = None,
        created_by: str | None = None,
    ) -> Server:
        auth = self._normalize_auth_type(authentication_type)
        self._validate_ssh_fields(host, username, auth, password, private_key)
        account_id = None
        if created_by:
            owner = self._session.get(User, created_by)
            account_id = getattr(owner, "account_id", None) if owner else None
        server = server_crud.create_server(
            self._session,
            {
                "server_name": server_name.strip(),
                "host": host.strip(),
                "port": port,
                "username": username.strip(),
                "authentication_type": auth,
                "encrypted_password": encrypt_secret(password) if auth == "password" and password else None,
                "encrypted_private_key": encrypt_secret(private_key) if auth == "ssh_key" and private_key else None,
                "operating_system": operating_system,
                "environment": self._normalize_environment(environment),
                "description": description,
                "status": "active",
                "health_status": HealthStatus.UNKNOWN,
                "owner_id": created_by,
                "account_id": account_id,
                "created_by": created_by,
            },
        )
        self._session.commit()
        get_health_engine().trigger_async(server_id=server.id)
        return server

    def update_server(self, server_id: str, updates: dict[str, Any]) -> Server:
        server = self.get_server(server_id)
        payload = dict(updates)

        if "authentication_type" in payload and payload["authentication_type"]:
            payload["authentication_type"] = self._normalize_auth_type(payload["authentication_type"])

        password = payload.pop("password", None)
        private_key = payload.pop("private_key", None)
        if "username" in payload and payload["username"] is not None:
            username = payload["username"].strip()
            if not username:
                raise ValidationException("Username cannot be empty.")
            # The stored secret belongs to the current account; keeping it for another account cannot work.
            if username != server.username and not (password or private_key):
                raise ValidationException(
                    "Changing the SSH username requires a new password or private key for that account."
                )
            payload["username"] = username
        # Set directly: server_crud.update_server ignores None, and the previous secret must be cleared.
        if password:
            server.encrypted_password = encrypt_secret(password)
            server.encrypted_private_key = None
            payload["authentication_type"] = "password"
        elif private_key:
            server.encrypted_private_key = encrypt_secret(private_key)
            server.encrypted_password = None
            payload["authentication_type"] = "ssh_key"

        if "status" in payload and payload["status"] == "inactive":
            payload["status"] = "inactive"
            payload["health_status"] = HealthStatus.UNKNOWN
        elif "status" in payload and payload["status"] == "active":
            payload["status"] = "active"

        if "server_name" in payload and payload["server_name"]:
            payload["server_name"] = payload["server_name"].strip()
        if "environment" in payload and payload["environment"]:
            payload["environment"] = self._normalize_environment(payload["environment"])

        updated = server_crud.update_server(self._session, server, payload)
        self._session.commit()
        if updated.status != "inactive":
            get_health_engine().trigger_async(server_id=updated.id)
        return updated

    def list_server_rows(self, *, active_only: bool = False, owner_id: str | None = None, account_id: str | None = None) -> list[dict[str, Any]]:
        return [self._server_to_dict(server) for server in self.list_servers(active_only=active_only, owner_id=owner_id, account_id=account_id)]

    def server_row(self, server_id: str) -> dict[str, Any]:
        return self._server_to_dict(self.get_server(server_id))

    def delete_server(self, server_id: str) -> None:
        server = self.get_server(server_id)
        server_crud.delete_server(self._session, server)
        self._session.commit()

    def refresh_server_statuses(
        self,
        *,
        owner_id: str | None = None,
        server_id: str | None = None,
    ) -> dict[str, Any]:
        """Queue a non-blocking health check cycle."""
        return get_health_engine().trigger_async(owner_id=owner_id, server_id=server_id)

    def test_connection(self, server_id: str) -> dict[str, Any]:
        server = self.get_server(server_id)
        result = SSHService.test_connection(server)
        if server.status == "inactive":
            health_status = HealthStatus.UNKNOWN
        elif result["success"]:
            health_status = HealthStatus.ONLINE
        else:
            health_status = result.get("health_status") or HealthStatus.OFFLINE

        updates: dict[str, Any] = {}
        if result.get("operating_system"):
            updates["operating_system"] = result["operating_system"]
        if updates:
            server_crud.update_server(self._session, server, updates)

        server_crud.apply_health_result(
            self._session,
            server,
            HealthCheckResult(
                server_id=server.id,
                health_status=health_status,
                latency_ms=result.get("latency_ms"),
                error_message=None if result["success"] else result.get("message"),
                checked_at=datetime.now(timezone.utc),
            ),
        )
        self._session.commit()
        result["status"] = server.status
        result["health_status"] = health_status
        result["connection_state"] = health_label(health_status)
        return result

    def diagnose_server(self, server_id: str) -> dict[str, Any]:
        """Stepwise SSH diagnostic with stored credentials; does not change health state."""
        server = self.get_server(server_id)
        report = SSHService.diagnose_server(server)
        report["server_id"] = server.id
        report["server_name"] = server.server_name
        return report

    def test_credentials(
        self,
        *,
        host: str,
        port: int,
        username: str,
        authentication_type: str,
        password: str | None = None,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        """Test SSH before saving server — credentials are not persisted."""
        auth = self._normalize_auth_type(authentication_type)
        self._validate_ssh_fields(host, username, auth, password, private_key)
        return SSHService.test_credentials(
            host=host.strip(),
            port=port,
            username=username.strip(),
            authentication_type=auth,
            password=password,
            private_key=private_key,
        )

    def collect_for_server(
        self,
        server_id: str,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
        requested_by: User | None = None,
    ) -> dict[str, Any]:
        """`requested_by` is the user of a manual collection; scheduled and internal runs leave it unset."""
        server = self.get_server(server_id)
        if server.status == "inactive":
            raise ValidationException(f"Server '{server.server_name}' is inactive.")

        run = server_crud.create_collection_run(self._session, server.id)
        self._session.commit()

        started = time.perf_counter()
        pipeline = PipelineService(self._session)
        try:
            config = SSHService.config_from_server(server)
        except ValueError as exc:
            self._health.record_collection_failure(
                server,
                error_message=str(exc),
                health_status=HealthStatus.CREDENTIAL_ERROR,
            )
            server_crud.complete_collection_run(
                self._session,
                run,
                status="failed",
                stats={"processed": 0, "inserted": 0, "duplicates": 0, "failed": 1, "skipped": 0},
                error_message=str(exc),
            )
            self._session.commit()
            raise ValidationException(f"Server '{server.server_name}': {exc}") from exc
        try:
            stats = pipeline.collect_and_process(
                config,
                tail_lines=tail_lines,
                log_sources=log_sources,
                server_id=server.id,
                owner_id=server.owner_id or server.created_by,
                server_name=server.server_name,
            )
            duration_ms = int((time.perf_counter() - started) * 1000)
            stats["duration_ms"] = duration_ms
            stats["server_id"] = server.id
            stats["collected_events"] = stats.get("inserted", 0)
            collect_errors = [e for e in stats.get("errors", []) if e.get("stage") == "collect"]
            ssh_failed = bool(collect_errors)
            stats["success"] = not ssh_failed and stats.get("failed", 0) == 0

            if stats["success"]:
                self._health.record_collection_success(server)
            else:
                self._health.record_collection_failure(
                    server,
                    error_message=collect_errors[0].get("error") if collect_errors else "Collection pipeline failed.",
                    ssh_failed=ssh_failed,
                    health_status=collect_errors[0].get("health_status") if collect_errors else None,
                )

            server_crud.complete_collection_run(
                self._session,
                run,
                status="completed" if stats["success"] else "failed",
                stats=stats,
            )
            self._session.commit()
            if stats.get("success"):
                presentation = record_linux_presentation_trigger(self._session, user=requested_by, server=server, run=run)
                if presentation is not None:
                    stats["presentation_trigger"] = presentation["trigger"]
                owner_id = server.owner_id or server.created_by
                stats["collection_n8n"] = record_linux_success(
                    self._session,
                    collection_run_id=run.id,
                    owner_id=owner_id,
                    account_id=server.account_id,
                    completed_at=getattr(run, "completed_at", None),
                )
                # One background detection pass for this server scope; do not start a second thread here.
                threading.Thread(
                    target=_run_post_collection_detection,
                    args=(owner_id, server.id, server.account_id),
                    daemon=True,
                    name=f"post-collect-detection-{server.id}",
                ).start()
                stats["detection"] = {
                    "status": "queued",
                    "message": (
                        "Detection started in the background for this server. "
                        "Refresh DefenSync Intelligence for status and predictions."
                    ),
                }
            return stats
        except Exception as exc:
            # SSH/retrieval errors are returned as "collect" stats above, so anything raised here
            # happened while processing or storing logs that were already retrieved.
            logger.exception("Collection processing failed for server=%s run=%s", server_id, run.id)
            self._session.rollback()
            self._health.record_collection_failure(
                server,
                error_message=f"Log processing failed: {type(exc).__name__}",
                ssh_failed=False,
            )
            server_crud.complete_collection_run(
                self._session,
                run,
                status="failed",
                stats={"processed": 0, "inserted": 0, "duplicates": 0, "failed": 1, "skipped": 0},
                error_message=str(exc),
            )
            self._session.commit()
            raise CollectionProcessingError(
                f"Logs were retrieved from '{server.server_name}', but processing failed "
                f"({type(exc).__name__}). No events were stored; check the backend log for run {run.id}.",
                stage="process",
                run_id=run.id,
                server_id=server.id,
            ) from exc

    def collect_all_active(
        self,
        *,
        tail_lines: int | None = None,
        log_sources: frozenset[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Iterate all active servers and collect logs."""
        results: list[dict[str, Any]] = []
        for server in self.list_servers(active_only=True):
            try:
                stats = self.collect_for_server(
                    server.id,
                    tail_lines=tail_lines,
                    log_sources=log_sources,
                )
                results.append({"server_id": server.id, "server_name": server.server_name, **stats})
            except Exception as exc:
                results.append({
                    "server_id": server.id,
                    "server_name": server.server_name,
                    "success": False,
                    "errors": [{"stage": "collect", "error": str(exc)}],
                })
        return results

    def server_stats(self, server_id: str) -> dict[str, Any]:
        server = self.get_server(server_id)
        return {
            "server_id": server.id,
            "server_name": server.server_name,
            "host": server.host,
            "port": server.port,
            "status": server.status,
            "health_status": server.health_status,
            "connection_latency_ms": server.connection_latency_ms,
            "last_connected": server.last_connected,
            "last_seen": server.last_seen or server.last_connected,
            "last_health_check": server.last_health_check,
            "last_successful_collection": server.last_successful_collection,
            "health_error_message": server.health_error_message,
            "consecutive_failures": server.consecutive_failures,
            "event_count": server_crud.count_events_for_server(self._session, server.id),
            "recent_collections": [
                {
                    "id": run.id,
                    "status": run.status,
                    "inserted": run.inserted,
                    "started_at": run.started_at,
                    "duration_ms": run.duration_ms,
                }
                for run in server_crud.list_collection_runs(self._session, server.id, limit=10)
            ],
        }

    def _server_to_dict(self, server: Server) -> dict[str, Any]:
        latest = server_crud.latest_collection_run(self._session, server.id)
        risk_score = server_crud.average_risk_for_server(self._session, server.id)
        health = server.health_status or HealthStatus.UNKNOWN
        return {
            "id": server.id,
            "server_name": server.server_name,
            "host": server.host,
            "port": server.port,
            "username": server.username,
            "authentication_type": server.authentication_type,
            "operating_system": server.operating_system,
            "environment": server.environment,
            "description": server.description,
            "owner_id": server.owner_id or server.created_by,
            "status": server.status,
            "health_status": health,
            "connection_state": health_label(health) if server.status != "inactive" else "Inactive",
            "connection_latency_ms": server.connection_latency_ms,
            "last_seen": server.last_seen or server.last_connected,
            "last_connected": server.last_connected,
            "last_health_check": server.last_health_check,
            "last_successful_collection": server.last_successful_collection,
            "health_error_message": server.health_error_message,
            "consecutive_failures": server.consecutive_failures or 0,
            "last_collection": latest.completed_at or latest.started_at if latest else None,
            "last_collection_status": latest.status if latest else None,
            "risk_score": risk_score,
            "high_risk_count": server_crud.high_risk_count_for_server(self._session, server.id),
            "created_by": server.created_by,
            "created_at": server.created_at,
            "updated_at": server.updated_at,
        }

    @staticmethod
    def _normalize_auth_type(auth_type: str) -> str:
        normalized = auth_type.strip().lower()
        if normalized in {"ssh_key", "private_key", "key"}:
            return "ssh_key"
        return "password"

    @staticmethod
    def _normalize_environment(environment: str | None) -> str:
        value = (environment or "production").strip().lower()
        if value not in {"production", "development", "testing"}:
            raise ValidationException("environment must be production, development, or testing.")
        return value

    @staticmethod
    def _validate_ssh_fields(
        host: str,
        username: str,
        auth_type: str,
        password: str | None,
        private_key: str | None,
    ) -> None:
        if not host or not username:
            raise ValidationException("Host and username are required.")
        if auth_type not in {"password", "ssh_key"}:
            raise ValidationException("authentication_type must be 'password' or 'ssh_key'.")
        if auth_type == "password" and (not password or len(password.strip()) < 1):
            raise ValidationException("Password is required for password authentication.")
        if auth_type == "ssh_key" and (not private_key or len(private_key.strip()) < 10):
            raise ValidationException("Valid private key PEM content is required.")
        if any(c in host for c in (";", "&", "|", "`", "$")):
            raise ValidationException("Invalid characters in host.")
