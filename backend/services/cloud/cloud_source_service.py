"""Account-owned cloud sources (CLOUD environment): Azure Log Analytics onboarding.

Credentials are validated with the collector's AzureConfig, the client secret is
stored with the same Fernet helper used for SSH credentials, and connection tests
and collections reuse LogAnalyticsClient / AzureCollector unchanged. Nothing here
returns or logs the client secret or an access token.

Every collection request with a valid window is recorded as a CloudCollectionRun
(window, row counts, SUCCESS / PARTIAL / FAILED, safe error code), including runs
that fail before Azure is reached.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any

from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.core.config import Settings, get_settings
from backend.core.encryption import CredentialDecryptionError, decrypt_secret, encrypt_secret
from backend.core.environments import CLOUD
from backend.core.exceptions import DefenSyncException, DuplicateResourceError, ResourceNotFoundError, ValidationException
from backend.core.timestamps import collection_now
from backend.database.connection import storage_timezone
from backend.database.models import Account, CloudCollectionRun, CloudSource, User
from backend.database.scope import cloud_source_visibility_clause, is_admin, resolve_account_id, user_can_access_cloud_source
from backend.services.alert_service import AlertService
from backend.services.cloud.azure_client import (
    AZURE_UNAVAILABLE,
    EXPIRED_CREDENTIALS,
    INVALID_CREDENTIALS,
    INVALID_TENANT,
    INVALID_WORKSPACE,
    PERMISSION_DENIED,
    RATE_LIMITED,
    TIMEOUT,
    AzureCollectorError,
    LogAnalyticsClient,
    Transport,
)
from backend.services.cloud.azure_collector import (
    OUTCOME_FAILED,
    OUTCOME_SUCCESS,
    REQUIRED_SETTINGS,
    STATUS_COLLECTION_OK,
    AzureCollector,
    AzureConfig,
    CollectionLimits,
    resolve_window,
    validate_collection_request,
)
from backend.services.cloud.presentation_telemetry import (
    cloud_demo_n8n_every_success,
    presentation_enabled,
    record_presentation_telemetry,
)
from backend.services.collection_n8n_trigger import TRIGGER_EVERY, dispatch_for_run, record_cloud_success

logger = logging.getLogger(__name__)

PROVIDER_AZURE = "AZURE"
SOURCE_AZURE_LOG_ANALYTICS = "AZURE_LOG_ANALYTICS"
PROVIDER_LABELS = {PROVIDER_AZURE: "Microsoft Azure"}
SOURCE_TYPE_LABELS = {SOURCE_AZURE_LOG_ANALYTICS: "Azure Log Analytics"}

CONNECTION_UNTESTED = "UNTESTED"
CONNECTION_CONNECTED = "CONNECTED"
CONNECTION_FAILED = "FAILED"

CONNECTION_FAILED_CODE = "CLOUD_CONNECTION_FAILED"
CREDENTIAL_UNREADABLE = "CREDENTIAL_UNREADABLE"
COLLECTION_ERROR = "COLLECTION_ERROR"
MAX_SECRET_LENGTH = 1024

RUN_RUNNING = "RUNNING"
MODE_LOOKBACK = "LOOKBACK"
MODE_HISTORICAL = "HISTORICAL"
DEFAULT_RUN_LIST_LIMIT = 20

# A constant expression: proves token + workspace read access without reading any table.
CONNECTION_TEST_QUERY = "print connection_test = 1"
CONNECTION_TEST_WINDOW = timedelta(minutes=5)

_FIELDS = dict(zip(REQUIRED_SETTINGS, ("tenant_id", "client_id", "client_secret", "workspace_id"), strict=True))
_FIELD_LABELS = {"tenant_id": "Tenant ID", "client_id": "Client ID", "client_secret": "Client Secret", "workspace_id": "Workspace ID"}

# The collector's messages name .env settings; onboarding forms name the form fields instead.
_FORM_MESSAGES = {
    INVALID_CREDENTIALS: "Azure rejected the credentials. Check the Tenant ID, Client ID and Client Secret.",
    EXPIRED_CREDENTIALS: "The client secret has expired. Create a new secret for the app registration.",
    INVALID_TENANT: "The Azure tenant was not found. Check the Tenant ID.",
    INVALID_WORKSPACE: "The Log Analytics workspace was not found. Check the Workspace ID (GUID).",
}
_CREDENTIAL_FAILURES = {INVALID_CREDENTIALS, EXPIRED_CREDENTIALS, INVALID_TENANT, INVALID_WORKSPACE, PERMISSION_DENIED, CREDENTIAL_UNREADABLE}
_TRANSIENT_FAILURES = {AZURE_UNAVAILABLE, RATE_LIMITED, TIMEOUT}


class CloudConnectionError(DefenSyncException):
    """Connection test failed during creation; carries only the safe Azure error code."""

    def __init__(self, error: dict[str, Any]) -> None:
        self.status_code = 422
        self.details = {"code": CONNECTION_FAILED_CODE, "azure_error": error}
        super().__init__(error["message"])


def azure_config(*, tenant_id: str, client_id: str, client_secret: str, workspace_id: str) -> AzureConfig:
    return AzureConfig(
        tenant_id=(tenant_id or "").strip(),
        client_id=(client_id or "").strip(),
        client_secret=(client_secret or "").strip(),
        workspace_id=(workspace_id or "").strip(),
    )


def validate_config(config: AzureConfig) -> None:
    """Field-level validation; messages name fields, never values."""
    missing = [_FIELD_LABELS[_FIELDS[name]] for name in config.missing()]
    if missing:
        raise ValidationException(f"Required: {', '.join(missing)}.")
    invalid = [_FIELD_LABELS[_FIELDS[name]] for name in config.invalid()]
    if invalid:
        raise ValidationException(f"Invalid format: {', '.join(invalid)}. Use the GUIDs shown in the Azure portal.")
    if len(config.client_secret) > MAX_SECRET_LENGTH:
        raise ValidationException("Client Secret is too long.")


def _safe_error(exc: AzureCollectorError) -> dict[str, Any]:
    return {"code": exc.code, "message": _FORM_MESSAGES.get(exc.code, exc.message), "retry_after": exc.retry_after}


def check_connection(config: AzureConfig, *, transport: Transport | None = None) -> dict[str, Any]:
    """Read-only: authenticate, then run a constant query against the workspace. Stores nothing."""
    tested_at = collection_now()
    client = LogAnalyticsClient(
        tenant_id=config.tenant_id,
        client_id=config.client_id,
        client_secret=config.client_secret,
        workspace_id=config.workspace_id,
        transport=transport,
    )
    try:
        client.query(CONNECTION_TEST_QUERY, start=tested_at - CONNECTION_TEST_WINDOW, end=tested_at)
    except AzureCollectorError as exc:
        return {"success": False, "status": CONNECTION_FAILED, "error": _safe_error(exc), "tested_at": tested_at.isoformat()}
    return {"success": True, "status": CONNECTION_CONNECTED, "error": None, "tested_at": tested_at.isoformat()}


def run_view(run: CloudCollectionRun, storage_tz: tzinfo = timezone.utc) -> dict[str, Any]:
    """Public representation of one collection run (no credentials are ever stored on it)."""
    return {
        "id": run.id,
        "cloud_source_id": run.cloud_source_id,
        "collection_id": run.collection_id,
        "mode": run.mode,
        "status": run.status,
        "started_at": _utc_iso(run.started_at, storage_tz),
        "window_start": _utc_iso(run.window_start, storage_tz),
        "window_end": _utc_iso(run.window_end, storage_tz),
        "completed_at": _utc_iso(run.completed_at, storage_tz),
        "max_records_per_source": run.max_records_per_source,
        "rows_retrieved": run.rows_retrieved,
        "rows_normalized": run.rows_normalized,
        "rows_failed": run.rows_failed,
        "rows_stored": run.rows_stored,
        "rows_duplicate": run.rows_duplicate,
        "truncated": bool(run.truncated),
        "error": {"code": run.error_code, "message": run.error_message} if run.error_code else None,
        "sources": json.loads(run.source_results) if run.source_results else [],
    }


def source_view(source: CloudSource, last_run: CloudCollectionRun | None = None, storage_tz: tzinfo = timezone.utc) -> dict[str, Any]:
    """Public representation. The secret is reported only as configured/not configured."""
    error = {"code": source.connection_error_code, "message": source.connection_error} if source.connection_error_code else None
    return {
        "id": source.id,
        "environment": CLOUD,
        "provider": source.provider,
        "provider_label": PROVIDER_LABELS.get(source.provider, source.provider),
        "source_type": source.source_type,
        "source_type_label": SOURCE_TYPE_LABELS.get(source.source_type, source.source_type),
        "tenant_id": source.tenant_id,
        "client_id": source.client_id,
        "workspace_id": source.workspace_id,
        "client_secret_configured": bool(source.encrypted_client_secret),
        "connection_status": source.connection_status,
        "last_connection_test": _iso(source.last_connection_test),
        "connection_error": error,
        "last_collection_at": _iso(source.last_collection_at),
        "last_collection_status": source.last_collection_status,
        "last_collection_error": source.last_collection_error,
        "last_successful_collection": _iso(source.last_successful_collection),
        "last_collection_run": run_view(last_run, storage_tz) if last_run is not None else None,
        "account_id": source.account_id,
        "owner_id": source.owner_id,
        "created_at": _iso(source.created_at),
        "updated_at": _iso(source.updated_at),
    }


class CloudSourceService:
    def __init__(self, session: Session, *, transport: Transport | None = None) -> None:
        self._session = session
        self._transport = transport

    def list_sources(self, user: User) -> list[CloudSource]:
        stmt = select(CloudSource).order_by(CloudSource.created_at)
        clause = cloud_source_visibility_clause(user)
        if clause is not None:
            stmt = stmt.where(clause)
        return list(self._session.scalars(stmt).all())

    def get_source(self, user: User, source_id: str) -> CloudSource:
        """Inaccessible sources are reported as not found so their existence is not revealed."""
        source = self._session.get(CloudSource, source_id)
        if source is None or not user_can_access_cloud_source(user, source):
            raise ResourceNotFoundError("Cloud source not found.")
        return source

    def test_credentials(self, config: AzureConfig) -> dict[str, Any]:
        validate_config(config)
        result = check_connection(config, transport=self._transport)
        logger.info("Cloud connection test (unsaved source): %s", result["error"]["code"] if result["error"] else CONNECTION_CONNECTED)
        return result

    def create(self, user: User, config: AzureConfig, *, account_id: str | None = None) -> CloudSource:
        validate_config(config)
        if is_admin(user):
            if account_id and self._session.get(Account, account_id) is None:
                raise ResourceNotFoundError(f"Account '{account_id}' not found.")
        else:
            account_id = resolve_account_id(user)
        self._reject_duplicate(user, config.workspace_id, account_id)

        result = check_connection(config, transport=self._transport)
        if not result["success"]:
            logger.info("Cloud source not created for user %s: connection test failed (%s)", user.id, result["error"]["code"])
            raise CloudConnectionError(result["error"])

        now = collection_now()
        source = CloudSource(
            provider=PROVIDER_AZURE,
            source_type=SOURCE_AZURE_LOG_ANALYTICS,
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            encrypted_client_secret=encrypt_secret(config.client_secret),
            workspace_id=config.workspace_id,
            connection_status=CONNECTION_CONNECTED,
            last_connection_test=now,
            owner_id=user.id,
            account_id=account_id,
            created_by=user.id,
            created_at=now,
            updated_at=now,
        )
        self._session.add(source)
        self._session.commit()
        logger.info("Cloud source %s (%s) created by user %s for account %s", source.id, source.source_type, user.id, account_id)
        return source

    def test_saved(self, user: User, source_id: str) -> dict[str, Any]:
        source = self.get_source(user, source_id)
        try:
            config = self._stored_config(source)
        except CredentialDecryptionError:
            result = {"success": False, "status": CONNECTION_FAILED, "tested_at": collection_now().isoformat(), "error": {
                "code": CREDENTIAL_UNREADABLE, "message": "The stored client secret can no longer be decrypted. Remove and re-add this cloud source.", "retry_after": None,
            }}
        else:
            result = check_connection(config, transport=self._transport)
        now = collection_now()
        source.last_connection_test = now
        source.updated_at = now
        if result["success"]:
            source.connection_status, source.connection_error_code, source.connection_error = CONNECTION_CONNECTED, None, None
        elif result["error"]["code"] not in _TRANSIENT_FAILURES:
            source.connection_status = CONNECTION_FAILED
            source.connection_error_code, source.connection_error = result["error"]["code"], result["error"]["message"]
        self._session.commit()
        logger.info("Cloud source %s connection test: %s", source.id, result["error"]["code"] if result["error"] else CONNECTION_CONNECTED)
        return {**result, "source": source_view(source)}

    def collection_limits(self) -> dict[str, int]:
        return CollectionLimits.from_settings(get_settings()).view()

    def collect(
        self,
        user: User,
        source_id: str,
        *,
        lookback_minutes: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        max_records: int | None = None,
        sources: list[str] | None = None,
    ) -> dict[str, Any]:
        """Manual read-only collection into the source's account, via the existing AzureCollector.

        Either a recent lookback or an explicit (historical) start/end window. Invalid windows are
        rejected before anything is recorded; every accepted request is stored as a run.
        """
        source = self.get_source(user, source_id)
        app_settings = get_settings()
        limits = CollectionLimits.from_settings(app_settings)
        requested_at = collection_now()
        try:
            window_start, window_end = resolve_window(
                lookback_minutes=lookback_minutes, start=start, end=end, now=requested_at, limits=limits,
            )
            selected, limit = validate_collection_request(sources, max_records)
        except ValueError as exc:
            raise ValidationException(str(exc)) from exc

        run = CloudCollectionRun(
            cloud_source_id=source.id,
            account_id=source.account_id,
            requested_by=user.id,
            mode=MODE_HISTORICAL if start is not None else MODE_LOOKBACK,
            status=RUN_RUNNING,
            started_at=requested_at,
            window_start=window_start,
            window_end=window_end,
            max_records_per_source=limit,
        )
        self._session.add(run)
        self._session.commit()

        try:
            config = self._stored_config(source)
        except CredentialDecryptionError as exc:
            message = "The stored client secret can no longer be decrypted. Remove and re-add this cloud source."
            self._fail_run(run, CREDENTIAL_UNREADABLE, message)
            raise ValidationException(message) from exc
        settings = Settings.model_construct(
            AZURE_TENANT_ID=config.tenant_id,
            AZURE_CLIENT_ID=config.client_id,
            AZURE_CLIENT_SECRET=SecretStr(config.client_secret),
            AZURE_LOG_ANALYTICS_WORKSPACE_ID=config.workspace_id,
            CLOUD_COLLECTION_MAX_WINDOW_HOURS=limits.max_window_hours,
            CLOUD_COLLECTION_MAX_HISTORY_DAYS=limits.max_history_days,
        )
        try:
            result = AzureCollector(self._session, settings=settings, transport=self._transport).collect(
                owner_id=user.id, account_id=source.account_id, lookback_minutes=lookback_minutes,
                start=start, end=end, sources=selected, max_records=limit, now=requested_at,
            )
        except ValueError as exc:
            self._session.rollback()
            self._fail_run(run, COLLECTION_ERROR, str(exc))
            raise ValidationException(str(exc)) from exc
        except Exception as exc:
            self._session.rollback()
            self._fail_run(run, COLLECTION_ERROR, "The collection stopped unexpectedly. Rows stored before the error are kept.")
            logger.error("Cloud source %s collection run %s stopped: %s", source.id, run.id, type(exc).__name__)
            raise
        self._complete_run(run, result)

        now = collection_now()
        error = result.get("error") or None
        source.last_collection_at = now
        source.last_collection_status = result["status"]
        source.last_collection_error = error.get("message") if error else None
        if result["status"] == STATUS_COLLECTION_OK:
            source.last_successful_collection = now
            source.connection_status, source.connection_error_code, source.connection_error = CONNECTION_CONNECTED, None, None
        elif error and error.get("code") in _CREDENTIAL_FAILURES:
            source.connection_status = CONNECTION_FAILED
            source.connection_error_code = error["code"]
            source.connection_error = _FORM_MESSAGES.get(error["code"], error.get("message"))
        source.updated_at = now
        self._session.commit()
        logger.info(
            "Cloud source %s collection run %s (%s): %s retrieved=%d stored=%d duplicates=%d",
            source.id, run.id, run.mode, run.status, run.rows_retrieved, run.rows_stored, run.rows_duplicate,
        )
        storage_tz = self.storage_tz()
        presentation = None
        collection_n8n = None
        demo_feedback: dict[str, Any] = {
            "presentation_enabled": False,
            "demo_incident_created": False,
            "demo_event_id": None,
            "n8n_policy": f"alternate_every_{TRIGGER_EVERY}",
        }
        if run.status == OUTCOME_SUCCESS and result["status"] == STATUS_COLLECTION_OK:
            # presentation_telemetry.get_settings is patched in tests; do not force cloud get_settings here.
            demo_feedback["presentation_enabled"] = presentation_enabled(user, source)
            presentation = record_presentation_telemetry(
                self._session, user=user, source=source, run=run, storage_tz=storage_tz,
            )
            # Cloud DEMO notify-every-success is independent of Linux alternate every-2.
            # When enabled and a demo incident exists for this run, trigger_every=1 + security_demo.
            demo_n8n = (
                cloud_demo_n8n_every_success()
                and presentation is not None
                and presentation.get("security_demo")
            )
            if demo_n8n:
                demo_feedback["n8n_policy"] = "cloud_demo_every_success"
            collection_n8n = record_cloud_success(
                self._session,
                collection_run_id=run.id,
                owner_id=user.id,
                account_id=source.account_id,
                completed_at=run.completed_at,
                security_demo=(presentation or {}).get("security_demo") if demo_n8n else None,
                trigger_every=1 if demo_n8n else TRIGGER_EVERY,
                policy="cloud_demo_every_success" if demo_n8n else "alternate_success",
            )
            if presentation:
                demo_feedback["demo_incident_created"] = bool(presentation.get("demo_incident_created"))
                demo_feedback["demo_event_id"] = presentation.get("trigger_event_id")
                demo_feedback["trigger_risk_score"] = presentation.get("trigger_risk_score")
        # Rule alerts for newly stored high-risk cloud events (does not invent severity).
        alerts_created = 0
        if int(result.get("records_inserted") or 0) > 0 or (presentation and presentation.get("alert_created")):
            alerts_created = AlertService(self._session).sync_from_events(owner_id=user.id)
        run_payload = run_view(run, storage_tz)
        if collection_n8n is not None:
            run_payload["collection_n8n"] = collection_n8n
        elif run.status == OUTCOME_SUCCESS:
            prior = dispatch_for_run(self._session, source_type=CLOUD, collection_run_id=run.id)
            if prior:
                run_payload["collection_n8n"] = prior
        response = {
            **result,
            "cloud_source_id": source.id,
            "source": source_view(source, run, storage_tz),
            "collection_run": run_payload,
            "alerts_created": alerts_created,
            "demo_feedback": demo_feedback,
        }
        if presentation is not None:
            response["presentation_trigger"] = presentation["trigger"]
            if presentation.get("security_demo"):
                response["security_demo"] = presentation["security_demo"]
            if presentation.get("trigger_risk_score") is not None:
                response["presentation_trigger_risk_score"] = presentation["trigger_risk_score"]
        if collection_n8n is not None:
            response["collection_n8n"] = collection_n8n
        return response

    def storage_tz(self) -> tzinfo:
        return storage_timezone(self._session)

    def latest_run(self, source_id: str) -> CloudCollectionRun | None:
        stmt = (
            select(CloudCollectionRun)
            .where(CloudCollectionRun.cloud_source_id == source_id)
            .order_by(CloudCollectionRun.started_at.desc(), CloudCollectionRun.id.desc())
            .limit(1)
        )
        return self._session.scalar(stmt)

    def view(self, source: CloudSource) -> dict[str, Any]:
        return source_view(source, self.latest_run(source.id), self.storage_tz())

    def list_runs(self, user: User, source_id: str, *, limit: int = DEFAULT_RUN_LIST_LIMIT) -> list[CloudCollectionRun]:
        source = self.get_source(user, source_id)
        stmt = (
            select(CloudCollectionRun)
            .where(CloudCollectionRun.cloud_source_id == source.id)
            .order_by(CloudCollectionRun.started_at.desc(), CloudCollectionRun.id.desc())
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())

    def get_run(self, user: User, source_id: str, run_id: str) -> CloudCollectionRun:
        source = self.get_source(user, source_id)
        run = self._session.get(CloudCollectionRun, run_id)
        if run is None or run.cloud_source_id != source.id:
            raise ResourceNotFoundError("Collection run not found.")
        return run

    def delete(self, user: User, source_id: str) -> None:
        source = self.get_source(user, source_id)
        self._session.execute(delete(CloudCollectionRun).where(CloudCollectionRun.cloud_source_id == source.id))
        self._session.delete(source)
        self._session.commit()
        logger.info("Cloud source %s deleted by user %s", source_id, user.id)

    def _complete_run(self, run: CloudCollectionRun, result: dict[str, Any]) -> None:
        sources = result.get("sources") or []
        issues = result.get("issues") or []
        error = result.get("error") or None
        run.collection_id = result.get("collection_id")
        run.status = result.get("outcome") or OUTCOME_FAILED
        run.completed_at = collection_now()
        run.rows_retrieved = int(result.get("records_retrieved") or 0)
        run.rows_normalized = int(result.get("records_normalized") or 0)
        run.rows_failed = int(result.get("records_failed") or 0)
        run.rows_stored = int(result.get("records_inserted") or 0)
        run.rows_duplicate = int(result.get("records_deduplicated") or 0)
        run.truncated = any(item.get("truncated") for item in sources)
        if error:
            run.error_code, run.error_message = error.get("code"), error.get("message")
        elif issues:
            run.error_code = issues[0]["code"]
            run.error_message = " ".join(f"{item['source']}: {item['message']}" for item in issues)[:2000]
        else:
            run.error_code = run.error_message = None
        run.source_results = json.dumps([
            {key: item.get(key) for key in ("source", "table", "status", "message", "warning", "retrieved", "normalized", "failed", "truncated", "resume_from")}
            for item in sources
        ])
        self._session.commit()

    def _fail_run(self, run: CloudCollectionRun, code: str, message: str) -> None:
        run.status = OUTCOME_FAILED
        run.completed_at = collection_now()
        run.error_code = code
        run.error_message = message
        self._session.commit()

    def _reject_duplicate(self, user: User, workspace_id: str, account_id: str | None) -> None:
        stmt = select(CloudSource.id).where(CloudSource.provider == PROVIDER_AZURE, CloudSource.workspace_id == workspace_id)
        stmt = stmt.where(CloudSource.account_id == account_id) if account_id else stmt.where(CloudSource.account_id.is_(None), CloudSource.owner_id == user.id)
        if self._session.scalar(stmt.limit(1)) is not None:
            raise DuplicateResourceError("This Log Analytics workspace is already registered as a cloud source.")

    @staticmethod
    def _stored_config(source: CloudSource) -> AzureConfig:
        return azure_config(
            tenant_id=source.tenant_id,
            client_id=source.client_id,
            client_secret=decrypt_secret(source.encrypted_client_secret),
            workspace_id=source.workspace_id,
        )


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _utc_iso(value: datetime | None, storage_tz: tzinfo) -> str | None:
    """Naive DateTime column values are wall clock in the storage zone; report them as UTC."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=storage_tz)
    return value.astimezone(timezone.utc).isoformat()
