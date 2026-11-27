"""Normalize Log Analytics `SigninLogs` (Entra) and `AzureActivity` rows into the events table.

Every normalized row is real Azure telemetry: source_type=CLOUD, provider=AZURE,
data_scope=PRIVATE, data_origin=AZURE_LOG_ANALYTICS. It is never a dataset import.

Identity: `owner_id` is the DefenSync user who ran the collection and `account_id`
is the DefenSync account (tenant ACL) the telemetry belongs to. The Azure identity
the record describes is stored separately: `actor_id` is the Entra object ID when
the record has one (otherwise the UPN / caller), `username` is the UPN / caller,
and `normalized_data.cloud_identity` keeps tenant, object ID, UPN, and application.

Dedup: `azure_event_hash` is namespaced (scheme + DefenSync account + Azure tenant
+ source + Azure record ID), so it never collides with the global Linux/dataset
hash and two accounts or two Azure identities never collapse into one row.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime
from typing import Any

from backend.core.environments import CLOUD
from backend.core.privacy import redact_secrets
from backend.core.timestamps import parse_occurrence
from backend.database.models import DATA_SCOPE_PRIVATE
from backend.services.cloud.azure_client import parse_dynamic
from backend.services.datasets.azure_import_service import classify_azure_event

PROVIDER = "AZURE"
DATA_ORIGIN = "AZURE_LOG_ANALYTICS"
DEDUP_SCHEME = "AZURE_ACCOUNT_SCOPED_V1"
ENTRA_SIGNIN = "ENTRA_SIGNIN"
AZURE_ACTIVITY = "AZURE_ACTIVITY"
SOURCE_TABLES = {ENTRA_SIGNIN: "SigninLogs", AZURE_ACTIVITY: "AzureActivity"}

_EVENT_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "defensync:azure-telemetry")
_UPN_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
_NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
_OBJECT_ID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_RESOURCE_TYPE = re.compile(r"/providers/([^/]+)/([^/]+)", re.IGNORECASE)
_RECORD_ID_FIELDS = {ENTRA_SIGNIN: ("Id", "_ItemId"), AZURE_ACTIVITY: ("EventDataId", "_ItemId")}
_IDENTIFYING_FIELDS = {
    ENTRA_SIGNIN: ("Id", "_ItemId", "UserId", "UserPrincipalName", "CorrelationId", "AppId"),
    AZURE_ACTIVITY: ("EventDataId", "_ItemId", "Caller", "OperationNameValue", "OperationName", "CorrelationId"),
}
_FAILED_STATUSES = {"failed", "failure"}


class MalformedAzureRecord(ValueError):
    """A Log Analytics row that cannot be normalized; the message never includes record content."""


def normalize_record(
    source: str,
    record: Any,
    *,
    owner_id: str,
    account_id: str | None,
    collected_at: datetime,
    collection_id: str,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise MalformedAzureRecord("Row is not a column/value record.")
    if not any(record.get(name) not in (None, "") for name in _IDENTIFYING_FIELDS[source]):
        raise MalformedAzureRecord("Row has no Azure record ID, identity, or operation.")
    record = {key: parse_dynamic(value) for key, value in record.items()}
    builder = _signin if source == ENTRA_SIGNIN else _activity
    fields, metadata, explicit_time = builder(record)
    occurrence = parse_occurrence(None, collected_at=collected_at, explicit=explicit_time)
    event_hash = azure_event_hash(source, record, owner_id=owner_id, account_id=account_id)
    failed = fields.pop("failed")
    metadata.update({
        "azure_source": source,
        "azure_table": SOURCE_TABLES[source],
        "collection_id": collection_id,
        "dedup_scheme": DEDUP_SCHEME,
        "timestamp_source": occurrence.source,
        "source_timestamp_raw": None if explicit_time in (None, "") else str(explicit_time),
    })
    return {
        "event_id": str(uuid.uuid5(_EVENT_ID_NAMESPACE, event_hash)),
        "hash": event_hash,
        "timestamp": occurrence.event_time,
        "collection_timestamp": collected_at,
        "timestamp_source": occurrence.source,
        "category": "cloud",
        "severity": "medium" if failed else "info",
        "risk_score": 70 if failed else 20,
        "raw_log": redact_secrets(json.dumps(record, default=str, sort_keys=True)),
        "normalized_data": json.dumps(metadata, default=str),
        "source_type": CLOUD,
        "provider": PROVIDER,
        "data_origin": DATA_ORIGIN,
        "data_scope": DATA_SCOPE_PRIVATE,
        "dataset_name": None,
        "owner_id": owner_id,
        "account_id": account_id,
        "server_id": None,
        "parser_status": "PARSED",
        **fields,
    }


def azure_event_hash(source: str, record: dict[str, Any], *, owner_id: str, account_id: str | None) -> str:
    """Account-scoped Azure dedup key. The Azure record ID identifies the event; without one the
    full record (including its identity) is fingerprinted, so different identities never merge."""
    scope = f"account:{account_id}" if account_id else f"owner:{owner_id}"
    record_id = next((str(record[name]) for name in _RECORD_ID_FIELDS[source] if record.get(name) not in (None, "")), None)
    key = f"id:{record_id}" if record_id else "record:" + json.dumps(record, default=str, sort_keys=True)
    material = "|".join((DEDUP_SCHEME, scope, str(record.get("TenantId") or ""), source, key))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _signin(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Any]:
    status = record.get("Status") if isinstance(record.get("Status"), dict) else {}
    result_type = record.get("ResultType")
    outcome = result_type if result_type not in (None, "") else status.get("errorCode")
    sign_in_failed = None if outcome in (None, "") else str(outcome).strip() != "0"
    operation = str(record.get("OperationName") or "Sign-in activity")
    event_type = classify_azure_event(record, operation=operation, sign_in=True, sign_in_failed=sign_in_failed)
    object_id = _text(record.get("UserId"))
    upn = _text(record.get("UserPrincipalName"))
    app_id = _text(record.get("AppId"))
    app_name = _text(record.get("AppDisplayName"))
    methods = record.get("AuthenticationDetails")
    result = "failure" if sign_in_failed else "success" if sign_in_failed is False else "unknown result"
    metadata = {
        "original_operation": operation,
        "record_id": _text(record.get("Id")),
        "correlation_id": _text(record.get("CorrelationId")),
        "cloud_identity": {
            "tenant_id": _text(record.get("TenantId")),
            "object_id": object_id,
            "user_principal_name": upn,
            "display_name": _text(record.get("UserDisplayName")),
            "identity_type": "user",
            "application_id": app_id,
        },
        "application": app_name,
        "client_app": _text(record.get("ClientAppUsed")),
        "resource_display_name": _text(record.get("ResourceDisplayName")),
        "device": record.get("DeviceDetail") if isinstance(record.get("DeviceDetail"), dict) else None,
        "location": record.get("LocationDetails") if isinstance(record.get("LocationDetails"), dict) else _text(record.get("Location")),
        "authentication_result": {
            "result_type": None if result_type in (None, "") else str(result_type),
            "error_code": status.get("errorCode"),
            "failure_reason": status.get("failureReason"),
            "result_description": _text(record.get("ResultDescription")),
        },
        "authentication_requirement": _text(record.get("AuthenticationRequirement")),
        "authentication_methods": sorted({
            str(item.get("authenticationMethod")) for item in methods if isinstance(item, dict) and item.get("authenticationMethod")
        }) if isinstance(methods, list) else [],
        "conditional_access_status": _text(record.get("ConditionalAccessStatus")),
        "is_interactive": record.get("IsInteractive"),
    }
    fields = {
        "hostname": "entra-id",
        "username": _clip(upn or record.get("UserDisplayName") or object_id, 100),
        "actor_id": _clip(object_id or upn, 255),
        "source_ip": _ip(record.get("IPAddress")),
        "event_type": event_type,
        "message": f"Entra sign-in {result} for {upn or object_id or 'unknown identity'} to {app_name or app_id or 'unknown application'}",
        "resource_id": _clip(app_id, 255),
        "resource_type": "ENTRA_APPLICATION" if app_id else None,
        "operation": operation,
        "failed": bool(sign_in_failed),
    }
    return fields, metadata, record.get("CreatedDateTime") or record.get("TimeGenerated")


def _activity(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Any]:
    claims = record.get("Claims_d") if isinstance(record.get("Claims_d"), dict) else record.get("Claims")
    claims = claims if isinstance(claims, dict) else {}
    authorization = record.get("Authorization_d") if isinstance(record.get("Authorization_d"), dict) else record.get("Authorization")
    authorization = authorization if isinstance(authorization, dict) else {}
    caller = _text(record.get("Caller"))
    upn = _text(claims.get(_UPN_CLAIM)) or _text(claims.get(_NAME_CLAIM)) or (caller if caller and "@" in caller else None)
    object_id = _text(claims.get(_OBJECT_ID_CLAIM))
    app_id = _text(claims.get("appid"))
    operation = str(record.get("OperationNameValue") or record.get("OperationName") or "AzureActivity")
    status = _text(record.get("ActivityStatusValue") or record.get("ActivityStatus"))
    resource_id = _text(record.get("_ResourceId") or record.get("ResourceId"))
    event_type = classify_azure_event(record, operation=operation, sign_in=False, sign_in_failed=None)
    identity_type = "user" if upn else "application" if caller and _GUID.match(caller) else "unknown"
    metadata = {
        "original_operation": operation,
        "operation_display_name": _text(record.get("OperationName")),
        "record_id": _text(record.get("EventDataId")),
        "correlation_id": _text(record.get("CorrelationId")),
        "cloud_identity": {
            "tenant_id": _text(record.get("TenantId")),
            "object_id": object_id,
            "user_principal_name": upn,
            "caller": caller,
            "identity_type": identity_type,
            "application_id": app_id,
        },
        "subscription_id": _text(record.get("SubscriptionId")),
        "resource_group": _text(record.get("ResourceGroup")),
        "resource_provider": _text(record.get("ResourceProviderValue") or record.get("ResourceProvider")),
        "resource_id_full": resource_id,
        "status": status,
        "sub_status": _text(record.get("ActivitySubstatusValue") or record.get("ActivitySubstatus")),
        "category": _text(record.get("CategoryValue") or record.get("Category")),
        "level": _text(record.get("Level")),
        "authorization": {key: authorization.get(key) for key in ("action", "scope") if authorization.get(key)},
    }
    fields = {
        "hostname": _clip(record.get("ResourceGroup") or "azure", 100),
        "username": _clip(upn or caller, 100),
        "actor_id": _clip(object_id or upn or caller, 255),
        "source_ip": _ip(record.get("CallerIpAddress")),
        "event_type": event_type,
        "message": f"{operation} {status or 'status unknown'} by {upn or caller or 'unknown caller'}",
        "resource_id": _clip(resource_id, 255),
        "resource_type": _clip(_resource_type(resource_id), 80),
        "operation": operation,
        "failed": (status or "").lower() in _FAILED_STATUSES,
    }
    return fields, metadata, record.get("TimeGenerated")


def _resource_type(resource_id: str | None) -> str | None:
    matches = _RESOURCE_TYPE.findall(resource_id or "")
    if not matches:
        return None
    namespace, kind = matches[-1]
    return f"{namespace}/{kind}"


def _text(value: Any) -> str | None:
    return None if value in (None, "") or isinstance(value, (dict, list)) else str(value)


def _clip(value: Any, limit: int) -> str | None:
    text = _text(value)
    return text[:limit] if text else None


def _ip(value: Any) -> str | None:
    text = _text(value)
    return text if text and len(text) <= 45 else None
