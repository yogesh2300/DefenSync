"""Read-only Azure Monitor Log Analytics client using the official REST APIs.

Authentication: Microsoft Entra OAuth 2.0 client-credentials flow for a service
principal (POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token).
Query: Log Analytics Query API (POST https://api.loganalytics.io/v1/workspaces/{id}/query).

Both calls only read. The client exposes no operation that changes Azure.
Error messages are built from fixed text plus Azure error *codes* only; response
bodies, tokens, and the client secret never appear in messages or logs.
"""

from __future__ import annotations

import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace}/query"
LOG_ANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
HTTP_TIMEOUT_SECONDS = 30.0

NOT_CONFIGURED = "NOT_CONFIGURED"
INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
EXPIRED_CREDENTIALS = "EXPIRED_CREDENTIALS"
INVALID_TENANT = "INVALID_TENANT"
AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
INVALID_WORKSPACE = "INVALID_WORKSPACE"
PERMISSION_DENIED = "PERMISSION_DENIED"
SOURCE_NOT_AVAILABLE = "SOURCE_NOT_AVAILABLE"
QUERY_FAILED = "QUERY_FAILED"
RATE_LIMITED = "RATE_LIMITED"
TIMEOUT = "TIMEOUT"
AZURE_UNAVAILABLE = "AZURE_UNAVAILABLE"
MALFORMED_RESPONSE = "MALFORMED_RESPONSE"

# Microsoft Entra AADSTS error codes returned by the token endpoint.
_TOKEN_ERRORS = {
    7000215: (INVALID_CREDENTIALS, "Azure rejected the client secret. Check AZURE_CLIENT_SECRET."),
    7000222: (EXPIRED_CREDENTIALS, "The Azure client secret has expired. Create a new secret for the app registration and update AZURE_CLIENT_SECRET."),
    700016: (INVALID_CREDENTIALS, "The application was not found in the tenant. Check AZURE_CLIENT_ID and AZURE_TENANT_ID."),
    90002: (INVALID_TENANT, "The Azure tenant was not found. Check AZURE_TENANT_ID."),
    900023: (INVALID_TENANT, "AZURE_TENANT_ID is not a valid tenant identifier."),
}
_SAFE_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_.]{0,63}$")
_MISSING_TABLE = re.compile(r"Failed to resolve (?:table|scalar|table or column) expression", re.IGNORECASE)


class AzureCollectorError(Exception):
    """Safe, actionable collector error. `message` never contains secrets or response bodies."""

    def __init__(self, code: str, message: str, *, retry_after: str | None = None) -> None:
        self.code = code
        self.message = message
        self.retry_after = retry_after
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


Transport = Callable[[str, bytes, dict[str, str], float], HttpResponse]


def urllib_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> HttpResponse:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed https Azure endpoints
            return HttpResponse(response.status, response.read(), dict(response.headers))
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, exc.read() or b"", dict(exc.headers or {}))


@dataclass(frozen=True)
class QueryResult:
    columns: list[dict[str, Any]]
    rows: list[Any]
    partial_error: str | None = None


class LogAnalyticsClient:
    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        workspace_id: str,
        transport: Transport | None = None,
        timeout: float = HTTP_TIMEOUT_SECONDS,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._workspace_id = workspace_id
        self._transport = transport or urllib_transport
        self._timeout = timeout
        self._token: str | None = None

    def __repr__(self) -> str:
        return "LogAnalyticsClient(workspace=<configured>)"

    def query(self, kql: str, *, start: datetime, end: datetime) -> QueryResult:
        body = json.dumps({"query": kql, "timespan": f"{_iso(start)}/{_iso(end)}"}).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self._access_token()}",
            "Content-Type": "application/json",
            "Prefer": "include-statistics=false",
        }
        url = QUERY_URL.format(workspace=urllib.parse.quote(self._workspace_id, safe=""))
        response = self._send(url, body, headers)
        if response.status != 200:
            raise _query_error(response)
        payload = _json(response.body)
        tables = payload.get("tables") if isinstance(payload, dict) else None
        if not isinstance(tables, list) or not tables or not isinstance(tables[0], dict):
            raise AzureCollectorError(MALFORMED_RESPONSE, "Log Analytics returned a response without a result table.")
        table = tables[0]
        columns = table.get("columns") if isinstance(table.get("columns"), list) else []
        rows = table.get("rows") if isinstance(table.get("rows"), list) else []
        partial = payload.get("error")
        partial_code = _safe_code(partial.get("code")) if isinstance(partial, dict) else None
        return QueryResult(columns=columns, rows=rows, partial_error=partial_code)

    def _access_token(self) -> str:
        if self._token:
            return self._token
        body = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": LOG_ANALYTICS_SCOPE,
        }).encode("utf-8")
        url = TOKEN_URL.format(tenant=urllib.parse.quote(self._tenant_id, safe=""))
        response = self._send(url, body, {"Content-Type": "application/x-www-form-urlencoded"})
        payload = _json(response.body)
        if response.status == 200 and isinstance(payload, dict) and payload.get("access_token"):
            self._token = str(payload["access_token"])
            return self._token
        raise _token_error(response, payload)

    def _send(self, url: str, body: bytes, headers: dict[str, str]) -> HttpResponse:
        try:
            return self._transport(url, body, headers, self._timeout)
        except (TimeoutError, socket.timeout) as exc:
            raise AzureCollectorError(TIMEOUT, "Azure did not respond within the collector timeout.") from exc
        except urllib.error.URLError as exc:
            if isinstance(getattr(exc, "reason", None), (TimeoutError, socket.timeout)):
                raise AzureCollectorError(TIMEOUT, "Azure did not respond within the collector timeout.") from exc
            raise AzureCollectorError(AZURE_UNAVAILABLE, "Azure could not be reached (network error).") from exc
        except OSError as exc:
            raise AzureCollectorError(AZURE_UNAVAILABLE, "Azure could not be reached (network error).") from exc


def parse_dynamic(value: Any) -> Any:
    """Log Analytics returns `dynamic` columns as JSON text."""
    if isinstance(value, str) and value[:1] in {"{", "["}:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _token_error(response: HttpResponse, payload: Any) -> AzureCollectorError:
    codes = payload.get("error_codes") if isinstance(payload, dict) else None
    for code in codes or []:
        if isinstance(code, int) and code in _TOKEN_ERRORS:
            kind, message = _TOKEN_ERRORS[code]
            return AzureCollectorError(kind, message)
    if response.status == 429:
        return AzureCollectorError(RATE_LIMITED, "Microsoft Entra rate-limited the token request; retry later.", retry_after=_retry_after(response))
    if response.status >= 500:
        return AzureCollectorError(AZURE_UNAVAILABLE, f"Microsoft Entra is unavailable (HTTP {response.status}); retry later.")
    first = next((code for code in codes or [] if isinstance(code, int)), None)
    suffix = f" (AADSTS{first})" if first else f" (HTTP {response.status})"
    return AzureCollectorError(AUTHENTICATION_FAILED, f"Azure authentication failed{suffix}. Check the service principal configuration.")


def _query_error(response: HttpResponse) -> AzureCollectorError:
    payload = _json(response.body)
    error = payload.get("error") if isinstance(payload, dict) else None
    error = error if isinstance(error, dict) else {}
    inner = error.get("innererror") if isinstance(error.get("innererror"), dict) else {}
    code = _safe_code(inner.get("code")) or _safe_code(error.get("code"))
    text = " ".join(str(part) for part in (error.get("message"), inner.get("message")) if part)
    status = response.status
    if status == 401:
        return AzureCollectorError(INVALID_CREDENTIALS, "Log Analytics rejected the service principal token.")
    if status == 403:
        return AzureCollectorError(PERMISSION_DENIED, "The service principal has no read access to the workspace. Assign the 'Log Analytics Reader' role on the workspace.")
    if status == 404:
        return AzureCollectorError(INVALID_WORKSPACE, "Log Analytics workspace not found. AZURE_LOG_ANALYTICS_WORKSPACE_ID must be the workspace ID (GUID).")
    if status == 429:
        return AzureCollectorError(RATE_LIMITED, "Log Analytics rate-limited the query; retry later.", retry_after=_retry_after(response))
    if status in {408, 504}:
        return AzureCollectorError(TIMEOUT, "The Log Analytics query timed out; use a shorter window.")
    if status >= 500:
        return AzureCollectorError(AZURE_UNAVAILABLE, f"Log Analytics is unavailable (HTTP {status}); retry later.")
    if status == 400 and _MISSING_TABLE.search(text):
        return AzureCollectorError(SOURCE_NOT_AVAILABLE, "The table is not present in the workspace; configure the diagnostic setting that exports it.")
    return AzureCollectorError(QUERY_FAILED, f"Log Analytics query failed (HTTP {status}{', ' + code if code else ''}).")


def _retry_after(response: HttpResponse) -> str | None:
    for key, value in response.headers.items():
        if key.lower() == "retry-after" and str(value).isdigit():
            return str(value)
    return None


def _safe_code(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and _SAFE_CODE.match(value) else None


def _json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8")) if body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
