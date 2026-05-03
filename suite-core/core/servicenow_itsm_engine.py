"""ALDECI ServiceNow ITSM Engine.

Thin pass-through client for the **ServiceNow Table API** (`/api/now/table/`)
covering ITSM core records — incidents, change requests, generic tasks, users,
and CMDB CIs. Distinct from the bidirectional finding-sync engine in
``core/servicenow_sync.py``.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
all lookup endpoints return HTTP 503.

Environment variables
---------------------
SERVICENOW_URL       — base instance URL, e.g. ``https://acme.service-now.com``
SERVICENOW_USER      — username for HTTP basic auth
SERVICENOW_PASSWORD  — password / API token for HTTP basic auth

The engine is a process-level singleton accessible via
:func:`get_servicenow_itsm_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_API_PATH = "/api/now/table/"

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/now/table/incident",
    "/api/now/table/change_request",
    "/api/now/table/task",
    "/api/now/table/sys_user",
    "/api/now/table/cmdb_ci",
]


class ServiceNowUnavailable(RuntimeError):
    """Raised when SERVICENOW_URL / SERVICENOW_USER / SERVICENOW_PASSWORD are not configured."""


class ServiceNowHTTPError(RuntimeError):
    """Raised when ServiceNow returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (e.g. 400/401/403/404/409/422/429 are surfaced verbatim;
    everything else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class ServiceNowITSMEngine:
    """Pass-through ServiceNow Table API client backed by ``httpx.Client``."""

    def __init__(
        self,
        servicenow_url: Optional[str] = None,
        servicenow_user: Optional[str] = None,
        servicenow_password: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (
            servicenow_url
            if servicenow_url is not None
            else os.environ.get("SERVICENOW_URL", "")
        ).strip()
        self._user = (
            servicenow_user
            if servicenow_user is not None
            else os.environ.get("SERVICENOW_USER", "")
        ).strip()
        self._password = (
            servicenow_password
            if servicenow_password is not None
            else os.environ.get("SERVICENOW_PASSWORD", "")
        )
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def servicenow_url_present(self) -> bool:
        return bool(self._url)

    @property
    def servicenow_user_present(self) -> bool:
        return bool(self._user)

    @property
    def servicenow_password_present(self) -> bool:
        return bool(self._password)

    @property
    def configured(self) -> bool:
        return (
            self.servicenow_url_present
            and self.servicenow_user_present
            and self.servicenow_password_present
        )

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "ServiceNow ITSM",
            "endpoints": list(_ENDPOINT_CATALOG),
            "servicenow_url_present": self.servicenow_url_present,
            "servicenow_user_present": self.servicenow_user_present,
            "servicenow_password_present": self.servicenow_password_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise ServiceNowUnavailable(
                "SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD must be set "
                "to call ServiceNow Table API endpoints"
            )

    def _build_url(self, path: str) -> str:
        base = self._url.rstrip("/") + _API_PATH
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self._user, self._password)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_204: bool = False,
    ) -> Any:
        self._require_configured()
        url = self._build_url(path)
        try:
            resp = self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(),
                auth=self._auth(),
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "servicenow upstream error %s %s: %s",
                method,
                path,
                type(exc).__name__,
            )
            raise ServiceNowHTTPError(
                502, f"Upstream ServiceNow request failed: {type(exc).__name__}"
            ) from exc

        if expect_204 and resp.status_code in (200, 204):
            return None

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx: surface upstream payload when it's JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise ServiceNowHTTPError(
            resp.status_code, f"ServiceNow returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _build_query_params(
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if sysparm_query is not None:
            params["sysparm_query"] = sysparm_query
        if sysparm_fields is not None:
            params["sysparm_fields"] = sysparm_fields
        if sysparm_limit is not None:
            params["sysparm_limit"] = sysparm_limit
        if sysparm_offset is not None:
            params["sysparm_offset"] = sysparm_offset
        if sysparm_display_value is not None:
            params["sysparm_display_value"] = sysparm_display_value
        return params

    # ------------------------------------------------------------------ ops: incident

    def list_incidents(
        self,
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            sysparm_query=sysparm_query,
            sysparm_fields=sysparm_fields,
            sysparm_limit=sysparm_limit,
            sysparm_offset=sysparm_offset,
            sysparm_display_value=sysparm_display_value,
        )
        return self._request("GET", "incident", params=params or None) or {"result": []}

    def create_incident(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", "incident", json_body=fields) or {"result": {}}

    def update_incident(self, sys_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        return self._request(
            "PATCH", f"incident/{sys_id}", json_body=fields
        ) or {"result": {}}

    def delete_incident(self, sys_id: str) -> None:
        self._request("DELETE", f"incident/{sys_id}", expect_204=True)

    # ------------------------------------------------------------------ ops: change_request

    def list_change_requests(
        self,
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            sysparm_query=sysparm_query,
            sysparm_fields=sysparm_fields,
            sysparm_limit=sysparm_limit,
            sysparm_offset=sysparm_offset,
            sysparm_display_value=sysparm_display_value,
        )
        return self._request(
            "GET", "change_request", params=params or None
        ) or {"result": []}

    # ------------------------------------------------------------------ ops: task

    def list_tasks(
        self,
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            sysparm_query=sysparm_query,
            sysparm_fields=sysparm_fields,
            sysparm_limit=sysparm_limit,
            sysparm_offset=sysparm_offset,
            sysparm_display_value=sysparm_display_value,
        )
        return self._request("GET", "task", params=params or None) or {"result": []}

    # ------------------------------------------------------------------ ops: sys_user

    def list_users(
        self,
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            sysparm_query=sysparm_query,
            sysparm_fields=sysparm_fields,
            sysparm_limit=sysparm_limit,
            sysparm_offset=sysparm_offset,
            sysparm_display_value=sysparm_display_value,
        )
        return self._request("GET", "sys_user", params=params or None) or {"result": []}

    # ------------------------------------------------------------------ ops: cmdb_ci

    def list_cmdb_cis(
        self,
        sysparm_query: Optional[str] = None,
        sysparm_fields: Optional[str] = None,
        sysparm_limit: Optional[int] = None,
        sysparm_offset: Optional[int] = None,
        sysparm_display_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            sysparm_query=sysparm_query,
            sysparm_fields=sysparm_fields,
            sysparm_limit=sysparm_limit,
            sysparm_offset=sysparm_offset,
            sysparm_display_value=sysparm_display_value,
        )
        return self._request("GET", "cmdb_ci", params=params or None) or {"result": []}

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover - defensive
                pass


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[ServiceNowITSMEngine] = None
_engine_lock = Lock()


def get_servicenow_itsm_engine() -> ServiceNowITSMEngine:
    """Return (or create) the process-wide ServiceNowITSMEngine singleton.

    Picks up SERVICENOW_URL / SERVICENOW_USER / SERVICENOW_PASSWORD lazily
    from the environment so tests that monkeypatch env vars before first call
    get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = ServiceNowITSMEngine()
    return _engine


def reset_servicenow_itsm_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
