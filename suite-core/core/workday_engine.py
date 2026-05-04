"""ALDECI Workday HCM Engine.

Thin pass-through client for the **Workday Staffing REST API**
(`/ccx/api/staffing/v6/{tenant}/...`) — covering Workers, Positions,
Organizations, and Org Charts.

Configuration is environment-driven. NO SQLite cache. NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
all lookup endpoints respond with HTTP 503.

Environment variables
---------------------
WORKDAY_TENANT     — tenant short-name, e.g. ``acme_pilot`` or ``acme_dpt1``
WORKDAY_BASE_URL   — base URL, e.g. ``https://wd2-impl-services1.workday.com``
WORKDAY_USERNAME   — username (without the ``@{tenant}`` suffix)
WORKDAY_PASSWORD   — password / integration system user (ISU) password

Workday REST uses HTTP Basic auth with the username formatted as
``{username}@{tenant}`` (e.g. ``aldeci_isu@acme_pilot``).

The engine is a process-level singleton accessible via
:func:`get_workday_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_API_PATH_TEMPLATE = "/ccx/api/staffing/v6/{tenant}/"

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/ccx/api/staffing/v6/{tenant}/workers",
    "/ccx/api/staffing/v6/{tenant}/positions",
    "/ccx/api/staffing/v6/{tenant}/organizations",
    "/ccx/api/staffing/v6/{tenant}/orgChart",
]


class WorkdayUnavailable(RuntimeError):
    """Raised when WORKDAY_* env vars are not configured."""


class WorkdayHTTPError(RuntimeError):
    """Raised when Workday returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException.
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class WorkdayEngine:
    """Pass-through Workday Staffing REST API client backed by ``httpx.Client``."""

    def __init__(
        self,
        workday_tenant: Optional[str] = None,
        workday_base_url: Optional[str] = None,
        workday_username: Optional[str] = None,
        workday_password: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._tenant = (
            workday_tenant
            if workday_tenant is not None
            else os.environ.get("WORKDAY_TENANT", "")
        ).strip()
        self._base_url = (
            workday_base_url
            if workday_base_url is not None
            else os.environ.get("WORKDAY_BASE_URL", "")
        ).strip()
        self._username = (
            workday_username
            if workday_username is not None
            else os.environ.get("WORKDAY_USERNAME", "")
        ).strip()
        self._password = (
            workday_password
            if workday_password is not None
            else os.environ.get("WORKDAY_PASSWORD", "")
        )
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def workday_tenant_present(self) -> bool:
        return bool(self._tenant)

    @property
    def workday_base_url_present(self) -> bool:
        return bool(self._base_url)

    @property
    def workday_username_present(self) -> bool:
        return bool(self._username)

    @property
    def workday_password_present(self) -> bool:
        return bool(self._password)

    @property
    def configured(self) -> bool:
        return (
            self.workday_tenant_present
            and self.workday_base_url_present
            and self.workday_username_present
            and self.workday_password_present
        )

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Workday HCM",
            "endpoints": list(_ENDPOINT_CATALOG),
            "workday_tenant_present": self.workday_tenant_present,
            "workday_base_url_present": self.workday_base_url_present,
            "workday_username_present": self.workday_username_present,
            "workday_password_present": self.workday_password_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise WorkdayUnavailable(
                "WORKDAY_TENANT, WORKDAY_BASE_URL, WORKDAY_USERNAME, and "
                "WORKDAY_PASSWORD must be set to call Workday Staffing REST endpoints"
            )

    def _build_url(self, tenant: str, path: str) -> str:
        api_path = _API_PATH_TEMPLATE.format(tenant=tenant)
        base = self._base_url.rstrip("/") + api_path
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _auth(self) -> httpx.BasicAuth:
        # Workday REST: username formatted as ``{username}@{tenant}``
        return httpx.BasicAuth(f"{self._username}@{self._tenant}", self._password)

    def _request(
        self,
        method: str,
        tenant: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        url = self._build_url(tenant, path)
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
                "workday upstream error %s %s: %s",
                method,
                path,
                type(exc).__name__,
            )
            raise WorkdayHTTPError(
                502, f"Upstream Workday request failed: {type(exc).__name__}"
            ) from exc

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
        raise WorkdayHTTPError(
            resp.status_code, f"Workday returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _build_query_params(**kwargs: Any) -> Dict[str, Any]:
        return {k: v for k, v in kwargs.items() if v is not None}

    # ------------------------------------------------------------------ ops: workers

    def list_workers(
        self,
        tenant: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        search: Optional[str] = None,
        inactiveAndTerminated: Optional[bool] = None,
        supervisoryOrganization: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(
            limit=limit,
            offset=offset,
            search=search,
            inactiveAndTerminated=inactiveAndTerminated,
            supervisoryOrganization=supervisoryOrganization,
        )
        return self._request("GET", tenant, "workers", params=params or None) or {
            "data": [],
            "total": 0,
        }

    def get_worker(self, tenant: str, wid: str) -> Dict[str, Any]:
        return self._request("GET", tenant, f"workers/{wid}") or {}

    def get_worker_history(
        self,
        tenant: str,
        wid: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(limit=limit, offset=offset)
        return self._request(
            "GET", tenant, f"workers/{wid}/historyChange", params=params or None
        ) or {"data": [], "total": 0}

    # ------------------------------------------------------------------ ops: positions

    def list_positions(
        self,
        tenant: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(limit=limit, offset=offset, search=search)
        return self._request(
            "GET", tenant, "positions", params=params or None
        ) or {"data": [], "total": 0}

    # ------------------------------------------------------------------ ops: organizations

    def list_organizations(
        self,
        tenant: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = self._build_query_params(limit=limit, offset=offset)
        return self._request(
            "GET", tenant, "organizations", params=params or None
        ) or {"data": [], "total": 0}

    # ------------------------------------------------------------------ ops: orgChart

    def get_org_chart(self, tenant: str, org_id: str) -> Dict[str, Any]:
        return self._request("GET", tenant, f"orgChart/{org_id}") or {}

    def get_management_chain(self, tenant: str, org_id: str) -> Dict[str, Any]:
        return self._request(
            "GET", tenant, f"orgChart/{org_id}/managementChain"
        ) or {"data": []}

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

_engine: Optional[WorkdayEngine] = None
_engine_lock = Lock()


def get_workday_engine() -> WorkdayEngine:
    """Return (or create) the process-wide WorkdayEngine singleton.

    Picks up WORKDAY_* vars lazily from the environment so tests that
    monkeypatch env vars before first call get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = WorkdayEngine()
    return _engine


def reset_workday_engine() -> None:
    """Test helper — drop the cached singleton."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
