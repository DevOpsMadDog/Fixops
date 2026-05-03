"""Netskope CASB API — REAL token-header REST API client (NEW — 2026-05-04).

Live counterpart for the ``/api/v1/netskope`` router so consumers can
read alerts / events / DLP incidents / SCIM users / URL policy lists /
User Confidence Index series straight from the Netskope tenant.

Endpoints (all prefixed by NETSKOPE_TENANT_URL, e.g. https://{tenant}.goskope.com):

  GET  /api/v2/events/data/page              alerts / page / app / network / infra / incident
  GET  /api/v2/events/data/incidents          DLP incidents
  GET  /api/v2/scim/Users                     SCIM v2 user directory
  GET  /api/v2/policy/url/list                URL policy lists
  GET  /api/v2/services/operational/uci       User Confidence Index series
  POST /api/v2/incidents/uba/getuci           per-user UCI detail (UBA)

Required env vars
-----------------
    NETSKOPE_TENANT_URL  e.g. ``https://acme.goskope.com``
    NETSKOPE_API_TOKEN   v2 API token. Sent as ``Netskope-Api-Token: {token}``.

NO MOCKS rule
-------------
* If either env var is unset the engine reports
  ``credentials_present()=False`` and every live call raises
  ``NetskopeUnavailableError`` (router translates to HTTP 503).
* No fabricated alerts / incidents / users / policies / UCI samples — ever.
* No SQLite cache — pure HTTP passthrough.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


class NetskopeUnavailableError(RuntimeError):
    """Raised when Netskope credentials are missing or upstream call fails."""


class NetskopeCASBEngine:
    """Live Netskope CASB v2 REST client.

    Stateless. Designed to be used as a process-wide singleton via
    ``get_netskope_casb_engine()``.
    """

    def __init__(
        self,
        tenant_url: Optional[str] = None,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._tenant_url = (
            tenant_url
            if tenant_url is not None
            else os.getenv("NETSKOPE_TENANT_URL")
        )
        if self._tenant_url:
            self._tenant_url = self._tenant_url.rstrip("/")
        self._token = (
            api_token
            if api_token is not None
            else os.getenv("NETSKOPE_API_TOKEN")
        )
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def tenant_url_present(self) -> bool:
        return bool(self._tenant_url and str(self._tenant_url).strip())

    def api_token_present(self) -> bool:
        return bool(self._token and str(self._token).strip())

    def credentials_present(self) -> bool:
        return self.tenant_url_present() and self.api_token_present()

    def base_url(self) -> Optional[str]:
        return self._tenant_url

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        return {
            "Netskope-Api-Token": str(self._token),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _ensure_creds(self) -> None:
        if not self.credentials_present():
            raise NetskopeUnavailableError(
                "NETSKOPE_TENANT_URL and NETSKOPE_API_TOKEN must be set"
            )

    def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self._ensure_creds()
        url = f"{self._tenant_url}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = self._client.get(
                url, params=clean_params, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise NetskopeUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    def _post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._ensure_creds()
        url = f"{self._tenant_url}{path}"
        try:
            resp = self._client.post(
                url, json=json or {}, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise NetskopeUnavailableError(
                f"POST {path} failed: {exc}"
            ) from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = (getattr(resp, "text", "") or "")[:300]
            raise NetskopeUnavailableError(
                f"{path} returned {status}: {text}"
            )
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise NetskopeUnavailableError(
                f"{path} returned non-JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise NetskopeUnavailableError(
                f"{path} returned non-object payload"
            )
        return data

    # ------------------------------------------------------------------
    # Events: alerts / page / app / infrastructure / network / incident
    # ------------------------------------------------------------------
    def list_events_page(
        self,
        type: Optional[str] = None,
        query: Optional[str] = None,
        starttime: Optional[int] = None,
        endtime: Optional[int] = None,
        limit: Optional[int] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "type": type,
            "query": query,
            "starttime": starttime,
            "endtime": endtime,
            "limit": limit,
            "token": token,
        }
        return self._get("/api/v2/events/data/page", params=params)

    # ------------------------------------------------------------------
    # DLP incidents
    # ------------------------------------------------------------------
    def list_dlp_incidents(
        self,
        starttime: Optional[int] = None,
        endtime: Optional[int] = None,
        query: Optional[str] = None,
        limit: Optional[int] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "starttime": starttime,
            "endtime": endtime,
            "query": query,
            "limit": limit,
            "token": token,
        }
        return self._get("/api/v2/events/data/incidents", params=params)

    # ------------------------------------------------------------------
    # SCIM v2 Users
    # ------------------------------------------------------------------
    def list_scim_users(
        self,
        startIndex: Optional[int] = None,
        count: Optional[int] = None,
        filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "startIndex": startIndex,
            "count": count,
            "filter": filter,
        }
        return self._get("/api/v2/scim/Users", params=params)

    # ------------------------------------------------------------------
    # URL Policy Lists
    # ------------------------------------------------------------------
    def list_url_policy(
        self,
        cursor: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = {"cursor": cursor, "limit": limit}
        return self._get("/api/v2/policy/url/list", params=params)

    # ------------------------------------------------------------------
    # User Confidence Index time series
    # ------------------------------------------------------------------
    def get_uci_series(
        self,
        starttime: Optional[int] = None,
        endtime: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = {"starttime": starttime, "endtime": endtime}
        return self._get("/api/v2/services/operational/uci", params=params)

    # ------------------------------------------------------------------
    # Per-user UCI detail (UBA)
    # ------------------------------------------------------------------
    def get_uba_uci(
        self,
        start_time: int,
        end_time: int,
        ip: str,
        user_id: Optional[str] = None,
        user_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        if start_time is None or end_time is None:
            raise ValueError("start_time and end_time are required")
        if not ip or not str(ip).strip():
            raise ValueError("ip is required")
        body: Dict[str, Any] = {
            "start_time": start_time,
            "end_time": end_time,
            "ip": ip,
        }
        if user_id is not None:
            body["user_id"] = user_id
        if user_name is not None:
            body["user_name"] = user_name
        return self._post("/api/v2/incidents/uba/getuci", json=body)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except (RuntimeError, OSError):
                pass


# --------------------------------------------------------------- singleton
_singleton: Optional[NetskopeCASBEngine] = None
_singleton_lock = threading.Lock()


def get_netskope_casb_engine(
    tenant_url: Optional[str] = None,
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> NetskopeCASBEngine:
    """Return the process-wide NetskopeCASBEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = NetskopeCASBEngine(
                tenant_url=tenant_url,
                api_token=api_token,
                client=client,
            )
        return _singleton


def reset_netskope_casb_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "NetskopeCASBEngine",
    "NetskopeUnavailableError",
    "get_netskope_casb_engine",
    "reset_netskope_casb_engine",
]
