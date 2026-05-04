"""SentinelOne Singularity EDR — REAL ApiToken REST API client.

This engine is the *live* counterpart to the parser-only
``connectors/sentinelone_connector.py`` (which ingests customer-supplied
JSON dumps). Here we hit SentinelOne's documented REST surface:

  GET  /web/api/v2.1/agents
  GET  /web/api/v2.1/threats
  GET  /web/api/v2.1/sites
  GET  /web/api/v2.1/groups
  POST /web/api/v2.1/threats/mitigate/{action}

Authentication is the tenant-scoped ``Authorization: ApiToken <token>``
header documented in the SentinelOne Singularity XDR Public API guide.
The engine reads ``SENTINELONE_URL`` (e.g.
``https://usea1-XXX.sentinelone.net``) and ``SENTINELONE_API_TOKEN``
from the environment.

NO MOCKS rule:
  * If ``SENTINELONE_URL`` or ``SENTINELONE_API_TOKEN`` is unset the
    engine reports ``api_credentials_present()=False`` and *every* live
    lookup raises ``SentinelOneUnavailableError`` (router translates to
    503).
  * No fabricated agents, threats, sites, or groups ever.
  * No SQLite cache — all results stream straight back from the upstream.

References:
  https://github.com/cobaltstrikereviews/sentinelone-mgmt-api
  https://usea1-partners.sentinelone.net/api-doc/overview
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0

_VALID_MITIGATE_ACTIONS = {
    "kill",
    "quarantine",
    "un-quarantine",
    "remediate",
    "rollback-remediation",
    "network-quarantine",
    "disconnect-from-network",
    "reconnect-to-network",
}


class SentinelOneUnavailableError(RuntimeError):
    """Raised when SentinelOne credentials are missing or upstream call fails."""


class SentinelOneEDREngine:
    """Live SentinelOne Singularity EDR REST API client.

    Stateless. Designed to be used as a process-wide singleton via
    ``get_sentinelone_edr_engine()``.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._url = (url if url is not None else os.getenv("SENTINELONE_URL") or "").rstrip("/")
        self._api_token = (
            api_token if api_token is not None else os.getenv("SENTINELONE_API_TOKEN")
        )
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._owns_client = client is None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def url_present(self) -> bool:
        return bool(self._url and str(self._url).strip())

    def api_token_present(self) -> bool:
        return bool(self._api_token and str(self._api_token).strip())

    def api_credentials_present(self) -> bool:
        return self.url_present() and self.api_token_present()

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------
    def _auth_headers(self) -> Dict[str, str]:
        if not self.api_credentials_present():
            raise SentinelOneUnavailableError(
                "SENTINELONE_URL and SENTINELONE_API_TOKEN must be set"
            )
        return {
            "Authorization": f"ApiToken {self._api_token}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self._url}{path}"
        headers = self._auth_headers()
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = self._client.get(url, params=clean_params, headers=headers)
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise SentinelOneUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    def _post(self, path: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self._url}{path}"
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        try:
            resp = self._client.post(url, json=json_body, headers=headers)
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise SentinelOneUnavailableError(f"POST {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = getattr(resp, "text", "")[:300]
            raise SentinelOneUnavailableError(f"{path} returned {status}: {text}")
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise SentinelOneUnavailableError(f"{path} returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise SentinelOneUnavailableError(f"{path} returned non-object payload")
        return data

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------
    def list_agents(
        self,
        limit: int = 100,
        site_ids: Optional[str] = None,
        group_ids: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_up_to_date: Optional[bool] = None,
        infected: Optional[bool] = None,
        is_pending_uninstall: Optional[bool] = None,
        os_types: Optional[str] = None,
        query: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": int(limit)}
        if site_ids:
            params["siteIds"] = site_ids
        if group_ids:
            params["groupIds"] = group_ids
        if is_active is not None:
            params["isActive"] = "true" if is_active else "false"
        if is_up_to_date is not None:
            params["isUpToDate"] = "true" if is_up_to_date else "false"
        if infected is not None:
            params["infected"] = "true" if infected else "false"
        if is_pending_uninstall is not None:
            params["isPendingUninstall"] = "true" if is_pending_uninstall else "false"
        if os_types:
            params["osTypes"] = os_types
        if query:
            params["query"] = query
        if cursor:
            params["cursor"] = cursor
        data = self._get("/web/api/v2.1/agents", params=params)
        return {
            "data": [a for a in (data.get("data") or []) if isinstance(a, dict)],
            "pagination": data.get("pagination") or {},
        }

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------
    def list_threats(
        self,
        limit: int = 100,
        statuses: Optional[str] = None,
        resolved: Optional[bool] = None,
        site_ids: Optional[str] = None,
        engines: Optional[str] = None,
        classifications: Optional[str] = None,
        created_at_gte: Optional[str] = None,
        query: Optional[str] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": int(limit)}
        if statuses:
            params["mitigationStatuses"] = statuses
        if resolved is not None:
            params["resolved"] = "true" if resolved else "false"
        if site_ids:
            params["siteIds"] = site_ids
        if engines:
            params["engines"] = engines
        if classifications:
            params["classifications"] = classifications
        if created_at_gte:
            params["createdAt__gte"] = created_at_gte
        if query:
            params["query"] = query
        if cursor:
            params["cursor"] = cursor
        data = self._get("/web/api/v2.1/threats", params=params)
        threats = [t for t in (data.get("data") or []) if isinstance(t, dict)]
        if _get_tg_bus:
            for t in threats:
                tid = t.get("id") or (t.get("threatInfo") or {}).get("threatId")
                if not tid:
                    continue
                ti = t.get("threatInfo") or {}
                try:
                    _bus = _get_tg_bus()
                    if _bus:
                        _bus.emit(
                            "threat.detected",
                            {
                                "entity_id": str(tid),
                                "type": "sentinelone_threat",
                                "severity": ti.get("confidenceLevel") or ti.get("classification") or "unknown",
                                "source_engine": "sentinelone_edr",
                                "classification": ti.get("classification"),
                                "mitigation_status": ti.get("mitigationStatus"),
                            },
                        )
                except Exception:
                    pass
        return {
            "data": threats,
            "pagination": data.get("pagination") or {},
        }

    # ------------------------------------------------------------------
    # Sites
    # ------------------------------------------------------------------
    def list_sites(
        self,
        limit: int = 100,
        site_type: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": int(limit)}
        if site_type:
            params["siteType"] = site_type
        if state:
            params["state"] = state
        data = self._get("/web/api/v2.1/sites", params=params)
        return {"data": data.get("data") or {}}

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------
    def list_groups(
        self,
        limit: int = 100,
        site_ids: Optional[str] = None,
        type: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": int(limit)}
        if site_ids:
            params["siteIds"] = site_ids
        if type:
            params["type"] = type
        data = self._get("/web/api/v2.1/groups", params=params)
        return {
            "data": [g for g in (data.get("data") or []) if isinstance(g, dict)],
            "pagination": data.get("pagination") or {},
        }

    # ------------------------------------------------------------------
    # Threat mitigation
    # ------------------------------------------------------------------
    def mitigate_threats(
        self,
        action: str,
        filter_body: Dict[str, Any],
        data_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if action not in _VALID_MITIGATE_ACTIONS:
            raise ValueError(
                f"action must be one of {sorted(_VALID_MITIGATE_ACTIONS)}"
            )
        if not isinstance(filter_body, dict) or not filter_body:
            raise ValueError("filter must be a non-empty object")
        body: Dict[str, Any] = {"filter": filter_body}
        if data_body is not None:
            if not isinstance(data_body, dict):
                raise ValueError("data must be an object if provided")
            body["data"] = data_body
        path = f"/web/api/v2.1/threats/mitigate/{action}"
        result = self._post(path, body)
        return {"data": result.get("data") or {}}

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
_singleton: Optional[SentinelOneEDREngine] = None
_singleton_lock = threading.Lock()


def get_sentinelone_edr_engine(
    url: Optional[str] = None,
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> SentinelOneEDREngine:
    """Return the process-wide SentinelOneEDREngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SentinelOneEDREngine(
                url=url,
                api_token=api_token,
                client=client,
            )
        return _singleton


def reset_sentinelone_edr_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "SentinelOneEDREngine",
    "SentinelOneUnavailableError",
    "get_sentinelone_edr_engine",
    "reset_sentinelone_edr_engine",
]
