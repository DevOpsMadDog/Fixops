"""Orca Security Engine — ALDECI.

Live Orca Security REST client. API token auth via
``Authorization: Token {ORCA_API_TOKEN}`` header. NO SQLite cache.
NO MOCKS — when env unset, capability_summary returns
``status=unavailable`` and lookup endpoints raise ``RuntimeError``.

Env:
  ORCA_API_TOKEN      — Orca API token (Bearer-like Token header)
  ORCA_API_URL        — Optional override (default https://api.orcasecurity.io)

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Mapping, Optional

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.orcasecurity.io"


class OrcaSecurityEngine:
    """Live Orca Security client.

    Sends ``Authorization: Token {ORCA_API_TOKEN}`` per the Orca REST API
    spec. No on-disk cache — caller is expected to paginate via
    ``next_page_token``.
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._api_token = api_token if api_token is not None else os.environ.get("ORCA_API_TOKEN", "")
        self._api_url = (api_url or os.environ.get("ORCA_API_URL", DEFAULT_BASE_URL)).rstrip("/")
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def api_token_present(self) -> bool:
        return bool(self._api_token)

    @property
    def configured(self) -> bool:
        return self.api_token_present

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _client_inst(self) -> httpx.Client:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = httpx.Client(
                        timeout=self._timeout,
                        verify=self._verify_tls,
                    )
        return self._client

    def _require_configured(self) -> None:
        if not self.configured:
            raise RuntimeError("Orca not configured: ORCA_API_TOKEN must be set")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self._api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get(
        self,
        path: str,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        url = f"{self._api_url}{path}"
        clean = {k: v for k, v in (params or {}).items() if v is not None}
        resp = self._client_inst().get(url, headers=self._headers(), params=clean)
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"data": [], "raw": resp.text}
        if not isinstance(payload, dict):
            payload = {"data": payload}
        return payload

    def _post(self, path: str, body: Mapping[str, Any]) -> Dict[str, Any]:
        self._require_configured()
        url = f"{self._api_url}{path}"
        resp = self._client_inst().post(url, headers=self._headers(), json=dict(body))
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"data": [], "raw": resp.text}
        if not isinstance(payload, dict):
            payload = {"data": payload}
        return payload

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "Orca Security",
            "endpoints": [
                "/api/alerts",
                "/api/asset",
                "/api/policies",
                "/api/sonar/query",
                "/api/clouds",
                "/api/users",
            ],
            "orca_api_token_present": self.api_token_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        next_page_token: Optional[str] = None,
        limit: Optional[int] = None,
        start_at_time: Optional[str] = None,
        end_at_time: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        type_: Optional[str] = None,
        cloud_account: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "next_page_token": next_page_token,
            "limit": limit,
            "start_at_time": start_at_time,
            "end_at_time": end_at_time,
            "status": status,
            "priority": priority,
            "type": type_,
            "cloud_account": cloud_account,
        }
        payload = self._get("/api/alerts", params=params)
        self._emit_event("orca.alerts.listed", {"count": len(payload.get("data") or [])})
        return {
            "data": payload.get("data") or [],
            "next_page_token": payload.get("next_page_token"),
            "total_items": payload.get("total_items"),
        }

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def list_assets(
        self,
        type_: Optional[str] = None,
        limit: Optional[int] = None,
        next_page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "type": type_,
            "limit": limit,
            "next_page_token": next_page_token,
        }
        payload = self._get("/api/asset", params=params)
        return {
            "data": payload.get("data") or [],
            "next_page_token": payload.get("next_page_token"),
            "total_items": payload.get("total_items"),
        }

    def get_asset(self, asset_unique_id: str) -> Dict[str, Any]:
        if not asset_unique_id:
            raise ValueError("asset_unique_id required")
        payload = self._get(f"/api/asset/{asset_unique_id}")
        return payload

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def list_policies(self) -> Dict[str, Any]:
        payload = self._get("/api/policies")
        return {"data": payload.get("data") or []}

    # ------------------------------------------------------------------
    # Sonar
    # ------------------------------------------------------------------

    def sonar_query(
        self,
        query: str,
        limit: Optional[int] = None,
        next_page_token: Optional[str] = None,
        additional_attributes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not query or not query.strip():
            raise ValueError("query required")
        body: Dict[str, Any] = {"query": query}
        if limit is not None:
            body["limit"] = limit
        if next_page_token is not None:
            body["next_page_token"] = next_page_token
        if additional_attributes is not None:
            body["additional_attributes"] = additional_attributes
        payload = self._post("/api/sonar/query", body=body)
        self._emit_event("orca.sonar.query", {"query": query})
        return {
            "data": payload.get("data") or [],
            "next_page_token": payload.get("next_page_token"),
            "total_items": payload.get("total_items"),
            "query_meta": payload.get("query_meta") or {},
        }

    # ------------------------------------------------------------------
    # Clouds
    # ------------------------------------------------------------------

    def list_clouds(self) -> Dict[str, Any]:
        payload = self._get("/api/clouds")
        return {"data": payload.get("data") or []}

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def list_users(self) -> Dict[str, Any]:
        payload = self._get("/api/users")
        return {"data": payload.get("data") or []}

    # ------------------------------------------------------------------
    # TrustGraph emit (best-effort)
    # ------------------------------------------------------------------

    def _emit_event(self, kind: str, body: Mapping[str, Any]) -> None:
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(kind, dict(body))
        except Exception:  # pragma: no cover - best-effort
            pass

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    self._client.close()
                finally:
                    self._client = None


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[OrcaSecurityEngine] = None


def get_orca_engine() -> OrcaSecurityEngine:
    """Return process-wide OrcaSecurityEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = OrcaSecurityEngine()
    return _singleton


def reset_orca_engine() -> None:
    """Reset singleton (test helper)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            try:
                _singleton.close()
            except Exception:
                pass
        _singleton = None


__all__ = [
    "OrcaSecurityEngine",
    "get_orca_engine",
    "reset_orca_engine",
]
