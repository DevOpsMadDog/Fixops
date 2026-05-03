"""Azure Sentinel Engine — ALDECI.

Live Microsoft Sentinel REST API client (incidents, alert rules, bookmarks,
watchlists, entity expansion).

Reads AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET from env.
OAuth2 client_credentials flow against
``login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with
``scope=https://management.azure.com/.default``. Token cached in-memory ~50min.

NO SQLite cache. NO MOCKS — when env unset every lookup raises RuntimeError
which the router maps to HTTP 503.

Compliance: NIST CSF DE.AE, ISO/IEC 27001 A.16.1, SOC 2 CC7.3
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


# Public Azure cloud endpoints (override-able via env for sovereign clouds).
_LOGIN_BASE = os.environ.get(
    "AZURE_AAD_LOGIN_BASE", "https://login.microsoftonline.com"
).rstrip("/")
_MGMT_BASE = os.environ.get(
    "AZURE_MGMT_BASE", "https://management.azure.com"
).rstrip("/")
_MGMT_SCOPE = os.environ.get(
    "AZURE_MGMT_SCOPE", "https://management.azure.com/.default"
)

# Sentinel API version (Microsoft.SecurityInsights resource provider).
_SENTINEL_API_VERSION = os.environ.get("AZURE_SENTINEL_API_VERSION", "2023-02-01")

# Token cache lifetime — Microsoft tokens are 60min; refresh at ~50min.
_TOKEN_TTL_SECONDS = 50 * 60


class AzureSentinelEngine:
    """Live Microsoft Sentinel client via Azure Management REST API.

    Uses OAuth2 client_credentials flow. Token is cached in-memory with a
    50-minute TTL (well below the 60-minute Azure default). No persistent
    storage of credentials or tokens.
    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._tenant_id = (tenant_id or os.environ.get("AZURE_TENANT_ID", "")).strip()
        self._client_id = (client_id or os.environ.get("AZURE_CLIENT_ID", "")).strip()
        self._client_secret = (
            client_secret or os.environ.get("AZURE_CLIENT_SECRET", "")
        ).strip()
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

        # Token cache.
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Configuration probes
    # ------------------------------------------------------------------

    @property
    def tenant_present(self) -> bool:
        return bool(self._tenant_id)

    @property
    def client_present(self) -> bool:
        return bool(self._client_id) and bool(self._client_secret)

    @property
    def configured(self) -> bool:
        return self.tenant_present and self.client_present

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
            raise RuntimeError(
                "Azure Sentinel not configured: AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET must be set"
            )

    # ------------------------------------------------------------------
    # OAuth2 client_credentials flow
    # ------------------------------------------------------------------

    def _fetch_token(self) -> str:
        """Acquire a fresh bearer token via client_credentials flow."""
        self._require_configured()
        url = f"{_LOGIN_BASE}/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": _MGMT_SCOPE,
        }
        resp = self._client_inst().post(
            url,
            data=data,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Azure AAD token endpoint returned non-JSON: {exc}"
            ) from exc
        token = payload.get("access_token")
        if not token:
            raise RuntimeError(
                f"Azure AAD token response missing access_token: {payload}"
            )
        return token

    def _get_token(self) -> str:
        """Return cached token or fetch a new one if expired."""
        now = time.time()
        with self._lock:
            if self._token and now < self._token_expires_at:
                return self._token
            self._token = self._fetch_token()
            self._token_expires_at = now + _TOKEN_TTL_SECONDS
            return self._token

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        elif not (self.tenant_present and self.client_present):
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "Azure Sentinel",
            "endpoints": [
                "/incidents",
                "/alertRules",
                "/bookmarks",
                "/watchlists",
                "/entities",
            ],
            "azure_tenant_present": self.tenant_present,
            "azure_client_present": self.client_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Sentinel REST helpers
    # ------------------------------------------------------------------

    def _sentinel_base(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> str:
        return (
            f"{_MGMT_BASE}/subscriptions/{subscription_id}"
            f"/resourceGroups/{resource_group_name}"
            f"/providers/Microsoft.OperationalInsights"
            f"/workspaces/{workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )

    def _get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        merged = {"api-version": _SENTINEL_API_VERSION}
        if params:
            for k, v in params.items():
                if v is not None:
                    merged[k] = v
        resp = self._client_inst().get(
            url,
            params=merged,
            headers=self._auth_headers(),
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def _post(
        self,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        merged = {"api-version": _SENTINEL_API_VERSION}
        if params:
            for k, v in params.items():
                if v is not None:
                    merged[k] = v
        resp = self._client_inst().post(
            url,
            params=merged,
            json=json_body or {},
            headers={
                **self._auth_headers(),
                "Content-Type": "application/json",
            },
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
        odata_filter: Optional[str] = None,
        top: Optional[int] = None,
    ) -> Dict[str, Any]:
        url = (
            self._sentinel_base(subscription_id, resource_group_name, workspace_name)
            + "/incidents"
        )
        params: Dict[str, Any] = {}
        if odata_filter:
            params["$filter"] = odata_filter
        if top is not None:
            params["$top"] = top
        return self._get(url, params=params)

    # ------------------------------------------------------------------
    # Alert rules
    # ------------------------------------------------------------------

    def list_alert_rules(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> Dict[str, Any]:
        url = (
            self._sentinel_base(subscription_id, resource_group_name, workspace_name)
            + "/alertRules"
        )
        return self._get(url)

    # ------------------------------------------------------------------
    # Bookmarks
    # ------------------------------------------------------------------

    def list_bookmarks(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> Dict[str, Any]:
        url = (
            self._sentinel_base(subscription_id, resource_group_name, workspace_name)
            + "/bookmarks"
        )
        return self._get(url)

    # ------------------------------------------------------------------
    # Watchlists
    # ------------------------------------------------------------------

    def list_watchlists(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
    ) -> Dict[str, Any]:
        url = (
            self._sentinel_base(subscription_id, resource_group_name, workspace_name)
            + "/watchlists"
        )
        return self._get(url)

    # ------------------------------------------------------------------
    # Entity expansion
    # ------------------------------------------------------------------

    def expand_entity(
        self,
        subscription_id: str,
        resource_group_name: str,
        workspace_name: str,
        entity_id: str,
        expansion_id: str,
        end_time: Optional[str] = None,
        start_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /entities/{entityId}/expand — expand entity via expansion."""
        base = self._sentinel_base(
            subscription_id, resource_group_name, workspace_name
        )
        url = f"{base}/entities/{entity_id}/expand"
        body: Dict[str, Any] = {"expansionId": expansion_id}
        if end_time:
            body["endTime"] = end_time
        if start_time:
            body["startTime"] = start_time
        return self._post(url, json_body=body)

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
            self._token = None
            self._token_expires_at = 0.0


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[AzureSentinelEngine] = None


def get_azure_sentinel_engine() -> AzureSentinelEngine:
    """Return process-wide AzureSentinelEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AzureSentinelEngine()
    return _singleton


def reset_azure_sentinel_engine() -> None:
    """Reset the singleton (test helper)."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            try:
                _singleton.close()
            except Exception:
                pass
        _singleton = None


__all__ = [
    "AzureSentinelEngine",
    "get_azure_sentinel_engine",
    "reset_azure_sentinel_engine",
]
