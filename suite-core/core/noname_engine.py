"""Noname Security API Posture Engine — ALDECI.

Live Noname Security REST client. OAuth2 client_credentials at
``{NONAME_BASE_URL}/oauth/token``. Token cached in-memory ~50 min.
NO SQLite cache. NO MOCKS — when env unset, capability_summary returns
``status=unavailable`` and lookup endpoints raise.

Env:
  NONAME_BASE_URL        — Noname tenant base URL (e.g. https://tenant.nonamesecurity.com)
  NONAME_CLIENT_ID       — OAuth2 client id
  NONAME_CLIENT_SECRET   — OAuth2 client secret

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.14.2, SOC 2 CC7.2,
            OWASP API Security Top 10
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

try:  # pragma: no cover - bus optional
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


class NonameClient:
    """Live Noname Security API client.

    Uses OAuth2 client_credentials against ``{base_url}/oauth/token`` and
    caches the access token in-memory for ~50 min (tokens typically live
    1 h; we refresh proactively).
    """

    OAUTH_TOKEN_PATH = "/oauth/token"
    TOKEN_TTL_SECONDS = 50 * 60  # 50 min in-memory cache

    def __init__(
        self,
        base_url: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._base_url = (base_url or os.environ.get("NONAME_BASE_URL", "")).rstrip("/")
        self._client_id = client_id or os.environ.get("NONAME_CLIENT_ID", "")
        self._client_secret = client_secret or os.environ.get("NONAME_CLIENT_SECRET", "")
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None
        # Token cache
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def base_url_present(self) -> bool:
        return bool(self._base_url)

    @property
    def client_id_present(self) -> bool:
        return bool(self._client_id)

    @property
    def client_secret_present(self) -> bool:
        return bool(self._client_secret)

    @property
    def configured(self) -> bool:
        return (
            self.base_url_present
            and self.client_id_present
            and self.client_secret_present
        )

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
                "Noname not configured: NONAME_BASE_URL, NONAME_CLIENT_ID, "
                "and NONAME_CLIENT_SECRET must be set"
            )

    def _get_access_token(self) -> str:
        """OAuth2 client_credentials w/ in-memory ~50 min cache."""
        now = time.time()
        if self._access_token and now < self._token_expires_at:
            return self._access_token

        with self._lock:
            now = time.time()
            if self._access_token and now < self._token_expires_at:
                return self._access_token

            url = self._base_url + self.OAUTH_TOKEN_PATH
            resp = self._client_inst().post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            payload = resp.json()
            token = payload.get("access_token", "")
            if not token:
                raise RuntimeError("noname oauth: empty access_token in response")
            self._access_token = token
            self._token_expires_at = now + self.TOKEN_TTL_SECONDS
            return token

    def _headers(self) -> Dict[str, str]:
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Authenticated GET against ``{base_url}{path}``."""
        self._require_configured()
        url = self._base_url + path
        resp = self._client_inst().get(
            url,
            params=params or None,
            headers=self._headers(),
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"data": [], "raw": resp.text}

        if not isinstance(payload, dict):
            payload = {"data": payload}

        # TrustGraph emit (best-effort)
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(
                        "noname.api.query",
                        {"path": path, "params": dict(params or {})},
                    )
        except Exception:  # pragma: no cover
            pass

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
            "service": "Noname Security",
            "endpoints": [
                "/api/v3/apis",
                "/api/v3/issues",
                "/api/v3/inventory/endpoints",
                "/api/v3/sources",
                "/api/v3/posture-policies",
            ],
            "noname_base_url_present": self.base_url_present,
            "noname_client_id_present": self.client_id_present,
            "noname_client_secret_present": self.client_secret_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # API discovery
    # ------------------------------------------------------------------

    def list_apis(
        self,
        limit: int = 50,
        page: int = 1,
        filter_: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if filter_:
            params["filter"] = filter_
        return self._get("/api/v3/apis", params=params)

    def get_api(self, api_id: str) -> Dict[str, Any]:
        return self._get(f"/api/v3/apis/{api_id}")

    def list_api_endpoints(
        self,
        api_id: str,
        limit: int = 50,
        page: int = 1,
    ) -> Dict[str, Any]:
        return self._get(
            f"/api/v3/apis/{api_id}/endpoints",
            params={"limit": limit, "page": page},
        )

    # ------------------------------------------------------------------
    # Issues / posture
    # ------------------------------------------------------------------

    def list_issues(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        type_: Optional[str] = None,
        api_id: Optional[str] = None,
        limit: int = 50,
        page: int = 1,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        if type_:
            params["type"] = type_
        if api_id:
            params["apiId"] = api_id
        return self._get("/api/v3/issues", params=params)

    # ------------------------------------------------------------------
    # Inventory / sources / policies
    # ------------------------------------------------------------------

    def list_inventory_endpoints(
        self,
        limit: int = 50,
        page: int = 1,
        filter_: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if filter_:
            params["filter"] = filter_
        return self._get("/api/v3/inventory/endpoints", params=params)

    def list_sources(self, type_: Optional[str] = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if type_:
            params["type"] = type_
        return self._get("/api/v3/sources", params=params or None)

    def list_posture_policies(self) -> Dict[str, Any]:
        return self._get("/api/v3/posture-policies")

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
            self._access_token = None
            self._token_expires_at = 0.0


# Backwards-compatible alias
NonameEngine = NonameClient


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[NonameClient] = None


def get_noname_engine() -> NonameClient:
    """Return process-wide NonameClient singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = NonameClient()
    return _singleton


def reset_noname_engine() -> None:
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
    "NonameClient",
    "NonameEngine",
    "get_noname_engine",
    "reset_noname_engine",
]
