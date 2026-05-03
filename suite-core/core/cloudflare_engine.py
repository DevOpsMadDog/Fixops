"""Cloudflare API v4 — REAL Bearer-token REST API client (NEW — 2026-05-04).

Live counterpart for the ``/api/v1/cloudflare`` router so consumers can
read Zones / DNS Records / Firewall Rules / WAF Packages / Security
Events / Access Groups directly from the Cloudflare control plane.

Endpoints (all prefixed with the Cloudflare API v4 base URL):

  GET  /client/v4/zones
  GET  /client/v4/zones/{zone_id}
  GET  /client/v4/zones/{zone_id}/dns_records
  GET  /client/v4/zones/{zone_id}/firewall/rules
  GET  /client/v4/zones/{zone_id}/waf/packages
  GET  /client/v4/zones/{zone_id}/security_events
  GET  /client/v4/accounts/{account_id}/access/groups

Required env vars
-----------------
    CLOUDFLARE_API_TOKEN  Bearer token. Sent as
                          ``Authorization: Bearer {CLOUDFLARE_API_TOKEN}``.

NO MOCKS rule
-------------
* If the env var is unset the engine reports
  ``credentials_present()=False`` and every live call raises
  ``CloudflareUnavailableError`` (router translates to HTTP 503).
* No fabricated zones / DNS records / firewall rules / events — ever.
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
CLOUDFLARE_BASE_URL = "https://api.cloudflare.com"


class CloudflareUnavailableError(RuntimeError):
    """Raised when Cloudflare credentials are missing or upstream call fails."""


class CloudflareEngine:
    """Live Cloudflare API v4 REST client.

    Stateless. Designed to be used as a process-wide singleton via
    ``get_cloudflare_engine()``.
    """

    def __init__(
        self,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
        base_url: str = CLOUDFLARE_BASE_URL,
    ) -> None:
        self._token = (
            api_token
            if api_token is not None
            else os.getenv("CLOUDFLARE_API_TOKEN")
        )
        self._base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def token_present(self) -> bool:
        return bool(self._token and str(self._token).strip())

    def credentials_present(self) -> bool:
        return self.token_present()

    def base_url(self) -> str:
        return self._base_url

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _ensure_creds(self) -> None:
        if not self.credentials_present():
            raise CloudflareUnavailableError(
                "CLOUDFLARE_API_TOKEN must be set"
            )

    def _get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self._ensure_creds()
        url = f"{self._base_url}{path}"
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        try:
            resp = self._client.get(
                url, params=clean_params, headers=self._headers()
            )
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover
            raise CloudflareUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = (getattr(resp, "text", "") or "")[:300]
            raise CloudflareUnavailableError(
                f"{path} returned {status}: {text}"
            )
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise CloudflareUnavailableError(
                f"{path} returned non-JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise CloudflareUnavailableError(
                f"{path} returned non-object payload"
            )
        return data

    # ------------------------------------------------------------------
    # Zones
    # ------------------------------------------------------------------
    def list_zones(
        self,
        name: Optional[str] = None,
        status: Optional[str] = None,
        account_id: Optional[str] = None,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
        order: Optional[str] = None,
        direction: Optional[str] = None,
        match: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = {
            "name": name,
            "status": status,
            "account.id": account_id,
            "page": page,
            "per_page": per_page,
            "order": order,
            "direction": direction,
            "match": match,
        }
        return self._get("/client/v4/zones", params=params)

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        if not zone_id or not str(zone_id).strip():
            raise ValueError("zone_id is required")
        return self._get(f"/client/v4/zones/{zone_id}")

    # ------------------------------------------------------------------
    # DNS Records
    # ------------------------------------------------------------------
    def list_dns_records(
        self,
        zone_id: str,
        type: Optional[str] = None,
        name: Optional[str] = None,
        content: Optional[str] = None,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
        order: Optional[str] = None,
        direction: Optional[str] = None,
        match: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not zone_id or not str(zone_id).strip():
            raise ValueError("zone_id is required")
        params = {
            "type": type,
            "name": name,
            "content": content,
            "page": page,
            "per_page": per_page,
            "order": order,
            "direction": direction,
            "match": match,
        }
        return self._get(
            f"/client/v4/zones/{zone_id}/dns_records", params=params
        )

    # ------------------------------------------------------------------
    # Firewall Rules
    # ------------------------------------------------------------------
    def list_firewall_rules(
        self,
        zone_id: str,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not zone_id or not str(zone_id).strip():
            raise ValueError("zone_id is required")
        params = {"page": page, "per_page": per_page}
        return self._get(
            f"/client/v4/zones/{zone_id}/firewall/rules", params=params
        )

    # ------------------------------------------------------------------
    # WAF Packages
    # ------------------------------------------------------------------
    def list_waf_packages(self, zone_id: str) -> Dict[str, Any]:
        if not zone_id or not str(zone_id).strip():
            raise ValueError("zone_id is required")
        return self._get(f"/client/v4/zones/{zone_id}/waf/packages")

    # ------------------------------------------------------------------
    # Security Events
    # ------------------------------------------------------------------
    def list_security_events(
        self,
        zone_id: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
        action: Optional[str] = None,
        kind: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not zone_id or not str(zone_id).strip():
            raise ValueError("zone_id is required")
        params = {
            "since": since,
            "until": until,
            "action": action,
            "kind": kind,
            "limit": limit,
        }
        return self._get(
            f"/client/v4/zones/{zone_id}/security_events", params=params
        )

    # ------------------------------------------------------------------
    # Access Groups
    # ------------------------------------------------------------------
    def list_access_groups(
        self,
        account_id: str,
        name: Optional[str] = None,
        page: Optional[int] = None,
        per_page: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not account_id or not str(account_id).strip():
            raise ValueError("account_id is required")
        params = {
            "name": name,
            "page": page,
            "per_page": per_page,
        }
        return self._get(
            f"/client/v4/accounts/{account_id}/access/groups", params=params
        )

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
_singleton: Optional[CloudflareEngine] = None
_singleton_lock = threading.Lock()


def get_cloudflare_engine(
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> CloudflareEngine:
    """Return the process-wide CloudflareEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = CloudflareEngine(
                api_token=api_token,
                client=client,
            )
        return _singleton


def reset_cloudflare_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "CloudflareEngine",
    "CloudflareUnavailableError",
    "get_cloudflare_engine",
    "reset_cloudflare_engine",
]
