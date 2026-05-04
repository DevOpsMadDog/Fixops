"""Lacework CSPM Engine — ALDECI.

Live Lacework REST client. Two-phase auth:
  1. POST /api/v2/access/tokens with key+secret header X-LW-UAKS
     → returns {expiresAt, token}
  2. Subsequent calls use Bearer header on https://{LACEWORK_ACCOUNT}.lacework.net

Token cached in-memory ~50 min. NO SQLite cache. NO MOCKS — when env unset,
capability_summary returns ``status=unavailable`` and lookup endpoints raise.

Env:
  LACEWORK_ACCOUNT  — sub-account / tenant name (lacework_account.lacework.net)
  LACEWORK_KEY_ID   — API key id
  LACEWORK_SECRET   — API key secret

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
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


class LaceworkEngine:
    """Live Lacework CSPM client.

    Two-phase auth. Token cached in-memory ~50 min (Lacework default ttl is
    typically 1 h but we refresh proactively).
    """

    TOKEN_TTL_SECONDS = 50 * 60  # 50 min in-memory cache
    DEFAULT_TOKEN_EXPIRY = 3600  # 1 h request body default

    def __init__(
        self,
        account: Optional[str] = None,
        key_id: Optional[str] = None,
        secret: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._account = account or os.environ.get("LACEWORK_ACCOUNT", "")
        self._key_id = key_id or os.environ.get("LACEWORK_KEY_ID", "")
        self._secret = secret or os.environ.get("LACEWORK_SECRET", "")
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
    def account_present(self) -> bool:
        return bool(self._account)

    @property
    def key_id_present(self) -> bool:
        return bool(self._key_id)

    @property
    def secret_present(self) -> bool:
        return bool(self._secret)

    @property
    def configured(self) -> bool:
        return self.account_present and self.key_id_present and self.secret_present

    @property
    def base_url(self) -> str:
        return f"https://{self._account}.lacework.net" if self._account else ""

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
                "Lacework not configured: LACEWORK_ACCOUNT, LACEWORK_KEY_ID, "
                "and LACEWORK_SECRET must be set"
            )

    def request_access_token(
        self,
        key_id: Optional[str] = None,
        expiry_time: Optional[int] = None,
    ) -> Dict[str, Any]:
        """POST /api/v2/access/tokens — direct passthrough.

        Returns ``{"token": "...", "expiresAt": "..."}`` from upstream.
        Used both internally (token cache) and via the router /access/tokens
        endpoint.
        """
        self._require_configured()
        body: Dict[str, Any] = {
            "keyId": key_id or self._key_id,
            "expiryTime": expiry_time or self.DEFAULT_TOKEN_EXPIRY,
        }
        headers = {
            "X-LW-UAKS": self._secret,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        url = f"{self.base_url}/api/v2/access/tokens"
        resp = self._client_inst().post(url, json=body, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def _get_access_token(self) -> str:
        """Two-phase auth w/ ~50min in-memory cache."""
        now = time.time()
        if self._access_token and now < self._token_expires_at:
            return self._access_token

        with self._lock:
            now = time.time()
            if self._access_token and now < self._token_expires_at:
                return self._access_token

            payload = self.request_access_token()
            token = payload.get("token", "")
            if not token:
                raise RuntimeError("lacework auth: empty token in response")
            self._access_token = token
            self._token_expires_at = now + self.TOKEN_TTL_SECONDS
            return token

    def _headers(self) -> Dict[str, str]:
        token = self._get_access_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._require_configured()
        url = f"{self.base_url}{path}"
        resp = self._client_inst().get(url, params=params, headers=self._headers())
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"data": [], "raw": resp.text}

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        self._require_configured()
        url = f"{self.base_url}{path}"
        resp = self._client_inst().post(url, json=body, headers=self._headers())
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            return {"data": [], "raw": resp.text}

    def _emit(self, event: str, data: Dict[str, Any]) -> None:
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                if bus is not None:
                    bus.emit_event(event, data)
        except Exception:  # pragma: no cover
            pass

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "Lacework",
            "endpoints": [
                "/api/v2/Alerts",
                "/api/v2/Compliance/Reports",
                "/api/v2/Vulnerabilities/Hosts/search",
                "/api/v2/Vulnerabilities/Containers/search",
                "/api/v2/Inventory",
            ],
            "lacework_account_present": self.account_present,
            "lacework_key_id_present": self.key_id_present,
            "lacework_secret_present": self.secret_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        status: Optional[str] = None,
        page_size: Optional[int] = None,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        if status:
            params["status"] = status
        if page_size:
            params["pageSize"] = page_size
        if token:
            params["token"] = token
        payload = self._get("/api/v2/Alerts", params=params)
        self._emit("lacework.alerts.list", {"params": params, "count": len(payload.get("data", []))})
        return payload

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        payload = self._get(f"/api/v2/Alerts/{alert_id}")
        self._emit("lacework.alerts.get", {"alert_id": alert_id})
        return payload

    # ------------------------------------------------------------------
    # Compliance
    # ------------------------------------------------------------------

    def aws_compliance_latest(
        self,
        account_id: str,
        report_format: str = "json",
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "accountId": account_id,
            "format": report_format,
        }
        payload = self._get("/api/v2/Compliance/Reports/AwsLatest", params=params)
        self._emit(
            "lacework.compliance.aws_latest",
            {"account_id": account_id, "format": report_format},
        )
        return payload

    # ------------------------------------------------------------------
    # Vulnerabilities — hosts + containers
    # ------------------------------------------------------------------

    def search_host_vulnerabilities(self, body: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._post("/api/v2/Vulnerabilities/Hosts/search", body)
        self._emit(
            "lacework.vulns.hosts.search",
            {"filters": body.get("filters"), "count": len(payload.get("data", []))},
        )
        return payload

    def search_container_vulnerabilities(self, body: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._post("/api/v2/Vulnerabilities/Containers/search", body)
        self._emit(
            "lacework.vulns.containers.search",
            {"filters": body.get("filters"), "count": len(payload.get("data", []))},
        )
        return payload

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------

    def list_inventory(
        self,
        inv_type: Optional[str] = None,
        csp: Optional[str] = None,
        page_size: Optional[int] = None,
        token: Optional[str] = None,
        filters: Optional[List[Dict[str, Any]]] = None,
        returns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if inv_type:
            params["type"] = inv_type
        if csp:
            params["csp"] = csp
        if page_size:
            params["pageSize"] = page_size
        if token:
            params["token"] = token
        if filters:
            params["filters"] = filters
        if returns:
            params["returns"] = returns
        payload = self._get("/api/v2/Inventory", params=params)
        self._emit(
            "lacework.inventory.list",
            {"type": inv_type, "csp": csp, "count": len(payload.get("data", []))},
        )
        return payload

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


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[LaceworkEngine] = None


def get_lacework_engine() -> LaceworkEngine:
    """Return process-wide LaceworkEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = LaceworkEngine()
    return _singleton


def reset_lacework_engine() -> None:
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
    "LaceworkEngine",
    "get_lacework_engine",
    "reset_lacework_engine",
]
