"""CrowdStrike Falcon EDR — REAL OAuth2 REST API client.

This engine is the *live* counterpart to the parser-only
``connectors/crowdstrike_falcon_connector.py`` (which ingests customer-
supplied JSON dumps). Here we hit Falcon's documented REST surface:

  POST /oauth2/token                       OAuth2 client_credentials grant
  GET  /detects/queries/detects            list detection ids by FQL
  POST /detects/entities/summaries/GET     fetch detection details by id
  GET  /incidents/queries/incidents        list incident ids by FQL
  GET  /iocs/queries/indicators            list IoC ids by type
  POST /iocs/entities/indicators           submit IoCs

API base host defaults to ``https://api.crowdstrike.com`` and is
overridable via ``FALCON_BASE_URL`` (eu-1 / us-2 / gov tenants use
different hosts per CrowdStrike public docs).

NO MOCKS rule:
  * If ``FALCON_CLIENT_ID`` or ``FALCON_CLIENT_SECRET`` is unset the
    engine reports ``api_credentials_present()=False`` and *every* live
    lookup raises ``FalconUnavailableError`` (router translates to 503).
  * No fabricated detection ids, incidents, indicators ever.

Token cache is in-memory only (Falcon recommends ~30 minute lifetime).

References:
  https://falcon.crowdstrike.com/documentation/page/x2hyh17q
  https://falcon.crowdstrike.com/documentation/page/oauth2/api-reference
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.crowdstrike.com"
TOKEN_TTL_SECONDS = 30 * 60          # Falcon tokens are 30 min by default
TOKEN_REFRESH_GRACE = 60             # refresh 60 s before expiry
DEFAULT_TIMEOUT = 30.0


class FalconUnavailableError(RuntimeError):
    """Raised when Falcon credentials are missing or upstream call fails."""


class FalconEDREngine:
    """Live CrowdStrike Falcon REST API client.

    Stateless except for an in-memory OAuth2 token cache. Designed to be
    used as a process-wide singleton via ``get_falcon_edr_engine()``.
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._client_id = client_id if client_id is not None else os.getenv("FALCON_CLIENT_ID")
        self._client_secret = (
            client_secret if client_secret is not None else os.getenv("FALCON_CLIENT_SECRET")
        )
        self._base_url = (base_url or os.getenv("FALCON_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self._client = client or httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._owns_client = client is None
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Public introspection
    # ------------------------------------------------------------------
    def client_id_present(self) -> bool:
        return bool(self._client_id and str(self._client_id).strip())

    def client_secret_present(self) -> bool:
        return bool(self._client_secret and str(self._client_secret).strip())

    def api_credentials_present(self) -> bool:
        return self.client_id_present() and self.client_secret_present()

    # ------------------------------------------------------------------
    # OAuth2 token management
    # ------------------------------------------------------------------
    def _ensure_token(self) -> str:
        if not self.api_credentials_present():
            raise FalconUnavailableError(
                "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET must be set"
            )
        with self._lock:
            now = time.time()
            if self._token and now < (self._token_expires_at - TOKEN_REFRESH_GRACE):
                return self._token
            url = f"{self._base_url}/oauth2/token"
            try:
                resp = self._client.post(
                    url,
                    data={
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
                raise FalconUnavailableError(f"oauth2 token request failed: {exc}") from exc
            if getattr(resp, "status_code", 500) != 200:
                detail = getattr(resp, "text", "")[:200]
                raise FalconUnavailableError(
                    f"oauth2 token rejected (status={resp.status_code}): {detail}"
                )
            try:
                payload = resp.json() or {}
            except (ValueError, TypeError) as exc:
                raise FalconUnavailableError(f"oauth2 token JSON malformed: {exc}") from exc
            token = payload.get("access_token")
            if not token:
                raise FalconUnavailableError("oauth2 response missing access_token")
            ttl = int(payload.get("expires_in") or TOKEN_TTL_SECONDS)
            self._token = str(token)
            self._token_expires_at = now + ttl
            return self._token

    def _auth_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------
    # REST helpers
    # ------------------------------------------------------------------
    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            resp = self._client.get(url, params=params or {}, headers=self._auth_headers())
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise FalconUnavailableError(f"GET {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    def _post(self, path: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"
        try:
            resp = self._client.post(url, json=json_body, headers=headers)
        except (httpx.HTTPError, httpx.TimeoutException) as exc:  # pragma: no cover - network
            raise FalconUnavailableError(f"POST {path} failed: {exc}") from exc
        return self._unwrap(resp, path)

    @staticmethod
    def _unwrap(resp: Any, path: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 500)
        if status >= 400:
            text = getattr(resp, "text", "")[:300]
            raise FalconUnavailableError(f"{path} returned {status}: {text}")
        try:
            data = resp.json()
        except (ValueError, TypeError) as exc:
            raise FalconUnavailableError(f"{path} returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise FalconUnavailableError(f"{path} returned non-object payload")
        return data

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------
    def query_detects(
        self,
        fql: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List detection ids matching an FQL filter."""
        params: Dict[str, Any] = {"limit": int(limit), "offset": int(offset)}
        if fql:
            params["filter"] = fql
        if sort:
            params["sort"] = sort
        data = self._get("/detects/queries/detects/v1", params=params)
        meta = data.get("meta") or {}
        resources = [str(r) for r in (data.get("resources") or []) if r]
        return {"meta": meta, "resources": resources}

    def get_detect_summaries(self, ids: List[str]) -> Dict[str, Any]:
        """Fetch full detection summary objects for a list of ids."""
        if not isinstance(ids, list) or not ids:
            raise ValueError("ids must be a non-empty list")
        clean_ids = [str(i).strip() for i in ids if str(i).strip()]
        if not clean_ids:
            raise ValueError("ids must contain at least one non-empty value")
        data = self._post("/detects/entities/summaries/GET/v1", {"ids": clean_ids})
        meta = data.get("meta") or {}
        resources_in = data.get("resources") or []
        resources_out: List[Dict[str, Any]] = []
        for raw in resources_in:
            if not isinstance(raw, dict):
                continue
            device = raw.get("device") or {}
            normalized = {
                "detection_id":  raw.get("detection_id") or raw.get("DetectId") or "",
                "severity":      raw.get("max_severity") or raw.get("severity") or 0,
                "severity_name": raw.get("max_severity_displayname")
                                   or raw.get("severity_name") or "",
                "status":        raw.get("status") or "",
                "behaviors":     raw.get("behaviors") or [],
                "device": {
                    "hostname":     device.get("hostname") or "",
                    "platform_name": device.get("platform_name") or "",
                    "os_version":   device.get("os_version") or "",
                },
                "hostinfo":      raw.get("hostinfo") or {},
            }
            resources_out.append(normalized)
            if _get_tg_bus and normalized["detection_id"]:
                try:
                    _bus = _get_tg_bus()
                    if _bus:
                        _bus.emit(
                            "threat.detected",
                            {
                                "entity_id": normalized["detection_id"],
                                "type": "falcon_edr_detection",
                                "severity": normalized["severity_name"] or str(normalized["severity"]),
                                "source_engine": "falcon_edr",
                                "status": normalized["status"],
                                "hostname": normalized["device"]["hostname"],
                            },
                        )
                except Exception:
                    pass
        return {"meta": meta, "resources": resources_out}

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------
    def query_incidents(
        self,
        fql: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        sort: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": int(limit), "offset": int(offset)}
        if fql:
            params["filter"] = fql
        if sort:
            params["sort"] = sort
        data = self._get("/incidents/queries/incidents/v1", params=params)
        return {
            "meta": data.get("meta") or {},
            "resources": [str(r) for r in (data.get("resources") or []) if r],
        }

    # ------------------------------------------------------------------
    # IoCs
    # ------------------------------------------------------------------
    _ALLOWED_IOC_TYPES = {"ipv4", "ipv6", "domain", "md5", "sha256", "sha1"}
    _ALLOWED_IOC_ACTIONS = {"detect", "prevent", "allow", "no_action"}

    def query_indicators(self, ioc_type: str, limit: int = 50) -> Dict[str, Any]:
        if ioc_type not in self._ALLOWED_IOC_TYPES:
            raise ValueError(
                f"ioc_type must be one of {sorted(self._ALLOWED_IOC_TYPES)}"
            )
        params = {"types": ioc_type, "limit": int(limit)}
        data = self._get("/iocs/queries/indicators/v1", params=params)
        return {
            "meta": data.get("meta") or {},
            "resources": [str(r) for r in (data.get("resources") or []) if r],
        }

    def submit_indicators(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not isinstance(indicators, list) or not indicators:
            raise ValueError("indicators must be a non-empty list")
        payload: List[Dict[str, Any]] = []
        for raw in indicators:
            if not isinstance(raw, dict):
                raise ValueError("each indicator must be a dict")
            t = str(raw.get("type") or "").lower().strip()
            v = str(raw.get("value") or "").strip()
            action = str(raw.get("action") or "detect").lower().strip()
            if t not in self._ALLOWED_IOC_TYPES:
                raise ValueError(
                    f"indicator.type must be one of {sorted(self._ALLOWED_IOC_TYPES)}"
                )
            if not v:
                raise ValueError("indicator.value is required")
            if action not in self._ALLOWED_IOC_ACTIONS:
                raise ValueError(
                    f"indicator.action must be one of {sorted(self._ALLOWED_IOC_ACTIONS)}"
                )
            entry: Dict[str, Any] = {
                "type":   t,
                "value":  v,
                "action": action,
            }
            for opt in ("severity", "source", "description", "expiration", "platforms"):
                if raw.get(opt) is not None:
                    entry[opt] = raw[opt]
            payload.append(entry)
        data = self._post("/iocs/entities/indicators/v1", {"indicators": payload})
        meta = data.get("meta") or {}
        resources_in = data.get("resources") or []
        resources_out: List[Dict[str, Any]] = []
        for raw in resources_in:
            if not isinstance(raw, dict):
                continue
            resources_out.append(
                {
                    "id":     raw.get("id") or "",
                    "value":  raw.get("value") or "",
                    "action": raw.get("action") or "",
                }
            )
        return {"meta": meta, "resources": resources_out}

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
_singleton: Optional[FalconEDREngine] = None
_singleton_lock = threading.Lock()


def get_falcon_edr_engine(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> FalconEDREngine:
    """Return the process-wide FalconEDREngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = FalconEDREngine(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
                client=client,
            )
        return _singleton


def reset_falcon_edr_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "FalconEDREngine",
    "FalconUnavailableError",
    "get_falcon_edr_engine",
    "reset_falcon_edr_engine",
]
