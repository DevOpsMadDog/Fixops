"""ALDECI Microsoft Defender XDR engine — REAL httpx only, NO MOCKS, NO CACHE.

Wraps three Microsoft security APIs over OAuth2 client_credentials:

  1. Microsoft Graph Security API (alerts_v2, incidents)
       https://graph.microsoft.com/v1.0/security/...
       scope: https://graph.microsoft.com/.default
  2. Microsoft Defender for Endpoint (machines, security recommendations)
       https://api.securitycenter.microsoft.com/api/...
       scope: https://api.securitycenter.microsoft.com/.default
  3. Microsoft 365 Defender (advanced hunting KQL)
       https://api.security.microsoft.com/api/advancedhunting/run
       scope: https://api.security.microsoft.com/.default

Each scope has its own cached bearer token (refreshed near expiry).

Singleton keyed by env (AZURE_TENANT_ID / AZURE_CLIENT_ID /
AZURE_CLIENT_SECRET). When credentials are absent the capability summary
returns ``status="unavailable"`` and every lookup endpoint raises
``DefenderXDRUnavailableError`` which the router translates to HTTP 503.

NO SQLite cache. NO mock fallback.

Singleton:
    eng = get_defender_xdr_engine()

Reset (tests):
    reset_defender_xdr_engine()
"""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
_TOKEN_REFRESH_SLACK_SECONDS = 60.0

# Resource scopes for the three Microsoft security surfaces.
SCOPE_GRAPH = "https://graph.microsoft.com/.default"
SCOPE_DEFENDER_ENDPOINT = "https://api.securitycenter.microsoft.com/.default"
SCOPE_M365_DEFENDER = "https://api.security.microsoft.com/.default"

# Resource base URLs.
BASE_GRAPH = "https://graph.microsoft.com"
BASE_DEFENDER_ENDPOINT = "https://api.securitycenter.microsoft.com"
BASE_M365_DEFENDER = "https://api.security.microsoft.com"

# Microsoft Identity Platform OAuth2 token endpoint.
_LOGIN_HOST = "https://login.microsoftonline.com"


# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Best-effort TrustGraph emit. Never raises. Handles async bus.emit safely."""
    if _get_tg_bus is None:
        return
    try:
        import asyncio
        import inspect
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        if inspect.isawaitable(result):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(result)
            except RuntimeError:
                result.close()
    except Exception:  # pragma: no cover
        pass


class DefenderXDRUnavailableError(RuntimeError):
    """Raised when Defender XDR creds are unset or the API rejected the call."""


class DefenderXDREngine:
    """Real httpx-backed Microsoft Defender XDR client.

    All public methods raise ``DefenderXDRUnavailableError`` when
    AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET are not
    configured. Routers translate this to HTTP 503.
    """

    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_tenant = tenant_id
        self._explicit_client_id = client_id
        self._explicit_client_secret = client_secret

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout

        # Per-scope token cache: scope -> (bearer, expires_at_unix)
        self._tokens: Dict[str, Any] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ creds

    def _tenant_id(self) -> str:
        if self._explicit_tenant is not None:
            return self._explicit_tenant.strip()
        return (os.environ.get("AZURE_TENANT_ID") or "").strip()

    def _client_id(self) -> str:
        if self._explicit_client_id is not None:
            return self._explicit_client_id.strip()
        return (os.environ.get("AZURE_CLIENT_ID") or "").strip()

    def _client_secret(self) -> str:
        if self._explicit_client_secret is not None:
            return self._explicit_client_secret.strip()
        return (os.environ.get("AZURE_CLIENT_SECRET") or "").strip()

    def tenant_present(self) -> bool:
        return bool(self._tenant_id())

    def client_present(self) -> bool:
        return bool(self._client_id())

    def is_configured(self) -> bool:
        return (
            bool(self._tenant_id())
            and bool(self._client_id())
            and bool(self._client_secret())
        )

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise DefenderXDRUnavailableError(
                "AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET not set "
                "— set all three to call Microsoft Defender XDR"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    # ---------------------------------------------------------------- token

    def _token_for(self, scope: str) -> str:
        """Return a cached bearer for ``scope``; fetch + cache if expired."""
        now = time.time()
        with self._lock:
            cached = self._tokens.get(scope)
            if cached is not None:
                bearer, expires_at = cached
                if expires_at - _TOKEN_REFRESH_SLACK_SECONDS > now:
                    return bearer

            self._require_configured()
            client = self._ensure_client()
            url = f"{_LOGIN_HOST}/{self._tenant_id()}/oauth2/v2.0/token"
            data = {
                "grant_type": "client_credentials",
                "client_id": self._client_id(),
                "client_secret": self._client_secret(),
                "scope": scope,
            }
            try:
                resp = client.post(
                    url,
                    data=data,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
            except httpx.HTTPError as exc:
                raise DefenderXDRUnavailableError(
                    f"Azure token request failed: {exc}"
                ) from exc

            if resp.status_code in (400, 401, 403):
                raise DefenderXDRUnavailableError(
                    f"Azure rejected client_credentials (HTTP {resp.status_code}): "
                    f"{resp.text[:200]}"
                )
            if resp.status_code >= 400:
                raise DefenderXDRUnavailableError(
                    f"Azure token endpoint returned HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
            try:
                payload = resp.json()
            except ValueError as exc:
                raise DefenderXDRUnavailableError(
                    f"Azure token response was not JSON: {exc}"
                ) from exc
            bearer = payload.get("access_token")
            if not bearer or not isinstance(bearer, str):
                raise DefenderXDRUnavailableError(
                    "Azure token response missing 'access_token'"
                )
            try:
                expires_in = float(payload.get("expires_in", 3600))
            except (TypeError, ValueError):
                expires_in = 3600.0
            self._tokens[scope] = (bearer, now + expires_in)
            return bearer

    # ---------------------------------------------------------------- request

    def _request(
        self,
        method: str,
        base_url: str,
        path: str,
        scope: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        bearer = self._token_for(scope)
        client = self._ensure_client()
        url = f"{base_url}{path}"
        headers = {
            "Authorization": f"Bearer {bearer}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            if method == "GET":
                resp = client.get(url, headers=headers, params=params or None)
            elif method == "POST":
                resp = client.post(
                    url,
                    headers=headers,
                    json=json_body,
                    params=params or None,
                )
            else:
                raise DefenderXDRUnavailableError(
                    f"Unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise DefenderXDRUnavailableError(
                f"Defender XDR request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            # Drop the cached token so the next call re-auths.
            with self._lock:
                self._tokens.pop(scope, None)
            raise DefenderXDRUnavailableError(
                f"Defender XDR rejected token (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise DefenderXDRUnavailableError(
                f"Defender XDR returned 404 for {path}"
            )
        if resp.status_code >= 400:
            raise DefenderXDRUnavailableError(
                f"Defender XDR returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise DefenderXDRUnavailableError(
                f"Defender XDR returned non-JSON response: {exc}"
            ) from exc
        return payload if isinstance(payload, dict) else {"value": payload}

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Microsoft Defender XDR",
            "endpoints": [
                "/v1.0/security/alerts_v2",
                "/v1.0/security/incidents",
                "/api/machines",
                "/api/advancedhunting/run",
                "/api/securityrecommendations",
            ],
            "azure_tenant_present": self.tenant_present(),
            "azure_client_present": self.client_present(),
            "status": status,
        }

    # ----------------------------------------------------- alerts (Graph)

    def list_alerts(
        self,
        odata_filter: Optional[str] = None,
        top: Optional[int] = None,
        orderby: Optional[str] = None,
        select: Optional[str] = None,
        count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if odata_filter:
            params["$filter"] = odata_filter
        if top is not None:
            params["$top"] = int(top)
        if orderby:
            params["$orderby"] = orderby
        if select:
            params["$select"] = select
        if count is not None:
            params["$count"] = "true" if bool(count) else "false"
        out = self._request(
            "GET",
            BASE_GRAPH,
            "/v1.0/security/alerts_v2",
            SCOPE_GRAPH,
            params=params,
        )
        try:
            data_count = len(out.get("value") or [])
            _emit_event(
                "defender_xdr.alerts_listed",
                {"count": data_count, "filter": odata_filter or ""},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    # -------------------------------------------------- incidents (Graph)

    def list_incidents(
        self,
        odata_filter: Optional[str] = None,
        top: Optional[int] = None,
        orderby: Optional[str] = None,
        expand: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if odata_filter:
            params["$filter"] = odata_filter
        if top is not None:
            params["$top"] = int(top)
        if orderby:
            params["$orderby"] = orderby
        if expand:
            params["$expand"] = expand
        return self._request(
            "GET",
            BASE_GRAPH,
            "/v1.0/security/incidents",
            SCOPE_GRAPH,
            params=params,
        )

    # ---------------------------------------------- machines (Defender for Endpoint)

    def list_machines(
        self,
        odata_filter: Optional[str] = None,
        top: Optional[int] = None,
        orderby: Optional[str] = None,
        skip: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if odata_filter:
            params["$filter"] = odata_filter
        if top is not None:
            params["$top"] = int(top)
        if orderby:
            params["$orderby"] = orderby
        if skip is not None:
            params["$skip"] = int(skip)
        return self._request(
            "GET",
            BASE_DEFENDER_ENDPOINT,
            "/api/machines",
            SCOPE_DEFENDER_ENDPOINT,
            params=params,
        )

    # ------------------------------- security recommendations (Defender for Endpoint)

    def list_security_recommendations(
        self,
        odata_filter: Optional[str] = None,
        top: Optional[int] = None,
        orderby: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if odata_filter:
            params["$filter"] = odata_filter
        if top is not None:
            params["$top"] = int(top)
        if orderby:
            params["$orderby"] = orderby
        return self._request(
            "GET",
            BASE_DEFENDER_ENDPOINT,
            "/api/securityrecommendations",
            SCOPE_DEFENDER_ENDPOINT,
            params=params,
        )

    # -------------------------------------- advanced hunting (M365 Defender)

    def run_advanced_hunting(self, kql_query: str) -> Dict[str, Any]:
        if not kql_query or not kql_query.strip():
            raise ValueError("Query must not be empty")
        body = {"Query": kql_query}
        return self._request(
            "POST",
            BASE_M365_DEFENDER,
            "/api/advancedhunting/run",
            SCOPE_M365_DEFENDER,
            json_body=body,
        )

    # ----------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            try:
                self._client.close()
            except Exception:  # pragma: no cover
                pass


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[DefenderXDREngine] = None
_singleton_lock = threading.RLock()


def get_defender_xdr_engine(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> DefenderXDREngine:
    """Return the process-wide DefenderXDREngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (tenant_id, client_id, client_secret, client)
        ):
            if _singleton is not None:
                _singleton.close()
            _singleton = DefenderXDREngine(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                client=client,
            )
        return _singleton


def reset_defender_xdr_engine() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "DefenderXDREngine",
    "DefenderXDRUnavailableError",
    "get_defender_xdr_engine",
    "reset_defender_xdr_engine",
    "SCOPE_GRAPH",
    "SCOPE_DEFENDER_ENDPOINT",
    "SCOPE_M365_DEFENDER",
]
