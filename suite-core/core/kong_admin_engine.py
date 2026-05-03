"""ALDECI Kong Admin API Engine.

Thin pass-through client for the **Kong Admin API** — services, routes,
plugins, consumers, upstreams, targets, certificates, SNIs, and status. The
Kong Admin API is the canonical control plane surface for an OSS / Enterprise
Kong gateway and exposes the entire declarative configuration as REST.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env var (``KONG_ADMIN_URL``) is unset the engine reports
``status="unavailable"`` and lookup endpoints return HTTP 503.

The optional ``KONG_ADMIN_TOKEN`` is forwarded as ``Kong-Admin-Token``. Kong
Admin API on private networks frequently runs unauthenticated, so missing
``KONG_ADMIN_TOKEN`` is **not** treated as unavailable — only the URL is
required.

Environment variables
---------------------
KONG_ADMIN_URL    — base Kong Admin URL, e.g. ``http://kong-admin.example.com:8001``
KONG_ADMIN_TOKEN  — optional Kong-Admin-Token header (Enterprise / RBAC)

The engine is a process-level singleton accessible via
:func:`get_kong_admin_engine`.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin

import httpx

logger = logging.getLogger(__name__)

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/services",
    "/routes",
    "/plugins",
    "/consumers",
    "/upstreams",
    "/certificates",
    "/sni",
]


class KongAdminUnavailable(RuntimeError):
    """Raised when KONG_ADMIN_URL is not configured."""


class KongAdminHTTPError(RuntimeError):
    """Raised when Kong returns a non-2xx response."""

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class KongAdminEngine:
    """Pass-through Kong Admin API client backed by ``httpx.Client``."""

    def __init__(
        self,
        kong_admin_url: Optional[str] = None,
        kong_admin_token: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._kong_admin_url = (
            kong_admin_url
            if kong_admin_url is not None
            else os.environ.get("KONG_ADMIN_URL", "")
        ).strip()
        self._kong_admin_token = (
            kong_admin_token
            if kong_admin_token is not None
            else os.environ.get("KONG_ADMIN_TOKEN", "")
        ).strip()
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def kong_admin_url_present(self) -> bool:
        return bool(self._kong_admin_url)

    @property
    def kong_admin_token_present(self) -> bool:
        return bool(self._kong_admin_token)

    @property
    def configured(self) -> bool:
        # Token is OPTIONAL — Kong Admin API on private networks runs unauth.
        return self.kong_admin_url_present

    def status(self) -> str:
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Kong API Gateway",
            "endpoints": list(_ENDPOINT_CATALOG),
            "kong_admin_url_present": self.kong_admin_url_present,
            "kong_admin_token_present": self.kong_admin_token_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise KongAdminUnavailable(
                "KONG_ADMIN_URL must be set to call Kong Admin endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._kong_admin_url.rstrip("/") + "/"
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {
            "Accept": "application/json",
        }
        if self._kong_admin_token:
            h["Kong-Admin-Token"] = self._kong_admin_token
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        url = self._url(path)
        try:
            resp = self._client.request(
                method,
                url,
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "kong upstream error %s %s: %s", method, path, type(exc).__name__
            )
            raise KongAdminHTTPError(
                502, f"Upstream Kong request failed: {type(exc).__name__}"
            ) from exc

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise KongAdminHTTPError(
            resp.status_code, f"Kong returned {resp.status_code}", payload
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _list_params(
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if size is not None:
            params["size"] = size
        if offset:
            params["offset"] = offset
        if tags:
            params["tags"] = tags
        for k, v in extra.items():
            if v is not None and v != "":
                params[k] = v
        return params

    @staticmethod
    def _normalize_collection(body: Any) -> Dict[str, Any]:
        """Kong returns ``{data:[...], next:..., offset:...}`` for collections."""
        if not isinstance(body, dict):
            return {"data": [], "next": None, "offset": None}
        data = body.get("data") if isinstance(body.get("data"), list) else []
        return {
            "data": data,
            "next": body.get("next"),
            "offset": body.get("offset"),
        }

    # ------------------------------------------------------------------ ops

    def list_services(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(size=size, offset=offset, tags=tags)
        body = self._request("GET", "/services", params=params)
        return self._normalize_collection(body)

    def get_service(self, service_id_or_name: str) -> Dict[str, Any]:
        body = self._request(
            "GET", f"/services/{quote(service_id_or_name, safe='')}"
        )
        return body if isinstance(body, dict) else {}

    def list_routes(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
        service_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Kong filter is documented as ?service.id=<uuid>
        extra: Dict[str, Any] = {}
        if service_id:
            extra["service.id"] = service_id
        params = self._list_params(size=size, offset=offset, tags=tags, **extra)
        body = self._request("GET", "/routes", params=params)
        return self._normalize_collection(body)

    def list_plugins(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
        service_id: Optional[str] = None,
        route_id: Optional[str] = None,
        consumer_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        extra: Dict[str, Any] = {}
        if service_id:
            extra["service.id"] = service_id
        if route_id:
            extra["route.id"] = route_id
        if consumer_id:
            extra["consumer.id"] = consumer_id
        params = self._list_params(size=size, offset=offset, tags=tags, **extra)
        body = self._request("GET", "/plugins", params=params)
        return self._normalize_collection(body)

    def list_consumers(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
        custom_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        extra: Dict[str, Any] = {}
        if custom_id:
            extra["custom_id"] = custom_id
        params = self._list_params(size=size, offset=offset, tags=tags, **extra)
        body = self._request("GET", "/consumers", params=params)
        return self._normalize_collection(body)

    def consumer_key_auth(self, consumer_id_or_username: str) -> Dict[str, Any]:
        body = self._request(
            "GET",
            f"/consumers/{quote(consumer_id_or_username, safe='')}/key-auth",
        )
        return self._normalize_collection(body)

    def list_upstreams(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(size=size, offset=offset, tags=tags)
        body = self._request("GET", "/upstreams", params=params)
        return self._normalize_collection(body)

    def upstream_targets(self, upstream_id_or_name: str) -> Dict[str, Any]:
        body = self._request(
            "GET", f"/upstreams/{quote(upstream_id_or_name, safe='')}/targets"
        )
        return self._normalize_collection(body)

    def list_certificates(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(size=size, offset=offset, tags=tags)
        body = self._request("GET", "/certificates", params=params)
        return self._normalize_collection(body)

    def list_snis(
        self,
        *,
        size: Optional[int] = None,
        offset: Optional[str] = None,
        tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._list_params(size=size, offset=offset, tags=tags)
        body = self._request("GET", "/snis", params=params)
        return self._normalize_collection(body)

    def status_report(self) -> Dict[str, Any]:
        body = self._request("GET", "/status")
        return body if isinstance(body, dict) else {}

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

_engine: Optional[KongAdminEngine] = None
_engine_lock = Lock()


def get_kong_admin_engine(
    *,
    kong_admin_url: Optional[str] = None,
    kong_admin_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> KongAdminEngine:
    """Return (or create) the process-wide ``KongAdminEngine`` singleton.

    Tests can pass ``kong_admin_url=`` / ``kong_admin_token=`` / ``client=``
    explicitly to bypass env-var pickup. In normal use these are read lazily
    from the environment so monkeypatched env vars before first call still
    take effect.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = KongAdminEngine(
                kong_admin_url=kong_admin_url,
                kong_admin_token=kong_admin_token,
                client=client,
            )
    return _engine


def reset_kong_admin_engine() -> None:
    """Test helper — drop the cached singleton."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
