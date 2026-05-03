"""
ALDECI Grafana Loki Integration Engine.

Thin singleton client around Grafana Loki's HTTP API. Loki itself is the
durable store, so this engine is intentionally cache-free — it proxies
queries / pushes / label lookups to LOKI_URL.

Configuration:
    LOKI_URL           — required.  e.g. "http://loki:3100"
    LOKI_TIMEOUT_SEC   — optional, default 30
    LOKI_TENANT_ID     — optional, sent as X-Scope-OrgID header (multi-tenant Loki)
    LOKI_AUTH_TOKEN    — optional, sent as Authorization: Bearer ...

Status:
    "ok"           — LOKI_URL set; ready to proxy
    "unavailable"  — LOKI_URL unset (no upstream configured)

Vision Pillars: V8 (Observability), V9 (Operations)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class LokiUnavailableError(RuntimeError):
    """Raised when LOKI_URL is unset."""


class LokiUpstreamError(RuntimeError):
    """Raised when the Loki upstream returns a non-2xx response."""

    def __init__(self, status_code: int, body: str) -> None:
        super().__init__(f"Loki upstream returned {status_code}: {body[:200]}")
        self.status_code = status_code
        self.body = body


class LokiIntegrationEngine:
    """
    Stateless proxy to a Grafana Loki instance.

    Reads `LOKI_URL` *every call* so monkeypatch.setenv works in tests
    without rebuilding the singleton.
    """

    SUPPORTED_ENDPOINTS = (
        "/labels",
        "/push",
        "/query",
        "/query_range",
        "/series",
    )

    def __init__(self) -> None:
        self._client: Optional[httpx.Client] = None

    # ---- configuration helpers ----------------------------------------

    def loki_url(self) -> Optional[str]:
        v = os.environ.get("LOKI_URL", "").strip()
        return v or None

    def status(self) -> str:
        return "ok" if self.loki_url() else "unavailable"

    def is_available(self) -> bool:
        return self.loki_url() is not None

    def _timeout(self) -> float:
        try:
            return float(os.environ.get("LOKI_TIMEOUT_SEC", "30"))
        except ValueError:
            return 30.0

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"User-Agent": "ALDECI-LokiClient/1.0"}
        tenant = os.environ.get("LOKI_TENANT_ID", "").strip()
        if tenant:
            h["X-Scope-OrgID"] = tenant
        token = os.environ.get("LOKI_AUTH_TOKEN", "").strip()
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _client_or_new(self) -> httpx.Client:
        # New client per call keeps tests with monkeypatched httpx simple.
        return httpx.Client(timeout=self._timeout())

    # ---- low-level transport ------------------------------------------

    def _require_url(self) -> str:
        url = self.loki_url()
        if not url:
            raise LokiUnavailableError("LOKI_URL environment variable is not set")
        return url.rstrip("/")

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base = self._require_url()
        url = f"{base}{path}"
        with self._client_or_new() as c:
            try:
                resp = c.get(url, params=params or None, headers=self._headers())
            except httpx.RequestError as exc:
                logger.warning("loki_get_transport_error url=%s err=%s", url, exc)
                raise LokiUpstreamError(502, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise LokiUpstreamError(resp.status_code, resp.text)
        try:
            return resp.json()
        except ValueError:
            raise LokiUpstreamError(502, f"invalid JSON from upstream: {resp.text[:200]}")

    def _post_json(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        base = self._require_url()
        url = f"{base}{path}"
        headers = self._headers()
        headers["Content-Type"] = "application/json"
        with self._client_or_new() as c:
            try:
                resp = c.post(url, json=body, headers=headers)
            except httpx.RequestError as exc:
                logger.warning("loki_post_transport_error url=%s err=%s", url, exc)
                raise LokiUpstreamError(502, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise LokiUpstreamError(resp.status_code, resp.text)
        # /push returns 204; query endpoints return JSON.
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            raise LokiUpstreamError(502, f"invalid JSON from upstream: {resp.text[:200]}")

    # ---- public API ---------------------------------------------------

    def get_labels(self) -> Dict[str, Any]:
        return self._get("/loki/api/v1/labels")

    def get_label_values(self, name: str) -> Dict[str, Any]:
        # Loki path-encodes label name; httpx handles it via params=None.
        return self._get(f"/loki/api/v1/label/{name}/values")

    def push(self, streams_payload: Dict[str, Any]) -> None:
        """
        streams_payload = {"streams": [{"stream": {...labels}, "values": [[ts_ns, line], ...]}]}
        """
        self._post_json("/loki/api/v1/push", streams_payload)

    def query(
        self,
        logql: str,
        time: Optional[str] = None,
        limit: Optional[int] = None,
        direction: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"query": logql}
        if time is not None:
            params["time"] = time
        if limit is not None:
            params["limit"] = limit
        if direction is not None:
            params["direction"] = direction
        # Loki accepts both GET & POST (form) for /query; we use GET with params.
        return self._get("/loki/api/v1/query", params=params)

    def query_range(
        self,
        logql: str,
        start: str,
        end: str,
        step: Optional[str] = None,
        limit: Optional[int] = None,
        direction: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "query": logql,
            "start": start,
            "end": end,
        }
        if step is not None:
            params["step"] = step
        if limit is not None:
            params["limit"] = limit
        if direction is not None:
            params["direction"] = direction
        return self._get("/loki/api/v1/query_range", params=params)

    def series(
        self,
        match: List[str],
        start: Optional[str] = None,
        end: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: List[tuple] = [("match[]", m) for m in match]
        if start is not None:
            params.append(("start", start))
        if end is not None:
            params.append(("end", end))
        # Use httpx params= with list-of-tuples for repeated match[] keys.
        url = f"{self._require_url()}/loki/api/v1/series"
        with self._client_or_new() as c:
            try:
                resp = c.get(url, params=params, headers=self._headers())
            except httpx.RequestError as exc:
                logger.warning("loki_series_transport_error url=%s err=%s", url, exc)
                raise LokiUpstreamError(502, f"transport error: {exc}") from exc
        if resp.status_code >= 400:
            raise LokiUpstreamError(resp.status_code, resp.text)
        try:
            return resp.json()
        except ValueError:
            raise LokiUpstreamError(502, f"invalid JSON from upstream: {resp.text[:200]}")


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_singleton: Optional[LokiIntegrationEngine] = None


def get_loki_integration_engine() -> LokiIntegrationEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = LokiIntegrationEngine()
    return _engine_singleton


__all__ = [
    "LokiIntegrationEngine",
    "LokiUnavailableError",
    "LokiUpstreamError",
    "get_loki_integration_engine",
]
