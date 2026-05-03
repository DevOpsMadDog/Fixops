"""ALDECI Drata Compliance Engine.

Thin pass-through client for the **Drata Public API** (https://public-api.drata.com),
providing direct compliance/audit-management workflows for ALDECI personas.

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env var is unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
DRATA_API_KEY  — Drata API token (sent as ``Authorization: Bearer <token>``)

The engine is a process-level singleton accessible via
:func:`get_drata_compliance_engine`.

This engine is intentionally minimal — Pydantic models live in the router; the
engine just shapes auth headers and returns parsed JSON / raises HTTP errors.
"""

from __future__ import annotations

import logging
import os
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_API_BASE = "https://public-api.drata.com"
_API_PATH = "/"

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/api/controls",
    "/api/controls/{id}/tests",
    "/api/integrations",
    "/api/audits",
    "/api/people",
    "/api/findings",
]


class DrataUnavailable(RuntimeError):
    """Raised when DRATA_API_KEY is not configured."""


class DrataHTTPError(RuntimeError):
    """Raised when Drata returns a non-2xx response."""

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


class DrataComplianceEngine:
    """Pass-through Drata client backed by ``httpx.Client``."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = _API_BASE,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._api_key = (api_key if api_key is not None else os.environ.get("DRATA_API_KEY", "")).strip()
        self._base_url = (base_url or _API_BASE).rstrip("/")
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def drata_api_key_present(self) -> bool:
        return bool(self._api_key)

    @property
    def configured(self) -> bool:
        return self.drata_api_key_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Drata",
            "endpoints": list(_ENDPOINT_CATALOG),
            "drata_api_key_present": self.drata_api_key_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise DrataUnavailable(
                "DRATA_API_KEY must be set to call Drata endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._base_url + _API_PATH
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        self._require_configured()
        url = self._url(path)
        try:
            resp = self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            logger.warning("drata upstream error %s %s: %s", method, path, type(exc).__name__)
            raise DrataHTTPError(502, f"Upstream Drata request failed: {type(exc).__name__}") from exc

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
        raise DrataHTTPError(resp.status_code, f"Drata returned {resp.status_code}", payload)

    # ------------------------------------------------------------------ ops

    @staticmethod
    def _build_params(**kwargs: Any) -> Dict[str, Any]:
        return {k: v for k, v in kwargs.items() if v is not None and v != ""}

    def list_controls(
        self,
        *,
        status: Optional[str] = None,
        framework: Optional[str] = None,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            status=status,
            framework=framework,
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/controls", params=params or None) or {}

    def get_control(self, control_id: str) -> Dict[str, Any]:
        return self._request("GET", f"api/controls/{control_id}") or {}

    def list_control_tests(
        self,
        control_id: str,
        *,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request(
            "GET",
            f"api/controls/{control_id}/tests",
            params=params or None,
        ) or {}

    def list_integrations(
        self,
        *,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/integrations", params=params or None) or {}

    def list_audits(
        self,
        *,
        status: Optional[str] = None,
        framework: Optional[str] = None,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            status=status,
            framework=framework,
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/audits", params=params or None) or {}

    def list_people(
        self,
        *,
        role: Optional[str] = None,
        status: Optional[str] = None,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            role=role,
            status=status,
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/people", params=params or None) or {}

    def list_findings(
        self,
        *,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            severity=severity,
            status=status,
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/findings", params=params or None) or {}

    def list_policies(
        self,
        *,
        published: Optional[bool] = None,
        page_size: Optional[int] = None,
        page_cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params = self._build_params(
            published=("true" if published is True else ("false" if published is False else None)),
            pageSize=page_size,
            pageCursor=page_cursor,
        )
        return self._request("GET", "api/policies", params=params or None) or {}

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

_engine: Optional[DrataComplianceEngine] = None
_engine_lock = Lock()


def get_drata_compliance_engine() -> DrataComplianceEngine:
    """Return (or create) the process-wide DrataComplianceEngine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = DrataComplianceEngine()
    return _engine


def reset_drata_compliance_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
