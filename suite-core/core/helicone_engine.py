"""
Helicone LLM Observability Engine — ALDECI.

Wraps Helicone's REST/JAWS API surface for querying LLM request logs, custom
properties, user metrics, cost-by-time aggregates, datasets, and feedback. We
target the documented endpoints under ``https://api.helicone.ai`` (overridable
via ``HELICONE_BASE_URL`` for self-hosted deployments).

Endpoint coverage
-----------------
* POST /v1/request/query                           — list/filter request logs
* GET  /v1/property?propertyName=&offset=&limit=   — custom property values
* GET  /v1/user/metrics?userId=&startTime=&endTime= — per-user aggregates
* POST /v1/cost-by-time                             — cost timeseries
* GET  /v1/dataset                                  — dataset list
* POST /v1/feedback                                 — request feedback

Auth
----
Bearer token from ``HELICONE_API_KEY`` env var (sent as
``Authorization: Bearer {key}``). Optional ``HELICONE_BASE_URL`` overrides
the default ``https://api.helicone.ai`` host.

Cache
-----
NO SQLite cache. Every call hits Helicone live.

NO MOCKS rule
-------------
* If ``HELICONE_API_KEY`` is unset:
    - All live endpoints raise ``HeliconeUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Helicone.
"""

from __future__ import annotations

import json as _json
import logging
import os
import threading
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0
DEFAULT_BASE_URL = "https://api.helicone.ai"


class HeliconeUnavailableError(RuntimeError):
    """Raised when Helicone creds are missing, network failed, or upstream
    returned an unrecoverable status."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class HeliconeEngine:
    """Thread-safe Helicone REST client (no cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_api_key = api_key
        self._explicit_base_url = base_url

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ----------------------------------------------------------- creds

    def _api_key(self) -> Optional[str]:
        return self._explicit_api_key or os.environ.get("HELICONE_API_KEY") or None

    def _base_url(self) -> str:
        return (
            self._explicit_base_url
            or os.environ.get("HELICONE_BASE_URL")
            or DEFAULT_BASE_URL
        ).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def base_url(self) -> str:
        return self._base_url()

    # --------------------------------------------------------- request

    def _ensure_creds(self) -> str:
        key = self._api_key()
        if not key:
            raise HeliconeUnavailableError(
                "Helicone credentials missing: HELICONE_API_KEY"
            )
        return key

    def _build_url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self._base_url()}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        key = self._ensure_creds()
        url = self._build_url(path)
        headers: Dict[str, str] = {
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
        }
        body_bytes: Optional[bytes] = None
        if json_body is not None:
            body_bytes = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = self._client.post(url, headers=headers, content=body_bytes)
            elif method.upper() == "PUT":
                resp = self._client.put(url, headers=headers, content=body_bytes)
            else:
                raise HeliconeUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise HeliconeUnavailableError(
                f"Helicone request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise HeliconeUnavailableError(
                f"Helicone rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise HeliconeUnavailableError(
                f"Helicone resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Helicone validation error: {body}")
        if sc == 429:
            raise HeliconeUnavailableError(
                "Helicone rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise HeliconeUnavailableError(
                f"Helicone returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise HeliconeUnavailableError(
                f"Helicone returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------------- API

    def request_query(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /v1/request/query — list/filter request logs."""
        if not isinstance(payload, dict):
            raise ValueError("request_query payload must be a dict")
        return self._request("POST", "/v1/request/query", json_body=payload)

    def property_values(
        self,
        property_name: str,
        offset: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """GET /v1/property?propertyName=&offset=&limit=."""
        if not property_name:
            raise ValueError("propertyName must not be empty")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        if limit < 1 or limit > 10000:
            raise ValueError("limit must be in [1, 10000]")
        return self._request(
            "GET",
            "/v1/property",
            params={
                "propertyName": property_name,
                "offset": offset,
                "limit": limit,
            },
        )

    def user_metrics(
        self,
        user_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v1/user/metrics?userId=&startTime=&endTime=."""
        if not user_id:
            raise ValueError("userId must not be empty")
        params: Dict[str, Any] = {"userId": user_id}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        return self._request("GET", "/v1/user/metrics", params=params)

    def cost_by_time(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /v1/cost-by-time — cost timeseries aggregator."""
        if not isinstance(payload, dict):
            raise ValueError("cost_by_time payload must be a dict")
        timeframe = payload.get("timeframe") or {}
        if not (timeframe.get("start") and timeframe.get("end")):
            raise ValueError("timeframe.start and timeframe.end are required")
        increment = payload.get("dbIncrement", "day")
        if increment not in {"hour", "day", "week", "month"}:
            raise ValueError(
                "dbIncrement must be one of: hour, day, week, month"
            )
        return self._request("POST", "/v1/cost-by-time", json_body=payload)

    def dataset_list(self) -> Dict[str, Any]:
        """GET /v1/dataset — dataset list."""
        return self._request("GET", "/v1/dataset")

    def feedback(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /v1/feedback — attach feedback to a logged request."""
        if not isinstance(payload, dict):
            raise ValueError("feedback payload must be a dict")
        # Accept both "helicone-id" (per spec) and "helicone_id" (snake-case alias).
        hid = payload.get("helicone-id") or payload.get("helicone_id")
        if not hid:
            raise ValueError(
                "feedback payload must include 'helicone-id'"
            )
        if "rating" not in payload:
            raise ValueError("feedback payload must include 'rating' (bool)")
        if not isinstance(payload["rating"], bool):
            raise ValueError("feedback 'rating' must be a bool")
        # Normalise: ensure we always send the dashed key Helicone expects.
        normalised = dict(payload)
        normalised["helicone-id"] = hid
        normalised.pop("helicone_id", None)
        return self._request("POST", "/v1/feedback", json_body=normalised)

    # --------------------------------------------------------------- close

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[HeliconeEngine] = None
_singleton_lock = threading.Lock()


def get_helicone_engine(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> HeliconeEngine:
    """Return the process-wide HeliconeEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = HeliconeEngine(
                api_key=api_key,
                base_url=base_url,
                client=client,
            )
        return _singleton


def reset_helicone_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "HeliconeEngine",
    "HeliconeUnavailableError",
    "DEFAULT_BASE_URL",
    "get_helicone_engine",
    "reset_helicone_engine",
]
