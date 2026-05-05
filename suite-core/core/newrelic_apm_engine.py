"""ALDECI New Relic APM engine — REAL httpx only, NO MOCKS, NO CACHE.

Wraps the New Relic v2 REST API (https://api.newrelic.com or
https://api.eu.newrelic.com) plus NerdGraph at /graphql.

Singleton keyed by env (NEWRELIC_API_KEY / NEWRELIC_ACCOUNT_ID /
NEWRELIC_REGION). When credentials are absent the capability summary
returns ``status="unavailable"`` and every lookup endpoint raises
``NewRelicAPMUnavailableError`` which the router translates to HTTP 503.

NO SQLite cache. NO mock fallback.

Singleton:
    eng = get_newrelic_apm_engine()

Reset (tests):
    reset_newrelic_apm_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


_VALID_REGIONS = {"US", "EU"}
DEFAULT_REGION = "US"
DEFAULT_TIMEOUT_SECONDS = 8.0


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


class NewRelicAPMUnavailableError(RuntimeError):
    """Raised when New Relic credentials are unset or the API rejected the call."""


class NewRelicAPMEngine:
    """Real httpx-backed New Relic APM client.

    All non-summary public methods raise ``NewRelicAPMUnavailableError``
    when ``NEWRELIC_API_KEY`` is not configured. Routers translate this
    to HTTP 503.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_account_id = account_id
        self._explicit_region = region

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ creds

    def _api_key(self) -> str:
        if self._explicit_api_key is not None:
            return self._explicit_api_key.strip()
        return (os.environ.get("NEWRELIC_API_KEY") or "").strip()

    def _account_id(self) -> str:
        if self._explicit_account_id is not None:
            return self._explicit_account_id.strip()
        return (os.environ.get("NEWRELIC_ACCOUNT_ID") or "").strip()

    def _region(self) -> str:
        raw = (
            self._explicit_region
            if self._explicit_region is not None
            else os.environ.get("NEWRELIC_REGION", "")
        )
        region = (raw or "").strip().upper() or DEFAULT_REGION
        if region not in _VALID_REGIONS:
            region = DEFAULT_REGION
        return region

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def account_id_present(self) -> bool:
        return bool(self._account_id())

    def is_configured(self) -> bool:
        return self.api_key_present()

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise NewRelicAPMUnavailableError(
                "NEWRELIC_API_KEY not set — set the env var to call New Relic APM"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _rest_headers(self) -> Dict[str, str]:
        # New Relic REST v2 uses X-Api-Key
        return {
            "X-Api-Key": self._api_key(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _graphql_headers(self) -> Dict[str, str]:
        # NerdGraph uses Api-Key
        return {
            "Api-Key": self._api_key(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _base_rest_url(self) -> str:
        if self._region() == "EU":
            return "https://api.eu.newrelic.com"
        return "https://api.newrelic.com"

    def _graphql_url(self) -> str:
        if self._region() == "EU":
            return "https://api.eu.newrelic.com/graphql"
        return "https://api.newrelic.com/graphql"

    # ---------------------------------------------------------------- request

    def _request_rest(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_rest_url()}{path}"
        try:
            if method == "GET":
                resp = client.get(url, headers=self._rest_headers(), params=params or None)
            elif method == "POST":
                resp = client.post(
                    url,
                    headers=self._rest_headers(),
                    json=json_body,
                    params=params or None,
                )
            else:
                raise NewRelicAPMUnavailableError(
                    f"Unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise NewRelicAPMUnavailableError(
                f"New Relic request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise NewRelicAPMUnavailableError(
                f"New Relic rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise NewRelicAPMUnavailableError(
                f"New Relic returned 404 for {path}"
            )
        if resp.status_code >= 400:
            raise NewRelicAPMUnavailableError(
                f"New Relic returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise NewRelicAPMUnavailableError(
                f"New Relic returned non-JSON response: {exc}"
            ) from exc
        return payload if isinstance(payload, dict) else {"data": payload}

    def _request_graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = self._graphql_url()
        body = {"query": query, "variables": variables or {}}
        try:
            resp = client.post(url, headers=self._graphql_headers(), json=body)
        except httpx.HTTPError as exc:
            raise NewRelicAPMUnavailableError(
                f"New Relic NerdGraph request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise NewRelicAPMUnavailableError(
                f"New Relic NerdGraph rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code >= 400:
            raise NewRelicAPMUnavailableError(
                f"New Relic NerdGraph returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise NewRelicAPMUnavailableError(
                f"New Relic NerdGraph returned non-JSON response: {exc}"
            ) from exc
        return payload if isinstance(payload, dict) else {"data": payload}

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "New Relic",
            "endpoints": [
                "/v2/applications.json",
                "/v2/applications/{id}.json",
                "/v2/alerts_incidents.json",
                "/v2/alerts_violations.json",
                "/graphql",
            ],
            "api_key_present": self.api_key_present(),
            "account_id_present": self.account_id_present(),
            "region": self._region(),
            "status": status,
        }

    # ------------------------------------------------------------- applications

    def list_applications(
        self,
        filter_name: Optional[str] = None,
        filter_language: Optional[str] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if filter_name:
            params["filter[name]"] = filter_name
        if filter_language:
            params["filter[language]"] = filter_language
        if page is not None:
            params["page"] = int(page)
        out = self._request_rest("GET", "/v2/applications.json", params=params)
        try:
            count = len(out.get("applications") or [])
            _emit_event(
                "newrelic_apm.applications_list",
                {"count": count, "region": self._region()},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def get_application(self, application_id: int | str) -> Dict[str, Any]:
        if not str(application_id):
            raise ValueError("application_id must not be empty")
        return self._request_rest(
            "GET", f"/v2/applications/{application_id}.json"
        )

    # ----------------------------------------------------------------- alerts

    def list_incidents(
        self,
        only_open: bool = True,
        exclude_violations: bool = False,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "only_open": "true" if only_open else "false",
            "exclude_violations": "true" if exclude_violations else "false",
        }
        return self._request_rest(
            "GET", "/v2/alerts_incidents.json", params=params
        )

    def list_violations(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        only_open: bool = True,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "only_open": "true" if only_open else "false",
        }
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        return self._request_rest(
            "GET", "/v2/alerts_violations.json", params=params
        )

    # --------------------------------------------------------------- nerdgraph

    def graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not query or not isinstance(query, str):
            raise ValueError("graphql query must be a non-empty string")
        return self._request_graphql(query, variables=variables)

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

_singleton: Optional[NewRelicAPMEngine] = None
_singleton_lock = threading.RLock()


def get_newrelic_apm_engine(
    api_key: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> NewRelicAPMEngine:
    """Return the process-wide NewRelicAPMEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (api_key, account_id, region, client)
        ):
            if _singleton is not None:
                _singleton.close()
            _singleton = NewRelicAPMEngine(
                api_key=api_key,
                account_id=account_id,
                region=region,
                client=client,
            )
        return _singleton


def reset_newrelic_apm_engine() -> None:
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
    "NewRelicAPMEngine",
    "NewRelicAPMUnavailableError",
    "get_newrelic_apm_engine",
    "reset_newrelic_apm_engine",
]
