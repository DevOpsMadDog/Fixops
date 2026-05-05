"""ALDECI Datadog Cloud SIEM engine — REAL httpx only, NO MOCKS, NO CACHE.

Wraps the Datadog v2 REST API (https://api.{site}/api/v2). Singleton
keyed by env (DD_API_KEY / DD_APP_KEY / DD_SITE). When credentials are
absent the capability summary returns ``status="unavailable"`` and every
lookup endpoint raises ``DatadogSecurityUnavailableError`` which the
router translates to HTTP 503.

NO SQLite cache. NO mock fallback.

Singleton:
    eng = get_datadog_security_engine()

Reset (tests):
    reset_datadog_security_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# Datadog accepts these site shards
_VALID_SITES = {
    "datadoghq.com",
    "datadoghq.eu",
    "us3.datadoghq.com",
    "us5.datadoghq.com",
    "ddog-gov.com",
    "ap1.datadoghq.com",
}

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


class DatadogSecurityUnavailableError(RuntimeError):
    """Raised when Datadog credentials are unset or the API rejected the call."""


class DatadogSecurityEngine:
    """Real httpx-backed Datadog Cloud SIEM client.

    All public methods raise ``DatadogSecurityUnavailableError`` when
    DD_API_KEY/DD_APP_KEY are not configured. Routers translate this
    to HTTP 503.
    """

    DEFAULT_SITE = "datadoghq.com"

    def __init__(
        self,
        api_key: Optional[str] = None,
        app_key: Optional[str] = None,
        site: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_app_key = app_key
        self._explicit_site = site

        self._client: Optional[httpx.Client] = client
        self._owns_client: bool = client is None
        self._timeout: float = timeout

        self._lock = threading.RLock()

    # ------------------------------------------------------------------ creds

    def _api_key(self) -> str:
        if self._explicit_api_key is not None:
            return self._explicit_api_key.strip()
        return (os.environ.get("DD_API_KEY") or "").strip()

    def _app_key(self) -> str:
        if self._explicit_app_key is not None:
            return self._explicit_app_key.strip()
        return (os.environ.get("DD_APP_KEY") or "").strip()

    def _site(self) -> str:
        raw = (
            self._explicit_site
            if self._explicit_site is not None
            else os.environ.get("DD_SITE", "")
        )
        site = (raw or "").strip() or self.DEFAULT_SITE
        if site not in _VALID_SITES:
            # Don't raise — accept anything that looks like a Datadog host so
            # private deployments still work — but normalise stray protocol.
            site = site.replace("https://", "").replace("http://", "").rstrip("/")
        return site

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def app_key_present(self) -> bool:
        return bool(self._app_key())

    def is_configured(self) -> bool:
        return self.api_key_present() and self.app_key_present()

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise DatadogSecurityUnavailableError(
                "DD_API_KEY/DD_APP_KEY not set — set both env vars to call "
                "Datadog Cloud SIEM"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
            self._owns_client = True
        return self._client

    def _headers(self) -> Dict[str, str]:
        return {
            "DD-API-KEY": self._api_key(),
            "DD-APPLICATION-KEY": self._app_key(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _base_url(self) -> str:
        return f"https://api.{self._site()}"

    # ---------------------------------------------------------------- request

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._require_configured()
        client = self._ensure_client()
        url = f"{self._base_url()}{path}"
        try:
            if method == "GET":
                resp = client.get(url, headers=self._headers(), params=params or None)
            elif method == "POST":
                resp = client.post(
                    url,
                    headers=self._headers(),
                    json=json_body,
                    params=params or None,
                )
            else:
                raise DatadogSecurityUnavailableError(
                    f"Unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise DatadogSecurityUnavailableError(
                f"Datadog request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise DatadogSecurityUnavailableError(
                f"Datadog rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise DatadogSecurityUnavailableError(
                f"Datadog returned 404 for {path}"
            )
        if resp.status_code >= 400:
            raise DatadogSecurityUnavailableError(
                f"Datadog returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise DatadogSecurityUnavailableError(
                f"Datadog returned non-JSON response: {exc}"
            ) from exc
        return payload if isinstance(payload, dict) else {"data": payload}

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Datadog Cloud SIEM",
            "endpoints": [
                "/api/v2/security_monitoring/signals/search",
                "/api/v2/security_monitoring/rules",
                "/api/v2/security/cases",
                "/api/v2/security_monitoring/configuration/suppressions",
                "/api/v2/security_monitoring/notification_rules",
            ],
            "dd_api_key_present": self.api_key_present(),
            "dd_app_key_present": self.app_key_present(),
            "dd_site": self._site(),
            "status": status,
        }

    # ----------------------------------------------------------------- signals

    def search_signals(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """POST /api/v2/security_monitoring/signals/search."""
        out = self._request(
            "POST",
            "/api/v2/security_monitoring/signals/search",
            json_body=body or {},
        )
        try:
            data_count = len(out.get("data") or [])
            _emit_event(
                "datadog_security.signals_search",
                {"count": data_count, "site": self._site()},
            )
        except Exception:  # pragma: no cover
            pass
        return out

    # ------------------------------------------------------------------- rules

    def list_rules(
        self,
        page_size: Optional[int] = None,
        page_number: Optional[int] = None,
        filter_name: Optional[str] = None,
        filter_severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["page[size]"] = int(page_size)
        if page_number is not None:
            params["page[number]"] = int(page_number)
        if filter_name:
            params["filter[name]"] = filter_name
        if filter_severity:
            params["filter[severity]"] = filter_severity
        return self._request(
            "GET",
            "/api/v2/security_monitoring/rules",
            params=params,
        )

    def get_rule(self, rule_id: str) -> Dict[str, Any]:
        if not rule_id:
            raise ValueError("rule_id must not be empty")
        return self._request(
            "GET",
            f"/api/v2/security_monitoring/rules/{rule_id}",
        )

    # ------------------------------------------------------------------- cases

    def create_case(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/v2/security/cases",
            json_body=body or {},
        )

    def get_case(self, case_id: str) -> Dict[str, Any]:
        if not case_id:
            raise ValueError("case_id must not be empty")
        return self._request(
            "GET",
            f"/api/v2/security/cases/{case_id}",
        )

    # ----------------------------------------------------------- suppressions

    def list_suppressions(self) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/api/v2/security_monitoring/configuration/suppressions",
        )

    # ----------------------------------------------------------- notification

    def list_notification_rules(self) -> Dict[str, Any]:
        return self._request(
            "GET",
            "/api/v2/security_monitoring/notification_rules",
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

_singleton: Optional[DatadogSecurityEngine] = None
_singleton_lock = threading.RLock()


def get_datadog_security_engine(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None,
    site: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    force_refresh: bool = False,
) -> DatadogSecurityEngine:
    """Return the process-wide DatadogSecurityEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (api_key, app_key, site, client)
        ):
            if _singleton is not None:
                _singleton.close()
            _singleton = DatadogSecurityEngine(
                api_key=api_key,
                app_key=app_key,
                site=site,
                client=client,
            )
        return _singleton


def reset_datadog_security_engine() -> None:
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
    "DatadogSecurityEngine",
    "DatadogSecurityUnavailableError",
    "get_datadog_security_engine",
    "reset_datadog_security_engine",
]
