"""
ThousandEyes Network Intelligence Engine — ALDECI.

Wraps the ThousandEyes v6 REST API (https://api.thousandeyes.com/v6) and
provides a process-wide singleton. NO sqlite cache (per task spec) — every
call hits upstream.

Endpoint coverage
-----------------
* /v6/tests.json                 (GET)  — list tests (optionally filtered by aid)
* /v6/tests/{test_id}.json       (GET)  — single test detail
* /v6/agents.json                (GET)  — agents list (enterprise/cloud/cluster)
* /v6/alerts.json                (GET)  — alerts within window
* /v6/web/page-load.json         (GET)  — page-load test results
* /v6/net/metrics.json           (GET)  — network-layer metrics
* /v6/dns/server-metrics.json    (GET)  — DNS server metrics
* /v6/bgp/metrics.json           (GET)  — BGP metrics

NO MOCKS rule
-------------
* THOUSANDEYES_API_TOKEN env unset:
    - All live endpoints raise ThousandEyesUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by ThousandEyes.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

THOUSANDEYES_API_BASE = "https://api.thousandeyes.com"
DEFAULT_TIMEOUT_SECONDS = 10.0


class ThousandEyesUnavailableError(RuntimeError):
    """Raised when ThousandEyes API token is missing, network failed, or
    upstream returned an unrecoverable status."""


class ThousandEyesEngine:
    """Thread-safe ThousandEyes v6 REST client. NO local cache."""

    def __init__(
        self,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit api_token wins over env (re-read each call so tests can monkeypatch).
        self._explicit_api_token = api_token

        # HTTP client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_token(self) -> Optional[str]:
        if self._explicit_api_token:
            return self._explicit_api_token
        v = os.environ.get("THOUSANDEYES_API_TOKEN")
        return v or None

    def api_token_present(self) -> bool:
        return bool(self._api_token())

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        api_token = self._api_token()
        if not api_token:
            raise ThousandEyesUnavailableError(
                "THOUSANDEYES_API_TOKEN is not configured"
            )
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Authorization": f"Bearer {api_token}",
        }
        url = f"{THOUSANDEYES_API_BASE}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            else:
                raise ThousandEyesUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise ThousandEyesUnavailableError(
                f"ThousandEyes request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise ThousandEyesUnavailableError(
                f"ThousandEyes rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise ThousandEyesUnavailableError(
                f"ThousandEyes returned HTTP 404 for {path}"
            )
        if resp.status_code == 429:
            raise ThousandEyesUnavailableError(
                "ThousandEyes rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code == 422 or resp.status_code == 400:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"ThousandEyes validation error: {body}")
        if resp.status_code >= 400:
            raise ThousandEyesUnavailableError(
                f"ThousandEyes returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ThousandEyesUnavailableError(
                f"ThousandEyes returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    @staticmethod
    def _common_params(aid: Optional[str], **extras: Any) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if aid:
            params["aid"] = aid
        for k, v in extras.items():
            if v is not None and v != "":
                params[k] = v
        return params

    def list_tests(self, aid: Optional[str] = None) -> Dict[str, Any]:
        """GET /v6/tests.json — list all tests for the optional account group."""
        raw = self._request(
            "GET",
            "/v6/tests.json",
            params=self._common_params(aid, format="json"),
        )
        if not isinstance(raw, dict):
            raw = {}
        tests = raw.get("test")
        if not isinstance(tests, list):
            tests = []
        return {"test": tests}

    def test_detail(
        self,
        test_id: str,
        aid: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/tests/{test_id}.json — single test detail."""
        if not test_id:
            raise ValueError("test_id must not be empty")
        raw = self._request(
            "GET",
            f"/v6/tests/{test_id}.json",
            params=self._common_params(aid, format="json"),
        )
        if not isinstance(raw, dict):
            raw = {}
        return raw

    def list_agents(
        self,
        aid: Optional[str] = None,
        agent_types: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/agents.json — agents list (enterprise|cloud|enterprise-cluster)."""
        if agent_types is not None:
            allowed = {"enterprise", "cloud", "enterprise-cluster"}
            for token in [t.strip() for t in agent_types.split(",") if t.strip()]:
                if token not in allowed:
                    raise ValueError(
                        f"agentTypes must be one of {sorted(allowed)} (got {token!r})"
                    )
        raw = self._request(
            "GET",
            "/v6/agents.json",
            params=self._common_params(aid, agentTypes=agent_types, format="json"),
        )
        if not isinstance(raw, dict):
            raw = {}
        agents = raw.get("agents")
        if not isinstance(agents, list):
            agents = []
        return {"agents": agents}

    def list_alerts(
        self,
        aid: Optional[str] = None,
        from_iso: Optional[str] = None,
        to_iso: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/alerts.json — alerts within a window."""
        raw = self._request(
            "GET",
            "/v6/alerts.json",
            params=self._common_params(
                aid, **{"from": from_iso, "to": to_iso, "format": "json"}
            ),
        )
        if not isinstance(raw, dict):
            raw = {}
        alerts = raw.get("alert")
        if not isinstance(alerts, list):
            alerts = []
        return {"alert": alerts}

    def web_page_load(
        self,
        test_id: str,
        aid: Optional[str] = None,
        from_iso: Optional[str] = None,
        to_iso: Optional[str] = None,
        window: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/web/page-load.json — page-load test results."""
        if not test_id:
            raise ValueError("testId must not be empty")
        raw = self._request(
            "GET",
            "/v6/web/page-load.json",
            params=self._common_params(
                aid,
                testId=test_id,
                **{"from": from_iso, "to": to_iso, "window": window, "format": "json"},
            ),
        )
        if not isinstance(raw, dict):
            raw = {}
        web = raw.get("web") if isinstance(raw.get("web"), dict) else {}
        page_load = web.get("pageLoad")
        if not isinstance(page_load, list):
            page_load = []
        return {"web": {"pageLoad": page_load}}

    def net_metrics(
        self,
        test_id: str,
        aid: Optional[str] = None,
        from_iso: Optional[str] = None,
        to_iso: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/net/metrics.json — network-layer metrics."""
        if not test_id:
            raise ValueError("testId must not be empty")
        raw = self._request(
            "GET",
            "/v6/net/metrics.json",
            params=self._common_params(
                aid,
                testId=test_id,
                **{"from": from_iso, "to": to_iso, "format": "json"},
            ),
        )
        if not isinstance(raw, dict):
            raw = {}
        net = raw.get("net") if isinstance(raw.get("net"), dict) else {}
        metrics = net.get("metrics")
        if not isinstance(metrics, list):
            metrics = []
        return {"net": {"metrics": metrics}}

    def dns_server_metrics(
        self,
        test_id: str,
        aid: Optional[str] = None,
        from_iso: Optional[str] = None,
        to_iso: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/dns/server-metrics.json — DNS server metrics."""
        if not test_id:
            raise ValueError("testId must not be empty")
        raw = self._request(
            "GET",
            "/v6/dns/server-metrics.json",
            params=self._common_params(
                aid,
                testId=test_id,
                **{"from": from_iso, "to": to_iso, "format": "json"},
            ),
        )
        if not isinstance(raw, dict):
            raw = {}
        return raw

    def bgp_metrics(
        self,
        test_id: str,
        aid: Optional[str] = None,
        from_iso: Optional[str] = None,
        to_iso: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v6/bgp/metrics.json — BGP metrics."""
        if not test_id:
            raise ValueError("testId must not be empty")
        raw = self._request(
            "GET",
            "/v6/bgp/metrics.json",
            params=self._common_params(
                aid,
                testId=test_id,
                **{"from": from_iso, "to": to_iso, "format": "json"},
            ),
        )
        if not isinstance(raw, dict):
            raw = {}
        return raw

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ThousandEyesEngine] = None
_singleton_lock = threading.Lock()


def get_thousandeyes_engine(
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ThousandEyesEngine:
    """Return the process-wide ThousandEyesEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ThousandEyesEngine(api_token=api_token, client=client)
        return _singleton


def reset_thousandeyes_engine() -> None:
    """Tear down the singleton — used by tests with stub httpx clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ThousandEyesEngine",
    "ThousandEyesUnavailableError",
    "get_thousandeyes_engine",
    "reset_thousandeyes_engine",
]
