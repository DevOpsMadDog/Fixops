"""Splunk SIEM Engine — ALDECI.

Live Splunk REST API client (search jobs, saved searches, server info).

Reads SPLUNK_URL + SPLUNK_TOKEN from env. NO SQLite cache, NO MOCKS.
When env unset: status=unavailable, lookup endpoints raise.

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None


_logger = logging.getLogger(__name__)


class SplunkSIEMEngine:
    """Live Splunk SIEM client — wraps the Splunk REST API.

    Auth header (per Splunk docs): ``Authorization: Bearer <token>`` for
    tokens issued by Splunk Cloud / 8.0+; legacy/HEC fall back to
    ``Authorization: Splunk <token>``. We try Bearer first.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._url = (url or os.environ.get("SPLUNK_URL", "")).rstrip("/")
        self._token = token or os.environ.get("SPLUNK_TOKEN", "")
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def url_present(self) -> bool:
        return bool(self._url)

    @property
    def token_present(self) -> bool:
        return bool(self._token)

    @property
    def configured(self) -> bool:
        return self.url_present and self.token_present

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        # Splunk accepts both `Bearer` (Cloud / 8.0+) and `Splunk` schemes.
        # We send Bearer; callers that need legacy can override via env.
        scheme = os.environ.get("SPLUNK_AUTH_SCHEME", "Bearer")
        return {
            "Authorization": f"{scheme} {self._token}",
            "Accept": "application/json",
        }

    def _client_inst(self) -> httpx.Client:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = httpx.Client(
                        base_url=self._url,
                        timeout=self._timeout,
                        verify=self._verify_tls,
                        headers=self._headers(),
                    )
        return self._client

    def _require_configured(self) -> None:
        if not self.configured:
            raise RuntimeError(
                "Splunk not configured: SPLUNK_URL and SPLUNK_TOKEN must be set"
            )

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        if not self.configured:
            status = "unavailable"
        else:
            status = "ok"
        return {
            "service": "Splunk",
            "endpoints": [
                "/services/search/jobs",
                "/services/saved/searches",
                "/services/data/inputs",
                "/services/server/info",
            ],
            "splunk_url_present": self.url_present,
            "splunk_token_present": self.token_present,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Search jobs
    # ------------------------------------------------------------------

    def create_search_job(
        self,
        search: str,
        earliest_time: Optional[str] = None,
        latest_time: Optional[str] = None,
        exec_mode: str = "normal",
        output_mode: str = "json",
    ) -> Dict[str, Any]:
        """POST /services/search/jobs — returns {sid} or {sid, content} for oneshot."""
        self._require_configured()

        # Splunk requires the search SPL to be prefixed with `search ` if missing.
        spl = search if search.lstrip().lower().startswith(("search ", "|")) else f"search {search}"

        data: Dict[str, Any] = {
            "search": spl,
            "exec_mode": exec_mode,
            "output_mode": output_mode,
        }
        if earliest_time:
            data["earliest_time"] = earliest_time
        if latest_time:
            data["latest_time"] = latest_time

        resp = self._client_inst().post("/services/search/jobs", data=data)
        resp.raise_for_status()
        # Splunk returns either {"sid": "..."} (normal/blocking) or
        # {"results": [...], "fields": [...], "preview": false} (oneshot).
        try:
            payload = resp.json()
        except ValueError:
            payload = {"raw": resp.text}

        if exec_mode == "oneshot":
            return {"sid": None, "content": {"results": payload.get("results", [])}}
        sid = payload.get("sid") or payload.get("entry", [{}])[0].get("name", "")
        return {"sid": sid}

    def get_search_job(self, sid: str) -> Dict[str, Any]:
        """GET /services/search/jobs/{sid} — job metadata."""
        self._require_configured()
        resp = self._client_inst().get(
            f"/services/search/jobs/{sid}",
            params={"output_mode": "json"},
        )
        resp.raise_for_status()
        return resp.json()

    def get_search_job_results(
        self,
        sid: str,
        output_mode: str = "json",
        offset: int = 0,
        count: int = 100,
    ) -> Dict[str, Any]:
        """GET /services/search/jobs/{sid}/results — fetch results page."""
        self._require_configured()
        resp = self._client_inst().get(
            f"/services/search/jobs/{sid}/results",
            params={
                "output_mode": output_mode,
                "offset": offset,
                "count": count,
            },
        )
        resp.raise_for_status()
        if output_mode == "json":
            return resp.json()
        return {"raw": resp.text}

    def delete_search_job(self, sid: str) -> Dict[str, Any]:
        """DELETE /services/search/jobs/{sid}."""
        self._require_configured()
        resp = self._client_inst().delete(
            f"/services/search/jobs/{sid}",
            params={"output_mode": "json"},
        )
        resp.raise_for_status()
        return {"sid": sid, "cancelled": True}

    # ------------------------------------------------------------------
    # Saved searches
    # ------------------------------------------------------------------

    def list_saved_searches(self, count: int = 30) -> Dict[str, Any]:
        """GET /services/saved/searches?count=N."""
        self._require_configured()
        resp = self._client_inst().get(
            "/services/saved/searches",
            params={"output_mode": "json", "count": count},
        )
        resp.raise_for_status()
        return resp.json()

    def dispatch_saved_search(
        self,
        name: str,
        trigger_actions: int = 1,
    ) -> Dict[str, Any]:
        """POST /services/saved/searches/{name}/dispatch."""
        self._require_configured()
        resp = self._client_inst().post(
            f"/services/saved/searches/{name}/dispatch",
            data={"trigger_actions": trigger_actions, "output_mode": "json"},
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        sid = payload.get("sid") or payload.get("entry", [{}])[0].get("name", "")
        return {"sid": sid}

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


# ----------------------------------------------------------------------
# Singleton accessor
# ----------------------------------------------------------------------

_singleton_lock = threading.RLock()
_singleton: Optional[SplunkSIEMEngine] = None


def get_splunk_siem_engine() -> SplunkSIEMEngine:
    """Return process-wide SplunkSIEMEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SplunkSIEMEngine()
    return _singleton


def reset_splunk_siem_engine() -> None:
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
    "SplunkSIEMEngine",
    "get_splunk_siem_engine",
    "reset_splunk_siem_engine",
]
