"""Sumo Logic Cloud SIEM Engine — ALDECI.

Live Sumo Logic REST API client (search jobs, dashboards, collectors, sources,
Cloud SIEM insights, health events).

Reads SUMO_ACCESS_ID + SUMO_ACCESS_KEY + SUMO_ENDPOINT from env.
Default SUMO_ENDPOINT: https://api.us2.sumologic.com

NO SQLite cache, NO MOCKS. When env unset: status=unavailable, lookup
endpoints raise RuntimeError → mapped to 503 by router.

Auth: HTTP Basic with (SUMO_ACCESS_ID, SUMO_ACCESS_KEY) per Sumo Logic docs.

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

DEFAULT_SUMO_ENDPOINT = "https://api.us2.sumologic.com"


class SumoLogicSIEMEngine:
    """Live Sumo Logic Cloud SIEM client — wraps the Sumo Logic REST API.

    Endpoints implemented:
      * Search Job API:    /api/v1/search/jobs (+ /messages, /records, DELETE)
      * Dashboards API:    /api/v2/dashboards (paginated via token cursor)
      * Collectors API:    /api/v1/collectors  (offset/limit), /sources nested
      * Cloud SIEM API:    /api/sec/v1/insights
      * Monitors API:      /api/v1/healthEvents (cluster health)

    Auth (per docs):
      ``Authorization: Basic base64(<accessId>:<accessKey>)`` —
      we delegate the encoding to httpx via the ``auth`` kwarg.
    """

    def __init__(
        self,
        access_id: Optional[str] = None,
        access_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        self._access_id = access_id or os.environ.get("SUMO_ACCESS_ID", "")
        self._access_key = access_key or os.environ.get("SUMO_ACCESS_KEY", "")
        self._endpoint = (
            endpoint or os.environ.get("SUMO_ENDPOINT", DEFAULT_SUMO_ENDPOINT)
        ).rstrip("/")
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._lock = threading.RLock()
        self._client: Optional[httpx.Client] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def access_id_present(self) -> bool:
        return bool(self._access_id)

    @property
    def access_key_present(self) -> bool:
        return bool(self._access_key)

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def configured(self) -> bool:
        return self.access_id_present and self.access_key_present

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _client_inst(self) -> httpx.Client:
        if self._client is None:
            with self._lock:
                if self._client is None:
                    self._client = httpx.Client(
                        base_url=self._endpoint,
                        timeout=self._timeout,
                        verify=self._verify_tls,
                        auth=(self._access_id, self._access_key),
                        headers={
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                        },
                    )
        return self._client

    def _require_configured(self) -> None:
        if not self.configured:
            raise RuntimeError(
                "Sumo Logic not configured: SUMO_ACCESS_ID and "
                "SUMO_ACCESS_KEY must be set"
            )

    # ------------------------------------------------------------------
    # Capability summary
    # ------------------------------------------------------------------

    def capability_summary(self) -> Dict[str, Any]:
        status = "ok" if self.configured else "unavailable"
        return {
            "service": "Sumo Logic",
            "endpoints": [
                "/api/v1/search/jobs",
                "/api/v1/dashboards",
                "/api/v1/collectors",
                "/api/sec/v1/insights",
                "/api/v1/health-events",
            ],
            "sumo_access_id_present": self.access_id_present,
            "sumo_access_key_present": self.access_key_present,
            "sumo_endpoint": self._endpoint,
            "status": status,
        }

    # ------------------------------------------------------------------
    # Search Job API
    # ------------------------------------------------------------------

    def create_search_job(
        self,
        query: str,
        from_ts: str,
        to_ts: str,
        time_zone: str = "UTC",
        by_receipt_time: Optional[bool] = None,
        auto_parsing_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /api/v1/search/jobs — create a search job; returns ``{id, link}``."""
        self._require_configured()
        body: Dict[str, Any] = {
            "query": query,
            "from": from_ts,
            "to": to_ts,
            "timeZone": time_zone,
        }
        if by_receipt_time is not None:
            body["byReceiptTime"] = by_receipt_time
        if auto_parsing_mode is not None:
            body["autoParsingMode"] = auto_parsing_mode

        resp = self._client_inst().post("/api/v1/search/jobs", json=body)
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError:
            payload = {"raw": resp.text}
        result: Dict[str, Any] = {"id": payload.get("id")}
        if "link" in payload:
            result["link"] = payload["link"]
        return result

    def get_search_job(self, job_id: str) -> Dict[str, Any]:
        """GET /api/v1/search/jobs/{job_id} — returns state + counts."""
        self._require_configured()
        resp = self._client_inst().get(f"/api/v1/search/jobs/{job_id}")
        resp.raise_for_status()
        return resp.json()

    def get_search_job_messages(
        self,
        job_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """GET /api/v1/search/jobs/{job_id}/messages — raw message page."""
        self._require_configured()
        resp = self._client_inst().get(
            f"/api/v1/search/jobs/{job_id}/messages",
            params={"offset": offset, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()

    def get_search_job_records(
        self,
        job_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """GET /api/v1/search/jobs/{job_id}/records — aggregate records."""
        self._require_configured()
        resp = self._client_inst().get(
            f"/api/v1/search/jobs/{job_id}/records",
            params={"offset": offset, "limit": limit},
        )
        resp.raise_for_status()
        return resp.json()

    def delete_search_job(self, job_id: str) -> Dict[str, Any]:
        """DELETE /api/v1/search/jobs/{job_id} — cancel/delete a job."""
        self._require_configured()
        resp = self._client_inst().delete(f"/api/v1/search/jobs/{job_id}")
        resp.raise_for_status()
        return {"id": job_id, "cancelled": True}

    # ------------------------------------------------------------------
    # Dashboards API
    # ------------------------------------------------------------------

    def list_dashboards(
        self,
        limit: int = 100,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/v2/dashboards?limit=N&token=cursor — list dashboards.

        Returns ``{"dashboards":[...], "next": <cursor or None>}``.
        """
        self._require_configured()
        params: Dict[str, Any] = {"limit": limit}
        if token:
            params["token"] = token
        resp = self._client_inst().get("/api/v2/dashboards", params=params)
        resp.raise_for_status()
        payload = resp.json()
        # Normalize cursor key
        return {
            "dashboards": payload.get("data") or payload.get("dashboards") or [],
            "next": payload.get("next"),
        }

    # ------------------------------------------------------------------
    # Collectors + sources
    # ------------------------------------------------------------------

    def list_collectors(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """GET /api/v1/collectors — page of collectors."""
        self._require_configured()
        resp = self._client_inst().get(
            "/api/v1/collectors",
            params={"limit": limit, "offset": offset},
        )
        resp.raise_for_status()
        return resp.json()

    def list_collector_sources(self, collector_id: str) -> Dict[str, Any]:
        """GET /api/v1/collectors/{cid}/sources — nested sources."""
        self._require_configured()
        resp = self._client_inst().get(
            f"/api/v1/collectors/{collector_id}/sources"
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Cloud SIEM Insights
    # ------------------------------------------------------------------

    def list_insights(
        self,
        limit: int = 100,
        offset: int = 0,
        q: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/sec/v1/insights — Cloud SIEM detection insights."""
        self._require_configured()
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if q:
            params["q"] = q
        resp = self._client_inst().get("/api/sec/v1/insights", params=params)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Health events
    # ------------------------------------------------------------------

    def list_health_events(
        self,
        limit: int = 100,
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /api/v1/healthEvents — cluster/source health events."""
        self._require_configured()
        params: Dict[str, Any] = {"limit": limit}
        if token:
            params["token"] = token
        resp = self._client_inst().get("/api/v1/healthEvents", params=params)
        resp.raise_for_status()
        return resp.json()

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
_singleton: Optional[SumoLogicSIEMEngine] = None


def get_sumologic_siem_engine() -> SumoLogicSIEMEngine:
    """Return process-wide SumoLogicSIEMEngine singleton (reads env)."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SumoLogicSIEMEngine()
    return _singleton


def reset_sumologic_siem_engine() -> None:
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
    "SumoLogicSIEMEngine",
    "get_sumologic_siem_engine",
    "reset_sumologic_siem_engine",
    "DEFAULT_SUMO_ENDPOINT",
]
