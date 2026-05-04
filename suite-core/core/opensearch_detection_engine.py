"""OpenSearch Anomaly Detection Engine — ALDECI.

Wraps the OpenSearch Anomaly Detection plugin REST API
(https://opensearch.org/docs/latest/observing-your-data/ad/api/) and provides
a process-wide singleton bound to ``OPENSEARCH_URL`` (with optional
``OPENSEARCH_USERNAME`` / ``OPENSEARCH_PASSWORD`` basic auth credentials).

Endpoints exposed via the router (``/api/v1/opensearch``):

  * GET  /                               capability summary
  * GET  /detectors                      list all detectors
  * POST /detectors                      create detector
  * GET  /detectors/{id}                 single detector
  * POST /detectors/{id}/_start          start detection job
  * POST /detectors/{id}/_stop           stop detection job
  * GET  /detectors/{id}/results         anomaly results (window query)

NO MOCKS rule
-------------
When ``OPENSEARCH_URL`` is unset the engine remains constructible (so the
capability summary can render with ``status="unavailable"``), but every live
call raises :class:`OpenSearchUnavailableError` which the router translates
to HTTP 503. We never fabricate detectors, jobs, or anomaly results.

NO SQLite cache — every request hits the upstream OpenSearch cluster.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0
_AD_PREFIX = "/_plugins/_anomaly_detection/detectors"


class OpenSearchUnavailableError(RuntimeError):
    """Raised when OPENSEARCH_URL is unset or upstream returned an error."""


class OpenSearchDetectionEngine:
    """Thread-safe OpenSearch Anomaly Detection client (no local cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_ssl: bool = True,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_username = username
        self._explicit_password = password
        self._verify_ssl = verify_ssl
        self._timeout = timeout

        self._client = client or httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
        )
        self._owns_client = client is None
        self._lock = threading.RLock()

    # ------------------------------------------------------------ helpers

    def _base_url(self) -> Optional[str]:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("OPENSEARCH_URL")
        return v.rstrip("/") if v else None

    def _auth(self) -> Optional[Tuple[str, str]]:
        user = self._explicit_username or os.environ.get("OPENSEARCH_USERNAME")
        pwd = self._explicit_password or os.environ.get("OPENSEARCH_PASSWORD")
        if user and pwd:
            return (user, pwd)
        return None

    def url_present(self) -> bool:
        return bool(self._base_url())

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        base = self._base_url()
        if not base:
            raise OpenSearchUnavailableError(
                "OPENSEARCH_URL is not configured"
            )
        url = f"{base}{path}"
        try:
            resp = self._client.request(
                method.upper(),
                url,
                json=json_body,
                params=params,
                auth=self._auth(),
            )
        except httpx.HTTPError as exc:
            raise OpenSearchUnavailableError(
                f"OpenSearch request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise OpenSearchUnavailableError(
                f"OpenSearch rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise OpenSearchUnavailableError(
                "OpenSearch returned 404 — resource not found"
            )
        if resp.status_code >= 400:
            raise OpenSearchUnavailableError(
                f"OpenSearch returned HTTP {resp.status_code}: "
                f"{(resp.text or '')[:200]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise OpenSearchUnavailableError(
                f"OpenSearch returned non-JSON response: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise OpenSearchUnavailableError(
                "OpenSearch returned non-mapping response"
            )
        return data

    # ----------------------------------------------------------- detectors

    def list_detectors(self, size: int = 100) -> Dict[str, Any]:
        """Search for detectors via the AD plugin's match_all query."""
        body = {
            "query": {"match_all": {}},
            "size": max(1, min(size, 1000)),
        }
        raw = self._request("POST", f"{_AD_PREFIX}/_search", json_body=body)
        return self._normalize_detector_list(raw)

    def create_detector(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(body, dict) or not body:
            raise ValueError("body must be a non-empty mapping")
        if not body.get("name"):
            raise ValueError("name is required")
        if not body.get("indices"):
            raise ValueError("indices is required")
        raw = self._request("POST", _AD_PREFIX, json_body=body)
        detector_id = raw.get("_id")
        if _get_tg_bus and detector_id:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "asset.discovered",
                        {
                            "entity_id": detector_id,
                            "type": "opensearch_anomaly_detector",
                            "severity": "info",
                            "source_engine": "opensearch_detection",
                            "name": body.get("name"),
                            "indices": body.get("indices"),
                        },
                    )
            except Exception:
                pass
        return {
            "detector_id": detector_id,
            "version": raw.get("_version"),
            "result": raw.get("anomaly_detector") or {},
        }

    def get_detector(self, detector_id: str) -> Dict[str, Any]:
        if not detector_id:
            raise ValueError("detector_id must not be empty")
        raw = self._request("GET", f"{_AD_PREFIX}/{detector_id}")
        return self._normalize_detector(raw, detector_id=detector_id)

    def start_detector(self, detector_id: str) -> Dict[str, Any]:
        if not detector_id:
            raise ValueError("detector_id must not be empty")
        raw = self._request("POST", f"{_AD_PREFIX}/{detector_id}/_start")
        return {
            "detector_id": detector_id,
            "started": True,
            "result": raw,
        }

    def stop_detector(self, detector_id: str) -> Dict[str, Any]:
        if not detector_id:
            raise ValueError("detector_id must not be empty")
        raw = self._request("POST", f"{_AD_PREFIX}/{detector_id}/_stop")
        return {
            "detector_id": detector_id,
            "stopped": True,
            "result": raw,
        }

    def get_results(
        self,
        detector_id: str,
        start_time: Optional[int] = None,
        end_time: Optional[int] = None,
        size: int = 100,
    ) -> Dict[str, Any]:
        if not detector_id:
            raise ValueError("detector_id must not be empty")
        must: List[Dict[str, Any]] = [
            {"term": {"detector_id": detector_id}},
        ]
        if start_time is not None or end_time is not None:
            range_clause: Dict[str, Any] = {}
            if start_time is not None:
                range_clause["gte"] = int(start_time)
            if end_time is not None:
                range_clause["lte"] = int(end_time)
            must.append({"range": {"data_start_time": range_clause}})
        body = {
            "query": {"bool": {"must": must}},
            "size": max(1, min(size, 1000)),
            "sort": [{"data_start_time": {"order": "desc"}}],
        }
        raw = self._request("POST", f"{_AD_PREFIX}/results/_search", json_body=body)
        return self._normalize_results(raw, detector_id=detector_id)

    # ------------------------------------------------------------ normalize

    @staticmethod
    def _normalize_feature_attribute(entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "feature_name": entry.get("feature_name"),
            "feature_enabled": bool(entry.get("feature_enabled", True)),
            "aggregation_query": entry.get("aggregation_query") or {},
        }

    @staticmethod
    def _normalize_detector(
        raw: Dict[str, Any], *, detector_id: Optional[str] = None
    ) -> Dict[str, Any]:
        ad = raw.get("anomaly_detector") or {}
        out: Dict[str, Any] = {
            "detector_id": raw.get("_id") or detector_id,
            "name": ad.get("name"),
            "description": ad.get("description"),
            "time_field": ad.get("time_field"),
            "indices": list(ad.get("indices") or []),
            "feature_attributes": [
                OpenSearchDetectionEngine._normalize_feature_attribute(f)
                for f in (ad.get("feature_attributes") or [])
            ],
            "detection_interval": ad.get("detection_interval") or {},
            "window_delay": ad.get("window_delay") or {},
            "last_update_time": ad.get("last_update_time"),
        }
        return out

    @staticmethod
    def _normalize_detector_list(raw: Dict[str, Any]) -> Dict[str, Any]:
        hits = (raw.get("hits") or {}).get("hits") or []
        detectors: List[Dict[str, Any]] = []
        for hit in hits:
            ad = (hit.get("_source") or {})
            detectors.append({
                "detector_id": hit.get("_id"),
                "name": ad.get("name"),
                "description": ad.get("description"),
                "time_field": ad.get("time_field"),
                "indices": list(ad.get("indices") or []),
                "feature_attributes": [
                    OpenSearchDetectionEngine._normalize_feature_attribute(f)
                    for f in (ad.get("feature_attributes") or [])
                ],
                "detection_interval": ad.get("detection_interval") or {},
                "window_delay": ad.get("window_delay") or {},
            })
        total_obj = (raw.get("hits") or {}).get("total") or {}
        if isinstance(total_obj, dict):
            total = int(total_obj.get("value") or len(detectors))
        else:
            total = int(total_obj or len(detectors))
        return {"detectors": detectors, "totalDetectors": total}

    @staticmethod
    def _normalize_results(
        raw: Dict[str, Any], *, detector_id: str
    ) -> Dict[str, Any]:
        hits = (raw.get("hits") or {}).get("hits") or []
        results: List[Dict[str, Any]] = []
        for hit in hits:
            src = hit.get("_source") or {}
            results.append({
                "result_id": hit.get("_id"),
                "detector_id": src.get("detector_id") or detector_id,
                "data_start_time": src.get("data_start_time"),
                "data_end_time": src.get("data_end_time"),
                "anomaly_grade": src.get("anomaly_grade"),
                "confidence": src.get("confidence"),
                "feature_data": list(src.get("feature_data") or []),
            })
        total_obj = (raw.get("hits") or {}).get("total") or {}
        if isinstance(total_obj, dict):
            total = int(total_obj.get("value") or len(results))
        else:
            total = int(total_obj or len(results))
        return {
            "detector_id": detector_id,
            "results": results,
            "totalResults": total,
        }

    # ------------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[OpenSearchDetectionEngine] = None
_singleton_lock = threading.Lock()


def get_opensearch_detection_engine(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> OpenSearchDetectionEngine:
    """Return the process-wide OpenSearchDetectionEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = OpenSearchDetectionEngine(
                base_url=base_url,
                username=username,
                password=password,
                client=client,
            )
        return _singleton


def reset_opensearch_detection_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "OpenSearchDetectionEngine",
    "OpenSearchUnavailableError",
    "get_opensearch_detection_engine",
    "reset_opensearch_detection_engine",
]
