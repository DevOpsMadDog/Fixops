"""Elastic Security Detection Engine — ALDECI.

Wraps the Elastic Security detection-engine REST API
(https://www.elastic.co/guide/en/security/current/security-apis.html) and
provides a process-wide singleton bound to ``ELASTIC_URL`` +
``ELASTIC_API_KEY`` (Authorization: ApiKey <key>, kbn-xsrf: true).

Endpoints exposed via the router (``/api/v1/elastic-security``):

  * GET  /                                 capability summary
  * GET  /api/detection_engine/rules       list detection rules
  * POST /api/detection_engine/signals/search  query alert signals via ES DSL
  * GET  /api/cases                        list cases (open/closed/in-progress)
  * GET  /api/exception_lists              detection-rule exception lists

NO MOCKS rule
-------------
When ``ELASTIC_URL`` or ``ELASTIC_API_KEY`` is unset the engine remains
constructible (so the capability summary can render with
``status="unavailable"``), but every live call raises
:class:`ElasticSecurityUnavailableError` which the router translates to
HTTP 503. We never fabricate rules, signals, cases, or exception lists.

NO SQLite cache — every request hits upstream Elastic.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 8.0


class ElasticSecurityUnavailableError(RuntimeError):
    """Raised when ELASTIC_URL/ELASTIC_API_KEY is unset or upstream errored."""


class ElasticSecurityEngine:
    """Thread-safe Elastic Security detection-engine client (no local cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_ssl: bool = True,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_api_key = api_key
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
        v = os.environ.get("ELASTIC_URL")
        return v.rstrip("/") if v else None

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        return os.environ.get("ELASTIC_API_KEY")

    def url_present(self) -> bool:
        return bool(self._base_url())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _headers(self) -> Dict[str, str]:
        key = self._api_key()
        if not key:
            raise ElasticSecurityUnavailableError(
                "ELASTIC_API_KEY is not configured"
            )
        return {
            "Authorization": f"ApiKey {key}",
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

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
            raise ElasticSecurityUnavailableError(
                "ELASTIC_URL is not configured"
            )
        headers = self._headers()
        url = f"{base}{path}"
        try:
            resp = self._client.request(
                method.upper(),
                url,
                json=json_body,
                params=params,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise ElasticSecurityUnavailableError(
                f"Elastic Security request failed: {exc}"
            ) from exc

        if resp.status_code in (401, 403):
            raise ElasticSecurityUnavailableError(
                f"Elastic Security rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise ElasticSecurityUnavailableError(
                "Elastic Security returned 404 — resource not found"
            )
        if resp.status_code >= 400:
            raise ElasticSecurityUnavailableError(
                f"Elastic Security returned HTTP {resp.status_code}: "
                f"{(resp.text or '')[:200]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise ElasticSecurityUnavailableError(
                f"Elastic Security returned non-JSON response: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ElasticSecurityUnavailableError(
                "Elastic Security returned non-mapping response"
            )
        return data

    # ----------------------------------------------------------- rules

    def list_rules(self, per_page: int = 25, page: int = 1) -> Dict[str, Any]:
        per_page = max(1, min(int(per_page), 1000))
        page = max(1, int(page))
        raw = self._request(
            "GET",
            "/api/detection_engine/rules/_find",
            params={"per_page": per_page, "page": page},
        )
        return self._normalize_rules(raw, per_page=per_page, page=page)

    # ----------------------------------------------------------- signals

    def search_signals(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(body, dict):
            raise ValueError("body must be a mapping")
        if "query" not in body:
            raise ValueError("body.query (Elasticsearch DSL) is required")
        raw = self._request(
            "POST",
            "/api/detection_engine/signals/search",
            json_body=body,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "threat.detected",
                        {
                            "entity_id": "elastic_security",
                            "type": "elastic_signals",
                            "source_engine": "elastic_security",
                            "hit_count": len((raw.get("hits") or {}).get("hits") or []),
                        },
                    )
            except Exception:
                pass
        return self._normalize_signals(raw)

    # ----------------------------------------------------------- cases

    def list_cases(
        self,
        per_page: int = 20,
        page: int = 1,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        per_page = max(1, min(int(per_page), 1000))
        page = max(1, int(page))
        params: Dict[str, Any] = {"perPage": per_page, "page": page}
        if status:
            allowed = {"open", "closed", "in-progress"}
            if status not in allowed:
                raise ValueError(
                    f"status must be one of {sorted(allowed)}, got {status!r}"
                )
            params["status"] = status
        raw = self._request("GET", "/api/cases/_find", params=params)
        return self._normalize_cases(raw, per_page=per_page, page=page)

    # ----------------------------------------------------------- exception lists

    def list_exception_lists(
        self,
        per_page: int = 20,
        page: int = 1,
    ) -> Dict[str, Any]:
        per_page = max(1, min(int(per_page), 1000))
        page = max(1, int(page))
        raw = self._request(
            "GET",
            "/api/exception_lists/_find",
            params={"per_page": per_page, "page": page},
        )
        return self._normalize_exception_lists(raw, per_page=per_page, page=page)

    # ------------------------------------------------------------ normalize

    @staticmethod
    def _normalize_rules(
        raw: Dict[str, Any], *, per_page: int, page: int
    ) -> Dict[str, Any]:
        items = raw.get("data") or raw.get("rules") or []
        rules: List[Dict[str, Any]] = []
        for r in items:
            if not isinstance(r, dict):
                continue
            rules.append({
                "id": r.get("id") or r.get("rule_id"),
                "name": r.get("name"),
                "description": r.get("description"),
                "severity": r.get("severity"),
                "risk_score": r.get("risk_score"),
                "type": r.get("type"),
                "language": r.get("language"),
                "query": r.get("query"),
                "enabled": bool(r.get("enabled", False)),
                "tags": list(r.get("tags") or []),
            })
        total = int(raw.get("total") or len(rules))
        return {
            "data": rules,
            "total": total,
            "perPage": int(raw.get("perPage") or per_page),
            "page": int(raw.get("page") or page),
        }

    @staticmethod
    def _normalize_signals(raw: Dict[str, Any]) -> Dict[str, Any]:
        hits_obj = raw.get("hits") or {}
        hit_list = hits_obj.get("hits") or []
        normalized_hits: List[Dict[str, Any]] = []
        for h in hit_list:
            if not isinstance(h, dict):
                continue
            src = h.get("_source") or {}
            normalized_hits.append({
                "_id": h.get("_id"),
                "_source": {
                    "rule_id": (src.get("kibana.alert.rule.uuid")
                                or src.get("rule_id")),
                    "rule_name": (src.get("kibana.alert.rule.name")
                                  or src.get("rule_name")),
                    "signal_status": (src.get("kibana.alert.workflow_status")
                                       or src.get("signal_status")),
                    "kibana_alert_severity": (src.get("kibana.alert.severity")
                                              or src.get("signal", {}).get("severity")
                                              if isinstance(src.get("signal"), dict)
                                              else src.get("kibana.alert.severity")),
                    "host": src.get("host"),
                    "user": src.get("user"),
                    "source_ip": (
                        (src.get("source") or {}).get("ip")
                        if isinstance(src.get("source"), dict)
                        else src.get("source_ip")
                    ),
                },
            })
        total_obj = hits_obj.get("total")
        if isinstance(total_obj, dict):
            total = int(total_obj.get("value") or len(normalized_hits))
        else:
            total = int(total_obj or len(normalized_hits))
        return {
            "took": int(raw.get("took") or 0),
            "hits": {
                "total": total,
                "hits": normalized_hits,
            },
        }

    @staticmethod
    def _normalize_cases(
        raw: Dict[str, Any], *, per_page: int, page: int
    ) -> Dict[str, Any]:
        items = raw.get("cases") or raw.get("data") or []
        cases: List[Dict[str, Any]] = []
        for c in items:
            if not isinstance(c, dict):
                continue
            cases.append({
                "id": c.get("id"),
                "title": c.get("title"),
                "description": c.get("description"),
                "status": c.get("status"),
                "severity": c.get("severity"),
                "owner": c.get("owner"),
                "tags": list(c.get("tags") or []),
                "totalAlerts": int(c.get("totalAlerts") or 0),
                "totalComments": int(c.get("totalComments") or 0),
            })
        return {
            "cases": cases,
            "total": int(raw.get("total") or len(cases)),
            "perPage": int(raw.get("perPage") or per_page),
            "page": int(raw.get("page") or page),
        }

    @staticmethod
    def _normalize_exception_lists(
        raw: Dict[str, Any], *, per_page: int, page: int
    ) -> Dict[str, Any]:
        items = raw.get("data") or raw.get("exception_lists") or []
        lists: List[Dict[str, Any]] = []
        for e in items:
            if not isinstance(e, dict):
                continue
            lists.append({
                "id": e.get("id"),
                "list_id": e.get("list_id"),
                "name": e.get("name"),
                "description": e.get("description"),
                "type": e.get("type"),
                "namespace_type": e.get("namespace_type"),
                "tags": list(e.get("tags") or []),
                "version": e.get("version"),
            })
        return {
            "data": lists,
            "total": int(raw.get("total") or len(lists)),
            "perPage": int(raw.get("perPage") or per_page),
            "page": int(raw.get("page") or page),
        }

    # ------------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ElasticSecurityEngine] = None
_singleton_lock = threading.Lock()


def get_elastic_security_engine(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ElasticSecurityEngine:
    """Return the process-wide ElasticSecurityEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ElasticSecurityEngine(
                base_url=base_url,
                api_key=api_key,
                client=client,
            )
        return _singleton


def reset_elastic_security_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ElasticSecurityEngine",
    "ElasticSecurityUnavailableError",
    "get_elastic_security_engine",
    "reset_elastic_security_engine",
]
