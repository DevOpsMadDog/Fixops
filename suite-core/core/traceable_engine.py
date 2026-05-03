"""Traceable AI Engine — ALDECI.

Wraps Traceable AI Platform REST API surface for runtime API security
discovery, sensitive-data classification, anomaly detection, attack
surfacing, user attribution, and policy testing.

Endpoint coverage
-----------------
* GET /api/v1/services
* GET /api/v1/apis
* GET /api/v1/apis/{api_id}
* GET /api/v1/anomalies
* GET /api/v1/threats
* GET /api/v1/users-and-attribution
* POST /api/v1/policies/test

Auth
----
``TRACEABLE_BASE_URL`` (e.g. ``https://api.traceable.ai``) +
``TRACEABLE_API_TOKEN`` are read from env. Calls send
``Authorization: Bearer {TRACEABLE_API_TOKEN}``.

Cache
-----
NO SQLite cache. Every call hits Traceable live.

NO MOCKS rule
-------------
* Missing creds -> ``TraceableUnavailableError`` (router translates to 503).
* Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Traceable.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0


class TraceableUnavailableError(RuntimeError):
    """Raised when creds are missing, network failed, or upstream returned an
    unrecoverable status."""


class TraceableEngine:
    """Thread-safe Traceable AI REST client (no cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_base_url = base_url
        self._explicit_api_token = api_token
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        return (
            self._explicit_base_url
            or os.environ.get("TRACEABLE_BASE_URL")
            or None
        )

    def _api_token(self) -> Optional[str]:
        return (
            self._explicit_api_token
            or os.environ.get("TRACEABLE_API_TOKEN")
            or None
        )

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def api_token_present(self) -> bool:
        return bool(self._api_token())

    def creds_complete(self) -> bool:
        return self.base_url_present() and self.api_token_present()

    # ----------------------------------------------------------- request

    def _build_url(self, path: str) -> str:
        base = self._base_url()
        if not base:
            raise TraceableUnavailableError("TRACEABLE_BASE_URL is not configured")
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        return f"{base}{path}"

    def _headers(self) -> Dict[str, str]:
        token = self._api_token()
        if not token:
            raise TraceableUnavailableError(
                "TRACEABLE_API_TOKEN is not configured"
            )
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not self.creds_complete():
            missing = []
            if not self.base_url_present():
                missing.append("TRACEABLE_BASE_URL")
            if not self.api_token_present():
                missing.append("TRACEABLE_API_TOKEN")
            raise TraceableUnavailableError(
                "Traceable AI credentials missing: " + ",".join(missing)
            )
        url = self._build_url(path)
        headers = self._headers()
        # Drop None/empty params for hygiene
        clean_params = None
        if params:
            clean_params = {
                k: v for k, v in params.items() if v is not None and v != ""
            }
            if not clean_params:
                clean_params = None
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=clean_params)
            elif method.upper() == "POST":
                headers["Content-Type"] = "application/json"
                resp = self._client.post(
                    url, headers=headers, params=clean_params, json=json_body or {}
                )
            else:
                raise TraceableUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise TraceableUnavailableError(
                f"Traceable request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise TraceableUnavailableError(
                f"Traceable rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise TraceableUnavailableError(
                f"Traceable resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Traceable validation error: {body}")
        if sc == 429:
            raise TraceableUnavailableError(
                "Traceable rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise TraceableUnavailableError(
                f"Traceable returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise TraceableUnavailableError(
                f"Traceable returned non-JSON response: {exc}"
            ) from exc

    # --------------------------------------------------------------- helpers

    @staticmethod
    def _pagination(raw: Dict[str, Any]) -> Dict[str, Any]:
        pag = raw.get("pagination") if isinstance(raw.get("pagination"), dict) else {}
        return {"nextPageToken": pag.get("nextPageToken") or ""}

    @staticmethod
    def _list_or_empty(value: Any) -> List[Any]:
        return list(value) if isinstance(value, list) else []

    # --------------------------------------------------------------- services

    def list_services(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        raw = self._request("GET", "/api/v1/services", params=params)
        return self._normalize_services(raw)

    @staticmethod
    def _normalize_services(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        services = TraceableEngine._list_or_empty(raw.get("services"))
        out: List[Dict[str, Any]] = []
        for entry in services:
            if not isinstance(entry, dict):
                continue
            tech = entry.get("technologyStack") if isinstance(entry.get("technologyStack"), dict) else {}
            out.append(
                {
                    "id": entry.get("id") or "",
                    "name": entry.get("name") or "",
                    "environment": entry.get("environment") or "",
                    "type": entry.get("type") or "HTTP",
                    "technologyStack": {
                        "language": tech.get("language") or "",
                        "framework": tech.get("framework") or "",
                    },
                    "totalRequests": entry.get("totalRequests") or 0,
                    "totalErrors": entry.get("totalErrors") or 0,
                    "errorRate": entry.get("errorRate") or 0.0,
                    "avgLatencyMs": entry.get("avgLatencyMs") or 0,
                    "p50": entry.get("p50") or 0,
                    "p95": entry.get("p95") or 0,
                    "p99": entry.get("p99") or 0,
                    "riskScore": entry.get("riskScore") or 0,
                    "sensitiveDataDetected": bool(entry.get("sensitiveDataDetected")),
                    "dataTypes": list(entry.get("dataTypes") or []),
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                }
            )
        return {"services": out, "pagination": TraceableEngine._pagination(raw)}

    # --------------------------------------------------------------- apis

    def list_apis(
        self,
        service_id: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        search_string: Optional[str] = None,
        sensitive_data_only: Optional[bool] = None,
        risk_score_gte: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if service_id:
            params["serviceId"] = service_id
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        if search_string:
            params["searchString"] = search_string
        if sensitive_data_only is not None:
            params["sensitiveDataOnly"] = (
                "true" if sensitive_data_only else "false"
            )
        if risk_score_gte is not None:
            params["riskScoreGte"] = risk_score_gte
        raw = self._request("GET", "/api/v1/apis", params=params)
        return self._normalize_apis(raw)

    def get_api(self, api_id: str) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        raw = self._request("GET", f"/api/v1/apis/{api_id}")
        return self._normalize_api(raw)

    @staticmethod
    def _normalize_one_api(entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            entry = {}
        owner = entry.get("owner") if isinstance(entry.get("owner"), dict) else {}
        schema = entry.get("schema") if isinstance(entry.get("schema"), dict) else {}
        sensitive = entry.get("sensitiveDataAccessed")
        sensitive_list: List[Dict[str, Any]] = []
        if isinstance(sensitive, list):
            for s in sensitive:
                if isinstance(s, dict):
                    sensitive_list.append(
                        {"type": s.get("type") or "", "count": s.get("count") or 0}
                    )
        return {
            "id": entry.get("id") or "",
            "name": entry.get("name") or "",
            "path": entry.get("path") or "",
            "method": entry.get("method") or "GET",
            "serviceId": entry.get("serviceId") or "",
            "serviceName": entry.get("serviceName") or "",
            "host": entry.get("host") or "",
            "port": entry.get("port") or 0,
            "protocol": entry.get("protocol") or "",
            "totalRequests": entry.get("totalRequests") or 0,
            "totalErrors": entry.get("totalErrors") or 0,
            "anomalyCount": entry.get("anomalyCount") or 0,
            "threatCount": entry.get("threatCount") or 0,
            "sensitiveDataAccessed": sensitive_list,
            "firstSeen": entry.get("firstSeen") or "",
            "lastSeen": entry.get("lastSeen") or "",
            "riskScore": entry.get("riskScore") or 0,
            "status": entry.get("status") or "active",
            "owner": {
                "name": owner.get("name") or "",
                "email": owner.get("email") or "",
                "team": owner.get("team") or "",
            },
            "classification": entry.get("classification") or "internal",
            "schema": {
                "requestParams": list(schema.get("requestParams") or []),
                "responseParams": list(schema.get("responseParams") or []),
            },
        }

    @staticmethod
    def _normalize_apis(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        apis = TraceableEngine._list_or_empty(raw.get("apis"))
        out = [TraceableEngine._normalize_one_api(a) for a in apis if isinstance(a, dict)]
        return {"apis": out, "pagination": TraceableEngine._pagination(raw)}

    @staticmethod
    def _normalize_api(raw: Dict[str, Any]) -> Dict[str, Any]:
        # Single-API endpoint may return either {"api": {...}} or the bare object
        if isinstance(raw, dict) and isinstance(raw.get("api"), dict):
            return {"api": TraceableEngine._normalize_one_api(raw["api"])}
        return {"api": TraceableEngine._normalize_one_api(raw)}

    # --------------------------------------------------------------- anomalies

    def list_anomalies(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        severity: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        service_id: Optional[str] = None,
        api_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        if severity:
            params["severity"] = severity
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        if service_id:
            params["serviceId"] = service_id
        if api_id:
            params["apiId"] = api_id
        raw = self._request("GET", "/api/v1/anomalies", params=params)
        return self._normalize_anomalies(raw)

    @staticmethod
    def _normalize_anomalies(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        anomalies = TraceableEngine._list_or_empty(raw.get("anomalies"))
        out: List[Dict[str, Any]] = []
        for entry in anomalies:
            if not isinstance(entry, dict):
                continue
            evidence = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
            out.append(
                {
                    "id": entry.get("id") or "",
                    "type": entry.get("type") or "",
                    "severity": entry.get("severity") or "low",
                    "title": entry.get("title") or "",
                    "description": entry.get("description") or "",
                    "serviceId": entry.get("serviceId") or "",
                    "apiId": entry.get("apiId") or "",
                    "startTime": entry.get("startTime") or "",
                    "endTime": entry.get("endTime") or "",
                    "evidence": dict(evidence),
                    "riskScore": entry.get("riskScore") or 0,
                }
            )
        return {"anomalies": out, "pagination": TraceableEngine._pagination(raw)}

    # --------------------------------------------------------------- threats

    def list_threats(
        self,
        threat_type: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if threat_type:
            params["type"] = threat_type
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        if severity:
            params["severity"] = severity
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        raw = self._request("GET", "/api/v1/threats", params=params)
        return self._normalize_threats(raw)

    @staticmethod
    def _normalize_threats(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        threats = TraceableEngine._list_or_empty(raw.get("threats"))
        out: List[Dict[str, Any]] = []
        for entry in threats:
            if not isinstance(entry, dict):
                continue
            target = entry.get("targetApi") if isinstance(entry.get("targetApi"), dict) else {}
            evidence_in = entry.get("evidence") if isinstance(entry.get("evidence"), list) else []
            evidence_out: List[Dict[str, Any]] = []
            for ev in evidence_in:
                if isinstance(ev, dict):
                    evidence_out.append(
                        {
                            "requestId": ev.get("requestId") or "",
                            "payload": ev.get("payload") or "",
                            "response": ev.get("response") or "",
                            "timestamp": ev.get("timestamp") or "",
                        }
                    )
            out.append(
                {
                    "id": entry.get("id") or "",
                    "name": entry.get("name") or "",
                    "type": entry.get("type") or "",
                    "severity": entry.get("severity") or "low",
                    "status": entry.get("status") or "active",
                    "attackerIp": entry.get("attackerIp") or "",
                    "attackerUserAgent": entry.get("attackerUserAgent") or "",
                    "attackerCountry": entry.get("attackerCountry") or "",
                    "targetApi": {
                        "id": target.get("id") or "",
                        "name": target.get("name") or "",
                    },
                    "evidence": evidence_out,
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                    "mitigationApplied": bool(entry.get("mitigationApplied")),
                    "mitigationDetails": entry.get("mitigationDetails") or "",
                    "attackVector": entry.get("attackVector") or "",
                    "owaspCategory": entry.get("owaspCategory") or "",
                    "cwe": entry.get("cwe") or "",
                }
            )
        return {"threats": out, "pagination": TraceableEngine._pagination(raw)}

    # --------------------------------------------------------------- users

    def list_users(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        page_size: Optional[int] = None,
        page_token: Optional[str] = None,
        search_user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if start_time:
            params["startTime"] = start_time
        if end_time:
            params["endTime"] = end_time
        if page_size:
            params["pageSize"] = page_size
        if page_token:
            params["pageToken"] = page_token
        if search_user_id:
            params["searchUserId"] = search_user_id
        raw = self._request("GET", "/api/v1/users-and-attribution", params=params)
        return self._normalize_users(raw)

    @staticmethod
    def _normalize_users(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        users = TraceableEngine._list_or_empty(raw.get("users"))
        out: List[Dict[str, Any]] = []
        for entry in users:
            if not isinstance(entry, dict):
                continue
            top_apis_in = entry.get("topApis") if isinstance(entry.get("topApis"), list) else []
            top_apis: List[Dict[str, Any]] = []
            for ta in top_apis_in:
                if isinstance(ta, dict):
                    top_apis.append(
                        {
                            "apiId": ta.get("apiId") or "",
                            "count": ta.get("count") or 0,
                        }
                    )
            out.append(
                {
                    "userId": entry.get("userId") or "",
                    "userType": entry.get("userType") or "UNKNOWN",
                    "totalRequests": entry.get("totalRequests") or 0,
                    "uniqueIps": entry.get("uniqueIps") or 0,
                    "geoCountries": list(entry.get("geoCountries") or []),
                    "topApis": top_apis,
                    "totalAnomalies": entry.get("totalAnomalies") or 0,
                    "totalThreats": entry.get("totalThreats") or 0,
                    "riskScore": entry.get("riskScore") or 0,
                    "firstSeen": entry.get("firstSeen") or "",
                    "lastSeen": entry.get("lastSeen") or "",
                }
            )
        return {"users": out, "pagination": TraceableEngine._pagination(raw)}

    # --------------------------------------------------------------- policies

    def test_policy(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(body, dict):
            raise ValueError("body must be a dict")
        if not body.get("policyId"):
            raise ValueError("policyId is required")
        if not isinstance(body.get("sampleRequest"), dict):
            raise ValueError("sampleRequest must be a dict")
        raw = self._request("POST", "/api/v1/policies/test", json_body=body)
        return self._normalize_policy_test(raw)

    @staticmethod
    def _normalize_policy_test(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        rule_results_in = (
            raw.get("ruleResults") if isinstance(raw.get("ruleResults"), list) else []
        )
        rule_results: List[Dict[str, Any]] = []
        for rr in rule_results_in:
            if isinstance(rr, dict):
                rule_results.append(dict(rr))
        return {
            "evaluationResult": raw.get("evaluationResult") or "monitor",
            "ruleResults": rule_results,
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[TraceableEngine] = None
_singleton_lock = threading.Lock()


def get_traceable_engine(
    base_url: Optional[str] = None,
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> TraceableEngine:
    """Return the process-wide TraceableEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = TraceableEngine(
                base_url=base_url,
                api_token=api_token,
                client=client,
            )
        return _singleton


def reset_traceable_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "TraceableEngine",
    "TraceableUnavailableError",
    "get_traceable_engine",
    "reset_traceable_engine",
]
