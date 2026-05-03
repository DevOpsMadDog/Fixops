"""
Akto API Security Engine — ALDECI.

Wraps Akto's REST surfaces (https://docs.akto.io/api-reference) for API
discovery, sensitive-data detection, vulnerability test results, runtime
issue triage, and on-demand test launches.

Endpoint coverage
-----------------
* GET  /api/discovered-apis          — inventory of discovered APIs
* GET  /api/sensitive-data           — sensitive-data findings per API
* GET  /api/test-results             — security test results
* GET  /api/runtime-issues           — runtime detected issues
* POST /api/start-test               — kick off a test run
* GET  /api/test-runs                — historical test-run summaries
* GET  /api/collections              — API collection list

Auth
----
Akto's REST API uses an opaque API token in the ``X-API-KEY`` header. We
read it from the env (``AKTO_API_TOKEN``) and the base URL from
``AKTO_BASE_URL`` (e.g. ``https://flash.akto.io``). Both are required.

Cache
-----
NO SQLite cache (per task spec). Every call hits Akto live.

NO MOCKS rule
-------------
* If either AKTO_BASE_URL or AKTO_API_TOKEN is unset:
    - All live endpoints raise ``AktoUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response originated from upstream Akto.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 12.0


class AktoUnavailableError(RuntimeError):
    """Raised when Akto creds/base URL are missing, network failed, or
    upstream returned an unrecoverable status."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AktoEngine:
    """Thread-safe Akto REST client (no cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_base_url = base_url
        self._explicit_api_token = api_token

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()

    # ----------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        return self._explicit_base_url or os.environ.get("AKTO_BASE_URL") or None

    def _api_token(self) -> Optional[str]:
        return self._explicit_api_token or os.environ.get("AKTO_API_TOKEN") or None

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def api_token_present(self) -> bool:
        return bool(self._api_token())

    def creds_complete(self) -> bool:
        return self.base_url_present() and self.api_token_present()

    # --------------------------------------------------------- request

    def _build_url(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> str:
        base = self._base_url()
        if not base:
            raise AktoUnavailableError("AKTO_BASE_URL is not configured")
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base}{path}"
        if params:
            qs = urlencode(
                [(k, v) for k, v in params.items() if v is not None and v != ""]
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    def _headers(self) -> Dict[str, str]:
        token = self._api_token()
        if not token:
            raise AktoUnavailableError("AKTO_API_TOKEN is not configured")
        return {
            "Accept": "application/json",
            "X-API-KEY": token,
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
            missing: List[str] = []
            if not self.base_url_present():
                missing.append("AKTO_BASE_URL")
            if not self.api_token_present():
                missing.append("AKTO_API_TOKEN")
            raise AktoUnavailableError(
                "Akto credentials missing: " + ",".join(missing)
            )
        url = self._build_url(path, params=params)
        headers = self._headers()
        body_bytes: Optional[bytes] = None
        if json_body is not None:
            import json as _json

            body_bytes = _json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, content=body_bytes
                )
            else:
                raise AktoUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise AktoUnavailableError(
                f"Akto request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise AktoUnavailableError(
                f"Akto rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise AktoUnavailableError(
                f"Akto resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Akto validation error: {body}")
        if sc == 429:
            raise AktoUnavailableError(
                "Akto rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise AktoUnavailableError(
                f"Akto returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise AktoUnavailableError(
                f"Akto returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------------- API

    def discovered_apis(
        self,
        collection_id: Optional[int] = None,
        limit: int = 50,
        skip: int = 0,
        sort_field: Optional[str] = None,
        sort_order: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if skip < 0:
            raise ValueError("skip must be >= 0")
        if sort_order is not None and sort_order.lower() not in ("asc", "desc"):
            raise ValueError("sortOrder must be asc or desc")
        params: Dict[str, Any] = {"limit": limit, "skip": skip}
        if collection_id is not None:
            params["collectionId"] = collection_id
        if sort_field:
            params["sortField"] = sort_field
        if sort_order:
            params["sortOrder"] = sort_order.lower()
        raw = self._request("GET", "/api/discovered-apis", params=params)
        return self._normalize_discovered_apis(raw)

    def sensitive_data(
        self,
        collection_id: Optional[int] = None,
        data_type: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if skip < 0:
            raise ValueError("skip must be >= 0")
        params: Dict[str, Any] = {"limit": limit, "skip": skip}
        if collection_id is not None:
            params["collectionId"] = collection_id
        if data_type:
            params["dataType"] = data_type
        raw = self._request("GET", "/api/sensitive-data", params=params)
        return self._normalize_sensitive_data(raw)

    def test_results(
        self,
        test_run_id: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if skip < 0:
            raise ValueError("skip must be >= 0")
        params: Dict[str, Any] = {"limit": limit, "skip": skip}
        if test_run_id:
            params["testRunId"] = test_run_id
        raw = self._request("GET", "/api/test-results", params=params)
        return self._normalize_test_results(raw)

    def runtime_issues(
        self,
        start_timestamp: Optional[int] = None,
        end_timestamp: Optional[int] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if skip < 0:
            raise ValueError("skip must be >= 0")
        if severity is not None and severity.upper() not in (
            "HIGH",
            "MEDIUM",
            "LOW",
        ):
            raise ValueError("severity must be HIGH|MEDIUM|LOW")
        params: Dict[str, Any] = {"limit": limit, "skip": skip}
        if start_timestamp is not None:
            params["startTimestamp"] = start_timestamp
        if end_timestamp is not None:
            params["endTimestamp"] = end_timestamp
        if severity:
            params["severity"] = severity.upper()
        raw = self._request("GET", "/api/runtime-issues", params=params)
        return self._normalize_runtime_issues(raw)

    def start_test(
        self,
        collection_id: int,
        test_ids: List[str],
        test_run_time: int,
        test_run_hourly_schedule: Optional[int] = None,
        send_slack_alert: Optional[bool] = None,
        recurring_daily_option: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if collection_id is None or collection_id < 0:
            raise ValueError("collectionId must be >= 0")
        if not isinstance(test_ids, list) or not test_ids:
            raise ValueError("testIds must be a non-empty list")
        if test_run_time is None or test_run_time < 0:
            raise ValueError("testRunTime must be >= 0")
        body: Dict[str, Any] = {
            "collectionId": collection_id,
            "testIds": list(test_ids),
            "testRunTime": test_run_time,
        }
        if test_run_hourly_schedule is not None:
            body["testRunHourlySchedule"] = test_run_hourly_schedule
        if send_slack_alert is not None:
            body["sendSlackAlert"] = bool(send_slack_alert)
        if recurring_daily_option is not None:
            body["recurringDailyOption"] = bool(recurring_daily_option)
        raw = self._request("POST", "/api/start-test", json_body=body)
        return self._normalize_start_test(raw)

    def test_runs(
        self,
        limit: int = 50,
        skip: int = 0,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        if skip < 0:
            raise ValueError("skip must be >= 0")
        if state is not None and state.upper() not in (
            "RUNNING",
            "COMPLETED",
            "FAILED",
            "SCHEDULED",
            "CANCELED",
        ):
            raise ValueError(
                "state must be RUNNING|COMPLETED|FAILED|SCHEDULED|CANCELED"
            )
        params: Dict[str, Any] = {"limit": limit, "skip": skip}
        if state:
            params["state"] = state.upper()
        raw = self._request("GET", "/api/test-runs", params=params)
        return self._normalize_test_runs(raw)

    def collections(self) -> Dict[str, Any]:
        raw = self._request("GET", "/api/collections")
        return self._normalize_collections(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_discovered_apis(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("apiInfoList")
            if isinstance(raw.get("apiInfoList"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "apiCollectionId": entry.get("apiCollectionId") or 0,
                    "url": entry.get("url") or "",
                    "method": entry.get("method") or "GET",
                    "allAuthTypes": list(entry.get("allAuthTypes") or []),
                    "usersCount": entry.get("usersCount") or 0,
                    "lastSeen": entry.get("lastSeen") or 0,
                    "severityScore": entry.get("severityScore") or 0,
                    "totalRequests": entry.get("totalRequests") or 0,
                    "sensitiveDataDetected": bool(
                        entry.get("sensitiveDataDetected")
                    ),
                    "sensitiveDataTypes": list(
                        entry.get("sensitiveDataTypes") or []
                    ),
                    "discoveredTimestamp": entry.get("discoveredTimestamp") or 0,
                    "firstSeenTimestamp": entry.get("firstSeenTimestamp") or 0,
                    "hasTested": bool(entry.get("hasTested")),
                    "lastTestedTimestamp": entry.get("lastTestedTimestamp") or 0,
                    "openIssuesCount": entry.get("openIssuesCount") or 0,
                    "isCustomized": bool(entry.get("isCustomized")),
                    "hostName": entry.get("hostName") or "",
                    "environments": list(entry.get("environments") or []),
                }
            )
        return {
            "apiInfoList": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    @staticmethod
    def _normalize_sensitive_data(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("sensitiveDataList")
            if isinstance(raw.get("sensitiveDataList"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "apiCollectionId": entry.get("apiCollectionId") or 0,
                    "url": entry.get("url") or "",
                    "method": entry.get("method") or "GET",
                    "parameterName": entry.get("parameterName") or "",
                    "parameterLocation": entry.get("parameterLocation")
                    or "request_body",
                    "dataType": entry.get("dataType") or "",
                    "severity": entry.get("severity") or "INFO",
                    "count": entry.get("count") or 0,
                    "firstDetected": entry.get("firstDetected") or 0,
                    "lastDetected": entry.get("lastDetected") or 0,
                    "sampleValues": list(entry.get("sampleValues") or []),
                }
            )
        return {
            "sensitiveDataList": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    @staticmethod
    def _normalize_test_results(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("testResults")
            if isinstance(raw.get("testResults"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            api_info = (
                entry.get("apiInfoKey")
                if isinstance(entry.get("apiInfoKey"), dict)
                else {}
            )
            sub_results = (
                entry.get("testResults")
                if isinstance(entry.get("testResults"), list)
                else []
            )
            errors = entry.get("errors") if isinstance(entry.get("errors"), list) else []
            out.append(
                {
                    "testRunId": entry.get("testRunId") or "",
                    "testRunResultSummaryHexId": entry.get(
                        "testRunResultSummaryHexId"
                    )
                    or "",
                    "apiInfoKey": {
                        "apiCollectionId": api_info.get("apiCollectionId") or 0,
                        "url": api_info.get("url") or "",
                        "method": api_info.get("method") or "GET",
                    },
                    "testSubType": entry.get("testSubType") or "",
                    "vulnerable": bool(entry.get("vulnerable")),
                    "severity": entry.get("severity") or "LOW",
                    "errors": list(errors),
                    "testResults": [
                        {
                            "message": tr.get("message") or "",
                            "request": tr.get("request") or "",
                            "response": tr.get("response") or "",
                            "statusCode": tr.get("statusCode") or 0,
                        }
                        for tr in sub_results
                        if isinstance(tr, dict)
                    ],
                    "confidence": entry.get("confidence") or "LOW",
                    "startTimestamp": entry.get("startTimestamp") or 0,
                    "endTimestamp": entry.get("endTimestamp") or 0,
                }
            )
        return {
            "testResults": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    @staticmethod
    def _normalize_runtime_issues(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("issues") if isinstance(raw.get("issues"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or "",
                    "type": entry.get("type") or "",
                    "severity": entry.get("severity") or "LOW",
                    "title": entry.get("title") or "",
                    "description": entry.get("description") or "",
                    "firstDetected": entry.get("firstDetected") or 0,
                    "lastDetected": entry.get("lastDetected") or 0,
                    "status": entry.get("status") or "open",
                    "apiCollectionId": entry.get("apiCollectionId") or 0,
                    "urlPattern": entry.get("urlPattern") or "",
                    "method": entry.get("method") or "GET",
                    "evidenceCount": entry.get("evidenceCount") or 0,
                    "recommendedAction": entry.get("recommendedAction") or "",
                }
            )
        return {
            "issues": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    @staticmethod
    def _normalize_start_test(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "testRunId": raw.get("testRunId") or "",
            "status": raw.get("status") or "QUEUED",
            "scheduledAt": raw.get("scheduledAt") or 0,
        }

    @staticmethod
    def _normalize_test_runs(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("testingRuns")
            if isinstance(raw.get("testingRuns"), list)
            else raw.get("testRuns")
            if isinstance(raw.get("testRuns"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items or []:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "testRunId": entry.get("testRunId")
                    or entry.get("hexId")
                    or "",
                    "name": entry.get("name") or "",
                    "state": entry.get("state") or "SCHEDULED",
                    "scheduleTimestamp": entry.get("scheduleTimestamp") or 0,
                    "endTimestamp": entry.get("endTimestamp") or 0,
                    "testingRunConfigId": entry.get("testingRunConfigId") or 0,
                    "totalApis": entry.get("totalApis") or 0,
                    "vulnerableApis": entry.get("vulnerableApis") or 0,
                }
            )
        return {
            "testRuns": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    @staticmethod
    def _normalize_collections(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("apiCollections")
            if isinstance(raw.get("apiCollections"), list)
            else raw.get("collections")
            if isinstance(raw.get("collections"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items or []:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "hostName": entry.get("hostName") or "",
                    "type": entry.get("type") or "API_GROUP",
                    "urlsCount": entry.get("urlsCount") or 0,
                    "startTs": entry.get("startTs") or 0,
                }
            )
        return {
            "apiCollections": out,
            "totalCount": raw.get("totalCount") or len(out),
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[AktoEngine] = None
_singleton_lock = threading.Lock()


def get_akto_engine(
    base_url: Optional[str] = None,
    api_token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> AktoEngine:
    """Return the process-wide AktoEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AktoEngine(
                base_url=base_url,
                api_token=api_token,
                client=client,
            )
        return _singleton


def reset_akto_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "AktoEngine",
    "AktoUnavailableError",
    "get_akto_engine",
    "reset_akto_engine",
]
