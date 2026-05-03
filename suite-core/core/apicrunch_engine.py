"""
42Crunch API Security Engine — ALDECI.

Wraps the 42Crunch Platform REST API (https://platform.42crunch.com) and provides
a process-wide singleton. NO SQLite cache — scan/audit reports are large and
short-lived; we forward live to upstream every call.

Endpoint coverage (v2 surface)
------------------------------
* GET  /api/v2/collections                         — list collections (listOption / paging)
* GET  /api/v2/collections/{coll_id}               — single collection
* GET  /api/v2/collections/{coll_id}/apis          — list APIs in a collection
* GET  /api/v2/apis/{api_id}                       — single API descriptor
* GET  /api/v2/apis/{api_id}/auditReport           — audit report (FINDINGS|REPORT)
* POST /api/v2/apis/{api_id}/scan                  — trigger conformance scan
* GET  /api/v2/apis/{api_id}/scanReport            — latest scan report
* GET  /api/v2/apis/{api_id}/scanReport/{scan_id}  — specific scan report by id

Auth
----
``Authorization: Bearer {APICRUNCH_API_TOKEN}``  (env var APICRUNCH_API_TOKEN)
Optional override: APICRUNCH_BASE_URL.

NO MOCKS rule
-------------
* APICRUNCH_API_TOKEN env unset:
    - All live endpoints raise ApicrunchUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by 42Crunch.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://platform.42crunch.com"
DEFAULT_TIMEOUT_SECONDS = 12.0

ALLOWED_LIST_OPTIONS = {"ALL", "MINE", "SHARED", "PROVIDED"}
ALLOWED_REPORT_TYPES = {"FINDINGS", "REPORT"}
ALLOWED_SCOPES = {"READ_ONLY", "FULL_ACCESS", "EDIT"}
ALLOWED_SOURCES = {"DEFAULT", "API", "UI"}
ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class ApicrunchUnavailableError(RuntimeError):
    """Raised when APICRUNCH_API_TOKEN is missing, network failed, or
    upstream returned an unrecoverable status."""


class ApicrunchEngine:
    """Thread-safe 42Crunch REST client (no cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._explicit_base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("APICRUNCH_API_TOKEN")
        return v or None

    def _base_url(self) -> str:
        if self._explicit_base_url:
            return self._explicit_base_url.rstrip("/")
        v = os.environ.get("APICRUNCH_BASE_URL")
        return (v or DEFAULT_BASE_URL).rstrip("/")

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _headers(self) -> Dict[str, str]:
        api_key = self._api_key()
        if not api_key:
            raise ApicrunchUnavailableError(
                "APICRUNCH_API_TOKEN is not configured"
            )
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        headers = self._headers()
        url = f"{self._base_url()}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise ApicrunchUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise ApicrunchUnavailableError(
                f"42Crunch request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise ApicrunchUnavailableError(
                f"42Crunch rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise ApicrunchUnavailableError(
                f"42Crunch resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"42Crunch validation error: {body}")
        if resp.status_code == 429:
            raise ApicrunchUnavailableError(
                "42Crunch rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise ApicrunchUnavailableError(
                f"42Crunch returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ApicrunchUnavailableError(
                f"42Crunch returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- v2 calls

    def list_collections(
        self,
        *,
        list_option: str = "ALL",
        limit: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        if list_option not in ALLOWED_LIST_OPTIONS:
            raise ValueError(
                f"listOption must be one of {sorted(ALLOWED_LIST_OPTIONS)}"
            )
        params: Dict[str, Any] = {"listOption": list_option}
        if limit is not None:
            params["limit"] = int(limit)
        if page is not None:
            params["page"] = int(page)
        raw = self._request("GET", "/api/v2/collections", params=params)
        return self._normalize_collections(raw)

    def get_collection(self, coll_id: str) -> Dict[str, Any]:
        if not coll_id:
            raise ValueError("coll_id must not be empty")
        raw = self._request("GET", f"/api/v2/collections/{coll_id}")
        return self._normalize_collection_entry(raw)

    def list_collection_apis(
        self,
        coll_id: str,
        *,
        limit: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not coll_id:
            raise ValueError("coll_id must not be empty")
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = int(limit)
        if page is not None:
            params["page"] = int(page)
        raw = self._request(
            "GET",
            f"/api/v2/collections/{coll_id}/apis",
            params=params or None,
        )
        return self._normalize_apis_list(raw)

    def get_api(self, api_id: str) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        raw = self._request("GET", f"/api/v2/apis/{api_id}")
        return self._normalize_api_entry(raw)

    def get_audit_report(
        self,
        api_id: str,
        *,
        report_type: str = "REPORT",
    ) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        if report_type not in ALLOWED_REPORT_TYPES:
            raise ValueError(
                f"reportType must be one of {sorted(ALLOWED_REPORT_TYPES)}"
            )
        raw = self._request(
            "GET",
            f"/api/v2/apis/{api_id}/auditReport",
            params={"reportType": report_type},
        )
        return self._normalize_audit_report(raw)

    def trigger_scan(
        self,
        api_id: str,
        *,
        scan_configuration: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        body: Dict[str, Any] = {}
        if scan_configuration is not None:
            if not isinstance(scan_configuration, dict):
                raise ValueError("scanConfiguration must be a dict")
            body["scanConfiguration"] = scan_configuration
        raw = self._request(
            "POST",
            f"/api/v2/apis/{api_id}/scan",
            json_body=body,
        )
        return self._normalize_scan_trigger(raw)

    def get_scan_report(
        self,
        api_id: str,
        *,
        scan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not api_id:
            raise ValueError("api_id must not be empty")
        if scan_id:
            path = f"/api/v2/apis/{api_id}/scanReport/{scan_id}"
        else:
            path = f"/api/v2/apis/{api_id}/scanReport"
        raw = self._request("GET", path)
        return self._normalize_scan_report(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _owner(raw: Any) -> Dict[str, str]:
        if not isinstance(raw, dict):
            return {"id": "", "name": "", "email": ""}
        return {
            "id": str(raw.get("id") or ""),
            "name": str(raw.get("name") or ""),
            "email": str(raw.get("email") or ""),
        }

    @staticmethod
    def _coll_summary(raw: Any) -> Dict[str, int]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "apis": int(raw.get("apis") or 0),
            "requirements": int(raw.get("requirements") or 0),
        }

    @staticmethod
    def _api_summary(raw: Any) -> Dict[str, int]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "errors": int(raw.get("errors") or 0),
            "warnings": int(raw.get("warnings") or 0),
            "info": int(raw.get("info") or 0),
            "low": int(raw.get("low") or 0),
            "medium": int(raw.get("medium") or 0),
            "high": int(raw.get("high") or 0),
            "critical": int(raw.get("critical") or 0),
        }

    @staticmethod
    def _audit_block(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "score": float(raw.get("score") or 0.0),
            "latestAuditId": str(raw.get("latestAuditId") or ""),
            "latestAuditDate": str(raw.get("latestAuditDate") or ""),
            "lastAuditScore": float(raw.get("lastAuditScore") or 0.0),
        }

    @staticmethod
    def _scan_block(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "conformanceScore": float(raw.get("conformanceScore") or 0.0),
            "latestScanId": str(raw.get("latestScanId") or ""),
            "latestScanDate": str(raw.get("latestScanDate") or ""),
        }

    @classmethod
    def _normalize_collection_entry(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        desc_in = raw.get("desc") if isinstance(raw.get("desc"), dict) else raw
        sharing_in = raw.get("sharing") if isinstance(raw.get("sharing"), dict) else {}
        groups_in = (
            sharing_in.get("groups")
            if isinstance(sharing_in.get("groups"), list)
            else []
        )
        users_in = (
            sharing_in.get("users")
            if isinstance(sharing_in.get("users"), list)
            else []
        )
        groups_out: List[Dict[str, str]] = []
        for g in groups_in:
            if not isinstance(g, dict):
                continue
            scope = str(g.get("scope") or "")
            groups_out.append(
                {
                    "group_id": str(g.get("group_id") or g.get("id") or ""),
                    "name": str(g.get("name") or ""),
                    "scope": scope if scope in ALLOWED_SCOPES else "",
                }
            )
        users_out: List[Dict[str, str]] = []
        for u in users_in:
            if not isinstance(u, dict):
                continue
            scope = str(u.get("scope") or "")
            users_out.append(
                {
                    "user_id": str(u.get("user_id") or u.get("id") or ""),
                    "scope": scope if scope in ALLOWED_SCOPES else "",
                }
            )
        source = str(desc_in.get("source") or "")
        return {
            "desc": {
                "id": str(desc_in.get("id") or ""),
                "name": str(desc_in.get("name") or ""),
                "description": str(desc_in.get("description") or ""),
                "source": source if source in ALLOWED_SOURCES else "",
                "owner": cls._owner(desc_in.get("owner")),
                "source_id": str(desc_in.get("source_id") or ""),
                "source_name": str(desc_in.get("source_name") or ""),
                "summary": cls._coll_summary(desc_in.get("summary")),
            },
            "sharing": {"groups": groups_out, "users": users_out},
            "write": bool(raw.get("write", False)),
            "read": bool(raw.get("read", False)),
            "requirements": list(raw.get("requirements") or []),
        }

    @classmethod
    def _normalize_collections(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("list") if isinstance(raw.get("list"), list) else []
        out_list = [cls._normalize_collection_entry(i) for i in items]
        return {
            "list": out_list,
            "totalCount": int(raw.get("totalCount") or len(out_list)),
        }

    @classmethod
    def _normalize_api_entry(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        desc_in = raw.get("desc") if isinstance(raw.get("desc"), dict) else raw
        return {
            "desc": {
                "id": str(desc_in.get("id") or ""),
                "name": str(desc_in.get("name") or ""),
                "cid": str(desc_in.get("cid") or ""),
                "technicalName": str(desc_in.get("technicalName") or ""),
                "description": str(desc_in.get("description") or ""),
                "owner": cls._owner(desc_in.get("owner")),
                "summary": cls._api_summary(desc_in.get("summary")),
                "score": float(desc_in.get("score") or 0.0),
                "audit": cls._audit_block(desc_in.get("audit")),
                "scan": cls._scan_block(desc_in.get("scan")),
            }
        }

    @classmethod
    def _normalize_apis_list(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("list") if isinstance(raw.get("list"), list) else []
        out_list: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            entry = cls._normalize_api_entry(item)
            entry["write"] = bool(item.get("write", False))
            entry["read"] = bool(item.get("read", False))
            # Drop scan block per spec for the collection-apis listing
            entry["desc"].pop("scan", None)
            out_list.append(entry)
        return {
            "list": out_list,
            "totalCount": int(raw.get("totalCount") or len(out_list)),
        }

    @classmethod
    def _normalize_finding_bucket(cls, raw: Any) -> List[Dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        out: List[Dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            sev = str(item.get("severity") or "")
            out.append(
                {
                    "id": str(item.get("id") or ""),
                    "severity": sev if sev in ALLOWED_SEVERITIES else "",
                    "code": str(item.get("code") or ""),
                    "message": str(item.get("message") or ""),
                    "pointer": str(item.get("pointer") or ""),
                    "requirementId": str(item.get("requirementId") or ""),
                    "severityRationale": str(item.get("severityRationale") or ""),
                }
            )
        return out

    @classmethod
    def _normalize_audit_report(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        report = data.get("report") if isinstance(data.get("report"), dict) else data
        summary = (
            report.get("summary")
            if isinstance(report.get("summary"), dict)
            else {}
        )
        details = (
            summary.get("details")
            if isinstance(summary.get("details"), dict)
            else {}
        )
        scoring_rules = (
            summary.get("scoringRules")
            if isinstance(summary.get("scoringRules"), dict)
            else {}
        )
        return {
            "data": {
                "report": {
                    "summary": {
                        "score": float(summary.get("score") or 0.0),
                        "criticality": str(summary.get("criticality") or ""),
                        "errors": cls._normalize_finding_bucket(
                            summary.get("errors")
                        ),
                        "warnings": cls._normalize_finding_bucket(
                            summary.get("warnings")
                        ),
                        "info": cls._normalize_finding_bucket(
                            summary.get("info")
                        ),
                        "details": details,
                        "scoringRules": scoring_rules,
                    }
                }
            }
        }

    @staticmethod
    def _normalize_scan_trigger(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "scanId": str(raw.get("scanId") or raw.get("id") or ""),
            "status": str(raw.get("status") or "queued"),
        }

    @classmethod
    def _normalize_scan_path_finding(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        sev = str(raw.get("severity") or "")
        owasp = raw.get("owasp") if isinstance(raw.get("owasp"), list) else []
        request = raw.get("request") if isinstance(raw.get("request"), dict) else {}
        response = raw.get("response") if isinstance(raw.get("response"), dict) else {}
        return {
            "type": str(raw.get("type") or ""),
            "severity": sev if sev in ALLOWED_SEVERITIES else "",
            "status": str(raw.get("status") or ""),
            "message": str(raw.get("message") or ""),
            "request": request,
            "response": response,
            "cwe": str(raw.get("cwe") or ""),
            "owasp": [str(x) for x in owasp],
            "description": str(raw.get("description") or ""),
        }

    @classmethod
    def _normalize_scan_report(cls, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        paths_in = data.get("paths") if isinstance(data.get("paths"), list) else []
        paths_out: List[Dict[str, Any]] = []
        for p in paths_in:
            if not isinstance(p, dict):
                continue
            findings_in = (
                p.get("findings") if isinstance(p.get("findings"), list) else []
            )
            expectations_in = (
                p.get("expectations")
                if isinstance(p.get("expectations"), list)
                else []
            )
            paths_out.append(
                {
                    "path": str(p.get("path") or ""),
                    "method": str(p.get("method") or ""),
                    "statusCode": str(p.get("statusCode") or ""),
                    "expectations": list(expectations_in),
                    "findings": [
                        cls._normalize_scan_path_finding(f) for f in findings_in
                    ],
                }
            )
        return {
            "data": {
                "summary": {
                    "conformanceScore": float(
                        summary.get("conformanceScore") or 0.0
                    ),
                    "errors": int(summary.get("errors") or 0),
                    "warnings": int(summary.get("warnings") or 0),
                    "vulnerabilities": int(summary.get("vulnerabilities") or 0),
                    "executionTime": float(summary.get("executionTime") or 0.0),
                    "totalRequests": int(summary.get("totalRequests") or 0),
                    "totalIssues": int(summary.get("totalIssues") or 0),
                },
                "paths": paths_out,
            }
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ApicrunchEngine] = None
_singleton_lock = threading.Lock()


def get_apicrunch_engine(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ApicrunchEngine:
    """Return the process-wide ApicrunchEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ApicrunchEngine(
                api_key=api_key, base_url=base_url, client=client
            )
        return _singleton


def reset_apicrunch_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ApicrunchEngine",
    "ApicrunchUnavailableError",
    "ALLOWED_LIST_OPTIONS",
    "ALLOWED_REPORT_TYPES",
    "ALLOWED_SCOPES",
    "ALLOWED_SOURCES",
    "ALLOWED_SEVERITIES",
    "DEFAULT_BASE_URL",
    "get_apicrunch_engine",
    "reset_apicrunch_engine",
]
