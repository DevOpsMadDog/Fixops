"""
Contrast Security RASP/IAST Engine — ALDECI.

Wraps Contrast Security's NG REST API (``/api/ng/{org}/...``):

  - GET /api/ng/{org}/applications
  - GET /api/ng/{org}/applications/{app_id}
  - GET /api/ng/{org}/traces/{app_id}/filter
  - GET /api/ng/{org}/traces/{org}/{trace_uuid}
  - GET /api/ng/{org}/protect/policies
  - GET /api/ng/{org}/servers
  - GET /api/ng/{org}/libraries

Auth
----
Contrast uses 4 header values combined per request:

    Authorization: <CONTRAST_AUTH_HEADER>   (already-base64 of "userid:service-key")
    API-Key:       <CONTRAST_API_KEY>

Plus configuration:
    CONTRAST_BASE_URL       — e.g. https://app.contrastsecurity.com/Contrast
    CONTRAST_SERVICE_KEY    — kept for completeness (some installs need it)

Cache
-----
NO SQLite cache. Every call hits Contrast live.

NO MOCKS rule
-------------
* If any of CONTRAST_BASE_URL / CONTRAST_API_KEY / CONTRAST_AUTH_HEADER /
  CONTRAST_SERVICE_KEY is unset:
    - All live endpoints raise ``ContrastUnavailableError`` (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Contrast.
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


class ContrastUnavailableError(RuntimeError):
    """Raised when Contrast creds are missing, network failed, or upstream
    returned an unrecoverable status."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ContrastEngine:
    """Thread-safe Contrast NG REST client (no cache)."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        auth_header: Optional[str] = None,
        service_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Explicit values win over env (re-read each call so tests can monkeypatch).
        self._explicit_base_url = base_url
        self._explicit_api_key = api_key
        self._explicit_auth_header = auth_header
        self._explicit_service_key = service_key

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- creds

    def _base_url(self) -> Optional[str]:
        return self._explicit_base_url or os.environ.get("CONTRAST_BASE_URL") or None

    def _api_key(self) -> Optional[str]:
        return self._explicit_api_key or os.environ.get("CONTRAST_API_KEY") or None

    def _auth_header(self) -> Optional[str]:
        return self._explicit_auth_header or os.environ.get("CONTRAST_AUTH_HEADER") or None

    def _service_key(self) -> Optional[str]:
        return self._explicit_service_key or os.environ.get("CONTRAST_SERVICE_KEY") or None

    def base_url_present(self) -> bool:
        return bool(self._base_url())

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def auth_header_present(self) -> bool:
        return bool(self._auth_header())

    def service_key_present(self) -> bool:
        return bool(self._service_key())

    def creds_complete(self) -> bool:
        return (
            self.base_url_present()
            and self.api_key_present()
            and self.auth_header_present()
            and self.service_key_present()
        )

    # --------------------------------------------------------- request

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        base = self._base_url()
        if not base:
            raise ContrastUnavailableError("CONTRAST_BASE_URL is not configured")
        base = base.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        url = f"{base}{path}"
        if params:
            qs = urlencode(
                [
                    (k, v)
                    for k, v in params.items()
                    if v is not None and v != ""
                ],
                doseq=True,
            )
            if qs:
                url = f"{url}?{qs}"
        return url

    def _check_creds(self) -> None:
        if not self.creds_complete():
            missing: List[str] = []
            if not self.base_url_present():
                missing.append("CONTRAST_BASE_URL")
            if not self.api_key_present():
                missing.append("CONTRAST_API_KEY")
            if not self.auth_header_present():
                missing.append("CONTRAST_AUTH_HEADER")
            if not self.service_key_present():
                missing.append("CONTRAST_SERVICE_KEY")
            raise ContrastUnavailableError(
                "Contrast credentials missing: " + ",".join(missing)
            )

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": str(self._auth_header() or ""),
            "API-Key": str(self._api_key() or ""),
            "Accept": "application/json",
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._check_creds()
        url = self._build_url(path, params=params)
        headers = self._headers()
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers)
            else:
                raise ContrastUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise ContrastUnavailableError(
                f"Contrast request failed: {exc}"
            ) from exc

        sc = getattr(resp, "status_code", 0)
        if sc in (401, 403):
            raise ContrastUnavailableError(
                f"Contrast rejected credentials (HTTP {sc})"
            )
        if sc == 404:
            raise ContrastUnavailableError(
                f"Contrast resource not found (HTTP 404): {path}"
            )
        if sc == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": getattr(resp, "text", "")[:200]}
            raise ValueError(f"Contrast validation error: {body}")
        if sc == 429:
            raise ContrastUnavailableError(
                "Contrast rate-limit exceeded (HTTP 429)"
            )
        if sc >= 400:
            raise ContrastUnavailableError(
                f"Contrast returned HTTP {sc}: {getattr(resp, 'text', '')[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ContrastUnavailableError(
                f"Contrast returned non-JSON response: {exc}"
            ) from exc

    # ------------------------------------------------------ Applications

    def applications(
        self,
        org_id: str,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        filter_text: Optional[str] = None,
        filter_servers: Optional[str] = None,
        filter_tags: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        params: Dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if filter_text:
            params["filterText"] = filter_text
        if filter_servers:
            params["filterServers"] = filter_servers
        if filter_tags:
            params["filterTags"] = filter_tags
        raw = self._request(
            "GET",
            f"/api/ng/{org_id}/applications",
            params=params or None,
        )
        return self._normalize_applications(raw)

    def application(self, org_id: str, app_id: str) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        if not app_id:
            raise ValueError("app_id must not be empty")
        raw = self._request(
            "GET", f"/api/ng/{org_id}/applications/{app_id}"
        )
        return self._normalize_single_application(raw)

    # --------------------------------------------------------- Traces

    def traces_filter(
        self,
        org_id: str,
        app_id: str,
        *,
        severities: Optional[str] = None,
        statuses: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        if not app_id:
            raise ValueError("app_id must not be empty")
        params: Dict[str, Any] = {}
        if severities:
            params["severities"] = severities
        if statuses:
            params["quickFilter"] = statuses  # contrast NG name
            params["statuses"] = statuses
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        raw = self._request(
            "GET",
            f"/api/ng/{org_id}/traces/{app_id}/filter",
            params=params or None,
        )
        return self._normalize_traces(raw)

    def trace(self, org_id: str, trace_uuid: str) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        if not trace_uuid:
            raise ValueError("trace_uuid must not be empty")
        raw = self._request(
            "GET", f"/api/ng/{org_id}/traces/{trace_uuid}"
        )
        return self._normalize_single_trace(raw)

    # --------------------------------------------------- Protect policies

    def protect_policies(self, org_id: str) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        raw = self._request(
            "GET", f"/api/ng/{org_id}/protect/policies"
        )
        return self._normalize_policies(raw)

    # ------------------------------------------------------------ Servers

    def servers(
        self,
        org_id: str,
        *,
        expand: Optional[str] = None,
        q: Optional[str] = None,
        application_ids: Optional[str] = None,
        environment: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = expand
        if q:
            params["q"] = q
        if application_ids:
            params["applicationIds"] = application_ids
        if environment:
            params["environment"] = environment
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        raw = self._request(
            "GET",
            f"/api/ng/{org_id}/servers",
            params=params or None,
        )
        return self._normalize_servers(raw)

    # --------------------------------------------------------- Libraries

    def libraries(
        self,
        org_id: str,
        *,
        expand: Optional[str] = None,
        q: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        filter_score: Optional[str] = None,
        filter_language: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not org_id:
            raise ValueError("org_id must not be empty")
        params: Dict[str, Any] = {}
        if expand:
            params["expand"] = expand
        if q:
            params["q"] = q
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if filter_score:
            params["filterScore"] = filter_score
        if filter_language:
            params["filterLanguage"] = filter_language
        raw = self._request(
            "GET",
            f"/api/ng/{org_id}/libraries",
            params=params or None,
        )
        return self._normalize_libraries(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_applications(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = (
            raw.get("applications")
            if isinstance(raw.get("applications"), list)
            else []
        )
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            tags_raw = entry.get("tags")
            tags: List[str] = (
                [str(t) for t in tags_raw if t is not None]
                if isinstance(tags_raw, list)
                else []
            )
            out.append(
                {
                    "app_id": entry.get("app_id") or entry.get("appId") or entry.get("id") or "",
                    "name": entry.get("name") or "",
                    "status": entry.get("status") or "",
                    "language": entry.get("language") or "",
                    "license": entry.get("license") or "",
                    "last_seen": entry.get("last_seen") or entry.get("lastSeen") or "",
                    "importance": entry.get("importance") or "",
                    "tags": tags,
                    "assess": bool(entry.get("assess", False)),
                    "defend": bool(entry.get("defend", False)),
                }
            )
        facets = raw.get("facets") if isinstance(raw.get("facets"), dict) else {}
        return {
            "success": bool(raw.get("success", True)),
            "applications": out,
            "facets": facets,
        }

    @staticmethod
    def _normalize_single_application(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        app = raw.get("application") if isinstance(raw.get("application"), dict) else raw
        if not isinstance(app, dict):
            app = {}
        tags_raw = app.get("tags")
        tags: List[str] = (
            [str(t) for t in tags_raw if t is not None]
            if isinstance(tags_raw, list)
            else []
        )
        return {
            "success": bool(raw.get("success", True)),
            "application": {
                "app_id": app.get("app_id") or app.get("appId") or app.get("id") or "",
                "name": app.get("name") or "",
                "status": app.get("status") or "",
                "language": app.get("language") or "",
                "license": app.get("license") or "",
                "last_seen": app.get("last_seen") or app.get("lastSeen") or "",
                "importance": app.get("importance") or "",
                "tags": tags,
                "assess": bool(app.get("assess", False)),
                "defend": bool(app.get("defend", False)),
            },
        }

    @staticmethod
    def _normalize_traces(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("traces") if isinstance(raw.get("traces"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            req = entry.get("request") if isinstance(entry.get("request"), dict) else {}
            app = (
                entry.get("application")
                if isinstance(entry.get("application"), dict)
                else {}
            )
            tags_raw = entry.get("tags")
            tags: List[str] = (
                [str(t) for t in tags_raw if t is not None]
                if isinstance(tags_raw, list)
                else []
            )
            out.append(
                {
                    "uuid": entry.get("uuid") or "",
                    "request": {
                        "method": req.get("method") or "",
                        "uri": req.get("uri") or "",
                        "host": req.get("host") or "",
                    },
                    "rule_name": entry.get("rule_name")
                    or entry.get("ruleName")
                    or "",
                    "severity": entry.get("severity") or "",
                    "status": entry.get("status") or "",
                    "application": {
                        "app_id": app.get("app_id") or app.get("appId") or app.get("id") or "",
                        "name": app.get("name") or "",
                    },
                    "evidence": str(entry.get("evidence") or ""),
                    "tags": tags,
                    "first_time_seen": entry.get("first_time_seen")
                    or entry.get("firstTimeSeen")
                    or "",
                    "last_time_seen": entry.get("last_time_seen")
                    or entry.get("lastTimeSeen")
                    or "",
                }
            )
        facets = raw.get("facets") if isinstance(raw.get("facets"), dict) else {}
        return {
            "success": bool(raw.get("success", True)),
            "traces": out,
            "facets": facets,
            "count": int(raw.get("count") or len(out)),
        }

    @staticmethod
    def _normalize_single_trace(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        trace = raw.get("trace") if isinstance(raw.get("trace"), dict) else raw
        if not isinstance(trace, dict):
            trace = {}
        req = trace.get("request") if isinstance(trace.get("request"), dict) else {}
        app = (
            trace.get("application")
            if isinstance(trace.get("application"), dict)
            else {}
        )
        tags_raw = trace.get("tags")
        tags: List[str] = (
            [str(t) for t in tags_raw if t is not None]
            if isinstance(tags_raw, list)
            else []
        )
        return {
            "success": bool(raw.get("success", True)),
            "trace": {
                "uuid": trace.get("uuid") or "",
                "request": {
                    "method": req.get("method") or "",
                    "uri": req.get("uri") or "",
                    "host": req.get("host") or "",
                },
                "rule_name": trace.get("rule_name")
                or trace.get("ruleName")
                or "",
                "severity": trace.get("severity") or "",
                "status": trace.get("status") or "",
                "application": {
                    "app_id": app.get("app_id") or app.get("appId") or app.get("id") or "",
                    "name": app.get("name") or "",
                },
                "evidence": str(trace.get("evidence") or ""),
                "tags": tags,
                "first_time_seen": trace.get("first_time_seen")
                or trace.get("firstTimeSeen")
                or "",
                "last_time_seen": trace.get("last_time_seen")
                or trace.get("lastTimeSeen")
                or "",
            },
        }

    @staticmethod
    def _normalize_policies(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("policies") if isinstance(raw.get("policies"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "id": entry.get("id") or 0,
                    "name": entry.get("name") or "",
                    "mode": entry.get("mode") or "",
                    "applications": list(entry.get("applications") or []),
                    "rules": list(entry.get("rules") or []),
                }
            )
        return {
            "success": bool(raw.get("success", True)),
            "policies": out,
        }

    @staticmethod
    def _normalize_servers(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("servers") if isinstance(raw.get("servers"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            out.append(
                {
                    "server_id": entry.get("server_id")
                    or entry.get("serverId")
                    or entry.get("id")
                    or 0,
                    "name": entry.get("name") or "",
                    "hostname": entry.get("hostname") or "",
                    "environment": entry.get("environment") or "",
                    "language": entry.get("language") or "",
                    "container": entry.get("container") or "",
                    "last_activity": entry.get("last_activity")
                    or entry.get("lastActivity")
                    or "",
                    "status": entry.get("status") or "",
                    "applications": list(entry.get("applications") or []),
                    "assess": bool(entry.get("assess", False)),
                    "defend": bool(entry.get("defend", False)),
                }
            )
        return {
            "success": bool(raw.get("success", True)),
            "servers": out,
            "count": int(raw.get("count") or len(out)),
        }

    @staticmethod
    def _normalize_libraries(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        items = raw.get("libraries") if isinstance(raw.get("libraries"), list) else []
        out: List[Dict[str, Any]] = []
        for entry in items:
            if not isinstance(entry, dict):
                continue
            vulns_raw = entry.get("vulns") or entry.get("vulnerabilities")
            vulns: List[Dict[str, Any]] = []
            if isinstance(vulns_raw, list):
                for v in vulns_raw:
                    if not isinstance(v, dict):
                        continue
                    vulns.append(
                        {
                            "cve": v.get("cve") or v.get("name") or "",
                            "severity": v.get("severity") or "",
                            "title": v.get("title") or v.get("description") or "",
                            "cvss": v.get("cvss") or 0,
                        }
                    )
            out.append(
                {
                    "hash": entry.get("hash") or "",
                    "file_name": entry.get("file_name")
                    or entry.get("fileName")
                    or "",
                    "file_version": entry.get("file_version")
                    or entry.get("fileVersion")
                    or "",
                    "language": entry.get("language") or "",
                    "grade": entry.get("grade") or entry.get("score") or "",
                    "latest_version": entry.get("latest_version")
                    or entry.get("latestVersion")
                    or "",
                    "release_date": entry.get("release_date")
                    or entry.get("releaseDate")
                    or "",
                    "applications": list(entry.get("applications") or []),
                    "vulns": vulns,
                }
            )
        return {
            "success": bool(raw.get("success", True)),
            "libraries": out,
            "count": int(raw.get("count") or len(out)),
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ContrastEngine] = None
_singleton_lock = threading.Lock()


def get_contrast_engine(
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    auth_header: Optional[str] = None,
    service_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ContrastEngine:
    """Return the process-wide ContrastEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ContrastEngine(
                base_url=base_url,
                api_key=api_key,
                auth_header=auth_header,
                service_key=service_key,
                client=client,
            )
        return _singleton


def reset_contrast_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ContrastEngine",
    "ContrastUnavailableError",
    "get_contrast_engine",
    "reset_contrast_engine",
]
