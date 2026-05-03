"""
Snyk Vulnerability Engine — ALDECI.

Wraps the Snyk v1 REST API (https://snyk.io/api/v1) and provides a
process-wide singleton. NO SQLite cache — Snyk responses are large and
short-lived; we forward live to upstream every call.

Endpoint coverage
-----------------
* GET  /v1/orgs                                              — list organisations
* GET  /v1/orgs/{org_id}/projects                            — list projects (filters/names)
* POST /v1/test/{ecosystem}/{file_path}                      — manifest dependency test
* GET  /v1/orgs/{org_id}/projects/{project_id}/issues        — list issues for a project

Auth
----
``Authorization: token {SNYK_TOKEN}``  (env var SNYK_TOKEN)

NO MOCKS rule
-------------
* SNYK_TOKEN env unset:
    - All live endpoints raise SnykUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every response was actually returned by Snyk.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

SNYK_API_BASE = "https://snyk.io/api/v1"
DEFAULT_TIMEOUT_SECONDS = 12.0

ALLOWED_ECOSYSTEMS = {"npm", "maven", "pip", "gomodules", "composer", "gradle", "rubygems"}


class SnykUnavailableError(RuntimeError):
    """Raised when SNYK_TOKEN is missing, network failed, or upstream
    returned an unrecoverable status."""


class SnykVulnEngine:
    """Thread-safe Snyk REST client (no cache)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_api_key = api_key
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("SNYK_TOKEN")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def _headers(self) -> Dict[str, str]:
        api_key = self._api_key()
        if not api_key:
            raise SnykUnavailableError("SNYK_TOKEN is not configured")
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"token {api_key}",
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
        url = f"{SNYK_API_BASE}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = self._client.post(
                    url, headers=headers, params=params, json=json_body
                )
            else:
                raise SnykUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise SnykUnavailableError(
                f"Snyk request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise SnykUnavailableError(
                f"Snyk rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise SnykUnavailableError(
                f"Snyk resource not found: {path}"
            )
        if resp.status_code == 422:
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"Snyk validation error: {body}")
        if resp.status_code == 429:
            raise SnykUnavailableError(
                "Snyk rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise SnykUnavailableError(
                f"Snyk returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise SnykUnavailableError(
                f"Snyk returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- v1 calls

    def list_orgs(self) -> Dict[str, Any]:
        """GET /v1/orgs — list organisations."""
        raw = self._request("GET", "/orgs")
        return self._normalize_orgs(raw)

    def list_projects(
        self,
        org_id: str,
        *,
        filters: Optional[List[str]] = None,
        names: Optional[str] = None,
    ) -> Dict[str, Any]:
        """GET /v1/org/{org_id}/projects — list projects.

        Snyk's actual path is ``/org/{org_id}/projects`` (singular ``org``)
        even though the REST surface is ``/v1``."""
        if not org_id:
            raise ValueError("org_id must not be empty")
        params: Dict[str, Any] = {}
        if filters:
            # Snyk supports filters[] repeated query params; httpx handles list.
            params["filters[]"] = filters
        if names:
            params["names"] = names
        raw = self._request("GET", f"/org/{org_id}/projects", params=params or None)
        return self._normalize_projects(raw)

    def test_manifest(
        self,
        ecosystem: str,
        file_path: str,
        *,
        encoding: str = "plain",
        files: Optional[Dict[str, Any]] = None,
        display_target_file: str = "",
    ) -> Dict[str, Any]:
        """POST /v1/test/{ecosystem}/{file_path} — test a manifest."""
        if ecosystem not in ALLOWED_ECOSYSTEMS:
            raise ValueError(
                f"ecosystem must be one of {sorted(ALLOWED_ECOSYSTEMS)}"
            )
        if not file_path:
            raise ValueError("file_path must not be empty")
        if encoding not in ("plain", "base64"):
            raise ValueError("encoding must be 'plain' or 'base64'")
        body: Dict[str, Any] = {
            "encoding": encoding,
            "files": files or {},
            "displayTargetFile": display_target_file or "",
        }
        # Snyk expects path-encoded file path; we forward as-is. httpx will
        # re-encode internally.
        raw = self._request(
            "POST",
            f"/test/{ecosystem}/{file_path}",
            json_body=body,
        )
        return self._normalize_test(raw)

    def project_issues(
        self,
        org_id: str,
        project_id: str,
        *,
        severities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """GET /v1/org/{org_id}/project/{project_id}/issues — list issues.

        Note: Snyk's v1 issues endpoint is GET (not POST). We accept
        ``severities`` as an optional filter param.
        """
        if not org_id:
            raise ValueError("org_id must not be empty")
        if not project_id:
            raise ValueError("project_id must not be empty")
        params: Dict[str, Any] = {}
        if severities:
            params["severities[]"] = severities
        raw = self._request(
            "GET",
            f"/org/{org_id}/project/{project_id}/issues",
            params=params or None,
        )
        return self._normalize_issues(raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_orgs(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        orgs_in = raw.get("orgs") if isinstance(raw.get("orgs"), list) else []
        orgs_out: List[Dict[str, Any]] = []
        for org in orgs_in:
            if not isinstance(org, dict):
                continue
            group = org.get("group") if isinstance(org.get("group"), dict) else {}
            orgs_out.append(
                {
                    "id": org.get("id") or "",
                    "name": org.get("name") or "",
                    "slug": org.get("slug") or "",
                    "group": {
                        "id": group.get("id") or "",
                        "name": group.get("name") or "",
                    },
                }
            )
        return {"orgs": orgs_out}

    @staticmethod
    def _normalize_projects(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        projects_in = (
            raw.get("projects") if isinstance(raw.get("projects"), list) else []
        )
        projects_out: List[Dict[str, Any]] = []
        for proj in projects_in:
            if not isinstance(proj, dict):
                continue
            sev = (
                proj.get("issueCountsBySeverity")
                if isinstance(proj.get("issueCountsBySeverity"), dict)
                else {}
            )
            projects_out.append(
                {
                    "id": proj.get("id") or "",
                    "name": proj.get("name") or "",
                    "type": proj.get("type") or "",
                    "origin": proj.get("origin") or "",
                    "branch": proj.get("branch") or "",
                    "isMonitored": bool(proj.get("isMonitored", False)),
                    "totalDependencies": int(proj.get("totalDependencies") or 0),
                    "issueCountsBySeverity": {
                        "critical": int(sev.get("critical") or 0),
                        "high": int(sev.get("high") or 0),
                        "medium": int(sev.get("medium") or 0),
                        "low": int(sev.get("low") or 0),
                    },
                }
            )
        return {"projects": projects_out}

    @staticmethod
    def _normalize_test(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        ok = bool(raw.get("ok", False))
        dep_count = int(raw.get("dependencyCount") or 0)
        issues = raw.get("issues") if isinstance(raw.get("issues"), dict) else {}
        # Snyk v1 /test sometimes returns `vulnerabilities` at top-level instead
        # of `issues.vulnerabilities` — accept both.
        vulns_in = (
            issues.get("vulnerabilities")
            if isinstance(issues.get("vulnerabilities"), list)
            else (raw.get("vulnerabilities") if isinstance(raw.get("vulnerabilities"), list) else [])
        )
        licenses_in = (
            issues.get("licenses")
            if isinstance(issues.get("licenses"), list)
            else (raw.get("licenses") if isinstance(raw.get("licenses"), list) else [])
        )
        vulns_out: List[Dict[str, Any]] = []
        for v in vulns_in:
            if not isinstance(v, dict):
                continue
            vulns_out.append(
                {
                    "id": v.get("id") or "",
                    "title": v.get("title") or "",
                    "severity": v.get("severity") or "",
                    "package": v.get("package") or v.get("packageName") or "",
                    "version": v.get("version") or "",
                    "fixedIn": list(v.get("fixedIn") or []),
                }
            )
        licenses_out: List[Dict[str, Any]] = []
        for lic in licenses_in:
            if not isinstance(lic, dict):
                continue
            licenses_out.append(
                {
                    "id": lic.get("id") or "",
                    "title": lic.get("title") or "",
                    "severity": lic.get("severity") or "",
                    "package": lic.get("package") or lic.get("packageName") or "",
                    "version": lic.get("version") or "",
                }
            )
        return {
            "ok": ok,
            "dependencyCount": dep_count,
            "issues": {
                "vulnerabilities": vulns_out,
                "licenses": licenses_out,
            },
        }

    @staticmethod
    def _normalize_issues(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        issues = raw.get("issues") if isinstance(raw.get("issues"), dict) else raw
        vulns_in = (
            issues.get("vulnerabilities")
            if isinstance(issues.get("vulnerabilities"), list)
            else []
        )
        licenses_in = (
            issues.get("licenses")
            if isinstance(issues.get("licenses"), list)
            else []
        )
        vulns_out: List[Dict[str, Any]] = []
        for v in vulns_in:
            if not isinstance(v, dict):
                continue
            vulns_out.append(
                {
                    "id": v.get("id") or "",
                    "title": v.get("title") or "",
                    "severity": v.get("severity") or "",
                    "package": v.get("package") or v.get("packageName") or "",
                    "version": v.get("version") or "",
                    "fixedIn": list(v.get("fixedIn") or []),
                }
            )
        licenses_out: List[Dict[str, Any]] = []
        for lic in licenses_in:
            if not isinstance(lic, dict):
                continue
            licenses_out.append(
                {
                    "id": lic.get("id") or "",
                    "title": lic.get("title") or "",
                    "severity": lic.get("severity") or "",
                    "package": lic.get("package") or lic.get("packageName") or "",
                    "version": lic.get("version") or "",
                }
            )
        return {
            "issues": {
                "vulnerabilities": vulns_out,
                "licenses": licenses_out,
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

_singleton: Optional[SnykVulnEngine] = None
_singleton_lock = threading.Lock()


def get_snyk_vuln_engine(
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> SnykVulnEngine:
    """Return the process-wide SnykVulnEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SnykVulnEngine(api_key=api_key, client=client)
        return _singleton


def reset_snyk_vuln_engine() -> None:
    """Tear down the singleton — used by tests with stub clients."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "SnykVulnEngine",
    "SnykUnavailableError",
    "ALLOWED_ECOSYSTEMS",
    "get_snyk_vuln_engine",
    "reset_snyk_vuln_engine",
]
