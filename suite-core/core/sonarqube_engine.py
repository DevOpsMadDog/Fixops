"""SonarQube Engine — ALDECI.

Wraps the SonarQube Web API and exposes a process-wide singleton.
Talks to a SonarQube server via HTTP basic auth using the configured
``SONAR_TOKEN`` as the *username* (SonarQube convention; password empty).

Configuration (env)
-------------------
  SONARQUBE_URL    Base URL of the SonarQube server, e.g. https://sonar.example.com
  SONAR_TOKEN      User token (used as the basic-auth username)

NO MOCKS rule
-------------
When ``SONARQUBE_URL`` or ``SONAR_TOKEN`` is unset the engine is still
constructible (capability summary still renders) but every live API call
raises ``SonarQubeUnavailableError`` which the router translates to HTTP
503. We never fabricate findings, never use a SQLite cache.
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


class SonarQubeUnavailableError(RuntimeError):
    """Raised when SonarQube credentials/URL are absent or upstream errored."""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SonarQubeEngine:
    """Thread-safe SonarQube Web API client. No SQLite cache."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._explicit_url = base_url
        self._explicit_token = token
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout
        self._lock = threading.RLock()

    # ----------------------------------------------------------------- env

    def base_url(self) -> Optional[str]:
        v = self._explicit_url or os.environ.get("SONARQUBE_URL")
        return v.rstrip("/") if v else None

    def token(self) -> Optional[str]:
        v = self._explicit_token or os.environ.get("SONAR_TOKEN")
        return v.strip() if v else None

    def sonarqube_url_present(self) -> bool:
        return bool(self.base_url())

    def sonar_token_present(self) -> bool:
        return bool(self.token())

    # -------------------------------------------------------------- helpers

    def _ensure_available(self) -> None:
        if not self.sonarqube_url_present():
            raise SonarQubeUnavailableError(
                "SONARQUBE_URL unset — configure the SonarQube server URL."
            )
        if not self.sonar_token_present():
            raise SonarQubeUnavailableError(
                "SONAR_TOKEN unset — configure a SonarQube user token."
            )

    def _http_get(
        self, path: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        self._ensure_available()
        base = self.base_url() or ""
        # SonarQube convention: token is the basic-auth username, empty password.
        auth = (self.token() or "", "")
        url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
        # Strip None-valued params so httpx doesn't serialize them as "None"
        clean: Dict[str, Any] = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        try:
            resp = self._client.get(url, params=clean, auth=auth)
        except Exception as exc:  # noqa: BLE001
            raise SonarQubeUnavailableError(
                f"SonarQube request failed transport-level: {exc}"
            ) from exc
        if resp.status_code == 401:
            raise SonarQubeUnavailableError("SonarQube rejected credentials (401).")
        if resp.status_code == 403:
            raise SonarQubeUnavailableError(
                "SonarQube permission denied (403) — check token scope."
            )
        if resp.status_code >= 400:
            raise SonarQubeUnavailableError(
                f"SonarQube returned {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise SonarQubeUnavailableError(
                f"SonarQube returned non-JSON payload: {exc}"
            ) from exc

    # ----------------------------------------------------------- public API

    def projects_search(
        self,
        qualifiers: str = "TRK",
        q: Optional[str] = None,
        projects: Optional[str] = None,
        p: Optional[int] = None,
        ps: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"qualifiers": qualifiers}
        if q:
            params["q"] = q
        if projects:
            params["projects"] = projects
        if p is not None:
            params["p"] = int(p)
        if ps is not None:
            params["ps"] = int(ps)
        body = self._http_get("/api/projects/search", params=params)
        components: List[Dict[str, Any]] = []
        for c in body.get("components", []) or []:
            components.append({
                "key": c.get("key", ""),
                "name": c.get("name", ""),
                "qualifier": c.get("qualifier", "TRK"),
                "project": c.get("project", c.get("key", "")),
                "lastAnalysisDate": c.get("lastAnalysisDate", ""),
                "revision": c.get("revision", ""),
                "visibility": c.get("visibility", "private"),
                "managed": bool(c.get("managed", False)),
            })
        paging = body.get("paging", {}) or {}
        return {
            "paging": {
                "pageIndex": int(paging.get("pageIndex", 1)),
                "pageSize": int(paging.get("pageSize", len(components))),
                "total": int(paging.get("total", len(components))),
            },
            "components": components,
        }

    def issues_search(
        self,
        componentKeys: Optional[str] = None,
        severities: Optional[str] = None,
        types: Optional[str] = None,
        statuses: Optional[str] = None,
        p: Optional[int] = None,
        ps: Optional[int] = None,
        assignees: Optional[str] = None,
        tags: Optional[str] = None,
        createdAfter: Optional[str] = None,
        createdBefore: Optional[str] = None,
    ) -> Dict[str, Any]:
        if severities:
            valid = {"INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER"}
            bad = [s for s in severities.split(",") if s.strip() and s.strip().upper() not in valid]
            if bad:
                raise ValueError(
                    f"invalid severities: {bad} — allowed: {sorted(valid)}"
                )
        if types:
            valid_t = {"CODE_SMELL", "BUG", "VULNERABILITY", "SECURITY_HOTSPOT"}
            bad_t = [t for t in types.split(",") if t.strip() and t.strip().upper() not in valid_t]
            if bad_t:
                raise ValueError(
                    f"invalid types: {bad_t} — allowed: {sorted(valid_t)}"
                )
        if statuses:
            valid_s = {"OPEN", "CONFIRMED", "REOPENED", "RESOLVED", "CLOSED"}
            bad_s = [s for s in statuses.split(",") if s.strip() and s.strip().upper() not in valid_s]
            if bad_s:
                raise ValueError(
                    f"invalid statuses: {bad_s} — allowed: {sorted(valid_s)}"
                )

        params: Dict[str, Any] = {}
        if componentKeys:
            params["componentKeys"] = componentKeys
        if severities:
            params["severities"] = severities
        if types:
            params["types"] = types
        if statuses:
            params["statuses"] = statuses
        if p is not None:
            params["p"] = int(p)
        if ps is not None:
            params["ps"] = int(ps)
        if assignees:
            params["assignees"] = assignees
        if tags:
            params["tags"] = tags
        if createdAfter:
            params["createdAfter"] = createdAfter
        if createdBefore:
            params["createdBefore"] = createdBefore

        body = self._http_get("/api/issues/search", params=params)

        issues: List[Dict[str, Any]] = []
        for i in body.get("issues", []) or []:
            tr = i.get("textRange") or {}
            impacts = []
            for imp in i.get("impacts", []) or []:
                impacts.append({
                    "softwareQuality": imp.get("softwareQuality", ""),
                    "severity": imp.get("severity", ""),
                })
            issues.append({
                "key": i.get("key", ""),
                "rule": i.get("rule", ""),
                "severity": i.get("severity", ""),
                "component": i.get("component", ""),
                "project": i.get("project", ""),
                "line": i.get("line"),
                "hash": i.get("hash", ""),
                "textRange": {
                    "startLine": tr.get("startLine", 0),
                    "endLine": tr.get("endLine", 0),
                    "startOffset": tr.get("startOffset", 0),
                    "endOffset": tr.get("endOffset", 0),
                },
                "flows": i.get("flows", []) or [],
                "status": i.get("status", ""),
                "message": i.get("message", ""),
                "effort": i.get("effort", ""),
                "debt": i.get("debt", ""),
                "author": i.get("author", ""),
                "tags": i.get("tags", []) or [],
                "creationDate": i.get("creationDate", ""),
                "updateDate": i.get("updateDate", ""),
                "type": i.get("type", ""),
                "cleanCodeAttribute": i.get("cleanCodeAttribute", ""),
                "cleanCodeAttributeCategory": i.get("cleanCodeAttributeCategory", ""),
                "impacts": impacts,
                "scope": i.get("scope", "MAIN"),
            })

        paging = body.get("paging", {}) or {}
        result_payload = {
            "total": int(body.get("total", paging.get("total", len(issues)))),
            "p": int(body.get("p", paging.get("pageIndex", 1))),
            "ps": int(body.get("ps", paging.get("pageSize", len(issues)))),
            "paging": {
                "pageIndex": int(paging.get("pageIndex", 1)),
                "pageSize": int(paging.get("pageSize", len(issues))),
                "total": int(paging.get("total", len(issues))),
            },
            "components": body.get("components", []) or [],
            "rules": body.get("rules", []) or [],
            "users": body.get("users", []) or [],
            "issues": issues,
            "facets": body.get("facets", []) or [],
        }
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "threat.detected",
                        {
                            "entity_id": componentKeys or "all",
                            "type": "sonarqube_issues",
                            "severity": (severities or "unknown").split(",")[0].lower(),
                            "source_engine": "sonarqube",
                            "issue_count": len(issues),
                        },
                    )
            except Exception:
                pass
        return result_payload

    def qualitygates_project_status(
        self,
        projectKey: str,
        pullRequest: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not projectKey or not str(projectKey).strip():
            raise ValueError("projectKey is required.")
        params: Dict[str, Any] = {"projectKey": projectKey}
        if pullRequest:
            params["pullRequest"] = pullRequest
        if branch:
            params["branch"] = branch
        body = self._http_get("/api/qualitygates/project_status", params=params)
        ps_raw = body.get("projectStatus") or {}
        conditions = []
        for c in ps_raw.get("conditions", []) or []:
            conditions.append({
                "status": c.get("status", ""),
                "metricKey": c.get("metricKey", ""),
                "comparator": c.get("comparator", ""),
                "errorThreshold": c.get("errorThreshold", ""),
                "actualValue": c.get("actualValue", ""),
            })
        periods = []
        for pp in ps_raw.get("periods", []) or []:
            periods.append({
                "index": pp.get("index", 0),
                "mode": pp.get("mode", ""),
                "date": pp.get("date", ""),
                "parameter": pp.get("parameter", ""),
            })
        period = ps_raw.get("period") or {}
        return {
            "projectStatus": {
                "status": ps_raw.get("status", "NONE"),
                "ignoredConditions": bool(ps_raw.get("ignoredConditions", False)),
                "conditions": conditions,
                "periods": periods,
                "period": {
                    "mode": period.get("mode", ""),
                    "date": period.get("date", ""),
                    "parameter": period.get("parameter", ""),
                },
                "caycStatus": ps_raw.get("caycStatus", "non-compliant"),
            }
        }

    def measures_component(
        self,
        component: str,
        metricKeys: str,
        branch: Optional[str] = None,
        pullRequest: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not component or not str(component).strip():
            raise ValueError("component is required.")
        if not metricKeys or not str(metricKeys).strip():
            raise ValueError("metricKeys is required.")
        params: Dict[str, Any] = {
            "component": component,
            "metricKeys": metricKeys,
        }
        if branch:
            params["branch"] = branch
        if pullRequest:
            params["pullRequest"] = pullRequest
        body = self._http_get("/api/measures/component", params=params)
        comp = body.get("component") or {}
        measures = []
        for m in comp.get("measures", []) or []:
            measures.append({
                "metric": m.get("metric", ""),
                "value": m.get("value", ""),
                "periods": m.get("periods", []) or [],
            })
        period = body.get("period") or {}
        return {
            "component": {
                "key": comp.get("key", ""),
                "name": comp.get("name", ""),
                "qualifier": comp.get("qualifier", ""),
                "measures": measures,
            },
            "period": {
                "mode": period.get("mode", ""),
                "date": period.get("date", ""),
                "parameter": period.get("parameter", ""),
            },
            "periods": body.get("periods", []) or [],
        }

    def components_show(
        self, key: str, branch: Optional[str] = None
    ) -> Dict[str, Any]:
        if not key or not str(key).strip():
            raise ValueError("key is required.")
        params: Dict[str, Any] = {"key": key}
        if branch:
            params["branch"] = branch
        body = self._http_get("/api/components/show", params=params)
        comp = body.get("component") or {}
        return {
            "component": {
                "key": comp.get("key", ""),
                "name": comp.get("name", ""),
                "qualifier": comp.get("qualifier", ""),
                "path": comp.get("path", ""),
                "language": comp.get("language", ""),
                "version": comp.get("version", ""),
                "description": comp.get("description", ""),
            },
            "ancestors": body.get("ancestors", []) or [],
        }

    def hotspots_search(
        self,
        projectKey: Optional[str] = None,
        hotspots: Optional[str] = None,
        status: Optional[str] = None,
        resolution: Optional[str] = None,
        pullRequest: Optional[str] = None,
        branch: Optional[str] = None,
        p: Optional[int] = None,
        ps: Optional[int] = None,
    ) -> Dict[str, Any]:
        if status and status.upper() not in {"TO_REVIEW", "REVIEWED"}:
            raise ValueError(
                "status must be one of TO_REVIEW, REVIEWED."
            )
        params: Dict[str, Any] = {}
        if projectKey:
            params["projectKey"] = projectKey
        if hotspots:
            params["hotspots"] = hotspots
        if status:
            params["status"] = status
        if resolution:
            params["resolution"] = resolution
        if pullRequest:
            params["pullRequest"] = pullRequest
        if branch:
            params["branch"] = branch
        if p is not None:
            params["p"] = int(p)
        if ps is not None:
            params["ps"] = int(ps)

        body = self._http_get("/api/hotspots/search", params=params)
        hots: List[Dict[str, Any]] = []
        for h in body.get("hotspots", []) or []:
            tr = h.get("textRange") or {}
            hots.append({
                "key": h.get("key", ""),
                "component": h.get("component", ""),
                "project": h.get("project", ""),
                "securityCategory": h.get("securityCategory", ""),
                "vulnerabilityProbability": h.get("vulnerabilityProbability", ""),
                "status": h.get("status", "TO_REVIEW"),
                "line": h.get("line"),
                "message": h.get("message", ""),
                "author": h.get("author", ""),
                "creationDate": h.get("creationDate", ""),
                "updateDate": h.get("updateDate", ""),
                "textRange": {
                    "startLine": tr.get("startLine", 0),
                    "endLine": tr.get("endLine", 0),
                    "startOffset": tr.get("startOffset", 0),
                    "endOffset": tr.get("endOffset", 0),
                },
                "flows": h.get("flows", []) or [],
                "ruleKey": h.get("ruleKey", ""),
            })
        paging = body.get("paging", {}) or {}
        return {
            "paging": {
                "pageIndex": int(paging.get("pageIndex", 1)),
                "pageSize": int(paging.get("pageSize", len(hots))),
                "total": int(paging.get("total", len(hots))),
            },
            "hotspots": hots,
            "components": body.get("components", []) or [],
        }

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Process-wide singleton
# ---------------------------------------------------------------------------

_engine_lock = threading.Lock()
_engine_instance: Optional[SonarQubeEngine] = None


def get_sonarqube_engine(
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    client: Optional[httpx.Client] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> SonarQubeEngine:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = SonarQubeEngine(
                base_url=base_url,
                token=token,
                client=client,
                timeout=timeout,
            )
        return _engine_instance


def reset_sonarqube_engine() -> None:
    global _engine_instance
    with _engine_lock:
        if _engine_instance is not None:
            _engine_instance.close()
        _engine_instance = None
