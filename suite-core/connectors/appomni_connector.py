"""AppOmni — Live API Connector (SSPM).

Fetches SaaS security posture findings from AppOmni REST API to surface
SaaS application risk findings in ALDECI.

Live API flow:
1. GET  /api/v1/findings (paginated via cursor/offset)
2. GET  /api/v1/apps       (SaaS app inventory)
3. Normalize to ALDECI common-finding shape
4. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- APPOMNI_API_KEY required.
- APPOMNI_BASE_URL optional (default: https://api.appomni.com).
- If credentials absent → graceful no-op: returns {status: "needs_credentials"}.

Cache: 1-hour TTL per org_id. Idempotent via correlation_key.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.appomni.com"
_CACHE_TTL_SECONDS = 3600
_PAGE_SIZE = 100

_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(os.environ.get("APPOMNI_API_KEY"))


def _headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {os.environ.get('APPOMNI_API_KEY', '')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _paginate_findings(base_url: str) -> List[Dict[str, Any]]:
    """Page through AppOmni /findings endpoint."""
    import httpx

    items: List[Dict[str, Any]] = []
    offset = 0

    while True:
        params = {"limit": _PAGE_SIZE, "offset": offset}
        resp = httpx.get(
            f"{base_url}/api/v1/findings",
            params=params,
            headers=_headers(),
            timeout=30,
        )
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        body = resp.json()
        batch = body.get("results") or body.get("findings") or body.get("data") or []
        items.extend(batch)
        total = int(body.get("count") or body.get("total") or 0)
        offset += len(batch)
        if not batch or offset >= total:
            break

    return items


def _paginate_apps(base_url: str) -> List[Dict[str, Any]]:
    """Page through AppOmni /apps endpoint."""
    import httpx

    items: List[Dict[str, Any]] = []
    offset = 0

    while True:
        params = {"limit": _PAGE_SIZE, "offset": offset}
        resp = httpx.get(
            f"{base_url}/api/v1/apps",
            params=params,
            headers=_headers(),
            timeout=20,
        )
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        body = resp.json()
        batch = body.get("results") or body.get("apps") or body.get("data") or []
        items.extend(batch)
        total = int(body.get("count") or body.get("total") or 0)
        offset += len(batch)
        if not batch or offset >= total:
            break

    return items


_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}


def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an AppOmni finding to ALDECI common-finding shape."""
    finding_id = str(finding.get("id") or finding.get("uuid") or "unknown")
    title = finding.get("title") or finding.get("name") or f"AppOmni finding {finding_id}"
    description = finding.get("description") or finding.get("details") or ""
    raw_sev = str(finding.get("severity") or finding.get("risk_level") or "medium").lower()
    severity = _SEVERITY_MAP.get(raw_sev, "medium")
    app_name = finding.get("app_name") or finding.get("service") or "unknown"
    app_id = str(finding.get("app_id") or finding.get("service_id") or "unknown")
    category = finding.get("category") or finding.get("type") or "sspm"
    status = finding.get("status") or finding.get("state") or "open"
    created_at = finding.get("created_at") or finding.get("discovered_at") or ""
    remediation = finding.get("remediation") or finding.get("recommendation") or (
        "Review and remediate the SaaS misconfiguration in AppOmni console."
    )

    return {
        "asset_id": f"appomni:app:{app_id}",
        "asset_type": "saas_application",
        "title": title[:200],
        "description": (
            f"[{app_name}] {description} "
            f"Category: {category}. Status: {status}. Discovered: {created_at}."
        )[:500],
        "severity": severity,
        "cvss_score": 0.0,
        "source_tool": "appomni",
        "finding_type": "sspm",
        "app_name": app_name,
        "app_id": app_id,
        "category": category,
        "status": status,
        "correlation_key": f"appomni_finding|{finding_id}",
        "remediation": remediation[:300],
    }


class AppOmniConnector:
    """AppOmni SSPM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override APPOMNI_BASE_URL env var.
        max_findings:    Cap on findings to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_findings: int = 5000,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url or os.environ.get("APPOMNI_BASE_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self._max_findings = max(1, min(max_findings, 100_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync AppOmni SSPM findings for an org."""
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        api_key = os.environ.get("APPOMNI_API_KEY", "")
        if not api_key:
            _logger.warning(
                "AppOmniConnector: APPOMNI_API_KEY not set — skipping for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "findings_count": 0,
                "findings_recorded": 0,
                "findings": [],
                "apps_count": 0,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set APPOMNI_API_KEY environment variable "
                    "to enable live AppOmni SSPM integration."
                ),
            }

        cache_key = (org_id, self._base_url)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            raw_findings = _paginate_findings(self._base_url)
            raw_findings = raw_findings[: self._max_findings]
            apps = _paginate_apps(self._base_url)
        except Exception as exc:
            _logger.error("AppOmniConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "findings_count": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for raw in raw_findings:
            finding = _normalize_finding(raw)
            all_findings.append(finding)

            if self._findings is not None:
                try:
                    sev = finding["severity"]
                    if sev == "informational":
                        sev = "low"
                    self._findings.record_finding(
                        org_id=org_id,
                        title=finding["title"],
                        finding_type=finding["finding_type"],
                        source_tool=finding["source_tool"],
                        severity=sev,
                        cvss_score=finding["cvss_score"],
                        asset_id=finding["asset_id"][:200],
                        asset_type=finding["asset_type"],
                        description=finding["description"],
                        remediation=finding["remediation"],
                        correlation_key=finding["correlation_key"],
                    )
                    recorded += 1
                except Exception as exc:
                    _logger.warning("AppOmniConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="AppOmniConnector",
            org_id=org_id,
            source_kind="cspm",
            finding_count=recorded,
            extra={
                "mode": "live",
                "findings_count": len(raw_findings),
                "apps_count": len(apps),
            },
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "findings_count": len(raw_findings),
            "apps_count": len(apps),
            "findings_recorded": recorded,
            "findings": all_findings,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


_singleton_lock = threading.Lock()
_singleton: Optional[AppOmniConnector] = None


def get_appomni_connector() -> AppOmniConnector:
    """Lazy singleton — wires SecurityFindingsEngine on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            findings = None
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable: %s", exc)
            _singleton = AppOmniConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "AppOmniConnector",
    "get_appomni_connector",
    "_creds_present",
    "_normalize_finding",
]
