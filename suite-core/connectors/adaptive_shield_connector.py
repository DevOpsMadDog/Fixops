"""Adaptive Shield — Live API Connector (SSPM).

Fetches SaaS security posture checks and misconfigurations from Adaptive
Shield REST API to surface SaaS risk findings in ALDECI.

Live API flow:
1. GET /v1/checks         (security check results, paginated)
2. GET /v1/apps           (connected SaaS app inventory)
3. Normalize to ALDECI common-finding shape
4. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- ADAPTIVESHIELD_API_KEY required.
- ADAPTIVESHIELD_BASE_URL optional (default: https://api.adaptive-shield.com).
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

_DEFAULT_BASE_URL = "https://api.adaptive-shield.com"
_CACHE_TTL_SECONDS = 3600
_PAGE_SIZE = 100

_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(os.environ.get("ADAPTIVESHIELD_API_KEY"))


def _headers() -> Dict[str, str]:
    return {
        "X-Api-Key": os.environ.get("ADAPTIVESHIELD_API_KEY", ""),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _paginate(base_url: str, endpoint: str) -> List[Dict[str, Any]]:
    """Page through an Adaptive Shield list endpoint."""
    import httpx

    items: List[Dict[str, Any]] = []
    offset = 0

    while True:
        params = {"limit": _PAGE_SIZE, "offset": offset}
        resp = httpx.get(
            f"{base_url}{endpoint}",
            params=params,
            headers=_headers(),
            timeout=30,
        )
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        body = resp.json()
        # Adaptive Shield wraps results in various keys
        batch = (
            body.get("results")
            or body.get("checks")
            or body.get("apps")
            or body.get("data")
            or (body if isinstance(body, list) else [])
        )
        items.extend(batch)
        total = int(body.get("count") or body.get("total") or 0) if isinstance(body, dict) else 0
        offset += len(batch)
        if not batch or (total and offset >= total):
            break

    return items


_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
    "pass": "informational",
    "fail": "medium",
}

_STATUS_SEVERITY_BUMP = {
    "fail": "medium",
    "error": "high",
}


def _normalize_check(check: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an Adaptive Shield security check to ALDECI finding shape."""
    check_id = str(check.get("id") or check.get("checkId") or "unknown")
    title = check.get("title") or check.get("name") or f"Adaptive Shield check {check_id}"
    description = check.get("description") or check.get("details") or ""
    raw_sev = str(check.get("severity") or check.get("riskLevel") or "medium").lower()
    status = str(check.get("status") or check.get("result") or "unknown").lower()
    # Bump severity if check explicitly failed
    if status in _STATUS_SEVERITY_BUMP and raw_sev in ("low", "informational"):
        raw_sev = _STATUS_SEVERITY_BUMP[status]
    severity = _SEVERITY_MAP.get(raw_sev, "medium")

    app_name = check.get("appName") or check.get("service") or check.get("app") or "unknown"
    app_id = str(check.get("appId") or check.get("serviceId") or "unknown")
    category = check.get("category") or check.get("domain") or "sspm"
    remediation = check.get("remediation") or check.get("recommendation") or (
        "Review and remediate the SaaS misconfiguration in Adaptive Shield."
    )
    last_checked = check.get("lastChecked") or check.get("updatedAt") or ""

    return {
        "asset_id": f"adaptive_shield:app:{app_id}",
        "asset_type": "saas_application",
        "title": title[:200],
        "description": (
            f"[{app_name}] {description} "
            f"Status: {status}. Category: {category}. Last checked: {last_checked}."
        )[:500],
        "severity": severity,
        "cvss_score": 0.0,
        "source_tool": "adaptive_shield",
        "finding_type": "sspm",
        "app_name": app_name,
        "app_id": app_id,
        "category": category,
        "status": status,
        "correlation_key": f"adaptive_shield_check|{check_id}",
        "remediation": remediation[:300],
    }


class AdaptiveShieldConnector:
    """Adaptive Shield SSPM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override ADAPTIVESHIELD_BASE_URL env var.
        max_checks:      Cap on checks to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_checks: int = 5000,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url
            or os.environ.get("ADAPTIVESHIELD_BASE_URL")
            or _DEFAULT_BASE_URL
        ).rstrip("/")
        self._max_checks = max(1, min(max_checks, 100_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Adaptive Shield SSPM checks for an org."""
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        api_key = os.environ.get("ADAPTIVESHIELD_API_KEY", "")
        if not api_key:
            _logger.warning(
                "AdaptiveShieldConnector: ADAPTIVESHIELD_API_KEY not set — skipping for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "checks_count": 0,
                "findings_recorded": 0,
                "findings": [],
                "apps_count": 0,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set ADAPTIVESHIELD_API_KEY environment variable "
                    "to enable live Adaptive Shield SSPM integration."
                ),
            }

        cache_key = (org_id, self._base_url)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            raw_checks = _paginate(self._base_url, "/v1/checks")
            raw_checks = raw_checks[: self._max_checks]
            apps = _paginate(self._base_url, "/v1/apps")
        except Exception as exc:
            _logger.error("AdaptiveShieldConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "checks_count": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for raw in raw_checks:
            # Only surface failed checks
            status = str(raw.get("status") or raw.get("result") or "unknown").lower()
            if status in ("pass", "passed", "ok"):
                continue
            finding = _normalize_check(raw)
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
                    _logger.warning("AdaptiveShieldConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="AdaptiveShieldConnector",
            org_id=org_id,
            source_kind="cspm",
            finding_count=recorded,
            extra={
                "mode": "live",
                "checks_count": len(raw_checks),
                "apps_count": len(apps),
            },
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "checks_count": len(raw_checks),
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
_singleton: Optional[AdaptiveShieldConnector] = None


def get_adaptive_shield_connector() -> AdaptiveShieldConnector:
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
            _singleton = AdaptiveShieldConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "AdaptiveShieldConnector",
    "get_adaptive_shield_connector",
    "_creds_present",
    "_normalize_check",
]
