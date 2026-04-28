"""API Security Testing Router — OWASP API Top 10 scanning endpoints.

Security hardening:
- SSRF prevention on target_url (blocks RFC1918, localhost, link-local, metadata)
- Spec size limit (5 MB) to prevent DoS via oversized payloads
- URL length limit (2048 chars)
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/api-security", tags=["API Security"])

# ---------------------------------------------------------------------------
# SSRF blocklist
# ---------------------------------------------------------------------------

_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",  # nosec B104 — SSRF blocklist, not a bind call
    "metadata.google.internal", "169.254.169.254",
})


def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _validate_target_url(url: str) -> str:
    if len(url) > 2048:
        raise ValueError("URL exceeds 2048 character limit")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https schemes allowed")
    host = parsed.hostname or ""
    if host.lower() in _BLOCKED_HOSTS:
        raise ValueError("Target host is blocked (internal/metadata address)")
    if _is_private_ip(host):
        raise ValueError("Private/reserved IP addresses are blocked")
    return url


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

_MAX_SPEC_KEYS = 5000  # rough guard against deeply nested specs


class ScanRequest(BaseModel):
    """POST /scan — scan an API from an OpenAPI spec URL or JSON body."""
    target_url: Optional[str] = None
    openapi_spec: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    check_rate_limits: bool = False
    check_graphql: bool = False
    max_rate_limit_endpoints: int = 3

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return _validate_target_url(v)
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is not None and len(v) > 50:
            raise ValueError("Too many headers (max 50)")
        return v

    @field_validator("max_rate_limit_endpoints")
    @classmethod
    def validate_max_endpoints(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_rate_limit_endpoints must be >= 1")
        if v > 20:
            raise ValueError("max_rate_limit_endpoints must be <= 20")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/scan")
async def scan_api(req: ScanRequest) -> Dict[str, Any]:
    """Scan an API for OWASP API Top 10 vulnerabilities.

    Accepts an OpenAPI spec as JSON body or a target URL for auto-discovery.
    Returns a full scan result with findings, schema issues, and auth analysis.
    """
    if req.openapi_spec is None and req.target_url is None:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'openapi_spec' (JSON) or 'target_url' for auto-discovery",
        )

    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    try:
        result = await engine.run_scan(
            spec=req.openapi_spec,
            target_url=req.target_url,
            headers=req.headers,
            check_rate_limits=req.check_rate_limits,
            check_graphql=req.check_graphql,
            max_rate_limit_endpoints=req.max_rate_limit_endpoints,
        )
    except Exception as exc:
        _logger.exception("api_security_scan_error")
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    return result.to_dict()


@router.get("/findings")
async def get_findings(
    severity: Optional[str] = None,
    owasp_category: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """Return all API security findings, optionally filtered by severity or OWASP category."""
    if limit < 1 or limit > 1000:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 1000")

    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    findings = engine.get_all_findings()

    if severity:
        findings = [f for f in findings if f.severity.value == severity.lower()]
    if owasp_category:
        findings = [f for f in findings if owasp_category.lower() in f.owasp_category.value.lower()]

    findings = findings[:limit]

    by_severity: Dict[str, int] = {}
    for f in findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/inventory")
async def get_inventory() -> Dict[str, Any]:
    """Return discovered API inventory (endpoints from all completed scans)."""
    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    inventory = engine.get_inventory()
    return {
        "total_scans": len(inventory),
        "inventory": inventory,
    }


@router.get("/auth-analysis")
async def get_auth_analysis() -> Dict[str, Any]:
    """Return authentication weakness analysis from all completed scans."""
    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    analyses = engine.get_auth_analyses()
    return {
        "total": len(analyses),
        "analyses": [a.to_dict() for a in analyses],
    }


@router.get("/rate-limits")
async def get_rate_limits() -> Dict[str, Any]:
    """Return rate limit test results from all completed scans."""
    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    results = engine.get_rate_limit_results()
    no_limit_detected = [r for r in results if not r.rate_limit_detected]
    return {
        "total": len(results),
        "endpoints_without_rate_limit": len(no_limit_detected),
        "results": [r.to_dict() for r in results],
    }


@router.get("/schema-issues")
async def get_schema_issues(
    issue_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Return schema validation findings (mass assignment, PII leak, missing validation)."""
    from core.api_security_engine import get_api_security_engine

    engine = get_api_security_engine()
    issues = engine.get_schema_issues()

    if issue_type:
        issues = [i for i in issues if i.issue_type == issue_type]

    by_type: Dict[str, int] = {}
    for i in issues:
        by_type[i.issue_type] = by_type.get(i.issue_type, 0) + 1

    return {
        "total": len(issues),
        "by_type": by_type,
        "issues": [i.to_dict() for i in issues],
    }


@router.get("/health")
async def health() -> Dict[str, Any]:
    """Health check for the API Security engine."""
    return {"status": "healthy", "engine": "api_security", "version": "1.0.0"}
