"""DAST Scanner Router — Dynamic Application Security Testing endpoints.

Security hardening:
- SSRF prevention on target_url (blocks RFC1918, localhost, link-local, metadata)
- Profile-based rate limiting
- URL length limit (2048 chars)
- Max depth bounded to [1, 10]
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, field_validator

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dast", tags=["DAST"])

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
    if not host:
        raise ValueError("URL must include a hostname")
    if host.lower() in _BLOCKED_HOSTS:
        raise ValueError("Target host is blocked (internal address)")
    if _is_private_ip(host):
        raise ValueError("Private/reserved IP addresses are blocked")
    return url


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class AuthConfigRequest(BaseModel):
    auth_type: str = "none"
    cookie_name: str = ""
    cookie_value: str = ""
    token: str = ""
    header_name: str = "Authorization"
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    username: str = ""
    password: str = ""
    login_url: str = ""
    login_username_field: str = "username"
    login_password_field: str = "password"

    @field_validator("auth_type")
    @classmethod
    def validate_auth_type(cls, v: str) -> str:
        allowed = {"none", "cookie", "jwt_bearer", "oauth2", "api_key_header", "basic_auth"}
        if v not in allowed:
            raise ValueError(f"auth_type must be one of: {sorted(allowed)}")
        return v

    @field_validator("header_name")
    @classmethod
    def validate_header_name(cls, v: str) -> str:
        if len(v) > 100:
            raise ValueError("header_name too long (max 100 chars)")
        return v


class ScanRequest(BaseModel):
    target_url: str
    profile: str = "standard"
    auth: Optional[AuthConfigRequest] = None
    max_depth: int = 3
    max_urls: int = 100
    requests_per_second: float = 5.0
    timeout: float = 10.0
    respect_robots_txt: bool = True
    scope_pattern: str = ""
    custom_headers: Optional[Dict[str, str]] = None
    openapi_spec: Optional[Dict[str, Any]] = None

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        return _validate_target_url(v)

    @field_validator("profile")
    @classmethod
    def validate_profile(cls, v: str) -> str:
        allowed = {"quick", "standard", "full", "api_only"}
        if v not in allowed:
            raise ValueError(f"profile must be one of: {sorted(allowed)}")
        return v

    @field_validator("max_depth")
    @classmethod
    def validate_max_depth(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_depth must be >= 1")
        if v > 10:
            raise ValueError("max_depth must be <= 10")
        return v

    @field_validator("max_urls")
    @classmethod
    def validate_max_urls(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_urls must be >= 1")
        if v > 500:
            raise ValueError("max_urls must be <= 500")
        return v

    @field_validator("requests_per_second")
    @classmethod
    def validate_rps(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("requests_per_second must be > 0")
        if v > 50:
            raise ValueError("requests_per_second must be <= 50")
        return v

    @field_validator("custom_headers")
    @classmethod
    def validate_custom_headers(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is not None and len(v) > 50:
            raise ValueError("Too many custom_headers (max 50)")
        return v

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, v: float) -> float:
        if v < 1:
            raise ValueError("timeout must be >= 1 second")
        if v > 60:
            raise ValueError("timeout must be <= 60 seconds")
        return v


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_scan_config(req: ScanRequest):
    """Convert ScanRequest to ScanConfig (lazy import to avoid circular deps)."""
    from core.dast_scanner import (
        AuthConfig, AuthType, ScanConfig, ScanProfile,
    )

    auth_cfg = AuthConfig()
    if req.auth:
        try:
            auth_cfg.auth_type = AuthType(req.auth.auth_type)
        except ValueError:
            auth_cfg.auth_type = AuthType.NONE
        auth_cfg.cookie_name = req.auth.cookie_name
        auth_cfg.cookie_value = req.auth.cookie_value
        auth_cfg.token = req.auth.token
        auth_cfg.header_name = req.auth.header_name
        auth_cfg.token_url = req.auth.token_url
        auth_cfg.client_id = req.auth.client_id
        auth_cfg.client_secret = req.auth.client_secret
        auth_cfg.scope = req.auth.scope
        auth_cfg.username = req.auth.username
        auth_cfg.password = req.auth.password
        auth_cfg.login_url = req.auth.login_url
        auth_cfg.login_username_field = req.auth.login_username_field
        auth_cfg.login_password_field = req.auth.login_password_field

    return ScanConfig(
        target_url=req.target_url,
        profile=ScanProfile(req.profile),
        auth=auth_cfg,
        max_depth=req.max_depth,
        max_urls=req.max_urls,
        requests_per_second=req.requests_per_second,
        timeout=req.timeout,
        respect_robots_txt=req.respect_robots_txt,
        scope_pattern=req.scope_pattern,
        custom_headers=req.custom_headers or {},
        openapi_spec=req.openapi_spec,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/")
async def dast_root() -> Dict[str, Any]:
    """DAST scanner capabilities and available endpoints."""
    return {
        "service": "DAST Scanner",
        "version": "1.0.0",
        "description": "Dynamic Application Security Testing — real HTTP-based security scans",
        "capabilities": [
            "web_crawl",
            "sql_injection",
            "xss",
            "path_traversal",
            "ssrf",
            "security_headers",
            "info_disclosure",
            "api_scan_openapi",
            "authenticated_scanning",
        ],
        "endpoints": {
            "POST /scan": "Start a DAST scan (returns scan_id immediately)",
            "GET /scans/{scan_id}": "Poll scan status and retrieve results",
            "GET /findings": "List all findings with optional severity/scan_id filter",
            "GET /headers/{url}": "Quick security-headers check for a URL",
            "GET /profiles": "List available scan profiles",
            "GET /stats": "Aggregate scan statistics",
            "GET /health": "Engine health check",
        },
        "auth_modes": ["none", "cookie", "jwt_bearer", "oauth2", "api_key_header", "basic_auth"],
        "scan_profiles": ["quick", "standard", "full", "api_only"],
    }


@router.post("/scan")
async def start_scan(req: ScanRequest) -> Dict[str, Any]:
    """Start a DAST scan against a target URL.

    Returns scan_id immediately; scan runs in a background thread.
    Poll GET /api/v1/dast/scans/{id} for status and results.
    """
    from core.dast_scanner import get_dast_scanner

    try:
        config = _build_scan_config(req)
        scanner = get_dast_scanner()
        scan_id = scanner.start_scan(config)
        _logger.info("DAST scan started: %s -> %s (%s)", scan_id, req.target_url, req.profile)
        return {
            "scan_id": scan_id,
            "target_url": req.target_url,
            "profile": req.profile,
            "status": "pending",
            "message": f"Scan started. Poll GET /api/v1/dast/scans/{scan_id} for results.",
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except (OSError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        _logger.error("Failed to start DAST scan: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to start scan")


@router.get("/scans/{scan_id}")
async def get_scan_status(scan_id: str) -> Dict[str, Any]:
    """Get DAST scan status and full results (once completed)."""
    from core.dast_scanner import get_dast_scanner

    scanner = get_dast_scanner()
    result = scanner.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
    return result.to_dict()


@router.get("/findings")
async def get_findings(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    scan_id: Optional[str] = Query(None, description="Filter by scan_id"),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """List DAST findings with reproducible PoC details."""
    from core.dast_scanner import get_dast_scanner, FindingSeverity

    if severity is not None:
        allowed_severities = {s.value for s in FindingSeverity}
        if severity not in allowed_severities:
            raise HTTPException(
                status_code=422,
                detail=f"severity must be one of: {sorted(allowed_severities)}",
            )

    scanner = get_dast_scanner()

    if scan_id is not None:
        result = scanner.get_scan(scan_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")
        findings = result.findings
        if severity:
            findings = [f for f in findings if f.severity.value == severity]
    else:
        findings = scanner.get_all_findings(severity_filter=severity)

    findings = findings[:limit]
    return {
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/headers/{url:path}")
async def check_security_headers(url: str) -> Dict[str, Any]:
    """Quick security headers check for a target URL.

    Checks: CSP, X-Frame-Options, HSTS, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, X-XSS-Protection.
    Also reports TLS version.
    """
    if not url.startswith("http"):
        url = "https://" + url

    try:
        _validate_target_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    try:
        from core.dast_scanner import (
            AuthConfig, ScanConfig, ScanProfile, SecurityHeadersAnalyser,
            _HttpClient,
        )

        config = ScanConfig(
            target_url=url,
            profile=ScanProfile.QUICK,
            auth=AuthConfig(),
            requests_per_second=10.0,
            timeout=10.0,
        )
        client = _HttpClient(config, {})
        analyser = SecurityHeadersAnalyser()
        result = analyser.analyse(url, client)
        return result.to_dict()
    except (OSError, RuntimeError, KeyError, TypeError, AttributeError, ValueError) as exc:
        _logger.error("Security headers check failed for %s: %s", url, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Headers check failed")


@router.get("/profiles")
async def list_scan_profiles() -> Dict[str, Any]:
    """List available DAST scan profiles with descriptions."""
    return {
        "profiles": [
            {
                "id": "quick",
                "name": "Quick",
                "description": "Security headers and server configuration checks only. No active injection tests.",
                "tests": [
                    "Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)",
                    "TLS/HTTPS redirect check",
                    "Server version disclosure",
                    "Clickjacking protection",
                ],
                "active_testing": False,
                "estimated_duration": "30-60 seconds",
            },
            {
                "id": "standard",
                "name": "Standard",
                "description": "Full crawl + all passive checks + light active injection testing. Recommended for CI/CD.",
                "tests": [
                    "Web crawling and endpoint discovery",
                    "Security headers analysis",
                    "SQL/NoSQL injection (safe payloads)",
                    "SSRF detection",
                    "Broken access control (IDOR, privileged paths)",
                    "Security misconfiguration (directory listing, verbose errors, unnecessary methods)",
                    "Vulnerable component detection (server headers)",
                    "Clickjacking and CSP checks",
                    "Rate limit assessment on sensitive endpoints",
                ],
                "active_testing": True,
                "estimated_duration": "2-10 minutes",
            },
            {
                "id": "full",
                "name": "Full",
                "description": "Everything in Standard plus authentication testing, session fixation, OS command injection.",
                "tests": [
                    "All Standard tests",
                    "Authentication failure testing (session fixation)",
                    "Default credential testing",
                    "OS command injection probes",
                    "Business logic flaw detection",
                    "Logging/monitoring gap assessment",
                ],
                "active_testing": True,
                "estimated_duration": "5-30 minutes",
            },
            {
                "id": "api_only",
                "name": "API Only",
                "description": "OpenAPI/Swagger-driven scan — no browser crawling. Requires openapi_spec in request body.",
                "tests": [
                    "OpenAPI endpoint discovery",
                    "Broken access control per endpoint",
                    "Injection testing on API parameters",
                    "SSRF via URL-type parameters",
                    "Server version / stack disclosure",
                ],
                "active_testing": True,
                "estimated_duration": "1-5 minutes",
            },
        ]
    }


@router.get("/stats")
async def get_dast_stats(org_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    """Return aggregate DAST scan statistics."""
    from core.dast_scanner import get_dast_scanner
    scanner = get_dast_scanner()
    all_findings = scanner.get_all_findings()
    scan_count = len(scanner._scans)
    critical = sum(1 for f in all_findings if f.severity.value == "critical")
    high = sum(1 for f in all_findings if f.severity.value == "high")
    endpoints_tested = len({f.url for f in all_findings})
    return {
        "scans": scan_count,
        "findings": len(all_findings),
        "critical": critical,
        "high": high,
        "endpoints_tested": endpoints_tested,
    }


@router.get("/health")
async def dast_health() -> Dict[str, Any]:
    """Health check for the DAST scanner engine."""
    return {"status": "healthy", "engine": "dast_scanner", "version": "1.0.0"}


@router.get("/status")
async def dast_status() -> Dict[str, Any]:
    """Status alias for the DAST scanner engine."""
    return await dast_health()
