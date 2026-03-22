"""DAST Router — Dynamic Application Security Testing endpoints.

Hardened with SSRF protection, input validation, and rate limiting awareness.
Supports authenticated scanning (Bearer, Basic, API Key, Form Login, OAuth2)
and OpenAPI-driven API security testing.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Depends
from apps.api.dependencies import get_org_id
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dast", tags=["DAST"])

# Maximum scan depth to prevent resource exhaustion
_MAX_SCAN_DEPTH = 10
# Maximum number of custom headers to prevent header injection abuse
_MAX_HEADERS = 20
# Blocked internal network ranges for SSRF protection
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 private
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def _is_safe_url(url: str) -> bool:
    """Check if URL is safe (not targeting internal networks)."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block non-HTTP(S) schemes
        if parsed.scheme not in ("http", "https"):
            return False
        # Block common internal hostnames
        blocked_hosts = {"localhost", "metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in blocked_hosts:
            return False
        # Try to resolve and check against blocked networks
        try:
            addr = ipaddress.ip_address(hostname)
            for network in _BLOCKED_NETWORKS:
                if addr in network:
                    return False
        except ValueError:
            # hostname is a domain name, not an IP — allow it
            # (DNS resolution would require network access)
            pass
        return True
    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
        return False


_MAX_HEADER_VALUE_LEN = 8192  # Per-header/cookie value size limit
_MAX_COOKIE_COUNT = 50  # Max number of cookies


class AuthConfigRequest(BaseModel):
    """Authentication configuration for DAST scanning."""
    mode: str = Field("none", description="Auth mode: bearer, basic, api_key, form_login, cookie, oauth2, none")
    bearer_token: Optional[str] = Field(None, description="Bearer token", max_length=8192)
    basic_username: Optional[str] = Field(None, description="Basic auth username", max_length=256)
    basic_password: Optional[str] = Field(None, description="Basic auth password", max_length=1024)
    api_key_header: Optional[str] = Field("X-API-Key", description="Header name for API key", max_length=256)
    api_key_value: Optional[str] = Field(None, description="API key value", max_length=8192)
    login_url: Optional[str] = Field(None, description="URL of login form", max_length=2048)
    username_field: Optional[str] = Field("username", description="Login form username field name", max_length=256)
    password_field: Optional[str] = Field("password", description="Login form password field name", max_length=256)
    login_username: Optional[str] = Field(None, description="Login username", max_length=256)
    login_password: Optional[str] = Field(None, description="Login password", max_length=1024)
    extra_form_fields: Optional[Dict[str, str]] = Field(None, description="Extra login form fields")
    success_indicator: Optional[str] = Field(None, description="Text indicating login success", max_length=1024)
    failure_indicator: Optional[str] = Field(None, description="Text indicating login failure", max_length=1024)
    token_url: Optional[str] = Field(None, description="OAuth2 token endpoint", max_length=2048)
    client_id: Optional[str] = Field(None, description="OAuth2 client ID", max_length=256)
    client_secret: Optional[str] = Field(None, description="OAuth2 client secret", max_length=1024)
    scope: Optional[str] = Field(None, description="OAuth2 scope", max_length=1024)
    session_check_url: Optional[str] = Field(None, description="URL to verify session", max_length=2048)
    session_check_pattern: Optional[str] = Field(None, description="Pattern for valid session", max_length=1024)
    reauth_on_401: bool = Field(True, description="Re-authenticate on 401 responses")

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid_modes = {"none", "bearer", "basic", "api_key", "form_login", "cookie", "oauth2"}
        if v not in valid_modes:
            raise ValueError(f"Invalid auth mode: {v}. Must be one of: {', '.join(sorted(valid_modes))}")
        return v


class DastScanRequest(BaseModel):
    target_url: str = Field(
        ...,
        description="Target URL to scan (must be http/https, external only)",
        max_length=2048,
    )
    headers: Optional[Dict[str, str]] = Field(
        None, description="Custom HTTP headers for scanning"
    )
    cookies: Optional[Dict[str, str]] = Field(
        None, description="Cookies to include in scan requests"
    )
    crawl: bool = Field(True, description="Whether to crawl the target")
    max_depth: int = Field(3, ge=1, le=_MAX_SCAN_DEPTH, description="Max crawl depth")
    auth: Optional[AuthConfigRequest] = Field(None, description="Authentication configuration")

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target_url cannot be empty")
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        if not _is_safe_url(v):
            raise ValueError(
                "target_url points to an internal/restricted network address"
            )
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is None:
            return v
        for key, val in v.items():
            if len(key) > 256:
                raise ValueError(f"Header name too long: {len(key)} chars (max 256)")
            if len(val) > _MAX_HEADER_VALUE_LEN:
                raise ValueError(
                    f"Header '{key[:64]}' value too long: {len(val)} chars (max {_MAX_HEADER_VALUE_LEN})"
                )
        return v

    @field_validator("cookies")
    @classmethod
    def validate_cookies(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is None:
            return v
        if len(v) > _MAX_COOKIE_COUNT:
            raise ValueError(f"Too many cookies: {len(v)} (max {_MAX_COOKIE_COUNT})")
        for key, val in v.items():
            if len(key) > 256:
                raise ValueError(f"Cookie name too long: {len(key)} chars (max 256)")
            if len(val) > _MAX_HEADER_VALUE_LEN:
                raise ValueError(
                    f"Cookie '{key[:64]}' value too long: {len(val)} chars (max {_MAX_HEADER_VALUE_LEN})"
                )
        return v


class DastApiScanRequest(BaseModel):
    """Request for API-specific DAST scanning using OpenAPI spec."""
    target_url: str = Field(
        ...,
        description="Base URL of the API to scan",
        max_length=2048,
    )
    openapi_spec: Dict[str, Any] = Field(
        ..., description="OpenAPI 3.x or Swagger 2.x specification"
    )
    headers: Optional[Dict[str, str]] = Field(None, description="Custom HTTP headers")
    cookies: Optional[Dict[str, str]] = Field(None, description="Cookies to include")
    auth: Optional[AuthConfigRequest] = Field(None, description="Authentication configuration")

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target_url cannot be empty")
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        if not _is_safe_url(v):
            raise ValueError("target_url points to an internal/restricted network address")
        return v

    @field_validator("openapi_spec")
    @classmethod
    def validate_spec(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if "paths" not in v:
            raise ValueError("OpenAPI spec must contain 'paths'")
        return v


def _build_auth_config(auth_req: Optional[AuthConfigRequest]) -> "AuthSessionConfig | None":
    """Convert router AuthConfigRequest to engine AuthSessionConfig."""
    if not auth_req or auth_req.mode == "none":
        return None
    from core.dast_engine import AuthMode, AuthSessionConfig
    return AuthSessionConfig(
        mode=AuthMode(auth_req.mode),
        bearer_token=auth_req.bearer_token or "",
        basic_username=auth_req.basic_username or "",
        basic_password=auth_req.basic_password or "",
        api_key_header=auth_req.api_key_header or "X-API-Key",
        api_key_value=auth_req.api_key_value or "",
        login_url=auth_req.login_url or "",
        username_field=auth_req.username_field or "username",
        password_field=auth_req.password_field or "password",
        login_username=auth_req.login_username or "",
        login_password=auth_req.login_password or "",
        extra_form_fields=auth_req.extra_form_fields or {},
        success_indicator=auth_req.success_indicator or "",
        failure_indicator=auth_req.failure_indicator or "",
        token_url=auth_req.token_url or "",
        client_id=auth_req.client_id or "",
        client_secret=auth_req.client_secret or "",
        scope=auth_req.scope or "",
        session_check_url=auth_req.session_check_url or "",
        session_check_pattern=auth_req.session_check_pattern or "",
        reauth_on_401=auth_req.reauth_on_401,
    )


@router.post("/scan")
async def dast_scan(req: DastScanRequest) -> Dict[str, Any]:
    """Launch a DAST scan against a live target.

    SSRF Protection: Internal network addresses are blocked.
    Supports authenticated scanning via Bearer, Basic, API Key, Form Login, OAuth2.
    """
    # Additional header count validation
    if req.headers and len(req.headers) > _MAX_HEADERS:
        raise HTTPException(
            400, f"Too many custom headers: {len(req.headers)} (max {_MAX_HEADERS})"
        )

    from core.dast_engine import get_dast_engine

    engine = get_dast_engine()
    auth_config = _build_auth_config(req.auth)
    try:
        result = await engine.scan(
            target_url=req.target_url,
            headers=req.headers,
            cookies=req.cookies,
            crawl=req.crawl,
            max_depth=req.max_depth,
            auth_config=auth_config,
        )
        return result.to_dict()
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.exception("DAST scan failed for target %s", req.target_url)
        raise HTTPException(500, f"Scan failed: {type(e).__name__}")


@router.post("/scan/api")
async def dast_api_scan(req: DastApiScanRequest) -> Dict[str, Any]:
    """Launch an API-specific DAST scan using an OpenAPI/Swagger specification.

    Tests each endpoint for injection, auth bypass, error handling, and misconfig.
    """
    from core.dast_engine import get_dast_engine

    engine = get_dast_engine()
    auth_config = _build_auth_config(req.auth)
    try:
        result = await engine.scan_api(
            target_url=req.target_url,
            openapi_spec=req.openapi_spec,
            headers=req.headers,
            cookies=req.cookies,
            auth_config=auth_config,
        )
        return result.to_dict()
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        logger.exception("DAST API scan failed for target %s", req.target_url)
        raise HTTPException(500, f"API scan failed: {type(e).__name__}")


@router.get("/auth-modes")
async def dast_auth_modes() -> Dict[str, Any]:
    """List supported DAST authentication modes."""
    return {
        "modes": [
            {"id": "none", "name": "No Authentication", "description": "Unauthenticated scan"},
            {"id": "bearer", "name": "Bearer Token", "description": "JWT or OAuth2 Bearer token in Authorization header"},
            {"id": "basic", "name": "Basic Auth", "description": "HTTP Basic Authentication (username:password)"},
            {"id": "api_key", "name": "API Key", "description": "API key sent in a custom header"},
            {"id": "form_login", "name": "Form Login", "description": "Automated login form submission with session cookie persistence"},
            {"id": "cookie", "name": "Cookie", "description": "Cookies provided directly (pre-authenticated session)"},
            {"id": "oauth2", "name": "OAuth2 Client Credentials", "description": "OAuth2 client_credentials flow for machine-to-machine auth"},
        ],
    }


@router.get("/status")
async def dast_status() -> Dict[str, Any]:
    return {
        "engine": "dast",
        "status": "ready",
        "version": "2.0.0",
        "features": [
            "authenticated_scanning",
            "openapi_api_scanning",
            "form_login_automation",
            "session_persistence",
            "auth_bypass_detection",
        ],
    }


@router.get("/health")
async def dast_health() -> Dict[str, Any]:
    """DAST engine health check (alias for /status)."""
    return await dast_status()
