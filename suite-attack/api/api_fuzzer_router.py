"""API Fuzzer Router — API Discovery & Fuzzing endpoints.

Security hardening:
- SSRF prevention on base_url (blocks RFC1918, localhost, link-local, metadata)
- max_per_endpoint bounded to [1, 100] to prevent DoS
- Header count limit (50 max)
- URL length limit (2048 chars)
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/api-fuzzer", tags=["API Fuzzer"])

# ---------------------------------------------------------------------------
# SSRF blocklist — prevent scanning internal services
# ---------------------------------------------------------------------------
_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",  # nosec B104 — SSRF blocklist, not a bind call
    "metadata.google.internal", "169.254.169.254",
})


def _is_private_ip(host: str) -> bool:
    """Check if host resolves to a private/reserved IP."""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


def _validate_fuzz_url(url: str) -> str:
    """Validate URL for SSRF prevention."""
    if len(url) > 2048:
        raise ValueError("URL exceeds 2048 character limit")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https schemes allowed")
    host = parsed.hostname or ""
    if host.lower() in _BLOCKED_HOSTS:
        raise ValueError("Target host is blocked")
    if _is_private_ip(host):
        raise ValueError("Private/reserved IP addresses are blocked")
    return url


class DiscoverRequest(BaseModel):
    openapi_spec: Dict[str, Any]


class FuzzRequest(BaseModel):
    base_url: str
    openapi_spec: Dict[str, Any]
    headers: Optional[Dict[str, str]] = None
    max_per_endpoint: int = 5

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        return _validate_fuzz_url(v)

    @field_validator("max_per_endpoint")
    @classmethod
    def validate_max_per_endpoint(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_per_endpoint must be >= 1")
        if v > 100:
            raise ValueError("max_per_endpoint must be <= 100")
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if v is not None and len(v) > 50:
            raise ValueError("Too many headers (max 50)")
        return v


@router.post("/discover")
async def discover_endpoints(req: DiscoverRequest) -> Dict[str, Any]:
    """Discover API endpoints from an OpenAPI/Swagger spec."""
    from core.api_fuzzer import get_api_fuzzer_engine

    engine = get_api_fuzzer_engine()
    endpoints = engine.discover_from_openapi(req.openapi_spec)
    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "total": len(endpoints),
    }


@router.post("/fuzz")
async def fuzz_endpoints(req: FuzzRequest) -> Dict[str, Any]:
    """Discover and fuzz API endpoints."""
    from core.api_fuzzer import get_api_fuzzer_engine

    engine = get_api_fuzzer_engine()
    endpoints = engine.discover_from_openapi(req.openapi_spec)
    result = await engine.fuzz_endpoints(
        base_url=req.base_url,
        endpoints=endpoints,
        headers=req.headers,
        max_per_endpoint=req.max_per_endpoint,
    )
    return result.to_dict()


@router.get("/health")
async def fuzzer_health() -> Dict[str, Any]:
    """Health check for API fuzzer engine."""
    return {"status": "healthy", "engine": "api_fuzzer", "version": "1.0.0"}


@router.get("/status")
async def fuzzer_status() -> Dict[str, Any]:
    """Status check for API fuzzer engine."""
    return {"status": "healthy", "engine": "api_fuzzer", "version": "1.0.0"}
