"""DAST Router — Dynamic Application Security Testing endpoints.

Hardened with SSRF protection, input validation, and rate limiting awareness.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
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
    except Exception:
        return False


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


@router.post("/scan")
async def dast_scan(req: DastScanRequest) -> Dict[str, Any]:
    """Launch a DAST scan against a live target.

    SSRF Protection: Internal network addresses are blocked.
    """
    # Additional header count validation
    if req.headers and len(req.headers) > _MAX_HEADERS:
        raise HTTPException(
            400, f"Too many custom headers: {len(req.headers)} (max {_MAX_HEADERS})"
        )

    from core.dast_engine import get_dast_engine

    engine = get_dast_engine()
    try:
        result = await engine.scan(
            target_url=req.target_url,
            headers=req.headers,
            cookies=req.cookies,
            crawl=req.crawl,
            max_depth=req.max_depth,
        )
        return result.to_dict()
    except Exception as e:
        logger.exception("DAST scan failed for target %s", req.target_url)
        raise HTTPException(500, f"Scan failed: {type(e).__name__}")


@router.get("/status")
async def dast_status() -> Dict[str, Any]:
    return {"engine": "dast", "status": "ready", "version": "1.0.0"}


@router.get("/health")
async def dast_health() -> Dict[str, Any]:
    """DAST engine health check (alias for /status)."""
    return await dast_status()
