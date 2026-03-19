"""Tests for SecurityHeadersMiddleware — verifies OWASP-recommended headers are set.

Compliance mapping:
- SOC2 CC6.1 (Logical Access Security)
- PCI-DSS Req 6.5.9 (Cross-Site Request Forgery)
- OWASP A05:2021 (Security Misconfiguration)
"""

import pytest
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI

import sys
import os

# Ensure suite paths are available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))


@pytest.fixture
def app_with_security_headers():
    """Create a minimal FastAPI app with SecurityHeadersMiddleware."""
    from apps.api.middleware import SecurityHeadersMiddleware

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"status": "ok"}

    @app.get("/api/v1/health")
    async def health():
        return {"healthy": True}

    return app


@pytest.mark.asyncio
async def test_x_content_type_options(app_with_security_headers):
    """X-Content-Type-Options must be 'nosniff' to prevent MIME sniffing."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        assert resp.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_x_frame_options(app_with_security_headers):
    """X-Frame-Options must be 'DENY' to prevent clickjacking."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        assert resp.headers.get("x-frame-options") == "DENY"


@pytest.mark.asyncio
async def test_referrer_policy(app_with_security_headers):
    """Referrer-Policy must be set to prevent information leakage."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


@pytest.mark.asyncio
async def test_permissions_policy(app_with_security_headers):
    """Permissions-Policy must restrict browser feature access."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        pp = resp.headers.get("permissions-policy")
        assert pp is not None
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp


@pytest.mark.asyncio
async def test_cache_control(app_with_security_headers):
    """Cache-Control must prevent caching of sensitive API data."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        cc = resp.headers.get("cache-control")
        assert cc is not None
        assert "no-store" in cc


@pytest.mark.asyncio
async def test_x_permitted_cross_domain(app_with_security_headers):
    """X-Permitted-Cross-Domain-Policies must be 'none'."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        assert resp.headers.get("x-permitted-cross-domain-policies") == "none"


@pytest.mark.asyncio
async def test_pragma_no_cache(app_with_security_headers):
    """Pragma header must be set to no-cache for HTTP/1.0 compatibility."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        assert resp.headers.get("pragma") == "no-cache"


@pytest.mark.asyncio
async def test_content_security_policy(app_with_security_headers):
    """Content-Security-Policy must restrict resource loading (XSS prevention)."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        csp = resp.headers.get("content-security-policy")
        assert csp is not None, "Missing Content-Security-Policy header"
        assert "default-src" in csp
        assert "frame-ancestors 'none'" in csp


@pytest.mark.asyncio
async def test_x_xss_protection(app_with_security_headers):
    """X-XSS-Protection must be set for legacy browser XSS filtering."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        xss = resp.headers.get("x-xss-protection")
        assert xss is not None, "Missing X-XSS-Protection header"
        assert "1; mode=block" in xss


@pytest.mark.asyncio
async def test_all_security_headers_present(app_with_security_headers):
    """Comprehensive check: all 9 security headers must be present on every response."""
    expected_headers = [
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "cache-control",
        "x-permitted-cross-domain-policies",
        "content-security-policy",
        "x-xss-protection",
    ]
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/test")
        for header in expected_headers:
            assert header in resp.headers, f"Missing security header: {header}"


@pytest.mark.asyncio
async def test_headers_on_health_endpoint(app_with_security_headers):
    """Security headers must be present even on health check endpoints."""
    async with AsyncClient(
        transport=ASGITransport(app=app_with_security_headers),
        base_url="http://test",
    ) as client:
        resp = await client.get("/api/v1/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
