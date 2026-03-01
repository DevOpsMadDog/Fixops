"""Tests for health and status endpoint aliases across all routers.

Every router MUST have both /health and /status endpoints returning 200.
This is a DEMO-001 requirement for the enterprise demo.

Run with:
    PYTHONPATH=suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations \
    python -m pytest tests/test_health_status_endpoints.py -v --timeout=30
"""

from __future__ import annotations

import os
import pytest

# Set API token BEFORE importing the app
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-for-e2e")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from httpx import ASGITransport, AsyncClient

from apps.api.app import create_app

_TEST_TOKEN = os.environ["FIXOPS_API_TOKEN"]
_HEADERS = {"X-API-Key": _TEST_TOKEN}


@pytest.fixture(scope="module")
def app():
    """Create the FastAPI app once for all tests."""
    return create_app()


@pytest.fixture()
async def client(app):
    """Async HTTP client for testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Core security scanner routers — MUST have both /health and /status
# ---------------------------------------------------------------------------

_SCANNER_PATHS = [
    ("SAST", "/api/v1/sast"),
    ("DAST", "/api/v1/dast"),
    ("Secrets", "/api/v1/secrets"),
    ("Container", "/api/v1/container"),
    ("CSPM", "/api/v1/cspm"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _SCANNER_PATHS)
async def test_scanner_health(client, name, prefix):
    """Each scanner MUST have a /health endpoint."""
    resp = await client.get(f"{prefix}/health", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /health returned {resp.status_code}"
    data = resp.json()
    assert "status" in data, f"{name} /health missing 'status' key"


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _SCANNER_PATHS)
async def test_scanner_status(client, name, prefix):
    """Each scanner MUST have a /status endpoint."""
    resp = await client.get(f"{prefix}/status", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /status returned {resp.status_code}"
    data = resp.json()
    assert "status" in data or "engine" in data, f"{name} /status missing key fields"


# ---------------------------------------------------------------------------
# Core intelligence routers
# ---------------------------------------------------------------------------

_INTELLIGENCE_PATHS = [
    ("Brain", "/api/v1/brain"),
    ("AutoFix", "/api/v1/autofix"),
    ("FAIL", "/api/v1/fail"),
    ("Knowledge Graph", "/api/v1/knowledge-graph"),
    ("Feeds", "/api/v1/feeds"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _INTELLIGENCE_PATHS)
async def test_intelligence_health(client, name, prefix):
    resp = await client.get(f"{prefix}/health", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /health returned {resp.status_code}"


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _INTELLIGENCE_PATHS)
async def test_intelligence_status(client, name, prefix):
    resp = await client.get(f"{prefix}/status", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /status returned {resp.status_code}"


# ---------------------------------------------------------------------------
# Attack routers
# ---------------------------------------------------------------------------

_ATTACK_PATHS = [
    ("MPTE", "/api/v1/mpte"),
    ("Micro Pentest", "/api/v1/micro-pentest"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _ATTACK_PATHS)
async def test_attack_health(client, name, prefix):
    resp = await client.get(f"{prefix}/health", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /health returned {resp.status_code}"


@pytest.mark.asyncio
@pytest.mark.parametrize("name,prefix", _ATTACK_PATHS)
async def test_attack_status(client, name, prefix):
    resp = await client.get(f"{prefix}/status", headers=_HEADERS)
    assert resp.status_code == 200, f"{name} /status returned {resp.status_code}"


# ---------------------------------------------------------------------------
# Root-level endpoints (no auth needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_root_health(client):
    """Legacy /health endpoint must work without auth."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_api_v1_health(client):
    """/api/v1/health must work without auth."""
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_openapi_json(client):
    """/openapi.json must return 200 with valid JSON schema."""
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "paths" in data
    assert len(data["paths"]) > 600, f"Only {len(data['paths'])} paths (expected 600+)"


# ---------------------------------------------------------------------------
# Health/Status response contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_response_has_status_field(client):
    """All health endpoints must return a JSON object with 'status' key."""
    paths = [
        "/api/v1/brain/health",
        "/api/v1/autofix/health",
        "/api/v1/fail/health",
        "/api/v1/sast/health",
        "/api/v1/dast/health",
    ]
    for path in paths:
        resp = await client.get(path, headers=_HEADERS)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        data = resp.json()
        assert "status" in data, f"{path} response missing 'status': {data}"
