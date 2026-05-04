"""Tests for GET /api/v1/admin/connectors/inventory."""

from __future__ import annotations

import pytest
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from fastapi.testclient import TestClient

TEST_KEY = "test-key-aldeci"

# ---------------------------------------------------------------------------
# Minimal app — avoids the full create_app() Pydantic recursion issue
# ---------------------------------------------------------------------------

def _make_app(api_key: str = TEST_KEY) -> FastAPI:
    """Minimal FastAPI app with only the connectors inventory router."""
    import apps.api.admin_connectors_router as mod

    _header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def _test_auth(key: str = Security(_header)):
        if key != api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")

    test_router = APIRouter(prefix="/api/v1/admin/connectors", tags=["admin"])

    @test_router.get("/inventory", dependencies=[Depends(_test_auth)])
    async def _inventory():
        return await mod.connector_inventory()

    app = FastAPI()
    app.include_router(test_router)
    return app


@pytest.fixture(scope="module")
def client():
    return TestClient(_make_app(), raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_inventory_requires_auth(client: TestClient):
    """Endpoint must return 401 when no API key is supplied."""
    resp = client.get("/api/v1/admin/connectors/inventory")
    assert resp.status_code == 401, (
        f"Expected 401 without auth, got {resp.status_code}"
    )


def test_inventory_returns_200_with_key(client: TestClient):
    """Endpoint must return 200 when a valid API key is provided."""
    resp = client.get(
        "/api/v1/admin/connectors/inventory",
        headers={"X-API-Key": TEST_KEY},
    )
    assert resp.status_code == 200, (
        f"Expected 200, got {resp.status_code}: {resp.text}"
    )


def test_inventory_response_shape(client: TestClient):
    """Response must include 'connectors' list and matching 'count' integer."""
    resp = client.get(
        "/api/v1/admin/connectors/inventory",
        headers={"X-API-Key": TEST_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "connectors" in body, "Response missing 'connectors' key"
    assert "count" in body, "Response missing 'count' key"
    assert isinstance(body["connectors"], list), "'connectors' must be a list"
    assert isinstance(body["count"], int), "'count' must be an int"
    assert body["count"] == len(body["connectors"]), (
        "'count' must equal len(connectors)"
    )
    # Spot-check shape of successfully loaded entries
    for entry in body["connectors"]:
        if "error" not in entry:
            for key in ("name", "module", "doc", "methods"):
                assert key in entry, f"Entry missing '{key}': {entry}"
            assert isinstance(entry["methods"], list), (
                f"'methods' must be a list: {entry}"
            )
