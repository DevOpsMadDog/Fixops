"""Tests for GET /api/v1/admin/db/stats endpoint."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import pathlib
from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers — build a minimal FastAPI app with just the router under test
# ---------------------------------------------------------------------------

def _make_app(api_key: str = "test-key") -> FastAPI:
    """Return a minimal FastAPI app with the admin_db router mounted."""
    # Patch api_key_auth to accept our test key
    import apps.api.admin_db_router as mod

    app = FastAPI()

    # Override api_key_auth so we can control auth in tests
    from fastapi.security import APIKeyHeader
    from fastapi import Security, HTTPException

    _header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def _test_auth(key: str = Security(_header)):
        if key != api_key:
            raise HTTPException(status_code=401, detail="Invalid API key")

    # Re-include router with our test dependency override
    from fastapi import APIRouter, Depends
    from apps.api import admin_db_router as dbmod

    # Build a fresh router referencing the same handler but with patched dep
    test_router = APIRouter(prefix="/api/v1/admin/db", tags=["admin"])

    @test_router.get("/stats", dependencies=[Depends(_test_auth)])
    async def _stats():
        return await dbmod.db_stats()

    app.include_router(test_router)
    return app


TEST_KEY = "test-key-aldeci"


@pytest.fixture(scope="module")
def client():
    app = _make_app(api_key=TEST_KEY)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_db_stats_requires_auth(client: TestClient):
    """Endpoint must reject requests with no API key (401)."""
    resp = client.get("/api/v1/admin/db/stats")
    assert resp.status_code == 401


def test_db_stats_returns_200_with_key(client: TestClient):
    """Endpoint returns 200 when a valid API key is supplied."""
    resp = client.get(
        "/api/v1/admin/db/stats",
        headers={"X-API-Key": TEST_KEY},
    )
    assert resp.status_code == 200


def test_db_stats_response_shape(client: TestClient):
    """Response dict must contain databases, total_size_bytes, total_rows, count."""
    resp = client.get(
        "/api/v1/admin/db/stats",
        headers={"X-API-Key": TEST_KEY},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "databases" in body
    assert "total_size_bytes" in body
    assert "total_rows" in body
    assert "count" in body
    assert isinstance(body["databases"], list)
    assert isinstance(body["total_size_bytes"], int)
    assert isinstance(body["total_rows"], int)
    assert isinstance(body["count"], int)


def test_db_stats_empty_data_dir(tmp_path):
    """When data/ does not exist the endpoint returns zero counts."""
    import asyncio
    import apps.api.admin_db_router as mod

    # Run the handler with cwd pointing to a dir with no data/ subdir
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = asyncio.run(mod.db_stats())
    finally:
        os.chdir(original_cwd)

    assert result["count"] == 0
    assert result["total_size_bytes"] == 0
    assert result["total_rows"] == 0
    assert result["databases"] == []
