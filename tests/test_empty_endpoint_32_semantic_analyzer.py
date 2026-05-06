"""Multica #4051 — empty endpoint #32: semantic_analyzer_router mounted.

Verifies that /api/v1/semantic/* endpoints are reachable (not 404)
after semantic_analyzer_router was wired into app.py.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_semantic_stats_reachable(client):
    """GET /api/v1/semantic/stats must not return 404 — router is mounted."""
    resp = client.get("/api/v1/semantic/stats", params={"org_id": "test-org"})
    assert resp.status_code != 404, (
        f"semantic_analyzer_router not mounted — got 404"
    )


def test_semantic_symbols_reachable(client):
    """GET /api/v1/semantic/symbols must not return 404."""
    resp = client.get(
        "/api/v1/semantic/symbols",
        params={"org_id": "test-org", "repo_ref": "test@main"},
    )
    # 404 = not mounted, 422 = mounted but missing required param (also fine)
    assert resp.status_code != 404, (
        f"semantic_analyzer_router symbols not mounted — got 404"
    )
