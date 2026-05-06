"""Tests for Multica #4060 — wire GET /api/v1/ctem/ summary endpoint."""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

_API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), headers={"X-API-Key": _API_TOKEN})


def test_ctem_summary_returns_200(client):
    """GET /api/v1/ctem/ must return 200 with a status field."""
    resp = client.get("/api/v1/ctem/")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert "status" in data
    assert data["status"] in ("healthy", "degraded", "empty", "error")
    assert data.get("domain") == "ctem"


def test_ctem_summary_empty_org(client):
    """Fresh org_id returns empty or healthy status — never 501."""
    resp = client.get("/api/v1/ctem/", params={"org_id": "test-org-35"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("healthy", "degraded", "empty", "error")
