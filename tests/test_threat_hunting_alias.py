"""Tests for /api/v1/threat-hunting alias router.

Verifies that the UI-facing prefix /api/v1/threat-hunting/stats and
/api/v1/threat-hunting/hunts are reachable and return valid JSON,
so ThreatHuntingDashboard.tsx gets real data instead of a 404.
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

# Use the canonical token from conftest (it's already in os.environ by the
# time this module loads, since conftest.py sets it unconditionally).
_API_TOKEN = os.environ.get(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
_HEADERS = {"X-API-Key": _API_TOKEN}


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_threat_hunting_alias_routes_registered():
    """Both alias routes must appear in the alias router's route table."""
    from apps.api.threat_hunting_router import threat_hunting_alias
    paths = {r.path for r in threat_hunting_alias.routes if hasattr(r, "path")}
    assert "/api/v1/threat-hunting/stats" in paths
    assert "/api/v1/threat-hunting/hunts" in paths


def test_threat_hunting_alias_stats(client: TestClient):
    """/api/v1/threat-hunting/stats must return 200 with a dict."""
    resp = client.get("/api/v1/threat-hunting/stats", headers=_HEADERS)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert isinstance(resp.json(), dict)


def test_threat_hunting_alias_hunts(client: TestClient):
    """/api/v1/threat-hunting/hunts must return 200 with a list."""
    resp = client.get("/api/v1/threat-hunting/hunts", headers=_HEADERS)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert isinstance(resp.json(), list)
