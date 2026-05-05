"""
Smoke tests for /api/v1/risk-scoring/summary and companion endpoints.

Uses dependency_overrides to bypass auth (same pattern as test_trust_center.py
and test_abuseipdb_summary_endpoint.py), so no real API token is needed.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi.testclient import TestClient

from apps.api.app import create_app
from apps.api.auth_deps import api_key_auth, verify_api_key


def _no_auth():
    """Auth override: always passes, returns None."""
    return None


@pytest.fixture(scope="module")
def client():
    app = create_app()
    # The risk_scoring router is mounted via app.include_router(..., dependencies=[Depends(verify_api_key)])
    # so we must override verify_api_key (module-level) AND api_key_auth (router-level dep).
    app.dependency_overrides[verify_api_key] = _no_auth
    app.dependency_overrides[api_key_auth] = _no_auth
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# GET /api/v1/risk-scoring/summary
# ---------------------------------------------------------------------------


def test_summary_without_auth_returns_401() -> None:
    """Endpoint must reject unauthenticated requests with 401 (no override)."""
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/v1/risk-scoring/summary")
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text[:200]}"


def test_summary_returns_200(client: TestClient) -> None:
    """Authenticated GET returns HTTP 200."""
    r = client.get("/api/v1/risk-scoring/summary")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:300]}"


def test_summary_shape(client: TestClient) -> None:
    """Response contains required top-level keys."""
    r = client.get("/api/v1/risk-scoring/summary")
    assert r.status_code == 200
    body = r.json()
    required_keys = {
        "org_id",
        "total",
        "exposure_score",
        "rating",
        "by_severity",
        "last_updated",
    }
    missing = required_keys - set(body.keys())
    assert not missing, f"Missing keys in summary response: {missing}"


def test_summary_org_id_param(client: TestClient) -> None:
    """?org_id query param is reflected in the response."""
    r = client.get("/api/v1/risk-scoring/summary", params={"org_id": "test-tenant"})
    assert r.status_code == 200
    assert r.json()["org_id"] == "test-tenant"


def test_summary_by_severity_structure(client: TestClient) -> None:
    """by_severity must contain critical/high/medium/low numeric keys."""
    r = client.get("/api/v1/risk-scoring/summary")
    body = r.json()
    sev = body.get("by_severity", {})
    for key in ("critical", "high", "medium", "low"):
        assert key in sev, f"by_severity missing key: {key}"
        assert isinstance(sev[key], (int, float)), f"by_severity[{key}] not numeric"


# ---------------------------------------------------------------------------
# GET /api/v1/risk-scoring/exposure/org
# ---------------------------------------------------------------------------


def test_exposure_org_returns_200(client: TestClient) -> None:
    r = client.get("/api/v1/risk-scoring/exposure/org")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


# ---------------------------------------------------------------------------
# GET /api/v1/risk-scoring/exposure/trend
# ---------------------------------------------------------------------------


def test_exposure_trend_returns_200(client: TestClient) -> None:
    r = client.get("/api/v1/risk-scoring/exposure/trend")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}: {r.text[:200]}"


def test_exposure_trend_shape(client: TestClient) -> None:
    r = client.get("/api/v1/risk-scoring/exposure/trend")
    assert r.status_code == 200
    body = r.json()
    assert "org_id" in body, f"Missing org_id in trend response: {body.keys()}"
    assert "trend" in body, f"Missing trend in trend response: {body.keys()}"
    assert isinstance(body["trend"], list)
