"""Empty endpoint #15 — GET /api/v1/analytics/ wired to AnalyticsDB.get_dashboard_overview().

Before fix: returned {"router": "analytics", "org_id": ..., "items": [], "count": 0} (hardcoded stub).
After fix: delegates to the live AnalyticsDB and returns real counts.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

API_KEY = "fixops_test_key_ep15"
os.environ["FIXOPS_API_TOKEN"] = API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402

HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def test_analytics_index_returns_200(client: TestClient) -> None:
    """Root index must return HTTP 200."""
    r = client.get("/api/v1/analytics/", headers=HEADERS)
    assert r.status_code == 200, r.text


def test_analytics_index_has_real_fields(client: TestClient) -> None:
    """Response must contain live AnalyticsDB fields, not the hardcoded stub."""
    r = client.get("/api/v1/analytics/", headers=HEADERS)
    data = r.json()
    # Fields injected by get_dashboard_overview()
    assert "total_findings" in data, f"missing total_findings: {data}"
    assert "open_findings" in data, f"missing open_findings: {data}"
    assert "critical_findings" in data, f"missing critical_findings: {data}"
    assert "recent_findings_30d" in data, f"missing recent_findings_30d: {data}"
    assert "timestamp" in data, f"missing timestamp: {data}"
    # Router metadata still present
    assert data.get("router") == "analytics"
    assert "org_id" in data
    # Stub sentinel keys must NOT appear
    assert "items" not in data, "hardcoded stub 'items' key still present"
    assert "count" not in data, "hardcoded stub 'count' key still present"
