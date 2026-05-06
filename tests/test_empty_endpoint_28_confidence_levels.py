"""Test #28: GET /api/v1/autofix/confidence-levels wired to AutoFixEngine."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), headers={"X-API-Key": "test-key"})


def test_confidence_levels_returns_200(client):
    resp = client.get("/api/v1/autofix/confidence-levels")
    assert resp.status_code == 200


def test_confidence_levels_has_real_engine_fields(client):
    data = client.get("/api/v1/autofix/confidence-levels").json()
    assert data["status"] == "ok"
    levels = data["levels"]
    assert set(levels.keys()) == {"high", "medium", "low"}
    assert levels["high"]["min_score"] == 0.85
    assert levels["medium"]["min_score"] == 0.60
    assert levels["low"]["min_score"] == 0.0
    # live engine fields — must exist (count comes from engine.get_stats())
    for lvl in levels.values():
        assert "count" in lvl
    assert "total_fixes" in data
    assert "avg_confidence_score" in data
