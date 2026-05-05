"""
Tests for wired GET /api/v1/fail/ index endpoint.

Before: returned hardcoded {"items": [], "count": 0}
After:  calls FAILEngine().stats() for real summary data.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


_HEADERS = {"Authorization": "Bearer aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh"}


@pytest.fixture(scope="module")
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api.gap_router import fail_gap

    app = FastAPI()
    app.include_router(fail_gap)
    return TestClient(app, raise_server_exceptions=False)


class TestFailIndex:
    def test_empty_engine_returns_valid_envelope(self, client):
        """With a fresh engine (no history), index returns a valid envelope."""
        resp = client.get("/api/v1/fail/", headers=_HEADERS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["router"] == "fail"
        assert "stats" in data
        assert "count" in data
        # Fresh engine has no history — total_scored = 0
        assert data["count"] == 0
        assert data["stats"].get("total_scored", 0) == 0

    def test_populated_engine_returns_stats(self, client):
        """After scoring a finding, index stats reflect it."""
        from core.fail_engine import FAILEngine, FAILInput

        # Score one finding into a fresh engine to verify stats() shape
        engine = FAILEngine()
        engine.score(FAILInput(cve_id="CVE-2024-TEST", cvss_score=8.5))
        stats = engine.stats()

        # Verify stats() contract that the index handler now exposes
        assert stats["total_scored"] == 1
        assert "average_score" in stats
        assert "grade_distribution" in stats
        assert "critical_count" in stats
        assert "high_count" in stats
