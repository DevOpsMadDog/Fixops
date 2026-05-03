"""Tests for the Feature Flags API router.

Covers:
  - GET /api/v1/feature-flags           list all / filter by tag
  - GET /api/v1/feature-flags/{key}     evaluate a flag
  - POST /api/v1/feature-flags/{key}/override  set runtime override
  - DELETE /api/v1/feature-flags/{key}/override remove runtime override
  - POST /api/v1/feature-flags/rollout/{key}  evaluate rollout
  - 404 on unknown flag key
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Minimal app fixture — isolate from the full 684-router app to avoid
# TestClient state pollution (see feedback_test_pollution_batch67)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    import apps.api.feature_flags_router as ffr
    from apps.api.auth_deps import api_key_auth

    ffr._runtime_overrides.clear()

    app = FastAPI()
    app.include_router(ffr.router)

    # Override auth dependency so all requests pass without a real API key
    app.dependency_overrides[api_key_auth] = lambda: None

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestListFlags:
    def test_returns_all_flags(self, client):
        resp = client.get("/api/v1/feature-flags")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 30  # registry has 35+ flags

    def test_filter_by_tag(self, client):
        resp = client.get("/api/v1/feature-flags?tag=compliance")
        assert resp.status_code == 200
        data = resp.json()
        assert all("compliance" in f["tags"] for f in data)
        assert len(data) >= 3

    def test_flag_shape(self, client):
        resp = client.get("/api/v1/feature-flags")
        assert resp.status_code == 200
        flag = resp.json()[0]
        assert "key" in flag
        assert "type" in flag
        assert "default" in flag
        assert "description" in flag
        assert "owner" in flag
        assert "overridden" in flag


class TestGetFlag:
    def test_known_bool_flag(self, client):
        resp = client.get("/api/v1/feature-flags/fixops.ops.kill_switch")
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"] == "fixops.ops.kill_switch"
        assert data["type"] == "bool"
        assert data["value"] is False
        assert data["overridden"] is False

    def test_known_string_flag(self, client):
        resp = client.get("/api/v1/feature-flags/fixops.model.risk.default")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "string"
        assert data["value"] == "weighted_scoring_v1"

    def test_unknown_flag_returns_404(self, client):
        resp = client.get("/api/v1/feature-flags/fixops.nonexistent.flag")
        assert resp.status_code == 404

    def test_number_flag(self, client):
        resp = client.get("/api/v1/feature-flags/fixops.ops.rate_limit.requests_per_minute")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "number"
        assert data["value"] == 60


class TestOverride:
    def test_set_and_read_override(self, client):
        import apps.api.feature_flags_router as ffr
        ffr._runtime_overrides.clear()

        # Set override
        resp = client.post(
            "/api/v1/feature-flags/fixops.ops.kill_switch/override",
            json={"value": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["value"] is True
        assert data["overridden"] is True

        # Read it back — flag list should show overridden=True
        resp2 = client.get("/api/v1/feature-flags")
        flag = next(f for f in resp2.json() if f["key"] == "fixops.ops.kill_switch")
        assert flag["overridden"] is True
        assert flag["runtime_value"] is True

    def test_delete_override(self, client):
        import apps.api.feature_flags_router as ffr
        ffr._runtime_overrides["fixops.ops.dry_run"] = True

        resp = client.delete("/api/v1/feature-flags/fixops.ops.dry_run/override")
        assert resp.status_code == 204

        resp2 = client.get("/api/v1/feature-flags/fixops.ops.dry_run")
        assert resp2.json()["overridden"] is False

    def test_delete_nonexistent_override_returns_404(self, client):
        import apps.api.feature_flags_router as ffr
        ffr._runtime_overrides.clear()

        resp = client.delete("/api/v1/feature-flags/fixops.ops.kill_switch/override")
        assert resp.status_code == 404


class TestRollout:
    def test_variant_flag_returns_valid_variant(self, client):
        import apps.api.feature_flags_router as ffr
        ffr._runtime_overrides.clear()

        resp = client.post(
            "/api/v1/feature-flags/rollout/fixops.model.risk.ab_test",
            json={"tenant_id": "tenant-abc-123"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # default is "control" since no overlay configured; consistent hash → default
        assert data["key"] == "fixops.model.risk.ab_test"
        assert isinstance(data["value"], str)
        assert "tenant_id" in data["context"]

    def test_rollout_unknown_flag_returns_404(self, client):
        resp = client.post(
            "/api/v1/feature-flags/rollout/fixops.does.not.exist",
            json={"tenant_id": "tenant-xyz"},
        )
        assert resp.status_code == 404
