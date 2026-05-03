"""
Tests for the two new API Gateway Policy endpoints:
  GET  /api/v1/gateway/           — policy summary root
  DELETE /api/v1/gateway/throttle-policies/{target_id} — remove throttle policy

These tests are isolated: each uses a fresh APIGatewayEngine with a temp-dir
DB prefix so they never interfere with other test state.
"""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-testing-only")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_gateway import APIGatewayEngine, ThrottlePolicy, get_api_gateway_engine
from apps.api.api_gateway_router import router as gateway_router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def isolated_engine(tmp_path):
    """Fresh APIGatewayEngine backed by temp-dir SQLite files."""
    prefix = str(tmp_path / "gw")
    engine = APIGatewayEngine(db_prefix=prefix)
    return engine


@pytest.fixture()
def client(isolated_engine):
    """TestClient wired to the gateway router using the isolated engine."""
    app = FastAPI()
    app.include_router(gateway_router)

    # Override the engine dependency to use our isolated instance
    from apps.api import api_gateway_router as _mod

    original = _mod._engine

    def _patched_engine():
        return isolated_engine

    _mod._engine = _patched_engine
    with TestClient(app) as tc:
        yield tc
    _mod._engine = original


# ---------------------------------------------------------------------------
# GET / tests
# ---------------------------------------------------------------------------


def test_gateway_root_returns_200(client):
    """GET / must return HTTP 200."""
    resp = client.get("/api/v1/gateway/")
    assert resp.status_code == 200


def test_gateway_root_contains_required_keys(client):
    """GET / body must expose service, tier_configs, subsystems, and window metadata."""
    resp = client.get("/api/v1/gateway/")
    body = resp.json()
    for key in ("service", "tier_configs", "subsystems", "windows",
                "request_validation", "supported_api_versions"):
        assert key in body, f"Missing key: {key!r}"


def test_gateway_root_tier_configs_has_all_tiers(client):
    """GET / tier_configs must include free, pro, and enterprise entries."""
    body = client.get("/api/v1/gateway/").json()
    tiers = body["tier_configs"]
    assert set(tiers.keys()) >= {"free", "pro", "enterprise"}


def test_gateway_root_reflects_active_policy_count(client, isolated_engine):
    """GET / active_throttle_policies count increments after upsert."""
    before = client.get("/api/v1/gateway/").json()["active_throttle_policies"]

    policy = ThrottlePolicy(
        target_id="ak_test_root_count",
        target_type="api_key",
        burst_limit=5,
        sustained_limit=20,
        requests_per_minute=20,
        requests_per_hour=200,
        description="test policy",
    )
    isolated_engine.policy_store.upsert_policy(policy)

    after = client.get("/api/v1/gateway/").json()["active_throttle_policies"]
    assert after == before + 1


# ---------------------------------------------------------------------------
# DELETE /throttle-policies/{target_id} tests
# ---------------------------------------------------------------------------


def test_delete_throttle_policy_removes_existing(client, isolated_engine):
    """DELETE /throttle-policies/{id} returns 200 and deleted=True for an existing policy."""
    policy = ThrottlePolicy(
        target_id="ak_to_delete",
        target_type="api_key",
        burst_limit=5,
        sustained_limit=20,
        requests_per_minute=20,
        requests_per_hour=200,
        description="will be deleted",
    )
    isolated_engine.policy_store.upsert_policy(policy)
    isolated_engine.rate_limiter.register_policy(policy)

    resp = client.delete("/api/v1/gateway/throttle-policies/ak_to_delete")
    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted"] is True
    assert body["target_id"] == "ak_to_delete"

    # Confirm it is gone from the store
    assert isolated_engine.policy_store.get_policy("ak_to_delete") is None


def test_delete_throttle_policy_404_when_not_found(client):
    """DELETE /throttle-policies/{id} returns 404 for a non-existent target."""
    resp = client.delete("/api/v1/gateway/throttle-policies/ak_nonexistent_xyz")
    assert resp.status_code == 404
