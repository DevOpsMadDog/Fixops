"""
Tests for POST /api/v1/policy-engine/evaluate/batch
Covers: response shape, count, invalid scope, empty-inputs validation,
        org isolation, and scope echo.

Router: suite-api/apps/api/policy_engine_router.py
Engine: suite-core/core/policy_engine.py  (evaluate_batch)
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-32chars!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client():
    """Isolated FastAPI TestClient for policy_engine_router with auth bypassed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api.auth_deps import api_key_auth
    from apps.api.policy_engine_router import router

    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. Happy-path: response shape and count
# ---------------------------------------------------------------------------


def test_evaluate_batch_returns_results_list(api_client):
    """Batch of 3 inputs returns 3 evaluations with required keys."""
    payload = {
        "inputs": [
            {"severity": "low"},
            {"severity": "medium"},
            {"severity": "critical"},
        ],
        "scope": "findings",
    }
    resp = api_client.post("/api/v1/policy-engine/evaluate/batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert "total" in data
    assert data["total"] == 3
    assert len(data["results"]) == 3
    for item in data["results"]:
        assert "decision" in item
        assert "matched_rules" in item
        assert "explanation" in item


# ---------------------------------------------------------------------------
# 2. Scope echoed back in response
# ---------------------------------------------------------------------------


def test_evaluate_batch_scope_echoed(api_client):
    """Response envelope echoes the requested scope string."""
    payload = {"inputs": [{"action": "deploy"}], "scope": "deployments"}
    resp = api_client.post("/api/v1/policy-engine/evaluate/batch", json=payload)
    assert resp.status_code == 200
    assert resp.json()["scope"] == "deployments"


# ---------------------------------------------------------------------------
# 3. Invalid scope returns 422
# ---------------------------------------------------------------------------


def test_evaluate_batch_invalid_scope_returns_422(api_client):
    """An unrecognised scope value must be rejected before hitting the engine."""
    payload = {
        "inputs": [{"severity": "high"}],
        "scope": "not_a_real_scope",
    }
    resp = api_client.post("/api/v1/policy-engine/evaluate/batch", json=payload)
    # FastAPI/Pydantic rejects the enum value at request-validation time
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 4. Empty inputs list is rejected
# ---------------------------------------------------------------------------


def test_evaluate_batch_empty_inputs_rejected(api_client):
    """Sending an empty inputs list must fail validation (min_length=1)."""
    payload = {"inputs": [], "scope": "findings"}
    resp = api_client.post("/api/v1/policy-engine/evaluate/batch", json=payload)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 5. Org isolation: results carry the correct org_id
# ---------------------------------------------------------------------------


def test_evaluate_batch_org_id_propagated(api_client):
    """When org_id is supplied it is echoed in the response envelope."""
    payload = {
        "inputs": [{"severity": "low"}, {"severity": "high"}],
        "scope": "findings",
        "org_id": "tenant-acme",
    }
    resp = api_client.post("/api/v1/policy-engine/evaluate/batch", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["org_id"] == "tenant-acme"
    assert data["total"] == 2
