"""Router-level tests for zero_trust_policy_router.

Tests the HTTP layer (GET /, CRUD, evaluate, stats, compliance) using
FastAPI TestClient with a temp-DB engine override. No mocks — real engine.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.zero_trust_policy_router import router
from apps.api.auth_deps import api_key_auth
from core.zero_trust_policy_engine import ZeroTrustPolicyEngine
import apps.api.zero_trust_policy_router as _router_mod


def _make_client(tmp_path, monkeypatch, eng=None):
    """Return a TestClient with auth bypassed and an isolated engine."""
    if eng is None:
        eng = ZeroTrustPolicyEngine(db_path=str(tmp_path / "zt_router_test.db"))
    monkeypatch.setattr(_router_mod, "_engine", lambda: eng)

    app = FastAPI()
    app.include_router(router)
    # Override FastAPI dependency so auth is skipped
    app.dependency_overrides[api_key_auth] = lambda: None
    return TestClient(app), eng


# ---------------------------------------------------------------------------
# GET /  — root summary
# ---------------------------------------------------------------------------


def test_get_summary_empty(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/zero-trust-policy/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "zero-trust-policy"
    assert body["total_policies"] == 0
    assert body["enabled_policies"] == 0
    assert body["zt_maturity_score"] == 0
    # always has at least 1 recommendation when no policies exist
    assert body["top_recommendation"] is not None


def test_get_summary_reflects_created_policies(tmp_path, monkeypatch):
    client, eng = _make_client(tmp_path, monkeypatch)
    eng.create_policy("default", {"name": "Block all", "policy_type": "network", "action": "deny"})
    eng.create_policy("default", {"name": "MFA identity", "policy_type": "identity", "action": "mfa_required"})

    resp = client.get("/api/v1/zero-trust-policy/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_policies"] == 2
    assert body["enabled_policies"] == 2
    assert body["zt_maturity_score"] > 0


# ---------------------------------------------------------------------------
# POST /policies + GET /policies
# ---------------------------------------------------------------------------


def test_create_and_list_policy(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    payload = {
        "name": "Deny BYOD",
        "policy_type": "device",
        "action": "deny",
        "priority": 10,
    }
    create_resp = client.post("/api/v1/zero-trust-policy/policies", json=payload)
    assert create_resp.status_code == 201
    created = create_resp.json()
    assert created["name"] == "Deny BYOD"
    assert created["policy_type"] == "device"
    assert created["action"] == "deny"
    assert created["policy_id"]

    list_resp = client.get("/api/v1/zero-trust-policy/policies")
    assert list_resp.status_code == 200
    policies = list_resp.json()
    assert len(policies) == 1
    assert policies[0]["policy_id"] == created["policy_id"]


def test_create_policy_invalid_type_returns_422(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/zero-trust-policy/policies",
        json={"name": "Bad", "policy_type": "quantum", "action": "deny"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# POST /evaluate
# ---------------------------------------------------------------------------


def test_evaluate_no_policies_defaults_allow(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/v1/zero-trust-policy/evaluate",
        json={"user": "alice", "resource": "/api/data", "org_id": "default"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["matched_policy_id"] is None


# ---------------------------------------------------------------------------
# GET /stats
# ---------------------------------------------------------------------------


def test_stats_empty(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/zero-trust-policy/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_policies"] == 0
    assert "allow_rate" in body
    assert "deny_rate" in body


# ---------------------------------------------------------------------------
# GET /compliance
# ---------------------------------------------------------------------------


def test_compliance_posture_structure(tmp_path, monkeypatch):
    client, _ = _make_client(tmp_path, monkeypatch)
    resp = client.get("/api/v1/zero-trust-policy/compliance")
    assert resp.status_code == 200
    body = resp.json()
    assert "zt_maturity_score" in body
    assert "pillars" in body
    pillars = body["pillars"]
    assert set(pillars.keys()) == {"identity", "device", "network", "application", "data"}
    assert isinstance(body["recommendations"], list)
    assert len(body["recommendations"]) > 0
