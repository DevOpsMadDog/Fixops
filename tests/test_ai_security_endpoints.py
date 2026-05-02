"""Tests for AI security empty-endpoint wiring — 4 new ai-governance endpoints.

Covers:
  POST /api/v1/ai-governance/rules/context-requirements
  GET  /api/v1/ai-governance/rules/context-requirements
  POST /api/v1/ai-governance/cost/estimate
  POST /api/v1/ai-governance/cost/preflight
"""
from __future__ import annotations

import os

# Must be set before any app imports so auth_deps picks them up.
os.environ["FIXOPS_MODE"] = "enterprise"
os.environ["FIXOPS_API_TOKEN"] = "test-key"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-at-least-32chars!"
os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Mount only the ai_governance router to avoid full create_app() cost."""
    from apps.api.ai_governance_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# X-API-Key is the correct header name per auth_deps.py line 128
AUTH = {"X-API-Key": "test-key"}
ORG = "test-ai-security"


# ---------------------------------------------------------------------------
# POST /rules/context-requirements
# ---------------------------------------------------------------------------

def test_register_rule_context_requirement_created(client):
    resp = client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "owasp-a01-sqli", "tier": "metadata", "max_tokens": 2048},
        headers=AUTH,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["rule_key"] == "owasp-a01-sqli"
    assert data["tier"] == "metadata"
    assert data["max_tokens"] == 2048
    assert "id" in data


def test_register_rule_context_requirement_upsert(client):
    """Second call with same rule_key updates rather than duplicate-creates."""
    client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "owasp-a03-xss", "tier": "targeted", "max_tokens": 4096},
        headers=AUTH,
    )
    resp = client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "owasp-a03-xss", "tier": "full_file", "max_tokens": 8192},
        headers=AUTH,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["tier"] == "full_file"
    assert data["max_tokens"] == 8192


def test_register_rule_context_requirement_invalid_tier(client):
    resp = client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "some-rule", "tier": "invalid_tier", "max_tokens": 1024},
        headers=AUTH,
    )
    assert resp.status_code == 400


def test_register_rule_context_requirement_zero_tokens(client):
    resp = client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "zero-rule", "tier": "metadata", "max_tokens": 0},
        headers=AUTH,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /rules/context-requirements
# ---------------------------------------------------------------------------

def test_list_rule_context_requirements_returns_list(client):
    client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "list-test-rule", "tier": "targeted", "max_tokens": 3000},
        headers=AUTH,
    )
    resp = client.get(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    rule_keys = [r["rule_key"] for r in data]
    assert "list-test-rule" in rule_keys


def test_list_rule_context_requirements_empty_org(client):
    resp = client.get(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": "brand-new-org-xyz"},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# POST /cost/estimate
# ---------------------------------------------------------------------------

def test_cost_estimate_empty_rules(client):
    resp = client.post(
        "/api/v1/ai-governance/cost/estimate",
        params={"org_id": ORG},
        json={"rule_keys": [], "file_count": 1},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total" in data
    assert "by_tier" in data
    assert data["total"]["rules"] == 0
    assert data["total"]["est_cost_usd"] == 0.0


def test_cost_estimate_with_registered_rule(client):
    client.post(
        "/api/v1/ai-governance/rules/context-requirements",
        params={"org_id": ORG},
        json={"rule_key": "cost-test-rule", "tier": "targeted", "max_tokens": 4096},
        headers=AUTH,
    )
    resp = client.post(
        "/api/v1/ai-governance/cost/estimate",
        params={"org_id": ORG},
        json={"rule_keys": ["cost-test-rule", "unknown-rule"], "file_count": 3},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"]["rules"] == 2
    assert data["total"]["est_tokens_in"] > 0
    assert data["total"]["est_cost_usd"] >= 0.0
    assert "targeted" in data["by_tier"]


def test_cost_estimate_invalid_file_count(client):
    resp = client.post(
        "/api/v1/ai-governance/cost/estimate",
        params={"org_id": ORG},
        json={"rule_keys": ["r1"], "file_count": 0},
        headers=AUTH,
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /cost/preflight
# ---------------------------------------------------------------------------

def test_preflight_estimate_returns_summary(client):
    resp = client.post(
        "/api/v1/ai-governance/cost/preflight",
        params={"org_id": ORG},
        json={"rule_keys": ["owasp-a01-sqli", "owasp-a03-xss"], "file_count": 5},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "tier_distribution" in data
    assert "total" in data
    assert "by_tier" in data
    assert data["org_id"] == ORG
    assert data["file_count"] == 5
    assert isinstance(data["summary"], str)
    assert len(data["summary"]) > 10


def test_preflight_estimate_tier_distribution_keys(client):
    resp = client.post(
        "/api/v1/ai-governance/cost/preflight",
        params={"org_id": ORG},
        json={"rule_keys": [], "file_count": 1},
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["tier_distribution"], dict)


def test_preflight_invalid_file_count(client):
    resp = client.post(
        "/api/v1/ai-governance/cost/preflight",
        params={"org_id": ORG},
        json={"rule_keys": [], "file_count": -1},
        headers=AUTH,
    )
    assert resp.status_code == 400
