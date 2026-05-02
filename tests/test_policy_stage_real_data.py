"""Beast Mode — Policy Stage Matrix Real-Data Tests (batch 4).

Domain: Policy Enforcement / CTEM Stage Matrix (wave_d_integrations_router)
Endpoints under test:
  1. POST /api/v1/policies/{id}/stage-matrix  — set CTEM stage opt-in matrix
  2. GET  /api/v1/policies/{id}/stage-matrix  — retrieve stage matrix for a policy
  3. POST /api/v1/evaluate?stage=<stage>      — evaluate context against stage-aware policies
  4. GET  /api/v1/waivers                     — list waivers (optionally auto-only)

All assertions hit the real PolicyEnforcementEngine (SQLite-backed); zero MOCK_ constants.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Add suite paths
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app():
    """Build a minimal FastAPI test app with auth bypassed."""
    from apps.api.auth_deps import api_key_auth
    from apps.api.wave_d_integrations_router import router

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: None
    return app


def _create_policy(org_id: str = "batch4-test") -> str:
    """Create a real policy via engine and return its ID."""
    from core.policy_enforcement_engine import get_engine
    eng = get_engine(org_id)
    p = eng.create_policy(org_id, {
        "name": "batch4-stage-policy",
        "description": "batch 4 stage matrix test",
        "rule_type": "block",
        "conditions": {},
        "policy_domain": "network",
    })
    return p["id"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    return TestClient(_make_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def policy_id():
    return _create_policy("batch4-stage-org")


# ===========================================================================
# 1. POST /api/v1/policies/{id}/stage-matrix — set stage matrix
# ===========================================================================

class TestSetStageMatrix:
    STAGE_MATRIX = {"ide": True, "pr": True, "build": False, "deploy": False, "runtime": False}

    def test_set_200(self, client, policy_id):
        r = client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": self.STAGE_MATRIX},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 200, r.text

    def test_set_returns_org_id(self, client, policy_id):
        data = client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": self.STAGE_MATRIX},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["org_id"] == "batch4-stage-org"

    def test_set_returns_policy_id(self, client, policy_id):
        data = client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": self.STAGE_MATRIX},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["policy_id"] == policy_id

    def test_set_returns_stage_matrix_key(self, client, policy_id):
        data = client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": self.STAGE_MATRIX},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert "stage_matrix" in data

    def test_set_unknown_policy_404(self, client):
        r = client.post(
            "/api/v1/policies/nonexistent-uuid-xyz/stage-matrix",
            json={"stage_matrix": {"ide": True}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 404

    def test_set_unknown_stage_key_4xx(self, client, policy_id):
        r = client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": {"badstage": True}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        # Pydantic validation rejects unknown stage keys with 422; engine raises 400 as fallback
        assert r.status_code in (400, 422)


# ===========================================================================
# 2. GET /api/v1/policies/{id}/stage-matrix — retrieve stage matrix
# ===========================================================================

class TestGetStageMatrix:
    def test_get_200(self, client, policy_id):
        # Ensure matrix is set first
        client.post(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            json={"stage_matrix": {"ide": True, "pr": False, "build": True, "deploy": False, "runtime": False}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        r = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 200, r.text

    def test_get_returns_org_id(self, client, policy_id):
        data = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["org_id"] == "batch4-stage-org"

    def test_get_returns_policy_id(self, client, policy_id):
        data = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["policy_id"] == policy_id

    def test_get_stage_matrix_is_dict(self, client, policy_id):
        data = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert isinstance(data["stage_matrix"], dict)

    def test_get_stage_matrix_has_all_stages(self, client, policy_id):
        data = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        sm = data["stage_matrix"]
        for stage in ("ide", "pr", "build", "deploy", "runtime"):
            assert stage in sm, f"missing stage: {stage}"

    def test_get_stage_matrix_values_are_bool(self, client, policy_id):
        data = client.get(
            f"/api/v1/policies/{policy_id}/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        for k, v in data["stage_matrix"].items():
            assert isinstance(v, bool), f"stage {k} value is not bool: {v}"

    def test_get_unknown_policy_404(self, client):
        r = client.get(
            "/api/v1/policies/does-not-exist-abc/stage-matrix",
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 404


# ===========================================================================
# 3. POST /api/v1/evaluate?stage=<stage> — evaluate context against policies
# ===========================================================================

class TestEvaluateAtStage:
    def test_evaluate_ide_200(self, client):
        r = client.post(
            "/api/v1/evaluate?stage=ide",
            json={"context": {"severity": "high", "asset_id": "asset-001"}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 200, r.text

    def test_evaluate_pr_200(self, client):
        r = client.post(
            "/api/v1/evaluate?stage=pr",
            json={"context": {"severity": "medium"}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 200

    def test_evaluate_returns_org_id(self, client):
        data = client.post(
            "/api/v1/evaluate?stage=build",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["org_id"] == "batch4-stage-org"

    def test_evaluate_returns_stage(self, client):
        data = client.post(
            "/api/v1/evaluate?stage=deploy",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["stage"] == "deploy"

    def test_evaluate_returns_decision(self, client):
        data = client.post(
            "/api/v1/evaluate?stage=runtime",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["decision"] in ("block", "enforce", "advisory", "allow")

    def test_evaluate_returns_matched_policies(self, client):
        data = client.post(
            "/api/v1/evaluate?stage=ide",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert "matched_policies" in data
        assert isinstance(data["matched_policies"], list)

    def test_evaluate_policy_count_numeric(self, client):
        data = client.post(
            "/api/v1/evaluate?stage=pr",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert isinstance(data["policy_count"], int)
        assert data["policy_count"] >= 0

    def test_evaluate_invalid_stage_400(self, client):
        r = client.post(
            "/api/v1/evaluate?stage=badstage",
            json={"context": {}},
            headers={"X-Org-ID": "batch4-stage-org"},
        )
        assert r.status_code == 400

    def test_evaluate_context_echoed(self, client):
        ctx = {"severity": "critical", "component": "auth-service"}
        data = client.post(
            "/api/v1/evaluate?stage=ide",
            json={"context": ctx},
            headers={"X-Org-ID": "batch4-stage-org"},
        ).json()
        assert data["context"] == ctx


# ===========================================================================
# 4. GET /api/v1/waivers — list waivers
# ===========================================================================

class TestListWaivers:
    def test_waivers_200(self, client):
        r = client.get("/api/v1/waivers", headers={"X-Org-ID": "batch4-stage-org"})
        assert r.status_code == 200, r.text

    def test_waivers_returns_org_id(self, client):
        data = client.get("/api/v1/waivers", headers={"X-Org-ID": "batch4-stage-org"}).json()
        assert data["org_id"] == "batch4-stage-org"

    def test_waivers_returns_count(self, client):
        data = client.get("/api/v1/waivers", headers={"X-Org-ID": "batch4-stage-org"}).json()
        assert "count" in data
        assert isinstance(data["count"], int)
        assert data["count"] >= 0

    def test_waivers_returns_list(self, client):
        data = client.get("/api/v1/waivers", headers={"X-Org-ID": "batch4-stage-org"}).json()
        assert "waivers" in data
        assert isinstance(data["waivers"], list)

    def test_waivers_auto_filter(self, client):
        r = client.get("/api/v1/waivers?auto=true", headers={"X-Org-ID": "batch4-stage-org"})
        assert r.status_code == 200
        data = r.json()
        assert data["auto_only"] is True

    def test_waivers_no_auto_filter(self, client):
        data = client.get("/api/v1/waivers?auto=false", headers={"X-Org-ID": "batch4-stage-org"}).json()
        assert data["auto_only"] is False

    def test_waivers_count_matches_list_len(self, client):
        data = client.get("/api/v1/waivers", headers={"X-Org-ID": "batch4-stage-org"}).json()
        assert data["count"] == len(data["waivers"])

    def test_waivers_limit_param(self, client):
        r = client.get("/api/v1/waivers?limit=10", headers={"X-Org-ID": "batch4-stage-org"})
        assert r.status_code == 200
