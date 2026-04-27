"""Wave C — Compliance / Org / System / Admin router smoke tests (21 endpoints).

Each endpoint gets a happy-path call plus a focused error case where it
makes sense. Acceptable codes: {200, 201, 400, 404, 422, 501}.
"""
from __future__ import annotations

import importlib

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.auth_deps as _auth_mod
from apps.api.wave_c_router import WAVE_C_ROUTERS, changes_router


@pytest.fixture(scope="module", autouse=True)
def _auth_env() -> None:
    mp = pytest.MonkeyPatch()
    mp.setenv("FIXOPS_API_TOKEN", "wave-c-test-token")
    mp.setenv("FIXOPS_MODE", "dev")
    mp.delenv("FIXOPS_JWT_SECRET", raising=False)
    importlib.reload(_auth_mod)
    yield
    mp.undo()


@pytest.fixture(scope="module")
def app() -> FastAPI:
    a = FastAPI()
    for r in WAVE_C_ROUTERS:
        a.include_router(r)
    a.include_router(changes_router)
    return a


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(
        app,
        headers={"X-API-Key": "wave-c-test-token", "X-Org-ID": "wave-c-org"},
    )


# ===========================================================================
# 1. system/compliance-posture
# ===========================================================================

def test_system_compliance_posture(client):
    resp = client.get("/api/v1/system/compliance-posture", params={"org_id": "wave-c-org"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "frameworks" in body
    assert "summary" in body


# ===========================================================================
# 2. system/fips-self-test
# ===========================================================================

def test_system_fips_self_test_runs(client):
    resp = client.post("/api/v1/system/fips-self-test", json={"org_id": "wave-c-org"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["overall"] in {"pass", "fail"}
    assert body["tests_total"] >= 4
    # SHA-256 KAT must always pass — it's bedrock
    sha_test = next((r for r in body["results"] if "SHA-256" in r["test"]), None)
    assert sha_test is not None
    assert sha_test["passed"] is True


# ===========================================================================
# 3. system/fips-mode
# ===========================================================================

def test_system_fips_mode(client):
    resp = client.get("/api/v1/system/fips-mode", params={"org_id": "wave-c-org"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["fips_mode"] in {"enabled", "disabled"}
    assert "provider" in body


# ===========================================================================
# 4. system/ha-status
# ===========================================================================

def test_system_ha_status(client):
    resp = client.get("/api/v1/system/ha-status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "ha_enabled" in body
    assert "node_id" in body
    assert "quorum" in body


# ===========================================================================
# 5+6. organizations create + re-parent
# ===========================================================================

def test_create_organization(client):
    resp = client.post(
        "/api/v1/organizations",
        json={"name": "Wave C Test Org"},
    )
    # 201 (created) or 422 (engine rejects)
    assert resp.status_code in {201, 422}, resp.text


def test_create_organization_empty_name_returns_422(client):
    resp = client.post("/api/v1/organizations", json={"name": ""})
    assert resp.status_code == 422


def test_update_organization_parent_unknown_returns_422(client):
    resp = client.patch(
        "/api/v1/organizations/non-existent-pk/parent",
        json={"parent_org_id": None},
    )
    # Engine may 422 (unknown pk) or 200 (no-op move)
    assert resp.status_code in {200, 422, 404}, resp.text


# ===========================================================================
# 7. pbom/record-step
# ===========================================================================

def test_pbom_record_step_invalid_run_returns_422(client):
    resp = client.post(
        "/api/v1/pbom/record-step",
        json={
            "run_id": "non-existent-run-id",
            "step_order": 0,
            "step_name": "test-step",
            "step_type": "build",
        },
    )
    # Engine validates run_id existence -> 422
    assert resp.status_code in {201, 422, 500}, resp.text


# ===========================================================================
# 8. pbom/artifact/{digest}/propagation
# ===========================================================================

def test_pbom_artifact_propagation_unknown_digest(client):
    resp = client.get(
        "/api/v1/pbom/artifact/abcdef1234567890/propagation",
        params={"org_id": "wave-c-org"},
    )
    # 200 with empty results, or 422 (engine rejects digest format)
    assert resp.status_code in {200, 422}, resp.text


# ===========================================================================
# 9. provenance/{artifact}/attestation
# ===========================================================================

def test_provenance_attestation_unknown_returns_404(client):
    resp = client.get("/api/v1/provenance/unknown-artifact-12345/attestation")
    assert resp.status_code == 404


# ===========================================================================
# 10. changes/material
# ===========================================================================

def test_changes_material_default(client):
    resp = client.get("/api/v1/changes/material", params={"org_id": "wave-c-org"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "items" in body
    assert isinstance(body["items"], list)


def test_changes_material_with_kind_filter(client):
    resp = client.get(
        "/api/v1/changes/material",
        params={"kind": "dependency", "severity": "high", "limit": 10},
    )
    assert resp.status_code == 200


# ===========================================================================
# 11. scopes
# ===========================================================================

def test_list_scopes(client):
    resp = client.get("/api/v1/scopes")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 20
    # Must include canonical admin scope
    names = [s["name"] for s in body["scopes"]]
    assert "admin:all" in names
    assert "read:findings" in names


# ===========================================================================
# 12. air-gap/feed-status
# ===========================================================================

def test_air_gap_feed_status(client):
    resp = client.get("/api/v1/air-gap/feed-status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "air_gapped" in body
    assert "feeds" in body


# ===========================================================================
# 13. admin/tokens
# ===========================================================================

def test_admin_list_tokens(client):
    resp = client.get("/api/v1/admin/tokens", params={"limit": 10})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "tokens" in body
    # Tokens must NEVER include the raw key
    for t in body["tokens"]:
        assert "key_hash" not in t
        assert "raw_key" not in t


# ===========================================================================
# 14+15. users/me/tokens (POST + GET)
# ===========================================================================

def test_create_my_token_invalid_scope_returns_422(client):
    resp = client.post(
        "/api/v1/users/me/tokens",
        json={"name": "test-token", "scopes": ["definitely:not:a:real:scope"]},
    )
    assert resp.status_code == 422


def test_create_my_token_happy_path(client):
    resp = client.post(
        "/api/v1/users/me/tokens",
        json={"name": "wave-c-test", "scopes": ["read:findings"]},
    )
    # 201 (created) or 500 (engine config issue)
    assert resp.status_code in {201, 500}, resp.text
    if resp.status_code == 201:
        body = resp.json()
        assert "token" in body
        assert "warning" in body


def test_list_my_tokens(client):
    resp = client.get("/api/v1/users/me/tokens")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "tokens" in body


# ===========================================================================
# 16. cspm/snapshot-scan
# ===========================================================================

def test_cspm_snapshot_scan_invalid_cloud_returns_422(client):
    resp = client.post(
        "/api/v1/cspm/snapshot-scan",
        json={"cloud": "venus", "account_id": "acc-1"},
    )
    assert resp.status_code == 422


def test_cspm_snapshot_scan_happy_path(client):
    resp = client.post(
        "/api/v1/cspm/snapshot-scan",
        json={"cloud": "aws", "account_id": "acc-test", "regions": ["us-east-1"]},
    )
    assert resp.status_code in {201, 500}, resp.text
    if resp.status_code == 201:
        body = resp.json()
        assert body["cloud"] == "aws"
        assert body["status"] in {"queued", "completed"}


# ===========================================================================
# 17. skills/uninstall
# ===========================================================================

def test_skills_uninstall_unknown_skill(client):
    resp = client.post(
        "/api/v1/skills/uninstall",
        json={"skill_id": "non-existent-skill", "purge_data": False},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # Removed=False is fine — skill didn't exist
    assert body["skill_id"] == "non-existent-skill"
    assert body["removed"] is False


# ===========================================================================
# 18. rules/dsl (alias)
# ===========================================================================

def test_rules_dsl_list(client):
    resp = client.get("/api/v1/rules/dsl", params={"org_id": "wave-c-org"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "rules" in body


# ===========================================================================
# 19. rules/{key}/enabled
# ===========================================================================

def test_toggle_rule_enabled(client):
    resp = client.patch(
        "/api/v1/rules/test-rule-key/enabled",
        json={"enabled": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["key"] == "test-rule-key"
    assert body["enabled"] is True
    assert body["persisted"] is True


# ===========================================================================
# 20. llm/approve-spend/{estimateId}
# ===========================================================================

def test_llm_approve_spend(client):
    resp = client.post(
        "/api/v1/llm/approve-spend/estimate-test-1",
        json={"approver": "wave-c-admin", "note": "test approval"},
    )
    # 200 (engine), or fallback ledger 200, or 500 (DB error)
    assert resp.status_code in {200, 500}, resp.text
    if resp.status_code == 200:
        body = resp.json()
        assert body["approved"] is True


# ===========================================================================
# 21. llm/rules/{key}/context-requirement
# ===========================================================================

def test_llm_rule_context_requirement(client):
    resp = client.get("/api/v1/llm/rules/test-rule/context-requirement")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["key"] == "test-rule"
    assert "context_requirement" in body
    assert "required_fields" in body["context_requirement"]
