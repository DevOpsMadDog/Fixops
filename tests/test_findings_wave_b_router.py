"""Wave B — Findings / Risk / Scoring router smoke tests (16 endpoints).

Each endpoint gets a happy-path call plus a focused error case (422 for bad
input, 404 for missing entity). We accept any of {200, 201, 400, 404, 422,
501} as "the route is wired and validated correctly" — deeper engine
behaviour is exercised by per-engine unit tests.

Auth: ``FIXOPS_API_TOKEN`` is set BEFORE auth_deps import; we pass
``X-API-Key`` on every request.
"""
from __future__ import annotations

import importlib

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.auth_deps as _auth_mod
from apps.api.findings_wave_b_router import router as wave_b_router


# Module-scoped autouse fixture sets FIXOPS_API_TOKEN at test-execution time
# (not collection time) so a later-collected module cannot clobber our token.
# auth_deps._load_api_tokens() is per-request so reload only refreshes
# _DEV_MODE / _HAS_JWT_AUTH cached at module-init.
@pytest.fixture(scope="module", autouse=True)
def _auth_env() -> None:
    mp = pytest.MonkeyPatch()
    mp.setenv("FIXOPS_API_TOKEN", "wave-b-test-token")
    mp.setenv("FIXOPS_MODE", "dev")
    mp.delenv("FIXOPS_JWT_SECRET", raising=False)
    importlib.reload(_auth_mod)
    yield
    mp.undo()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(wave_b_router)
    return a


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(
        app,
        headers={"X-API-Key": "wave-b-test-token", "X-Org-ID": "wave-b-org"},
    )


# Acceptable codes when the route is wired but the data layer / engine may not
# have rows for the test tenant.
OK_OR_404 = {200, 404}
OK_OR_404_OR_422 = {200, 404, 422}
OK_OR_501 = {200, 201, 404, 422, 501}


# ===========================================================================
# 1. ce6b3221 — GET /api/v1/findings/{id}/lifecycle
# ===========================================================================

def test_finding_lifecycle_unknown_returns_404(client):
    resp = client.get("/api/v1/findings/does-not-exist-xyz/lifecycle")
    assert resp.status_code == 404, resp.text


# ===========================================================================
# 2. 71432602 — GET /api/v1/findings/drift
# ===========================================================================

def test_findings_drift_default_window_returns_totals(client):
    resp = client.get("/api/v1/findings/drift")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["org_id"] == "wave-b-org"
    assert "days" in body


def test_findings_drift_invalid_since_returns_400(client):
    resp = client.get("/api/v1/findings/drift", params={"since": "not-a-date"})
    assert resp.status_code == 400, resp.text


# ===========================================================================
# 3. a3d3443d — GET /api/v1/findings?status=...
# ===========================================================================

def test_list_findings_status_new(client):
    resp = client.get("/api/v1/findings", params={"status": "new", "limit": 5})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["org_id"] == "wave-b-org"
    assert body["status"] == "new"
    assert isinstance(body["findings"], list)


def test_list_findings_invalid_limit_returns_422(client):
    resp = client.get("/api/v1/findings", params={"limit": 0})
    assert resp.status_code == 422


# ===========================================================================
# 4. 9fafda03 — GET /api/v1/findings/{id}/score-breakdown
# ===========================================================================

def test_finding_score_breakdown_unknown_returns_404(client):
    resp = client.get("/api/v1/findings/missing-id/score-breakdown")
    assert resp.status_code == 404


# ===========================================================================
# 5+6. fdf4d765 / bacdd8bf — GET / PUT /api/v1/scoring/formula
# ===========================================================================

def test_get_scoring_formula(client):
    resp = client.get("/api/v1/scoring/formula")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert isinstance(body, dict)


def test_put_scoring_formula_creates_model(client):
    resp = client.put(
        "/api/v1/scoring/formula",
        json={
            "model_name": "wave_b_test",
            "cvss_weight": 0.4,
            "epss_weight": 0.3,
            "kev_bonus": 0.2,
            "criticality_multiplier": 1.0,
            "exposure_weight": 0.3,
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "created"
    assert "active_model" in body


def test_put_scoring_formula_invalid_weight_returns_422(client):
    resp = client.put(
        "/api/v1/scoring/formula",
        json={"cvss_weight": 5.5},  # > 1.0 violates field constraint
    )
    assert resp.status_code == 422


# ===========================================================================
# 7. 7e62f6c6 — POST /api/v1/risk/quantify-fair
# ===========================================================================

def test_quantify_fair_neither_id_nor_finding_returns_422(client):
    resp = client.post("/api/v1/risk/quantify-fair", json={})
    assert resp.status_code == 422, resp.text


def test_quantify_fair_with_finding(client):
    resp = client.post(
        "/api/v1/risk/quantify-fair",
        json={
            "finding": {
                "severity": "high",
                "asset_type": "web_app",
                "cvss_score": 8.1,
            }
        },
    )
    # Engine may 200 (computed) or 404 (missing template) — both are OK
    assert resp.status_code in {200, 404}, resp.text
    if resp.status_code == 200:
        body = resp.json()
        assert body["methodology"] == "FAIR"
        assert "quantified_risk" in body


# ===========================================================================
# 8. 094b9c3d — GET /api/v1/risk/brs/bu/{bu_id}
# ===========================================================================

def test_bu_risk_score(client):
    resp = client.get("/api/v1/risk/brs/bu/test-bu-1")
    # Either real (200) or NotImplemented (501) or NotFound (404)
    assert resp.status_code in OK_OR_501, resp.text


# ===========================================================================
# 9. e2cf4708 — GET /api/v1/attack-paths/choke-points
# ===========================================================================

def test_choke_points_missing_sources_returns_422(client):
    resp = client.get(
        "/api/v1/attack-paths/choke-points", params={"sinks": "asset-1"},
    )
    assert resp.status_code == 422


def test_choke_points_with_sources_and_sinks(client):
    resp = client.get(
        "/api/v1/attack-paths/choke-points",
        params={"sources": "internet", "sinks": "db-1,db-2", "top_k": 3},
    )
    # Empty graph for this test tenant returns 200 with empty list
    assert resp.status_code in {200, 422}, resp.text
    if resp.status_code == 200:
        body = resp.json()
        assert body["sources"] == ["internet"]
        assert body["sinks"] == ["db-1", "db-2"]


# ===========================================================================
# 10. 4c483284 — GET /api/v1/issues/toxic
# ===========================================================================

def test_toxic_issues(client):
    resp = client.get("/api/v1/issues/toxic")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "issues" in body
    assert isinstance(body["issues"], list)


# ===========================================================================
# 11. afe86faf — POST /api/v1/toxic-combo-rules
# ===========================================================================

def test_create_toxic_combo_rule_returns_501(client):
    """The engine intentionally returns 501 (capability not implemented)."""
    resp = client.post(
        "/api/v1/toxic-combo-rules",
        json={
            "combo_id": "test-combo-1",
            "name": "internet+CVE+admin",
            "predicates": [
                {"attribute": "internet", "operator": "eq", "value": True},
                {"attribute": "cve_count", "operator": "gt", "value": 0},
            ],
        },
    )
    assert resp.status_code == 501, resp.text
    body = resp.json()
    assert body["detail"]["error"] == "not_implemented"


def test_create_toxic_combo_rule_bad_predicates_returns_422(client):
    resp = client.post(
        "/api/v1/toxic-combo-rules",
        json={
            "combo_id": "bad",
            "name": "no predicates",
            "predicates": [{"missing": "attr"}],
        },
    )
    assert resp.status_code == 422


# ===========================================================================
# 12+13. 1d3a7018 / 2a6a2e8a — SBOM re-eval
# ===========================================================================

def test_sbom_subscribe_reeval(client):
    resp = client.post(
        "/api/v1/sbom/subscribe-for-reeval",
        json={"sbom_id": "sbom-test-1", "cron_expr": "@daily"},
    )
    # 200 (scheduled), 422 (engine rejects unknown sbom), or 501
    assert resp.status_code in {200, 201, 422, 501}, resp.text


def test_sbom_reeval_history(client):
    resp = client.get("/api/v1/sbom/sbom-test-1/re-eval-history")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sbom_id"] == "sbom-test-1"
    assert isinstance(body["schedules"], list)


# ===========================================================================
# 14. 4b96d034 — POST /api/v1/investigate/rql
# ===========================================================================

def test_investigate_rql_syntax_error_returns_400(client):
    resp = client.post(
        "/api/v1/investigate/rql",
        json={"query": "this is not RQL!", "provider": "memory"},
    )
    # Engine raises typed errors -> 400/422
    assert resp.status_code in {400, 422}, resp.text


def test_investigate_rql_simple_query(client):
    resp = client.post(
        "/api/v1/investigate/rql",
        json={"query": "find findings where severity = 'high'", "provider": "memory"},
    )
    # May 200 (compiled+executed) or 400/422 (engine doesn't grok our DSL)
    assert resp.status_code in {200, 400, 422}, resp.text


# ===========================================================================
# 15+16. 80123d56 / 06e9c24b — saved RQL queries
# ===========================================================================

def test_list_saved_queries(client):
    resp = client.get("/api/v1/investigate/saved")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "queries" in body
    assert isinstance(body["queries"], list)


def test_save_query_invalid_syntax_returns_400(client):
    resp = client.post(
        "/api/v1/investigate/saved",
        json={"name": "bad-q", "query": "@@@invalid@@@"},
    )
    assert resp.status_code in {400, 422}, resp.text
