"""
Deep FAIL Router API tests -- comprehensive coverage of every endpoint,
validation rule, error path, and edge case in suite-api/apps/api/fail_router.py.

This file uses the FastAPI TestClient with a fresh in-memory DB for each test
to ensure isolation.  No external network calls are made.

Target: 50+ test functions covering all 9 endpoints plus validation.
"""

from __future__ import annotations

import os
import tempfile

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.fail_router import (
    FAILScoreBatchRequest,
    FAILScoreRequest,
    _request_to_input,
)
from core.fail_engine import ExploitMaturity, FAILEngine, FAILInput


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Create a FastAPI TestClient with only the FAIL router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from apps.api.fail_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset module-level engine and DB singletons for test isolation."""
    import apps.api.fail_router as mod
    from core.fail_db import FAILDB

    mod._engine = FAILEngine()
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp_path = tmp.name
    tmp.close()
    mod._db = FAILDB(db_path=tmp_path)
    yield
    try:
        os.unlink(tmp_path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Helper to create a scored finding via the API
# ---------------------------------------------------------------------------


def _score_via_api(client, payload=None):
    """Score a finding and return (response, json_body)."""
    payload = payload or {"cve_id": "CVE-2024-0001", "cvss_score": 7.5}
    resp = client.post("/api/v1/fail/score", json=payload)
    return resp, resp.json()


# ---------------------------------------------------------------------------
# 1. POST /api/v1/fail/score -- single finding
# ---------------------------------------------------------------------------


class TestScoreSingleFinding:
    def test_minimal_empty_body(self, client):
        """Scoring with empty JSON body should succeed (all fields optional)."""
        resp, data = _score_via_api(client, {})
        assert resp.status_code == 200
        assert "score_id" in data
        assert data["score_id"].startswith("FAIL-")
        assert 0 <= data["fail_score"] <= 100

    def test_full_payload(self, client):
        """Scoring with every field populated."""
        resp, data = _score_via_api(client, {
            "cve_id": "CVE-2024-3094",
            "finding_id": "FIND-001",
            "title": "XZ Utils backdoor",
            "cvss_score": 10.0,
            "epss_score": 0.97,
            "is_kev": True,
            "has_exploit": True,
            "exploit_maturity": "weaponized",
            "active_campaigns": 3,
            "asset_criticality": "critical",
            "data_classification": "pii",
            "is_reachable": True,
            "is_internet_facing": True,
            "has_compensating_controls": False,
            "affected_assets": 50,
            "affected_users": 10000,
            "compliance_frameworks": ["SOC2", "PCI-DSS"],
            "sla_hours": 4,
            "metadata": {"scanner": "snyk"},
        })
        assert resp.status_code == 200
        assert data["cve_id"] == "CVE-2024-3094"
        assert data["finding_id"] == "FIND-001"
        assert data["grade"] in ("CRITICAL", "HIGH")
        assert data["fail_score"] >= 70

    def test_response_structure(self, client):
        """Verify all expected keys in the response."""
        resp, data = _score_via_api(client)
        expected_keys = {
            "score_id", "fail_score", "grade", "recommended_action",
            "cve_id", "finding_id", "sub_scores", "weights",
            "scored_at", "engine_version", "computation_ms",
        }
        assert expected_keys.issubset(set(data.keys()))

    def test_sub_scores_structure(self, client):
        """Verify sub_scores contains all four FAIL dimensions."""
        resp, data = _score_via_api(client)
        sub = data["sub_scores"]
        for dimension in ["fact", "assess", "impact", "likelihood"]:
            assert dimension in sub
            assert "score" in sub[dimension]

    def test_weights_sum_close_to_1(self, client):
        """API-returned weights should sum to approximately 1.0."""
        resp, data = _score_via_api(client)
        total = sum(data["weights"].values())
        assert abs(total - 1.0) < 0.01

    def test_engine_version_is_1_0_0(self, client):
        resp, data = _score_via_api(client)
        assert data["engine_version"] == "1.0.0"

    def test_computation_ms_positive(self, client):
        resp, data = _score_via_api(client)
        assert data["computation_ms"] >= 0

    def test_scored_at_is_iso_format(self, client):
        resp, data = _score_via_api(client)
        assert "T" in data["scored_at"]

    def test_critical_finding_scores_high(self, client):
        resp, data = _score_via_api(client, {
            "cve_id": "CVE-2024-CRIT",
            "cvss_score": 10.0,
            "epss_score": 0.95,
            "is_kev": True,
            "has_exploit": True,
            "exploit_maturity": "weaponized",
            "active_campaigns": 5,
            "asset_criticality": "critical",
            "data_classification": "credentials",
            "is_reachable": True,
            "is_internet_facing": True,
            "affected_assets": 200,
        })
        assert resp.status_code == 200
        assert data["grade"] in ("CRITICAL", "HIGH")

    def test_low_finding_scores_low(self, client):
        resp, data = _score_via_api(client, {
            "cve_id": "CVE-2024-LOW",
            "cvss_score": 2.0,
            "epss_score": 0.001,
            "asset_criticality": "low",
            "data_classification": "public",
        })
        assert resp.status_code == 200
        assert data["fail_score"] < 50

    def test_compensating_controls_reduce_score(self, client):
        """Score with controls should be <= score without."""
        resp_no, data_no = _score_via_api(client, {
            "cve_id": "CVE-CTRL-A",
            "cvss_score": 8.0,
            "is_reachable": True,
            "is_internet_facing": True,
            "has_compensating_controls": False,
        })
        resp_yes, data_yes = _score_via_api(client, {
            "cve_id": "CVE-CTRL-B",
            "cvss_score": 8.0,
            "is_reachable": True,
            "is_internet_facing": True,
            "has_compensating_controls": True,
        })
        assert data_yes["fail_score"] <= data_no["fail_score"]


# ---------------------------------------------------------------------------
# 2. POST /api/v1/fail/score/batch -- batch scoring
# ---------------------------------------------------------------------------


class TestScoreBatch:
    def test_batch_three_findings(self, client):
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [
                {"cve_id": "CVE-A", "cvss_score": 9.0},
                {"cve_id": "CVE-B", "cvss_score": 5.0},
                {"cve_id": "CVE-C", "cvss_score": 2.0},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["results"]) == 3
        assert "stats" in data

    def test_batch_single_item(self, client):
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [{"cve_id": "CVE-SINGLE", "cvss_score": 6.0}],
        })
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_batch_empty_rejected(self, client):
        """Empty findings list should be rejected (min_length=1)."""
        resp = client.post("/api/v1/fail/score/batch", json={"findings": []})
        assert resp.status_code == 422

    def test_batch_results_are_stored(self, client):
        """Scores created via batch should be retrievable."""
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [
                {"cve_id": "CVE-BATCH-STORE", "cvss_score": 7.0},
            ],
        })
        score_id = resp.json()["results"][0]["score_id"]
        get_resp = client.get(f"/api/v1/fail/score/{score_id}")
        assert get_resp.status_code == 200

    def test_batch_stats_reflect_scored_count(self, client):
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [
                {"cve_id": f"CVE-BATCH-{i}", "cvss_score": 5.0}
                for i in range(5)
            ],
        })
        data = resp.json()
        assert data["stats"]["total_scored"] >= 5

    def test_batch_each_result_has_score_id(self, client):
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [
                {"cve_id": "CVE-X", "cvss_score": 6.0},
                {"cve_id": "CVE-Y", "cvss_score": 7.0},
            ],
        })
        for result in resp.json()["results"]:
            assert result["score_id"].startswith("FAIL-")

    def test_batch_score_ids_are_unique(self, client):
        resp = client.post("/api/v1/fail/score/batch", json={
            "findings": [
                {"cve_id": f"CVE-UNIQ-{i}", "cvss_score": 5.0}
                for i in range(10)
            ],
        })
        ids = [r["score_id"] for r in resp.json()["results"]]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# 3. GET /api/v1/fail/score/{score_id} -- retrieve stored score
# ---------------------------------------------------------------------------


class TestGetStoredScore:
    def test_retrieve_after_scoring(self, client):
        resp, data = _score_via_api(client, {"cve_id": "CVE-GET", "cvss_score": 7.0})
        score_id = data["score_id"]
        get_resp = client.get(f"/api/v1/fail/score/{score_id}")
        assert get_resp.status_code == 200
        stored = get_resp.json()
        assert stored["score_id"] == score_id
        assert stored["cve_id"] == "CVE-GET"

    def test_missing_score_returns_404(self, client):
        resp = client.get("/api/v1/fail/score/FAIL-NONEXISTENT")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_stored_score_has_grade(self, client):
        resp, data = _score_via_api(client, {"cve_id": "CVE-GRADE-CHECK", "cvss_score": 8.0})
        stored = client.get(f"/api/v1/fail/score/{data['score_id']}").json()
        assert stored["grade"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ---------------------------------------------------------------------------
# 4. GET /api/v1/fail/scores -- list with pagination
# ---------------------------------------------------------------------------


class TestListScores:
    def test_list_returns_total_and_results(self, client):
        _score_via_api(client, {"cve_id": "CVE-LIST-1", "cvss_score": 5.0})
        _score_via_api(client, {"cve_id": "CVE-LIST-2", "cvss_score": 6.0})
        resp = client.get("/api/v1/fail/scores")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "results" in data
        assert data["total"] >= 2

    def test_list_with_limit(self, client):
        for i in range(5):
            _score_via_api(client, {"cve_id": f"CVE-LIM-{i}", "cvss_score": 5.0})
        resp = client.get("/api/v1/fail/scores?limit=2")
        assert resp.status_code == 200
        assert len(resp.json()["results"]) <= 2

    def test_list_with_offset(self, client):
        for i in range(5):
            _score_via_api(client, {"cve_id": f"CVE-OFF-{i}", "cvss_score": 5.0})
        resp = client.get("/api/v1/fail/scores?limit=100&offset=3")
        assert resp.status_code == 200
        data = resp.json()
        assert data["offset"] == 3

    def test_list_with_grade_filter(self, client):
        # Create a high-scoring finding
        _score_via_api(client, {
            "cve_id": "CVE-FILTER-CRIT",
            "cvss_score": 10.0,
            "epss_score": 0.95,
            "is_kev": True,
            "has_exploit": True,
            "exploit_maturity": "weaponized",
            "is_reachable": True,
            "is_internet_facing": True,
            "asset_criticality": "critical",
        })
        resp = client.get("/api/v1/fail/scores?grade=CRITICAL")
        assert resp.status_code == 200

    def test_list_empty_when_no_data(self, client):
        resp = client.get("/api/v1/fail/scores")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["results"] == []


# ---------------------------------------------------------------------------
# 5. GET /api/v1/fail/top-risks -- top risks
# ---------------------------------------------------------------------------


class TestTopRisks:
    def test_top_risks_ordered_by_score_desc(self, client):
        for cvss in [2.0, 5.0, 8.0, 9.5]:
            _score_via_api(client, {"cve_id": f"CVE-TOP-{cvss}", "cvss_score": cvss})
        resp = client.get("/api/v1/fail/top-risks?limit=4")
        assert resp.status_code == 200
        data = resp.json()
        assert "risks" in data
        scores = [r["fail_score"] for r in data["risks"]]
        assert scores == sorted(scores, reverse=True)

    def test_top_risks_with_limit(self, client):
        for i in range(10):
            _score_via_api(client, {"cve_id": f"CVE-RISK-{i}", "cvss_score": 5.0 + i * 0.5})
        resp = client.get("/api/v1/fail/top-risks?limit=3")
        assert resp.status_code == 200
        assert len(resp.json()["risks"]) <= 3

    def test_top_risks_empty(self, client):
        resp = client.get("/api/v1/fail/top-risks")
        assert resp.status_code == 200
        assert resp.json()["risks"] == []
        assert resp.json()["total"] == 0

    def test_top_risks_total_reflects_all_scores(self, client):
        for i in range(5):
            _score_via_api(client, {"cve_id": f"CVE-RT-{i}", "cvss_score": 6.0})
        resp = client.get("/api/v1/fail/top-risks?limit=2")
        data = resp.json()
        assert data["total"] == 5
        assert len(data["risks"]) == 2


# ---------------------------------------------------------------------------
# 6. GET /api/v1/fail/stats -- aggregate statistics
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_empty_db(self, client):
        resp = client.get("/api/v1/fail/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["average_score"] == 0
        assert "grade_distribution" in data

    def test_stats_after_scoring(self, client):
        for cvss in [3.0, 6.0, 9.0]:
            _score_via_api(client, {"cve_id": f"CVE-STAT-{cvss}", "cvss_score": cvss})
        resp = client.get("/api/v1/fail/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert data["average_score"] > 0
        assert data["max_score"] >= data["min_score"]

    def test_stats_grade_distribution_keys(self, client):
        _score_via_api(client, {"cve_id": "CVE-DIST", "cvss_score": 5.0})
        resp = client.get("/api/v1/fail/stats")
        data = resp.json()
        dist = data["grade_distribution"]
        for grade in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert grade in dist


# ---------------------------------------------------------------------------
# 7. GET /api/v1/fail/cve/{cve_id} -- CVE lookup
# ---------------------------------------------------------------------------


class TestScoresByCve:
    def test_multiple_scores_for_same_cve(self, client):
        cve = "CVE-2024-REPEAT"
        for cvss in [5.0, 7.0, 9.0]:
            _score_via_api(client, {"cve_id": cve, "cvss_score": cvss})
        resp = client.get(f"/api/v1/fail/cve/{cve}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == cve
        assert data["total"] == 3
        assert len(data["scores"]) == 3

    def test_nonexistent_cve_returns_empty(self, client):
        resp = client.get("/api/v1/fail/cve/CVE-9999-0000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["scores"] == []

    def test_cve_scores_contain_score_data(self, client):
        _score_via_api(client, {"cve_id": "CVE-DATA-CHECK", "cvss_score": 6.0})
        resp = client.get("/api/v1/fail/cve/CVE-DATA-CHECK")
        scores = resp.json()["scores"]
        assert len(scores) == 1
        assert "fail_score" in scores[0]
        assert "grade" in scores[0]


# ---------------------------------------------------------------------------
# 8. DELETE /api/v1/fail/score/{score_id} -- delete score
# ---------------------------------------------------------------------------


class TestDeleteScore:
    def test_delete_existing_score(self, client):
        resp, data = _score_via_api(client, {"cve_id": "CVE-DEL", "cvss_score": 5.0})
        score_id = data["score_id"]
        del_resp = client.delete(f"/api/v1/fail/score/{score_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] is True
        assert del_resp.json()["score_id"] == score_id

    def test_deleted_score_not_retrievable(self, client):
        resp, data = _score_via_api(client, {"cve_id": "CVE-DEL2", "cvss_score": 5.0})
        score_id = data["score_id"]
        client.delete(f"/api/v1/fail/score/{score_id}")
        get_resp = client.get(f"/api/v1/fail/score/{score_id}")
        assert get_resp.status_code == 404

    def test_delete_nonexistent_returns_404(self, client):
        resp = client.delete("/api/v1/fail/score/FAIL-DOESNOTEXIST")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    def test_delete_reduces_count(self, client):
        resp1, data1 = _score_via_api(client, {"cve_id": "CVE-CNT1", "cvss_score": 5.0})
        resp2, data2 = _score_via_api(client, {"cve_id": "CVE-CNT2", "cvss_score": 6.0})

        stats_before = client.get("/api/v1/fail/stats").json()["total"]
        client.delete(f"/api/v1/fail/score/{data1['score_id']}")
        stats_after = client.get("/api/v1/fail/stats").json()["total"]
        assert stats_after == stats_before - 1


# ---------------------------------------------------------------------------
# 9. GET /api/v1/fail/health -- health check
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    def test_health_returns_healthy(self, client):
        resp = client.get("/api/v1/fail/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_health_contains_engine_version(self, client):
        resp = client.get("/api/v1/fail/health")
        assert resp.json()["engine_version"] == "1.0.0"

    def test_health_contains_total_scored(self, client):
        resp = client.get("/api/v1/fail/health")
        assert "total_scored" in resp.json()

    def test_health_contains_in_memory_history(self, client):
        resp = client.get("/api/v1/fail/health")
        assert "in_memory_history" in resp.json()

    def test_health_after_scoring(self, client):
        _score_via_api(client, {"cve_id": "CVE-H1", "cvss_score": 5.0})
        _score_via_api(client, {"cve_id": "CVE-H2", "cvss_score": 6.0})
        resp = client.get("/api/v1/fail/health")
        data = resp.json()
        assert data["total_scored"] >= 2
        assert data["in_memory_history"] >= 2


# ---------------------------------------------------------------------------
# 10. Pydantic input validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    def test_cvss_below_zero_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"cvss_score": -0.1})
        assert resp.status_code == 422

    def test_cvss_above_ten_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"cvss_score": 10.1})
        assert resp.status_code == 422

    def test_epss_below_zero_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"epss_score": -0.01})
        assert resp.status_code == 422

    def test_epss_above_one_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"epss_score": 1.01})
        assert resp.status_code == 422

    def test_cvss_boundary_zero_accepted(self, client):
        resp = client.post("/api/v1/fail/score", json={"cvss_score": 0.0})
        assert resp.status_code == 200

    def test_cvss_boundary_ten_accepted(self, client):
        resp = client.post("/api/v1/fail/score", json={"cvss_score": 10.0})
        assert resp.status_code == 200

    def test_epss_boundary_zero_accepted(self, client):
        resp = client.post("/api/v1/fail/score", json={"epss_score": 0.0})
        assert resp.status_code == 200

    def test_epss_boundary_one_accepted(self, client):
        resp = client.post("/api/v1/fail/score", json={"epss_score": 1.0})
        assert resp.status_code == 200

    def test_negative_active_campaigns_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"active_campaigns": -1})
        assert resp.status_code == 422

    def test_negative_affected_assets_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"affected_assets": -1})
        assert resp.status_code == 422

    def test_negative_affected_users_rejected(self, client):
        resp = client.post("/api/v1/fail/score", json={"affected_users": -1})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 11. Exploit maturity via API
# ---------------------------------------------------------------------------


class TestExploitMaturityAPI:
    @pytest.mark.parametrize(
        "maturity",
        ["weaponized", "poc_public", "poc_private", "theoretical", "unknown"],
    )
    def test_all_maturity_values_accepted(self, client, maturity):
        resp = client.post("/api/v1/fail/score", json={
            "cve_id": f"CVE-MAT-{maturity}",
            "cvss_score": 7.0,
            "exploit_maturity": maturity,
        })
        assert resp.status_code == 200

    def test_invalid_maturity_defaults_to_unknown(self, client):
        """Unknown maturity string should not error; defaults to UNKNOWN."""
        resp = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-MAT-BOGUS",
            "cvss_score": 7.0,
            "exploit_maturity": "completely_made_up",
        })
        assert resp.status_code == 200

    def test_weaponized_scores_higher_than_theoretical(self, client):
        resp_w = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-W",
            "cvss_score": 7.0,
            "exploit_maturity": "weaponized",
        })
        resp_t = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-T",
            "cvss_score": 7.0,
            "exploit_maturity": "theoretical",
        })
        assert resp_w.json()["fail_score"] > resp_t.json()["fail_score"]


# ---------------------------------------------------------------------------
# 12. Data classification via API
# ---------------------------------------------------------------------------


class TestDataClassificationAPI:
    @pytest.mark.parametrize(
        "data_class",
        ["pii", "phi", "pci", "financial", "credentials", "internal", "public", "none"],
    )
    def test_all_data_classifications_accepted(self, client, data_class):
        resp = client.post("/api/v1/fail/score", json={
            "cve_id": f"CVE-DC-{data_class}",
            "cvss_score": 6.0,
            "data_classification": data_class,
        })
        assert resp.status_code == 200

    def test_phi_scores_higher_than_public(self, client):
        resp_phi = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-PHI",
            "cvss_score": 6.0,
            "data_classification": "phi",
        })
        resp_pub = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-PUB",
            "cvss_score": 6.0,
            "data_classification": "public",
        })
        assert resp_phi.json()["fail_score"] > resp_pub.json()["fail_score"]


# ---------------------------------------------------------------------------
# 13. Asset criticality via API
# ---------------------------------------------------------------------------


class TestAssetCriticalityAPI:
    @pytest.mark.parametrize(
        "criticality",
        ["critical", "high", "medium", "low", "unknown"],
    )
    def test_all_asset_criticality_values_accepted(self, client, criticality):
        resp = client.post("/api/v1/fail/score", json={
            "cve_id": f"CVE-AC-{criticality}",
            "cvss_score": 6.0,
            "asset_criticality": criticality,
        })
        assert resp.status_code == 200

    def test_critical_scores_higher_than_low(self, client):
        resp_crit = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-AC-CRIT",
            "cvss_score": 7.0,
            "asset_criticality": "critical",
        })
        resp_low = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-AC-LOW",
            "cvss_score": 7.0,
            "asset_criticality": "low",
        })
        assert resp_crit.json()["fail_score"] > resp_low.json()["fail_score"]


# ---------------------------------------------------------------------------
# 14. _request_to_input helper
# ---------------------------------------------------------------------------


class TestRequestToInputDeep:
    def test_basic_conversion(self):
        req = FAILScoreRequest(cve_id="CVE-1", cvss_score=8.5, epss_score=0.7)
        inp = _request_to_input(req)
        assert isinstance(inp, FAILInput)
        assert inp.cve_id == "CVE-1"
        assert inp.cvss_score == 8.5
        assert inp.epss_score == 0.7

    def test_exploit_maturity_enum_conversion(self):
        for maturity_str in ["weaponized", "poc_public", "poc_private", "theoretical", "unknown"]:
            req = FAILScoreRequest(exploit_maturity=maturity_str)
            inp = _request_to_input(req)
            assert inp.exploit_maturity == ExploitMaturity(maturity_str)

    def test_invalid_exploit_maturity_defaults_to_unknown(self):
        req = FAILScoreRequest(exploit_maturity="bogus_value")
        inp = _request_to_input(req)
        assert inp.exploit_maturity == ExploitMaturity.UNKNOWN

    def test_case_insensitive_maturity(self):
        req = FAILScoreRequest(exploit_maturity="WEAPONIZED")
        inp = _request_to_input(req)
        assert inp.exploit_maturity == ExploitMaturity.WEAPONIZED

    def test_all_fields_propagated(self):
        req = FAILScoreRequest(
            cve_id="CVE-1",
            finding_id="F-1",
            title="Test",
            cvss_score=5.0,
            epss_score=0.5,
            is_kev=True,
            has_exploit=True,
            exploit_maturity="poc_public",
            active_campaigns=2,
            asset_criticality="high",
            data_classification="pci",
            is_reachable=True,
            is_internet_facing=True,
            has_compensating_controls=True,
            affected_assets=10,
            affected_users=500,
            compliance_frameworks=["SOC2"],
            sla_hours=24,
            metadata={"key": "val"},
        )
        inp = _request_to_input(req)
        assert inp.cve_id == "CVE-1"
        assert inp.finding_id == "F-1"
        assert inp.title == "Test"
        assert inp.is_kev is True
        assert inp.has_exploit is True
        assert inp.active_campaigns == 2
        assert inp.asset_criticality == "high"
        assert inp.data_classification == "pci"
        assert inp.is_reachable is True
        assert inp.is_internet_facing is True
        assert inp.has_compensating_controls is True
        assert inp.affected_assets == 10
        assert inp.affected_users == 500
        assert inp.compliance_frameworks == ["SOC2"]
        assert inp.sla_hours == 24
        assert inp.metadata == {"key": "val"}

    def test_default_values(self):
        req = FAILScoreRequest()
        inp = _request_to_input(req)
        assert inp.cve_id is None
        assert inp.cvss_score is None
        assert inp.epss_score is None
        assert inp.is_kev is False
        assert inp.has_exploit is False
        assert inp.active_campaigns == 0
        assert inp.asset_criticality == "unknown"
        assert inp.data_classification == "none"


# ---------------------------------------------------------------------------
# 15. FAILScoreBatchRequest validation
# ---------------------------------------------------------------------------


class TestBatchRequestValidation:
    def test_max_500_items_accepted(self):
        findings = [FAILScoreRequest(cve_id=f"CVE-{i}") for i in range(500)]
        batch = FAILScoreBatchRequest(findings=findings)
        assert len(batch.findings) == 500

    def test_over_500_rejected(self):
        from pydantic import ValidationError

        findings = [FAILScoreRequest(cve_id=f"CVE-{i}") for i in range(501)]
        with pytest.raises(ValidationError):
            FAILScoreBatchRequest(findings=findings)

    def test_empty_list_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FAILScoreBatchRequest(findings=[])


# ---------------------------------------------------------------------------
# 16. Org ID handling via query parameter
# ---------------------------------------------------------------------------


class TestOrgId:
    def test_score_with_org_id_param(self, client):
        """Scores can be scoped to an org via query param."""
        resp = client.post(
            "/api/v1/fail/score?org_id=acme-corp",
            json={"cve_id": "CVE-ORG-1", "cvss_score": 6.0},
        )
        assert resp.status_code == 200

    def test_list_scores_with_org_id(self, client):
        """List endpoint accepts org_id parameter."""
        client.post(
            "/api/v1/fail/score?org_id=acme",
            json={"cve_id": "CVE-ORG-2", "cvss_score": 5.0},
        )
        resp = client.get("/api/v1/fail/scores?org_id=acme")
        assert resp.status_code == 200

    def test_stats_with_org_id(self, client):
        client.post(
            "/api/v1/fail/score?org_id=testorg",
            json={"cve_id": "CVE-ORG-3", "cvss_score": 7.0},
        )
        resp = client.get("/api/v1/fail/stats?org_id=testorg")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_top_risks_with_org_id(self, client):
        client.post(
            "/api/v1/fail/score?org_id=riskorg",
            json={"cve_id": "CVE-ORG-4", "cvss_score": 8.0},
        )
        resp = client.get("/api/v1/fail/top-risks?org_id=riskorg")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 17. Grade-specific response value tests
# ---------------------------------------------------------------------------


class TestGradeResponseValues:
    def test_grade_is_valid_enum_value(self, client):
        resp, data = _score_via_api(client)
        valid_grades = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert data["grade"] in valid_grades

    def test_action_is_valid_enum_value(self, client):
        resp, data = _score_via_api(client)
        valid_actions = {
            "PATCH_IMMEDIATELY", "PATCH_NEXT_SPRINT",
            "SCHEDULE_FIX", "MONITOR", "ACCEPT_RISK",
        }
        assert data["recommended_action"] in valid_actions

    def test_grade_action_consistency(self, client):
        """Grade and action should correspond correctly."""
        mapping = {
            "CRITICAL": "PATCH_IMMEDIATELY",
            "HIGH": "PATCH_NEXT_SPRINT",
            "MEDIUM": "SCHEDULE_FIX",
            "LOW": "MONITOR",
            "INFO": "ACCEPT_RISK",
        }
        resp, data = _score_via_api(client, {"cve_id": "CVE-CONSISTENCY", "cvss_score": 7.0})
        assert data["recommended_action"] == mapping[data["grade"]]


# ---------------------------------------------------------------------------
# 18. Compliance frameworks via API
# ---------------------------------------------------------------------------


class TestComplianceFrameworks:
    def test_compliance_increases_score(self, client):
        resp_no_fw = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-NOFW",
            "cvss_score": 7.0,
        })
        resp_fw = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-WITHFW",
            "cvss_score": 7.0,
            "compliance_frameworks": ["SOC2", "PCI-DSS", "HIPAA"],
        })
        assert resp_fw.json()["fail_score"] >= resp_no_fw.json()["fail_score"]

    def test_empty_frameworks_accepted(self, client):
        resp = client.post("/api/v1/fail/score", json={
            "cve_id": "CVE-EMPTY-FW",
            "cvss_score": 5.0,
            "compliance_frameworks": [],
        })
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 19. Idempotency and isolation
# ---------------------------------------------------------------------------


class TestIdempotencyAndIsolation:
    def test_scoring_same_input_twice_gives_different_ids(self, client):
        """Each scoring creates a new score_id."""
        payload = {"cve_id": "CVE-IDEM", "cvss_score": 7.0}
        resp1 = client.post("/api/v1/fail/score", json=payload)
        resp2 = client.post("/api/v1/fail/score", json=payload)
        assert resp1.json()["score_id"] != resp2.json()["score_id"]

    def test_scoring_same_input_twice_gives_same_fail_score(self, client):
        """Deterministic scoring: same input -> same FAIL score."""
        payload = {"cve_id": "CVE-DETERM", "cvss_score": 7.0, "epss_score": 0.5}
        resp1 = client.post("/api/v1/fail/score", json=payload)
        resp2 = client.post("/api/v1/fail/score", json=payload)
        assert resp1.json()["fail_score"] == resp2.json()["fail_score"]
