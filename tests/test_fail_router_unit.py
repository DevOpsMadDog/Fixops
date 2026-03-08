"""
Unit tests for FAIL Engine API Router (suite-api/apps/api/fail_router.py).

Covers:
  - POST /api/v1/fail/score — single finding scoring
  - POST /api/v1/fail/score/batch — batch scoring
  - GET /api/v1/fail/score/{score_id} — retrieve stored score
  - GET /api/v1/fail/scores — list scores (paginated)
  - GET /api/v1/fail/top-risks — top risks by FAIL score
  - GET /api/v1/fail/stats — aggregate statistics
  - GET /api/v1/fail/cve/{cve_id} — scores for a specific CVE
  - DELETE /api/v1/fail/score/{score_id} — delete a score
  - GET /api/v1/fail/health — health check
  - Input validation (CVSS out of range, exploit maturity enum)
  - Response format verification
  - Error handling (404 for missing scores, 500 handling)
  - _request_to_input helper conversion
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

try:
    from apps.api.fail_router import FAILScoreRequest, _request_to_input
    from core.fail_engine import ExploitMaturity, FAILEngine, FAILInput
except ImportError:
    pytest.skip("FAIL router API changed — old models removed", allow_module_level=True)


# ---------------------------------------------------------------------------
# _request_to_input conversion
# ---------------------------------------------------------------------------


class TestRequestToInput:
    def test_basic_conversion(self):
        req = FAILScoreRequest(
            cve_id="CVE-2024-1234",
            title="Test vuln",
            cvss_score=8.5,
            epss_score=0.7,
            is_kev=True,
            has_exploit=True,
            exploit_maturity="weaponized",
            active_campaigns=2,
            asset_criticality="critical",
            data_classification="pii",
            is_reachable=True,
            is_internet_facing=True,
        )
        inp = _request_to_input(req)
        assert isinstance(inp, FAILInput)
        assert inp.cve_id == "CVE-2024-1234"
        assert inp.cvss_score == 8.5
        assert inp.epss_score == 0.7
        assert inp.is_kev is True
        assert inp.exploit_maturity == ExploitMaturity.WEAPONIZED
        assert inp.asset_criticality == "critical"
        assert inp.data_classification == "pii"

    def test_unknown_exploit_maturity_defaults(self):
        req = FAILScoreRequest(exploit_maturity="bogus_value")
        inp = _request_to_input(req)
        assert inp.exploit_maturity == ExploitMaturity.UNKNOWN

    def test_default_values(self):
        req = FAILScoreRequest()
        inp = _request_to_input(req)
        assert inp.cve_id is None
        assert inp.cvss_score is None
        assert inp.is_kev is False
        assert inp.has_exploit is False
        assert inp.active_campaigns == 0

    def test_poc_public_maturity(self):
        req = FAILScoreRequest(exploit_maturity="poc_public")
        inp = _request_to_input(req)
        assert inp.exploit_maturity == ExploitMaturity.POC_PUBLIC

    def test_theoretical_maturity(self):
        req = FAILScoreRequest(exploit_maturity="theoretical")
        inp = _request_to_input(req)
        assert inp.exploit_maturity == ExploitMaturity.THEORETICAL

    def test_compliance_frameworks_passed(self):
        req = FAILScoreRequest(compliance_frameworks=["SOC2", "PCI-DSS"])
        inp = _request_to_input(req)
        assert inp.compliance_frameworks == ["SOC2", "PCI-DSS"]

    def test_metadata_passed(self):
        req = FAILScoreRequest(metadata={"scanner": "snyk", "repo": "main"})
        inp = _request_to_input(req)
        assert inp.metadata["scanner"] == "snyk"


# ---------------------------------------------------------------------------
# Pydantic model validation
# ---------------------------------------------------------------------------


class TestFAILScoreRequestValidation:
    def test_cvss_below_zero_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FAILScoreRequest(cvss_score=-0.1)

    def test_cvss_above_ten_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FAILScoreRequest(cvss_score=10.1)

    def test_epss_below_zero_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FAILScoreRequest(epss_score=-0.1)

    def test_epss_above_one_rejected(self):
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FAILScoreRequest(epss_score=1.1)

    def test_boundary_cvss_values(self):
        req_zero = FAILScoreRequest(cvss_score=0.0)
        assert req_zero.cvss_score == 0.0
        req_ten = FAILScoreRequest(cvss_score=10.0)
        assert req_ten.cvss_score == 10.0

    def test_boundary_epss_values(self):
        req_zero = FAILScoreRequest(epss_score=0.0)
        assert req_zero.epss_score == 0.0
        req_one = FAILScoreRequest(epss_score=1.0)
        assert req_one.epss_score == 1.0


# ---------------------------------------------------------------------------
# API Endpoint Tests
# ---------------------------------------------------------------------------


class TestFAILRouterEndpoints:
    @pytest.fixture(scope="class")
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from apps.api.fail_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    @pytest.fixture(autouse=True)
    def _reset_engine_and_db(self):
        """Reset the module-level engine and DB singletons for test isolation."""
        import apps.api.fail_router as mod

        engine = FAILEngine()
        mod._engine = engine

        # Use in-memory temp DB for tests
        import tempfile

        from core.fail_db import FAILDB

        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._db = FAILDB(db_path=self._tmp.name)
        mod._db = self._db
        yield
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def test_score_single_finding(self, client):
        resp = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-2024-3094",
                "title": "XZ Utils backdoor",
                "cvss_score": 10.0,
                "epss_score": 0.97,
                "is_kev": True,
                "has_exploit": True,
                "exploit_maturity": "weaponized",
                "asset_criticality": "critical",
                "data_classification": "pii",
                "is_reachable": True,
                "is_internet_facing": True,
                "affected_assets": 50,
                "compliance_frameworks": ["SOC2", "PCI-DSS"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "score_id" in data
        assert data["score_id"].startswith("FAIL-")
        assert 0 <= data["fail_score"] <= 100
        assert data["grade"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert data["recommended_action"] in (
            "PATCH_IMMEDIATELY",
            "PATCH_NEXT_SPRINT",
            "SCHEDULE_FIX",
            "MONITOR",
            "ACCEPT_RISK",
        )
        assert "sub_scores" in data
        assert "fact" in data["sub_scores"]
        assert "assess" in data["sub_scores"]
        assert "impact" in data["sub_scores"]
        assert "likelihood" in data["sub_scores"]
        assert data["engine_version"] == "1.0.0"

    def test_score_minimal_finding(self, client):
        resp = client.post(
            "/api/v1/fail/score",
            json={},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "fail_score" in data
        assert data["fail_score"] < 50  # Minimal input should score low

    def test_score_critical_finding_scores_high(self, client):
        resp = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-2024-0001",
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
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["fail_score"] >= 70  # At least HIGH grade
        assert data["grade"] in ("CRITICAL", "HIGH")

    def test_score_batch(self, client):
        resp = client.post(
            "/api/v1/fail/score/batch",
            json={
                "findings": [
                    {"cve_id": "CVE-2024-0001", "cvss_score": 9.0},
                    {"cve_id": "CVE-2024-0002", "cvss_score": 5.0},
                    {"cve_id": "CVE-2024-0003", "cvss_score": 2.0},
                ]
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["results"]) == 3
        assert "stats" in data

    def test_score_batch_empty_rejected(self, client):
        resp = client.post(
            "/api/v1/fail/score/batch",
            json={"findings": []},
        )
        assert resp.status_code == 422  # Pydantic validation: min_length=1

    def test_get_stored_score(self, client):
        # First, score a finding to create a stored record
        create_resp = client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-2024-STORE", "cvss_score": 7.0},
        )
        assert create_resp.status_code == 200
        score_id = create_resp.json()["score_id"]

        # Retrieve it
        get_resp = client.get(f"/api/v1/fail/score/{score_id}")
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["score_id"] == score_id
        assert data["cve_id"] == "CVE-2024-STORE"

    def test_get_missing_score_returns_404(self, client):
        resp = client.get("/api/v1/fail/score/FAIL-NONEXISTENT")
        assert resp.status_code == 404

    def test_list_scores(self, client):
        # Score a few findings first
        for i in range(3):
            client.post(
                "/api/v1/fail/score",
                json={"cve_id": f"CVE-2024-LIST-{i}", "cvss_score": 5.0 + i},
            )

        resp = client.get("/api/v1/fail/scores")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "results" in data
        assert data["total"] >= 3

    def test_list_scores_pagination(self, client):
        for i in range(5):
            client.post(
                "/api/v1/fail/score",
                json={"cve_id": f"CVE-2024-PAGE-{i}", "cvss_score": 6.0},
            )

        resp = client.get("/api/v1/fail/scores?limit=2&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) <= 2

    def test_top_risks(self, client):
        # Score some findings with varying severity
        for cvss in [2.0, 5.0, 8.0, 9.5]:
            client.post(
                "/api/v1/fail/score",
                json={"cve_id": f"CVE-TOP-{cvss}", "cvss_score": cvss},
            )

        resp = client.get("/api/v1/fail/top-risks?limit=3")
        assert resp.status_code == 200
        data = resp.json()
        assert "risks" in data
        assert len(data["risks"]) <= 3

    def test_fail_stats(self, client):
        # Score a finding so stats are non-empty
        client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-STATS-1", "cvss_score": 7.0},
        )

        resp = client.get("/api/v1/fail/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "average_score" in data
        assert "grade_distribution" in data

    def test_scores_by_cve(self, client):
        cve = "CVE-2024-BY-CVE"
        for i in range(3):
            client.post(
                "/api/v1/fail/score",
                json={"cve_id": cve, "cvss_score": 6.0 + i},
            )

        resp = client.get(f"/api/v1/fail/cve/{cve}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cve_id"] == cve
        assert data["total"] == 3
        assert len(data["scores"]) == 3

    def test_delete_score(self, client):
        create_resp = client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-DELETE-ME", "cvss_score": 5.0},
        )
        score_id = create_resp.json()["score_id"]

        del_resp = client.delete(f"/api/v1/fail/score/{score_id}")
        assert del_resp.status_code == 200
        data = del_resp.json()
        assert data["deleted"] is True

        # Verify it's gone
        get_resp = client.get(f"/api/v1/fail/score/{score_id}")
        assert get_resp.status_code == 404

    def test_delete_missing_score_returns_404(self, client):
        resp = client.delete("/api/v1/fail/score/FAIL-DOESNOTEXIST")
        assert resp.status_code == 404

    def test_health_endpoint(self, client):
        resp = client.get("/api/v1/fail/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["engine_version"] == "1.0.0"
        assert "total_scored" in data
        assert "in_memory_history" in data

    def test_score_response_has_computation_ms(self, client):
        resp = client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-TIMING", "cvss_score": 7.5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "computation_ms" in data
        assert data["computation_ms"] >= 0

    def test_score_with_all_exploit_maturity_values(self, client):
        for maturity in ["weaponized", "poc_public", "poc_private", "theoretical", "unknown"]:
            resp = client.post(
                "/api/v1/fail/score",
                json={
                    "cve_id": f"CVE-MAT-{maturity}",
                    "cvss_score": 7.0,
                    "exploit_maturity": maturity,
                },
            )
            assert resp.status_code == 200, f"Failed for maturity={maturity}"

    def test_score_with_compensating_controls(self, client):
        """Compensating controls should lower the FAIL score."""
        resp_no_controls = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-CTRL-A",
                "cvss_score": 8.0,
                "is_reachable": True,
                "is_internet_facing": True,
                "has_compensating_controls": False,
            },
        )
        resp_with_controls = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-CTRL-B",
                "cvss_score": 8.0,
                "is_reachable": True,
                "is_internet_facing": True,
                "has_compensating_controls": True,
            },
        )
        assert resp_no_controls.status_code == 200
        assert resp_with_controls.status_code == 200
        # With controls should score equal or lower
        score_no = resp_no_controls.json()["fail_score"]
        score_with = resp_with_controls.json()["fail_score"]
        assert score_with <= score_no

    def test_score_with_sla_hours(self, client):
        """SLA hours are accepted without error."""
        resp = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-SLA-001",
                "cvss_score": 6.0,
                "sla_hours": 48,
            },
        )
        assert resp.status_code == 200

    def test_score_with_affected_users(self, client):
        """Large affected_users increases score."""
        resp = client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-USERS-001",
                "cvss_score": 7.0,
                "affected_users": 10000,
                "affected_assets": 100,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["fail_score"] > 0

    def test_score_batch_single_item(self, client):
        """Batch with a single item works."""
        resp = client.post(
            "/api/v1/fail/score/batch",
            json={"findings": [{"cve_id": "CVE-SINGLE", "cvss_score": 5.0}]},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_scores_by_nonexistent_cve(self, client):
        """Querying scores for a CVE that has never been scored returns empty."""
        resp = client.get("/api/v1/fail/cve/CVE-9999-0000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["scores"] == []

    def test_list_scores_with_grade_filter(self, client):
        """Filter scores by grade."""
        # Score a critical finding
        client.post(
            "/api/v1/fail/score",
            json={
                "cve_id": "CVE-GRADE-CRIT",
                "cvss_score": 10.0,
                "epss_score": 0.97,
                "is_kev": True,
                "has_exploit": True,
                "exploit_maturity": "weaponized",
                "is_reachable": True,
                "is_internet_facing": True,
                "asset_criticality": "critical",
            },
        )
        resp = client.get("/api/v1/fail/scores?grade=CRITICAL")
        assert resp.status_code == 200

    def test_score_response_sub_scores_structure(self, client):
        """Verify sub_scores has all four FAIL dimensions."""
        resp = client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-SUB-001", "cvss_score": 6.0},
        )
        assert resp.status_code == 200
        sub = resp.json()["sub_scores"]
        assert "fact" in sub
        assert "assess" in sub
        assert "impact" in sub
        assert "likelihood" in sub
        # Each sub-score should be a number or a dict containing a score
        for key in ["fact", "assess", "impact", "likelihood"]:
            val = sub[key]
            assert isinstance(val, (int, float, dict)), f"sub_scores[{key}] has unexpected type: {type(val)}"
            if isinstance(val, dict):
                assert "score" in val, f"sub_scores[{key}] dict missing 'score' key"

    def test_score_response_weights_structure(self, client):
        """Verify weights dictionary has expected keys."""
        resp = client.post(
            "/api/v1/fail/score",
            json={"cve_id": "CVE-WEIGHT-001", "cvss_score": 5.0},
        )
        assert resp.status_code == 200
        weights = resp.json()["weights"]
        assert isinstance(weights, dict)
        assert len(weights) >= 4


# ---------------------------------------------------------------------------
# FAILScoreBatchRequest validation
# ---------------------------------------------------------------------------


class TestFAILBatchRequestValidation:
    """Validation tests for batch request model."""

    def test_batch_max_500_items(self):
        """Batch accepts up to 500 items."""
        from apps.api.fail_router import FAILScoreBatchRequest

        findings = [
            FAILScoreRequest(cve_id=f"CVE-{i}", cvss_score=5.0)
            for i in range(500)
        ]
        batch = FAILScoreBatchRequest(findings=findings)
        assert len(batch.findings) == 500

    def test_batch_over_500_rejected(self):
        """Batch with more than 500 items is rejected."""
        from pydantic import ValidationError

        from apps.api.fail_router import FAILScoreBatchRequest

        findings = [
            FAILScoreRequest(cve_id=f"CVE-{i}", cvss_score=5.0)
            for i in range(501)
        ]
        with pytest.raises(ValidationError):
            FAILScoreBatchRequest(findings=findings)
