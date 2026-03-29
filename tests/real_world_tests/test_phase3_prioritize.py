"""
Phase 3 — Prioritize & Decide
Owner: Vulnerability Manager + Security Architect

Validates:
- FAIL scoring engine
- Risk ranking and prioritization
- Ownership assignment
- Decision queue generation
- Brain pipeline readiness
"""
import pytest


class TestFAILScoring:
    """Risk Manager: Verify FAIL scoring engine is operational."""

    def test_fail_scores(self, api):
        """Retrieve FAIL scores list."""
        r = api.get("/api/v1/fail/scores")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, (dict, list))

    def test_fail_top_risks(self, api):
        r = api.get("/api/v1/fail/top-risks")
        assert r.status_code == 200

    def test_fail_stats(self, api):
        r = api.get("/api/v1/fail/stats")
        assert r.status_code == 200

    def test_fail_history(self, api):
        """Retrieve FAIL score history."""
        r = api.get("/api/v1/fail/history")
        assert r.status_code == 200


class TestBrainPipeline:
    """Security Architect: Verify brain pipeline decision engine."""

    def test_brain_stats(self, api):
        r = api.get("/api/v1/brain/stats")
        assert r.status_code == 200

    def test_brain_nodes(self, api):
        r = api.get("/api/v1/brain/nodes")
        assert r.status_code == 200

    def test_brain_most_connected(self, api):
        r = api.get("/api/v1/brain/most-connected")
        assert r.status_code == 200


class TestRiskAnalytics:
    """Risk Manager: Verify analytics and predictions."""

    def test_risk_velocity(self, api):
        r = api.get("/api/v1/analytics/risk-velocity")
        assert r.status_code == 200

    def test_coverage_analysis(self, api):
        r = api.get("/api/v1/analytics/coverage")
        assert r.status_code == 200

    def test_triage_funnel(self, api):
        r = api.get("/api/v1/analytics/triage-funnel")
        assert r.status_code == 200

    def test_noise_reduction(self, api):
        r = api.get("/api/v1/analytics/noise-reduction")
        assert r.status_code == 200


class TestPredictions:
    """Data Scientist: Verify ML predictions are available."""

    def test_risk_trajectory(self, api):
        r = api.post("/api/v1/predictions/risk-trajectory", json={
            "asset_id": "web-app",
            "timeframe_days": 30,
        })
        assert r.status_code == 200

    def test_ml_status(self, api):
        r = api.get("/api/v1/ml/status")
        assert r.status_code == 200

    def test_ml_models(self, api):
        r = api.get("/api/v1/ml/models")
        assert r.status_code == 200


class TestTriageQueue:
    """AppSec Lead: Verify prioritized queue is available."""

    def test_remediation_backlog(self, api):
        r = api.get("/api/v1/remediation/backlog")
        assert r.status_code == 200

    def test_remediation_tasks(self, api):
        r = api.get("/api/v1/remediation/tasks")
        assert r.status_code == 200

    def test_dashboard_top_risks(self, api):
        r = api.get("/api/v1/analytics/dashboard/top-risks")
        assert r.status_code == 200

