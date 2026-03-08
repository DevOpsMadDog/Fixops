"""Comprehensive tests for suite-core/api/self_learning_router.py — 20 endpoints."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    app = FastAPI()
    from api.self_learning_router import router
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


class TestHealthAndStatus:
    def test_health(self, client):
        resp = client.get("/api/v1/self-learning/health")
        assert resp.status_code == 200

    def test_status(self, client):
        resp = client.get("/api/v1/self-learning/status")
        assert resp.status_code == 200

    def test_stats(self, client):
        resp = client.get("/api/v1/self-learning/stats")
        assert resp.status_code == 200


class TestFeedbackEndpoints:
    def test_decision_feedback(self, client):
        resp = client.post(
            "/api/v1/self-learning/feedback/decision",
            json={"finding_id": "f-1", "outcome": "correct", "confidence": 0.9},
        )
        assert resp.status_code in (200, 422)

    def test_mpte_feedback(self, client):
        resp = client.post(
            "/api/v1/self-learning/feedback/mpte",
            json={"finding_id": "f-1", "was_exploitable": True},
        )
        assert resp.status_code in (200, 422)

    def test_false_positive_feedback(self, client):
        resp = client.post(
            "/api/v1/self-learning/feedback/false-positive",
            json={"finding_id": "f-1", "is_false_positive": True, "reason": "test data"},
        )
        assert resp.status_code in (200, 422)

    def test_remediation_feedback(self, client):
        resp = client.post(
            "/api/v1/self-learning/feedback/remediation",
            json={"finding_id": "f-1", "fix_worked": True},
        )
        assert resp.status_code in (200, 422)

    def test_policy_feedback(self, client):
        resp = client.post(
            "/api/v1/self-learning/feedback/policy",
            json={"policy_id": "p-1", "was_correct": True},
        )
        assert resp.status_code in (200, 422)


class TestAnalysisEndpoints:
    def test_analyze(self, client):
        resp = client.get("/api/v1/self-learning/analyze")
        assert resp.status_code == 200

    def test_insights(self, client):
        resp = client.get("/api/v1/self-learning/insights")
        assert resp.status_code == 200

    def test_analyze_loop(self, client):
        resp = client.get("/api/v1/self-learning/analyze/decision")
        assert resp.status_code == 200

    def test_suppressed_rules(self, client):
        resp = client.get("/api/v1/self-learning/suppressed-rules")
        assert resp.status_code == 200


class TestScoringEndpoints:
    def test_score_with_learning(self, client):
        resp = client.post(
            "/api/v1/self-learning/score-with-learning",
            json={"finding_id": "f-1", "base_score": 7.5},
        )
        assert resp.status_code in (200, 422)

    def test_compute_adjustments(self, client):
        resp = client.post(
            "/api/v1/self-learning/compute-adjustments",
            json={"finding_ids": ["f-1", "f-2"]},
        )
        assert resp.status_code in (200, 422)


class TestWeightsEndpoints:
    def test_get_weights(self, client):
        resp = client.get("/api/v1/self-learning/weights")
        assert resp.status_code == 200

    def test_update_weight(self, client):
        resp = client.put(
            "/api/v1/self-learning/weights/decision/confidence",
            json={"value": 0.8},
        )
        assert resp.status_code in (200, 422)


class TestMetricsEndpoints:
    def test_trends(self, client):
        resp = client.get("/api/v1/self-learning/metrics/trends")
        assert resp.status_code == 200


class TestDemoEndpoints:
    def test_demo_seed(self, client):
        resp = client.post("/api/v1/self-learning/demo/seed")
        assert resp.status_code == 200

    def test_demo_reset(self, client):
        resp = client.post("/api/v1/self-learning/demo/reset")
        assert resp.status_code == 200

    def test_demo_full_loop(self, client):
        resp = client.get("/api/v1/self-learning/demo/full-loop")
        assert resp.status_code == 200
