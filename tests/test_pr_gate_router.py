"""Tests for PR Gate & CI/CD Gate router."""

import os
import pytest
from unittest.mock import patch, MagicMock

os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create test client with API key auth."""
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app)


@pytest.fixture
def api_headers():
    return {"X-API-Key": os.environ["FIXOPS_API_TOKEN"]}


# ---------------------------------------------------------------------------
# Evaluate endpoint
# ---------------------------------------------------------------------------


class TestEvaluateGate:
    """Tests for POST /api/v1/pr-gate/evaluate."""

    def test_pass_with_no_findings(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={"findings": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "pass"
        assert data["exit_code"] == 0
        assert data["findings_total"] == 0

    def test_fail_on_critical_finding(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "f1",
                        "title": "SQL Injection",
                        "severity": "critical",
                        "category": "sast",
                    }
                ]
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "fail"
        assert data["exit_code"] == 1
        assert len(data["blocking_findings"]) == 1

    def test_fail_on_high_finding_default_policy(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "f2",
                        "title": "XSS",
                        "severity": "high",
                        "category": "sast",
                    }
                ],
                "policy": {
                    "fail_on": "high",
                    "warn_on": "medium",
                    "max_high": 0,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "fail"
        assert data["exit_code"] == 1

    def test_warn_on_medium_finding(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "f3",
                        "title": "Missing CSRF Token",
                        "severity": "medium",
                        "category": "sast",
                    }
                ],
                "policy": {
                    "fail_on": "high",
                    "warn_on": "medium",
                    "max_high": 0,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "warn"
        assert data["exit_code"] == 2

    def test_pass_on_low_finding(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "f4",
                        "title": "Info Disclosure",
                        "severity": "low",
                        "category": "sast",
                    }
                ],
                "policy": {
                    "fail_on": "high",
                    "warn_on": "medium",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "pass"

    def test_custom_policy_fail_on_medium(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "f5",
                        "title": "Weak Hash",
                        "severity": "medium",
                        "category": "sast",
                    }
                ],
                "policy": {
                    "fail_on": "medium",
                    "warn_on": "low",
                },
            },
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "fail"

    def test_secrets_always_block(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "s1",
                        "title": "AWS Secret Key",
                        "severity": "info",
                        "category": "secret",
                    }
                ],
                "policy": {"block_secrets": True, "fail_on": "critical"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "fail"

    def test_unreachable_findings_skipped_by_default(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "u1",
                        "title": "Unreachable Vuln",
                        "severity": "critical",
                        "category": "sast",
                        "reachable": False,
                    }
                ]
            },
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "pass"

    def test_unreachable_findings_blocked_when_policy_set(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "u2",
                        "title": "Unreachable Vuln",
                        "severity": "critical",
                        "category": "sast",
                        "reachable": False,
                    }
                ],
                "policy": {"block_unreachable": True},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "fail"

    def test_evaluation_returns_severity_counts(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={
                "findings": [
                    {"id": "c1", "title": "SQLi", "severity": "critical", "category": "sast"},
                    {"id": "h1", "title": "XSS", "severity": "high", "category": "sast"},
                    {"id": "m1", "title": "CSRF", "severity": "medium", "category": "sast"},
                ],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["findings_by_severity"]["critical"] == 1
        assert data["findings_by_severity"]["high"] == 1
        assert data["findings_by_severity"]["medium"] == 1

    def test_evaluation_has_id_and_timestamp(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={"findings": []},
        )
        data = resp.json()
        assert "evaluation_id" in data
        assert "evaluated_at" in data


# ---------------------------------------------------------------------------
# CI Gate endpoint
# ---------------------------------------------------------------------------


class TestCIGate:
    """Tests for POST /api/v1/pr-gate/ci-gate."""

    def test_ci_gate_pass(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/ci-gate",
            headers=api_headers,
            json={"findings": []},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "pass"
        assert data["exit_code"] == 0

    def test_ci_gate_fail(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/ci-gate",
            headers=api_headers,
            json={
                "findings": [
                    {
                        "id": "ci1",
                        "title": "Critical Bug",
                        "severity": "critical",
                        "category": "sast",
                    }
                ]
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["verdict"] == "fail"
        assert data["exit_code"] == 1
        assert data["blocking_count"] == 1

    def test_ci_gate_text_format(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/ci-gate",
            headers=api_headers,
            json={
                "findings": [],
                "format": "text",
            },
        )
        data = resp.json()
        assert "text_output" in data
        assert "PASS" in data["text_output"]

    def test_ci_gate_with_pipeline_metadata(self, client, api_headers):
        resp = client.post(
            "/api/v1/pr-gate/ci-gate",
            headers=api_headers,
            json={
                "findings": [],
                "pipeline_id": "gh-123",
                "commit_sha": "abc123",
                "branch": "feature/test",
                "repository": "acme/web-app",
            },
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Policy endpoint
# ---------------------------------------------------------------------------


class TestPolicy:
    """Tests for GET/PUT /api/v1/pr-gate/policy."""

    def test_get_default_policy(self, client, api_headers):
        resp = client.get("/api/v1/pr-gate/policy", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "policy" in data
        # fail_on is configurable per-org; just verify it's a valid severity
        assert data["policy"]["fail_on"] in ("critical", "high", "medium", "low", "info")

    def test_update_policy(self, client, api_headers):
        resp = client.put(
            "/api/v1/pr-gate/policy",
            headers=api_headers,
            json={
                "fail_on": "critical",
                "warn_on": "high",
                "max_critical": 0,
                "max_high": 5,
                "block_secrets": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "updated"
        assert data["policy"]["fail_on"] == "critical"
        assert data["policy"]["max_high"] == 5


# ---------------------------------------------------------------------------
# History endpoint
# ---------------------------------------------------------------------------


class TestHistory:
    """Tests for GET /api/v1/pr-gate/history."""

    def test_get_empty_history(self, client, api_headers):
        resp = client.get("/api/v1/pr-gate/history", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "evaluations" in data

    def test_history_after_evaluation(self, client, api_headers):
        # First, create an evaluation
        client.post(
            "/api/v1/pr-gate/evaluate",
            headers=api_headers,
            json={"findings": [{"id": "h1", "title": "Test", "severity": "critical", "category": "sast"}]},
        )
        # Then check history
        resp = client.get("/api/v1/pr-gate/history", headers=api_headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Report endpoint (mocked GitHub)
# ---------------------------------------------------------------------------


class TestReport:
    """Tests for POST /api/v1/pr-gate/report."""

    def test_report_requires_github_config(self, client, api_headers):
        """Report should fail gracefully when GitHub is not configured."""
        resp = client.post(
            "/api/v1/pr-gate/report",
            headers=api_headers,
            json={
                "owner": "acme",
                "repo": "web-app",
                "head_sha": "abc123def456",
                "pr_number": 42,
                "findings": [
                    {"id": "r1", "title": "SQLi", "severity": "critical", "category": "sast"}
                ],
            },
        )
        # Without GITHUB_TOKEN set, should return 422
        assert resp.status_code == 422
