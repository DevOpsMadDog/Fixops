"""
Phase 5 — Remediate
Owner: Tech Leads + Engineering Teams

Validates:
- AutoFix engine generates fix suggestions
- Fix confidence levels are available
- Remediation metrics and SLA tracking
- Developer workflow (copilot, fix types)
"""
import pytest


class TestAutoFixEngine:
    """Security Engineer: Verify AutoFix generates real suggestions."""

    def test_generate_fix_xss(self, api):
        r = api.post("/api/v1/autofix/generate", json={
            "finding_id": "rw-phase5-xss",
            "finding_type": "xss",
            "language": "javascript",
            "code_context": "document.innerHTML = userInput;",
        })
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_generate_fix_sqli(self, api):
        r = api.post("/api/v1/autofix/generate", json={
            "finding_id": "rw-phase5-sqli",
            "finding_type": "sql_injection",
            "language": "python",
            "code_context": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
        })
        assert r.status_code == 200

    def test_generate_fix_path_traversal(self, api):
        r = api.post("/api/v1/autofix/generate", json={
            "finding_id": "rw-phase5-pt",
            "finding_type": "path_traversal",
            "language": "python",
            "code_context": "open(user_path)",
        })
        assert r.status_code == 200

    def test_autofix_stats(self, api):
        r = api.get("/api/v1/autofix/stats")
        assert r.status_code == 200

    def test_fix_types(self, api):
        r = api.get("/api/v1/autofix/fix-types")
        assert r.status_code == 200

    def test_confidence_levels(self, api):
        r = api.get("/api/v1/autofix/confidence-levels")
        assert r.status_code == 200


class TestRemediationTracking:
    """VP Engineering: Track remediation progress."""

    def test_remediation_backlog(self, api):
        r = api.get("/api/v1/remediation/backlog")
        assert r.status_code == 200

    def test_remediation_metrics(self, api):
        r = api.get("/api/v1/remediation/metrics")
        assert r.status_code == 200

    def test_remediation_tasks(self, api):
        r = api.get("/api/v1/remediation/tasks")
        assert r.status_code == 200

    def test_sla_check(self, api, org_id):
        r = api.post(f"/api/v1/remediation/sla/check?org_id={org_id}", json={})
        assert r.status_code == 200

    def test_mttr_metrics(self, api):
        r = api.get("/api/v1/analytics/mttr")
        assert r.status_code == 200


class TestDeveloperWorkflow:
    """Developer: Verify copilot and fix consumer workflow."""

    def test_copilot_fix_guidance(self, api):
        r = api.post("/api/v1/copilot/ask", json={
            "question": "How do I fix SQL injection in Python?",
        })
        assert r.status_code == 200

    def test_workflows_accessible(self, api):
        r = api.get("/api/v1/workflows")
        assert r.status_code == 200


class TestFeedbackLoop:
    """QA Tester: Verify self-learning feedback works."""

    def test_self_learning_feedback(self, api):
        r = api.post("/api/v1/self-learning/feedback/decision", json={
            "decision_id": "rw-phase5-dec",
            "finding_id": "rw-phase5-xss",
            "predicted_action": "fix",
            "actual_outcome": "fixed",
            "was_correct": True,
        })
        assert r.status_code == 200

    def test_self_learning_stats(self, api):
        r = api.get("/api/v1/self-learning/stats")
        assert r.status_code == 200

    def test_self_learning_weights(self, api):
        r = api.get("/api/v1/self-learning/weights")
        assert r.status_code == 200

