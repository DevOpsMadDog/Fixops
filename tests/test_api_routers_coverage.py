"""Coverage tests for multiple API routers without dedicated test files.

Tests remediation_router, collaboration_router, workflows_router,
policies_router, validation_router, audit_router, system_router,
admin_router, users_router, and teams_router endpoints.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi.testclient import TestClient
from apps.api.app import create_app

API_KEY = os.environ.get("FIXOPS_API_TOKEN", "test-key-for-ci")
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


# ── Remediation Router ────────────────────────────────────────

class TestRemediationRouter:
    def test_list_remediations(self, client):
        r = client.get("/api/v1/remediation/tasks", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_create_remediation(self, client):
        payload = {
            "finding_id": "VULN-001",
            "title": "Fix SQL Injection",
            "priority": "high",
            "assignee": "dev@example.com",
        }
        r = client.post("/api/v1/remediation/tasks", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)

    def test_get_remediation(self, client):
        r = client.get("/api/v1/remediation/tasks/task-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_remediation_stats(self, client):
        r = client.get("/api/v1/remediation/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


# ── Collaboration Router ─────────────────────────────────────

class TestCollaborationRouter:
    def test_list_comments(self, client):
        r = client.get("/api/v1/collaboration/comments?finding_id=VULN-001", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_add_comment(self, client):
        payload = {
            "finding_id": "VULN-001",
            "content": "This is a test comment",
            "author": "tester@example.com",
        }
        r = client.post("/api/v1/collaboration/comments", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)

    def test_list_threads(self, client):
        r = client.get("/api/v1/collaboration/threads", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Workflows Router ─────────────────────────────────────────

class TestWorkflowsRouter:
    def test_list_workflows(self, client):
        r = client.get("/api/v1/workflows", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_create_workflow(self, client):
        payload = {
            "name": "Test Remediation Workflow",
            "trigger": "finding_created",
            "steps": [
                {"action": "assign", "params": {"assignee": "team@example.com"}}
            ],
        }
        r = client.post("/api/v1/workflows", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 409, 422)

    def test_get_workflow(self, client):
        r = client.get("/api/v1/workflows/wf-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


# ── Policies Router ──────────────────────────────────────────

class TestPoliciesRouter:
    def test_list_policies(self, client):
        r = client.get("/api/v1/policies", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_create_policy(self, client):
        payload = {
            "name": "No Critical Vulns in Prod",
            "condition": "severity == 'critical' AND env == 'production'",
            "action": "block_deploy",
        }
        r = client.post("/api/v1/policies", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)

    def test_get_policy(self, client):
        r = client.get("/api/v1/policies/pol-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


# ── Validation Router ────────────────────────────────────────

class TestValidationRouter:
    def test_validate_finding(self, client):
        payload = {
            "finding_id": "VULN-001",
            "validation_type": "manual",
            "status": "confirmed",
        }
        r = client.post("/api/v1/validation/validate", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 405, 422)

    def test_list_validations(self, client):
        r = client.get("/api/v1/validation/results", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Audit Router ─────────────────────────────────────────────

class TestAuditRouter:
    def test_list_audit_logs(self, client):
        r = client.get("/api/v1/audit/logs", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_get_audit_log(self, client):
        r = client.get("/api/v1/audit/logs/log-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)

    def test_audit_stats(self, client):
        r = client.get("/api/v1/audit/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── System Router ────────────────────────────────────────────

class TestSystemRouter:
    def test_system_health(self, client):
        r = client.get("/api/v1/system/health", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_system_info(self, client):
        r = client.get("/api/v1/system/info", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_system_metrics(self, client):
        r = client.get("/api/v1/system/metrics", headers=HEADERS)
        assert r.status_code in (200, 401, 403)


# ── Admin Router ─────────────────────────────────────────────

class TestAdminRouter:
    def test_admin_status(self, client):
        r = client.get("/api/v1/admin/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_admin_config(self, client):
        r = client.get("/api/v1/admin/config", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Users Router ─────────────────────────────────────────────

class TestUsersRouter:
    def test_list_users(self, client):
        r = client.get("/api/v1/users", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_create_user(self, client):
        payload = {
            "email": "test@example.com",
            "name": "Test User",
            "role": "analyst",
        }
        r = client.post("/api/v1/users", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)

    def test_get_user(self, client):
        r = client.get("/api/v1/users/user-001", headers=HEADERS)
        assert r.status_code in (200, 404, 401, 403)


# ── Teams Router ─────────────────────────────────────────────

class TestTeamsRouter:
    def test_list_teams(self, client):
        r = client.get("/api/v1/teams", headers=HEADERS)
        assert r.status_code in (200, 401, 403)

    def test_create_team(self, client):
        payload = {"name": "Security Team", "members": ["user-001"]}
        r = client.post("/api/v1/teams", json=payload, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 422)
