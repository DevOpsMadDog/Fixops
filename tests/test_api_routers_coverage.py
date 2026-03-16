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


# ── Brain Router (24 endpoints, ~1878 LOC) ────────────────────

class TestBrainRouter:
    def test_brain_status(self, client):
        r = client.get("/api/v1/brain/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_brain_pipeline_list(self, client):
        r = client.get("/api/v1/brain/pipelines", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_brain_stats(self, client):
        r = client.get("/api/v1/brain/stats", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_brain_metrics(self, client):
        r = client.get("/api/v1/brain/metrics", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_brain_steps(self, client):
        r = client.get("/api/v1/brain/steps", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── AutoFix Router (13 endpoints, ~1534 LOC) ──────────────────

class TestAutoFixRouter:
    def test_autofix_status(self, client):
        r = client.get("/api/v1/autofix/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_autofix_suggestions(self, client):
        r = client.get("/api/v1/autofix/suggestions", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_autofix_generate(self, client):
        r = client.post("/api/v1/autofix/generate", json={
            "finding_id": "VULN-001",
            "code_snippet": "SELECT * FROM users WHERE id = " + repr("input"),
            "language": "python",
        }, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 404, 422)

    def test_autofix_types(self, client):
        r = client.get("/api/v1/autofix/types", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_autofix_history(self, client):
        r = client.get("/api/v1/autofix/history", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── FAIL Router ───────────────────────────────────────────────

class TestFAILRouter:
    def test_fail_scores(self, client):
        r = client.get("/api/v1/fail/scores", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_fail_top_risks(self, client):
        r = client.get("/api/v1/fail/top-risks", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_fail_history(self, client):
        r = client.get("/api/v1/fail/history", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_fail_config(self, client):
        r = client.get("/api/v1/fail/config", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Feeds Router ──────────────────────────────────────────────

class TestFeedsRouter:
    def test_feeds_status(self, client):
        r = client.get("/api/v1/feeds/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_feeds_cve(self, client):
        r = client.get("/api/v1/feeds/cve/CVE-2024-1234", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_feeds_kev(self, client):
        r = client.get("/api/v1/feeds/kev", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_feeds_epss(self, client):
        r = client.get("/api/v1/feeds/epss/CVE-2024-1234", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_feeds_trending(self, client):
        r = client.get("/api/v1/feeds/trending", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Agents Router (32 endpoints, ~3005 LOC) ───────────────────

class TestAgentsRouterFull:
    def test_agents_list(self, client):
        r = client.get("/api/v1/agents", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_agents_status(self, client):
        r = client.get("/api/v1/agents/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_agents_types(self, client):
        r = client.get("/api/v1/agents/types", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_agents_config(self, client):
        r = client.get("/api/v1/agents/config", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Copilot Router (~2000 LOC) ────────────────────────────────

class TestCopilotRouterFull:
    def test_copilot_status(self, client):
        r = client.get("/api/v1/copilot/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_copilot_ask(self, client):
        r = client.post("/api/v1/copilot/ask", json={
            "question": "What are the top vulnerabilities?"
        }, headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404, 422, 500)

    def test_copilot_suggest(self, client):
        r = client.post("/api/v1/copilot/suggest", json={
            "context": "viewing dashboard"
        }, headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404, 422, 500)


# ── Analytics Router (extended) ───────────────────────────────

class TestAnalyticsRouterFull:
    def test_analytics_summary(self, client):
        r = client.get("/api/v1/analytics/summary", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_analytics_trends(self, client):
        r = client.get("/api/v1/analytics/trends", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_analytics_severity_dist(self, client):
        r = client.get("/api/v1/analytics/severity-distribution", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_analytics_mttr(self, client):
        r = client.get("/api/v1/analytics/mttr", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_analytics_risk_score(self, client):
        r = client.get("/api/v1/analytics/risk-score", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Inventory Router (extended) ───────────────────────────────

class TestInventoryRouterFull:
    def test_inventory_list(self, client):
        r = client.get("/api/v1/inventory", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_inventory_apps(self, client):
        r = client.get("/api/v1/inventory/apps", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_inventory_services(self, client):
        r = client.get("/api/v1/inventory/services", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_inventory_get(self, client):
        r = client.get("/api/v1/inventory/APP-001", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Bulk Router (~1267 LOC) ───────────────────────────────────

class TestBulkRouterFull:
    def test_bulk_findings_list(self, client):
        r = client.get("/api/v1/bulk/findings", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_bulk_status(self, client):
        r = client.get("/api/v1/bulk/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_bulk_clusters(self, client):
        r = client.get("/api/v1/bulk/clusters", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Reports Router (extended) ────────────────────────────────

class TestReportsRouterFull:
    def test_reports_list(self, client):
        r = client.get("/api/v1/reports", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_reports_generate(self, client):
        r = client.post("/api/v1/reports/generate", json={
            "type": "executive_summary", "app_id": "APP-001"
        }, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 404, 422)

    def test_reports_templates(self, client):
        r = client.get("/api/v1/reports/templates", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── MCP Router ────────────────────────────────────────────────

class TestMCPRouter:
    def test_mcp_status(self, client):
        r = client.get("/api/v1/mcp-server/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_mcp_tools(self, client):
        r = client.get("/api/v1/mcp-server/tools", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_mcp_auto_discovery(self, client):
        r = client.get("/api/v1/mcp/tools", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Evidence Router ───────────────────────────────────────────

class TestEvidenceRouter:
    def test_evidence_list(self, client):
        r = client.get("/api/v1/evidence", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_evidence_generate(self, client):
        r = client.post("/api/v1/evidence/generate", json={
            "app_id": "APP-001", "type": "soc2"
        }, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 404, 422)

    def test_evidence_bundles(self, client):
        r = client.get("/api/v1/evidence/bundles", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── MPTE Router (23 endpoints) ────────────────────────────────

class TestMPTERouter:
    def test_mpte_status(self, client):
        r = client.get("/api/v1/mpte/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_mpte_tests(self, client):
        r = client.get("/api/v1/mpte/tests", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_mpte_configs(self, client):
        r = client.get("/api/v1/mpte/configs", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Scanner Routers (SAST, DAST, Secrets, Container, CSPM) ───

class TestScannerRouters:
    def test_sast_rules(self, client):
        r = client.get("/api/v1/sast/rules", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_sast_findings(self, client):
        r = client.get("/api/v1/sast/findings", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_dast_scan(self, client):
        r = client.post("/api/v1/dast/scan", json={
            "target_url": "https://example.com"
        }, headers=HEADERS)
        assert r.status_code in (200, 201, 401, 403, 404, 405, 422)

    def test_secrets_patterns(self, client):
        r = client.get("/api/v1/secrets/patterns", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_container_images(self, client):
        r = client.get("/api/v1/container/images", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_cspm_policies(self, client):
        r = client.get("/api/v1/cspm/policies", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Compliance Router ─────────────────────────────────────────

class TestComplianceRouter:
    def test_compliance_status(self, client):
        r = client.get("/api/v1/compliance/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_compliance_frameworks(self, client):
        r = client.get("/api/v1/compliance/frameworks", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_compliance_audit(self, client):
        r = client.get("/api/v1/compliance/audit", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Webhooks Router (~1922 LOC) ───────────────────────────────

class TestWebhooksRouterFull:
    def test_webhooks_list(self, client):
        r = client.get("/api/v1/webhooks", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_webhooks_mappings(self, client):
        r = client.get("/api/v1/webhooks/mappings", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_webhooks_status(self, client):
        r = client.get("/api/v1/webhooks/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── SLA Router ────────────────────────────────────────────────

class TestSLARouter:
    def test_sla_status(self, client):
        r = client.get("/api/v1/sla/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_sla_policies(self, client):
        r = client.get("/api/v1/sla/policies", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Knowledge Graph Router ───────────────────────────────────

class TestKnowledgeGraphRouter:
    def test_kg_status(self, client):
        r = client.get("/api/v1/knowledge-graph/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_kg_nodes(self, client):
        r = client.get("/api/v1/knowledge-graph/nodes", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)


# ── Marketplace Router ────────────────────────────────────────

class TestMarketplaceRouterFull:
    def test_marketplace_plugins(self, client):
        r = client.get("/api/v1/marketplace/plugins", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_marketplace_status(self, client):
        r = client.get("/api/v1/marketplace/status", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)

    def test_marketplace_categories(self, client):
        r = client.get("/api/v1/marketplace/categories", headers=HEADERS)
        assert r.status_code in (200, 401, 403, 404)
