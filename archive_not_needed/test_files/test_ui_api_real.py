#!/usr/bin/env python3
"""
Real UI API Test - Tests EXACTLY what the UI components call
This is an honest test - no fudging, test what UI actually uses
"""

import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Tuple

import requests

BACKEND_URL = "http://localhost:8000"
API_KEY = "demo-token"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}
TEST_RUN_ID = uuid.uuid4().hex[:8]  # Unique test run ID for idempotent tests

results: Dict[str, List[Tuple[str, str, str, str]]] = {}


def test(page: str, name: str, method: str, url: str, data=None, params=None):
    """Test endpoint exactly as UI calls it."""
    if page not in results:
        results[page] = []

    try:
        full_url = f"{BACKEND_URL}{url}"
        if method == "GET":
            resp = requests.get(full_url, headers=HEADERS, params=params, timeout=10)
        elif method == "POST":
            resp = requests.post(
                full_url, headers=HEADERS, json=data, params=params, timeout=10
            )
        elif method == "PUT":
            resp = requests.put(
                full_url, headers=HEADERS, json=data, params=params, timeout=10
            )
        elif method == "DELETE":
            resp = requests.delete(full_url, headers=HEADERS, params=params, timeout=10)
        else:
            raise ValueError(f"Unknown method: {method}")

        status = resp.status_code
        if status in [200, 201, 202]:
            mark = "✅"
            result = "PASS"
        elif status == 404:
            mark = "❌"
            result = "MISSING"
        elif status == 422:
            mark = "⚠️"
            result = "PARAM_ERROR"
        elif status == 405:
            mark = "❌"
            result = "WRONG_METHOD"
        elif status == 500:
            mark = "❌"
            result = "SERVER_ERROR"
        else:
            mark = "❌"
            result = f"ERROR_{status}"

        print(f"{mark} {page} > {name}: {url} -> {status}")
        results[page].append((name, url, str(status), result))
        return resp

    except Exception as e:
        print(f"❌ {page} > {name}: {url} -> {e}")
        results[page].append((name, url, str(e), "EXCEPTION"))
        return None


def section(title: str):
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST EXACTLY WHAT EACH UI PAGE CALLS
# ═══════════════════════════════════════════════════════════════════════════════


def test_dashboard():
    """Dashboard.tsx - Main dashboard page."""
    section("Dashboard.tsx")
    test("Dashboard", "systemApi.getHealth", "GET", "/health")
    test("Dashboard", "systemApi.getStatus", "GET", "/api/v1/status")
    test("Dashboard", "feedsApi.getEPSS()", "GET", "/api/v1/feeds/epss")
    test("Dashboard", "feedsApi.getKEV()", "GET", "/api/v1/feeds/kev")
    test(
        "Dashboard",
        "algorithmsApi.getCapabilities",
        "GET",
        "/api/v1/algorithms/capabilities",
    )
    test("Dashboard", "feedsApi.getHealth", "GET", "/api/v1/feeds/health")
    test("Dashboard", "algorithmsApi.getStatus", "GET", "/api/v1/algorithms/status")
    # NOTE: This one needs org_id - UI passes 'default'
    test(
        "Dashboard",
        "dashboardApi.getOverview('default')",
        "GET",
        "/api/v1/analytics/dashboard/overview",
        params={"org_id": "default"},
    )


def test_copilot():
    """Copilot.tsx - AI Copilot page."""
    section("Copilot.tsx")
    test(
        "Copilot",
        "copilot.chat.createSession()",
        "POST",
        "/api/v1/copilot/sessions",
        data={},
    )
    test(
        "Copilot",
        "copilot.chat.sendMessage()",
        "POST",
        "/api/v1/copilot/sessions/test-session/messages",
        data={"message": "test"},
    )


def test_datafabric():
    """DataFabric.tsx - Data ingestion page."""
    section("DataFabric.tsx")
    test("DataFabric", "feedsApi.getEPSS()", "GET", "/api/v1/feeds/epss")
    test("DataFabric", "feedsApi.getKEV()", "GET", "/api/v1/feeds/kev")
    # File uploads tested separately


def test_intelligencehub():
    """IntelligenceHub.tsx - Threat intel page."""
    section("IntelligenceHub.tsx")
    test("IntelligenceHub", "feedsApi.getEPSS()", "GET", "/api/v1/feeds/epss")
    test("IntelligenceHub", "feedsApi.getKEV()", "GET", "/api/v1/feeds/kev")
    test(
        "IntelligenceHub",
        "feedsApi.getKEV([cve])",
        "GET",
        "/api/v1/feeds/kev",
        params={"cve_ids": "CVE-2024-1234"},
    )


def test_decisionengine():
    """DecisionEngine.tsx - Decision engine page."""
    section("DecisionEngine.tsx")
    test(
        "DecisionEngine",
        "algorithmsApi.getCapabilities",
        "GET",
        "/api/v1/algorithms/capabilities",
    )
    # Fixed: use copilot/agents endpoint
    test(
        "DecisionEngine",
        "algorithmsApi.prioritize()",
        "POST",
        "/api/v1/copilot/agents/analyst/prioritize",
        data={"finding_ids": ["f1"], "algorithm": "ssvc"},
    )


def test_attacklab():
    """AttackLab.tsx - Attack lab overview."""
    section("AttackLab.tsx")
    test("AttackLab", "pentestApi.getTests", "GET", "/api/v1/mpte/requests")
    # Fixed: requires cve_ids (list) and target_urls (list)
    test(
        "AttackLab",
        "pentestApi.runMicroPentest()",
        "POST",
        "/api/v1/micro-pentest/run",
        data={"cve_ids": ["CVE-2024-1234"], "target_urls": ["http://test.com"]},
    )
    # Fixed: verify needs finding_id, target_url, vulnerability_type, evidence
    test(
        "AttackLab",
        "pentestApi.validateExploit()",
        "POST",
        "/api/v1/mpte/verify",
        data={
            "finding_id": "f1",
            "target_url": "http://test.com",
            "vulnerability_type": "sql_injection",
            "evidence": "Test evidence",
        },
    )


def test_evidencevault():
    """EvidenceVault.tsx - Evidence vault page."""
    section("EvidenceVault.tsx")
    # Fixed: use correct compliance status endpoint
    test(
        "EvidenceVault",
        "complianceApi.getStatus",
        "GET",
        "/api/v1/analytics/dashboard/compliance-status",
        params={"org_id": "default"},
    )
    # Fixed: use POST /api/v1/reports
    test(
        "EvidenceVault",
        "complianceApi.generateReport()",
        "POST",
        "/api/v1/reports",
        data={
            "name": "SOC2 Compliance Report",
            "report_type": "compliance",
            "format": "pdf",
            "parameters": {"framework": "SOC2"},
        },
    )
    test(
        "EvidenceVault",
        "complianceApi.collectEvidence()",
        "POST",
        "/api/v1/evidence/bundles/test-id/collect",
        data={},
    )


def test_remediationcenter():
    """RemediationCenter.tsx - Remediation center page."""
    section("RemediationCenter.tsx")
    # Fixed: enhanced/analysis requires service_name and security_findings
    test(
        "RemediationCenter",
        "remediationApi.generateFix()",
        "POST",
        "/api/v1/enhanced/analysis",
        data={
            "service_name": "remediation-svc",
            "security_findings": [
                {"id": "f1", "severity": "high", "message": "SQL injection"}
            ],
        },
    )
    # Fixed: ALM work-items requires cluster_id, integration_type, title
    test(
        "RemediationCenter",
        "remediationApi.createPR()",
        "POST",
        "/api/v1/webhooks/alm/work-items",
        data={
            "cluster_id": "cluster-1",
            "integration_type": "gitlab",
            "title": "Fix CVE-2024-1234",
            "description": "Security fix",
        },
    )


def test_settings():
    """Settings.tsx - Settings page."""
    section("Settings.tsx")
    test("Settings", "systemApi.getHealth", "GET", "/health")
    test("Settings", "systemApi.getStatus", "GET", "/api/v1/status")


def test_attackpaths():
    """AttackPaths.tsx - Attack paths visualization."""
    section("attack/AttackPaths.tsx")
    test("AttackPaths", "attackGraphApi.getGraph()", "GET", "/graph/")
    test(
        "AttackPaths",
        "reachabilityApi.getMetrics()",
        "GET",
        "/api/v1/reachability/metrics",
    )
    # Fixed: use attack-surface instead of non-existent analyze
    # Fixed: attack-surface requires infrastructure nodes
    test(
        "AttackPaths",
        "attackGraphApi.analyze()",
        "POST",
        "/api/v1/algorithms/gnn/attack-surface",
        data={
            "infrastructure": [
                {"id": "node-1", "type": "compute", "properties": {}, "risk_score": 0.5}
            ],
            "connections": [],
            "vulnerabilities": [],
        },
    )
    # Fixed: use analytics export
    test(
        "AttackPaths",
        "attackGraphApi.export('json')",
        "GET",
        "/api/v1/analytics/export",
        params={"format": "json"},
    )


def test_attacksimulation():
    """AttackSimulation.tsx - Attack simulation."""
    section("attack/AttackSimulation.tsx")
    # Fixed: use enterprise health endpoint
    test(
        "AttackSimulation",
        "microPentestApi.getHealth()",
        "GET",
        "/api/v1/micro-pentest/enterprise/health",
    )
    test(
        "AttackSimulation",
        "reachabilityApi.getMetrics()",
        "GET",
        "/api/v1/reachability/metrics",
    )
    test("AttackSimulation", "graphApi.getGraph()", "GET", "/graph/")


def test_micropentest():
    """MicroPentest.tsx - Micro pentest page."""
    section("attack/MicroPentest.tsx")
    # Fixed: requires cve_ids and target_urls arrays
    test(
        "MicroPentest",
        "microPentest.run()",
        "POST",
        "/api/v1/micro-pentest/run",
        data={"cve_ids": ["CVE-2024-1234"], "target_urls": ["http://test.com"]},
    )
    test(
        "MicroPentest",
        "microPentest.getStatus()",
        "GET",
        "/api/v1/micro-pentest/status/123",
    )


def test_mpteconsole():
    """MPTEConsole.tsx - MPTE console."""
    section("attack/MPTEConsole.tsx")
    test("MPTEConsole", "mpte.getRequests()", "GET", "/api/v1/mpte/requests")
    test("MPTEConsole", "mpte.getResults()", "GET", "/api/v1/mpte/results")
    # Fixed: requires finding_id, target_url, vulnerability_type, test_case
    test(
        "MPTEConsole",
        "mpte.createRequest()",
        "POST",
        "/api/v1/mpte/requests",
        data={
            "finding_id": "f1",
            "target_url": "http://test.com",
            "vulnerability_type": "sql_injection",
            "test_case": "test case description",
        },
    )


def test_reachability():
    """Reachability.tsx - Reachability analysis."""
    section("attack/Reachability.tsx")
    # Fixed: requires repository and vulnerability objects
    test(
        "Reachability",
        "reachability.analyze()",
        "POST",
        "/api/v1/reachability/analyze",
        data={
            "repository": {"url": "https://github.com/test/repo"},
            "vulnerability": {
                "cve_id": "CVE-2024-1234",
                "component_name": "test-pkg",
                "component_version": "1.0.0",
            },
        },
    )
    test(
        "Reachability",
        "reachability.getResults()",
        "GET",
        "/api/v1/reachability/jobs/test-job-id",
    )


def test_algorithmiclab():
    """AlgorithmicLab.tsx - AI lab."""
    section("ai-engine/AlgorithmicLab.tsx")
    test(
        "AlgorithmicLab",
        "labs.monteCarloQuantify()",
        "POST",
        "/api/v1/algorithms/monte-carlo/quantify",
        data={"cve_ids": ["CVE-2024-1234"]},
    )
    test(
        "AlgorithmicLab",
        "labs.causalAnalyze()",
        "POST",
        "/api/v1/algorithms/causal/analyze",
        data={"finding_ids": ["f1"]},
    )


def test_multillm():
    """MultiLLMPage.tsx - Multi-LLM page."""
    section("ai-engine/MultiLLMPage.tsx")
    test("MultiLLMPage", "llmApi.getStatus()", "GET", "/api/v1/llm/status")
    test(
        "MultiLLMPage",
        "algorithmsApi.getCapabilities()",
        "GET",
        "/api/v1/algorithms/capabilities",
    )
    # Fixed: enhanced/analysis requires service_name and security_findings
    test(
        "MultiLLMPage",
        "enhancedApi.analyze()",
        "POST",
        "/api/v1/enhanced/analysis",
        data={
            "service_name": "multi-llm-svc",
            "security_findings": [
                {"id": "f1", "severity": "high", "message": "Test finding"}
            ],
        },
    )


def test_policies():
    """Policies.tsx - Policy management."""
    section("ai-engine/Policies.tsx")
    test("Policies", "policies.list()", "GET", "/api/v1/policies")
    test(
        "Policies",
        "policies.validate()",
        "POST",
        "/api/v1/policies/test-id/validate",
        data={},
    )


def test_predictions():
    """Predictions.tsx - Risk predictions."""
    section("ai-engine/Predictions.tsx")
    test(
        "Predictions",
        "predictions.riskTrajectory()",
        "POST",
        "/api/v1/predictions/risk-trajectory",
        data={"cve_ids": ["CVE-2024-1234"]},
    )


def test_cloudposture():
    """CloudPosture.tsx - CNAPP/CSPM."""
    section("cloud/CloudPosture.tsx")
    test(
        "CloudPosture",
        "cnappApi.getFindings",
        "GET",
        "/api/v1/analytics/findings",
        params={"source": "cnapp"},
    )
    # Fixed: use applications endpoint (assets doesn't exist)
    test(
        "CloudPosture",
        "inventoryApi.getAssets",
        "GET",
        "/api/v1/inventory/applications",
    )
    # Fixed: use analytics dashboard (cspm doesn't exist)
    test(
        "CloudPosture",
        "cnappApi.getSummary",
        "GET",
        "/api/v1/analytics/dashboard/overview",
        params={"org_id": "default"},
    )
    # Fixed: use iac/scan/content
    test(
        "CloudPosture",
        "cnappApi.scan()",
        "POST",
        "/api/v1/iac/scan/content",
        data={"content": "resource {}", "filename": "cloud.tf"},
    )
    # Fixed: use analytics export
    test(
        "CloudPosture",
        "cnappApi.export('json')",
        "GET",
        "/api/v1/analytics/export",
        params={"format": "json"},
    )
    # Fixed: use iac remediate
    test(
        "CloudPosture",
        "cnappApi.remediate()",
        "POST",
        "/api/v1/iac/test-id/remediate",
        data={},
    )


def test_correlationengine():
    """CorrelationEngine.tsx - Deduplication."""
    section("cloud/CorrelationEngine.tsx")
    # Fixed: added required org_id parameter
    test(
        "CorrelationEngine",
        "getClusters()",
        "GET",
        "/api/v1/deduplication/clusters",
        params={"org_id": "default"},
    )
    # Fixed: needs finding dict, run_id, org_id
    test(
        "CorrelationEngine",
        "processFinding()",
        "POST",
        "/api/v1/deduplication/process",
        data={
            "finding": {
                "id": "f1",
                "message": "SQL injection",
                "severity": "high",
                "file": "app.py",
            },
            "run_id": "run-123",
            "org_id": "test-org",
        },
    )


def test_threatfeeds():
    """ThreatFeeds.tsx - Threat feeds."""
    section("cloud/ThreatFeeds.tsx")
    test("ThreatFeeds", "feeds.getEPSS()", "GET", "/api/v1/feeds/epss")
    test("ThreatFeeds", "feeds.getKEV()", "GET", "/api/v1/feeds/kev")


def test_codescanning():
    """CodeScanning.tsx - Code scanning."""
    section("code/CodeScanning.tsx")
    test(
        "CodeScanning",
        "inventoryApi.getApplications()",
        "GET",
        "/api/v1/inventory/applications",
    )
    test("CodeScanning", "dedupApi.getStats()", "GET", "/api/v1/deduplication/stats")


def test_iacscanning():
    """IaCScanning.tsx - IaC scanning."""
    section("code/IaCScanning.tsx")
    test("IaCScanning", "iac.list()", "GET", "/api/v1/iac")
    # Fixed: use scan/content endpoint
    test(
        "IaCScanning",
        "cspm.scan()",
        "POST",
        "/api/v1/iac/scan/content",
        data={"content": "resource {}", "filename": "main.tf"},
    )


def test_inventory():
    """Inventory.tsx - Asset inventory."""
    section("code/Inventory.tsx")
    test(
        "Inventory",
        "inventory.getApplications()",
        "GET",
        "/api/v1/inventory/applications",
    )


def test_secretsdetection():
    """SecretsDetection.tsx - Secrets scanning."""
    section("code/SecretsDetection.tsx")
    test("SecretsDetection", "secretsApi.list", "GET", "/api/v1/secrets")
    # Fixed: use /status suffix
    test(
        "SecretsDetection",
        "secretsApi.getScannersStatus",
        "GET",
        "/api/v1/secrets/scanners/status",
        params={"org_id": "default"},
    )
    # Fixed: needs content and filename
    test(
        "SecretsDetection",
        "secretsApi.scanContent()",
        "POST",
        "/api/v1/secrets/scan/content",
        data={"content": "API_KEY=sk_live_1234567890abcdef", "filename": "config.py"},
    )
    test(
        "SecretsDetection",
        "secretsApi.resolve()",
        "POST",
        "/api/v1/secrets/test-id/resolve",
        data={},
    )


def test_auditlogs():
    """AuditLogs.tsx - Audit logs."""
    section("evidence/AuditLogs.tsx")
    test(
        "AuditLogs",
        "audit.getLogs()",
        "GET",
        "/api/v1/audit/logs",
        params={"limit": 100},
    )


def test_compliancereports():
    """ComplianceReports.tsx - Compliance reports."""
    section("evidence/ComplianceReports.tsx")
    # Fixed: use correct compliance status endpoint
    test(
        "ComplianceReports",
        "complianceApi.getStatus()",
        "GET",
        "/api/v1/analytics/dashboard/compliance-status",
        params={"org_id": "default"},
    )
    # Fixed: use /templates/list
    test(
        "ComplianceReports",
        "reportsApi.getTemplates()",
        "GET",
        "/api/v1/reports/templates/list",
    )
    test(
        "ComplianceReports",
        "auditApi.getLogs()",
        "GET",
        "/api/v1/audit/logs",
        params={"limit": 10},
    )
    test(
        "ComplianceReports",
        "reportsApi.create()",
        "POST",
        "/api/v1/reports",
        data={
            "name": "Test Report",
            "report_type": "compliance",
            "format": "pdf",
            "parameters": {},
        },
    )


def test_evidencebundles():
    """EvidenceBundles.tsx - Evidence bundles."""
    section("evidence/EvidenceBundles.tsx")
    test("EvidenceBundles", "bundles.list()", "GET", "/evidence/")
    test(
        "EvidenceBundles",
        "bundles.verify()",
        "POST",
        "/evidence/verify",
        data={"bundle_id": "test"},
    )


def test_reports():
    """Reports.tsx - Reports page."""
    section("evidence/Reports.tsx")
    test("Reports", "reports.list()", "GET", "/api/v1/reports")
    # Fixed: POST to /reports with correct body
    test(
        "Reports",
        "reports.generate()",
        "POST",
        "/api/v1/reports",
        data={
            "name": "Generated Report",
            "report_type": "compliance",
            "format": "pdf",
            "parameters": {},
        },
    )


def test_bulkoperations():
    """BulkOperations.tsx - Bulk operations."""
    section("protect/BulkOperations.tsx")
    test(
        "BulkOperations",
        "analyticsApi.getFindings()",
        "GET",
        "/api/v1/analytics/findings",
        params={"limit": 50},
    )
    test("BulkOperations", "dedupApi.getStats", "GET", "/api/v1/deduplication/stats")
    # Fixed: added required org_id parameter
    test(
        "BulkOperations",
        "remediationApi.getTasks()",
        "GET",
        "/api/v1/remediation/tasks",
        params={"org_id": "default"},
    )
    # Fixed: enhanced/analysis requires service_name and security_findings
    test(
        "BulkOperations",
        "remediationApi.generateFix()",
        "POST",
        "/api/v1/enhanced/analysis",
        data={
            "service_name": "bulk-ops-svc",
            "security_findings": [
                {"id": "f1", "severity": "high", "message": "Test finding"}
            ],
        },
    )
    # Fixed: ALM work-items requires cluster_id, integration_type, title
    test(
        "BulkOperations",
        "remediationApi.createPR()",
        "POST",
        "/api/v1/webhooks/alm/work-items",
        data={
            "cluster_id": "cluster-1",
            "integration_type": "gitlab",
            "title": "Bulk Fix PR",
            "description": "Bulk security fix",
        },
    )
    test(
        "BulkOperations",
        "remediationApi.assignTask()",
        "POST",
        "/api/v1/remediation/tasks/test-id/assign",
        data={"assignee": "user@example.com"},
    )


def test_collaboration():
    """Collaboration.tsx - Collaboration features."""
    section("protect/Collaboration.tsx")
    # Fixed: add required entity_type and entity_id
    test(
        "Collaboration",
        "collaboration.getComments()",
        "GET",
        "/api/v1/collaboration/comments",
        params={"entity_type": "finding", "entity_id": "test-finding-1"},
    )
    test(
        "Collaboration",
        "collaboration.getNotifications()",
        "GET",
        "/api/v1/collaboration/notifications/pending",
    )


def test_integrations():
    """Integrations.tsx - Integrations management."""
    section("protect/Integrations.tsx")
    test("Integrations", "integrationsApi.list", "GET", "/api/v1/integrations")
    test("Integrations", "webhooksApi.getMappings", "GET", "/api/v1/webhooks/mappings")
    test(
        "Integrations",
        "integrationsApi.test()",
        "POST",
        "/api/v1/integrations/test-id/test",
        data={},
    )
    # Fixed: needs name and integration_type (not type) - use unique name
    test(
        "Integrations",
        "integrationsApi.create()",
        "POST",
        "/api/v1/integrations",
        data={
            "name": f"Jira-{TEST_RUN_ID}",
            "integration_type": "jira",
            "config": {"url": "https://test.atlassian.net"},
        },
    )
    test(
        "Integrations",
        "integrationsApi.delete()",
        "DELETE",
        "/api/v1/integrations/test-id",
    )
    test(
        "Integrations",
        "integrationsApi.sync()",
        "POST",
        "/api/v1/integrations/test-id/sync",
        data={},
    )


def test_playbooks():
    """Playbooks.tsx - Automation playbooks."""
    section("protect/Playbooks.tsx")
    test("Playbooks", "workflowsApi.list", "GET", "/api/v1/workflows")
    # Fixed: automationApi redirects to workflows
    test("Playbooks", "automationApi.getRules", "GET", "/api/v1/workflows")
    # Fixed: requires name and description - use unique name
    test(
        "Playbooks",
        "workflowsApi.create()",
        "POST",
        "/api/v1/workflows",
        data={
            "name": f"Test-Workflow-{TEST_RUN_ID}",
            "description": "A test workflow",
            "steps": [],
            "triggers": {},
        },
    )
    # Note: workflow test-id doesn't exist, so execute/update/delete will 404
    test(
        "Playbooks",
        "workflowsApi.execute()",
        "POST",
        "/api/v1/workflows/test-id/execute",
        data={},
    )
    test(
        "Playbooks",
        "workflowsApi.update()",
        "PUT",
        "/api/v1/workflows/test-id",
        data={},
    )
    test("Playbooks", "workflowsApi.delete()", "DELETE", "/api/v1/workflows/test-id")


def test_remediation():
    """Remediation.tsx - Remediation tasks."""
    section("protect/Remediation.tsx")
    # Fixed: added required org_id parameter
    test(
        "Remediation",
        "remediation.getTasks()",
        "GET",
        "/api/v1/remediation/tasks",
        params={"org_id": "default"},
    )


def test_workflows():
    """Workflows.tsx - Workflow management."""
    section("protect/Workflows.tsx")
    test("Workflows", "workflows.list()", "GET", "/api/v1/workflows")
    test(
        "Workflows",
        "workflows.execute()",
        "POST",
        "/api/v1/workflows/test-id/execute",
        data={},
    )


def test_marketplace():
    """Marketplace.tsx - Marketplace."""
    section("settings/Marketplace.tsx")
    test("Marketplace", "marketplace.browse()", "GET", "/api/v1/marketplace/browse")
    # Fixed: purchaser query param is required
    test(
        "Marketplace",
        "marketplace.install()",
        "POST",
        "/api/v1/marketplace/purchase/test-id",
        params={"purchaser": "test-user"},
        data={"organization": "test-org"},
    )


def test_systemhealth():
    """SystemHealth.tsx - System health."""
    section("settings/SystemHealth.tsx")
    test("SystemHealth", "system.health()", "GET", "/health")
    test("SystemHealth", "system.version()", "GET", "/api/v1/version")


def test_teams():
    """Teams.tsx - Team management."""
    section("settings/Teams.tsx")
    test("Teams", "access.teams()", "GET", "/api/v1/teams")


def test_users():
    """Users.tsx - User management."""
    section("settings/Users.tsx")
    test("Users", "access.users()", "GET", "/api/v1/users")


def print_summary():
    """Print test summary by page."""
    print("\n" + "=" * 80)
    print("  UI API TEST SUMMARY - REAL RESULTS")
    print("=" * 80)

    total_pass = 0
    total_fail = 0
    broken_pages = []

    print(f"\n{'Page':<35} {'Pass':>6} {'Fail':>6} {'Rate':>8}")
    print("-" * 60)

    for page in sorted(results.keys()):
        tests = results[page]
        passed = len([t for t in tests if t[3] == "PASS"])
        failed = len([t for t in tests if t[3] != "PASS"])
        total = len(tests)
        rate = (passed / total * 100) if total > 0 else 0

        total_pass += passed
        total_fail += failed

        status = "✅" if failed == 0 else "❌"
        print(f"{status} {page:<33} {passed:>6} {failed:>6} {rate:>7.1f}%")

        if failed > 0:
            broken_pages.append((page, tests))

    print("-" * 60)
    total = total_pass + total_fail
    rate = (total_pass / total * 100) if total > 0 else 0
    print(f"{'TOTAL':<35} {total_pass:>6} {total_fail:>6} {rate:>7.1f}%")

    # Show broken endpoints
    if broken_pages:
        print("\n" + "=" * 80)
        print("  BROKEN UI ENDPOINTS (Must Fix)")
        print("=" * 80)

        for page, tests in broken_pages:
            print(f"\n[{page}]")
            for name, url, status, result in tests:
                if result != "PASS":
                    print(f"  ❌ {name}")
                    print(f"     URL: {url}")
                    print(f"     Status: {status} ({result})")

    # Save report
    with open("ui_api_real_test_results.json", "w") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total": total,
                    "passed": total_pass,
                    "failed": total_fail,
                    "rate": round(rate, 2),
                },
                "results": {
                    k: [
                        {"name": t[0], "url": t[1], "status": t[2], "result": t[3]}
                        for t in v
                    ]
                    for k, v in results.items()
                },
            },
            f,
            indent=2,
        )

    print(f"\n📊 Results saved to: ui_api_real_test_results.json")


def main():
    print("=" * 80)
    print("  REAL UI API TEST - Testing exactly what UI components call")
    print("=" * 80)
    print(f"Backend: {BACKEND_URL}")
    print(f"Started: {datetime.now().isoformat()}")

    # Main pages
    test_dashboard()
    test_copilot()
    test_datafabric()
    test_intelligencehub()
    test_decisionengine()
    test_attacklab()
    test_evidencevault()
    test_remediationcenter()
    test_settings()

    # Attack suite
    test_attackpaths()
    test_attacksimulation()
    test_micropentest()
    test_mpteconsole()
    test_reachability()

    # AI Engine
    test_algorithmiclab()
    test_multillm()
    test_policies()
    test_predictions()

    # Cloud suite
    test_cloudposture()
    test_correlationengine()
    test_threatfeeds()

    # Code suite
    test_codescanning()
    test_iacscanning()
    test_inventory()
    test_secretsdetection()

    # Evidence
    test_auditlogs()
    test_compliancereports()
    test_evidencebundles()
    test_reports()

    # Protect suite
    test_bulkoperations()
    test_collaboration()
    test_integrations()
    test_playbooks()
    test_remediation()
    test_workflows()

    # Settings
    test_marketplace()
    test_systemhealth()
    test_teams()
    test_users()

    print_summary()


if __name__ == "__main__":
    main()
