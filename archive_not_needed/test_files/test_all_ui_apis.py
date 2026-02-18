#!/usr/bin/env python3
"""
Comprehensive UI API Testing Suite for FixOps
Tests all UI functions with their corresponding real API endpoints separately.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Tuple

import requests

# Test configuration
BACKEND_URL = os.getenv("FIXOPS_API_URL", "http://localhost:8000")
API_KEY = os.getenv("FIXOPS_API_KEY", "demo-token")
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

# Results tracking
test_results: Dict[str, Dict[str, bool]] = {}


def log_test(
    category: str,
    test_name: str,
    passed: bool,
    status_code: int = None,
    error: str = None,
):
    """Log test result."""
    if category not in test_results:
        test_results[category] = {}
    test_results[category][test_name] = passed

    emoji = "✅" if passed else "❌"
    status_info = f" [{status_code}]" if status_code else ""
    error_info = f" - {error}" if error and not passed else ""
    print(f"{emoji} {category} > {test_name}{status_info}{error_info}")


def test_api_endpoint(
    category: str,
    name: str,
    method: str,
    endpoint: str,
    data=None,
    files=None,
    allow_statuses=[200],
):
    """Generic API endpoint tester."""
    try:
        url = f"{BACKEND_URL}{endpoint}"
        headers = HEADERS.copy()

        if files:
            headers.pop("Content-Type", None)  # Let requests set it for multipart

        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            if files:
                response = requests.post(url, headers=headers, files=files, timeout=10)
            else:
                response = requests.post(url, headers=headers, json=data, timeout=10)
        elif method == "PUT":
            response = requests.put(url, headers=headers, json=data, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            raise ValueError(f"Unsupported method: {method}")

        passed = response.status_code in allow_statuses
        log_test(category, name, passed, response.status_code)

        # Return response for further inspection if needed
        return response if passed else None

    except requests.exceptions.Timeout:
        log_test(category, name, False, error="Timeout")
        return None
    except requests.exceptions.ConnectionError:
        log_test(category, name, False, error="Connection failed")
        return None
    except Exception as e:
        log_test(category, name, False, error=str(e))
        return None


# ═══════════════════════════════════════════════════════════════════════════
# 1. DASHBOARD & ANALYTICS TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_dashboard_apis():
    """Test Dashboard page APIs."""
    print("\n" + "=" * 80)
    print("1. DASHBOARD & ANALYTICS")
    print("=" * 80)

    category = "Dashboard"

    # Core dashboard endpoints
    test_api_endpoint(
        category, "Get Overview", "GET", "/api/v1/analytics/dashboard/overview"
    )
    test_api_endpoint(
        category,
        "Get Trends (30 days)",
        "GET",
        "/api/v1/analytics/dashboard/trends?days=30",
    )
    test_api_endpoint(
        category,
        "Get Top Risks",
        "GET",
        "/api/v1/analytics/dashboard/top-risks?limit=10",
    )
    test_api_endpoint(
        category,
        "Get Compliance Status",
        "GET",
        "/api/v1/analytics/dashboard/compliance-status",
    )

    # Metrics
    test_api_endpoint(category, "Get MTTR", "GET", "/api/v1/analytics/mttr")
    test_api_endpoint(
        category, "Get Noise Reduction", "GET", "/api/v1/analytics/noise-reduction"
    )
    test_api_endpoint(category, "Get ROI", "GET", "/api/v1/analytics/roi")
    test_api_endpoint(category, "Get Coverage", "GET", "/api/v1/analytics/coverage")

    # Analytics
    test_api_endpoint(category, "Get Findings", "GET", "/api/v1/analytics/findings")
    test_api_endpoint(category, "Get Decisions", "GET", "/api/v1/analytics/decisions")
    test_api_endpoint(category, "Get Stats", "GET", "/api/v1/analytics/stats")


# ═══════════════════════════════════════════════════════════════════════════
# 2. COPILOT (AI ASSISTANT) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_copilot_apis():
    """Test AI Copilot page APIs."""
    print("\n" + "=" * 80)
    print("2. COPILOT (AI ASSISTANT)")
    print("=" * 80)

    category = "Copilot"

    # Health check
    resp = test_api_endpoint(category, "Get Health", "GET", "/api/v1/copilot/health")

    # Session management
    session_resp = test_api_endpoint(
        category,
        "Create Chat Session",
        "POST",
        "/api/v1/copilot/sessions",
        data={"context": {"source": "ui"}},
    )
    test_api_endpoint(category, "List Sessions", "GET", "/api/v1/copilot/sessions")

    if session_resp and session_resp.status_code == 200:
        session_data = session_resp.json()
        session_id = session_data.get("session_id") or session_data.get("id")
        if session_id:
            test_api_endpoint(
                category,
                f"Get Session {session_id}",
                "GET",
                f"/api/v1/copilot/sessions/{session_id}",
            )
            test_api_endpoint(
                category,
                "Send Message",
                "POST",
                f"/api/v1/copilot/sessions/{session_id}/messages",
                data={"message": "Analyze CVE-2024-1234", "context": {}},
            )
            test_api_endpoint(
                category,
                "Get Messages",
                "GET",
                f"/api/v1/copilot/sessions/{session_id}/messages",
            )

    # Quick analyze
    test_api_endpoint(
        category,
        "Quick Analyze",
        "POST",
        "/api/v1/copilot/quick/analyze",
        data={"target": "vulnerability-analysis", "context": {"cve": "CVE-2024-1234"}},
    )

    # Agents
    test_api_endpoint(
        category,
        "Security Analyst - Analyze",
        "POST",
        "/api/v1/copilot/agents/analyst/analyze",
        data={"findings": [], "context": {}},
    )
    test_api_endpoint(
        category,
        "Security Analyst - Threat Intel",
        "POST",
        "/api/v1/copilot/agents/analyst/threat-intel",
        data={"cve_ids": ["CVE-2024-1234"]},
    )
    test_api_endpoint(
        category,
        "Pentest Agent - Validate",
        "POST",
        "/api/v1/copilot/agents/pentest/validate",
        data={"target": "example.com", "cve_ids": ["CVE-2024-1234"]},
    )
    test_api_endpoint(
        category,
        "Compliance Agent - Gap Analysis",
        "POST",
        "/api/v1/copilot/agents/compliance/gap-analysis",
        data={"framework": "SOC2", "scope": {}},
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. CODE SUITE (INGEST) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_code_suite_apis():
    """Test Code Suite (Ingest) page APIs."""
    print("\n" + "=" * 80)
    print("3. CODE SUITE (INGEST)")
    print("=" * 80)

    category = "Code Suite"

    # Code Scanning (SBOM/SARIF ingestion)
    # Note: File upload tests require actual files, tested separately
    test_api_endpoint(
        category,
        "Validate Input",
        "POST",
        "/api/v1/validate/input",
        data={"content": "test", "type": "sbom"},
    )

    # Secrets Detection
    test_api_endpoint(category, "List Secrets", "GET", "/api/v1/secrets")
    test_api_endpoint(
        category,
        "Scan Content for Secrets",
        "POST",
        "/api/v1/secrets/scan/content",
        data={"content": "password=test123"},
    )
    test_api_endpoint(category, "Get Secrets Status", "GET", "/api/v1/secrets/status")
    test_api_endpoint(
        category, "Get Scanners Status", "GET", "/api/v1/secrets/scanners"
    )

    # IaC Scanning
    test_api_endpoint(category, "List IaC Findings", "GET", "/api/v1/iac")
    test_api_endpoint(
        category,
        "Scan IaC Content",
        "POST",
        "/api/v1/iac/scan/content",
        data={"content": "resource 'aws_s3_bucket'", "type": "terraform"},
    )
    test_api_endpoint(
        category,
        "IaC Scan",
        "POST",
        "/api/v1/iac/scan",
        data={"scan_type": "cloud", "provider": "aws"},
    )

    # Inventory
    test_api_endpoint(
        category, "Search Inventory", "GET", "/api/v1/inventory/search?query=test"
    )
    test_api_endpoint(
        category, "Get Applications", "GET", "/api/v1/inventory/applications"
    )
    test_api_endpoint(category, "Get Assets", "GET", "/api/v1/inventory/assets")


# ═══════════════════════════════════════════════════════════════════════════
# 4. CLOUD SUITE (CORRELATE) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_cloud_suite_apis():
    """Test Cloud Suite (Correlate) page APIs."""
    print("\n" + "=" * 80)
    print("4. CLOUD SUITE (CORRELATE)")
    print("=" * 80)

    category = "Cloud Suite"

    # Cloud Posture (CSPM/CNAPP)
    test_api_endpoint(
        category, "Get CNAPP Findings", "GET", "/api/v1/analytics/findings?source=cnapp"
    )
    test_api_endpoint(category, "Get CSPM Summary", "GET", "/api/v1/cspm/summary")

    # Threat Feeds
    test_api_endpoint(category, "Get EPSS Scores", "GET", "/api/v1/feeds/epss")
    test_api_endpoint(category, "Get KEV Data", "GET", "/api/v1/feeds/kev")
    test_api_endpoint(category, "Get Exploits", "GET", "/api/v1/feeds/exploits")
    test_api_endpoint(
        category, "Get Threat Actors", "GET", "/api/v1/feeds/threat-actors"
    )
    test_api_endpoint(category, "Get Feeds Health", "GET", "/api/v1/feeds/health")
    test_api_endpoint(category, "Get Feeds Stats", "GET", "/api/v1/feeds/stats")

    # Correlation Engine (Deduplication)
    test_api_endpoint(category, "Get Clusters", "GET", "/api/v1/deduplication/clusters")
    test_api_endpoint(category, "Get Dedup Stats", "GET", "/api/v1/deduplication/stats")
    test_api_endpoint(
        category,
        "Process Finding",
        "POST",
        "/api/v1/deduplication/process",
        data={"finding": {"id": "test", "cve_id": "CVE-2024-1234"}},
    )

    # Attack Path Analysis
    test_api_endpoint(category, "Get Attack Graph", "GET", "/graph/")
    test_api_endpoint(
        category,
        "Analyze Attack Surface (GNN)",
        "POST",
        "/api/v1/algorithms/gnn/attack-surface",
        data={"asset_ids": ["asset1"], "depth": 3},
    )
    test_api_endpoint(
        category,
        "Get Critical Nodes (GNN)",
        "POST",
        "/api/v1/algorithms/gnn/critical-nodes",
        data={"threshold": 0.7},
    )


# ═══════════════════════════════════════════════════════════════════════════
# 5. ATTACK SUITE (VERIFY) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_attack_suite_apis():
    """Test Attack Suite (Verify) page APIs."""
    print("\n" + "=" * 80)
    print("5. ATTACK SUITE (VERIFY)")
    print("=" * 80)

    category = "Attack Suite"

    # MPTE
    test_api_endpoint(category, "Get MPTE Requests", "GET", "/api/v1/mpte/requests")
    test_api_endpoint(
        category,
        "Create MPTE Request",
        "POST",
        "/api/v1/mpte/requests",
        data={"target": "example.com", "scope": "web", "priority": "high"},
    )
    test_api_endpoint(category, "Get MPTE Results", "GET", "/api/v1/mpte/results")
    test_api_endpoint(
        category,
        "Verify Vulnerability",
        "POST",
        "/api/v1/mpte/verify",
        data={"cve_id": "CVE-2024-1234", "target": "example.com"},
    )
    test_api_endpoint(category, "Get MPTE Configs", "GET", "/api/v1/mpte/configs")

    # Micro Pentest
    test_api_endpoint(
        category,
        "Run Micro Pentest",
        "POST",
        "/api/v1/micro-pentest/run",
        data={"target": "example.com", "cve_id": "CVE-2024-1234", "safe_mode": True},
    )
    test_api_endpoint(
        category, "Get Micro Pentest Health", "GET", "/api/v1/micro-pentest/health"
    )

    # Attack Simulation
    test_api_endpoint(
        category,
        "Simulate Attack",
        "POST",
        "/api/v1/predictions/simulate-attack",
        data={"scenario": "ransomware", "assets": ["asset1"]},
    )
    test_api_endpoint(
        category,
        "Analyze Attack Chain",
        "POST",
        "/api/v1/predictions/attack-chain",
        data={"target": "asset1"},
    )

    # Reachability Analysis
    test_api_endpoint(
        category,
        "Analyze Reachability",
        "POST",
        "/api/v1/reachability/analyze",
        data={"cve_id": "CVE-2024-1234", "target": "example.com"},
    )
    test_api_endpoint(
        category, "Get Reachability Metrics", "GET", "/api/v1/reachability/metrics"
    )

    # Vulnerability Discovery
    test_api_endpoint(
        category,
        "Report Discovered Vuln",
        "POST",
        "/api/v1/vulns/discovered",
        data={"title": "Test Vulnerability", "severity": "high"},
    )
    test_api_endpoint(category, "Get Internal Vulns", "GET", "/api/v1/vulns/internal")


# ═══════════════════════════════════════════════════════════════════════════
# 6. PROTECT SUITE (REMEDIATE) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_protect_suite_apis():
    """Test Protect Suite (Remediate) page APIs."""
    print("\n" + "=" * 80)
    print("6. PROTECT SUITE (REMEDIATE)")
    print("=" * 80)

    category = "Protect Suite"

    # Remediation
    test_api_endpoint(
        category, "Get Remediation Tasks", "GET", "/api/v1/remediation/tasks"
    )
    test_api_endpoint(
        category,
        "Create Remediation Task",
        "POST",
        "/api/v1/remediation/tasks",
        data={"title": "Fix CVE-2024-1234", "priority": "high"},
    )
    test_api_endpoint(
        category, "Get Remediation Metrics", "GET", "/api/v1/remediation/metrics"
    )
    test_api_endpoint(
        category,
        "Generate Fix",
        "POST",
        "/api/v1/enhanced/analysis",
        data={
            "service": "remediation",
            "context": {"cve_id": "CVE-2024-1234", "action": "generate_fix"},
        },
    )

    # Bulk Operations
    test_api_endpoint(
        category,
        "Bulk Update Findings",
        "POST",
        "/api/v1/bulk/findings/update",
        data={"finding_ids": ["id1", "id2"], "updates": {"status": "resolved"}},
    )
    test_api_endpoint(
        category,
        "Bulk Assign Clusters",
        "POST",
        "/api/v1/bulk/clusters/assign",
        data={"cluster_ids": ["cluster1"], "assignee": "user@example.com"},
    )

    # Collaboration
    test_api_endpoint(category, "Get Comments", "GET", "/api/v1/collaboration/comments")
    test_api_endpoint(
        category,
        "Add Comment",
        "POST",
        "/api/v1/collaboration/comments",
        data={"entity_type": "finding", "entity_id": "123", "content": "Test comment"},
    )
    test_api_endpoint(
        category,
        "Get Notifications",
        "GET",
        "/api/v1/collaboration/notifications/pending",
    )

    # Workflows
    test_api_endpoint(category, "List Workflows", "GET", "/api/v1/workflows")
    test_api_endpoint(category, "Get Workflow Rules", "GET", "/api/v1/workflows/rules")
    test_api_endpoint(
        category,
        "Create Workflow",
        "POST",
        "/api/v1/workflows",
        data={"name": "Auto-triage", "trigger": "new_finding", "actions": []},
    )

    # Playbooks
    # Playbooks are typically part of workflows in FixOps

    # Integrations
    test_api_endpoint(category, "List Integrations", "GET", "/api/v1/integrations")
    test_api_endpoint(
        category,
        "Create Integration",
        "POST",
        "/api/v1/integrations",
        data={"type": "jira", "config": {"url": "https://jira.example.com"}},
    )


# ═══════════════════════════════════════════════════════════════════════════
# 7. AI ENGINE (DECIDE) TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_ai_engine_apis():
    """Test AI Engine (Decision Engine) page APIs."""
    print("\n" + "=" * 80)
    print("7. AI ENGINE (DECIDE)")
    print("=" * 80)

    category = "AI Engine"

    # Multi-LLM Consensus
    test_api_endpoint(category, "Get LLM Status", "GET", "/api/v1/llm/status")
    test_api_endpoint(category, "Get LLM Providers", "GET", "/api/v1/llm/providers")
    test_api_endpoint(
        category,
        "Enhanced Analysis",
        "POST",
        "/api/v1/enhanced/analysis",
        data={"service": "decision", "context": {"cve_id": "CVE-2024-1234"}},
    )
    test_api_endpoint(
        category,
        "Compare LLMs",
        "POST",
        "/api/v1/enhanced/compare-llms",
        data={"prompt": "Analyze CVE-2024-1234"},
    )
    test_api_endpoint(
        category, "Get Enhanced Capabilities", "GET", "/api/v1/enhanced/capabilities"
    )

    # Algorithmic Lab
    test_api_endpoint(
        category, "Get Algorithms Status", "GET", "/api/v1/algorithms/status"
    )
    test_api_endpoint(
        category,
        "Get Algorithms Capabilities",
        "GET",
        "/api/v1/algorithms/capabilities",
    )
    test_api_endpoint(
        category,
        "Monte Carlo Quantification",
        "POST",
        "/api/v1/algorithms/monte-carlo/quantify",
        data={"cve_ids": ["CVE-2024-1234"], "simulations": 1000},
    )
    test_api_endpoint(
        category,
        "Causal Analysis",
        "POST",
        "/api/v1/algorithms/causal/analyze",
        data={"finding_ids": ["finding1", "finding2"]},
    )
    test_api_endpoint(
        category,
        "Prioritize Findings",
        "POST",
        "/api/v1/algorithms/prioritize",
        data={"findings": [{"id": "1", "severity": "high"}]},
    )

    # Predictions
    test_api_endpoint(
        category,
        "Risk Trajectory",
        "POST",
        "/api/v1/predictions/risk-trajectory",
        data={"cve_ids": ["CVE-2024-1234"]},
    )

    # Policies
    test_api_endpoint(category, "List Policies", "GET", "/api/v1/policies")


# ═══════════════════════════════════════════════════════════════════════════
# 8. EVIDENCE VAULT TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_evidence_vault_apis():
    """Test Evidence Vault page APIs."""
    print("\n" + "=" * 80)
    print("8. EVIDENCE VAULT")
    print("=" * 80)

    category = "Evidence"

    # Evidence Bundles
    test_api_endpoint(category, "List Evidence Bundles", "GET", "/evidence/")
    test_api_endpoint(category, "Get Evidence Stats", "GET", "/api/v1/evidence/stats")
    test_api_endpoint(
        category,
        "Verify Bundle",
        "POST",
        "/evidence/verify",
        data={"bundle_id": "test-bundle"},
    )

    # SLSA Provenance
    # Provenance is part of evidence bundles

    # Compliance Reports
    test_api_endpoint(
        category,
        "Get Compliance Frameworks",
        "GET",
        "/api/v1/audit/compliance/frameworks",
    )
    test_api_endpoint(
        category, "Get Compliance Status", "GET", "/api/v1/compliance/status"
    )

    # Audit Trail
    test_api_endpoint(category, "Get Audit Logs", "GET", "/api/v1/audit/logs")
    test_api_endpoint(
        category, "Get Audit Logs (Limited)", "GET", "/api/v1/audit/logs?limit=50"
    )

    # Reports
    test_api_endpoint(category, "List Reports", "GET", "/api/v1/reports")
    test_api_endpoint(
        category, "Get Report Templates", "GET", "/api/v1/reports/templates"
    )
    test_api_endpoint(
        category,
        "Generate Report",
        "POST",
        "/api/v1/reports/generate",
        data={"type": "compliance", "format": "pdf"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# 9. SETTINGS TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_settings_apis():
    """Test Settings page APIs."""
    print("\n" + "=" * 80)
    print("9. SETTINGS")
    print("=" * 80)

    category = "Settings"

    # Users & Teams
    test_api_endpoint(category, "List Users", "GET", "/api/v1/users")
    test_api_endpoint(category, "List Teams", "GET", "/api/v1/teams")
    test_api_endpoint(category, "Get SSO Config", "GET", "/api/v1/auth/sso")

    # Integrations
    test_api_endpoint(category, "List Integrations", "GET", "/api/v1/integrations")

    # Marketplace
    test_api_endpoint(
        category, "Browse Marketplace", "GET", "/api/v1/marketplace/browse"
    )

    # System Health
    test_api_endpoint(category, "System Health", "GET", "/health")
    test_api_endpoint(category, "API Health", "GET", "/api/v1/health")
    test_api_endpoint(category, "System Version", "GET", "/api/v1/version")
    test_api_endpoint(category, "System Status", "GET", "/api/v1/status")

    # Webhooks
    test_api_endpoint(category, "List Webhooks", "GET", "/api/v1/webhooks")
    test_api_endpoint(
        category, "Get Webhook Mappings", "GET", "/api/v1/webhooks/mappings"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 10. ADDITIONAL API TESTS
# ═══════════════════════════════════════════════════════════════════════════


def test_additional_apis():
    """Test additional core APIs."""
    print("\n" + "=" * 80)
    print("10. ADDITIONAL CORE APIs")
    print("=" * 80)

    category = "Core APIs"

    # Risk APIs
    test_api_endpoint(category, "Get Risk Graph", "GET", "/graph/")

    # Provenance APIs
    # Provenance is typically part of evidence bundles

    # Search API
    test_api_endpoint(category, "Global Search", "GET", "/api/v1/search?q=test")

    # IDE Integration (for developer workflows)
    # IDE endpoints are typically used by IDE plugins


# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════


def print_summary():
    """Print test summary."""
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    total_categories = len(test_results)
    total_tests = sum(len(tests) for tests in test_results.values())
    total_passed = sum(
        sum(1 for result in tests.values() if result) for tests in test_results.values()
    )
    total_failed = total_tests - total_passed

    print(f"\nCategories Tested: {total_categories}")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed} ✅")
    print(f"Failed: {total_failed} ❌")
    print(f"Success Rate: {(total_passed/total_tests*100):.1f}%\n")

    # Per-category breakdown
    print("Per-Category Results:")
    print("-" * 80)

    for category, tests in sorted(test_results.items()):
        passed = sum(1 for result in tests.values() if result)
        total = len(tests)
        percentage = (passed / total * 100) if total > 0 else 0
        status = "✅" if passed == total else "⚠️" if passed > 0 else "❌"
        print(f"{status} {category:30} {passed:3}/{total:3} ({percentage:5.1f}%)")

    print("\n" + "=" * 80)
    print("DETAILED RESULTS BY CATEGORY")
    print("=" * 80)

    for category, tests in sorted(test_results.items()):
        print(f"\n{category}:")
        for test_name, result in sorted(tests.items()):
            emoji = "✅" if result else "❌"
            print(f"  {emoji} {test_name}")

    # Recommendations
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)

    if total_failed == 0:
        print("🎉 All tests passed! The UI has full API connectivity.")
    else:
        print(f"⚠️ {total_failed} test(s) failed. Recommendations:")
        print("  1. Check that the backend is running: http://localhost:8000")
        print(
            "  2. Verify API key is valid (current: '{}')".format(API_KEY[:10] + "...")
        )
        print("  3. Review backend logs for errors")
        print("  4. Ensure all optional enterprise modules are installed")
        print("  5. Some endpoints may require specific data to be present")

    print("\n📊 Test Report saved to: test_results.json")

    # Save detailed results
    with open("test_results.json", "w") as f:
        json.dump(
            {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "summary": {
                    "total_categories": total_categories,
                    "total_tests": total_tests,
                    "passed": total_passed,
                    "failed": total_failed,
                    "success_rate": round(total_passed / total_tests * 100, 2),
                },
                "results": test_results,
            },
            f,
            indent=2,
        )


# ═══════════════════════════════════════════════════════════════════════════
# MAIN TEST RUNNER
# ═══════════════════════════════════════════════════════════════════════════


def main():
    """Run all UI API tests."""
    print("=" * 80)
    print("FixOps UI API Comprehensive Test Suite")
    print("=" * 80)
    print(f"Backend URL: {BACKEND_URL}")
    print(f"API Key: {API_KEY[:10]}..." if len(API_KEY) > 10 else f"API Key: {API_KEY}")
    print(f"Started: {datetime.utcnow().isoformat()}Z")

    # Run all test suites
    test_dashboard_apis()
    test_copilot_apis()
    test_code_suite_apis()
    test_cloud_suite_apis()
    test_attack_suite_apis()
    test_protect_suite_apis()
    test_ai_engine_apis()
    test_evidence_vault_apis()
    test_settings_apis()
    test_additional_apis()

    # Print summary
    print_summary()

    print(f"\n✅ Testing completed at {datetime.utcnow().isoformat()}Z")


if __name__ == "__main__":
    main()
