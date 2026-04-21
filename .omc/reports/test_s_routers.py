#!/usr/bin/env python3
"""Test ALL endpoints from S-prefix router files against http://localhost:8000"""

import requests
import json
import time
import sys
from datetime import datetime

BASE = "http://localhost:8000"
TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
HEADERS = {"X-API-Key": TOKEN, "Content-Type": "application/json"}
ORG = "default"

results = []

def test(method, path, body=None, label=None):
    """Hit an endpoint and record the result."""
    # Replace path params with test values
    url_path = path
    url_path = url_path.replace("{org_id}", ORG)
    url_path = url_path.replace("{provider}", "saml")
    url_path = url_path.replace("{user_id}", "test-user-1")
    url_path = url_path.replace("{user_email}", "test@example.com")
    url_path = url_path.replace("{session_id}", "test-session-1")
    url_path = url_path.replace("{secret_id}", "test-secret-1")
    url_path = url_path.replace("{rotation_id}", "test-rot-1")
    url_path = url_path.replace("{review_id}", "test-review-1")
    url_path = url_path.replace("{rule_id}", "test-rule-1")
    url_path = url_path.replace("{finding_id}", "test-finding-1")
    url_path = url_path.replace("{app_id}", "test-app-1")
    url_path = url_path.replace("{assessment_id}", "test-assess-1")
    url_path = url_path.replace("{gap_id}", "test-gap-1")
    url_path = url_path.replace("{plan_id}", "test-plan-1")
    url_path = url_path.replace("{check_id}", "test-check-1")
    url_path = url_path.replace("{incident_id}", "test-incident-1")
    url_path = url_path.replace("{alert_id}", "test-alert-1")
    url_path = url_path.replace("{allocation_id}", "test-alloc-1")
    url_path = url_path.replace("{transaction_id}", "test-tx-1")
    url_path = url_path.replace("{champion_id}", "test-champ-1")
    url_path = url_path.replace("{change_id}", "test-change-1")
    url_path = url_path.replace("{experiment_id}", "test-exp-1")
    url_path = url_path.replace("{initiative_id}", "test-init-1")
    url_path = url_path.replace("{pipeline_id}", "test-pipe-1")
    url_path = url_path.replace("{service_id}", "test-svc-1")
    url_path = url_path.replace("{dependency_id}", "test-dep-1")
    url_path = url_path.replace("{dep_id}", "test-dep-1")
    url_path = url_path.replace("{vuln_id}", "test-vuln-1")
    url_path = url_path.replace("{source_id}", "test-src-1")
    url_path = url_path.replace("{request_id}", "test-req-1")
    url_path = url_path.replace("{baseline_id}", "test-base-1")
    url_path = url_path.replace("{benchmark_id}", "test-bench-1")
    url_path = url_path.replace("{metric_name}", "mttd")
    url_path = url_path.replace("{metric_id}", "test-metric-1")
    url_path = url_path.replace("{domain_id}", "test-domain-1")
    url_path = url_path.replace("{dashboard_id}", "test-dash-1")
    url_path = url_path.replace("{objective_id}", "test-obj-1")
    url_path = url_path.replace("{obj_id}", "test-obj-1")
    url_path = url_path.replace("{kr_id}", "test-kr-1")
    url_path = url_path.replace("{playbook_id}", "test-pb-1")
    url_path = url_path.replace("{execution_id}", "test-exec-1")
    url_path = url_path.replace("{report_id}", "test-report-1")
    url_path = url_path.replace("{report_type}", "executive")
    url_path = url_path.replace("{control_id}", "test-ctrl-1")
    url_path = url_path.replace("{item_id}", "test-item-1")
    url_path = url_path.replace("{timeline_id}", "test-tl-1")
    url_path = url_path.replace("{actor}", "attacker1")
    url_path = url_path.replace("{exception_id}", "test-exc-1")
    url_path = url_path.replace("{article_id}", "test-art-1")
    url_path = url_path.replace("{cwe_id}", "CWE-79")
    url_path = url_path.replace("{owasp_id}", "A01")
    url_path = url_path.replace("{kpi_name}", "mttd")
    url_path = url_path.replace("{enrollment_id}", "test-enroll-1")
    url_path = url_path.replace("{program_id}", "test-prog-1")
    url_path = url_path.replace("{scorecard_id}", "test-sc-1")
    url_path = url_path.replace("{entity_type}", "org")
    url_path = url_path.replace("{entity_id}", "test-ent-1")
    url_path = url_path.replace("{exercise_id}", "test-exer-1")
    url_path = url_path.replace("{tool_id}", "test-tool-1")
    url_path = url_path.replace("{schedule_id}", "test-sched-1")
    url_path = url_path.replace("{run_id}", "test-run-1")
    url_path = url_path.replace("{questionnaire_id}", "test-quest-1")
    url_path = url_path.replace("{artifact_id}", "test-art-1")
    url_path = url_path.replace("{milestone_id}", "test-ms-1")
    url_path = url_path.replace("{investment_id}", "test-inv-1")
    url_path = url_path.replace("{fiscal_year}", "2026")
    url_path = url_path.replace("{team_id}", "test-team-1")
    url_path = url_path.replace("{challenge_id}", "test-chal-1")
    url_path = url_path.replace("{package_id}", "test-pkg-1")
    url_path = url_path.replace("{detection_id}", "test-det-1")
    url_path = url_path.replace("{pkg_id}", "test-pkg-1")
    url_path = url_path.replace("{supplier_id}", "test-sup-1")
    url_path = url_path.replace("{event_id}", "test-evt-1")
    url_path = url_path.replace("{component_id}", "test-comp-1")
    url_path = url_path.replace("{component_name}", "test-comp")
    url_path = url_path.replace("{asset_id}", "test-asset-1")
    url_path = url_path.replace("{project_id}", "test-proj-1")
    url_path = url_path.replace("{project_name}", "test-project")
    url_path = url_path.replace("{scan_id}", "test-scan-1")
    url_path = url_path.replace("{ecosystem}", "npm")
    url_path = url_path.replace("{package}", "lodash")
    url_path = url_path.replace("{version:path}", "4.17.21")
    url_path = url_path.replace("{scanner_type}", "trivy")
    url_path = url_path.replace("{channel}", "alerts")
    url_path = url_path.replace("{subsystem}", "database")
    url_path = url_path.replace("{action}", "quarantine")
    url_path = url_path.replace("{siem_id}", "test-siem-1")
    url_path = url_path.replace("{group_id}", "test-group-1")
    url_path = url_path.replace("{record_id}", "test-rec-1")
    url_path = url_path.replace("{violation_id}", "test-viol-1")
    url_path = url_path.replace("{outage_id}", "test-outage-1")
    url_path = url_path.replace("{remediation_id}", "test-rem-1")
    url_path = url_path.replace("{vendor_id}", "test-vendor-1")
    url_path = url_path.replace("{domain}", "network")
    url_path = url_path.replace("{improvement_id}", "test-imp-1")
    url_path = url_path.replace("{package_name}", "test-pkg")
    url_path = url_path.replace("{loop}", "decision")
    url_path = url_path.replace("{key:path}", "risk.base_weight")
    url_path = url_path.replace("{id}", "test-id-1")

    # Add org_id query param
    sep = "&" if "?" in url_path else "?"
    url = f"{BASE}{url_path}{sep}org_id={ORG}"

    try:
        if method == "GET":
            r = requests.get(url, headers=HEADERS, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=HEADERS, json=body or {}, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=HEADERS, json=body or {}, timeout=10)
        elif method == "PATCH":
            r = requests.patch(url, headers=HEADERS, json=body or {}, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=HEADERS, timeout=10)
        else:
            r = requests.get(url, headers=HEADERS, timeout=10)

        status = r.status_code
        # Try to get error detail
        detail = ""
        if status >= 400:
            try:
                detail = r.json().get("detail", "")[:120]
            except:
                detail = r.text[:120]
    except requests.exceptions.ConnectionError:
        status = 0
        detail = "CONNECTION_REFUSED"
    except requests.exceptions.Timeout:
        status = 0
        detail = "TIMEOUT"
    except Exception as e:
        status = 0
        detail = str(e)[:120]

    results.append({
        "method": method,
        "path": path,
        "url": url,
        "status": status,
        "detail": detail
    })

    icon = "PASS" if 200 <= status < 300 else ("SKIP" if status == 404 else ("AUTH" if status in (401, 403) else "FAIL"))
    print(f"  {icon} {status:3d} {method:6s} {path}")
    return status

# ============================================================
# ALL GET ENDPOINTS (no body needed)
# ============================================================
print("=" * 80)
print("TESTING ALL GET ENDPOINTS FROM S-PREFIX ROUTERS")
print("=" * 80)

gets = [
    "/api/v1/ai-agent/backends",
    "/api/v1/ai-agent/experts",
    "/api/v1/ai-agent/health",
    "/api/v1/ai-agent/status",
    "/api/v1/arch-review/control-gaps",
    "/api/v1/arch-review/reviews",
    "/api/v1/arch-review/reviews/{review_id}",
    "/api/v1/arch-review/summary",
    "/api/v1/auth/sso/providers",
    "/api/v1/auth/sso/session",
    "/api/v1/auth/sso/{provider}/login",
    "/api/v1/auth/sso/{provider}/metadata",
    "/api/v1/awareness-gamification/challenges",
    "/api/v1/awareness-gamification/leaderboard",
    "/api/v1/awareness-gamification/stats",
    "/api/v1/awareness-gamification/users/{user_id}",
    "/api/v1/awareness-metrics/benchmarks",
    "/api/v1/awareness-metrics/metrics",
    "/api/v1/awareness-metrics/metrics/latest",
    "/api/v1/awareness-metrics/metrics/trend",
    "/api/v1/awareness-metrics/stats",
    "/api/v1/awareness-program/",
    "/api/v1/awareness-program/department-compliance",
    "/api/v1/awareness-program/overdue",
    "/api/v1/awareness-program/programs/{program_id}/stats",
    "/api/v1/awareness-program/summary",
    "/api/v1/capacity-planning/skill-gaps",
    "/api/v1/capacity-planning/summary",
    "/api/v1/capacity-planning/teams",
    "/api/v1/change-management/approvals",
    "/api/v1/change-management/changes",
    "/api/v1/change-management/changes/{change_id}",
    "/api/v1/change-management/stats",
    "/api/v1/data-pipeline/pipelines",
    "/api/v1/data-pipeline/pipelines/{pipeline_id}",
    "/api/v1/data-pipeline/runs",
    "/api/v1/data-pipeline/stats",
    "/api/v1/dependency-mapping/critical-paths",
    "/api/v1/dependency-mapping/services",
    "/api/v1/dependency-mapping/services/{service_id}",
    "/api/v1/dependency-mapping/source-trace",
    "/api/v1/dependency-mapping/summary",
    "/api/v1/dependency-risk/",
    "/api/v1/dependency-risk/graph/{package_name}",
    "/api/v1/dependency-risk/license-conflicts",
    "/api/v1/dependency-risk/risky",
    "/api/v1/dependency-risk/summary",
    "/api/v1/dependency-risk/vulns",
    "/api/v1/event-correlation/events",
    "/api/v1/event-correlation/incidents",
    "/api/v1/event-correlation/rules",
    "/api/v1/event-correlation/stats",
    "/api/v1/event-timeline/actor/{incident_id}/{actor}",
    "/api/v1/event-timeline/events/{incident_id}",
    "/api/v1/event-timeline/search",
    "/api/v1/event-timeline/summary",
    "/api/v1/event-timeline/timelines/{incident_id}",
    "/api/v1/exception-workflow/expired",
    "/api/v1/exception-workflow/expiring",
    "/api/v1/exception-workflow/requests",
    "/api/v1/exception-workflow/requests/{request_id}",
    "/api/v1/exception-workflow/summary",
    "/api/v1/gap-analysis/assessments",
    "/api/v1/gap-analysis/assessments/{assessment_id}",
    "/api/v1/gap-analysis/framework-coverage",
    "/api/v1/gap-analysis/overdue",
    "/api/v1/gap-analysis/summary",
    "/api/v1/health-scorecard",
    "/api/v1/health-scorecard/current",
    "/api/v1/health-scorecard/domains",
    "/api/v1/health-scorecard/grade-trend",
    "/api/v1/health-scorecard/history",
    "/api/v1/integrations/slack/status",
    "/api/v1/kb/articles",
    "/api/v1/kb/articles/{article_id}",
    "/api/v1/kb/articles/{article_id}/versions",
    "/api/v1/kb/cwe/{cwe_id}",
    "/api/v1/kb/for-finding",
    "/api/v1/kb/owasp/{owasp_id}",
    "/api/v1/kb/search",
    "/api/v1/kb/stats",
    "/api/v1/kb/tags",
    "/api/v1/kpi/benchmarks",
    "/api/v1/kpi/current",
    "/api/v1/kpi/scorecard",
    "/api/v1/kpi/snapshots",
    "/api/v1/kpi/targets",
    "/api/v1/kpi/trend/{kpi_name}",
    "/api/v1/license-security/policies",
    "/api/v1/license-security/records",
    "/api/v1/license-security/records/{record_id}",
    "/api/v1/license-security/stats",
    "/api/v1/license-security/violations",
    "/api/v1/metrics-aggregator/aggregations",
    "/api/v1/metrics-aggregator/metrics",
    "/api/v1/metrics-aggregator/metrics/latest/{metric_name}",
    "/api/v1/metrics-aggregator/sources",
    "/api/v1/metrics-aggregator/stats",
    "/api/v1/metrics-dashboard/dashboards",
    "/api/v1/metrics-dashboard/dashboards/{dashboard_id}",
    "/api/v1/metrics-dashboard/dashboards/{dashboard_id}/widgets",
    "/api/v1/metrics-dashboard/snapshots",
    "/api/v1/metrics-dashboard/stats",
    "/api/v1/metrics/benchmarks",
    "/api/v1/metrics/dora",
    "/api/v1/metrics/objectives",
    "/api/v1/metrics/sla",
    "/api/v1/metrics/trends",
    "/api/v1/posture-benchmarking/benchmarks",
    "/api/v1/posture-benchmarking/benchmarks/{benchmark_id}",
    "/api/v1/posture-benchmarking/comparisons",
    "/api/v1/posture-benchmarking/controls",
    "/api/v1/posture-benchmarking/stats",
    "/api/v1/posture-history/",
    "/api/v1/posture-history/baselines/{domain}",
    "/api/v1/posture-history/delta",
    "/api/v1/posture-history/snapshots",
    "/api/v1/posture-history/summary",
    "/api/v1/posture-history/trends",
    "/api/v1/posture-maturity/domains",
    "/api/v1/posture-maturity/overdue",
    "/api/v1/posture-maturity/overview",
    "/api/v1/posture-maturity/roadmap",
    "/api/v1/posture-reports/reports",
    "/api/v1/posture-reports/reports/{report_id}",
    "/api/v1/posture-reports/reports/latest/{report_type}",
    "/api/v1/posture-reports/trends",
    "/api/v1/posture-scoring/context/{entity_id}",
    "/api/v1/posture-scoring/controls",
    "/api/v1/posture-scoring/controls/{control_id}",
    "/api/v1/posture-scoring/history",
    "/api/v1/posture-scoring/stats",
    "/api/v1/posture-trends/",
    "/api/v1/posture-trends/stagnating",
    "/api/v1/posture-trends/targets",
    "/api/v1/posture-trends/trends",
    "/api/v1/posture-trends/trends/{metric_name}",
    "/api/v1/posture-trends/velocity-summary",
    "/api/v1/program-maturity/assessments",
    "/api/v1/program-maturity/domains",
    "/api/v1/program-maturity/profile",
    "/api/v1/program-maturity/roadmap",
    "/api/v1/program-maturity/summary",
    "/api/v1/sast/findings",
    "/api/v1/sast/health",
    "/api/v1/sast/languages",
    "/api/v1/sast/rules",
    "/api/v1/sast/status",
    "/api/v1/sast/summary",
    "/api/v1/sbom-export/",
    "/api/v1/sbom-export/cyclonedx",
    "/api/v1/sbom-export/formats",
    "/api/v1/sbom-export/projects",
    "/api/v1/sbom-export/projects/{project_name}/history",
    "/api/v1/sbom-export/projects/{project_name}/summary",
    "/api/v1/sbom-export/search",
    "/api/v1/sbom-export/spdx",
    "/api/v1/sbom/assets",
    "/api/v1/sbom/assets/{asset_id}",
    "/api/v1/sbom/assets/{asset_id}/components",
    "/api/v1/sbom/assets/{asset_id}/export/cyclonedx",
    "/api/v1/sbom/assets/{asset_id}/export/spdx",
    "/api/v1/sbom/license-summary",
    "/api/v1/sbom/stats",
    "/api/v1/sbom/vuln-exposure",
    "/api/v1/sca/projects",
    "/api/v1/sca/projects/{project_id}",
    "/api/v1/sca/scans",
    "/api/v1/sca/scans/{scan_id}",
    "/api/v1/sca/scans/{scan_id}/license-report",
    "/api/v1/sca/scans/{scan_id}/vulnerable-deps",
    "/api/v1/sca/stats",
    "/api/v1/sca/test/{ecosystem}/{package}/{version:path}",
    "/api/v1/scan/semgrep/history",
    "/api/v1/scan/semgrep/rulesets",
    "/api/v1/scan/semgrep/status",
    "/api/v1/scan/snyk/history",
    "/api/v1/scan/snyk/issues",
    "/api/v1/scan/snyk/projects",
    "/api/v1/scan/snyk/status",
    "/api/v1/scanner-ingest/",
    "/api/v1/scanner-ingest/health",
    "/api/v1/scanner-ingest/stats",
    "/api/v1/scanner-ingest/status",
    "/api/v1/scanner-ingest/supported",
    "/api/v1/scheduled-reports/runs",
    "/api/v1/scheduled-reports/runs/{run_id}",
    "/api/v1/scheduled-reports/schedules",
    "/api/v1/scheduled-reports/schedules/{schedule_id}",
    "/api/v1/scheduled-reports/stats",
    "/api/v1/scheduled-reports/templates",
    "/api/v1/scorecard/{org_id}",
    "/api/v1/scorecard/{org_id}/breakdown",
    "/api/v1/scorecard/{org_id}/history",
    "/api/v1/scorecard/{org_id}/improvement",
    "/api/v1/scorecard/categories",
    "/api/v1/secret-scanner/engine-patterns",
    "/api/v1/secret-scanner/findings",
    "/api/v1/secret-scanner/jobs",
    "/api/v1/secret-scanner/jobs/{job_id}",
    "/api/v1/secret-scanner/stats",
    "/api/v1/secret-scanner/suppressions",
    "/api/v1/secrets-management/expiring",
    "/api/v1/secrets-management/secrets",
    "/api/v1/secrets-management/secrets/{secret_id}",
    "/api/v1/secrets-management/secrets/{secret_id}/access",
    "/api/v1/secrets-management/stats",
    "/api/v1/secrets-manager/secrets",
    "/api/v1/secrets-manager/secrets/{secret_id}/history",
    "/api/v1/secrets-manager/secrets/expiring",
    "/api/v1/secrets-manager/stats",
    "/api/v1/secrets-manager/vaults",
    "/api/v1/secrets-rotation/",
    "/api/v1/secrets-rotation/{rotation_id}",
    "/api/v1/secrets-rotation/{rotation_id}/audit",
    "/api/v1/secrets-rotation/metrics",
    "/api/v1/secrets-rotation/overdue",
    "/api/v1/secrets/active",
    "/api/v1/secrets/compliance",
    "/api/v1/secrets/findings",
    "/api/v1/secrets/health",
    "/api/v1/secrets/history",
    "/api/v1/secrets/patterns",
    "/api/v1/secrets/policies",
    "/api/v1/secrets/pre-commit",
    "/api/v1/secrets/precommit-config",
    "/api/v1/secrets/rotation-status",
    "/api/v1/secrets/scan/results",
    "/api/v1/secrets/scanners/status",
    "/api/v1/secrets/status",
    "/api/v1/secrets/{id}",
    "/api/v1/security-automation/executions",
    "/api/v1/security-automation/rules",
    "/api/v1/security-automation/rules/{rule_id}",
    "/api/v1/security-automation/stats",
    "/api/v1/security-baselines/",
    "/api/v1/security-baselines/baselines",
    "/api/v1/security-baselines/baselines/{baseline_id}",
    "/api/v1/security-baselines/baselines/{baseline_id}/drift",
    "/api/v1/security-baselines/baselines/{baseline_id}/trend",
    "/api/v1/security-benchmarks/",
    "/api/v1/security-benchmarks/benchmarks",
    "/api/v1/security-benchmarks/metrics/{metric_name}/trend",
    "/api/v1/security-benchmarks/summary",
    "/api/v1/security-budget/allocations",
    "/api/v1/security-budget/allocations/{allocation_id}",
    "/api/v1/security-budget/roi-assessments",
    "/api/v1/security-budget/stats",
    "/api/v1/security-budget/transactions",
    "/api/v1/security-champions/campaigns",
    "/api/v1/security-champions/champions",
    "/api/v1/security-champions/champions/{champion_id}",
    "/api/v1/security-champions/champions/{champion_id}/certifications",
    "/api/v1/security-champions/stats",
    "/api/v1/security-chaos/experiments",
    "/api/v1/security-chaos/experiments/{experiment_id}",
    "/api/v1/security-chaos/experiments/{experiment_id}/observations",
    "/api/v1/security-chaos/stats",
    "/api/v1/security-culture/",
    "/api/v1/security-culture/assessments/latest",
    "/api/v1/security-culture/departments",
    "/api/v1/security-culture/metrics/{metric_name}/trend",
    "/api/v1/security-culture/summary",
    "/api/v1/security-exceptions/{org_id}",
    "/api/v1/security-exceptions/{org_id}/{exception_id}",
    "/api/v1/security-exceptions/{org_id}/{exception_id}/assets",
    "/api/v1/security-exceptions/{org_id}/expiring",
    "/api/v1/security-exceptions/{org_id}/stats",
    "/api/v1/security-findings/",
    "/api/v1/security-findings/assets/{asset_id}/findings",
    "/api/v1/security-findings/findings",
    "/api/v1/security-findings/findings/{finding_id}",
    "/api/v1/security-findings/summary",
    "/api/v1/security-health/checks",
    "/api/v1/security-health/incidents",
    "/api/v1/security-health/snapshots",
    "/api/v1/security-health/snapshots/latest",
    "/api/v1/security-health/stats",
    "/api/v1/security-investment/budgets/{fiscal_year}",
    "/api/v1/security-investment/investments",
    "/api/v1/security-investment/portfolio",
    "/api/v1/security-maturity/assessments",
    "/api/v1/security-maturity/assessments/{assessment_id}",
    "/api/v1/security-maturity/domains/{domain_id}/controls",
    "/api/v1/security-maturity/roadmap",
    "/api/v1/security-maturity/stats",
    "/api/v1/security-maturity/targets",
    "/api/v1/security-metrics-collector/aggregates",
    "/api/v1/security-metrics-collector/alerts",
    "/api/v1/security-metrics-collector/dashboard",
    "/api/v1/security-metrics-collector/metrics",
    "/api/v1/security-metrics-collector/metrics/{metric_id}/readings",
    "/api/v1/security-okrs/objectives",
    "/api/v1/security-okrs/objectives/{objective_id}",
    "/api/v1/security-okrs/summary/{period}",
    "/api/v1/security-okrs/team/{owner}",
    "/api/v1/security-okrs/velocity",
    "/api/v1/security-playbooks/executions",
    "/api/v1/security-playbooks/executions/{execution_id}",
    "/api/v1/security-playbooks/playbooks",
    "/api/v1/security-playbooks/playbooks/{playbook_id}",
    "/api/v1/security-playbooks/playbooks/builtins",
    "/api/v1/security-posture-pdf/download",
    "/api/v1/security-questionnaires",
    "/api/v1/security-questionnaires/assessments",
    "/api/v1/security-questionnaires/assessments/{assessment_id}",
    "/api/v1/security-questionnaires/overdue",
    "/api/v1/security-questionnaires/vendor/{vendor_id}/summary",
    "/api/v1/security-registry",
    "/api/v1/security-registry/artifacts",
    "/api/v1/security-registry/artifacts/{artifact_id}",
    "/api/v1/security-registry/artifacts/{artifact_id}/references",
    "/api/v1/security-registry/reviews",
    "/api/v1/security-registry/stats",
    "/api/v1/security-roadmap/gaps",
    "/api/v1/security-roadmap/initiatives",
    "/api/v1/security-roadmap/initiatives/{initiative_id}",
    "/api/v1/security-roadmap/initiatives/{initiative_id}/milestones",
    "/api/v1/security-roadmap/stats",
    "/api/v1/security-roi/breach-estimate",
    "/api/v1/security-roi/budget",
    "/api/v1/security-roi/health",
    "/api/v1/security-roi/investments",
    "/api/v1/security-roi/investments/{investment_id}/roi",
    "/api/v1/security-roi/portfolio",
    "/api/v1/security-roi/recommendations",
    "/api/v1/security-roi/risk-reduction",
    "/api/v1/security-roi/trend",
    "/api/v1/security-scoreboard/challenges",
    "/api/v1/security-scoreboard/leaderboard",
    "/api/v1/security-scoreboard/stats",
    "/api/v1/security-scoreboard/teams",
    "/api/v1/security-scoreboard/teams/{team_id}",
    "/api/v1/security-scorecard/benchmarks",
    "/api/v1/security-scorecard/scorecards",
    "/api/v1/security-scorecard/scorecards/{scorecard_id}",
    "/api/v1/security-scorecard/scorecards/{scorecard_id}/compare",
    "/api/v1/security-scorecard/stats",
    "/api/v1/security-scorecard/trend",
    "/api/v1/security-scorecard/trends/{entity_type}/{entity_id}",
    "/api/v1/security-telemetry/datapoints",
    "/api/v1/security-telemetry/datapoints/latest",
    "/api/v1/security-telemetry/rules",
    "/api/v1/security-telemetry/stats",
    "/api/v1/security-training/campaigns",
    "/api/v1/security-training/courses",
    "/api/v1/security-training/enrollments",
    "/api/v1/security-training/stats",
    "/api/v1/security-training/users/{user_id}/progress",
    "/api/v1/self-learning/analyze",
    "/api/v1/self-learning/analyze/{loop}",
    "/api/v1/self-learning/demo/full-loop",
    "/api/v1/self-learning/health",
    "/api/v1/self-learning/insights",
    "/api/v1/self-learning/metrics/trends",
    "/api/v1/self-learning/stats",
    "/api/v1/self-learning/status",
    "/api/v1/self-learning/suppressed-rules",
    "/api/v1/self-learning/weights",
    "/api/v1/self-scan/findings",
    "/api/v1/self-scan/results",
    "/api/v1/self-scan/score",
    "/api/v1/service-account-auditor/accounts",
    "/api/v1/service-account-auditor/accounts/{account_id}/rotation-history",
    "/api/v1/service-account-auditor/accounts/overprivileged",
    "/api/v1/service-account-auditor/accounts/unused",
    "/api/v1/service-account-auditor/stats",
    "/api/v1/service-catalog/services/{service_id}",
    "/api/v1/service-catalog/sla-performance",
    "/api/v1/service-catalog/summary",
    "/api/v1/servicenow-sync/field-mapping",
    "/api/v1/servicenow-sync/history",
    "/api/v1/servicenow-sync/stats",
    "/api/v1/sessions/{session_id}",
    "/api/v1/sessions/concurrent/{user_email}",
    "/api/v1/sessions/stats/{org_id}",
    "/api/v1/sessions/suspicious/{org_id}",
    "/api/v1/sessions/user/{user_email}",
    "/api/v1/siem/alerts",
    "/api/v1/siem/events",
    "/api/v1/siem/integrations",
    "/api/v1/siem/integrations/{siem_id}",
    "/api/v1/siem/sources",
    "/api/v1/siem/sources/{source_id}",
    "/api/v1/siem/stats",
    "/api/v1/sla-engine/at-risk",
    "/api/v1/sla-engine/compliance-rate",
    "/api/v1/sla-engine/dashboard",
    "/api/v1/sla-engine/status/{finding_id}",
    "/api/v1/sla-escalation/check",
    "/api/v1/sla-escalation/history",
    "/api/v1/sla-escalation/policy",
    "/api/v1/sla-management/exceptions",
    "/api/v1/sla-management/policies",
    "/api/v1/sla-management/report",
    "/api/v1/sla-management/status/{finding_id}",
    "/api/v1/sla-management/teams/{team_id}/metrics",
    "/api/v1/sla-management/teams/leaderboard",
    "/api/v1/sla/",
    "/api/v1/sla/at-risk",
    "/api/v1/sla/breached",
    "/api/v1/sla/breaches",
    "/api/v1/sla/compliance",
    "/api/v1/sla/dashboard",
    "/api/v1/sla/dashboard-legacy",
    "/api/v1/sla/health",
    "/api/v1/sla/metrics",
    "/api/v1/sla/policies",
    "/api/v1/sla/status/{finding_id}",
    "/api/v1/soar/executions",
    "/api/v1/soar/mttr",
    "/api/v1/soar/playbooks",
    "/api/v1/soar/playbooks/{playbook_id}",
    "/api/v1/soar/stats",
    "/api/v1/soc-automation/rules",
    "/api/v1/soc-automation/rules/{rule_id}",
    "/api/v1/soc-automation/stats",
    "/api/v1/soc-metrics/",
    "/api/v1/soc-metrics/analyst-performance",
    "/api/v1/soc-metrics/mttd-trend",
    "/api/v1/soc-metrics/summary",
    "/api/v1/soc-triage/alerts",
    "/api/v1/soc-triage/alerts/{alert_id}",
    "/api/v1/soc-triage/metrics",
    "/api/v1/soc-triage/rules",
    "/api/v1/soc-triage/stats",
    "/api/v1/soc-workflow/executions",
    "/api/v1/soc-workflow/stats",
    "/api/v1/soc-workflow/workflows",
    "/api/v1/soc-workflow/workflows/{workflow_id}",
    "/api/v1/sspm/apps",
    "/api/v1/sspm/apps/{app_id}",
    "/api/v1/sspm/assessments",
    "/api/v1/sspm/findings",
    "/api/v1/sspm/stats",
    "/api/v1/stream/health",
    "/api/v1/stream/recent/{channel}",
    "/api/v1/stream/stats",
    "/api/v1/stream/status",
    "/api/v1/supply-chain-attacks/detections",
    "/api/v1/supply-chain-attacks/packages",
    "/api/v1/supply-chain-attacks/packages/{package_id}",
    "/api/v1/supply-chain-attacks/policies",
    "/api/v1/supply-chain-attacks/stats",
    "/api/v1/supply-chain-intel/check",
    "/api/v1/supply-chain-intel/malicious",
    "/api/v1/supply-chain-intel/packages",
    "/api/v1/supply-chain-intel/sbom/snapshots",
    "/api/v1/supply-chain-intel/stats",
    "/api/v1/supply-chain-intel/vulns",
    "/api/v1/supply-chain-monitoring/events",
    "/api/v1/supply-chain-monitoring/stats",
    "/api/v1/supply-chain-monitoring/suppliers",
    "/api/v1/supply-chain-monitoring/suppliers/{supplier_id}",
    "/api/v1/supply-chain/components",
    "/api/v1/supply-chain/license-audit",
    "/api/v1/supply-chain/policies",
    "/api/v1/supply-chain/provenance/{component_name}",
    "/api/v1/supply-chain/risks",
    "/api/v1/supply-chain/stats",
    "/api/v1/supply-chain/suppliers",
    "/api/v1/supply-chain/vendors",
    "/api/v1/system/config",
    "/api/v1/system/db-stats",
    "/api/v1/system/endpoint-health",
    "/api/v1/system/health",
    "/api/v1/system/health/degraded",
    "/api/v1/system/health/history",
    "/api/v1/system/health/{subsystem}",
    "/api/v1/system/health/{subsystem}/trend",
    "/api/v1/system/info",
    "/api/v1/system/logs/recent",
    "/api/v1/system/metrics",
    "/api/v1/system/onboarding",
    "/api/v1/system/readiness",
    "/api/v1/system/resources",
    "/api/v1/system/status",
    "/api/v1/system/traces/recent",
    "/api/v1/system/warnings",
    "/api/v1/tabletop/exercises",
    "/api/v1/tabletop/exercises/{exercise_id}",
    "/api/v1/tabletop/exercises/{exercise_id}/participants",
    "/api/v1/tabletop/findings",
    "/api/v1/tabletop/stats",
    "/api/v1/tool-inventory/assessments",
    "/api/v1/tool-inventory/integrations",
    "/api/v1/tool-inventory/stats",
    "/api/v1/tool-inventory/tools",
    "/api/v1/tool-inventory/tools/{tool_id}",
    "/api/v1/training-effectiveness/",
    "/api/v1/training-effectiveness/department-compliance",
    "/api/v1/training-effectiveness/programs",
    "/api/v1/training-effectiveness/programs/{program_id}/effectiveness",
    "/api/v1/training-effectiveness/summary",
    "/scim/v2/Groups",
    "/scim/v2/Schemas",
    "/scim/v2/ServiceProviderConfig",
    "/scim/v2/Users",
    "/scim/v2/Users/{user_id}",
]

for g in gets:
    test("GET", g)

# ============================================================
# ALL POST ENDPOINTS (with minimal bodies)
# ============================================================
print("\n" + "=" * 80)
print("TESTING ALL POST ENDPOINTS FROM S-PREFIX ROUTERS")
print("=" * 80)

posts = [
    ("/api/v1/ai-agent/batch-decide", {"queries": [{"query": "test"}]}),
    ("/api/v1/ai-agent/decide", {"query": "test decision"}),
    ("/api/v1/arch-review/reviews", {"name": "test review", "scope": "test"}),
    ("/api/v1/arch-review/reviews/{review_id}/complete", {}),
    ("/api/v1/arch-review/reviews/{review_id}/controls", {"control_name": "test", "status": "implemented"}),
    ("/api/v1/arch-review/reviews/{review_id}/findings", {"title": "test", "severity": "high"}),
    ("/api/v1/auth/sso/{provider}/callback", {"code": "test-code"}),
    ("/api/v1/auth/sso/logout", {}),
    ("/api/v1/awareness-gamification/challenges", {"name": "test", "type": "quiz", "points": 10}),
    ("/api/v1/awareness-gamification/completions", {"user_id": "u1", "challenge_id": "c1", "score": 80}),
    ("/api/v1/awareness-gamification/users/{user_id}/badges", {"badge_name": "test", "badge_type": "gold"}),
    ("/api/v1/awareness-metrics/benchmarks", {"metric_name": "test", "benchmark_value": 80.0, "source": "industry"}),
    ("/api/v1/awareness-metrics/metrics", {"metric_name": "phishing_click_rate", "value": 5.2, "department": "engineering"}),
    ("/api/v1/awareness-program/events", {"program_id": "p1", "event_type": "quiz", "user_id": "u1"}),
    ("/api/v1/awareness-program/programs", {"name": "test program", "description": "test"}),
    ("/api/v1/awareness-program/programs/{program_id}/enroll", {"user_id": "u1"}),
    ("/api/v1/capacity-planning/demands", {"title": "test demand", "skill_required": "python", "hours": 40}),
    ("/api/v1/capacity-planning/resources", {"name": "analyst-1", "role": "analyst", "skills": ["python"]}),
    ("/api/v1/capacity-planning/snapshots", {}),
    ("/api/v1/change-management/changes", {"title": "test change", "type": "standard", "description": "test"}),
    ("/api/v1/change-management/changes/{change_id}/approvals", {"approver": "admin", "decision": "approved"}),
    ("/api/v1/data-pipeline/pipelines", {"name": "test pipeline", "source_type": "siem", "destination": "datalake"}),
    ("/api/v1/data-pipeline/pipelines/{pipeline_id}/runs", {"triggered_by": "admin"}),
    ("/api/v1/dependency-mapping/dependencies", {"source_service_id": "svc-1", "target_service_id": "svc-2", "dependency_type": "api"}),
    ("/api/v1/dependency-mapping/services", {"name": "test-svc", "service_type": "api", "criticality": "high"}),
    ("/api/v1/dependency-mapping/services/{service_id}/blast-radius", {}),
    ("/api/v1/dependency-risk/dependencies", {"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}),
    ("/api/v1/dependency-risk/dependencies/{dep_id}/vulns", {"cve_id": "CVE-2021-23337", "severity": "high", "cvss": 7.5}),
    ("/api/v1/dependency-risk/license-risks", {"license_name": "GPL-3.0", "risk_level": "high", "reason": "copyleft"}),
    ("/api/v1/event-correlation/events", {"event_type": "login_failure", "source": "auth-svc", "severity": "medium"}),
    ("/api/v1/event-correlation/incidents", {"title": "test incident", "severity": "high"}),
    ("/api/v1/event-correlation/rules", {"name": "brute force", "pattern": "login_failure", "threshold": 5, "window_minutes": 10}),
    ("/api/v1/event-correlation/run", {}),
    ("/api/v1/event-timeline/correlations", {"incident_id": "inc-1", "source_event_id": "ev-1", "target_event_id": "ev-2", "correlation_type": "causal"}),
    ("/api/v1/event-timeline/events", {"incident_id": "inc-1", "event_type": "detection", "description": "test event", "actor": "attacker1"}),
    ("/api/v1/event-timeline/timelines", {"incident_id": "inc-1", "title": "test timeline"}),
    ("/api/v1/exception-workflow/requests", {"exception_type": "vulnerability", "justification": "test", "requested_by": "admin", "expires_at": "2027-01-01T00:00:00"}),
    ("/api/v1/exception-workflow/requests/{request_id}/renew", {"new_expires_at": "2027-06-01T00:00:00", "justification": "still needed"}),
    ("/api/v1/exception-workflow/requests/{request_id}/review", {"reviewer": "admin", "decision": "approved"}),
    ("/api/v1/exception-workflow/requests/{request_id}/revoke", {}),
    ("/api/v1/gap-analysis/assessments", {"name": "test assessment", "framework": "NIST CSF"}),
    ("/api/v1/gap-analysis/assessments/{assessment_id}/gaps", {"control_id": "AC-1", "current_state": "partial", "target_state": "full", "priority": "high"}),
    ("/api/v1/gap-analysis/gaps/{gap_id}/plans", {"title": "remediation plan", "owner": "admin"}),
    ("/api/v1/health-scorecard/domains", {"name": "network", "weight": 1.0, "score": 85.0}),
    ("/api/v1/health-scorecard/snapshots", {}),
    ("/api/v1/health-scorecard/targets", {"domain": "network", "target_score": 90.0, "target_date": "2027-01-01"}),
    ("/api/v1/integrations/slack/configure", {"webhook_url": "https://hooks.slack.com/test"}),
    ("/api/v1/integrations/slack/notify/alert", {"title": "test alert", "severity": "critical", "message": "test"}),
    ("/api/v1/integrations/slack/notify/compliance", {"framework": "SOC2", "message": "test failure"}),
    ("/api/v1/integrations/slack/notify/incident", {"title": "test incident", "severity": "high", "message": "test"}),
    ("/api/v1/integrations/slack/test", {}),
    ("/api/v1/kb/articles", {"title": "test article", "content": "test content", "category": "vulnerability"}),
    ("/api/v1/kpi/record", {"kpi_name": "mttd", "value": 4.5}),
    ("/api/v1/kpi/record-batch", {"records": [{"kpi_name": "mttd", "value": 4.5}]}),
    ("/api/v1/kpi/snapshot", {}),
    ("/api/v1/kpi/targets", {"kpi_name": "mttd", "target_value": 3.0, "direction": "lower"}),
    ("/api/v1/license-security/policies", {"name": "test policy", "allowed_licenses": ["MIT", "Apache-2.0"]}),
    ("/api/v1/license-security/records", {"package_name": "test-pkg", "license_type": "MIT", "version": "1.0.0"}),
    ("/api/v1/license-security/violations", {"record_id": "rec-1", "violation_type": "copyleft", "description": "test"}),
    ("/api/v1/metrics-aggregator/aggregations", {"name": "daily", "metric_names": ["mttd"], "period": "daily"}),
    ("/api/v1/metrics-aggregator/metrics", {"metric_name": "mttd", "value": 4.5, "source": "soc"}),
    ("/api/v1/metrics-aggregator/sources", {"name": "soc", "source_type": "siem"}),
    ("/api/v1/metrics-dashboard/dashboards", {"name": "SOC Dashboard", "description": "test"}),
    ("/api/v1/metrics-dashboard/dashboards/{dashboard_id}/widgets", {"name": "MTTD Chart", "widget_type": "chart", "metric_name": "mttd"}),
    ("/api/v1/metrics-dashboard/snapshots", {"dashboard_id": "test-dash-1"}),
    ("/api/v1/metrics/deployments", {"service": "api", "version": "1.0.0"}),
    ("/api/v1/metrics/events", {"event_type": "deploy", "description": "test"}),
    ("/api/v1/metrics/objectives", {"name": "test obj", "target": 90.0}),
    ("/api/v1/metrics/objectives/{obj_id}/key-results", {"name": "test kr", "target": 100}),
    ("/api/v1/metrics/reports", {"name": "monthly report"}),
    ("/api/v1/metrics/roi", {"investment": "siem", "cost": 50000, "benefit": 200000}),
    ("/api/v1/posture-benchmarking/benchmarks", {"name": "test benchmark", "framework": "NIST"}),
    ("/api/v1/posture-benchmarking/comparisons", {"benchmark_id": "bench-1", "comparison_type": "peer"}),
    ("/api/v1/posture-benchmarking/controls", {"benchmark_id": "bench-1", "control_name": "AC-1", "score": 85}),
    ("/api/v1/posture-history/snapshots", {"domain": "network", "score": 85.0}),
    ("/api/v1/posture-history/trends/compute", {"domain": "network"}),
    ("/api/v1/posture-maturity/assessments", {"domain": "network", "maturity_level": 3}),
    ("/api/v1/posture-maturity/roadmap", {"title": "test roadmap item", "domain": "network", "priority": "high"}),
    ("/api/v1/posture-maturity/snapshots", {}),
    ("/api/v1/posture-reports/reports", {"title": "test report", "report_type": "executive"}),
    ("/api/v1/posture-reports/reports/{report_id}/metrics", {"metric_name": "score", "value": 85.0}),
    ("/api/v1/posture-reports/reports/{report_id}/sections", {"title": "overview", "content": "test content"}),
    ("/api/v1/posture-scoring/controls", {"name": "AC-1", "category": "access", "weight": 1.0, "score": 85}),
    ("/api/v1/posture-scoring/score", {}),
    ("/api/v1/posture-trends/analyze/{metric_name}", {}),
    ("/api/v1/posture-trends/datapoints", {"metric_name": "posture_score", "value": 85.0}),
    ("/api/v1/posture-trends/targets", {"metric_name": "posture_score", "target_value": 90.0}),
    ("/api/v1/program-maturity/assessments", {"name": "test assessment"}),
    ("/api/v1/program-maturity/assessments/{assessment_id}/complete", {}),
    ("/api/v1/program-maturity/domains", {"name": "vulnerability_mgmt", "description": "test"}),
    ("/api/v1/program-maturity/domains/{domain_id}/assess", {"maturity_level": 3, "assessor": "admin"}),
    ("/api/v1/program-maturity/domains/{domain_id}/improvements", {"title": "improve vuln mgmt", "priority": "high", "effort": "medium"}),
    ("/api/v1/program-maturity/improvements/{improvement_id}/complete", {}),
    ("/api/v1/sast/rules/custom", {"pattern": "eval(", "severity": "high", "message": "no eval"}),
    ("/api/v1/sast/scan", {"target": "/tmp/test", "language": "python"}),
    ("/api/v1/sast/scan/code", {"code": "x = eval(input())", "language": "python"}),
    ("/api/v1/sast/scan/files", {"files": [{"path": "test.py", "content": "x=1"}]}),
    ("/api/v1/sbom-export/components", {"name": "lodash", "version": "4.17.21", "type": "library", "project_name": "test"}),
    ("/api/v1/sbom-export/components/{component_id}/vulns", {"cve_id": "CVE-2021-23337", "severity": "high"}),
    ("/api/v1/sbom-export/generate/cyclonedx", {"project_name": "test"}),
    ("/api/v1/sbom-export/generate/spdx", {"project_name": "test"}),
    ("/api/v1/sbom/assets", {"name": "test-app", "type": "application"}),
    ("/api/v1/sbom/assets/{asset_id}/components", {"name": "react", "version": "19.0.0", "type": "library"}),
    ("/api/v1/sca/projects", {"name": "test-project", "ecosystem": "npm"}),
    ("/api/v1/sca/projects/{project_id}/scans", {"scanner": "trivy"}),
    ("/api/v1/scan/semgrep/config", {"rules": ["security"]}),
    ("/api/v1/scan/semgrep/directory", {"path": "/tmp/test"}),
    ("/api/v1/scan/semgrep/file", {"path": "/tmp/test.py"}),
    ("/api/v1/scan/snyk/import", {"project_url": "https://github.com/test/test"}),
    ("/api/v1/scan/snyk/test-package", {"name": "lodash", "version": "4.17.21"}),
    ("/api/v1/scanner-ingest/detect", {"content": "test scan data"}),
    ("/api/v1/scanner-ingest/upload", {"scanner_type": "trivy", "data": "{}"}),
    ("/api/v1/scanner-ingest/webhook/{scanner_type}", {"findings": []}),
    ("/api/v1/scheduled-reports/schedules", {"name": "daily report", "report_type": "executive", "schedule": "daily"}),
    ("/api/v1/scheduled-reports/schedules/{schedule_id}/pause", {}),
    ("/api/v1/scheduled-reports/schedules/{schedule_id}/resume", {}),
    ("/api/v1/scheduled-reports/schedules/{schedule_id}/trigger", {}),
    ("/api/v1/scheduled-reports/seed-defaults", {}),
    ("/api/v1/scheduled-reports/templates", {"name": "exec template", "template_type": "executive"}),
    ("/api/v1/scorecard/{org_id}/generate", {}),
    ("/api/v1/scorecard/compare", {"org_ids": ["org1", "org2"]}),
    ("/api/v1/secret-scanner/engine-patterns", {"pattern_name": "aws_key", "regex": "AKIA[0-9A-Z]{16}"}),
    ("/api/v1/secret-scanner/findings/{finding_id}/validate", {}),
    ("/api/v1/secret-scanner/jobs", {"name": "test scan", "target": "/tmp"}),
    ("/api/v1/secret-scanner/jobs/{job_id}/start", {}),
    ("/api/v1/secret-scanner/suppressions", {"finding_id": "f1", "reason": "false positive"}),
    ("/api/v1/secrets", {"finding_type": "aws_key", "file_path": "test.py", "line_number": 10, "secret_hash": "abc123"}),
    ("/api/v1/secrets-management/secrets", {"name": "db-password", "secret_type": "password", "owner": "admin"}),
    ("/api/v1/secrets-management/secrets/{secret_id}/access", {"accessor": "app-1", "action": "read"}),
    ("/api/v1/secrets-management/secrets/{secret_id}/revoke", {}),
    ("/api/v1/secrets-management/secrets/{secret_id}/rotate", {"rotated_by": "admin"}),
    ("/api/v1/secrets-manager/secrets", {"name": "api-key", "vault_id": "v1", "secret_type": "api_key"}),
    ("/api/v1/secrets-manager/secrets/{secret_id}/rotate", {"rotated_by": "admin"}),
    ("/api/v1/secrets-manager/secrets/{secret_id}/schedule", {"rotation_days": 90}),
    ("/api/v1/secrets-manager/vaults", {"name": "production", "vault_type": "kms"}),
    ("/api/v1/secrets-rotation/expose", {"secret_type": "api_key", "source": "github", "secret_hash": "abc123"}),
    ("/api/v1/secrets-rotation/{rotation_id}/confirm", {"rotated_by": "admin"}),
    ("/api/v1/secrets-rotation/{rotation_id}/defer", {"reason": "pending review", "deferred_by": "admin"}),
    ("/api/v1/secrets-rotation/{rotation_id}/fail", {"reason": "rotation error"}),
    ("/api/v1/secrets-rotation/{rotation_id}/start", {}),
    ("/api/v1/secrets-rotation/{rotation_id}/verify", {"verified_by": "admin"}),
    ("/api/v1/secrets/{id}/resolve", {"resolved_by": "admin"}),
    ("/api/v1/secrets/{secret_id}/false-positive", {}),
    ("/api/v1/secrets/{secret_id}/rotate", {"rotated_by": "admin"}),
    ("/api/v1/secrets/patterns", {"name": "custom_key", "pattern": "KEY_[A-Z]{20}"}),
    ("/api/v1/secrets/rotate/{finding_id}", {}),
    ("/api/v1/secrets/scan", {"target": "/tmp/test"}),
    ("/api/v1/secrets/scan/content", {"content": "AWS_KEY=AKIAIOSFODNN7EXAMPLE"}),
    ("/api/v1/secrets/text-scan", {"text": "password=secret123"}),
    ("/api/v1/security-automation/rules", {"name": "auto-block", "trigger": "critical_vuln", "action": "block"}),
    ("/api/v1/security-automation/rules/{rule_id}/execute", {}),
    ("/api/v1/security-baselines/baselines", {"name": "CIS Baseline", "framework": "CIS"}),
    ("/api/v1/security-baselines/baselines/{baseline_id}/assess", {"assessor": "admin"}),
    ("/api/v1/security-baselines/baselines/{baseline_id}/controls", {"control_name": "AC-1", "expected_state": "enabled"}),
    ("/api/v1/security-benchmarks/benchmarks", {"name": "industry avg", "benchmark_type": "industry"}),
    ("/api/v1/security-benchmarks/compare", {"benchmark_ids": ["b1", "b2"]}),
    ("/api/v1/security-benchmarks/metrics", {"metric_name": "mttd", "value": 4.5}),
    ("/api/v1/security-budget/allocations", {"name": "SIEM", "category": "detection", "amount": 50000, "fiscal_year": 2026}),
    ("/api/v1/security-budget/roi-assessments", {"allocation_id": "a1", "roi_pct": 150, "assessment_notes": "good"}),
    ("/api/v1/security-budget/transactions", {"allocation_id": "a1", "amount": 10000, "description": "license"}),
    ("/api/v1/security-champions/campaigns", {"name": "Q1 campaign", "start_date": "2026-01-01"}),
    ("/api/v1/security-champions/champions", {"name": "John Doe", "team": "engineering", "email": "john@test.com"}),
    ("/api/v1/security-champions/champions/{champion_id}/activities", {"activity_type": "code_review", "description": "test"}),
    ("/api/v1/security-champions/champions/{champion_id}/certifications", {"certification_name": "CISSP", "date_earned": "2026-01-01"}),
    ("/api/v1/security-chaos/experiments", {"name": "test experiment", "target": "api-gateway", "chaos_type": "latency"}),
    ("/api/v1/security-chaos/experiments/{experiment_id}/observations", {"observation": "latency increased", "severity": "medium"}),
    ("/api/v1/security-chaos/experiments/{experiment_id}/remediations", {"action": "rollback", "description": "test"}),
    ("/api/v1/security-culture/assessments", {"department": "engineering", "score": 85}),
    ("/api/v1/security-culture/initiatives", {"name": "awareness training", "category": "training", "status": "planned"}),
    ("/api/v1/security-culture/metrics", {"metric_name": "phishing_rate", "value": 5.0, "category": "awareness"}),
    ("/api/v1/security-exceptions/{org_id}", {"exception_type": "vulnerability", "justification": "test", "asset_id": "a1"}),
    ("/api/v1/security-exceptions/{org_id}/{exception_id}/assets", {"asset_id": "a2"}),
    ("/api/v1/security-exceptions/{org_id}/{exception_id}/review", {"reviewer": "admin", "decision": "approved"}),
    ("/api/v1/security-exceptions/{org_id}/{exception_id}/revoke", {}),
    ("/api/v1/security-findings/findings", {"title": "test finding", "severity": "high", "source": "scanner", "asset_id": "a1"}),
    ("/api/v1/security-findings/findings/{finding_id}/evidence", {"evidence_type": "screenshot", "content": "test"}),
    ("/api/v1/security-findings/findings/{finding_id}/suppress", {"reason": "false positive", "suppressed_by": "admin"}),
    ("/api/v1/security-health/checks", {"name": "db_check", "check_type": "database", "status": "healthy"}),
    ("/api/v1/security-health/checks/{check_id}/incidents", {"description": "db slow", "severity": "medium"}),
    ("/api/v1/security-health/incidents/{incident_id}/resolve", {}),
    ("/api/v1/security-health/snapshots", {}),
    ("/api/v1/security-investment/budgets", {"fiscal_year": 2026, "total_budget": 500000, "category": "detection"}),
    ("/api/v1/security-investment/budgets/spend", {"fiscal_year": 2026, "category": "detection", "amount": 10000, "description": "SIEM license"}),
    ("/api/v1/security-investment/investments", {"name": "SIEM deployment", "category": "detection", "amount": 50000}),
    ("/api/v1/security-investment/investments/{investment_id}/activate", {}),
    ("/api/v1/security-investment/investments/{investment_id}/complete", {}),
    ("/api/v1/security-investment/investments/{investment_id}/outcomes", {"outcome_type": "cost_savings", "value": 100000}),
    ("/api/v1/security-maturity/assessments", {"name": "Q1 assessment"}),
    ("/api/v1/security-maturity/assessments/{assessment_id}/complete", {}),
    ("/api/v1/security-maturity/domains/{domain_id}/controls", {"control_name": "AC-1", "status": "implemented"}),
    ("/api/v1/security-maturity/targets", {"domain_id": "d1", "target_level": 4}),
    ("/api/v1/security-metrics-collector/alerts/{alert_id}/acknowledge", {}),
    ("/api/v1/security-metrics-collector/metrics", {"name": "mttd", "metric_type": "time", "unit": "hours"}),
    ("/api/v1/security-metrics-collector/metrics/{metric_id}/aggregates", {"period": "daily"}),
    ("/api/v1/security-metrics-collector/metrics/{metric_id}/readings", {"value": 4.5}),
    ("/api/v1/security-okrs/objectives", {"title": "Reduce MTTD", "period": "Q1-2026", "owner": "soc-lead"}),
    ("/api/v1/security-okrs/objectives/{objective_id}/close", {}),
    ("/api/v1/security-okrs/objectives/{objective_id}/key-results", {"title": "MTTD < 4hrs", "target_value": 4.0, "unit": "hours"}),
    ("/api/v1/security-okrs/objectives/{objective_id}/key-results/{kr_id}/update", {"current_value": 3.5}),
    ("/api/v1/security-playbooks/playbooks", {"name": "ransomware response", "description": "test"}),
    ("/api/v1/security-playbooks/playbooks/{playbook_id}/execute", {"triggered_by": "admin"}),
    ("/api/v1/security-questionnaires/assessments", {"questionnaire_id": "q1", "vendor_id": "v1"}),
    ("/api/v1/security-questionnaires/assessments/{assessment_id}/responses", {"question_id": "q1", "response": "yes", "score": 4}),
    ("/api/v1/security-questionnaires/assessments/{assessment_id}/score", {}),
    ("/api/v1/security-questionnaires/questionnaires", {"name": "vendor assessment", "framework": "SOC2", "questionnaire_type": "vendor"}),
    ("/api/v1/security-questionnaires/questionnaires/{questionnaire_id}/questions", {"text": "Do you encrypt?", "required": True}),
    ("/api/v1/security-registry/artifacts", {"name": "auth-policy", "artifact_type": "policy", "content": "test"}),
    ("/api/v1/security-registry/artifacts/{artifact_id}/references", {"reference_type": "url", "reference_value": "https://test.com"}),
    ("/api/v1/security-registry/artifacts/{artifact_id}/reviews", {"reviewer": "admin", "status": "approved"}),
    ("/api/v1/security-roadmap/gaps", {"title": "missing WAF", "priority": "high"}),
    ("/api/v1/security-roadmap/gaps/{gap_id}/link", {"initiative_id": "init-1"}),
    ("/api/v1/security-roadmap/initiatives", {"title": "deploy WAF", "priority": "high", "status": "planned"}),
    ("/api/v1/security-roadmap/initiatives/{initiative_id}/metrics", {"metric_name": "completion", "value": 50}),
    ("/api/v1/security-roadmap/initiatives/{initiative_id}/milestones", {"title": "POC complete", "due_date": "2026-06-01"}),
    ("/api/v1/security-roadmap/milestones/{milestone_id}/complete", {}),
    ("/api/v1/security-roi/investments", {"category": "detection", "name": "SIEM", "annual_cost": 50000}),
    ("/api/v1/security-scoreboard/challenges", {"name": "CTF Q1", "challenge_type": "ctf", "max_score": 100}),
    ("/api/v1/security-scoreboard/challenges/{challenge_id}/score", {"team_id": "t1", "score": 85}),
    ("/api/v1/security-scoreboard/teams", {"name": "Blue Team", "department": "security"}),
    ("/api/v1/security-scorecard/benchmarks", {"name": "industry", "overall_score": 75.0}),
    ("/api/v1/security-scorecard/scorecards", {"entity_type": "org", "entity_id": "default", "overall_score": 82.0}),
    ("/api/v1/security-scorecard/scorecards/domain", {"scorecard_id": "sc-1", "domain": "network", "score": 85.0}),
    ("/api/v1/security-telemetry/aggregate", {"telemetry_type": "cpu", "aggregation": "avg", "period": "1h"}),
    ("/api/v1/security-telemetry/datapoints", {"source": "firewall", "telemetry_type": "network", "value": 1024.0}),
    ("/api/v1/security-telemetry/rules", {"name": "high cpu", "telemetry_type": "cpu", "threshold": 90.0, "action": "alert"}),
    ("/api/v1/security-telemetry/rules/check", {}),
    ("/api/v1/security-training/campaigns", {"name": "Q1 training", "start_date": "2026-01-01"}),
    ("/api/v1/security-training/courses", {"title": "OWASP Top 10", "description": "test", "duration_hours": 4}),
    ("/api/v1/security-training/enrollments", {"course_id": "c1", "user_id": "u1"}),
    ("/api/v1/security-training/enrollments/{enrollment_id}/complete", {"score": 90}),
    ("/api/v1/self-learning/compute-adjustments", {"finding_type": "xss", "base_score": 7.5}),
    ("/api/v1/self-learning/demo/live-feedback", {}),
    ("/api/v1/self-learning/demo/reset", {}),
    ("/api/v1/self-learning/demo/seed", {}),
    ("/api/v1/self-learning/feedback/decision", {"finding_id": "f1", "decision": "true_positive"}),
    ("/api/v1/self-learning/feedback/false-positive", {"finding_id": "f1", "reason": "test"}),
    ("/api/v1/self-learning/feedback/mpte", {"test_id": "t1", "success": True}),
    ("/api/v1/self-learning/feedback/policy", {"policy_id": "p1", "effective": True}),
    ("/api/v1/self-learning/feedback/remediation", {"finding_id": "f1", "remediation_type": "patch", "success": True}),
    ("/api/v1/self-learning/score-with-learning", {"finding_type": "sqli", "base_score": 8.0}),
    ("/api/v1/self-scan/run", {}),
    ("/api/v1/service-account-auditor/accounts", {"name": "svc-deploy", "account_type": "service", "owner": "devops"}),
    ("/api/v1/service-account-auditor/accounts/{account_id}/audit", {}),
    ("/api/v1/service-account-auditor/accounts/{account_id}/rotate", {"rotated_by": "admin"}),
    ("/api/v1/service-catalog/services", {"name": "auth-service", "service_type": "api", "owner": "platform"}),
    ("/api/v1/service-catalog/services/{service_id}/outages", {"description": "service down", "severity": "critical"}),
    ("/api/v1/service-catalog/services/{service_id}/requests", {"request_type": "access", "requester": "user1"}),
    ("/api/v1/servicenow-sync/configure", {"instance_url": "https://test.service-now.com", "username": "admin", "password": "test"}),
    ("/api/v1/servicenow-sync/sync-all", {}),
    ("/api/v1/servicenow-sync/sync-finding", {"finding_id": "f1"}),
    ("/api/v1/servicenow-sync/sync-status", {}),
    ("/api/v1/sessions", {"user_email": "test@example.com", "org_id": "default", "ip_address": "127.0.0.1", "user_agent": "test"}),
    ("/api/v1/sessions/{session_id}/refresh", {}),
    ("/api/v1/sessions/cleanup", {}),
    ("/api/v1/siem/alerts", {"title": "suspicious login", "severity": "high", "source_id": "s1"}),
    ("/api/v1/siem/alerts/{alert_id}/resolve", {}),
    ("/api/v1/siem/events", {"event_type": "login", "source": "auth", "raw_log": "test"}),
    ("/api/v1/siem/ingest", {"log_format": "syslog", "raw_data": "test log data"}),
    ("/api/v1/siem/integrations", {"name": "splunk", "siem_type": "splunk", "endpoint": "https://splunk.test.com"}),
    ("/api/v1/siem/sources", {"name": "firewall", "source_type": "network", "endpoint": "syslog://fw1:514"}),
    ("/api/v1/sla-engine/alerts", {}),
    ("/api/v1/sla-engine/policy", {"severity": "critical", "response_hours": 4, "resolution_hours": 24}),
    ("/api/v1/sla-engine/resolve/{finding_id}", {}),
    ("/api/v1/sla-engine/track", {"finding_id": "f1", "severity": "critical"}),
    ("/api/v1/sla-escalation/cycle", {}),
    ("/api/v1/sla-management/assign", {"finding_id": "f1", "assignee": "analyst1"}),
    ("/api/v1/sla-management/assign/bulk", {"finding_ids": ["f1", "f2"], "assignee": "analyst1"}),
    ("/api/v1/sla-management/escalate", {"finding_id": "f1", "reason": "overdue"}),
    ("/api/v1/sla-management/exceptions", {"finding_id": "f1", "reason": "vendor dependency", "new_deadline": "2027-01-01T00:00:00"}),
    ("/api/v1/sla-management/policies", {"name": "critical-24h", "severity": "critical", "response_hours": 4, "resolution_hours": 24}),
    ("/api/v1/sla/escalate", {"finding_id": "f1"}),
    ("/api/v1/sla/policies", {"severity": "critical", "response_hours": 4, "resolution_hours": 24, "org_id": "default"}),
    ("/api/v1/sla/track", {"finding_id": "f1", "severity": "critical"}),
    ("/api/v1/sla/track/bulk", {"items": [{"finding_id": "f1", "severity": "critical"}]}),
    ("/api/v1/slack/commands", {"command": "/security", "text": "status"}),
    ("/api/v1/slack/events", {"type": "event_callback", "event": {"type": "message"}}),
    ("/api/v1/slack/interactions", {"type": "block_actions", "actions": []}),
    ("/api/v1/soar/playbooks", {"name": "ransomware", "description": "test", "steps": []}),
    ("/api/v1/soar/playbooks/{playbook_id}/execute", {"triggered_by": "admin"}),
    ("/api/v1/soar/trigger", {"playbook_id": "pb-1", "trigger_type": "alert"}),
    ("/api/v1/soc-automation/actions/{action}", {"target": "192.168.1.100"}),
    ("/api/v1/soc-automation/evaluate", {"event": {"type": "login_failure", "count": 10}}),
    ("/api/v1/soc-automation/rules", {"name": "block brute force", "condition": "login_failures > 5", "action": "block_ip"}),
    ("/api/v1/soc-metrics/alerts", {"title": "test alert", "severity": "high", "source": "siem"}),
    ("/api/v1/soc-metrics/snapshots", {}),
    ("/api/v1/soc-triage/alerts", {"title": "suspicious activity", "source": "edr", "severity": "high"}),
    ("/api/v1/soc-triage/alerts/{alert_id}/verdict", {"verdict": "true_positive", "analyst": "admin"}),
    ("/api/v1/soc-triage/rules", {"name": "auto-escalate critical", "condition": "severity == critical", "action": "escalate"}),
    ("/api/v1/soc-triage/sessions", {"analyst": "admin"}),
    ("/api/v1/soc-triage/sessions/{session_id}/close", {}),
    ("/api/v1/soc-workflow/executions", {"workflow_id": "w1", "triggered_by": "admin"}),
    ("/api/v1/soc-workflow/workflows", {"name": "incident response", "description": "test", "steps": ["triage", "contain", "eradicate"]}),
    ("/api/v1/sspm/apps", {"name": "slack", "category": "collaboration", "vendor": "Salesforce"}),
    ("/api/v1/sspm/apps/{app_id}/assess", {}),
    ("/api/v1/sspm/apps/{app_id}/findings", {"title": "weak auth", "severity": "high"}),
    ("/api/v1/stream/publish", {"channel": "alerts", "data": {"message": "test"}}),
    ("/api/v1/supply-chain-attacks/detections", {"package_id": "p1", "detection_type": "typosquat", "confidence": 0.9}),
    ("/api/v1/supply-chain-attacks/packages", {"name": "lodash", "ecosystem": "npm", "version": "4.17.21"}),
    ("/api/v1/supply-chain-attacks/policies", {"name": "block malicious", "policy_type": "block", "ecosystem": "npm"}),
    ("/api/v1/supply-chain-intel/malicious", {"package_name": "evil-pkg", "ecosystem": "npm", "reason": "malware"}),
    ("/api/v1/supply-chain-intel/packages", {"name": "lodash", "ecosystem": "npm", "version": "4.17.21"}),
    ("/api/v1/supply-chain-intel/packages/{pkg_id}/vulns", {"cve_id": "CVE-2021-23337", "severity": "high"}),
    ("/api/v1/supply-chain-intel/sbom/snapshots", {"project_name": "test", "components": []}),
    ("/api/v1/supply-chain-monitoring/events", {"supplier_id": "s1", "event_type": "breach", "description": "test"}),
    ("/api/v1/supply-chain-monitoring/suppliers", {"name": "Acme Corp", "category": "saas", "risk_level": "medium"}),
    ("/api/v1/supply-chain-monitoring/suppliers/{supplier_id}/assess", {"assessment_score": 75, "assessor": "admin"}),
    ("/api/v1/supply-chain/components", {"name": "react", "version": "19.0.0", "ecosystem": "npm"}),
    ("/api/v1/supply-chain/osv-scan", {"ecosystem": "npm", "package": "lodash", "version": "4.17.21"}),
    ("/api/v1/supply-chain/policies", {"name": "block GPL", "policy_type": "license_block"}),
    ("/api/v1/supply-chain/risks", {"component_id": "c1", "risk_type": "vulnerability", "severity": "high"}),
    ("/api/v1/supply-chain/sbom", {"project": "test", "format": "cyclonedx"}),
    ("/api/v1/supply-chain/sbom/import", {"format": "cyclonedx", "content": "{}"}),
    ("/api/v1/supply-chain/sbom/upload", {"format": "cyclonedx", "content": "{}"}),
    ("/api/v1/supply-chain/scan", {"target": "package.json"}),
    ("/api/v1/supply-chain/suppliers", {"name": "Acme", "tier": "critical"}),
    ("/api/v1/supply-chain/sync", {}),
    ("/api/v1/supply-chain/vendors", {"name": "test vendor", "category": "saas"}),
    ("/api/v1/tabletop/exercises", {"name": "ransomware scenario", "scenario_type": "ransomware"}),
    ("/api/v1/tabletop/findings", {"exercise_id": "e1", "title": "slow response", "severity": "medium"}),
    ("/api/v1/tabletop/participants", {"exercise_id": "e1", "name": "John Doe", "role": "incident_commander"}),
    ("/api/v1/tool-inventory/assessments", {"tool_id": "t1", "assessment_type": "effectiveness", "score": 85}),
    ("/api/v1/tool-inventory/integrations", {"source_tool_id": "t1", "target_tool_id": "t2", "integration_type": "api"}),
    ("/api/v1/tool-inventory/tools", {"name": "Splunk", "category": "siem", "vendor": "Splunk Inc", "status": "active"}),
    ("/api/v1/training-effectiveness/programs", {"name": "OWASP training", "program_type": "technical"}),
    ("/api/v1/training-effectiveness/programs/{program_id}/complete", {"user_id": "u1", "pre_score": 60, "post_score": 90}),
    ("/api/v1/training-effectiveness/programs/{program_id}/enroll", {"user_id": "u1", "department": "engineering"}),
    ("/api/v1/training-effectiveness/programs/{program_id}/retention", {"user_id": "u1", "retention_score": 85, "days_since_completion": 30}),
    ("/scim/v2/Groups", {"displayName": "Security Team", "members": []}),
    ("/scim/v2/Users", {"userName": "test@example.com", "name": {"givenName": "Test", "familyName": "User"}, "emails": [{"value": "test@example.com", "primary": True}]}),
]

for path, body in posts:
    test("POST", path, body)

# ============================================================
# ALL PUT ENDPOINTS
# ============================================================
print("\n" + "=" * 80)
print("TESTING ALL PUT ENDPOINTS FROM S-PREFIX ROUTERS")
print("=" * 80)

puts = [
    ("/api/v1/awareness-program/enrollments/{enrollment_id}/complete", {"score": 85}),
    ("/api/v1/capacity-planning/demands/{demand_id}/assign", {"resource_id": "r1"}),
    ("/api/v1/capacity-planning/resources/{resource_id}/utilization", {"utilization_pct": 80}),
    ("/api/v1/dependency-risk/vulns/{vuln_id}/patch", {}),
    ("/api/v1/event-timeline/timelines/{timeline_id}/close", {}),
    ("/api/v1/gap-analysis/gaps/{gap_id}/status", {"status": "in_progress"}),
    ("/api/v1/gap-analysis/plans/{plan_id}/complete", {}),
    ("/api/v1/kb/articles/{article_id}", {"title": "updated", "content": "updated content"}),
    ("/api/v1/license-security/records/{record_id}/approve", {}),
    ("/api/v1/license-security/violations/{violation_id}/resolve", {"resolved_by": "admin"}),
    ("/api/v1/metrics-aggregator/sources/{source_id}/sync", {}),
    ("/api/v1/posture-benchmarking/benchmarks/{benchmark_id}/complete", {}),
    ("/api/v1/posture-history/baselines", {"domain": "network", "baseline_score": 80}),
    ("/api/v1/posture-maturity/assessments/{assessment_id}", {"maturity_level": 4}),
    ("/api/v1/posture-maturity/roadmap/{item_id}/advance", {}),
    ("/api/v1/posture-reports/reports/{report_id}/publish", {}),
    ("/api/v1/posture-trends/targets/{metric_name}/progress", {"current_value": 87.5}),
    ("/api/v1/security-baselines/baselines/{baseline_id}/publish", {}),
    ("/api/v1/security-budget/transactions/{transaction_id}/approve", {"approved_by": "cfo"}),
    ("/api/v1/security-chaos/experiments/{experiment_id}/complete", {"resilience_score": 85}),
    ("/api/v1/security-chaos/experiments/{experiment_id}/start", {}),
    ("/api/v1/security-chaos/remediations/{remediation_id}/status", {"status": "completed"}),
    ("/api/v1/security-maturity/domains/{domain_id}/score", {"maturity_level": 4}),
    ("/api/v1/self-learning/weights/{key:path}", {"value": 1.5}),
    ("/api/v1/service-catalog/outages/{outage_id}/resolve", {}),
    ("/api/v1/service-catalog/requests/{request_id}/acknowledge", {}),
    ("/api/v1/service-catalog/requests/{request_id}/resolve", {}),
    ("/api/v1/servicenow-sync/field-mapping", {"mappings": {"severity": "priority"}}),
    ("/api/v1/siem/alerts/{alert_id}/acknowledge", {}),
    ("/api/v1/siem/integrations/{siem_id}/status", {"status": "active"}),
    ("/api/v1/sla-escalation/policy", {"tiers": [{"name": "tier1", "hours": 4}]}),
    ("/api/v1/soc-automation/rules/{rule_id}", {"name": "updated rule", "condition": "test", "action": "alert"}),
    ("/api/v1/soc-metrics/alerts/{alert_id}/acknowledge", {}),
    ("/api/v1/soc-metrics/alerts/{alert_id}/resolve", {}),
    ("/api/v1/soc-metrics/workload", {"analyst": "admin", "queue_size": 10}),
    ("/api/v1/soc-workflow/executions/{execution_id}/complete", {}),
    ("/api/v1/soc-workflow/executions/{execution_id}/step", {"step_name": "triage", "status": "completed"}),
    ("/api/v1/supply-chain-attacks/detections/{detection_id}/confirm", {"confirmed_by": "admin"}),
    ("/api/v1/supply-chain-attacks/packages/{package_id}/status", {"status": "blocked"}),
    ("/api/v1/supply-chain-monitoring/events/{event_id}/resolve", {"resolved_by": "admin"}),
    ("/api/v1/tabletop/exercises/{exercise_id}/complete", {"score": 85}),
    ("/api/v1/tool-inventory/tools/{tool_id}/status", {"status": "deprecated"}),
    ("/scim/v2/Users/{user_id}", {"userName": "updated@example.com", "name": {"givenName": "Updated", "familyName": "User"}}),
]

for path, body in puts:
    test("PUT", path, body)

# ============================================================
# ALL PATCH ENDPOINTS
# ============================================================
print("\n" + "=" * 80)
print("TESTING ALL PATCH ENDPOINTS FROM S-PREFIX ROUTERS")
print("=" * 80)

patches = [
    ("/api/v1/change-management/changes/{change_id}/status", {"status": "approved"}),
    ("/api/v1/data-pipeline/pipelines/{pipeline_id}/status", {"status": "active"}),
    ("/api/v1/metrics/objectives/{obj_id}/key-results/{kr_id}", {"progress": 75}),
    ("/api/v1/posture-scoring/controls/{control_id}/status", {"status": "passing"}),
    ("/api/v1/scheduled-reports/schedules/{schedule_id}", {"name": "updated schedule"}),
    ("/api/v1/secret-scanner/findings/{finding_id}", {"status": "resolved"}),
    ("/api/v1/security-automation/rules/{rule_id}/disable", {}),
    ("/api/v1/security-automation/rules/{rule_id}/enable", {}),
    ("/api/v1/security-culture/initiatives/{initiative_id}/progress", {"progress_pct": 75}),
    ("/api/v1/security-findings/findings/{finding_id}/status", {"status": "resolved"}),
    ("/api/v1/security-health/checks/{check_id}/status", {"status": "degraded"}),
    ("/api/v1/security-registry/artifacts/{artifact_id}/status", {"status": "active"}),
    ("/api/v1/security-roadmap/initiatives/{initiative_id}", {"status": "in_progress"}),
    ("/api/v1/sla-management/exceptions/{exception_id}/approve", {"approved_by": "admin"}),
    ("/scim/v2/Groups/{group_id}", {"Operations": [{"op": "add", "path": "members", "value": []}]}),
    ("/scim/v2/Users/{user_id}", {"Operations": [{"op": "replace", "path": "active", "value": False}]}),
]

for path, body in patches:
    test("PATCH", path, body)

# ============================================================
# ALL DELETE ENDPOINTS
# ============================================================
print("\n" + "=" * 80)
print("TESTING ALL DELETE ENDPOINTS FROM S-PREFIX ROUTERS")
print("=" * 80)

deletes = [
    "/api/v1/ai-agent/cache",
    "/api/v1/dependency-mapping/dependencies/{dependency_id}",
    "/api/v1/kb/articles/{article_id}",
    "/api/v1/metrics/objectives/{obj_id}",
    "/api/v1/scheduled-reports/schedules/{schedule_id}",
    "/api/v1/sessions/{session_id}",
    "/api/v1/sessions/user/{user_email}",
    "/api/v1/soc-automation/rules/{rule_id}",
    "/scim/v2/Users/{user_id}",
]

for d in deletes:
    test("DELETE", d)

# ============================================================
# GENERATE REPORT
# ============================================================
print("\n" + "=" * 80)
print("GENERATING REPORT")
print("=" * 80)

total = len(results)
pass_2xx = sum(1 for r in results if 200 <= r["status"] < 300)
fail_5xx = sum(1 for r in results if 500 <= r["status"] < 600)
fail_4xx = sum(1 for r in results if 400 <= r["status"] < 500)
fail_conn = sum(1 for r in results if r["status"] == 0)
not_found = sum(1 for r in results if r["status"] == 404)

print(f"\nTotal endpoints tested: {total}")
print(f"  2xx (OK):      {pass_2xx}")
print(f"  4xx (Client):  {fail_4xx}")
print(f"  5xx (Server):  {fail_5xx}")
print(f"  0xx (Conn):    {fail_conn}")
print(f"  404 (Missing): {not_found}")

# Write markdown report
with open("/Users/devops.ai/fixops/Fixops/.omc/reports/api_test_batch_S.md", "w") as f:
    f.write(f"# API Test Report: S-Prefix Routers\n\n")
    f.write(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"**Base URL**: {BASE}\n")
    f.write(f"**Router files tested**: 99 (s*_router.py)\n\n")

    f.write(f"## Summary\n\n")
    f.write(f"| Metric | Count |\n")
    f.write(f"|--------|-------|\n")
    f.write(f"| Total endpoints tested | {total} |\n")
    f.write(f"| 2xx Success | {pass_2xx} |\n")
    f.write(f"| 4xx Client Error | {fail_4xx} |\n")
    f.write(f"| 5xx Server Error | {fail_5xx} |\n")
    f.write(f"| Connection Error | {fail_conn} |\n")
    f.write(f"| 404 Not Found | {not_found} |\n\n")

    # Group by status
    f.write(f"## 5xx Server Errors (Bugs)\n\n")
    errs_5xx = [r for r in results if 500 <= r["status"] < 600]
    if errs_5xx:
        f.write(f"| Status | Method | Path | Detail |\n")
        f.write(f"|--------|--------|------|--------|\n")
        for r in errs_5xx:
            detail = r['detail'].replace('|', '\\|')[:100]
            f.write(f"| {r['status']} | {r['method']} | `{r['path']}` | {detail} |\n")
    else:
        f.write("None\n")

    f.write(f"\n## Connection Errors\n\n")
    errs_conn = [r for r in results if r["status"] == 0]
    if errs_conn:
        f.write(f"| Method | Path | Detail |\n")
        f.write(f"|--------|------|--------|\n")
        for r in errs_conn:
            f.write(f"| {r['method']} | `{r['path']}` | {r['detail']} |\n")
    else:
        f.write("None\n")

    f.write(f"\n## 404 Not Found (Unwired Routes)\n\n")
    errs_404 = [r for r in results if r["status"] == 404]
    if errs_404:
        f.write(f"| Method | Path |\n")
        f.write(f"|--------|------|\n")
        for r in errs_404:
            f.write(f"| {r['method']} | `{r['path']}` |\n")
    else:
        f.write("None\n")

    f.write(f"\n## Full Results\n\n")
    f.write(f"| Status | Method | Path |\n")
    f.write(f"|--------|--------|------|\n")
    for r in results:
        icon = "PASS" if 200 <= r["status"] < 300 else ("WARN" if 400 <= r["status"] < 500 else "FAIL")
        f.write(f"| {r['status']} | {r['method']} | `{r['path']}` |\n")

print(f"\nReport written to .omc/reports/api_test_batch_S.md")
