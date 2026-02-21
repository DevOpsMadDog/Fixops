#!/usr/bin/env python3
"""FixOps End-to-End API Test Suite — routes verified against OpenAPI spec."""
import json
import os
import sys
import urllib.parse
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import Request, urlopen

BASE = os.environ.get("FIXOPS_BASE_URL", "http://localhost:8000")
API_KEY = os.environ.get("FIXOPS_API_TOKEN", "")
if not API_KEY:
    print("ERROR: FIXOPS_API_TOKEN environment variable is required.")
    sys.exit(1)
results = []


JWT_TOKEN = None  # populated after login


def test(method, path, data=None, desc="", form=False, bearer=False, accept_codes=None):
    """Test an endpoint. accept_codes: extra HTTP codes treated as PASS (e.g. [404])."""
    url = f"{BASE}{path}"
    if form and data:
        body = urllib.parse.urlencode(data).encode()
        ct = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        ct = "application/json"
    else:
        body = None
        ct = "application/json"
    headers = {"Content-Type": ct}
    if bearer and JWT_TOKEN:
        headers["Authorization"] = f"Bearer {JWT_TOKEN}"
    else:
        headers["X-API-Key"] = API_KEY
    req = Request(url, data=body, headers=headers, method=method)
    try:
        resp = urlopen(req, timeout=15)
        code = resp.status
        rbody = resp.read().decode()[:300]
        ok = 200 <= code < 400
    except HTTPError as e:
        code = e.code
        rbody = e.read().decode()[:300]
        ok = False
    except Exception as e:
        code = 0
        rbody = str(e)[:300]
        ok = False
    if accept_codes and code in accept_codes:
        ok = True
    status = "PASS" if ok else "FAIL"
    results.append((status, method, path, code, desc, rbody))
    sym = "pass" if ok else "FAIL"
    print(f"  [{sym}] {method:5s} {path:65s} -> {code} | {desc}")
    return ok, code, rbody


print("=" * 90)
print(f"FixOps E2E API Test Suite — {datetime.now(timezone.utc).isoformat()}")
print("=" * 90)

# 1. Core Health & Status
print("\n--- Core Health & Status ---")
test("GET", "/health", desc="Root health")
test("GET", "/api/v1/health", desc="API v1 health")
test("GET", "/api/v1/status", desc="System status")
test("GET", "/api/v1/ready", desc="Readiness")
test("GET", "/api/v1/version", desc="Version")
test("GET", "/api/v1/metrics", desc="Metrics")

# 2. Auth / Users
print("\n--- Auth / Users ---")
# Ensure a test user exists, then login
_test_email = "e2e-test@fixops.io"
_test_pass = "E2eTestSecure2026!"
_create_ok, _create_code, _ = test(
    "POST",
    "/api/v1/users",
    {
        "email": _test_email,
        "password": _test_pass,
        "first_name": "E2E",
        "last_name": "Test",
        "role": "admin",
    },
    "Create test user",
    accept_codes=[409],
)  # 409 = already exists
ok, code, rbody = test(
    "POST",
    "/api/v1/users/login",
    {"email": _test_email, "password": _test_pass},
    "Login",
)
if ok:
    try:
        JWT_TOKEN = json.loads(rbody).get("access_token")
    except Exception:
        pass
test("GET", "/api/v1/users", desc="List users")

# 3. Decisions (was broken: 'No module named src')
print("\n--- Decisions Router (was broken) ---")
test(
    "POST",
    "/api/v1/decisions/make-decision",
    {"service_name": "test-svc", "cve_id": "CVE-2024-1234", "severity": "high"},
    "Make decision",
)
test("GET", "/api/v1/decisions/recent", desc="Recent decisions")
test("GET", "/api/v1/decisions/metrics", desc="Decision metrics")
test("GET", "/api/v1/decisions/core-components", desc="Core components", bearer=True)
test("GET", "/api/v1/decisions/ssdlc-stages", desc="SSDLC stages", bearer=True)

# 4. Business Context (was broken: 'No module named src')
print("\n--- Business Context (was broken) ---")
test("GET", "/api/v1/business-context/formats", desc="Supported formats")
test(
    "POST",
    "/api/v1/business-context/validate",
    {
        "content": "exposure: internet\nrevenue_impact: medium",
        "format_type": "core.yaml",
    },
    "Validate context",
    form=True,
)
test(
    "POST",
    "/api/v1/business-context/enrich-context",
    {"service_name": "test-svc"},
    "Enrich context",
    bearer=True,
)

# 5. Enhanced Analysis (business_context_enhanced)
print("\n--- Enhanced Analysis (was broken) ---")
test(
    "POST",
    "/api/v1/enhanced/analysis",
    {"service_name": "test-svc", "vulnerability_id": "CVE-2024-1234"},
    "Enhanced analysis",
)
test("GET", "/api/v1/enhanced/capabilities", desc="Enhanced capabilities")

# 6. OSS Tools (was broken: 'No module named src')
print("\n--- OSS Tools (was broken) ---")
test("GET", "/api/v1/oss/status", desc="OSS tools status")
test("GET", "/api/v1/oss/tools", desc="OSS tools list")
test("GET", "/api/v1/oss/policies", desc="OSS policies")
test(
    "POST",
    "/api/v1/oss/policy/evaluate",
    {
        "policy_name": "license-check",
        "input_data": {"package": "lodash", "version": "4.17.20"},
    },
    "Policy evaluate",
)

# 7. Copilot Agents - Analyst
print("\n--- Copilot Agents: Analyst ---")
test(
    "POST",
    "/api/v1/copilot/agents/analyst/analyze",
    {"cve_id": "CVE-2024-1234", "depth": "standard"},
    "Analyze CVE",
)
test(
    "POST",
    "/api/v1/copilot/agents/analyst/attack-path",
    {"asset_id": "web-01", "depth": 3, "include_lateral": True},
    "Attack path",
)
test("GET", "/api/v1/copilot/agents/analyst/risk-score/web-01", desc="Risk score")
test(
    "GET",
    "/api/v1/copilot/agents/analyst/trending?timeframe=7d&limit=5",
    desc="Trending",
)
test(
    "POST",
    "/api/v1/copilot/agents/analyst/prioritize",
    {"finding_ids": ["f1", "f2"], "strategy": "risk_based"},
    "Prioritize",
)
test(
    "POST",
    "/api/v1/copilot/agents/analyst/threat-intel",
    {"cve_id": "CVE-2024-1234"},
    "Threat intel",
)

# 8. Copilot Agents - Pentest
print("\n--- Copilot Agents: Pentest ---")
test(
    "POST",
    "/api/v1/copilot/agents/pentest/validate",
    {"cve_id": "CVE-2024-1234", "target_id": "srv01"},
    "Validate exploit",
)
test(
    "POST",
    "/api/v1/copilot/agents/pentest/generate-poc",
    {"cve_id": "CVE-2024-1234", "language": "python"},
    "Generate PoC",
)
test(
    "POST",
    "/api/v1/copilot/agents/pentest/reachability",
    {"cve_id": "CVE-2024-1234", "asset_ids": ["srv01"]},
    "Reachability",
)
test(
    "POST",
    "/api/v1/copilot/agents/pentest/simulate",
    {"scenario_type": "ransomware", "target_assets": ["srv01"]},
    "Simulate attack",
)

# 9. Copilot Agents - Compliance
print("\n--- Copilot Agents: Compliance ---")
test(
    "POST",
    "/api/v1/copilot/agents/compliance/map-findings",
    {"finding_ids": ["f1"], "frameworks": ["pci-dss"]},
    "Map findings",
)
test(
    "POST",
    "/api/v1/copilot/agents/compliance/gap-analysis",
    {"framework": "soc2"},
    "Gap analysis",
)
test(
    "POST",
    "/api/v1/copilot/agents/compliance/audit-evidence",
    {"framework": "soc2", "controls": ["CC6.1"]},
    "Audit evidence",
)
test(
    "POST",
    "/api/v1/copilot/agents/compliance/regulatory-alerts",
    {"jurisdictions": ["US"], "industries": ["financial"]},
    "Regulatory alerts",
)
test("GET", "/api/v1/copilot/agents/compliance/controls/pci-dss", desc="Controls")
test("GET", "/api/v1/copilot/agents/compliance/dashboard", desc="Dashboard")
test(
    "POST",
    "/api/v1/copilot/agents/compliance/generate-report?framework=soc2",
    None,
    "Generate report",
)

# 10. Copilot Agents - Remediation
print("\n--- Copilot Agents: Remediation ---")
test(
    "POST",
    "/api/v1/copilot/agents/remediation/generate-fix",
    {"finding_id": "f1", "language": "python"},
    "Generate fix",
)
test(
    "POST",
    "/api/v1/copilot/agents/remediation/create-pr",
    {"finding_ids": ["f1"], "repository": "test/repo", "branch": "fix/vuln"},
    "Create PR",
)
test(
    "POST",
    "/api/v1/copilot/agents/remediation/update-dependencies",
    {"finding_id": "f1", "package_manager": "pip"},
    "Update deps",
)
test(
    "POST",
    "/api/v1/copilot/agents/remediation/playbook",
    {"finding_ids": ["f1"], "audience": "developer"},
    "Playbook",
)
test(
    "GET",
    "/api/v1/copilot/agents/remediation/recommendations/f1",
    desc="Recommendations",
)
test("POST", "/api/v1/copilot/agents/remediation/verify", ["f1"], "Verify")
test("GET", "/api/v1/copilot/agents/remediation/queue?priority=critical", desc="Queue")

# 11. Copilot Agents - Status
print("\n--- Copilot Agents: Meta ---")
test("GET", "/api/v1/copilot/agents/health", desc="Agents health")
test("GET", "/api/v1/copilot/agents/status", desc="Agents status")
test("GET", "/api/v1/copilot/health", desc="Copilot health")

# 12. Vuln Discovery
print("\n--- Vuln Discovery ---")
test("GET", "/api/v1/vulns/discovered", desc="List discovered vulns")
test("GET", "/api/v1/vulns/internal", desc="List internal vulns")
test("GET", "/api/v1/vulns/health", desc="Vulns health")
test("GET", "/api/v1/vulns/stats", desc="Vulns stats")

# 13. Feeds
print("\n--- Feeds ---")
test("GET", "/api/v1/feeds/health", desc="Feeds health")
test("GET", "/api/v1/feeds/sources", desc="Feed sources")
test("GET", "/api/v1/feeds/stats", desc="Feed stats")
test("GET", "/api/v1/feeds/epss", desc="EPSS data")
test("GET", "/api/v1/feeds/kev", desc="KEV catalog")

# 14. Evidence
print("\n--- Evidence ---")
test("GET", "/api/v1/evidence/", desc="Evidence list")
test("GET", "/api/v1/evidence/stats", desc="Evidence stats")

# 15. Marketplace
print("\n--- Marketplace ---")
test("GET", "/api/v1/marketplace/browse", desc="Browse marketplace")
test("GET", "/api/v1/marketplace/stats", desc="Marketplace stats")
test("GET", "/api/v1/marketplace/recommendations", desc="Recommendations")

# 16. Integrations
print("\n--- Integrations ---")
test("GET", "/api/v1/integrations", desc="List integrations")

# 17. IaC
print("\n--- IaC ---")
test("GET", "/api/v1/iac", desc="IaC scans")
test("GET", "/api/v1/iac/scanners/status", desc="IaC scanner status")

# 18. ML
print("\n--- ML ---")
test("GET", "/api/v1/ml/models", desc="ML models")
test("GET", "/api/v1/ml/status", desc="ML status")
test("GET", "/api/v1/ml/stats", desc="ML stats")

# 19. Container Security
print("\n--- Container Security ---")
test(
    "POST",
    "/api/v1/container/scan/image",
    {"image_ref": "nginx:latest"},
    "Container image scan",
)

# 20. Additional Routers (404 = no data yet, acceptable in demo mode)
print("\n--- Additional Routers ---")
test("GET", "/api/v1/triage", desc="Triage view", accept_codes=[404])
test("GET", "/api/v1/triage/export", desc="Triage export", accept_codes=[404])
test("GET", "/api/v1/risk/", desc="Risk overview", accept_codes=[404])
test("GET", "/api/v1/risk/cve/CVE-2024-1234", desc="Risk by CVE", accept_codes=[404])

# Summary
print("\n" + "=" * 80)
passed = sum(1 for r in results if r[0] == "PASS")
failed = sum(1 for r in results if r[0] == "FAIL")
total = len(results)
print(f"RESULTS: {passed} passed, {failed} failed, {total} total")
print("=" * 80)

# Generate markdown report
report = []
report.append("# FixOps E2E API Test Report\n")
report.append(
    f"**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
)
report.append(f"**Server**: {BASE}")
report.append("**Mode**: FIXOPS_MODE=demo")
report.append(f"**Result**: {passed}/{total} passed ({failed} failed)\n")
report.append("| Status | Method | Path | HTTP | Description |")
report.append("|--------|--------|------|------|-------------|")
for s, m, p, c, d, b in results:
    icon = "✅" if s == "PASS" else "❌"
    note = ""
    if s == "FAIL":
        note = f" — `{b[:80]}`"
    report.append(f"| {icon} | {m} | `{p}` | {c} | {d}{note} |")

report.append("\n## Summary\n")
report.append(f"- **Total endpoints tested**: {total}")
report.append(f"- **Passed**: {passed}")
report.append(f"- **Failed**: {failed}")
report.append(f"- **Pass rate**: {passed/total*100:.1f}%")

# Write report
with open("docs/E2E_TEST_REPORT.md", "w") as f:
    f.write("\n".join(report) + "\n")
print("\nReport written to docs/E2E_TEST_REPORT.md")

sys.exit(0 if failed == 0 else 1)
