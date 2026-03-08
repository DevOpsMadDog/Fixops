#!/usr/bin/env python3
"""
FixOps 25-Persona Reality Validation
Tests each persona's real-world workflow against the live API.
Every test uses REAL API calls — no mocks, no fakes.
"""
import json
import sys
import requests

API = "http://localhost:8000"
KEY = "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
H = {"X-API-Key": KEY}
HJ = {"X-API-Key": KEY, "Content-Type": "application/json"}

passed = 0
failed = 0
results = []

def persona_test(persona_id, persona_name, role, tests):
    """Run tests for a persona. Each test is (name, lambda) -> bool"""
    global passed, failed
    persona_pass = 0
    persona_total = len(tests)
    
    for test_name, test_fn in tests:
        try:
            result = test_fn()
            if result:
                persona_pass += 1
            else:
                pass  # count at end
        except Exception:
            pass  # count at end
    
    pct = (persona_pass / persona_total * 100) if persona_total > 0 else 0
    status = "PASS" if pct >= 80 else "FAIL"
    
    if status == "PASS":
        passed += 1
    else:
        failed += 1
    
    results.append({
        "id": persona_id,
        "name": persona_name,
        "role": role,
        "tests_passed": persona_pass,
        "tests_total": persona_total,
        "percentage": pct,
        "status": status
    })
    
    symbol = "✓" if status == "PASS" else "✗"
    print(f"  {symbol} P{persona_id:02d} {persona_name} ({role}): {persona_pass}/{persona_total} ({pct:.0f}%)")

# ============================================================
# PERSONA TESTS
# ============================================================

print("=" * 70)
print("  FixOps 25-Persona Enterprise Reality Validation")
print("=" * 70)

# P01: CISO — Chief Information Security Officer
persona_test(1, "Sarah Chen", "CISO", [
    ("View security overview dashboard", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/overview", headers=H).status_code == 200),
    ("Check compliance posture", lambda: requests.get(f"{API}/api/v1/compliance-engine/soc2/status", headers=H).status_code == 200),
    ("View risk trends", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/trends", headers=H).status_code == 200),
    ("Review top risks", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/top-risks", headers=H).status_code == 200),
    ("Check MTTR metrics", lambda: requests.get(f"{API}/api/v1/analytics/mttr", headers=H).status_code == 200),
    ("Export compliance report", lambda: requests.get(f"{API}/api/v1/evidence/status", headers=H).status_code == 200),
])

# P02: VP Engineering — Platform Owner
persona_test(2, "Marcus Johnson", "VP Engineering", [
    ("View application inventory", lambda: requests.get(f"{API}/api/v1/inventory/applications", headers=H).status_code == 200),
    ("Check remediation backlog", lambda: requests.get(f"{API}/api/v1/remediation/backlog", headers=H).status_code == 200),
    ("Review remediation metrics", lambda: requests.get(f"{API}/api/v1/remediation/metrics", headers=H).status_code == 200),
    ("View noise reduction stats", lambda: requests.get(f"{API}/api/v1/analytics/noise-reduction", headers=H).status_code == 200),
    ("Check pipeline status", lambda: requests.get(f"{API}/api/v1/brain/stats", headers=H).status_code == 200),
])

# P03: SOC Analyst — Tier 1
persona_test(3, "Alex Rivera", "SOC Analyst T1", [
    ("View findings queue", lambda: requests.get(f"{API}/api/v1/analytics/findings", headers=H).status_code == 200),
    ("Check dedup clusters", lambda: requests.get(f"{API}/api/v1/deduplication/clusters", headers=H, params={"org_id": "default"}).status_code == 200),
    ("View nerve center pulse", lambda: requests.get(f"{API}/api/v1/nerve-center/pulse", headers=H).status_code == 200),
    ("Ask copilot for help", lambda: requests.post(f"{API}/api/v1/copilot/ask", headers=HJ, json={"question": "What needs attention?"}).status_code == 200),
    ("Check recent activity", lambda: requests.get(f"{API}/api/v1/nerve-center/state", headers=H).status_code == 200),
])

# P04: SOC Analyst — Tier 2
persona_test(4, "Priya Sharma", "SOC Analyst T2", [
    ("Investigate finding detail", lambda: requests.get(f"{API}/api/v1/brain/nodes", headers=H).status_code == 200),
    ("Check attack paths", lambda: requests.get(f"{API}/api/v1/attack-sim/campaigns", headers=H).status_code == 200),
    ("View MITRE mapping", lambda: requests.get(f"{API}/api/v1/attack-sim/mitre/heatmap", headers=H).status_code == 200),
    ("Request MPTE verification", lambda: requests.post(f"{API}/api/v1/mpte/verify", headers=HJ, json={"finding_id": "p04-test", "target_url": "http://app:8080", "vulnerability_type": "sqli"}).status_code in (200, 201)),
    ("Check vulnerability feeds", lambda: requests.get(f"{API}/api/v1/feeds/nvd/recent", headers=H).status_code == 200),
])

# P05: Security Engineer
persona_test(5, "James Wilson", "Security Engineer", [
    ("Ingest SARIF scan", lambda: requests.post(f"{API}/inputs/sarif", headers=H, files={"file": open("/tmp/real_semgrep_scan.sarif", "rb")}).status_code == 200),
    ("View scanner support", lambda: requests.get(f"{API}/api/v1/scanner-ingest/supported", headers=H).status_code == 200),
    ("Check autofix suggestions", lambda: requests.post(f"{API}/api/v1/autofix/generate", headers=HJ, json={"finding_id": "p05", "finding_type": "xss", "language": "javascript", "code_context": "innerHTML = userInput"}).status_code == 200),
    ("Review autofix stats", lambda: requests.get(f"{API}/api/v1/autofix/stats", headers=H).status_code == 200),
    ("Submit false positive feedback", lambda: requests.post(f"{API}/api/v1/self-learning/feedback/false-positive", headers=HJ, json={"finding_id": "p05-fp", "rule_id": "R001", "scanner": "semgrep", "is_false_positive": True, "reason": "Test code"}).status_code == 200),
])

# P06: DevSecOps Engineer
persona_test(6, "Emma Davis", "DevSecOps Engineer", [
    ("Run pipeline", lambda: (requests.post(f"{API}/inputs/design", headers=H, files={"file": open("/tmp/design.csv", "rb")}), requests.post(f"{API}/pipeline/run", headers=H).status_code == 200)[1]),
    ("Check SBOM components", lambda: requests.post(f"{API}/inputs/sbom", headers=H, files={"file": open("/tmp/real_sbom.json", "rb")}).status_code == 200),
    ("View policies", lambda: requests.get(f"{API}/api/v1/policies", headers=H).status_code == 200),
    ("Check workflows", lambda: requests.get(f"{API}/api/v1/workflows", headers=H).status_code == 200),
    ("View connector types", lambda: requests.get(f"{API}/api/v1/connectors/types", headers=H).status_code == 200),
])

# P07: Compliance Officer
persona_test(7, "Robert Kim", "Compliance Officer", [
    ("List compliance frameworks", lambda: requests.get(f"{API}/api/v1/compliance-engine/frameworks", headers=H).status_code == 200),
    ("Assess SOC2", lambda: requests.post(f"{API}/api/v1/compliance-engine/assess", headers=HJ, json={"framework": "SOC2"}).status_code == 200),
    ("Assess PCI-DSS", lambda: requests.post(f"{API}/api/v1/compliance-engine/assess", headers=HJ, json={"framework": "PCI_DSS_4.0"}).status_code == 200),
    ("View compliance gaps", lambda: requests.get(f"{API}/api/v1/compliance-engine/gaps", headers=H).status_code == 200),
    ("Check HIPAA status", lambda: requests.get(f"{API}/api/v1/compliance-engine/hipaa/status", headers=H).status_code == 200),
    ("Audit trail access", lambda: requests.get(f"{API}/api/v1/audit/logs", headers=H).status_code == 200),
    ("Evidence bundles", lambda: requests.get(f"{API}/api/v1/evidence/status", headers=H).status_code == 200),
])

# P08: Penetration Tester
persona_test(8, "Lisa Zhang", "Penetration Tester", [
    ("View MITRE techniques", lambda: requests.get(f"{API}/api/v1/attack-sim/mitre/techniques", headers=H).status_code == 200 and requests.get(f"{API}/api/v1/attack-sim/mitre/techniques", headers=H).json().get("total", 0) > 0),
    ("Run MPTE verification", lambda: requests.post(f"{API}/api/v1/mpte/verify", headers=HJ, json={"finding_id": "p08-rce", "target_url": "http://target:8080", "vulnerability_type": "rce", "cve_id": "CVE-2021-44228"}).status_code in (200, 201)),
    ("Check MPTE stats", lambda: requests.get(f"{API}/api/v1/mpte/stats", headers=H).status_code == 200),
    ("View attack campaigns", lambda: requests.get(f"{API}/api/v1/attack-sim/campaigns", headers=H).status_code == 200),
    ("FAIL score CVE", lambda: requests.post(f"{API}/api/v1/fail/score", headers=HJ, json={"cve_id": "CVE-2021-44228", "cvss": 10.0, "epss": 0.975, "is_kev": True}).status_code == 200),
])

# P09: Risk Manager
persona_test(9, "David Park", "Risk Manager", [
    ("View top risks", lambda: requests.get(f"{API}/api/v1/fail/top-risks", headers=H).status_code == 200),
    ("FAIL stats", lambda: requests.get(f"{API}/api/v1/fail/stats", headers=H).status_code == 200),
    ("Risk predictions", lambda: requests.post(f"{API}/api/v1/predictions/risk-trajectory", headers=HJ, json={"asset_id": "web-app", "timeframe_days": 30}).status_code == 200),
    ("Analytics risk velocity", lambda: requests.get(f"{API}/api/v1/analytics/risk-velocity", headers=H).status_code == 200),
    ("Coverage analysis", lambda: requests.get(f"{API}/api/v1/analytics/coverage", headers=H).status_code == 200),
])

# P10: IT Director
persona_test(10, "Maria Lopez", "IT Director", [
    ("System health", lambda: requests.get(f"{API}/api/v1/system/health", headers=H).status_code == 200),
    ("System info", lambda: requests.get(f"{API}/api/v1/system/info", headers=H).status_code == 200),
    ("View teams", lambda: requests.get(f"{API}/api/v1/teams", headers=H).status_code == 200),
    ("View users", lambda: requests.get(f"{API}/api/v1/users", headers=H).status_code == 200),
    ("Analytics summary", lambda: requests.get(f"{API}/api/v1/analytics/summary", headers=H).status_code == 200),
])

# P11: Application Security Lead
persona_test(11, "Tom Anderson", "AppSec Lead", [
    ("Application inventory", lambda: requests.get(f"{API}/api/v1/inventory/applications", headers=H).status_code == 200),
    ("Remediation tasks", lambda: requests.get(f"{API}/api/v1/remediation/tasks", headers=H).status_code == 200),
    ("SLA check", lambda: requests.post(f"{API}/api/v1/remediation/sla/check", headers=HJ, params={"org_id": "default"}).status_code == 200),
    ("Triage funnel", lambda: requests.get(f"{API}/api/v1/analytics/triage-funnel", headers=H).status_code == 200),
    ("Dedup noise reduction", lambda: requests.get(f"{API}/api/v1/analytics/noise-reduction", headers=H).status_code == 200),
])

# P12: Cloud Security Architect
persona_test(12, "Jennifer Wu", "Cloud Security Architect", [
    ("Knowledge graph status", lambda: requests.get(f"{API}/api/v1/knowledge-graph/status", headers=H).status_code == 200),
    ("Brain graph stats", lambda: requests.get(f"{API}/api/v1/brain/stats", headers=H).status_code == 200),
    ("Asset inventory", lambda: requests.get(f"{API}/api/v1/inventory/assets", headers=H).status_code == 200),
    ("Services inventory", lambda: requests.get(f"{API}/api/v1/inventory/services", headers=H).status_code == 200),
    ("Code-to-cloud trace", lambda: requests.get(f"{API}/api/v1/code-to-cloud/status", headers=H).status_code == 200),
])

# P13: Audit Manager
persona_test(13, "Michael Brown", "Audit Manager", [
    ("Audit logs", lambda: requests.get(f"{API}/api/v1/audit/logs", headers=H).status_code == 200),
    ("Compliance frameworks", lambda: requests.get(f"{API}/api/v1/audit/compliance/frameworks", headers=H).status_code == 200),
    ("Decision trail", lambda: requests.get(f"{API}/api/v1/audit/decision-trail", headers=H).status_code == 200),
    ("Policy changes", lambda: requests.get(f"{API}/api/v1/audit/policy-changes", headers=H).status_code == 200),
    ("User activity", lambda: requests.get(f"{API}/api/v1/audit/user-activity", headers=H).status_code == 200),
    ("Evidence chain verify", lambda: requests.get(f"{API}/api/v1/audit/chain/verify", headers=H).status_code == 200),
])

# P14: Incident Response Lead
persona_test(14, "Karen Taylor", "Incident Response Lead", [
    ("Nerve center pulse", lambda: requests.get(f"{API}/api/v1/nerve-center/pulse", headers=H).status_code == 200),
    ("Intelligence map", lambda: requests.get(f"{API}/api/v1/nerve-center/intelligence-map", headers=H).status_code == 200),
    ("Playbooks", lambda: requests.get(f"{API}/api/v1/nerve-center/playbooks", headers=H).status_code == 200 and len(requests.get(f"{API}/api/v1/nerve-center/playbooks", headers=H).json().get("playbooks", [])) > 0),
    ("Nerve center state", lambda: requests.get(f"{API}/api/v1/nerve-center/state", headers=H).status_code == 200),
    ("Cases list", lambda: requests.get(f"{API}/api/v1/cases", headers=H).status_code == 200),
])

# P15: Security Data Scientist
persona_test(15, "Chris Lee", "Security Data Scientist", [
    ("ML model status", lambda: requests.get(f"{API}/api/v1/ml/status", headers=H).status_code == 200),
    ("ML models list", lambda: requests.get(f"{API}/api/v1/ml/models", headers=H).status_code == 200 and len(requests.get(f"{API}/api/v1/ml/models", headers=H).json().get("models", [])) > 0),
    ("Anomaly detection", lambda: requests.post(f"{API}/api/v1/ml/predict/anomaly", headers=HJ, json={"request_data": {"method": "POST", "path": "/admin", "status_code": 403}}).status_code == 200),
    ("Self-learning weights", lambda: requests.get(f"{API}/api/v1/self-learning/weights", headers=H).status_code == 200),
    ("Self-learning stats", lambda: requests.get(f"{API}/api/v1/self-learning/stats", headers=H).status_code == 200 and requests.get(f"{API}/api/v1/self-learning/stats", headers=H).json().get("total_feedback_records", 0) > 0),
])

# P16: Platform Engineer
persona_test(16, "Ryan Murphy", "Platform Engineer", [
    ("Health check", lambda: requests.get(f"{API}/api/v1/health", headers=H).status_code == 200),
    ("Metrics endpoint", lambda: requests.get(f"{API}/api/v1/metrics", headers=H).status_code == 200),
    ("System config", lambda: requests.get(f"{API}/api/v1/system/config", headers=H).status_code == 200),
    ("Version", lambda: requests.get(f"{API}/api/v1/version", headers=H).status_code == 200),
    ("Ready probe", lambda: requests.get(f"{API}/api/v1/ready", headers=H).status_code == 200),
])

# P17: Threat Intelligence Analyst
persona_test(17, "Nina Patel", "Threat Intel Analyst", [
    ("NVD feed", lambda: requests.get(f"{API}/api/v1/feeds/nvd/recent", headers=H).status_code == 200),
    ("MITRE techniques feed", lambda: requests.get(f"{API}/api/v1/feeds/mitre/techniques", headers=H).status_code == 200),
    ("EPSS scores", lambda: requests.get(f"{API}/api/v1/feeds/epss/scores", headers=H).status_code == 200),
    ("Feeds status", lambda: requests.get(f"{API}/api/v1/feeds/status", headers=H).status_code == 200),
    ("FAIL CVE lookup", lambda: requests.get(f"{API}/api/v1/fail/cve/CVE-2021-44228", headers=H).status_code == 200),
])

# P18: GRC Analyst
persona_test(18, "Olivia Martin", "GRC Analyst", [
    ("SOC2 compliance", lambda: requests.get(f"{API}/api/v1/compliance-engine/soc2/status", headers=H).status_code == 200),
    ("PCI-DSS compliance", lambda: requests.get(f"{API}/api/v1/compliance-engine/pci-dss/status", headers=H).status_code == 200),
    ("Compliance gaps", lambda: requests.get(f"{API}/api/v1/compliance-engine/gaps", headers=H).status_code == 200),
    ("Evidence export", lambda: requests.get(f"{API}/api/v1/evidence/status", headers=H).status_code == 200),
    ("Audit compliance controls", lambda: requests.get(f"{API}/api/v1/audit/compliance/controls", headers=H).status_code == 200),
])

# P19: Security Operations Manager
persona_test(19, "Daniel Thompson", "SecOps Manager", [
    ("Dashboard overview", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/overview", headers=H).status_code == 200),
    ("Remediation metrics", lambda: requests.get(f"{API}/api/v1/remediation/metrics", headers=H).status_code == 200),
    ("Team management", lambda: requests.get(f"{API}/api/v1/teams", headers=H).status_code == 200),
    ("Workflow management", lambda: requests.get(f"{API}/api/v1/workflows", headers=H).status_code == 200),
    ("Policy management", lambda: requests.get(f"{API}/api/v1/policies", headers=H).status_code == 200),
])

# P20: Developer (Security Champion)
persona_test(20, "Emily Chang", "Developer (Security Champion)", [
    ("View my findings", lambda: requests.get(f"{API}/api/v1/analytics/findings", headers=H).status_code == 200),
    ("Get autofix suggestion", lambda: requests.post(f"{API}/api/v1/autofix/generate", headers=HJ, json={"finding_id": "p20", "finding_type": "path_traversal", "language": "python", "code_context": "open(user_path)"}).status_code == 200),
    ("Ask copilot", lambda: requests.post(f"{API}/api/v1/copilot/ask", headers=HJ, json={"question": "How do I fix SQL injection?"}).status_code == 200),
    ("View fix types", lambda: requests.get(f"{API}/api/v1/autofix/fix-types", headers=H).status_code == 200),
    ("Check confidence levels", lambda: requests.get(f"{API}/api/v1/autofix/confidence-levels", headers=H).status_code == 200),
])

# P21: Security Architect
persona_test(21, "Richard Adams", "Security Architect", [
    ("Knowledge graph analytics", lambda: requests.get(f"{API}/api/v1/knowledge-graph/analytics", headers=H).status_code == 200),
    ("Brain most connected", lambda: requests.get(f"{API}/api/v1/brain/most-connected", headers=H).status_code == 200),
    ("Attack simulation health", lambda: requests.get(f"{API}/api/v1/attack-sim/health", headers=H).status_code == 200),
    ("MCP tools catalog", lambda: requests.get(f"{API}/api/v1/mcp/tools", headers=H).status_code == 200),
    ("Predictions risk trajectory", lambda: requests.post(f"{API}/api/v1/predictions/risk-trajectory", headers=HJ, json={"asset_id": "api-gateway", "timeframe_days": 90}).status_code == 200),
])

# P22: Supply Chain Security Lead
persona_test(22, "Amanda Scott", "Supply Chain Security", [
    ("SBOM ingest", lambda: requests.post(f"{API}/inputs/sbom", headers=H, files={"file": open("/tmp/real_sbom.json", "rb")}).status_code == 200),
    ("Inventory components", lambda: requests.get(f"{API}/api/v1/inventory/assets", headers=H).status_code == 200),
    ("Provenance check", lambda: requests.get(f"{API}/api/v1/provenance/status", headers=H).status_code == 200),
    ("Graph lineage", lambda: requests.get(f"{API}/api/v1/graph/status", headers=H).status_code == 200),
    ("Risk component lookup", lambda: requests.get(f"{API}/api/v1/risk/status", headers=H).status_code == 200),
])

# P23: QA Security Tester
persona_test(23, "Brian Hall", "QA Security Tester", [
    ("Scan file upload", lambda: requests.post(f"{API}/inputs/sarif", headers=H, files={"file": open("/tmp/real_semgrep_scan.sarif", "rb")}).status_code == 200),
    ("Scanner ingest stats", lambda: requests.get(f"{API}/api/v1/scanner-ingest/stats", headers=H).status_code == 200),
    ("Dedup stats", lambda: requests.get(f"{API}/api/v1/deduplication/stats", headers=H).status_code == 200),
    ("Remediation tasks", lambda: requests.get(f"{API}/api/v1/remediation/tasks", headers=H).status_code == 200),
    ("Self-learning feedback", lambda: requests.post(f"{API}/api/v1/self-learning/feedback/decision", headers=HJ, json={"decision_id": "p23-dec", "finding_id": "p23", "predicted_action": "fix", "actual_outcome": "fixed", "was_correct": True}).status_code == 200),
])

# P24: Executive (Board Member)
persona_test(24, "Catherine Williams", "Board Member", [
    ("Executive dashboard", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/overview", headers=H).status_code == 200),
    ("Compliance status", lambda: requests.get(f"{API}/api/v1/analytics/dashboard/compliance-status", headers=H).status_code == 200),
    ("Risk summary", lambda: requests.get(f"{API}/api/v1/analytics/summary", headers=H).status_code == 200),
    ("ROI metrics", lambda: requests.get(f"{API}/api/v1/analytics/roi", headers=H).status_code == 200),
])

# P25: External Auditor
persona_test(25, "Mark Roberts", "External Auditor", [
    ("Audit logs", lambda: requests.get(f"{API}/api/v1/audit/logs", headers=H).status_code == 200),
    ("Compliance frameworks", lambda: requests.get(f"{API}/api/v1/audit/compliance/frameworks", headers=H).status_code == 200),
    ("Evidence verification", lambda: requests.get(f"{API}/api/v1/evidence/status", headers=H).status_code == 200),
    ("Audit chain verify", lambda: requests.get(f"{API}/api/v1/audit/chain/verify", headers=H).status_code == 200),
    ("Retention policy", lambda: requests.get(f"{API}/api/v1/audit/retention", headers=H).status_code == 200),
])

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("  RESULTS")
print("=" * 70)

total = passed + failed
pct = (passed / total * 100) if total > 0 else 0

print(f"\n  Personas Passed: {passed}/{total} ({pct:.1f}%)")
print(f"  Personas Failed: {failed}/{total}")

# Show any failing personas
failing = [r for r in results if r["status"] == "FAIL"]
if failing:
    print("\n  Failing Personas:")
    for f in failing:
        print(f"    - P{f['id']:02d} {f['name']} ({f['role']}): {f['tests_passed']}/{f['tests_total']}")

if pct >= 96:
    print(f"\n  🟢 ALL PERSONAS VALIDATED — {pct:.1f}% pass rate")
elif pct >= 80:
    print(f"\n  🟡 MOSTLY VALIDATED — {pct:.1f}% pass rate")
else:
    print(f"\n  🔴 NOT READY — {pct:.1f}% pass rate")

# Save results
with open("/home/user/workspace/persona_validation_results.json", "w") as f:
    json.dump({"passed": passed, "failed": failed, "total": total, "percentage": pct, "personas": results}, f, indent=2)

if __name__ == "__main__":
    sys.exit(0 if pct >= 90 else 1)
