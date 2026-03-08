#!/usr/bin/env python3
"""
FixOps Enterprise E2E Workflow Test
Tests the complete vulnerability management lifecycle:
  Ingest → Dedupe → Triage → Remediate → Verify → Comply
"""
import sys
import requests

API = "http://localhost:8000"
KEY = "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
H = {"X-API-Key": KEY}
HJ = {"X-API-Key": KEY, "Content-Type": "application/json"}

passed = 0
failed = 0
total = 0

def test(name, func):
    global passed, failed, total
    total += 1
    try:
        result = func()
        if result:
            passed += 1
            print(f"  ✓ {name}")
        else:
            failed += 1
            print(f"  ✗ {name} — returned falsy")
    except Exception as e:
        failed += 1
        print(f"  ✗ {name} — {e}")

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

# ============================================================
# PHASE 1: SYSTEM HEALTH & INFRASTRUCTURE
# ============================================================
section("PHASE 1: SYSTEM HEALTH & INFRASTRUCTURE")

def t_health():
    r = requests.get(f"{API}/api/v1/health", headers=H)
    d = r.json()
    return r.status_code == 200 and d.get("status") in ("ok", "healthy")
test("API Health Check", t_health)

def t_version():
    r = requests.get(f"{API}/api/v1/version", headers=H)
    return r.status_code == 200
test("Version Endpoint", t_version)

def t_system_info():
    r = requests.get(f"{API}/api/v1/system/info", headers=H)
    return r.status_code == 200
test("System Info", t_system_info)

def t_metrics():
    r = requests.get(f"{API}/api/v1/metrics", headers=H)
    return r.status_code == 200
test("Prometheus Metrics", t_metrics)

# ============================================================
# PHASE 2: SCAN DATA INGESTION
# ============================================================
section("PHASE 2: SCAN DATA INGESTION")

def t_ingest_sarif():
    with open("/tmp/real_semgrep_scan.sarif", "rb") as f:
        r = requests.post(f"{API}/inputs/sarif", headers=H, files={"file": f})
    d = r.json()
    return r.status_code == 200 and d.get("metadata", {}).get("finding_count", 0) > 0
test("Ingest SARIF (8 Semgrep findings)", t_ingest_sarif)

def t_ingest_sbom():
    with open("/tmp/real_sbom.json", "rb") as f:
        r = requests.post(f"{API}/inputs/sbom", headers=H, files={"file": f})
    d = r.json()
    return r.status_code == 200 and d.get("metadata", {}).get("component_count", 0) > 0
test("Ingest SBOM (15 CycloneDX components)", t_ingest_sbom)

def t_ingest_cve():
    with open("/tmp/cve_feed.json", "rb") as f:
        r = requests.post(f"{API}/inputs/cve", headers=H, files={"file": f})
    return r.status_code == 200
test("Ingest CVE Feed", t_ingest_cve)

def t_scanner_detect():
    # scanner-ingest/detect expects file upload, not JSON content
    with open("/tmp/real_semgrep_scan.sarif", "rb") as f:
        r = requests.post(f"{API}/api/v1/scanner-ingest/detect", headers=H, files={"file": f})
    return r.status_code == 200
test("Scanner Auto-Detect Format", t_scanner_detect)

def t_scanner_supported():
    r = requests.get(f"{API}/api/v1/scanner-ingest/supported", headers=H)
    d = r.json()
    return r.status_code == 200 and len(d.get("scanners", d.get("supported", []))) > 0
test("List Supported Scanners", t_scanner_supported)

# ============================================================
# PHASE 3: PIPELINE EXECUTION
# ============================================================
section("PHASE 3: PIPELINE EXECUTION")

def t_pipeline_run():
    # Ingest design CSV first
    with open("/tmp/design.csv", "rb") as f:
        requests.post(f"{API}/inputs/design", headers=H, files={"file": f})
    r = requests.post(f"{API}/pipeline/run", headers=H)
    d = r.json()
    return r.status_code == 200 and ("sarif_summary" in d or "status" in d)
test("Full Pipeline Run", t_pipeline_run)

# ============================================================
# PHASE 4: BRAIN / KNOWLEDGE GRAPH
# ============================================================
section("PHASE 4: BRAIN / KNOWLEDGE GRAPH")

def t_brain_stats():
    r = requests.get(f"{API}/api/v1/brain/stats", headers=H)
    d = r.json()
    return r.status_code == 200 and d.get("total_nodes", 0) > 0
test("Brain Stats (nodes/edges)", t_brain_stats)

def t_brain_nodes():
    r = requests.get(f"{API}/api/v1/brain/nodes", headers=H)
    d = r.json()
    d.get("nodes", d) if isinstance(d, dict) else d
    return r.status_code == 200
test("Brain Nodes Query", t_brain_nodes)

def t_brain_trends():
    r = requests.get(f"{API}/api/v1/brain/trends", headers=H)
    return r.status_code == 200
test("Brain Trends", t_brain_trends)

def t_brain_ingest_finding():
    r = requests.post(f"{API}/api/v1/brain/ingest/finding", headers=HJ, json={
        "finding_id": "test-e2e-001",
        "title": "SQL Injection in login.py",
        "severity": "critical",
        "cwe": "CWE-89",
        "source": "semgrep"
    })
    return r.status_code == 200
test("Brain Ingest Finding", t_brain_ingest_finding)

# ============================================================
# PHASE 5: DEDUPLICATION
# ============================================================
section("PHASE 5: DEDUPLICATION")

def t_dedup_process():
    r = requests.post(f"{API}/api/v1/deduplication/process", headers=HJ, json={
        "finding": {"id": "f1", "title": "SQL Injection in auth", "severity": "critical", "cwe": "CWE-89", "file": "auth.py", "source": "semgrep"},
        "org_id": "default",
        "run_id": "e2e-test-run-001"
    })
    return r.status_code == 200
test("Dedup Process Finding", t_dedup_process)

def t_dedup_stats():
    r = requests.get(f"{API}/api/v1/deduplication/stats", headers=H)
    return r.status_code == 200
test("Dedup Stats", t_dedup_stats)

def t_dedup_clusters():
    r = requests.get(f"{API}/api/v1/deduplication/clusters", headers=H, params={"org_id": "default"})
    return r.status_code == 200
test("Dedup Clusters List", t_dedup_clusters)

# ============================================================
# PHASE 6: RISK SCORING (FAIL)
# ============================================================
section("PHASE 6: RISK SCORING (FAIL)")

def t_fail_score():
    r = requests.post(f"{API}/api/v1/fail/score", headers=HJ, json={
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "epss": 0.975,
        "is_kev": True,
        "asset_criticality": "mission-critical"
    })
    d = r.json()
    return r.status_code == 200 and d.get("score", d.get("fail_score", 0)) > 0
test("FAIL Score (Log4Shell)", t_fail_score)

def t_fail_top_risks():
    r = requests.get(f"{API}/api/v1/fail/top-risks", headers=H)
    return r.status_code == 200
test("FAIL Top Risks", t_fail_top_risks)

def t_fail_stats():
    r = requests.get(f"{API}/api/v1/fail/stats", headers=H)
    return r.status_code == 200
test("FAIL Stats", t_fail_stats)

# ============================================================
# PHASE 7: ANALYTICS
# ============================================================
section("PHASE 7: ANALYTICS")

def t_analytics_overview():
    r = requests.get(f"{API}/api/v1/analytics/dashboard/overview", headers=H)
    d = r.json()
    return r.status_code == 200 and "total_findings" in d
test("Analytics Dashboard Overview", t_analytics_overview)

def t_analytics_trends():
    r = requests.get(f"{API}/api/v1/analytics/dashboard/trends", headers=H)
    return r.status_code == 200
test("Analytics Trends", t_analytics_trends)

def t_analytics_compliance():
    r = requests.get(f"{API}/api/v1/analytics/dashboard/compliance-status", headers=H)
    return r.status_code == 200
test("Analytics Compliance Status", t_analytics_compliance)

def t_analytics_top_risks():
    r = requests.get(f"{API}/api/v1/analytics/dashboard/top-risks", headers=H)
    return r.status_code == 200
test("Analytics Top Risks", t_analytics_top_risks)

def t_analytics_mttr():
    r = requests.get(f"{API}/api/v1/analytics/mttr", headers=H)
    return r.status_code == 200
test("Analytics MTTR", t_analytics_mttr)

def t_analytics_noise():
    r = requests.get(f"{API}/api/v1/analytics/noise-reduction", headers=H)
    return r.status_code == 200
test("Analytics Noise Reduction", t_analytics_noise)

# ============================================================
# PHASE 8: COMPLIANCE
# ============================================================
section("PHASE 8: COMPLIANCE")

def t_compliance_frameworks():
    r = requests.get(f"{API}/api/v1/compliance-engine/frameworks", headers=H)
    d = r.json()
    fws = d.get("frameworks", [])
    return r.status_code == 200 and len(fws) > 0
test("List Compliance Frameworks", t_compliance_frameworks)

def t_compliance_assess_soc2():
    r = requests.post(f"{API}/api/v1/compliance-engine/assess", headers=HJ, json={"framework": "SOC2"})
    d = r.json()
    return r.status_code == 200 and "total_controls" in d
test("Assess SOC2 Compliance", t_compliance_assess_soc2)

def t_compliance_assess_pci():
    r = requests.post(f"{API}/api/v1/compliance-engine/assess", headers=HJ, json={"framework": "PCI_DSS_4.0"})
    d = r.json()
    return r.status_code == 200 and "total_controls" in d
test("Assess PCI-DSS 4.0 Compliance", t_compliance_assess_pci)

def t_compliance_gaps():
    r = requests.get(f"{API}/api/v1/compliance-engine/gaps", headers=H)
    return r.status_code == 200
test("Compliance Gaps Analysis", t_compliance_gaps)

def t_compliance_soc2_status():
    r = requests.get(f"{API}/api/v1/compliance-engine/soc2/status", headers=H)
    return r.status_code == 200
test("SOC2 Status Dashboard", t_compliance_soc2_status)

def t_compliance_hipaa():
    r = requests.get(f"{API}/api/v1/compliance-engine/hipaa/status", headers=H)
    return r.status_code == 200
test("HIPAA Status Dashboard", t_compliance_hipaa)

def t_compliance_pci():
    r = requests.get(f"{API}/api/v1/compliance-engine/pci-dss/status", headers=H)
    return r.status_code == 200
test("PCI-DSS Status Dashboard", t_compliance_pci)

# ============================================================
# PHASE 9: REMEDIATION
# ============================================================
section("PHASE 9: REMEDIATION")

def t_remediation_tasks():
    r = requests.get(f"{API}/api/v1/remediation/tasks", headers=H)
    d = r.json()
    tasks = d.get("tasks", [])
    return r.status_code == 200 and len(tasks) > 0
test("List Remediation Tasks", t_remediation_tasks)

def t_remediation_metrics():
    r = requests.get(f"{API}/api/v1/remediation/metrics", headers=H)
    return r.status_code == 200
test("Remediation Metrics", t_remediation_metrics)

def t_remediation_backlog():
    r = requests.get(f"{API}/api/v1/remediation/backlog", headers=H)
    return r.status_code == 200
test("Remediation Backlog", t_remediation_backlog)

def t_remediation_sla():
    r = requests.post(f"{API}/api/v1/remediation/sla/check", headers=HJ, params={"org_id": "default"})
    return r.status_code == 200
test("SLA Check", t_remediation_sla)

# ============================================================
# PHASE 10: AUTOFIX
# ============================================================
section("PHASE 10: AUTOFIX")

def t_autofix_generate():
    r = requests.post(f"{API}/api/v1/autofix/generate", headers=HJ, json={
        "finding_id": "test-e2e-001",
        "finding_type": "sql_injection",
        "language": "python",
        "code_context": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"
    })
    return r.status_code == 200
test("AutoFix Generate Fix", t_autofix_generate)

def t_autofix_stats():
    r = requests.get(f"{API}/api/v1/autofix/stats", headers=H)
    return r.status_code == 200
test("AutoFix Stats", t_autofix_stats)

def t_autofix_confidence():
    r = requests.get(f"{API}/api/v1/autofix/confidence-levels", headers=H)
    d = r.json()
    return r.status_code == 200 and "levels" in d
test("AutoFix Confidence Levels", t_autofix_confidence)

def t_autofix_fix_types():
    r = requests.get(f"{API}/api/v1/autofix/fix-types", headers=H)
    d = r.json()
    return r.status_code == 200 and "fix_types" in d
test("AutoFix Fix Types", t_autofix_fix_types)

# ============================================================
# PHASE 11: SELF-LEARNING
# ============================================================
section("PHASE 11: SELF-LEARNING")

def t_sl_stats():
    r = requests.get(f"{API}/api/v1/self-learning/stats", headers=H)
    d = r.json()
    return r.status_code == 200 and d.get("total_feedback_records", 0) > 0
test("Self-Learning Stats", t_sl_stats)

def t_sl_weights():
    r = requests.get(f"{API}/api/v1/self-learning/weights", headers=H)
    return r.status_code == 200
test("Self-Learning Weights", t_sl_weights)

def t_sl_feedback():
    r = requests.post(f"{API}/api/v1/self-learning/feedback/decision", headers=HJ, json={
        "decision_id": "dec-e2e-001",
        "finding_id": "test-e2e-001",
        "predicted_action": "fix",
        "actual_outcome": "resolved",
        "was_correct": True,
        "confidence": 0.9
    })
    return r.status_code == 200
test("Submit Decision Feedback", t_sl_feedback)

def t_sl_fp_feedback():
    r = requests.post(f"{API}/api/v1/self-learning/feedback/false-positive", headers=HJ, json={
        "finding_id": "test-fp-001",
        "rule_id": "SAST-002",
        "scanner": "semgrep",
        "is_false_positive": True,
        "reason": "Test code, not production"
    })
    return r.status_code == 200
test("Submit False Positive Feedback", t_sl_fp_feedback)

# ============================================================
# PHASE 12: COPILOT
# ============================================================
section("PHASE 12: AI COPILOT")

def t_copilot_ask():
    r = requests.post(f"{API}/api/v1/copilot/ask", headers=HJ, json={
        "question": "What are my top critical vulnerabilities?"
    })
    return r.status_code == 200
test("Copilot Ask Question", t_copilot_ask)

def t_copilot_suggestions():
    r = requests.get(f"{API}/api/v1/copilot/suggestions", headers=H)
    return r.status_code == 200
test("Copilot Suggestions", t_copilot_suggestions)

def t_copilot_sessions():
    r = requests.get(f"{API}/api/v1/copilot/sessions", headers=H)
    return r.status_code == 200
test("Copilot Sessions", t_copilot_sessions)

# ============================================================
# PHASE 13: INVENTORY
# ============================================================
section("PHASE 13: INVENTORY")

def t_inventory_assets():
    r = requests.get(f"{API}/api/v1/inventory/assets", headers=H)
    r.json()
    return r.status_code == 200
test("List Inventory Assets", t_inventory_assets)

def t_inventory_apps():
    r = requests.get(f"{API}/api/v1/inventory/applications", headers=H)
    return r.status_code == 200
test("List Applications", t_inventory_apps)

def t_inventory_services():
    r = requests.get(f"{API}/api/v1/inventory/services", headers=H)
    return r.status_code == 200
test("List Services", t_inventory_services)

# ============================================================
# PHASE 14: ATTACK SIMULATION / MPTE
# ============================================================
section("PHASE 14: ATTACK SIMULATION / MPTE")

def t_attack_campaigns():
    r = requests.get(f"{API}/api/v1/attack-sim/campaigns", headers=H)
    return r.status_code == 200
test("List Attack Campaigns", t_attack_campaigns)

def t_mitre_heatmap():
    r = requests.get(f"{API}/api/v1/attack-sim/mitre/heatmap", headers=H)
    d = r.json()
    return r.status_code == 200 and "heatmap" in d
test("MITRE ATT&CK Heatmap", t_mitre_heatmap)

def t_mitre_techniques():
    r = requests.get(f"{API}/api/v1/attack-sim/mitre/techniques", headers=H)
    d = r.json()
    return r.status_code == 200 and d.get("total", 0) > 0
test("MITRE Techniques Library", t_mitre_techniques)

def t_mpte_verify():
    r = requests.post(f"{API}/api/v1/mpte/verify", headers=HJ, json={
        "finding_id": "CVE-2021-44228-log4j",
        "target_url": "http://internal.app:8080",
        "vulnerability_type": "remote_code_execution",
        "cve_id": "CVE-2021-44228",
        "evidence": "Log4j JNDI lookup exploitation"
    })
    d = r.json()
    return r.status_code in (200, 201) and (d.get("status") == "pending" or d.get("id"))
test("MPTE Exploit Verification", t_mpte_verify)

def t_mpte_stats():
    r = requests.get(f"{API}/api/v1/mpte/stats", headers=H)
    return r.status_code == 200
test("MPTE Stats", t_mpte_stats)

# ============================================================
# PHASE 15: FEEDS (Vulnerability Intelligence)
# ============================================================
section("PHASE 15: VULNERABILITY INTELLIGENCE FEEDS")

def t_feeds_status():
    r = requests.get(f"{API}/api/v1/feeds/status", headers=H)
    return r.status_code == 200
test("Feeds Status", t_feeds_status)

def t_feeds_nvd():
    r = requests.get(f"{API}/api/v1/feeds/nvd/recent", headers=H)
    return r.status_code == 200
test("NVD Recent Feed", t_feeds_nvd)

def t_feeds_mitre():
    r = requests.get(f"{API}/api/v1/feeds/mitre/techniques", headers=H)
    return r.status_code == 200
test("MITRE Techniques Feed", t_feeds_mitre)

def t_feeds_epss():
    r = requests.get(f"{API}/api/v1/feeds/epss/scores", headers=H)
    return r.status_code == 200
test("EPSS Scores Feed", t_feeds_epss)

# ============================================================
# PHASE 16: POLICIES & WORKFLOWS
# ============================================================
section("PHASE 16: POLICIES & WORKFLOWS")

def t_policies_list():
    r = requests.get(f"{API}/api/v1/policies", headers=H)
    return r.status_code == 200
test("List Policies", t_policies_list)

def t_workflows_list():
    r = requests.get(f"{API}/api/v1/workflows", headers=H)
    return r.status_code == 200
test("List Workflows", t_workflows_list)

# ============================================================
# PHASE 17: NERVE CENTER
# ============================================================
section("PHASE 17: NERVE CENTER")

def t_nerve_pulse():
    r = requests.get(f"{API}/api/v1/nerve-center/pulse", headers=H)
    return r.status_code == 200
test("Nerve Center Pulse", t_nerve_pulse)

def t_nerve_state():
    r = requests.get(f"{API}/api/v1/nerve-center/state", headers=H)
    return r.status_code == 200
test("Nerve Center State", t_nerve_state)

def t_nerve_playbooks():
    r = requests.get(f"{API}/api/v1/nerve-center/playbooks", headers=H)
    d = r.json()
    return r.status_code == 200 and len(d.get("playbooks", [])) > 0
test("Nerve Center Playbooks", t_nerve_playbooks)

def t_nerve_intel_map():
    r = requests.get(f"{API}/api/v1/nerve-center/intelligence-map", headers=H)
    return r.status_code == 200
test("Intelligence Map", t_nerve_intel_map)

# ============================================================
# PHASE 18: ML / PREDICTIONS
# ============================================================
section("PHASE 18: ML & PREDICTIONS")

def t_ml_status():
    r = requests.get(f"{API}/api/v1/ml/status", headers=H)
    d = r.json()
    return r.status_code == 200 and "models" in d
test("ML Status", t_ml_status)

def t_ml_models():
    r = requests.get(f"{API}/api/v1/ml/models", headers=H)
    d = r.json()
    return r.status_code == 200 and len(d.get("models", [])) > 0
test("ML Models List", t_ml_models)

def t_predictions_risk():
    r = requests.post(f"{API}/api/v1/predictions/risk-trajectory", headers=HJ, json={
        "asset_id": "web-frontend",
        "timeframe_days": 30
    })
    return r.status_code == 200
test("Risk Trajectory Prediction", t_predictions_risk)

# ============================================================
# PHASE 19: EVIDENCE & AUDIT
# ============================================================
section("PHASE 19: EVIDENCE & AUDIT")

def t_evidence_status():
    r = requests.get(f"{API}/api/v1/evidence/status", headers=H)
    return r.status_code == 200
test("Evidence Status", t_evidence_status)

def t_audit_logs():
    r = requests.get(f"{API}/api/v1/audit/logs", headers=H)
    return r.status_code == 200
test("Audit Logs", t_audit_logs)

def t_audit_frameworks():
    r = requests.get(f"{API}/api/v1/audit/compliance/frameworks", headers=H)
    return r.status_code == 200
test("Audit Compliance Frameworks", t_audit_frameworks)

# ============================================================
# PHASE 20: CONNECTORS & INTEGRATIONS
# ============================================================
section("PHASE 20: CONNECTORS & INTEGRATIONS")

def t_connectors_list():
    r = requests.get(f"{API}/api/v1/connectors", headers=H)
    return r.status_code == 200
test("List Connectors", t_connectors_list)

def t_connectors_types():
    r = requests.get(f"{API}/api/v1/connectors/types", headers=H)
    r.json()
    return r.status_code == 200
test("Connector Types", t_connectors_types)

def t_mcp_tools():
    r = requests.get(f"{API}/api/v1/mcp/tools", headers=H)
    return r.status_code == 200
test("MCP Tools Catalog", t_mcp_tools)

# ============================================================
# PHASE 21: SECURITY AUTH & ENTERPRISE
# ============================================================
section("PHASE 21: SECURITY & AUTH")

def t_auth_reject_bad_key():
    # Health may not require auth; test a protected endpoint instead
    r = requests.get(f"{API}/api/v1/brain/stats", headers={"X-API-Key": "bad-key"})
    return r.status_code == 401
test("Reject Invalid API Key", t_auth_reject_bad_key)

def t_auth_no_key():
    r = requests.get(f"{API}/api/v1/brain/stats")
    return r.status_code == 401
test("Reject Missing API Key", t_auth_no_key)

def t_user_login():
    r = requests.post(f"{API}/api/v1/users/login", headers=HJ, json={
        "email": "admin@fixops.io",
        "password": "admin123"
    })
    return r.status_code in (200, 401, 404)  # Just checking it doesn't 500
test("User Login Endpoint Functional", t_user_login)

# ============================================================
# SUMMARY
# ============================================================
section("RESULTS")
pct = (passed / total * 100) if total > 0 else 0
print(f"\n  Passed: {passed}/{total} ({pct:.1f}%)")
print(f"  Failed: {failed}/{total}")

if pct >= 90:
    print(f"\n  🟢 ENTERPRISE READY — {pct:.1f}% pass rate")
elif pct >= 75:
    print(f"\n  🟡 NEAR READY — {pct:.1f}% pass rate, needs fixes")
else:
    print(f"\n  🔴 NOT READY — {pct:.1f}% pass rate")

if __name__ == "__main__":
    sys.exit(0 if pct >= 85 else 1)
