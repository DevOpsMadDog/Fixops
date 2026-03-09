"""Seed realistic DoD-grade demo data for ALdeci RFP demo."""
import requests
import json
import time
import sys

BASE = "http://localhost:8000"
HEADERS = {
    "X-API-Key": "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U",
    "Content-Type": "application/json"
}

def api(method, path, data=None, silent=False):
    url = f"{BASE}{path}"
    try:
        if method == "POST":
            r = requests.post(url, headers=HEADERS, json=data, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=HEADERS, json=data, timeout=10)
        else:
            r = requests.get(url, headers=HEADERS, timeout=10)
        if not silent:
            status = "✅" if r.status_code < 400 else "❌"
            print(f"  {status} {method} {path} → {r.status_code}")
        return r.json() if r.status_code < 400 else None
    except Exception as e:
        if not silent:
            print(f"  ⚠️ {method} {path} → {e}")
        return None

print("═══════════════════════════════════════")
print(" ALdeci DoD Demo Data Seeding")
print("═══════════════════════════════════════\n")

# ── 1. Register DoD Applications ──
print("📋 Registering DoD Applications...")
DOD_APPS = [
    {"name": "JADC2-Gateway", "app_id": "dod-jadc2-gw", "description": "Joint All-Domain Command & Control API Gateway", "criticality": "critical", "data_classification": "SECRET", "owner": "jadc2-team@dod.mil", "environment": "production"},
    {"name": "DCGS-Analytics", "app_id": "dod-dcgs-analytics", "description": "Distributed Common Ground System - Analytics Engine", "criticality": "critical", "data_classification": "TOP_SECRET", "owner": "dcgs-team@dod.mil", "environment": "production"},
    {"name": "ATAK-Server", "app_id": "dod-atak-srv", "description": "Android Team Awareness Kit Server Backend", "criticality": "high", "data_classification": "SECRET", "owner": "atak-team@dod.mil", "environment": "production"},
    {"name": "LogiSTICS-Core", "app_id": "dod-logistics", "description": "Defense Logistics Information Service - Core Platform", "criticality": "high", "data_classification": "CUI", "owner": "logistics@dod.mil", "environment": "production"},
    {"name": "MilCloud-IAM", "app_id": "dod-milcloud-iam", "description": "MilCloud Identity & Access Management Service", "criticality": "critical", "data_classification": "SECRET", "owner": "identity-team@dod.mil", "environment": "production"},
    {"name": "SIPR-Mesh", "app_id": "dod-sipr-mesh", "description": "SIPRNet Service Mesh & mTLS Gateway", "criticality": "critical", "data_classification": "SECRET", "owner": "network-team@dod.mil", "environment": "production"},
    {"name": "DevSecOps-Pipeline", "app_id": "dod-pipeline", "description": "DoD Enterprise DevSecOps Pipeline (Iron Bank)", "criticality": "high", "data_classification": "CUI", "owner": "devsecops@dod.mil", "environment": "production"},
    {"name": "Cyber-SIEM", "app_id": "dod-cyber-siem", "description": "Cybersecurity SIEM & Threat Hunting Platform", "criticality": "high", "data_classification": "SECRET", "owner": "cyber-ops@dod.mil", "environment": "production"},
]

for app in DOD_APPS:
    api("POST", "/api/v1/apps/", app)

# ── 2. Ingest Findings via Brain Pipeline ──
print("\n🧠 Ingesting Findings into Knowledge Graph...")
FINDINGS = [
    {"finding_id": "CVE-2024-3094", "title": "xz-utils backdoor (liblzma)", "severity": "critical", "cve_id": "CVE-2024-3094", "cwe_id": "CWE-506", "scanner": "trivy", "app_id": "dod-jadc2-gw", "file_path": "Dockerfile", "description": "Backdoor in xz-utils 5.6.0/5.6.1 allows unauthorized SSH access", "status": "open", "epss_score": 0.97},
    {"finding_id": "CVE-2024-21626", "title": "runc container escape", "severity": "critical", "cve_id": "CVE-2024-21626", "cwe_id": "CWE-269", "scanner": "grype", "app_id": "dod-dcgs-analytics", "file_path": "k8s/deployment.yaml", "description": "Container escape via runc file descriptor leak", "status": "open", "epss_score": 0.94},
    {"finding_id": "CVE-2023-44487", "title": "HTTP/2 Rapid Reset DDoS", "severity": "critical", "cve_id": "CVE-2023-44487", "cwe_id": "CWE-400", "scanner": "snyk", "app_id": "dod-sipr-mesh", "file_path": "go.mod", "description": "HTTP/2 rapid reset attack causes denial of service", "status": "triaged", "epss_score": 0.96},
    {"finding_id": "CVE-2024-27983", "title": "Node.js HTTP/2 crash", "severity": "high", "cve_id": "CVE-2024-27983", "cwe_id": "CWE-400", "scanner": "semgrep", "app_id": "dod-atak-srv", "file_path": "server/index.js", "description": "HTTP/2 CONTINUATION frames cause Node.js OOM crash", "status": "open", "epss_score": 0.72},
    {"finding_id": "SAST-001", "title": "SQL Injection in query builder", "severity": "critical", "cve_id": None, "cwe_id": "CWE-89", "scanner": "semgrep", "app_id": "dod-logistics", "file_path": "src/db/query.py", "description": "User input concatenated directly into SQL query without parameterization", "status": "open", "epss_score": 0.89},
    {"finding_id": "SECRET-001", "title": "AWS Secret Key in config", "severity": "critical", "cve_id": None, "cwe_id": "CWE-798", "scanner": "gitleaks", "app_id": "dod-pipeline", "file_path": ".env.production", "description": "AWS_SECRET_ACCESS_KEY exposed in production environment file", "status": "open", "epss_score": 0.85},
    {"finding_id": "CVE-2024-29018", "title": "Docker DNS spoofing", "severity": "high", "cve_id": "CVE-2024-29018", "cwe_id": "CWE-346", "scanner": "trivy", "app_id": "dod-milcloud-iam", "file_path": "docker-compose.yml", "description": "Docker internal DNS spoofing via DHCP", "status": "triaged", "epss_score": 0.58},
    {"finding_id": "IAC-001", "title": "S3 bucket public access", "severity": "critical", "cve_id": None, "cwe_id": "CWE-284", "scanner": "checkov", "app_id": "dod-dcgs-analytics", "file_path": "terraform/s3.tf", "description": "S3 bucket allows public read access - potential data exfiltration", "status": "open", "epss_score": 0.91},
    {"finding_id": "CVE-2024-0567", "title": "GnuTLS cert verification bypass", "severity": "high", "cve_id": "CVE-2024-0567", "cwe_id": "CWE-295", "scanner": "grype", "app_id": "dod-cyber-siem", "file_path": "requirements.txt", "description": "Certificate verification bypass in GnuTLS", "status": "open", "epss_score": 0.61},
    {"finding_id": "CVE-2024-1086", "title": "Linux kernel nf_tables LPE", "severity": "critical", "cve_id": "CVE-2024-1086", "cwe_id": "CWE-416", "scanner": "trivy", "app_id": "dod-jadc2-gw", "file_path": "k8s/node-pool.yaml", "description": "Linux kernel use-after-free in nf_tables allows local privilege escalation to root", "status": "open", "epss_score": 0.95},
]

for f in FINDINGS:
    api("POST", "/api/v1/brain/ingest/finding", f)

# ── 3. Ingest Assets ──
print("\n📦 Ingesting Assets...")
ASSETS = [
    {"name": "jadc2-api-pod", "type": "container", "app_id": "dod-jadc2-gw", "environment": "production", "tags": ["kubernetes", "secret", "c2"]},
    {"name": "dcgs-spark-cluster", "type": "compute", "app_id": "dod-dcgs-analytics", "environment": "production", "tags": ["spark", "top-secret", "analytics"]},
    {"name": "atak-redis-cache", "type": "database", "app_id": "dod-atak-srv", "environment": "production", "tags": ["redis", "geospatial", "secret"]},
    {"name": "milcloud-keycloak", "type": "service", "app_id": "dod-milcloud-iam", "environment": "production", "tags": ["iam", "cac", "piv", "secret"]},
    {"name": "sipr-envoy-proxy", "type": "container", "app_id": "dod-sipr-mesh", "environment": "production", "tags": ["envoy", "mtls", "siprnet"]},
    {"name": "ironbank-registry", "type": "container", "app_id": "dod-pipeline", "environment": "production", "tags": ["registry", "hardened", "disa-stig"]},
]

for a in ASSETS:
    api("POST", "/api/v1/brain/ingest/asset", a)

# ── 4. Ingest CVE enrichment data ──
print("\n🔍 Enriching CVEs...")
CVES = [
    {"cve_id": "CVE-2024-3094", "cvss_score": 10.0, "epss_score": 0.97, "kev_status": True, "description": "Backdoor in xz-utils", "published": "2024-03-29"},
    {"cve_id": "CVE-2024-21626", "cvss_score": 8.6, "epss_score": 0.94, "kev_status": True, "description": "runc container escape", "published": "2024-01-31"},
    {"cve_id": "CVE-2023-44487", "cvss_score": 7.5, "epss_score": 0.96, "kev_status": True, "description": "HTTP/2 Rapid Reset", "published": "2023-10-10"},
    {"cve_id": "CVE-2024-1086", "cvss_score": 7.8, "epss_score": 0.95, "kev_status": True, "description": "Linux kernel nf_tables LPE", "published": "2024-01-31"},
]

for c in CVES:
    api("POST", "/api/v1/brain/ingest/cve", c)

# ── 5. Create Workflows ──
print("\n⚡ Creating Workflows...")
WORKFLOWS = [
    {"name": "Critical CVE Auto-Triage", "description": "Automatically triage critical CVEs with EPSS > 0.9 and KEV status", "trigger": "new_finding", "conditions": {"severity": "critical", "epss_score_gt": 0.9}, "actions": ["triage", "assign", "notify"], "enabled": True},
    {"name": "Secret Detection Escalation", "description": "Immediately escalate and block pipeline on secret detection", "trigger": "new_finding", "conditions": {"scanner": "gitleaks", "severity": "critical"}, "actions": ["block_pipeline", "notify_security", "create_ticket"], "enabled": True},
    {"name": "MPTE Verification Loop", "description": "Auto-run MPTE on all high/critical findings after initial triage", "trigger": "triage_complete", "conditions": {"severity_in": ["critical", "high"]}, "actions": ["run_mpte", "update_finding"], "enabled": True},
    {"name": "Auto-Fix & PR", "description": "Generate AI fix and create PR for findings with known remediation", "trigger": "mpte_verified", "conditions": {"exploitable": True, "fix_available": True}, "actions": ["generate_fix", "create_pr", "notify_owner"], "enabled": True},
    {"name": "Evidence Auto-Generation", "description": "Generate compliance evidence bundle on remediation completion", "trigger": "remediation_complete", "conditions": {"compliance_relevant": True}, "actions": ["generate_evidence", "sign_bundle"], "enabled": True},
    {"name": "SLA Breach Alert", "description": "Alert when finding age exceeds SLA threshold for its severity", "trigger": "sla_check", "conditions": {"sla_breached": True}, "actions": ["escalate", "notify_management"], "enabled": True},
]

for w in WORKFLOWS:
    api("POST", "/api/v1/workflows", w)

# ── 6. Create FAIL Drills ──
print("\n🔥 Creating FAIL Engine Scenarios...")
SCENARIOS = [
    {"name": "Zero-Day Response Drill", "description": "Simulate zero-day CVE disclosure and measure team response time", "category": "incident_response", "severity": "critical", "inject_type": "vulnerability", "target_app": "dod-jadc2-gw"},
    {"name": "Container Escape Simulation", "description": "Simulate container breakout and lateral movement detection", "category": "detection", "severity": "critical", "inject_type": "attack", "target_app": "dod-dcgs-analytics"},
    {"name": "Secret Leak Detection Test", "description": "Test secret detection pipeline with planted credentials", "category": "detection", "severity": "high", "inject_type": "secret", "target_app": "dod-pipeline"},
    {"name": "Supply Chain Attack Drill", "description": "Simulate compromised dependency injection into build pipeline", "category": "supply_chain", "severity": "critical", "inject_type": "dependency", "target_app": "dod-pipeline"},
]

for s in SCENARIOS:
    api("POST", "/api/v1/fail/scenarios", s)

# ── 7. Inject FAIL drills ──
print("\n💉 Injecting FAIL Drills...")
DRILLS = [
    {"scenario": "Zero-Day Response", "org_id": "default", "inject_type": "vulnerability", "target": "dod-jadc2-gw", "cve_id": "CVE-2024-3094", "severity": "critical"},
    {"scenario": "Container Escape", "org_id": "default", "inject_type": "attack", "target": "dod-dcgs-analytics", "severity": "critical"},
]

for d in DRILLS:
    api("POST", "/api/v1/fail/inject", d)

# ── 8. Run Brain Pipeline ──
print("\n🧠 Running Brain Pipeline...")
api("POST", "/api/v1/brain/pipeline/run", {"source": "demo-seed", "scan_all": True})

# ── 9. Generate Evidence ──
print("\n📜 Generating Evidence Bundles...")
api("POST", "/api/v1/brain/evidence/generate", {
    "framework": "NIST-800-53",
    "scope": "all",
    "include_mpte": True,
    "include_remediation": True,
    "sign": True
})

# ── 10. Seed Self-Learning feedback ──
print("\n🔄 Seeding Self-Learning Feedback...")
FEEDBACK = [
    {"type": "decision", "finding_id": "CVE-2024-3094", "original_action": "triage", "corrected_action": "fix", "reason": "Known exploited in the wild"},
    {"type": "false_positive", "finding_id": "IAC-001", "is_false_positive": False, "reason": "Confirmed public S3 bucket"},
    {"type": "remediation", "finding_id": "CVE-2024-21626", "fix_success": True, "time_to_fix_hours": 4.2},
]

for fb in FEEDBACK:
    fb_type = fb.pop("type")
    api("POST", f"/api/v1/self-learning/feedback/{fb_type}", fb)

# ── 11. Seed Remediation Tasks ──
print("\n🔧 Creating Remediation Tasks...")
REMEDIATIONS = [
    {"finding_id": "CVE-2024-3094", "title": "Upgrade xz-utils to 5.6.2+", "status": "in_progress", "assigned_to": "j.smith@dod.mil", "priority": "critical", "app_id": "dod-jadc2-gw"},
    {"finding_id": "CVE-2024-21626", "title": "Upgrade runc to 1.1.12+", "status": "pending", "assigned_to": "k.jones@dod.mil", "priority": "critical", "app_id": "dod-dcgs-analytics"},
    {"finding_id": "SECRET-001", "title": "Rotate AWS credentials & remove from git", "status": "completed", "assigned_to": "s.kumar@dod.mil", "priority": "critical", "app_id": "dod-pipeline"},
    {"finding_id": "SAST-001", "title": "Use parameterized queries", "status": "in_progress", "assigned_to": "m.chen@dod.mil", "priority": "critical", "app_id": "dod-logistics"},
]

for rem in REMEDIATIONS:
    api("POST", "/api/v1/brain/ingest/remediation", rem)

# ── 12. Run MPTE on key targets ──
print("\n🎯 Running MPTE Scans...")
MPTE_TARGETS = [
    {"target_url": "https://jadc2-gateway.mil.dod.gov", "scan_type": "full", "vulnerability_type": "web_application"},
    {"target_url": "https://milcloud-iam.dod.mil", "scan_type": "full", "vulnerability_type": "authentication"},
]

for target in MPTE_TARGETS:
    api("POST", "/api/v1/mpte/scan", target)

print("\n═══════════════════════════════════════")
print(" ✅ Demo data seeding complete!")
print("═══════════════════════════════════════")
