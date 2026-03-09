"""Seed realistic DoD-grade demo data — v2 with correct API schemas."""
import requests
import json
import uuid
import time

BASE = "http://localhost:8000"
HEADERS = {
    "X-API-Key": "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U",
    "Content-Type": "application/json"
}

def api(method, path, data=None):
    url = f"{BASE}{path}"
    try:
        r = requests.request(method, url, headers=HEADERS, json=data, timeout=10)
        status = "✅" if r.status_code < 400 else "❌"
        print(f"  {status} {method} {path} → {r.status_code}")
        return r.json() if r.status_code < 400 else None
    except Exception as e:
        print(f"  ⚠️ {method} {path} → {e}")
        return None

print("═══════════════════════════════════════")
print(" ALdeci DoD Demo Data Seeding v2")
print("═══════════════════════════════════════\n")

# ── 1. Register Apps via YAML format ──
print("📋 Registering DoD Applications...")
APPS_YAML = [
    {"yaml_content": "app_id: dod-jadc2-gw\nname: JADC2-Gateway\ndescription: Joint All-Domain Command & Control API Gateway\ncriticality: mission_critical\ndata_classification: SECRET\nowner: jadc2-team@dod.mil\ncomponents:\n  - name: api-gateway\n    language: go\n    repo_url: https://code.mil/jadc2/gateway"},
    {"yaml_content": "app_id: dod-dcgs-analytics\nname: DCGS-Analytics\ndescription: Distributed Common Ground System Analytics Engine\ncriticality: mission_critical\ndata_classification: TOP_SECRET\nowner: dcgs-team@dod.mil\ncomponents:\n  - name: spark-engine\n    language: python\n    repo_url: https://code.mil/dcgs/analytics"},
    {"yaml_content": "app_id: dod-atak-srv\nname: ATAK-Server\ndescription: Android Team Awareness Kit Server Backend\ncriticality: high\ndata_classification: SECRET\nowner: atak-team@dod.mil"},
    {"yaml_content": "app_id: dod-logistics\nname: LogiSTICS-Core\ndescription: Defense Logistics Platform\ncriticality: high\ndata_classification: CUI\nowner: logistics@dod.mil"},
    {"yaml_content": "app_id: dod-milcloud-iam\nname: MilCloud-IAM\ndescription: MilCloud Identity & Access Management\ncriticality: mission_critical\ndata_classification: SECRET\nowner: identity-team@dod.mil"},
    {"yaml_content": "app_id: dod-sipr-mesh\nname: SIPR-Mesh\ndescription: SIPRNet Service Mesh & mTLS Gateway\ncriticality: mission_critical\ndata_classification: SECRET\nowner: network-team@dod.mil"},
    {"yaml_content": "app_id: dod-pipeline\nname: DevSecOps-Pipeline\ndescription: DoD Enterprise DevSecOps Pipeline (Iron Bank)\ncriticality: high\ndata_classification: CUI\nowner: devsecops@dod.mil"},
    {"yaml_content": "app_id: dod-cyber-siem\nname: Cyber-SIEM\ndescription: Cybersecurity SIEM & Threat Hunting Platform\ncriticality: high\ndata_classification: SECRET\nowner: cyber-ops@dod.mil"},
]

for app in APPS_YAML:
    api("POST", "/api/v1/apps/", app)

# ── 2. Ingest Assets with correct schema ──
print("\n📦 Ingesting Assets...")
ASSETS = [
    {"asset_id": "jadc2-api-pod", "name": "JADC2 API Pod", "asset_type": "container", "metadata": {"app_id": "dod-jadc2-gw", "environment": "production", "classification": "SECRET"}},
    {"asset_id": "dcgs-spark-cluster", "name": "DCGS Spark Cluster", "asset_type": "compute", "metadata": {"app_id": "dod-dcgs-analytics", "environment": "production", "classification": "TOP_SECRET"}},
    {"asset_id": "atak-redis", "name": "ATAK Redis Cache", "asset_type": "database", "metadata": {"app_id": "dod-atak-srv", "environment": "production", "classification": "SECRET"}},
    {"asset_id": "milcloud-keycloak", "name": "MilCloud Keycloak", "asset_type": "service", "metadata": {"app_id": "dod-milcloud-iam", "environment": "production", "classification": "SECRET"}},
    {"asset_id": "sipr-envoy", "name": "SIPR Envoy Proxy", "asset_type": "container", "metadata": {"app_id": "dod-sipr-mesh", "environment": "production", "classification": "SECRET"}},
    {"asset_id": "ironbank-registry", "name": "Iron Bank Container Registry", "asset_type": "container", "metadata": {"app_id": "dod-pipeline", "environment": "production", "classification": "CUI"}},
]

for a in ASSETS:
    api("POST", "/api/v1/brain/ingest/asset", a)

# ── 3. FAIL scenarios with correct schema ──
print("\n🔥 Creating FAIL Engine Scenarios...")
SCENARIOS = [
    {"scenario_id": "fail-zeroday-01", "name": "Zero-Day Response Drill", "description": "Simulate zero-day CVE disclosure and measure team response time", "category": "incident_response", "severity": "critical", "cve_pattern": "CVE-2024-*", "inject_type": "vulnerability"},
    {"scenario_id": "fail-escape-01", "name": "Container Escape Simulation", "description": "Simulate container breakout and lateral movement detection", "category": "detection", "severity": "critical", "cve_pattern": "CVE-2024-21626", "inject_type": "attack"},
    {"scenario_id": "fail-secret-01", "name": "Secret Leak Detection Test", "description": "Test secret detection pipeline with planted credentials", "category": "detection", "severity": "high", "cve_pattern": "CWE-798", "inject_type": "secret"},
    {"scenario_id": "fail-supply-01", "name": "Supply Chain Attack Drill", "description": "Simulate compromised dependency injection", "category": "supply_chain", "severity": "critical", "cve_pattern": "CVE-2024-3094", "inject_type": "dependency"},
]

for s in SCENARIOS:
    api("POST", "/api/v1/fail/scenarios", s)

# ── 4. FAIL injection with correct schema ──
print("\n💉 Injecting FAIL Drills...")
DRILLS = [
    {"target_component": "dod-jadc2-gw", "org_id": "default", "scenario": "fail-zeroday-01", "cve_id": "CVE-2024-3094", "severity": "critical"},
    {"target_component": "dod-dcgs-analytics", "org_id": "default", "scenario": "fail-escape-01", "cve_id": "CVE-2024-21626", "severity": "critical"},
]

for d in DRILLS:
    api("POST", "/api/v1/fail/inject", d)

# ── 5. Brain pipeline run ──
print("\n🧠 Running Brain Pipeline...")
api("POST", "/api/v1/brain/pipeline/run", {"org_id": "default", "source": "demo-seed", "scan_all": True})

# ── 6. Evidence generation ──
print("\n📜 Generating Evidence...")
api("POST", "/api/v1/brain/evidence/generate", {
    "org_id": "default",
    "framework": "NIST-800-53",
    "scope": "all",
    "include_mpte": True,
    "sign": True
})

# ── 7. Self-learning feedback ──
print("\n🔄 Seeding Self-Learning Feedback...")
api("POST", "/api/v1/self-learning/feedback/decision", {
    "decision_id": str(uuid.uuid4()),
    "finding_id": "CVE-2024-3094",
    "predicted_action": "triage",
    "actual_outcome": "fix_immediately",
    "was_correct": False,
    "notes": "Known exploited CVE, should be immediate fix"
})
api("POST", "/api/v1/self-learning/feedback/false-positive", {
    "finding_id": "IAC-001",
    "scanner": "checkov",
    "is_false_positive": False,
    "notes": "Confirmed public S3 bucket with sensitive data"
})
api("POST", "/api/v1/self-learning/feedback/remediation", {
    "finding_id": "CVE-2024-21626",
    "remediation_id": str(uuid.uuid4()),
    "fix_type": "dependency_upgrade",
    "was_successful": True,
    "time_to_fix_hours": 4.2,
    "notes": "Upgraded runc to 1.1.12"
})

# ── 8. Remediation ingest ──
print("\n🔧 Ingesting Remediations...")
REMS = [
    {"finding_id": "CVE-2024-3094", "action": "upgrade", "status": "in_progress", "details": "Upgrading xz-utils to 5.6.2+", "assigned_to": "j.smith@dod.mil"},
    {"finding_id": "CVE-2024-21626", "action": "upgrade", "status": "completed", "details": "Upgraded runc to 1.1.12", "assigned_to": "k.jones@dod.mil"},
    {"finding_id": "SECRET-001", "action": "rotate", "status": "completed", "details": "Rotated AWS credentials and removed from git history", "assigned_to": "s.kumar@dod.mil"},
    {"finding_id": "SAST-001", "action": "code_fix", "status": "in_progress", "details": "Replacing string concatenation with parameterized queries", "assigned_to": "m.chen@dod.mil"},
]

for r in REMS:
    api("POST", "/api/v1/brain/ingest/remediation", r)

# ── 9. MPTE scan via correct endpoint ──
print("\n🎯 Running MPTE Scans...")
api("POST", "/api/v1/mpte/requests", {
    "target_url": "https://jadc2-gateway.mil.dod.gov",
    "scan_type": "comprehensive",
    "vulnerability_type": "web_application",
    "priority": "high"
})
api("POST", "/api/v1/mpte/requests", {
    "target_url": "https://milcloud-iam.dod.mil",
    "scan_type": "comprehensive",
    "vulnerability_type": "authentication",
    "priority": "high"
})
# Run real scan too
api("POST", "/api/v1/mpte/scan/comprehensive", {
    "target_url": "https://jadc2-gateway.mil.dod.gov",
    "scan_types": ["web", "ssl", "headers", "dns"]
})

print("\n═══════════════════════════════════════")
print(" ✅ Demo data seeding v2 complete!")
print("═══════════════════════════════════════")
