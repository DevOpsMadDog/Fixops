#!/usr/bin/env python3
"""
seed_attack_sim.py — Populate FixOps Attack Simulation system with realistic scenarios.

Creates 6 attack simulation scenarios covering major threat vectors and runs
full campaigns for each. Scenarios are based on real-world attack patterns
aligned with MITRE ATT&CK and OWASP Top 10.

Usage:
    python3 seed_attack_sim.py
    FIXOPS_API_TOKEN=$YOUR_KEY python3 seed_attack_sim.py --base-url http://localhost:8000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_URL = "http://localhost:8000"
API_KEY = os.environ.get("FIXOPS_API_TOKEN")
if not API_KEY:
    sys.exit("FIXOPS_API_TOKEN environment variable required")
HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _request(method: str, path: str, body: Optional[Dict] = None) -> Any:
    """Send an authenticated HTTP request and return parsed JSON."""
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {method} {path}: {detail}") from e


def get(path: str) -> Any:
    return _request("GET", path)


def post(path: str, body: Dict) -> Any:
    return _request("POST", path, body)


# ---------------------------------------------------------------------------
# Scenario definitions
# ---------------------------------------------------------------------------

SCENARIOS: List[Dict] = [
    {
        "name": "OWASP Top 10 Web Attack Campaign",
        "description": (
            "Comprehensive simulation of OWASP Top 10 attack categories against a "
            "modern web application stack. Covers injection, broken authentication, "
            "XSS, IDOR, security misconfiguration, vulnerable components, and SSRF. "
            "Threat actor simulates a financially-motivated cybercriminal with moderate "
            "to high technical capability targeting customer data and payment systems."
        ),
        "threat_actor": "cybercriminal",
        "complexity": "high",
        "target_assets": [
            "web-app-prod",
            "api-gateway",
            "auth-service",
            "payment-processor",
            "customer-db",
        ],
        "target_cves": [
            "CVE-2021-44228",   # Log4Shell
            "CVE-2022-22965",   # Spring4Shell
            "CVE-2023-44487",   # HTTP/2 Rapid Reset
        ],
        "objectives": [
            "exploit_injection_vulnerabilities",
            "bypass_authentication",
            "exfiltrate_customer_pii",
            "compromise_payment_data",
            "establish_persistence",
        ],
        "initial_access_vector": "T1190",   # Exploit Public-Facing Application
    },
    {
        "name": "Software Supply Chain Attack",
        "description": (
            "Nation-state adversary simulating a SolarWinds/XZ Utils style supply chain "
            "compromise. Threat actor targets the CI/CD pipeline and third-party "
            "dependencies to inject malicious code into production builds. Focus on "
            "long-term persistence, credential harvesting, and covert data exfiltration "
            "while evading EDR and SIEM detection."
        ),
        "threat_actor": "nation_state",
        "complexity": "critical",
        "target_assets": [
            "ci-cd-pipeline",
            "build-server",
            "artifact-registry",
            "source-code-repo",
            "npm-package-registry",
            "production-deployment",
        ],
        "target_cves": [
            "CVE-2020-10148",   # SolarWinds authentication bypass
            "CVE-2021-35247",   # SolarWinds Serv-U
            "CVE-2024-3094",    # XZ Utils backdoor
        ],
        "objectives": [
            "inject_malicious_dependency",
            "compromise_build_pipeline",
            "establish_backdoor_in_production",
            "harvest_credentials_at_scale",
            "maintain_persistent_access",
            "avoid_detection_for_90_days",
        ],
        "initial_access_vector": "T1195",   # Supply Chain Compromise
    },
    {
        "name": "Lateral Movement and Domain Compromise",
        "description": (
            "APT simulation modeling an adversary who has established initial foothold "
            "via phishing and is now pivoting through the internal network to reach "
            "domain controllers and high-value systems. Employs Pass-the-Hash, "
            "Kerberoasting, Golden Ticket attacks, and RDP lateral movement to "
            "enumerate and compromise Active Directory and achieve full domain dominance."
        ),
        "threat_actor": "apt",
        "complexity": "critical",
        "target_assets": [
            "workstation-initial-beachhead",
            "domain-controller-primary",
            "domain-controller-secondary",
            "file-server-finance",
            "backup-server",
            "vpn-concentrator",
        ],
        "target_cves": [
            "CVE-2021-42278",   # SAM Name impersonation
            "CVE-2021-42287",   # Kerberos PAC spoofing (NoPac)
            "CVE-2020-1472",    # Zerologon
            "CVE-2022-26923",   # AD domain privilege escalation
        ],
        "objectives": [
            "pivot_from_workstation_to_server",
            "kerberoast_service_accounts",
            "dump_ntds_dit",
            "forge_golden_ticket",
            "achieve_domain_admin",
            "exfiltrate_intellectual_property",
        ],
        "initial_access_vector": "T1566",   # Phishing
    },
    {
        "name": "API Security Breach — Broken Object Level Authorization",
        "description": (
            "Targeted attack against a REST API with BOLA/IDOR vulnerabilities "
            "(OWASP API Top 1). Cybercriminal enumerates object IDs to access "
            "unauthorized user records, escalates via JWT algorithm confusion, "
            "and exploits GraphQL introspection and batch query abuse to extract "
            "the entire user database. Includes mass account takeover via "
            "credential stuffing at the authentication endpoint."
        ),
        "threat_actor": "cybercriminal",
        "complexity": "high",
        "target_assets": [
            "api-v2-public",
            "graphql-endpoint",
            "user-profile-service",
            "jwt-auth-service",
            "rate-limiter",
            "user-database",
        ],
        "target_cves": [
            "CVE-2023-29007",   # JWT algorithm confusion
            "CVE-2022-41082",   # ProxyNotShell API abuse
        ],
        "objectives": [
            "enumerate_bola_idor_vulnerabilities",
            "bypass_jwt_validation",
            "abuse_graphql_introspection",
            "mass_account_takeover",
            "exfiltrate_user_pii_database",
        ],
        "initial_access_vector": "T1190",   # Exploit Public-Facing Application
    },
    {
        "name": "Cloud Misconfiguration Exploitation — AWS S3 and IAM",
        "description": (
            "Simulation of a cloud security breach exploiting common AWS "
            "misconfigurations: publicly exposed S3 buckets, overly permissive IAM "
            "roles, exposed instance metadata service (IMDS v1), and insecure "
            "security group rules. Threat actor escalates from S3 data discovery "
            "to full AWS account compromise via IAM privilege escalation and "
            "CloudTrail log tampering to cover tracks."
        ),
        "threat_actor": "cybercriminal",
        "complexity": "high",
        "target_assets": [
            "s3-bucket-prod-data",
            "iam-role-ec2-production",
            "ec2-instance-webserver",
            "rds-postgres-prod",
            "cloudtrail-logging",
            "secrets-manager",
        ],
        "target_cves": [
            "CVE-2019-3980",    # AWS metadata service exposure
            "CVE-2023-0466",    # OpenSSL cert validation
        ],
        "objectives": [
            "discover_exposed_s3_buckets",
            "exploit_imds_v1_ssrf",
            "escalate_iam_privileges",
            "exfiltrate_secrets_from_secrets_manager",
            "tamper_cloudtrail_logs",
            "pivot_to_rds_database",
        ],
        "initial_access_vector": "T1078",   # Valid Accounts (via stolen cloud credentials)
    },
    {
        "name": "Insider Threat — Privileged User Data Exfiltration",
        "description": (
            "Simulation of a malicious insider (disgruntled system administrator) "
            "with legitimate elevated access who systematically exfiltrates sensitive "
            "intellectual property and customer data over 30 days while evading "
            "DLP controls. Models staged data collection, compression, "
            "obfuscated exfiltration channels (DNS tunneling, cloud storage), "
            "and cover-up actions including log deletion and audit trail tampering."
        ),
        "threat_actor": "insider_threat",
        "complexity": "high",
        "target_assets": [
            "intellectual-property-repo",
            "customer-data-warehouse",
            "hr-records-system",
            "financial-systems",
            "email-archive",
            "backup-infrastructure",
        ],
        "target_cves": [],   # Insider uses legitimate access — no CVEs required
        "objectives": [
            "enumerate_accessible_sensitive_data",
            "compress_and_stage_exfiltration_data",
            "bypass_dlp_controls",
            "exfiltrate_via_dns_tunneling",
            "delete_audit_logs",
            "cover_tracks_and_maintain_deniability",
        ],
        "initial_access_vector": "T1078",   # Valid Accounts
    },
]

# ---------------------------------------------------------------------------
# Main seeding logic
# ---------------------------------------------------------------------------


def seed_scenarios_and_campaigns() -> Dict[str, Any]:
    """
    Create all scenarios and run campaigns for each. Returns a summary dict.
    """
    results = {
        "scenarios_created": [],
        "campaigns_run": [],
        "errors": [],
    }

    print("=" * 65)
    print("FixOps Attack Simulation — Seeding Script")
    print("=" * 65)

    # ---- Step 1: Verify health ----
    print("\n[1/3] Checking attack simulation engine health...")
    try:
        health = get("/api/v1/attack-sim/health")
        print(f"  Engine: {health['engine']}")
        print(f"  MITRE techniques: {health['mitre_techniques']}")
        print(f"  Kill chain phases: {health['kill_chain_phases']}")
        print(f"  Existing scenarios: {health['scenarios_count']}")
        print(f"  Existing campaigns: {health['campaigns_count']}")
        print("  Status: HEALTHY ✓")
    except Exception as e:
        print(f"  ERROR: {e}")
        results["errors"].append(f"health_check: {e}")
        return results

    # ---- Step 2: Create scenarios ----
    print(f"\n[2/3] Creating {len(SCENARIOS)} attack scenarios...")
    for idx, scenario_def in enumerate(SCENARIOS, 1):
        name = scenario_def["name"]
        print(f"\n  [{idx}/{len(SCENARIOS)}] {name}")
        try:
            resp = post("/api/v1/attack-sim/scenarios", scenario_def)
            scenario_id = resp["scenario_id"]
            threat_actor = resp["threat_actor"]
            complexity = resp["complexity"]
            phases = len(resp["kill_chain_phases"])
            print(f"    ID:           {scenario_id}")
            print(f"    Threat actor: {threat_actor}")
            print(f"    Complexity:   {complexity}")
            print(f"    Kill chain:   {phases} phases")
            print(f"    Assets:       {len(resp['target_assets'])} targets")
            print(f"    Objectives:   {len(resp['objectives'])} objectives")
            results["scenarios_created"].append({
                "scenario_id": scenario_id,
                "name": name,
                "threat_actor": threat_actor,
                "complexity": complexity,
                "kill_chain_phases": resp["kill_chain_phases"],
                "target_assets": resp["target_assets"],
                "objectives": resp["objectives"],
                "created_at": resp["created_at"],
            })
        except Exception as e:
            print(f"    FAILED: {e}")
            results["errors"].append(f"create_scenario '{name}': {e}")

    # ---- Step 3: Run campaigns ----
    print(f"\n[3/3] Running campaigns for {len(results['scenarios_created'])} scenarios...")
    print("      (Campaigns run asynchronously in background threads)")

    for scenario in results["scenarios_created"]:
        sid = scenario["scenario_id"]
        name = scenario["name"]
        print(f"\n  Running campaign: {name}")
        print(f"    Scenario ID: {sid}")
        try:
            run_resp = post("/api/v1/attack-sim/campaigns/run", {
                "scenario_id": sid,
                "org_id": "aldeci-fixops-seed",
            })
            cid = run_resp.get("campaign_id", "unknown")
            status = run_resp.get("status", "unknown")
            print(f"    Campaign ID: {cid}")
            print(f"    Status:      {status}")
            results["campaigns_run"].append({
                "campaign_id": cid,
                "scenario_id": sid,
                "scenario_name": name,
                "status": status,
                "message": run_resp.get("message", ""),
            })
        except Exception as e:
            print(f"    FAILED: {e}")
            results["errors"].append(f"run_campaign for '{name}': {e}")

    # ---- Wait for campaigns to complete ----
    print("\n  Waiting 20s for background campaigns to complete...")
    time.sleep(20)

    # ---- Verify final state ----
    print("\n" + "=" * 65)
    print("VERIFICATION")
    print("=" * 65)

    try:
        scenarios_list = get("/api/v1/attack-sim/scenarios")
        print(f"\nScenarios in system:  {len(scenarios_list)}")
        for s in scenarios_list:
            print(f"  - [{s['scenario_id']}] {s['name']} ({s['complexity']})")
    except Exception as e:
        print(f"  Could not list scenarios: {e}")

    try:
        campaigns_list = get("/api/v1/attack-sim/campaigns")
        print(f"\nCampaigns in system:  {len(campaigns_list)}")
        for c in campaigns_list:
            risk = c.get("risk_score", 0)
            steps_exec = c.get("steps_executed", 0)
            steps_ok = c.get("steps_succeeded", 0)
            print(
                f"  - [{c['campaign_id'][:20]}...] "
                f"{c.get('scenario_name', 'n/a')[:45]:<45} "
                f"status={c['status']:<10} "
                f"risk={risk:.2f} "
                f"steps={steps_ok}/{steps_exec}"
            )
        results["final_campaigns"] = campaigns_list
    except Exception as e:
        print(f"  Could not list campaigns: {e}")
        results["errors"].append(f"list_campaigns: {e}")

    try:
        heatmap = get("/api/v1/attack-sim/mitre/heatmap")
        coverage = heatmap.get("heatmap", {})
        total_campaigns = heatmap.get("total_campaigns", 0)
        print(f"\nMITRE ATT&CK Heatmap ({total_campaigns} total campaigns):")
        for phase, techniques in sorted(coverage.items()):
            print(f"  {phase:<25} {len(techniques)} techniques: {', '.join(techniques[:4])}{'...' if len(techniques) > 4 else ''}")
        results["mitre_heatmap"] = coverage
    except Exception as e:
        print(f"  Could not get MITRE heatmap: {e}")

    # ---- Summary ----
    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print(f"  Scenarios created:  {len(results['scenarios_created'])}/{len(SCENARIOS)}")
    print(f"  Campaigns started:  {len(results['campaigns_run'])}")
    completed = sum(1 for c in results.get("final_campaigns", []) if c["status"] == "completed")
    total = len(results.get("final_campaigns", []))
    print(f"  Campaigns finished: {completed}/{total}")
    if results["errors"]:
        print(f"  Errors:             {len(results['errors'])}")
        for err in results["errors"]:
            print(f"    - {err}")
    else:
        print("  Errors:             0")

    success = len(results["scenarios_created"]) > 0 and len(results["campaigns_run"]) > 0
    print(f"\n  Overall result: {'SUCCESS' if success else 'PARTIAL FAILURE'}")
    print("=" * 65)

    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed FixOps attack simulation data")
    parser.add_argument("--base-url", default=BASE_URL, help="API base URL")
    parser.add_argument("--api-key", default=API_KEY, help="API key")
    args = parser.parse_args()

    BASE_URL = args.base_url
    API_KEY = args.api_key
    HEADERS["X-API-Key"] = API_KEY

    results = seed_scenarios_and_campaigns()
    sys.exit(0 if not results["errors"] or results["scenarios_created"] else 1)
