#!/usr/bin/env python3
"""
Seed realistic enterprise data into the top 50 most-used API endpoints.
Run: python3 scripts/seed_top50_endpoints.py
"""
import json
import sys
import time
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

BASE = "http://localhost:8000"
TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
ORG = "default"

ok = 0
skipped = 0
failed = 0


def req(method: str, path: str, body: Optional[Dict] = None, quiet: bool = False) -> Optional[Dict]:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"X-API-Key": TOKEN, "Content-Type": "application/json"}
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            result = json.loads(resp.read())
            if not quiet:
                pass
            return result
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:200]
        if not quiet:
            print(f"  WARN {method} {path} -> {e.code}: {body_text}")
        return None
    except Exception as e:
        if not quiet:
            print(f"  ERR {method} {path} -> {e}")
        return None


def post(path: str, body: Dict, quiet: bool = False) -> Optional[Dict]:
    global ok, failed
    result = req("POST", path, body, quiet)
    if result is not None:
        ok += 1
    else:
        failed += 1
    return result


def get_count(path: str) -> str:
    result = req("GET", f"{path}?org_id={ORG}", quiet=True)
    if result is None:
        return "err"
    if isinstance(result, list):
        return str(len(result))
    if isinstance(result, dict):
        for k, v in result.items():
            if isinstance(v, list):
                return f"{k}:{len(v)}"
        return "dict"
    return str(result)


def section(name: str):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")


# ============================================================
# 1. POSTURE ADVISOR — generate recommendations
# ============================================================
section("1. Posture Advisor")
post(f"/api/v1/posture-advisor/analyze", {
    "posture_score": 62.5,
    "open_critical_vulns": 14,
    "avg_patch_time_days": 18.3,
    "mfa_coverage_pct": 74.0,
    "avg_mttd_hours": 36.5,
    "unencrypted_databases": 3,
    "wildcard_permissions_count": 47,
    "sla_compliance_pct": 81.0,
    "org_id": ORG,
})
post(f"/api/v1/posture-advisor/analyze", {
    "posture_score": 71.0,
    "open_critical_vulns": 8,
    "avg_patch_time_days": 12.0,
    "mfa_coverage_pct": 88.0,
    "avg_mttd_hours": 24.0,
    "unencrypted_databases": 1,
    "wildcard_permissions_count": 22,
    "sla_compliance_pct": 91.0,
    "org_id": ORG,
})
print(f"  -> posture-advisor/stats: {get_count('/api/v1/posture-advisor/stats')}")

# ============================================================
# 2. KPI TRACKER — record KPIs
# ============================================================
section("2. KPI Tracker (/api/v1/kpi)")
kpis = [
    ("mttd", 4.2, "hours"),
    ("mttr", 18.7, "hours"),
    ("mean_time_to_contain", 6.1, "hours"),
    ("patch_compliance_rate", 87.3, "percentage"),
    ("vulnerability_backlog", 142, "count"),
    ("critical_open_vulns", 14, "count"),
    ("mfa_coverage", 74.0, "percentage"),
    ("security_training_completion", 89.5, "percentage"),
    ("phishing_click_rate", 3.2, "percentage"),
    ("sla_compliance", 91.0, "percentage"),
]
for kpi_name, value, period in kpis:
    post(f"/api/v1/kpi/record", {
        "kpi_name": kpi_name,
        "value": value,
        "org_id": ORG,
        "period": "monthly",
    })
post(f"/api/v1/kpi/snapshot", {"org_id": ORG})
print(f"  -> kpi/current: {get_count('/api/v1/kpi/current')}")

# ============================================================
# 3. RISK QUANTIFICATION (v2 / FAIR)
# ============================================================
section("3. Risk Quantification v2 (/api/v1/risk-quant)")
scenarios = [
    ("Ransomware Attack - Core Infrastructure", "core-infra-001", "Eastern European cybercriminal group", "ransomware", 8500000, 0.6, 0.8),
    ("Supply Chain Compromise", "scm-dev-002", "Nation-state APT group", "supply_chain", 12000000, 0.4, 0.3),
    ("Insider Data Exfiltration", "hr-db-003", "Malicious insider", "insider", 2500000, 0.3, 1.2),
    ("Phishing-based Credential Theft", "ad-domain-004", "Cybercriminal syndicate", "phishing", 1800000, 0.7, 3.0),
    ("DDoS on Public Services", "cdn-web-005", "Hacktivist collective", "ddos", 500000, 0.5, 6.0),
]
scenario_ids = []
for name, asset, actor, threat_type, asset_val, exp_factor, aro in scenarios:
    r = post(f"/api/v1/risk-quant/scenarios?org_id={ORG}", {
        "scenario_name": name,
        "asset_name": asset,
        "threat_actor": actor,
        "threat_type": threat_type,
        "asset_value": asset_val,
        "exposure_factor": exp_factor,
        "annual_rate_occurrence": aro,
    })
    if r:
        scenario_ids.append(r.get("scenario_id", ""))

for sid in scenario_ids[:3]:
    if sid:
        post(f"/api/v1/risk-quant/scenarios/{sid}/controls?org_id={ORG}", {
            "control_name": "Multi-Factor Authentication",
            "control_type": "preventive",
            "implementation_cost": 25000,
            "annual_cost": 8000,
            "effectiveness_pct": 75.0,
        })
print(f"  -> risk-quant/scenarios: {get_count('/api/v1/risk-quant/scenarios')}")

# ============================================================
# 4. AI SECURITY ADVISOR — generate recommendations
# ============================================================
section("4. AI Security Advisor (/api/v1/ai-advisor)")
post(f"/api/v1/ai-advisor/posture-review?org_id={ORG}", {
    "context": {
        "risk_score": 67.5,
        "critical_findings": 14,
        "top_vulnerabilities": ["CVE-2024-3400", "CVE-2024-21762", "CVE-2023-46805"],
        "compliance_status": {"SOC2": "partial", "PCI-DSS": "non-compliant", "ISO27001": "compliant"},
        "mfa_coverage": 74,
        "patch_lag_days": 18,
        "unencrypted_dbs": 3,
    }
})
post(f"/api/v1/ai-advisor/posture-review?org_id={ORG}", {
    "context": {
        "risk_score": 54.0,
        "critical_findings": 22,
        "top_vulnerabilities": ["CVE-2024-27198", "CVE-2024-1709"],
        "compliance_status": {"HIPAA": "partial", "GDPR": "compliant"},
        "exposed_apis": 8,
        "shadow_it_apps": 34,
    }
})
print(f"  -> ai-advisor/recommendations: {get_count('/api/v1/ai-advisor/recommendations')}")

# ============================================================
# 5. VULN PRIORITIZATION — score vulnerabilities
# ============================================================
section("5. Vulnerability Prioritization (/api/v1/vuln-prioritization)")
vulns = [
    ("CVE-2024-3400", "paloalto-fw-01", "critical", 10.0, 0.97, True, "network_exploitable", "internet_facing"),
    ("CVE-2024-21762", "fortigate-02", "critical", 9.8, 0.95, True, "network_exploitable", "internet_facing"),
    ("CVE-2023-46805", "ivanti-vpn-03", "critical", 8.2, 0.91, True, "authenticated", "internet_facing"),
    ("CVE-2024-1709", "screenconnect-04", "critical", 10.0, 0.93, True, "unauthenticated", "internet_facing"),
    ("CVE-2024-27198", "jetbrains-tc-05", "critical", 9.8, 0.88, False, "authenticated", "internal"),
    ("CVE-2024-0204", "goanywhere-06", "critical", 9.8, 0.85, True, "unauthenticated", "internal"),
    ("CVE-2023-48788", "fortisiem-07", "high", 9.8, 0.72, False, "network_exploitable", "internal"),
    ("CVE-2024-20353", "cisco-asa-08", "high", 8.6, 0.68, False, "network_exploitable", "internet_facing"),
]
for cve, asset, crit, cvss, epss, kev, exploit, exposure in vulns:
    post(f"/api/v1/vuln-prioritization/score?org_id={ORG}", {
        "cve_id": cve,
        "asset_id": asset,
        "asset_criticality": crit,
        "cvss_score": cvss,
        "epss_score": epss,
        "kev_listed": kev,
        "exploitability": exploit,
        "exposure": exposure,
    })
print(f"  -> vuln-prioritization/scored: {get_count('/api/v1/vuln-prioritization/scored')}")

# ============================================================
# 6. VULN INTEL — advisories and CVEs
# ============================================================
section("6. Vulnerability Intelligence (/api/v1/vuln-intel)")
# Try both possible POST paths
cve_data = [
    {"cve_id": "CVE-2024-3400", "title": "PAN-OS Command Injection", "severity": "critical", "cvss_score": 10.0, "epss_score": 0.97, "kev_listed": True, "affected_products": ["PAN-OS 10.2", "PAN-OS 11.0"], "description": "Command injection in GlobalProtect Gateway"},
    {"cve_id": "CVE-2024-21762", "title": "Fortinet SSL-VPN RCE", "severity": "critical", "cvss_score": 9.8, "epss_score": 0.95, "kev_listed": True, "affected_products": ["FortiOS 7.4"], "description": "Out-of-bounds write vulnerability"},
    {"cve_id": "CVE-2023-46805", "title": "Ivanti Connect Secure Auth Bypass", "severity": "critical", "cvss_score": 8.2, "epss_score": 0.91, "kev_listed": True, "affected_products": ["ICS 9.x", "ICS 22.x"], "description": "Authentication bypass in web component"},
    {"cve_id": "CVE-2024-1709", "title": "ScreenConnect Auth Bypass", "severity": "critical", "cvss_score": 10.0, "epss_score": 0.93, "kev_listed": True, "affected_products": ["ScreenConnect 23.9.7"], "description": "Authentication bypass vulnerability"},
    {"cve_id": "CVE-2024-27198", "title": "JetBrains TeamCity RCE", "severity": "critical", "cvss_score": 9.8, "epss_score": 0.88, "kev_listed": False, "affected_products": ["TeamCity 2023.11.3"], "description": "Remote code execution via authentication bypass"},
]
for cve in cve_data:
    post(f"/api/v1/vuln-intel/cves?org_id={ORG}", cve, quiet=True)
    post(f"/api/v1/vuln-intel/advisories?org_id={ORG}", {
        "advisory_id": f"ADV-{cve['cve_id'].replace('CVE-', '')}",
        "title": cve["title"],
        "severity": cve["severity"],
        "affected_cves": [cve["cve_id"]],
        "vendor": "Multiple",
        "summary": cve["description"],
        "remediation": "Apply vendor patch immediately. Enable WAF rules as interim mitigation.",
    }, quiet=True)
print(f"  -> vuln-intel/advisories: {get_count('/api/v1/vuln-intel/advisories')}")

# ============================================================
# 7. SECURITY TRAINING EFFECTIVENESS
# ============================================================
section("7. Security Training Effectiveness (/api/v1/training-effectiveness)")
prog_ids = []
programs = [
    ("Phishing Awareness 2026", "phishing_simulation", "all", "online", 45, 80.0),
    ("Security Fundamentals", "awareness", "all", "online", 60, 75.0),
    ("Advanced Threat Detection", "technical", "security_team", "instructor_led", 480, 85.0),
    ("GDPR & Data Privacy", "compliance", "all", "online", 90, 70.0),
    ("Secure Coding Practices", "technical", "engineering", "online", 120, 82.0),
]
for name, ttype, audience, method, dur, passing in programs:
    r = post(f"/api/v1/training-effectiveness/programs?org_id={ORG}", {
        "program_name": name,
        "training_type": ttype,
        "target_audience": audience,
        "delivery_method": method,
        "duration_mins": dur,
        "passing_score": passing,
    })
    if r:
        prog_ids.append(r.get("program_id", ""))

employees = [
    ("EMP-001", "Engineering"), ("EMP-002", "Finance"), ("EMP-003", "HR"),
    ("EMP-004", "Sales"), ("EMP-005", "Security"), ("EMP-006", "Marketing"),
    ("EMP-007", "Legal"), ("EMP-008", "Operations"),
]
for pid in prog_ids[:2]:
    if pid:
        for emp_id, dept in employees:
            post(f"/api/v1/training-effectiveness/programs/{pid}/enroll?org_id={ORG}",
                 {"employee_id": emp_id, "department": dept}, quiet=True)
        for emp_id, _ in employees:
            post(f"/api/v1/training-effectiveness/programs/{pid}/complete?org_id={ORG}", {
                "employee_id": emp_id,
                "pre_score": 55.0 + (hash(emp_id) % 20),
                "post_score": 78.0 + (hash(emp_id) % 18),
                "time_spent_mins": 42,
            }, quiet=True)
print(f"  -> training-effectiveness/programs: {get_count('/api/v1/training-effectiveness/programs')}")

# ============================================================
# 8. TPRM EXCHANGE — vendors
# ============================================================
section("8. TPRM Exchange (/api/v1/tprm-exchange)")
vendor_data = [
    ("Salesforce Inc", "saas", "critical", ["customer_data", "employee_data"], "2025-01-01", "2026-12-31", 285000, "vendor@salesforce.com"),
    ("AWS", "iaas", "critical", ["all_data"], "2020-01-01", "2027-12-31", 1200000, "enterprise@aws.com"),
    ("Okta", "saas", "high", ["identity_data", "access_logs"], "2023-06-01", "2026-06-01", 95000, "support@okta.com"),
    ("Crowdstrike", "saas", "high", ["endpoint_telemetry", "threat_intel"], "2024-01-01", "2026-12-31", 340000, "cs@crowdstrike.com"),
    ("Palo Alto Networks", "hardware_vendor", "critical", ["network_traffic", "firewall_logs"], "2022-03-01", "2025-03-01", 420000, "enterprise@paloalto.com"),
    ("ServiceNow", "saas", "medium", ["it_tickets", "employee_data"], "2023-09-01", "2026-09-01", 180000, "support@servicenow.com"),
    ("Splunk", "saas", "high", ["log_data", "security_events"], "2023-01-01", "2026-01-01", 520000, "enterprise@splunk.com"),
]
vendor_ids = []
for name, cat, crit, data, cs, ce, spend, contact in vendor_data:
    r = post(f"/api/v1/tprm-exchange/vendors?org_id={ORG}", {
        "vendor_name": name,
        "vendor_category": cat,
        "criticality": crit,
        "data_shared": data,
        "contract_start": cs,
        "contract_end": ce,
        "annual_spend": spend,
        "primary_contact": contact,
    })
    if r:
        vendor_ids.append(r.get("vendor_id", ""))

for vid in vendor_ids[:4]:
    if vid:
        post(f"/api/v1/tprm-exchange/vendors/{vid}/assessments?org_id={ORG}", {
            "assessment_type": "annual",
            "assessor": "vendor-risk@company.com",
            "due_date": "2026-06-30",
        }, quiet=True)
print(f"  -> tprm-exchange/vendors: {get_count('/api/v1/tprm-exchange/vendors')}")

# ============================================================
# 9. THREAT INDICATORS (IOCs)
# ============================================================
section("9. Threat Indicators (/api/v1/threat-indicators)")
iocs = [
    ("185.220.101.47", "ip", "C2 infrastructure", 0.95, "critical", "red", ["apt29", "cozy-bear"]),
    ("malware-download.ru", "domain", "Malware distribution domain", 0.92, "critical", "red", ["malware-dist"]),
    ("d41d8cd98f00b204e9800998ecf8427e", "file_hash", "Known ransomware payload", 0.98, "critical", "red", ["ransomware", "lockbit"]),
    ("192.168.100.254", "ip", "Internal lateral movement pivot", 0.75, "high", "amber", ["lateral-movement"]),
    ("phishing-portal.xyz", "domain", "Active phishing campaign domain", 0.88, "high", "amber", ["phishing", "credential-theft"]),
    ("hxxps://evil-cdn.net/payload.exe", "url", "Malware delivery URL", 0.91, "critical", "red", ["dropper"]),
    ("45.33.32.156", "ip", "Shodan-identified scanning source", 0.65, "medium", "amber", ["scanning"]),
    ("cobalt-strike-beacon.dll SHA256:abc123", "file_hash", "Cobalt Strike beacon", 0.97, "critical", "red", ["cobalt-strike", "c2"]),
]
for val, itype, source, conf, sev, tlp, tags in iocs:
    post(f"/api/v1/threat-indicators/indicators?org_id={ORG}", {
        "indicator_value": val,
        "indicator_type": itype,
        "source": source,
        "confidence": conf,
        "severity": sev,
        "tlp": tlp,
        "tags": tags,
        "expiry_at": "2026-10-17T00:00:00Z",
    })
print(f"  -> threat-indicators/indicators: {get_count('/api/v1/threat-indicators/indicators')}")

# ============================================================
# 10. RANSOMWARE PROTECTION
# ============================================================
section("10. Ransomware Protection (/api/v1/ransomware-protection)")
detections = [
    ("LockBit 3.0 Variant", "behavioral", ["file_server_01", "backup_srv_02"], [".locked", ".lockbit", ".lk3"], 0.94, "critical"),
    ("BlackCat/ALPHV Activity", "signature", ["workstation-042", "dc-prod-01"], [".alphv", ".cat"], 0.87, "high"),
    ("Scattered Spider Social Eng", "behavioral", ["helpdesk-portal", "ad-srv-01"], [], 0.75, "high"),
]
for name, dtype, systems, exts, conf, sev in detections:
    post(f"/api/v1/ransomware-protection/detections", {
        "org_id": ORG,
        "detection_name": name,
        "detection_type": dtype,
        "affected_systems": systems,
        "file_extensions": exts,
        "confidence": conf,
        "severity": sev,
    })
# Add backup records
backups = [
    ("Core Business Data", "full", "s3://backup-prod-us-east-1", True, True, 90),
    ("AD/DNS Infrastructure", "incremental", "azure://backup-container", True, True, 365),
    ("Customer Database Replica", "full", "s3://backup-prod-us-west-2", True, True, 180),
    ("Email Archive", "differential", "azure://mail-backup", False, True, 90),
]
for system, btype, loc, immutable, encrypted, ret in backups:
    post(f"/api/v1/ransomware-protection/backups", {
        "org_id": ORG,
        "system_name": system,
        "backup_type": btype,
        "backup_location": loc,
        "immutable": immutable,
        "encrypted": encrypted,
        "retention_days": ret,
    })
print(f"  -> ransomware-protection/detections: {get_count('/api/v1/ransomware-protection/detections')}")

# ============================================================
# 11. PRIVACY IMPACT ASSESSMENTS
# ============================================================
section("11. Privacy Impact Assessment (/api/v1/privacy-impact)")
pias = [
    ("Customer Analytics Platform", "dpia", "ACME Corp", "DataProc Ltd", "legitimate_interest",
     ["behavioral_data", "purchase_history", "location"], ["customers", "prospects"], 730, True),
    ("Employee Monitoring System", "pia", "ACME Corp", "HR Systems Inc", "legitimate_interest",
     ["activity_logs", "email_metadata"], ["employees"], 365, False),
    ("Marketing Automation Tool", "pia", "ACME Corp", "MarketingCo", "consent",
     ["email", "name", "preferences"], ["customers", "leads"], 180, False),
    ("Payment Processing Upgrade", "dpia", "ACME Corp", "PaymentGW Ltd", "contract",
     ["financial_data", "card_data", "billing_address"], ["customers"], 2555, True),
]
pia_ids = []
for proj, atype, controller, processor, basis, cats, subjects, ret, cross in pias:
    r = post(f"/api/v1/privacy-impact/assessments?org_id={ORG}", {
        "project_name": proj,
        "assessment_type": atype,
        "data_controller": controller,
        "data_processor": processor,
        "legal_basis": basis,
        "data_categories": cats,
        "data_subjects": subjects,
        "retention_period_days": ret,
        "cross_border_transfer": cross,
    })
    if r:
        pia_ids.append(r.get("assessment_id", ""))

for pid in pia_ids[:3]:
    if pid:
        post(f"/api/v1/privacy-impact/assessments/{pid}/risks?org_id={ORG}", {
            "risk_category": "data_breach",
            "risk_description": "Unauthorized access to personal data via SQL injection",
            "likelihood": "medium",
            "impact": "high",
            "mitigation": "Implement parameterized queries, WAF, and database encryption",
            "residual_risk": "low",
        })
print(f"  -> privacy-impact/assessments: {get_count('/api/v1/privacy-impact/assessments')}")

# ============================================================
# 12. POSTURE TRENDS
# ============================================================
section("12. Posture Trends (/api/v1/posture-trends)")
metrics_trend = [
    ("overall_security_score", "vulnerability", 72.5, "score", "vulnerability_scanner"),
    ("patch_compliance", "vulnerability", 87.3, "percentage", "patch_manager"),
    ("mfa_adoption", "identity", 74.0, "percentage", "identity_provider"),
    ("cloud_security_posture", "cloud", 68.2, "score", "cspm_tool"),
    ("endpoint_protection", "endpoint", 91.5, "percentage", "edr_platform"),
    ("data_encryption", "data", 83.7, "percentage", "dlp_tool"),
    ("network_segmentation_score", "network", 65.4, "score", "network_scanner"),
    ("security_awareness_score", "awareness", 78.9, "percentage", "training_platform"),
]
for metric, cat, val, unit, source in metrics_trend:
    post(f"/api/v1/posture-trends/datapoints?org_id={ORG}", {
        "metric_name": metric,
        "metric_category": cat,
        "value": val,
        "unit": unit,
        "source": source,
    })
# Compute trends for each metric
for metric, _, _, _, _ in metrics_trend:
    post(f"/api/v1/posture-trends/analyze/{metric}?org_id={ORG}", {"period_days": 30})
print(f"  -> posture-trends: {get_count('/api/v1/posture-trends/trends')}")

# ============================================================
# 13. POSTURE HISTORY
# ============================================================
section("13. Posture History (/api/v1/posture-history)")
domains = [
    ("vulnerability_management", 72.5, 14, 3, 8),
    ("identity_access", 74.0, 8, 1, 4),
    ("network_security", 68.3, 11, 2, 5),
    ("cloud_security", 65.8, 18, 4, 7),
    ("endpoint_security", 91.2, 3, 0, 2),
    ("data_security", 78.4, 7, 1, 3),
    ("application_security", 69.1, 12, 2, 6),
    ("compliance", 84.6, 5, 0, 3),
]
for domain, score, findings, critical, high in domains:
    post(f"/api/v1/posture-history/snapshots?org_id={ORG}", {
        "domain": domain,
        "score": score,
        "findings_count": findings,
        "critical_count": critical,
        "high_count": high,
        "source": "automated_scan",
    })
    post(f"/api/v1/posture-history/trends/compute?org_id={ORG}", {
        "domain": domain,
        "period": "monthly",
    })
print(f"  -> posture-history/snapshots: {get_count('/api/v1/posture-history/snapshots')}")

# ============================================================
# 14. NETWORK THREATS
# ============================================================
section("14. Network Threats (/api/v1/network-threats)")
threats = [
    ("Port Scan - External", "reconnaissance", "203.0.113.42", "10.0.1.1", 22, "tcp", "medium", 0.78),
    ("Brute Force SSH", "brute_force", "198.51.100.17", "10.0.1.50", 22, "tcp", "high", 0.91),
    ("DNS Tunneling Detected", "exfiltration", "10.0.5.44", "8.8.8.8", 53, "udp", "high", 0.84),
    ("Lateral Movement SMB", "lateral_movement", "10.0.3.22", "10.0.1.100", 445, "tcp", "critical", 0.93),
    ("C2 Beacon Detected", "c2_communication", "10.0.2.88", "185.220.101.47", 443, "tcp", "critical", 0.96),
    ("SQL Injection Attempt", "web_attack", "45.33.32.156", "10.0.4.10", 443, "tcp", "high", 0.87),
    ("Unauthorized LDAP Query", "reconnaissance", "10.0.6.15", "10.0.1.5", 389, "tcp", "medium", 0.72),
]
for name, ttype, src, dst, port, proto, sev, conf in threats:
    post(f"/api/v1/network-threats/threats?org_id={ORG}", {
        "threat_name": name,
        "threat_type": ttype,
        "source_ip": src,
        "dest_ip": dst,
        "dest_port": port,
        "protocol": proto,
        "severity": sev,
        "confidence": conf,
    })
print(f"  -> network-threats/threats/active: {get_count('/api/v1/network-threats/threats/active')}")

# ============================================================
# 15. SECURITY OKRs
# ============================================================
section("15. Security OKRs (/api/v1/security-okrs)")
objectives = [
    ("Reduce Critical Vulnerability Exposure by 60%", "Eliminate all critical CVEs from internet-facing assets and reduce critical vuln backlog by 60%", "CISO", "Q2-2026", "2026-06-30"),
    ("Achieve 95% MFA Coverage Across All Systems", "Enforce MFA on all privileged and standard accounts enterprise-wide", "IAM Lead", "Q2-2026", "2026-06-30"),
    ("Attain SOC 2 Type II Certification", "Complete all controls implementation and undergo formal audit for SOC 2 Type II", "Compliance Lead", "Q3-2026", "2026-09-30"),
    ("Reduce Mean Time to Detect to Under 1 Hour", "Improve detection capabilities through SIEM tuning, threat hunting, and automation", "SOC Manager", "Q2-2026", "2026-06-30"),
    ("Zero Critical Cloud Misconfigurations", "Remediate all critical cloud misconfigurations and implement continuous compliance monitoring", "Cloud Security Lead", "Q2-2026", "2026-06-30"),
]
obj_ids = []
for title, desc, owner, period, due in objectives:
    r = post(f"/api/v1/security-okrs/objectives?org_id={ORG}", {
        "title": title,
        "description": desc,
        "owner": owner,
        "period": period,
        "due_date": due,
    })
    if r:
        obj_ids.append(r.get("objective_id", ""))

kr_data = [
    [("Close 100% of critical CVEs on internet-facing assets", 100, "percentage"),
     ("Reduce vuln backlog from 142 to 57 findings", 57, "count")],
    [("Enable MFA on all 847 privileged accounts", 847, "count"),
     ("Enforce MFA on all 3200 standard user accounts", 3200, "count")],
    [("Complete all 93 SOC 2 control implementations", 93, "count"),
     ("Pass external audit with zero major findings", 0, "count")],
    [("Tune SIEM rules to reduce false positive rate to under 5%", 5, "percentage"),
     ("Achieve MTTD of 60 minutes or less", 60, "minutes")],
]
for i, obj_id in enumerate(obj_ids[:4]):
    if obj_id and i < len(kr_data):
        for kr_title, target, unit in kr_data[i]:
            r = post(f"/api/v1/security-okrs/objectives/{obj_id}/key-results?org_id={ORG}", {
                "title": kr_title,
                "target_value": target,
                "unit": unit,
            }, quiet=True)
            if r:
                kr_id = r.get("key_result_id", "")
                if kr_id:
                    progress = target * (0.3 + (hash(kr_title) % 50) / 100)
                    post(f"/api/v1/security-okrs/key-results/{kr_id}/update?org_id={ORG}", {
                        "new_value": round(progress, 1),
                        "notes": "Automated progress update",
                        "updated_by": "security-automation",
                    }, quiet=True)
print(f"  -> security-okrs/objectives: {get_count('/api/v1/security-okrs/objectives')}")

# ============================================================
# 16. SECURITY FINDINGS
# ============================================================
section("16. Security Findings (/api/v1/security-findings)")
findings = [
    ("Critical S3 Bucket Publicly Accessible", "misconfiguration", "cloud_scanner", "critical", 9.1, "s3-prod-data-001", "s3_bucket", "Production data bucket has public read access enabled", "Disable public access block; apply bucket policy denying public GetObject"),
    ("Log4Shell Vulnerable Instance", "vulnerability", "vuln_scanner", "critical", 10.0, "app-server-prod-03", "ec2_instance", "Application server running Log4j 2.14.1 vulnerable to CVE-2021-44228", "Upgrade Log4j to 2.17.1 or later immediately"),
    ("Admin Account Without MFA", "configuration", "identity_scanner", "high", 8.5, "admin-account-007", "iam_user", "Privileged IAM account lacks multi-factor authentication", "Enable MFA on all accounts with admin privileges"),
    ("Unencrypted RDS Database", "misconfiguration", "cloud_scanner", "high", 7.8, "rds-customer-prod", "rds_instance", "Customer database RDS instance lacks encryption at rest", "Enable RDS encryption; create encrypted snapshot and restore"),
    ("Overprivileged Service Account", "misconfiguration", "iam_scanner", "high", 7.5, "svc-app-prod-01", "service_account", "Service account has wildcard S3 permissions far exceeding requirements", "Apply least privilege; scope permissions to required buckets only"),
    ("Expired SSL Certificate - API Gateway", "configuration", "cert_scanner", "high", 7.2, "api-gateway-prod", "api_gateway", "SSL certificate expired 3 days ago on production API gateway", "Renew certificate immediately; implement auto-renewal via ACM"),
    ("Default Credentials on Network Device", "misconfiguration", "network_scanner", "critical", 9.8, "switch-floor2-07", "network_switch", "Network switch using default vendor credentials", "Change default credentials; implement 802.1X authentication"),
    ("Unrestricted Outbound to Port 25", "network_misconfiguration", "network_scanner", "medium", 5.5, "sg-webapp-prod", "security_group", "Security group allows unrestricted outbound SMTP traffic", "Restrict outbound port 25 to authorized mail relay only"),
]
for title, ftype, tool, sev, cvss, asset_id, asset_type, desc, rem in findings:
    post(f"/api/v1/security-findings/findings", {
        "org_id": ORG,
        "title": title,
        "finding_type": ftype,
        "source_tool": tool,
        "severity": sev,
        "cvss_score": cvss,
        "asset_id": asset_id,
        "asset_type": asset_type,
        "description": desc,
        "remediation": rem,
    })
print(f"  -> security-findings/findings: {get_count('/api/v1/security-findings/findings')}")

# ============================================================
# 17. RISK SCENARIOS
# ============================================================
section("17. Risk Scenarios (/api/v1/risk-scenarios)")
scenarios = [
    ("Advanced Persistent Threat - Nation State", "nation_state_attack", "Nation-state actor targeting IP and trade secrets via spear-phishing and supply chain compromise", 0.35, 9.2, "CISO"),
    ("Ransomware Outbreak - Business Critical Systems", "ransomware", "Ransomware deployment via phishing affecting ERP, CRM and production systems", 0.45, 9.8, "IR Lead"),
    ("Insider Threat - Privileged Admin", "insider_threat", "Disgruntled sysadmin exfiltrating customer PII and sabotaging infrastructure", 0.20, 8.5, "Security Ops"),
    ("Cloud Misconfiguration Data Breach", "cloud_breach", "Exposed S3 bucket or misconfigured cloud service leaking customer data", 0.55, 7.8, "Cloud Security"),
    ("Third-Party Supply Chain Attack", "supply_chain", "Compromise via malicious update from trusted software vendor (SolarWinds-style)", 0.25, 9.5, "Third-Party Risk"),
    ("DDoS on Critical Services", "ddos", "Volumetric DDoS attack taking down e-commerce and customer portal for extended period", 0.60, 6.5, "Network Team"),
]
for name, cat, desc, like, impact, owner in scenarios:
    post(f"/api/v1/risk-scenarios/scenarios?org_id={ORG}", {
        "scenario_name": name,
        "threat_category": cat,
        "description": desc,
        "likelihood": like,
        "impact": impact,
        "owner": owner,
    })
print(f"  -> risk-scenarios/scenarios: {get_count('/api/v1/risk-scenarios/scenarios')}")

# ============================================================
# 18. SECURITY QUESTIONNAIRES
# ============================================================
section("18. Security Questionnaires (/api/v1/security-questionnaires)")
q_templates = [
    ("Vendor Security Assessment 2026", "vendor", "iso27001"),
    ("Cloud Provider Security Review", "cloud_vendor", "soc2"),
    ("Software Supply Chain Assessment", "vendor", "nist_csf"),
]
q_ids = []
for qname, qtype, framework in q_templates:
    r = post(f"/api/v1/security-questionnaires/questionnaires?org_id={ORG}", {
        "questionnaire_name": qname,
        "questionnaire_type": qtype,
        "framework": framework,
    })
    if r:
        q_ids.append(r.get("questionnaire_id", ""))

questions = [
    ("Does your organization have a documented Information Security Policy?", "governance", 2.0),
    ("Do you perform annual security risk assessments?", "risk_management", 1.5),
    ("Is multi-factor authentication enforced for all privileged access?", "access_control", 2.5),
    ("Do you maintain an incident response plan and test it annually?", "incident_response", 2.0),
    ("Is all customer data encrypted at rest and in transit?", "data_security", 2.5),
    ("Do you perform background checks on employees with data access?", "personnel_security", 1.5),
]
for qid in q_ids[:2]:
    if qid:
        for qtext, qcat, weight in questions:
            post(f"/api/v1/security-questionnaires/questionnaires/{qid}/questions?org_id={ORG}", {
                "question_text": qtext,
                "question_category": qcat,
                "weight": weight,
                "required": True,
            }, quiet=True)
print(f"  -> security-questionnaires: {get_count('/api/v1/security-questionnaires/questionnaires')}")

# ============================================================
# 19. SECURITY SCORECARD (engine)
# ============================================================
section("19. Security Scorecard Engine (/api/v1/security-scorecard)")
scorecards = [
    ("team", "soc-team-01", "Security Operations Center", "2026-Q2", [
        {"name": "detection_rate", "score": 87.5, "weight": 1.5},
        {"name": "response_time", "score": 72.3, "weight": 1.2},
        {"name": "false_positive_rate", "score": 91.0, "weight": 1.0},
    ]),
    ("team", "cloud-team-01", "Cloud Security Team", "2026-Q2", [
        {"name": "misconfiguration_rate", "score": 65.4, "weight": 1.5},
        {"name": "compliance_score", "score": 78.9, "weight": 1.2},
        {"name": "patch_velocity", "score": 82.1, "weight": 1.0},
    ]),
    ("vendor", "vendor-aws-01", "Amazon Web Services", "2026-Q2", [
        {"name": "sla_compliance", "score": 99.5, "weight": 1.0},
        {"name": "security_certifications", "score": 98.0, "weight": 1.5},
        {"name": "incident_response", "score": 95.0, "weight": 1.2},
    ]),
    ("project", "zerotrust-proj", "Zero Trust Initiative", "2026-Q2", [
        {"name": "completion_pct", "score": 45.0, "weight": 1.0},
        {"name": "risk_reduction", "score": 62.0, "weight": 1.5},
    ]),
    ("asset", "dc-prod-01", "Production Data Center", "2026-Q2", [
        {"name": "vulnerability_score", "score": 74.2, "weight": 1.5},
        {"name": "access_control", "score": 88.5, "weight": 1.2},
    ]),
]
for etype, eid, ename, period, dims in scorecards:
    post(f"/api/v1/security-scorecard/scorecards?org_id={ORG}", {
        "entity_type": etype,
        "entity_id": eid,
        "entity_name": ename,
        "period_label": period,
        "dimensions": dims,
    })
# Also generate domain scorecard
post(f"/api/v1/security-scorecard/scorecards/domain?org_id={ORG}", {
    "identity": 74.0,
    "endpoint": 91.2,
    "network": 68.3,
    "cloud": 65.8,
    "data": 78.4,
    "application": 69.1,
})
print(f"  -> security-scorecard/scorecards: {get_count('/api/v1/security-scorecard/scorecards')}")

# Also trigger the legacy scorecard generator
post(f"/api/v1/security-scorecard/default/generate", {"validity_days": 90}, quiet=True)
req("POST", f"/api/v1/security-scorecard/default/generate", {"validity_days": 90}, quiet=True)

# ============================================================
# 20. ATTACK PATHS
# ============================================================
section("20. Attack Paths (/api/v1/attack-paths)")
nodes = [
    ("ext-attacker", "external", "External Attacker", 90.0, False, []),
    ("web-dmz-01", "server", "Web Server DMZ", 65.0, False, ["CVE-2024-3400"]),
    ("app-server-01", "server", "Application Server", 72.0, False, ["CVE-2023-46805"]),
    ("db-prod-01", "database", "Production Database", 85.0, True, []),
    ("ad-dc-01", "server", "Active Directory DC", 88.0, True, ["CVE-2024-1709"]),
    ("workstation-042", "workstation", "Compromised Workstation", 60.0, False, ["CVE-2024-21762"]),
    ("backup-srv-01", "server", "Backup Server", 78.0, True, []),
    ("cloud-mgmt-01", "cloud_service", "Cloud Management Console", 80.0, True, []),
]
for nid, ntype, name, risk, crown, vulns in nodes:
    post(f"/api/v1/attack-paths/nodes", {
        "node_id": nid,
        "node_type": ntype,
        "name": name,
        "risk_score": risk,
        "is_crown_jewel": crown,
        "vulnerabilities": vulns,
        "org_id": ORG,
    })
edges = [
    ("ext-attacker", "web-dmz-01", "tcp", 443, None),
    ("web-dmz-01", "app-server-01", "tcp", 8080, "CVE-2024-3400"),
    ("app-server-01", "db-prod-01", "tcp", 5432, None),
    ("app-server-01", "ad-dc-01", "tcp", 389, "CVE-2023-46805"),
    ("workstation-042", "ad-dc-01", "tcp", 445, "CVE-2024-21762"),
    ("ad-dc-01", "backup-srv-01", "tcp", 445, None),
    ("ad-dc-01", "cloud-mgmt-01", "tcp", 443, None),
]
for src, dst, proto, port, vuln in edges:
    post(f"/api/v1/attack-paths/edges", {
        "from_node": src,
        "to_node": dst,
        "protocol": proto,
        "port": port,
        "requires_vuln": vuln,
        "org_id": ORG,
    })
print(f"  -> attack-paths/nodes: {get_count('/api/v1/attack-paths/nodes')}")

# ============================================================
# 21. CLOUD SECURITY FINDINGS
# ============================================================
section("21. Cloud Security Findings (/api/v1/cloud-findings)")
cloud_findings = [
    ("aws", "123456789012", "us-east-1", "s3", "s3://prod-customer-data", "Public S3 Bucket Exposed", "misconfiguration", "critical", 9.5, "Remove public access; apply deny-public policy"),
    ("aws", "123456789012", "us-east-1", "ec2", "i-0abc12345def67890", "IMDSv2 Not Enforced", "misconfiguration", "high", 7.5, "Enforce IMDSv2 on all EC2 instances via instance metadata options"),
    ("aws", "123456789012", "us-west-2", "rds", "db-prod-postgres-01", "RDS Encryption Disabled", "misconfiguration", "high", 8.0, "Enable encryption at rest; create encrypted snapshot and restore"),
    ("azure", "sub-prod-001", "eastus", "storage", "stgaccountprod001", "Azure Storage Public Blob Access", "misconfiguration", "high", 7.8, "Disable anonymous blob access on storage account"),
    ("aws", "123456789012", "us-east-1", "iam", "iam-policy-wildcard", "Wildcard IAM Policy Attached", "misconfiguration", "critical", 9.0, "Replace wildcard policies with least-privilege equivalents"),
    ("gcp", "project-prod-001", "us-central1", "gcs", "gs://ml-training-data", "GCS Bucket Publicly Readable", "misconfiguration", "critical", 9.2, "Remove allUsers from bucket IAM policy"),
    ("aws", "123456789012", "eu-west-1", "lambda", "fn-payment-processor", "Lambda with Overprivileged Role", "misconfiguration", "high", 7.5, "Scope Lambda execution role to minimum required permissions"),
    ("azure", "sub-prod-001", "westeurope", "vm", "vm-prod-app-02", "VM Disk Unencrypted", "misconfiguration", "medium", 6.5, "Enable Azure Disk Encryption using Key Vault"),
]
for provider, account, region, rtype, rid, title, ftype, sev, cvss, rem in cloud_findings:
    post(f"/api/v1/cloud-findings/findings", {
        "org_id": ORG,
        "provider": provider,
        "account_id": account,
        "region": region,
        "resource_type": rtype,
        "resource_id": rid,
        "finding_title": title,
        "finding_type": ftype,
        "severity": sev,
        "cvss_score": cvss,
        "remediation": rem,
    })
print(f"  -> cloud-findings/findings: {get_count('/api/v1/cloud-findings/findings')}")

# ============================================================
# 22. POSTURE MATURITY
# ============================================================
section("22. Security Posture Maturity (/api/v1/posture-maturity)")
maturity_data = [
    ("vulnerability_management", "Vulnerability Scanning", 3, "Regular scanning with automated remediation workflows in place", "Security Engineer"),
    ("vulnerability_management", "Patch Management", 2, "Patch management process exists but is manual and inconsistent", "IT Operations"),
    ("identity_access_management", "MFA Enforcement", 3, "MFA enforced on 74% of accounts; privileged accounts fully covered", "IAM Admin"),
    ("identity_access_management", "Privileged Access Management", 3, "PAM solution deployed for critical systems; some gaps remain", "IAM Admin"),
    ("network_security", "Network Segmentation", 2, "Basic VLAN segmentation; micro-segmentation not implemented", "Network Team"),
    ("cloud_security", "CSPM", 3, "CSPM tool deployed with automated alerting; remediation partially automated", "Cloud Security"),
    ("endpoint_security", "EDR Coverage", 4, "EDR deployed on 98% of endpoints with active threat hunting", "SOC Team"),
    ("data_security", "DLP Implementation", 2, "DLP policies exist for email; endpoint and cloud DLP incomplete", "Data Security"),
    ("incident_response", "IR Capability", 3, "Documented IR plan; tabletop exercises quarterly; 24/7 SOC coverage", "IR Lead"),
    ("compliance", "Compliance Monitoring", 3, "Automated compliance scanning for major frameworks; evidence collection partially automated", "Compliance Team"),
]
for domain, capability, level, evidence, assessor in maturity_data:
    post(f"/api/v1/posture-maturity/assessments", {
        "org_id": ORG,
        "domain": domain,
        "capability": capability,
        "maturity_level": level,
        "max_level": 5,
        "evidence": evidence,
        "assessor": assessor,
        "next_review": "2026-07-17T00:00:00Z",
    })
print(f"  -> posture-maturity/assessments: {get_count('/api/v1/posture-maturity/assessments')}")

# ============================================================
# 23. VULN AGE — track vulnerability age
# ============================================================
section("23. Vulnerability Age (/api/v1/vuln-age)")
# Check what endpoint exists
r = req("GET", f"/api/v1/vuln-age/vulnerabilities?org_id={ORG}", quiet=True)
if r is None:
    # Try adding via lifecycle
    print("  -> vuln-age endpoint check:", get_count("/api/v1/vuln-age/vulnerabilities"))
else:
    print(f"  -> vuln-age/vulnerabilities existing: {len(r) if isinstance(r, list) else r}")
# Seed via vuln-lifecycle if it exists
vuln_lifecycle_items = [
    ("CVE-2024-3400", "PAN-OS Command Injection", "critical", "paloalto-fw-01", "firewall"),
    ("CVE-2024-21762", "Fortinet SSL-VPN RCE", "critical", "fortigate-02", "vpn"),
    ("CVE-2023-46805", "Ivanti Auth Bypass", "critical", "ivanti-vpn-03", "vpn"),
    ("CVE-2024-1709", "ScreenConnect Auth Bypass", "critical", "screenconnect-04", "remote_access"),
    ("CVE-2024-27198", "JetBrains TeamCity RCE", "critical", "jetbrains-tc-05", "build_server"),
    ("CVE-2023-48788", "FortiSIEM SQL Injection", "high", "fortisiem-07", "siem"),
]
for cve, title, sev, asset, asset_type in vuln_lifecycle_items:
    post(f"/api/v1/vuln-lifecycle/vulnerabilities?org_id={ORG}", {
        "cve_id": cve,
        "title": title,
        "severity": sev,
        "cvss_score": 9.5 if sev == "critical" else 7.5,
        "asset_id": asset,
        "asset_type": asset_type,
        "org_id": ORG,
    }, quiet=True)
print(f"  -> vuln-lifecycle/vulnerabilities: {get_count('/api/v1/vuln-lifecycle/vulnerabilities')}")

# ============================================================
# 24. THREAT ATTRIBUTION — actors
# ============================================================
section("24. Threat Attribution (/api/v1/threat-attribution)")
actors = [
    ("APT29 / Cozy Bear", "nation_state", ["Cozy Bear", "The Dukes", "NOBELIUM"], "RU", "Espionage and intellectual property theft targeting government and defense", "advanced", True),
    ("LockBit 3.0", "criminal_group", ["LockBit Black", "LockBit 3"], "unknown", "Financial extortion via ransomware-as-a-service", "advanced", True),
    ("APT41", "nation_state", ["BARIUM", "Winnti", "Double Dragon"], "CN", "Dual espionage and financially motivated operations", "advanced", True),
    ("Lazarus Group", "nation_state", ["Hidden Cobra", "ZINC"], "KP", "Financial theft and critical infrastructure disruption", "advanced", True),
    ("Scattered Spider", "criminal_group", ["UNC3944", "Muddled Libra"], "unknown", "Social engineering and identity-based attacks targeting cloud environments", "moderate", True),
    ("Anonymous Sudan", "hacktivist", ["Storm-1359"], "SD", "DDoS campaigns against Western organizations", "moderate", True),
]
actor_ids = []
for name, atype, aliases, country, motivation, soph, active in actors:
    r = post(f"/api/v1/threat-attribution/actors", {
        "org_id": ORG,
        "name": name,
        "actor_type": atype,
        "aliases": aliases,
        "origin_country": country,
        "motivation": motivation,
        "sophistication": soph,
        "active": active,
    })
    if r:
        actor_ids.append(r.get("actor_id", ""))

# Create attributions for recent incidents
if actor_ids:
    post(f"/api/v1/threat-attribution/attributions", {
        "org_id": ORG,
        "incident_id": "INC-2026-001",
        "actor_id": actor_ids[0] if actor_ids else "",
        "confidence": "likely",
        "evidence": {"iocs": ["185.220.101.47"], "ttps": ["T1566.001", "T1078"]},
        "analyst": "threat-intel@company.com",
        "notes": "Phishing campaign targeting executives with APT29 TTPs",
    })
print(f"  -> threat-attribution/actors: {get_count('/api/v1/threat-attribution/actors')}")

# ============================================================
# 25. INCIDENT COSTS
# ============================================================
section("25. Incident Costs (/api/v1/incident-costs)")
incidents_cost = [
    ("INC-2026-001", "Ransomware Attack - Partial Encryption", "ransomware", "critical"),
    ("INC-2025-047", "Phishing Campaign - 12 Accounts Compromised", "phishing", "high"),
    ("INC-2025-031", "S3 Bucket Data Exposure", "data_breach", "high"),
    ("INC-2025-018", "DDoS Attack - 4 Hour Outage", "ddos", "high"),
    ("INC-2025-009", "Insider Data Exfiltration", "insider_threat", "critical"),
]
inc_ids = []
for inc_id, title, itype, sev in incidents_cost:
    r = post(f"/api/v1/incident-costs/incidents?org_id={ORG}", {
        "incident_id": inc_id,
        "title": title,
        "incident_type": itype,
        "severity": sev,
    }, quiet=True)
    if r:
        inc_ids.append(r.get("incident_record_id", r.get("id", "")))

cost_items = [
    ("forensic_investigation", 45000, 38500),
    ("legal_fees", 85000, 92000),
    ("regulatory_fines", 0, 75000),
    ("business_interruption", 250000, 187500),
    ("customer_notification", 15000, 12800),
    ("pr_crisis_management", 35000, 41000),
    ("system_recovery", 75000, 68000),
    ("employee_overtime", 28000, 31500),
]
for inc_id_val in inc_ids[:3]:
    if inc_id_val:
        for cat, est, actual in cost_items[:4]:
            post(f"/api/v1/incident-costs/incidents/{inc_id_val}/costs?org_id={ORG}", {
                "cost_category": cat,
                "estimated_cost": est,
                "actual_cost": actual,
                "currency": "USD",
                "notes": f"Cost tracking for {cat}",
            }, quiet=True)
print(f"  -> incident-costs/incidents: {get_count('/api/v1/incident-costs/incidents')}")

# ============================================================
# 26. SOAR EXECUTIONS (already has playbooks, need executions)
# ============================================================
section("26. SOAR Executions (/api/v1/soar)")
# Fetch existing playbooks
playbooks_r = req("GET", f"/api/v1/soar/playbooks?org_id={ORG}", quiet=True)
pb_ids = []
if isinstance(playbooks_r, list) and playbooks_r:
    pb_ids = [p.get("playbook_id", p.get("id", "")) for p in playbooks_r[:3] if p]
elif isinstance(playbooks_r, dict):
    items = playbooks_r.get("playbooks", playbooks_r.get("items", []))
    pb_ids = [p.get("playbook_id", p.get("id", "")) for p in items[:3] if p]

for pb_id in pb_ids:
    if pb_id:
        post(f"/api/v1/soar/playbooks/{pb_id}/execute?org_id={ORG}", {
            "trigger_event": "alert_fired",
            "context": {"alert_id": "ALT-001", "severity": "critical"},
        }, quiet=True)
        post(f"/api/v1/soar/playbooks/{pb_id}/execute?org_id={ORG}", {
            "trigger_event": "incident_created",
            "context": {"incident_id": "INC-2026-001"},
        }, quiet=True)
print(f"  -> soar/executions: {get_count('/api/v1/soar/executions')}")

# ============================================================
# 27. SCHEDULED REPORTS
# ============================================================
section("27. Scheduled Reports (/api/v1/scheduled-reports)")
report_schedules = [
    ("Weekly Security Digest", "security_summary", "weekly", "email", ["ciso@company.com", "security-team@company.com"]),
    ("Monthly Executive Risk Report", "executive_summary", "monthly", "email", ["ceo@company.com", "cfo@company.com", "ciso@company.com"]),
    ("Daily Threat Intelligence Brief", "threat_intel", "daily", "slack", ["#security-ops", "#soc-team"]),
    ("Quarterly Compliance Status", "compliance_report", "quarterly", "email", ["compliance@company.com", "legal@company.com"]),
    ("Weekly Vulnerability Summary", "vuln_summary", "weekly", "email", ["vuln-team@company.com"]),
]
for name, rtype, freq, channel, recipients in report_schedules:
    post(f"/api/v1/scheduled-reports/schedules?org_id={ORG}", {
        "report_name": name,
        "report_type": rtype,
        "frequency": freq,
        "delivery_channel": channel,
        "recipients": recipients,
        "org_id": ORG,
    })
print(f"  -> scheduled-reports/schedules: {get_count('/api/v1/scheduled-reports/schedules')}")

# ============================================================
# 28. SCA STATS — seed via SCA scan
# ============================================================
section("28. SCA (/api/v1/sca)")
sca_components = [
    ("log4j-core", "2.14.1", "java", "Apache", ["CVE-2021-44228", "CVE-2021-45046"], "critical", "Apache-2.0"),
    ("spring-core", "5.3.27", "java", "Pivotal", [], "none", "Apache-2.0"),
    ("lodash", "4.17.20", "npm", "John-David Dalton", ["CVE-2021-23337"], "high", "MIT"),
    ("axios", "0.21.1", "npm", "Matt Zabriskie", ["CVE-2021-3749"], "medium", "MIT"),
    ("openssl", "1.1.1t", "system", "OpenSSL Project", [], "none", "OpenSSL"),
    ("requests", "2.28.2", "pypi", "Kenneth Reitz", [], "none", "Apache-2.0"),
    ("com.h2database:h2", "2.1.210", "java", "H2 Group", ["CVE-2022-23221"], "critical", "EPL-2.0"),
    ("moment", "2.29.1", "npm", "Moment.js", ["CVE-2022-24785"], "medium", "MIT"),
    ("jackson-databind", "2.13.0", "java", "FasterXML", ["CVE-2022-42003"], "high", "Apache-2.0"),
    ("pyyaml", "5.4.1", "pypi", "Kirill Simonov", ["CVE-2022-45061"], "medium", "MIT"),
]
for name, version, ecosystem, author, cves, sev, license_id in sca_components:
    post(f"/api/v1/sca/components?org_id={ORG}", {
        "component_name": name,
        "version": version,
        "ecosystem": ecosystem,
        "author": author,
        "cve_ids": cves,
        "severity": sev,
        "license": license_id,
    }, quiet=True)
print(f"  -> sca/stats: {get_count('/api/v1/sca/stats')}")

# ============================================================
# 29. PASSWORD POLICY STATS
# ============================================================
section("29. Password Policy (/api/v1/password-policy)")
# Already has data but stats is empty - trigger a run_audit
post(f"/api/v1/password-policy/audits?org_id={ORG}", {
    "audit_name": "Q2 2026 Password Audit",
    "scope": "all_users",
}, quiet=True)
print(f"  -> password-policy/stats: {get_count('/api/v1/password-policy/stats')}")

# ============================================================
# 30. TIP IOCs
# ============================================================
section("30. TIP / IOCs (/api/v1/tip)")
tip_iocs = [
    ("185.220.101.47", "ip", "high", 0.94, "red"),
    ("malware-download.ru", "domain", "critical", 0.97, "red"),
    ("phishing-portal.xyz", "domain", "high", 0.88, "amber"),
    ("d41d8cd98f00b204e9800998ecf8427e", "file_hash", "critical", 0.99, "red"),
    ("45.33.32.156", "ip", "medium", 0.71, "amber"),
    ("hxxps://evil-cdn.net/payload.exe", "url", "critical", 0.95, "red"),
    ("cobalt-beacon-hash-abc123def456", "file_hash", "critical", 0.98, "red"),
    ("10.0.5.44", "ip", "medium", 0.65, "amber"),
]
for ioc_val, ioc_type, sev, conf, tlp in tip_iocs:
    post(f"/api/v1/tip/iocs?org_id={ORG}", {
        "ioc_value": ioc_val,
        "ioc_type": ioc_type,
        "severity": sev,
        "confidence": conf,
        "tlp": tlp,
        "source": "automated_threat_intel",
        "tags": ["automated", "2026-q2"],
    }, quiet=True)
print(f"  -> tip/iocs: {get_count('/api/v1/tip/iocs')}")

# ============================================================
# 31. VULN INTEL advisories
# ============================================================
section("31. VULN Intel advisories (/api/v1/vuln-intel)")
advisories = [
    ("ADV-2024-001", "Critical PAN-OS Vulnerability Requires Immediate Patching", "critical", ["CVE-2024-3400"], "Palo Alto Networks", "PAN-OS GlobalProtect feature contains a command injection vulnerability. Active exploitation observed."),
    ("ADV-2024-002", "Fortinet SSL-VPN Critical RCE - Emergency Patch Required", "critical", ["CVE-2024-21762"], "Fortinet", "Critical out-of-bounds write in FortiOS SSL-VPN. PoC exploits publicly available."),
    ("ADV-2024-003", "Ivanti Connect Secure Zero-Day - Mass Exploitation Ongoing", "critical", ["CVE-2023-46805", "CVE-2024-21887"], "Ivanti", "Authentication bypass combined with command injection. Nation-state actors actively exploiting."),
    ("ADV-2024-004", "ScreenConnect Authentication Bypass - Actively Exploited", "critical", ["CVE-2024-1709", "CVE-2024-1708"], "ConnectWise", "Two vulnerabilities chained together allowing unauthenticated RCE on ScreenConnect servers."),
    ("ADV-2026-001", "Spring Framework RCE in Spring MVC Applications", "high", ["CVE-2022-22965"], "Spring Framework", "Remote code execution vulnerability in Spring MVC and WebFlux applications. Patch available."),
]
for aid, title, sev, cves, vendor, summary in advisories:
    post(f"/api/v1/vuln-intel/advisories?org_id={ORG}", {
        "advisory_id": aid,
        "title": title,
        "severity": sev,
        "affected_cves": cves,
        "vendor": vendor,
        "summary": summary,
        "remediation": "Apply vendor-provided patch. Enable compensating controls pending patch deployment.",
    })
print(f"  -> vuln-intel/advisories: {get_count('/api/v1/vuln-intel/advisories')}")

# ============================================================
# 32. THREAT LANDSCAPE
# ============================================================
section("32. Threat Landscape (/api/v1/threat-landscape)")
# Already has data in top_target_sectors - check actors/threats
threat_actors_landscape = [
    ("APT29", "nation_state", "russia", "espionage", ["T1566", "T1078", "T1190"], "advanced"),
    ("LockBit 3.0", "criminal_group", "unknown", "financial", ["T1486", "T1490", "T1489"], "advanced"),
    ("APT41", "nation_state", "china", "dual_purpose", ["T1059", "T1027", "T1071"], "advanced"),
    ("Lazarus Group", "nation_state", "north_korea", "financial_espionage", ["T1566", "T1059", "T1486"], "advanced"),
    ("Scattered Spider", "criminal_group", "unknown", "financial", ["T1598", "T1621", "T1550"], "moderate"),
]
for name, atype, country, motivation, ttps, soph in threat_actors_landscape:
    post(f"/api/v1/threat-landscape/actors?org_id={ORG}", {
        "actor_name": name,
        "actor_type": atype,
        "country_of_origin": country,
        "motivation": motivation,
        "primary_ttps": ttps,
        "sophistication": soph,
    }, quiet=True)

threat_categories = [
    ("ransomware", "Ransomware", "critical", 0.85, ["financial_services", "healthcare", "manufacturing"]),
    ("supply_chain", "Supply Chain Attack", "critical", 0.65, ["technology", "defense", "government"]),
    ("phishing", "Phishing/BEC", "high", 0.92, ["all_sectors"]),
    ("cloud_misconfiguration", "Cloud Misconfiguration", "high", 0.78, ["technology", "financial_services"]),
    ("insider_threat", "Insider Threat", "high", 0.45, ["financial_services", "healthcare"]),
    ("zero_day", "Zero-Day Exploitation", "critical", 0.55, ["government", "defense", "critical_infrastructure"]),
]
for cat, name, sev, prob, sectors in threat_categories:
    post(f"/api/v1/threat-landscape/threats?org_id={ORG}", {
        "threat_name": name,
        "threat_category": cat,
        "severity": sev,
        "probability": prob,
        "target_sectors": sectors,
        "trend": "increasing",
    }, quiet=True)
print(f"  -> threat-landscape/actors: {get_count('/api/v1/threat-landscape/actors')}")

# ============================================================
# FINAL SUMMARY
# ============================================================
print(f"\n{'='*60}")
print(f"  SEEDING COMPLETE")
print(f"{'='*60}")
print(f"  Successful POSTs: {ok}")
print(f"  Failed POSTs:     {failed}")
print(f"  Skipped:          {skipped}")
print()

# Verification pass
print("VERIFICATION — re-checking all seeded endpoints:")
checks = [
    ("/api/v1/posture-advisor/stats", "posture-advisor"),
    ("/api/v1/posture-advisor/recommendations", "posture-advisor/recommendations"),
    ("/api/v1/kpi/current", "kpi/current"),
    ("/api/v1/risk-quant/scenarios", "risk-quant/scenarios"),
    ("/api/v1/ai-advisor/recommendations", "ai-advisor/recommendations"),
    ("/api/v1/vuln-prioritization/scored", "vuln-prioritization/scored"),
    ("/api/v1/vuln-intel/advisories", "vuln-intel/advisories"),
    ("/api/v1/training-effectiveness/programs", "training-effectiveness/programs"),
    ("/api/v1/tprm-exchange/vendors", "tprm-exchange/vendors"),
    ("/api/v1/threat-indicators/indicators", "threat-indicators/indicators"),
    ("/api/v1/ransomware-protection/detections", "ransomware-protection/detections"),
    ("/api/v1/privacy-impact/assessments", "privacy-impact/assessments"),
    ("/api/v1/posture-trends/trends", "posture-trends/trends"),
    ("/api/v1/posture-history/snapshots", "posture-history/snapshots"),
    ("/api/v1/network-threats/threats/active", "network-threats/active"),
    ("/api/v1/security-okrs/objectives", "security-okrs/objectives"),
    ("/api/v1/security-findings/findings", "security-findings/findings"),
    ("/api/v1/risk-scenarios/scenarios", "risk-scenarios/scenarios"),
    ("/api/v1/security-questionnaires/questionnaires", "security-questionnaires"),
    ("/api/v1/security-scorecard/scorecards", "security-scorecard/scorecards"),
    ("/api/v1/attack-paths/nodes", "attack-paths/nodes"),
    ("/api/v1/cloud-findings/findings", "cloud-findings/findings"),
    ("/api/v1/posture-maturity/assessments", "posture-maturity/assessments"),
    ("/api/v1/vuln-lifecycle/vulnerabilities", "vuln-lifecycle/vulnerabilities"),
    ("/api/v1/threat-attribution/actors", "threat-attribution/actors"),
    ("/api/v1/threat-landscape/actors", "threat-landscape/actors"),
    ("/api/v1/scheduled-reports/schedules", "scheduled-reports/schedules"),
    ("/api/v1/incident-costs/incidents", "incident-costs/incidents"),
]
for path, label in checks:
    count = get_count(path)
    status = "OK" if count not in ("0", "dict:empty", "err") else "EMPTY"
    print(f"  [{status:5}] {label}: {count}")
