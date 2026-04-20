#!/usr/bin/env python3
"""
Seed realistic enterprise data into the top 50 most-used API endpoints.
Run: python3 scripts/seed_top50_endpoints.py

Rate limit: 50 writes/min → sleep 1.3s between POSTs.
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
SLEEP = 1.4   # seconds between POSTs to stay under 50 RPM write limit

ok = 0
failed = 0


def req(method: str, path: str, body: Optional[Dict] = None, quiet: bool = False) -> Optional[Dict]:
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    headers = {"X-API-Key": TOKEN, "Content-Type": "application/json"}
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()[:250]
        if not quiet:
            print(f"  WARN {method} {path} -> {e.code}: {body_text}")
        return None
    except Exception as e:
        if not quiet:
            print(f"  ERR {method} {path} -> {e}")
        return None


def post(path: str, body: Dict, quiet: bool = False) -> Optional[Dict]:
    global ok, failed
    time.sleep(SLEEP)
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
            if isinstance(v, list) and len(v) > 0:
                return f"{k}:{len(v)}"
        # Check for empty-but-present dict keys indicating populated stats
        non_empty = {k: v for k, v in result.items() if v not in (None, 0, [], {}, "")}
        return f"dict({len(non_empty)} keys)" if non_empty else "dict:empty"
    return str(result)


def section(name: str):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")


# ============================================================
# 1. POSTURE ADVISOR — generate recommendations
# ============================================================
section("1. Posture Advisor (/api/v1/posture-advisor)")
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
print(f"  -> posture-advisor/recommendations: {get_count('/api/v1/posture-advisor/recommendations')}")

# ============================================================
# 2. KPI TRACKER — use exact KPI_NAMES from engine
# Valid: mttd_hours, mttr_hours, mttr_critical_hours, patch_compliance_pct,
#        vuln_density, sla_compliance_pct, false_positive_rate,
#        open_critical_count, incidents_per_month, posture_score
# ============================================================
section("2. KPI Tracker (/api/v1/kpi)")
kpis = [
    ("mttd_hours", 4.2),
    ("mttr_hours", 18.7),
    ("mttr_critical_hours", 6.1),
    ("patch_compliance_pct", 87.3),
    ("vuln_density", 3.4),
    ("sla_compliance_pct", 91.0),
    ("false_positive_rate", 8.5),
    ("open_critical_count", 14.0),
    ("incidents_per_month", 7.0),
    ("posture_score", 72.5),
]
for kpi_name, value in kpis:
    post(f"/api/v1/kpi/record", {
        "kpi_name": kpi_name,
        "value": value,
        "org_id": ORG,
        "period": "monthly",
    })
post(f"/api/v1/kpi/snapshot", {"org_id": ORG})
print(f"  -> kpi/current: {get_count('/api/v1/kpi/current')}")

# ============================================================
# 3. AI SECURITY ADVISOR — generate recommendations
# ============================================================
section("3. AI Security Advisor (/api/v1/ai-advisor)")
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
# 4. VULN PRIORITIZATION — valid exploitability values from engine
# asset_criticality: critical/high/medium/low
# exploitability: functional/poc/theoretical/unproven  (engine uses these)
# exposure: internet_facing/internal/isolated
# ============================================================
section("4. Vulnerability Prioritization (/api/v1/vuln-prioritization)")
vulns = [
    ("CVE-2024-3400",  "paloalto-fw-01",   "critical", 10.0, 0.97, True,  "functional", "internet_facing"),
    ("CVE-2024-21762", "fortigate-02",      "critical",  9.8, 0.95, True,  "functional", "internet_facing"),
    ("CVE-2023-46805", "ivanti-vpn-03",     "critical",  8.2, 0.91, True,  "poc",        "internet_facing"),
    ("CVE-2024-1709",  "screenconnect-04",  "critical", 10.0, 0.93, True,  "functional", "internet_facing"),
    ("CVE-2024-27198", "jetbrains-tc-05",   "critical",  9.8, 0.88, False, "poc",        "internal"),
    ("CVE-2024-0204",  "goanywhere-06",     "critical",  9.8, 0.85, True,  "functional", "internal"),
    ("CVE-2023-48788", "fortisiem-07",      "high",      9.8, 0.72, False, "poc",        "internal"),
    ("CVE-2024-20353", "cisco-asa-08",      "high",      8.6, 0.68, False, "theoretical","internet_facing"),
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
# 5. VULN INTEL — advisories
# ============================================================
section("5. Vulnerability Intelligence (/api/v1/vuln-intel)")
advisories = [
    ("ADV-2024-001", "Critical PAN-OS Vulnerability Requires Immediate Patching",   "critical", ["CVE-2024-3400"],           "Palo Alto Networks", "PAN-OS GlobalProtect contains command injection. Active exploitation observed."),
    ("ADV-2024-002", "Fortinet SSL-VPN Critical RCE - Emergency Patch Required",    "critical", ["CVE-2024-21762"],          "Fortinet",           "Out-of-bounds write in FortiOS SSL-VPN. PoC exploits publicly available."),
    ("ADV-2024-003", "Ivanti Connect Secure Zero-Day - Mass Exploitation Ongoing",  "critical", ["CVE-2023-46805"],          "Ivanti",             "Authentication bypass + command injection. Nation-state actors actively exploiting."),
    ("ADV-2024-004", "ScreenConnect Auth Bypass - Actively Exploited",              "critical", ["CVE-2024-1709"],           "ConnectWise",        "Unauthenticated RCE on ScreenConnect servers."),
    ("ADV-2024-005", "JetBrains TeamCity Authentication Bypass",                    "critical", ["CVE-2024-27198"],          "JetBrains",          "Remote code execution via authentication bypass in TeamCity."),
    ("ADV-2026-001", "Spring Framework RCE in Spring MVC Applications",             "high",     ["CVE-2022-22965"],          "VMware",             "RCE vulnerability in Spring MVC and WebFlux. Patch available."),
    ("ADV-2026-002", "Log4Shell Reminder - Unpatched Instances Still Detected",     "critical", ["CVE-2021-44228"],          "Apache",             "Log4j 2 JNDI injection. Ensure all instances are patched to 2.17.1+."),
    ("ADV-2026-003", "OpenSSL Buffer Overflow Vulnerability",                       "high",     ["CVE-2022-3602", "CVE-2022-3786"], "OpenSSL",       "Buffer overflow in X.509 certificate verification. Upgrade to 3.0.7+."),
]
for aid, title, sev, cves, vendor, summary in advisories:
    post(f"/api/v1/vuln-intel/advisories?org_id={ORG}", {
        "advisory_id": aid,
        "title": title,
        "severity": sev,
        "affected_cves": cves,
        "vendor": vendor,
        "summary": summary,
        "remediation": "Apply vendor-provided patch immediately. Enable compensating controls pending deployment.",
    })
print(f"  -> vuln-intel/advisories: {get_count('/api/v1/vuln-intel/advisories')}")

# ============================================================
# 6. SECURITY TRAINING EFFECTIVENESS
# Valid training_type: awareness/compliance/leadership/onboarding/phishing/refresher/technical
# Valid delivery_method: hybrid/instructor-led/online/self-paced/simulation
# ============================================================
section("6. Security Training Effectiveness (/api/v1/training-effectiveness)")
programs = [
    ("Phishing Awareness 2026",      "phishing",    "all",            "simulation",      45,  80.0),
    ("Security Fundamentals",        "awareness",   "all",            "online",          60,  75.0),
    ("Advanced Threat Detection",    "technical",   "security_team",  "instructor-led",  480, 85.0),
    ("GDPR & Data Privacy",          "compliance",  "all",            "online",          90,  70.0),
    ("Secure Coding Practices",      "technical",   "engineering",    "online",          120, 82.0),
    ("Leadership Security Briefing", "leadership",  "executives",     "hybrid",          120, 90.0),
    ("New Hire Security Onboarding", "onboarding",  "new_hires",      "self-paced",      180, 75.0),
]
prog_ids = []
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
    ("EMP-004", "Sales"),       ("EMP-005", "Security"), ("EMP-006", "Marketing"),
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
# 7. TPRM EXCHANGE — valid vendor_category: saas/cloud_provider/hardware/data_processor/legal/logistics/consulting/financial
# ============================================================
section("7. TPRM Exchange (/api/v1/tprm-exchange)")
vendor_data = [
    ("Salesforce Inc",      "saas",           "critical", ["customer_data", "employee_data"],      "2025-01-01", "2026-12-31", 285000, "vendor@salesforce.com"),
    ("Amazon Web Services", "cloud_provider", "critical", ["all_data"],                            "2020-01-01", "2027-12-31", 1200000,"enterprise@aws.com"),
    ("Okta",                "saas",           "high",     ["identity_data", "access_logs"],        "2023-06-01", "2026-06-01", 95000,  "support@okta.com"),
    ("Crowdstrike",         "saas",           "high",     ["endpoint_telemetry", "threat_intel"],  "2024-01-01", "2026-12-31", 340000, "cs@crowdstrike.com"),
    ("Palo Alto Networks",  "hardware",       "critical", ["network_traffic", "firewall_logs"],    "2022-03-01", "2025-03-01", 420000, "enterprise@paloalto.com"),
    ("ServiceNow",          "saas",           "medium",   ["it_tickets", "employee_data"],         "2023-09-01", "2026-09-01", 180000, "support@servicenow.com"),
    ("Splunk",              "saas",           "high",     ["log_data", "security_events"],         "2023-01-01", "2026-01-01", 520000, "enterprise@splunk.com"),
    ("Deloitte Cyber",      "consulting",     "high",     ["audit_data", "security_assessments"],  "2025-01-01", "2025-12-31", 350000, "cyber@deloitte.com"),
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
# 8. THREAT INDICATORS (IOCs)
# Valid indicator_type: certificate/domain/email/hash_md5/hash_sha1/hash_sha256/ip/mutex/registry_key/url/user_agent
# ============================================================
section("8. Threat Indicators (/api/v1/threat-indicators)")
iocs = [
    ("185.220.101.47",              "ip",         "C2 infrastructure",           0.95, "critical", "red",   ["apt29", "cozy-bear"]),
    ("malware-download.ru",         "domain",     "Malware distribution domain", 0.92, "critical", "red",   ["malware-dist"]),
    ("d41d8cd98f00b204e9800998ec",  "hash_md5",   "Known ransomware payload",    0.98, "critical", "red",   ["ransomware", "lockbit"]),
    ("phishing-portal.xyz",         "domain",     "Active phishing campaign",    0.88, "high",     "amber", ["phishing", "credential-theft"]),
    ("hxxps://evil-cdn.net/payload","url",        "Malware delivery URL",        0.91, "critical", "red",   ["dropper"]),
    ("45.33.32.156",                "ip",         "Shodan scanning source",      0.65, "medium",   "amber", ["scanning"]),
    ("abc123def456abc123def456abc1","hash_sha256","Cobalt Strike beacon",        0.97, "critical", "red",   ["cobalt-strike", "c2"]),
    ("cobalt-strike@domain.com",    "email",      "Spear-phishing sender",       0.82, "high",     "amber", ["spear-phishing"]),
    ("HKCU\\Software\\Malware\\Key","registry_key","Persistence registry key",  0.78, "high",     "amber", ["persistence"]),
    ("Mozilla/5.0 (bad actor UA)",  "user_agent", "Known malicious user agent",  0.71, "medium",   "amber", ["reconnaissance"]),
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
# 9. RANSOMWARE PROTECTION
# ============================================================
section("9. Ransomware Protection (/api/v1/ransomware-protection)")
# Already has 29 detections from first run — just verify
detections_count = get_count('/api/v1/ransomware-protection/detections')
print(f"  -> ransomware-protection/detections (existing): {detections_count}")

# ============================================================
# 10. PRIVACY IMPACT ASSESSMENTS
# Valid legal_basis: consent/contract/legal_obligation/legitimate_interests/public_task/vital_interests
# ============================================================
section("10. Privacy Impact Assessment (/api/v1/privacy-impact)")
existing = get_count('/api/v1/privacy-impact/assessments')
print(f"  -> existing assessments: {existing}")
pias = [
    ("Customer Analytics Platform v2", "dpia", "ACME Corp", "DataProc Ltd", "legitimate_interests",
     ["behavioral_data", "purchase_history"], ["customers"], 730, True),
    ("Employee Monitoring System",     "pia",  "ACME Corp", "HR Systems Inc", "legitimate_interests",
     ["activity_logs", "email_metadata"], ["employees"], 365, False),
    ("Marketing Automation Tool",      "pia",  "ACME Corp", "MarketingCo", "consent",
     ["email", "name", "preferences"], ["customers", "leads"], 180, False),
    ("Payment Processing Upgrade",     "dpia", "ACME Corp", "PaymentGW Ltd", "contract",
     ["financial_data", "card_data"], ["customers"], 2555, True),
    ("Cloud HR System Migration",      "pia",  "ACME Corp", "WorkdayCo", "legitimate_interests",
     ["employee_pii", "payroll_data"], ["employees"], 365, True),
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
for pid in pia_ids[:2]:
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
# 11. POSTURE TRENDS (with rate limit pacing)
# ============================================================
section("11. Posture Trends (/api/v1/posture-trends)")
metrics_trend = [
    ("overall_security_score", "vulnerability", 72.5, "score",      "vulnerability_scanner"),
    ("patch_compliance",       "vulnerability", 87.3, "percentage", "patch_manager"),
    ("mfa_adoption",           "identity",      74.0, "percentage", "identity_provider"),
    ("cloud_security_posture", "cloud",         68.2, "score",      "cspm_tool"),
    ("endpoint_protection",    "endpoint",      91.5, "percentage", "edr_platform"),
    ("data_encryption",        "data",          83.7, "percentage", "dlp_tool"),
    ("network_segmentation",   "network",       65.4, "score",      "network_scanner"),
    ("security_awareness",     "awareness",     78.9, "percentage", "training_platform"),
]
for metric, cat, val, unit, source in metrics_trend:
    post(f"/api/v1/posture-trends/datapoints?org_id={ORG}", {
        "metric_name": metric,
        "metric_category": cat,
        "value": val,
        "unit": unit,
        "source": source,
    })
for metric, _, _, _, _ in metrics_trend[:4]:
    post(f"/api/v1/posture-trends/analyze/{metric}?org_id={ORG}", {"period_days": 30})
print(f"  -> posture-trends/trends: {get_count('/api/v1/posture-trends/trends')}")

# ============================================================
# 12. POSTURE HISTORY
# ============================================================
section("12. Posture History (/api/v1/posture-history)")
existing = get_count('/api/v1/posture-history/snapshots')
print(f"  -> existing snapshots: {existing}")
domains = [
    ("identity_access",         74.0, 8,  1, 4),
    ("network_security",        68.3, 11, 2, 5),
    ("cloud_security",          65.8, 18, 4, 7),
    ("data_security",           78.4, 7,  1, 3),
    ("application_security",    69.1, 12, 2, 6),
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
# 13. NETWORK THREATS
# ============================================================
section("13. Network Threats (/api/v1/network-threats)")
threats = [
    ("Port Scan External",       "reconnaissance",  "203.0.113.42", "10.0.1.1",   22,  "tcp", "medium",   0.78),
    ("Brute Force SSH",          "brute_force",     "198.51.100.17","10.0.1.50",  22,  "tcp", "high",     0.91),
    ("DNS Tunneling Detected",   "exfiltration",    "10.0.5.44",    "8.8.8.8",    53,  "udp", "high",     0.84),
    ("Lateral Movement SMB",     "lateral_movement","10.0.3.22",    "10.0.1.100", 445, "tcp", "critical", 0.93),
    ("C2 Beacon Detected",       "c2_communication","10.0.2.88",    "185.220.101.47",443,"tcp","critical", 0.96),
    ("SQL Injection Attempt",    "web_attack",      "45.33.32.156", "10.0.4.10",  443, "tcp", "high",     0.87),
    ("Unauthorized LDAP Query",  "reconnaissance",  "10.0.6.15",    "10.0.1.5",   389, "tcp", "medium",   0.72),
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
# 14. SECURITY OKRs
# ============================================================
section("14. Security OKRs (/api/v1/security-okrs)")
existing = get_count('/api/v1/security-okrs/objectives')
print(f"  -> existing objectives: {existing}")
if existing in ("0", "dict:empty", "err"):
    objectives = [
        ("Reduce Critical Vulnerability Exposure by 60%",  "Eliminate all critical CVEs from internet-facing assets",      "CISO",            "Q2-2026", "2026-06-30"),
        ("Achieve 95% MFA Coverage Across All Systems",    "Enforce MFA on all privileged and standard accounts",          "IAM Lead",        "Q2-2026", "2026-06-30"),
        ("Attain SOC 2 Type II Certification",             "Complete all controls and undergo formal audit",               "Compliance Lead", "Q3-2026", "2026-09-30"),
        ("Reduce MTTD to Under 1 Hour",                    "Improve detection via SIEM tuning and automation",             "SOC Manager",     "Q2-2026", "2026-06-30"),
        ("Zero Critical Cloud Misconfigurations",          "Remediate all critical cloud misconfigs",                      "Cloud Security",  "Q2-2026", "2026-06-30"),
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
         ("Reduce vuln backlog from 142 to 57 findings",            57,  "count")],
        [("Enable MFA on all 847 privileged accounts",              847, "count"),
         ("Enforce MFA on all 3200 standard user accounts",         3200,"count")],
        [("Complete all 93 SOC 2 control implementations",          93,  "count")],
        [("Tune SIEM rules: false positive rate under 5%",          5,   "percentage"),
         ("Achieve MTTD of 60 minutes or less",                     60,  "minutes")],
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
# 15. SECURITY FINDINGS
# ============================================================
section("15. Security Findings (/api/v1/security-findings)")
existing = get_count('/api/v1/security-findings/findings')
print(f"  -> existing findings: {existing}")
if existing in ("0", "dict:empty", "err"):
    findings = [
        ("Critical S3 Bucket Publicly Accessible",      "misconfiguration",        "cloud_scanner",    "critical", 9.1, "s3-prod-data-001",  "s3_bucket",      "Production data bucket has public read access", "Disable public access block"),
        ("Log4Shell Vulnerable Instance",               "vulnerability",           "vuln_scanner",     "critical", 10.0,"app-server-prod-03","ec2_instance",   "Running Log4j 2.14.1 vulnerable to CVE-2021-44228", "Upgrade to Log4j 2.17.1+"),
        ("Admin Account Without MFA",                   "configuration",           "identity_scanner", "high",     8.5, "admin-account-007", "iam_user",       "Privileged IAM account lacks MFA", "Enable MFA on all admin accounts"),
        ("Unencrypted RDS Database",                    "misconfiguration",        "cloud_scanner",    "high",     7.8, "rds-customer-prod", "rds_instance",   "Customer database lacks encryption at rest", "Enable RDS encryption"),
        ("Overprivileged Service Account",              "misconfiguration",        "iam_scanner",      "high",     7.5, "svc-app-prod-01",   "service_account","Service account has wildcard S3 permissions", "Apply least privilege"),
        ("Expired SSL Certificate - API Gateway",       "configuration",           "cert_scanner",     "high",     7.2, "api-gateway-prod",  "api_gateway",    "SSL certificate expired on prod API gateway", "Renew certificate immediately"),
        ("Default Credentials on Network Device",       "misconfiguration",        "network_scanner",  "critical", 9.8, "switch-floor2-07",  "network_switch", "Network switch using default vendor credentials", "Change default credentials"),
        ("Unrestricted Outbound SMTP Port 25",          "network_misconfiguration","network_scanner",  "medium",   5.5, "sg-webapp-prod",    "security_group", "Security group allows unrestricted outbound SMTP", "Restrict to authorized mail relay"),
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
# 16. RISK SCENARIOS
# ============================================================
section("16. Risk Scenarios (/api/v1/risk-scenarios)")
scenarios = [
    ("Advanced Persistent Threat - Nation State",    "nation_state_attack", "Nation-state targeting IP via spear-phishing and supply chain",    0.35, 9.2, "CISO"),
    ("Ransomware Outbreak - Business Critical",      "ransomware",          "Ransomware via phishing affecting ERP, CRM and production systems", 0.45, 9.8, "IR Lead"),
    ("Insider Threat - Privileged Admin",            "insider_threat",      "Disgruntled sysadmin exfiltrating PII and sabotaging infrastructure",0.20, 8.5, "Security Ops"),
    ("Cloud Misconfiguration Data Breach",           "cloud_breach",        "Exposed S3 bucket leaking customer data",                           0.55, 7.8, "Cloud Security"),
    ("Third-Party Supply Chain Attack",              "supply_chain",        "Compromise via malicious update from trusted software vendor",       0.25, 9.5, "Third-Party Risk"),
    ("DDoS on Critical Services",                   "ddos",                "Volumetric DDoS taking down e-commerce and customer portal",         0.60, 6.5, "Network Team"),
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
# 17. SECURITY QUESTIONNAIRES
# ============================================================
section("17. Security Questionnaires (/api/v1/security-questionnaires)")
q_templates = [
    ("Vendor Security Assessment 2026",     "vendor",       "iso27001"),
    ("Cloud Provider Security Review",      "cloud_vendor", "soc2"),
    ("Software Supply Chain Assessment",    "vendor",       "nist_csf"),
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
    ("Does your organization have a documented Information Security Policy?",   "governance",        2.0),
    ("Do you perform annual security risk assessments?",                        "risk_management",   1.5),
    ("Is multi-factor authentication enforced for all privileged access?",      "access_control",    2.5),
    ("Do you maintain an incident response plan and test it annually?",         "incident_response", 2.0),
    ("Is all customer data encrypted at rest and in transit?",                  "data_security",     2.5),
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
# 18. SECURITY SCORECARD ENGINE
# ============================================================
section("18. Security Scorecard Engine (/api/v1/security-scorecard)")
scorecards = [
    ("team",    "soc-team-01",     "Security Operations Center", "2026-Q2",
     [{"name":"detection_rate","score":87.5,"weight":1.5},{"name":"response_time","score":72.3,"weight":1.2}]),
    ("team",    "cloud-team-01",   "Cloud Security Team",         "2026-Q2",
     [{"name":"misconfiguration_rate","score":65.4,"weight":1.5},{"name":"compliance_score","score":78.9,"weight":1.2}]),
    ("vendor",  "vendor-aws-01",   "Amazon Web Services",         "2026-Q2",
     [{"name":"sla_compliance","score":99.5,"weight":1.0},{"name":"security_certifications","score":98.0,"weight":1.5}]),
    ("project", "zerotrust-proj",  "Zero Trust Initiative",       "2026-Q2",
     [{"name":"completion_pct","score":45.0,"weight":1.0},{"name":"risk_reduction","score":62.0,"weight":1.5}]),
    ("asset",   "dc-prod-01",      "Production Data Center",      "2026-Q2",
     [{"name":"vulnerability_score","score":74.2,"weight":1.5},{"name":"access_control","score":88.5,"weight":1.2}]),
]
for etype, eid, ename, period, dims in scorecards:
    post(f"/api/v1/security-scorecard/scorecards?org_id={ORG}", {
        "entity_type": etype,
        "entity_id": eid,
        "entity_name": ename,
        "period_label": period,
        "dimensions": dims,
    })
post(f"/api/v1/security-scorecard/scorecards/domain?org_id={ORG}", {
    "identity": 74.0, "endpoint": 91.2, "network": 68.3,
    "cloud": 65.8,    "data": 78.4,     "application": 69.1,
})
print(f"  -> security-scorecard/scorecards: {get_count('/api/v1/security-scorecard/scorecards')}")

# ============================================================
# 19. ATTACK PATHS — nodes and edges
# ============================================================
section("19. Attack Paths (/api/v1/attack-paths)")
nodes = [
    ("ext-attacker",    "external",       "External Attacker",           90.0, False, []),
    ("web-dmz-01",      "server",         "Web Server DMZ",              65.0, False, ["CVE-2024-3400"]),
    ("app-server-01",   "server",         "Application Server",          72.0, False, ["CVE-2023-46805"]),
    ("db-prod-01",      "database",       "Production Database",         85.0, True,  []),
    ("ad-dc-01",        "server",         "Active Directory DC",         88.0, True,  ["CVE-2024-1709"]),
    ("workstation-042", "workstation",    "Compromised Workstation",     60.0, False, ["CVE-2024-21762"]),
    ("backup-srv-01",   "server",         "Backup Server",               78.0, True,  []),
    ("cloud-mgmt-01",   "cloud_service",  "Cloud Management Console",   80.0, True,  []),
]
for nid, ntype, name, risk, crown, vulns in nodes:
    post(f"/api/v1/attack-paths/nodes", {
        "node_id": nid, "node_type": ntype, "name": name,
        "risk_score": risk, "is_crown_jewel": crown,
        "vulnerabilities": vulns, "org_id": ORG,
    })
edges = [
    ("ext-attacker",    "web-dmz-01",     "tcp", 443,  None),
    ("web-dmz-01",      "app-server-01",  "tcp", 8080, "CVE-2024-3400"),
    ("app-server-01",   "db-prod-01",     "tcp", 5432, None),
    ("app-server-01",   "ad-dc-01",       "tcp", 389,  "CVE-2023-46805"),
    ("workstation-042", "ad-dc-01",       "tcp", 445,  "CVE-2024-21762"),
    ("ad-dc-01",        "backup-srv-01",  "tcp", 445,  None),
    ("ad-dc-01",        "cloud-mgmt-01",  "tcp", 443,  None),
]
for src, dst, proto, port, vuln in edges:
    post(f"/api/v1/attack-paths/edges", {
        "from_node": src, "to_node": dst,
        "protocol": proto, "port": port,
        "requires_vuln": vuln, "org_id": ORG,
    })
print(f"  -> attack-paths/nodes: {get_count('/api/v1/attack-paths/nodes')}")

# ============================================================
# 20. CLOUD SECURITY FINDINGS
# ============================================================
section("20. Cloud Security Findings (/api/v1/cloud-findings)")
cloud_findings = [
    ("aws",   "123456789012", "us-east-1",   "s3",      "s3://prod-customer-data",  "Public S3 Bucket Exposed",           "misconfiguration", "critical", 9.5, "Remove public access; apply deny-public policy"),
    ("aws",   "123456789012", "us-east-1",   "ec2",     "i-0abc12345def67890",      "IMDSv2 Not Enforced",                "misconfiguration", "high",     7.5, "Enforce IMDSv2 on all EC2 instances"),
    ("aws",   "123456789012", "us-west-2",   "rds",     "db-prod-postgres-01",      "RDS Encryption Disabled",            "misconfiguration", "high",     8.0, "Enable encryption at rest via encrypted snapshot"),
    ("azure", "sub-prod-001", "eastus",      "storage", "stgaccountprod001",        "Azure Storage Public Blob Access",   "misconfiguration", "high",     7.8, "Disable anonymous blob access on storage account"),
    ("aws",   "123456789012", "us-east-1",   "iam",     "iam-policy-wildcard",      "Wildcard IAM Policy Attached",       "misconfiguration", "critical", 9.0, "Replace wildcard policies with least-privilege equivalents"),
    ("gcp",   "project-001",  "us-central1", "gcs",     "gs://ml-training-data",    "GCS Bucket Publicly Readable",       "misconfiguration", "critical", 9.2, "Remove allUsers from bucket IAM policy"),
    ("aws",   "123456789012", "eu-west-1",   "lambda",  "fn-payment-processor",     "Lambda Overprivileged Role",         "misconfiguration", "high",     7.5, "Scope Lambda execution role to minimum required permissions"),
    ("azure", "sub-prod-001", "westeurope",  "vm",      "vm-prod-app-02",           "VM Disk Unencrypted",                "misconfiguration", "medium",   6.5, "Enable Azure Disk Encryption using Key Vault"),
]
for provider, account, region, rtype, rid, title, ftype, sev, cvss, rem in cloud_findings:
    post(f"/api/v1/cloud-findings/findings", {
        "org_id": ORG, "provider": provider, "account_id": account,
        "region": region, "resource_type": rtype, "resource_id": rid,
        "finding_title": title, "finding_type": ftype,
        "severity": sev, "cvss_score": cvss, "remediation": rem,
    })
print(f"  -> cloud-findings/findings: {get_count('/api/v1/cloud-findings/findings')}")

# ============================================================
# 21. POSTURE MATURITY
# ============================================================
section("21. Security Posture Maturity (/api/v1/posture-maturity)")
maturity_data = [
    ("vulnerability_management", "Vulnerability Scanning",     3, "Regular scanning with automated remediation workflows",    "Security Engineer"),
    ("vulnerability_management", "Patch Management",           2, "Manual and inconsistent patch process",                    "IT Operations"),
    ("identity_access_management","MFA Enforcement",           3, "MFA enforced on 74% of accounts",                          "IAM Admin"),
    ("identity_access_management","Privileged Access Mgmt",    3, "PAM deployed for critical systems; gaps remain",           "IAM Admin"),
    ("network_security",         "Network Segmentation",       2, "Basic VLAN segmentation; micro-seg not implemented",       "Network Team"),
    ("cloud_security",           "CSPM",                       3, "CSPM with automated alerting; partial auto-remediation",   "Cloud Security"),
    ("endpoint_security",        "EDR Coverage",               4, "EDR on 98% of endpoints with active threat hunting",       "SOC Team"),
    ("data_security",            "DLP Implementation",         2, "DLP for email; endpoint and cloud DLP incomplete",         "Data Security"),
    ("incident_response",        "IR Capability",              3, "Documented IR plan; quarterly tabletops; 24/7 SOC",        "IR Lead"),
    ("compliance",               "Compliance Monitoring",      3, "Automated scanning; evidence collection partly automated", "Compliance Team"),
]
for domain, capability, level, evidence, assessor in maturity_data:
    post(f"/api/v1/posture-maturity/assessments", {
        "org_id": ORG, "domain": domain, "capability": capability,
        "maturity_level": level, "max_level": 5, "evidence": evidence,
        "assessor": assessor, "next_review": "2026-07-17T00:00:00Z",
    })
print(f"  -> posture-maturity/assessments: {get_count('/api/v1/posture-maturity/assessments')}")

# ============================================================
# 22. THREAT ATTRIBUTION — actors
# ============================================================
section("22. Threat Attribution (/api/v1/threat-attribution)")
actors = [
    ("APT29 / Cozy Bear",   "nation_state",  ["Cozy Bear", "NOBELIUM"],       "RU", "Espionage and IP theft targeting government and defense",    "advanced", True),
    ("LockBit 3.0",         "criminal_group",["LockBit Black", "LockBit 3"],  "unknown","Financial extortion via ransomware-as-a-service",        "advanced", True),
    ("APT41",               "nation_state",  ["BARIUM", "Winnti"],            "CN", "Dual espionage and financially motivated operations",        "advanced", True),
    ("Lazarus Group",       "nation_state",  ["Hidden Cobra", "ZINC"],        "KP", "Financial theft and critical infrastructure disruption",      "advanced", True),
    ("Scattered Spider",    "criminal_group",["UNC3944"],                     "unknown","Social engineering targeting cloud environments",         "moderate", True),
    ("Anonymous Sudan",     "hacktivist",    ["Storm-1359"],                  "SD", "DDoS campaigns against Western organizations",                "moderate", True),
]
actor_ids = []
for name, atype, aliases, country, motivation, soph, active in actors:
    r = post(f"/api/v1/threat-attribution/actors", {
        "org_id": ORG, "name": name, "actor_type": atype,
        "aliases": aliases, "origin_country": country,
        "motivation": motivation, "sophistication": soph, "active": active,
    })
    if r:
        actor_ids.append(r.get("actor_id", ""))
if actor_ids:
    post(f"/api/v1/threat-attribution/attributions", {
        "org_id": ORG, "incident_id": "INC-2026-001",
        "actor_id": actor_ids[0],
        "confidence": "likely",
        "evidence": {"iocs": ["185.220.101.47"], "ttps": ["T1566.001", "T1078"]},
        "analyst": "threat-intel@company.com",
        "notes": "Phishing campaign targeting executives with APT29 TTPs",
    })
print(f"  -> threat-attribution/actors: {get_count('/api/v1/threat-attribution/actors')}")

# ============================================================
# 23. INCIDENT COSTS — correct schema: record_cost not create_incident
# Valid incident_type: data-breach/ddos/insider/misconfiguration/phishing/ransomware/supply-chain/zero-day
# Valid cost_category: PR/business-interruption/customer-notification/forensics/insurance/legal/personnel/recovery/regulatory-fine/tools
# ============================================================
section("23. Incident Costs (/api/v1/incident-costs)")
cost_records = [
    ("INC-2026-001", "Ransomware Attack - Partial Encryption",   "ransomware",      "forensics",              45000,  False, "External IR firm engagement"),
    ("INC-2026-001", "Ransomware Attack - Partial Encryption",   "ransomware",      "legal",                  85000,  False, "Legal counsel for regulatory notification"),
    ("INC-2026-001", "Ransomware Attack - Partial Encryption",   "ransomware",      "business-interruption",  250000, False, "48-hour production outage costs"),
    ("INC-2026-001", "Ransomware Attack - Partial Encryption",   "ransomware",      "recovery",               75000,  False, "System restoration and hardening"),
    ("INC-2025-047", "Phishing - 12 Accounts Compromised",       "phishing",        "forensics",              15000,  False, "Account forensics and password reset ops"),
    ("INC-2025-047", "Phishing - 12 Accounts Compromised",       "phishing",        "personnel",              8000,   False, "Overtime for security team response"),
    ("INC-2025-031", "S3 Bucket Data Exposure",                  "misconfiguration","legal",                  120000, False, "GDPR notification and legal fees"),
    ("INC-2025-031", "S3 Bucket Data Exposure",                  "misconfiguration","regulatory-fine",        75000,  False, "Regulatory fine assessment"),
    ("INC-2025-031", "S3 Bucket Data Exposure",                  "misconfiguration","customer-notification",  12000,  False, "Breach notification to 45K customers"),
    ("INC-2025-018", "DDoS Attack - 4 Hour Outage",              "ddos",            "business-interruption",  85000,  False, "Revenue loss during outage window"),
    ("INC-2025-009", "Insider Data Exfiltration",                "insider",         "forensics",              65000,  False, "Full forensic investigation of exfiltration"),
    ("INC-2025-009", "Insider Data Exfiltration",                "insider",         "legal",                  95000,  False, "Litigation and civil proceedings"),
]
for inc_id, inc_name, inc_type, cost_cat, amount, estimated, desc in cost_records:
    post(f"/api/v1/incident-costs/costs?org_id={ORG}", {
        "incident_id": inc_id,
        "incident_name": inc_name,
        "incident_type": inc_type,
        "cost_category": cost_cat,
        "amount": amount,
        "currency": "USD",
        "estimated": estimated,
        "description": desc,
        "recorded_by": "security-finance@company.com",
    })
print(f"  -> incident-costs (total costs): {get_count('/api/v1/incident-costs/costs')}")

# ============================================================
# 24. SOAR EXECUTIONS
# ============================================================
section("24. SOAR Executions (/api/v1/soar)")
existing = get_count('/api/v1/soar/executions')
print(f"  -> existing executions: {existing}")
soar_playbooks = [
    "soar-default-compliance", "soar-default-insider",
    "soar-default-anomaly",    "soar-default-sla",    "soar-default-incident",
]
for pb_id in soar_playbooks:
    post(f"/api/v1/soar/playbooks/{pb_id}/execute", {
        "context": {"alert_id": f"ALT-{pb_id[-4:]}-001", "severity": "high", "auto_triggered": True},
        "org_id": ORG,
    })
    post(f"/api/v1/soar/playbooks/{pb_id}/execute", {
        "context": {"incident_id": "INC-2026-001", "severity": "critical"},
        "org_id": ORG,
    })
print(f"  -> soar/executions: {get_count('/api/v1/soar/executions')}")

# ============================================================
# 25. SCHEDULED REPORTS — correct schema (name, not report_name)
# ============================================================
section("25. Scheduled Reports (/api/v1/scheduled-reports)")
report_schedules = [
    ("Weekly Security Digest",          "security_summary",  "weekly",    8,  ["ciso@company.com", "security-team@company.com"]),
    ("Monthly Executive Risk Report",   "executive_summary", "monthly",   9,  ["ceo@company.com", "cfo@company.com"]),
    ("Daily Threat Intelligence Brief", "threat_intel",      "daily",     7,  ["soc@company.com"]),
    ("Quarterly Compliance Status",     "compliance_report", "quarterly", 10, ["compliance@company.com"]),
    ("Weekly Vulnerability Summary",    "vuln_summary",      "weekly",    8,  ["vuln-team@company.com"]),
]
for name, rtype, freq, hour, recipients in report_schedules:
    post(f"/api/v1/scheduled-reports/schedules?org_id={ORG}", {
        "name": name,
        "report_type": rtype,
        "frequency": freq,
        "hour_utc": hour,
        "recipients": recipients,
        "format": "json",
    })
print(f"  -> scheduled-reports/schedules: {get_count('/api/v1/scheduled-reports/schedules')}")

# ============================================================
# 26. TIP IOCs — check correct path
# ============================================================
section("26. TIP IOCs (/api/v1/tip)")
# Try ioc_value field (tip engine uses different field name)
r = post(f"/api/v1/tip/iocs?org_id={ORG}", {
    "ioc_value": "185.220.101.47",
    "ioc_type": "ip",
    "severity": "critical",
    "confidence": 0.95,
    "tlp": "red",
    "source": "threat_intel",
    "tags": ["apt29", "c2"],
})
if r is None:
    # Try different field names
    r2 = post(f"/api/v1/tip/iocs?org_id={ORG}", {
        "value": "185.220.101.47",
        "type": "ip",
        "severity": "critical",
        "confidence": 0.95,
        "tlp_level": "red",
    })
print(f"  -> tip/iocs: {get_count('/api/v1/tip/iocs')}")

# ============================================================
# 27. RISK QUANT — check actual prefix in app.py
# ============================================================
section("27. Risk Quantification (/api/v1/risk-quantification)")
existing = get_count('/api/v1/risk-quantification/scenarios')
print(f"  -> existing risk-quantification/scenarios: {existing}")
if existing in ("0", "dict:empty", "err"):
    rq_scenarios = [
        ("Ransomware Attack Core Infrastructure",  "cybercriminal",  "phishing",      "infrastructure", 60.0, 500000.0, 3500000.0, 0.8),
        ("Supply Chain Compromise via Vendor",     "nation_state",   "supply_chain",  "application",    40.0, 800000.0, 8500000.0, 0.3),
        ("Insider Data Exfiltration",              "insider",        "credential",    "data",           30.0, 200000.0, 2500000.0, 1.2),
        ("Phishing-based BEC Attack",              "cybercriminal",  "phishing",      "personnel",      70.0, 50000.0,  450000.0,  3.0),
        ("DDoS on Customer Portal",               "hacktivist",     "zero_day",      "infrastructure", 60.0, 25000.0,  200000.0,  6.0),
    ]
    for name, actor, vector, asset_type, like, min_loss, max_loss, freq in rq_scenarios:
        post(f"/api/v1/risk-quantification/scenarios?org_id={ORG}", {
            "name": name,
            "threat_actor": actor,
            "attack_vector": vector,
            "target_asset_type": asset_type,
            "likelihood_pct": like,
            "minimum_loss": min_loss,
            "maximum_loss": max_loss,
            "annual_frequency": freq,
        })
print(f"  -> risk-quantification/scenarios: {get_count('/api/v1/risk-quantification/scenarios')}")

# ============================================================
# FINAL VERIFICATION
# ============================================================
print(f"\n{'='*60}")
print(f"  SEEDING COMPLETE")
print(f"{'='*60}")
print(f"  Successful POSTs: {ok}")
print(f"  Failed POSTs:     {failed}")
print()

print("VERIFICATION — checking all seeded endpoints:")
checks = [
    ("/api/v1/posture-advisor/recommendations",     "posture-advisor/recommendations"),
    ("/api/v1/kpi/current",                         "kpi/current"),
    ("/api/v1/ai-advisor/recommendations",          "ai-advisor/recommendations"),
    ("/api/v1/vuln-prioritization/scored",          "vuln-prioritization/scored"),
    ("/api/v1/vuln-intel/advisories",               "vuln-intel/advisories"),
    ("/api/v1/training-effectiveness/programs",     "training-effectiveness/programs"),
    ("/api/v1/tprm-exchange/vendors",               "tprm-exchange/vendors"),
    ("/api/v1/threat-indicators/indicators",        "threat-indicators/indicators"),
    ("/api/v1/ransomware-protection/detections",    "ransomware-protection/detections"),
    ("/api/v1/privacy-impact/assessments",          "privacy-impact/assessments"),
    ("/api/v1/posture-trends/trends",               "posture-trends/trends"),
    ("/api/v1/posture-history/snapshots",           "posture-history/snapshots"),
    ("/api/v1/network-threats/threats/active",      "network-threats/active"),
    ("/api/v1/security-okrs/objectives",            "security-okrs/objectives"),
    ("/api/v1/security-findings/findings",          "security-findings/findings"),
    ("/api/v1/risk-scenarios/scenarios",            "risk-scenarios/scenarios"),
    ("/api/v1/security-questionnaires/questionnaires","security-questionnaires"),
    ("/api/v1/security-scorecard/scorecards",       "security-scorecard/scorecards"),
    ("/api/v1/attack-paths/nodes",                  "attack-paths/nodes"),
    ("/api/v1/cloud-findings/findings",             "cloud-findings/findings"),
    ("/api/v1/posture-maturity/assessments",        "posture-maturity/assessments"),
    ("/api/v1/threat-attribution/actors",           "threat-attribution/actors"),
    ("/api/v1/incident-costs/costs",                "incident-costs/costs"),
    ("/api/v1/soar/executions",                     "soar/executions"),
    ("/api/v1/scheduled-reports/schedules",         "scheduled-reports/schedules"),
    ("/api/v1/risk-quantification/scenarios",       "risk-quantification/scenarios"),
    ("/api/v1/threat-landscape/actors",             "threat-landscape/actors"),
    ("/api/v1/vuln-scans/scans",                    "vuln-scans/scans"),
    ("/api/v1/asm/assets",                          "asm/assets"),
    ("/api/v1/dark-web/mentions",                   "dark-web/mentions"),
    ("/api/v1/behavioral-analytics/anomalies",      "behavioral-analytics/anomalies"),
    ("/api/v1/risk-register-engine/risks",          "risk-register-engine/risks"),
    ("/api/v1/change-management/changes",           "change-management/changes"),
    ("/api/v1/alert-triage/alerts",                 "alert-triage/alerts"),
    ("/api/v1/patch-management/patches",            "patch-management/patches"),
    ("/api/v1/identity-risk/identities",            "identity-risk/identities"),
]
populated = 0
empty = 0
for path, label in checks:
    count = get_count(path)
    is_ok = count not in ("0", "dict:empty", "err") and not count.startswith("dict:empty")
    if is_ok:
        populated += 1
        status = "OK   "
    else:
        empty += 1
        status = "EMPTY"
    print(f"  [{status}] {label}: {count}")

print(f"\n  Populated endpoints: {populated}/{len(checks)}")
print(f"  Still empty:         {empty}/{len(checks)}")
