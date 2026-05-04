#!/usr/bin/env python3
"""Seed all empty API endpoints with realistic demo data.
Run: python3 scripts/seed_all_empty_endpoints.py
"""
import time
import requests
import sys

TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
BASE = "http://localhost:8000"
ORG = "default"
HDR = {"X-API-Key": TOKEN, "Content-Type": "application/json"}

_ok = 0
_fail = 0
_skip = 0


def post(path, body, delay=0.4, org_in_body=False):
    global _ok, _fail
    time.sleep(delay)
    url = f"{BASE}{path}"
    if "org_id" not in path:
        url += f"?org_id={ORG}"
    if org_in_body and "org_id" not in body:
        body["org_id"] = ORG
    try:
        r = requests.post(url, json=body, headers=HDR, timeout=10)
        if r.status_code in (200, 201):
            _ok += 1
            return True, r.json()
        else:
            _fail += 1
            print(f"  [ERR {r.status_code}] POST {path}: {r.text[:120]}")
            return False, {}
    except Exception as e:
        _fail += 1
        print(f"  [EXC] POST {path}: {e}")
        return False, {}


def get(path, delay=0.2):
    time.sleep(delay)
    url = f"{BASE}{path}?org_id={ORG}"
    try:
        r = requests.get(url, headers=HDR, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, list):
                return len(d)
            elif isinstance(d, dict):
                for k in ("total", "count", "total_count", "items", "data", "records",
                          "assessments", "sources", "models", "policies", "rules"):
                    if k in d:
                        v = d[k]
                        return len(v) if isinstance(v, list) else (v if isinstance(v, int) else 1)
                return 1 if d and "detail" not in d else 0
        return 0
    except Exception:
        return 0


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ─────────────────────────────────────────────────────────────
section("1. Actor Tracking")
actors = [
    {"actor_name": "Lazarus Group",   "actor_type": "nation-state", "origin_country": "KP", "motivation": "financial", "sophistication": "advanced", "aliases": ["Hidden Cobra"]},
    {"actor_name": "FIN7",            "actor_type": "criminal",     "origin_country": "UA", "motivation": "financial", "sophistication": "advanced", "aliases": ["Carbanak"]},
    {"actor_name": "APT29",           "actor_type": "nation-state", "origin_country": "RU", "motivation": "espionage","sophistication": "advanced", "aliases": ["Cozy Bear"]},
    {"actor_name": "Scattered Spider","actor_type": "hacktivist",   "origin_country": "US", "motivation": "financial", "sophistication": "intermediate","aliases": []},
    {"actor_name": "BlackCat/ALPHV",  "actor_type": "criminal",     "origin_country": "RU", "motivation": "financial", "sophistication": "advanced", "aliases": ["ALPHV"]},
]
for a in actors:
    post("/api/v1/actor-tracking/actors", a)
print(f"  Actor tracking: {get('/api/v1/actor-tracking/actors')} records")

# ─────────────────────────────────────────────────────────────
section("2. Vuln Correlation")
for i in range(1, 6):
    ok, res = post("/api/v1/vuln-correlation/assets",
                   {"asset_id": f"asset-{i:03d}", "asset_name": f"server-{i:02d}.internal",
                    "asset_type": "server", "criticality": "high", "ip_address": f"10.0.{i}.10"})
    if ok:
        aid = res.get("asset_id", f"asset-{i:03d}")
        post(f"/api/v1/vuln-correlation/assets/{aid}/vulns",
             {"cve_id": f"CVE-2024-{1000+i}", "cvss": 7.5+i*0.2, "epss": 0.1+i*0.05,
              "kev": i % 2 == 0, "description": f"Critical vuln #{i}"})
print(f"  Vuln correlation: {get('/api/v1/vuln-correlation/assets')} assets")

# ─────────────────────────────────────────────────────────────
section("3. Asset Criticality")
for i, (name, atype, score) in enumerate([
    ("erp-prod-01", "server", 95), ("db-finance-01", "database", 98),
    ("web-app-01",  "application", 85), ("dc-01", "server", 92),
    ("backup-01",   "server", 70), ("vpn-gw", "network_device", 88),
]):
    post("/api/v1/asset-criticality/assets",
         {"asset_name": name, "asset_type": atype,
          "business_impact": "critical" if score > 90 else "high",
          "data_sensitivity": "confidential", "exposure_level": "internal",
          "recovery_time_hours": 4, "dependencies": []})
print(f"  Asset criticality: {get('/api/v1/asset-criticality/assets')} assets")

# ─────────────────────────────────────────────────────────────
section("4. Threat Vectors")
for ttype, risk in [("phishing","high"),("sql_injection","critical"),("ransomware","critical"),
                    ("insider_threat","medium"),("supply_chain","high"),("zero_day","critical")]:
    post("/api/v1/threat-vectors/vectors",
         {"vector_name": ttype.replace("_"," ").title(), "vector_type": ttype,
          "frequency": 7, "impact_score": 8.5, "risk_level": risk,
          "description": f"Active {ttype} threat vector", "mitre_techniques": ["T1566"]})
print(f"  Threat vectors: {get('/api/v1/threat-vectors/vectors')} vectors")

# ─────────────────────────────────────────────────────────────
section("5. TI Automation")
for feed in ["misp-community","abuse-ch","alienvault-otx","emerging-threats","feodo-tracker"]:
    post("/api/v1/ti-automation/feeds",
         {"feed_name": feed, "feed_type": "threat_intel", "feed_url": f"https://{feed}.example.com/feed",
          "format": "stix2", "enabled": True, "poll_interval_minutes": 60})
print(f"  TI automation feeds: {get('/api/v1/ti-automation/feeds')} feeds")

# ─────────────────────────────────────────────────────────────
section("6. Intel Enrichment")
for ioc in ["1.2.3.4","5.6.7.8","malware.example.com","evil.ru"]:
    post("/api/v1/intel-enrichment/requests",
         {"indicator": ioc, "indicator_type": "ip" if "." in ioc and ioc[0].isdigit() else "domain",
          "priority": "high", "sources": ["virustotal","shodan","greynoise"]})
print(f"  Intel enrichment: {get('/api/v1/intel-enrichment/requests')} requests")

# ─────────────────────────────────────────────────────────────
section("7. Posture Reports")
for i, framework in enumerate(["NIST CSF","ISO 27001","CIS Controls","SOC 2","GDPR"]):
    post("/api/v1/posture-reports/reports",
         {"report_name": f"{framework} Posture Report Q1-2026",
          "report_type": "quarterly", "framework": framework,
          "period_start": "2026-01-01", "period_end": "2026-03-31"})
print(f"  Posture reports: {get('/api/v1/posture-reports/reports')} reports")

# ─────────────────────────────────────────────────────────────
section("8. Posture Benchmarking")
for i, framework in enumerate(["CIS Controls","NIST CSF","ISO 27001"]):
    ok, res = post("/api/v1/posture-benchmarking/benchmarks",
                   {"benchmark_name": framework, "framework": framework, "version": "2024",
                    "description": f"{framework} security benchmark"})
    if ok:
        bid = res.get("benchmark_id", "")
        if bid:
            for ctrl in ["AC-1","AC-2","SC-7","SC-28","RA-5"]:
                post(f"/api/v1/posture-benchmarking/benchmarks/{bid}/controls",
                     {"control_id": ctrl, "title": f"Control {ctrl}",
                      "description": f"Security control {ctrl}", "weight": 1.0,
                      "implementation_status": "implemented"}, delay=0.2)
print(f"  Posture benchmarking: {get('/api/v1/posture-benchmarking/benchmarks')} benchmarks")

# ─────────────────────────────────────────────────────────────
section("9. Risk Treatment")
for risk, treat in [("SQL Injection Risk","mitigate"),("Unpatched Servers","remediate"),
                    ("Weak MFA Policy","mitigate"),("Third-party Access","transfer"),
                    ("Legacy Systems","accept")]:
    post("/api/v1/risk-treatment/treatments",
         {"risk_description": risk, "treatment_type": treat,
          "owner": "security-team", "due_date": "2026-06-30",
          "priority": "high", "estimated_cost": 25000})
print(f"  Risk treatments: {get('/api/v1/risk-treatment/treatments')} treatments")

# ─────────────────────────────────────────────────────────────
section("10. Security Benchmarks")
for bname, btype in [("Industry Average 2026","industry"),("Top Quartile","top_quartile"),
                     ("Regulatory Minimum","regulatory"),("Peer Group","peer_group")]:
    post("/api/v1/security-benchmarks/benchmarks",
         {"benchmark_name": bname, "benchmark_type": btype,
          "sample_size": 250, "source": "SANS Security Survey 2026",
          "published_year": 2026, "overall_score": 72.5})
print(f"  Security benchmarks: {get('/api/v1/security-benchmarks/benchmarks')} benchmarks")

# ─────────────────────────────────────────────────────────────
section("11. Security Budget")
for cat, amt in [("tooling",450000),("personnel",1200000),("training",85000),
                 ("compliance",150000),("incident_response",200000),("cloud_security",320000)]:
    post("/api/v1/security-budget/allocations",
         {"category": cat, "allocated_amount": amt, "fiscal_year": 2026,
          "description": f"{cat.replace('_',' ').title()} budget allocation",
          "owner": "CISO", "quarter": "Q1"})
print(f"  Security budget: {get('/api/v1/security-budget/allocations')} allocations")

# ─────────────────────────────────────────────────────────────
section("12. Access Requests")
for user, res in [("alice.johnson","admin_access"),("bob.smith","database_read"),
                  ("carol.white","vpn_access"),("dave.jones","server_ssh"),
                  ("eve.brown","cloud_console")]:
    post("/api/v1/access-requests/requests",
         {"requestor_id": user, "resource_id": res, "access_type": "read",
          "justification": f"Required for {res} duties", "duration_days": 30,
          "urgency": "normal"})
print(f"  Access requests: {get('/api/v1/access-requests/requests')} requests")

# ─────────────────────────────────────────────────────────────
section("13. PAG (Privileged Access Governance)")
for acct, atype in [("svc-backup","service"),("admin-prod","admin"),
                    ("root-db01","admin"),("svc-monitoring","service"),
                    ("deploy-bot","service")]:
    post("/api/v1/pag/accounts",
         {"account_name": acct, "account_type": atype,
          "system": "linux", "owner": "ops-team",
          "last_reviewed": "2026-01-15", "risk_level": "high"})
print(f"  PAG accounts: {get('/api/v1/pag/accounts')} accounts")

# ─────────────────────────────────────────────────────────────
section("14. Session Recording")
for user, stype in [("admin-prod","ssh"),("root-db01","rdp"),
                    ("svc-backup","sftp"),("deploy-bot","api"),("admin-dev","ssh")]:
    post("/api/v1/session-recording/sessions",
         {"user_id": user, "session_type": stype,
          "target_host": f"{user}.internal", "target_ip": "10.0.1.50",
          "duration_seconds": 1800, "commands_count": 45,
          "risk_score": 65.0})
print(f"  Session recording: {get('/api/v1/session-recording/sessions')} sessions")

# ─────────────────────────────────────────────────────────────
section("15. Cloud Posture Findings")
for svc, sev in [("S3 bucket public","critical"),("RDS no encryption","high"),
                 ("IAM wildcard policy","critical"),("SG unrestricted ingress","high"),
                 ("CloudTrail disabled","medium")]:
    post("/api/v1/cloud-posture/findings",
         {"resource_id": f"res-{svc[:8].replace(' ','-')}", "resource_type": "aws_s3",
          "finding_title": svc, "severity": sev,
          "provider": "aws", "region": "us-east-1",
          "remediation": f"Fix: {svc}"})
print(f"  Cloud posture findings: {get('/api/v1/cloud-posture/findings')} findings")

# ─────────────────────────────────────────────────────────────
section("16. Cloud Governance")
for pol, ptype in [("No Public S3","data_protection"),("MFA Required","access_control"),
                   ("Encryption at Rest","encryption"),("Tagging Mandatory","operations"),
                   ("Logging Enabled","compliance")]:
    post("/api/v1/cloud-governance/policies",
         {"policy_name": pol, "policy_type": ptype,
          "provider": "aws", "severity": "high",
          "description": f"Cloud governance: {pol}", "enabled": True})
print(f"  Cloud governance: {get('/api/v1/cloud-governance/policies')} policies")

# ─────────────────────────────────────────────────────────────
section("17. Cloud IR")
for title, sev in [("Ransomware in EC2","critical"),("S3 Data Exfiltration","high"),
                   ("IAM Key Compromise","critical"),("Cryptomining Detected","medium"),
                   ("Lateral Movement AWS","high")]:
    post("/api/v1/cloud-ir/incidents",
         {"title": title, "severity": sev, "provider": "aws",
          "affected_resources": ["ec2-001"], "description": title,
          "detection_source": "cloudtrail"})
print(f"  Cloud IR: {get('/api/v1/cloud-ir/incidents')} incidents")

# ─────────────────────────────────────────────────────────────
section("18. Cloud Cost")
for svc, amt, prev in [("EC2","45000","30000"),("S3","8500","7000"),
                       ("RDS","22000","18000"),("Lambda","3200","2800"),
                       ("CloudFront","5100","4200")]:
    post("/api/v1/cloud-cost/snapshots",
         {"service": svc, "provider": "aws", "region": "us-east-1",
          "current_month_cost": float(amt), "previous_month_cost": float(prev),
          "resource_count": 25})
print(f"  Cloud cost: {get('/api/v1/cloud-cost/anomalies')} anomalies")

# ─────────────────────────────────────────────────────────────
section("19. CWP (Cloud Workload Protection)")
for wl, wtype, provider in [("web-prod-01","container","aws"),("api-svc-02","vm","azure"),
                              ("ml-worker-03","serverless","gcp"),("db-replica","vm","aws"),
                              ("kafka-broker","container","aws")]:
    post("/api/v1/cwp/workloads",
         {"workload_name": wl, "workload_type": wtype, "provider": provider,
          "region": "us-east-1", "risk_score": 65.0,
          "image": f"{wl}:latest", "running": True})
print(f"  CWP workloads: {get('/api/v1/cwp/workloads')} workloads")

# ─────────────────────────────────────────────────────────────
section("20. SSPM")
for app, cat in [("Salesforce","crm"),("Slack","collaboration"),("GitHub","devtools"),
                 ("Okta","identity"),("Zoom","collaboration"),("Jira","project_mgmt")]:
    post("/api/v1/sspm/apps",
         {"app_name": app, "app_category": cat, "vendor": app,
          "users_count": 150, "data_sensitivity": "confidential",
          "oauth_scopes": ["read","write"], "mfa_enabled": True})
print(f"  SSPM apps: {get('/api/v1/sspm/apps')} apps")

# ─────────────────────────────────────────────────────────────
section("21. Network Forensics")
for cap, iface in [("capture-2026-001","eth0"),("capture-2026-002","eth1"),
                   ("capture-2026-003","eth0"),("capture-2026-004","bond0")]:
    post("/api/v1/network-forensics/captures",
         {"capture_name": cap, "interface": iface,
          "filter_expression": "port 443 or port 80",
          "duration_seconds": 3600, "trigger": "incident"})
print(f"  Network forensics: {get('/api/v1/network-forensics/captures')} captures")

# ─────────────────────────────────────────────────────────────
section("22. Network Segmentation")
for seg, stype in [("DMZ","dmz"),("Corp-LAN","internal"),("PCI-Zone","pci"),
                   ("OT-Network","ot"),("Guest-WiFi","guest"),("Cloud-VPC","cloud")]:
    post("/api/v1/network-segmentation/segments",
         {"segment_name": seg, "segment_type": stype,
          "cidr": f"10.{len(seg)%10}.0.0/24", "vlan_id": 100+len(seg),
          "security_level": "high", "description": f"{seg} network segment"})
print(f"  Network segmentation: {get('/api/v1/network-segmentation/segments')} segments")

# ─────────────────────────────────────────────────────────────
section("23. Microsegmentation")
for seg, stype in [("web-tier","application"),("app-tier","application"),
                   ("db-tier","database"),("mgmt-zone","management"),
                   ("dmz","dmz")]:
    post("/api/v1/microsegmentation/segments",
         {"segment_name": seg, "segment_type": stype,
          "description": f"Microsegment: {seg}",
          "allowed_protocols": ["tcp","udp"], "default_deny": True})
print(f"  Microsegmentation: {get('/api/v1/microsegmentation/segments')} segments")

# ─────────────────────────────────────────────────────────────
section("24. MDM Devices")
for host, platform in [("iphone-alice","ios"),("macbook-bob","macos"),
                       ("android-carol","android"),("surface-dave","windows"),
                       ("ipad-eve","ios")]:
    post("/api/v1/mdm/devices",
         {"device_name": host, "platform": platform,
          "serial_number": f"SN-{host.upper()[:8]}",
          "owner_id": host.split("-")[1], "enrollment_type": "supervised",
          "os_version": "17.4"})
print(f"  MDM devices: {get('/api/v1/mdm/devices')} devices")

# ─────────────────────────────────────────────────────────────
section("25. Mobile App Security")
for app, platform in [("ALDECI Mobile","ios"),("ALDECI Mobile","android"),
                      ("FieldOps App","ios"),("FieldOps App","android"),
                      ("SecureVault","ios")]:
    post("/api/v1/mobile-app-security/apps",
         {"app_name": app, "platform": platform,
          "app_version": "2.1.0", "bundle_id": f"com.aldeci.{app.lower().replace(' ','.')}",
          "team": "mobile-dev", "store": "enterprise"})
print(f"  Mobile app security: {get('/api/v1/mobile-app-security/apps')} apps")

# ─────────────────────────────────────────────────────────────
section("26. Security Chaos Experiments")
for exp, etype in [("DB Failover","availability"),("Network Partition","network"),
                   ("Auth Service Down","availability"),("CPU Exhaustion","resource"),
                   ("Cert Expiry Simulation","security")]:
    post("/api/v1/security-chaos/experiments",
         {"experiment_name": exp, "experiment_type": etype,
          "target_system": "production", "hypothesis": f"System survives {exp}",
          "blast_radius": "low", "duration_seconds": 300})
print(f"  Chaos experiments: {get('/api/v1/security-chaos/experiments')} experiments")

# ─────────────────────────────────────────────────────────────
section("27. AI-Powered SOC")
for sig, sev in [("Lateral Movement Detected","critical"),("C2 Beacon Pattern","high"),
                 ("Privilege Escalation","critical"),("Data Staging Activity","high"),
                 ("Unusual Auth Pattern","medium")]:
    post("/api/v1/ai-soc/detections",
         {"signal_description": sig, "severity": sev,
          "confidence_score": 0.87, "source_system": "xdr",
          "entity_id": "host-prod-01", "entity_type": "host",
          "mitre_technique": "T1078"})
print(f"  AI SOC detections: {get('/api/v1/ai-soc/detections')} detections")

# ─────────────────────────────────────────────────────────────
section("28. Hunting Playbooks")
for pb, ttype in [("Ransomware Hunt","ransomware"),("Lateral Movement Hunt","lateral_movement"),
                  ("C2 Beacon Hunt","c2"),("Data Exfil Hunt","exfiltration"),
                  ("Privilege Abuse Hunt","privilege_escalation")]:
    post("/api/v1/hunting-playbooks/playbooks",
         {"playbook_name": pb, "threat_type": ttype,
          "description": f"Hunt for {pb}", "author": "threat-hunt-team",
          "mitre_tactics": ["TA0001","TA0002"],
          "steps": [{"step": 1, "action": "Query SIEM for IOCs"}]})
print(f"  Hunting playbooks: {get('/api/v1/hunting-playbooks/playbooks')} playbooks")

# ─────────────────────────────────────────────────────────────
section("29. Awareness Gamification")
for ch, ctype in [("Phishing Quiz","quiz"),("Password Challenge","quiz"),
                  ("MFA Setup","task"),("Incident Report Drill","simulation"),
                  ("Security Policy Ack","acknowledgement")]:
    post("/api/v1/awareness-gamification/challenges",
         {"challenge_name": ch, "challenge_type": ctype,
          "points": 100, "difficulty": "medium",
          "description": f"Complete: {ch}", "time_limit_minutes": 15})
print(f"  Awareness gamification: {get('/api/v1/awareness-gamification/challenges')} challenges")

# ─────────────────────────────────────────────────────────────
section("30. GDPR")
for activity, basis in [("User Registration","consent"),("Marketing Emails","consent"),
                         ("Analytics Processing","legitimate_interest"),
                         ("HR Data Processing","contract"),("Audit Logging","legal_obligation")]:
    post("/api/v1/gdpr/activities",
         {"activity_name": activity, "lawful_basis": basis,
          "data_categories": ["personal","contact"], "data_subjects": ["employees"],
          "retention_period_days": 365, "processor": "internal",
          "cross_border_transfer": False})
print(f"  GDPR activities: {get('/api/v1/gdpr/activities')} activities")

# ─────────────────────────────────────────────────────────────
section("31. Data Retention")
for pol, dtype in [("Email Retention","email"),("Log Retention","logs"),
                   ("HR Records","hr_data"),("Financial Records","financial"),
                   ("Security Events","security_logs")]:
    post("/api/v1/data-retention/policies",
         {"policy_name": pol, "data_type": dtype,
          "retention_days": 2555, "legal_basis": "compliance",
          "action_on_expiry": "delete", "applies_to": ["all_orgs"]})
print(f"  Data retention: {get('/api/v1/data-retention/policies')} policies")

# ─────────────────────────────────────────────────────────────
section("32. Third-Party Vendor")
for vendor, cat in [("CrowdStrike","security_software"),("Splunk","security_software"),
                    ("AWS","cloud_provider"),("Okta","identity"),
                    ("PaloAlto","network_security")]:
    post("/api/v1/third-party-vendor/vendors",
         {"vendor_name": vendor, "vendor_category": cat,
          "risk_level": "medium", "contract_value": 150000,
          "data_access": True, "last_assessment_date": "2026-01-15"})
print(f"  Third-party vendors: {get('/api/v1/third-party-vendor/vendors')} vendors")

# ─────────────────────────────────────────────────────────────
section("33. Vendor Compliance")
for vendor, framework in [("CrowdStrike","SOC2"),("Splunk","ISO27001"),
                           ("AWS","PCI-DSS"),("Okta","SOC2"),("Okta","ISO27001")]:
    post("/api/v1/vendor-compliance/vendors",
         {"vendor_name": vendor, "framework": framework,
          "compliance_status": "compliant", "last_audit_date": "2026-01-01",
          "certificate_expiry": "2027-01-01", "auditor": "Big4-Audit"})
print(f"  Vendor compliance: {get('/api/v1/vendor-compliance/vendors')} vendors")

# ─────────────────────────────────────────────────────────────
section("34. Supply Chain Attacks")
for pkg, eco in [("log4j","maven"),("xz-utils","linux"),("event-stream","npm"),
                 ("colors","npm"),("node-ipc","npm")]:
    post("/api/v1/supply-chain-attacks/packages",
         {"package_name": pkg, "ecosystem": eco,
          "version": "1.0.0", "compromised": True,
          "cve_ids": ["CVE-2021-44228"], "severity": "critical",
          "description": f"Supply chain compromise: {pkg}"})
print(f"  Supply chain attacks: {get('/api/v1/supply-chain-attacks/packages')} packages")

# ─────────────────────────────────────────────────────────────
section("35. Supply Chain Monitoring")
for supplier, cat in [("GitHub","devtools"),("npm Registry","package_registry"),
                      ("DockerHub","container_registry"),("PyPI","package_registry"),
                      ("Maven Central","package_registry")]:
    post("/api/v1/supply-chain-monitoring/suppliers",
         {"supplier_name": supplier, "category": cat,
          "risk_level": "medium", "monitoring_enabled": True,
          "contact_email": f"security@{supplier.lower().replace(' ','')}.com"})
print(f"  Supply chain monitoring: {get('/api/v1/supply-chain-monitoring/suppliers')} suppliers")

# ─────────────────────────────────────────────────────────────
section("36. PKI")
for ca, catype in [("ALDECI Root CA","root"),("ALDECI Intermediate CA","intermediate"),
                   ("TLS Issuing CA","issuing"),("Code Signing CA","issuing")]:
    post("/api/v1/pki/certificates",
         {"common_name": ca, "cert_type": "ca",
          "subject_dn": f"CN={ca},O=ALDECI,C=US",
          "validity_days": 3650, "key_algorithm": "RSA",
          "key_size": 4096, "issuer": "ALDECI Root CA"})
print(f"  PKI certs: {get('/api/v1/pki/cas')} CAs")

# ─────────────────────────────────────────────────────────────
section("37. Metrics Dashboard")
for dash, dtype in [("Executive Overview","executive"),("SOC Operations","operational"),
                    ("Compliance Status","compliance"),("Threat Intelligence","threat"),
                    ("Vulnerability Management","vulnerability")]:
    post("/api/v1/metrics-dashboard/dashboards",
         {"dashboard_name": dash, "dashboard_type": dtype,
          "description": f"{dash} dashboard", "refresh_interval_minutes": 5,
          "is_public": False})
print(f"  Metrics dashboards: {get('/api/v1/metrics-dashboard/dashboards')} dashboards")

# ─────────────────────────────────────────────────────────────
section("38. Regulatory Reporting")
for reg, framework in [("GDPR Article 30","gdpr"),("SOC2 Annual Report","soc2"),
                       ("PCI-DSS SAQ","pci-dss"),("HIPAA Risk Analysis","hipaa"),
                       ("ISO 27001 Audit","iso27001")]:
    post("/api/v1/regulatory-reporting/regulations",
         {"regulation_name": reg, "framework": framework,
          "reporting_period": "2026-Q1", "due_date": "2026-06-30",
          "status": "in_progress", "responsible_team": "compliance"})
print(f"  Regulatory reporting: {get('/api/v1/regulatory-reporting/reports')} reports")

# ─────────────────────────────────────────────────────────────
section("39. Policy Enforcement")
for pol, ptype in [("Password Policy","identity"),("Encryption Policy","data"),
                   ("Access Control Policy","access"),("Incident Response Policy","operations"),
                   ("Acceptable Use Policy","governance")]:
    post("/api/v1/policy-enforcement/policies",
         {"policy_name": pol, "policy_type": ptype,
          "version": "1.0", "status": "active",
          "enforcement_mode": "blocking", "description": f"{pol} enforcement"})
print(f"  Policy enforcement: {get('/api/v1/policy-enforcement/policies')} policies")

# ─────────────────────────────────────────────────────────────
section("40. Malware Analysis")
for sample, mtype in [("emotet.exe","trojan"),("wannacry.bin","ransomware"),
                      ("cobalt_strike.dll","rat"),("mimikatz.exe","credential_stealer"),
                      ("njrat.exe","rat")]:
    post("/api/v1/malware-analysis/samples",
         {"file_name": sample, "malware_type": mtype,
          "file_hash": f"deadbeef{len(sample):04x}cafebabe{len(mtype):04x}",
          "file_size": 204800, "submission_source": "endpoint",
          "priority": "high"})
print(f"  Malware samples: {get('/api/v1/malware-analysis/samples')} samples")

# ─────────────────────────────────────────────────────────────
section("41. Threat Modeling Pipeline")
for model, system in [("Web App Threat Model","ALDECI Web App"),
                       ("API Gateway Model","API Gateway"),
                       ("Cloud Infra Model","AWS Infrastructure"),
                       ("Mobile App Model","ALDECI Mobile"),
                       ("CI/CD Pipeline Model","Build Pipeline")]:
    post("/api/v1/threat-modeling-pipeline/models",
         {"model_name": model, "system_name": system,
          "methodology": "STRIDE", "description": f"Threat model for {system}",
          "team": "security-architecture"})
print(f"  Threat models: {get('/api/v1/threat-modeling-pipeline/models')} models")

# ─────────────────────────────────────────────────────────────
section("42. Arch Review")
for review, rtype in [("API Gateway Security Review","design"),
                       ("Cloud Migration Review","migration"),
                       ("Zero Trust Architecture Review","design"),
                       ("Container Platform Review","implementation"),
                       ("SSO Integration Review","design")]:
    post("/api/v1/arch-review/reviews",
         {"review_name": review, "review_type": rtype,
          "system_name": review.replace(" Review",""),
          "reviewer": "security-architecture-team",
          "scheduled_date": "2026-05-01"})
print(f"  Arch reviews: {get('/api/v1/arch-review/reviews')} reviews")

# ─────────────────────────────────────────────────────────────
section("43. Program Maturity")
for prog, domain in [("Security Awareness Program","training"),
                      ("Vulnerability Management Program","vulnerability"),
                      ("Incident Response Program","operations"),
                      ("Identity Governance Program","identity"),
                      ("Cloud Security Program","cloud")]:
    post("/api/v1/program-maturity/assessments",
         {"program_name": prog, "domain": domain,
          "current_maturity": 3, "target_maturity": 4,
          "assessor": "security-team", "assessment_date": "2026-01-15"})
print(f"  Program maturity: {get('/api/v1/program-maturity/assessments')} assessments")

# ─────────────────────────────────────────────────────────────
section("44. IAM Policy")
for pol, principal in [("AdminAccess","arn:aws:iam::123456789:role/Admin"),
                        ("S3FullAccess","arn:aws:iam::123456789:user/svc-backup"),
                        ("EC2PowerUser","arn:aws:iam::123456789:role/DevOps"),
                        ("LambdaExecution","arn:aws:iam::123456789:role/Lambda"),
                        ("ReadOnlyAccess","arn:aws:iam::123456789:user/analyst")]:
    post("/api/v1/iam-policy/policies",
         {"policy_name": pol, "principal": principal,
          "policy_document": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*"}]},
          "policy_type": "managed"})
print(f"  IAM policies: {get('/api/v1/iam-policy/policies')} policies")

# ─────────────────────────────────────────────────────────────
section("45. Service Account Auditor")
for acct, sys in [("svc-jenkins","ci-cd"),("svc-terraform","iac"),
                  ("svc-splunk","siem"),("svc-crowdstrike","edr"),
                  ("svc-ansible","automation")]:
    post("/api/v1/service-account-auditor/accounts",
         {"account_name": acct, "system": sys,
          "owner": "platform-team", "permissions": ["read","write"],
          "last_used": "2026-04-01", "active": True})
print(f"  Service accounts: {get('/api/v1/service-account-auditor/accounts')} accounts")

# ─────────────────────────────────────────────────────────────
section("46. Identity Analytics")
for user, dept in [("alice.johnson","engineering"),("bob.smith","finance"),
                   ("carol.white","hr"),("dave.jones","it"),
                   ("eve.brown","executive")]:
    post("/api/v1/identity-analytics/identities",
         {"user_id": user, "department": dept,
          "role": "employee", "risk_score": 35.0,
          "mfa_enabled": True, "last_active": "2026-04-10"})
print(f"  Identity analytics: {get('/api/v1/identity-analytics/identities')} identities")

# ─────────────────────────────────────────────────────────────
section("47. OT Security")
for asset, atype in [("PLC-Line-01","plc"),("SCADA-Server","scada"),
                     ("HMI-Panel-01","hmi"),("RTU-Pump-01","rtu"),
                     ("Engineering-WS","workstation")]:
    post("/api/v1/ot-security/assets",
         {"asset_name": asset, "asset_type": atype,
          "zone": "level-2", "vendor": "Siemens",
          "firmware_version": "v2.4.1", "network": "OT-LAN",
          "criticality": "high"})
print(f"  OT security assets: {get('/api/v1/ot-security/assets')} assets")

# ─────────────────────────────────────────────────────────────
section("48. Physical Security")
for loc, ltype in [("HQ Building","office"),("Data Center A","datacenter"),
                   ("Data Center B","datacenter"),("Branch Office NYC","office"),
                   ("Server Room 1F","server_room")]:
    post("/api/v1/physical-security/locations",
         {"location_name": loc, "location_type": ltype,
          "address": f"123 Main St, {loc}", "floor": "1",
          "security_level": "high", "access_control": True})
print(f"  Physical security: {get('/api/v1/physical-security/locations')} locations")

# ─────────────────────────────────────────────────────────────
section("49. Log Management")
for src, ltype in [("Firewall Logs","network"),("EDR Telemetry","endpoint"),
                   ("Web App Logs","application"),("DNS Logs","network"),
                   ("Auth Logs","identity"),("CloudTrail","cloud")]:
    post("/api/v1/log-management/sources",
         {"source_name": src, "log_type": ltype,
          "retention_days": 365, "daily_volume_gb": 15.5,
          "format": "syslog", "enabled": True})
print(f"  Log sources: {get('/api/v1/log-management/sources')} sources")

# ─────────────────────────────────────────────────────────────
section("50. WAF")
for title, vuln_type in [("SQLi Block Rule","sql_injection"),
                          ("XSS Block Rule","xss"),
                          ("Path Traversal Rule","path_traversal"),
                          ("Command Injection","command_injection"),
                          ("SSRF Protection","ssrf")]:
    post("/api/v1/waf/rules",
         {"title": title, "vuln_type": vuln_type,
          "severity": "high", "endpoint": "/api/*",
          "description": f"WAF rule: {title}"})
print(f"  WAF rules: {get('/api/v1/waf/rules')} rules")

# ─────────────────────────────────────────────────────────────
section("51. CASB")
for app, cat in [("Salesforce","crm"),("Box","storage"),("Dropbox","storage"),
                 ("Slack","collaboration"),("Google Workspace","productivity")]:
    post("/api/v1/casb/apps",
         {"app_name": app, "app_category": cat,
          "risk_score": 45.0, "users_count": 200,
          "data_sensitivity": "confidential", "sanctioned": True})
print(f"  CASB apps: {get('/api/v1/casb/apps')} apps")

# ─────────────────────────────────────────────────────────────
section("52. NDR")
for src, dst, ftype in [("10.0.1.5","10.0.2.10","internal"),
                         ("192.168.1.100","8.8.8.8","external"),
                         ("10.0.3.15","10.0.1.5","lateral"),
                         ("10.0.2.20","203.0.113.1","external"),
                         ("10.0.1.8","10.0.1.9","internal")]:
    post("/api/v1/ndr/flows",
         {"src_ip": src, "dst_ip": dst, "src_port": 443, "dst_port": 8443,
          "protocol": "TCP", "bytes_sent": 15000, "bytes_recv": 8000,
          "duration_ms": 1200, "flow_type": ftype})
print(f"  NDR flows: {get('/api/v1/ndr/alerts')} alerts")

# ─────────────────────────────────────────────────────────────
section("53. Threat Geolocation")
for ip, country in [("1.2.3.4","CN"),("5.6.7.8","RU"),("9.10.11.12","KP"),
                    ("13.14.15.16","IR"),("17.18.19.20","NG")]:
    post("/api/v1/threat-geolocation/events",
         {"source_ip": ip, "country_code": country,
          "threat_type": "malicious_scan", "severity": "high",
          "latitude": 39.9, "longitude": 116.4,
          "event_count": 150})
print(f"  Threat geolocation: {get('/api/v1/threat-geolocation/events')} events")

# ─────────────────────────────────────────────────────────────
section("54. Tool Inventory")
for tool, ttype in [("CrowdStrike Falcon","edr"),("Splunk SIEM","siem"),
                    ("PaloAlto NGFW","firewall"),("Tenable.io","vulnerability_scanner"),
                    ("Okta","iam"),("CyberArk PAM","pam"),("Qualys VMDR","vulnerability_scanner")]:
    post("/api/v1/tool-inventory/tools",
         {"tool_name": tool, "tool_type": ttype,
          "vendor": tool.split()[0], "version": "latest",
          "license_count": 500, "annual_cost": 85000,
          "deployed": True, "coverage": 95.0})
print(f"  Tool inventory: {get('/api/v1/tool-inventory/tools')} tools")

# ─────────────────────────────────────────────────────────────
section("55. Tabletop Exercises")
for ex, scenario in [("Ransomware Response","ransomware"),
                      ("Data Breach Response","data_breach"),
                      ("Insider Threat Scenario","insider_threat"),
                      ("Supply Chain Attack","supply_chain"),
                      ("DDoS Response","ddos")]:
    post("/api/v1/tabletop/exercises",
         {"exercise_name": ex, "scenario_type": scenario,
          "scheduled_date": "2026-05-15", "duration_hours": 4,
          "facilitator": "CISO", "participants": ["security-team","it-ops","legal"],
          "objectives": [f"Test {ex} procedures"]})
print(f"  Tabletop exercises: {get('/api/v1/tabletop/exercises')} exercises")

# ─────────────────────────────────────────────────────────────
section("56. Threat Deception")
for decoy, dtype in [("fake-admin-account","honeypot_user"),
                     ("honey-db-server","honeypot_system"),
                     ("canary-doc-finance","canary_token"),
                     ("fake-api-key","canary_token"),
                     ("honey-share","honeypot_share")]:
    post("/api/v1/threat-deception/decoys",
         {"decoy_name": decoy, "decoy_type": dtype,
          "description": f"Deception asset: {decoy}",
          "alert_on_access": True, "deployed": True,
          "network_segment": "corp-lan"})
print(f"  Threat deception: {get('/api/v1/threat-deception/decoys')} decoys")

# ─────────────────────────────────────────────────────────────
section("57. Audit Management")
for audit, atype in [("ISO 27001 Audit 2026","external"),
                      ("SOC 2 Type II Audit","external"),
                      ("PCI-DSS QSA Audit","external"),
                      ("Internal Security Audit Q1","internal"),
                      ("GDPR DPA Review","regulatory")]:
    post("/api/v1/audit-management/audits",
         {"audit_name": audit, "audit_type": atype,
          "framework": audit.split()[0], "auditor": "Big4-Firm",
          "scheduled_start": "2026-05-01", "scheduled_end": "2026-06-30",
          "scope": "full_organization"})
print(f"  Audits: {get('/api/v1/audit-management/audits')} audits")

# ─────────────────────────────────────────────────────────────
section("58. UBA")
for user, dept in [("alice.johnson","engineering"),("bob.smith","finance"),
                   ("carol.white","hr"),("dave.jones","it"),
                   ("eve.brown","executive"),("frank.miller","sales")]:
    post("/api/v1/uba/users",
         {"org_id": ORG, "username": user, "department": dept,
          "role": "employee", "status": "active"})
print(f"  UBA users: {get('/api/v1/uba/users')} users")

# ─────────────────────────────────────────────────────────────
section("59. WAF Virtual Patches (via generate)")
# WAF rules already seeded above, add virtual patches
for cve, ep in [("CVE-2021-44228","/api/jndi"),("CVE-2022-22965","/api/spring"),
                ("CVE-2023-44487","/api/h2c")]:
    post("/api/v1/waf/virtual-patches",
         {"cve_id": cve, "endpoint": ep,
          "attack_vector": "remote", "description": f"Virtual patch for {cve}"})

# ─────────────────────────────────────────────────────────────
section("60. XDR Signals")
for stype, sev in [("malware","critical"),("lateral_movement","high"),
                   ("credential_theft","critical"),("c2","high"),
                   ("exfiltration","critical"),("anomaly","medium")]:
    post("/api/v1/xdr/signals",
         {"source_type": "endpoint", "source_system": "crowdstrike",
          "signal_type": stype, "severity": sev,
          "entity_id": "host-prod-01", "entity_type": "host",
          "confidence": 0.88})
print(f"  XDR signals: {get('/api/v1/xdr/signals')} signals")

# ─────────────────────────────────────────────────────────────
section("61. EDR Endpoints")
for host, os_type in [("win-ws-001","windows"),("lin-srv-001","linux"),
                      ("mac-dev-001","macos"),("win-srv-002","windows"),
                      ("lin-db-001","linux")]:
    post("/api/v1/edr/endpoints",
         {"hostname": host, "ip_address": f"10.0.1.{10+len(host)%100}",
          "os_type": os_type, "os_version": "latest",
          "agent_version": "7.12.0", "risk_score": 42.0})
print(f"  EDR endpoints: {get('/api/v1/edr/endpoints')} endpoints")

# ─────────────────────────────────────────────────────────────
section("62. IP Reputation")
for ip, score, cats in [("1.2.3.4",10,["malware","botnet"]),
                         ("5.6.7.8",15,["spam","scanner"]),
                         ("9.10.11.12",5,["tor","proxy"]),
                         ("13.14.15.16",20,["malware"]),
                         ("185.220.101.1",8,["tor","scanner"])]:
    post("/api/v1/ip-reputation/submit",
         {"org_id": ORG, "ip": ip, "reputation_score": score, "categories": cats})
print(f"  IP reputation: {get('/api/v1/ip-reputation/stats')} stats")

# ─────────────────────────────────────────────────────────────
section("63. Security Telemetry")
for ttype, source in [("events_per_second","siem"),("alerts_per_hour","edr"),
                       ("bytes_ingested","firewall"),("mean_detection_time","xdr"),
                       ("false_positive_rate","ids")]:
    post("/api/v1/security-telemetry/datapoints",
         {"telemetry_type": ttype, "source": source,
          "value": 42.5, "unit": "count/s", "tags": {"env": "prod"}})
print(f"  Security telemetry: {get('/api/v1/security-telemetry/datapoints/latest')} latest")

# ─────────────────────────────────────────────────────────────
section("64. Capacity Planning")
for plan, skill in [("SOC Analyst Hiring","soc_analysis"),
                     ("Threat Hunter Hire","threat_hunting"),
                     ("Cloud Security Hire","cloud_security"),
                     ("AppSec Engineer Hire","application_security"),
                     ("IR Specialist Hire","incident_response")]:
    post("/api/v1/capacity-planning/plans",
         {"plan_name": plan, "skill_required": skill,
          "current_headcount": 3, "target_headcount": 5,
          "timeline": "Q3 2026", "priority": "high",
          "estimated_cost": 180000})
print(f"  Capacity plans: {get('/api/v1/capacity-planning/plans')} plans")

# ─────────────────────────────────────────────────────────────
section("65. License Security")
for comp, license_type, eco in [("log4j","Apache-2.0","maven"),
                                   ("openssl","OpenSSL","c"),
                                   ("commons-text","Apache-2.0","maven"),
                                   ("lodash","MIT","npm"),
                                   ("requests","Apache-2.0","pypi")]:
    post("/api/v1/license-security/components",
         {"component_name": comp, "license_type": license_type,
          "ecosystem": eco, "version": "latest",
          "risk_level": "medium", "oss": True})
print(f"  License security: {get('/api/v1/license-security/components')} components")

# ─────────────────────────────────────────────────────────────
section("66. Exception Workflow")
for exc, etype in [("Legacy TLS 1.0 Exception","vulnerability"),
                    ("Unpatched Dev Server","patch"),
                    ("Weak Cipher Suite Dev","cryptography"),
                    ("Shared Admin Account","access_control"),
                    ("HTTP-only internal","encryption")]:
    post("/api/v1/exception-workflow/exceptions",
         {"exception_title": exc, "exception_type": etype,
          "risk_level": "medium", "justification": f"Business need: {exc}",
          "requested_by": "dev-team", "duration_days": 90})
print(f"  Exception workflows: {get('/api/v1/exception-workflow/exceptions')} exceptions")

# ─────────────────────────────────────────────────────────────
section("67. Dependency Mapping")
for asset, atype in [("api-gateway","service"),("auth-service","service"),
                      ("user-db","database"),("payment-svc","service"),
                      ("notification-svc","service")]:
    ok, res = post("/api/v1/dependency-mapping/assets",
                   {"asset_name": asset, "asset_type": atype,
                    "criticality": "high", "team": "platform",
                    "environment": "production"})
    if ok:
        aid = res.get("asset_id","")
        if aid:
            post(f"/api/v1/dependency-mapping/assets/{aid}/dependencies",
                 {"depends_on_id": "user-db-001", "dependency_type": "database",
                  "criticality": "high"}, delay=0.2)
print(f"  Dependency mapping: {get('/api/v1/dependency-mapping/assets')} assets")

# ─────────────────────────────────────────────────────────────
section("68. Dependency Risk")
for dep, eco in [("log4j:2.14.0","maven"),("spring-core:5.3.18","maven"),
                  ("node:14.0.0","docker"),("python:3.8","docker"),
                  ("openssl:1.1.1","linux")]:
    post("/api/v1/dependency-risk/dependencies",
         {"dependency_name": dep.split(":")[0], "version": dep.split(":")[1],
          "ecosystem": eco, "direct": True,
          "known_vulns": 2, "avg_cvss": 7.5})
print(f"  Dependency risk: {get('/api/v1/dependency-risk/dependencies')} deps")

# ─────────────────────────────────────────────────────────────
section("69. SBOM Assets")
for app, atype in [("ALDECI API","application"),("ALDECI UI","application"),
                   ("ALDECI Worker","service"),("ALDECI Auth","service")]:
    ok, res = post("/api/v1/sbom/assets",
                   {"asset_name": app, "asset_type": atype,
                    "asset_version": "2.1.0", "team_owner": "platform",
                    "sbom_format": "cyclonedx"})
    if ok:
        aid = res.get("asset_id","")
        if aid:
            for comp, ver in [("requests","2.28.0"),("fastapi","0.100.0"),("pydantic","2.0.0")]:
                post(f"/api/v1/sbom/assets/{aid}/components",
                     {"component_name": comp, "component_version": ver,
                      "component_type": "library", "ecosystem": "pypi"}, delay=0.15)
print(f"  SBOM assets: {get('/api/v1/sbom/assets')} assets")

# ─────────────────────────────────────────────────────────────
section("70. Ransomware Protection")
# Use correct route - /api/v1/ransomware-protection/
r = requests.get(f"{BASE}/api/v1/ransomware-protection/?org_id={ORG}", headers=HDR, timeout=10)
print(f"  Ransomware protection root: {r.status_code}")
for pat, ptype in [("*.locky","extension_pattern"),("ransom_note.txt","file_pattern"),
                    ("vssadmin delete","command_pattern"),("cryptolocker_mutex","mutex_pattern")]:
    post("/api/v1/ransomware-protection/patterns",
         {"pattern_name": pat, "pattern_type": ptype,
          "description": f"Ransomware indicator: {pat}", "severity": "critical",
          "action": "block"})
print(f"  Ransomware patterns: {get('/api/v1/ransomware-protection/patterns')} patterns")

# ─────────────────────────────────────────────────────────────
section("71. Attack Paths")
node_ids = []
for nid, ntype, name in [("web-01","server","Web Server"),("app-01","server","App Server"),
                           ("db-01","database","Database"),("dc-01","server","Domain Controller"),
                           ("ext-01","external","External Attacker")]:
    ok, res = post("/api/v1/attack-paths/nodes",
                   {"node_id": nid, "node_type": ntype, "name": name, "risk_score": 75.0})
    if ok:
        node_ids.append(nid)
if len(node_ids) >= 2:
    post("/api/v1/attack-paths/edges",
         {"from_node": node_ids[0], "to_node": node_ids[1],
          "protocol": "https", "port": 443})
print(f"  Attack path nodes: {get('/api/v1/attack-paths/nodes')} nodes")

# ─────────────────────────────────────────────────────────────
section("72. Privilege Escalation")
for user, src, dst in [("svc-jenkins","developer","admin"),
                         ("bob.smith","user","domain_admin"),
                         ("svc-ansible","service","root"),
                         ("carol.white","user","sudo"),
                         ("dave.jones","analyst","local_admin")]:
    post("/api/v1/privilege-escalation/detections",
         {"user_id": user, "source_privilege": src, "target_privilege": dst,
          "detection_method": "ueba", "confidence": 0.85,
          "host": "server-prod-01", "technique": "T1078"})
print(f"  Priv escalation: {get('/api/v1/privilege-escalation/detections')} detections")

# ─────────────────────────────────────────────────────────────
section("73. CIEM")
for account, principal in [("123456789012","arn:aws:iam::123456789012:role/Admin"),
                             ("123456789013","arn:aws:iam::123456789013:user/svc-deploy"),
                             ("123456789014","arn:aws:iam::123456789014:role/Lambda")]:
    post("/api/v1/ciem/accounts",
         {"account_id": account,
          "policies": [{"principal": principal,
                        "policy": {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}]})
print(f"  CIEM accounts: {get('/api/v1/ciem/accounts')} accounts")

# ─────────────────────────────────────────────────────────────
section("74. Event Correlation")
for pat, ptype in [("Brute Force Pattern","authentication"),
                    ("Lateral Movement Pattern","network"),
                    ("Data Exfil Pattern","data"),
                    ("Privilege Abuse Pattern","identity"),
                    ("C2 Beacon Pattern","network")]:
    post("/api/v1/event-correlation/patterns",
         {"pattern_name": pat, "pattern_type": ptype,
          "description": f"Correlation: {pat}",
          "severity": "high", "enabled": True,
          "conditions": [{"field": "event_type", "op": "eq", "value": "login_failure"}]})
print(f"  Event correlation: {get('/api/v1/event-correlation/patterns')} patterns")

# ─────────────────────────────────────────────────────────────
section("75. Event Timeline")
for timeline, ttype in [("Ransomware Attack TL","incident"),
                          ("Data Breach TL","incident"),
                          ("Insider Threat TL","investigation"),
                          ("APT Campaign TL","threat"),
                          ("Phishing Campaign TL","incident")]:
    post("/api/v1/event-timeline/timelines",
         {"timeline_name": timeline, "timeline_type": ttype,
          "description": f"Event timeline: {timeline}",
          "start_time": "2026-01-01T00:00:00Z"})
print(f"  Event timelines: {get('/api/v1/event-timeline/timelines')} timelines")

# ─────────────────────────────────────────────────────────────
section("76. Security Baselines")
for bl, framework in [("CIS L1 Baseline","CIS"),("STIG Windows Baseline","STIG"),
                       ("NIST 800-53 Baseline","NIST"),("PCI DSS Baseline","PCI-DSS")]:
    post("/api/v1/security-baselines/",
         {"baseline_name": bl, "framework": framework,
          "description": f"Security baseline: {bl}",
          "version": "2026.1", "controls_count": 50})
print(f"  Security baselines: {get('/api/v1/security-baselines/')} baselines")

# ─────────────────────────────────────────────────────────────
section("77. Gap Analysis")
for analysis, framework in [("NIST CSF Gap Analysis","NIST CSF"),
                              ("ISO 27001 Gap Analysis","ISO 27001"),
                              ("SOC 2 Readiness","SOC 2"),
                              ("PCI DSS Gap","PCI-DSS")]:
    post("/api/v1/gap-analysis/analyses",
         {"analysis_name": analysis, "framework": framework,
          "scope": "enterprise", "assessor": "security-team",
          "target_compliance_pct": 95.0})
print(f"  Gap analyses: {get('/api/v1/gap-analysis/analyses')} analyses")

# ─────────────────────────────────────────────────────────────
section("78. Evidence Vault")
for ev, etype in [("Firewall Config Screenshot","screenshot"),
                   ("Pen Test Report 2026","report"),
                   ("Vulnerability Scan XML","scan_result"),
                   ("Training Completion CSV","training_record"),
                   ("Audit Log Archive","log_archive")]:
    post("/api/v1/evidence-vault/evidence",
         {"evidence_name": ev, "evidence_type": etype,
          "description": ev, "collected_by": "security-team",
          "control_id": "AC-1", "content_hash": f"sha256:{len(ev):064x}"})
print(f"  Evidence vault: {get('/api/v1/evidence-vault/evidence')} items")

# ─────────────────────────────────────────────────────────────
section("79. Evidence Chain")
for case, severity in [("Ransomware Investigation","critical"),
                        ("Insider Threat Case","high"),
                        ("Data Breach Investigation","critical"),
                        ("Fraud Investigation","high")]:
    post("/api/v1/evidence-chain/cases",
         {"case_name": case, "case_type": "investigation",
          "severity": severity, "investigator": "forensics-team",
          "description": case, "opened_at": "2026-01-15T09:00:00Z"})
print(f"  Evidence chains: {get('/api/v1/evidence-chain/cases')} cases")

# ─────────────────────────────────────────────────────────────
section("80. Cyber Threat Models")
for model, methodology in [("API Gateway STRIDE Model","STRIDE"),
                             ("Cloud Infrastructure PASTA","PASTA"),
                             ("Mobile App DREAD Model","DREAD"),
                             ("CI/CD Pipeline Model","STRIDE")]:
    post("/api/v1/cyber-threat-models/models",
         {"model_name": model, "methodology": methodology,
          "system_description": model, "team": "security-architecture",
          "scope": "enterprise"})
print(f"  Cyber threat models: {get('/api/v1/cyber-threat-models/models')} models")

# ─────────────────────────────────────────────────────────────
section("81. Awareness Score / Awareness Metrics")
# Check route variants
r = requests.get(f"{BASE}/api/v1/awareness-score/summary?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Awareness score summary: {r.status_code}")
r2 = requests.get(f"{BASE}/api/v1/awareness-metrics/summary?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Awareness metrics summary: {r2.status_code}")

# ─────────────────────────────────────────────────────────────
section("82. Forensics Readiness")
r = requests.get(f"{BASE}/api/v1/forensics-readiness/summary?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Forensics readiness summary: {r.status_code}")
for src, rtype in [("SIEM Logs","log_source"),("Endpoint Telemetry","endpoint"),
                    ("Network Captures","network"),("Cloud Logs","cloud")]:
    post("/api/v1/forensics-readiness/sources",
         {"source_name": src, "source_type": rtype,
          "retention_days": 180, "enabled": True, "coverage_pct": 88.0})
print(f"  Forensics sources: {get('/api/v1/forensics-readiness/sources')} sources")

# ─────────────────────────────────────────────────────────────
section("83. SCA")
for comp, ver, eco in [("log4j-core","2.17.1","maven"),("spring-web","5.3.23","maven"),
                        ("lodash","4.17.21","npm"),("requests","2.28.2","pypi"),
                        ("openssl","3.0.7","linux")]:
    post("/api/v1/sca/components",
         {"component_name": comp, "component_version": ver, "ecosystem": eco,
          "direct_dependency": True, "license": "Apache-2.0"})
print(f"  SCA components: {get('/api/v1/sca/components')} components")

# ─────────────────────────────────────────────────────────────
section("84. SBOM Export")
for app in ["ALDECI API","ALDECI UI","ALDECI Worker"]:
    post("/api/v1/sbom-export/",
         {"asset_name": app, "format": "cyclonedx", "version": "1.4",
          "include_vulnerabilities": True, "include_licenses": True})
print(f"  SBOM exports: {get('/api/v1/sbom-export/')} exports")

# ─────────────────────────────────────────────────────────────
section("85. SOC Workflow")
for case, priority in [("Ransomware Alert Investigation","critical"),
                         ("Suspicious Login Case","high"),
                         ("DLP Alert Review","medium"),
                         ("Phishing Email Case","high"),
                         ("Insider Threat Case","critical")]:
    post("/api/v1/soc-workflow/workflows",
         {"case_title": case, "priority": priority,
          "assigned_to": "soc-analyst-1", "description": case,
          "source": "alert"})
print(f"  SOC workflows: {get('/api/v1/soc-workflow/cases')} cases")

# ─────────────────────────────────────────────────────────────
section("86. Breach Detection")
for rule, rtype in [("Multiple Failed Logins","brute_force"),
                     ("Large Data Download","data_exfil"),
                     ("New Admin Account","privilege_escalation"),
                     ("Off-hours Access","anomaly"),
                     ("Impossible Travel","anomaly")]:
    post("/api/v1/breach-detection/rules",
         {"rule_name": rule, "rule_type": rtype,
          "description": rule, "severity": "high",
          "enabled": True, "threshold": 5})
print(f"  Breach detection rules: {get('/api/v1/breach-detection/rules')} rules")

# ─────────────────────────────────────────────────────────────
section("87. Threat Hunting")
r = requests.get(f"{BASE}/api/v1/hunting/hunts?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Hunting hunts: {r.status_code} -> {r.text[:100]}")
r2 = requests.get(f"{BASE}/api/v1/threat-hunt/hunts?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Threat hunt hunts: {r2.status_code}")

# ─────────────────────────────────────────────────────────────
section("88. Hunting Automation")
for hunt, trigger in [("Daily IOC Hunt","scheduled"),("Hourly C2 Hunt","scheduled"),
                       ("On-alert Lateral Hunt","event_driven"),
                       ("Weekly Persistence Hunt","scheduled")]:
    post("/api/v1/hunting-automation/hunts",
         {"hunt_name": hunt, "trigger_type": trigger,
          "query": "sourcetype=endpoint action=process_create | stats count by host",
          "data_sources": ["siem","edr"],
          "schedule": "0 */6 * * *"})
print(f"  Hunting automation: {get('/api/v1/hunting-automation/hunts')} hunts")

# ─────────────────────────────────────────────────────────────
section("89. Awareness Program")
for prog, ptype in [("Security Onboarding","onboarding"),
                     ("Annual Security Training","annual"),
                     ("Phishing Awareness","awareness"),
                     ("Executive Briefing Program","executive")]:
    post("/api/v1/awareness-program/programs",
         {"program_name": prog, "program_type": ptype,
          "description": prog, "duration_weeks": 4,
          "target_audience": "all_employees", "mandatory": True})
print(f"  Awareness programs: {get('/api/v1/awareness-program/programs')} programs")

# ─────────────────────────────────────────────────────────────
section("90. Data Lake Security")
for store, stype in [("Security Data Lake","s3"),("SIEM Data Store","elasticsearch"),
                      ("Analytics Warehouse","snowflake"),("Log Archive","s3"),
                      ("Threat Intel DB","postgresql")]:
    post("/api/v1/data-lake-security/stores",
         {"store_name": store, "store_type": stype,
          "provider": "aws", "region": "us-east-1",
          "data_sensitivity": "confidential", "encryption_enabled": True,
          "access_controls": True})
print(f"  Data lake stores: {get('/api/v1/data-lake-security/stores')} stores")

# ─────────────────────────────────────────────────────────────
section("91. Crypto Keys")
for key, algo in [("TLS Signing Key","RSA-4096"),("Encryption Master Key","AES-256"),
                   ("Code Signing Key","ECDSA-P384"),("DB Encryption Key","AES-256"),
                   ("JWT Signing Key","RSA-2048")]:
    post("/api/v1/crypto-keys/keys",
         {"key_name": key, "algorithm": algo,
          "purpose": "encryption", "key_length": 4096,
          "expiry_date": "2027-01-01", "rotation_policy_days": 365})
print(f"  Crypto keys: {get('/api/v1/crypto-keys/expiring')} expiring")

# ─────────────────────────────────────────────────────────────
section("92. Certificates")
for cert, ctype in [("*.aldeci.io","wildcard"),("api.aldeci.io","san"),
                     ("auth.aldeci.io","san"),("Code Signing Cert","code_signing"),
                     ("Internal CA Cert","ca")]:
    post("/api/v1/certificates/",
         {"common_name": cert, "cert_type": ctype,
          "subject_dn": f"CN={cert},O=ALDECI,C=US",
          "issuer": "ALDECI Intermediate CA",
          "valid_from": "2026-01-01", "valid_to": "2027-01-01",
          "san_names": [cert]})
print(f"  Certificates: {get('/api/v1/certificates/expiring')} expiring")

# ─────────────────────────────────────────────────────────────
section("93. Threat Exposure")
r = requests.get(f"{BASE}/api/v1/threat-exposure/summary?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Threat exposure summary: {r.status_code} -> {r.text[:100]}")
for sig, stype in [("CVE-2024-1234 Exploited","vulnerability"),
                    ("Phishing Campaign Active","campaign"),
                    ("DarkWeb Credentials Found","credential"),
                    ("APT29 Targeting Sector","threat_actor")]:
    post("/api/v1/threat-exposure/signals",
         {"signal_name": sig, "signal_type": stype,
          "severity": "high", "confidence": 0.85,
          "source": "threat_intel"})
print(f"  Threat exposure signals: {get('/api/v1/threat-exposure/signals')} signals")

# ─────────────────────────────────────────────────────────────
section("94. Security Posture Scoring (snapshots)")
for domain in ["identity","network","endpoint","cloud","application"]:
    post("/api/v1/posture-scoring/scores",
         {"domain": domain, "score": 72.0 + len(domain),
          "weight": 1.0, "evidence_count": 15, "control_count": 20})
print(f"  Posture scores: {get('/api/v1/posture-scoring/scores')} scores")

# ─────────────────────────────────────────────────────────────
section("95. Health Scorecard")
r = requests.get(f"{BASE}/api/v1/health-scorecard/summary?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Health scorecard summary: {r.status_code} -> {r.text[:100]}")
r2 = requests.get(f"{BASE}/api/v1/health-scorecard/?org_id={ORG}", headers=HDR, timeout=8)
print(f"  Health scorecard root: {r2.status_code}")
for domain, score in [("identity",82),("network",76),("endpoint",88),("cloud",71),("governance",90)]:
    post("/api/v1/health-scorecard/scores",
         {"domain": domain, "score": float(score),
          "weight": 1.0, "controls_passing": 18, "controls_total": 20})

# ─────────────────────────────────────────────────────────────
section("96. Risk Quant / FAIR")
for portfolio in ["Enterprise Risk Portfolio 2026","Cloud Risk Portfolio","Application Risk Portfolio"]:
    post("/api/v1/risk-quant/portfolios",
         {"portfolio_name": portfolio, "methodology": "FAIR",
          "description": portfolio, "owner": "CISO"})
print(f"  Risk quant portfolios: {get('/api/v1/risk-quant/portfolios')} portfolios")

# ─────────────────────────────────────────────────────────────
section("97. Access Governance")
for policy, ptype in [("SoD: Finance-Admin","segregation_of_duties"),
                        ("Role: SecurityAnalyst","role_based"),
                        ("Entitlement: DB-Read","entitlement"),
                        ("Review: ExecAccess","certification")]:
    post("/api/v1/access-governance/policies",
         {"policy_name": policy, "policy_type": ptype,
          "description": policy, "enforcement": "blocking",
          "owner": "iam-team"})
print(f"  Access governance: {get('/api/v1/access-governance/policies')} policies")

# ─────────────────────────────────────────────────────────────
section("98. Identity Lifecycle")
for user, stage in [("alice.johnson","active"),("bob.smith","active"),
                     ("charlie.old","offboarding"),("dave.new","onboarding"),
                     ("eve.contractor","active")]:
    post("/api/v1/identity-lifecycle/identities",
         {"user_id": user, "lifecycle_stage": stage,
          "department": "engineering", "role": "employee",
          "manager": "manager@aldeci.io", "start_date": "2025-01-01"})
print(f"  Identity lifecycle: {get('/api/v1/identity-lifecycle/identities')} identities")

# ─────────────────────────────────────────────────────────────
section("99. Digital Identity")
for user, ial in [("alice.johnson","IAL2"),("bob.smith","IAL1"),
                   ("admin.jones","IAL3"),("svc.account","IAL1")]:
    post("/api/v1/digital-identity/profiles",
         {"user_id": user, "identity_assurance_level": ial,
          "verification_method": "in_person", "authenticator_type": "hardware_key",
          "mfa_enrolled": True})
print(f"  Digital identity: {get('/api/v1/digital-identity/profiles')} profiles")

# ─────────────────────────────────────────────────────────────
section("100. Privileged Identity")
for user, role in [("admin.prod","domain_admin"),("root.db01","db_admin"),
                    ("ciso.alice","ciso"),("svc.deploy","service_account"),
                    ("admin.azure","cloud_admin")]:
    post("/api/v1/privileged-identity/accounts",
         {"account_id": user, "role": role,
          "system": "production", "access_level": "privileged",
          "mfa_required": True, "session_recording": True})
print(f"  Privileged identity: {get('/api/v1/privileged-identity/summary')} summary")

# ─────────────────────────────────────────────────────────────
section("101. MFA")
for user, method in [("alice.johnson","totp"),("bob.smith","sms"),
                      ("carol.white","hardware_key"),("dave.jones","push"),
                      ("admin.jones","hardware_key")]:
    post("/api/v1/mfa/enrollments",
         {"user_id": user, "method": method,
          "device_name": f"{user}-device", "verified": True})
print(f"  MFA enrollments: {get('/api/v1/mfa/enrollments')} enrollments")

# ─────────────────────────────────────────────────────────────
section("102. Cloud Native Security")
for account, provider in [("123456789012","aws"),("subscription-abc123","azure"),
                            ("project-aldeci-prod","gcp")]:
    post("/api/v1/cloud-native/accounts",
         {"account_id": account, "provider": provider,
          "account_name": f"{provider}-prod", "region": "us-east-1",
          "environment": "production"})
print(f"  Cloud native: {get('/api/v1/cloud-native/accounts')} accounts")

# ─────────────────────────────────────────────────────────────
section("103. Container Registry Security")
for reg, provider in [("hub.docker.com","dockerhub"),("ghcr.io","github"),
                        ("123456789.dkr.ecr.us-east-1.amazonaws.com","ecr")]:
    post("/api/v1/container-registry-security/registries",
         {"registry_name": reg, "provider": provider,
          "url": f"https://{reg}", "scan_on_push": True,
          "auth_required": True})
print(f"  Container registries: {get('/api/v1/container-registry-security/registries')} registries")

# ─────────────────────────────────────────────────────────────
section("104. Network Threats")
for threat, ttype in [("Port Scan from 1.2.3.4","port_scan"),
                        ("DNS Tunneling Detected","dns_tunneling"),
                        ("ARP Spoofing","arp_spoofing"),
                        ("Man-in-the-Middle","mitm"),
                        ("Botnet C2 Traffic","c2_traffic")]:
    post("/api/v1/network-threats/threats",
         {"threat_name": threat, "threat_type": ttype,
          "source_ip": "1.2.3.4", "destination_ip": "10.0.1.5",
          "severity": "high", "protocol": "TCP",
          "confidence": 0.88})
print(f"  Network threats: {get('/api/v1/network-threats/threats')} threats")

# ─────────────────────────────────────────────────────────────
section("105. Network Anomaly")
for iface, metric in [("eth0",1500.0),("eth1",850.0),("bond0",2200.0)]:
    post("/api/v1/network-anomaly/baselines",
         {"interface": iface, "metric_type": "bytes_per_second",
          "baseline_value": metric, "std_deviation": metric * 0.1,
          "sample_count": 1000})
print(f"  Network anomaly: {get('/api/v1/network-anomaly/summary')} summary")

# ─────────────────────────────────────────────────────────────
section("106. Firewall Policy")
for fw, vendor in [("fw-dc-01","paloalto"),("fw-dc-02","paloalto"),
                    ("fw-edge-01","fortinet"),("fw-dmz-01","cisco")]:
    post("/api/v1/firewall-policy/firewalls",
         {"firewall_name": fw, "vendor": vendor,
          "management_ip": f"10.0.0.{10+len(fw)%100}", "version": "11.0.2",
          "ha_enabled": True, "zone": "datacenter"})
print(f"  Firewalls: {get('/api/v1/firewall-policy/firewalls')} firewalls")

# ─────────────────────────────────────────────────────────────
section("107. Bandwidth Analysis")
for link, cap in [("WAN-Link-Primary",1000.0),("WAN-Link-Secondary",500.0),
                   ("DC-Interconnect",10000.0),("Internet-Edge",2000.0)]:
    post("/api/v1/bandwidth-analysis/links",
         {"link_name": link, "capacity_mbps": cap,
          "link_type": "wan", "provider": "ISP-1",
          "monitoring_enabled": True})
print(f"  Bandwidth links: {get('/api/v1/bandwidth-analysis/links')} links")

# ─────────────────────────────────────────────────────────────
section("108. Passive DNS")
for domain, ip in [("malware.example.com","1.2.3.4"),
                    ("c2.evil.ru","5.6.7.8"),
                    ("phishing.badactor.cn","9.10.11.12"),
                    ("legitimate.aldeci.io","10.0.1.100")]:
    post("/api/v1/passive-dns/resolutions",
         {"domain": domain, "resolved_ip": ip,
          "first_seen": "2026-01-01T00:00:00Z",
          "last_seen": "2026-04-15T00:00:00Z",
          "record_type": "A", "ttl": 3600})
print(f"  Passive DNS: {get('/api/v1/passive-dns/resolutions')} resolutions")

# ─────────────────────────────────────────────────────────────
section("109. Wireless Security")
for ap, security in [("AP-Floor1-01","WPA3"),("AP-Floor2-01","WPA3"),
                      ("AP-Conf-Room-01","WPA2"),("AP-Guest-01","WPA2"),
                      ("AP-DC-01","WPA3-Enterprise")]:
    post("/api/v1/wireless-security/access-points",
         {"ap_name": ap, "ssid": f"ALDECI-Corp",
          "security_protocol": security, "band": "5GHz",
          "location": "Building A", "mac_address": f"AA:BB:CC:DD:EE:{len(ap):02x}"})
print(f"  Wireless APs: {get('/api/v1/wireless-security/access-points')} APs")

# ─────────────────────────────────────────────────────────────
section("110. AppSec Findings")
for finding, ftype in [("SQL Injection in /api/login","sqli"),
                         ("XSS in search parameter","xss"),
                         ("Insecure Deserialization","deserialization"),
                         ("Broken Auth in /api/admin","auth"),
                         ("SSRF in image upload","ssrf")]:
    post("/api/v1/appsec/findings",
         {"title": finding, "finding_type": ftype,
          "severity": "high", "cwe": "CWE-89",
          "endpoint": "/api/v1/test", "method": "POST",
          "scanner": "burp_suite"})
print(f"  AppSec findings: {get('/api/v1/appsec/findings')} findings")

# ─────────────────────────────────────────────────────────────
section("111. API Threat Protection")
for rule, ttype in [("Rate Limit Auth","rate_limiting"),
                     ("Block SQLi Patterns","injection"),
                     ("JWT Validation","authentication"),
                     ("Block Bot Traffic","bot_detection"),
                     ("CORS Enforcement","cors")]:
    post("/api/v1/api-threat-protection/rules",
         {"rule_name": rule, "threat_type": ttype,
          "action": "block", "enabled": True,
          "description": rule, "priority": 1})
print(f"  API threat rules: {get('/api/v1/api-threat-protection/rules')} rules")

# ─────────────────────────────────────────────────────────────
print("\n" + "="*60)
print(f"  SEEDING COMPLETE")
print(f"  Successful POSTs: {_ok}")
print(f"  Failed POSTs:     {_fail}")
print("="*60)
