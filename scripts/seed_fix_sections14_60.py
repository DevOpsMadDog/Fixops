#!/usr/bin/env python3
"""Re-seed sections 14-60 that failed in seed_all_empty_endpoints.py due to
wrong field names or a mid-run server drop. Fields corrected against actual
router schemas.
"""
import time
import requests

TOKEN = "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti_5NcdISXSogi_4grP24NAe_XymVfps_"
BASE = "http://localhost:8000"
ORG = "default"
HDR = {"X-API-Key": TOKEN, "Content-Type": "application/json"}

_ok = 0
_fail = 0


def post(path, body, delay=0.3):
    global _ok, _fail
    time.sleep(delay)
    url = f"{BASE}{path}"
    if "org_id" not in path:
        url += f"?org_id={ORG}"
    try:
        r = requests.post(url, json=body, headers=HDR, timeout=15)
        if r.status_code in (200, 201):
            _ok += 1
            return True, r.json()
        else:
            _fail += 1
            print(f"  [ERR {r.status_code}] POST {path}: {r.text[:140]}")
            return False, {}
    except Exception as e:
        _fail += 1
        print(f"  [EXC] POST {path}: {e}")
        return False, {}


def get(path, delay=0.1):
    time.sleep(delay)
    try:
        r = requests.get(f"{BASE}{path}?org_id={ORG}", headers=HDR, timeout=10)
        if r.status_code == 200:
            d = r.json()
            if isinstance(d, list):
                return len(d)
            for k in ("total", "count", "items", "data", "records", "audits",
                      "sources", "models", "policies", "rules", "sessions",
                      "workloads", "apps", "experiments", "challenges",
                      "activities", "suppliers", "vendors", "packages",
                      "benchmarks", "dashboards", "policies", "samples",
                      "playbooks", "allocations", "accounts", "segments",
                      "decoys", "exercises", "users", "tools", "findings",
                      "captures", "detections", "devices"):
                if k in d:
                    v = d[k]
                    return len(v) if isinstance(v, list) else (v if isinstance(v, int) else 1)
            return 1 if d and "detail" not in d else 0
        return 0
    except Exception:
        return 0


def section(n, title):
    print(f"\n{'='*60}\n  {n}. {title}\n{'='*60}")


# ─────────────────────────────────────────────────────────────
section(14, "Session Recording")
# Correct fields: user, session_type, target_host, target_ip, initiated_by
for user, stype in [("admin-prod", "ssh"), ("root-db01", "rdp"),
                    ("svc-backup", "sftp"), ("deploy-bot", "api"),
                    ("admin-dev", "ssh")]:
    post("/api/v1/session-recording/sessions",
         {"user": user, "session_type": stype,
          "target_host": f"{user}.internal", "target_ip": "10.0.1.50",
          "initiated_by": "pam-system"})
print(f"  Session recording: {get('/api/v1/session-recording/sessions')} sessions")

# ─────────────────────────────────────────────────────────────
section(15, "Cloud Posture")
# Requires cloud_account_id — first register an account
ok, res = post("/api/v1/cloud-posture/accounts",
               {"account_id": "aws-prod-123456", "account_name": "AWS Production",
                "provider": "aws", "region": "us-east-1",
                "resource_count": 450, "status": "active", "org_id": ORG})
acct_id = res.get("internal_id", "aws-prod-123456") if ok else "aws-prod-123456"
for title, sev, rtype in [
    ("S3 bucket public", "critical", "storage"),
    ("RDS no encryption", "high", "database"),
    ("IAM wildcard policy", "critical", "iam"),
    ("SG unrestricted ingress", "high", "network"),
    ("CloudTrail disabled", "medium", "compute"),
]:
    post("/api/v1/cloud-posture/findings",
         {"cloud_account_id": acct_id, "resource_id": f"res-{title[:8].replace(' ','-')}",
          "resource_type": rtype, "provider": "aws", "severity": sev,
          "title": title, "description": title,
          "remediation": f"Fix: {title}", "org_id": ORG})
print(f"  Cloud posture accounts: {get('/api/v1/cloud-posture/accounts')} | findings: {get('/api/v1/cloud-posture/findings')}")

# ─────────────────────────────────────────────────────────────
section(16, "Cloud Governance")
# Correct fields: name, policy_type, cloud_provider, enforcement, description
for pol, ptype in [("No Public S3", "security"), ("MFA Required", "access"),
                   ("Encryption at Rest", "security"), ("Tagging Mandatory", "resource"),
                   ("Logging Enabled", "compliance")]:
    post("/api/v1/cloud-governance/policies",
         {"name": pol, "policy_type": ptype,
          "cloud_provider": "aws", "enforcement": "blocking",
          "description": f"Cloud governance: {pol}"})
print(f"  Cloud governance: {get('/api/v1/cloud-governance/policies')} policies")

# ─────────────────────────────────────────────────────────────
section(17, "Cloud IR")
# Correct fields: org_id in body, incident_name, cloud_provider, incident_type, severity
for name, itype, sev in [
    ("Ransomware in EC2", "ransomware", "critical"),
    ("S3 Data Exfiltration", "data_exfiltration", "high"),
    ("IAM Key Compromise", "credential_compromise", "critical"),
    ("Cryptomining Detected", "cryptomining", "medium"),
    ("Lateral Movement AWS", "lateral_movement", "high"),
]:
    post("/api/v1/cloud-ir/incidents",
         {"org_id": ORG, "incident_name": name, "cloud_provider": "aws",
          "incident_type": itype, "severity": sev,
          "affected_services": ["ec2"], "affected_regions": ["us-east-1"]})
print(f"  Cloud IR: {get('/api/v1/cloud-ir/incidents')} incidents")

# ─────────────────────────────────────────────────────────────
section(18, "Cloud Cost")
# Correct fields: org_id, account_id, provider, service_name, region, cost_usd, previous_cost_usd, change_pct, snapshot_date
import datetime
today = datetime.date.today().isoformat()
for svc, cost, prev in [("EC2", 45000, 30000), ("S3", 8500, 7000),
                         ("RDS", 22000, 18000), ("Lambda", 3200, 2800),
                         ("CloudFront", 5100, 4200)]:
    pct = round((cost - prev) / prev * 100, 1)
    post("/api/v1/cloud-cost/snapshots",
         {"org_id": ORG, "account_id": "aws-prod-123456",
          "provider": "aws", "service_name": svc, "region": "us-east-1",
          "cost_usd": float(cost), "previous_cost_usd": float(prev),
          "change_pct": pct, "snapshot_date": today})
print(f"  Cloud cost snapshots: {get('/api/v1/cloud-cost/snapshots')} snapshots")

# ─────────────────────────────────────────────────────────────
section(19, "CWP (Cloud Workload Protection)")
# Correct fields: workload_id, workload_type, name, metadata, org_id
for wl, wtype in [("web-prod-01", "container"), ("api-svc-02", "vm"),
                   ("ml-worker-03", "serverless"), ("db-replica", "vm"),
                   ("kafka-broker", "container")]:
    post("/api/v1/cwp/workloads",
         {"workload_id": wl, "workload_type": wtype,
          "name": wl, "org_id": ORG,
          "metadata": {"image": f"{wl}:latest", "cloud_account": "aws-prod"}})
print(f"  CWP workloads: {get('/api/v1/cwp/workloads')} workloads")

# ─────────────────────────────────────────────────────────────
section(20, "SSPM")
# SSPM uses saas_security_posture_router — POST /apps with app_name, app_category
for app, cat in [("Salesforce", "crm"), ("Slack", "collaboration"),
                  ("GitHub", "devtools"), ("Okta", "identity"),
                  ("Zoom", "collaboration"), ("Jira", "project_mgmt")]:
    post("/api/v1/sspm/apps",
         {"app_name": app, "app_category": cat, "vendor": app,
          "user_count": 150, "data_sensitivity": "confidential",
          "oauth_scopes": "read,write", "mfa_enabled": True})
print(f"  SSPM apps: {get('/api/v1/sspm/apps')} apps")

# ─────────────────────────────────────────────────────────────
section(21, "Network Forensics")
for cap, iface in [("capture-2026-001", "eth0"), ("capture-2026-002", "eth1"),
                    ("capture-2026-003", "eth0"), ("capture-2026-004", "bond0")]:
    post("/api/v1/network-forensics/captures",
         {"capture_name": cap, "interface": iface,
          "filter_expression": "port 443 or port 80",
          "duration_seconds": 3600, "trigger": "incident"})
print(f"  Network forensics: {get('/api/v1/network-forensics/captures')} captures")

# ─────────────────────────────────────────────────────────────
section(22, "Network Segmentation")
# Correct fields: name, cidr, segment_type, trust_level, description
for seg, stype in [("DMZ", "dmz"), ("Corp-LAN", "internal"), ("PCI-Zone", "pci"),
                   ("OT-Network", "ot"), ("Guest-WiFi", "guest"), ("Cloud-VPC", "cloud")]:
    post("/api/v1/network-segmentation/segments",
         {"name": seg, "cidr": f"10.{len(seg)%10}.0.0/24",
          "segment_type": stype, "trust_level": 5,
          "description": f"{seg} network segment"})
print(f"  Network segmentation: {get('/api/v1/network-segmentation/segments')} segments")

# ─────────────────────────────────────────────────────────────
section(23, "Microsegmentation")
# Correct fields: name, cidr, segment_type, trust_level, description
for seg, stype in [("web-tier", "application"), ("app-tier", "application"),
                   ("db-tier", "database"), ("mgmt-zone", "management"),
                   ("dmz", "dmz")]:
    post("/api/v1/microsegmentation/segments",
         {"name": seg, "segment_type": stype,
          "description": f"Microsegment: {seg}",
          "trust_level": 7, "cidr": f"10.20.{len(seg)}.0/24"})
print(f"  Microsegmentation: {get('/api/v1/microsegmentation/segments')} segments")

# ─────────────────────────────────────────────────────────────
section(24, "MDM Devices")
# Correct fields: device_name, platform, model, serial_number, owner_email, enrollment_type, os_version
for host, platform, model in [
    ("iphone-alice", "ios", "iPhone 15 Pro"),
    ("macbook-bob", "macos", "MacBook Pro 14"),
    ("android-carol", "android", "Pixel 8"),
    ("surface-dave", "windows", "Surface Pro 9"),
    ("ipad-eve", "ios", "iPad Air 5"),
]:
    post("/api/v1/mdm/devices",
         {"device_name": host, "platform": platform, "model": model,
          "serial_number": f"SN-{host.upper()[:8]}",
          "owner_email": f"{host.split('-')[1]}@aldeci.io",
          "enrollment_type": "corporate",
          "os_version": "17.4"})
print(f"  MDM devices: {get('/api/v1/mdm/devices')} devices")

# ─────────────────────────────────────────────────────────────
section(25, "Mobile App Security")
# Correct fields: app_name, bundle_id, platform, version, category, risk_score
for app, platform, cat in [
    ("ALDECI Mobile", "ios", "enterprise"),
    ("ALDECI Mobile", "android", "enterprise"),
    ("FieldOps App", "ios", "enterprise"),
    ("FieldOps App", "android", "enterprise"),
    ("SecureVault", "ios", "security"),
]:
    post("/api/v1/mobile-app-security/apps",
         {"app_name": app, "platform": platform,
          "bundle_id": f"com.aldeci.{app.lower().replace(' ', '.')}",
          "version": "2.1.0", "category": cat,
          "risk_score": 35.0, "risk_level": "low"})
print(f"  Mobile app security: {get('/api/v1/mobile-app-security/apps')} apps")

# ─────────────────────────────────────────────────────────────
section(26, "Security Chaos Experiments")
# Correct fields: experiment_name, experiment_type, target_system, hypothesis, expected_outcome
for exp, etype in [("DB Failover", "availability"), ("Network Partition", "network"),
                   ("Auth Service Down", "availability"), ("CPU Exhaustion", "resource"),
                   ("Cert Expiry Simulation", "security")]:
    post("/api/v1/security-chaos/experiments",
         {"experiment_name": exp, "experiment_type": etype,
          "target_system": "production",
          "hypothesis": f"System survives {exp}",
          "expected_outcome": "Auto-recovery within 60s"})
print(f"  Chaos experiments: {get('/api/v1/security-chaos/experiments')} experiments")

# ─────────────────────────────────────────────────────────────
section(27, "AI-Powered SOC")
for sig, sev in [("Lateral Movement Detected", "critical"),
                  ("C2 Beacon Pattern", "high"),
                  ("Privilege Escalation", "critical"),
                  ("Data Staging Activity", "high"),
                  ("Unusual Auth Pattern", "medium")]:
    post("/api/v1/ai-soc/detections",
         {"signal_description": sig, "severity": sev,
          "confidence_score": 0.87, "source_system": "xdr",
          "entity_id": "host-prod-01", "entity_type": "host",
          "mitre_technique": "T1078"})
print(f"  AI SOC detections: {get('/api/v1/ai-soc/detections')} detections")

# ─────────────────────────────────────────────────────────────
section(28, "Hunting Playbooks")
# Correct fields: playbook_name, hunt_type, threat_category, mitre_technique, hypothesis
for pb, htype, cat in [
    ("Ransomware Hunt", "ttp", "ransomware"),
    ("Lateral Movement Hunt", "behavioral", "lateral_movement"),
    ("C2 Beacon Hunt", "ioc", "c2"),
    ("Data Exfil Hunt", "anomaly", "exfiltration"),
    ("Privilege Abuse Hunt", "hypothesis", "privilege_escalation"),
]:
    post("/api/v1/hunting-playbooks/playbooks",
         {"playbook_name": pb, "hunt_type": htype,
          "threat_category": cat,
          "mitre_technique": "T1078",
          "hypothesis": f"Detect {pb} activity",
          "data_sources": ["siem", "edr"],
          "tools": ["kql", "sigma"]})
print(f"  Hunting playbooks: {get('/api/v1/hunting-playbooks/playbooks')} playbooks")

# ─────────────────────────────────────────────────────────────
section(29, "Awareness Gamification")
# Correct fields: title, challenge_type, difficulty, points, department
for ch, ctype in [("Phishing Quiz", "quiz"), ("Password Challenge", "quiz"),
                  ("MFA Setup", "quiz"), ("Incident Report Drill", "quiz"),
                  ("Security Policy Ack", "quiz")]:
    post("/api/v1/awareness-gamification/challenges",
         {"title": ch, "challenge_type": ctype,
          "points": 100, "difficulty": "medium",
          "department": "all"})
print(f"  Awareness gamification: {get('/api/v1/awareness-gamification/challenges')} challenges")

# ─────────────────────────────────────────────────────────────
section(30, "GDPR")
# Correct fields: org_id, name, purpose, lawful_basis, data_categories, recipients, retention_period
for activity, basis in [("User Registration", "consent"),
                         ("Marketing Emails", "consent"),
                         ("Analytics Processing", "legitimate_interest"),
                         ("HR Data Processing", "contract"),
                         ("Audit Logging", "legal_obligation")]:
    post("/api/v1/gdpr/activities",
         {"org_id": ORG, "name": activity, "purpose": f"Process {activity}",
          "lawful_basis": basis,
          "data_categories": ["personal", "contact"],
          "recipients": ["internal"],
          "retention_period": "365 days"})
print(f"  GDPR activities: {get('/api/v1/gdpr/activities')} activities")

# ─────────────────────────────────────────────────────────────
section(31, "Data Retention")
# Correct fields: policy_name, data_category, retention_days, action_on_expiry, legal_hold, regulation
for pol, dtype in [("Email Retention", "email"), ("Log Retention", "logs"),
                   ("HR Records", "hr_data"), ("Financial Records", "financial"),
                   ("Security Events", "security_logs")]:
    post("/api/v1/data-retention/policies",
         {"org_id": ORG, "policy_name": pol, "data_category": dtype,
          "retention_days": 2555, "action_on_expiry": "delete",
          "legal_hold": False, "regulation": "gdpr"})
print(f"  Data retention: {get('/api/v1/data-retention/policies')} policies")

# ─────────────────────────────────────────────────────────────
section(32, "Third-Party Vendor")
# Correct fields: name, vendor_category, website, primary_contact, data_access_level, contract_status
for vendor, cat in [("CrowdStrike", "security_software"),
                    ("Splunk", "security_software"),
                    ("AWS", "cloud_provider"),
                    ("Okta", "identity"),
                    ("PaloAlto", "network_security")]:
    post("/api/v1/third-party-vendor/vendors",
         {"name": vendor, "vendor_category": cat,
          "website": f"https://www.{vendor.lower()}.com",
          "primary_contact": f"security@{vendor.lower()}.com",
          "data_access_level": "confidential",
          "contract_status": "active"})
print(f"  Third-party vendors: {get('/api/v1/third-party-vendor/vendors')} vendors")

# ─────────────────────────────────────────────────────────────
section(33, "Vendor Compliance")
# Correct fields: org_id, name, vendor_category, contract_type, contact_name, contact_email
for vendor, cat in [("CrowdStrike", "saas"), ("Splunk", "saas"),
                    ("AWS", "iaas"), ("Okta", "saas"), ("GitHub", "saas")]:
    post("/api/v1/vendor-compliance/vendors",
         {"org_id": ORG, "name": vendor, "vendor_category": cat,
          "contract_type": "annual",
          "contact_name": f"{vendor} Account Manager",
          "contact_email": f"accounts@{vendor.lower()}.com",
          "contract_start": "2026-01-01", "contract_end": "2027-01-01"})
print(f"  Vendor compliance: {get('/api/v1/vendor-compliance/vendors')} vendors")

# ─────────────────────────────────────────────────────────────
section(34, "Supply Chain Attacks")
# Correct fields: org_id in body, package_name, ecosystem, version, risk_score, attack_type
for pkg, eco in [("log4j", "maven"), ("xz-utils", "linux"),
                  ("event-stream", "npm"), ("colors", "npm"), ("node-ipc", "npm")]:
    post("/api/v1/supply-chain-attacks/packages",
         {"org_id": ORG, "package_name": pkg, "ecosystem": eco,
          "version": "1.0.0", "risk_score": 95.0,
          "attack_type": "malicious_code"})
print(f"  Supply chain attacks: {get('/api/v1/supply-chain-attacks/packages')} packages")

# ─────────────────────────────────────────────────────────────
section(35, "Supply Chain Monitoring")
# Correct fields: org_id, name, supplier_type, risk_tier, contact_email, website
for supplier, stype in [("GitHub", "software"), ("npm Registry", "software"),
                         ("DockerHub", "software"), ("PyPI", "software"),
                         ("Maven Central", "software")]:
    post("/api/v1/supply-chain-monitoring/suppliers",
         {"org_id": ORG, "name": supplier, "supplier_type": "software",
          "risk_tier": "medium",
          "contact_email": f"security@{supplier.lower().replace(' ','')}.com",
          "website": f"https://{supplier.lower().replace(' ','')}.com"})
print(f"  Supply chain monitoring: {get('/api/v1/supply-chain-monitoring/suppliers')} suppliers")

# ─────────────────────────────────────────────────────────────
section(36, "PKI")
# Correct fields: common_name, expires_at, serial_number, issuer, key_algorithm, cert_type
import datetime
future = (datetime.date.today() + datetime.timedelta(days=3650)).isoformat()
for ca, ctype in [("ALDECI Root CA", "root_ca"),
                   ("ALDECI Intermediate CA", "intermediate_ca"),
                   ("TLS Issuing CA", "intermediate_ca"),
                   ("Code Signing CA", "intermediate_ca")]:
    post("/api/v1/pki/certificates",
         {"common_name": ca, "expires_at": f"{future}T00:00:00Z",
          "serial_number": f"SN-{abs(hash(ca)) % 999999:06d}",
          "issuer": "ALDECI Root CA",
          "key_algorithm": "RSA", "key_size": 4096,
          "cert_type": ctype, "status": "active",
          "auto_renew": True, "actor": "pki-admin"})
print(f"  PKI certs: {get('/api/v1/pki/certificates')} certs")

# ─────────────────────────────────────────────────────────────
section(37, "Metrics Dashboard")
# Correct fields: name, dashboard_type, refresh_interval, widgets
for dash, dtype in [("Executive Overview", "executive"),
                    ("SOC Operations", "operational"),
                    ("Compliance Status", "compliance"),
                    ("Threat Intelligence", "threat"),
                    ("Vulnerability Management", "vulnerability")]:
    post("/api/v1/metrics-dashboard/dashboards",
         {"name": dash, "dashboard_type": dtype,
          "refresh_interval": 300, "widgets": []})
print(f"  Metrics dashboards: {get('/api/v1/metrics-dashboard/dashboards')} dashboards")

# ─────────────────────────────────────────────────────────────
section(38, "Regulatory Reporting")
# Check endpoint — use /regulations
for reg, framework in [("GDPR Article 30", "gdpr"), ("SOC2 Annual Report", "soc2"),
                        ("PCI-DSS SAQ", "pci-dss"), ("HIPAA Risk Analysis", "hipaa"),
                        ("ISO 27001 Audit", "iso27001")]:
    post("/api/v1/regulatory-reporting/regulations",
         {"org_id": ORG, "regulation_name": reg, "framework": framework,
          "reporting_period": "2026-Q1", "due_date": "2026-06-30",
          "status": "in_progress", "responsible_team": "compliance"})
print(f"  Regulatory reporting: {get('/api/v1/regulatory-reporting/regulations')} regulations")

# ─────────────────────────────────────────────────────────────
section(39, "Policy Enforcement")
# Correct fields: name, policy_domain, policy_type, enforcement_mechanism, content
for pol, domain in [("Password Policy", "identity"), ("Encryption Policy", "data"),
                    ("Access Control Policy", "access"), ("Incident Response Policy", "operations"),
                    ("Acceptable Use Policy", "governance")]:
    # policy_domain must be network/identity/data/endpoint/cloud/application/physical
    dom_map = {"operations": "endpoint", "governance": "application",
               "access": "identity"}
    post("/api/v1/policy-enforcement/policies",
         {"name": pol, "policy_domain": dom_map.get(domain, domain),
          "policy_type": "mandatory",
          "enforcement_mechanism": "automated",
          "content": f"{pol} enforcement policy v1.0"})
print(f"  Policy enforcement: {get('/api/v1/policy-enforcement/policies')} policies")

# ─────────────────────────────────────────────────────────────
section(40, "Malware Analysis")
# Correct fields: sha256, file_name, file_type, file_size, source
for sample, mtype in [("emotet.exe", "trojan"), ("wannacry.bin", "ransomware"),
                       ("cobalt_strike.dll", "rat"), ("mimikatz.exe", "credential_stealer"),
                       ("njrat.exe", "rat")]:
    sha = f"deadbeef{abs(hash(sample)):016x}"[:64]
    post("/api/v1/malware-analysis/samples",
         {"sha256": sha, "file_name": sample,
          "file_type": mtype, "file_size": 204800,
          "source": "endpoint-edr"})
print(f"  Malware samples: {get('/api/v1/malware-analysis/samples')} samples")

# ─────────────────────────────────────────────────────────────
section(41, "Threat Modeling Pipeline")
for model, system in [("Web App Threat Model", "ALDECI Web App"),
                       ("API Gateway Model", "API Gateway"),
                       ("Cloud Infra Model", "AWS Infrastructure"),
                       ("Mobile App Model", "ALDECI Mobile"),
                       ("CI/CD Pipeline Model", "Build Pipeline")]:
    post("/api/v1/threat-modeling-pipeline/models",
         {"model_name": model, "system_name": system,
          "methodology": "STRIDE", "description": f"Threat model for {system}",
          "team": "security-architecture"})
print(f"  Threat models: {get('/api/v1/threat-modeling-pipeline/models')} models")

# ─────────────────────────────────────────────────────────────
section(42, "Arch Review")
for review, rtype in [("API Gateway Security Review", "design"),
                       ("Cloud Migration Review", "migration"),
                       ("Zero Trust Architecture Review", "design"),
                       ("Container Platform Review", "implementation"),
                       ("SSO Integration Review", "design")]:
    post("/api/v1/arch-review/reviews",
         {"review_name": review, "review_type": rtype,
          "system_name": review.replace(" Review", ""),
          "reviewer": "security-architecture-team",
          "scheduled_date": "2026-05-01"})
print(f"  Arch reviews: {get('/api/v1/arch-review/reviews')} reviews")

# ─────────────────────────────────────────────────────────────
section(43, "Program Maturity")
# Correct: POST /domains with org_id, domain_name, domain_type, target_level (in body)
for prog, domain in [("Vulnerability Management", "technical"),
                      ("Incident Response", "operations"),
                      ("Identity Governance", "governance"),
                      ("Cloud Security", "technical"),
                      ("Security Awareness", "training")]:
    post("/api/v1/program-maturity/domains",
         {"org_id": ORG, "domain_name": prog,
          "domain_type": domain, "target_level": 4})
print(f"  Program maturity: {get('/api/v1/program-maturity/domains')} domains")

# ─────────────────────────────────────────────────────────────
section(44, "IAM Policy")
# Correct fields: policy_name, policy_type, principal_type, principal_id, permissions, resources
for pol, principal_id in [
    ("AdminAccess", "arn:aws:iam::123456789:role/Admin"),
    ("S3FullAccess", "arn:aws:iam::123456789:user/svc-backup"),
    ("EC2PowerUser", "arn:aws:iam::123456789:role/DevOps"),
    ("LambdaExecution", "arn:aws:iam::123456789:role/Lambda"),
    ("ReadOnlyAccess", "arn:aws:iam::123456789:user/analyst"),
]:
    post("/api/v1/iam-policy/policies",
         {"policy_name": pol, "policy_type": "aws_iam",
          "principal_type": "role", "principal_id": principal_id,
          "permissions": ["s3:GetObject", "ec2:DescribeInstances"],
          "resources": ["*"], "conditions": {}, "is_managed": True})
print(f"  IAM policies: {get('/api/v1/iam-policy/policies')} policies")

# ─────────────────────────────────────────────────────────────
section(45, "Service Account Auditor")
# Correct fields: org_id, name, system, permissions, last_used_days_ago
for acct, sys in [("svc-jenkins", "k8s"), ("svc-terraform", "aws"),
                  ("svc-splunk", "linux"), ("svc-crowdstrike", "linux"),
                  ("svc-ansible", "linux")]:
    post("/api/v1/service-account-auditor/accounts",
         {"org_id": ORG, "name": acct, "system": sys,
          "permissions": ["read", "write"],
          "last_used_days_ago": 5})
print(f"  Service accounts: {get('/api/v1/service-account-auditor/accounts')} accounts")

# ─────────────────────────────────────────────────────────────
section(46, "Identity Analytics")
for user, dept in [("alice.johnson", "engineering"), ("bob.smith", "finance"),
                   ("carol.white", "hr"), ("dave.jones", "it-ops"),
                   ("eve.brown", "security")]:
    post("/api/v1/identity-risk/identities",
         {"org_id": ORG, "username": user, "department": dept,
          "role": "analyst", "identity_type": "employee",
          "authentication_methods": ["password", "mfa"]})
print(f"  Identity risk: {get('/api/v1/identity-risk/identities')} identities")

# ─────────────────────────────────────────────────────────────
section(47, "OT Security")
for asset, atype in [("PLC-001", "plc"), ("SCADA-Server-01", "scada"),
                     ("HMI-01", "hmi"), ("RTU-02", "rtu"),
                     ("Historian-01", "historian")]:
    post("/api/v1/ot-sec/assets",
         {"org_id": ORG, "asset_name": asset, "asset_type": atype,
          "vendor": "Siemens", "model": "S7-1500",
          "firmware_version": "2.9.4", "ip_address": f"192.168.100.{len(asset)}",
          "zone": "level_2", "criticality": "high"})
print(f"  OT security assets: {get('/api/v1/ot-sec/assets')} assets")

# ─────────────────────────────────────────────────────────────
section(48, "Physical Security")
for loc, ltype in [("HQ Main Office", "office"), ("Data Center A", "datacenter"),
                   ("Branch Office NYC", "office"), ("Server Room B2", "server_room"),
                   ("DR Site Chicago", "datacenter")]:
    post("/api/v1/physical-security/locations",
         {"org_id": ORG, "location_name": loc, "location_type": ltype,
          "address": f"123 {loc} St", "country": "US",
          "access_control_level": "high", "camera_count": 12})
print(f"  Physical security: {get('/api/v1/physical-security/locations')} locations")

# ─────────────────────────────────────────────────────────────
section(49, "Log Management")
# Correct fields: org_id, name, log_type, format, retention_days, status
for src, ltype in [("AWS CloudTrail", "audit"), ("Okta Logs", "identity"),
                   ("Linux Syslog", "system"), ("Nginx Access", "web"),
                   ("Firewall Logs", "network")]:
    post("/api/v1/log-management/sources",
         {"org_id": ORG, "name": src, "log_type": ltype,
          "format": "json", "retention_days": 365, "status": "active"})
print(f"  Log sources: {get('/api/v1/log-management/sources')} sources")

# ─────────────────────────────────────────────────────────────
section(50, "WAF")
# WAF uses generate endpoint for virtual patches — use /rules directly
for rule, rtype in [("SQL Injection Block", "sqli"), ("XSS Prevention", "xss"),
                    ("CSRF Protection", "csrf"), ("RCE Block", "rce"),
                    ("Path Traversal", "lfi")]:
    post("/api/v1/waf/rules",
         {"org_id": ORG, "rule_name": rule, "rule_type": rtype,
          "action": "block", "severity": "high",
          "pattern": f"(?i)({rtype})", "description": f"Block {rule}"})
print(f"  WAF rules: {get('/api/v1/waf/rules')} rules")

# ─────────────────────────────────────────────────────────────
section(51, "CASB")
# Correct fields: org_id, app_name, app_category, risk_level, users_count
for app, cat in [("Dropbox", "storage"), ("Box", "storage"),
                  ("Slack", "collaboration"), ("Teams", "collaboration"),
                  ("Google Drive", "storage")]:
    post("/api/v1/casb/apps",
         {"org_id": ORG, "app_name": app, "app_category": cat,
          "risk_level": "medium", "users_count": 85})
print(f"  CASB apps: {get('/api/v1/casb/apps')} apps")

# ─────────────────────────────────────────────────────────────
section(52, "NDR")
# Correct fields: src_ip, dst_ip, src_port, dst_port, protocol, bytes_sent, bytes_recv, flow_type
for src, dst, proto, ftype in [
    ("10.0.1.5", "185.220.101.1", "TCP", "c2_suspect"),
    ("10.0.2.10", "10.0.3.20", "TCP", "lateral"),
    ("192.168.1.100", "203.0.113.50", "UDP", "exfiltration_suspect"),
    ("10.0.5.15", "8.8.8.8", "DNS", "external"),
    ("172.16.0.5", "10.0.10.1", "TCP", "internal"),
]:
    post("/api/v1/ndr/flows",
         {"src_ip": src, "dst_ip": dst, "src_port": 52431,
          "dst_port": 443, "protocol": proto,
          "bytes_sent": 1024000, "bytes_recv": 512000,
          "duration_ms": 5000, "flow_type": ftype,
          "mitre_technique": "T1041"})
print(f"  NDR flows: {get('/api/v1/ndr/alerts')} alerts")

# ─────────────────────────────────────────────────────────────
section(53, "Threat Geolocation")
for src_ip, country in [("185.220.101.1", "RU"), ("45.33.32.156", "US"),
                          ("203.0.113.50", "CN"), ("198.51.100.1", "KP"),
                          ("192.0.2.100", "IR")]:
    post("/api/v1/threat-geolocation/events",
         {"org_id": ORG, "source_ip": src_ip, "country_code": country,
          "event_type": "connection", "severity": "high",
          "destination_ip": "10.0.1.50", "destination_port": 443})
print(f"  Threat geolocation: {get('/api/v1/threat-geolocation/events')} events")

# ─────────────────────────────────────────────────────────────
section(54, "Tool Inventory")
# Correct fields: name, vendor, version, tool_category, license_type
for tool, cat, vendor in [
    ("CrowdStrike Falcon", "edr", "CrowdStrike"),
    ("Splunk Enterprise", "siem", "Splunk"),
    ("Tenable.io", "vulnerability_scanner", "Tenable"),
    ("PaloAlto NGFW", "firewall", "Palo Alto"),
    ("Okta IAM", "iam", "Okta"),
]:
    post("/api/v1/tool-inventory/tools",
         {"name": tool, "vendor": vendor,
          "version": "2026.1", "tool_category": cat,
          "license_type": "subscription",
          "license_expiry": f"{future}T00:00:00Z"})
print(f"  Tool inventory: {get('/api/v1/tool-inventory/tools')} tools")

# ─────────────────────────────────────────────────────────────
section(55, "Tabletop Exercises")
# Correct fields: title, scenario_type, status, scheduled_at, facilitator, participant_count
for ex, stype in [("Ransomware Response TTX", "ransomware"),
                   ("Data Breach TTX", "data_breach"),
                   ("BCP/DR TTX", "business_continuity"),
                   ("Insider Threat TTX", "insider_threat"),
                   ("Supply Chain Attack TTX", "supply_chain")]:
    post("/api/v1/tabletop/exercises",
         {"title": ex, "scenario_type": stype,
          "status": "planned",
          "scheduled_at": "2026-05-15T09:00:00Z",
          "facilitator": "security-team-lead",
          "participant_count": 12})
print(f"  Tabletop exercises: {get('/api/v1/tabletop/exercises')} exercises")

# ─────────────────────────────────────────────────────────────
section(56, "Threat Deception")
# Correct fields: name, decoy_type, ip_address, port, description, active
for name, dtype, port in [
    ("Honeypot-DB-01", "honeypot", 5432),
    ("Canary-S3-Bucket", "honeytoken", 443),
    ("Fake-RDP-Server", "fake_service", 3389),
    ("Honey-SSH-01", "honeypot", 22),
    ("Canary-API-Key", "honeytoken", 0),
]:
    post("/api/v1/threat-deception/decoys",
         {"name": name, "decoy_type": dtype,
          "ip_address": "10.0.50.10", "port": port,
          "description": f"Deception asset: {name}", "active": True})
print(f"  Threat deception: {get('/api/v1/threat-deception/decoys')} decoys")

# ─────────────────────────────────────────────────────────────
section(57, "Audit Management")
# Correct fields: name, audit_type, scope, auditor, planned_date
for aname, atype in [("ISO 27001 Audit 2026", "compliance"),
                      ("SOC 2 Type II Audit", "external"),
                      ("Internal Security Review", "internal"),
                      ("PCI-DSS QSA Audit", "compliance"),
                      ("Pentest Review Audit", "security")]:
    post("/api/v1/audit-management/audits",
         {"name": aname, "audit_type": atype,
          "scope": "Full organization", "auditor": "Big4-Firm",
          "planned_date": "2026-06-01"})
print(f"  Audits: {get('/api/v1/audit-management/audits')} audits")

# ─────────────────────────────────────────────────────────────
section(58, "UBA")
# Correct fields: org_id, username, department, role, manager, status
for user, dept in [("alice.johnson", "engineering"), ("bob.smith", "finance"),
                   ("carol.white", "hr"), ("dave.jones", "it-ops"),
                   ("eve.brown", "security"), ("frank.miller", "sales")]:
    post("/api/v1/uba/users",
         {"org_id": ORG, "username": user, "department": dept,
          "role": "analyst", "manager": "manager@aldeci.io",
          "status": "active"})
print(f"  UBA users: {get('/api/v1/uba/users')} users")

# ─────────────────────────────────────────────────────────────
section(59, "WAF Virtual Patches")
for cve, ep in [("CVE-2021-44228", "/api/v1/search"),
                 ("CVE-2022-22965", "/actuator"),
                 ("CVE-2023-34362", "/api/data")]:
    post("/api/v1/waf/virtual-patches",
         {"cve_id": cve, "endpoint": ep,
          "attack_vector": "http", "description": f"Virtual patch for {cve}"})
print(f"  WAF virtual patches: {get('/api/v1/waf/virtual-patches')} patches")

# ─────────────────────────────────────────────────────────────
section(60, "XDR Signals")
for sig_type, sev in [("malware", "critical"), ("lateral_movement", "high"),
                       ("credential_theft", "critical"), ("exfiltration", "high"),
                       ("c2", "high")]:
    post("/api/v1/xdr/signals",
         {"source_type": "endpoint", "source_system": "crowdstrike",
          "signal_type": sig_type, "severity": sev,
          "entity_id": "host-prod-01", "entity_type": "host",
          "raw_data": {"process": "cmd.exe"},
          "confidence": 0.92})
print(f"  XDR signals: {get('/api/v1/xdr/signals')} signals")

# ─────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  FINAL SUMMARY")
print(f"{'='*60}")
print(f"  Total OK:   {_ok}")
print(f"  Total FAIL: {_fail}")
print(f"  Success rate: {round(_ok/(_ok+_fail)*100)}%" if (_ok + _fail) > 0 else "  No requests made")
print()

# Quick probe of all seeded endpoints
endpoints_to_check = [
    ("/api/v1/session-recording/sessions", "Session Recording"),
    ("/api/v1/cloud-posture/accounts", "Cloud Posture"),
    ("/api/v1/cloud-governance/policies", "Cloud Governance"),
    ("/api/v1/cloud-ir/incidents", "Cloud IR"),
    ("/api/v1/cloud-cost/snapshots", "Cloud Cost"),
    ("/api/v1/cwp/workloads", "CWP"),
    ("/api/v1/sspm/apps", "SSPM"),
    ("/api/v1/network-forensics/captures", "Network Forensics"),
    ("/api/v1/network-segmentation/segments", "Network Segmentation"),
    ("/api/v1/microsegmentation/segments", "Microsegmentation"),
    ("/api/v1/mdm/devices", "MDM"),
    ("/api/v1/mobile-app-security/apps", "Mobile App Security"),
    ("/api/v1/security-chaos/experiments", "Security Chaos"),
    ("/api/v1/ai-soc/detections", "AI SOC"),
    ("/api/v1/hunting-playbooks/playbooks", "Hunting Playbooks"),
    ("/api/v1/awareness-gamification/challenges", "Gamification"),
    ("/api/v1/gdpr/activities", "GDPR"),
    ("/api/v1/data-retention/policies", "Data Retention"),
    ("/api/v1/third-party-vendor/vendors", "Third-Party Vendor"),
    ("/api/v1/vendor-compliance/vendors", "Vendor Compliance"),
    ("/api/v1/supply-chain-attacks/packages", "Supply Chain Attacks"),
    ("/api/v1/supply-chain-monitoring/suppliers", "Supply Chain Monitoring"),
    ("/api/v1/pki/certificates", "PKI"),
    ("/api/v1/metrics-dashboard/dashboards", "Metrics Dashboard"),
    ("/api/v1/policy-enforcement/policies", "Policy Enforcement"),
    ("/api/v1/malware-analysis/samples", "Malware Analysis"),
    ("/api/v1/threat-modeling-pipeline/models", "Threat Modeling Pipeline"),
    ("/api/v1/arch-review/reviews", "Arch Review"),
    ("/api/v1/program-maturity/domains", "Program Maturity"),
    ("/api/v1/iam-policy/policies", "IAM Policy"),
    ("/api/v1/service-account-auditor/accounts", "Service Account Auditor"),
    ("/api/v1/identity-risk/identities", "Identity Risk"),
    ("/api/v1/ot-sec/assets", "OT Security"),
    ("/api/v1/physical-security/locations", "Physical Security"),
    ("/api/v1/log-management/sources", "Log Management"),
    ("/api/v1/waf/rules", "WAF Rules"),
    ("/api/v1/casb/apps", "CASB"),
    ("/api/v1/ndr/alerts", "NDR"),
    ("/api/v1/tool-inventory/tools", "Tool Inventory"),
    ("/api/v1/tabletop/exercises", "Tabletop"),
    ("/api/v1/threat-deception/decoys", "Threat Deception"),
    ("/api/v1/audit-management/audits", "Audit Management"),
    ("/api/v1/uba/users", "UBA"),
    ("/api/v1/xdr/signals", "XDR"),
]

print("  Endpoint data counts:")
populated = 0
empty = 0
for path, name in endpoints_to_check:
    count = get(path, delay=0.05)
    status = "OK" if count > 0 else "EMPTY"
    if count > 0:
        populated += 1
    else:
        empty += 1
    print(f"  [{status:5s}] {name}: {count}")

print(f"\n  Endpoints with data: {populated}/{len(endpoints_to_check)}")
print(f"  Still empty:        {empty}/{len(endpoints_to_check)}")
