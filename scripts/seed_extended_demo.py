#!/usr/bin/env python3
"""Extended demo data seeder — seeds alerts, vulns, incidents, assets, compliance, risks, IOCs.

Run from repo root:
    python3 scripts/seed_extended_demo.py
"""
from __future__ import annotations
import sys, random, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-api"))

ORG = "default"
random.seed(42)


def _ts(days_ago=0, hours_ago=0):
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat()


def _date(days_ago=0, days_ahead=0):
    from datetime import date, timedelta as td
    d = date.today() + td(days=days_ahead) - td(days=days_ago)
    return d.isoformat()


# ---------------------------------------------------------------------------
# 1. Alerts (50) via AlertTriageEngine
# ---------------------------------------------------------------------------
def seed_alerts():
    from core.alert_triage_engine import AlertTriageEngine
    e = AlertTriageEngine()

    severities = ["critical", "high", "medium", "low"]
    sources = ["SIEM", "EDR", "NDR", "WAF", "CASB", "CloudTrail", "IDS", "DLP"]
    types = [
        "Ransomware activity detected", "Lateral movement — SMB brute force",
        "Privilege escalation via sudo", "Data exfiltration to unknown IP",
        "Phishing payload executed", "C2 beacon detected", "Credential stuffing attack",
        "Anomalous admin login", "Malware signature match", "DNS tunneling detected",
        "SQL injection attempt", "XSS payload in request", "Crypto-mining process",
        "Unauthorized S3 bucket access", "Root login from unknown location",
        "Port scan from internal host", "Log tampering detected", "MFA bypass attempt",
        "Suspicious PowerShell execution", "Zero-day exploit attempt",
    ]
    mitre_ids = [
        "T1566.001", "T1078", "T1021.002", "T1059.001", "T1055",
        "T1071.001", "T1110.003", "T1048", "T1027", "T1547.001",
    ]

    count = 0
    for i in range(50):
        sev = severities[i % len(severities)]
        src = sources[i % len(sources)]
        alert_type = types[i % len(types)]
        try:
            e.ingest_alert(ORG, {
                "title": f"[{src}] {alert_type}",
                "severity": sev,
                "source": src,
                "alert_type": alert_type,
                "description": f"Automated detection from {src}: {alert_type}. "
                               f"Host: host-{i:03d}.internal. Confidence: {70 + (i % 30)}%.",
                "mitre_technique_id": mitre_ids[i % len(mitre_ids)],
                "asset_id": f"asset-{i % 20:03d}",
                "raw_data": {"confidence": 70 + (i % 30), "count": i + 1},
                "detected_at": _ts(days_ago=i // 5, hours_ago=i % 24),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] alert {i}: {ex}")

    # Triage some alerts to show workflow activity
    try:
        alerts = e.list_alerts(ORG, limit=20)
        for idx, alert in enumerate(alerts[:15]):
            aid = alert.get("alert_id") or alert.get("id")
            if not aid:
                continue
            if idx < 5:
                e.triage_alert(ORG, aid, {"status": "investigating", "assigned_to": "alice@aldeci.io", "notes": "Under investigation"})
            elif idx < 10:
                e.triage_alert(ORG, aid, {"status": "resolved", "assigned_to": "bob@aldeci.io", "notes": "False positive confirmed", "resolution": "false_positive"})
            elif idx < 13:
                e.triage_alert(ORG, aid, {"status": "escalated", "assigned_to": "soc-lead@aldeci.io", "notes": "Escalated to T3"})
    except Exception as ex:
        print(f"  [WARN] triage: {ex}")

    stats = e.get_triage_stats(ORG)
    return {"engine": "AlertTriageEngine", "alerts_seeded": count, "stats": stats}


# ---------------------------------------------------------------------------
# 2. Vulnerabilities (100) via VulnIntelligenceEngine
# ---------------------------------------------------------------------------
def seed_vulnerabilities():
    from core.vuln_intelligence_engine import VulnIntelligenceEngine
    e = VulnIntelligenceEngine()

    products = [
        ("OpenSSL", "3.1.0"), ("Linux Kernel", "6.1.0"), ("Apache HTTP", "2.4.50"),
        ("Django", "4.2.0"), ("nginx", "1.24.0"), ("PostgreSQL", "15.0"),
        ("Redis", "7.0.0"), ("Docker Engine", "24.0.0"), ("Kubernetes", "1.27.0"),
        ("Elasticsearch", "8.0.0"), ("Spring Boot", "3.0.0"), ("Node.js", "20.0.0"),
        ("Python", "3.11.0"), ("Go", "1.21.0"), ("Ruby on Rails", "7.0.0"),
        ("Tomcat", "10.1.0"), ("Jenkins", "2.400"), ("Terraform", "1.5.0"),
        ("Ansible", "8.0.0"), ("GitLab CE", "16.0.0"),
    ]
    severities = ["critical", "high", "medium", "low"]
    cwe_ids = ["CWE-79", "CWE-89", "CWE-22", "CWE-502", "CWE-78", "CWE-120", "CWE-287", "CWE-918"]
    descriptions = [
        "Heap buffer overflow allowing unauthenticated remote code execution via crafted packet.",
        "SQL injection in user-supplied parameter allows data exfiltration.",
        "Directory traversal vulnerability exposes sensitive files.",
        "Insecure deserialization leads to arbitrary code execution.",
        "OS command injection via unsanitized shell metacharacters.",
        "Stack buffer overflow in parsing library.",
        "Authentication bypass via malformed JWT token.",
        "Server-Side Request Forgery allows access to internal services.",
    ]

    count = 0
    for i in range(100):
        prod, ver = products[i % len(products)]
        sev = severities[i % len(severities)]
        cvss = {"critical": 9.0 + (i % 10) * 0.1, "high": 7.0 + (i % 20) * 0.1,
                "medium": 4.0 + (i % 30) * 0.1, "low": 1.0 + (i % 30) * 0.1}[sev]
        cvss = min(10.0, round(cvss, 1))
        epss = round(random.uniform(0.01, 0.95), 4)
        kev = i % 10 == 0  # 10 KEV entries
        year = 2024 + (i % 2)
        cve_id = f"CVE-{year}-{10000 + i:05d}"

        try:
            # add_cve is the correct method name
            e.add_cve(ORG, {
                "cve_id": cve_id,
                "title": f"{prod} {ver} — {descriptions[i % len(descriptions)][:60]}",
                "description": descriptions[i % len(descriptions)],
                "severity": sev,
                "cvss_score": cvss,
                "epss_score": epss,
                "kev_listed": kev,
                "affected_product": prod,
                "affected_version": ver,
                "cwe_id": cwe_ids[i % len(cwe_ids)],
                "published_date": _ts(days_ago=180 - i),
                "patch_available": i % 3 != 0,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln {i}: {ex}")

    return {"engine": "VulnIntelligenceEngine", "vulns_seeded": count}


# ---------------------------------------------------------------------------
# 3. Incidents (5) via IncidentOrchestrationEngine
# ---------------------------------------------------------------------------
def seed_incidents():
    from core.incident_orchestration_engine import IncidentOrchestrationEngine
    e = IncidentOrchestrationEngine()

    incidents_def = [
        {
            "title": "BlackCat Ransomware — Finance Cluster",
            "description": "Ransomware outbreak on finance-srv-01 through finance-srv-06. 4TB encrypted. Backup systems isolated.",
            "severity": "critical", "incident_type": "ransomware",
            "affected_systems": ["finance-srv-01", "finance-srv-02", "finance-srv-03"],
            "assigned_to": "incident-lead@aldeci.io",
        },
        {
            "title": "APT41 Supply Chain Compromise",
            "description": "Nation-state actor compromised CI/CD pipeline. Malicious code injected into 3 packages.",
            "severity": "critical", "incident_type": "supply_chain",
            "affected_systems": ["build-server-01", "github-actions", "artifactory"],
            "assigned_to": "alice@aldeci.io",
        },
        {
            "title": "Insider Data Exfiltration — Departing Employee",
            "description": "Departing sales engineer exfiltrated 7.2GB of customer PII to personal Dropbox.",
            "severity": "high", "incident_type": "insider_threat",
            "affected_systems": ["workstation-SE-14", "dropbox"],
            "assigned_to": "bob@aldeci.io",
        },
        {
            "title": "PCI Data Breach — E-commerce Application",
            "description": "SQL injection in checkout endpoint exposed 8,432 payment card records. Dwell time: 11 days.",
            "severity": "critical", "incident_type": "data_breach",
            "affected_systems": ["ecomm-web-01", "ecomm-db-01"],
            "assigned_to": "carol@aldeci.io",
        },
        {
            "title": "DDoS Attack — Customer Portal",
            "description": "Layer 7 DDoS targeting /api/login. Peak 2.4M req/s. Mitigated via Cloudflare within 45 min.",
            "severity": "high", "incident_type": "ddos",
            "affected_systems": ["portal-lb-01", "portal-web-01", "portal-web-02"],
            "assigned_to": "netops@aldeci.io",
        },
    ]

    count = 0
    for inc_def in incidents_def:
        try:
            result = e.create_incident(ORG, inc_def)
            inc_id = result.get("id") or result.get("incident_id")
            if inc_id:
                try:
                    e.add_timeline_event(ORG, inc_id, {
                        "event_type": "detection",
                        "description": "Alert triggered by SIEM correlation rule.",
                        "actor": "SIEM",
                    })
                    e.add_timeline_event(ORG, inc_id, {
                        "event_type": "response",
                        "description": "Incident response team engaged. Containment initiated.",
                        "actor": inc_def["assigned_to"],
                    })
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] incident {inc_def['title'][:30]}: {ex}")

    return {"engine": "IncidentOrchestrationEngine", "incidents_seeded": count}


# ---------------------------------------------------------------------------
# 4. Assets (200) via AssetRiskCalculator
# ---------------------------------------------------------------------------
def seed_assets():
    from core.asset_risk_calculator import AssetRiskCalculator
    e = AssetRiskCalculator()

    # Valid asset_types: server, workstation, application, cloud_instance, database, network_device, iot
    asset_types = ["server", "workstation", "network_device", "cloud_instance", "database", "application", "iot", "server"]
    environments = ["production", "staging", "development", "dmz", "corporate"]
    owners = ["engineering@aldeci.io", "infra@aldeci.io", "security@aldeci.io", "cloudops@aldeci.io"]
    cloud_providers = [None, None, None, "aws", "azure", "gcp"]  # More on-prem

    count = 0
    for i in range(200):
        asset_type = asset_types[i % len(asset_types)]
        env = environments[i % len(environments)]
        owner = owners[i % len(owners)]
        cloud = cloud_providers[i % len(cloud_providers)]

        criticality = random.choice(["critical", "high", "medium", "low"])
        # Valid exposure values: internet_facing, internal, air_gapped
        exposure = "internet_facing" if env == "dmz" else ("air_gapped" if env == "corporate" and i % 10 == 0 else "internal")

        try:
            e.register_asset(ORG, {
                "name": f"{asset_type}-{i:03d}.{env}.internal",
                "asset_type": asset_type,
                "environment": env,
                "owner": owner,
                "cloud_provider": cloud,
                "ip_address": f"10.{i // 256}.{i % 256}.{(i * 7) % 256}",
                "os": random.choice(["Ubuntu 22.04", "RHEL 9", "Windows Server 2022", "Amazon Linux 2", "Debian 12"]),
                "criticality": criticality,
                "exposure": exposure,
                "data_classification": random.choice(["public", "internal", "confidential", "restricted"]),
                "tags": [env, asset_type, f"team-{i % 5}"],
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] asset {i}: {ex}")

    return {"engine": "AssetRiskCalculator", "assets_seeded": count}


# ---------------------------------------------------------------------------
# 5. Compliance Controls (50) via ComplianceScannerEngine
# ---------------------------------------------------------------------------
def seed_compliance_controls():
    from core.compliance_scanner_engine import ComplianceScannerEngine
    e = ComplianceScannerEngine()

    # ComplianceScannerEngine uses create_profile + start_scan pattern
    profiles_def = [
        {
            "profile_name": "SOC2 Type II — Production",
            "framework": "soc2",
            "description": "SOC2 Type II compliance scan for production environment",
            "target_scope": "production",
            "checks": [
                {"check_id": "CC6.1", "check_name": "Logical access security", "category": "access_control", "expected_value": "enabled"},
                {"check_id": "CC6.2", "check_name": "Authentication mechanisms", "category": "access_control", "expected_value": "mfa_enabled"},
                {"check_id": "CC6.3", "check_name": "Authorization controls", "category": "access_control", "expected_value": "rbac"},
                {"check_id": "CC7.1", "check_name": "System monitoring", "category": "monitoring", "expected_value": "enabled"},
                {"check_id": "CC7.2", "check_name": "Security event alerting", "category": "monitoring", "expected_value": "configured"},
                {"check_id": "CC8.1", "check_name": "Change management", "category": "change_mgmt", "expected_value": "approved"},
                {"check_id": "CC9.1", "check_name": "Risk mitigation", "category": "risk", "expected_value": "documented"},
                {"check_id": "A1.1",  "check_name": "Availability commitments", "category": "availability", "expected_value": "99.9"},
                {"check_id": "A1.2",  "check_name": "Incident response", "category": "availability", "expected_value": "plan_exists"},
                {"check_id": "A1.3",  "check_name": "Recovery testing", "category": "availability", "expected_value": "quarterly"},
            ],
        },
        {
            "profile_name": "NIST CSF — Enterprise",
            "framework": "nist_csf",
            "description": "NIST Cybersecurity Framework assessment",
            "target_scope": "enterprise",
            "checks": [
                {"check_id": "ID.AM-1", "check_name": "Asset inventory", "category": "identify", "expected_value": "complete"},
                {"check_id": "ID.AM-2", "check_name": "Software inventory", "category": "identify", "expected_value": "complete"},
                {"check_id": "PR.AC-1", "check_name": "Identity management", "category": "protect", "expected_value": "enabled"},
                {"check_id": "PR.AC-4", "check_name": "Access permissions", "category": "protect", "expected_value": "least_privilege"},
                {"check_id": "PR.DS-1", "check_name": "Data-at-rest protection", "category": "protect", "expected_value": "encrypted"},
                {"check_id": "PR.DS-5", "check_name": "Data leak protection", "category": "protect", "expected_value": "dlp_enabled"},
                {"check_id": "DE.CM-1", "check_name": "Network monitoring", "category": "detect", "expected_value": "continuous"},
                {"check_id": "DE.CM-7", "check_name": "Unauthorized device monitoring", "category": "detect", "expected_value": "enabled"},
                {"check_id": "RS.RP-1", "check_name": "Response plan", "category": "respond", "expected_value": "documented"},
                {"check_id": "RC.RP-1", "check_name": "Recovery plan", "category": "recover", "expected_value": "tested"},
            ],
        },
        {
            "profile_name": "PCI DSS v4.0 — Cardholder Environment",
            "framework": "pci_dss",
            "description": "PCI DSS v4.0 compliance for cardholder data environment",
            "target_scope": "cde",
            "checks": [
                {"check_id": "1.1", "check_name": "Network security controls", "category": "network", "expected_value": "configured"},
                {"check_id": "2.1", "check_name": "Default credentials changed", "category": "hardening", "expected_value": "yes"},
                {"check_id": "3.1", "check_name": "Account data storage limited", "category": "data_protection", "expected_value": "minimized"},
                {"check_id": "4.1", "check_name": "Strong cryptography in transit", "category": "encryption", "expected_value": "tls1.2+"},
                {"check_id": "6.1", "check_name": "Vulnerability management", "category": "vuln_mgmt", "expected_value": "patched"},
                {"check_id": "8.1", "check_name": "User identification", "category": "access_control", "expected_value": "unique_ids"},
                {"check_id": "10.1", "check_name": "Audit log implementation", "category": "logging", "expected_value": "enabled"},
            ],
        },
        {
            "profile_name": "ISO 27001 — Information Security",
            "framework": "iso27001",
            "description": "ISO/IEC 27001:2022 information security management",
            "target_scope": "enterprise",
            "checks": [
                {"check_id": "A.5.1",  "check_name": "Information security policies", "category": "policy", "expected_value": "approved"},
                {"check_id": "A.6.1",  "check_name": "Internal organization", "category": "organization", "expected_value": "defined"},
                {"check_id": "A.8.1",  "check_name": "Asset inventory", "category": "asset_mgmt", "expected_value": "complete"},
                {"check_id": "A.9.1",  "check_name": "Access control policy", "category": "access_control", "expected_value": "documented"},
                {"check_id": "A.10.1", "check_name": "Cryptography policy", "category": "crypto", "expected_value": "aes256"},
                {"check_id": "A.12.1", "check_name": "Operational procedures", "category": "operations", "expected_value": "documented"},
                {"check_id": "A.13.1", "check_name": "Network security management", "category": "network", "expected_value": "segmented"},
            ],
        },
        {
            "profile_name": "CIS Controls v8 — Enterprise",
            "framework": "cis_v8",
            "description": "CIS Critical Security Controls v8 implementation assessment",
            "target_scope": "enterprise",
            "checks": [
                {"check_id": "CIS-1", "check_name": "Enterprise asset inventory", "category": "asset_mgmt", "expected_value": "complete"},
                {"check_id": "CIS-2", "check_name": "Software asset inventory", "category": "asset_mgmt", "expected_value": "complete"},
                {"check_id": "CIS-3", "check_name": "Data protection", "category": "data_protection", "expected_value": "classified"},
                {"check_id": "CIS-4", "check_name": "Secure configuration", "category": "hardening", "expected_value": "baseline"},
                {"check_id": "CIS-5", "check_name": "Account management", "category": "access_control", "expected_value": "mfa"},
                {"check_id": "CIS-6", "check_name": "Access control management", "category": "access_control", "expected_value": "rbac"},
                {"check_id": "CIS-7", "check_name": "Vulnerability management", "category": "vuln_mgmt", "expected_value": "automated"},
                {"check_id": "CIS-8", "check_name": "Audit log management", "category": "logging", "expected_value": "centralized"},
                {"check_id": "CIS-9", "check_name": "Email and browser protections", "category": "endpoint", "expected_value": "enabled"},
                {"check_id": "CIS-10", "check_name": "Malware defenses", "category": "endpoint", "expected_value": "edr_deployed"},
            ],
        },
    ]

    profiles_created = scans_run = 0
    for pdef in profiles_def:
        try:
            prof = e.create_profile(ORG, pdef)
            pid = prof.get("profile_id") or prof.get("id")
            profiles_created += 1
            if pid:
                try:
                    e.start_scan(ORG, pid)
                    scans_run += 1
                except Exception:
                    pass
        except Exception as ex:
            print(f"  [WARN] compliance profile {pdef['profile_name'][:30]}: {ex}")

    stats = e.get_compliance_stats(ORG)
    return {"engine": "ComplianceScannerEngine",
            "profiles_created": profiles_created,
            "scans_run": scans_run,
            "stats": stats}


# ---------------------------------------------------------------------------
# 6. Risk Scores (20) via RiskAggregatorEngine
# ---------------------------------------------------------------------------
def seed_risk_scores():
    from core.risk_aggregator_engine import RiskAggregatorEngine
    e = RiskAggregatorEngine()

    # Valid entity_types: user, application, asset, vendor, network
    entities = [
        ("Finance Portal",           "application"),
        ("Customer Portal",          "application"),
        ("Payment Processing API",   "application"),
        ("Data Analytics Platform",  "application"),
        ("Salesforce CRM",           "application"),
        ("Workday HR System",        "application"),
        ("ServiceNow ITSM",          "application"),
        ("CI/CD Pipeline",           "application"),
        ("Accenture",                "vendor"),
        ("Deloitte",                 "vendor"),
        ("AWS Support",              "vendor"),
        ("Contractor Pool",          "vendor"),
        ("CISO",                     "user"),
        ("CTO",                      "user"),
        ("DevOps Lead",              "user"),
        ("Finance Admin",            "user"),
        ("Production Network",       "network"),
        ("DMZ Network",              "network"),
        ("Database Cluster",         "asset"),
        ("Mail Server",              "asset"),
    ]

    count = 0
    for name, etype in entities:
        risk_score = round(random.uniform(20, 90), 1)
        risk_level = "critical" if risk_score >= 80 else "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"

        try:
            e.record_risk_score(ORG, {
                "entity_id": str(uuid.uuid4()),
                "entity_name": name,
                "entity_type": etype,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": {
                    "vulnerability_score": round(random.uniform(15, 85), 1),
                    "threat_score": round(random.uniform(10, 80), 1),
                    "exposure_score": round(random.uniform(10, 75), 1),
                    "compliance_score": round(random.uniform(30, 95), 1),
                },
                "assessed_at": _ts(days_ago=count % 14),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] risk {name}: {ex}")

    try:
        e.calculate_org_risk_score(ORG)
    except Exception as ex:
        print(f"  [WARN] composite: {ex}")

    return {"engine": "RiskAggregatorEngine", "risk_scores_seeded": count}


# ---------------------------------------------------------------------------
# 7. Threat Intel IOCs (30) via ThreatIntelPlatformEngine
# ---------------------------------------------------------------------------
def seed_threat_iocs():
    from core.threat_intel_platform_engine import ThreatIntelPlatformEngine
    e = ThreatIntelPlatformEngine()

    ioc_types = ["ip", "domain", "url", "hash_md5", "hash_sha256", "email"]
    iocs = [
        # IPs (C2 servers)
        ("ip", "185.234.219.108", "critical", "APT41 C2 server — confirmed active"),
        ("ip", "91.243.44.148",   "critical", "IcedID banking trojan C2"),
        ("ip", "194.61.55.219",   "high",     "Emotet botnet C2 node"),
        ("ip", "103.75.201.2",    "high",     "Feodo tracker — confirmed C2"),
        ("ip", "51.178.61.60",    "high",     "Cobalt Strike team server"),
        ("ip", "185.220.70.91",   "critical", "CLOP ransomware exfil endpoint"),
        ("ip", "203.76.251.21",   "high",     "APT41 data exfil endpoint"),
        ("ip", "45.142.212.100",  "high",     "LockBit 3.0 C2"),
        ("ip", "5.188.87.57",     "medium",   "Scanner — Shodan-verified active"),
        ("ip", "89.248.167.131",  "medium",   "Brute force source — multiple reports"),
        # Domains
        ("domain", "blackcat-c2.onion.ws",     "critical", "BlackCat ransomware C2"),
        ("domain", "apt41-c2.hk-hosting.com",  "critical", "APT41 supply chain campaign"),
        ("domain", "lazarus-job-offer.pdf.io", "critical", "Lazarus Group spear phish"),
        ("domain", "update-srv.software-cdn.net", "high",  "APT41 DLL update server"),
        ("domain", "emotet-epoch5.cdn-fast.net",  "high",  "Emotet epoch 5 C2"),
        ("domain", "carbanak-c2.cdn-update.net",  "high",  "FIN7 Carbanak C2"),
        ("domain", "aldeci-login.phish.xyz",    "high",    "Typosquat phishing site"),
        ("domain", "microsofft-login.net",      "medium",  "Typosquat — credential harvest"),
        ("domain", "paypa1-secure.com",         "medium",  "PayPal typosquat"),
        # URLs
        ("url", "hxxp://evil-cdn.biz/payload.exe",        "critical", "Raccoon stealer payload dropper"),
        ("url", "hxxps://secure-aldeci.tk/login.html",    "high",     "Phishing login page"),
        # MD5 hashes
        ("hash_md5", "a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5", "critical", "BlackCat ransomware sample"),
        ("hash_md5", "45c48cce2e2d7fbdea1afc51c7c6ad26", "high",     "APT41 dropper — signed with stolen cert"),
        ("hash_md5", "70efdf2ec9b086079795c442636b55fb", "high",     "AgentTesla stealer"),
        # SHA256 hashes
        ("hash_sha256", "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", "critical", "BlackCat updated EDR bypass variant"),
        ("hash_sha256", "2c624232cdd221771294dfbb310acbc8a04a1f3fff1fa07e998e86f7f7a27ae4", "high",     "Cobalt Strike beacon"),
        ("hash_sha256", "19581e27de7ced00ff1ce50b2047e7a5a04a1f3fff1fa07e998e86f7f7a27ae5", "high",     "Mimikatz credential dumper"),
        # Emails
        ("email", "agentexfil@gmail.com",      "high",   "AgentTesla SMTP exfil account"),
        ("email", "lazarus.recruit@proton.me", "critical","Lazarus Group spear phish sender"),
        ("email", "carbanak-team@onionmail.org","high",   "FIN7 command email"),
    ]

    # First ensure we have a source
    src_id = None
    try:
        sources = e.list_sources(ORG)
        if sources:
            src_id = sources[0].get("id") or sources[0].get("source_id") or ""
        else:
            src = e.add_source(ORG, {
                "name": "ALDECI Threat Intel Platform",
                "source_type": "internal",
                "description": "Aggregated IOCs from multiple feeds",
                "reliability": "high",
            })
            src_id = src.get("id") or src.get("source_id") or ""
    except Exception as ex:
        print(f"  [WARN] source lookup: {ex}")
        src_id = ""

    count = 0
    for ioc_type, value, severity, description in iocs:
        try:
            e.add_indicator(ORG, {
                "indicator_type": ioc_type,
                "value": value,
                "severity": severity,
                "description": description,
                "source_id": src_id,
                "confidence": 0.85 if severity == "critical" else 0.70,
                "tlp": "amber",
                "tags": [ioc_type, severity],
                "first_seen": _ts(days_ago=30),
                "last_seen": _ts(days_ago=1),
                "active": True,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] ioc {value[:20]}: {ex}")

    return {"engine": "ThreatIntelPlatformEngine", "iocs_seeded": count}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print(f"\nALDECI Extended Demo Seeder")
    print(f"  Org ID : {ORG}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    seeders = [
        ("Alert Triage Engine (50 alerts)",      seed_alerts),
        ("Vuln Intelligence Engine (100 vulns)", seed_vulnerabilities),
        ("Incident Orchestration Engine (5)",    seed_incidents),
        ("Asset Risk Calculator (200 assets)",   seed_assets),
        ("Compliance Scanner Engine (50 ctrls)", seed_compliance_controls),
        ("Risk Aggregator Engine (20 scores)",   seed_risk_scores),
        ("Threat Intel Platform (30 IOCs)",      seed_threat_iocs),
    ]

    ok = fail = 0
    for name, fn in seeders:
        try:
            result = fn()
            ok += 1
            summary = ", ".join(f"{k}={v}" for k, v in result.items() if k != "engine")
            print(f"  [OK]   {name}: {summary}")
        except Exception as exc:
            fail += 1
            print(f"  [FAIL] {name}: {exc}")

    print(f"\n  Seeded {ok}/{len(seeders)} engines  ({fail} failed)")
    print(f"\nExtended demo data ready. Org ID: {ORG}")


if __name__ == "__main__":
    main()
