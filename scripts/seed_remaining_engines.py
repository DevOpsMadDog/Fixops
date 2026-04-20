#!/usr/bin/env python3
"""Seed remaining 68 empty engine databases with realistic demo data.

Run from repo root:
    PYTHONPATH="suite-core:suite-api" python3 scripts/seed_remaining_engines.py

Covers:
  - Fixes for engines that failed in seed_bulk_engines.py (wrong field names)
  - New engines not covered: dlp, insider_threat, ip_reputation, sbom,
    vuln_lifecycle, sla_escalation, zero_trust, pentest, scorecards, rbac,
    training, vendor, supply_chain, workflows, playbooks, etc.
  - Direct SQLite inserts for DBs whose engines are complex/async
"""
from __future__ import annotations
import sys, sqlite3, random, uuid, json, hashlib
from datetime import datetime, timezone, timedelta, date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "suite-core"))
sys.path.insert(0, str(ROOT / "suite-api"))

ORG = "default"
random.seed(42)

DATA_DIR = ROOT / "data"

def _ts(days_ago=0, hours_ago=0):
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat()

def _date(days_ago=0, days_ahead=0):
    d = date.today() + timedelta(days=days_ahead) - timedelta(days=days_ago)
    return d.isoformat()

def _id(): return str(uuid.uuid4())

SEVERITIES = ["critical", "high", "medium", "low"]
USERS = ["alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io", "eve@corp.io"]
HOSTS = [f"host-{i:03d}.internal" for i in range(1, 21)]
IPS = [f"10.0.{i}.{j}" for i in range(1, 5) for j in range(1, 6)]


# ---------------------------------------------------------------------------
# Helpers for direct SQLite inserts (for complex/legacy engines)
# ---------------------------------------------------------------------------
def _db(name: str) -> sqlite3.Connection:
    path = DATA_DIR / name
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    return con


def _tables(con: sqlite3.Connection):
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()]


def _count(con: sqlite3.Connection) -> int:
    tables = _tables(con)
    return sum(con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] for t in tables)


# ---------------------------------------------------------------------------
# Fix: api_discovery (scan_name required)
# ---------------------------------------------------------------------------
def seed_api_discovery_fix():
    from core.api_discovery_engine import APIDiscoveryEngine
    e = APIDiscoveryEngine()
    count = 0
    services = [
        ("auth-service", "https://auth.internal/api"),
        ("payment-service", "https://pay.internal/api"),
        ("user-service", "https://users.internal/api"),
        ("notification-service", "https://notify.internal/api"),
    ]
    for svc, base_url in services:
        try:
            scan = e.create_scan(ORG, {
                "scan_name": f"Discovery scan: {svc}",
                "target": base_url,
                "scan_type": "passive",
            })
            scan_id = scan.get("scan_id") or scan.get("id")
            for i in range(3):
                e.register_endpoint(ORG, {
                    "path": f"/api/v1/{svc.split('-')[0]}/{i}",
                    "method": ["GET", "POST", "PUT"][i % 3],
                    "service": svc,
                    "authenticated": i % 2 == 0,
                    "documented": i < 2,
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_discovery {svc}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: api_gateway_security (register_gateway not register_api)
# ---------------------------------------------------------------------------
def seed_api_gateway_fix():
    from core.api_gateway_security_engine import APIGatewaySecurityEngine
    e = APIGatewaySecurityEngine()
    count = 0
    gateways = [
        ("Main API Gateway", "Kong", "https://api.corp.io"),
        ("Internal Gateway", "Nginx", "https://internal.corp.io"),
        ("Partner Gateway", "AWS API GW", "https://partner.corp.io"),
    ]
    for name, provider, url in gateways:
        try:
            gw = e.register_gateway(ORG, {
                "name": name,
                "provider": provider,
                "base_url": url,
                "environment": "production",
                "rate_limit_enabled": True,
                "auth_required": True,
            })
            gw_id = gw.get("gateway_id") or gw.get("id")
            if gw_id:
                e.register_api(ORG, {
                    "gateway_id": gw_id,
                    "name": f"{name} - Users API",
                    "path": "/api/v1/users",
                    "method": "GET",
                    "auth_type": "bearer",
                    "rate_limit": 1000,
                })
                e.record_security_event(ORG, {
                    "gateway_id": gw_id,
                    "event_type": "rate_limit_exceeded",
                    "source_ip": random.choice(IPS),
                    "severity": "medium",
                    "description": "Rate limit exceeded on users endpoint",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_gateway {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: cloud_accounts (UNIQUE conflict — try different account IDs)
# ---------------------------------------------------------------------------
def seed_cloud_accounts_fix():
    from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine
    e = CloudAccountMonitoringEngine()
    count = 0
    accounts = [
        {"account_id": f"aws-seed-{_id()[:8]}", "provider": "aws", "name": "AWS Production Seed", "region": "us-east-1", "account_type": "production"},
        {"account_id": f"az-seed-{_id()[:8]}", "provider": "azure", "name": "Azure Corp Seed", "region": "eastus", "account_type": "production"},
        {"account_id": f"gcp-seed-{_id()[:8]}", "provider": "gcp", "name": "GCP Data Seed", "region": "us-central1", "account_type": "development"},
    ]
    for acc in accounts:
        try:
            r = e.register_account(ORG, acc)
            acc_id = r.get("account_id") or r.get("id")
            if acc_id:
                e.record_event(ORG, {
                    "account_id": acc_id,
                    "event_type": "config_change",
                    "severity": "medium",
                    "description": "Security group modified",
                    "resource_id": f"sg-{_id()[:8]}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_accounts: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: cloud_governance (resource_type required)
# ---------------------------------------------------------------------------
def seed_cloud_governance_fix():
    from core.cloud_governance_engine import CloudGovernanceEngine
    e = CloudGovernanceEngine()
    count = 0
    policies = [
        ("No public S3 buckets", "storage", "preventive"),
        ("Require MFA for console access", "identity", "detective"),
        ("No unencrypted EBS volumes", "compute", "preventive"),
        ("Approved AWS regions only", "network", "preventive"),
    ]
    for name, resource_type, control_type in policies:
        try:
            p = e.create_governance_policy(ORG, {
                "name": name,
                "resource_type": resource_type,
                "provider": "aws",
                "control_type": control_type,
                "severity": "high",
                "description": f"Policy: {name}",
            })
            pol_id = p.get("policy_id") or p.get("id")
            if pol_id:
                e.record_violation(ORG, {
                    "policy_id": pol_id,
                    "resource_id": f"resource-{_id()[:8]}",
                    "resource_type": resource_type,
                    "severity": "high",
                    "description": f"Violation of: {name}",
                    "account_id": "aws-123456789",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_governance {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: compliance_gaps (create_assessment first then add_control_gap)
# ---------------------------------------------------------------------------
def seed_compliance_gaps_fix():
    from core.compliance_gap_engine import ComplianceGapEngine
    e = ComplianceGapEngine()
    count = 0
    frameworks = [
        ("SOC2 Gap Analysis Q1 2025", "soc2"),
        ("PCI DSS v4.0 Assessment", "pci_dss"),
        ("ISO 27001 Gap Analysis", "iso27001"),
    ]
    for name, fw in frameworks:
        try:
            ass = e.create_assessment(ORG, {"framework": fw, "name": name, "scope": "enterprise"})
            ass_id = ass.get("assessment_id") or ass.get("id")
            if ass_id:
                e.add_control_gap(ORG, {
                    "assessment_id": ass_id,
                    "control_id": f"{fw.upper()}-001",
                    "control_name": "Access Control",
                    "gap_description": "MFA not enforced for all users",
                    "severity": "high",
                    "current_state": "partial",
                    "target_state": "full",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] compliance_gaps {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: container_registry (register_registry not register_container_registry)
# ---------------------------------------------------------------------------
def seed_container_registry_fix():
    from core.container_registry_security_engine import ContainerRegistrySecurityEngine
    e = ContainerRegistrySecurityEngine()
    count = 0
    registries = [
        ("AWS ECR Production", "ecr", "123456789.dkr.ecr.us-east-1.amazonaws.com"),
        ("Docker Hub Corporate", "dockerhub", "registry.hub.docker.com"),
        ("Azure Container Registry", "acr", "corp.azurecr.io"),
    ]
    for name, registry_type, url in registries:
        try:
            r = e.register_registry(ORG, {
                "name": name,
                "registry_type": registry_type,
                "url": url,
                "scan_on_push": True,
                "private": True,
            })
            reg_id = r.get("registry_id") or r.get("id")
            if reg_id:
                scan = e.scan_image(ORG, {
                    "registry_id": reg_id,
                    "image_name": f"myapp/api",
                    "image_tag": "latest",
                    "image_digest": f"sha256:{hashlib.sha256(name.encode()).hexdigest()}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] container_registry {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: container_runtime (correct event_type values)
# ---------------------------------------------------------------------------
def seed_container_runtime_fix():
    from core.container_runtime_security_engine import ContainerRuntimeSecurityEngine
    e = ContainerRuntimeSecurityEngine()
    count = 0
    containers = [
        ("api-backend-01", "network_connection"),
        ("db-postgres-01", "file_write"),
        ("redis-cache-01", "exec_command"),
        ("nginx-proxy-01", "port_scan"),
    ]
    for name, event_type in containers:
        try:
            c = e.register_container(ORG, {
                "container_name": name,
                "image": f"corp/{name.split('-')[0]}:latest",
                "namespace": "production",
                "pod_name": f"pod-{name}",
                "node_name": random.choice(HOSTS),
            })
            cid = c.get("container_id") or c.get("id")
            if cid:
                e.record_runtime_event(ORG, {
                    "container_id": cid,
                    "event_type": event_type,
                    "severity": random.choice(SEVERITIES),
                    "description": f"Runtime event: {event_type} on {name}",
                    "source_ip": random.choice(IPS),
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] container_runtime {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: crypto_keys (no dict in metadata param)
# ---------------------------------------------------------------------------
def seed_crypto_keys_fix():
    from core.crypto_key_management_engine import CryptoKeyManagementEngine
    e = CryptoKeyManagementEngine()
    count = 0
    keys = [
        ("data-encryption-key-prod", "aes_256", "data_encryption", 365),
        ("signing-key-api", "rsa_2048", "signing", 730),
        ("tls-cert-key", "rsa_4096", "tls", 365),
        ("hmac-webhook-key", "hmac_sha256", "authentication", 180),
        ("old-key-deprecated", "aes_128", "legacy", 30),
    ]
    for name, algo, purpose, expiry in keys:
        try:
            e.create_key(ORG, {
                "name": name,
                "algorithm": algo,
                "purpose": purpose,
                "expiry_days": expiry,
                "key_size": 256,
                "rotation_policy": "annual",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] crypto_keys {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: ddos_protection (register_protected_resource needs 'name')
# ---------------------------------------------------------------------------
def seed_ddos_fix():
    from core.ddos_protection_engine import DDoSProtectionEngine
    e = DDoSProtectionEngine()
    count = 0
    resources = [
        ("Customer Portal", "web_application", "https://portal.corp.io"),
        ("API Gateway", "api_endpoint", "https://api.corp.io"),
        ("DNS Servers", "dns", "8.8.8.1"),
        ("Load Balancer", "network", "10.0.1.1"),
    ]
    for name, rtype, endpoint in resources:
        try:
            r = e.register_protected_resource(ORG, {
                "name": name,
                "resource_type": rtype,
                "endpoint": endpoint,
                "protection_level": "high",
                "threshold_pps": 100000,
            })
            rid = r.get("resource_id") or r.get("id")
            if rid:
                e.record_attack_event(ORG, {
                    "resource_id": rid,
                    "attack_type": "volumetric",
                    "source_ips": random.sample(IPS, 3),
                    "peak_pps": random.randint(50000, 500000),
                    "severity": random.choice(["high", "critical"]),
                    "description": f"DDoS attack on {name}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] ddos {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: digital_identity (UNIQUE conflict — use unique user IDs)
# ---------------------------------------------------------------------------
def seed_digital_identity_fix():
    from core.digital_identity_engine import DigitalIdentityEngine
    e = DigitalIdentityEngine()
    count = 0
    uid = _id()[:8]
    users = [
        (f"alice-{uid}@corp.io", "IAL2", "employee"),
        (f"bob-{uid}@corp.io", "IAL1", "contractor"),
        (f"carol-{uid}@corp.io", "IAL3", "admin"),
    ]
    for user_id, ial, role in users:
        try:
            profile = e.create_identity(ORG, {
                "user_id": user_id,
                "identity_assurance_level": ial,
                "role": role,
                "email": user_id,
                "mfa_enabled": True,
                "department": "Engineering",
            })
            pid = profile.get("identity_id") or profile.get("id")
            if pid:
                e.record_verification_event(ORG, {
                    "identity_id": pid,
                    "event_type": "login",
                    "method": "password+totp",
                    "success": True,
                    "ip_address": random.choice(IPS),
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] digital_identity {user_id}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: firewall_policy (register_firewall not add_firewall)
# ---------------------------------------------------------------------------
def seed_firewall_fix():
    from core.firewall_policy_engine import FirewallPolicyEngine
    e = FirewallPolicyEngine()
    count = 0
    firewalls = [
        ("Core Perimeter Firewall", "palo_alto", "perimeter"),
        ("Internal Segmentation FW", "cisco_asa", "internal"),
        ("Cloud WAF", "aws_waf", "cloud"),
    ]
    for name, vendor, fw_type in firewalls:
        try:
            fw = e.register_firewall(ORG, {
                "name": name,
                "vendor": vendor,
                "firewall_type": fw_type,
                "ip_address": random.choice(IPS),
                "management_ip": random.choice(IPS),
            })
            fw_id = fw.get("firewall_id") or fw.get("id")
            if fw_id:
                for i in range(3):
                    e.add_rule(ORG, fw_id, {
                        "name": f"Rule-{i+1}: Allow {['HTTP', 'HTTPS', 'SSH'][i]}",
                        "action": "allow",
                        "source_zones": ["external"],
                        "dest_zones": ["dmz"],
                        "ports": [str([80, 443, 22][i])],
                        "protocols": ["tcp"],
                        "order_num": i + 1,
                        "enabled": True,
                    })
            count += 1
        except Exception as ex:
            print(f"  [WARN] firewall {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Fix: forensics_readiness (correct source_type values)
# ---------------------------------------------------------------------------
def seed_forensics_readiness_fix():
    from core.forensics_readiness_engine import ForensicsReadinessEngine
    e = ForensicsReadinessEngine()
    count = 0
    sources = [
        ("SIEM Event Logs", "endpoint_logs", 90),
        ("Endpoint Memory Dumps", "endpoint_logs", 30),
        ("Network PCAP", "network_pcap", 7),
        ("Cloud Trail Logs", "cloud_trail", 365),
        ("Database Audit Logs", "database_audit", 180),
    ]
    for name, source_type, retention in sources:
        try:
            e.register_evidence_source(ORG, {
                "name": name,
                "source_type": source_type,
                "retention_days": retention,
                "collection_method": "automated",
                "location": f"s3://forensics/{name.lower().replace(' ', '-')}",
                "integrity_check": True,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] forensics {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# DLP engine
# ---------------------------------------------------------------------------
def seed_dlp():
    from core.dlp_engine import DLPEngine
    e = DLPEngine()
    count = 0
    # Scan some text with PII to generate records
    sample_texts = [
        ("Employee SSNs", "SSN: 123-45-6789, DOB: 1985-03-15, Name: John Smith"),
        ("Credit card data", "Card: 4111-1111-1111-1111, CVV: 123, Exp: 12/26"),
        ("Medical records", "Patient DOB: 1990-01-01, Diagnosis: Hypertension, MRN: 12345"),
        ("Email list", "Contacts: alice@corp.io, bob@corp.io, carol@example.com"),
        ("Clean data", "No PII here — just regular log output from system"),
    ]
    for context, text in sample_texts:
        try:
            e.scan_text(text, context=context, org_id=ORG)
            count += 1
        except Exception as ex:
            print(f"  [WARN] dlp scan {context}: {ex}")
    # Add a custom pattern
    try:
        e.add_custom_pattern(
            name="Employee ID",
            pattern=r"EMP-\d{6}",
            severity="medium",
            description="Internal employee ID pattern",
            org_id=ORG,
        )
        count += 1
    except Exception as ex:
        print(f"  [WARN] dlp custom pattern: {ex}")
    return count


# ---------------------------------------------------------------------------
# Insider threat engine
# ---------------------------------------------------------------------------
def seed_insider_threat():
    from core.insider_threat_engine import InsiderThreatEngine
    e = InsiderThreatEngine()
    count = 0
    events = [
        ("user-alice", "large_download", "high", {"bytes": 5_000_000_000, "destination": "personal_dropbox"}),
        ("user-bob", "after_hours_access", "medium", {"time": "02:30 AM", "resource": "finance_db"}),
        ("user-carol", "privilege_escalation", "critical", {"from_role": "viewer", "to_role": "admin"}),
        ("user-dave", "mass_email", "high", {"recipients": 500, "attachments": 3}),
        ("user-eve", "vpn_anomaly", "medium", {"location": "Unknown Country", "usual_location": "US"}),
    ]
    for user_id, event_type, severity, details in events:
        try:
            e.record_user_event(ORG, {
                "user_id": user_id,
                "event_type": event_type,
                "severity": severity,
                "details": details,
                "source_ip": random.choice(IPS),
                "timestamp": _ts(days_ago=random.randint(0, 30)),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] insider_threat {user_id}: {ex}")
    # Analyze risk to populate risk records
    for user_id in ["user-alice", "user-bob", "user-carol"]:
        try:
            e.analyze_user_risk(ORG, user_id)
            count += 1
        except Exception as ex:
            print(f"  [WARN] insider_threat analyze {user_id}: {ex}")
    return count


# ---------------------------------------------------------------------------
# IP reputation engine
# ---------------------------------------------------------------------------
def seed_ip_reputation():
    from core.ip_reputation_engine import IPReputationEngine
    e = IPReputationEngine()
    count = 0
    ips_data = [
        ("185.220.101.1", 15, "tor_exit_node", "Known Tor exit node"),
        ("192.168.1.100", 85, "internal", "Internal trusted host"),
        ("45.33.32.156", 25, "scanner", "Known vulnerability scanner"),
        ("104.21.0.1", 72, "cdn", "Cloudflare CDN IP"),
        ("198.20.69.74", 10, "botnet", "Botnet C2 infrastructure"),
        ("8.8.8.8", 95, "dns", "Google Public DNS"),
        ("91.108.4.1", 20, "spam", "Known spam source"),
    ]
    for ip, score, category, desc in ips_data:
        try:
            e.submit_reputation(ORG, {
                "ip": ip,
                "score": score,
                "category": category,
                "description": desc,
                "source": "threat_intel_feed",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] ip_reputation {ip}: {ex}")
    # Add a few to blocklist
    for ip in ["185.220.101.1", "198.20.69.74", "91.108.4.1"]:
        try:
            e.add_to_blocklist(ORG, ip, reason="Known malicious source")
            count += 1
        except Exception as ex:
            print(f"  [WARN] ip_reputation blocklist {ip}: {ex}")
    return count


# ---------------------------------------------------------------------------
# SBOM engine
# ---------------------------------------------------------------------------
def seed_sbom():
    try:
        from core.sbom_engine import SBOMEngine
        e = SBOMEngine()
        count = 0
        components = [
            ("django", "python", "4.2.1", "MIT"),
            ("fastapi", "python", "0.104.0", "MIT"),
            ("react", "npm", "18.2.0", "MIT"),
            ("log4j-core", "java", "2.20.0", "Apache-2.0"),
            ("openssl", "c", "3.1.2", "OpenSSL"),
        ]
        sbom_id = None
        try:
            result = e.create_sbom(ORG, {
                "name": "ALDECI Platform v1.0",
                "version": "1.0.0",
                "component_type": "application",
                "supplier": "DevOpsAI",
            })
            sbom_id = result.get("sbom_id") or result.get("id")
        except Exception as ex:
            print(f"  [WARN] sbom create: {ex}")
        for pkg, ecosystem, version, lic in components:
            try:
                e.add_component(ORG, {
                    "sbom_id": sbom_id,
                    "name": pkg,
                    "version": version,
                    "ecosystem": ecosystem,
                    "license": lic,
                    "purl": f"pkg:{ecosystem}/{pkg}@{version}",
                })
                count += 1
            except Exception as ex:
                print(f"  [WARN] sbom component {pkg}: {ex}")
        return count
    except ImportError:
        # Try sbom_export_engine
        from core.sbom_export_engine import SBOMExportEngine
        e = SBOMExportEngine()
        count = 0
        for fmt in ["cyclonedx", "spdx"]:
            try:
                e.create_sbom(ORG, {
                    "name": f"ALDECI Platform ({fmt})",
                    "version": "1.0.0",
                    "format": fmt,
                    "component": "api-server",
                })
                count += 1
            except Exception as ex:
                print(f"  [WARN] sbom_export {fmt}: {ex}")
        return count


# ---------------------------------------------------------------------------
# Vuln lifecycle tracker
# ---------------------------------------------------------------------------
def seed_vuln_lifecycle():
    from core.vuln_lifecycle_tracker import VulnLifecycleTracker
    e = VulnLifecycleTracker()
    count = 0
    findings = [
        {"cve_id": "CVE-2024-1234", "title": "RCE in log4j-core", "severity": "critical", "cvss": 9.8, "asset": "app-server-01"},
        {"cve_id": "CVE-2024-5678", "title": "XSS in Django admin", "severity": "high", "cvss": 7.5, "asset": "web-frontend"},
        {"cve_id": "CVE-2024-9012", "title": "SQLi in user search", "severity": "high", "cvss": 8.1, "asset": "api-gateway"},
        {"cve_id": "CVE-2024-3456", "title": "SSRF in file upload", "severity": "medium", "cvss": 6.5, "asset": "file-service"},
        {"cve_id": "CVE-2024-7890", "title": "Insecure deserialization", "severity": "critical", "cvss": 9.0, "asset": "backend-api"},
    ]
    for f in findings:
        try:
            lid = e.register_finding(f, org_id=ORG)
            # Transition some through lifecycle
            if f["severity"] == "critical":
                e.transition(lid, "triaged", org_id=ORG, notes="Critical - fast track")
                e.transition(lid, "in_remediation", org_id=ORG, notes="Patch in progress")
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln_lifecycle {f.get('cve_id')}: {ex}")
    return count


# ---------------------------------------------------------------------------
# SLA escalation engine — direct SQLite (engine only has check_sla_breaches)
# ---------------------------------------------------------------------------
def seed_sla_escalation():
    con = _db("sla_escalation.db")
    tables = _tables(con)
    count = 0
    if not tables:
        con.close()
        return 0
    # Try to create tickets table data if it exists
    if "sla_tickets" in tables or "tickets" in tables:
        tbl = "sla_tickets" if "sla_tickets" in tables else "tickets"
        cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
        for i in range(5):
            row = {c: None for c in cols}
            row.update({
                "id": _id(),
                "org_id": ORG,
                "ticket_id": f"TKT-{1000+i}",
                "severity": SEVERITIES[i % len(SEVERITIES)],
                "created_at": _ts(days_ago=i+1),
                "status": "open",
                "title": f"Security incident #{i+1}",
            })
            vals = [row.get(c) for c in cols]
            placeholders = ",".join(["?"] * len(cols))
            try:
                con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({placeholders})", vals)
                count += 1
            except Exception as ex:
                print(f"  [WARN] sla_escalation insert: {ex}")
    else:
        # direct insert into escalation_events if it exists
        for tbl in tables:
            if "escalat" in tbl or "sla" in tbl or "ticket" in tbl:
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                for i in range(3):
                    row = {c: None for c in cols}
                    row.update({"id": _id(), "org_id": ORG, "created_at": _ts(days_ago=i)})
                    vals = [row.get(c) for c in cols]
                    placeholders = ",".join(["?"] * len(cols))
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({placeholders})", vals)
                        count += 1
                    except Exception:
                        pass
    con.commit()
    con.close()
    return count


# ---------------------------------------------------------------------------
# Zero trust policy engine
# ---------------------------------------------------------------------------
def seed_zero_trust():
    from core.zero_trust_policy_engine import ZeroTrustPolicyEngine
    e = ZeroTrustPolicyEngine()
    count = 0
    policies = [
        ("Never Trust Unmanaged Devices", "device", "block_unmanaged_devices"),
        ("MFA Everywhere", "identity", "require_mfa"),
        ("Micro-segment by Workload", "network", "deny_lateral_movement"),
        ("Encrypt All Data In Transit", "data", "enforce_tls"),
        ("Least Privilege Access", "application", "enforce_least_privilege"),
    ]
    for name, category, policy_type in policies:
        try:
            p = e.create_policy(ORG, {
                "name": name,
                "category": category,
                "policy_type": policy_type,
                "action": "block",
                "conditions": {"risk_score_threshold": 70},
                "enabled": True,
                "description": f"Zero Trust: {name}",
            })
            pid = p.get("policy_id") or p.get("id")
            if pid:
                e.evaluate_access(ORG, {
                    "policy_id": pid,
                    "user_id": random.choice(USERS),
                    "resource": f"resource-{_id()[:8]}",
                    "context": {"device_managed": True, "mfa_verified": True},
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] zero_trust {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# RBAC engine
# ---------------------------------------------------------------------------
def seed_rbac():
    from core.rbac_engine import RBACEngine
    e = RBACEngine()
    count = 0
    assignments = [
        ("alice@corp.io", "admin"),
        ("bob@corp.io", "analyst"),
        ("carol@corp.io", "viewer"),
        ("dave@corp.io", "responder"),
        ("eve@corp.io", "analyst"),
    ]
    for user_id, role in assignments:
        try:
            e.assign_role(user_id=user_id, role=role, org_id=ORG)
            count += 1
        except Exception as ex:
            print(f"  [WARN] rbac {user_id}/{role}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Pentest management engine
# ---------------------------------------------------------------------------
def seed_pentest():
    from core.pentest_mgmt_engine import PentestMgmtEngine
    e = PentestMgmtEngine()
    count = 0
    engagements = [
        ("Q1 2025 External Pentest", "external", "black_box"),
        ("API Security Assessment", "api", "grey_box"),
        ("Internal Network Pentest", "internal", "white_box"),
        ("Web Application Assessment", "web", "grey_box"),
    ]
    for name, scope, methodology in engagements:
        try:
            eng = e.create_engagement(ORG, {
                "name": name,
                "scope": scope,
                "methodology": methodology,
                "start_date": _date(days_ago=30),
                "end_date": _date(days_ago=7),
                "team": ["alice@corp.io", "bob@corp.io"],
                "target_systems": [random.choice(HOSTS) for _ in range(3)],
            })
            eng_id = eng.get("engagement_id") or eng.get("id")
            if eng_id:
                e.update_engagement_status(ORG, eng_id, "in_progress")
            count += 1
        except Exception as ex:
            print(f"  [WARN] pentest {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Security scorecard engine
# ---------------------------------------------------------------------------
def seed_scorecard():
    from core.security_scorecard_engine import SecurityScorecardEngine
    e = SecurityScorecardEngine()
    count = 0
    entities = [
        ("ALDECI Platform", "internal"),
        ("AWS Infrastructure", "cloud"),
        ("Corporate Endpoints", "endpoint"),
        ("Supply Chain Vendors", "third_party"),
    ]
    for entity_name, entity_type in entities:
        try:
            sc = e.create_scorecard(ORG, {
                "entity_name": entity_name,
                "entity_type": entity_type,
                "domain_scores": {
                    "network_security": random.randint(60, 95),
                    "endpoint_security": random.randint(55, 90),
                    "application_security": random.randint(50, 85),
                    "data_protection": random.randint(65, 95),
                    "identity_management": random.randint(70, 98),
                },
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] scorecard {entity_name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Security KPI tracker
# ---------------------------------------------------------------------------
def seed_security_kpi():
    from core.security_kpi_tracker import SecurityKPITracker
    e = SecurityKPITracker()
    count = 0
    kpis = [
        ("mttd", "Mean Time to Detect", 4.2, 2.0, "hours"),
        ("mttr", "Mean Time to Respond", 18.5, 8.0, "hours"),
        ("patch_compliance", "Patch Compliance Rate", 87.3, 95.0, "percent"),
        ("mfa_adoption", "MFA Adoption Rate", 94.1, 100.0, "percent"),
        ("vuln_critical_open", "Critical Vulns Open", 12, 0, "count"),
        ("phishing_click_rate", "Phishing Click Rate", 3.2, 1.0, "percent"),
    ]
    for metric_name, display_name, current, target, unit in kpis:
        try:
            e.record_kpi(
                org_id=ORG,
                metric_name=metric_name,
                value=current,
                target=target,
                unit=unit,
            )
            count += 1
        except Exception as ex:
            print(f"  [WARN] kpi {metric_name}: {ex}")
    try:
        e.record_snapshot(org_id=ORG)
        count += 1
    except Exception as ex:
        print(f"  [WARN] kpi snapshot: {ex}")
    return count


# ---------------------------------------------------------------------------
# Vuln risk scoring
# ---------------------------------------------------------------------------
def seed_vuln_risk_scores():
    from core.vuln_risk_scoring import VulnRiskScorer
    e = VulnRiskScorer()
    count = 0
    vulns = [
        {"cve_id": "CVE-2024-1111", "cvss_score": 9.8, "epss_score": 0.92, "kev": True,
         "asset_criticality": "critical", "exposure": "internet"},
        {"cve_id": "CVE-2024-2222", "cvss_score": 7.5, "epss_score": 0.45, "kev": False,
         "asset_criticality": "high", "exposure": "internal"},
        {"cve_id": "CVE-2024-3333", "cvss_score": 5.0, "epss_score": 0.12, "kev": False,
         "asset_criticality": "medium", "exposure": "internal"},
    ]
    for v in vulns:
        try:
            result = e.score_vulnerability(ORG, v)
            e.save_score(ORG, v["cve_id"], result)
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln_risk_score {v['cve_id']}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Vendor risk engine
# ---------------------------------------------------------------------------
def seed_vendor_risk():
    try:
        from core.vendor_risk_engine import VendorRiskEngine
        e = VendorRiskEngine()
        count = 0
        vendors = [
            ("Salesforce", "crm", "critical"),
            ("AWS", "cloud", "critical"),
            ("Zoom", "communications", "high"),
            ("GitHub", "devtools", "high"),
        ]
        for name, category, tier in vendors:
            try:
                v = e.register_vendor(ORG, {
                    "name": name,
                    "category": category,
                    "criticality_tier": tier,
                    "contact_email": f"security@{name.lower()}.com",
                    "website": f"https://www.{name.lower()}.com",
                })
                vid = v.get("vendor_id") or v.get("id")
                if vid:
                    e.create_assessment(ORG, {
                        "vendor_id": vid,
                        "assessment_type": "annual",
                        "questionnaire_score": random.randint(70, 95),
                    })
                count += 1
            except Exception as ex:
                print(f"  [WARN] vendor_risk {name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] vendor_risk import: {ex}")
        return 0


# ---------------------------------------------------------------------------
# Vendor scorecard
# ---------------------------------------------------------------------------
def seed_vendor_scorecard():
    try:
        from core.vendor_scorecard import VendorScorecard, Vendor
        e = VendorScorecard()
        count = 0
        vendors = [
            Vendor(id=_id(), name="Microsoft", category="software", criticality="high",
                   contact_email="security@microsoft.com", website="https://microsoft.com"),
            Vendor(id=_id(), name="Okta", category="identity", criticality="critical",
                   contact_email="security@okta.com", website="https://okta.com"),
            Vendor(id=_id(), name="Crowdstrike", category="security", criticality="critical",
                   contact_email="security@crowdstrike.com", website="https://crowdstrike.com"),
        ]
        for v in vendors:
            try:
                e.add_vendor(v)
                count += 1
            except Exception as ex:
                print(f"  [WARN] vendor_scorecard {v.name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] vendor_scorecard import: {ex}")
        return 0


# ---------------------------------------------------------------------------
# Supply chain intel engine
# ---------------------------------------------------------------------------
def seed_supply_chain():
    from core.supply_chain_intel_engine import SupplyChainIntelEngine
    e = SupplyChainIntelEngine()
    count = 0
    packages = [
        ("log4j-core", "2.14.1", "java", "maven", True),
        ("openssl", "1.1.1t", "c", "system", False),
        ("requests", "2.28.0", "python", "pypi", False),
        ("lodash", "4.17.21", "javascript", "npm", False),
        ("spring-core", "5.3.27", "java", "maven", True),
    ]
    for name, version, lang, ecosystem, vulnerable in packages:
        try:
            e.track_package(ORG, {
                "name": name,
                "version": version,
                "language": lang,
                "ecosystem": ecosystem,
                "known_vulnerable": vulnerable,
                "license": "Apache-2.0",
                "maintainer": f"{name}-maintainers",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] supply_chain {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Threat hunting engine
# ---------------------------------------------------------------------------
def seed_threat_hunting():
    from core.threat_hunting_engine import ThreatHuntingEngine
    e = ThreatHuntingEngine()
    count = 0
    hunts = [
        ("Hunt: Lateral Movement via SMB", "lateral_movement", "network"),
        ("Hunt: Credential Dumping", "credential_access", "endpoint"),
        ("Hunt: C2 Beaconing", "command_and_control", "network"),
        ("Hunt: Data Exfiltration via DNS", "exfiltration", "network"),
    ]
    for name, tactic, scope in hunts:
        try:
            hunt = e.create_hunt(ORG, {
                "name": name,
                "tactic": tactic,
                "scope": scope,
                "hypothesis": f"Adversaries may be using {tactic.replace('_', ' ')}",
                "data_sources": ["siem", "edr", "network_logs"],
                "analyst": random.choice(USERS),
            })
            hid = hunt.get("hunt_id") or hunt.get("id")
            count += 1
        except Exception as ex:
            print(f"  [WARN] threat_hunting {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# IR playbook engine
# ---------------------------------------------------------------------------
def seed_ir_playbook():
    from core.ir_playbook_engine import IRPlaybookRunner, IncidentType
    e = IRPlaybookRunner()
    count = 0
    incident_types = [
        (IncidentType.MALWARE, "Ransomware outbreak on finance-srv-01"),
        (IncidentType.DATA_BREACH, "PII exfiltration detected via DLP"),
        (IncidentType.PHISHING, "CEO impersonation phishing campaign"),
    ]
    for itype, desc in incident_types:
        try:
            inc = e.create_incident(
                incident_type=itype,
                title=desc,
                description=desc,
                severity="critical" if "ransomware" in desc.lower() else "high",
                org_id=ORG,
                reported_by=random.choice(USERS),
            )
            iid = inc.incident_id if hasattr(inc, "incident_id") else (inc.get("incident_id") or inc.get("id"))
            if iid:
                e.add_timeline_event(
                    incident_id=iid,
                    event_type="detection",
                    description="Initial alert triggered by SIEM",
                    author=random.choice(USERS),
                    org_id=ORG,
                )
            count += 1
        except Exception as ex:
            print(f"  [WARN] ir_playbook {desc[:30]}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Workflow engine
# ---------------------------------------------------------------------------
def seed_workflow():
    try:
        from core.workflow_engine import WorkflowEngine, Workflow
        e = WorkflowEngine()
        count = 0
        workflows = [
            ("Vuln Remediation Workflow", "remediation"),
            ("Incident Response Workflow", "incident_response"),
            ("Change Approval Workflow", "change_management"),
        ]
        for name, wtype in workflows:
            try:
                wf = Workflow(
                    id=_id(),
                    name=name,
                    workflow_type=wtype,
                    org_id=ORG,
                    steps=[
                        {"name": "Triage", "assignee": USERS[0], "action": "review"},
                        {"name": "Remediate", "assignee": USERS[1], "action": "fix"},
                        {"name": "Verify", "assignee": USERS[2], "action": "validate"},
                    ],
                )
                e.create_workflow(wf)
                count += 1
            except Exception as ex:
                print(f"  [WARN] workflow {name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] workflow import: {ex}")
        return 0


# ---------------------------------------------------------------------------
# Security playbook engine
# ---------------------------------------------------------------------------
def seed_security_playbooks():
    from core.security_playbook_engine import SecurityPlaybookEngine
    e = SecurityPlaybookEngine()
    count = 0
    playbooks = [
        ("Ransomware Response", "incident_response", ["isolate", "preserve", "restore"]),
        ("Phishing Triage", "incident_response", ["analyze_email", "check_links", "notify_users"]),
        ("CVE Patch Procedure", "vulnerability", ["identify", "test_patch", "deploy", "verify"]),
        ("DDoS Mitigation", "network", ["detect", "activate_scrubbing", "monitor"]),
    ]
    for name, category, steps in playbooks:
        try:
            e.create_playbook(ORG, {
                "name": name,
                "category": category,
                "steps": [{"step": i+1, "action": s, "assignee": USERS[i % len(USERS)]} for i, s in enumerate(steps)],
                "severity_threshold": "high",
                "auto_trigger": False,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] security_playbook {name}: {ex}")
    return count


# ---------------------------------------------------------------------------
# SOC workflow engine
# ---------------------------------------------------------------------------
def seed_soc_workflow():
    from core.soc_workflow_engine import SOCWorkflowEngine
    e = SOCWorkflowEngine()
    count = 0
    cases = [
        ("Suspicious login from Russia", "authentication_anomaly", "high"),
        ("Malware detected on endpoint", "malware_infection", "critical"),
        ("Data exfiltration attempt", "data_leak", "critical"),
        ("Brute force against admin portal", "brute_force", "high"),
    ]
    for title, wtype, severity in cases:
        try:
            e.create_workflow(ORG, {
                "title": title,
                "workflow_type": wtype,
                "severity": severity,
                "assignee": random.choice(USERS),
                "sla_hours": 4 if severity == "critical" else 8,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] soc_workflow {title[:30]}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Training tracker
# ---------------------------------------------------------------------------
def seed_training():
    from core.training_tracker import TrainingTracker
    e = TrainingTracker()
    count = 0
    # TrainingTracker seeds built-in modules in _seed_builtin_modules
    # Try to enroll users in existing modules
    try:
        modules = e.list_modules()
        for user in USERS[:3]:
            for mod in (modules[:3] if modules else []):
                mid = mod.get("id") or mod.get("module_id")
                try:
                    e.enroll_user(user_id=user, module_id=mid, org_id=ORG)
                    count += 1
                except Exception:
                    pass
    except Exception as ex:
        print(f"  [WARN] training list_modules: {ex}")
    # Also try record_completion directly
    for user in USERS[:2]:
        try:
            e.record_completion(
                user_id=user,
                module_id="security-awareness-101",
                org_id=ORG,
                score=random.randint(75, 100),
                passed=True,
            )
            count += 1
        except Exception:
            pass
    return count


# ---------------------------------------------------------------------------
# Change management (security_change_management_engine)
# ---------------------------------------------------------------------------
def seed_change_management():
    from core.security_change_management_engine import SecurityChangeManagementEngine
    e = SecurityChangeManagementEngine()
    count = 0
    changes = [
        ("Patch OpenSSL on all web servers", "patch", "high"),
        ("Upgrade TLS 1.0 to TLS 1.3", "configuration", "high"),
        ("Enable MFA for all admin accounts", "security_control", "critical"),
        ("Rotate API keys for external integrations", "rotation", "medium"),
        ("Deploy WAF rules for OWASP Top 10", "security_control", "high"),
    ]
    for title, change_type, risk in changes:
        try:
            e.create_change(ORG, {
                "title": title,
                "change_type": change_type,
                "risk_level": risk,
                "description": f"Change: {title}",
                "requested_by": random.choice(USERS),
                "planned_date": _date(days_ahead=random.randint(1, 14)),
                "rollback_plan": "Revert to previous version",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] change_mgmt {title[:30]}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Vulnerability analytics
# ---------------------------------------------------------------------------
def seed_vulnerability_analytics():
    from core.vulnerability_analytics import VulnerabilityAnalytics
    e = VulnerabilityAnalytics()
    count = 0
    events = [
        ("CVE-2024-0001", "opened", "critical", "app-server-01"),
        ("CVE-2024-0002", "opened", "high", "web-server-02"),
        ("CVE-2024-0001", "remediated", "critical", "app-server-01"),
        ("CVE-2024-0003", "opened", "medium", "db-server-01"),
        ("CVE-2024-0004", "opened", "critical", "api-gateway"),
        ("CVE-2024-0002", "remediated", "high", "web-server-02"),
    ]
    for cve, event_type, severity, asset in events:
        try:
            e.record_finding_event(
                org_id=ORG,
                cve_id=cve,
                event_type=event_type,
                severity=severity,
                asset_id=asset,
                scanner="openvas",
            )
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln_analytics {cve}/{event_type}: {ex}")
    return count


# ---------------------------------------------------------------------------
# Metrics aggregator engine
# ---------------------------------------------------------------------------
def seed_metrics_aggregator():
    try:
        from core.security_metrics_aggregator_engine import SecurityMetricsAggregatorEngine
        e = SecurityMetricsAggregatorEngine()
        count = 0
        sources = [
            ("siem-prod", "siem", "https://siem.corp.io"),
            ("edr-agent", "edr", "https://edr.corp.io"),
            ("vuln-scanner", "scanner", "https://scanner.corp.io"),
        ]
        for name, stype, url in sources:
            try:
                src = e.register_source(ORG, {
                    "name": name,
                    "source_type": stype,
                    "endpoint_url": url,
                    "polling_interval_secs": 300,
                })
                sid = src.get("source_id") or src.get("id")
                if sid:
                    for metric_name, value in [("alerts_per_hour", 42), ("endpoint_coverage", 94.5), ("scan_coverage", 88)]:
                        e.record_metric(ORG, {
                            "source_id": sid,
                            "metric_name": metric_name,
                            "value": value,
                            "unit": "count" if isinstance(value, int) else "percent",
                        })
                count += 1
            except Exception as ex:
                print(f"  [WARN] metrics_aggregator {name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] metrics_aggregator import: {ex}")
        return 0


# ---------------------------------------------------------------------------
# Direct SQLite inserts for DBs with no matching engine
# ---------------------------------------------------------------------------
def _direct_insert_generic(db_name: str, table_rows: dict) -> int:
    """Insert rows directly into specified tables for a DB."""
    con = _db(db_name)
    tables = _tables(con)
    count = 0
    for tbl, rows in table_rows.items():
        if tbl not in tables:
            continue
        cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
        for row in rows:
            vals = [row.get(c) for c in cols]
            placeholders = ",".join(["?"] * len(cols))
            try:
                con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({placeholders})", vals)
                count += 1
            except Exception as ex:
                pass
    con.commit()
    con.close()
    return count


def seed_direct_sqlite():
    """Seed remaining DBs via direct SQLite inserts."""
    total = 0

    # users.db
    try:
        con = _db("users.db")
        tables = _tables(con)
        for tbl in tables:
            if "user" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                for i, user in enumerate(USERS):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "email": user, "username": user.split("@")[0],
                        "role": ["admin", "analyst", "viewer", "responder", "analyst"][i],
                        "department": ["Security", "IT", "DevOps", "SecOps", "GRC"][i],
                        "active": True, "created_at": _ts(days_ago=90+i*10),
                        "mfa_enabled": True, "last_login": _ts(days_ago=i),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] users.db: {ex}")

    # policies.db
    try:
        con = _db("policies.db")
        tables = _tables(con)
        for tbl in tables:
            if "polic" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                policy_names = ["Acceptable Use Policy", "Password Policy", "Data Retention Policy", "Incident Response Policy", "Change Management Policy"]
                for i, name in enumerate(policy_names):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG, "name": name,
                        "version": "1.0", "status": "active",
                        "created_at": _ts(days_ago=365-i*30),
                        "updated_at": _ts(days_ago=i*10),
                        "owner": random.choice(USERS),
                        "category": ["security", "technical", "data", "operations", "management"][i],
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] policies.db: {ex}")

    # playbooks.db
    try:
        con = _db("playbooks.db")
        tables = _tables(con)
        for tbl in tables:
            if "playbook" in tbl.lower() or "runbook" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                pb_names = ["Malware Containment", "DDoS Response", "Data Breach Notification", "Insider Threat Response"]
                for i, name in enumerate(pb_names):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG, "name": name,
                        "version": "2.0", "status": "active",
                        "created_at": _ts(days_ago=180-i*30),
                        "severity_threshold": SEVERITIES[i % len(SEVERITIES)],
                        "category": "incident_response",
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] playbooks.db: {ex}")

    # notifications.db
    try:
        con = _db("notifications.db")
        tables = _tables(con)
        for tbl in tables:
            if "notif" in tbl.lower() or "alert" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                notif_types = ["alert", "warning", "info", "critical", "digest"]
                for i, ntype in enumerate(notif_types):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "type": ntype, "channel": ["email", "slack", "pagerduty", "sms", "webhook"][i],
                        "recipient": random.choice(USERS),
                        "message": f"Security notification: {ntype.upper()} event detected",
                        "status": "sent", "sent_at": _ts(days_ago=i),
                        "created_at": _ts(days_ago=i+1),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] notifications.db: {ex}")

    # reports.db
    try:
        con = _db("reports.db")
        tables = _tables(con)
        for tbl in tables:
            if "report" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                report_types = ["executive_summary", "threat_intelligence", "compliance_status", "vulnerability_report", "soc_weekly"]
                for i, rtype in enumerate(report_types):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "type": rtype, "name": f"Security Report: {rtype.replace('_', ' ').title()}",
                        "status": "completed",
                        "created_at": _ts(days_ago=i*7),
                        "generated_by": random.choice(USERS),
                        "format": "pdf",
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] reports.db: {ex}")

    # system_health.db
    try:
        con = _db("system_health.db")
        tables = _tables(con)
        for tbl in tables:
            if "health" in tbl.lower() or "metric" in tbl.lower() or "status" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                services = ["api-server", "siem-connector", "threat-feed", "auth-service", "db-engine"]
                for i, svc in enumerate(services):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "service": svc, "status": "healthy",
                        "cpu_pct": random.uniform(10, 75),
                        "memory_pct": random.uniform(20, 85),
                        "latency_ms": random.uniform(5, 200),
                        "uptime_pct": random.uniform(99.0, 99.99),
                        "checked_at": _ts(days_ago=0, hours_ago=i),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] system_health.db: {ex}")

    # threat_hunting.db / threat_hunt_rules.db
    for db_name in ["threat_hunting.db", "threat_hunt_rules.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "hunt" in tbl.lower() or "rule" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    for i in range(5):
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "name": f"Hunt rule #{i+1}: {['Beacon', 'Lateral', 'Exfil', 'Persistence', 'C2'][i]}",
                            "tactic": ["command_and_control", "lateral_movement", "exfiltration", "persistence", "command_and_control"][i],
                            "query": f"SELECT * FROM events WHERE type = '{['network', 'auth', 'file', 'registry', 'dns'][i]}'",
                            "severity": SEVERITIES[i % len(SEVERITIES)],
                            "enabled": True,
                            "created_at": _ts(days_ago=30+i*5),
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # posture_advisor.db
    try:
        con = _db("posture_advisor.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(5):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "domain": ["network", "endpoint", "identity", "data", "application"][i],
                    "score": random.randint(55, 95),
                    "risk_level": SEVERITIES[i % len(SEVERITIES)],
                    "recommendation": f"Improve {['network segmentation', 'patch coverage', 'MFA adoption', 'encryption', 'SAST coverage'][i]}",
                    "priority": i + 1,
                    "created_at": _ts(days_ago=7),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] posture_advisor.db: {ex}")

    # rbac.db — direct insert if engine fails
    try:
        con = _db("rbac.db")
        tables = _tables(con)
        for tbl in tables:
            if "role" in tbl.lower() or "rbac" in tbl.lower() or "assignment" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                for i, (user, role) in enumerate(zip(USERS, ["admin", "analyst", "viewer", "responder", "analyst"])):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "user_id": user, "role": role,
                        "granted_by": "system", "granted_at": _ts(days_ago=90+i),
                        "active": True,
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] rbac.db: {ex}")

    # workflows.db / workflow_engine.db
    for db_name in ["workflows.db", "workflow_engine.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "workflow" in tbl.lower() or "process" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    wf_types = ["incident_response", "remediation", "change_approval", "access_request", "escalation"]
                    for i, wtype in enumerate(wf_types):
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "name": f"{wtype.replace('_', ' ').title()} Workflow",
                            "workflow_type": wtype,
                            "status": ["active", "in_progress", "completed", "pending", "active"][i],
                            "created_at": _ts(days_ago=30+i*5),
                            "owner": random.choice(USERS),
                            "priority": ["critical", "high", "medium", "low", "high"][i],
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # evidence_chain.db / evidence_collector.db
    for db_name in ["evidence_chain.db", "evidence_collector.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "evidence" in tbl.lower() or "chain" in tbl.lower() or "artifact" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    for i in range(5):
                        content = f"Evidence artifact {i+1}: network capture from {HOSTS[i]}"
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "name": f"Evidence-{i+1:03d}",
                            "type": ["pcap", "memory_dump", "log_file", "screenshot", "email"][i],
                            "hash": hashlib.sha256(content.encode()).hexdigest(),
                            "source": HOSTS[i], "collected_at": _ts(days_ago=i),
                            "collector": random.choice(USERS),
                            "status": "collected",
                            "size_bytes": random.randint(1024, 10_000_000),
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # sla_tracking.db
    try:
        con = _db("sla_tracking.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(5):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "ticket_id": f"INC-{1000+i}",
                    "severity": SEVERITIES[i % len(SEVERITIES)],
                    "sla_hours": [1, 4, 8, 24, 48][i],
                    "created_at": _ts(days_ago=i+1),
                    "resolved_at": _ts(days_ago=i) if i < 3 else None,
                    "breached": i > 2,
                    "status": "resolved" if i < 3 else "open",
                    "assignee": random.choice(USERS),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] sla_tracking.db: {ex}")

    # zero_trust.db / zero_trust_engine.db
    for db_name in ["zero_trust.db", "zero_trust_engine.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "trust" in tbl.lower() or "policy" in tbl.lower() or "access" in tbl.lower() or "event" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    for i in range(5):
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "name": f"ZT-Policy-{i+1}: {['Device Trust', 'User Identity', 'Network Segment', 'App Access', 'Data Access'][i]}",
                            "category": ["device", "identity", "network", "application", "data"][i],
                            "action": ["allow", "block", "allow", "block", "allow"][i],
                            "risk_score": random.randint(10, 90),
                            "enabled": True,
                            "created_at": _ts(days_ago=60+i*10),
                            "status": "active",
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # vuln_prioritizer.db
    try:
        con = _db("vuln_prioritizer.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(6):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "cve_id": f"CVE-2024-{5000+i}",
                    "cvss_score": round(random.uniform(5.0, 10.0), 1),
                    "epss_score": round(random.uniform(0.01, 0.99), 3),
                    "kev": i < 2,
                    "priority_score": round(random.uniform(40, 100), 1),
                    "priority_rank": i + 1,
                    "asset_id": random.choice(HOSTS),
                    "severity": SEVERITIES[i % len(SEVERITIES)],
                    "created_at": _ts(days_ago=30-i*4),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] vuln_prioritizer.db: {ex}")

    # vuln_lifecycle.db
    try:
        con = _db("vuln_lifecycle.db")
        tables = _tables(con)
        for tbl in tables:
            if "lifecycle" in tbl.lower() or "vuln" in tbl.lower() or "finding" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                for i in range(5):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "cve_id": f"CVE-2024-{6000+i}",
                        "title": f"Vulnerability {i+1}: {['RCE', 'SQLi', 'XSS', 'SSRF', 'LFI'][i]}",
                        "severity": SEVERITIES[i % len(SEVERITIES)],
                        "cvss": round(random.uniform(5.0, 10.0), 1),
                        "status": ["open", "triaged", "in_remediation", "resolved", "accepted_risk"][i],
                        "asset_id": random.choice(HOSTS),
                        "discovered_at": _ts(days_ago=30+i*5),
                        "updated_at": _ts(days_ago=i),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] vuln_lifecycle.db: {ex}")

    # insider_threat.db direct
    try:
        con = _db("insider_threat.db")
        tables = _tables(con)
        for tbl in tables:
            if "event" in tbl.lower() or "risk" in tbl.lower() or "alert" in tbl.lower():
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                for i, user in enumerate(USERS):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "user_id": user,
                        "event_type": ["large_download", "after_hours_access", "privilege_escalation", "mass_email", "vpn_anomaly"][i],
                        "severity": SEVERITIES[i % len(SEVERITIES)],
                        "risk_score": random.randint(30, 95),
                        "details": json.dumps({"source_ip": random.choice(IPS)}),
                        "created_at": _ts(days_ago=i+1),
                        "status": "open",
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] insider_threat.db direct: {ex}")

    # training.db / training_progress.db
    for db_name in ["training.db", "training_progress.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "train" in tbl.lower() or "module" in tbl.lower() or "progress" in tbl.lower() or "completion" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    modules = ["Security Awareness 101", "Phishing Recognition", "Password Best Practices", "Data Handling", "Incident Reporting"]
                    for i, (user, mod) in enumerate([(u, modules[i % len(modules)]) for i, u in enumerate(USERS * 2)]):
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "user_id": user,
                            "module_id": f"mod-{i+1:03d}",
                            "module_name": mod,
                            "status": ["completed", "in_progress", "completed", "not_started", "completed"][i % 5],
                            "score": random.randint(70, 100) if i % 5 in [0, 2, 4] else None,
                            "completed_at": _ts(days_ago=random.randint(1, 60)) if i % 5 in [0, 2, 4] else None,
                            "created_at": _ts(days_ago=90+i*5),
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # sbom.db
    try:
        con = _db("sbom.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            if "sbom" in tbl.lower() or "component" in tbl.lower() or "package" in tbl.lower():
                packages = [
                    ("django", "4.2.1", "python", "MIT"),
                    ("fastapi", "0.104.0", "python", "MIT"),
                    ("react", "18.2.0", "javascript", "MIT"),
                    ("openssl", "3.1.2", "c", "OpenSSL"),
                    ("log4j-core", "2.20.0", "java", "Apache-2.0"),
                ]
                for i, (name, ver, lang, lic) in enumerate(packages):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(), "org_id": ORG,
                        "name": name, "version": ver,
                        "language": lang, "license": lic,
                        "purl": f"pkg:{lang}/{name}@{ver}",
                        "risk_level": ["low", "low", "low", "medium", "high"][i],
                        "created_at": _ts(days_ago=30),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        total += 1
                    except Exception:
                        pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] sbom.db: {ex}")

    # mpte.db
    try:
        con = _db("mpte.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(5):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "name": f"MPTE Scenario {i+1}: {['Ransomware', 'APT', 'Supply Chain', 'Insider', 'DDoS'][i]}",
                    "status": ["running", "completed", "planned", "running", "completed"][i],
                    "severity": SEVERITIES[i % len(SEVERITIES)],
                    "created_at": _ts(days_ago=30+i*5),
                    "target_system": random.choice(HOSTS),
                    "technique": f"T{1059+i}",
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] mpte.db: {ex}")

    # user_analytics.db
    try:
        con = _db("user_analytics.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i, user in enumerate(USERS):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "user_id": user,
                    "page_views": random.randint(50, 500),
                    "api_calls": random.randint(100, 5000),
                    "alerts_reviewed": random.randint(10, 200),
                    "avg_session_mins": round(random.uniform(5, 60), 1),
                    "last_active": _ts(days_ago=i),
                    "risk_score": random.randint(10, 80),
                    "created_at": _ts(days_ago=90),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] user_analytics.db: {ex}")

    # vendor_risk.db / vendor_risk_engine.db
    for db_name in ["vendor_risk.db", "vendor_risk_engine.db"]:
        try:
            con = _db(db_name)
            tables = _tables(con)
            for tbl in tables:
                if "vendor" in tbl.lower() or "risk" in tbl.lower() or "assessment" in tbl.lower():
                    cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                    vendors = ["Salesforce", "AWS", "Zoom", "GitHub", "Okta"]
                    for i, vendor in enumerate(vendors):
                        row = {c: None for c in cols}
                        row.update({
                            "id": _id(), "org_id": ORG,
                            "vendor_name": vendor, "name": vendor,
                            "category": ["crm", "cloud", "communications", "devtools", "identity"][i],
                            "risk_score": random.randint(20, 80),
                            "risk_level": SEVERITIES[i % len(SEVERITIES)],
                            "status": "active",
                            "last_assessed": _ts(days_ago=random.randint(30, 180)),
                            "created_at": _ts(days_ago=365),
                        })
                        vals = [row.get(c) for c in cols]
                        try:
                            con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                            total += 1
                        except Exception:
                            pass
            con.commit()
            con.close()
        except Exception as ex:
            print(f"  [WARN] {db_name}: {ex}")

    # supply_chain.db
    try:
        con = _db("supply_chain.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(5):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "supplier_name": ["ACME Corp", "TechVend", "CloudPlus", "SecureSoft", "DataSystems"][i],
                    "component": ["ssl-library", "auth-module", "cloud-sdk", "crypto-lib", "data-connector"][i],
                    "version": f"1.{i}.0",
                    "risk_score": random.randint(10, 90),
                    "status": ["approved", "under_review", "approved", "blocked", "approved"][i],
                    "created_at": _ts(days_ago=60+i*10),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] supply_chain.db: {ex}")

    # security_kpi.db direct
    try:
        con = _db("security_kpi.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            kpis = [
                ("mttd_hours", 4.2, 2.0, "hours"),
                ("mttr_hours", 18.5, 8.0, "hours"),
                ("patch_compliance_pct", 87.3, 95.0, "percent"),
                ("mfa_adoption_pct", 94.1, 100.0, "percent"),
                ("critical_vulns_open", 12, 0, "count"),
            ]
            for i, (metric, val, target, unit) in enumerate(kpis):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "metric_name": metric, "value": val,
                    "target": target, "unit": unit,
                    "period": "monthly",
                    "recorded_at": _ts(days_ago=i),
                    "created_at": _ts(days_ago=i),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] security_kpi.db direct: {ex}")

    # security_scorecard.db direct
    try:
        con = _db("security_scorecard.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            entities = ["ALDECI Platform", "AWS Infrastructure", "Corporate Endpoints", "Supply Chain"]
            for i, entity in enumerate(entities):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "entity_name": entity,
                    "entity_type": ["internal", "cloud", "endpoint", "third_party"][i],
                    "overall_score": random.randint(60, 95),
                    "grade": ["A", "B", "B", "C"][i],
                    "created_at": _ts(days_ago=7+i*7),
                    "status": "active",
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] security_scorecard.db direct: {ex}")

    # metrics_aggregator.db direct
    try:
        con = _db("metrics_aggregator.db")
        tables = _tables(con)
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i in range(5):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "source": ["siem", "edr", "scanner", "firewall", "cloud"][i],
                    "metric_name": ["alerts_per_hour", "endpoint_health", "vuln_count", "blocked_conns", "misconfigs"][i],
                    "value": random.uniform(1, 1000),
                    "unit": ["count", "percent", "count", "count", "count"][i],
                    "recorded_at": _ts(days_ago=i),
                    "created_at": _ts(days_ago=i),
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] metrics_aggregator.db direct: {ex}")

    # ip_reputation.db direct
    try:
        con = _db("ip_reputation.db")
        tables = _tables(con)
        malicious_ips = ["185.220.101.1", "198.20.69.74", "91.108.4.1", "45.33.32.156", "192.168.1.100"]
        for tbl in tables:
            cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
            for i, ip in enumerate(malicious_ips):
                row = {c: None for c in cols}
                row.update({
                    "id": _id(), "org_id": ORG,
                    "ip": ip, "ip_address": ip,
                    "score": [15, 10, 20, 25, 85][i],
                    "risk_level": ["critical", "critical", "high", "high", "low"][i],
                    "category": ["tor_exit", "botnet", "spam", "scanner", "trusted"][i],
                    "source": "threat_intel",
                    "created_at": _ts(days_ago=i),
                    "updated_at": _ts(days_ago=i),
                    "blocked": i < 3,
                })
                vals = [row.get(c) for c in cols]
                try:
                    con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                    total += 1
                except Exception:
                    pass
        con.commit()
        con.close()
    except Exception as ex:
        print(f"  [WARN] ip_reputation.db direct: {ex}")

    # Catch-all: seed remaining empty DBs generically
    remaining_dbs = [
        "ai_orchestrator.db", "anomaly_ml_engine.db", "api_analytics.db", "api_versioning.db",
        "audit_trail.db", "auth.db", "auto_evidence.db", "breach_simulation.db",
        "bulk_operations.db", "cicd_integration.db", "collaboration.db", "compliance_planner.db",
        "cwpp.db", "dashboard_builder.db", "developer_portal.db", "developer_profiles.db",
        "dlp.db", "enhanced_council.db", "event_emitter.db", "exception_policy.db",
        "executive_reports.db", "feed_manager.db", "github_issues.db", "iac.db", "iga.db",
        "integrations.db", "inventory.db", "ir_playbook.db", "mcp_state.db",
        "network_analyzer.db", "network_security.db", "onboarding.db",
        "rasp_engine.db", "report_schedules.db", "results.db", "secrets.db",
        "security_kb.db", "sla_escalation.db", "soar_engine.db", "soc_automation.db",
        "state.db", "vulnerability_analytics.db", "webhook_dlq.db", "webhook_verifier.db",
    ]

    for db_name in remaining_dbs:
        try:
            con = _db(db_name)
            if _count(con) > 0:
                con.close()
                continue
            tables = _tables(con)
            inserted = 0
            for tbl in tables:
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                if not cols:
                    continue
                for i in range(3):
                    row = {c: None for c in cols}
                    row.update({
                        "id": _id(),
                        "org_id": ORG,
                        "created_at": _ts(days_ago=30+i*5),
                        "updated_at": _ts(days_ago=i),
                        "status": "active",
                        "name": f"{db_name.replace('.db','').replace('_', ' ').title()} record {i+1}",
                        "type": "automated_seed",
                        "severity": SEVERITIES[i % len(SEVERITIES)],
                        "description": f"Demo data for {db_name}",
                        "value": random.randint(1, 100),
                        "score": random.uniform(50, 95),
                        "enabled": True,
                        "active": True,
                        "count": random.randint(1, 50),
                    })
                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
                        inserted += 1
                    except Exception:
                        pass
            con.commit()
            total += inserted
            con.close()
        except Exception as ex:
            print(f"  [WARN] catch-all {db_name}: {ex}")

    return total


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
SEEDERS = [
    ("api_discovery_fix",       seed_api_discovery_fix),
    ("api_gateway_fix",         seed_api_gateway_fix),
    ("cloud_accounts_fix",      seed_cloud_accounts_fix),
    ("cloud_governance_fix",    seed_cloud_governance_fix),
    ("compliance_gaps_fix",     seed_compliance_gaps_fix),
    ("container_registry_fix",  seed_container_registry_fix),
    ("container_runtime_fix",   seed_container_runtime_fix),
    ("crypto_keys_fix",         seed_crypto_keys_fix),
    ("ddos_fix",                seed_ddos_fix),
    ("digital_identity_fix",    seed_digital_identity_fix),
    ("firewall_fix",            seed_firewall_fix),
    ("forensics_readiness_fix", seed_forensics_readiness_fix),
    ("dlp",                     seed_dlp),
    ("insider_threat",          seed_insider_threat),
    ("ip_reputation",           seed_ip_reputation),
    ("sbom",                    seed_sbom),
    ("vuln_lifecycle",          seed_vuln_lifecycle),
    ("sla_escalation",          seed_sla_escalation),
    ("zero_trust",              seed_zero_trust),
    ("rbac",                    seed_rbac),
    ("pentest",                 seed_pentest),
    ("scorecard",               seed_scorecard),
    ("security_kpi",            seed_security_kpi),
    ("vuln_risk_scores",        seed_vuln_risk_scores),
    ("vendor_risk",             seed_vendor_risk),
    ("vendor_scorecard",        seed_vendor_scorecard),
    ("supply_chain",            seed_supply_chain),
    ("threat_hunting",          seed_threat_hunting),
    ("ir_playbook",             seed_ir_playbook),
    ("workflow",                seed_workflow),
    ("security_playbooks",      seed_security_playbooks),
    ("soc_workflow",            seed_soc_workflow),
    ("training",                seed_training),
    ("change_management",       seed_change_management),
    ("vulnerability_analytics", seed_vulnerability_analytics),
    ("metrics_aggregator",      seed_metrics_aggregator),
    ("direct_sqlite",           seed_direct_sqlite),
]


def main():
    print(f"\nALDECI Remaining Engine Seeder — {len(SEEDERS)} seeders")
    print(f"  Org ID : {ORG}")
    print(f"  Time   : {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    ok = fail = total_records = 0
    for name, fn in SEEDERS:
        try:
            n = fn()
            ok += 1
            total_records += (n or 0)
            print(f"  [OK ] {name}: {n} records")
        except Exception as exc:
            fail += 1
            print(f"  [FAIL] {name}: {exc}")

    print(f"\n  Done: {ok}/{len(SEEDERS)} seeders ran, {fail} failed, {total_records} total records inserted")

    # Final count
    empty = 0
    for f in sorted((DATA_DIR).iterdir()):
        if not f.name.endswith('.db'):
            continue
        try:
            con = sqlite3.connect(str(f))
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            rows = sum(con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] for t in tables)
            if rows == 0:
                empty += 1
                print(f"  [EMPTY] {f.name}")
            con.close()
        except Exception:
            pass
    print(f"\n  Remaining empty DBs: {empty}")


if __name__ == "__main__":
    main()
