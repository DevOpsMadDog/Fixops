#!/usr/bin/env python3
"""Final targeted fixes for engines that still have empty DBs.

Run from repo root:
    PYTHONPATH="suite-core:suite-api" python3 scripts/seed_final_fix.py
"""
from __future__ import annotations
import sys, sqlite3, random, uuid, json, hashlib
from datetime import datetime, timezone, timedelta, date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "suite-core"))
sys.path.insert(0, str(ROOT / "suite-api"))

ORG = "default"
random.seed(7)
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

def _db(name):
    path = DATA_DIR / name
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    return con

def _tables(con):
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()]

def _count(con):
    return sum(con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] for t in _tables(con))


# ---------------------------------------------------------------------------
def seed_api_discovery():
    from core.api_discovery_engine import APIDiscoveryEngine
    e = APIDiscoveryEngine()
    count = 0
    services = [
        ("Auth Discovery", "https://auth.internal/api"),
        ("Payment Discovery", "https://pay.internal/api"),
        ("User Discovery", "https://users.internal/api"),
    ]
    for scan_name, target in services:
        try:
            scan = e.create_scan(ORG, {"scan_name": scan_name, "scan_target": target, "scan_type": "passive"})
            sid = scan.get("scan_id") or scan.get("id")
            for i in range(2):
                e.register_endpoint(ORG, {
                    "path": f"/api/v1/{scan_name.split()[0].lower()}/{i}",
                    "method": ["GET", "POST"][i],
                    "service": scan_name,
                    "authenticated": True,
                    "documented": True,
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_discovery {scan_name}: {ex}")
    return count


def seed_api_gateway():
    from core.api_gateway_security_engine import APIGatewaySecurityEngine
    e = APIGatewaySecurityEngine()
    count = 0
    gateways = [
        ("Main API Gateway", "kong", "https://api.corp.io"),
        ("Internal Gateway", "nginx", "https://internal.corp.io"),
        ("Partner Gateway", "aws_api_gw", "https://partner.corp.io"),
    ]
    for name, gtype, url in gateways:
        try:
            gw = e.register_gateway(ORG, {
                "name": name, "gateway_type": gtype,
                "base_url": url, "environment": "production",
            })
            gw_id = gw.get("id") or gw.get("gateway_id")
            if gw_id:
                e.register_api(ORG, {
                    "gateway_id": gw_id, "name": f"{name} - Users API",
                    "path": "/api/v1/users", "method": "GET", "auth_type": "bearer",
                })
                e.record_security_event(ORG, {
                    "gateway_id": gw_id, "event_type": "rate_limit_exceeded",
                    "source_ip": random.choice(IPS), "severity": "medium",
                    "description": "Rate limit exceeded",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] api_gateway {name}: {ex}")
    return count


def seed_cloud_accounts():
    from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine
    e = CloudAccountMonitoringEngine()
    count = 0
    accounts = [
        (f"aws-{_id()[:8]}", "AWS Production", "aws", "us-east-1"),
        (f"az-{_id()[:8]}", "Azure Corp", "azure", "eastus"),
        (f"gcp-{_id()[:8]}", "GCP Data", "gcp", "us-central1"),
    ]
    for acct_id, name, provider, region in accounts:
        try:
            r = e.register_account(ORG, acct_id, name, provider, region)
            aid = r.get("account_id") or r.get("id")
            if aid:
                e.record_event(ORG, {
                    "account_id": aid, "event_type": "config_change",
                    "severity": "medium", "description": "Security group modified",
                    "resource_id": f"sg-{_id()[:8]}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_accounts {name}: {ex}")
    return count


def seed_cloud_governance():
    from core.cloud_governance_engine import CloudGovernanceEngine
    e = CloudGovernanceEngine()
    count = 0
    policies = [
        ("No public S3 buckets", "storage", "security"),
        ("Require MFA for console", "identity", "security"),
        ("No unencrypted EBS volumes", "compute", "compliance"),
        ("Approved AWS regions only", "network", "compliance"),
    ]
    for name, resource_type, policy_type in policies:
        try:
            p = e.create_governance_policy(ORG, {
                "name": name, "resource_type": resource_type,
                "policy_type": policy_type, "provider": "aws",
                "severity": "high", "description": name,
            })
            pid = p.get("policy_id") or p.get("id")
            if pid:
                e.record_violation(ORG, {
                    "policy_id": pid, "resource_id": f"res-{_id()[:8]}",
                    "resource_type": resource_type, "severity": "high",
                    "description": f"Violation of: {name}",
                    "account_id": "aws-123456789",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] cloud_governance {name}: {ex}")
    return count


def seed_compliance_gaps():
    from core.compliance_gap_engine import ComplianceGapEngine
    e = ComplianceGapEngine()
    count = 0
    assessments = [
        ("SOC2 Q1 2025", "soc2"),
        ("PCI DSS v4.0", "pci_dss"),
        ("ISO 27001 2025", "iso27001"),
    ]
    for assessment_name, framework in assessments:
        try:
            a = e.create_assessment(ORG, {
                "assessment_name": assessment_name,
                "framework": framework, "scope": "enterprise",
            })
            aid = a.get("assessment_id") or a.get("id")
            if aid:
                e.add_control_gap(ORG, {
                    "assessment_id": aid,
                    "control_id": f"{framework.upper()}-CC6.1",
                    "control_name": "Logical Access Controls",
                    "gap_description": "MFA not enforced for privileged accounts",
                    "severity": "high",
                    "current_state": "partial",
                    "target_state": "full_compliance",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] compliance_gaps {assessment_name}: {ex}")
    return count


def seed_container_registry():
    from core.container_registry_security_engine import ContainerRegistrySecurityEngine
    e = ContainerRegistrySecurityEngine()
    count = 0
    registries = [
        ("AWS ECR Production", "ecr", "123456789.dkr.ecr.us-east-1.amazonaws.com"),
        ("Docker Hub Corporate", "docker", "registry.hub.docker.com"),
        ("Azure Container Registry", "acr", "corp.azurecr.io"),
        ("GCR Production", "gcr", "gcr.io/corp-project"),
    ]
    for name, rtype, url in registries:
        try:
            r = e.register_registry(ORG, {"name": name, "registry_type": rtype, "url": url, "private": True})
            rid = r.get("registry_id") or r.get("id")
            if rid:
                e.scan_image(ORG, {
                    "registry_id": rid,
                    "image_name": "myapp/api",
                    "image_tag": "latest",
                    "image_digest": f"sha256:{hashlib.sha256(name.encode()).hexdigest()}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] container_registry {name}: {ex}")
    return count


def seed_container_runtime():
    from core.container_runtime_security_engine import ContainerRuntimeSecurityEngine
    e = ContainerRuntimeSecurityEngine()
    count = 0
    containers = [
        ("api-backend-01", "network_connection"),
        ("db-postgres-01", "file_write"),
        ("redis-cache-01", "exec_command"),
    ]
    for cname, etype in containers:
        try:
            c = e.register_container(ORG, {
                "container_name": cname, "image": f"corp/{cname}:latest",
                "namespace": "production", "pod_name": f"pod-{cname}",
                "node_name": random.choice(HOSTS),
            })
            cid = c.get("container_id") or c.get("id")
            if cid:
                e.record_runtime_event(ORG, {
                    "container_id": cid, "event_type": etype,
                    "severity": "high", "description": f"Runtime: {etype} on {cname}",
                    "source_ip": random.choice(IPS),
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] container_runtime {cname}: {ex}")
    return count


def seed_ddos():
    from core.ddos_protection_engine import DDoSProtectionEngine
    e = DDoSProtectionEngine()
    count = 0
    resources = [
        ("Customer Portal", "https://portal.corp.io", "web_application"),
        ("API Gateway", "https://api.corp.io", "api_endpoint"),
        ("DNS Servers", "8.8.8.1", "dns"),
        ("Load Balancer", "10.0.1.1", "network"),
    ]
    for name, endpoint, rtype in resources:
        try:
            r = e.register_protected_resource(ORG, {
                "name": name, "ip_or_fqdn": endpoint,
                "resource_type": rtype, "protection_tier": "advanced",
                "threshold_pps": 100000,
            })
            rid = r.get("resource_id") or r.get("id")
            if rid:
                e.record_attack_event(ORG, {
                    "resource_id": rid, "attack_type": "volumetric",
                    "source_ips": random.sample(IPS, 2),
                    "peak_pps": random.randint(50000, 500000),
                    "severity": "high", "description": f"DDoS on {name}",
                })
            count += 1
        except Exception as ex:
            print(f"  [WARN] ddos {name}: {ex}")
    return count


def seed_digital_identity():
    from core.digital_identity_engine import DigitalIdentityEngine
    e = DigitalIdentityEngine()
    count = 0
    uid = _id()[:6]
    profiles = [
        (f"alice-{uid}@corp.io", "IAL2", "employee"),
        (f"bob-{uid}@corp.io", "IAL1", "contractor"),
        (f"carol-{uid}@corp.io", "IAL3", "admin"),
    ]
    for user_id, ial, role in profiles:
        try:
            p = e.create_profile(ORG, {
                "user_id": user_id, "identity_assurance_level": ial,
                "role": role, "email": user_id,
                "mfa_enabled": True, "department": "Engineering",
            })
            pid = p.get("profile_id") or p.get("identity_id") or p.get("id")
            if pid:
                try:
                    e.record_verification_event(ORG, {
                        "identity_id": pid, "event_type": "login",
                        "method": "password+totp", "success": True,
                        "ip_address": random.choice(IPS),
                    })
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] digital_identity {user_id}: {ex}")
    return count


def seed_firewall():
    from core.firewall_policy_engine import FirewallPolicyEngine
    e = FirewallPolicyEngine()
    count = 0
    firewalls = [
        ("Core Perimeter Firewall", "palo_alto", "perimeter"),
        ("Internal Segmentation FW", "fortinet", "internal"),
        ("Cloud Security Group", "aws_sg", "cloud"),
    ]
    for name, vendor, fw_type in firewalls:
        try:
            fw = e.register_firewall(ORG, {
                "name": name, "vendor": vendor, "fw_type": vendor,
                "ip_address": random.choice(IPS), "environment": "production",
            })
            fw_id = fw.get("firewall_id") or fw.get("id")
            if fw_id:
                for i in range(3):
                    e.add_rule(ORG, fw_id, {
                        "name": f"Rule-{i+1}: {['Allow HTTPS', 'Allow SSH', 'Deny All'][i]}",
                        "action": ["allow", "allow", "deny"][i],
                        "source_zones": ["external"],
                        "dest_zones": ["dmz"],
                        "ports": [["443", "22", "0"][i]],
                        "protocols": ["tcp"],
                        "order_num": i + 1,
                        "enabled": True,
                    })
            count += 1
        except Exception as ex:
            print(f"  [WARN] firewall {name}: {ex}")
    return count


def seed_forensics():
    from core.forensics_readiness_engine import ForensicsReadinessEngine
    e = ForensicsReadinessEngine()
    count = 0
    sources = [
        ("SIEM Event Logs", "endpoint_logs", "agent", 90),
        ("Network PCAP", "network_pcap", "api", 7),
        ("Cloud Trail Logs", "cloud_trail", "api", 365),
        ("Database Audit Logs", "database_audit", "syslog", 180),
        ("Email Archive", "email_archive", "api", 730),
    ]
    for name, source_type, method, retention in sources:
        try:
            e.register_evidence_source(ORG, {
                "name": name, "source_type": source_type,
                "retention_days": retention, "collection_method": method,
                "location": f"s3://forensics/{name.lower().replace(' ', '-')}",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] forensics {name}: {ex}")
    return count


def seed_insider_threat():
    from core.insider_threat_engine import InsiderThreatEngine
    e = InsiderThreatEngine()
    count = 0
    events = [
        ("user-alice", "large_download", "high", "s3://sensitive-bucket", {"bytes": 5_000_000_000}),
        ("user-bob", "after_hours_access", "medium", "finance_db", {"time": "02:30 AM"}),
        ("user-carol", "privilege_escalation", "critical", "admin_console", {"from_role": "viewer"}),
        ("user-dave", "mass_email", "high", "email_server", {"recipients": 500}),
        ("user-eve", "vpn_anomaly", "medium", "vpn_gateway", {"location": "Unknown"}),
    ]
    for user_id, etype, severity, resource, details in events:
        try:
            e.record_user_event(
                org_id=ORG, user_id=user_id, event_type=etype,
                resource=resource, severity=severity, details=details,
            )
            count += 1
        except Exception as ex:
            print(f"  [WARN] insider_threat {user_id}: {ex}")
    return count


def seed_sbom():
    from core.sbom_engine import SBOMEngine
    e = SBOMEngine()
    count = 0
    # Register an asset first, then add components
    try:
        asset = e.register_asset(ORG, {
            "asset_name": "ALDECI Platform",
            "asset_type": "application",
            "version": "1.0.0",
            "description": "Main security platform",
        })
        asset_id = asset.get("asset_id") or asset.get("id")
        components = [
            ("django", "4.2.1", "framework", "MIT", "python"),
            ("fastapi", "0.104.0", "framework", "MIT", "python"),
            ("react", "18.2.0", "library", "MIT", "javascript"),
            ("openssl", "3.1.2", "library", "OpenSSL", "c"),
            ("log4j-core", "2.20.0", "library", "Apache-2.0", "java"),
        ]
        for name, version, ctype, lic, ecosystem in components:
            try:
                e.add_component(ORG, asset_id, {
                    "name": name, "version": version,
                    "component_type": ctype, "license": lic,
                    "ecosystem": ecosystem,
                    "purl": f"pkg:{ecosystem}/{name}@{version}",
                })
                count += 1
            except Exception as ex:
                print(f"  [WARN] sbom component {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] sbom asset: {ex}")
    return count


def seed_zero_trust():
    from core.zero_trust_policy_engine import ZeroTrustPolicyEngine
    e = ZeroTrustPolicyEngine()
    count = 0
    policies = [
        ("Block Unmanaged Devices", "device", "block"),
        ("Require MFA - Identity", "identity", "allow"),
        ("Micro-segment Network", "network", "block"),
        ("App Access Control", "application", "allow"),
        ("Device Health Check", "device", "block"),
    ]
    for name, ptype, action in policies:
        try:
            p = e.create_policy(ORG, {
                "name": name, "policy_type": ptype, "action": action,
                "conditions": {"risk_score_threshold": 70},
                "enabled": True, "description": f"Zero Trust: {name}",
            })
            pid = p.get("policy_id") or p.get("id")
            if pid:
                try:
                    e.evaluate_access(ORG, {
                        "policy_id": pid,
                        "user_id": random.choice(USERS),
                        "resource": f"resource-{_id()[:8]}",
                        "context": {"device_managed": True, "mfa_verified": True},
                    })
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] zero_trust {name}: {ex}")
    return count


def seed_rbac():
    from core.rbac_engine import RBACEngine
    e = RBACEngine()
    count = 0
    # Use actual valid roles from the engine
    assignments = [
        ("alice@corp.io", "super_admin"),
        ("bob@corp.io", "analyst"),
        ("carol@corp.io", "org_admin"),
        ("dave@corp.io", "security_engineer"),
        ("eve@corp.io", "viewer"),
    ]
    for user_id, role in assignments:
        try:
            e.assign_role(user_id=user_id, role=role, org_id=ORG)
            count += 1
        except Exception as ex:
            print(f"  [WARN] rbac {user_id}/{role}: {ex}")
    return count


def seed_pentest():
    from core.pentest_mgmt_engine import PentestMgmtEngine
    e = PentestMgmtEngine()
    count = 0
    engagements = [
        ("Q1 2025 External Pentest", "external", "black_box"),
        ("API Security Assessment", "api", "grey_box"),
        ("Internal Network Pentest", "internal", "white_box"),
    ]
    for name, scope, methodology in engagements:
        try:
            eng = e.create_engagement(ORG, {
                "name": name, "scope": scope, "methodology": methodology,
                "start_date": _date(days_ago=30), "end_date": _date(days_ago=7),
                "team": ["alice@corp.io"], "target_systems": [random.choice(HOSTS)],
            })
            eid = eng.get("engagement_id") or eng.get("id")
            if eid:
                try:
                    e.update_engagement_status(ORG, eid, "in_progress")
                except Exception:
                    pass
            count += 1
        except Exception as ex:
            print(f"  [WARN] pentest {name}: {ex}")
    return count


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
            e.create_scorecard(ORG, {
                "entity_name": entity_name, "entity_type": entity_type,
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
    for cve, etype, severity, asset in events:
        try:
            e.record_finding_event(
                org_id=ORG, cve_id=cve, event_type=etype,
                severity=severity, asset_id=asset, scanner="openvas",
            )
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln_analytics {cve}: {ex}")
    return count


def seed_vuln_risk_scores():
    from core.vuln_risk_scoring import VulnRiskScorer
    e = VulnRiskScorer()
    count = 0
    vulns = [
        {"cve_id": "CVE-2024-1111", "cvss_score": 9.8, "epss_score": 0.92, "kev": True, "asset_criticality": "critical", "exposure": "internet"},
        {"cve_id": "CVE-2024-2222", "cvss_score": 7.5, "epss_score": 0.45, "kev": False, "asset_criticality": "high", "exposure": "internal"},
        {"cve_id": "CVE-2024-3333", "cvss_score": 5.0, "epss_score": 0.12, "kev": False, "asset_criticality": "medium", "exposure": "internal"},
    ]
    for v in vulns:
        try:
            result = e.score_vulnerability(ORG, v)
            e.save_score(ORG, v["cve_id"], result)
            count += 1
        except Exception as ex:
            print(f"  [WARN] vuln_risk {v['cve_id']}: {ex}")
    return count


def seed_soc_workflow():
    from core.soc_workflow_engine import SOCWorkflowEngine
    e = SOCWorkflowEngine()
    count = 0
    cases = [
        ("Suspicious login from Russia", "authentication_anomaly", "high"),
        ("Malware detected on endpoint", "malware_infection", "critical"),
        ("Brute force on admin portal", "brute_force", "high"),
        ("Data exfiltration attempt", "data_leak", "critical"),
    ]
    for title, wtype, severity in cases:
        try:
            e.create_workflow(ORG, {
                "title": title, "workflow_type": wtype, "severity": severity,
                "assignee": random.choice(USERS), "sla_hours": 4,
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] soc_workflow {title[:30]}: {ex}")
    return count


def seed_security_playbooks():
    from core.security_playbook_engine import SecurityPlaybookEngine
    e = SecurityPlaybookEngine()
    count = 0
    playbooks = [
        ("Ransomware Response", "incident_response", ["isolate", "preserve", "restore"]),
        ("Phishing Triage", "incident_response", ["analyze_email", "check_links", "notify"]),
        ("DDoS Mitigation", "network", ["detect", "activate_scrubbing", "monitor"]),
        ("CVE Patch Procedure", "vulnerability", ["identify", "test_patch", "deploy"]),
    ]
    for name, category, steps in playbooks:
        try:
            e.create_playbook(ORG, {
                "name": name, "category": category,
                "steps": [{"step": i+1, "action": s} for i, s in enumerate(steps)],
                "severity_threshold": "high",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] playbook {name}: {ex}")
    return count


def seed_workflow():
    try:
        from core.workflow_engine import WorkflowEngine, Workflow
        e = WorkflowEngine()
        count = 0
        for i, (name, wtype) in enumerate([
            ("Incident Response Workflow", "incident_response"),
            ("Vuln Remediation Workflow", "remediation"),
            ("Change Approval Workflow", "change_management"),
        ]):
            try:
                wf = Workflow(
                    id=_id(), name=name, workflow_type=wtype, org_id=ORG,
                    steps=[{"name": "Triage", "action": "review"}, {"name": "Fix", "action": "remediate"}],
                )
                e.create_workflow(wf)
                count += 1
            except Exception as ex:
                print(f"  [WARN] workflow {name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] workflow import: {ex}")
        return 0


def seed_training():
    from core.training_tracker import TrainingTracker
    e = TrainingTracker()
    count = 0
    try:
        modules = e.list_modules()
        mids = [m.get("id") or m.get("module_id") for m in (modules or [])][:3]
        for user in USERS[:3]:
            for mid in mids:
                if not mid:
                    continue
                try:
                    e.enroll_user(user_id=user, module_id=mid, org_id=ORG)
                    count += 1
                except Exception:
                    pass
    except Exception:
        pass
    # Direct completion records
    for user in USERS[:2]:
        for mod_id in ["security-awareness-101", "phishing-recognition-201", "password-best-practices-301"]:
            try:
                e.record_completion(
                    user_id=user, module_id=mod_id, org_id=ORG,
                    score=random.randint(75, 100), passed=True,
                )
                count += 1
            except Exception:
                pass
    return count


def seed_threat_hunting():
    from core.threat_hunting_engine import ThreatHuntingEngine
    e = ThreatHuntingEngine()
    count = 0
    hunts = [
        ("Hunt: Lateral Movement via SMB", "lateral_movement", "network"),
        ("Hunt: Credential Dumping", "credential_access", "endpoint"),
        ("Hunt: C2 Beaconing", "command_and_control", "network"),
    ]
    for name, tactic, scope in hunts:
        try:
            e.create_hunt(ORG, {
                "name": name, "tactic": tactic, "scope": scope,
                "hypothesis": f"Adversaries using {tactic}",
                "data_sources": ["siem", "edr"],
                "analyst": random.choice(USERS),
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] threat_hunting {name}: {ex}")
    return count


def seed_ir_playbook():
    try:
        from core.ir_playbook_engine import IRPlaybookRunner, IncidentType
        e = IRPlaybookRunner()
        count = 0
        for itype, title in [
            (IncidentType.MALWARE, "Ransomware on finance-srv-01"),
            (IncidentType.DATA_BREACH, "PII exfiltration via DLP alert"),
            (IncidentType.PHISHING, "CEO impersonation campaign"),
        ]:
            try:
                inc = e.create_incident(
                    incident_type=itype, title=title, description=title,
                    severity="critical", org_id=ORG, reported_by=random.choice(USERS),
                )
                iid = getattr(inc, "incident_id", None) or (inc.get("incident_id") if isinstance(inc, dict) else None)
                if iid:
                    e.add_timeline_event(
                        incident_id=iid, event_type="detection",
                        description="Initial SIEM alert", author=random.choice(USERS), org_id=ORG,
                    )
                count += 1
            except Exception as ex:
                print(f"  [WARN] ir_playbook {title[:30]}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] ir_playbook import: {ex}")
        return 0


def seed_change_management():
    from core.security_change_management_engine import SecurityChangeManagementEngine
    e = SecurityChangeManagementEngine()
    count = 0
    changes = [
        ("Patch OpenSSL on web servers", "patch", "high"),
        ("Enable MFA for all admins", "security_control", "critical"),
        ("Rotate API keys", "rotation", "medium"),
        ("Deploy WAF for OWASP Top 10", "security_control", "high"),
        ("Upgrade TLS 1.0 to 1.3", "configuration", "high"),
    ]
    for title, ctype, risk in changes:
        try:
            e.create_change(ORG, {
                "title": title, "change_type": ctype, "risk_level": risk,
                "description": title, "requested_by": random.choice(USERS),
                "planned_date": _date(days_ahead=7),
                "rollback_plan": "Revert to previous configuration",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] change_mgmt {title}: {ex}")
    return count


def seed_supply_chain():
    from core.supply_chain_intel_engine import SupplyChainIntelEngine
    e = SupplyChainIntelEngine()
    count = 0
    packages = [
        ("log4j-core", "2.14.1", "java", "maven", True),
        ("openssl", "1.1.1t", "c", "system", False),
        ("requests", "2.28.0", "python", "pypi", False),
        ("lodash", "4.17.21", "javascript", "npm", False),
    ]
    for name, version, lang, ecosystem, vuln in packages:
        try:
            e.track_package(ORG, {
                "name": name, "version": version, "language": lang,
                "ecosystem": ecosystem, "known_vulnerable": vuln,
                "license": "Apache-2.0",
            })
            count += 1
        except Exception as ex:
            print(f"  [WARN] supply_chain {name}: {ex}")
    return count


def seed_metrics_aggregator():
    try:
        from core.security_metrics_aggregator_engine import SecurityMetricsAggregatorEngine
        e = SecurityMetricsAggregatorEngine()
        count = 0
        for name, stype, url in [
            ("siem-prod", "siem", "https://siem.corp.io"),
            ("edr-agent", "edr", "https://edr.corp.io"),
            ("vuln-scanner", "scanner", "https://scanner.corp.io"),
        ]:
            try:
                src = e.register_source(ORG, {"name": name, "source_type": stype, "endpoint_url": url, "polling_interval_secs": 300})
                sid = src.get("source_id") or src.get("id")
                if sid:
                    e.record_metric(ORG, {"source_id": sid, "metric_name": "alerts_per_hour", "value": 42, "unit": "count"})
                count += 1
            except Exception as ex:
                print(f"  [WARN] metrics_aggregator {name}: {ex}")
        return count
    except Exception as ex:
        print(f"  [WARN] metrics_aggregator import: {ex}")
        return 0


# ---------------------------------------------------------------------------
# Direct SQLite for DBs whose engines are too complex or not imported
# ---------------------------------------------------------------------------
def seed_remaining_direct():
    total = 0

    # Generic catch-all for all remaining empty DBs
    empty_dbs = []
    for f in sorted(DATA_DIR.iterdir()):
        if not f.name.endswith('.db'):
            continue
        try:
            con = sqlite3.connect(str(f))
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            rows = sum(con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] for t in tables)
            con.close()
            if rows == 0 and tables:
                empty_dbs.append(f.name)
        except Exception:
            pass

    print(f"  [INFO] {len(empty_dbs)} DBs still empty, doing direct inserts...")

    for db_name in empty_dbs:
        try:
            con = sqlite3.connect(str(DATA_DIR / db_name))
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            inserted = 0
            for tbl in tables:
                cols = [c[1] for c in con.execute(f"PRAGMA table_info([{tbl}])").fetchall()]
                if not cols:
                    continue
                for i in range(4):
                    row = {}
                    for c in cols:
                        cl = c.lower()
                        if cl in ('id',):
                            row[c] = _id()
                        elif cl == 'org_id':
                            row[c] = ORG
                        elif 'created_at' in cl or 'timestamp' in cl or 'updated_at' in cl or 'date' in cl:
                            row[c] = _ts(days_ago=30+i*5)
                        elif 'name' in cl or 'title' in cl:
                            row[c] = f"{db_name.replace('.db','').replace('_',' ').title()} {tbl} {i+1}"
                        elif 'status' in cl or 'state' in cl:
                            row[c] = ['active', 'completed', 'pending', 'open'][i]
                        elif 'severity' in cl or 'priority' in cl or 'level' in cl:
                            row[c] = SEVERITIES[i % len(SEVERITIES)]
                        elif 'type' in cl or 'category' in cl or 'kind' in cl:
                            row[c] = ['security', 'compliance', 'operations', 'risk'][i]
                        elif 'score' in cl or 'value' in cl or 'count' in cl or 'rate' in cl or 'pct' in cl:
                            row[c] = round(random.uniform(10, 95), 2)
                        elif 'enabled' in cl or 'active' in cl or 'is_' in cl:
                            row[c] = 1
                        elif 'email' in cl or 'user' in cl or 'owner' in cl or 'assignee' in cl:
                            row[c] = USERS[i % len(USERS)]
                        elif 'ip' in cl or 'host' in cl or 'address' in cl:
                            row[c] = random.choice(IPS)
                        elif 'description' in cl or 'message' in cl or 'notes' in cl or 'details' in cl:
                            row[c] = f"Demo data for {db_name} - {tbl} record {i+1}"
                        elif 'version' in cl:
                            row[c] = f"1.{i}.0"
                        elif 'provider' in cl or 'source' in cl or 'vendor' in cl:
                            row[c] = ['aws', 'azure', 'gcp', 'internal'][i]
                        elif 'format' in cl or 'method' in cl or 'protocol' in cl:
                            row[c] = ['json', 'api', 'tcp', 'https'][i]
                        else:
                            row[c] = None

                    vals = [row.get(c) for c in cols]
                    try:
                        con.execute(
                            f"INSERT OR IGNORE INTO [{tbl}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})",
                            vals
                        )
                        inserted += 1
                    except Exception:
                        pass
            con.commit()
            con.close()
            total += inserted
        except Exception as ex:
            print(f"  [WARN] direct {db_name}: {ex}")

    return total


# ---------------------------------------------------------------------------
SEEDERS = [
    ("api_discovery",           seed_api_discovery),
    ("api_gateway",             seed_api_gateway),
    ("cloud_accounts",          seed_cloud_accounts),
    ("cloud_governance",        seed_cloud_governance),
    ("compliance_gaps",         seed_compliance_gaps),
    ("container_registry",      seed_container_registry),
    ("container_runtime",       seed_container_runtime),
    ("ddos",                    seed_ddos),
    ("digital_identity",        seed_digital_identity),
    ("firewall",                seed_firewall),
    ("forensics",               seed_forensics),
    ("insider_threat",          seed_insider_threat),
    ("sbom",                    seed_sbom),
    ("zero_trust",              seed_zero_trust),
    ("rbac",                    seed_rbac),
    ("pentest",                 seed_pentest),
    ("scorecard",               seed_scorecard),
    ("vuln_risk_scores",        seed_vuln_risk_scores),
    ("vulnerability_analytics", seed_vulnerability_analytics),
    ("soc_workflow",            seed_soc_workflow),
    ("security_playbooks",      seed_security_playbooks),
    ("workflow",                seed_workflow),
    ("training",                seed_training),
    ("threat_hunting",          seed_threat_hunting),
    ("ir_playbook",             seed_ir_playbook),
    ("change_management",       seed_change_management),
    ("supply_chain",            seed_supply_chain),
    ("metrics_aggregator",      seed_metrics_aggregator),
    ("remaining_direct",        seed_remaining_direct),
]


def main():
    print(f"\nALDECI Final Engine Seeder — {len(SEEDERS)} seeders")
    print(f"  Org: {ORG}  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

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

    print(f"\n  Done: {ok}/{len(SEEDERS)} ran, {fail} failed, {total_records} total records inserted\n")

    # Count remaining empty DBs
    empty = []
    for f in sorted(DATA_DIR.iterdir()):
        if not f.name.endswith('.db'):
            continue
        try:
            con = sqlite3.connect(str(f))
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()]
            rows = sum(con.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0] for t in tables)
            con.close()
            if rows == 0:
                empty.append(f.name)
        except Exception:
            pass

    if empty:
        print(f"  Still empty ({len(empty)}):")
        for d in empty:
            print(f"    - {d}")
    else:
        print("  All DBs have data!")

    print(f"\n  Remaining empty DBs: {len(empty)}")


if __name__ == "__main__":
    main()
