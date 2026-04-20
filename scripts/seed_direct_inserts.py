#!/usr/bin/env python3
"""Precise direct SQLite inserts for remaining empty DBs.

Run from repo root:
    PYTHONPATH="suite-core:suite-api" python3 scripts/seed_direct_inserts.py
"""
from __future__ import annotations
import sys, sqlite3, random, uuid, json, hashlib
from datetime import datetime, timezone, timedelta, date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "suite-core"))
sys.path.insert(0, str(ROOT / "suite-api"))

ORG = "default"
random.seed(13)
DATA_DIR = ROOT / "data"

def _ts(days_ago=0, hours_ago=0):
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=hours_ago)
    return dt.isoformat()

def _date(days_ago=0, days_ahead=0):
    d = date.today() + timedelta(days=days_ahead) - timedelta(days=days_ago)
    return d.isoformat()

def _id(): return str(uuid.uuid4())
def _hash(s): return hashlib.sha256(s.encode()).hexdigest()

SEVERITIES = ["critical", "high", "medium", "low"]
USERS = ["alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io", "eve@corp.io"]
HOSTS = [f"host-{i:03d}.internal" for i in range(1, 10)]
IPS = [f"10.0.{i}.{j}" for i in range(1, 4) for j in range(1, 5)]


def db(name):
    return sqlite3.connect(str(DATA_DIR / name))


def insert(con, table, rows):
    count = 0
    for row in rows:
        cols = list(row.keys())
        vals = [row[c] for c in cols]
        try:
            con.execute(f"INSERT OR IGNORE INTO [{table}] ({','.join(cols)}) VALUES ({','.join(['?']*len(cols))})", vals)
            count += 1
        except Exception as ex:
            print(f"    [skip] {table}: {ex}")
    con.commit()
    return count


def also_fix_engines():
    """Fix engines that still need correct args."""
    total = 0

    # api_discovery — needs scan_target + service_name
    try:
        from core.api_discovery_engine import APIDiscoveryEngine
        e = APIDiscoveryEngine()
        for scan_name, target, svc in [
            ("Auth API Scan", "https://auth.corp.io/api", "auth-service"),
            ("Payment API Scan", "https://pay.corp.io/api", "payment-service"),
            ("User API Scan", "https://users.corp.io/api", "user-service"),
        ]:
            try:
                e.create_scan(ORG, {"scan_name": scan_name, "scan_target": target,
                                    "scan_type": "passive", "service_name": svc})
                total += 1
            except Exception as ex:
                print(f"  [WARN] api_discovery {scan_name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] api_discovery import: {ex}")

    # api_gateway — needs env='prod'
    try:
        from core.api_gateway_security_engine import APIGatewaySecurityEngine
        e = APIGatewaySecurityEngine()
        for name, gtype, url in [
            ("Main API Gateway", "kong", "https://api.corp.io"),
            ("Partner Gateway", "aws_api_gw", "https://partner.corp.io"),
        ]:
            try:
                gw = e.register_gateway(ORG, {"name": name, "gateway_type": gtype,
                                               "base_url": url, "environment": "prod"})
                total += 1
            except Exception as ex:
                print(f"  [WARN] api_gateway {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] api_gateway import: {ex}")

    # cloud_accounts — positional args
    try:
        from core.cloud_account_monitoring_engine import CloudAccountMonitoringEngine
        e = CloudAccountMonitoringEngine()
        for acct_id, name, provider, region in [
            (f"aws-{_id()[:8]}", "AWS Production", "aws", "us-east-1"),
            (f"az-{_id()[:8]}", "Azure Corp", "azure", "eastus"),
        ]:
            try:
                e.register_account(ORG, acct_id, name, provider, region)
                total += 1
            except Exception as ex:
                print(f"  [WARN] cloud_accounts {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] cloud_accounts import: {ex}")

    # compliance_gaps — correct framework codes
    try:
        from core.compliance_gap_engine import ComplianceGapEngine
        e = ComplianceGapEngine()
        for assessment_name, framework in [
            ("SOC2 Q1 2025 Assessment", "SOC2"),
            ("PCI DSS 4.0 Assessment", "PCI-DSS"),
            ("ISO 27001 2025 Assessment", "ISO27001"),
        ]:
            try:
                a = e.create_assessment(ORG, {"assessment_name": assessment_name, "framework": framework, "scope": "enterprise"})
                aid = a.get("assessment_id") or a.get("id")
                if aid:
                    e.add_control_gap(ORG, {"assessment_id": aid, "control_id": f"{framework}-CC6.1",
                                            "control_name": "Logical Access", "gap_description": "MFA gap",
                                            "severity": "high", "current_state": "partial", "target_state": "full"})
                total += 1
            except Exception as ex:
                print(f"  [WARN] compliance_gaps {assessment_name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] compliance_gaps import: {ex}")

    # container_runtime — register first then record event with returned id
    try:
        from core.container_runtime_security_engine import ContainerRuntimeSecurityEngine
        e = ContainerRuntimeSecurityEngine()
        for cname, etype in [("api-pod-01", "network_connection"), ("db-pod-01", "file_write"), ("cache-pod-01", "exec_command")]:
            try:
                c = e.register_container(ORG, {"container_name": cname, "image": f"corp/{cname}:latest",
                                                "namespace": "prod", "pod_name": cname, "node_name": HOSTS[0]})
                cid = c.get("container_id") or c.get("id")
                if not cid:
                    # check all string values for a uuid-like value
                    cid = next((v for v in c.values() if isinstance(v, str) and len(v) == 36), None)
                if cid:
                    e.record_runtime_event(ORG, {"container_id": cid, "event_type": etype,
                                                  "severity": "high", "description": f"Event on {cname}",
                                                  "source_ip": random.choice(IPS)})
                total += 1
            except Exception as ex:
                print(f"  [WARN] container_runtime {cname}: {ex}")
    except Exception as ex:
        print(f"  [WARN] container_runtime import: {ex}")

    # ddos — correct resource_type and protection_tier
    try:
        from core.ddos_protection_engine import DDoSProtectionEngine
        e = DDoSProtectionEngine()
        for name, endpoint, rtype, tier in [
            ("Customer Portal", "portal.corp.io", "web", "premium"),
            ("API Gateway", "api.corp.io", "api", "premium"),
            ("DNS Cluster", "8.8.8.1", "dns", "standard"),
            ("Main Load Balancer", "10.0.1.1", "network", "standard"),
        ]:
            try:
                r = e.register_protected_resource(ORG, {"name": name, "ip_or_fqdn": endpoint,
                                                         "resource_type": rtype, "protection_tier": tier})
                rid = r.get("resource_id") or r.get("id")
                if rid:
                    e.record_attack_event(ORG, {"resource_id": rid, "attack_type": "volumetric",
                                                 "source_ips": [random.choice(IPS)],
                                                 "peak_pps": 100000, "severity": "high", "description": f"Attack on {name}"})
                total += 1
            except Exception as ex:
                print(f"  [WARN] ddos {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] ddos import: {ex}")

    # insider_threat — no 'severity' kwarg
    try:
        from core.insider_threat_engine import InsiderThreatEngine
        e = InsiderThreatEngine()
        for user_id, etype, resource, details in [
            ("user-alice", "large_download", "s3://sensitive", {"bytes": 5_000_000_000}),
            ("user-bob", "after_hours_access", "finance_db", {"time": "02:30 AM"}),
            ("user-carol", "privilege_escalation", "admin_console", {"from_role": "viewer"}),
            ("user-dave", "mass_email", "email_server", {"recipients": 500}),
            ("user-eve", "vpn_anomaly", "vpn_gateway", {"location": "Unknown"}),
        ]:
            try:
                e.record_user_event(org_id=ORG, user_id=user_id, event_type=etype, resource=resource, details=details)
                total += 1
            except Exception as ex:
                print(f"  [WARN] insider_threat {user_id}: {ex}")
    except Exception as ex:
        print(f"  [WARN] insider_threat import: {ex}")

    # sbom — use component_name
    try:
        from core.sbom_engine import SBOMEngine
        e = SBOMEngine()
        try:
            asset = e.register_asset(ORG, {"asset_name": "ALDECI Platform", "asset_type": "application", "version": "1.0.0"})
            aid = asset.get("asset_id") or asset.get("id")
            for pkg, ver, ctype, lic, eco in [
                ("django", "4.2.1", "framework", "MIT", "pypi"),
                ("fastapi", "0.104.0", "framework", "MIT", "pypi"),
                ("react", "18.2.0", "library", "MIT", "npm"),
                ("openssl", "3.1.2", "library", "OpenSSL", "os"),
            ]:
                try:
                    e.add_component(ORG, aid, {"component_name": pkg, "version": ver,
                                                "component_type": ctype, "license_spdx": lic, "ecosystem": eco})
                    total += 1
                except Exception as ex:
                    print(f"  [WARN] sbom {pkg}: {ex}")
        except Exception as ex:
            print(f"  [WARN] sbom asset: {ex}")
    except Exception as ex:
        print(f"  [WARN] sbom import: {ex}")

    # pentest — check valid methodologies
    try:
        from core.pentest_mgmt_engine import PentestMgmtEngine
        e = PentestMgmtEngine()
        # Get valid methodologies from engine
        for name, scope in [("Q1 External Pentest", "external"), ("API Assessment", "api"), ("Network Pentest", "internal")]:
            try:
                e.create_engagement(ORG, {"name": name, "scope": scope, "methodology": "automated",
                                          "start_date": _date(days_ago=30), "end_date": _date(days_ago=7),
                                          "team": [USERS[0]], "target_systems": [HOSTS[0]]})
                total += 1
            except Exception as ex:
                # try without methodology
                try:
                    e.create_engagement(ORG, {"name": name, "scope": scope,
                                              "start_date": _date(days_ago=30), "end_date": _date(days_ago=7),
                                              "team": [USERS[0]], "target_systems": [HOSTS[0]]})
                    total += 1
                except Exception as ex2:
                    print(f"  [WARN] pentest {name}: {ex2}")
    except Exception as ex:
        print(f"  [WARN] pentest import: {ex}")

    # scorecard — needs entity_id
    try:
        from core.security_scorecard_engine import SecurityScorecardEngine
        e = SecurityScorecardEngine()
        for entity_name, entity_type in [("ALDECI Platform", "internal"), ("AWS", "cloud"), ("Endpoints", "endpoint")]:
            try:
                e.create_scorecard(ORG, {"entity_id": _id(), "entity_name": entity_name, "entity_type": entity_type,
                                         "domain_scores": {"network_security": 80, "endpoint_security": 75,
                                                           "application_security": 70, "data_protection": 85,
                                                           "identity_management": 90}})
                total += 1
            except Exception as ex:
                print(f"  [WARN] scorecard {entity_name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] scorecard import: {ex}")

    # vuln_risk_scores — needs org_id + cve_id + context positional
    try:
        from core.vuln_risk_scoring import VulnRiskScorer
        e = VulnRiskScorer()
        for cve, cvss, epss, kev in [("CVE-2024-1111", 9.8, 0.92, True), ("CVE-2024-2222", 7.5, 0.45, False)]:
            try:
                ctx = {"cvss_score": cvss, "epss_score": epss, "kev": kev,
                       "asset_criticality": "critical", "exposure": "internet"}
                r = e.score_vulnerability(ORG, cve, ctx)
                e.save_score(ORG, cve, r)
                total += 1
            except Exception as ex:
                print(f"  [WARN] vuln_risk {cve}: {ex}")
    except Exception as ex:
        print(f"  [WARN] vuln_risk import: {ex}")

    # vulnerability_analytics — no asset_id kwarg
    try:
        from core.vulnerability_analytics import VulnerabilityAnalytics
        e = VulnerabilityAnalytics()
        for cve, etype, severity in [("CVE-2024-A001", "opened", "critical"), ("CVE-2024-A002", "opened", "high"),
                                      ("CVE-2024-A001", "remediated", "critical"), ("CVE-2024-A003", "opened", "medium")]:
            try:
                e.record_finding_event(org_id=ORG, cve_id=cve, event_type=etype, severity=severity, scanner="openvas")
                total += 1
            except Exception as ex:
                print(f"  [WARN] vuln_analytics {cve}: {ex}")
    except Exception as ex:
        print(f"  [WARN] vuln_analytics import: {ex}")

    # soc_workflow — needs 'name' not 'title'
    try:
        from core.soc_workflow_engine import SOCWorkflowEngine
        e = SOCWorkflowEngine()
        for name, wtype, severity in [
            ("Suspicious Login Russia", "authentication_anomaly", "high"),
            ("Malware on Endpoint", "malware_infection", "critical"),
            ("Brute Force Admin", "brute_force", "high"),
        ]:
            try:
                e.create_workflow(ORG, {"name": name, "workflow_type": wtype, "severity": severity,
                                         "assignee": random.choice(USERS), "sla_hours": 4})
                total += 1
            except Exception as ex:
                print(f"  [WARN] soc_workflow {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] soc_workflow import: {ex}")

    # threat_hunting — needs 'query' positional
    try:
        from core.threat_hunting_engine import ThreatHuntingEngine
        e = ThreatHuntingEngine()
        for name, tactic, query in [
            ("Lateral Movement SMB", "lateral_movement", "SELECT * FROM events WHERE type='smb'"),
            ("Credential Dumping", "credential_access", "SELECT * FROM events WHERE type='lsass_access'"),
            ("C2 Beaconing", "command_and_control", "SELECT * FROM netflow WHERE beacon_score > 0.7"),
        ]:
            try:
                e.create_hunt(ORG, name, query)
                total += 1
            except Exception as ex:
                try:
                    e.create_hunt(ORG, {"name": name, "tactic": tactic, "query": query,
                                        "data_sources": ["siem"], "analyst": USERS[0]})
                    total += 1
                except Exception as ex2:
                    print(f"  [WARN] threat_hunting {name}: {ex2}")
    except Exception as ex:
        print(f"  [WARN] threat_hunting import: {ex}")

    # metrics_aggregator — needs source_name
    try:
        from core.security_metrics_aggregator_engine import SecurityMetricsAggregatorEngine
        e = SecurityMetricsAggregatorEngine()
        for source_name, stype, url in [
            ("siem-prod", "siem", "https://siem.corp.io"),
            ("edr-agent", "edr", "https://edr.corp.io"),
        ]:
            try:
                src = e.register_source(ORG, {"source_name": source_name, "source_type": stype, "endpoint_url": url, "polling_interval_secs": 300})
                sid = src.get("source_id") or src.get("id")
                if sid:
                    e.record_metric(ORG, {"source_id": sid, "metric_name": "alerts_per_hour", "value": 42, "unit": "count"})
                total += 1
            except Exception as ex:
                print(f"  [WARN] metrics_aggregator {source_name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] metrics_aggregator import: {ex}")

    # change_management — correct change_types
    try:
        from core.security_change_management_engine import SecurityChangeManagementEngine
        e = SecurityChangeManagementEngine()
        for title, ctype, risk in [
            ("Enable MFA for all admins", "access_control", "critical"),
            ("Rotate API keys for integrations", "certificate", "medium"),
            ("Deploy WAF firewall rules", "firewall_rule", "high"),
            ("Update TLS configuration", "configuration", "high"),
        ]:
            try:
                e.create_change(ORG, {"title": title, "change_type": ctype, "risk_level": risk,
                                       "description": title, "requested_by": random.choice(USERS),
                                       "planned_date": _date(days_ahead=7), "rollback_plan": "Revert config"})
                total += 1
            except Exception as ex:
                print(f"  [WARN] change_mgmt {title}: {ex}")
    except Exception as ex:
        print(f"  [WARN] change_mgmt import: {ex}")

    # workflow — fix Workflow model
    try:
        from core.workflow_engine import WorkflowEngine, Workflow
        e = WorkflowEngine()
        for i, (name, wtype) in enumerate([("IR Workflow", "incident_response"), ("Remediation Flow", "remediation")]):
            try:
                # Try with minimal required fields
                wf = Workflow(name=name, workflow_type=wtype, org_id=ORG,
                              trigger={"type": "manual"}, steps=[{"name": "Review", "action": "approve"}])
                e.create_workflow(wf)
                total += 1
            except Exception as ex:
                print(f"  [WARN] workflow {name}: {ex}")
    except Exception as ex:
        print(f"  [WARN] workflow import: {ex}")

    return total


def seed_all_direct():
    """Precise direct SQLite inserts for all remaining empty DBs."""
    total = 0
    con = db("api_versioning.db")
    total += insert(con, "endpoint_versions", [
        {"id": _id(), "org_id": ORG, "path": f"/api/v1/users", "version": "v1", "method": "GET", "status": "active", "created_at": _ts(days_ago=90), "updated_at": _ts(days_ago=1)},
        {"id": _id(), "org_id": ORG, "path": f"/api/v1/alerts", "version": "v1", "method": "GET", "status": "active", "created_at": _ts(days_ago=60), "updated_at": _ts(days_ago=1)},
        {"id": _id(), "org_id": ORG, "path": f"/api/v2/findings", "version": "v2", "method": "POST", "status": "active", "created_at": _ts(days_ago=30), "updated_at": _ts(days_ago=1)},
    ])
    con.close()

    con = db("audit_trail.db")
    for i, path in enumerate(["/api/v1/users", "/api/v1/alerts", "/api/v1/findings", "/api/v1/reports", "/api/v1/policies"]):
        total += insert(con, "audit_trail", [{"id": _id(), "timestamp": _ts(days_ago=i), "method": ["GET","POST","PUT","DELETE","GET"][i],
            "path": path, "org_id": ORG, "actor_id": USERS[i % len(USERS)],
            "status_code": [200, 201, 200, 204, 200][i], "body_hash": _hash(path + str(i)),
            "duration_ms": round(random.uniform(5, 500), 2), "client_ip": random.choice(IPS)}])
    con.close()

    con = db("breach_simulation.db")
    for i, scenario in enumerate(["ransomware", "apt_lateral", "data_exfil", "insider_threat", "supply_chain"]):
        total += insert(con, "simulations", [{"id": _id(), "org_id": ORG, "scenario": scenario,
            "steps_executed": random.randint(5, 20), "steps_blocked": random.randint(2, 10),
            "detection_time_seconds": round(random.uniform(30, 3600), 1),
            "containment_time_seconds": round(random.uniform(300, 14400), 1),
            "data_at_risk": f"{random.randint(100, 10000)} records",
            "score": round(random.uniform(40, 95), 1), "simulated_at": _ts(days_ago=i*7)}])
    con.close()

    con = db("change_management.db")
    cids = [_id() for _ in range(4)]
    for i, (cid, title, status, risk, cat) in enumerate(zip(cids,
        ["Patch OpenSSL", "Enable WAF", "Rotate certs", "Harden SSH"],
        ["approved", "pending", "completed", "in_progress"],
        ["high", "medium", "low", "high"],
        ["patch", "security", "certificate", "configuration"])):
        total += insert(con, "change_requests", [{"id": cid, "org_id": ORG,
            "data": json.dumps({"title": title, "requestor": USERS[i % len(USERS)]}),
            "status": status, "risk_level": risk, "category": cat,
            "requestor_id": USERS[i % len(USERS)], "created_at": _ts(days_ago=30+i*5), "updated_at": _ts(days_ago=i)}])
        total += insert(con, "audit_trail", [{"id": _id(), "change_id": cid,
            "action": "created", "actor_id": USERS[i % len(USERS)],
            "data": json.dumps({"note": "Change created"}), "timestamp": _ts(days_ago=30+i*5)}])
    con.close()

    con = db("cicd_integration.db")
    pids = [_id(), _id()]
    for i, pid in enumerate(pids):
        total += insert(con, "policies", [{"id": pid, "org_id": ORG,
            "name": ["Require SAST scan", "Block critical CVEs"][i],
            "rules_json": json.dumps([{"rule": ["no_critical_vulns", "require_sast"][i], "action": "block"}]),
            "created_at": _ts(days_ago=90+i*30)}])
    for i in range(4):
        total += insert(con, "scan_history", [{"id": _id(), "org_id": ORG,
            "repo": f"corp/service-{i+1}", "policy_id": pids[i % len(pids)],
            "policy_action": ["passed", "blocked", "passed", "passed"][i],
            "findings_json": json.dumps({"critical": i, "high": i*2, "medium": i*3}),
            "scanned_at": _ts(days_ago=i*3)}])
    con.close()

    con = db("cwpp.db")
    wids = [_id() for _ in range(4)]
    for i, wid in enumerate(wids):
        total += insert(con, "workloads", [{"id": wid, "org_id": ORG,
            "workload_type": ["container", "vm", "serverless", "container"][i],
            "name": f"workload-{i+1:03d}", "provider": ["aws", "azure", "gcp", "aws"][i],
            "region": "us-east-1", "status": "running", "registered_at": _ts(days_ago=60+i*10)}])
        total += insert(con, "threats", [{"id": _id(), "org_id": ORG, "workload_id": wid,
            "category": ["malware", "network_anomaly", "privilege_escalation", "crypto_mining"][i],
            "severity": SEVERITIES[i % len(SEVERITIES)],
            "description": f"Threat on workload-{i+1}", "detected_at": _ts(days_ago=i*2)}])
        total += insert(con, "compliance_results", [{"id": _id(), "org_id": ORG, "workload_id": wid,
            "framework": ["CIS", "NIST", "SOC2", "PCI"][i],
            "score": round(random.uniform(60, 95), 1),
            "passed": random.randint(15, 30), "failed": random.randint(0, 5),
            "checked_at": _ts(days_ago=i*3)}])
    con.close()

    con = db("evidence_chain.db")
    prev_hash = "0" * 64
    for i in range(5):
        data_hash = _hash(f"evidence-{i}")
        sig = _hash(f"sig-{i}-{data_hash}")
        total += insert(con, "chain_entries", [{"id": _id(), "org_id": ORG,
            "sequence_number": i + 1, "event_type": ["collect", "transfer", "analyze", "seal", "verify"][i],
            "data_hash": data_hash, "previous_hash": prev_hash,
            "timestamp": _ts(days_ago=10-i*2), "signature": sig,
            "actor": USERS[i % len(USERS)]}])
        prev_hash = _hash(prev_hash + data_hash)
    con.close()

    con = db("evidence_collector.db")
    for i, (ctrl_id, framework, etype, title) in enumerate([
        ("CC6.1", "SOC2", "screenshot", "MFA enforcement screenshot"),
        ("PCI-8.2", "PCI-DSS", "log_export", "Access control logs"),
        ("A.9.1", "ISO27001", "policy_doc", "Access policy document"),
        ("GDPR-32", "GDPR", "report", "Data processing register"),
    ]):
        total += insert(con, "evidence", [{"id": _id(), "org_id": ORG,
            "control_id": ctrl_id, "framework": framework, "type": etype,
            "title": title, "description": f"Evidence for {ctrl_id}",
            "collected_at": _ts(days_ago=i*7), "collected_by": USERS[i % len(USERS)],
            "status": "approved", "file_path": f"/evidence/{ctrl_id.lower()}.pdf"}])
    for fw, ctrl, name, types in [("SOC2", "CC6.1", "Access Controls", '["screenshot","policy_doc"]'),
                                   ("PCI-DSS", "PCI-8.2", "Password Policy", '["policy_doc","audit_log"]')]:
        total += insert(con, "auto_requirements", [{"id": _id(), "org_id": ORG,
            "framework": fw, "control_id": ctrl, "control_name": name,
            "evidence_types": types, "created_at": _ts(days_ago=90)}])
    con.close()

    con = db("exception_policy.db")
    rule_ids = [_id(), _id(), _id()]
    for i, (rid, name, action) in enumerate(zip(rule_ids,
        ["Suppress low-severity findings", "Auto-approve known false positives", "Escalate unresolved criticals"],
        ["suppress", "approve", "escalate"])):
        total += insert(con, "exception_rules", [{"id": rid, "org_id": ORG, "name": name,
            "criteria": json.dumps({"severity": ["low", "info"][i % 2], "age_days": 30}),
            "action": action, "created_at": _ts(days_ago=60+i*10), "enabled": 1}])
    total += insert(con, "policy_versions", [{"id": _id(), "org_id": ORG, "version": 1,
        "rules_snapshot": json.dumps([{"name": "Default policy", "action": "suppress"}]),
        "published_at": _ts(days_ago=30), "published_by": USERS[0]}])
    for i, rid in enumerate(rule_ids[:3]):
        total += insert(con, "suppression_log", [{"id": _id(), "org_id": ORG,
            "finding_id": f"FIND-{1000+i}", "rule_id": rid,
            "action": "suppressed", "evaluated_at": _ts(days_ago=i)}])
    con.close()

    con = db("executive_reports.db")
    rids = [_id() for _ in range(4)]
    now = _ts()
    for i, (rid, title, rtype) in enumerate(zip(rids,
        ["Q1 2025 Security Summary", "Board Risk Report", "CISO Monthly", "Annual Security Review"],
        ["quarterly_summary", "board_report", "monthly_status", "annual_review"])):
        total += insert(con, "executive_reports", [{"id": rid, "org_id": ORG,
            "title": title, "type": rtype,
            "created_at": _ts(days_ago=i*30),
            "period_start": _date(days_ago=90+i*30),
            "period_end": _date(days_ago=i*30),
            "status": "published", "generated_by": USERS[0]}])
    for i, rtype in enumerate(["monthly_status", "quarterly_summary"]):
        total += insert(con, "report_schedules", [{"id": _id(), "org_id": ORG,
            "report_type": rtype, "frequency": ["monthly", "quarterly"][i],
            "next_run": _date(days_ahead=30-i*15), "recipients": json.dumps([USERS[0], USERS[1]]),
            "enabled": 1}])
    con.close()

    con = db("ir_playbook.db")
    inc_ids = [_id() for _ in range(3)]
    for i, (iid, ptype, title, sev) in enumerate(zip(inc_ids,
        ["malware", "data_breach", "phishing"],
        ["Ransomware on finance-srv-01", "PII exfiltration detected", "CEO phishing campaign"],
        ["critical", "critical", "high"])):
        pb_id = _id()
        total += insert(con, "ir_incidents", [{"id": iid, "org_id": ORG,
            "playbook_id": pb_id, "title": title, "incident_type": ptype, "severity": sev,
            "status": "open", "phase": "detection", "created_at": _ts(days_ago=i*7), "updated_at": _ts(days_ago=i)}])
        raw = f"Evidence for {title}"
        total += insert(con, "ir_evidence", [{"id": _id(), "org_id": ORG,
            "incident_id": iid, "collector_id": USERS[i % len(USERS)],
            "evidence_type": ["log_export", "memory_dump", "email_header"][i],
            "description": f"Evidence: {title}",
            "raw_content": raw, "sha256_hash": _hash(raw), "collected_at": _ts(days_ago=i*7)}])
        total += insert(con, "ir_timeline", [{"id": _id(), "org_id": ORG,
            "incident_id": iid, "event_type": "detection",
            "source": "siem", "description": f"Alert triggered: {title}",
            "timestamp": _ts(days_ago=i*7)}])
        total += insert(con, "ir_notifications", [{"id": _id(), "org_id": ORG,
            "incident_id": iid, "framework": "NIST",
            "detection_time": _ts(days_ago=i*7), "notified": 1}])
    con.close()

    con = db("metrics_aggregator.db")
    for i in range(5):
        total += insert(con, "metrics_snapshots", [{"id": _id(), "org_id": ORG,
            "timestamp": _ts(days_ago=i),
            "mttd_hours": round(random.uniform(1, 8), 2),
            "mttr_hours": round(random.uniform(4, 24), 2),
            "open_critical": random.randint(0, 10),
            "patch_compliance_pct": round(random.uniform(80, 99), 1),
            "mfa_coverage_pct": round(random.uniform(85, 100), 1)}])
    con.close()

    con = db("mpte.db")
    req_ids = [_id() for _ in range(4)]
    for i, (rid, vuln_type, url) in enumerate(zip(req_ids,
        ["sql_injection", "xss", "ssrf", "auth_bypass"],
        ["/api/v1/users", "/app/search", "/api/v1/fetch", "/api/v1/login"])):
        total += insert(con, "pen_test_requests", [{"id": rid, "org_id": ORG,
            "finding_id": f"FIND-{2000+i}", "target_url": f"https://app.corp.io{url}",
            "vulnerability_type": vuln_type,
            "test_case": f"Test for {vuln_type.replace('_', ' ')}",
            "priority": SEVERITIES[i % len(SEVERITIES)], "status": "completed",
            "created_at": _ts(days_ago=i*3)}])
        total += insert(con, "pen_test_results", [{"id": _id(), "org_id": ORG,
            "request_id": rid, "finding_id": f"FIND-{2000+i}",
            "exploitability": ["high", "medium", "low", "high"][i],
            "exploit_successful": [1, 0, 1, 0][i],
            "evidence": f"PoC: {vuln_type} exploited at {url}",
            "cvss_score": round(random.uniform(6, 10), 1), "created_at": _ts(days_ago=i*2)}])
    total += insert(con, "pen_test_configs", [{"id": _id(), "org_id": ORG,
        "name": "ALDECI MPTE Config", "mpte_url": "http://localhost:7000",
        "enabled": 1, "max_concurrent_tests": 5, "timeout_seconds": 300,
        "auto_trigger": 0, "created_at": _ts(days_ago=90), "updated_at": _ts(days_ago=1)}])
    con.close()

    con = db("network_analyzer.db")
    zone_ids = {}
    for i, (name, ztype, cidr, trust) in enumerate([
        ("DMZ", "dmz", "10.0.1.0/24", 2),
        ("Internal", "internal", "10.0.2.0/24", 4),
        ("External", "external", "0.0.0.0/0", 1),
        ("Management", "management", "10.0.3.0/24", 5),
    ]):
        zid = _id()
        zone_ids[name] = zid
        total += insert(con, "zones", [{"id": zid, "org_id": ORG, "name": name, "type": ztype,
            "cidrs": json.dumps([cidr]), "assets": json.dumps([HOSTS[i]]),
            "trust_level": trust, "metadata": json.dumps({}), "created_at": _ts(days_ago=90)}])
    for i, (src, dst, port, allowed) in enumerate([
        ("External", "DMZ", "443", 1),
        ("DMZ", "Internal", "8080", 1),
        ("External", "Internal", "22", 0),
        ("Internal", "External", "3306", 0),
    ]):
        fid = _id()
        total += insert(con, "flows", [{"id": fid, "org_id": ORG,
            "source_zone": src, "dest_zone": dst, "ports": json.dumps([port]),
            "protocol": "tcp", "direction": "inbound" if src == "External" else "outbound",
            "allowed": allowed, "risk_score": round(random.uniform(10, 90), 1),
            "metadata": json.dumps({}), "observed_at": _ts(days_ago=i)}])
        if not allowed:
            total += insert(con, "violations", [{"id": _id(), "org_id": ORG,
                "flow_id": fid, "flow_json": json.dumps({"src": src, "dst": dst}),
                "rule_violated": f"No {src}→{dst} on port {port}",
                "severity": "high", "detected_at": _ts(days_ago=i),
                "metadata": json.dumps({})}])
    con.close()

    con = db("notifications.db")
    for i, (name, channel, freq) in enumerate([
        ("Critical Alert Rule", "pagerduty", "immediate"),
        ("Daily Digest", "email", "daily"),
        ("Slack Security Alerts", "slack", "immediate"),
    ]):
        total += insert(con, "alert_rules", [{"id": _id(), "org_id": ORG, "name": name,
            "conditions": json.dumps({"severity": ["critical", "any", "high"][i]}),
            "channels": json.dumps([channel]), "recipients": json.dumps([USERS[i % len(USERS)]]),
            "digest_frequency": freq, "enabled": 1,
            "created_at": _ts(days_ago=60+i*10), "updated_at": _ts(days_ago=i)}])
    for i in range(5):
        total += insert(con, "notifications", [{"id": _id(), "org_id": ORG,
            "timestamp": _ts(days_ago=i), "rule_name": f"Alert rule {i+1}",
            "channel": ["email", "slack", "pagerduty", "email", "slack"][i],
            "recipient": USERS[i % len(USERS)],
            "subject": f"Security Alert: {SEVERITIES[i % len(SEVERITIES)].upper()} event detected",
            "body": f"Security notification #{i+1}: action required", "delivered": 1}])
    total += insert(con, "preferences", [{"id": _id(), "org_id": ORG,
        "channels": json.dumps(["email", "slack"]),
        "quiet_hours_start": "22:00", "quiet_hours_end": "07:00",
        "updated_at": _ts(days_ago=7)}])
    con.close()

    con = db("pentest.db")
    tgt_ids = [_id(), _id(), _id()]
    for i, (tid, name, url) in enumerate(zip(tgt_ids,
        ["Web App Production", "API Gateway", "Internal Network"],
        ["https://app.corp.io", "https://api.corp.io", "10.0.0.0/8"])):
        total += insert(con, "pentest_targets", [{"id": tid, "org_id": ORG,
            "name": name, "url_or_host": url,
            "target_type": ["web", "api", "network"][i],
            "created_at": _ts(days_ago=90+i*10)}])
        sched_id = _id()
        total += insert(con, "pentest_schedules", [{"id": sched_id, "org_id": ORG,
            "target_id": tid, "frequency": ["quarterly", "monthly", "annual"][i],
            "next_run": _date(days_ahead=30), "created_by": USERS[0],
            "created_at": _ts(days_ago=90)}])
        run_id = _id()
        total += insert(con, "pentest_runs", [{"id": run_id, "org_id": ORG,
            "target_id": tid, "test_type": ["black_box", "grey_box", "white_box"][i],
            "status": ["completed", "in_progress", "planned"][i],
            "started_at": _ts(days_ago=30), "created_at": _ts(days_ago=30+i)}])
        total += insert(con, "pentest_reports", [{"id": _id(), "org_id": ORG,
            "run_id": run_id, "executive_summary": f"Pentest of {name}: {random.randint(0,5)} critical, {random.randint(1,10)} high",
            "findings_count": random.randint(2, 15), "generated_at": _ts(days_ago=25)}])
    con.close()

    con = db("policies.db")
    for i, (name, ptype, status) in enumerate([
        ("Acceptable Use Policy", "governance", "active"),
        ("Password Policy", "technical", "active"),
        ("Data Retention Policy", "data", "active"),
        ("Incident Response Policy", "operations", "active"),
        ("Access Control Policy", "security", "active"),
    ]):
        total += insert(con, "policies", [{"id": _id(), "org_id": ORG,
            "name": name, "description": f"Corporate {name}",
            "policy_type": ptype, "status": status,
            "rules": json.dumps([{"rule": f"Comply with {name}"}]),
            "version": "1.0", "owner": USERS[0],
            "created_at": _ts(days_ago=365-i*30), "updated_at": _ts(days_ago=i*30)}])
    con.close()

    con = db("posture_advisor.db")
    an_ids = [_id(), _id()]
    for i, aid in enumerate(an_ids):
        rec_ids = [_id(), _id(), _id()]
        total += insert(con, "analyses", [{"id": aid, "org_id": ORG,
            "posture_score": round(random.uniform(60, 90), 1),
            "recommendation_ids": json.dumps(rec_ids),
            "created_at": _ts(days_ago=i*14)}])
        for j, rid in enumerate(rec_ids):
            total += insert(con, "recommendations", [{"id": rid, "org_id": ORG,
                "analysis_id": aid, "template_id": f"tpl-{j+1:03d}",
                "category": ["network", "identity", "data", "endpoint", "app"][j % 5],
                "priority": SEVERITIES[j % len(SEVERITIES)],
                "title": ["Enable MFA", "Patch Critical CVEs", "Encrypt Data at Rest"][j % 3],
                "description": "Recommended security improvement",
                "impact": "high", "effort": ["low", "medium", "high"][j % 3],
                "status": "open", "created_at": _ts(days_ago=i*14), "updated_at": _ts(days_ago=i*7)}])
    con.close()

    con = db("sbom.db")
    for i, (fmt, target, content) in enumerate([
        ("cyclonedx", "api-server:1.0.0", json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "django", "version": "4.2.1"}]})),
        ("spdx", "web-frontend:2.0.0", json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "react", "versionInfo": "18.2.0"}]})),
        ("cyclonedx", "data-service:1.5.0", json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "fastapi", "version": "0.104.0"}]})),
    ]):
        total += insert(con, "sboms", [{"id": _id(), "org_id": ORG,
            "format": fmt, "target": target, "content": content,
            "component_count": random.randint(10, 100),
            "created_at": _ts(days_ago=i*7)}])
    con.close()

    con = db("security_scorecard.db")
    for i, (entity, grade, score) in enumerate([
        ("ALDECI Platform", "A", 92.5),
        ("AWS Infrastructure", "B", 78.3),
        ("Corporate Endpoints", "B", 74.1),
        ("Supply Chain", "C", 61.7),
    ]):
        total += insert(con, "scorecards", [{"id": _id(), "org_id": ORG,
            "entity_id": _id(), "entity_name": entity, "entity_type": ["internal", "cloud", "endpoint", "third_party"][i],
            "overall_score": score, "grade": grade,
            "generated_at": _ts(days_ago=i*7),
            "valid_until": _date(days_ahead=90-i*7)}])
    con.close()

    con = db("sla_escalation.db")
    for i in range(3):
        total += insert(con, "escalation_policies", [{"id": _id(), "org_id": ORG,
            "name": ["Critical SLA", "High SLA", "Standard SLA"][i],
            "thresholds_json": json.dumps({"warn_hours": [1, 4, 8][i], "escalate_hours": [2, 8, 24][i]}),
            "updated_at": _ts(days_ago=90+i*30)}])
    fids = [f"FIND-{3000+i}" for i in range(5)]
    for i, fid in enumerate(fids):
        total += insert(con, "sla_tracked_findings", [{"id": _id(), "org_id": ORG,
            "finding_id": fid, "severity": SEVERITIES[i % len(SEVERITIES)],
            "deadline": _ts(days_ahead=1 if i < 3 else -1)}])
        total += insert(con, "escalation_events", [{"id": _id(), "org_id": ORG,
            "finding_id": fid, "action": ["notify", "escalate", "notify", "reassign", "escalate"][i],
            "hours_past": round(random.uniform(0.5, 48), 1), "created_at": _ts(days_ago=i)}])
    con.close()

    con = db("sla_tracking.db")
    for i, (name, sla_h) in enumerate([("Critical P1", 1), ("High P2", 4), ("Medium P3", 8), ("Low P4", 24)]):
        pol_id = _id()
        total += insert(con, "sla_policies", [{"id": pol_id, "org_id": ORG, "name": name,
            "sla_hours": sla_h, "severity": SEVERITIES[i % len(SEVERITIES)],
            "created_at": _ts(days_ago=90)}])
        for j in range(2):
            fid = f"FIND-{4000+i*2+j}"
            resolved = _ts(days_ago=j) if j == 0 else None
            total += insert(con, "sla_tracking", [{"id": _id(), "org_id": ORG,
                "finding_id": fid, "severity": SEVERITIES[i % len(SEVERITIES)],
                "sla_hours": sla_h, "policy_id": pol_id,
                "created_at": _ts(days_ago=3+j), "deadline": _ts(days_ago=3+j-sla_h/24),
                "resolved_at": resolved, "breached": 1 if j > 0 else 0}])
    con.close()

    con = db("threat_hunting.db")
    for i, (name, category) in enumerate([("Hunt SMB Lateral", "lateral_movement"), ("Hunt LSASS Dump", "credential_access"),
                                           ("Hunt DNS Beacon", "command_and_control"), ("Hunt Data Staging", "exfiltration")]):
        qid = _id()
        total += insert(con, "hunt_queries", [{"id": qid, "org_id": ORG,
            "name": name, "category": category,
            "query": f"SELECT * FROM events WHERE tactic='{category}'",
            "mitre_technique": f"T{1059+i}", "created_at": _ts(days_ago=60+i*10)}])
    for i, (name, hunter) in enumerate(zip(["Q1 Hunt", "APT Hunt", "Insider Hunt"], USERS[:3])):
        sid = _id()
        total += insert(con, "hunt_sessions", [{"id": sid, "org_id": ORG,
            "name": name, "hunter_email": hunter,
            "status": ["completed", "in_progress", "planned"][i],
            "started_at": _ts(days_ago=30+i*7)}])
        total += insert(con, "hunt_results", [{"id": _id(), "org_id": ORG,
            "hunt_id": sid, "severity": SEVERITIES[i % len(SEVERITIES)],
            "title": f"Finding from {name}", "description": "Suspicious activity detected",
            "detected_at": _ts(days_ago=28+i*7)}])
    for i, (name, htype) in enumerate([("Weekly Lateral Hunt", "hypothesis"), ("Monthly C2 Hunt", "ioc_based")]):
        hid = _id()
        total += insert(con, "hunts", [{"id": hid, "org_id": ORG, "name": name,
            "hunt_type": htype, "status": "active",
            "created_at": _ts(days_ago=60+i*30), "updated_at": _ts(days_ago=i*7)}])
        total += insert(con, "hunt_schedules", [{"id": _id(), "org_id": ORG, "hunt_id": hid,
            "frequency": ["weekly", "monthly"][i], "next_run": _date(days_ahead=7),
            "created_at": _ts(days_ago=60+i*30)}])
    con.close()

    con = db("user_analytics.db")
    for i, user in enumerate(USERS):
        total += insert(con, "activities", [
            {"id": _id(), "org_id": ORG, "user_email": user,
             "activity_type": act, "page": f"/dashboard/{j}",
             "timestamp": _ts(days_ago=i, hours_ago=j*2)}
            for j, act in enumerate(["page_view", "api_call", "alert_review", "report_view"])
        ])
    con.close()

    con = db("vendor_risk.db")
    vids = [_id() for _ in range(4)]
    for i, (vid, vname, category) in enumerate(zip(vids,
        ["Salesforce", "AWS", "Zoom", "GitHub"],
        ["crm", "cloud", "communications", "devtools"])):
        vdata = json.dumps({"name": vname, "category": category, "website": f"https://{vname.lower()}.com",
                            "contact": f"security@{vname.lower()}.com", "tier": ["critical","critical","high","high"][i]})
        total += insert(con, "vendors", [{"id": vid, "org_id": ORG,
            "data": vdata, "status": "active",
            "risk_score": round(random.uniform(20, 80), 1),
            "created_at": _ts(days_ago=365), "updated_at": _ts(days_ago=i*30)}])
        total += insert(con, "assessments", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid,
            "data": json.dumps({"type": "annual", "score": random.randint(70, 95)}),
            "status": "completed", "submitted_at": _ts(days_ago=180)}])
        total += insert(con, "risk_signals", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid,
            "data": json.dumps({"signal_type": "breach_news", "severity": SEVERITIES[i % len(SEVERITIES)]}),
            "detected_at": _ts(days_ago=i*15)}])
        total += insert(con, "scorecard_history", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid, "score": round(random.uniform(60, 95), 1),
            "grade": ["A", "B", "B", "C"][i], "calculated_at": _ts(days_ago=i*30)}])
    con.close()

    con = db("vendor_risk_engine.db")
    vids2 = [_id() for _ in range(3)]
    for i, (vid, vname, tier) in enumerate(zip(vids2, ["Microsoft", "Okta", "CrowdStrike"], ["critical", "critical", "high"])):
        total += insert(con, "vra_vendors", [{"id": vid, "org_id": ORG,
            "name": vname, "tier": tier, "contact": f"security@{vname.lower()}.com",
            "created_at": _ts(days_ago=365), "updated_at": _ts(days_ago=i*30)}])
        ass_id = _id()
        total += insert(con, "vra_assessments", [{"id": ass_id, "org_id": ORG,
            "vendor_id": vid, "status": "completed",
            "score": round(random.uniform(70, 95), 1),
            "created_at": _ts(days_ago=180+i*30)}])
        total += insert(con, "vra_responses", [{"id": _id(), "org_id": ORG,
            "assessment_id": ass_id, "question_id": f"Q-{i+1:03d}",
            "answer": True, "submitted_at": _ts(days_ago=175)}])
        total += insert(con, "engine_assessments", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid, "vendor_name": vname,
            "risk_score": round(random.uniform(20, 60), 1),
            "risk_level": SEVERITIES[i % len(SEVERITIES)],
            "assessed_at": _ts(days_ago=i*30)}])
        total += insert(con, "engine_scorecards", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid, "vendor_name": vname,
            "overall_score": round(random.uniform(60, 95), 1),
            "risk_level": SEVERITIES[i % len(SEVERITIES)],
            "grade": ["A", "B", "B"][i], "calculated_at": _ts(days_ago=i*30)}])
        total += insert(con, "engine_questionnaires", [{"id": _id(), "org_id": ORG,
            "vendor_id": vid,
            "questions_json": json.dumps([{"q": "Do you have SOC2?", "type": "boolean"}]),
            "sent_at": _ts(days_ago=200)}])
    con.close()

    con = db("vuln_risk_scores.db")
    for i, (cve, cvss, epss, kev) in enumerate([
        ("CVE-2024-1111", 9.8, 0.92, True), ("CVE-2024-2222", 7.5, 0.45, False),
        ("CVE-2024-3333", 5.0, 0.12, False), ("CVE-2024-4444", 8.8, 0.71, True),
    ]):
        score = min(100.0, cvss * 5 + epss * 20 + (30 if kev else 0))
        total += insert(con, "vuln_risk_scores", [{"id": _id(), "org_id": ORG,
            "cve_id": cve, "composite_score": round(score, 2),
            "priority": SEVERITIES[i % len(SEVERITIES)],
            "factors": json.dumps({"cvss": cvss, "epss": epss, "kev": kev}),
            "recommendation": "Patch immediately" if score > 80 else "Patch within SLA",
            "sla_hours": [24, 72, 168, 336][i],
            "context": json.dumps({"asset_criticality": "high", "exposure": "internet"}),
            "scored_at": _ts(days_ago=i)}])
    con.close()

    con = db("vulnerability_analytics.db")
    for i, (cve, etype, sev) in enumerate([
        ("CVE-2024-A001", "opened", "critical"), ("CVE-2024-A002", "opened", "high"),
        ("CVE-2024-A001", "remediated", "critical"), ("CVE-2024-A003", "opened", "medium"),
        ("CVE-2024-A004", "opened", "critical"), ("CVE-2024-A002", "remediated", "high"),
    ]):
        fid = _hash(f"{cve}-{etype}-{i}")[:36]
        total += insert(con, "finding_events", [{"id": _id(), "org_id": ORG,
            "finding_id": fid, "cve_id": cve,
            "event_type": etype, "severity": sev,
            "ts": _ts(days_ago=30-i*4), "scanner": "openvas"}])
    con.close()

    con = db("workflow_engine.db")
    wf_ids = [_id() for _ in range(3)]
    for i, (wid, name, trigger) in enumerate(zip(wf_ids,
        ["Incident Response", "Vuln Remediation", "Change Approval"],
        ["alert_created", "finding_opened", "change_requested"])):
        total += insert(con, "workflows", [{"id": wid, "org_id": ORG,
            "name": name, "trigger": trigger,
            "steps_json": json.dumps([{"name": "Triage", "action": "review"}, {"name": "Fix", "action": "remediate"}]),
            "status": "active", "created_at": _ts(days_ago=90+i*10)}])
        total += insert(con, "workflow_executions", [{"id": _id(), "org_id": ORG,
            "workflow_id": wid, "trigger_event": f"{trigger}:event-{i}",
            "status": "completed", "started_at": _ts(days_ago=i*7),
            "completed_at": _ts(days_ago=i*7-1)}])
    con.close()

    con = db("zero_trust.db")
    for i, (os_name, osver) in enumerate([("Windows", "11"), ("macOS", "14.0"), ("Linux", "Ubuntu 22.04")]):
        did = _id()
        total += insert(con, "devices", [{"id": did, "org_id": ORG,
            "device_name": f"laptop-{i+1:03d}", "os": os_name, "os_version": osver,
            "managed": 1, "compliant": 1, "trust_score": round(random.uniform(70, 99), 1),
            "registered_at": _ts(days_ago=180+i*30), "last_seen": _ts(days_ago=i)}])
    for i, (user, resource, allowed, trust) in enumerate([
        (USERS[0], "admin_console", 1, "high"), (USERS[1], "finance_db", 0, "low"),
        (USERS[2], "siem_dashboard", 1, "medium"), (USERS[3], "s3_sensitive", 0, "low"),
    ]):
        total += insert(con, "access_events", [{"id": _id(), "org_id": ORG,
            "user_id": user, "resource": resource, "allowed": allowed,
            "trust_level": trust, "reason": "Trust score evaluation",
            "evaluated_at": _ts(days_ago=i)}])
    for i in range(3):
        total += insert(con, "sessions", [{"id": _id(), "org_id": ORG,
            "user_id": USERS[i], "device_id": _id(), "trust_score": round(random.uniform(60, 95), 1),
            "created_at": _ts(days_ago=i), "updated_at": _ts(days_ago=i)}])
    total += insert(con, "geo_restrictions", [{"id": _id(), "org_id": ORG,
        "blocked_countries": json.dumps(["KP", "IR", "RU"]),
        "allowed_countries": json.dumps(["US", "GB", "CA", "AU"]),
        "created_at": _ts(days_ago=90)}])
    total += insert(con, "time_restrictions", [{"id": _id(), "org_id": ORG,
        "allowed_hours_start": "06:00", "allowed_hours_end": "22:00",
        "allowed_days": json.dumps(["Mon", "Tue", "Wed", "Thu", "Fri"]),
        "created_at": _ts(days_ago=90)}])
    for i, (name, action) in enumerate([("Block untrusted devices", "deny"), ("Allow MFA users", "allow"),
                                          ("Restrict after hours", "mfa_required")]):
        total += insert(con, "zt_policies", [{"id": _id(), "org_id": ORG,
            "name": name, "action": action, "enabled": 1,
            "created_at": _ts(days_ago=90+i*10), "updated_at": _ts(days_ago=i*7)}])
    for i, (user, decision, trust) in enumerate([(USERS[0], "allow", "high"), (USERS[1], "deny", "low"),
                                                   (USERS[2], "allow", "medium")]):
        total += insert(con, "zt_access_log", [{"id": _id(), "org_id": ORG,
            "user_id": user, "resource": f"resource-{i+1}", "decision": decision,
            "trust_level": trust, "evaluated_at": _ts(days_ago=i)}])
    con.close()

    con = db("zero_trust_engine.db")
    for i, (resource, action) in enumerate([("admin_portal", "allow"), ("finance_db", "deny"), ("siem", "allow")]):
        total += insert(con, "policies", [{"id": _id(), "org_id": ORG,
            "name": f"ZTE Policy {i+1}: {resource}", "resource": resource,
            "policy_type": ["identity", "device", "application"][i], "action": action,
            "enabled": 1, "created_at": _ts(days_ago=90+i*10), "updated_at": _ts(days_ago=i*7)}])
    for i, user in enumerate(USERS[:3]):
        total += insert(con, "entity_trust", [{"id": _id(), "org_id": ORG,
            "entity_id": user, "entity_type": "user",
            "trust_score": round(random.uniform(50, 99), 1),
            "signals": json.dumps({"mfa": True, "device_managed": i < 2}),
            "updated_at": _ts(days_ago=i)}])
    for i, (user, resource, decision, trust) in enumerate([
        (USERS[0], "admin_portal", "allow", 95.0),
        (USERS[1], "finance_db", "deny", 30.0),
        (USERS[2], "siem", "allow", 78.0),
    ]):
        total += insert(con, "access_log", [{"id": _id(), "org_id": ORG,
            "user_id": user, "device_id": _id(), "resource": resource,
            "action": "GET", "decision": decision,
            "trust_score": trust, "evaluated_at": _ts(days_ago=i)}])
    con.close()

    return total


def main():
    print(f"\nALDECI Direct Insert Seeder")
    print(f"  Org: {ORG}  Time: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")

    total = 0

    # Engine fixes first
    print("  [Phase 1] Engine API fixes...")
    try:
        n = also_fix_engines()
        total += n
        print(f"  [OK ] engine_fixes: {n} records")
    except Exception as ex:
        print(f"  [FAIL] engine_fixes: {ex}")

    # Direct SQLite inserts
    print("\n  [Phase 2] Direct SQLite inserts...")
    try:
        n = seed_all_direct()
        total += n
        print(f"  [OK ] direct_inserts: {n} records")
    except Exception as ex:
        print(f"  [FAIL] direct_inserts: {ex}")
        import traceback; traceback.print_exc()

    print(f"\n  Total records inserted: {total}")

    # Final count
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
        print(f"\n  Still empty ({len(empty)}):")
        for d in empty:
            print(f"    - {d}")
    else:
        print("\n  All DBs have data!")
    print(f"\n  Remaining empty DBs: {len(empty)}")


if __name__ == "__main__":
    main()
