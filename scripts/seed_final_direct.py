#!/usr/bin/env python3
"""
Final direct SQLite seeder for all 46 remaining empty DBs.
No imports from suite-core needed — pure sqlite3 inserts.
"""
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

DATA_DIR = Path(__file__).parent.parent / "data"

NOW = datetime.now(timezone.utc)

def ts(offset_days=0):
    return (NOW + timedelta(days=offset_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

def db(name):
    return sqlite3.connect(str(DATA_DIR / name))

def insert(con, table, rows):
    if not rows:
        return 0
    cols = list(rows[0].keys())
    placeholders = ",".join("?" * len(cols))
    sql = f"INSERT OR IGNORE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    count = 0
    for row in rows:
        try:
            con.execute(sql, [row[c] for c in cols])
            count += 1
        except Exception as e:
            print(f"    [warn] {table}: {e}")
    con.commit()
    return count

def seed_api_versioning():
    con = db("api_versioning.db")
    n = insert(con, "endpoint_versions", [
        {"path": "/api/v1/vulnerabilities", "version": "v1", "status": "active", "created_at": ts(-30), "updated_at": ts(-1)},
        {"path": "/api/v1/assets", "version": "v1", "status": "active", "created_at": ts(-25), "updated_at": ts(-2)},
        {"path": "/api/v1/incidents", "version": "v1", "status": "deprecated", "created_at": ts(-60), "updated_at": ts(-10)},
        {"path": "/api/v2/incidents", "version": "v2", "status": "active", "created_at": ts(-10), "updated_at": ts()},
    ])
    con.close()
    return n

def seed_audit_trail():
    con = db("audit_trail.db")
    import hashlib
    n = insert(con, "audit_trail", [
        {"timestamp": ts(-1), "method": "POST", "path": "/api/v1/vulnerabilities", "org_id": "default",
         "actor_id": "admin@acme.com", "status_code": 201, "body_hash": hashlib.sha256(b"vuln-payload").hexdigest(),
         "duration_ms": 42.3, "client_ip": "192.168.1.10"},
        {"timestamp": ts(-1), "method": "GET", "path": "/api/v1/assets", "org_id": "default",
         "actor_id": "analyst@acme.com", "status_code": 200, "body_hash": hashlib.sha256(b"").hexdigest(),
         "duration_ms": 15.1, "client_ip": "10.0.0.5"},
        {"timestamp": ts(), "method": "DELETE", "path": "/api/v1/findings/123", "org_id": "default",
         "actor_id": "admin@acme.com", "status_code": 200, "body_hash": hashlib.sha256(b"delete").hexdigest(),
         "duration_ms": 8.9, "client_ip": "192.168.1.10"},
    ])
    con.close()
    return n

def seed_cicd_integration():
    con = db("cicd_integration.db")
    n = insert(con, "policies", [
        {"rules_json": json.dumps({"block_on": "critical", "notify_on": "high"}), "created_at": ts(-10), "org_id": "default", "name": "block-critical"},
        {"rules_json": json.dumps({"block_on": "critical", "notify_on": "medium"}), "created_at": ts(-5), "org_id": "default", "name": "strict-policy"},
    ])
    n += insert(con, "scan_history", [
        {"repo": "github.com/acme/backend", "policy_action": "blocked", "scanned_at": ts(-2), "findings_count": 3, "org_id": "default"},
        {"repo": "github.com/acme/frontend", "policy_action": "passed", "scanned_at": ts(-1), "findings_count": 0, "org_id": "default"},
        {"repo": "github.com/acme/api", "policy_action": "warned", "scanned_at": ts(), "findings_count": 5, "org_id": "default"},
    ])
    con.close()
    return n

def seed_cwpp():
    con = db("cwpp.db")
    n = insert(con, "workloads", [
        {"workload_type": "container", "name": "api-server", "registered_at": ts(-30), "org_id": "default", "status": "running"},
        {"workload_type": "vm", "name": "db-primary", "registered_at": ts(-20), "org_id": "default", "status": "running"},
        {"workload_type": "serverless", "name": "event-processor", "registered_at": ts(-10), "org_id": "default", "status": "running"},
    ])
    n += insert(con, "threats", [
        {"workload_id": "1", "category": "malware", "severity": "high", "detected_at": ts(-2), "org_id": "default"},
        {"workload_id": "2", "category": "privilege_escalation", "severity": "critical", "detected_at": ts(-1), "org_id": "default"},
    ])
    n += insert(con, "compliance_results", [
        {"workload_id": "1", "framework": "CIS", "score": 87.5, "passed": 35, "failed": 5, "checked_at": ts(), "org_id": "default"},
        {"workload_id": "2", "framework": "NIST", "score": 72.0, "passed": 28, "failed": 11, "checked_at": ts(), "org_id": "default"},
    ])
    con.close()
    return n

def seed_evidence_chain():
    import hashlib
    con = db("evidence_chain.db")
    prev = "0" * 64
    rows = []
    for i, event in enumerate(["created", "modified", "reviewed", "approved", "sealed"]):
        data_hash = hashlib.sha256(f"data-{i}".encode()).hexdigest()
        cur_hash = hashlib.sha256(f"{prev}{data_hash}".encode()).hexdigest()
        rows.append({
            "sequence_number": i + 1,
            "event_type": event,
            "data_hash": data_hash,
            "previous_hash": prev,
            "timestamp": ts(-5 + i),
            "signature": hashlib.sha256(f"sig-{i}".encode()).hexdigest(),
            "org_id": "default",
        })
        prev = cur_hash
    n = insert(con, "chain_entries", rows)
    con.close()
    return n

def seed_evidence_collector():
    con = db("evidence_collector.db")
    n = insert(con, "evidence", [
        {"control_id": "CC6.1", "framework": "SOC2", "type": "screenshot", "title": "MFA Enabled",
         "description": "MFA enforced for all admin accounts", "collected_at": ts(-5),
         "collected_by": "system", "org_id": "default", "status": "approved"},
        {"control_id": "A.9.1", "framework": "ISO27001", "type": "log_export", "title": "Access Logs",
         "description": "Monthly access control logs", "collected_at": ts(-3),
         "collected_by": "analyst@acme.com", "org_id": "default", "status": "pending"},
        {"control_id": "PCI-8.3", "framework": "PCI-DSS", "type": "config_export", "title": "Password Policy Config",
         "description": "Password complexity requirements", "collected_at": ts(-1),
         "collected_by": "system", "org_id": "default", "status": "approved"},
    ])
    n += insert(con, "auto_requirements", [
        {"framework": "SOC2", "control_id": "CC6.1", "control_name": "Logical Access Controls",
         "evidence_types": json.dumps(["screenshot", "config_export"]), "created_at": ts(-10)},
        {"framework": "ISO27001", "control_id": "A.9.1", "control_name": "Access Control Policy",
         "evidence_types": json.dumps(["log_export", "policy_doc"]), "created_at": ts(-10)},
    ])
    con.close()
    return n

def seed_ir_playbook():
    con = db("ir_playbook.db")
    n = insert(con, "ir_incidents", [
        {"playbook_id": "pb-001", "title": "Ransomware Incident Q1", "incident_type": "ransomware",
         "severity": "critical", "status": "resolved", "created_at": ts(-15), "updated_at": ts(-10)},
        {"playbook_id": "pb-002", "title": "Phishing Campaign", "incident_type": "phishing",
         "severity": "high", "status": "investigating", "created_at": ts(-3), "updated_at": ts(-1)},
    ])
    n += insert(con, "ir_timeline", [
        {"incident_id": "1", "event_type": "detection", "source": "SIEM", "description": "Alert triggered", "timestamp": ts(-15)},
        {"incident_id": "1", "event_type": "containment", "source": "SOC", "description": "Isolated affected hosts", "timestamp": ts(-14)},
        {"incident_id": "1", "event_type": "resolution", "source": "SOC", "description": "Systems restored from backup", "timestamp": ts(-10)},
    ])
    con.close()
    return n

def seed_metrics_aggregator():
    con = db("metrics_aggregator.db")
    n = insert(con, "metrics_snapshots", [
        {"org_id": "default", "timestamp": ts(-2),
         "metrics_json": json.dumps({"mttr_hours": 4.2, "open_vulns": 142, "compliance_score": 87.3})},
        {"org_id": "default", "timestamp": ts(-1),
         "metrics_json": json.dumps({"mttr_hours": 3.8, "open_vulns": 138, "compliance_score": 88.1})},
        {"org_id": "default", "timestamp": ts(),
         "metrics_json": json.dumps({"mttr_hours": 3.5, "open_vulns": 131, "compliance_score": 89.0})},
    ])
    con.close()
    return n

def seed_mpte():
    con = db("mpte.db")
    n = insert(con, "pen_test_configs", [
        {"name": "Default MPTE Config", "mpte_url": "http://localhost:9000",
         "enabled": 1, "max_concurrent_tests": 5, "timeout_seconds": 300,
         "auto_trigger": 1, "created_at": ts(-30), "updated_at": ts(-1)},
    ])
    n += insert(con, "pen_test_requests", [
        {"finding_id": "FIND-001", "target_url": "https://api.acme.com/login",
         "vulnerability_type": "sql_injection", "test_case": "OR 1=1 payload",
         "priority": "high", "status": "completed", "created_at": ts(-5)},
        {"finding_id": "FIND-002", "target_url": "https://api.acme.com/upload",
         "vulnerability_type": "xss", "test_case": "script alert payload",
         "priority": "medium", "status": "pending", "created_at": ts(-2)},
    ])
    n += insert(con, "pen_test_results", [
        {"request_id": "1", "finding_id": "FIND-001", "exploitability": "confirmed",
         "exploit_successful": 1, "evidence": "Retrieved admin session token", "created_at": ts(-4)},
    ])
    con.close()
    return n

def seed_network_analyzer():
    con = db("network_analyzer.db")
    n = insert(con, "zones", [
        {"name": "DMZ", "type": "dmz", "cidrs": json.dumps(["10.0.1.0/24"]),
         "assets": json.dumps(["web-01", "lb-01"]), "trust_level": 2,
         "metadata": json.dumps({}), "created_at": ts(-30), "org_id": "default"},
        {"name": "Internal", "type": "internal", "cidrs": json.dumps(["10.0.0.0/16"]),
         "assets": json.dumps(["db-01", "app-01"]), "trust_level": 8,
         "metadata": json.dumps({}), "created_at": ts(-30), "org_id": "default"},
    ])
    n += insert(con, "flows", [
        {"source_zone": "DMZ", "dest_zone": "Internal", "ports": json.dumps([443, 8080]),
         "protocol": "TCP", "direction": "inbound", "allowed": 1, "risk_score": 3.5,
         "metadata": json.dumps({}), "observed_at": ts(-1), "org_id": "default"},
        {"source_zone": "External", "dest_zone": "DMZ", "ports": json.dumps([80, 443]),
         "protocol": "TCP", "direction": "inbound", "allowed": 1, "risk_score": 2.0,
         "metadata": json.dumps({}), "observed_at": ts(), "org_id": "default"},
    ])
    n += insert(con, "violations", [
        {"flow_id": "1", "flow_json": json.dumps({"src": "External", "dst": "Internal"}),
         "rule_violated": "no-direct-external-internal", "severity": "high",
         "detected_at": ts(-5), "metadata": json.dumps({}), "org_id": "default"},
    ])
    con.close()
    return n

def seed_notifications():
    con = db("notifications.db")
    n = insert(con, "alert_rules", [
        {"name": "Critical Vulnerability Alert", "conditions": json.dumps({"severity": "critical"}),
         "channels": json.dumps(["email", "slack"]), "recipients": json.dumps(["security@acme.com"]),
         "digest_frequency": "immediate", "created_at": ts(-10), "updated_at": ts(-1), "org_id": "default"},
        {"name": "Daily Digest", "conditions": json.dumps({"min_severity": "medium"}),
         "channels": json.dumps(["email"]), "recipients": json.dumps(["team@acme.com"]),
         "digest_frequency": "daily", "created_at": ts(-5), "updated_at": ts(-1), "org_id": "default"},
    ])
    n += insert(con, "notifications", [
        {"timestamp": ts(-1), "rule_name": "Critical Vulnerability Alert", "channel": "email",
         "recipient": "security@acme.com", "subject": "Critical CVE-2024-1234 detected",
         "body": "A critical vulnerability was detected in api-server. CVSS: 9.8"},
        {"timestamp": ts(-2), "rule_name": "Daily Digest", "channel": "slack",
         "recipient": "#security-alerts", "subject": "Daily Security Digest",
         "body": "5 new vulnerabilities, 2 incidents resolved"},
    ])
    n += insert(con, "preferences", [
        {"user_id": "admin@acme.com", "channels": json.dumps({"email": True, "slack": True, "sms": False}),
         "updated_at": ts(-5), "org_id": "default"},
    ])
    con.close()
    return n

def seed_policies():
    con = db("policies.db")
    n = insert(con, "policies", [
        {"name": "Acceptable Use Policy", "description": "Rules for acceptable use of IT resources",
         "policy_type": "acceptable_use", "status": "active",
         "rules": json.dumps(["No personal use of production systems", "MFA required for all logins"]),
         "created_at": ts(-180), "updated_at": ts(-30), "org_id": "default", "version": "2.1"},
        {"name": "Vulnerability Management Policy", "description": "SLA for vuln remediation",
         "policy_type": "security", "status": "active",
         "rules": json.dumps(["Critical: 24h", "High: 7d", "Medium: 30d"]),
         "created_at": ts(-90), "updated_at": ts(-10), "org_id": "default", "version": "1.3"},
        {"name": "Data Retention Policy", "description": "Data retention and deletion requirements",
         "policy_type": "data_governance", "status": "active",
         "rules": json.dumps(["PII: 2 years max", "Logs: 1 year", "Backups: 90 days"]),
         "created_at": ts(-120), "updated_at": ts(-15), "org_id": "default", "version": "1.0"},
    ])
    con.close()
    return n

def seed_posture_advisor():
    con = db("posture_advisor.db")
    n = insert(con, "analyses", [
        {"org_id": "default", "posture_score": 74.5,
         "recommendation_ids": json.dumps(["rec-001", "rec-002", "rec-003"]),
         "created_at": ts(-7), "status": "completed"},
        {"org_id": "default", "posture_score": 78.2,
         "recommendation_ids": json.dumps(["rec-004", "rec-005"]),
         "created_at": ts(-1), "status": "completed"},
    ])
    n += insert(con, "recommendations", [
        {"analysis_id": "1", "org_id": "default", "template_id": "tmpl-mfa",
         "category": "identity", "priority": "high", "title": "Enforce MFA org-wide",
         "description": "Enable MFA for all user accounts", "impact": "high",
         "effort": "low", "created_at": ts(-7), "updated_at": ts(-7), "status": "open"},
        {"analysis_id": "1", "org_id": "default", "template_id": "tmpl-patch",
         "category": "vulnerability", "priority": "critical", "title": "Patch critical CVEs within 24h",
         "description": "7 critical CVEs remain unpatched > 24h", "impact": "critical",
         "effort": "medium", "created_at": ts(-7), "updated_at": ts(-7), "status": "open"},
        {"analysis_id": "2", "org_id": "default", "template_id": "tmpl-encrypt",
         "category": "data", "priority": "medium", "title": "Enable encryption at rest",
         "description": "3 S3 buckets lack encryption", "impact": "high",
         "effort": "low", "created_at": ts(-1), "updated_at": ts(-1), "status": "open"},
    ])
    con.close()
    return n

def seed_sbom():
    con = db("sbom.db")
    n = insert(con, "sboms", [
        {"format": "cyclonedx", "target": "api-server:1.4.2", "org_id": "default",
         "created_at": ts(-10), "content": json.dumps({"components": [
             {"name": "fastapi", "version": "0.104.0", "type": "library"},
             {"name": "pydantic", "version": "2.5.0", "type": "library"},
             {"name": "sqlalchemy", "version": "2.0.23", "type": "library"},
         ]})},
        {"format": "spdx", "target": "frontend:3.2.1", "org_id": "default",
         "created_at": ts(-5), "content": json.dumps({"packages": [
             {"name": "react", "version": "19.0.0", "licenseId": "MIT"},
             {"name": "vite", "version": "6.0.0", "licenseId": "MIT"},
         ]})},
    ])
    con.close()
    return n

def seed_security_scorecard():
    con = db("security_scorecard.db")
    n = insert(con, "scorecards", [
        {"org_id": "default", "overall_score": 82.4, "grade": "B",
         "generated_at": ts(-7), "valid_until": ts(23),
         "domain_scores": json.dumps({"identity": 90, "vulnerability": 75, "network": 85, "compliance": 88})},
        {"org_id": "default", "overall_score": 85.1, "grade": "B+",
         "generated_at": ts(), "valid_until": ts(30),
         "domain_scores": json.dumps({"identity": 92, "vulnerability": 78, "network": 87, "compliance": 89})},
    ])
    con.close()
    return n

def seed_sla_escalation():
    con = db("sla_escalation.db")
    n = insert(con, "escalation_policies", [
        {"name": "Critical SLA Policy", "org_id": "default",
         "tiers": json.dumps([{"hours": 4, "action": "notify"}, {"hours": 8, "action": "reassign"}, {"hours": 24, "action": "escalate"}]),
         "updated_at": ts(-10)},
        {"name": "High SLA Policy", "org_id": "default",
         "tiers": json.dumps([{"hours": 24, "action": "notify"}, {"hours": 48, "action": "reassign"}]),
         "updated_at": ts(-5)},
    ])
    n += insert(con, "sla_tracked_findings", [
        {"finding_id": "FIND-001", "org_id": "default", "severity": "critical",
         "deadline": ts(1), "status": "open", "created_at": ts(-2)},
        {"finding_id": "FIND-002", "org_id": "default", "severity": "high",
         "deadline": ts(5), "status": "open", "created_at": ts(-1)},
    ])
    n += insert(con, "escalation_events", [
        {"finding_id": "FIND-001", "org_id": "default", "action": "notify",
         "hours_past": 4.5, "created_at": ts(-1)},
    ])
    con.close()
    return n

def seed_sla_tracking():
    con = db("sla_tracking.db")
    n = insert(con, "sla_policies", [
        {"name": "Critical", "org_id": "default", "severity": "critical", "hours": 24, "created_at": ts(-30)},
        {"name": "High", "org_id": "default", "severity": "high", "hours": 72, "created_at": ts(-30)},
        {"name": "Medium", "org_id": "default", "severity": "medium", "hours": 168, "created_at": ts(-30)},
    ])
    n += insert(con, "sla_tracking", [
        {"finding_id": "FIND-101", "severity": "critical", "org_id": "default",
         "created_at": ts(-2), "deadline": ts(-2+1), "status": "breached"},
        {"finding_id": "FIND-102", "severity": "high", "org_id": "default",
         "created_at": ts(-1), "deadline": ts(-1+3), "status": "on_track"},
        {"finding_id": "FIND-103", "severity": "medium", "org_id": "default",
         "created_at": ts(-3), "deadline": ts(-3+7), "status": "on_track"},
    ])
    con.close()
    return n

def seed_threat_hunting():
    con = db("threat_hunting.db")
    n = insert(con, "hunt_queries", [
        {"name": "Lateral Movement Detection", "category": "lateral_movement",
         "query": "SELECT * FROM events WHERE event_type='smb_access'", "org_id": "default"},
        {"name": "Suspicious PowerShell", "category": "execution",
         "query": "SELECT * FROM events WHERE process='powershell.exe' AND cmdline LIKE '-enc%'", "org_id": "default"},
        {"name": "Data Exfil to External IPs", "category": "exfiltration",
         "query": "SELECT * FROM net_flows WHERE bytes_out > 1000000 AND dest_is_external=1", "org_id": "default"},
    ])
    n += insert(con, "hunts", [
        {"org_id": "default", "name": "Q1 APT Hunt", "hunt_type": "hypothesis",
         "status": "completed", "created_at": ts(-30), "updated_at": ts(-20)},
        {"org_id": "default", "name": "Ransomware Precursor Hunt", "hunt_type": "ioc",
         "status": "active", "created_at": ts(-5), "updated_at": ts(-1)},
    ])
    n += insert(con, "hunt_sessions", [
        {"name": "APT Hunt Session 1", "hunter_email": "hunter@acme.com",
         "started_at": ts(-30), "ended_at": ts(-28), "findings_count": 3, "org_id": "default"},
    ])
    n += insert(con, "hunt_results", [
        {"hunt_id": "1", "detected_at": ts(-25), "type": "ioc", "severity": "high",
         "description": "Suspicious lateral movement pattern detected", "org_id": "default"},
    ])
    con.close()
    return n

def seed_user_analytics():
    con = db("user_analytics.db")
    n = insert(con, "activities", [
        {"user_email": "admin@acme.com", "activity_type": "login", "timestamp": ts(-1), "org_id": "default", "details": json.dumps({"ip": "192.168.1.1"})},
        {"user_email": "analyst@acme.com", "activity_type": "report_view", "timestamp": ts(-1), "org_id": "default", "details": json.dumps({"report": "vuln-summary"})},
        {"user_email": "admin@acme.com", "activity_type": "policy_change", "timestamp": ts(), "org_id": "default", "details": json.dumps({"policy": "password-policy"})},
        {"user_email": "soc@acme.com", "activity_type": "alert_ack", "timestamp": ts(), "org_id": "default", "details": json.dumps({"alert_id": "ALT-555"})},
    ])
    con.close()
    return n

def seed_vendor_risk():
    con = db("vendor_risk.db")
    n = insert(con, "vendors", [
        {"data": json.dumps({"name": "CloudProvider Inc", "category": "cloud", "tier": "tier-1"}), "created_at": ts(-60), "updated_at": ts(-5), "org_id": "default"},
        {"data": json.dumps({"name": "SecurityTools Ltd", "category": "security", "tier": "tier-2"}), "created_at": ts(-45), "updated_at": ts(-3), "org_id": "default"},
        {"data": json.dumps({"name": "DataProcessor Co", "category": "data", "tier": "tier-3"}), "created_at": ts(-30), "updated_at": ts(-1), "org_id": "default"},
    ])
    n += insert(con, "assessments", [
        {"vendor_id": "1", "data": json.dumps({"score": 85, "risk": "low", "status": "complete"}), "submitted_at": ts(-10), "org_id": "default"},
        {"vendor_id": "2", "data": json.dumps({"score": 62, "risk": "medium", "status": "complete"}), "submitted_at": ts(-7), "org_id": "default"},
    ])
    n += insert(con, "risk_signals", [
        {"vendor_id": "3", "data": json.dumps({"signal": "data_breach_news", "source": "media"}), "detected_at": ts(-3), "org_id": "default"},
    ])
    n += insert(con, "scorecard_history", [
        {"vendor_id": "1", "score": 85.0, "grade": "B", "calculated_at": ts(-10)},
        {"vendor_id": "2", "score": 62.0, "grade": "D", "calculated_at": ts(-7)},
    ])
    con.close()
    return n

def seed_vendor_risk_engine():
    con = db("vendor_risk_engine.db")
    n = insert(con, "vra_vendors", [
        {"name": "Acme Cloud Services", "tier": "tier-1", "status": "active", "created_at": ts(-90), "updated_at": ts(-5)},
        {"name": "SecureNet Analytics", "tier": "tier-2", "status": "active", "created_at": ts(-60), "updated_at": ts(-3)},
        {"name": "DataVault Corp", "tier": "tier-3", "status": "pending", "created_at": ts(-30), "updated_at": ts(-1)},
    ])
    n += insert(con, "engine_assessments", [
        {"vendor_id": "1", "vendor_name": "Acme Cloud Services", "risk_score": 25.0,
         "risk_level": "low", "assessed_at": ts(-5)},
        {"vendor_id": "2", "vendor_name": "SecureNet Analytics", "risk_score": 55.0,
         "risk_level": "medium", "assessed_at": ts(-3)},
    ])
    n += insert(con, "engine_scorecards", [
        {"vendor_id": "1", "vendor_name": "Acme Cloud Services", "overall_score": 88.0,
         "risk_level": "low", "grade": "A", "calculated_at": ts(-5)},
        {"vendor_id": "2", "vendor_name": "SecureNet Analytics", "overall_score": 71.0,
         "risk_level": "medium", "grade": "C", "calculated_at": ts(-3)},
    ])
    n += insert(con, "engine_questionnaires", [
        {"vendor_id": "1", "questions_json": json.dumps(["Do you have SOC2?", "Do you encrypt data at rest?"]),
         "sent_at": ts(-10), "status": "responded"},
    ])
    con.close()
    return n

def seed_vuln_risk_scores():
    con = db("vuln_risk_scores.db")
    n = insert(con, "vuln_risk_scores", [
        {"org_id": "default", "cve_id": "CVE-2024-1234", "composite_score": 9.2, "priority": "critical",
         "factors": json.dumps({"cvss": 9.8, "epss": 0.87, "kev": True}),
         "recommendation": "Patch immediately", "sla_hours": 24,
         "context": json.dumps({"asset_count": 12, "internet_facing": True}),
         "scored_at": ts(-1)},
        {"org_id": "default", "cve_id": "CVE-2024-5678", "composite_score": 7.5, "priority": "high",
         "factors": json.dumps({"cvss": 7.8, "epss": 0.42, "kev": False}),
         "recommendation": "Patch within 7 days", "sla_hours": 168,
         "context": json.dumps({"asset_count": 5, "internet_facing": False}),
         "scored_at": ts(-1)},
        {"org_id": "default", "cve_id": "CVE-2024-9012", "composite_score": 5.3, "priority": "medium",
         "factors": json.dumps({"cvss": 5.5, "epss": 0.12, "kev": False}),
         "recommendation": "Patch within 30 days", "sla_hours": 720,
         "context": json.dumps({"asset_count": 2, "internet_facing": False}),
         "scored_at": ts()},
    ])
    con.close()
    return n

def seed_vulnerability_analytics():
    con = db("vulnerability_analytics.db")
    n = insert(con, "finding_events", [
        {"org_id": "default", "finding_id": "FIND-001", "event_type": "opened", "ts": ts(-30)},
        {"org_id": "default", "finding_id": "FIND-001", "event_type": "assigned", "ts": ts(-29)},
        {"org_id": "default", "finding_id": "FIND-001", "event_type": "resolved", "ts": ts(-25)},
        {"org_id": "default", "finding_id": "FIND-002", "event_type": "opened", "ts": ts(-10)},
        {"org_id": "default", "finding_id": "FIND-002", "event_type": "assigned", "ts": ts(-9)},
        {"org_id": "default", "finding_id": "FIND-003", "event_type": "opened", "ts": ts(-3)},
        {"org_id": "default", "finding_id": "FIND-004", "event_type": "opened", "ts": ts(-1)},
    ])
    con.close()
    return n

def seed_workflow_engine():
    con = db("workflow_engine.db")
    n = insert(con, "workflows", [
        {"name": "Critical Vuln Response", "trigger": "vulnerability.critical",
         "status": "active", "steps": json.dumps(["notify_soc", "create_ticket", "assign_owner"]),
         "created_at": ts(-20), "org_id": "default"},
        {"name": "Incident Auto-Escalate", "trigger": "incident.sla_breach",
         "status": "active", "steps": json.dumps(["notify_manager", "page_oncall"]),
         "created_at": ts(-15), "org_id": "default"},
        {"name": "New Asset Scan", "trigger": "asset.discovered",
         "status": "active", "steps": json.dumps(["run_vuln_scan", "apply_tags"]),
         "created_at": ts(-10), "org_id": "default"},
    ])
    n += insert(con, "workflow_executions", [
        {"workflow_id": "1", "trigger_event": "vulnerability.critical",
         "status": "completed", "started_at": ts(-5), "completed_at": ts(-5)},
        {"workflow_id": "2", "trigger_event": "incident.sla_breach",
         "status": "completed", "started_at": ts(-3), "completed_at": ts(-3)},
    ])
    con.close()
    return n

def seed_zero_trust():
    con = db("zero_trust.db")
    n = insert(con, "devices", [
        {"os": "macOS", "os_version": "14.2", "registered_at": ts(-90), "last_seen": ts(-1),
         "device_name": "mbp-admin-01", "compliance_status": "compliant", "org_id": "default"},
        {"os": "Windows", "os_version": "11", "registered_at": ts(-60), "last_seen": ts(),
         "device_name": "win-dev-02", "compliance_status": "compliant", "org_id": "default"},
        {"os": "Linux", "os_version": "Ubuntu 22.04", "registered_at": ts(-30), "last_seen": ts(-2),
         "device_name": "srv-prod-01", "compliance_status": "non_compliant", "org_id": "default"},
    ])
    n += insert(con, "zt_policies", [
        {"name": "Require MFA for Admin", "action": "mfa_required",
         "conditions": json.dumps({"role": "admin"}), "created_at": ts(-30), "updated_at": ts(-5), "org_id": "default"},
        {"name": "Allow Corp Devices", "action": "allow",
         "conditions": json.dumps({"device_compliance": "compliant"}), "created_at": ts(-20), "updated_at": ts(-2), "org_id": "default"},
        {"name": "Deny Unmanaged", "action": "deny",
         "conditions": json.dumps({"managed": False}), "created_at": ts(-15), "updated_at": ts(-1), "org_id": "default"},
    ])
    n += insert(con, "access_events", [
        {"user_id": "admin@acme.com", "resource": "/api/admin", "allowed": 1,
         "trust_level": "high", "reason": "MFA verified, compliant device", "evaluated_at": ts(-1), "org_id": "default"},
        {"user_id": "guest@external.com", "resource": "/api/admin", "allowed": 0,
         "trust_level": "none", "reason": "Unmanaged device, no MFA", "evaluated_at": ts(), "org_id": "default"},
    ])
    n += insert(con, "zt_access_log", [
        {"decision": "allow", "trust_level": "high", "evaluated_at": ts(-1), "org_id": "default"},
        {"decision": "deny", "trust_level": "none", "evaluated_at": ts(), "org_id": "default"},
    ])
    con.close()
    return n

def seed_zero_trust_engine():
    con = db("zero_trust_engine.db")
    n = insert(con, "policies", [
        {"resource": "/api/admin/*", "action": "mfa_required", "conditions": json.dumps({"role": "admin"}),
         "created_at": ts(-30), "updated_at": ts(-5), "org_id": "default"},
        {"resource": "/api/reports/*", "action": "allow", "conditions": json.dumps({"role": ["analyst", "admin"]}),
         "created_at": ts(-20), "updated_at": ts(-2), "org_id": "default"},
        {"resource": "/api/config/*", "action": "deny", "conditions": json.dumps({"trust_score": {"lt": 0.5}}),
         "created_at": ts(-10), "updated_at": ts(-1), "org_id": "default"},
    ])
    n += insert(con, "entity_trust", [
        {"entity_id": "admin@acme.com", "entity_type": "user", "trust_score": 0.92,
         "factors": json.dumps({"mfa": True, "device_compliant": True, "location": "known"}),
         "updated_at": ts(-1), "org_id": "default"},
        {"entity_id": "analyst@acme.com", "entity_type": "user", "trust_score": 0.78,
         "factors": json.dumps({"mfa": True, "device_compliant": True, "location": "known"}),
         "updated_at": ts(), "org_id": "default"},
    ])
    n += insert(con, "access_log", [
        {"user_id": "admin@acme.com", "device_id": "mbp-admin-01", "resource": "/api/admin/users",
         "action": "GET", "decision": "allow", "trust_score": 0.92, "evaluated_at": ts(-1), "org_id": "default"},
        {"user_id": "analyst@acme.com", "device_id": "win-dev-02", "resource": "/api/reports/summary",
         "action": "GET", "decision": "allow", "trust_score": 0.78, "evaluated_at": ts(), "org_id": "default"},
    ])
    con.close()
    return n

# ---- DBs from other list ----

def seed_ai_orchestrator():
    con = db("ai_orchestrator.db")
    n = insert(con, "agent_tasks", [
        {"role": "analyzer", "prompt": "Analyze CVE-2024-1234 impact on api-server", "status": "completed",
         "result": json.dumps({"risk": "critical", "affected": 12}), "created_at": ts(-5), "org_id": "default"},
        {"role": "advisor", "prompt": "Recommend remediation for open S3 buckets", "status": "completed",
         "result": json.dumps({"steps": ["Enable encryption", "Apply bucket policy"]}), "created_at": ts(-2), "org_id": "default"},
        {"role": "summarizer", "prompt": "Summarize weekly security posture", "status": "pending",
         "result": None, "created_at": ts(), "org_id": "default"},
    ])
    n += insert(con, "consensus_results", [
        {"prompt": "Should we block CVE-2024-1234 exploitable hosts?", "decision": "yes",
         "confidence": 0.94, "reasoning": "KEV confirmed, EPSS 0.87, critical CVSS",
         "created_at": ts(-3), "org_id": "default"},
    ])
    con.close()
    return n

def seed_anomaly_ml_engine():
    con = db("anomaly_ml_engine.db")
    n = insert(con, "ts_events", [
        {"org_id": "default", "entity_id": "api-server", "metric_name": "cpu_usage", "value": 45.2, "recorded_at": ts(-3)},
        {"org_id": "default", "entity_id": "api-server", "metric_name": "cpu_usage", "value": 98.7, "recorded_at": ts(-1)},
        {"org_id": "default", "entity_id": "db-primary", "metric_name": "query_latency_ms", "value": 12.3, "recorded_at": ts(-2)},
    ])
    n += insert(con, "ml_anomalies", [
        {"org_id": "default", "entity_id": "api-server", "entity_type": "host",
         "metric_name": "cpu_usage", "category": "performance", "observed_value": 98.7,
         "expected_value": 45.2, "risk_level": "high", "description": "CPU spike 2x baseline",
         "detected_at": ts(-1)},
    ])
    con.close()
    return n

def seed_api_analytics():
    con = db("api_analytics.db")
    n = insert(con, "api_calls", [
        {"endpoint": "/api/v1/vulnerabilities", "method": "GET", "status_code": 200, "response_ms": 42.3, "timestamp": ts(-1), "org_id": "default"},
        {"endpoint": "/api/v1/assets", "method": "GET", "status_code": 200, "response_ms": 18.7, "timestamp": ts(-1), "org_id": "default"},
        {"endpoint": "/api/v1/incidents", "method": "POST", "status_code": 201, "response_ms": 65.2, "timestamp": ts(), "org_id": "default"},
        {"endpoint": "/api/v1/reports", "method": "GET", "status_code": 200, "response_ms": 312.1, "timestamp": ts(), "org_id": "default"},
        {"endpoint": "/api/v1/login", "method": "POST", "status_code": 401, "response_ms": 8.4, "timestamp": ts(), "org_id": "default"},
    ])
    con.close()
    return n

def seed_auto_evidence():
    con = db("auto_evidence.db")
    import hashlib
    n = insert(con, "auto_evidence", [
        {"source": "aws_config", "control_id": "CC6.1", "framework": "SOC2",
         "content_hash": hashlib.sha256(b"mfa-policy-config").hexdigest(),
         "collected_at": ts(-5), "org_id": "default", "status": "approved"},
        {"source": "github_actions", "control_id": "SA-11", "framework": "NIST800-53",
         "content_hash": hashlib.sha256(b"ci-scan-results").hexdigest(),
         "collected_at": ts(-3), "org_id": "default", "status": "pending"},
        {"source": "crowdstrike", "control_id": "SI-2", "framework": "NIST800-53",
         "content_hash": hashlib.sha256(b"patch-status-report").hexdigest(),
         "collected_at": ts(-1), "org_id": "default", "status": "approved"},
    ])
    con.close()
    return n

def seed_compliance_planner():
    con = db("compliance_planner.db")
    n = insert(con, "remediation_plans", [
        {"framework": "SOC2", "org_id": "default", "status": "active",
         "completion_pct": 45.0, "created_at": ts(-30), "target_date": ts(60)},
        {"framework": "ISO27001", "org_id": "default", "status": "active",
         "completion_pct": 72.0, "created_at": ts(-60), "target_date": ts(30)},
    ])
    n += insert(con, "gap_remediations", [
        {"plan_id": "1", "framework": "SOC2", "control_id": "CC6.1", "control_name": "Logical Access",
         "gap_description": "MFA not enforced for all users", "effort": "low", "priority": "high",
         "org_id": "default", "status": "in_progress", "created_at": ts(-20), "updated_at": ts(-5)},
        {"plan_id": "1", "framework": "SOC2", "control_id": "CC7.2", "control_name": "System Monitoring",
         "gap_description": "No centralized log management", "effort": "high", "priority": "medium",
         "org_id": "default", "status": "planned", "created_at": ts(-20), "updated_at": ts(-15)},
        {"plan_id": "2", "framework": "ISO27001", "control_id": "A.9.1", "control_name": "Access Policy",
         "gap_description": "Access policy not formally documented", "effort": "medium", "priority": "high",
         "org_id": "default", "status": "completed", "created_at": ts(-45), "updated_at": ts(-10)},
    ])
    con.close()
    return n

def seed_dashboard_builder():
    con = db("dashboard_builder.db")
    n = insert(con, "dashboards", [
        {"name": "SOC Overview", "owner_email": "soc@acme.com",
         "layout": json.dumps({"widgets": ["alert_count", "mttr", "open_vulns"]}),
         "created_at": ts(-30), "updated_at": ts(-5), "org_id": "default"},
        {"name": "Executive Summary", "owner_email": "ciso@acme.com",
         "layout": json.dumps({"widgets": ["posture_score", "compliance_rate", "risk_trend"]}),
         "created_at": ts(-20), "updated_at": ts(-2), "org_id": "default"},
        {"name": "Vulnerability Dashboard", "owner_email": "vuln@acme.com",
         "layout": json.dumps({"widgets": ["critical_count", "age_distribution", "sla_compliance"]}),
         "created_at": ts(-15), "updated_at": ts(-1), "org_id": "default"},
    ])
    con.close()
    return n

def seed_developer_profiles():
    con = db("developer_profiles.db")
    n = insert(con, "developer_profiles", [
        {"email_domain": "acme.com", "risk_score": 25.0, "first_seen": ts(-180), "last_seen": ts(-1),
         "commit_count": 342, "vuln_introduced": 3, "org_id": "default"},
        {"email_domain": "contractor.net", "risk_score": 65.0, "first_seen": ts(-90), "last_seen": ts(-3),
         "commit_count": 87, "vuln_introduced": 12, "org_id": "default"},
    ])
    n += insert(con, "developer_contributions", [
        {"commit_sha": "abc123def456", "developer_id": "1", "timestamp": ts(-5), "repo": "backend", "files_changed": 8},
        {"commit_sha": "789xyz012abc", "developer_id": "2", "timestamp": ts(-3), "repo": "api", "files_changed": 15},
    ])
    n += insert(con, "developer_findings", [
        {"developer_id": "2", "finding_id": "FIND-301", "introduced_at": ts(-45), "cve_id": "CVE-2024-999"},
    ])
    n += insert(con, "risk_score_history", [
        {"developer_id": "1", "risk_score": 18.0, "recorded_at": ts(-30)},
        {"developer_id": "1", "risk_score": 25.0, "recorded_at": ts(-1)},
    ])
    con.close()
    return n

def seed_enhanced_council():
    con = db("enhanced_council.db")
    n = insert(con, "enhanced_verdicts", [
        {"finding_json": json.dumps({"cve": "CVE-2024-1234", "cvss": 9.8}),
         "question": "Should we escalate this to P1?",
         "votes_json": json.dumps({"qwen": "yes", "mistral": "yes", "llama": "yes"}),
         "verdict": "yes", "confidence": 0.97, "agreement_pct": 100.0,
         "dissenting_json": json.dumps([]), "reasoning": "CVSS 9.8 + KEV confirmed + internet-facing",
         "created_at": ts(-2), "org_id": "default"},
    ])
    n += insert(con, "model_weights", [
        {"model_id": "qwen-3.6", "weight": 1.0, "updated_at": ts(-10)},
        {"model_id": "mistral-7b", "weight": 0.85, "updated_at": ts(-10)},
        {"model_id": "llama-3.1", "weight": 0.90, "updated_at": ts(-10)},
    ])
    con.close()
    return n

def seed_event_emitter():
    con = db("event_emitter.db")
    n = insert(con, "webhooks", [
        {"url": "https://hooks.slack.com/services/T123/B456/xyz", "event_types": json.dumps(["vulnerability.critical", "incident.created"]),
         "secret": "whsec_abc123", "status": "active", "created_at": ts(-30), "org_id": "default"},
        {"url": "https://api.pagerduty.com/v2/enqueue", "event_types": json.dumps(["incident.sla_breach"]),
         "secret": "whsec_def456", "status": "active", "created_at": ts(-20), "org_id": "default"},
    ])
    con.close()
    return n

def seed_feed_manager():
    con = db("feed_manager.db")
    n = insert(con, "feeds", [
        {"name": "NVD CVE Feed", "url": "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json",
         "type": "cve", "status": "active", "org_id": "default"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
         "type": "kev", "status": "active", "org_id": "default"},
        {"name": "AlienVault OTX", "url": "https://otx.alienvault.com/api/v1/pulses",
         "type": "threat_intel", "status": "active", "org_id": "default"},
    ])
    n += insert(con, "feed_refresh_log", [
        {"feed_id": "1", "refreshed_at": ts(-2), "success": 1, "ioc_count": 142},
        {"feed_id": "2", "refreshed_at": ts(-1), "success": 1, "ioc_count": 23},
        {"feed_id": "3", "refreshed_at": ts(-4), "success": 0, "ioc_count": 0},
    ])
    import hashlib
    n += insert(con, "iocs", [
        {"feed_id": "1", "type": "ip", "value": "185.220.101.45", "source_feed": "NVD CVE Feed",
         "first_seen": ts(-10), "last_seen": ts(-1), "dedup_hash": hashlib.sha256(b"ip:185.220.101.45").hexdigest(),
         "risk_score": 85.0, "org_id": "default"},
        {"feed_id": "2", "type": "domain", "value": "evil-c2.example.com", "source_feed": "CISA KEV",
         "first_seen": ts(-5), "last_seen": ts(), "dedup_hash": hashlib.sha256(b"domain:evil-c2.example.com").hexdigest(),
         "risk_score": 95.0, "org_id": "default"},
    ])
    con.close()
    return n

def seed_github_issues():
    con = db("github_issues.db")
    n = insert(con, "issue_links", [
        {"issue_number": 101, "repo": "acme/backend", "finding_id": "FIND-001",
         "created_at": ts(-10), "last_synced_at": ts(-1)},
        {"issue_number": 102, "repo": "acme/backend", "finding_id": "FIND-002",
         "created_at": ts(-5), "last_synced_at": ts()},
    ])
    n += insert(con, "sync_events", [
        {"finding_id": "FIND-001", "action": "created_issue", "success": 1, "occurred_at": ts(-10)},
        {"finding_id": "FIND-001", "action": "updated_issue", "success": 1, "occurred_at": ts(-5)},
        {"finding_id": "FIND-002", "action": "created_issue", "success": 1, "occurred_at": ts(-5)},
    ])
    n += insert(con, "issue_metrics", [
        {"issue_number": 101, "repo": "acme/backend", "status": "open", "age_days": 10, "created_at": ts(-10)},
        {"issue_number": 102, "repo": "acme/backend", "status": "open", "age_days": 5, "created_at": ts(-5)},
    ])
    con.close()
    return n

def seed_integrations():
    con = db("integrations.db")
    n = insert(con, "integrations", [
        {"name": "Jira Cloud", "integration_type": "ticketing", "status": "active",
         "config": json.dumps({"url": "https://acme.atlassian.net", "project": "SEC"}),
         "created_at": ts(-60), "updated_at": ts(-5), "org_id": "default"},
        {"name": "Slack", "integration_type": "notification", "status": "active",
         "config": json.dumps({"workspace": "acme", "channel": "#security-alerts"}),
         "created_at": ts(-45), "updated_at": ts(-3), "org_id": "default"},
        {"name": "Splunk SIEM", "integration_type": "siem", "status": "active",
         "config": json.dumps({"url": "https://splunk.acme.com:8089", "index": "security"}),
         "created_at": ts(-30), "updated_at": ts(-1), "org_id": "default"},
        {"name": "CrowdStrike", "integration_type": "edr", "status": "active",
         "config": json.dumps({"client_id": "cs_client_xxx"}),
         "created_at": ts(-20), "updated_at": ts(-2), "org_id": "default"},
    ])
    con.close()
    return n

def seed_ip_reputation():
    con = db("ip_reputation.db")
    n = insert(con, "ip_records", [
        {"ip_address": "185.220.101.45", "risk_score": 92.0, "categories": json.dumps(["tor", "botnet"]),
         "first_seen": ts(-30), "last_seen": ts(-1), "org_id": "default"},
        {"ip_address": "45.142.212.100", "risk_score": 78.0, "categories": json.dumps(["scanner"]),
         "first_seen": ts(-15), "last_seen": ts(), "org_id": "default"},
        {"ip_address": "10.0.0.5", "risk_score": 5.0, "categories": json.dumps(["internal"]),
         "first_seen": ts(-90), "last_seen": ts(), "org_id": "default"},
    ])
    n += insert(con, "ip_blocklist", [
        {"ip_address": "185.220.101.45", "reason": "Known Tor exit node + C2 traffic",
         "org_id": "default", "added_at": ts(-5), "added_by": "system"},
        {"ip_address": "45.142.212.100", "reason": "Active port scanner",
         "org_id": "default", "added_at": ts(-3), "added_by": "analyst@acme.com"},
    ])
    n += insert(con, "ip_history", [
        {"ip_address": "185.220.101.45", "org_id": "default", "event_type": "blocked", "recorded_at": ts(-5)},
        {"ip_address": "185.220.101.45", "org_id": "default", "event_type": "connection_attempt", "recorded_at": ts(-1)},
    ])
    con.close()
    return n

def seed_onboarding():
    con = db("onboarding.db")
    n = insert(con, "onboardings", [
        {"org_id": "default", "current_step": "integrations", "status": "in_progress",
         "steps": json.dumps(["org_setup", "user_invite", "integrations", "first_scan", "review"]),
         "started_at": ts(-7), "completed_at": None},
    ])
    n += insert(con, "step_configs", [
        {"org_id": "default", "step": "org_setup", "config": json.dumps({"completed": True, "skippable": False})},
        {"org_id": "default", "step": "user_invite", "config": json.dumps({"completed": True, "users_invited": 5})},
        {"org_id": "default", "step": "integrations", "config": json.dumps({"completed": False, "required": ["siem", "edr"]})},
    ])
    con.close()
    return n

def seed_report_schedules():
    con = db("report_schedules.db")
    n = insert(con, "schedules", [
        {"name": "Weekly Executive Summary", "report_type": "executive_summary",
         "frequency": "weekly", "status": "active", "recipients": json.dumps(["ciso@acme.com", "cto@acme.com"]),
         "created_at": ts(-30), "updated_at": ts(-1), "next_run_at": ts(7), "org_id": "default"},
        {"name": "Monthly Compliance Report", "report_type": "compliance",
         "frequency": "monthly", "status": "active", "recipients": json.dumps(["compliance@acme.com"]),
         "created_at": ts(-60), "updated_at": ts(-5), "next_run_at": ts(13), "org_id": "default"},
        {"name": "Daily Vuln Digest", "report_type": "vulnerability_digest",
         "frequency": "daily", "status": "active", "recipients": json.dumps(["vuln-team@acme.com"]),
         "created_at": ts(-10), "updated_at": ts(), "next_run_at": ts(1), "org_id": "default"},
    ])
    n += insert(con, "delivery_log", [
        {"schedule_id": "1", "report_type": "executive_summary", "delivered_at": ts(-7), "status": "delivered"},
        {"schedule_id": "2", "report_type": "compliance", "delivered_at": ts(-13), "status": "delivered"},
    ])
    con.close()
    return n

def seed_system_health():
    con = db("system_health.db")
    n = insert(con, "health_reports", [
        {"overall_status": "healthy", "subsystems_json": json.dumps({"api": "up", "db": "up", "cache": "up"}),
         "resources_json": json.dumps({"cpu": 34.2, "memory": 62.5, "disk": 41.0}),
         "uptime_seconds": 864000.0, "warnings_json": json.dumps([]), "checked_at": ts(-1)},
        {"overall_status": "degraded", "subsystems_json": json.dumps({"api": "up", "db": "up", "cache": "down"}),
         "resources_json": json.dumps({"cpu": 78.5, "memory": 89.2, "disk": 65.0}),
         "uptime_seconds": 950400.0, "warnings_json": json.dumps(["Cache unreachable"]), "checked_at": ts()},
    ])
    n += insert(con, "subsystem_history", [
        {"subsystem_name": "api", "status": "up", "response_ms": 12.3, "checked_at": ts(-1)},
        {"subsystem_name": "db", "status": "up", "response_ms": 3.1, "checked_at": ts(-1)},
        {"subsystem_name": "cache", "status": "up", "response_ms": 1.2, "checked_at": ts(-1)},
        {"subsystem_name": "cache", "status": "down", "response_ms": 5000.0, "checked_at": ts()},
    ])
    con.close()
    return n

def seed_vuln_prioritizer():
    con = db("vuln_prioritizer.db")
    n = insert(con, "epss_cache", [
        {"cve_id": "CVE-2024-1234", "epss": 0.87, "score_date": ts(-1), "fetched_at": ts(-1)},
        {"cve_id": "CVE-2024-5678", "epss": 0.42, "score_date": ts(-1), "fetched_at": ts(-1)},
        {"cve_id": "CVE-2024-9012", "epss": 0.12, "score_date": ts(-1), "fetched_at": ts(-1)},
    ])
    n += insert(con, "business_context", [
        {"asset_id": "api-server", "asset_name": "API Server", "criticality": 10,
         "internet_facing": 1, "data_sensitivity": "high", "updated_at": ts(-5)},
        {"asset_id": "db-primary", "asset_name": "Primary Database", "criticality": 10,
         "internet_facing": 0, "data_sensitivity": "critical", "updated_at": ts(-5)},
    ])
    n += insert(con, "prioritized_vulns", [
        {"finding_id": "FIND-001", "title": "SQL Injection in Login", "cve_id": "CVE-2024-1234",
         "asset_id": "api-server", "asset_name": "API Server", "priority_score": 9.8,
         "priority_label": "critical", "discovered_at": ts(-10), "last_prioritized": ts(-1)},
        {"finding_id": "FIND-002", "title": "XSS in Dashboard", "cve_id": "CVE-2024-5678",
         "asset_id": "frontend", "asset_name": "Frontend", "priority_score": 6.2,
         "priority_label": "high", "discovered_at": ts(-5), "last_prioritized": ts(-1)},
    ])
    n += insert(con, "vuln_groups", [
        {"group_type": "severity", "label": "critical", "count": 3, "created_at": ts(-1)},
        {"group_type": "asset_type", "label": "internet_facing", "count": 7, "created_at": ts(-1)},
    ])
    con.close()
    return n

def seed_webhook_dlq():
    con = db("webhook_dlq.db")
    n = insert(con, "webhook_deliveries", [
        {"webhook_id": "wh-001", "event_id": "evt-abc123", "payload": json.dumps({"event": "vulnerability.critical"}),
         "url": "https://hooks.slack.com/xxx", "status": "failed", "attempts": 3,
         "last_error": "connection timeout", "created_at": ts(-5), "org_id": "default"},
        {"webhook_id": "wh-002", "event_id": "evt-def456", "payload": json.dumps({"event": "incident.created"}),
         "url": "https://api.pagerduty.com/enqueue", "status": "pending",
         "attempts": 1, "last_error": None, "created_at": ts(-1), "org_id": "default"},
    ])
    con.close()
    return n

def seed_webhook_verifier():
    con = db("webhook_verifier.db")
    n = insert(con, "webhook_verification_log", [
        {"provider": "github", "valid": 1, "verified_at": ts(-3), "event_type": "push"},
        {"provider": "pagerduty", "valid": 1, "verified_at": ts(-2), "event_type": "alert"},
        {"provider": "slack", "valid": 0, "verified_at": ts(-1), "event_type": "slash_command"},
    ])
    con.close()
    return n

def main():
    total = 0
    seeders = [
        ("api_versioning", seed_api_versioning),
        ("audit_trail", seed_audit_trail),
        ("cicd_integration", seed_cicd_integration),
        ("cwpp", seed_cwpp),
        ("evidence_chain", seed_evidence_chain),
        ("evidence_collector", seed_evidence_collector),
        ("ir_playbook", seed_ir_playbook),
        ("metrics_aggregator", seed_metrics_aggregator),
        ("mpte", seed_mpte),
        ("network_analyzer", seed_network_analyzer),
        ("notifications", seed_notifications),
        ("policies", seed_policies),
        ("posture_advisor", seed_posture_advisor),
        ("sbom", seed_sbom),
        ("security_scorecard", seed_security_scorecard),
        ("sla_escalation", seed_sla_escalation),
        ("sla_tracking", seed_sla_tracking),
        ("threat_hunting", seed_threat_hunting),
        ("user_analytics", seed_user_analytics),
        ("vendor_risk", seed_vendor_risk),
        ("vendor_risk_engine", seed_vendor_risk_engine),
        ("vuln_risk_scores", seed_vuln_risk_scores),
        ("vulnerability_analytics", seed_vulnerability_analytics),
        ("workflow_engine", seed_workflow_engine),
        ("zero_trust", seed_zero_trust),
        ("zero_trust_engine", seed_zero_trust_engine),
        ("ai_orchestrator", seed_ai_orchestrator),
        ("anomaly_ml_engine", seed_anomaly_ml_engine),
        ("api_analytics", seed_api_analytics),
        ("auto_evidence", seed_auto_evidence),
        ("compliance_planner", seed_compliance_planner),
        ("dashboard_builder", seed_dashboard_builder),
        ("developer_profiles", seed_developer_profiles),
        ("enhanced_council", seed_enhanced_council),
        ("event_emitter", seed_event_emitter),
        ("feed_manager", seed_feed_manager),
        ("github_issues", seed_github_issues),
        ("integrations", seed_integrations),
        ("ip_reputation", seed_ip_reputation),
        ("onboarding", seed_onboarding),
        ("report_schedules", seed_report_schedules),
        ("system_health", seed_system_health),
        ("vuln_prioritizer", seed_vuln_prioritizer),
        ("webhook_dlq", seed_webhook_dlq),
        ("webhook_verifier", seed_webhook_verifier),
    ]

    for name, fn in seeders:
        try:
            n = fn()
            print(f"  [OK] {name}: {n} records")
            total += n
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")

    print(f"\n  Total records inserted: {total}")

    # Count remaining empty DBs
    from pathlib import Path
    DATA_DIR = Path("data")
    empty = []
    for db_path in sorted(DATA_DIR.glob("*.db")):
        con = sqlite3.connect(str(db_path))
        tables = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        total_rows = sum(con.execute(f"SELECT COUNT(*) FROM {t[0]}").fetchone()[0] for t in tables)
        con.close()
        if total_rows == 0:
            empty.append(db_path.name)

    print(f"\n  Still empty ({len(empty)}):")
    for e in sorted(empty):
        print(f"    - {e}")
    print(f"\n  Remaining empty DBs: {len(empty)}")

if __name__ == "__main__":
    main()
