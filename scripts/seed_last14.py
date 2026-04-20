#!/usr/bin/env python3
"""Seed the final 14 empty DBs using exact column schemas."""
import sqlite3, json, hashlib
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
    ph = ",".join("?" * len(cols))
    sql = f"INSERT OR IGNORE INTO {table} ({','.join(cols)}) VALUES ({ph})"
    count = 0
    for row in rows:
        try:
            con.execute(sql, [row[c] for c in cols])
            count += 1
        except Exception as e:
            print(f"    [warn] {table}: {e}")
    con.commit()
    return count

def seed_auto_evidence():
    con = db("auto_evidence.db")
    n = insert(con, "auto_evidence", [
        {"source": "aws_config", "control_id": "CC6.1", "framework": "SOC2",
         "content_hash": hashlib.sha256(b"mfa-policy").hexdigest(),
         "collected_at": ts(-5), "org_id": "default"},
        {"source": "github_actions", "control_id": "SA-11", "framework": "NIST800-53",
         "content_hash": hashlib.sha256(b"ci-scan").hexdigest(),
         "collected_at": ts(-3), "org_id": "default"},
        {"source": "crowdstrike", "control_id": "SI-2", "framework": "NIST800-53",
         "content_hash": hashlib.sha256(b"patch-status").hexdigest(),
         "collected_at": ts(-1), "org_id": "default"},
    ])
    con.close()
    return n

def seed_cicd_integration():
    con = db("cicd_integration.db")
    n = insert(con, "policies", [
        {"rules_json": json.dumps({"block_on": "critical", "notify_on": "high"}), "created_at": ts(-10)},
        {"rules_json": json.dumps({"block_on": "critical", "notify_on": "medium"}), "created_at": ts(-5)},
    ])
    n += insert(con, "scan_history", [
        {"repo": "github.com/acme/backend", "policy_action": "blocked", "scanned_at": ts(-2)},
        {"repo": "github.com/acme/frontend", "policy_action": "passed", "scanned_at": ts(-1)},
        {"repo": "github.com/acme/api", "policy_action": "warned", "scanned_at": ts()},
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
         "dissenting_json": json.dumps([]),
         "reasoning": "CVSS 9.8 + KEV confirmed + internet-facing asset",
         "created_at": ts(-2)},
        {"finding_json": json.dumps({"cve": "CVE-2024-5678", "cvss": 6.5}),
         "question": "Accept risk or remediate?",
         "votes_json": json.dumps({"qwen": "remediate", "mistral": "remediate", "llama": "accept"}),
         "verdict": "remediate", "confidence": 0.75, "agreement_pct": 66.7,
         "dissenting_json": json.dumps([{"model": "llama", "reason": "low exploitation probability"}]),
         "reasoning": "Majority recommends remediation within 7 days",
         "created_at": ts(-1)},
    ])
    n += insert(con, "model_weights", [
        {"model_name": "qwen-3.6", "weight": 1.0, "updated_at": ts(-10)},
        {"model_name": "mistral-7b", "weight": 0.85, "updated_at": ts(-10)},
        {"model_name": "llama-3.1", "weight": 0.90, "updated_at": ts(-10)},
    ])
    n += insert(con, "verdict_outcomes", [
        {"verdict_id": "1", "actual_outcome": "true_positive", "recorded_at": ts(-1)},
    ])
    con.close()
    return n

def seed_event_emitter():
    con = db("event_emitter.db")
    n = insert(con, "webhooks", [
        {"url": "https://hooks.slack.com/services/T123/B456/xyz",
         "event_types": json.dumps(["vulnerability.critical", "incident.created"]),
         "secret": "whsec_abc123", "created_at": ts(-30)},
        {"url": "https://api.pagerduty.com/v2/enqueue",
         "event_types": json.dumps(["incident.sla_breach"]),
         "secret": "whsec_def456", "created_at": ts(-20)},
        {"url": "https://hooks.example.com/security",
         "event_types": json.dumps(["compliance.failed"]),
         "secret": "whsec_ghi789", "created_at": ts(-10)},
    ])
    con.close()
    return n

def seed_integrations():
    con = db("integrations.db")
    n = insert(con, "integrations", [
        {"name": "Jira Cloud", "integration_type": "ticketing", "status": "active",
         "config": json.dumps({"url": "https://acme.atlassian.net", "project": "SEC"}),
         "created_at": ts(-60), "updated_at": ts(-5)},
        {"name": "Slack", "integration_type": "notification", "status": "active",
         "config": json.dumps({"workspace": "acme", "channel": "#security-alerts"}),
         "created_at": ts(-45), "updated_at": ts(-3)},
        {"name": "Splunk SIEM", "integration_type": "siem", "status": "active",
         "config": json.dumps({"url": "https://splunk.acme.com:8089", "index": "security"}),
         "created_at": ts(-30), "updated_at": ts(-1)},
        {"name": "CrowdStrike", "integration_type": "edr", "status": "active",
         "config": json.dumps({"client_id": "cs_client_xxx"}),
         "created_at": ts(-20), "updated_at": ts(-2)},
    ])
    con.close()
    return n

def seed_metrics_aggregator():
    con = db("metrics_aggregator.db")
    n = insert(con, "metrics_snapshots", [
        {"org_id": "default", "timestamp": ts(-2)},
        {"org_id": "default", "timestamp": ts(-1)},
        {"org_id": "default", "timestamp": ts()},
    ])
    con.close()
    return n

def seed_network_analyzer():
    con = db("network_analyzer.db")
    n = insert(con, "zones", [
        {"name": "DMZ", "type": "dmz", "cidrs": json.dumps(["10.0.1.0/24"]),
         "assets": json.dumps(["web-01", "lb-01"]), "trust_level": 2,
         "metadata": json.dumps({}), "created_at": ts(-30)},
        {"name": "Internal", "type": "internal", "cidrs": json.dumps(["10.0.0.0/16"]),
         "assets": json.dumps(["db-01", "app-01"]), "trust_level": 8,
         "metadata": json.dumps({}), "created_at": ts(-30)},
        {"name": "External", "type": "external", "cidrs": json.dumps(["0.0.0.0/0"]),
         "assets": json.dumps([]), "trust_level": 1,
         "metadata": json.dumps({}), "created_at": ts(-30)},
    ])
    n += insert(con, "flows", [
        {"source_zone": "External", "dest_zone": "DMZ",
         "ports": json.dumps([80, 443]), "protocol": "TCP", "direction": "inbound",
         "allowed": 1, "risk_score": 2.0, "metadata": json.dumps({}), "observed_at": ts(-1)},
        {"source_zone": "DMZ", "dest_zone": "Internal",
         "ports": json.dumps([5432]), "protocol": "TCP", "direction": "inbound",
         "allowed": 1, "risk_score": 4.5, "metadata": json.dumps({}), "observed_at": ts(-1)},
        {"source_zone": "External", "dest_zone": "Internal",
         "ports": json.dumps([22]), "protocol": "TCP", "direction": "inbound",
         "allowed": 0, "risk_score": 8.9, "metadata": json.dumps({}), "observed_at": ts()},
    ])
    n += insert(con, "violations", [
        {"flow_id": "3", "flow_json": json.dumps({"src": "External", "dst": "Internal", "port": 22}),
         "rule_violated": "no-direct-external-internal", "severity": "critical",
         "detected_at": ts(), "metadata": json.dumps({"blocked": True})},
    ])
    con.close()
    return n

def seed_policies():
    con = db("policies.db")
    n = insert(con, "policies", [
        {"name": "Acceptable Use Policy",
         "description": "Rules for acceptable use of IT resources",
         "policy_type": "acceptable_use", "status": "active",
         "rules": json.dumps(["No personal use of prod systems", "MFA required"]),
         "created_at": ts(-180), "updated_at": ts(-30)},
        {"name": "Vulnerability Management Policy",
         "description": "SLA for vulnerability remediation",
         "policy_type": "security", "status": "active",
         "rules": json.dumps(["Critical: 24h", "High: 7d", "Medium: 30d"]),
         "created_at": ts(-90), "updated_at": ts(-10)},
        {"name": "Data Retention Policy",
         "description": "Data retention and deletion requirements",
         "policy_type": "data_governance", "status": "active",
         "rules": json.dumps(["PII: 2 years max", "Logs: 1 year", "Backups: 90 days"]),
         "created_at": ts(-120), "updated_at": ts(-15)},
        {"name": "Incident Response Policy",
         "description": "Mandatory IR procedures for all security incidents",
         "policy_type": "incident_response", "status": "active",
         "rules": json.dumps(["P1: 15min response", "P2: 1h response", "Post-mortem required"]),
         "created_at": ts(-60), "updated_at": ts(-7)},
    ])
    con.close()
    return n

def seed_security_scorecard():
    con = db("security_scorecard.db")
    n = insert(con, "scorecards", [
        {"org_id": "default", "overall_score": 82.4, "grade": "B",
         "generated_at": ts(-7), "valid_until": ts(23)},
        {"org_id": "default", "overall_score": 85.1, "grade": "B+",
         "generated_at": ts(), "valid_until": ts(30)},
    ])
    con.close()
    return n

def seed_threat_hunting():
    con = db("threat_hunting.db")
    n = insert(con, "hunt_queries", [
        {"name": "Lateral Movement via SMB", "category": "lateral_movement",
         "query_logic": json.dumps({"filter": "event_type=smb_access", "threshold": 10})},
        {"name": "Suspicious PowerShell Execution", "category": "execution",
         "query_logic": json.dumps({"filter": "process=powershell.exe AND cmdline LIKE '-enc%'"})},
        {"name": "Data Exfiltration to External IPs", "category": "exfiltration",
         "query_logic": json.dumps({"filter": "bytes_out>1000000 AND dest_external=true"})},
    ])
    n += insert(con, "hunts", [
        {"org_id": "default", "name": "Q1 APT Hunt", "hunt_type": "hypothesis",
         "created_at": ts(-30), "updated_at": ts(-20)},
        {"org_id": "default", "name": "Ransomware Precursor Hunt", "hunt_type": "ioc",
         "created_at": ts(-5), "updated_at": ts(-1)},
    ])
    n += insert(con, "hunt_sessions", [
        {"name": "APT Hunt Session 1", "hunter_email": "hunter@acme.com",
         "started_at": ts(-30)},
        {"name": "Ransomware Hunt Session 1", "hunter_email": "hunter@acme.com",
         "started_at": ts(-5)},
    ])
    n += insert(con, "hunt_results", [
        {"hunt_id": "1", "detected_at": ts(-25)},
        {"hunt_id": "2", "detected_at": ts(-3)},
    ])
    con.close()
    return n

def seed_user_analytics():
    con = db("user_analytics.db")
    n = insert(con, "activities", [
        {"user_email": "admin@acme.com", "activity_type": "login",
         "timestamp": ts(-2), "org_id": "default"},
        {"user_email": "analyst@acme.com", "activity_type": "report_view",
         "timestamp": ts(-1), "org_id": "default"},
        {"user_email": "admin@acme.com", "activity_type": "policy_change",
         "timestamp": ts(), "org_id": "default"},
        {"user_email": "soc@acme.com", "activity_type": "alert_ack",
         "timestamp": ts(), "org_id": "default"},
        {"user_email": "vuln@acme.com", "activity_type": "finding_resolve",
         "timestamp": ts(), "org_id": "default"},
    ])
    con.close()
    return n

def seed_webhook_verifier():
    con = db("webhook_verifier.db")
    n = insert(con, "webhook_verification_log", [
        {"provider": "github", "valid": 1, "verified_at": ts(-3)},
        {"provider": "pagerduty", "valid": 1, "verified_at": ts(-2)},
        {"provider": "slack", "valid": 0, "verified_at": ts(-1)},
        {"provider": "jira", "valid": 1, "verified_at": ts()},
    ])
    con.close()
    return n

def seed_zero_trust_engine():
    con = db("zero_trust_engine.db")
    n = insert(con, "policies", [
        {"resource": "/api/admin/*",
         "rules": json.dumps([{"condition": "role==admin", "decision": "MFA_REQUIRED"}]),
         "default_decision": "DENY", "created_at": ts(-30), "updated_at": ts(-5)},
        {"resource": "/api/reports/*",
         "rules": json.dumps([{"condition": "role in [analyst,admin]", "decision": "ALLOW"}]),
         "default_decision": "DENY", "created_at": ts(-20), "updated_at": ts(-2)},
        {"resource": "/api/public/*",
         "rules": json.dumps([{"condition": "authenticated==true", "decision": "ALLOW"}]),
         "default_decision": "DENY", "created_at": ts(-10), "updated_at": ts(-1)},
    ])
    n += insert(con, "entity_trust", [
        {"entity_id": "admin@acme.com", "entity_type": "user", "trust_score": 0.92,
         "factors": json.dumps({"mfa": True, "device_compliant": True, "location": "known"}),
         "updated_at": ts(-1)},
        {"entity_id": "analyst@acme.com", "entity_type": "user", "trust_score": 0.78,
         "factors": json.dumps({"mfa": True, "device_compliant": True, "location": "known"}),
         "updated_at": ts()},
        {"entity_id": "device-mbp-01", "entity_type": "device", "trust_score": 0.95,
         "factors": json.dumps({"managed": True, "compliant": True, "encrypted": True}),
         "updated_at": ts()},
    ])
    n += insert(con, "access_log", [
        {"user_id": "admin@acme.com", "device_id": "device-mbp-01",
         "resource": "/api/admin/users", "action": "GET",
         "decision": "ALLOW", "trust_score": 0.92, "evaluated_at": ts(-1)},
        {"user_id": "analyst@acme.com", "device_id": "device-win-02",
         "resource": "/api/reports/summary", "action": "GET",
         "decision": "ALLOW", "trust_score": 0.78, "evaluated_at": ts()},
        {"user_id": "guest@external.com", "device_id": "device-unknown",
         "resource": "/api/admin/config", "action": "POST",
         "decision": "DENY", "trust_score": 0.12, "evaluated_at": ts()},
    ])
    con.close()
    return n

def main():
    seeders = [
        ("auto_evidence", seed_auto_evidence),
        ("cicd_integration", seed_cicd_integration),
        ("enhanced_council", seed_enhanced_council),
        ("event_emitter", seed_event_emitter),
        ("integrations", seed_integrations),
        ("metrics_aggregator", seed_metrics_aggregator),
        ("network_analyzer", seed_network_analyzer),
        ("policies", seed_policies),
        ("security_scorecard", seed_security_scorecard),
        ("threat_hunting", seed_threat_hunting),
        ("user_analytics", seed_user_analytics),
        ("webhook_verifier", seed_webhook_verifier),
        ("zero_trust_engine", seed_zero_trust_engine),
    ]

    total = 0
    for name, fn in seeders:
        try:
            n = fn()
            print(f"  [OK] {name}: {n} records")
            total += n
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")

    print(f"\n  Total records inserted: {total}")

    # Count remaining empty DBs
    empty = []
    for db_path in sorted(Path("data").glob("*.db")):
        con = sqlite3.connect(str(db_path))
        tables = con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        row_count = sum(con.execute(f"SELECT COUNT(*) FROM {t[0]}").fetchone()[0] for t in tables)
        con.close()
        if row_count == 0:
            empty.append(db_path.name)

    print(f"\n  Still empty ({len(empty)}):")
    for e in sorted(empty):
        print(f"    - {e}")

if __name__ == "__main__":
    main()
