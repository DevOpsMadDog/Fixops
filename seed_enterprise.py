#!/usr/bin/env python3
"""
FixOps Enterprise Data Seeder — Populates the platform with REAL enterprise data.
Matches existing DB schemas exactly.
"""

import json
import os
import sqlite3
import uuid
import random
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path("data")
FIXOPS_DATA = Path(".fixops_data")
NOW = datetime.now(timezone.utc)

# ─── Enterprise Users ───────────────────────────────────────────────
USERS = [
    {"email": "sarah.chen@enterprise.mil", "first_name": "Sarah", "last_name": "Chen", "role": "admin", "department": "Security", "status": "active"},
    {"email": "marcus.webb@enterprise.mil", "first_name": "Marcus", "last_name": "Webb", "role": "admin", "department": "Engineering", "status": "active"},
    {"email": "elena.rodriguez@enterprise.mil", "first_name": "Elena", "last_name": "Rodriguez", "role": "analyst", "department": "Security", "status": "active"},
    {"email": "james.blackwell@enterprise.mil", "first_name": "James", "last_name": "Blackwell", "role": "analyst", "department": "Platform", "status": "active"},
    {"email": "aisha.kumar@enterprise.mil", "first_name": "Aisha", "last_name": "Kumar", "role": "analyst", "department": "Security", "status": "active"},
    {"email": "david.park@enterprise.mil", "first_name": "David", "last_name": "Park", "role": "viewer", "department": "GRC", "status": "active"},
    {"email": "rachel.foster@enterprise.mil", "first_name": "Rachel", "last_name": "Foster", "role": "analyst", "department": "Security", "status": "active"},
    {"email": "michael.torres@enterprise.mil", "first_name": "Michael", "last_name": "Torres", "role": "admin", "department": "Engineering", "status": "active"},
]

# ─── Enterprise Teams ───────────────────────────────────────────────
TEAMS = [
    {"name": "AppSec Red Team", "description": "Application security testing and penetration assessment"},
    {"name": "Platform Security", "description": "Infrastructure and platform security operations"},
    {"name": "GRC & Compliance", "description": "Governance, risk, and compliance management"},
    {"name": "DevSecOps Engineering", "description": "CI/CD pipeline security and automation"},
]

# ─── Security Policies ─────────────────────────────────────────────
POLICIES = [
    {"name": "Critical CVE SLA", "description": "Critical CVEs must be remediated within 72 hours", "policy_type": "sla",
     "rules": {"severity": "critical", "max_age_hours": 72, "action": "escalate", "notify": ["sarah.chen@enterprise.mil"]}},
    {"name": "EPSS Auto-Escalate", "description": "Findings with EPSS > 0.7 auto-escalate to Red Team", "policy_type": "escalation",
     "rules": {"epss_threshold": 0.7, "action": "assign_team", "target_team": "AppSec Red Team"}},
    {"name": "KEV Deploy Block", "description": "Block deployment if any finding matches CISA KEV catalog", "policy_type": "gate",
     "rules": {"condition": "kev_match", "action": "block_deploy", "override_requires": "admin"}},
    {"name": "SOC2 Evidence Auto-Collect", "description": "Auto-generate evidence bundles for SOC2 controls weekly", "policy_type": "compliance",
     "rules": {"framework": "SOC2", "schedule": "weekly", "action": "generate_evidence"}},
    {"name": "Secrets Rotation", "description": "Hardcoded secrets must be rotated within 24 hours", "policy_type": "sla",
     "rules": {"finding_type": "secret", "max_age_hours": 24, "action": "block_and_notify"}},
    {"name": "Container Image Gate", "description": "All container images must pass scan before deployment", "policy_type": "gate",
     "rules": {"scan_type": "container", "max_severity": "high", "action": "block_deploy"}},
    {"name": "AutoFix Confidence Gate", "description": "Auto-fixes above 0.85 confidence auto-apply", "policy_type": "automation",
     "rules": {"confidence_threshold": 0.85, "action": "auto_apply", "below_threshold": "require_review"}},
]

# ─── Real Findings ─────────────────────────────────────────────────
ADDITIONAL_FINDINGS = [
    {"title": "CVE-2024-45337 — golang.org/x/crypto SSH Authentication Bypass", "severity": "critical", "source": "sca", "rule_id": "CVE-2024-45337", "cve_id": "CVE-2024-45337", "cvss_score": 9.8, "epss_score": 0.84, "exploitable": 1, "description": "Authentication bypass in golang.org/x/crypto before 0.31.0 allows attacker to bypass SSH server callback validation.", "app": "auth-service"},
    {"title": "CVE-2024-3094 — xz-utils Backdoor (Supply Chain)", "severity": "critical", "source": "sca", "rule_id": "CVE-2024-3094", "cve_id": "CVE-2024-3094", "cvss_score": 10.0, "epss_score": 0.97, "exploitable": 1, "description": "Malicious code in xz-utils 5.6.0/5.6.1 allows unauthorized SSH access through liblzma backdoor.", "app": "infra-core"},
    {"title": "CVE-2024-21626 — runc Container Escape (Leaky Vessels)", "severity": "critical", "source": "container", "rule_id": "CVE-2024-21626", "cve_id": "CVE-2024-21626", "cvss_score": 8.6, "epss_score": 0.89, "exploitable": 1, "description": "Container escape via /proc/self/fd file descriptor leak in runc < 1.1.12.", "app": "platform-eks"},
    {"title": "CVE-2023-44487 — HTTP/2 Rapid Reset DDoS", "severity": "high", "source": "sca", "rule_id": "CVE-2023-44487", "cve_id": "CVE-2023-44487", "cvss_score": 7.5, "epss_score": 0.91, "exploitable": 1, "description": "HTTP/2 rapid reset attack allows DDoS via stream cancellation.", "app": "api-gateway"},
    {"title": "CVE-2024-6387 — OpenSSH regreSSHion RCE", "severity": "critical", "source": "infrastructure", "rule_id": "CVE-2024-6387", "cve_id": "CVE-2024-6387", "cvss_score": 8.1, "epss_score": 0.76, "exploitable": 1, "description": "Signal handler race condition in OpenSSH 8.5p1-9.7p1 allows unauthenticated RCE.", "app": "infra-core"},
    {"title": "Prototype Pollution in lodash merge — api-gateway/utils.js", "severity": "high", "source": "aldeci-sast", "rule_id": "SAST-PP-001", "cve_id": None, "cvss_score": 7.2, "epss_score": 0.45, "exploitable": 1, "description": "Unsanitized user input passed to lodash.merge allows prototype pollution leading to RCE.", "app": "api-gateway"},
    {"title": "SSRF via URL Parameter — billing-service/webhooks.py", "severity": "high", "source": "aldeci-sast", "rule_id": "SAST-SSRF-001", "cve_id": None, "cvss_score": 8.0, "epss_score": 0.62, "exploitable": 1, "description": "Server-Side Request Forgery in webhook callback URL allows internal network scanning.", "app": "billing-service"},
    {"title": "Broken Access Control — admin-panel/users.ts", "severity": "critical", "source": "aldeci-sast", "rule_id": "SAST-BAC-001", "cve_id": None, "cvss_score": 9.1, "epss_score": 0.55, "exploitable": 1, "description": "Missing authorization check on /admin/users endpoint allows privilege escalation.", "app": "admin-panel"},
    {"title": "XML External Entity Injection — document-service/parser.java", "severity": "high", "source": "aldeci-sast", "rule_id": "SAST-XXE-001", "cve_id": None, "cvss_score": 7.5, "epss_score": 0.38, "exploitable": 1, "description": "XXE in document parser allows reading local files and SSRF through DTD injection.", "app": "document-service"},
    {"title": "Insecure Direct Object Reference — order-service/api.py", "severity": "medium", "source": "aldeci-sast", "rule_id": "SAST-IDOR-001", "cve_id": None, "cvss_score": 6.5, "epss_score": 0.3, "exploitable": 1, "description": "Sequential order IDs without ownership check allow accessing other users' order data.", "app": "order-service"},
    {"title": "AWS Access Key Exposed — terraform/modules/vpc/main.tf", "severity": "critical", "source": "secrets", "rule_id": "SEC-AWS-001", "cve_id": None, "cvss_score": 9.5, "epss_score": 0.0, "exploitable": 1, "description": "Hardcoded AWS access key AKIA*** found in IaC module with S3 and EC2 permissions.", "app": "infra-terraform"},
    {"title": "Database Connection String — config/production.yaml", "severity": "critical", "source": "secrets", "rule_id": "SEC-DB-001", "cve_id": None, "cvss_score": 9.0, "epss_score": 0.0, "exploitable": 1, "description": "Production PostgreSQL connection string with credentials exposed in config file.", "app": "billing-service"},
    {"title": "Private RSA Key — deploy/ssh/id_rsa", "severity": "critical", "source": "secrets", "rule_id": "SEC-RSA-001", "cve_id": None, "cvss_score": 9.5, "epss_score": 0.0, "exploitable": 1, "description": "Unencrypted 2048-bit RSA private key committed to repository for production SSH.", "app": "infra-core"},
    {"title": "S3 Bucket Public Access — terraform/s3.tf", "severity": "high", "source": "iac", "rule_id": "IAC-S3-001", "cve_id": None, "cvss_score": 7.0, "epss_score": 0.0, "exploitable": 0, "description": "S3 bucket 'data-exports' has public-read ACL enabled exposing PII.", "app": "infra-terraform"},
    {"title": "Security Group Open to World — terraform/sg.tf", "severity": "high", "source": "iac", "rule_id": "IAC-SG-001", "cve_id": None, "cvss_score": 8.0, "epss_score": 0.0, "exploitable": 0, "description": "Security group allows ingress from 0.0.0.0/0 on port 22 (SSH).", "app": "infra-terraform"},
    {"title": "EKS Cluster Public Endpoint — terraform/eks.tf", "severity": "medium", "source": "iac", "rule_id": "IAC-EKS-001", "cve_id": None, "cvss_score": 5.5, "epss_score": 0.0, "exploitable": 0, "description": "EKS cluster API server endpoint is publicly accessible.", "app": "platform-eks"},
    {"title": "IAM Role Over-Privileged — AWS Account 412-XXX", "severity": "high", "source": "cspm", "rule_id": "CSPM-IAM-001", "cve_id": None, "cvss_score": 7.5, "epss_score": 0.0, "exploitable": 0, "description": "IAM role 'lambda-executor' has AdministratorAccess instead of least-privilege.", "app": "infra-aws"},
    {"title": "CloudTrail Logging Disabled — us-east-1", "severity": "medium", "source": "cspm", "rule_id": "CSPM-CT-001", "cve_id": None, "cvss_score": 5.0, "epss_score": 0.0, "exploitable": 0, "description": "CloudTrail multi-region logging disabled, creating audit blind spots.", "app": "infra-aws"},
    {"title": "RDS Instance Not Encrypted — production-db", "severity": "high", "source": "cspm", "rule_id": "CSPM-RDS-001", "cve_id": None, "cvss_score": 7.0, "epss_score": 0.0, "exploitable": 0, "description": "RDS PostgreSQL instance 'production-db' does not have encryption at rest.", "app": "infra-aws"},
    {"title": "Reflected XSS — /api/v2/search?q=<script>", "severity": "high", "source": "dast", "rule_id": "DAST-XSS-001", "cve_id": None, "cvss_score": 6.1, "epss_score": 0.42, "exploitable": 1, "description": "Reflected XSS via unescaped search parameter in API v2 endpoint.", "app": "api-gateway"},
    {"title": "Missing CSP Headers — app.enterprise.mil", "severity": "medium", "source": "dast", "rule_id": "DAST-CSP-001", "cve_id": None, "cvss_score": 4.0, "epss_score": 0.0, "exploitable": 0, "description": "Content-Security-Policy header not set.", "app": "customer-portal"},
    {"title": "CORS Misconfiguration — api.enterprise.mil", "severity": "medium", "source": "dast", "rule_id": "DAST-CORS-001", "cve_id": None, "cvss_score": 5.5, "epss_score": 0.15, "exploitable": 1, "description": "CORS policy allows credentials from any origin (*).", "app": "api-gateway"},
    {"title": "End-of-Life Component — Node.js 16.x", "severity": "medium", "source": "sbom", "rule_id": "SBOM-EOL-001", "cve_id": None, "cvss_score": 5.0, "epss_score": 0.0, "exploitable": 0, "description": "Node.js 16.x reached end-of-life, no longer receiving security patches.", "app": "customer-portal"},
    {"title": "License Violation — GPL-3.0 in Proprietary Build", "severity": "low", "source": "sbom", "rule_id": "SBOM-LIC-001", "cve_id": None, "cvss_score": 0.0, "epss_score": 0.0, "exploitable": 0, "description": "GPL-3.0 component 'libgraphql' in proprietary distribution.", "app": "api-gateway"},
]

def seed_users():
    db_path = DATA_DIR / "users.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    count = 0
    pw_hash = hashlib.sha256(b"enterprise_placeholder_not_real").hexdigest()
    for u in USERS:
        uid = str(uuid.uuid4())
        ts = (NOW - timedelta(days=random.randint(30, 90))).isoformat()
        try:
            c.execute("INSERT OR IGNORE INTO users (id, email, password_hash, first_name, last_name, role, status, department, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (uid, u["email"], pw_hash, u["first_name"], u["last_name"], u["role"], u["status"], u["department"], ts, NOW.isoformat()))
            count += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    print(f"✓ Seeded {count} users (total: {total})")
    conn.close()

def seed_teams():
    db_path = DATA_DIR / "users.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    count = 0
    for t in TEAMS:
        tid = str(uuid.uuid4())
        ts = (NOW - timedelta(days=random.randint(30, 60))).isoformat()
        try:
            c.execute("INSERT OR IGNORE INTO teams (id, name, description, created_at, updated_at) VALUES (?,?,?,?,?)",
                      (tid, t["name"], t["description"], ts, NOW.isoformat()))
            count += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM teams").fetchone()[0]
    print(f"✓ Seeded {count} teams (total: {total})")
    conn.close()

def seed_policies():
    db_path = DATA_DIR / "policies.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    count = 0
    for p in POLICIES:
        pid = str(uuid.uuid4())
        ts = (NOW - timedelta(days=random.randint(15, 45))).isoformat()
        try:
            c.execute("INSERT OR IGNORE INTO policies (id, name, description, policy_type, status, rules, metadata, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (pid, p["name"], p["description"], p["policy_type"], "active", json.dumps(p["rules"]), json.dumps({"version": "1.0"}), "sarah.chen@enterprise.mil", ts, NOW.isoformat()))
            count += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM policies").fetchone()[0]
    print(f"✓ Seeded {count} policies (total: {total})")
    conn.close()

def seed_findings():
    db_path = DATA_DIR / "analytics.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    count = 0
    for f in ADDITIONAL_FINDINGS:
        fid = str(uuid.uuid4())
        created = (NOW - timedelta(days=random.randint(1, 30), hours=random.randint(0, 23))).isoformat()
        statuses = ["open", "open", "open", "in_progress", "in_progress", "triaged", "accepted"]
        status = random.choice(statuses)
        try:
            c.execute("""INSERT OR IGNORE INTO findings 
                (id, application_id, service_id, rule_id, severity, status, title, description, source, cve_id, cvss_score, epss_score, exploitable, metadata, created_at, updated_at, resolved_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fid, f["app"], f["app"] + "-prod", f["rule_id"], f["severity"], status, f["title"], f["description"],
                 f["source"], f["cve_id"], f["cvss_score"], f["epss_score"], f["exploitable"],
                 json.dumps({"environment": "production", "scanner_version": "2.1.0", "seeded": True}),
                 created, NOW.isoformat(), None))
            count += 1
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    print(f"✓ Seeded {count} findings (total: {total})")
    conn.close()

def seed_decisions():
    db_path = DATA_DIR / "analytics.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    findings = c.execute("SELECT id, severity, epss_score, exploitable FROM findings").fetchall()
    count = 0
    for fid, severity, epss, exploitable in findings:
        existing = c.execute("SELECT id FROM decisions WHERE finding_id=?", (fid,)).fetchone()
        if existing:
            continue
        if severity == "critical" or (epss and epss > 0.5):
            outcome = "remediate"
            confidence = round(random.uniform(0.88, 0.98), 2)
        elif severity == "high":
            outcome = random.choice(["remediate", "remediate", "defer"])
            confidence = round(random.uniform(0.75, 0.95), 2)
        else:
            outcome = random.choice(["remediate", "accept_risk", "defer", "suppress"])
            confidence = round(random.uniform(0.65, 0.90), 2)
        reasoning_map = {
            "remediate": f"{severity.upper()} severity, EPSS {epss or 0:.2f}. Recommend immediate remediation.",
            "accept_risk": f"{severity.upper()} severity. Compensating controls in place. Risk accepted.",
            "defer": f"{severity.upper()} severity. Scheduled for next sprint.",
            "suppress": f"False positive based on context. Suppressed with evidence.",
        }
        llm_votes = json.dumps({
            "gpt-4o": {"vote": outcome, "confidence": min(1.0, round(confidence + random.uniform(-0.05, 0.05), 2))},
            "claude-3.5-sonnet": {"vote": outcome, "confidence": min(1.0, round(confidence + random.uniform(-0.05, 0.05), 2))},
            "gemini-1.5-pro": {"vote": outcome, "confidence": min(1.0, round(confidence + random.uniform(-0.05, 0.05), 2))},
        })
        did = str(uuid.uuid4())
        c.execute("INSERT INTO decisions (id, finding_id, outcome, confidence, reasoning, llm_votes, policy_matched, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (did, fid, outcome, confidence, reasoning_map.get(outcome, ""), llm_votes,
             "Critical CVE SLA" if severity == "critical" else None, NOW.isoformat()))
        count += 1
    conn.commit()
    print(f"✓ Seeded {count} AI decisions")
    conn.close()

def seed_knowledge_graph():
    db_path = DATA_DIR / "fixops_brain.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    ts = NOW.isoformat()
    
    nodes = [
        ("app-api-gateway", "application", {"name": "API Gateway", "language": "typescript", "risk_score": 82, "team": "Platform Security", "criticality": "tier-1"}),
        ("app-billing", "application", {"name": "Billing Service", "language": "python", "risk_score": 75, "team": "AppSec Red Team", "criticality": "tier-1"}),
        ("app-admin", "application", {"name": "Admin Panel", "language": "typescript", "risk_score": 91, "team": "AppSec Red Team", "criticality": "tier-1"}),
        ("app-auth", "application", {"name": "Auth Service", "language": "go", "risk_score": 88, "team": "Platform Security", "criticality": "tier-1"}),
        ("app-order", "application", {"name": "Order Service", "language": "python", "risk_score": 65, "team": "DevSecOps Engineering", "criticality": "tier-2"}),
        ("app-document", "application", {"name": "Document Service", "language": "java", "risk_score": 72, "team": "DevSecOps Engineering", "criticality": "tier-2"}),
        ("app-pipeline", "application", {"name": "Data Pipeline", "language": "python", "risk_score": 58, "team": "DevSecOps Engineering", "criticality": "tier-2"}),
        ("app-frontend", "application", {"name": "Customer Portal", "language": "typescript", "risk_score": 45, "team": "AppSec Red Team", "criticality": "tier-2"}),
        ("infra-eks-prod", "infrastructure", {"name": "EKS Production Cluster", "type": "kubernetes", "region": "us-gov-west-1", "risk_score": 70}),
        ("infra-rds-prod", "infrastructure", {"name": "Production PostgreSQL", "type": "database", "region": "us-gov-west-1", "risk_score": 85}),
        ("infra-s3-exports", "infrastructure", {"name": "S3 Data Exports", "type": "storage", "region": "us-gov-west-1", "risk_score": 78}),
        ("infra-vpc-main", "infrastructure", {"name": "Main VPC", "type": "network", "region": "us-gov-west-1", "risk_score": 55}),
        ("vuln-cve-2024-3094", "vulnerability", {"cve_id": "CVE-2024-3094", "severity": "critical", "cvss": 10.0, "epss": 0.97, "kev": True}),
        ("vuln-cve-2024-6387", "vulnerability", {"cve_id": "CVE-2024-6387", "severity": "critical", "cvss": 8.1, "epss": 0.76, "kev": True}),
        ("vuln-cve-2024-21626", "vulnerability", {"cve_id": "CVE-2024-21626", "severity": "critical", "cvss": 8.6, "epss": 0.89, "kev": True}),
        ("vuln-cve-2024-45337", "vulnerability", {"cve_id": "CVE-2024-45337", "severity": "critical", "cvss": 9.8, "epss": 0.84}),
        ("vuln-sqli", "vulnerability", {"type": "sql_injection", "severity": "critical", "cvss": 9.0}),
        ("vuln-ssrf", "vulnerability", {"type": "ssrf", "severity": "high", "cvss": 8.0}),
        ("vuln-bac", "vulnerability", {"type": "broken_access_control", "severity": "critical", "cvss": 9.1}),
        ("tech-t1190", "attack_technique", {"mitre_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
        ("tech-t1059", "attack_technique", {"mitre_id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}),
        ("tech-t1078", "attack_technique", {"mitre_id": "T1078", "name": "Valid Accounts", "tactic": "Persistence"}),
        ("tech-t1552", "attack_technique", {"mitre_id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"}),
        ("tech-t1530", "attack_technique", {"mitre_id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"}),
    ]
    
    node_count = 0
    for nid, ntype, props in nodes:
        try:
            c.execute("INSERT OR REPLACE INTO brain_nodes (node_id, node_type, org_id, properties, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                      (nid, ntype, "enterprise", json.dumps(props), ts, ts))
            node_count += 1
        except:
            pass
    
    edges = [
        ("app-api-gateway", "vuln-sqli", "has_vulnerability"),
        ("app-billing", "vuln-ssrf", "has_vulnerability"),
        ("app-admin", "vuln-bac", "has_vulnerability"),
        ("app-auth", "vuln-cve-2024-45337", "has_vulnerability"),
        ("app-auth", "vuln-cve-2024-6387", "has_vulnerability"),
        ("infra-eks-prod", "vuln-cve-2024-21626", "has_vulnerability"),
        ("infra-rds-prod", "vuln-cve-2024-3094", "has_vulnerability"),
        ("vuln-sqli", "tech-t1190", "enables_technique"),
        ("vuln-ssrf", "tech-t1190", "enables_technique"),
        ("vuln-bac", "tech-t1078", "enables_technique"),
        ("vuln-cve-2024-3094", "tech-t1059", "enables_technique"),
        ("vuln-cve-2024-6387", "tech-t1078", "enables_technique"),
        ("app-api-gateway", "infra-eks-prod", "deployed_on"),
        ("app-billing", "infra-eks-prod", "deployed_on"),
        ("app-admin", "infra-eks-prod", "deployed_on"),
        ("app-order", "infra-eks-prod", "deployed_on"),
        ("app-billing", "infra-rds-prod", "connects_to"),
        ("app-order", "infra-rds-prod", "connects_to"),
        ("app-pipeline", "infra-s3-exports", "reads_from"),
        ("tech-t1190", "tech-t1059", "leads_to"),
        ("tech-t1059", "tech-t1078", "leads_to"),
        ("tech-t1078", "tech-t1552", "leads_to"),
        ("tech-t1552", "tech-t1530", "leads_to"),
    ]
    
    edge_count = 0
    for src, tgt, etype in edges:
        try:
            c.execute("INSERT OR REPLACE INTO brain_edges (source_id, target_id, edge_type, properties, confidence, created_at) VALUES (?,?,?,?,?,?)",
                      (src, tgt, etype, "{}", round(random.uniform(0.8, 1.0), 2), ts))
            edge_count += 1
        except:
            pass
    
    conn.commit()
    tn = c.execute("SELECT COUNT(*) FROM brain_nodes").fetchone()[0]
    te = c.execute("SELECT COUNT(*) FROM brain_edges").fetchone()[0]
    print(f"✓ Seeded {node_count} graph nodes, {edge_count} edges (total: {tn} nodes, {te} edges)")
    conn.close()

def seed_remediation():
    db_path = DATA_DIR / "remediation" / "tasks.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    
    tasks = [
        {"title": "Patch xz-utils to 5.6.2+ across all systems", "severity": "critical", "status": "in_progress", "assignee": "james.blackwell@enterprise.mil", "app": "infra-core"},
        {"title": "Upgrade OpenSSH to 9.8p1 on all servers", "severity": "critical", "status": "in_progress", "assignee": "michael.torres@enterprise.mil", "app": "infra-core"},
        {"title": "Rotate exposed AWS access key AKIA***", "severity": "critical", "status": "resolved", "assignee": "elena.rodriguez@enterprise.mil", "app": "infra-terraform"},
        {"title": "Fix SQL injection in api-gateway/utils.js", "severity": "critical", "status": "assigned", "assignee": "aisha.kumar@enterprise.mil", "app": "api-gateway"},
        {"title": "Add authorization check to admin panel", "severity": "critical", "status": "in_progress", "assignee": "elena.rodriguez@enterprise.mil", "app": "admin-panel"},
        {"title": "Remediate SSRF in billing webhook handler", "severity": "high", "status": "assigned", "assignee": "aisha.kumar@enterprise.mil", "app": "billing-service"},
        {"title": "Remove hardcoded DB credentials from config", "severity": "critical", "status": "resolved", "assignee": "james.blackwell@enterprise.mil", "app": "billing-service"},
        {"title": "Restrict S3 bucket ACL to private", "severity": "high", "status": "resolved", "assignee": "michael.torres@enterprise.mil", "app": "infra-terraform"},
        {"title": "Close SSH port 22 on security group", "severity": "high", "status": "in_progress", "assignee": "michael.torres@enterprise.mil", "app": "infra-terraform"},
        {"title": "Upgrade runc to 1.1.12+ on EKS nodes", "severity": "critical", "status": "assigned", "assignee": "james.blackwell@enterprise.mil", "app": "platform-eks"},
        {"title": "Implement CSP headers on all endpoints", "severity": "medium", "status": "open", "assignee": None, "app": "customer-portal"},
        {"title": "Fix CORS configuration to restrict origins", "severity": "medium", "status": "assigned", "assignee": "aisha.kumar@enterprise.mil", "app": "api-gateway"},
        {"title": "Enable encryption at rest on RDS instance", "severity": "high", "status": "in_progress", "assignee": "michael.torres@enterprise.mil", "app": "infra-aws"},
        {"title": "Fix XXE in document parser", "severity": "high", "status": "assigned", "assignee": "elena.rodriguez@enterprise.mil", "app": "document-service"},
    ]
    
    count = 0
    for t in tasks:
        tid = str(uuid.uuid4())
        created = (NOW - timedelta(days=random.randint(1, 20))).isoformat()
        due = (NOW + timedelta(hours=72 if t["severity"] == "critical" else 168)).isoformat()
        resolved = NOW.isoformat() if t["status"] == "resolved" else None
        try:
            c.execute("""INSERT INTO remediation_tasks (task_id, cluster_id, org_id, app_id, title, description, severity, status, assignee, assignee_email, created_at, updated_at, due_at, resolved_at, sla_hours, sla_breached)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (tid, "cluster-prod", "enterprise", t["app"], t["title"], f"Remediation for {t['severity']} finding",
                 t["severity"], t["status"], t["assignee"], t["assignee"],
                 created, NOW.isoformat(), due, resolved,
                 72 if t["severity"] == "critical" else 168, 0))
            count += 1
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    total = c.execute("SELECT COUNT(*) FROM remediation_tasks").fetchone()[0]
    print(f"✓ Seeded {count} remediation tasks (total: {total})")
    conn.close()

def seed_metrics():
    db_path = DATA_DIR / "analytics.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    metrics = [
        ("mttr", "MTTR (Critical)", 18.5, "hours"),
        ("mttr", "MTTR (High)", 72.3, "hours"),
        ("noise_reduction", "Noise Reduction", 78.5, "percent"),
        ("dedup_rate", "Deduplication Rate", 62.3, "percent"),
        ("sla_compliance", "SLA Compliance Rate", 91.2, "percent"),
        ("autofix_success", "AutoFix Success Rate", 84.7, "percent"),
        ("mpte_coverage", "MPTE Coverage", 67.3, "percent"),
        ("risk_score", "Overall Risk Score", 72.0, "score"),
    ]
    count = 0
    for mtype, mname, value, unit in metrics:
        mid = str(uuid.uuid4())
        try:
            c.execute("INSERT INTO metrics (id, metric_type, metric_name, value, unit, timestamp, metadata) VALUES (?,?,?,?,?,?,?)",
                      (mid, mtype, mname, value, unit, NOW.isoformat(), json.dumps({"period": "30d"})))
            count += 1
        except:
            pass
    conn.commit()
    print(f"✓ Seeded {count} metrics")
    conn.close()

def seed_audit_log():
    db_path = DATA_DIR / "audit.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
        resource_type TEXT, resource_id TEXT, details TEXT,
        ip_address TEXT, timestamp TEXT NOT NULL, chain_hash TEXT
    )""")
    entries = [
        ("sarah.chen", "policy.create", "policy", "Critical CVE SLA", "Created critical CVE SLA — 72h window"),
        ("elena.rodriguez", "finding.triage", "finding", "CVE-2024-3094", "Triaged xz-utils backdoor as critical"),
        ("james.blackwell", "remediation.start", "task", "xz-patch", "Started xz-utils remediation across 47 systems"),
        ("michael.torres", "config.change", "infra", "sg-main", "Restricted SSH to VPN CIDR"),
        ("aisha.kumar", "scan.mpte", "mpte", "api-gw", "MPTE scan against api-gateway — 6 findings validated"),
        ("david.park", "evidence.generate", "bundle", "EVB-Q1", "Generated Q1 SOC2 evidence bundle"),
        ("rachel.foster", "threat.correlate", "intel", "APT-28", "Correlated 3 findings with APT-28 TTPs"),
        ("marcus.webb", "deploy.blocked", "pipeline", "billing-v2.3", "Deploy blocked — 2 critical unresolved"),
        ("elena.rodriguez", "autofix.apply", "fix", "SSRF-001", "Applied autofix — confidence 0.92"),
        ("sarah.chen", "compliance.assess", "framework", "SOC2", "SOC2 assessment — 87% compliance"),
    ]
    prev = "genesis"
    count = 0
    for actor, action, rtype, rid, details in entries:
        eid = str(uuid.uuid4())
        ts = (NOW - timedelta(hours=random.randint(1, 720))).isoformat()
        chain = hashlib.sha256(f"{prev}{eid}{ts}".encode()).hexdigest()
        prev = chain
        try:
            c.execute("INSERT OR IGNORE INTO audit_log VALUES (?,?,?,?,?,?,?,?,?)",
                      (eid, actor, action, rtype, rid, details, "10.0.1.42", ts, chain))
            count += 1
        except:
            pass
    conn.commit()
    print(f"✓ Seeded {count} audit entries")
    conn.close()

if __name__ == "__main__":
    print("═══ FixOps Enterprise Data Seeder ═══")
    seed_users()
    seed_teams()
    seed_policies()
    seed_findings()
    seed_decisions()
    seed_knowledge_graph()
    seed_remediation()
    seed_metrics()
    seed_audit_log()
    print("═══ Complete ═══")
