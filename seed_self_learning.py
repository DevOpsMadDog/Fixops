"""Seed production-grade ML feedback data into the self-learning engine.

Seeds all 5 feedback loops with realistic records:
- Decision outcomes: 25 records
- MPTE results: 15 records
- False positive reports: 10 records
- Remediation outcomes: 15 records
- Policy violations: 8 records
Total: 73 records
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.error
from typing import Any, Dict

BASE_URL = "http://localhost:8000"
import os, sys
API_KEY = os.environ.get("FIXOPS_API_TOKEN")
if not API_KEY:
    sys.exit("ERROR: FIXOPS_API_TOKEN environment variable required. Set it before running.")
HEADERS = {"Content-Type": "application/json", "X-API-Key": API_KEY}


def post(path: str, body: Dict[str, Any]) -> Dict[str, Any]:
    url = f"{BASE_URL}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8")
        print(f"  ERROR {e.code} on {path}: {body_text[:200]}")
        return {"error": str(e)}


def get(path: str) -> Dict[str, Any]:
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"X-API-Key": API_KEY}, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# LOOP 1: Decision Outcome Feedback (25 records)
# predicted_action: block / allow / monitor
# actual_outcome: true_positive / false_positive / true_negative
# ---------------------------------------------------------------------------
DECISION_RECORDS = [
    # SQL Injection findings — high confidence, mostly correct
    {"decision_id": "DEC-001", "finding_id": "SAST-fab3f5e0b22e", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.95, "context": {"scanner": "semgrep", "cwe": "CWE-89", "severity": "critical"}},
    {"decision_id": "DEC-002", "finding_id": "SAST-a9c2d4f1e833", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.92, "context": {"scanner": "semgrep", "cwe": "CWE-89", "severity": "critical"}},
    {"decision_id": "DEC-003", "finding_id": "SAST-b7e1c3d5f902", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.88, "context": {"scanner": "semgrep", "cwe": "CWE-89", "severity": "high"}},
    {"decision_id": "DEC-004", "finding_id": "SAST-c4f2a6b8d011", "predicted_action": "monitor", "actual_outcome": "true_positive",  "confidence": 0.61, "context": {"scanner": "semgrep", "cwe": "CWE-89", "severity": "medium"}},
    {"decision_id": "DEC-005", "finding_id": "SAST-d1e3b5c7f123", "predicted_action": "allow",   "actual_outcome": "false_positive", "confidence": 0.72, "context": {"scanner": "semgrep", "cwe": "CWE-79", "severity": "low"}},
    # XSS — mixed outcomes
    {"decision_id": "DEC-006", "finding_id": "DAST-a1b2c3d4e5f6", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.89, "context": {"scanner": "zap", "cwe": "CWE-79", "severity": "high"}},
    {"decision_id": "DEC-007", "finding_id": "DAST-b2c3d4e5f601", "predicted_action": "block",   "actual_outcome": "false_positive", "confidence": 0.54, "context": {"scanner": "zap", "cwe": "CWE-79", "severity": "medium"}},
    {"decision_id": "DEC-008", "finding_id": "DAST-c3d4e5f60102", "predicted_action": "monitor", "actual_outcome": "true_positive",  "confidence": 0.67, "context": {"scanner": "zap", "cwe": "CWE-79", "severity": "high"}},
    {"decision_id": "DEC-009", "finding_id": "DAST-d4e5f6010203", "predicted_action": "allow",   "actual_outcome": "true_negative",  "confidence": 0.83, "context": {"scanner": "zap", "cwe": "CWE-79", "severity": "low"}},
    {"decision_id": "DEC-010", "finding_id": "DAST-e5f601020304", "predicted_action": "allow",   "actual_outcome": "true_negative",  "confidence": 0.91, "context": {"scanner": "zap", "cwe": "CWE-200", "severity": "informational"}},
    # SCA / dependency vulnerabilities
    {"decision_id": "DEC-011", "finding_id": "SCA-pkg-vuln-001", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.97, "context": {"scanner": "grype", "cwe": "CWE-502", "severity": "critical", "package": "log4j-2.14.1"}},
    {"decision_id": "DEC-012", "finding_id": "SCA-pkg-vuln-002", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.94, "context": {"scanner": "grype", "cwe": "CWE-502", "severity": "critical", "package": "spring-core-5.3.18"}},
    {"decision_id": "DEC-013", "finding_id": "SCA-pkg-vuln-003", "predicted_action": "monitor", "actual_outcome": "true_positive",  "confidence": 0.71, "context": {"scanner": "grype", "cwe": "CWE-400", "severity": "high",     "package": "jackson-databind-2.12.0"}},
    {"decision_id": "DEC-014", "finding_id": "SCA-pkg-vuln-004", "predicted_action": "allow",   "actual_outcome": "false_positive", "confidence": 0.58, "context": {"scanner": "grype", "cwe": "CWE-22",  "severity": "medium",   "package": "commons-io-2.6"}},
    {"decision_id": "DEC-015", "finding_id": "SCA-pkg-vuln-005", "predicted_action": "allow",   "actual_outcome": "true_negative",  "confidence": 0.85, "context": {"scanner": "grype", "cwe": "CWE-22",  "severity": "low",      "package": "guava-30.1"}},
    # SAST auth issues
    {"decision_id": "DEC-016", "finding_id": "SAST-e2f3a4b5c6d7", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.90, "context": {"scanner": "semgrep", "cwe": "CWE-287", "severity": "critical"}},
    {"decision_id": "DEC-017", "finding_id": "SAST-f3a4b5c6d7e8", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.87, "context": {"scanner": "semgrep", "cwe": "CWE-287", "severity": "high"}},
    {"decision_id": "DEC-018", "finding_id": "SAST-a4b5c6d7e8f9", "predicted_action": "monitor", "actual_outcome": "false_positive", "confidence": 0.52, "context": {"scanner": "semgrep", "cwe": "CWE-352", "severity": "medium"}},
    # Infrastructure / IaC
    {"decision_id": "DEC-019", "finding_id": "IaC-tf-s3-001",  "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.93, "context": {"scanner": "checkov", "cwe": "CWE-200", "severity": "high", "resource": "aws_s3_bucket.data"}},
    {"decision_id": "DEC-020", "finding_id": "IaC-tf-iam-002", "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.88, "context": {"scanner": "checkov", "cwe": "CWE-269", "severity": "high", "resource": "aws_iam_role.admin"}},
    {"decision_id": "DEC-021", "finding_id": "IaC-tf-sg-003",  "predicted_action": "monitor", "actual_outcome": "true_positive",  "confidence": 0.66, "context": {"scanner": "checkov", "cwe": "CWE-284", "severity": "medium", "resource": "aws_security_group.web"}},
    {"decision_id": "DEC-022", "finding_id": "IaC-tf-rds-004", "predicted_action": "allow",   "actual_outcome": "true_negative",  "confidence": 0.79, "context": {"scanner": "checkov", "cwe": "CWE-312", "severity": "low", "resource": "aws_db_instance.main"}},
    # Container / secrets
    {"decision_id": "DEC-023", "finding_id": "SECRET-jwt-001",  "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.98, "context": {"scanner": "trufflehog", "type": "jwt_secret", "severity": "critical"}},
    {"decision_id": "DEC-024", "finding_id": "SECRET-aws-002",  "predicted_action": "block",   "actual_outcome": "true_positive",  "confidence": 0.99, "context": {"scanner": "trufflehog", "type": "aws_access_key", "severity": "critical"}},
    {"decision_id": "DEC-025", "finding_id": "SECRET-api-003",  "predicted_action": "monitor", "actual_outcome": "false_positive", "confidence": 0.55, "context": {"scanner": "trufflehog", "type": "generic_api_key", "severity": "medium"}},
]

# ---------------------------------------------------------------------------
# LOOP 2: MPTE Results (15 records)
# predicted_exploitable: bool, actual_exploitable: bool
# ---------------------------------------------------------------------------
MPTE_RECORDS = [
    {"finding_id": "SAST-fab3f5e0b22e", "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.94, "context": {"cve": "CVE-2023-45678", "epss": 0.82, "kev": True}},
    {"finding_id": "SAST-a9c2d4f1e833", "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.91, "context": {"cve": "CVE-2023-44678", "epss": 0.71, "kev": False}},
    {"finding_id": "DAST-a1b2c3d4e5f6", "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.87, "context": {"cve": None, "epss": 0.45, "kev": False}},
    {"finding_id": "DAST-b2c3d4e5f601", "predicted_exploitable": True,  "actual_exploitable": False, "mpte_confidence": 0.53, "context": {"cve": None, "epss": 0.12, "kev": False}},
    {"finding_id": "SCA-pkg-vuln-001",  "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.97, "context": {"cve": "CVE-2021-44228", "epss": 0.97, "kev": True}},
    {"finding_id": "SCA-pkg-vuln-002",  "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.92, "context": {"cve": "CVE-2022-22965", "epss": 0.88, "kev": True}},
    {"finding_id": "SCA-pkg-vuln-003",  "predicted_exploitable": True,  "actual_exploitable": False, "mpte_confidence": 0.61, "context": {"cve": "CVE-2022-42003", "epss": 0.28, "kev": False}},
    {"finding_id": "SCA-pkg-vuln-004",  "predicted_exploitable": False, "actual_exploitable": False, "mpte_confidence": 0.78, "context": {"cve": "CVE-2021-29425", "epss": 0.08, "kev": False}},
    {"finding_id": "SCA-pkg-vuln-005",  "predicted_exploitable": False, "actual_exploitable": False, "mpte_confidence": 0.85, "context": {"cve": None,            "epss": 0.03, "kev": False}},
    {"finding_id": "SAST-e2f3a4b5c6d7", "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.89, "context": {"cve": "CVE-2023-12345", "epss": 0.62, "kev": False}},
    {"finding_id": "IaC-tf-s3-001",     "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.83, "context": {"cve": None, "epss": 0.35, "kev": False}},
    {"finding_id": "IaC-tf-iam-002",    "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.88, "context": {"cve": None, "epss": 0.41, "kev": False}},
    {"finding_id": "SECRET-jwt-001",     "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.98, "context": {"cve": None, "epss": 0.79, "kev": False}},
    {"finding_id": "SECRET-aws-002",     "predicted_exploitable": True,  "actual_exploitable": True,  "mpte_confidence": 0.99, "context": {"cve": None, "epss": 0.91, "kev": True}},
    {"finding_id": "DAST-c3d4e5f60102", "predicted_exploitable": True,  "actual_exploitable": False, "mpte_confidence": 0.56, "context": {"cve": None, "epss": 0.17, "kev": False}},
]

# ---------------------------------------------------------------------------
# LOOP 3: False Positive Feedback (10 records)
# scanner, rule_id, is_false_positive: bool
# ---------------------------------------------------------------------------
FP_RECORDS = [
    {"finding_id": "SAST-d1e3b5c7f123", "scanner": "semgrep",    "rule_id": "python.django.security.injection.tainted-sql-string", "is_false_positive": True,  "context": {"reporter": "alice@corp.com", "reason": "parameterized_query_confirmed", "team": "backend"}},
    {"finding_id": "DAST-b2c3d4e5f601", "scanner": "zap",        "rule_id": "10016-xss-reflected",                                  "is_false_positive": True,  "context": {"reporter": "bob@corp.com",   "reason": "input_sanitization_verified",   "team": "appsec"}},
    {"finding_id": "SAST-a4b5c6d7e8f9", "scanner": "semgrep",    "rule_id": "java.spring.security.csrf-disabled",                   "is_false_positive": True,  "context": {"reporter": "charlie@corp.com","reason": "csrf_protection_implemented",   "team": "backend"}},
    {"finding_id": "SCA-pkg-vuln-004",  "scanner": "grype",      "rule_id": "CVE-2021-29425",                                       "is_false_positive": True,  "context": {"reporter": "dave@corp.com",  "reason": "vulnerable_code_path_unreachable","team": "platform"}},
    {"finding_id": "SECRET-api-003",    "scanner": "trufflehog", "rule_id": "generic-api-key",                                      "is_false_positive": True,  "context": {"reporter": "eve@corp.com",   "reason": "test_fixture_not_real_secret",   "team": "devops"}},
    {"finding_id": "SAST-fab3f5e0b22e", "scanner": "semgrep",    "rule_id": "python.django.security.injection.tainted-sql-string",  "is_false_positive": False, "context": {"reporter": "frank@corp.com", "reason": "confirmed_exploitable",         "team": "appsec"}},
    {"finding_id": "DAST-a1b2c3d4e5f6", "scanner": "zap",        "rule_id": "10016-xss-reflected",                                  "is_false_positive": False, "context": {"reporter": "grace@corp.com", "reason": "reproduced_in_staging",         "team": "appsec"}},
    {"finding_id": "SCA-pkg-vuln-001",  "scanner": "grype",      "rule_id": "CVE-2021-44228",                                       "is_false_positive": False, "context": {"reporter": "heidi@corp.com", "reason": "log4shell_confirmed",            "team": "platform"}},
    {"finding_id": "IaC-tf-sg-003",     "scanner": "checkov",    "rule_id": "CKV_AWS_25",                                           "is_false_positive": True,  "context": {"reporter": "ivan@corp.com",  "reason": "internal_network_only",          "team": "infra"}},
    {"finding_id": "SAST-b7e1c3d5f902", "scanner": "semgrep",    "rule_id": "python.django.security.injection.tainted-sql-string",  "is_false_positive": False, "context": {"reporter": "judy@corp.com",  "reason": "raw_sql_no_sanitization",        "team": "backend"}},
]

# ---------------------------------------------------------------------------
# LOOP 4: Remediation Outcome Feedback (15 records)
# fix_type: CODE_PATCH / CONFIG / WAF_RULE / AUTOFIX / DEPENDENCY_UPGRADE
# resolved: bool, time_to_fix_hours: float
# ---------------------------------------------------------------------------
REMEDIATION_RECORDS = [
    {"finding_id": "SAST-fab3f5e0b22e", "fix_type": "CODE_PATCH",         "fix_applied": "Replaced raw SQL with parameterized query using Django ORM",             "resolved": True,  "time_to_fix_hours": 2.5,  "context": {"team": "backend",  "sprint": "Q1-S3", "ticket": "ENG-1204"}},
    {"finding_id": "SAST-a9c2d4f1e833", "fix_type": "CODE_PATCH",         "fix_applied": "Added input validation and prepared statements for user search endpoint", "resolved": True,  "time_to_fix_hours": 3.0,  "context": {"team": "backend",  "sprint": "Q1-S3", "ticket": "ENG-1205"}},
    {"finding_id": "DAST-a1b2c3d4e5f6", "fix_type": "CODE_PATCH",         "fix_applied": "Applied DOMPurify sanitization on all user-controlled output fields",     "resolved": True,  "time_to_fix_hours": 1.5,  "context": {"team": "frontend", "sprint": "Q1-S3", "ticket": "ENG-1210"}},
    {"finding_id": "DAST-c3d4e5f60102", "fix_type": "WAF_RULE",           "fix_applied": "Deployed Cloudflare WAF rule blocking reflected XSS pattern",            "resolved": True,  "time_to_fix_hours": 0.5,  "context": {"team": "appsec",   "sprint": "Q1-S3", "ticket": "ENG-1211"}},
    {"finding_id": "SCA-pkg-vuln-001",  "fix_type": "DEPENDENCY_UPGRADE", "fix_applied": "Upgraded log4j 2.14.1 → 2.17.2 across all services",                    "resolved": True,  "time_to_fix_hours": 8.0,  "context": {"team": "platform", "sprint": "Q1-S2", "ticket": "ENG-1180"}},
    {"finding_id": "SCA-pkg-vuln-002",  "fix_type": "DEPENDENCY_UPGRADE", "fix_applied": "Upgraded spring-core 5.3.18 → 5.3.27 with full regression suite",       "resolved": True,  "time_to_fix_hours": 12.0, "context": {"team": "platform", "sprint": "Q1-S3", "ticket": "ENG-1195"}},
    {"finding_id": "SCA-pkg-vuln-003",  "fix_type": "DEPENDENCY_UPGRADE", "fix_applied": "Upgraded jackson-databind to 2.15.2",                                    "resolved": True,  "time_to_fix_hours": 4.0,  "context": {"team": "platform", "sprint": "Q1-S3", "ticket": "ENG-1200"}},
    {"finding_id": "SECRET-jwt-001",    "fix_type": "CONFIG",              "fix_applied": "Rotated JWT secret, removed from code, moved to Vault",                  "resolved": True,  "time_to_fix_hours": 1.0,  "context": {"team": "devops",   "sprint": "Q1-S3", "ticket": "ENG-1220"}},
    {"finding_id": "SECRET-aws-002",    "fix_type": "CONFIG",              "fix_applied": "Revoked AWS access key, implemented IAM roles with instance profiles",   "resolved": True,  "time_to_fix_hours": 2.0,  "context": {"team": "devops",   "sprint": "Q1-S3", "ticket": "ENG-1221"}},
    {"finding_id": "IaC-tf-s3-001",     "fix_type": "CONFIG",              "fix_applied": "Enabled S3 block public access + bucket encryption",                     "resolved": True,  "time_to_fix_hours": 0.5,  "context": {"team": "infra",    "sprint": "Q1-S3", "ticket": "ENG-1230"}},
    {"finding_id": "IaC-tf-iam-002",    "fix_type": "CONFIG",              "fix_applied": "Applied least-privilege IAM policy, removed wildcard permissions",       "resolved": True,  "time_to_fix_hours": 3.5,  "context": {"team": "infra",    "sprint": "Q1-S3", "ticket": "ENG-1231"}},
    {"finding_id": "IaC-tf-sg-003",     "fix_type": "CONFIG",              "fix_applied": "Restricted security group ingress to known CIDR ranges",                 "resolved": True,  "time_to_fix_hours": 1.0,  "context": {"team": "infra",    "sprint": "Q1-S3", "ticket": "ENG-1232"}},
    {"finding_id": "SAST-e2f3a4b5c6d7", "fix_type": "CODE_PATCH",         "fix_applied": "Implemented MFA check in authentication middleware",                     "resolved": False, "time_to_fix_hours": 24.0, "context": {"team": "backend",  "sprint": "Q1-S4", "ticket": "ENG-1240", "blocked_by": "identity_team"}},
    {"finding_id": "SAST-f3a4b5c6d7e8", "fix_type": "CODE_PATCH",         "fix_applied": "Added CSRF token validation to all state-changing endpoints",            "resolved": True,  "time_to_fix_hours": 5.0,  "context": {"team": "backend",  "sprint": "Q1-S3", "ticket": "ENG-1241"}},
    {"finding_id": "DAST-d4e5f6010203", "fix_type": "WAF_RULE",           "fix_applied": "Deployed WAF rule blocking path traversal patterns",                     "resolved": True,  "time_to_fix_hours": 0.25, "context": {"team": "appsec",   "sprint": "Q1-S3", "ticket": "ENG-1215"}},
]

# ---------------------------------------------------------------------------
# LOOP 5: Policy Violation Feedback (8 records)
# policy_id, rule_id, violated: bool, was_justified: bool
# ---------------------------------------------------------------------------
POLICY_RECORDS = [
    {"policy_id": "POL-SEC-001", "rule_id": "no-critical-in-prod",           "violated": True,  "was_justified": False, "context": {"team": "backend",  "finding": "SAST-fab3f5e0b22e", "action": "deploy_blocked"}},
    {"policy_id": "POL-SEC-001", "rule_id": "no-critical-in-prod",           "violated": True,  "was_justified": False, "context": {"team": "platform", "finding": "SCA-pkg-vuln-001",  "action": "deploy_blocked"}},
    {"policy_id": "POL-SEC-002", "rule_id": "no-secrets-in-code",            "violated": True,  "was_justified": False, "context": {"team": "devops",   "finding": "SECRET-jwt-001",     "action": "pr_blocked"}},
    {"policy_id": "POL-SEC-002", "rule_id": "no-secrets-in-code",            "violated": True,  "was_justified": False, "context": {"team": "devops",   "finding": "SECRET-aws-002",     "action": "pr_blocked"}},
    {"policy_id": "POL-SEC-003", "rule_id": "sca-high-block-deploy",         "violated": True,  "was_justified": True,  "context": {"team": "platform", "finding": "SCA-pkg-vuln-002",  "action": "exception_granted", "justification": "patch_in_progress_48h"}},
    {"policy_id": "POL-OPS-001", "rule_id": "iac-changes-require-review",    "violated": True,  "was_justified": False, "context": {"team": "infra",    "finding": "IaC-tf-iam-002",    "action": "pr_blocked"}},
    {"policy_id": "POL-OPS-002", "rule_id": "container-image-scan-required", "violated": False, "was_justified": True,  "context": {"team": "platform", "pipeline": "prod-deploy-v2.3", "action": "scan_passed"}},
    {"policy_id": "POL-SEC-004", "rule_id": "pen-test-before-launch",        "violated": False, "was_justified": True,  "context": {"team": "appsec",   "product": "payments-api-v3",   "action": "pentest_completed", "report": "PT-2026-Q1-042"}},
]


def seed_all():
    results = {
        "decision_outcome": {"sent": 0, "ok": 0, "error": 0},
        "mpte_result":       {"sent": 0, "ok": 0, "error": 0},
        "false_positive":    {"sent": 0, "ok": 0, "error": 0},
        "remediation":       {"sent": 0, "ok": 0, "error": 0},
        "policy_violation":  {"sent": 0, "ok": 0, "error": 0},
    }

    # Loop 1: Decision Outcome
    print(f"\n[Loop 1] Seeding {len(DECISION_RECORDS)} decision outcome records...")
    for rec in DECISION_RECORDS:
        results["decision_outcome"]["sent"] += 1
        resp = post("/api/v1/self-learning/feedback/decision", rec)
        if resp.get("recorded"):
            results["decision_outcome"]["ok"] += 1
            print(f"  ✓ {rec['finding_id']} → {rec['predicted_action']} / {rec['actual_outcome']}")
        else:
            results["decision_outcome"]["error"] += 1
            print(f"  ✗ {rec['finding_id']}: {resp}")

    # Loop 2: MPTE
    print(f"\n[Loop 2] Seeding {len(MPTE_RECORDS)} MPTE result records...")
    for rec in MPTE_RECORDS:
        results["mpte_result"]["sent"] += 1
        resp = post("/api/v1/self-learning/feedback/mpte", rec)
        if resp.get("recorded"):
            results["mpte_result"]["ok"] += 1
            print(f"  ✓ {rec['finding_id']} predicted={rec['predicted_exploitable']} actual={rec['actual_exploitable']}")
        else:
            results["mpte_result"]["error"] += 1
            print(f"  ✗ {rec['finding_id']}: {resp}")

    # Loop 3: False Positive
    print(f"\n[Loop 3] Seeding {len(FP_RECORDS)} false positive records...")
    for rec in FP_RECORDS:
        results["false_positive"]["sent"] += 1
        resp = post("/api/v1/self-learning/feedback/false-positive", rec)
        if resp.get("recorded"):
            results["false_positive"]["ok"] += 1
            print(f"  ✓ {rec['finding_id']} is_fp={rec['is_false_positive']}")
        else:
            results["false_positive"]["error"] += 1
            print(f"  ✗ {rec['finding_id']}: {resp}")

    # Loop 4: Remediation
    print(f"\n[Loop 4] Seeding {len(REMEDIATION_RECORDS)} remediation outcome records...")
    for rec in REMEDIATION_RECORDS:
        results["remediation"]["sent"] += 1
        resp = post("/api/v1/self-learning/feedback/remediation", rec)
        if resp.get("recorded"):
            results["remediation"]["ok"] += 1
            print(f"  ✓ {rec['finding_id']} fix={rec['fix_type']} resolved={rec['resolved']}")
        else:
            results["remediation"]["error"] += 1
            print(f"  ✗ {rec['finding_id']}: {resp}")

    # Loop 5: Policy Violation
    print(f"\n[Loop 5] Seeding {len(POLICY_RECORDS)} policy violation records...")
    for rec in POLICY_RECORDS:
        results["policy_violation"]["sent"] += 1
        resp = post("/api/v1/self-learning/feedback/policy", rec)
        if resp.get("recorded"):
            results["policy_violation"]["ok"] += 1
            print(f"  ✓ {rec['policy_id']}/{rec['rule_id']} violated={rec['violated']}")
        else:
            results["policy_violation"]["error"] += 1
            print(f"  ✗ {rec['policy_id']}: {resp}")

    # Summary
    total_sent = sum(v["sent"] for v in results.values())
    total_ok   = sum(v["ok"]   for v in results.values())
    total_err  = sum(v["error"] for v in results.values())

    print("\n" + "=" * 60)
    print("SEED SUMMARY")
    print("=" * 60)
    for loop, counts in results.items():
        print(f"  {loop:25s}: {counts['ok']}/{counts['sent']} OK  ({counts['error']} errors)")
    print(f"\n  TOTAL: {total_ok}/{total_sent} records seeded successfully")

    # Verify with stats
    print("\n[Verify] Fetching /api/v1/self-learning/stats ...")
    stats = get("/api/v1/self-learning/stats")
    feedback_counts = stats.get("feedback_counts", {})
    total_records   = stats.get("total_feedback_records", 0)
    print(f"  feedback_counts: {json.dumps(feedback_counts, indent=4)}")
    print(f"  total_feedback_records: {total_records}")

    if total_records > 0:
        print(f"\n  ✓ SUCCESS: {total_records} feedback records confirmed in engine")
        return True
    else:
        print("\n  ✗ FAILURE: stats still shows 0 records")
        return False


if __name__ == "__main__":
    ok = seed_all()
    sys.exit(0 if ok else 1)
