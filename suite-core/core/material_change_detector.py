"""Material Change Detection Engine for FixOps.

This module implements a security-focused diff analysis engine that competes with
Apiiro's Design Change Analysis (DCA) capability. It parses unified diffs to detect
security-material changes across multiple languages and infrastructure formats,
scores each change by risk, classifies changes semantically, and produces
comprehensive PR/MR risk assessments.

Architecture:
    DiffParser          -- Parses raw unified diff text into structured hunks
    PatternLibrary      -- Language/category-specific regex pattern sets
    ASTAnalyzer         -- Python AST-based deep analysis
    RiskScorer          -- Multi-factor 0-100 risk scoring
    SemanticClassifier  -- BREAKING / MATERIAL / COSMETIC labeling
    PRAnalyzer          -- Full PR/MR risk assessment orchestrator
    VelocityTracker     -- Change velocity and security-debt-acceleration detection

All processing is pure Python, offline-capable, and air-gap safe.
No external API calls are made.

Supported languages:
    Python, JavaScript, TypeScript, Java, Go, C, C++, Terraform, YAML, Dockerfile
"""

from __future__ import annotations

import ast
import hashlib
import logging
import math
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, DefaultDict, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ChangeCategory(str, Enum):
    """High-level category of a security-relevant change."""

    AUTH = "auth"
    CRYPTO = "crypto"
    DATA_FLOW = "data_flow"
    API_SURFACE = "api_surface"
    DEPENDENCY = "dependency"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class ChangeClassification(str, Enum):
    """Semantic classification of a change's security impact."""

    BREAKING = "BREAKING"
    MATERIAL = "MATERIAL"
    COSMETIC = "COSMETIC"


class SeverityLevel(str, Enum):
    """Severity assigned to a detected material change."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------


@dataclass
class DiffHunk:
    """A single contiguous changed region within a diff file section.

    Attributes:
        old_start: Line number in the old file where this hunk begins.
        old_count: Number of lines from the old file covered.
        new_start: Line number in the new file where this hunk begins.
        new_count: Number of lines from the new file covered.
        added_lines: Lines present only in the new file (without leading '+').
        removed_lines: Lines present only in the old file (without leading '-').
        context_lines: Unchanged context lines surrounding the hunk.
        raw: The original raw hunk text.
    """

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    added_lines: List[str]
    removed_lines: List[str]
    context_lines: List[str]
    raw: str = ""

    @property
    def net_change_size(self) -> int:
        """Total lines changed (additions + removals)."""
        return len(self.added_lines) + len(self.removed_lines)

    @property
    def churn(self) -> int:
        """Absolute churn: sum of added and removed line counts."""
        return len(self.added_lines) + len(self.removed_lines)


@dataclass
class FileDiff:
    """Parsed diff for a single file.

    Attributes:
        path: Relative file path (new path for renames).
        old_path: Old path before rename, equals ``path`` if unchanged.
        language: Detected programming/config language.
        is_new_file: True when the file is being created in this diff.
        is_deleted_file: True when the file is being removed.
        is_rename: True when the file is being moved/renamed.
        hunks: Ordered list of diff hunks within this file.
        raw: Full raw diff text for this file.
    """

    path: str
    old_path: str
    language: str
    is_new_file: bool
    is_deleted_file: bool
    is_rename: bool
    hunks: List[DiffHunk]
    raw: str = ""

    @property
    def total_added(self) -> int:
        return sum(len(h.added_lines) for h in self.hunks)

    @property
    def total_removed(self) -> int:
        return sum(len(h.removed_lines) for h in self.hunks)

    @property
    def total_churn(self) -> int:
        return self.total_added + self.total_removed

    @property
    def all_added_text(self) -> str:
        return "\n".join(line for h in self.hunks for line in h.added_lines)

    @property
    def all_removed_text(self) -> str:
        return "\n".join(line for h in self.hunks for line in h.removed_lines)

    @property
    def all_changed_text(self) -> str:
        return self.all_added_text + "\n" + self.all_removed_text


@dataclass
class PatternMatch:
    """A single pattern hit within a diff.

    Attributes:
        pattern_id: Unique identifier for the rule that triggered.
        category: Security category of the match.
        description: Human-readable explanation.
        matched_text: The actual text fragment that matched.
        line_content: Full line containing the match.
        hunk_index: Index of the hunk where the match was found.
        is_addition: True if the match is on an added line (vs removed).
        confidence: Match confidence 0.0–1.0.
    """

    pattern_id: str
    category: ChangeCategory
    description: str
    matched_text: str
    line_content: str
    hunk_index: int
    is_addition: bool
    confidence: float = 1.0


@dataclass
class MaterialChange:
    """A fully analyzed, scored, and classified security-material change.

    Attributes:
        change_id: Deterministic SHA-256-based identifier.
        file_path: File in which the change was detected.
        category: Security category of the change.
        classification: BREAKING / MATERIAL / COSMETIC.
        severity: Severity level.
        risk_score: 0–100 composite risk score.
        summary: One-line human description.
        explanation: Detailed technical explanation.
        pattern_matches: Raw pattern matches that triggered detection.
        recommended_reviewers: Suggested expertise areas for review.
        review_items: Specific review checklist items.
        metadata: Arbitrary extra data (line numbers, ast nodes, etc.).
    """

    change_id: str
    file_path: str
    category: ChangeCategory
    classification: ChangeClassification
    severity: SeverityLevel
    risk_score: float
    summary: str
    explanation: str
    pattern_matches: List[PatternMatch]
    recommended_reviewers: List[str]
    review_items: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PRRiskAssessment:
    """Full risk assessment for a pull/merge request.

    Attributes:
        pr_id: Identifier of the PR (e.g. GitHub PR number or hash).
        overall_risk_score: 0–100 aggregated risk score.
        classification: Highest classification level observed.
        material_changes: All material changes detected across files.
        file_summaries: Per-file risk summaries.
        recommended_reviewers: Deduplicated reviewer expertise list.
        review_checklist: Full security review checklist.
        risk_breakdown: Score contribution per category.
        stats: Summary statistics about the diff.
        analyzed_at: ISO-8601 timestamp of analysis.
    """

    pr_id: str
    overall_risk_score: float
    classification: ChangeClassification
    material_changes: List[MaterialChange]
    file_summaries: List[Dict[str, Any]]
    recommended_reviewers: List[str]
    review_checklist: List[str]
    risk_breakdown: Dict[str, float]
    stats: Dict[str, Any]
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class VelocitySnapshot:
    """A point-in-time measurement of change velocity for a repository.

    Attributes:
        repo: Repository identifier.
        window_days: Time window for this measurement.
        material_change_count: Number of material changes in the window.
        breaking_change_count: Number of BREAKING changes.
        avg_risk_score: Average risk score of material changes.
        acceleration: Rate of change vs previous window (positive = accelerating).
        debt_acceleration_alert: True when velocity exceeds configured baseline.
        timestamp: When this snapshot was recorded.
    """

    repo: str
    window_days: int
    material_change_count: int
    breaking_change_count: int
    avg_risk_score: float
    acceleration: float
    debt_acceleration_alert: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Pattern Library
# ---------------------------------------------------------------------------


class PatternLibrary:
    """Comprehensive regex pattern library for detecting security-material changes.

    Patterns are organized by category and sub-category.  Each entry is a
    tuple of (pattern_id, compiled_regex, description, confidence, severity).

    All patterns are pre-compiled at class construction time for performance.
    The library supports Python, JavaScript/TypeScript, Java, Go, C/C++,
    Terraform, YAML, and Dockerfile.
    """

    def __init__(self) -> None:
        self._auth_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._crypto_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._data_flow_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._api_surface_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._dependency_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._infra_patterns: List[Tuple[str, re.Pattern, str, float, SeverityLevel]] = []
        self._build()

    def _c(
        self,
        pattern_id: str,
        regex: str,
        description: str,
        confidence: float,
        severity: SeverityLevel,
    ) -> Tuple[str, re.Pattern, str, float, SeverityLevel]:
        """Compile a single pattern entry."""
        try:
            compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
        except re.error as exc:
            logger.warning("Failed to compile pattern %s: %s", pattern_id, exc)
            compiled = re.compile(r"(?!x)x")  # never-matching fallback
        return (pattern_id, compiled, description, confidence, severity)

    def _build(self) -> None:
        """Populate all pattern lists."""
        self._build_auth_patterns()
        self._build_crypto_patterns()
        self._build_data_flow_patterns()
        self._build_api_surface_patterns()
        self._build_dependency_patterns()
        self._build_infra_patterns()

    # ------------------------------------------------------------------
    # Auth / AuthZ patterns
    # ------------------------------------------------------------------

    def _build_auth_patterns(self) -> None:
        p = self._auth_patterns
        c = self._c

        # Login / authentication entry points
        p.append(c("AUTH-001", r"\b(login|signin|sign_in|authenticate)\s*\(", "Authentication function call modified", 0.90, SeverityLevel.HIGH))
        p.append(c("AUTH-002", r"\b(logout|signout|sign_out|invalidate_session)\s*\(", "Logout/session invalidation change", 0.85, SeverityLevel.HIGH))
        p.append(c("AUTH-003", r"password\s*[=:]\s*['\"][^'\"]{0,64}['\"]", "Hardcoded password literal", 0.95, SeverityLevel.CRITICAL))
        p.append(c("AUTH-004", r"(verify_password|check_password|compare_password|bcrypt\.check)\s*\(", "Password verification logic changed", 0.88, SeverityLevel.CRITICAL))
        p.append(c("AUTH-005", r"\bpassword_hash\s*=|password\s*=\s*hashlib|hashpw\s*\(", "Password hashing logic changed", 0.90, SeverityLevel.CRITICAL))

        # OAuth / OpenID Connect
        p.append(c("AUTH-010", r"\b(oauth|oidc|openid)[._\s]*(token|flow|callback|redirect)", "OAuth/OIDC flow modification", 0.88, SeverityLevel.HIGH))
        p.append(c("AUTH-011", r"(client_secret|client_id)\s*[=:]\s*['\"][^'\"]{4,}['\"]", "OAuth client credential literal", 0.92, SeverityLevel.CRITICAL))
        p.append(c("AUTH-012", r"\baccess_token\s*=\s*|bearer\s+token|authorization:\s*bearer", "Bearer token handling change", 0.85, SeverityLevel.HIGH))
        p.append(c("AUTH-013", r"refresh_token|token_refresh|rotate_token", "Token refresh logic change", 0.82, SeverityLevel.HIGH))
        p.append(c("AUTH-014", r"(scope|grant_type|response_type)\s*=\s*['\"][^'\"]+['\"]", "OAuth scope/grant change", 0.80, SeverityLevel.MEDIUM))
        p.append(c("AUTH-015", r"redirect_uri\s*=\s*['\"][^'\"]+['\"]", "OAuth redirect_uri change (SSRF/open-redirect risk)", 0.90, SeverityLevel.HIGH))

        # JWT / session tokens
        p.append(c("AUTH-020", r"\bjwt\.(sign|verify|decode)\s*\(", "JWT sign/verify logic change", 0.92, SeverityLevel.HIGH))
        p.append(c("AUTH-021", r"jwt_secret|JWT_SECRET|jwt_key|JWT_KEY", "JWT secret key reference", 0.95, SeverityLevel.CRITICAL))
        p.append(c("AUTH-022", r"algorithm\s*=\s*['\"]none['\"]", "JWT algorithm set to 'none' (CVE-class)", 1.00, SeverityLevel.CRITICAL))
        p.append(c("AUTH-023", r"(session\.(set|get|delete|regenerate|destroy))\s*\(", "Session manipulation change", 0.85, SeverityLevel.HIGH))
        p.append(c("AUTH-024", r"session_secret|SESSION_SECRET|cookie_secret", "Session secret reference", 0.93, SeverityLevel.CRITICAL))
        p.append(c("AUTH-025", r"(httponly|secure|samesite)\s*[=:]\s*(false|0|none)", "Cookie security flag weakened", 0.95, SeverityLevel.HIGH))

        # RBAC / authorization
        p.append(c("AUTH-030", r"\b(authorize|is_authorized|check_permission|has_role|can_access)\s*\(", "Authorization check modification", 0.88, SeverityLevel.HIGH))
        p.append(c("AUTH-031", r"\b(admin|superuser|root)\s*[=:]\s*(true|1|yes)", "Admin/superuser flag assignment", 0.90, SeverityLevel.CRITICAL))
        p.append(c("AUTH-032", r"(role|permission|acl)\s*=\s*['\"][^'\"]+['\"]", "Role/permission assignment change", 0.82, SeverityLevel.HIGH))
        p.append(c("AUTH-033", r"(skip_auth|bypass_auth|no_auth|disable_auth|auth_disabled)", "Auth bypass flag", 0.97, SeverityLevel.CRITICAL))
        p.append(c("AUTH-034", r"(require_auth|@login_required|@auth\.required|@authenticated)", "Auth requirement decorator modified", 0.88, SeverityLevel.HIGH))
        p.append(c("AUTH-035", r"(whitelist|allowlist|blacklist|blocklist)\s*[=:+]", "Access control list modification", 0.80, SeverityLevel.HIGH))

        # MFA / 2FA
        p.append(c("AUTH-040", r"\b(mfa|2fa|totp|hotp|otp)\s*[=.(]", "MFA/OTP logic change", 0.87, SeverityLevel.HIGH))
        p.append(c("AUTH-041", r"(verify_otp|check_otp|validate_otp)\s*\(", "OTP verification change", 0.90, SeverityLevel.HIGH))

        # SAML / SSO
        p.append(c("AUTH-050", r"\b(saml|sso|idp|sp_metadata|assertion)\s*[=.(]", "SAML/SSO configuration change", 0.85, SeverityLevel.HIGH))
        p.append(c("AUTH-051", r"(wantMessagesSigned|wantAssertionsSigned)\s*[=:]\s*(false|0)", "SAML signature verification disabled", 1.00, SeverityLevel.CRITICAL))

    # ------------------------------------------------------------------
    # Crypto patterns
    # ------------------------------------------------------------------

    def _build_crypto_patterns(self) -> None:
        p = self._crypto_patterns
        c = self._c

        # Weak algorithms
        p.append(c("CRYPTO-001", r"\b(md5|sha1|sha-1)\s*\(|hashlib\.(md5|sha1)\s*\(", "Weak hash algorithm usage", 0.92, SeverityLevel.HIGH))
        p.append(c("CRYPTO-002", r"\b(des|3des|rc2|rc4)\s*[.(]", "Weak symmetric cipher usage", 0.95, SeverityLevel.CRITICAL))
        p.append(c("CRYPTO-003", r"(ecb)\s*(mode|=)", "ECB mode (insecure block cipher mode)", 0.95, SeverityLevel.CRITICAL))
        p.append(c("CRYPTO-004", r"AES\.(new|MODE_ECB)|Cipher\(algorithms\.AES", "AES cipher instantiation change", 0.85, SeverityLevel.HIGH))
        p.append(c("CRYPTO-005", r"(rsa|ecdsa|dsa)\.(generate|load|import).*key", "Asymmetric key operation change", 0.88, SeverityLevel.HIGH))
        p.append(c("CRYPTO-006", r"key_size\s*=\s*\d+|key_length\s*=\s*\d+|bits\s*=\s*\d+", "Cryptographic key size change", 0.85, SeverityLevel.HIGH))
        p.append(c("CRYPTO-007", r"(512|768|1024)\s*(bits?|_bits?|bit_key)", "Potentially weak key length (<2048 bits)", 0.90, SeverityLevel.HIGH))

        # Random / entropy
        p.append(c("CRYPTO-010", r"\brandom\.(random|randint|choice)\s*\(", "Non-cryptographic PRNG for security use", 0.75, SeverityLevel.MEDIUM))
        p.append(c("CRYPTO-011", r"(os\.urandom|secrets\.(token|choice)|random\.SystemRandom)", "Cryptographic RNG change", 0.82, SeverityLevel.MEDIUM))
        p.append(c("CRYPTO-012", r"(seed\s*\(|random\.seed)", "PRNG seed modification (deterministic random)", 0.88, SeverityLevel.HIGH))

        # TLS/SSL configuration
        p.append(c("CRYPTO-020", r"ssl\.(PROTOCOL_TLS|PROTOCOL_SSLv|TLSv1|SSLv)", "SSL/TLS protocol version change", 0.90, SeverityLevel.HIGH))
        p.append(c("CRYPTO-021", r"verify_ssl\s*=\s*(false|0|no)|ssl_verify\s*=\s*(false|0)|check_hostname\s*=\s*False", "SSL certificate verification disabled", 1.00, SeverityLevel.CRITICAL))
        p.append(c("CRYPTO-022", r"(SSLContext|ssl_context|TLSContext|tls_context)\s*[=(]", "TLS context configuration change", 0.85, SeverityLevel.HIGH))
        p.append(c("CRYPTO-023", r"set_ciphers\s*\(|cipher_list\s*=", "TLS cipher suite change", 0.88, SeverityLevel.HIGH))
        p.append(c("CRYPTO-024", r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)", "Deprecated TLS/SSL protocol version", 0.95, SeverityLevel.CRITICAL))
        p.append(c("CRYPTO-025", r"CERT_NONE|VERIFY_NONE|InsecureRequestWarning", "Certificate verification bypassed", 1.00, SeverityLevel.CRITICAL))

        # Key management
        p.append(c("CRYPTO-030", r"(private_key|secret_key|signing_key|encryption_key)\s*=\s*[b\"]", "Hardcoded cryptographic key", 0.95, SeverityLevel.CRITICAL))
        p.append(c("CRYPTO-031", r"(pem|der|p12|pfx)\s*(file|path|data)\s*[=:]", "Certificate/key file reference change", 0.82, SeverityLevel.HIGH))
        p.append(c("CRYPTO-032", r"(generate_key|new_key|create_key|rotate_key)\s*\(", "Key generation/rotation change", 0.83, SeverityLevel.HIGH))
        p.append(c("CRYPTO-033", r"(encrypt|decrypt|cipher|decipher)\s*\(", "Encryption/decryption call change", 0.78, SeverityLevel.MEDIUM))

        # Hashing for security
        p.append(c("CRYPTO-040", r"(pbkdf2|bcrypt|scrypt|argon2|hkdf)\s*\(", "Key derivation function change", 0.90, SeverityLevel.HIGH))
        p.append(c("CRYPTO-041", r"iterations\s*=\s*\d+|rounds\s*=\s*\d+|work_factor\s*=\s*\d+", "KDF iteration/round count change", 0.85, SeverityLevel.HIGH))

    # ------------------------------------------------------------------
    # Data flow patterns
    # ------------------------------------------------------------------

    def _build_data_flow_patterns(self) -> None:
        p = self._data_flow_patterns
        c = self._c

        # PII handling
        p.append(c("DATA-001", r"\b(ssn|social_security|national_id|passport|dob|date_of_birth)\b", "PII field reference (SSN/ID/DOB)", 0.85, SeverityLevel.HIGH))
        p.append(c("DATA-002", r"\b(email|phone|mobile|address|zip_code|postal_code)\s*[=:]", "Contact PII field assignment", 0.75, SeverityLevel.MEDIUM))
        p.append(c("DATA-003", r"\b(credit_card|card_number|cvv|pan|iban)\b", "Financial PII reference (card/IBAN)", 0.92, SeverityLevel.CRITICAL))
        p.append(c("DATA-004", r"\b(health_data|medical_record|diagnosis|prescription|phi)\b", "Health/PHI data reference", 0.90, SeverityLevel.CRITICAL))
        p.append(c("DATA-005", r"(log|print|console\.log|fmt\.print|println)\s*\(.*?(password|secret|token|key)", "Sensitive data logged", 0.90, SeverityLevel.HIGH))

        # Serialization
        p.append(c("DATA-010", r"\b(pickle\.loads|marshal\.loads|yaml\.load\s*\((?!.*Loader))", "Unsafe deserialization (pickle/marshal/yaml.load)", 1.00, SeverityLevel.CRITICAL))
        p.append(c("DATA-011", r"\beval\s*\(|exec\s*\(", "Dynamic code execution (eval/exec)", 0.95, SeverityLevel.CRITICAL))
        p.append(c("DATA-012", r"(xmlrpc|xml\.etree|lxml|defusedxml)", "XML parser change (XXE risk)", 0.80, SeverityLevel.HIGH))
        p.append(c("DATA-013", r"(json\.loads|JSON\.parse)\s*\(", "JSON deserialization change", 0.65, SeverityLevel.LOW))
        p.append(c("DATA-014", r"(deserializ|unmarshal|from_json|from_yaml)\s*\(", "Generic deserialization call change", 0.78, SeverityLevel.MEDIUM))

        # DB queries / SQL injection surface
        p.append(c("DATA-020", r"(cursor\.execute|session\.execute|db\.query|raw\s*\()\s*\(", "Raw DB query execution change", 0.85, SeverityLevel.HIGH))
        p.append(c("DATA-021", r"(f['\"].*SELECT|f['\"].*INSERT|f['\"].*UPDATE|f['\"].*DELETE)", "F-string SQL construction (injection risk)", 0.92, SeverityLevel.CRITICAL))
        p.append(c("DATA-022", r"(%s|%d|format\(\)).*?(SELECT|INSERT|UPDATE|DELETE|WHERE)", "String-formatted SQL (injection risk)", 0.90, SeverityLevel.CRITICAL))
        p.append(c("DATA-023", r"\.(filter|where|having)\s*\(", "ORM filter clause change", 0.72, SeverityLevel.MEDIUM))
        p.append(c("DATA-024", r"(GRANT|REVOKE|DROP TABLE|CREATE USER|ALTER USER)\b", "Privileged DDL/DCL statement change", 0.90, SeverityLevel.HIGH))

        # Output encoding / XSS
        p.append(c("DATA-030", r"(mark_safe||escape_html|autoescape|sanitize)\s*\(", "HTML escaping/sanitization change", 0.83, SeverityLevel.HIGH))
        p.append(c("DATA-031", r"(innerHTML|outerHTML|document\.write)\s*[=+]", "DOM XSS sink modification", 0.90, SeverityLevel.HIGH))
        p.append(c("DATA-032", r"(dangerouslySetInnerHTML|v-html)\s*[={]", "React/Vue dangerous HTML change", 0.92, SeverityLevel.HIGH))

        # File operations
        p.append(c("DATA-040", r"(open\s*\(|fopen|file_get_contents|readFile)\s*\(", "File open operation change", 0.68, SeverityLevel.MEDIUM))
        p.append(c("DATA-041", r"(os\.path\.join|Path\s*\()\s*\(.*\.\.", "Path traversal pattern", 0.85, SeverityLevel.HIGH))
        p.append(c("DATA-042", r"(upload|store|save)\s*.*\.(exe|sh|php|py|js|bat|cmd)\b", "Executable file upload/storage", 0.88, SeverityLevel.HIGH))

        # SSRF / request forgery
        p.append(c("DATA-050", r"(requests\.get|requests\.post|urllib\.request|fetch|axios)\s*\(", "Outbound HTTP request change (SSRF risk)", 0.70, SeverityLevel.MEDIUM))
        p.append(c("DATA-051", r"(user_input|request\.args|request\.form|req\.body|req\.query)\s*.*https?://", "User-controlled URL in request (SSRF)", 0.90, SeverityLevel.HIGH))

    # ------------------------------------------------------------------
    # API surface patterns
    # ------------------------------------------------------------------

    def _build_api_surface_patterns(self) -> None:
        p = self._api_surface_patterns
        c = self._c

        # New endpoints (Python/FastAPI/Flask/Django)
        p.append(c("API-001", r"@(app|router|blueprint)\.(get|post|put|patch|delete|head|options)\s*\(", "HTTP route decorator change", 0.88, SeverityLevel.HIGH))
        p.append(c("API-002", r"@(api_view|permission_classes|authentication_classes)\s*\(", "DRF view/permission decorator change", 0.87, SeverityLevel.HIGH))
        p.append(c("API-003", r"path\s*\(|url\s*\(|include\s*\(", "URL routing configuration change", 0.80, SeverityLevel.MEDIUM))

        # Express.js / Node routes
        p.append(c("API-010", r"(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]", "Express route handler change", 0.87, SeverityLevel.HIGH))
        p.append(c("API-011", r"express\.Router\s*\(\s*\)", "Express Router instantiation change", 0.80, SeverityLevel.MEDIUM))

        # Java (Spring Boot)
        p.append(c("API-020", r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(", "Spring MVC mapping annotation change", 0.88, SeverityLevel.HIGH))
        p.append(c("API-021", r"@(PreAuthorize|Secured|RolesAllowed)\s*\(", "Spring Security method security change", 0.92, SeverityLevel.HIGH))

        # Go (gin/echo/chi)
        p.append(c("API-030", r"\.(GET|POST|PUT|PATCH|DELETE|Any)\s*\(\s*['\"]", "Go HTTP handler registration change", 0.87, SeverityLevel.HIGH))
        p.append(c("API-031", r"(Handle|HandleFunc)\s*\(\s*['\"]", "Go net/http handler change", 0.82, SeverityLevel.MEDIUM))

        # Auth requirement removals / additions
        p.append(c("API-040", r"(AllowAnonymous|no_auth|public_endpoint|skip_authentication)", "Endpoint authentication requirement removed", 0.95, SeverityLevel.CRITICAL))
        p.append(c("API-041", r"(require_login|login_required|authenticate|IsAuthenticated)\s*[=:(]", "Auth requirement on endpoint changed", 0.88, SeverityLevel.HIGH))
        p.append(c("API-042", r"(CORS|cors|cross_origin)\s*[=(.]", "CORS policy change", 0.85, SeverityLevel.HIGH))
        p.append(c("API-043", r"(allow_methods|allow_origins|allow_headers|expose_headers)\s*[=:]", "CORS header configuration change", 0.83, SeverityLevel.HIGH))
        p.append(c("API-044", r"allow_origins\s*=\s*[\[\"']\s*\*\s*[\]\"']", "CORS wildcard origin (allow all)", 0.97, SeverityLevel.CRITICAL))

        # Rate limiting
        p.append(c("API-050", r"(rate_limit|throttle|ratelimiter|RateLimiter)\s*[=(.]", "Rate limiting configuration change", 0.80, SeverityLevel.MEDIUM))
        p.append(c("API-051", r"(max_requests|requests_per_second|burst_limit)\s*=\s*\d+", "Rate limit threshold change", 0.78, SeverityLevel.MEDIUM))

        # GraphQL
        p.append(c("API-060", r"(graphql|GraphQL|gql)\s*[.(=]", "GraphQL schema/resolver change", 0.80, SeverityLevel.MEDIUM))
        p.append(c("API-061", r"(depth_limit|complexity_limit|introspection)\s*[=:]", "GraphQL security control change", 0.87, SeverityLevel.HIGH))

        # WebSockets
        p.append(c("API-070", r"(websocket|WebSocket|ws://|wss://)\s*[=(.]", "WebSocket handler/config change", 0.78, SeverityLevel.MEDIUM))

    # ------------------------------------------------------------------
    # Dependency patterns
    # ------------------------------------------------------------------

    def _build_dependency_patterns(self) -> None:
        p = self._dependency_patterns
        c = self._c

        # Python
        p.append(c("DEP-001", r"^[\+\-]\s*([\w\-]+)\s*(==|>=|<=|~=|!=|>|<)\s*([\d\.]+)", "Python package version change (requirements.txt)", 0.88, SeverityLevel.MEDIUM))
        p.append(c("DEP-002", r"install_requires\s*=\s*\[", "Python setup.py dependency list change", 0.85, SeverityLevel.MEDIUM))
        p.append(c("DEP-003", r"\[tool\.poetry\.(dependencies|dev-dependencies)\]", "Poetry dependency section change", 0.85, SeverityLevel.MEDIUM))

        # Node / npm / yarn
        p.append(c("DEP-010", r'"(dependencies|devDependencies|peerDependencies)"\s*:', "Node package.json dependency block change", 0.87, SeverityLevel.MEDIUM))
        p.append(c("DEP-011", r'"(resolved|integrity)"\s*:', "npm lock file hash change (supply chain)", 0.90, SeverityLevel.HIGH))
        p.append(c("DEP-012", r'"version"\s*:\s*"([^"]+)"', "Package version change in lock file", 0.83, SeverityLevel.MEDIUM))

        # Java / Maven / Gradle
        p.append(c("DEP-020", r"<(groupId|artifactId|version)>", "Maven dependency coordinates change", 0.85, SeverityLevel.MEDIUM))
        p.append(c("DEP-021", r"(implementation|compile|testImplementation|api)\s+['\"]", "Gradle dependency declaration change", 0.83, SeverityLevel.MEDIUM))

        # Go modules
        p.append(c("DEP-030", r"^(require|replace)\s+\(", "Go module require/replace change", 0.85, SeverityLevel.MEDIUM))
        p.append(c("DEP-031", r"^\+?\s*([\w./\-]+)\s+v[\d.]+", "Go module version pin change", 0.82, SeverityLevel.MEDIUM))

        # Rust
        p.append(c("DEP-040", r"\[dependencies\]|\[dev-dependencies\]", "Cargo.toml dependency section change", 0.83, SeverityLevel.MEDIUM))

        # Known vulnerable patterns
        p.append(c("DEP-100", r"(log4j|log4shell|log4j2)\s*(:|==|>=)", "Log4j dependency (known critical CVEs)", 1.00, SeverityLevel.CRITICAL))
        p.append(c("DEP-101", r"(lodash|moment|express)\s*<\s*[\d.]+", "Known-vulnerable package version range", 0.88, SeverityLevel.HIGH))
        p.append(c("DEP-102", r"(struts2?|struts)\s*(:|==|>=)", "Apache Struts dependency (CVE history)", 0.90, SeverityLevel.HIGH))
        p.append(c("DEP-103", r"(openssl|libssl)\s*(:|==|>=)", "OpenSSL version change", 0.87, SeverityLevel.HIGH))

    # ------------------------------------------------------------------
    # Infrastructure patterns
    # ------------------------------------------------------------------

    def _build_infra_patterns(self) -> None:
        p = self._infra_patterns
        c = self._c

        # Docker
        p.append(c("INFRA-001", r"^FROM\s+", "Dockerfile base image change", 0.88, SeverityLevel.HIGH))
        p.append(c("INFRA-002", r"^USER\s+root|^USER\s+0\b", "Container running as root", 0.95, SeverityLevel.HIGH))
        p.append(c("INFRA-003", r"^(RUN|CMD|ENTRYPOINT)\s+", "Dockerfile execution command change", 0.82, SeverityLevel.MEDIUM))
        p.append(c("INFRA-004", r"^EXPOSE\s+", "Dockerfile port exposure change", 0.80, SeverityLevel.MEDIUM))
        p.append(c("INFRA-005", r"(curl|wget|apt-get|apk add)\s+", "Package installation in Dockerfile", 0.78, SeverityLevel.MEDIUM))
        p.append(c("INFRA-006", r"(--no-verify|--allow-unauthenticated|--insecure)", "Insecure package installation flag", 0.92, SeverityLevel.HIGH))
        p.append(c("INFRA-007", r"(ENV|ARG)\s+(PASSWORD|SECRET|KEY|TOKEN|API_KEY)\s*=", "Sensitive env var in Dockerfile", 0.95, SeverityLevel.CRITICAL))

        # Terraform
        p.append(c("INFRA-010", r"(publicly_accessible|public_access)\s*=\s*true", "Resource publicly accessible enabled", 0.97, SeverityLevel.CRITICAL))
        p.append(c("INFRA-011", r"(cidr_block|ingress)\s*=\s*['\"]0\.0\.0\.0/0['\"]", "Network open to all traffic (0.0.0.0/0)", 0.97, SeverityLevel.CRITICAL))
        p.append(c("INFRA-012", r"(encryption|encrypted)\s*=\s*(false|0)", "Storage/resource encryption disabled", 1.00, SeverityLevel.CRITICAL))
        p.append(c("INFRA-013", r"(deletion_protection|termination_protection)\s*=\s*(false|0)", "Deletion protection disabled", 0.88, SeverityLevel.HIGH))
        p.append(c("INFRA-014", r"(iam_role|service_account|assume_role)\s*[={]", "IAM role/service account change", 0.87, SeverityLevel.HIGH))
        p.append(c("INFRA-015", r"(acl|bucket_policy|policy_document)\s*[={]", "Access control policy change", 0.87, SeverityLevel.HIGH))
        p.append(c("INFRA-016", r"(\"Effect\"\s*:\s*\"Allow\"|Effect\s*=\s*\"Allow\")", "IAM Allow policy statement change", 0.85, SeverityLevel.HIGH))
        p.append(c("INFRA-017", r"(\"Action\"\s*:\s*\"\*\"|Action\s*=\s*\[.*\*)", "Wildcard IAM action (privilege escalation risk)", 0.97, SeverityLevel.CRITICAL))
        p.append(c("INFRA-018", r"(\"Principal\"\s*:\s*\"\*\"|Principal\s*=\s*\"\*\")", "Wildcard IAM principal (public access)", 1.00, SeverityLevel.CRITICAL))

        # Kubernetes
        p.append(c("INFRA-020", r"(privileged|hostPID|hostNetwork|hostIPC)\s*:\s*true", "Kubernetes privileged/host access enabled", 1.00, SeverityLevel.CRITICAL))
        p.append(c("INFRA-021", r"(allowPrivilegeEscalation)\s*:\s*true", "Kubernetes privilege escalation allowed", 0.97, SeverityLevel.CRITICAL))
        p.append(c("INFRA-022", r"(runAsNonRoot|readOnlyRootFilesystem)\s*:\s*false", "Kubernetes security context weakened", 0.90, SeverityLevel.HIGH))
        p.append(c("INFRA-023", r"(securityContext|podSecurityPolicy|PodSecurityContext)\s*:", "Kubernetes security context change", 0.85, SeverityLevel.HIGH))
        p.append(c("INFRA-024", r"(ServiceAccount|serviceAccountName)\s*:", "Kubernetes service account change", 0.82, SeverityLevel.MEDIUM))
        p.append(c("INFRA-025", r"(NetworkPolicy|networkPolicy)\s*:", "Kubernetes network policy change", 0.83, SeverityLevel.MEDIUM))
        p.append(c("INFRA-026", r"(Role|ClusterRole|RoleBinding|ClusterRoleBinding)\s*:", "Kubernetes RBAC resource change", 0.87, SeverityLevel.HIGH))

        # CI/CD
        p.append(c("INFRA-030", r"(secrets\.|vars\.|env\.)(GITHUB_TOKEN|DEPLOY_KEY|AWS_|GCP_|AZURE_)", "CI/CD secrets reference change", 0.88, SeverityLevel.HIGH))
        p.append(c("INFRA-031", r"(runs-on|run:|uses:)\s*", "GitHub Actions runner/step change", 0.72, SeverityLevel.LOW))
        p.append(c("INFRA-032", r"(upload-artifact|download-artifact|actions/checkout)", "CI/CD artifact/checkout step change", 0.75, SeverityLevel.MEDIUM))
        p.append(c("INFRA-033", r"(permissions:|id-token:)\s*write", "CI/CD permission escalation (write)", 0.90, SeverityLevel.HIGH))
        p.append(c("INFRA-034", r"(curl|wget|bash)\s*<\s*\(curl|bash\s+-c\s+['\"]curl", "Script injection via curl|bash pipe", 0.93, SeverityLevel.CRITICAL))
        p.append(c("INFRA-035", r"\$\{\{.*github\.event\.(issue|comment|pull_request)\.body", "GitHub Actions untrusted input injection", 0.95, SeverityLevel.CRITICAL))

    def get_patterns_for_category(
        self, category: ChangeCategory
    ) -> List[Tuple[str, re.Pattern, str, float, SeverityLevel]]:
        """Return all patterns for the given category."""
        mapping = {
            ChangeCategory.AUTH: self._auth_patterns,
            ChangeCategory.CRYPTO: self._crypto_patterns,
            ChangeCategory.DATA_FLOW: self._data_flow_patterns,
            ChangeCategory.API_SURFACE: self._api_surface_patterns,
            ChangeCategory.DEPENDENCY: self._dependency_patterns,
            ChangeCategory.INFRASTRUCTURE: self._infra_patterns,
        }
        return mapping.get(category, [])

    def get_all_patterns(
        self,
    ) -> List[Tuple[str, re.Pattern, str, float, ChangeCategory, SeverityLevel]]:
        """Return all patterns from all categories with their category tag."""
        result: List[Tuple[str, re.Pattern, str, float, ChangeCategory, SeverityLevel]] = []
        for cat, patterns in [
            (ChangeCategory.AUTH, self._auth_patterns),
            (ChangeCategory.CRYPTO, self._crypto_patterns),
            (ChangeCategory.DATA_FLOW, self._data_flow_patterns),
            (ChangeCategory.API_SURFACE, self._api_surface_patterns),
            (ChangeCategory.DEPENDENCY, self._dependency_patterns),
            (ChangeCategory.INFRASTRUCTURE, self._infra_patterns),
        ]:
            for pid, regex, desc, conf, sev in patterns:
                result.append((pid, regex, desc, conf, cat, sev))
        return result


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------

# Extension to language mapping
_EXTENSION_TO_LANGUAGE: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".dockerfile": "dockerfile",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".xml": "xml",
    ".gradle": "gradle",
    ".groovy": "groovy",
    ".kt": "kotlin",
    ".scala": "scala",
    ".swift": "swift",
    ".mod": "go",
    ".sum": "go",
}

# Filename patterns (basename) to language
_FILENAME_TO_LANGUAGE: Dict[str, str] = {
    "dockerfile": "dockerfile",
    "docker-compose.yml": "yaml",
    "docker-compose.yaml": "yaml",
    "package.json": "json",
    "package-lock.json": "json",
    "yarn.lock": "yaml",
    "requirements.txt": "python-deps",
    "requirements-dev.txt": "python-deps",
    "pipfile": "python-deps",
    "pipfile.lock": "python-deps",
    "setup.py": "python",
    "setup.cfg": "python-deps",
    "pyproject.toml": "python-deps",
    "go.mod": "go-deps",
    "go.sum": "go-deps",
    "cargo.toml": "rust-deps",
    "cargo.lock": "rust-deps",
    "pom.xml": "xml",
    "build.gradle": "gradle",
    "gemfile": "ruby-deps",
    "gemfile.lock": "ruby-deps",
    ".github/workflows": "yaml",
    "kubernetes": "yaml",
    "k8s": "yaml",
}

# File sensitivity scores for risk weighting (0.0–1.0)
_SENSITIVITY_SCORES: Dict[str, float] = {
    "auth": 1.0,
    "login": 1.0,
    "security": 1.0,
    "password": 1.0,
    "secret": 1.0,
    "token": 0.95,
    "session": 0.95,
    "oauth": 1.0,
    "saml": 1.0,
    "jwt": 1.0,
    "crypto": 0.95,
    "encrypt": 0.95,
    "decrypt": 0.95,
    "key": 0.90,
    "cert": 0.90,
    "route": 0.85,
    "router": 0.85,
    "controller": 0.85,
    "view": 0.80,
    "middleware": 0.85,
    "permission": 0.90,
    "rbac": 0.95,
    "acl": 0.90,
    "model": 0.75,
    "schema": 0.75,
    "serializ": 0.80,
    "migrat": 0.78,
    "db": 0.80,
    "database": 0.80,
    "sql": 0.85,
    "query": 0.80,
    "config": 0.85,
    "settings": 0.85,
    "env": 0.88,
    "vault": 0.95,
    "deploy": 0.80,
    "dockerfile": 0.85,
    "terraform": 0.90,
    "k8s": 0.90,
    "kubernetes": 0.90,
    "ci": 0.80,
    "workflow": 0.82,
    "github": 0.78,
    "util": 0.60,
    "helper": 0.55,
    "test": 0.40,
    "spec": 0.40,
    "mock": 0.35,
    "fixture": 0.35,
}


def detect_language(path: str) -> str:
    """Detect programming language from file path.

    Args:
        path: File path (relative or absolute).

    Returns:
        Language identifier string (e.g. 'python', 'javascript', 'yaml').
        Falls back to 'unknown' for unrecognized extensions.
    """
    path_lower = path.lower()
    basename = Path(path_lower).name

    # Exact filename match
    if basename in _FILENAME_TO_LANGUAGE:
        return _FILENAME_TO_LANGUAGE[basename]

    # Path segment match (e.g. contains ".github/workflows")
    for segment, lang in _FILENAME_TO_LANGUAGE.items():
        if segment in path_lower:
            return lang

    # Extension match
    suffix = Path(path_lower).suffix
    if suffix in _EXTENSION_TO_LANGUAGE:
        return _EXTENSION_TO_LANGUAGE[suffix]

    return "unknown"


def file_sensitivity_score(path: str) -> float:
    """Score file sensitivity based on path components (0.0–1.0).

    Security-critical files (auth, crypto, routes) score closer to 1.0;
    test/utility files score lower.

    Args:
        path: Relative file path.

    Returns:
        Float sensitivity score.
    """
    path_lower = path.lower()
    max_score = 0.50  # default for unrecognized files
    for keyword, score in _SENSITIVITY_SCORES.items():
        if keyword in path_lower:
            if score > max_score:
                max_score = score
    return max_score


# ---------------------------------------------------------------------------
# Diff Parser
# ---------------------------------------------------------------------------


class DiffParser:
    """Parse unified diff text into structured FileDiff / DiffHunk objects.

    Handles standard ``git diff`` output (``diff --git a/... b/...``) as well as
    plain ``diff -u`` output.  Supports binary file markers, rename detection,
    and new/deleted file markers.

    Example::

        parser = DiffParser()
        files = parser.parse(raw_diff_text)
        for f in files:
            print(f.path, f.total_churn)
    """

    # Patterns for diff meta-headers
    _DIFF_HEADER = re.compile(r"^diff --git a/(.*?) b/(.*)$")
    _OLD_FILE = re.compile(r"^--- a/(.*?)$")
    _NEW_FILE = re.compile(r"^\+\+\+ b/(.*?)$")
    _HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    _NEW_FILE_MODE = re.compile(r"^new file mode")
    _DELETED_FILE_MODE = re.compile(r"^deleted file mode")
    _RENAME_FROM = re.compile(r"^rename from (.*)")
    _RENAME_TO = re.compile(r"^rename to (.*)")
    _BINARY = re.compile(r"^Binary files")

    def parse(self, raw_diff: str) -> List[FileDiff]:
        """Parse a unified diff string into a list of FileDiff objects.

        Args:
            raw_diff: Raw unified diff text, typically from ``git diff``.

        Returns:
            List of FileDiff objects, one per changed file.
        """
        if not raw_diff or not raw_diff.strip():
            return []

        files: List[FileDiff] = []
        current_file: Optional[FileDiff] = None
        current_hunks: List[DiffHunk] = []
        current_hunk: Optional[DiffHunk] = None
        current_raw_lines: List[str] = []
        file_raw_lines: List[str] = []

        # Metadata state
        is_new_file = False
        is_deleted = False
        is_rename = False
        rename_to = ""
        old_path = ""
        new_path = ""

        lines = raw_diff.splitlines(keepends=True)

        def flush_hunk() -> None:
            nonlocal current_hunk
            if current_hunk is not None:
                current_hunk.raw = "".join(current_raw_lines)
                current_hunks.append(current_hunk)
                current_hunk = None
                current_raw_lines.clear()

        def flush_file() -> None:
            nonlocal current_file
            if current_file is not None:
                flush_hunk()
                current_file.hunks = list(current_hunks)
                current_file.raw = "".join(file_raw_lines)
                files.append(current_file)
                current_hunks.clear()
                file_raw_lines.clear()
            current_file = None

        for line in lines:
            stripped = line.rstrip("\n").rstrip("\r")

            # New diff block
            m = self._DIFF_HEADER.match(stripped)
            if m:
                flush_file()
                is_new_file = False
                is_deleted = False
                is_rename = False
                rename_to = ""
                old_path = m.group(1)
                new_path = m.group(2)
                file_raw_lines.append(line)
                continue

            if self._NEW_FILE_MODE.match(stripped):
                is_new_file = True
                file_raw_lines.append(line)
                continue

            if self._DELETED_FILE_MODE.match(stripped):
                is_deleted = True
                file_raw_lines.append(line)
                continue

            m = self._RENAME_FROM.match(stripped)
            if m:
                is_rename = True
                m.group(1)
                file_raw_lines.append(line)
                continue

            m = self._RENAME_TO.match(stripped)
            if m:
                rename_to = m.group(1)
                new_path = rename_to
                file_raw_lines.append(line)
                continue

            if self._BINARY.match(stripped):
                file_raw_lines.append(line)
                # Create a binary file entry with no hunks
                flush_file()
                bin_file = FileDiff(
                    path=new_path or old_path,
                    old_path=old_path,
                    language=detect_language(new_path or old_path),
                    is_new_file=is_new_file,
                    is_deleted_file=is_deleted,
                    is_rename=is_rename,
                    hunks=[],
                    raw=line,
                )
                files.append(bin_file)
                continue

            m = self._OLD_FILE.match(stripped)
            if m:
                old_path = m.group(1) if m.group(1) != "/dev/null" else ""
                file_raw_lines.append(line)
                # Materialize the FileDiff now that we have path info
                if current_file is None:
                    fp = new_path or old_path
                    current_file = FileDiff(
                        path=fp,
                        old_path=old_path,
                        language=detect_language(fp),
                        is_new_file=is_new_file,
                        is_deleted_file=is_deleted,
                        is_rename=is_rename,
                        hunks=[],
                    )
                continue

            m = self._NEW_FILE.match(stripped)
            if m:
                new_path_candidate = m.group(1) if m.group(1) != "/dev/null" else ""
                if new_path_candidate:
                    new_path = new_path_candidate
                file_raw_lines.append(line)
                if current_file is None:
                    fp = new_path or old_path
                    current_file = FileDiff(
                        path=fp,
                        old_path=old_path,
                        language=detect_language(fp),
                        is_new_file=is_new_file,
                        is_deleted_file=is_deleted,
                        is_rename=is_rename,
                        hunks=[],
                    )
                else:
                    current_file.path = new_path or old_path
                    current_file.language = detect_language(current_file.path)
                continue

            # Hunk header
            m = self._HUNK_HEADER.match(stripped)
            if m:
                flush_hunk()
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                current_hunk = DiffHunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    added_lines=[],
                    removed_lines=[],
                    context_lines=[],
                )
                current_raw_lines.append(line)
                file_raw_lines.append(line)
                continue

            # Diff content lines
            if current_hunk is not None:
                current_raw_lines.append(line)
                file_raw_lines.append(line)
                if stripped.startswith("+") and not stripped.startswith("+++"):
                    current_hunk.added_lines.append(stripped[1:])
                elif stripped.startswith("-") and not stripped.startswith("---"):
                    current_hunk.removed_lines.append(stripped[1:])
                else:
                    current_hunk.context_lines.append(stripped[1:] if stripped.startswith(" ") else stripped)
            elif current_file is not None:
                file_raw_lines.append(line)

        flush_file()
        return files


# ---------------------------------------------------------------------------
# AST Analyzer (Python)
# ---------------------------------------------------------------------------


class PythonASTAnalyzer:
    """Deep Python AST analysis for semantic security change detection.

    Supplements regex-based matching with structural analysis of Python
    source code to identify decorator changes, function signature changes,
    import additions, and class hierarchy changes.

    Only invoked when the changed file is identified as Python.
    """

    def analyze_added_code(self, code: str) -> List[Dict[str, Any]]:
        """Analyze newly added Python code via AST for security patterns.

        Args:
            code: Python source code snippet (may be incomplete).

        Returns:
            List of finding dicts with keys: finding_type, detail, line.
        """
        findings: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings  # Incomplete snippet — skip silently

        for node in ast.walk(tree):
            # Dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in ("eval", "exec", "compile", "__import__"):
                    findings.append({"finding_type": "dangerous_call", "detail": f"Call to {func_name}()", "line": node.lineno})
                if func_name in ("pickle.loads", "marshal.loads", "shelve.open"):
                    findings.append({"finding_type": "unsafe_deserialization", "detail": f"Unsafe deserialization: {func_name}()", "line": node.lineno})
                if func_name in ("subprocess.call", "subprocess.run", "os.system", "os.popen"):
                    findings.append({"finding_type": "shell_injection_risk", "detail": f"Shell execution: {func_name}()", "line": node.lineno})

            # Import additions
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = self._get_import_module(node)
                if module in ("pickle", "marshal", "shelve", "subprocess", "ctypes"):
                    findings.append({"finding_type": "dangerous_import", "detail": f"Import of risky module: {module}", "line": node.lineno})

            # Decorator changes
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    dec_name = self._get_decorator_name(decorator)
                    if "login_required" in dec_name or "auth" in dec_name:
                        findings.append({"finding_type": "auth_decorator", "detail": f"Auth decorator on {node.name}: @{dec_name}", "line": node.lineno})
                    if "permission" in dec_name or "role" in dec_name:
                        findings.append({"finding_type": "permission_decorator", "detail": f"Permission decorator on {node.name}: @{dec_name}", "line": node.lineno})

            # Password/secret assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = self._get_assign_target_name(target)
                    if name and any(kw in name.lower() for kw in ("password", "secret", "key", "token", "salt")):
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            findings.append({"finding_type": "hardcoded_secret", "detail": f"Hardcoded secret in {name}", "line": node.lineno})

        return findings

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract callable name string from an AST Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            cur: Any = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return ""

    def _get_import_module(self, node: Any) -> str:
        """Extract module name from Import or ImportFrom AST node."""
        if isinstance(node, ast.Import):
            return node.names[0].name if node.names else ""
        if isinstance(node, ast.ImportFrom):
            return node.module or ""
        return ""

    def _get_decorator_name(self, node: Any) -> str:
        """Extract decorator name string from an AST decorator node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_decorator_name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return ""

    def _get_assign_target_name(self, node: Any) -> Optional[str]:
        """Get assignment target name string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


# ---------------------------------------------------------------------------
# Risk Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Multi-factor risk scoring engine for individual material changes.

    The final score (0–100) is a weighted combination of:

    1. **Category weight** — Auth changes score highest (1.0), infra lowest (0.6).
    2. **Churn size factor** — Logarithmically scaled change size contribution.
    3. **File sensitivity** — Path-based sensitivity multiplier (0.5–1.0).
    4. **Severity level** — CRITICAL=1.0, HIGH=0.8, MEDIUM=0.5, LOW=0.3, INFO=0.1.
    5. **Confidence** — Pattern match confidence 0.0–1.0.
    6. **Historical vuln density** — Optional per-file historical vulnerability weight.
    7. **New-file bonus** — New files are higher risk (unconstrained patterns).
    8. **Deletion penalty** — Removing auth/validation code is high risk.
    """

    _CATEGORY_WEIGHTS: Dict[ChangeCategory, float] = {
        ChangeCategory.AUTH: 1.0,
        ChangeCategory.CRYPTO: 0.92,
        ChangeCategory.DATA_FLOW: 0.85,
        ChangeCategory.API_SURFACE: 0.80,
        ChangeCategory.DEPENDENCY: 0.70,
        ChangeCategory.INFRASTRUCTURE: 0.75,
        ChangeCategory.UNKNOWN: 0.40,
    }

    _SEVERITY_WEIGHTS: Dict[SeverityLevel, float] = {
        SeverityLevel.CRITICAL: 1.00,
        SeverityLevel.HIGH: 0.80,
        SeverityLevel.MEDIUM: 0.55,
        SeverityLevel.LOW: 0.30,
        SeverityLevel.INFO: 0.10,
    }

    def score(
        self,
        category: ChangeCategory,
        severity: SeverityLevel,
        churn: int,
        file_path: str,
        confidence: float,
        is_new_file: bool = False,
        is_deletion: bool = False,
        vuln_density: float = 0.0,
    ) -> float:
        """Compute a 0–100 risk score for a single material change.

        Args:
            category: Security category of the change.
            severity: Severity of the pattern that triggered detection.
            churn: Lines added + removed.
            file_path: Relative file path (for sensitivity scoring).
            confidence: Pattern match confidence (0.0–1.0).
            is_new_file: Whether this is a newly created file.
            is_deletion: Whether auth/validation code is being deleted.
            vuln_density: Historical vulnerability density for this file (0.0–1.0).

        Returns:
            Float risk score in [0, 100].
        """
        cat_w = self._CATEGORY_WEIGHTS.get(category, 0.5)
        sev_w = self._SEVERITY_WEIGHTS.get(severity, 0.5)
        sensitivity = file_sensitivity_score(file_path)

        # Logarithmic churn factor: 0 lines → 0.1, 10 lines → 0.4, 100 lines → 0.7
        churn_factor = min(1.0, 0.1 + 0.3 * math.log1p(max(0, churn)) / math.log1p(100))

        # Historical vulnerability density boosts score
        vuln_boost = 1.0 + (0.25 * min(1.0, vuln_density))

        # New file and deletion modifiers
        new_file_bonus = 1.15 if is_new_file else 1.0
        deletion_penalty = 1.20 if is_deletion else 1.0

        raw = (
            cat_w * 0.30
            + sev_w * 0.30
            + sensitivity * 0.15
            + churn_factor * 0.10
            + confidence * 0.15
        )

        score = raw * 100 * vuln_boost * new_file_bonus * deletion_penalty
        return round(min(100.0, score), 2)

    def aggregate_pr_score(self, change_scores: List[float]) -> float:
        """Aggregate individual change scores into an overall PR risk score.

        Uses a weighted percentile approach — the maximum score dominates
        but average also contributes, avoiding both over- and under-reporting.

        Args:
            change_scores: List of 0–100 scores for individual material changes.

        Returns:
            Aggregated 0–100 PR risk score.
        """
        if not change_scores:
            return 0.0
        max_score = max(change_scores)
        avg_score = sum(change_scores) / len(change_scores)
        # Weight: 60% max, 40% average — high-risk outliers dominate
        aggregate = 0.60 * max_score + 0.40 * avg_score
        # Boost slightly for breadth (many material changes in one PR)
        breadth_bonus = min(10.0, len(change_scores) * 0.5)
        return round(min(100.0, aggregate + breadth_bonus), 2)


# ---------------------------------------------------------------------------
# Semantic Classifier
# ---------------------------------------------------------------------------


class SemanticClassifier:
    """Classify changes as BREAKING, MATERIAL, or COSMETIC.

    Classification logic:
    - **BREAKING**: Score >= 75 OR contains CRITICAL pattern OR auth
      removal/bypass/weakening detected on removed lines.
    - **MATERIAL**: Score >= 35 OR category is security-relevant and
      confidence >= 0.7.
    - **COSMETIC**: Everything else (comments, whitespace, test files,
      documentation, formatting-only changes).
    """

    _COSMETIC_INDICATORS = [
        re.compile(r"^\s*#"),          # Comments
        re.compile(r"^\s*//"),         # JS/Java comments
        re.compile(r"^\s*/\*"),        # Block comment open
        re.compile(r"^\s*\*"),         # Block comment continuation
        re.compile(r"^\s*\*/"),        # Block comment close
        re.compile(r"^\s*$"),          # Blank lines
        re.compile(r'^\s*("""|\'\'\')'), # Python docstrings
        re.compile(r"^\s*(import|from)\s+[\w.]+\s+import\s+\w+\s*$"),  # Simple imports
    ]

    _TEST_PATH_PATTERNS = re.compile(
        r"(test_|_test\.|\.spec\.|\.test\.|/tests?/|/spec/|/__tests__/)",
        re.IGNORECASE,
    )

    def classify(
        self,
        risk_score: float,
        category: ChangeCategory,
        pattern_matches: List[PatternMatch],
        file_path: str,
        churn: int,
        is_new_file: bool = False,
    ) -> ChangeClassification:
        """Classify a change based on risk score and contextual signals.

        Args:
            risk_score: 0–100 computed risk score.
            category: Security category of the change.
            pattern_matches: All pattern matches for this change.
            file_path: File path (used to detect test files).
            churn: Lines changed.
            is_new_file: Whether the file is new.

        Returns:
            ChangeClassification enum value.
        """
        # Test/fixture files are generally lower classification
        is_test_file = bool(self._TEST_PATH_PATTERNS.search(file_path))

        # Check for CRITICAL-severity matches
        any(
            m.pattern_id.endswith("-001") or "CRITICAL" in m.description.upper()
            for m in pattern_matches
        )
        has_critical_sev = any(
            "critical" in m.description.lower() or
            any(kw in m.matched_text.lower() for kw in ("none", "false", "0.0.0.0", "*", "root"))
            for m in pattern_matches
        )

        # Auth bypass / removal patterns on removed lines
        auth_removal = any(
            m.category == ChangeCategory.AUTH and not m.is_addition
            and any(
                kw in m.line_content.lower()
                for kw in ("require_auth", "login_required", "authenticate", "check_permission")
            )
            for m in pattern_matches
        )

        if is_test_file:
            # Even test file changes can be MATERIAL if they remove security tests
            if auth_removal or risk_score >= 85:
                return ChangeClassification.MATERIAL
            if risk_score < 25:
                return ChangeClassification.COSMETIC
            return ChangeClassification.COSMETIC

        # BREAKING: very high risk, critical patterns, or auth removal
        if risk_score >= 75 or has_critical_sev or auth_removal or (is_new_file and risk_score >= 60):
            return ChangeClassification.BREAKING

        # MATERIAL: medium-high risk or security-relevant category with decent confidence
        if risk_score >= 35:
            return ChangeClassification.MATERIAL
        if category in (ChangeCategory.AUTH, ChangeCategory.CRYPTO, ChangeCategory.INFRASTRUCTURE) and risk_score >= 20:
            return ChangeClassification.MATERIAL
        if len(pattern_matches) >= 3 and not is_test_file:
            return ChangeClassification.MATERIAL

        return ChangeClassification.COSMETIC

    def is_cosmetic_only(self, added_lines: List[str], removed_lines: List[str]) -> bool:
        """Return True if all changed lines appear purely cosmetic.

        Checks for comment-only changes, blank lines, and import-only changes.

        Args:
            added_lines: Lines added in this hunk.
            removed_lines: Lines removed in this hunk.

        Returns:
            True if all changes appear cosmetic.
        """
        all_lines = added_lines + removed_lines
        if not all_lines:
            return True
        return all(
            any(pattern.match(line) for pattern in self._COSMETIC_INDICATORS)
            for line in all_lines
            if line.strip()
        )


# ---------------------------------------------------------------------------
# Reviewer Recommendation Engine
# ---------------------------------------------------------------------------


class ReviewerRecommender:
    """Maps detected change categories to recommended reviewer expertise areas.

    In a production deployment this would integrate with org LDAP / GitHub
    CODEOWNERS.  Here it returns expertise area strings that can be matched
    against an org's team registry.
    """

    _CATEGORY_TO_EXPERTISE: Dict[ChangeCategory, List[str]] = {
        ChangeCategory.AUTH: [
            "Identity & Access Management Engineer",
            "Auth Platform Team",
            "Security Engineer (AppSec)",
        ],
        ChangeCategory.CRYPTO: [
            "Cryptography Engineer",
            "Security Engineer (AppSec)",
            "Platform Security Team",
        ],
        ChangeCategory.DATA_FLOW: [
            "Data Security Engineer",
            "Privacy & Compliance Engineer",
            "Backend Security Reviewer",
        ],
        ChangeCategory.API_SURFACE: [
            "API Security Reviewer",
            "Backend Platform Team",
            "Security Engineer (AppSec)",
        ],
        ChangeCategory.DEPENDENCY: [
            "Supply Chain Security Engineer",
            "SCA / Dependency Management Team",
            "DevSecOps Engineer",
        ],
        ChangeCategory.INFRASTRUCTURE: [
            "Cloud Security Engineer",
            "DevSecOps Engineer",
            "Platform Infrastructure Team",
        ],
    }

    _SEVERITY_TO_MANDATORY: Dict[SeverityLevel, bool] = {
        SeverityLevel.CRITICAL: True,
        SeverityLevel.HIGH: True,
        SeverityLevel.MEDIUM: False,
        SeverityLevel.LOW: False,
        SeverityLevel.INFO: False,
    }

    def recommend(
        self,
        categories: List[ChangeCategory],
        severities: Optional[List[SeverityLevel]] = None,
    ) -> List[str]:
        """Return a deduplicated list of recommended reviewer expertise areas.

        Args:
            categories: Distinct categories of changes detected.
            severities: Corresponding severity levels (optional).

        Returns:
            Ordered list of reviewer expertise area strings.
        """
        seen: Set[str] = set()
        result: List[str] = []
        for cat in categories:
            for reviewer in self._CATEGORY_TO_EXPERTISE.get(cat, []):
                if reviewer not in seen:
                    seen.add(reviewer)
                    result.append(reviewer)
        return result


# ---------------------------------------------------------------------------
# Review Checklist Generator
# ---------------------------------------------------------------------------


_CHECKLIST_TEMPLATES: Dict[ChangeCategory, List[str]] = {
    ChangeCategory.AUTH: [
        "Verify that authentication bypass conditions (if any) are intentional and documented.",
        "Check that all new login/logout flows invalidate sessions completely.",
        "Confirm that passwords are hashed using a modern KDF (bcrypt/argon2/scrypt) with adequate cost factor.",
        "Ensure JWT algorithm is not set to 'none'; confirm key validation is enforced.",
        "Validate that OAuth redirect_uri values are strictly allowlisted — not open-redirect.",
        "Confirm OAuth client_secret is not committed to source; verify secret rotation policy.",
        "Ensure MFA is not bypassable via the new code paths.",
        "Review RBAC/permission checks for privilege escalation opportunities.",
        "Verify session cookies set HttpOnly, Secure, and SameSite=Strict/Lax.",
        "Check SAML/SSO assertion signature verification is still enforced.",
    ],
    ChangeCategory.CRYPTO: [
        "Confirm no weak algorithms (MD5, SHA-1, DES, RC4) are used for security purposes.",
        "Verify TLS configuration enforces TLS 1.2+ and disables SSLv2/3/TLS1.0/TLS1.1.",
        "Check that certificate verification (verify_ssl, check_hostname) is enabled in all environments.",
        "Ensure cryptographic keys are not hardcoded — verify key management via secrets manager.",
        "Confirm key sizes meet current standards: RSA≥2048, EC≥256, AES≥128.",
        "Verify KDF iteration counts meet NIST recommendations (PBKDF2≥600000, bcrypt cost≥12).",
        "Check CBC/ECB mode usage — prefer AES-GCM or other AEAD constructions.",
        "Confirm PRNG usage: os.urandom/secrets used for security, not random.random.",
        "Review cipher suite changes for forward secrecy (ECDHE/DHE key exchange).",
    ],
    ChangeCategory.DATA_FLOW: [
        "Verify PII fields are not logged in plaintext — confirm log scrubbing is in place.",
        "Check that deserialization (pickle, yaml.load, marshal) is only applied to trusted data.",
        "Confirm SQL queries use parameterized statements — no string formatting of user input.",
        "Validate that user-controlled input is not used directly in file paths (path traversal).",
        "Review SSRF protections for outbound URL fetches with user-controlled values.",
        "Confirm HTML output is properly escaped; check for new dangerouslySetInnerHTML/v-html usage.",
        "Verify file upload handlers reject executable file types and validate content-type.",
        "Check that eval()/exec() usage is absolutely necessary and input is fully controlled.",
        "Review data masking/tokenization for financial PII (card numbers, bank accounts).",
        "Confirm GDPR/CCPA compliance: new PII fields require data retention policy documentation.",
    ],
    ChangeCategory.API_SURFACE: [
        "Confirm all new endpoints have authentication requirements applied.",
        "Verify CORS policy changes do not introduce wildcard origins in production.",
        "Check that removed auth decorators/middleware are intentional — document reason.",
        "Review rate limiting configuration for new or modified endpoints.",
        "Validate that GraphQL introspection is disabled in production environments.",
        "Confirm new endpoints appear in the API security test suite.",
        "Check HTTP method restrictions — no unintended GET endpoints for state-changing operations.",
        "Review authorization (authz) at the endpoint level — not just authentication (authn).",
        "Verify new WebSocket endpoints authenticate the upgrade handshake.",
        "Check for IDOR vulnerabilities in new endpoint parameter patterns.",
    ],
    ChangeCategory.DEPENDENCY: [
        "Run SCA scan (Snyk/Dependabot/OWASP Dependency Check) on updated dependency manifest.",
        "Verify lock file integrity hashes are updated consistently with manifest changes.",
        "Check that new packages are from trusted publishers — audit npm/PyPI package reputation.",
        "Review changelog/release notes of bumped packages for security-relevant changes.",
        "Confirm no packages known to be deprecated or abandoned are being added.",
        "Verify that dev dependencies are not promoted to production dependencies.",
        "Check for typosquatting: verify exact package names against official registries.",
        "Confirm transitive dependencies do not introduce known CVEs (check SBOM diff).",
        "Review license compatibility for new packages (GPL vs Apache/MIT in commercial products).",
    ],
    ChangeCategory.INFRASTRUCTURE: [
        "Confirm containers do not run as root (USER root in Dockerfile is a finding).",
        "Verify Terraform S3/RDS/storage resources have encryption_at_rest enabled.",
        "Review security group/network policy changes — no 0.0.0.0/0 ingress on sensitive ports.",
        "Check IAM policies for least-privilege: no wildcard (*) Actions or Principals.",
        "Confirm Kubernetes pods have securityContext.runAsNonRoot=true and readOnlyRootFilesystem=true.",
        "Validate that CI/CD secret references are managed via the secrets manager — not env vars.",
        "Review GitHub Actions permission scopes — minimize id-token:write and contents:write.",
        "Check Dockerfile base image for known CVEs — use pinned digests rather than mutable tags.",
        "Confirm deletion_protection/termination_protection is enabled for critical resources.",
        "Review new CI/CD steps for script injection via untrusted GitHub event context variables.",
    ],
}


def generate_review_checklist(categories: List[ChangeCategory]) -> List[str]:
    """Generate a security review checklist for the given change categories.

    Deduplicates items and adds a general section always included.

    Args:
        categories: List of detected change categories.

    Returns:
        Ordered list of review checklist items.
    """
    general = [
        "Ensure the PR description accurately describes the security impact of changes.",
        "Verify that unit/integration tests cover new security-sensitive code paths.",
        "Confirm no secrets, tokens, or private keys are committed in any changed file.",
        "Check that the change does not regress an existing security control.",
    ]
    seen: Set[str] = set(general)
    items = list(general)
    for cat in categories:
        for item in _CHECKLIST_TEMPLATES.get(cat, []):
            if item not in seen:
                seen.add(item)
                items.append(item)
    return items


# ---------------------------------------------------------------------------
# Core Material Change Detector
# ---------------------------------------------------------------------------


class MaterialChangeDetector:
    """Core engine for detecting security-material changes in git diffs.

    Orchestrates the full analysis pipeline:
    1. Parse unified diff → FileDiff objects.
    2. Run PatternLibrary regex matching on each hunk.
    3. Run PythonASTAnalyzer for Python files (deeper semantic analysis).
    4. Score each hit with RiskScorer.
    5. Classify each change with SemanticClassifier.
    6. Assemble MaterialChange objects.

    Attributes:
        pattern_library: Shared PatternLibrary instance.
        risk_scorer: Shared RiskScorer instance.
        classifier: Shared SemanticClassifier instance.
        ast_analyzer: Python AST analyzer.
        reviewer_recommender: Reviewer recommendation engine.
        diff_parser: Unified diff parser.
    """

    def __init__(self) -> None:
        self.pattern_library = PatternLibrary()
        self.risk_scorer = RiskScorer()
        self.classifier = SemanticClassifier()
        self.ast_analyzer = PythonASTAnalyzer()
        self.reviewer_recommender = ReviewerRecommender()
        self.diff_parser = DiffParser()
        self._all_patterns = self.pattern_library.get_all_patterns()

    def analyze_diff(
        self,
        raw_diff: str,
        historical_vuln_density: Optional[Dict[str, float]] = None,
    ) -> List[MaterialChange]:
        """Analyze a unified diff and return all detected material changes.

        Args:
            raw_diff: Raw unified diff text.
            historical_vuln_density: Optional map of file_path → vuln_density (0-1)
                for historical risk boosting.

        Returns:
            List of MaterialChange objects (may include COSMETIC classification).
        """
        if historical_vuln_density is None:
            historical_vuln_density = {}

        parsed_files = self.diff_parser.parse(raw_diff)
        if not parsed_files:
            return []

        all_changes: List[MaterialChange] = []
        for file_diff in parsed_files:
            changes = self._analyze_file_diff(file_diff, historical_vuln_density)
            all_changes.extend(changes)

        return all_changes

    def _analyze_file_diff(
        self,
        file_diff: FileDiff,
        historical_vuln_density: Dict[str, float],
    ) -> List[MaterialChange]:
        """Analyze a single parsed file diff for material changes.

        Args:
            file_diff: Parsed FileDiff object.
            historical_vuln_density: File-level historical vuln density map.

        Returns:
            List of MaterialChange objects for this file.
        """
        changes: List[MaterialChange] = []
        vuln_density = historical_vuln_density.get(file_diff.path, 0.0)

        # Group matches by category for aggregation
        category_matches: DefaultDict[ChangeCategory, List[PatternMatch]] = defaultdict(list)

        for hunk_idx, hunk in enumerate(file_diff.hunks):
            # Check if this hunk is purely cosmetic
            if self.classifier.is_cosmetic_only(hunk.added_lines, hunk.removed_lines):
                continue

            for is_addition, lines in [(True, hunk.added_lines), (False, hunk.removed_lines)]:
                for line in lines:
                    for pid, regex, desc, conf, cat, sev in self._all_patterns:
                        m = regex.search(line)
                        if m:
                            pm = PatternMatch(
                                pattern_id=pid,
                                category=cat,
                                description=desc,
                                matched_text=m.group(0),
                                line_content=line,
                                hunk_index=hunk_idx,
                                is_addition=is_addition,
                                confidence=conf,
                            )
                            category_matches[cat].append(pm)

        # Python AST enhancement
        ast_findings: List[Dict[str, Any]] = []
        if file_diff.language == "python" and file_diff.all_added_text.strip():
            try:
                ast_findings = self.ast_analyzer.analyze_added_code(file_diff.all_added_text)
            except Exception:
                pass

        # Synthesize AST findings into AUTH / DATA_FLOW pattern matches
        for finding in ast_findings:
            ft = finding.get("finding_type", "")
            cat = ChangeCategory.AUTH if "auth" in ft or "secret" in ft else ChangeCategory.DATA_FLOW
            sev_map = {
                "hardcoded_secret": SeverityLevel.CRITICAL,
                "dangerous_call": SeverityLevel.CRITICAL,
                "unsafe_deserialization": SeverityLevel.CRITICAL,
                "shell_injection_risk": SeverityLevel.HIGH,
                "auth_decorator": SeverityLevel.HIGH,
                "permission_decorator": SeverityLevel.HIGH,
                "dangerous_import": SeverityLevel.HIGH,
            }
            sev_map.get(ft, SeverityLevel.MEDIUM)
            pm = PatternMatch(
                pattern_id=f"AST-{ft.upper()[:10]}",
                category=cat,
                description=finding.get("detail", ft),
                matched_text=finding.get("detail", ""),
                line_content=f"[AST line {finding.get('line', '?')}]",
                hunk_index=0,
                is_addition=True,
                confidence=0.90,
            )
            category_matches[cat].append(pm)

        # Create one MaterialChange per triggered category
        for cat, matches in category_matches.items():
            if not matches:
                continue

            # Deduplicate by pattern_id
            seen_pids: Set[str] = set()
            unique_matches: List[PatternMatch] = []
            for pm in matches:
                if pm.pattern_id not in seen_pids:
                    seen_pids.add(pm.pattern_id)
                    unique_matches.append(pm)

            # Pick highest severity from matches
            sev_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
            # Infer severity from pattern IDs
            top_severity = SeverityLevel.MEDIUM
            for pm in unique_matches:
                inferred = self._infer_severity_from_pattern(pm.pattern_id)
                if sev_order.index(inferred) < sev_order.index(top_severity):
                    top_severity = inferred

            # Check if this is a deletion of security controls
            is_deletion = any(not pm.is_addition for pm in unique_matches)

            score = self.risk_scorer.score(
                category=cat,
                severity=top_severity,
                churn=file_diff.total_churn,
                file_path=file_diff.path,
                confidence=max(pm.confidence for pm in unique_matches),
                is_new_file=file_diff.is_new_file,
                is_deletion=is_deletion,
                vuln_density=vuln_density,
            )

            classification = self.classifier.classify(
                risk_score=score,
                category=cat,
                pattern_matches=unique_matches,
                file_path=file_diff.path,
                churn=file_diff.total_churn,
                is_new_file=file_diff.is_new_file,
            )

            summary, explanation = self._build_summary(cat, unique_matches, file_diff)
            reviewers = self.reviewer_recommender.recommend([cat])
            checklist = generate_review_checklist([cat])

            change_id = self._make_change_id(file_diff.path, cat, unique_matches)

            change = MaterialChange(
                change_id=change_id,
                file_path=file_diff.path,
                category=cat,
                classification=classification,
                severity=top_severity,
                risk_score=score,
                summary=summary,
                explanation=explanation,
                pattern_matches=unique_matches,
                recommended_reviewers=reviewers,
                review_items=checklist,
                metadata={
                    "language": file_diff.language,
                    "is_new_file": file_diff.is_new_file,
                    "is_deleted_file": file_diff.is_deleted_file,
                    "is_rename": file_diff.is_rename,
                    "total_churn": file_diff.total_churn,
                    "hunk_count": len(file_diff.hunks),
                    "ast_findings_count": len(ast_findings),
                    "pattern_count": len(unique_matches),
                },
            )
            changes.append(change)

        return changes

    def _infer_severity_from_pattern(self, pattern_id: str) -> SeverityLevel:
        """Infer severity from pattern ID prefix heuristics.

        Looks up the pattern in the library to find its severity.  Falls back
        to MEDIUM for unrecognized IDs.

        Args:
            pattern_id: Pattern identifier string.

        Returns:
            SeverityLevel enum value.
        """
        for pid, _regex, _desc, _conf, _cat, sev in self._all_patterns:
            if pid == pattern_id:
                return sev
        # Heuristic fallback
        if "AST-HARDCODED" in pattern_id or "AST-DANGEROUS" in pattern_id:
            return SeverityLevel.CRITICAL
        if "AST-" in pattern_id:
            return SeverityLevel.HIGH
        return SeverityLevel.MEDIUM

    def _build_summary(
        self,
        category: ChangeCategory,
        matches: List[PatternMatch],
        file_diff: FileDiff,
    ) -> Tuple[str, str]:
        """Build a human-readable summary and detailed explanation.

        Args:
            category: Security category.
            matches: List of pattern matches.
            file_diff: The file diff that triggered this change.

        Returns:
            Tuple of (summary, explanation) strings.
        """
        cat_label = category.value.replace("_", " ").title()
        file_name = Path(file_diff.path).name
        num_patterns = len(matches)

        summary = (
            f"{cat_label} change in {file_name}: "
            f"{num_patterns} security-relevant pattern(s) detected"
        )

        [m.description for m in matches[:5]]
        explanation_lines = [
            f"File: {file_diff.path} ({file_diff.language})",
            f"Change size: +{file_diff.total_added} / -{file_diff.total_removed} lines",
            f"Detected patterns ({num_patterns}):",
        ]
        for i, m in enumerate(matches[:8], 1):
            direction = "added" if m.is_addition else "removed"
            explanation_lines.append(
                f"  {i}. [{m.pattern_id}] {m.description} ({direction}) "
                f"— matched: {m.matched_text[:60]!r}"
            )
        if len(matches) > 8:
            explanation_lines.append(f"  ... and {len(matches) - 8} more pattern(s)")

        return summary, "\n".join(explanation_lines)

    def _make_change_id(
        self,
        file_path: str,
        category: ChangeCategory,
        matches: List[PatternMatch],
    ) -> str:
        """Generate a deterministic change identifier.

        Args:
            file_path: File path string.
            category: Change category.
            matches: Pattern matches list.

        Returns:
            Short hex identifier string.
        """
        key = f"{file_path}:{category.value}:{','.join(sorted(m.pattern_id for m in matches))}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# PR Analyzer
# ---------------------------------------------------------------------------


class PRAnalyzer:
    """Full Pull/Merge Request risk assessment orchestrator.

    Accepts a list of (file_path, unified_diff_text) tuples and produces a
    comprehensive PRRiskAssessment including overall risk score, material
    changes, reviewer recommendations, and review checklist.

    Attributes:
        detector: MaterialChangeDetector instance.
        scorer: RiskScorer instance.
        classifier: SemanticClassifier instance.
    """

    def __init__(self) -> None:
        self.detector = MaterialChangeDetector()
        self.scorer = self.detector.risk_scorer
        self.classifier = self.detector.classifier

    def analyze_pr(
        self,
        pr_id: str,
        file_diffs: List[Dict[str, str]],
        historical_vuln_density: Optional[Dict[str, float]] = None,
    ) -> PRRiskAssessment:
        """Perform full PR risk assessment.

        Args:
            pr_id: PR/MR identifier string.
            file_diffs: List of dicts with keys:
                - ``path``: relative file path
                - ``diff``: unified diff text for this file (optional, use ``raw_diff`` for full diff)
                - ``raw_diff``: alternative full diff block (optional)
            historical_vuln_density: Optional per-file historical vulnerability density.

        Returns:
            PRRiskAssessment with full analysis.
        """
        if historical_vuln_density is None:
            historical_vuln_density = {}

        all_changes: List[MaterialChange] = []
        file_summaries: List[Dict[str, Any]] = []
        total_added = 0
        total_removed = 0
        files_touched = 0
        languages_seen: Set[str] = set()

        for fd in file_diffs:
            path = fd.get("path", "")
            diff_text = fd.get("diff", "") or fd.get("raw_diff", "")

            if not diff_text:
                continue

            files_touched += 1
            lang = detect_language(path)
            languages_seen.add(lang)

            changes = self.detector.analyze_diff(diff_text, historical_vuln_density)
            all_changes.extend(changes)

            file_score = max((c.risk_score for c in changes), default=0.0)
            file_classification = (
                max(
                    (c.classification for c in changes),
                    key=lambda x: {"BREAKING": 3, "MATERIAL": 2, "COSMETIC": 1}[x.value],
                    default=ChangeClassification.COSMETIC,
                )
                if changes else ChangeClassification.COSMETIC
            )

            # Tally churn from all parsed diffs for this file
            parsed = self.detector.diff_parser.parse(diff_text)
            for pf in parsed:
                total_added += pf.total_added
                total_removed += pf.total_removed

            file_summaries.append({
                "path": path,
                "language": lang,
                "risk_score": file_score,
                "classification": file_classification.value,
                "material_changes": len([c for c in changes if c.classification != ChangeClassification.COSMETIC]),
                "sensitivity_score": file_sensitivity_score(path),
            })

        # Aggregate overall score
        non_cosmetic = [c for c in all_changes if c.classification != ChangeClassification.COSMETIC]
        change_scores = [c.risk_score for c in non_cosmetic]
        overall_score = self.scorer.aggregate_pr_score(change_scores)

        # Overall classification
        classifications_seen = {c.classification for c in all_changes}
        if ChangeClassification.BREAKING in classifications_seen:
            overall_classification = ChangeClassification.BREAKING
        elif ChangeClassification.MATERIAL in classifications_seen:
            overall_classification = ChangeClassification.MATERIAL
        else:
            overall_classification = ChangeClassification.COSMETIC

        # Deduplicated reviewers and checklist
        categories_seen = list({c.category for c in non_cosmetic})
        recommended_reviewers = self.detector.reviewer_recommender.recommend(categories_seen)
        review_checklist = generate_review_checklist(categories_seen)

        # Risk breakdown by category
        risk_breakdown: Dict[str, float] = {}
        for cat in ChangeCategory:
            cat_changes = [c for c in non_cosmetic if c.category == cat]
            if cat_changes:
                risk_breakdown[cat.value] = round(
                    max(c.risk_score for c in cat_changes), 2
                )

        stats = {
            "files_analyzed": files_touched,
            "total_added_lines": total_added,
            "total_removed_lines": total_removed,
            "total_churn": total_added + total_removed,
            "material_change_count": len(non_cosmetic),
            "breaking_change_count": len([c for c in all_changes if c.classification == ChangeClassification.BREAKING]),
            "languages": sorted(languages_seen),
            "categories_detected": [c.value for c in categories_seen],
        }

        return PRRiskAssessment(
            pr_id=pr_id,
            overall_risk_score=overall_score,
            classification=overall_classification,
            material_changes=all_changes,
            file_summaries=file_summaries,
            recommended_reviewers=recommended_reviewers,
            review_checklist=review_checklist,
            risk_breakdown=risk_breakdown,
            stats=stats,
        )

    def classify_changes(
        self, file_diffs: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Classify a set of changes without full PR context.

        Useful for lightweight classification of individual files.

        Args:
            file_diffs: List of dicts with path and diff keys.

        Returns:
            Dict with classification_summary and per-file results.
        """
        results = []
        summary_counts: Dict[str, int] = {"BREAKING": 0, "MATERIAL": 0, "COSMETIC": 0}

        for fd in file_diffs:
            path = fd.get("path", "")
            diff_text = fd.get("diff", "") or fd.get("raw_diff", "")
            if not diff_text:
                continue

            changes = self.detector.analyze_diff(diff_text)
            if not changes:
                results.append({"path": path, "classification": "COSMETIC", "changes": []})
                summary_counts["COSMETIC"] += 1
                continue

            top_class = max(
                changes,
                key=lambda c: {"BREAKING": 3, "MATERIAL": 2, "COSMETIC": 1}[c.classification.value],
            ).classification
            summary_counts[top_class.value] += 1

            results.append({
                "path": path,
                "classification": top_class.value,
                "risk_score": max(c.risk_score for c in changes),
                "changes": [
                    {
                        "category": c.category.value,
                        "classification": c.classification.value,
                        "severity": c.severity.value,
                        "risk_score": c.risk_score,
                        "summary": c.summary,
                    }
                    for c in changes
                ],
            })

        return {
            "classification_summary": summary_counts,
            "total_files": len(results),
            "results": results,
        }


# ---------------------------------------------------------------------------
# Velocity Tracker
# ---------------------------------------------------------------------------


@dataclass
class _RepoRecord:
    """Internal state record for a single repository."""

    change_log: Deque[Dict[str, Any]] = field(default_factory=deque)
    """Deque of timed change records: {ts, risk_score, classification, category}."""

    baseline_velocity: float = 0.0
    """Computed baseline material changes/day."""

    baseline_computed_at: float = 0.0
    """Unix timestamp when baseline was last computed."""


class VelocityTracker:
    """Tracks rate of material security changes over time, per repository.

    Detects "security debt acceleration" — when the rate of breaking/material
    changes exceeds a computed baseline, indicating unsustainable pace or
    intentional circumvention of security review.

    Thread safety: not thread-safe — caller should lock if needed.

    Args:
        baseline_window_days: Number of days used to compute baseline velocity.
        alert_multiplier: Alert when current velocity exceeds baseline by this factor.
        max_log_entries: Maximum number of log entries to retain per repo.
    """

    def __init__(
        self,
        baseline_window_days: int = 30,
        alert_multiplier: float = 2.0,
        max_log_entries: int = 10000,
    ) -> None:
        self.baseline_window_days = baseline_window_days
        self.alert_multiplier = alert_multiplier
        self.max_log_entries = max_log_entries
        self._repos: DefaultDict[str, _RepoRecord] = defaultdict(_RepoRecord)

    def record_changes(
        self,
        repo: str,
        changes: List[MaterialChange],
        timestamp: Optional[float] = None,
    ) -> None:
        """Record a batch of material changes for a repository.

        Args:
            repo: Repository identifier string.
            changes: List of MaterialChange objects from the latest analysis.
            timestamp: Unix timestamp for the record (defaults to now).
        """
        ts = timestamp or time.time()
        record = self._repos[repo]
        for change in changes:
            if change.classification == ChangeClassification.COSMETIC:
                continue
            entry = {
                "ts": ts,
                "risk_score": change.risk_score,
                "classification": change.classification.value,
                "category": change.category.value,
                "file_path": change.file_path,
                "change_id": change.change_id,
            }
            record.change_log.append(entry)
            # Evict oldest if limit exceeded
            while len(record.change_log) > self.max_log_entries:
                record.change_log.popleft()

    def snapshot(self, repo: str, window_days: int = 7) -> VelocitySnapshot:
        """Compute a velocity snapshot for the given repo over the specified window.

        Args:
            repo: Repository identifier string.
            window_days: Measurement window in days.

        Returns:
            VelocitySnapshot with computed metrics.
        """
        record = self._repos[repo]
        now = time.time()
        window_start = now - (window_days * 86400)
        baseline_start = now - (self.baseline_window_days * 86400)

        # Filter changes within measurement window
        window_entries = [e for e in record.change_log if e["ts"] >= window_start]
        baseline_entries = [e for e in record.change_log if e["ts"] >= baseline_start]

        material_count = len(window_entries)
        breaking_count = sum(1 for e in window_entries if e["classification"] == "BREAKING")

        avg_risk = (
            sum(e["risk_score"] for e in window_entries) / len(window_entries)
            if window_entries else 0.0
        )

        # Compute daily velocity for current window
        current_velocity = material_count / max(1, window_days)

        # Compute baseline daily velocity
        if baseline_entries:
            baseline_velocity = len(baseline_entries) / max(1, self.baseline_window_days)
            record.baseline_velocity = baseline_velocity
            record.baseline_computed_at = now
        else:
            baseline_velocity = record.baseline_velocity or 0.0

        # Acceleration: ratio of current vs baseline velocity (1.0 = same, >1 = faster)
        if baseline_velocity > 0:
            acceleration = round(current_velocity / baseline_velocity, 3)
        else:
            acceleration = 1.0 if current_velocity == 0 else float("inf")

        debt_alert = (
            acceleration >= self.alert_multiplier
            or (breaking_count > 0 and current_velocity > baseline_velocity * 1.5)
        )

        return VelocitySnapshot(
            repo=repo,
            window_days=window_days,
            material_change_count=material_count,
            breaking_change_count=breaking_count,
            avg_risk_score=round(avg_risk, 2),
            acceleration=acceleration if acceleration != float("inf") else 999.0,
            debt_acceleration_alert=debt_alert,
        )

    def historical_profile(
        self, repo: str, window_days: int = 90
    ) -> Dict[str, Any]:
        """Return a historical risk profile for a repository.

        Provides a time-bucketed view of material changes over the specified
        window, useful for trend analysis and audit reporting.

        Args:
            repo: Repository identifier string.
            window_days: How many days of history to include.

        Returns:
            Dict with summary statistics and time-bucketed data.
        """
        record = self._repos[repo]
        now = time.time()
        window_start = now - (window_days * 86400)
        entries = [e for e in record.change_log if e["ts"] >= window_start]

        if not entries:
            return {
                "repo": repo,
                "window_days": window_days,
                "total_material_changes": 0,
                "total_breaking_changes": 0,
                "avg_risk_score": 0.0,
                "weekly_buckets": [],
                "category_distribution": {},
                "top_risk_files": [],
            }

        total_material = len(entries)
        total_breaking = sum(1 for e in entries if e["classification"] == "BREAKING")
        avg_risk = sum(e["risk_score"] for e in entries) / total_material

        # Weekly buckets
        num_weeks = max(1, window_days // 7)
        weekly_buckets = []
        for week in range(num_weeks):
            bucket_start = now - ((week + 1) * 7 * 86400)
            bucket_end = now - (week * 7 * 86400)
            bucket_entries = [e for e in entries if bucket_start <= e["ts"] < bucket_end]
            weekly_buckets.append({
                "week_offset": week,
                "start": datetime.utcfromtimestamp(bucket_start).isoformat() + "Z",
                "end": datetime.utcfromtimestamp(bucket_end).isoformat() + "Z",
                "material_count": len(bucket_entries),
                "breaking_count": sum(1 for e in bucket_entries if e["classification"] == "BREAKING"),
                "avg_risk": round(sum(e["risk_score"] for e in bucket_entries) / max(1, len(bucket_entries)), 2),
            })
        weekly_buckets.reverse()  # oldest first

        # Category distribution
        cat_dist: DefaultDict[str, int] = defaultdict(int)
        for e in entries:
            cat_dist[e["category"]] += 1

        # Top risk files
        file_risks: DefaultDict[str, List[float]] = defaultdict(list)
        for e in entries:
            file_risks[e["file_path"]].append(e["risk_score"])
        top_risk_files = sorted(
            [{"file": fp, "avg_risk": round(sum(scores) / len(scores), 2), "change_count": len(scores)}
             for fp, scores in file_risks.items()],
            key=lambda x: x["avg_risk"],
            reverse=True,
        )[:10]

        return {
            "repo": repo,
            "window_days": window_days,
            "total_material_changes": total_material,
            "total_breaking_changes": total_breaking,
            "avg_risk_score": round(avg_risk, 2),
            "weekly_buckets": weekly_buckets,
            "category_distribution": dict(cat_dist),
            "top_risk_files": top_risk_files,
            "velocity_snapshot": self.snapshot(repo).__dict__,
        }

    def clear_repo(self, repo: str) -> None:
        """Clear all change history for a repository.

        Args:
            repo: Repository identifier string.
        """
        if repo in self._repos:
            del self._repos[repo]

    def list_repos(self) -> List[str]:
        """Return all tracked repository identifiers.

        Returns:
            List of repo identifier strings.
        """
        return list(self._repos.keys())


# ---------------------------------------------------------------------------
# Serialization Helpers
# ---------------------------------------------------------------------------


def material_change_to_dict(change: MaterialChange) -> Dict[str, Any]:
    """Serialize a MaterialChange to a plain dict for JSON output.

    Args:
        change: MaterialChange instance.

    Returns:
        JSON-serializable dict.
    """
    return {
        "change_id": change.change_id,
        "file_path": change.file_path,
        "category": change.category.value,
        "classification": change.classification.value,
        "severity": change.severity.value,
        "risk_score": change.risk_score,
        "summary": change.summary,
        "explanation": change.explanation,
        "recommended_reviewers": change.recommended_reviewers,
        "review_items": change.review_items,
        "pattern_matches": [
            {
                "pattern_id": pm.pattern_id,
                "category": pm.category.value,
                "description": pm.description,
                "matched_text": pm.matched_text,
                "line_content": pm.line_content,
                "hunk_index": pm.hunk_index,
                "is_addition": pm.is_addition,
                "confidence": pm.confidence,
            }
            for pm in change.pattern_matches
        ],
        "metadata": change.metadata,
    }


def pr_assessment_to_dict(assessment: PRRiskAssessment) -> Dict[str, Any]:
    """Serialize a PRRiskAssessment to a plain dict for JSON output.

    Args:
        assessment: PRRiskAssessment instance.

    Returns:
        JSON-serializable dict.
    """
    return {
        "pr_id": assessment.pr_id,
        "overall_risk_score": assessment.overall_risk_score,
        "classification": assessment.classification.value,
        "material_changes": [material_change_to_dict(c) for c in assessment.material_changes],
        "file_summaries": assessment.file_summaries,
        "recommended_reviewers": assessment.recommended_reviewers,
        "review_checklist": assessment.review_checklist,
        "risk_breakdown": assessment.risk_breakdown,
        "stats": assessment.stats,
        "analyzed_at": assessment.analyzed_at,
    }


def velocity_snapshot_to_dict(snapshot: VelocitySnapshot) -> Dict[str, Any]:
    """Serialize a VelocitySnapshot to a plain dict.

    Args:
        snapshot: VelocitySnapshot instance.

    Returns:
        JSON-serializable dict.
    """
    return {
        "repo": snapshot.repo,
        "window_days": snapshot.window_days,
        "material_change_count": snapshot.material_change_count,
        "breaking_change_count": snapshot.breaking_change_count,
        "avg_risk_score": snapshot.avg_risk_score,
        "acceleration": snapshot.acceleration,
        "debt_acceleration_alert": snapshot.debt_acceleration_alert,
        "timestamp": snapshot.timestamp,
    }


# ---------------------------------------------------------------------------
# Singleton factory helpers
# ---------------------------------------------------------------------------

# Module-level singletons (shared state for velocity tracking)
_detector_instance: Optional[MaterialChangeDetector] = None
_pr_analyzer_instance: Optional[PRAnalyzer] = None
_velocity_tracker_instance: Optional[VelocityTracker] = None


def get_detector() -> MaterialChangeDetector:
    """Return (or create) the module-level MaterialChangeDetector singleton.

    Returns:
        Shared MaterialChangeDetector instance.
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MaterialChangeDetector()
    return _detector_instance


def get_pr_analyzer() -> PRAnalyzer:
    """Return (or create) the module-level PRAnalyzer singleton.

    Returns:
        Shared PRAnalyzer instance.
    """
    global _pr_analyzer_instance
    if _pr_analyzer_instance is None:
        _pr_analyzer_instance = PRAnalyzer()
    return _pr_analyzer_instance


def get_velocity_tracker() -> VelocityTracker:
    """Return (or create) the module-level VelocityTracker singleton.

    Returns:
        Shared VelocityTracker instance.
    """
    global _velocity_tracker_instance
    if _velocity_tracker_instance is None:
        _velocity_tracker_instance = VelocityTracker()
    return _velocity_tracker_instance


# ---------------------------------------------------------------------------
# Public convenience API
# ---------------------------------------------------------------------------


def analyze_diff(
    raw_diff: str,
    historical_vuln_density: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Top-level function: analyze a unified diff for material changes.

    Convenience wrapper around MaterialChangeDetector.analyze_diff that
    returns plain dicts ready for JSON serialization.

    Args:
        raw_diff: Raw unified diff text.
        historical_vuln_density: Optional per-file historical vuln density.

    Returns:
        List of serialized MaterialChange dicts.
    """
    detector = get_detector()
    changes = detector.analyze_diff(raw_diff, historical_vuln_density)
    return [material_change_to_dict(c) for c in changes]


def analyze_pr(
    pr_id: str,
    file_diffs: List[Dict[str, str]],
    historical_vuln_density: Optional[Dict[str, float]] = None,
    record_velocity: bool = True,
    repo: Optional[str] = None,
) -> Dict[str, Any]:
    """Top-level function: full PR risk assessment.

    Args:
        pr_id: Pull request / merge request identifier.
        file_diffs: List of {path, diff} dicts.
        historical_vuln_density: Optional per-file historical vuln density.
        record_velocity: If True and repo is provided, records changes in
            the velocity tracker for trend analysis.
        repo: Repository identifier for velocity tracking.

    Returns:
        Serialized PRRiskAssessment dict.
    """
    analyzer = get_pr_analyzer()
    assessment = analyzer.analyze_pr(pr_id, file_diffs, historical_vuln_density)

    if record_velocity and repo:
        tracker = get_velocity_tracker()
        tracker.record_changes(repo, assessment.material_changes)

    return pr_assessment_to_dict(assessment)


def get_risk_profile(repo: str, window_days: int = 90) -> Dict[str, Any]:
    """Return the historical risk profile for a repository.

    Args:
        repo: Repository identifier string.
        window_days: History window in days.

    Returns:
        Historical risk profile dict.
    """
    tracker = get_velocity_tracker()
    return tracker.historical_profile(repo, window_days)


def get_velocity(repo: str, window_days: int = 7) -> Dict[str, Any]:
    """Return change velocity metrics for a repository.

    Args:
        repo: Repository identifier string.
        window_days: Measurement window in days.

    Returns:
        Serialized VelocitySnapshot dict.
    """
    tracker = get_velocity_tracker()
    snapshot = tracker.snapshot(repo, window_days)
    return velocity_snapshot_to_dict(snapshot)


def classify_changes(file_diffs: List[Dict[str, str]]) -> Dict[str, Any]:
    """Classify a set of file diffs as BREAKING/MATERIAL/COSMETIC.

    Args:
        file_diffs: List of {path, diff} dicts.

    Returns:
        Classification result dict.
    """
    analyzer = get_pr_analyzer()
    return analyzer.classify_changes(file_diffs)


def generate_checklist(file_diffs: List[Dict[str, str]]) -> List[str]:
    """Generate a security review checklist from a set of file diffs.

    Analyzes the diffs, detects categories, and generates a targeted
    checklist covering all detected security change categories.

    Args:
        file_diffs: List of {path, diff} dicts.

    Returns:
        List of checklist item strings.
    """
    detector = get_detector()
    categories_seen: Set[ChangeCategory] = set()
    for fd in file_diffs:
        diff_text = fd.get("diff", "") or fd.get("raw_diff", "")
        if not diff_text:
            continue
        changes = detector.analyze_diff(diff_text)
        for c in changes:
            if c.classification != ChangeClassification.COSMETIC:
                categories_seen.add(c.category)
    return generate_review_checklist(list(categories_seen))
