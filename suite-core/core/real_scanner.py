"""Real vulnerability scanning module with actual HTTP-based security checks.

This module provides REAL security scanning capabilities without requiring
external tools like Checkov, Gitleaks, or MPTE. It performs actual
HTTP requests and pattern analysis to detect vulnerabilities.

Features:
- Real HTTP-based vulnerability detection (not simulated)
- SQL Injection detection via real payload testing
- XSS detection via reflection analysis
- Security header analysis
- SSL/TLS configuration checks
- Authentication bypass detection
- Secrets pattern detection with regex
- IaC misconfiguration detection with pattern matching
"""

import asyncio
import hashlib
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    Hub-level emit so this engine module participates in second-brain coverage.
    Downstream callers are AQUA via blast-radius (depth ≤ 2).
    """
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat — fires once per process so this file is observable
# in the TrustGraph second-brain, even if no public method is called yet.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ============================================================================
# Real Vulnerability Scanner - HTTP-based detection
# ============================================================================


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities detected."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_BYPASS = "authentication_bypass"
    SECURITY_HEADERS = "security_headers"
    SSL_TLS = "ssl_tls"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SECRETS_EXPOSURE = "secrets_exposure"
    IAC_MISCONFIGURATION = "iac_misconfiguration"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    COOKIE_SECURITY = "cookie_security"
    HTTP_METHOD_EXPOSURE = "http_method_exposure"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    WAF_DETECTION = "waf_detection"
    OPEN_REDIRECT = "open_redirect"
    CRLF_INJECTION = "crlf_injection"
    API_EXPOSURE = "api_exposure"
    SSTI = "ssti"
    HTTP_REQUEST_SMUGGLING = "http_request_smuggling"
    HOST_HEADER_INJECTION = "host_header_injection"
    DESERIALIZATION = "deserialization"
    CACHE_POISONING = "cache_poisoning"


@dataclass
class ArchitectureProfile:
    """Target architecture intelligence gathered during Phase 0."""

    os_fingerprint: Dict[str, Any] = field(default_factory=dict)
    cloud_provider: Dict[str, Any] = field(default_factory=dict)
    cdn_waf: Dict[str, Any] = field(default_factory=dict)
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    architecture_class: str = "unknown"  # monolith, microservices, serverless, hybrid
    deployment_model: str = "unknown"  # cloud-native, on-prem, hybrid, edge
    security_posture: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    raw_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "os_fingerprint": self.os_fingerprint,
            "cloud_provider": self.cloud_provider,
            "cdn_waf": self.cdn_waf,
            "tech_stack": self.tech_stack,
            "architecture_class": self.architecture_class,
            "deployment_model": self.deployment_model,
            "security_posture": self.security_posture,
            "confidence": self.confidence,
        }


@dataclass
class RealFinding:
    """A real security finding from actual scanning."""

    finding_id: str
    vulnerability_type: VulnerabilityType
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    evidence: Dict[str, Any]
    affected_url: str
    remediation: str
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    verified: bool = True  # These are real findings, not simulated
    # Source code traceability
    source_file: str = ""
    source_function: str = ""
    source_lines: str = ""
    detection_logic: str = ""


# SQL Injection test payloads (benign - cause errors but don't exploit)
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1' AND '1'='1",
    "'; DROP TABLE --",
    "1 UNION SELECT 1,2,3--",
    "' OR 1=1--",
    "1' OR '1'='1' --",
]

# SQL error patterns that indicate vulnerability
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"Microsoft SQL Native Client",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"unrecognized token:",
    r"SQLITE_ERROR",
]

# Time-based blind SQL injection payloads (one per DBMS)
BLIND_SQLI_PAYLOADS = [
    ("1' AND SLEEP(3)--", "mysql"),
    ("1'; WAITFOR DELAY '0:0:3'--", "mssql"),
    ("1' AND pg_sleep(3)--", "postgres"),
    ("1' AND LIKE('ABCDEFG', UPPER(HEX(RANDOMBLOB(500000000))))--", "sqlite"),
]

# Threshold in seconds: if response exceeds baseline by this much, flag it
_BLIND_SQLI_THRESHOLD_S = 2.5

# SSRF probe parameters — URL-accepting parameter names commonly vulnerable
_SSRF_PROBE_PARAMS = [
    "redirect", "url", "link", "next", "callback", "path",
    "file", "fetch", "load", "src", "image",
]

# SSRF probe URLs targeting internal/cloud metadata endpoints
_SSRF_PROBE_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://localhost:22/",
]

# SSRF response indicators suggesting the server made an outbound request
_SSRF_ERROR_INDICATORS = [
    "connection refused",
    "connect to",
    "could not connect",
    "getaddrinfo",
    "name or service not known",
    "no route to host",
]

# CSRF token field names (case-insensitive partial matches)
_CSRF_TOKEN_NAMES = [
    "csrf", "token", "_token", "authenticity_token", "nonce",
    "csrfmiddlewaretoken", "anti-forgery", "xsrf",
]

# XSS test payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
    "'><script>alert(1)</script>",
]

# Security headers to check
SECURITY_HEADERS = {
    "X-Frame-Options": {
        "expected": ["DENY", "SAMEORIGIN"],
        "severity": "medium",
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "expected": ["nosniff"],
        "severity": "low",
        "cwe": "CWE-16",
    },
    # NOTE: X-XSS-Protection intentionally REMOVED.
    # It is deprecated (Chrome 78+, Edge, Firefox never supported it).
    # Modern browsers ignore it; flagging it as missing is misleading.
    "Strict-Transport-Security": {
        "expected_pattern": r"max-age=\d+",
        "severity": "medium",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "expected_pattern": r".+",
        "severity": "medium",
        "cwe": "CWE-79",
    },
}

# Secrets patterns for detection
SECRETS_PATTERNS = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "critical", "CWE-798"),
    "AWS Secret Key": (r"['\"][0-9a-zA-Z/+]{40}['\"]", "critical", "CWE-798"),
    "GitHub Token": (r"ghp_[0-9a-zA-Z]{36}", "critical", "CWE-798"),
    "GitLab Token": (r"glpat-[0-9a-zA-Z\-]{20}", "critical", "CWE-798"),
    "Slack Token": (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "high", "CWE-798"),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "high", "CWE-798"),
    "Private Key": (
        r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "critical",
        "CWE-321",
    ),
    "Generic API Key": (
        r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]",
        "high",
        "CWE-798",
    ),
    "Generic Password": (
        r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "high",
        "CWE-798",
    ),
    "JWT Token": (
        r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "medium",
        "CWE-798",
    ),
    "Database Connection String": (
        r"(?i)(?:mongodb|postgres|mysql|redis)://[^\s\"']+",
        "high",
        "CWE-798",
    ),
    # ── YAML/Config unquoted value patterns ──────────────────────────────
    # These catch secrets in YAML/INI/TOML/env files where values are NOT quoted.
    # E.g.: password: my_secret_value  OR  aws_secret_access_key: wJalrXUt...
    "YAML/Config Password": (
        r"(?i)(?:password|passwd|pwd|secret)['\"]?\s*[:=]\s*(?!['\"])([a-zA-Z0-9/+_\-\.@!#%]{8,64})(?:\s|$)",
        "high",
        "CWE-798",
    ),
    "YAML/Config API Key": (
        r"(?i)(?:api[_-]?key|apikey|api[_-]?secret|app[_-]?secret|auth[_-]?token|access[_-]?token)['\"]?\s*[:=]\s*(?!['\"])([a-zA-Z0-9/+_\-]{16,128})(?:\s|$)",
        "high",
        "CWE-798",
    ),
    "YAML/Config AWS Secret": (
        r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)['\"]?\s*[:=]\s*(?!['\"])([a-zA-Z0-9/+]{20,64})(?:\s|$)",
        "critical",
        "CWE-798",
    ),
    "YAML/Config Database URL": (
        r"(?i)(?:database[_-]?url|db[_-]?url|database[_-]?uri|connection[_-]?string)['\"]?\s*[:=]\s*(?!['\"])(\S{10,256})(?:\s|$)",
        "high",
        "CWE-798",
    ),
    "Env File Secret": (
        r"(?i)^(?:export\s+)?(?:SECRET|TOKEN|PRIVATE|AUTH)[_A-Z0-9]*\s*=\s*(?!['\"])([a-zA-Z0-9/+_\-\.]{8,128})(?:\s|$)",
        "high",
        "CWE-798",
    ),
    "Azure/GCP Key": (
        r"(?i)(?:azure[_-]?(?:client[_-]?secret|storage[_-]?key|account[_-]?key)|google[_-]?(?:api[_-]?key|service[_-]?account[_-]?key))['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9/+=_\-]{16,128})",
        "critical",
        "CWE-798",
    ),
    "Stripe/Twilio Key": (
        r"(?:sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,}|SK[0-9a-f]{32}|AC[0-9a-f]{32})",
        "critical",
        "CWE-798",
    ),
    "SendGrid API Key": (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "critical", "CWE-798"),
    "NPM Token": (r"npm_[a-zA-Z0-9]{36}", "critical", "CWE-798"),
    "Heroku API Key": (
        r"(?i)heroku[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "high",
        "CWE-798",
    ),
}

# IaC misconfiguration patterns
IAC_PATTERNS = {
    # Terraform
    "Hardcoded AWS Keys": (
        r"access_key\s*=\s*\"AKIA[A-Z0-9]{16}\"",
        "critical",
        "CWE-798",
        "tf",
    ),
    "Unencrypted S3 Bucket": (
        r"resource\s+\"aws_s3_bucket\"[^}]*(?!server_side_encryption)",
        "high",
        "CWE-311",
        "tf",
    ),
    "Public S3 Bucket ACL": (r"acl\s*=\s*\"public-read\"", "critical", "CWE-284", "tf"),
    "Unrestricted Security Group": (
        r"cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]",
        "high",
        "CWE-284",
        "tf",
    ),
    "Unencrypted RDS": (
        r"resource\s+\"aws_db_instance\"[^}]*storage_encrypted\s*=\s*false",
        "high",
        "CWE-311",
        "tf",
    ),
    # Kubernetes
    "Privileged Container": (r"privileged:\s*true", "critical", "CWE-250", "yaml"),
    "Root User Container": (r"runAsUser:\s*0", "high", "CWE-250", "yaml"),
    "Missing Resource Limits": (
        r"containers:[^}]*(?!resources:)",
        "medium",
        "CWE-400",
        "yaml",
    ),
    "Host Network Access": (r"hostNetwork:\s*true", "high", "CWE-284", "yaml"),
    "Host PID Namespace": (r"hostPID:\s*true", "high", "CWE-284", "yaml"),
    # Docker
    "Running as Root": (r"^USER\s+root", "high", "CWE-250", "Dockerfile"),
    "Using Latest Tag": (r"FROM\s+\S+:latest", "medium", "CWE-1104", "Dockerfile"),
    "Exposed Sensitive Port": (
        r"EXPOSE\s+(22|23|3389)",
        "medium",
        "CWE-284",
        "Dockerfile",
    ),
    # CloudFormation
    "Unencrypted EBS Volume": (r"Encrypted:\s*false", "high", "CWE-311", "yaml"),
    "Public Subnet": (r"MapPublicIpOnLaunch:\s*true", "medium", "CWE-284", "yaml"),
}


logger = logging.getLogger(__name__)

# Valid authentication types for ScanConfig
_VALID_AUTH_TYPES = frozenset({
    "none", "cookie", "bearer", "basic", "oauth2", "custom_header",
})

# Maximum limits to prevent misuse
_MAX_CRAWL_DEPTH = 10
_MAX_CRAWL_URLS = 500
_MAX_EXCLUDE_PATTERNS = 50
_MAX_LOGIN_BODY_KEYS = 20
_MAX_COOKIES = 50
_MAX_PAYLOADS_PER_CHECK = 100
_MAX_SCAN_DELAY_MS = 10_000  # 10 seconds max delay


@dataclass
class ScanConfig:
    """Configuration for authenticated and crawled scans."""

    # Authentication
    auth_type: str = "none"  # none, cookie, bearer, basic, oauth2, custom_header
    auth_token: str = ""  # Bearer token, API key, etc.
    auth_cookies: Dict[str, str] = field(default_factory=dict)  # Session cookies
    auth_username: str = ""  # Basic auth username
    auth_password: str = ""  # Basic auth password
    auth_header_name: str = "Authorization"  # Custom header name
    auth_header_value: str = ""  # Custom header value

    # Login flow (for session-based auth)
    login_url: str = ""  # POST login URL
    login_body: Dict[str, str] = field(default_factory=dict)  # Login form data
    login_success_indicator: str = ""  # String in response that indicates success

    # Crawling
    crawl: bool = False  # Enable application crawling before scanning
    max_crawl_depth: int = 3  # Maximum crawl depth
    max_crawl_urls: int = 50  # Maximum URLs to crawl
    crawl_scope: str = "same-origin"  # same-origin, same-domain, custom
    exclude_patterns: List[str] = field(default_factory=list)  # URL patterns to skip

    # Scan tuning
    max_payloads_per_check: int = 10  # Limit payloads per vulnerability check
    scan_delay_ms: int = 0  # Delay between requests (rate limiting)

    def __post_init__(self) -> None:
        """Validate configuration values after initialization."""
        # Validate auth_type
        if self.auth_type not in _VALID_AUTH_TYPES:
            raise ValueError(
                f"Invalid auth_type '{self.auth_type}'. "
                f"Must be one of: {', '.join(sorted(_VALID_AUTH_TYPES))}"
            )
        # Clamp numeric limits
        self.max_crawl_depth = max(0, min(self.max_crawl_depth, _MAX_CRAWL_DEPTH))
        self.max_crawl_urls = max(1, min(self.max_crawl_urls, _MAX_CRAWL_URLS))
        self.max_payloads_per_check = max(1, min(self.max_payloads_per_check, _MAX_PAYLOADS_PER_CHECK))
        self.scan_delay_ms = max(0, min(self.scan_delay_ms, _MAX_SCAN_DELAY_MS))
        # Validate crawl_scope
        if self.crawl_scope not in ("same-origin", "same-domain", "custom"):
            self.crawl_scope = "same-origin"
        # Truncate lists to prevent abuse
        if len(self.exclude_patterns) > _MAX_EXCLUDE_PATTERNS:
            self.exclude_patterns = self.exclude_patterns[:_MAX_EXCLUDE_PATTERNS]
        if len(self.login_body) > _MAX_LOGIN_BODY_KEYS:
            raise ValueError(
                f"login_body has {len(self.login_body)} keys, maximum is {_MAX_LOGIN_BODY_KEYS}"
            )
        if len(self.auth_cookies) > _MAX_COOKIES:
            raise ValueError(
                f"auth_cookies has {len(self.auth_cookies)} entries, maximum is {_MAX_COOKIES}"
            )
        # Validate login_url scheme if provided
        if self.login_url:
            parsed = urlparse(self.login_url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"login_url must use http or https scheme, got '{parsed.scheme}'"
                )


class RealVulnerabilityScanner:
    """Real HTTP-based vulnerability scanner.

    This scanner performs ACTUAL security tests against target URLs,
    not simulated or mocked responses. Supports authenticated scanning
    via cookies, bearer tokens, basic auth, or custom headers, and
    application crawling to discover scan targets beyond the initial URL.
    """

    def __init__(
        self,
        timeout: float = 30.0,
        verify_ssl: bool = True,
        config: Optional[ScanConfig] = None,
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.config = config or ScanConfig()
        self._findings: List[RealFinding] = []
        self.architecture_profiles: Dict[str, ArchitectureProfile] = {}
        self._crawled_urls: List[str] = []

    async def scan_url(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> List[RealFinding]:
        """Perform comprehensive security scan on a URL.

        If a ScanConfig with authentication is provided, the scanner will
        authenticate before scanning.  If crawling is enabled, the scanner
        discovers additional URLs from the application and scans each one.

        Args:
            url: Target URL to scan
            headers: Optional HTTP headers to include

        Returns:
            List of real security findings
        """
        self._findings = []
        self._crawled_urls = []

        # Build auth-aware headers
        auth_headers = self._build_auth_headers(headers)

        # Build client kwargs including cookies from config
        client_kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "follow_redirects": True,
        }
        if self.config.auth_cookies:
            client_kwargs["cookies"] = dict(self.config.auth_cookies)

        # Basic auth support
        if self.config.auth_type == "basic" and self.config.auth_username:
            client_kwargs["auth"] = (self.config.auth_username, self.config.auth_password)

        async with httpx.AsyncClient(**client_kwargs) as client:
            # Perform login flow if configured
            if self.config.login_url:
                login_ok = await self._perform_login(client, self.config)
                if not login_ok:
                    logger.warning(
                        "Login flow failed for %s — proceeding unauthenticated",
                        self.config.login_url,
                    )

            # Determine scan targets
            scan_targets: List[str] = [url]
            if self.config.crawl:
                crawled = await self._crawl_application(client, url, auth_headers)
                self._crawled_urls = crawled
                # Merge: original URL + crawled URLs (deduplicated, order preserved)
                seen: Set[str] = {url}
                for crawled_url in crawled:
                    if crawled_url not in seen:
                        scan_targets.append(crawled_url)
                        seen.add(crawled_url)
                logger.info(
                    "Crawl complete: %d URLs discovered, %d total scan targets",
                    len(crawled),
                    len(scan_targets),
                )

            # Scan each target URL
            for target_url in scan_targets:
                await self._scan_single_url(client, target_url, auth_headers)

                # Respect scan delay between URLs
                if self.config.scan_delay_ms > 0 and target_url != scan_targets[-1]:
                    await asyncio.sleep(self.config.scan_delay_ms / 1000.0)

        return self._findings

    async def _scan_single_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Run all scan phases on a single URL.

        This method encapsulates the original scan logic so it can be
        called once per URL when crawling discovers multiple targets.
        """
        # Phase 0: Architecture Intelligence Profiling
        arch_profile = await self._profile_architecture(client, url, headers)
        self.architecture_profiles[url] = arch_profile

        # Phase 1: Basic connectivity and header check
        await self._check_security_headers(client, url, headers)

        # Phase 2: SSL/TLS check
        await self._check_ssl_tls(url)

        # Phase 3: SQL Injection check (error-based + time-based blind)
        await self._check_sql_injection(client, url, headers)

        # Phase 4: XSS check
        await self._check_xss(client, url, headers)

        # Phase 5: Information disclosure
        await self._check_information_disclosure(client, url, headers)

        # Phase 6: Path traversal
        await self._check_path_traversal(client, url, headers)

        # Phase 7: CORS misconfiguration
        await self._check_cors_misconfiguration(client, url, headers)

        # Phase 8: Cookie security
        await self._check_cookie_security(client, url, headers)

        # Phase 9: HTTP method enumeration
        await self._check_http_methods(client, url, headers)

        # Phase 10: Technology fingerprinting
        await self._check_technology_fingerprinting(client, url, headers)

        # Phase 11: WAF detection
        await self._check_waf_detection(client, url, headers)

        # Phase 12: Open redirect
        await self._check_open_redirect(client, url, headers)

        # Phase 13: CRLF injection
        await self._check_crlf_injection(client, url, headers)

        # Phase 14: API endpoint discovery
        await self._check_api_endpoint_discovery(client, url, headers)

        # Phase 15: Server-Side Template Injection (SSTI)
        await self._check_ssti(client, url, headers)

        # Phase 16: HTTP Request Smuggling indicators
        await self._check_http_request_smuggling(client, url, headers)

        # Phase 17: Host Header Injection
        await self._check_host_header_injection(client, url, headers)

        # Phase 18: Deserialization indicators
        await self._check_deserialization(client, url, headers)

        # Phase 19: Cache Poisoning
        await self._check_cache_poisoning(client, url, headers)

        # Phase 20: SSRF (Server-Side Request Forgery)
        await self._check_ssrf(client, url, headers)

        # Phase 21: CSRF (Cross-Site Request Forgery)
        await self._check_csrf(client, url, headers)

    def _build_auth_headers(
        self, base_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Merge authentication headers from ScanConfig into base headers.

        Returns a new dict — the original *base_headers* is never mutated.
        """
        merged: Dict[str, str] = dict(base_headers or {})
        cfg = self.config

        if cfg.auth_type == "bearer" and cfg.auth_token:
            merged["Authorization"] = f"Bearer {cfg.auth_token}"
        elif cfg.auth_type == "oauth2" and cfg.auth_token:
            merged["Authorization"] = f"Bearer {cfg.auth_token}"
        elif cfg.auth_type == "custom_header" and cfg.auth_header_name and cfg.auth_header_value:
            merged[cfg.auth_header_name] = cfg.auth_header_value
        # "basic" auth is handled via httpx's auth= parameter, not headers
        # "cookie" auth is handled via httpx's cookies= parameter
        # "none" requires no extra headers

        return merged

    async def _perform_login(
        self, client: httpx.AsyncClient, config: ScanConfig
    ) -> bool:
        """Perform session-based login flow.

        POSTs credentials to ``config.login_url`` and captures the resulting
        session cookies. Supports both form-encoded and JSON login bodies.

        Args:
            client: The httpx async client (cookies are stored on it).
            config: Scan configuration with login details.

        Returns:
            True if login succeeded, False otherwise.
        """
        if not config.login_url or not config.login_body:
            return False

        try:
            # Determine content type: if login URL hints at an API, use JSON.
            # Otherwise use form encoding.
            login_url_lower = config.login_url.lower()
            use_json = any(
                kw in login_url_lower
                for kw in ("/api/", "/graphql", "/auth/token", "/oauth/")
            )

            if use_json:
                response = await client.post(
                    config.login_url,
                    json=config.login_body,
                    timeout=min(self.timeout, 15.0),
                )
            else:
                response = await client.post(
                    config.login_url,
                    data=config.login_body,
                    timeout=min(self.timeout, 15.0),
                )

            # Check HTTP status first
            if response.status_code >= 400:
                logger.warning(
                    "Login POST to %s returned HTTP %d",
                    config.login_url,
                    response.status_code,
                )
                return False

            # Capture any Set-Cookie headers — httpx stores them on the client
            # automatically, so we just verify success.

            # Check for bearer token in JSON response body
            if "application/json" in response.headers.get("content-type", ""):
                try:
                    body = response.json()
                    # Common token field names
                    for token_field in ("access_token", "token", "jwt", "id_token", "auth_token"):
                        token_val = body.get(token_field)
                        if token_val and isinstance(token_val, str):
                            # Store as bearer token for subsequent requests
                            self.config = ScanConfig(
                                auth_type="bearer",
                                auth_token=token_val,
                                # Preserve the rest of the config
                                auth_cookies=config.auth_cookies,
                                crawl=config.crawl,
                                max_crawl_depth=config.max_crawl_depth,
                                max_crawl_urls=config.max_crawl_urls,
                                crawl_scope=config.crawl_scope,
                                exclude_patterns=config.exclude_patterns,
                                max_payloads_per_check=config.max_payloads_per_check,
                                scan_delay_ms=config.scan_delay_ms,
                            )
                            logger.info(
                                "Login succeeded — captured bearer token from '%s' field",
                                token_field,
                            )
                            return True
                except (ValueError, AttributeError):
                    pass

            # Verify via success indicator string
            if config.login_success_indicator:
                response_text = response.text
                if config.login_success_indicator in response_text:
                    logger.info("Login succeeded — success indicator found in response")
                    return True
                else:
                    logger.warning(
                        "Login success indicator '%s' not found in response",
                        config.login_success_indicator,
                    )
                    return False

            # No explicit indicator — if we got cookies and a 2xx/3xx, assume success
            if response.cookies or client.cookies:
                logger.info(
                    "Login assumed successful — %d cookies received",
                    len(response.cookies) + len(client.cookies),
                )
                return True

            # 2xx with no cookies and no indicator — optimistic success
            if 200 <= response.status_code < 300:
                logger.info("Login returned HTTP %d — assuming success", response.status_code)
                return True

            return False

        except httpx.RequestError as exc:
            logger.warning(
                "Login request to %s failed: %s",
                config.login_url,
                type(exc).__name__,
            )
            return False

    async def _crawl_application(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Crawl the target application to discover scannable URLs.

        Uses regex-based HTML parsing (no BeautifulSoup dependency) to extract
        links from ``href``, ``src``, and ``action`` attributes, plus common
        JavaScript ``fetch``/``axios`` URL patterns.

        Args:
            client: Authenticated httpx async client.
            base_url: Starting URL to crawl from.
            headers: HTTP headers to include in crawl requests.

        Returns:
            Deduplicated list of discovered URLs within scope.
        """
        parsed_base = urlparse(base_url)
        base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
        base_domain = parsed_base.hostname or ""

        discovered: List[str] = []
        visited: Set[str] = set()
        queue: List[tuple] = [(base_url, 0)]  # (url, depth) pairs

        # Compile exclude patterns once
        exclude_regexes: List[re.Pattern] = []
        for pattern in self.config.exclude_patterns:
            try:
                exclude_regexes.append(re.compile(pattern))
            except re.error:
                logger.warning("Invalid exclude pattern ignored: %s", pattern)

        # Regex patterns for link extraction (no external HTML parser needed)
        _HREF_SRC_ACTION = re.compile(
            r"""(?:href|src|action)\s*=\s*["']([^"'#]+?)["']""",
            re.IGNORECASE,
        )
        _JS_FETCH_URLS = re.compile(
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`]([^"'`]+?)["'`]""",
            re.IGNORECASE,
        )
        _JS_URL_ASSIGN = re.compile(
            r"""(?:url|endpoint|apiUrl|href)\s*[:=]\s*["'`]([^"'`]+?)["'`]""",
            re.IGNORECASE,
        )

        while queue and len(discovered) < self.config.max_crawl_urls:
            current_url, depth = queue.pop(0)

            # Normalize URL before checking visited set
            normalized = self._normalize_crawl_url(current_url, base_origin)
            if not normalized or normalized in visited:
                continue

            visited.add(normalized)

            # Enforce depth limit
            if depth > self.config.max_crawl_depth:
                continue

            # Check scope
            if not self._url_in_crawl_scope(normalized, parsed_base, base_domain):
                continue

            # Check exclude patterns
            if any(rx.search(normalized) for rx in exclude_regexes):
                continue

            # Fetch the page
            try:
                resp = await client.get(
                    normalized,
                    headers=headers,
                    timeout=min(self.timeout, 10.0),
                    follow_redirects=True,
                )
            except httpx.RequestError:
                continue

            # Skip error responses
            content_type = resp.headers.get("content-type", "").lower()
            if resp.status_code >= 400:
                continue

            # Record this URL as discovered
            if normalized != base_url and normalized not in discovered:
                discovered.append(normalized)

            # Only extract links from HTML/XHTML content
            if "html" not in content_type and "xhtml" not in content_type:
                continue

            # Limit body size we parse to avoid OOM on huge pages
            body = resp.text[:500_000]

            # Extract links from HTML attributes
            raw_links: List[str] = []
            raw_links.extend(_HREF_SRC_ACTION.findall(body))

            # Extract URLs from inline JavaScript
            raw_links.extend(_JS_FETCH_URLS.findall(body))
            raw_links.extend(_JS_URL_ASSIGN.findall(body))

            # Resolve and queue discovered links
            for raw_link in raw_links:
                raw_link = raw_link.strip()
                if not raw_link:
                    continue

                # Skip non-navigable schemes
                if raw_link.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue

                # Resolve relative URLs
                resolved = urljoin(normalized, raw_link)

                # Strip fragment
                frag_idx = resolved.find("#")
                if frag_idx != -1:
                    resolved = resolved[:frag_idx]

                if resolved and resolved not in visited:
                    queue.append((resolved, depth + 1))

            # Respect scan delay during crawling too
            if self.config.scan_delay_ms > 0:
                await asyncio.sleep(self.config.scan_delay_ms / 1000.0)

        logger.info(
            "Crawl finished: visited %d pages, discovered %d URLs",
            len(visited),
            len(discovered),
        )
        return discovered

    def _normalize_crawl_url(self, url: str, base_origin: str) -> Optional[str]:
        """Normalize a URL for crawling — resolve relative, strip fragments.

        Returns None if the URL is not valid for crawling.
        """
        if not url:
            return None

        # Resolve relative URLs against base origin
        if url.startswith("/"):
            url = base_origin + url

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None

        # Strip fragment and trailing whitespace
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"

        return clean

    def _url_in_crawl_scope(
        self, url: str, base_parsed: Any, base_domain: str
    ) -> bool:
        """Check whether a URL falls within the configured crawl scope."""
        parsed = urlparse(url)
        url_host = (parsed.hostname or "").lower()
        base_host = base_domain.lower()

        if self.config.crawl_scope == "same-origin":
            # Must match scheme + host + port exactly
            return (
                parsed.scheme == base_parsed.scheme
                and parsed.netloc == base_parsed.netloc
            )
        elif self.config.crawl_scope == "same-domain":
            # Host must match or be a subdomain of the base domain
            return url_host == base_host or url_host.endswith(f".{base_host}")
        elif self.config.crawl_scope == "custom":
            # Custom scope: rely solely on exclude_patterns for filtering
            return parsed.scheme in ("http", "https")

        return False

    # ── OpenAPI / Swagger Schema Import ──────────────────────────────

    @staticmethod
    def parse_openapi_spec(
        spec: Dict[str, Any], base_url: str
    ) -> List[Dict[str, Any]]:
        """Parse an OpenAPI/Swagger spec and generate scan targets.

        Supports OpenAPI 3.x (``servers``) and Swagger 2.0 (``basePath``).
        Path parameters are replaced with fuzz-safe defaults. Query parameters
        get type-aware placeholder values.

        Args:
            spec: Parsed OpenAPI/Swagger JSON dict.
            base_url: Fallback base URL when the spec has no ``servers``.

        Returns:
            List of target dicts with keys: ``url``, ``method``, ``path``,
            ``params``, ``content_type``, ``operation_id``, ``summary``.
        """
        targets: List[Dict[str, Any]] = []

        # Determine API base
        api_base = base_url.rstrip("/")
        if "servers" in spec and spec["servers"]:
            first_server = spec["servers"][0].get("url", "")
            if first_server.startswith("http"):
                api_base = first_server.rstrip("/")
            elif first_server.startswith("/"):
                api_base = base_url.rstrip("/") + first_server.rstrip("/")
        elif "basePath" in spec:
            api_base = base_url.rstrip("/") + spec["basePath"].rstrip("/")

        http_methods = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

        for path, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in http_methods or not isinstance(operation, dict):
                    continue

                # Replace path params with safe fuzz values
                fuzz_path = re.sub(r"\{[^}]+\}", "1", path)
                target_url = api_base + fuzz_path

                # Collect query parameters with type-aware values
                query_params: Dict[str, str] = {}
                for param in operation.get("parameters", []):
                    if not isinstance(param, dict):
                        continue
                    if param.get("in") != "query":
                        continue
                    name = param.get("name", "")
                    if not name:
                        continue
                    schema = param.get("schema", {})
                    ptype = schema.get("type", "string") if isinstance(schema, dict) else "string"
                    if ptype == "integer":
                        query_params[name] = "1"
                    elif ptype == "boolean":
                        query_params[name] = "true"
                    else:
                        query_params[name] = "test"

                if query_params:
                    target_url += "?" + urlencode(query_params)

                # Detect request content type
                content_type = "application/json"
                if "requestBody" in operation:
                    rb_content = operation["requestBody"].get("content", {})
                    if rb_content:
                        content_type = next(iter(rb_content.keys()), "application/json")

                targets.append({
                    "url": target_url,
                    "method": method.upper(),
                    "path": path,
                    "params": query_params,
                    "content_type": content_type,
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                })

        return targets

    async def scan_openapi(
        self,
        spec: Dict[str, Any],
        base_url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List["RealFinding"]:
        """Scan all endpoints defined in an OpenAPI/Swagger spec.

        Parses the spec, generates targets, and runs the full 22-phase
        scanner against each target URL.

        Args:
            spec: Parsed OpenAPI JSON dict.
            base_url: Base URL of the API server.
            headers: Optional additional HTTP headers.

        Returns:
            Combined findings across all spec endpoints.
        """
        targets = self.parse_openapi_spec(spec, base_url)
        logger.info("OpenAPI scan: %d endpoints parsed from spec", len(targets))

        all_findings: List[RealFinding] = []
        merged_headers = dict(headers or {})
        auth_hdrs = self._build_auth_headers(merged_headers)

        cookies = dict(self.config.auth_cookies)
        client_kwargs: Dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "follow_redirects": True,
        }
        if cookies:
            client_kwargs["cookies"] = cookies
        if self.config.auth_type == "basic" and self.config.auth_username:
            client_kwargs["auth"] = (self.config.auth_username, self.config.auth_password)

        async with httpx.AsyncClient(**client_kwargs) as client:
            if self.config.login_url:
                await self._perform_login(client, self.config)

            for target in targets:
                self._findings = []
                await self._scan_single_url(client, target["url"], auth_hdrs)
                all_findings.extend(self._findings)

                if self.config.scan_delay_ms > 0:
                    await asyncio.sleep(self.config.scan_delay_ms / 1000.0)

        self._findings = all_findings
        return all_findings

    # ── Phase 0: Architecture Intelligence Profiling ────────────────
    async def _profile_architecture(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> ArchitectureProfile:
        """Profile target architecture: OS, cloud, CDN/WAF, tech stack, deployment model."""
        profile = ArchitectureProfile()
        signals = 0
        try:
            resp = await client.get(url, headers=headers)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            profile.raw_headers = dict(hdrs)
            # ── OS fingerprinting ──
            server = hdrs.get("server", "")
            os_hints: Dict[str, float] = {}
            if any(
                k in server.lower()
                for k in ("ubuntu", "debian", "centos", "rhel", "amazon linux", "linux")
            ):
                os_hints["Linux"] = 0.9
            elif any(k in server.lower() for k in ("microsoft", "iis", "windows")):
                os_hints["Windows"] = 0.9
            elif "darwin" in server.lower() or "macos" in server.lower():
                os_hints["macOS"] = 0.8
            elif "freebsd" in server.lower() or "openbsd" in server.lower():
                os_hints["BSD"] = 0.8
            # Infer from server software
            if any(
                k in server.lower() for k in ("nginx", "apache", "gunicorn", "uvicorn")
            ):
                os_hints.setdefault("Linux", 0.7)
            if "iis" in server.lower():
                os_hints.setdefault("Windows", 0.85)
            # Date header timezone hint (RFC 7231)
            date_hdr = hdrs.get("date", "")
            if date_hdr and "gmt" in date_hdr.lower():
                signals += 1  # Confirms real web server
            profile.os_fingerprint = {
                "detected_os": max(os_hints, key=os_hints.get)
                if os_hints
                else "Unknown",
                "confidence": max(os_hints.values()) if os_hints else 0.0,
                "server_header": server,
                "signals": os_hints,
            }
            if os_hints:
                signals += 1

            # ── Cloud provider detection ──
            cloud: Dict[str, float] = {}
            _CLOUD_HEADERS = {
                "AWS": [
                    "x-amz-cf-id",
                    "x-amz-request-id",
                    "x-amzn-requestid",
                    "x-amz-id-2",
                    "x-amzn-trace-id",
                ],
                "Google Cloud": ["x-cloud-trace-context", "x-goog-", "via: 1.1 google"],
                "Azure": ["x-azure-ref", "x-ms-request-id", "x-msedge-ref"],
                "Cloudflare": ["cf-ray", "cf-cache-status"],
                "Fastly": ["x-served-by", "x-cache", "x-cache-hits", "fastly-restarts"],
                "DigitalOcean": ["x-do-"],
                "Vercel": ["x-vercel-id", "x-vercel-cache"],
                "Netlify": ["x-nf-request-id", "netlify"],
                "Heroku": ["heroku"],
            }
            for provider, indicators in _CLOUD_HEADERS.items():
                for ind in indicators:
                    if any(ind in k or ind in v.lower() for k, v in hdrs.items()):
                        cloud[provider] = max(cloud.get(provider, 0), 0.85)
                        break
            # Check CNAME / IP hints from via header
            via = hdrs.get("via", "")
            if "cloudfront" in via.lower():
                cloud["AWS"] = max(cloud.get("AWS", 0), 0.9)
            if "google" in via.lower():
                cloud["Google Cloud"] = max(cloud.get("Google Cloud", 0), 0.9)
            profile.cloud_provider = {
                "detected": max(cloud, key=cloud.get)
                if cloud
                else "Unknown / On-Premises",
                "confidence": max(cloud.values()) if cloud else 0.0,
                "signals": cloud,
            }
            if cloud:
                signals += 1

            # ── CDN / WAF detection ──
            cdn_waf: Dict[str, str] = {}
            _CDN_WAF_MAP = {
                "Cloudflare": ["cf-ray", "cf-cache-status"],
                "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
                "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
                "Fastly": ["x-served-by", "fastly-restarts"],
                "Google CDN": ["via: 1.1 google"],
                "Sucuri WAF": ["x-sucuri-id"],
                "Imperva/Incapsula": ["x-iinfo", "incap_ses"],
                "AWS WAF": ["x-amzn-waf-"],
                "ModSecurity": ["mod_security"],
                "F5 BIG-IP": ["bigipserver"],
            }
            for name, indicators in _CDN_WAF_MAP.items():
                for ind in indicators:
                    matched_keys = [k for k in hdrs if ind in k]
                    matched_vals = [k for k, v in hdrs.items() if ind in v.lower()]
                    if matched_keys or matched_vals:
                        cdn_waf[name] = "detected"
                        break
            profile.cdn_waf = {
                "detected": list(cdn_waf.keys()),
                "count": len(cdn_waf),
                "waf_present": any(
                    "WAF" in n
                    or "Incapsula" in n
                    or "ModSecurity" in n
                    or "Sucuri" in n
                    for n in cdn_waf
                ),
            }
            if cdn_waf:
                signals += 1

            # ── Tech stack ──
            tech: Dict[str, str] = {}
            if server:
                tech["web_server"] = server
            powered = hdrs.get("x-powered-by", "")
            if powered:
                tech["runtime"] = powered
            asp = hdrs.get("x-aspnet-version", "")
            if asp:
                tech["framework"] = f"ASP.NET {asp}"
            body = resp.text[:8000].lower()
            _FW_PATTERNS = [
                ("React", "__react", "frontend"),
                ("Next.js", "__next", "frontend"),
                ("Angular", "ng-version", "frontend"),
                ("Vue.js", "data-v-", "frontend"),
                ("WordPress", "wp-content", "cms"),
                ("Drupal", "drupal", "cms"),
                ("Django", "csrfmiddlewaretoken", "backend"),
                ("Laravel", "laravel_session", "backend"),
                ("Express", "x-powered-by: express", "backend"),
                ("Rails", "action_dispatch", "backend"),
                ("Spring", "x-application-context", "backend"),
                ("Flask", "werkzeug", "backend"),
            ]
            for name, pattern, category in _FW_PATTERNS:
                if (
                    pattern in body
                    or pattern in server.lower()
                    or pattern in powered.lower()
                ):
                    tech[category] = (
                        tech.get(category, "")
                        + (", " if tech.get(category) else "")
                        + name
                    )
            profile.tech_stack = tech
            if tech:
                signals += 1

            # ── Architecture classification ──
            # Heuristics: multiple microservice indicators vs monolith
            is_api = "application/json" in hdrs.get("content-type", "")
            has_cors = "access-control-allow-origin" in hdrs
            has_api_gateway = any(
                k in " ".join(hdrs.values()).lower()
                for k in ("api gateway", "kong", "envoy", "istio", "traefik")
            )
            if has_api_gateway:
                profile.architecture_class = "microservices"
            elif is_api and has_cors:
                profile.architecture_class = "api-first (likely microservices)"
            elif any(k in body for k in ("wp-content", "drupal", "joomla")):
                profile.architecture_class = "monolith (CMS)"
            elif is_api:
                profile.architecture_class = "api-first"
            else:
                profile.architecture_class = "traditional web (likely monolith)"

            # ── Deployment model ──
            if cloud:
                if any(
                    "Lambda" in v or "Functions" in v or "Cloud Run" in v
                    for v in hdrs.values()
                ):
                    profile.deployment_model = "serverless"
                else:
                    profile.deployment_model = "cloud-native"
            else:
                profile.deployment_model = "on-premises / unknown"

            # ── Security posture ──
            sec_headers_present = sum(
                1
                for h in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                )
                if h in hdrs
            )
            profile.security_posture = {
                "https_enforced": url.startswith("https"),
                "hsts_enabled": "strict-transport-security" in hdrs,
                "csp_enabled": "content-security-policy" in hdrs,
                "security_headers_count": sec_headers_present,
                "security_headers_max": 6,
                "security_headers_pct": round(sec_headers_present / 6 * 100, 1),
                "waf_present": profile.cdn_waf.get("waf_present", False),
            }
            signals += 1
            profile.confidence = min(1.0, signals / 5)

        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            profile.confidence = 0.0
        return profile

    async def _check_security_headers(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for missing or misconfigured security headers.

        Context-aware: skips X-Frame-Options / CSP checks on JSON API
        responses because those headers are only relevant for browser-
        rendered HTML content.
        """
        try:
            response = await client.get(url, headers=headers)

            # Detect response context for smart filtering
            ct = response.headers.get("content-type", "")
            is_json_api = "json" in ct.lower()

            # Headers that only matter on HTML pages (not JSON APIs)
            _HTML_ONLY_HEADERS = {"X-Frame-Options", "Content-Security-Policy"}

            for header_name, config in SECURITY_HEADERS.items():
                # Skip HTML-only headers on JSON API endpoints
                if is_json_api and header_name in _HTML_ONLY_HEADERS:
                    continue

                header_value = response.headers.get(header_name)

                if not header_value:
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.SECURITY_HEADERS,
                            title=f"Missing {header_name} Header",
                            description=f"The security header '{header_name}' is not present in the response. "
                            f"This header helps protect against various attacks.",
                            severity=config["severity"],
                            evidence={
                                "header": header_name,
                                "status": "missing",
                                "content_type": ct,
                                "response_headers": dict(response.headers),
                            },
                            affected_url=url,
                            remediation=f"Add the {header_name} header to all HTTP responses.",
                            cwe_id=config.get("cwe"),
                            cvss_score=self._severity_to_cvss(config["severity"]),
                        )
                    )
                elif "expected" in config:
                    if header_value not in config["expected"]:
                        self._findings.append(
                            RealFinding(
                                finding_id=self._generate_finding_id(),
                                vulnerability_type=VulnerabilityType.SECURITY_HEADERS,
                                title=f"Weak {header_name} Header Value",
                                description=f"The {header_name} header has value '{header_value}' "
                                f"which may not provide adequate protection.",
                                severity="low",
                                evidence={
                                    "header": header_name,
                                    "value": header_value,
                                    "expected": config["expected"],
                                    "content_type": ct,
                                },
                                affected_url=url,
                                remediation=f"Set {header_name} to one of: {', '.join(config['expected'])}",
                                cwe_id=config.get("cwe"),
                                cvss_score=3.0,
                            )
                        )

        except httpx.RequestError as e:
            # Connection errors are also findings
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    title="Connection Error - Target May Be Unreachable",
                    description=f"Failed to connect to target URL: {str(e)}",
                    severity="info",
                    evidence={"error": str(e), "url": url},
                    affected_url=url,
                    remediation="Verify the target URL is accessible and properly configured.",
                    cvss_score=0.0,
                )
            )

    async def _check_ssl_tls(self, url: str) -> None:
        """Check SSL/TLS configuration."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.SSL_TLS,
                    title="HTTP Used Instead of HTTPS",
                    description="The target URL uses HTTP instead of HTTPS, "
                    "which transmits data in plaintext and is vulnerable to eavesdropping.",
                    severity="high",
                    evidence={"scheme": parsed.scheme, "url": url},
                    affected_url=url,
                    remediation="Use HTTPS for all communications. Obtain an SSL/TLS certificate.",
                    cwe_id="CWE-319",
                    cvss_score=7.5,
                )
            )
            return

        # Check SSL certificate
        try:
            ssl.create_default_context()
            # Attempt connection to verify cert
            async with httpx.AsyncClient(verify=True) as client:
                await client.get(url)
        except ssl.SSLCertVerificationError as e:
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.SSL_TLS,
                    title="Invalid SSL/TLS Certificate",
                    description=f"SSL certificate verification failed: {str(e)}",
                    severity="high",
                    evidence={"error": str(e), "url": url},
                    affected_url=url,
                    remediation="Use a valid SSL certificate from a trusted Certificate Authority.",
                    cwe_id="CWE-295",
                    cvss_score=7.5,
                )
            )
        except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
            pass  # Other errors handled elsewhere

    async def _check_sql_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for SQL injection via differential analysis + error-based detection."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        for param_name in params:
            # Step 1: Baseline with benign value
            benign_params = dict(params)
            benign_params[param_name] = ["ALDECI_BENIGN_VALUE"]
            try:
                benign_resp = await client.get(
                    f"{base_url}?{urlencode(benign_params, doseq=True)}",
                    headers=headers,
                    timeout=5.0,
                )
                benign_text = benign_resp.text
                benign_status = benign_resp.status_code
            except httpx.RequestError:
                continue
            # Step 2: Malicious payloads with differential check
            for payload in SQL_INJECTION_PAYLOADS[:3]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    response = await client.get(
                        f"{base_url}?{urlencode(test_params, doseq=True)}",
                        headers=headers,
                        timeout=5.0,
                    )
                    text = response.text
                    # Must find SQL error pattern AND it must NOT appear in benign response
                    for pattern in SQL_ERROR_PATTERNS:
                        malicious_match = re.search(pattern, text, re.IGNORECASE)
                        benign_match = re.search(pattern, benign_text, re.IGNORECASE)
                        if malicious_match and not benign_match:
                            self._findings.append(
                                RealFinding(
                                    finding_id=self._generate_finding_id(),
                                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                    title="SQL Injection Vulnerability Detected (Differential Confirmed)",
                                    description=(
                                        f"SQL error message detected in response for parameter '{param_name}' "
                                        f"with payload '{payload}'. Confirmed by differential analysis: "
                                        f"benign input did NOT trigger the error."
                                    ),
                                    severity="critical",
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "error_pattern": pattern,
                                        "response_snippet": text[:500],
                                        "differential": True,
                                        "benign_status": benign_status,
                                        "malicious_status": response.status_code,
                                    },
                                    affected_url=url,
                                    remediation="Use parameterized queries or prepared statements. "
                                    "Never concatenate user input into SQL queries.",
                                    cwe_id="CWE-89",
                                    cvss_score=9.8,
                                )
                            )
                            return
                except httpx.RequestError:
                    pass

            # Step 3: Time-based blind SQL injection detection
            # Measure baseline response time first, then compare with sleep payloads
            try:
                baseline_t0 = time.monotonic()
                await client.get(
                    f"{base_url}?{urlencode(benign_params, doseq=True)}",
                    headers=headers,
                    timeout=10.0,
                )
                baseline_duration = time.monotonic() - baseline_t0
            except httpx.RequestError:
                continue  # Cannot measure baseline, skip blind checks for this param

            for blind_payload, dbms in BLIND_SQLI_PAYLOADS:
                blind_params = dict(params)
                blind_params[param_name] = [blind_payload]
                try:
                    t0 = time.monotonic()
                    blind_resp = await client.get(
                        f"{base_url}?{urlencode(blind_params, doseq=True)}",
                        headers=headers,
                        timeout=10.0,
                    )
                    elapsed = time.monotonic() - t0
                    delay = elapsed - baseline_duration
                    if delay >= _BLIND_SQLI_THRESHOLD_S:
                        self._findings.append(
                            RealFinding(
                                finding_id=self._generate_finding_id(),
                                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                title=f"Time-Based Blind SQL Injection Detected ({dbms})",
                                description=(
                                    f"Parameter '{param_name}' responded {delay:.1f}s slower "
                                    f"with time-delay payload targeting {dbms}. "
                                    f"Baseline: {baseline_duration:.2f}s, "
                                    f"Payload: {elapsed:.2f}s. "
                                    f"This strongly indicates blind SQL injection."
                                ),
                                severity="critical",
                                evidence={
                                    "parameter": param_name,
                                    "payload": blind_payload,
                                    "dbms_target": dbms,
                                    "baseline_time_s": round(baseline_duration, 3),
                                    "payload_time_s": round(elapsed, 3),
                                    "delay_s": round(delay, 3),
                                    "threshold_s": _BLIND_SQLI_THRESHOLD_S,
                                    "detection_type": "time-based_blind",
                                    "differential": True,
                                    "response_status": blind_resp.status_code,
                                },
                                affected_url=url,
                                remediation="Use parameterized queries or prepared statements. "
                                "Never concatenate user input into SQL queries. "
                                "Time-based blind SQLi is especially dangerous as it "
                                "requires no visible error messages.",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                            )
                        )
                        return  # Confirmed blind SQLi, stop testing
                except httpx.RequestError:
                    pass

    async def _check_xss(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for XSS via unique token reflection with differential analysis."""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        # Use a unique canary token so we don't match static page content
        canary = f"ALDECI{hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]}"
        for param_name in params:
            # Step 1: Check if the parameter reflects values at all using a unique canary
            canary_params = dict(params)
            canary_params[param_name] = [canary]
            try:
                canary_resp = await client.get(
                    f"{base_url}?{urlencode(canary_params, doseq=True)}",
                    headers=headers,
                    timeout=5.0,
                )
                if canary not in canary_resp.text:
                    continue  # Parameter is not reflected — skip
            except httpx.RequestError:
                continue
            # Step 2: Now test XSS payload — we know this param reflects
            for payload in XSS_PAYLOADS[:2]:
                test_params = dict(params)
                test_params[param_name] = [payload]
                try:
                    response = await client.get(
                        f"{base_url}?{urlencode(test_params, doseq=True)}",
                        headers=headers,
                        timeout=5.0,
                    )
                    if payload in response.text:
                        self._findings.append(
                            RealFinding(
                                finding_id=self._generate_finding_id(),
                                vulnerability_type=VulnerabilityType.XSS,
                                title="Reflected XSS Vulnerability Detected (Canary Confirmed)",
                                description=(
                                    f"XSS payload reflected without encoding in parameter '{param_name}'. "
                                    f"Confirmed via unique canary: param reflects arbitrary input."
                                ),
                                severity="high",
                                evidence={
                                    "parameter": param_name,
                                    "payload": payload,
                                    "reflected": True,
                                    "canary_reflected": True,
                                    "differential": True,
                                },
                                affected_url=url,
                                remediation="Encode all user input before reflecting it in responses. "
                                "Implement Content Security Policy headers.",
                                cwe_id="CWE-79",
                                cvss_score=7.5,
                            )
                        )
                        return
                except httpx.RequestError:
                    pass

    async def _check_information_disclosure(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for information disclosure in headers and error pages."""
        try:
            response = await client.get(url, headers=headers)

            # Check for server header leaking version info
            server = response.headers.get("Server", "")
            if re.search(r"[\d.]+", server):
                self._findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        title="Server Version Information Disclosure",
                        description=f"The Server header '{server}' reveals version information "
                        f"that could help attackers identify vulnerable software.",
                        severity="low",
                        evidence={"server_header": server},
                        affected_url=url,
                        remediation="Configure the server to hide or obscure version information.",
                        cwe_id="CWE-200",
                        cvss_score=3.0,
                    )
                )

            # Check for X-Powered-By header
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                self._findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        title="Technology Stack Disclosure via X-Powered-By",
                        description=f"The X-Powered-By header '{powered_by}' reveals "
                        f"the technology stack used by the application.",
                        severity="low",
                        evidence={"x_powered_by": powered_by},
                        affected_url=url,
                        remediation="Remove the X-Powered-By header from responses.",
                        cwe_id="CWE-200",
                        cvss_score=3.0,
                    )
                )

        except httpx.RequestError:
            pass

    async def _check_path_traversal(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for path traversal vulnerabilities."""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ]

        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                for payload in traversal_payloads[:1]:
                    test_params = dict(params)
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    try:
                        response = await client.get(test_url, headers=headers)

                        # Check for indicators of successful traversal
                        if "root:" in response.text or "daemon:" in response.text:
                            self._findings.append(
                                RealFinding(
                                    finding_id=self._generate_finding_id(),
                                    vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                                    title="Path Traversal Vulnerability Detected",
                                    description=f"Path traversal payload revealed system file contents "
                                    f"when testing parameter '{param_name}'.",
                                    severity="critical",
                                    evidence={
                                        "parameter": param_name,
                                        "payload": payload,
                                        "response_snippet": response.text[:500],
                                    },
                                    affected_url=url,
                                    remediation="Validate and sanitize file path inputs. "
                                    "Use allowlists for permitted files/directories.",
                                    cwe_id="CWE-22",
                                    cvss_score=9.1,
                                )
                            )
                            return

                    except httpx.RequestError:
                        pass

    async def _check_cors_misconfiguration(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for CORS misconfiguration vulnerabilities."""
        test_origins = ["https://evil.com", "null", "https://attacker.example.com"]
        for origin in test_origins:
            try:
                h = dict(headers or {})
                h["Origin"] = origin
                resp = await client.get(url, headers=h)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" or acao == origin:
                    sev = "high" if acac.lower() == "true" else "medium"
                    detail = f"ACAO reflects '{origin}'" + (
                        ", credentials allowed" if acac.lower() == "true" else ""
                    )
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.CORS_MISCONFIGURATION,
                            title="CORS Misconfiguration Detected",
                            description=f"Server reflects arbitrary Origin header. {detail}",
                            severity=sev,
                            evidence={
                                "origin_sent": origin,
                                "acao": acao,
                                "acac": acac,
                            },
                            affected_url=url,
                            remediation="Restrict Access-Control-Allow-Origin to trusted domains. "
                            "Never combine wildcard origin with Allow-Credentials: true.",
                            cwe_id="CWE-942",
                            cvss_score=7.5 if acac.lower() == "true" else 5.3,
                        )
                    )
                    return  # One finding per URL
            except httpx.RequestError:
                pass

    async def _check_cookie_security(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for insecure cookie configurations."""
        try:
            resp = await client.get(url, headers=headers)
            raw_cookies = (
                resp.headers.get_list("set-cookie")
                if hasattr(resp.headers, "get_list")
                else [
                    v
                    for k, v in resp.headers.multi_items()
                    if k.lower() == "set-cookie"
                ]
            )
            for cookie_str in raw_cookies:
                name = (
                    cookie_str.split("=")[0].strip()
                    if "=" in cookie_str
                    else cookie_str
                )
                lower = cookie_str.lower()
                issues = []
                if "secure" not in lower:
                    issues.append("missing Secure flag")
                if "httponly" not in lower:
                    issues.append("missing HttpOnly flag")
                if "samesite" not in lower:
                    issues.append("missing SameSite attribute")
                if issues:
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.COOKIE_SECURITY,
                            title=f"Insecure Cookie: {name}",
                            description=f"Cookie '{name}' has security issues: {', '.join(issues)}.",
                            severity="medium",
                            evidence={
                                "cookie_name": name,
                                "issues": issues,
                                "raw_header": cookie_str[:200],
                            },
                            affected_url=url,
                            remediation="Set Secure, HttpOnly, and SameSite=Strict on all sensitive cookies.",
                            cwe_id="CWE-614",
                            cvss_score=4.7,
                        )
                    )
        except httpx.RequestError:
            pass

    async def _check_http_methods(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Enumerate allowed HTTP methods and flag dangerous ones."""
        try:
            resp = await client.options(url, headers=headers)
            allow = resp.headers.get("Allow", "")
            if not allow:
                allow = resp.headers.get("Access-Control-Allow-Methods", "")
            if allow:
                methods = [m.strip().upper() for m in allow.split(",")]
                dangerous = [
                    m for m in methods if m in ("TRACE", "PUT", "DELETE", "CONNECT")
                ]
                if dangerous:
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.HTTP_METHOD_EXPOSURE,
                            title="Dangerous HTTP Methods Enabled",
                            description=f"Server allows potentially dangerous HTTP methods: {', '.join(dangerous)}.",
                            severity="medium" if "TRACE" in dangerous else "low",
                            evidence={
                                "allowed_methods": methods,
                                "dangerous_methods": dangerous,
                            },
                            affected_url=url,
                            remediation="Disable TRACE, PUT, DELETE, and CONNECT methods unless explicitly required.",
                            cwe_id="CWE-749",
                            cvss_score=5.3 if "TRACE" in dangerous else 3.7,
                        )
                    )
        except httpx.RequestError:
            pass

    async def _check_technology_fingerprinting(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Fingerprint web technologies from response headers and body."""
        try:
            resp = await client.get(url, headers=headers)
            techs = []
            server = resp.headers.get("Server", "")
            if server:
                techs.append(("Server", server))
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                techs.append(("Framework", powered))
            asp_ver = resp.headers.get("X-AspNet-Version", "")
            if asp_ver:
                techs.append(("ASP.NET", asp_ver))
            generator = resp.headers.get("X-Generator", "")
            if generator:
                techs.append(("Generator", generator))
            body = resp.text[:5000].lower()
            # Body-based detection
            fp_patterns = [
                ("WordPress", "wp-content"),
                ("Drupal", "drupal.settings"),
                ("Joomla", "joomla"),
                ("Django", "csrfmiddlewaretoken"),
                ("Laravel", "laravel_session"),
                ("Express", "x-powered-by: express"),
                ("React", "react"),
                ("Angular", "ng-version"),
                ("Vue.js", "data-v-"),
                ("Next.js", "__next"),
                ("Rails", "action_dispatch"),
                ("Spring", "x-application-context"),
                ("Tomcat", "apache-coyote"),
                ("nginx", "nginx"),
                ("IIS", "microsoft-iis"),
            ]
            for name, pattern in fp_patterns:
                if (
                    pattern in body
                    or pattern in server.lower()
                    or pattern in powered.lower()
                ):
                    techs.append(("Technology", name))
            if techs:
                self._findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.TECHNOLOGY_FINGERPRINT,
                        title="Technology Stack Fingerprinted",
                        description=f"Detected {len(techs)} technology indicators. "
                        "Detailed version information aids targeted attacks.",
                        severity="info",
                        evidence={
                            "technologies": [{"type": t, "value": v} for t, v in techs]
                        },
                        affected_url=url,
                        remediation="Remove version information from Server/X-Powered-By headers. "
                        "Use generic error pages to reduce technology fingerprinting.",
                        cwe_id="CWE-200",
                        cvss_score=0.0,
                    )
                )
        except httpx.RequestError:
            pass

    async def _check_waf_detection(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect presence of WAF/CDN/security appliances."""
        waf_indicators = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
            "Akamai": ["x-akamai-transformed", "akamai-origin-hop"],
            "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
            "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
            "F5 BIG-IP": ["x-cnection", "bigipserver"],
            "Barracuda": ["barra_counter_session"],
            "ModSecurity": ["mod_security", "modsecurity"],
        }
        try:
            resp = await client.get(url, headers=headers)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            detected = []
            for waf_name, indicators in waf_indicators.items():
                for ind in indicators:
                    if ind.lower() in resp_headers_lower:
                        detected.append(waf_name)
                        break
            # Also try a malicious-looking request to trigger WAF
            try:
                atk_resp = await client.get(
                    url + "?id=1' OR 1=1--&<script>alert(1)</script>",
                    headers=headers,
                    timeout=5.0,
                )
                if (
                    atk_resp.status_code in (403, 406, 429, 503)
                    and resp.status_code == 200
                ):
                    detected.append("WAF (behavior-based)")
            except httpx.RequestError:
                pass
            if detected:
                self._findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.WAF_DETECTION,
                        title=f"WAF/CDN Detected: {', '.join(set(detected))}",
                        description=f"Detected {len(set(detected))} security appliance(s). "
                        "This is informational and indicates defense-in-depth.",
                        severity="info",
                        evidence={
                            "detected_wafs": list(set(detected)),
                            "header_indicators": dict(resp_headers_lower),
                        },
                        affected_url=url,
                        remediation="WAF detected is positive. Ensure rules are up-to-date and properly tuned.",
                        cwe_id="CWE-693",
                        cvss_score=0.0,
                    )
                )
        except httpx.RequestError:
            pass

    async def _check_open_redirect(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for open redirect vulnerabilities.

        Uses hostname-level validation to avoid false positives: the Location
        header's **hostname** must match the evil probe domain.  A substring
        match is not enough — many servers (e.g. Google) redirect to their own
        error/CAPTCHA pages and include the original URL as a query parameter,
        which would cause a naive ``in`` check to false-positive.
        """
        redirect_params = [
            "url",
            "redirect",
            "next",
            "dest",
            "destination",
            "redir",
            "redirect_uri",
            "return",
            "returnTo",
            "go",
            "target",
            "link",
            "out",
        ]
        evil_host = "evil.example.com"
        redirect_target = f"https://{evil_host}"
        parsed = urlparse(url)
        original_host = parsed.hostname or ""
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in redirect_params:
            try:
                test_url = f"{base}?{param}={redirect_target}"
                resp = await client.get(
                    test_url, headers=headers, follow_redirects=False, timeout=5.0
                )
                location = resp.headers.get("Location", "")
                if resp.status_code not in (301, 302, 303, 307, 308) or not location:
                    continue
                # Parse the Location URL and check the HOSTNAME — not a substring
                loc_parsed = urlparse(location)
                loc_host = (loc_parsed.hostname or "").lower()
                # Redirect goes to evil domain → confirmed open redirect
                if loc_host == evil_host or loc_host.endswith(f".{evil_host}"):
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.OPEN_REDIRECT,
                            title=f"Open Redirect via '{param}' Parameter",
                            description=f"Server redirects to attacker-controlled URL when '{param}' "
                            f"parameter is set to an external domain.",
                            severity="medium",
                            evidence={
                                "parameter": param,
                                "redirect_target": redirect_target,
                                "location_header": location,
                                "status_code": resp.status_code,
                            },
                            affected_url=url,
                            remediation="Validate redirect URLs against an allowlist of trusted domains. "
                            "Use relative paths instead of full URLs.",
                            cwe_id="CWE-601",
                            cvss_score=6.1,
                        )
                    )
                    return  # One finding per URL
                # Redirect stays on same host but embeds evil URL → NOT vulnerable
                # (server is blocking the redirect, e.g. Google /sorry/ page)
                if loc_host == original_host or loc_host.endswith(f".{original_host}"):
                    continue
                # Redirect goes to a DIFFERENT external domain (not the probe) —
                # still suspicious but not a confirmed open redirect to our probe
            except httpx.RequestError:
                pass

    async def _check_crlf_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Check for CRLF injection in HTTP headers."""
        crlf_payloads = [
            "%0d%0aX-Injected: true",
            "%0d%0aSet-Cookie: crlf=injected",
            "\\r\\nX-CRLF-Test: true",
        ]
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for payload in crlf_payloads:
            try:
                test_url = f"{base}?q={payload}"
                resp = await client.get(
                    test_url, headers=headers, follow_redirects=False, timeout=5.0
                )
                if "x-injected" in resp.headers or "x-crlf-test" in resp.headers:
                    self._findings.append(
                        RealFinding(
                            finding_id=self._generate_finding_id(),
                            vulnerability_type=VulnerabilityType.CRLF_INJECTION,
                            title="CRLF Injection Detected",
                            description="Server processes CRLF sequences in URL parameters, allowing "
                            "HTTP response splitting and header injection.",
                            severity="high",
                            evidence={
                                "payload": payload,
                                "injected_header_found": True,
                                "response_headers": dict(resp.headers),
                            },
                            affected_url=url,
                            remediation="Sanitize all user input that appears in HTTP headers. "
                            "Strip CR (\\r) and LF (\\n) characters from header values.",
                            cwe_id="CWE-93",
                            cvss_score=7.5,
                        )
                    )
                    return
            except httpx.RequestError:
                pass

    async def _check_api_endpoint_discovery(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Discover exposed API endpoints and documentation."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        api_paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/graphql",
            "/graphiql",
            "/swagger",
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger.json",
            "/openapi.json",
            "/openapi.yaml",
            "/docs",
            "/redoc",
            "/api-docs",
            "/api/docs",
            "/.well-known/openid-configuration",
            "/actuator",
            "/actuator/health",
            "/actuator/env",
            "/debug",
            "/debug/vars",
            "/debug/pprof",
            "/metrics",
            "/prometheus/metrics",
            "/health",
            "/healthz",
            "/readyz",
            "/status",
            "/admin",
            "/admin/login",
            "/wp-admin",
            "/.env",
            "/config",
            "/config.json",
            "/server-status",
            "/server-info",
            "/phpinfo.php",
            "/info.php",
        ]
        discovered = []
        for path in api_paths:
            try:
                resp = await client.get(
                    urljoin(base, path), headers=headers, timeout=3.0
                )
                if resp.status_code in (200, 301, 302, 401):
                    content_type = resp.headers.get("Content-Type", "")
                    discovered.append(
                        {
                            "path": path,
                            "status_code": resp.status_code,
                            "content_type": content_type[:80],
                            "content_length": len(resp.content),
                        }
                    )
            except httpx.RequestError:
                pass
        if discovered:
            sensitive = [
                d
                for d in discovered
                if any(
                    s in d["path"]
                    for s in [
                        ".env",
                        "config",
                        "debug",
                        "admin",
                        "actuator/env",
                        "phpinfo",
                        "server-status",
                        "server-info",
                        "swagger",
                        "graphiql",
                    ]
                )
            ]
            sev = "high" if sensitive else "info"
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.API_EXPOSURE,
                    title=f"API/Endpoint Discovery: {len(discovered)} endpoints found",
                    description=f"Discovered {len(discovered)} accessible endpoints. "
                    f"{len(sensitive)} are potentially sensitive.",
                    severity=sev,
                    evidence={
                        "endpoints": discovered,
                        "sensitive_endpoints": sensitive,
                        "total": len(discovered),
                    },
                    affected_url=url,
                    remediation="Restrict access to admin panels, debug endpoints, and API documentation in production. "
                    "Use authentication and network-level access controls.",
                    cwe_id="CWE-200",
                    cvss_score=7.5 if sensitive else 0.0,
                )
            )

    async def _check_ssti(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect Server-Side Template Injection via differential math evaluation."""
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # Unique math probe: if the server evaluates the expression, the result shows up
        probes = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("{{7*'7'}}", "7777777"),  # Jinja2
            ("#{7*7}", "49"),
        ]
        for param_name in params:
            # First get baseline with benign value
            benign_params = dict(params)
            benign_params[param_name] = ["ALDECI_BENIGN_PROBE"]
            try:
                benign_resp = await client.get(
                    f"{base_url}?{urlencode(benign_params, doseq=True)}",
                    headers=headers,
                    timeout=5.0,
                )
                benign_text = benign_resp.text
            except httpx.RequestError:
                continue
            for tpl, expected in probes:
                test_params = dict(params)
                test_params[param_name] = [tpl]
                try:
                    resp = await client.get(
                        f"{base_url}?{urlencode(test_params, doseq=True)}",
                        headers=headers,
                        timeout=5.0,
                    )
                    # Only flag if: (a) expected result appears AND (b) it was NOT in benign response
                    if expected in resp.text and expected not in benign_text:
                        self._findings.append(
                            RealFinding(
                                finding_id=self._generate_finding_id(),
                                vulnerability_type=VulnerabilityType.SSTI,
                                title="Server-Side Template Injection (SSTI) Detected",
                                description=(
                                    f"Template expression '{tpl}' evaluated to '{expected}' "
                                    f"on parameter '{param_name}'. Confirms server-side template evaluation."
                                ),
                                severity="critical",
                                evidence={
                                    "parameter": param_name,
                                    "payload": tpl,
                                    "expected_result": expected,
                                    "reflected": True,
                                    "differential": True,
                                    "benign_contained_result": False,
                                },
                                affected_url=url,
                                remediation="Sanitize all user input before template rendering. "
                                "Use sandboxed template engines. Avoid rendering user input as templates.",
                                cwe_id="CWE-1336",
                                cvss_score=9.8,
                            )
                        )
                        return
                except httpx.RequestError:
                    pass

    async def _check_http_request_smuggling(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect HTTP Request Smuggling indicators via CL.TE / TE.CL probes."""
        indicators = []
        # Probe 1: Send conflicting Content-Length + Transfer-Encoding
        smuggle_headers = dict(headers or {})
        smuggle_headers["Transfer-Encoding"] = "chunked"
        smuggle_headers["Content-Length"] = "4"
        try:
            resp = await client.post(
                url,
                headers=smuggle_headers,
                content="0\r\n\r\n",
                timeout=8.0,
            )
            # A properly hardened server rejects conflicting CL/TE or returns 400
            if resp.status_code not in (400, 405, 501):
                indicators.append(
                    {
                        "probe": "CL.TE conflict",
                        "status_code": resp.status_code,
                        "note": "Server accepted conflicting Content-Length and Transfer-Encoding",
                    }
                )
        except httpx.RequestError:
            pass
        # Probe 2: Multiple Transfer-Encoding headers (obfuscation)
        try:
            te_headers = dict(headers or {})
            te_headers["Transfer-Encoding"] = "chunked"
            te_headers["Transfer-encoding"] = "cow"  # case variant
            resp2 = await client.post(
                url,
                headers=te_headers,
                content="0\r\n\r\n",
                timeout=8.0,
            )
            if resp2.status_code not in (400, 405, 501):
                indicators.append(
                    {
                        "probe": "TE.TE obfuscation",
                        "status_code": resp2.status_code,
                        "note": "Server accepted obfuscated Transfer-Encoding headers",
                    }
                )
        except httpx.RequestError:
            pass
        # Only flag if MULTIPLE indicators suggest smuggling susceptibility
        if len(indicators) >= 2:
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.HTTP_REQUEST_SMUGGLING,
                    title="HTTP Request Smuggling Indicators Detected",
                    description=(
                        f"Server shows {len(indicators)} indicators of HTTP Request Smuggling susceptibility. "
                        "Conflicting Content-Length/Transfer-Encoding headers were not rejected."
                    ),
                    severity="high",
                    evidence={
                        "indicators": indicators,
                        "indicator_count": len(indicators),
                    },
                    affected_url=url,
                    remediation="Ensure front-end and back-end servers normalize Transfer-Encoding handling. "
                    "Reject ambiguous requests with conflicting CL/TE. "
                    "Use HTTP/2 end-to-end to eliminate smuggling vectors.",
                    cwe_id="CWE-444",
                    cvss_score=8.1,
                )
            )

    async def _check_host_header_injection(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect Host Header Injection via differential response analysis."""
        canary = "aldeci-evil.example.com"
        try:
            # Baseline with legitimate Host
            baseline = await client.get(url, headers=headers, timeout=5.0)
            baseline_text = baseline.text
            # Inject evil host
            evil_headers = dict(headers or {})
            evil_headers["Host"] = canary
            evil_resp = await client.get(url, headers=evil_headers, timeout=5.0)
            evil_text = evil_resp.text
            # Only flag if the canary host is reflected back in the response body
            if canary in evil_text and canary not in baseline_text:
                self._findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.HOST_HEADER_INJECTION,
                        title="Host Header Injection Detected",
                        description=(
                            f"Injected Host header '{canary}' was reflected in the response body. "
                            "This can lead to cache poisoning, password reset hijacking, or SSRF."
                        ),
                        severity="high",
                        evidence={
                            "injected_host": canary,
                            "reflected": True,
                            "differential": True,
                            "baseline_contained_canary": False,
                        },
                        affected_url=url,
                        remediation="Validate the Host header against an allowed list. "
                        "Never use the Host header to generate URLs in responses.",
                        cwe_id="CWE-644",
                        cvss_score=7.5,
                    )
                )
        except httpx.RequestError:
            pass

    async def _check_deserialization(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect insecure deserialization indicators by probing accept/content headers."""
        indicators = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        # Check if the server accepts Java serialized objects
        deser_probes = [
            {"Accept": "application/x-java-serialized-object"},
            {"Content-Type": "application/x-java-serialized-object"},
            {"Accept": "application/x-python-serialize"},
        ]
        for probe_headers in deser_probes:
            try:
                h = dict(headers or {})
                h.update(probe_headers)
                resp = await client.get(url, headers=h, timeout=5.0)
                ct = resp.headers.get("Content-Type", "")
                # Server responding with serialized content type is an indicator
                if "java-serialized" in ct or "python-serialize" in ct:
                    indicators.append(
                        {
                            "sent_header": probe_headers,
                            "response_content_type": ct,
                        }
                    )
            except httpx.RequestError:
                pass
        # Also check for common deserialization endpoints
        deser_paths = [
            "/invoker/JMXInvokerServlet",
            "/invoker/EJBInvokerServlet",
            "/jmx-console",
            "/_session",
        ]
        for path in deser_paths:
            try:
                resp = await client.get(
                    urljoin(base, path), headers=headers, timeout=3.0
                )
                if resp.status_code in (200, 401, 403, 500):
                    indicators.append({"path": path, "status_code": resp.status_code})
            except httpx.RequestError:
                pass
        if indicators:
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.DESERIALIZATION,
                    title=f"Insecure Deserialization Indicators ({len(indicators)} signals)",
                    description=(
                        f"Detected {len(indicators)} indicators of insecure deserialization: "
                        "the server accepts or exposes serialized object endpoints."
                    ),
                    severity="high" if len(indicators) >= 2 else "medium",
                    evidence={"indicators": indicators, "count": len(indicators)},
                    affected_url=url,
                    remediation="Disable Java/Python deserialization endpoints. "
                    "Use allowlists for deserialized classes. "
                    "Prefer JSON/Protocol Buffers over native serialization.",
                    cwe_id="CWE-502",
                    cvss_score=8.1 if len(indicators) >= 2 else 5.5,
                )
            )

    async def _check_cache_poisoning(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect web cache poisoning via unkeyed header reflection."""
        canary = "aldeci-cache-probe-12345"
        # Unkeyed headers commonly used in cache poisoning attacks
        probe_headers_list = [
            {"X-Forwarded-Host": canary},
            {"X-Forwarded-Scheme": "nothttps"},
            {"X-Original-URL": f"/{canary}"},
            {"X-Rewrite-URL": f"/{canary}"},
        ]
        try:
            baseline = await client.get(url, headers=headers, timeout=5.0)
            baseline_text = baseline.text
            baseline_hdrs = dict(baseline.headers)
        except httpx.RequestError:
            return
        poisoned = []
        for probe in probe_headers_list:
            try:
                h = dict(headers or {})
                h.update(probe)
                resp = await client.get(url, headers=h, timeout=5.0)
                resp_text = resp.text
                header_name = list(probe.keys())[0]
                probe_val = list(probe.values())[0]
                # Check if probe value reflected in body or response headers
                reflected_in_body = (
                    probe_val in resp_text and probe_val not in baseline_text
                )
                reflected_in_headers = any(
                    probe_val in v for v in resp.headers.values()
                ) and not any(probe_val in v for v in baseline_hdrs.values())
                if reflected_in_body or reflected_in_headers:
                    poisoned.append(
                        {
                            "header": header_name,
                            "value": probe_val,
                            "reflected_in_body": reflected_in_body,
                            "reflected_in_headers": reflected_in_headers,
                        }
                    )
            except httpx.RequestError:
                pass
        if poisoned:
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.CACHE_POISONING,
                    title=f"Cache Poisoning via Unkeyed Headers ({len(poisoned)} vectors)",
                    description=(
                        f"Unkeyed header values reflected in {len(poisoned)} vectors. "
                        "If a cache sits in front, these reflections can poison cached responses."
                    ),
                    severity="high",
                    evidence={"poisoned_vectors": poisoned, "count": len(poisoned)},
                    affected_url=url,
                    remediation="Include all varied headers in cache keys. "
                    "Strip unexpected X-Forwarded-* headers at the edge. "
                    "Use Vary header or disable caching for dynamic content.",
                    cwe_id="CWE-349",
                    cvss_score=7.5,
                )
            )

    # ── Phase 20: SSRF Detection ───────────────────────────────────
    async def _check_ssrf(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect Server-Side Request Forgery (SSRF) vulnerabilities.

        Tests URL-accepting parameters by injecting internal/cloud metadata
        URLs and checking for response anomalies (status changes, body size
        shifts, error messages revealing outbound connections, or timing
        differences indicating the server followed the injected URL).
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Collect candidate parameters: from query string + common SSRF param names
        existing_params = parse_qs(parsed.query) if parsed.query else {}
        candidate_params: List[str] = list(existing_params.keys())
        # Also probe well-known SSRF-prone parameter names not already present
        for p in _SSRF_PROBE_PARAMS:
            if p not in candidate_params:
                candidate_params.append(p)

        if not candidate_params:
            return

        # Get baseline response for differential comparison
        try:
            baseline_t0 = time.monotonic()
            baseline_resp = await client.get(url, headers=headers, timeout=8.0)
            baseline_duration = time.monotonic() - baseline_t0
            baseline_status = baseline_resp.status_code
            baseline_size = len(baseline_resp.content)
            baseline_text = baseline_resp.text[:5000].lower()
        except httpx.RequestError:
            return

        for param_name in candidate_params:
            for probe_url in _SSRF_PROBE_URLS:
                test_params = dict(existing_params)
                test_params[param_name] = [probe_url]
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"

                try:
                    t0 = time.monotonic()
                    resp = await client.get(
                        test_url, headers=headers, timeout=8.0
                    )
                    elapsed = time.monotonic() - t0
                    resp_text = resp.text[:5000].lower()
                    resp_size = len(resp.content)

                    indicators: List[str] = []

                    # Indicator 1: Status code changed significantly
                    if resp.status_code != baseline_status and resp.status_code not in (
                        400, 404, 422,
                    ):
                        indicators.append(
                            f"status changed {baseline_status} -> {resp.status_code}"
                        )

                    # Indicator 2: Response body size changed >50%
                    if baseline_size > 0:
                        size_ratio = abs(resp_size - baseline_size) / baseline_size
                        if size_ratio > 0.5:
                            indicators.append(
                                f"body size changed {baseline_size} -> {resp_size} "
                                f"({size_ratio:.0%} delta)"
                            )

                    # Indicator 3: Error messages indicating outbound connection
                    for error_indicator in _SSRF_ERROR_INDICATORS:
                        if (
                            error_indicator in resp_text
                            and error_indicator not in baseline_text
                        ):
                            indicators.append(
                                f"network error leaked: '{error_indicator}'"
                            )
                            break

                    # Indicator 4: Blind SSRF via timing (response >3s slower)
                    timing_delay = elapsed - baseline_duration
                    if timing_delay > 3.0:
                        indicators.append(
                            f"timing anomaly: {timing_delay:.1f}s slower "
                            f"(baseline {baseline_duration:.2f}s, "
                            f"probe {elapsed:.2f}s)"
                        )

                    if indicators:
                        self._findings.append(
                            RealFinding(
                                finding_id=self._generate_finding_id(),
                                vulnerability_type=VulnerabilityType.SSRF,
                                title=f"Potential SSRF via '{param_name}' Parameter",
                                description=(
                                    f"Parameter '{param_name}' shows SSRF indicators when "
                                    f"injected with internal URL '{probe_url}'. "
                                    f"Signals: {'; '.join(indicators)}."
                                ),
                                severity="high",
                                evidence={
                                    "parameter": param_name,
                                    "probe_url": probe_url,
                                    "indicators": indicators,
                                    "indicator_count": len(indicators),
                                    "baseline_status": baseline_status,
                                    "probe_status": resp.status_code,
                                    "baseline_size": baseline_size,
                                    "probe_size": resp_size,
                                    "baseline_time_s": round(baseline_duration, 3),
                                    "probe_time_s": round(elapsed, 3),
                                    "differential": True,
                                },
                                affected_url=url,
                                remediation=(
                                    "Validate and sanitize all user-supplied URLs. "
                                    "Block requests to internal IP ranges (127.0.0.0/8, "
                                    "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, "
                                    "169.254.0.0/16). Use an allowlist of permitted "
                                    "external domains. Disable HTTP redirects in "
                                    "server-side HTTP clients."
                                ),
                                cwe_id="CWE-918",
                                cvss_score=7.5,
                            )
                        )
                        return  # One SSRF finding per URL is sufficient

                except httpx.RequestError:
                    pass

    # ── Phase 21: CSRF Detection ───────────────────────────────────
    async def _check_csrf(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Detect Cross-Site Request Forgery (CSRF) vulnerabilities.

        Fetches the target URL, parses HTML forms via regex, and checks
        whether POST forms include CSRF protection tokens, SameSite cookie
        attributes, or CSRF-related response headers.
        """
        try:
            resp = await client.get(url, headers=headers, timeout=8.0)
            body = resp.text
        except httpx.RequestError:
            return

        # Check response-level CSRF protections
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        has_csrf_header = any(
            h in resp_headers_lower
            for h in ("x-csrf-token", "x-xsrf-token", "csrf-token")
        )

        # Check if SameSite cookies are set
        raw_cookies = [
            v
            for k, v in resp.headers.multi_items()
            if k.lower() == "set-cookie"
        ]
        has_samesite_cookie = any(
            "samesite" in c.lower() for c in raw_cookies
        )

        # Parse <form> tags from the HTML body
        # Match <form ...> blocks: extract action and method attributes
        form_pattern = re.compile(
            r"<form\b([^>]*)>(.*?)</form>",
            re.IGNORECASE | re.DOTALL,
        )
        method_pattern = re.compile(
            r"""method\s*=\s*["']?(\w+)["']?""", re.IGNORECASE
        )
        action_pattern = re.compile(
            r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE
        )
        # Pattern for hidden input fields that look like CSRF tokens
        hidden_input_pattern = re.compile(
            r"""<input\b[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["']([^"']+)["'][^>]*/?>""",
            re.IGNORECASE,
        )
        # Also match reversed attribute order (name before type)
        hidden_input_pattern_alt = re.compile(
            r"""<input\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*type\s*=\s*["']hidden["'][^>]*/?>""",
            re.IGNORECASE,
        )

        vulnerable_forms: List[Dict[str, Any]] = []

        for form_match in form_pattern.finditer(body):
            form_attrs = form_match.group(1)
            form_body = form_match.group(2)

            # Extract method (default GET)
            method_m = method_pattern.search(form_attrs)
            method = method_m.group(1).upper() if method_m else "GET"

            # Only POST forms need CSRF protection
            if method != "POST":
                continue

            # Extract action
            action_m = action_pattern.search(form_attrs)
            action = action_m.group(1) if action_m else ""

            # Check for CSRF token in hidden fields
            hidden_names: List[str] = []
            for pattern in (hidden_input_pattern, hidden_input_pattern_alt):
                hidden_names.extend(
                    m.group(1).lower() for m in pattern.finditer(form_body)
                )

            has_csrf_field = any(
                any(token_name in field_name for token_name in _CSRF_TOKEN_NAMES)
                for field_name in hidden_names
            )

            if not has_csrf_field and not has_csrf_header and not has_samesite_cookie:
                vulnerable_forms.append({
                    "action": action or "(self)",
                    "method": method,
                    "hidden_fields": list(set(hidden_names)),
                    "csrf_token_found": False,
                    "csrf_header_present": has_csrf_header,
                    "samesite_cookie_present": has_samesite_cookie,
                })

        if vulnerable_forms:
            self._findings.append(
                RealFinding(
                    finding_id=self._generate_finding_id(),
                    vulnerability_type=VulnerabilityType.CSRF,
                    title=f"CSRF Vulnerability: {len(vulnerable_forms)} Unprotected POST Form(s)",
                    description=(
                        f"Found {len(vulnerable_forms)} POST form(s) without CSRF protection. "
                        "No CSRF token field, no X-CSRF-Token response header, and no "
                        "SameSite cookie attribute detected. An attacker can forge "
                        "cross-origin requests to these forms."
                    ),
                    severity="medium",
                    evidence={
                        "vulnerable_forms": vulnerable_forms[:10],  # Cap at 10 for readability
                        "total_vulnerable_forms": len(vulnerable_forms),
                        "csrf_header_present": has_csrf_header,
                        "samesite_cookie_present": has_samesite_cookie,
                    },
                    affected_url=url,
                    remediation=(
                        "Add CSRF tokens to all state-changing forms. Use a framework-provided "
                        "CSRF middleware (e.g., Django CSRF, Rails authenticity_token). "
                        "Set SameSite=Strict or SameSite=Lax on session cookies. "
                        "Verify the Origin/Referer header on the server side."
                    ),
                    cwe_id="CWE-352",
                    cvss_score=5.5,
                )
            )

    def _generate_finding_id(self) -> str:
        """Generate a unique finding ID."""
        import uuid

        return str(uuid.uuid4())

    def _severity_to_cvss(self, severity: str) -> float:
        """Convert severity string to CVSS score."""
        mapping = {
            "critical": 9.5,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        return mapping.get(severity.lower(), 5.0)


class RealSecretsScanner:
    """Real secrets scanner using pattern matching.

    This scanner detects secrets in code without requiring external tools.
    """

    def scan_content(self, content: str, filename: str = "") -> List[RealFinding]:
        """Scan content for secrets using regex patterns.

        Args:
            content: File content to scan
            filename: Optional filename for context

        Returns:
            List of secret findings
        """
        findings = []

        for secret_name, (pattern, severity, cwe_id) in SECRETS_PATTERNS.items():
            for match in re.finditer(pattern, content, re.MULTILINE):
                # Calculate line number
                line_number = content[: match.start()].count("\n") + 1

                # Redact the secret for safe reporting
                matched_text = match.group()
                redacted = self._redact_secret(matched_text)

                findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.SECRETS_EXPOSURE,
                        title=f"{secret_name} Detected",
                        description=f"A {secret_name.lower()} was found in the code at line {line_number}. "
                        f"Hardcoded secrets pose a security risk if the code is exposed.",
                        severity=severity,
                        evidence={
                            "secret_type": secret_name,
                            "line_number": line_number,
                            "redacted_match": redacted,
                            "filename": filename,
                        },
                        affected_url=filename,
                        remediation="Remove hardcoded secrets and use environment variables "
                        "or a secrets manager instead. Rotate the exposed secret immediately.",
                        cwe_id=cwe_id,
                        cvss_score=self._severity_to_cvss(severity),
                        verified=True,
                    )
                )

        return findings

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret for safe reporting."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _generate_finding_id(self) -> str:
        import uuid

        return str(uuid.uuid4())

    def _severity_to_cvss(self, severity: str) -> float:
        mapping = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}
        return mapping.get(severity.lower(), 5.0)


class RealIaCScanner:
    """Real IaC scanner using pattern matching.

    This scanner detects IaC misconfigurations without requiring Checkov or tfsec.
    """

    def scan_content(self, content: str, filename: str = "") -> List[RealFinding]:
        """Scan IaC content for misconfigurations.

        Args:
            content: IaC file content
            filename: Filename for provider detection

        Returns:
            List of IaC misconfiguration findings
        """
        findings = []
        file_type = self._detect_file_type(filename)

        for rule_name, (pattern, severity, cwe_id, applies_to) in IAC_PATTERNS.items():
            # Check if pattern applies to this file type
            if applies_to not in file_type and applies_to != "all":
                continue

            for match in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
                line_number = content[: match.start()].count("\n") + 1

                findings.append(
                    RealFinding(
                        finding_id=self._generate_finding_id(),
                        vulnerability_type=VulnerabilityType.IAC_MISCONFIGURATION,
                        title=f"IaC Misconfiguration: {rule_name}",
                        description=f"A security misconfiguration was detected at line {line_number}. "
                        f"This configuration may expose resources to security risks.",
                        severity=severity,
                        evidence={
                            "rule": rule_name,
                            "line_number": line_number,
                            "matched_content": match.group()[:200],
                            "filename": filename,
                            "file_type": file_type,
                        },
                        affected_url=filename,
                        remediation=self._get_remediation(rule_name),
                        cwe_id=cwe_id,
                        cvss_score=self._severity_to_cvss(severity),
                        verified=True,
                    )
                )

        return findings

    def _detect_file_type(self, filename: str) -> str:
        """Detect file type from filename."""
        filename_lower = filename.lower()
        if filename_lower.endswith(".tf") or filename_lower.endswith(".tfvars"):
            return "tf"
        elif filename_lower.endswith((".yaml", ".yml")):
            return "yaml"
        elif filename_lower == "dockerfile" or filename_lower.startswith("dockerfile."):
            return "Dockerfile"
        elif filename_lower.endswith(".json"):
            return "json"
        return "unknown"

    def _get_remediation(self, rule_name: str) -> str:
        """Get remediation advice for a rule."""
        remediations = {
            "Hardcoded AWS Keys": "Remove hardcoded credentials and use IAM roles or environment variables.",
            "Unencrypted S3 Bucket": "Enable server-side encryption on the S3 bucket.",
            "Public S3 Bucket ACL": "Set the bucket ACL to 'private' unless public access is required.",
            "Unrestricted Security Group": "Restrict CIDR blocks to specific IP ranges instead of 0.0.0.0/0.",
            "Unencrypted RDS": "Set storage_encrypted = true for the RDS instance.",
            "Privileged Container": "Set privileged: false unless absolutely necessary.",
            "Root User Container": "Specify a non-root user with runAsUser.",
            "Missing Resource Limits": "Add resource requests and limits to prevent resource exhaustion.",
            "Host Network Access": "Set hostNetwork: false unless required for networking purposes.",
            "Host PID Namespace": "Set hostPID: false to isolate container processes.",
            "Running as Root": "Add a USER directive with a non-root user.",
            "Using Latest Tag": "Pin container images to specific versions instead of 'latest'.",
            "Exposed Sensitive Port": "Avoid exposing administrative ports like SSH (22) or RDP (3389).",
            "Unencrypted EBS Volume": "Set Encrypted: true for EBS volumes.",
            "Public Subnet": "Set MapPublicIpOnLaunch: false for private subnets.",
        }
        return remediations.get(
            rule_name, "Review and fix the security misconfiguration."
        )

    def _generate_finding_id(self) -> str:
        import uuid

        return str(uuid.uuid4())

    def _severity_to_cvss(self, severity: str) -> float:
        mapping = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}
        return mapping.get(severity.lower(), 5.0)


# Singleton instances
_vuln_scanner: Optional[RealVulnerabilityScanner] = None
_secrets_scanner: Optional[RealSecretsScanner] = None
_iac_scanner: Optional[RealIaCScanner] = None


def get_real_vuln_scanner() -> RealVulnerabilityScanner:
    """Get the singleton vulnerability scanner instance."""
    global _vuln_scanner
    if _vuln_scanner is None:
        _vuln_scanner = RealVulnerabilityScanner()
    return _vuln_scanner


def get_real_secrets_scanner() -> RealSecretsScanner:
    """Get the singleton secrets scanner instance."""
    global _secrets_scanner
    if _secrets_scanner is None:
        _secrets_scanner = RealSecretsScanner()
    return _secrets_scanner


def get_real_iac_scanner() -> RealIaCScanner:
    """Get the singleton IaC scanner instance."""
    global _iac_scanner
    if _iac_scanner is None:
        _iac_scanner = RealIaCScanner()
    return _iac_scanner
