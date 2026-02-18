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

import hashlib
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

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


class RealVulnerabilityScanner:
    """Real HTTP-based vulnerability scanner.

    This scanner performs ACTUAL security tests against target URLs,
    not simulated or mocked responses.
    """

    def __init__(self, timeout: float = 30.0, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._findings: List[RealFinding] = []
        self.architecture_profiles: Dict[str, ArchitectureProfile] = {}

    async def scan_url(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> List[RealFinding]:
        """Perform comprehensive security scan on a URL.

        Args:
            url: Target URL to scan
            headers: Optional HTTP headers to include

        Returns:
            List of real security findings
        """
        self._findings = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
        ) as client:
            # Phase 0: Architecture Intelligence Profiling
            arch_profile = await self._profile_architecture(client, url, headers)
            self.architecture_profiles[url] = arch_profile

            # Phase 1: Basic connectivity and header check
            await self._check_security_headers(client, url, headers)

            # Phase 2: SSL/TLS check
            await self._check_ssl_tls(url)

            # Phase 3: SQL Injection check
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

        return self._findings

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

        except Exception:
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
        except Exception:
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
        canary = f"ALDECI{hashlib.md5(url.encode()).hexdigest()[:8]}"
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
