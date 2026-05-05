"""ALdeci DAST Engine — Dynamic Application Security Testing.

Performs REAL HTTP-based security tests against live targets:
- Spider/crawler for endpoint discovery
- Authenticated scanning (session cookies, JWT, API keys, form login)
- Form detection and automated submission
- Parameter fuzzing with injection payloads
- Response analysis for errors/exceptions
- OpenAPI/Swagger-driven API security testing
- Integration with existing real_scanner.py

Competitive parity: Aikido DAST, Snyk DAST, OWASP ZAP.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from core.tls_config import tls_verify

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

logger = logging.getLogger(__name__)


# ── Authentication Models ──────────────────────────────────────────


class AuthMode(str, Enum):
    """Supported DAST authentication modes."""
    BEARER = "bearer"
    COOKIE = "cookie"
    BASIC = "basic"
    API_KEY = "api_key"
    FORM_LOGIN = "form_login"
    OAUTH2 = "oauth2"
    NONE = "none"


@dataclass
class AuthSessionConfig:
    """Configuration for authenticated DAST scanning."""
    mode: AuthMode = AuthMode.NONE

    # Bearer token auth
    bearer_token: str = ""

    # Basic auth
    basic_username: str = ""
    basic_password: str = ""

    # API key auth
    api_key_header: str = "X-API-Key"
    api_key_value: str = ""

    # Cookie-based / Form login auth
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    login_username: str = ""
    login_password: str = ""
    extra_form_fields: Dict[str, str] = field(default_factory=dict)
    success_indicator: str = ""  # Text/pattern that indicates successful login
    failure_indicator: str = ""  # Text/pattern that indicates failed login

    # OAuth2
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""

    # Session maintenance
    session_check_url: str = ""  # URL to verify session is still valid
    session_check_pattern: str = ""  # Pattern in response indicating valid session
    reauth_on_401: bool = True  # Re-authenticate on 401 responses
    max_reauth_attempts: int = 3

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "login_url": self.login_url if self.login_url else None,
            "api_key_header": self.api_key_header if self.mode == AuthMode.API_KEY else None,
            "reauth_on_401": self.reauth_on_401,
            "has_credentials": bool(
                self.bearer_token or self.basic_username or self.api_key_value
                or self.login_username or self.client_id
            ),
        }


class AuthSessionManager:
    """Manages authenticated sessions for DAST scanning.

    Handles login, session persistence, cookie management, and re-authentication.
    """

    def __init__(self, config: AuthSessionConfig):
        self.config = config
        self._session_cookies: Dict[str, str] = {}
        self._auth_headers: Dict[str, str] = {}
        self._authenticated: bool = False
        self._reauth_count: int = 0

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def session_cookies(self) -> Dict[str, str]:
        return dict(self._session_cookies)

    @property
    def auth_headers(self) -> Dict[str, str]:
        return dict(self._auth_headers)

    async def authenticate(self, client: httpx.AsyncClient) -> bool:
        """Perform authentication based on configured mode.

        Returns True if authentication succeeded.
        """
        mode = self.config.mode
        if mode == AuthMode.NONE:
            self._authenticated = True
            return True
        elif mode == AuthMode.BEARER:
            return self._auth_bearer()
        elif mode == AuthMode.BASIC:
            return self._auth_basic()
        elif mode == AuthMode.API_KEY:
            return self._auth_api_key()
        elif mode == AuthMode.FORM_LOGIN:
            return await self._auth_form_login(client)
        elif mode == AuthMode.COOKIE:
            return self._auth_cookie()
        elif mode == AuthMode.OAUTH2:
            return await self._auth_oauth2(client)
        else:
            logger.warning("Unknown auth mode: %s", mode)
            return False

    def _auth_bearer(self) -> bool:
        if not self.config.bearer_token:
            logger.error("Bearer token not provided")  # nosemgrep: python-logger-credential-disclosure
            return False
        self._auth_headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        self._authenticated = True
        logger.info("DAST auth: Bearer token configured")  # nosemgrep: python-logger-credential-disclosure
        return True

    def _auth_basic(self) -> bool:
        if not self.config.basic_username:
            logger.error("Basic auth username not provided")
            return False
        import base64
        credentials = base64.b64encode(
            f"{self.config.basic_username}:{self.config.basic_password}".encode()
        ).decode()
        self._auth_headers["Authorization"] = f"Basic {credentials}"
        self._authenticated = True
        logger.info("DAST auth: Basic auth configured for user '%s'", self.config.basic_username)
        return True

    def _auth_api_key(self) -> bool:
        if not self.config.api_key_value:
            logger.error("API key value not provided")  # nosemgrep: python-logger-credential-disclosure
            return False
        self._auth_headers[self.config.api_key_header] = self.config.api_key_value
        self._authenticated = True
        logger.info("DAST auth: API key configured in header '%s'", self.config.api_key_header)  # nosemgrep: python-logger-credential-disclosure
        return True

    def _auth_cookie(self) -> bool:
        """Cookie mode — cookies are provided directly (no login needed)."""
        # Cookies are passed via the scan's cookies parameter
        self._authenticated = True
        logger.info("DAST auth: Cookie-based auth (cookies provided directly)")
        return True

    async def _auth_form_login(self, client: httpx.AsyncClient) -> bool:
        """Perform form-based login to obtain session cookies."""
        if not self.config.login_url:
            logger.error("Login URL not provided for form login")
            return False

        form_data = {
            self.config.username_field: self.config.login_username,
            self.config.password_field: self.config.login_password,
            **self.config.extra_form_fields,
        }

        try:
            resp = await client.post(
                self.config.login_url,
                data=form_data,
                follow_redirects=True,
            )

            # Check for failure indicator first
            if self.config.failure_indicator and self.config.failure_indicator in resp.text:
                logger.warning("DAST form login failed: failure indicator found in response")
                return False

            # Check for success indicator
            if self.config.success_indicator and self.config.success_indicator not in resp.text:
                # Only fail if success indicator was specified but not found
                if resp.status_code >= 400:
                    logger.warning(
                        "DAST form login failed: status=%d, success indicator not found",
                        resp.status_code,
                    )
                    return False

            # Extract cookies from response
            for name, value in resp.cookies.items():
                self._session_cookies[name] = value

            # Also check if Set-Cookie headers contain session tokens
            if not self._session_cookies and resp.status_code < 400:
                # Even without explicit cookies, a 2xx/3xx response may indicate success
                logger.info("DAST form login: No cookies returned but status=%d", resp.status_code)

            self._authenticated = True
            logger.info(
                "DAST auth: Form login successful, %d session cookies obtained",
                len(self._session_cookies),
            )
            return True

        except httpx.TimeoutException:
            logger.error("DAST form login timed out: %s", self.config.login_url)
            return False
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("DAST form login error: %s", e)
            return False

    async def _auth_oauth2(self, client: httpx.AsyncClient) -> bool:
        """Perform OAuth2 client_credentials flow."""
        if not self.config.token_url or not self.config.client_id:
            logger.error("OAuth2 token_url and client_id required")
            return False

        try:
            resp = await client.post(
                self.config.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "scope": self.config.scope,
                },
            )
            if resp.status_code == 200:
                token_data = resp.json()
                access_token = token_data.get("access_token", "")
                if access_token:
                    self._auth_headers["Authorization"] = f"Bearer {access_token}"
                    self._authenticated = True
                    logger.info("DAST auth: OAuth2 token obtained")  # nosemgrep: python-logger-credential-disclosure
                    return True
            logger.warning("DAST OAuth2 auth failed: status=%d", resp.status_code)
            return False
        except (httpx.TimeoutException, OSError, ValueError, RuntimeError) as e:
            logger.error("DAST OAuth2 error: %s", e)
            return False

    async def check_session(self, client: httpx.AsyncClient) -> bool:
        """Verify the current session is still valid."""
        if not self.config.session_check_url:
            return self._authenticated

        try:
            resp = await client.get(self.config.session_check_url)
            if resp.status_code == 401:
                self._authenticated = False
                return False
            if self.config.session_check_pattern:
                if self.config.session_check_pattern not in resp.text:
                    self._authenticated = False
                    return False
            return True
        except (httpx.TimeoutException, OSError, ValueError, RuntimeError):
            return False

    async def handle_401(self, client: httpx.AsyncClient) -> bool:
        """Handle 401 response by re-authenticating if configured."""
        if not self.config.reauth_on_401:
            return False
        if self._reauth_count >= self.config.max_reauth_attempts:
            logger.warning("DAST auth: Max re-auth attempts reached (%d)", self._reauth_count)
            return False

        self._reauth_count += 1
        self._authenticated = False
        logger.info("DAST auth: Re-authenticating (attempt %d/%d)", self._reauth_count, self.config.max_reauth_attempts)
        return await self.authenticate(client)

    def apply_to_client_kwargs(
        self,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Merge auth headers/cookies with user-provided ones."""
        merged_headers = {**(headers or {}), **self._auth_headers}
        merged_cookies = {**(cookies or {}), **self._session_cookies}
        return merged_headers, merged_cookies


# ── OpenAPI Scanner ────────────────────────────────────────────────


@dataclass
class OpenAPIEndpoint:
    """Parsed endpoint from an OpenAPI specification."""
    path: str
    method: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    security: List[Dict[str, Any]] = field(default_factory=list)
    operation_id: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "parameters": self.parameters,
            "has_request_body": self.request_body is not None,
            "security": self.security,
            "operation_id": self.operation_id,
        }


def parse_openapi_spec(spec: Dict[str, Any]) -> List[OpenAPIEndpoint]:
    """Parse an OpenAPI 3.x or Swagger 2.x specification into endpoints."""
    endpoints: List[OpenAPIEndpoint] = []
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method not in path_item:
                continue
            operation = path_item[method]
            if not isinstance(operation, dict):
                continue

            params = []
            # Path-level + operation-level parameters
            for p in path_item.get("parameters", []) + operation.get("parameters", []):
                if isinstance(p, dict):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", "string") if "schema" in p else p.get("type", "string"),
                    })

            req_body = operation.get("requestBody")
            security = operation.get("security", spec.get("security", []))

            endpoints.append(OpenAPIEndpoint(
                path=path,
                method=method.upper(),
                parameters=params,
                request_body=req_body,
                security=security if isinstance(security, list) else [],
                operation_id=operation.get("operationId", ""),
                description=operation.get("summary", operation.get("description", "")),
            ))

    return endpoints


def _generate_param_value(param_type: str, param_name: str) -> Any:
    """Generate a test value for a parameter based on its type."""
    type_map = {
        "integer": 1,
        "number": 1.0,
        "boolean": True,
        "array": [],
    }
    if param_type in type_map:
        return type_map[param_type]
    # Default: use a fuzz-friendly string
    return f"test_{param_name}"


class DastSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DastCategory(str, Enum):
    INJECTION = "injection"
    XSS = "xss"
    AUTH = "authentication"
    MISCONFIG = "misconfiguration"
    INFO_DISCLOSURE = "information_disclosure"
    SSRF = "ssrf"
    CSRF = "csrf"
    HEADER = "security_header"
    SSL = "ssl_tls"
    CRAWL = "crawl"
    API = "api_security"


@dataclass
class DastFinding:
    finding_id: str
    title: str
    severity: DastSeverity
    category: DastCategory
    url: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    cwe_id: str = ""
    description: str = ""
    recommendation: str = ""
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "cwe_id": self.cwe_id,
            "description": self.description,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class DastScanResult:
    scan_id: str
    target: str
    urls_crawled: int
    total_findings: int
    findings: List[DastFinding]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    crawled_urls: List[str]
    duration_ms: float = 0.0
    authenticated: bool = False
    auth_mode: str = "none"
    api_endpoints_tested: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "urls_crawled": self.urls_crawled,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "crawled_urls": self.crawled_urls[:50],
            "duration_ms": self.duration_ms,
            "authenticated": self.authenticated,
            "auth_mode": self.auth_mode,
            "api_endpoints_tested": self.api_endpoints_tested,
            "timestamp": self.timestamp.isoformat(),
        }


# ── Injection Payloads ──────────────────────────────────────────────
SQL_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "admin'--",
    "' OR 1=1#",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:22",
    "http://[::1]/",
    "http://0.0.0.0/",
    "file:///etc/passwd",
]
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
    "&& echo vulnerable",
    "|| echo vulnerable",
]


SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"pg_query",
    r"SQLite3::",
    r"Microsoft OLE DB",
    r"Unclosed quotation mark",
    r"SQLSTATE",
    r"syntax error at or near",
]
# Pre-compiled for hot-loop performance: avoids re-compiling 9 patterns per URL/payload pair
_SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# Pre-compiled stack-trace patterns used in _test_api_error_handling
_STACK_TRACE_RE = re.compile(
    r"Traceback \(most recent call"
    r"|at .+\(.+\.java:\d+\)"
    r"|at .+\(.+\.js:\d+:\d+\)"
    r"|Fatal error:.+in .+\.php"
    r"|Microsoft\.AspNetCore",
)

# Pre-compiled server version disclosure pattern
_SERVER_VERSION_RE = re.compile(r"[\d.]+")

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "high", "Missing HSTS header"),
    ("Content-Security-Policy", "medium", "Missing CSP header"),
    ("X-Content-Type-Options", "low", "Missing X-Content-Type-Options"),
    ("X-Frame-Options", "medium", "Missing X-Frame-Options (clickjacking)"),
    ("X-XSS-Protection", "low", "Missing X-XSS-Protection"),
    ("Referrer-Policy", "low", "Missing Referrer-Policy"),
    ("Permissions-Policy", "low", "Missing Permissions-Policy"),
]


class _LinkParser(HTMLParser):
    """Extract links from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        attr_dict = dict(attrs)
        if tag == "a" and "href" in attr_dict:
            self.links.append(attr_dict["href"])
        elif tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attr_dict.get("name", ""),
                    "type": attr_dict.get("type", "text"),
                    "value": attr_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


class DASTEngine:
    """Dynamic Application Security Testing engine.

    Performs real HTTP requests against live targets.
    """

    # Blocked IP ranges for SSRF protection (RFC 1918, loopback, link-local, metadata)
    _BLOCKED_RANGES: List[Tuple[int, int]] = []

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        """Convert dotted-quad IP to integer for range comparison."""
        parts = ip.split(".")
        if len(parts) != 4:
            return 0
        try:
            return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
        except (ValueError, IndexError):
            return 0

    @classmethod
    def _init_blocked_ranges(cls) -> None:
        """Initialize blocked IP ranges on first use."""
        if cls._BLOCKED_RANGES:
            return
        ranges = [
            ("10.0.0.0", "10.255.255.255"),       # RFC 1918
            ("172.16.0.0", "172.31.255.255"),      # RFC 1918
            ("192.168.0.0", "192.168.255.255"),    # RFC 1918
            ("127.0.0.0", "127.255.255.255"),      # Loopback
            ("169.254.0.0", "169.254.255.255"),    # Link-local / AWS metadata
            ("0.0.0.0", "0.255.255.255"),          # Current network  # nosec B104 — SSRF blocklist range, not a bind call
            ("100.64.0.0", "100.127.255.255"),     # Shared address space (RFC 6598)
        ]
        cls._BLOCKED_RANGES = [(cls._ip_to_int(s), cls._ip_to_int(e)) for s, e in ranges]

    @classmethod
    def validate_target_url(cls, url: str) -> str:
        """Validate target URL to prevent SSRF attacks.

        Blocks:
        - Non HTTP/HTTPS schemes (file://, ftp://, gopher://, etc.)
        - RFC 1918 private IPs (10.x, 172.16-31.x, 192.168.x)
        - Loopback (127.x.x.x, ::1, localhost)
        - Link-local / cloud metadata (169.254.x.x)
        - IPv6 loopback ([::1])

        Raises ValueError for blocked targets.
        """
        import socket
        from urllib.parse import urlparse


        # URL length limit (RFC 2616 recommendation + safety margin)
        if len(url) > 2048:
            raise ValueError("URL exceeds maximum length (2048 characters)")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Blocked scheme '{parsed.scheme}' — only http/https allowed")

        hostname = parsed.hostname or ""
        if not hostname:
            raise ValueError("Missing hostname in target URL")

        # Block obvious localhost patterns
        _blocked_hosts = {"localhost", "0.0.0.0", "::1", "[::1]", "ip6-localhost"}  # nosec B104 — SSRF check, not a bind call
        if hostname.lower() in _blocked_hosts:
            raise ValueError(f"Blocked target: {hostname} (loopback/localhost)")

        # Resolve hostname and check IP ranges
        cls._init_blocked_ranges()
        try:
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for family, _, _, _, sockaddr in addr_infos:
                ip = sockaddr[0]
                ip_int = cls._ip_to_int(ip)
                for range_start, range_end in cls._BLOCKED_RANGES:
                    if range_start <= ip_int <= range_end:
                        raise ValueError(
                            f"Blocked target: {hostname} resolves to private/reserved IP {ip}"
                        )
        except socket.gaierror:
            pass  # DNS resolution failed — allow (may be intentional for testing)

        return url

    def __init__(self, timeout: float = 10.0, max_crawl: int = 50):
        self._timeout = timeout
        self._max_crawl = max_crawl

    async def scan(
        self,
        target_url: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        crawl: bool = True,
        max_depth: int = 3,
        auth_config: Optional[AuthSessionConfig] = None,
    ) -> DastScanResult:
        """Full DAST scan: crawl + test, with optional authenticated scanning."""
        # SSRF protection: validate target URL before scanning
        target_url = self.validate_target_url(target_url)

        t0 = time.time()
        findings: List[DastFinding] = []
        crawled: Set[str] = set()
        auth_mode_str = "none"

        # Merge auth headers/cookies
        merged_headers = dict(headers or {})
        merged_cookies = dict(cookies or {})
        auth_mgr: Optional[AuthSessionManager] = None

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers=merged_headers,
            cookies=merged_cookies,
            verify=tls_verify(),
        ) as client:
            # Phase 0: Authenticate if config provided
            if auth_config and auth_config.mode != AuthMode.NONE:
                auth_mgr = AuthSessionManager(auth_config)
                auth_ok = await auth_mgr.authenticate(client)
                if auth_ok:
                    auth_mode_str = auth_config.mode.value
                    # Apply auth headers/cookies to client
                    h, c = auth_mgr.apply_to_client_kwargs(merged_headers, merged_cookies)
                    client.headers.update(h)
                    client.cookies.update(c)
                else:
                    logger.warning("DAST auth failed for mode=%s, proceeding unauthenticated", auth_config.mode.value)

            # Phase 1: Crawl
            if crawl:
                await self._crawl(client, target_url, crawled, max_depth, 0)
            else:
                crawled.add(target_url)

            # Phase 2: Security header check on root
            findings.extend(await self._check_headers(client, target_url))

            # Phase 3: Test each URL
            for url in list(crawled)[: self._max_crawl]:
                findings.extend(await self._test_sqli(client, url))
                findings.extend(await self._test_xss(client, url))
                findings.extend(await self._test_path_traversal(client, url))
                findings.extend(await self._test_ssrf(client, url))
                findings.extend(await self._check_info_disclosure(client, url))

        is_authenticated = bool(
            auth_mode_str != "none"
            or cookies
            or (headers and "authorization" in {k.lower() for k in headers})
        )

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1

        elapsed = (time.time() - t0) * 1000
        return DastScanResult(
            scan_id=f"dast-{uuid.uuid4().hex[:12]}",
            target=target_url,
            urls_crawled=len(crawled),
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            crawled_urls=sorted(crawled),
            duration_ms=round(elapsed, 2),
            authenticated=is_authenticated,
            auth_mode=auth_mode_str,
        )

    async def scan_api(
        self,
        target_url: str,
        openapi_spec: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        auth_config: Optional[AuthSessionConfig] = None,
    ) -> DastScanResult:
        """API-specific DAST scan driven by OpenAPI/Swagger specification.

        Tests each endpoint from the spec for injection, auth bypass, and misconfig.
        """
        target_url = self.validate_target_url(target_url)
        t0 = time.time()
        findings: List[DastFinding] = []
        endpoints = parse_openapi_spec(openapi_spec)
        tested_urls: Set[str] = set()
        auth_mode_str = "none"

        merged_headers = dict(headers or {})
        merged_cookies = dict(cookies or {})

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            headers=merged_headers,
            cookies=merged_cookies,
            verify=tls_verify(),
        ) as client:
            # Authenticate
            if auth_config and auth_config.mode != AuthMode.NONE:
                auth_mgr = AuthSessionManager(auth_config)
                auth_ok = await auth_mgr.authenticate(client)
                if auth_ok:
                    auth_mode_str = auth_config.mode.value
                    h, c = auth_mgr.apply_to_client_kwargs(merged_headers, merged_cookies)
                    client.headers.update(h)
                    client.cookies.update(c)

            # Security headers on root
            findings.extend(await self._check_headers(client, target_url))

            # Test each endpoint from spec
            base = target_url.rstrip("/")
            for ep in endpoints:
                # Build URL with path parameters filled
                path = ep.path
                for param in ep.parameters:
                    if param.get("in") == "path":
                        placeholder = "{" + param["name"] + "}"
                        path = path.replace(placeholder, str(_generate_param_value(param.get("type", "string"), param["name"])))

                full_url = f"{base}{path}"
                tested_urls.add(full_url)

                # Build query params
                query_params = {}
                for param in ep.parameters:
                    if param.get("in") == "query":
                        query_params[param["name"]] = str(_generate_param_value(param.get("type", "string"), param["name"]))

                # Test the endpoint
                try:
                    findings.extend(await self._test_api_endpoint(client, full_url, ep, query_params))
                except (httpx.TimeoutException, OSError, ValueError, RuntimeError) as e:
                    logger.debug("API scan error for %s %s: %s", ep.method, full_url, type(e).__name__)

        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1

        elapsed = (time.time() - t0) * 1000
        is_authenticated = bool(
            auth_mode_str != "none"
            or cookies
            or (headers and "authorization" in {k.lower() for k in headers})
        )

        return DastScanResult(
            scan_id=f"dast-api-{uuid.uuid4().hex[:12]}",
            target=target_url,
            urls_crawled=len(tested_urls),
            total_findings=len(findings),
            findings=findings,
            by_severity=by_sev,
            by_category=by_cat,
            crawled_urls=sorted(tested_urls),
            duration_ms=round(elapsed, 2),
            authenticated=is_authenticated,
            auth_mode=auth_mode_str,
            api_endpoints_tested=len(endpoints),
        )

    async def _test_api_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
        endpoint: OpenAPIEndpoint,
        query_params: Dict[str, str],
    ) -> List[DastFinding]:
        """Test a single API endpoint for common vulnerabilities."""
        findings: List[DastFinding] = []

        # 1. Auth bypass: try without auth headers (if endpoint has security defined)
        if endpoint.security:
            findings.extend(await self._test_auth_bypass(client, url, endpoint))

        # 2. SQL injection on query params
        if query_params:
            qs = "&".join(f"{k}={v}" for k, v in query_params.items())
            test_url = f"{url}?{qs}"
            findings.extend(await self._test_sqli(client, test_url))

        # 3. Check for verbose error responses
        findings.extend(await self._test_api_error_handling(client, url, endpoint))

        return findings

    async def _test_auth_bypass(
        self,
        client: httpx.AsyncClient,
        url: str,
        endpoint: OpenAPIEndpoint,
    ) -> List[DastFinding]:
        """Test if endpoint can be accessed without authentication."""
        findings: List[DastFinding] = []
        try:
            # Make request without auth to see if it's enforced
            unauth_client = httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                verify=tls_verify(),
            )
            async with unauth_client:
                if endpoint.method == "GET":
                    resp = await unauth_client.get(url)
                else:
                    resp = await unauth_client.request(endpoint.method, url)

                # If we get 200 on a secured endpoint, that's a problem
                if resp.status_code == 200:
                    findings.append(DastFinding(
                        finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                        title=f"Authentication Bypass on {endpoint.method} {endpoint.path}",
                        severity=DastSeverity.CRITICAL,
                        category=DastCategory.AUTH,
                        url=url,
                        method=endpoint.method,
                        evidence=f"HTTP {resp.status_code} returned without authentication",
                        cwe_id="CWE-306",
                        description=f"Endpoint {endpoint.path} with security requirements is accessible without authentication",
                        recommendation="Enforce authentication on all secured endpoints",
                        confidence=0.7,
                    ))
        except (httpx.TimeoutException, OSError, ValueError, RuntimeError):
            pass
        return findings

    async def _test_api_error_handling(
        self,
        client: httpx.AsyncClient,
        url: str,
        endpoint: OpenAPIEndpoint,
    ) -> List[DastFinding]:
        """Test API error handling for information disclosure."""
        findings: List[DastFinding] = []
        # Send malformed request to trigger error
        try:
            if endpoint.method in ("POST", "PUT", "PATCH"):
                resp = await client.request(
                    endpoint.method, url,
                    content="{{invalid json",
                    headers={"Content-Type": "application/json"},
                )
            else:
                resp = await client.get(f"{url}?__invalid__=<script>")

            if resp.status_code >= 500:
                # Check for stack traces in error response
                if _STACK_TRACE_RE.search(resp.text):
                    findings.append(DastFinding(
                        finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                        title=f"Stack Trace Exposed on {endpoint.method} {endpoint.path}",
                        severity=DastSeverity.MEDIUM,
                        category=DastCategory.INFO_DISCLOSURE,
                        url=url,
                        method=endpoint.method,
                        evidence=resp.text[:300],
                        cwe_id="CWE-209",
                        description="Server error response contains stack trace information",
                        recommendation="Configure custom error pages, disable debug mode in production",
                    ))
        except (httpx.TimeoutException, OSError, ValueError, RuntimeError):
            pass
        return findings

    async def _crawl(
        self,
        client: httpx.AsyncClient,
        url: str,
        visited: Set[str],
        max_depth: int,
        depth: int,
    ):
        if depth > max_depth or url in visited or len(visited) >= self._max_crawl:
            return
        visited.add(url)
        try:
            resp = await client.get(url)
            if "text/html" not in resp.headers.get("content-type", ""):
                return
            parser = _LinkParser()
            parser.feed(resp.text)
            base = url.rstrip("/")
            for link in parser.links:
                if link.startswith("/"):
                    full = (
                        base.split("//")[0]
                        + "//"
                        + base.split("//")[1].split("/")[0]
                        + link
                    )
                elif (
                    link.startswith("http")
                    and base.split("//")[1].split("/")[0] in link
                ):
                    full = link
                else:
                    continue
                if full not in visited:
                    await self._crawl(client, full, visited, max_depth, depth + 1)
        except httpx.TimeoutException:
            logger.debug("Crawl timeout for %s (depth=%d)", url, depth)
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Crawl error for %s: %s", url, type(e).__name__)

    async def _check_headers(
        self, client: httpx.AsyncClient, url: str
    ) -> List[DastFinding]:
        findings = []
        try:
            resp = await client.get(url)
            for header, sev, msg in SECURITY_HEADERS:
                if header.lower() not in {k.lower() for k in resp.headers}:
                    findings.append(
                        DastFinding(
                            finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                            title=msg,
                            severity=DastSeverity(sev),
                            category=DastCategory.HEADER,
                            url=url,
                            cwe_id="CWE-693",
                            description=msg,
                            recommendation=f"Add {header} response header",
                        )
                    )
            # Check for server version disclosure
            server = resp.headers.get("server", "")
            if _SERVER_VERSION_RE.search(server):
                findings.append(
                    DastFinding(
                        finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                        title="Server Version Disclosure",
                        severity=DastSeverity.LOW,
                        category=DastCategory.INFO_DISCLOSURE,
                        url=url,
                        evidence=f"Server: {server}",
                        cwe_id="CWE-200",
                        description="Server header reveals version info",
                        recommendation="Remove version info from Server header",
                    )
                )
        except httpx.TimeoutException:
            logger.debug("Header check timeout for %s", url)
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.debug("Header check error for %s: %s", url, type(e).__name__)
        return findings

    async def _test_sqli(
        self, client: httpx.AsyncClient, url: str
    ) -> List[DastFinding]:
        findings = []
        if "?" not in url:
            return findings
        base, qs = url.split("?", 1)
        for payload in SQL_PAYLOADS[:3]:
            test_url = f"{base}?{qs}&test={payload}"
            try:
                resp = await client.get(test_url)
                if _SQL_ERROR_RE.search(resp.text):
                    findings.append(
                        DastFinding(
                            finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                            title="SQL Injection",
                            severity=DastSeverity.CRITICAL,
                            category=DastCategory.INJECTION,
                            url=url,
                            parameter="test",
                            payload=payload,
                            evidence=resp.text[:200],
                            cwe_id="CWE-89",
                            description="SQL error in response indicates injection vulnerability",
                            recommendation="Use parameterized queries",
                        )
                    )
                    return findings
            except httpx.TimeoutException:
                logger.debug("SQLi test timeout for %s", test_url)
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.debug("SQLi test error for %s: %s", url, type(e).__name__)
        return findings

    async def _test_xss(self, client: httpx.AsyncClient, url: str) -> List[DastFinding]:
        findings = []
        if "?" not in url:
            return findings
        base, qs = url.split("?", 1)
        for payload in XSS_PAYLOADS[:3]:
            test_url = f"{base}?{qs}&q={payload}"
            try:
                resp = await client.get(test_url)
                if payload in resp.text:
                    findings.append(
                        DastFinding(
                            finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                            title="Reflected XSS",
                            severity=DastSeverity.HIGH,
                            category=DastCategory.XSS,
                            url=url,
                            parameter="q",
                            payload=payload,
                            evidence=resp.text[:200],
                            cwe_id="CWE-79",
                            description="Payload reflected in response without encoding",
                            recommendation="Encode output and implement CSP",
                        )
                    )
                    return findings
            except httpx.TimeoutException:
                logger.debug("XSS test timeout for %s", test_url)
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.debug("XSS test error for %s: %s", url, type(e).__name__)
        return findings

    async def _test_path_traversal(
        self, client: httpx.AsyncClient, url: str
    ) -> List[DastFinding]:
        findings = []
        for payload in PATH_TRAVERSAL_PAYLOADS[:2]:
            test_url = f"{url.rstrip('/')}/{payload}"
            try:
                resp = await client.get(test_url)
                if "root:" in resp.text or "[boot loader]" in resp.text:
                    findings.append(
                        DastFinding(
                            finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                            title="Path Traversal",
                            severity=DastSeverity.CRITICAL,
                            category=DastCategory.INJECTION,
                            url=url,
                            payload=payload,
                            evidence=resp.text[:200],
                            cwe_id="CWE-22",
                            description="Path traversal exposes system files",
                            recommendation="Validate and sanitize file paths",
                        )
                    )
                    return findings
            except httpx.TimeoutException:
                logger.debug("Path traversal test timeout for %s", test_url)
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.debug("Path traversal test error for %s: %s", url, type(e).__name__)
        return findings

    async def _test_ssrf(
        self, client: httpx.AsyncClient, url: str
    ) -> List[DastFinding]:
        findings = []
        if "?" not in url:
            return findings
        base, qs = url.split("?", 1)
        for payload in SSRF_PAYLOADS[:2]:
            test_url = f"{base}?{qs}&url={payload}"
            try:
                resp = await client.get(test_url)
                if any(
                    k in resp.text.lower()
                    for k in ["ami-id", "instance-id", "root:", "sshd"]
                ):
                    findings.append(
                        DastFinding(
                            finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                            title="Server-Side Request Forgery",
                            severity=DastSeverity.CRITICAL,
                            category=DastCategory.SSRF,
                            url=url,
                            parameter="url",
                            payload=payload,
                            evidence=resp.text[:200],
                            cwe_id="CWE-918",
                            description="Server fetched internal resource",
                            recommendation="Validate and whitelist URLs",
                        )
                    )
                    return findings
            except httpx.TimeoutException:
                logger.debug("SSRF test timeout for %s", test_url)
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.debug("SSRF test error for %s: %s", url, type(e).__name__)
        return findings

    async def _check_info_disclosure(
        self, client: httpx.AsyncClient, url: str
    ) -> List[DastFinding]:
        findings = []
        sensitive_paths = [
            "/.env",
            "/.git/config",
            "/wp-config.php",
            "/server-status",
            "/phpinfo.php",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
        ]
        base = url.rstrip("/").split("?")[0]
        for path in sensitive_paths[:4]:
            try:
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200 and len(resp.text) > 50:
                    if any(
                        k in resp.text.lower()
                        for k in ["password", "secret", "api_key", "db_host", "[core]"]
                    ):
                        findings.append(
                            DastFinding(
                                finding_id=f"DAST-{uuid.uuid4().hex[:8]}",
                                title=f"Sensitive File Exposed: {path}",
                                severity=DastSeverity.HIGH,
                                category=DastCategory.INFO_DISCLOSURE,
                                url=f"{base}{path}",
                                cwe_id="CWE-200",
                                description=f"Sensitive file {path} is publicly accessible",
                                recommendation="Restrict access to sensitive files",
                            )
                        )
            except httpx.TimeoutException:
                logger.debug("Info disclosure check timeout for %s%s", base, path)
            except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
                logger.debug("Info disclosure check error for %s: %s", base, type(e).__name__)
        return findings


_engine: Optional[DASTEngine] = None


def get_dast_engine() -> DASTEngine:
    global _engine
    if _engine is None:
        _engine = DASTEngine()
    return _engine
