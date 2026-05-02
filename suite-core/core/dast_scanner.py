"""ALDECI DAST (Dynamic Application Security Testing) Scanner.

Performs dynamic security testing against live web applications:
- Web crawling with form/parameter discovery
- Authentication handling (cookie, JWT, OAuth2, API key, basic auth)
- OWASP Top 10 dynamic tests
- Security header analysis
- Reproducible PoC generation
- Configurable scan profiles with rate limiting

Competitive parity: OWASP ZAP, Burp Suite Community, Nikto.
No external dependencies — uses urllib.request for HTTP.
"""

from __future__ import annotations

import base64
import html.parser
import ipaddress
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import structlog

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


_log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Enums & constants
# ---------------------------------------------------------------------------

class ScanProfile(str, Enum):
    QUICK = "quick"          # headers + config only
    STANDARD = "standard"   # passive + light active
    FULL = "full"            # everything including auth testing
    API_ONLY = "api_only"   # OpenAPI-driven


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OwaspCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


class AuthType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    JWT_BEARER = "jwt_bearer"
    OAUTH2 = "oauth2"
    API_KEY_HEADER = "api_key_header"
    BASIC_AUTH = "basic_auth"


# OWASP-safe injection payloads (non-destructive, detection-only)
_SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' AND SLEEP(0)--",
    "'; SELECT 1--",
]
_NOSQL_PAYLOADS = [
    '{"$gt": ""}',
    '{"$where": "1==1"}',
    '{"$ne": null}',
]
_LDAP_PAYLOADS = [
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "admin)(&(password=*))",
]
_CMD_PAYLOADS = [
    "; echo DAST_PROBE",
    "| echo DAST_PROBE",
    "& echo DAST_PROBE",
    "`echo DAST_PROBE`",
]
_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "file:///etc/passwd",
]
_DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("guest", "guest"),
]

_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

_SSRF_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "::1", "0.0.0.0",  # nosec B104 — SSRF blocklist, not a bind call
    "metadata.google.internal", "169.254.169.254",
})


# ---------------------------------------------------------------------------
# Pydantic-free data models (dataclasses for speed)
# ---------------------------------------------------------------------------

@dataclass
class AuthConfig:
    auth_type: AuthType = AuthType.NONE
    # Cookie auth
    cookie_name: str = ""
    cookie_value: str = ""
    # JWT / API key
    token: str = ""
    header_name: str = "Authorization"
    # OAuth2
    token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""
    # Basic auth
    username: str = ""
    password: str = ""
    # Login form
    login_url: str = ""
    login_username_field: str = "username"
    login_password_field: str = "password"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auth_type": self.auth_type.value,
            "header_name": self.header_name,
            "login_url": self.login_url,
        }


@dataclass
class ScanConfig:
    target_url: str
    profile: ScanProfile = ScanProfile.STANDARD
    auth: AuthConfig = field(default_factory=AuthConfig)
    max_depth: int = 3
    max_urls: int = 100
    requests_per_second: float = 5.0
    timeout: float = 10.0
    respect_robots_txt: bool = True
    scope_pattern: str = ""           # regex — restrict crawl to matching paths
    custom_headers: Dict[str, str] = field(default_factory=dict)
    openapi_spec: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "profile": self.profile.value,
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
            "requests_per_second": self.requests_per_second,
            "respect_robots_txt": self.respect_robots_txt,
        }


@dataclass
class HttpProbe:
    """Captured HTTP request/response for PoC reproduction."""
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    response_status: int
    response_headers: Dict[str, str]
    response_body_snippet: str   # first 500 chars
    duration_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "request_headers": self.headers,
            "request_body": self.body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body_snippet": self.response_body_snippet,
            "duration_ms": round(self.duration_ms, 2),
        }


@dataclass
class DastFinding:
    finding_id: str
    title: str
    severity: FindingSeverity
    owasp_category: OwaspCategory
    cwe_id: str
    url: str
    parameter: str
    payload: str
    description: str
    recommendation: str
    proof_of_concept: HttpProbe
    reproduction_steps: List[str]
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "owasp_category": self.owasp_category.value,
            "cwe_id": self.cwe_id,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "description": self.description,
            "recommendation": self.recommendation,
            "proof_of_concept": self.proof_of_concept.to_dict(),
            "reproduction_steps": self.reproduction_steps,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    depth: int = 0
    source: str = "crawl"  # crawl, openapi, robots

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "depth": self.depth,
            "source": self.source,
        }


@dataclass
class SecurityHeadersResult:
    url: str
    present: Dict[str, str]
    missing: List[str]
    warnings: List[str]
    score: int   # 0-100
    tls_version: str = ""
    hsts_enabled: bool = False
    cert_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "present": self.present,
            "missing": self.missing,
            "warnings": self.warnings,
            "score": self.score,
            "tls_version": self.tls_version,
            "hsts_enabled": self.hsts_enabled,
            "cert_valid": self.cert_valid,
        }


@dataclass
class ScanResult:
    scan_id: str
    target_url: str
    profile: ScanProfile
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    endpoints_discovered: int
    endpoints_tested: int
    total_findings: int
    findings: List[DastFinding]
    security_headers: Optional[SecurityHeadersResult]
    by_severity: Dict[str, int]
    by_owasp: Dict[str, int]
    duration_ms: float
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "profile": self.profile.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "endpoints_discovered": self.endpoints_discovered,
            "endpoints_tested": self.endpoints_tested,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "security_headers": self.security_headers.to_dict() if self.security_headers else None,
            "by_severity": self.by_severity,
            "by_owasp": self.by_owasp,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# HTML link/form parser
# ---------------------------------------------------------------------------

class _LinkFormParser(html.parser.HTMLParser):
    """Extract hrefs, form actions, input names from HTML."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_dict = dict(attrs)
        if tag == "a" and attr_dict.get("href"):
            href = attr_dict["href"]
            try:
                full = urllib.parse.urljoin(self.base_url, href)
                self.links.add(full)
            except Exception:
                pass
        elif tag == "form":
            self._current_form = {
                "action": urllib.parse.urljoin(self.base_url, attr_dict.get("action") or self.base_url),
                "method": (attr_dict.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "")
            if input_name:
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": input_type,
                    "value": attr_dict.get("value", ""),
                })
        elif tag == "script" and attr_dict.get("src"):
            try:
                full = urllib.parse.urljoin(self.base_url, attr_dict["src"])
                self.links.add(full)
            except Exception:
                pass

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


# ---------------------------------------------------------------------------
# HTTP client wrapper
# ---------------------------------------------------------------------------

class _HttpClient:
    """Thin urllib wrapper with rate limiting, auth, and PoC capture."""

    def __init__(self, config: ScanConfig, session_cookies: Dict[str, str]) -> None:
        self._config = config
        self._cookies = dict(session_cookies)
        self._session_headers: Dict[str, str] = dict(config.custom_headers)
        self._rate_lock = threading.Lock()
        self._last_request_time: float = 0.0
        self._interval = 1.0 / max(config.requests_per_second, 0.1)
        self._ssl_ctx = ssl.create_default_context()

    def _apply_auth_headers(self, headers: Dict[str, str]) -> None:
        auth = self._config.auth
        if auth.auth_type == AuthType.JWT_BEARER:
            headers[auth.header_name] = f"Bearer {auth.token}"
        elif auth.auth_type == AuthType.API_KEY_HEADER:
            headers[auth.header_name] = auth.token
        elif auth.auth_type == AuthType.BASIC_AUTH:
            cred = base64.b64encode(f"{auth.username}:{auth.password}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"
        elif auth.auth_type == AuthType.COOKIE and auth.cookie_name:
            existing = headers.get("Cookie", "")
            new_cookie = f"{auth.cookie_name}={auth.cookie_value}"
            headers["Cookie"] = f"{existing}; {new_cookie}".strip("; ")

    def _cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())

    def _rate_limit(self) -> None:
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_request_time = time.monotonic()

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        follow_redirects: bool = True,
    ) -> HttpProbe:
        self._rate_limit()

        req_headers: Dict[str, str] = {
            "User-Agent": "ALDECI-DAST/1.0 (security-scanner)",
            "Accept": "text/html,application/json,*/*",
        }
        req_headers.update(self._session_headers)
        if headers:
            req_headers.update(headers)

        # Cookies
        cookie_str = self._cookie_header()
        if cookie_str:
            req_headers["Cookie"] = cookie_str

        self._apply_auth_headers(req_headers)

        encoded_body: Optional[bytes] = body.encode() if body else None

        t0 = time.monotonic()
        try:
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                url,
                data=encoded_body,
                headers=req_headers,
                method=method,
            )
            with urllib.request.urlopen(  # nosemgrep: dynamic-urllib-use-detected  # nosec
                req,
                timeout=self._config.timeout,
                context=self._ssl_ctx if url.startswith("https://") else None,
            ) as resp:
                status = resp.status
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_body = resp.read(2048)
                body_snippet = raw_body.decode("utf-8", errors="replace")[:500]

                # Capture Set-Cookie
                for sc in resp.headers.get_all("Set-Cookie") or []:
                    if "=" in sc:
                        name, _, rest = sc.partition("=")
                        value = rest.split(";")[0]
                        self._cookies[name.strip()] = value.strip()

        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            try:
                body_snippet = exc.read(512).decode("utf-8", errors="replace")[:500]
            except Exception:
                body_snippet = str(exc)
        except Exception as exc:
            status = 0
            resp_headers = {}
            body_snippet = str(exc)[:200]

        duration_ms = (time.monotonic() - t0) * 1000

        return HttpProbe(
            method=method,
            url=url,
            headers={k: v for k, v in req_headers.items() if k.lower() != "authorization"},
            body=body or "",
            response_status=status,
            response_headers=resp_headers,
            response_body_snippet=body_snippet,
            duration_ms=duration_ms,
        )


# ---------------------------------------------------------------------------
# Robots.txt parser
# ---------------------------------------------------------------------------

def _fetch_robots_txt(base_url: str, timeout: float = 5.0) -> Set[str]:
    """Return set of disallowed path prefixes from robots.txt."""
    disallowed: Set[str] = set()
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    try:
        req = urllib.request.Request(robots_url, headers={"User-Agent": "ALDECI-DAST/1.0"})  # nosemgrep: dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
            content = resp.read(16384).decode("utf-8", errors="replace")
        in_block = False
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip()
                in_block = agent in ("*", "ALDECI-DAST")
            elif in_block and line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed.add(path)
    except Exception:
        pass
    return disallowed


def _is_disallowed(url: str, disallowed: Set[str]) -> bool:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    return any(path.startswith(d) for d in disallowed)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def _is_safe_url(url: str) -> bool:
    """Return False if URL targets internal/loopback addresses."""
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if host.lower() in _SSRF_BLOCKED_HOSTS:
            return False
        try:
            addr = ipaddress.ip_address(host)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return False
        except ValueError:
            pass  # hostname — allow
    except Exception:
        return False
    return True


# ---------------------------------------------------------------------------
# Web Crawler
# ---------------------------------------------------------------------------

class WebCrawler:
    """BFS crawler that discovers endpoints, forms, and URL parameters."""

    def __init__(self, config: ScanConfig, client: _HttpClient) -> None:
        self._config = config
        self._client = client
        self._scope_re = re.compile(config.scope_pattern) if config.scope_pattern else None

    def _in_scope(self, url: str) -> bool:
        base = self._config.target_url.rstrip("/")
        if not url.startswith(base):
            return False
        if self._scope_re and not self._scope_re.search(url):
            return False
        return True

    def crawl(self, disallowed: Set[str]) -> List[DiscoveredEndpoint]:
        visited: Set[str] = set()
        queue: List[Tuple[str, int]] = [(self._config.target_url, 0)]
        endpoints: List[DiscoveredEndpoint] = []

        while queue and len(visited) < self._config.max_urls:
            url, depth = queue.pop(0)

            # Normalise URL (strip fragment)
            url = url.split("#")[0]
            if url in visited:
                continue
            if not self._in_scope(url):
                continue
            if not _is_safe_url(url):
                continue
            if _is_disallowed(url, disallowed):
                continue

            visited.add(url)
            _log.debug("crawling", url=url, depth=depth)

            probe = self._client.request("GET", url)
            if probe.response_status == 0:
                continue

            # Extract URL parameters
            parsed = urllib.parse.urlparse(url)
            params = list(urllib.parse.parse_qs(parsed.query).keys())

            # Parse HTML for links and forms
            forms: List[Dict[str, Any]] = []
            new_links: List[str] = []

            content_type = probe.response_headers.get("content-type", "")
            if "html" in content_type or probe.response_status < 400:
                parser = _LinkFormParser(url)
                try:
                    # Fetch full body for parsing
                    full_probe = self._client.request("GET", url)
                    parser.feed(full_probe.response_body_snippet)
                except Exception:
                    pass
                new_links = list(parser.links)
                forms = parser.forms

            endpoints.append(DiscoveredEndpoint(
                url=url,
                method="GET",
                parameters=params,
                forms=forms,
                depth=depth,
                source="crawl",
            ))

            # Also add form actions as POST endpoints
            for form in forms:
                form_url = form.get("action", url)
                if form_url not in visited and self._in_scope(form_url):
                    input_names = [i["name"] for i in form.get("inputs", [])]
                    endpoints.append(DiscoveredEndpoint(
                        url=form_url,
                        method=form.get("method", "GET"),
                        parameters=input_names,
                        forms=[form],
                        depth=depth,
                        source="form",
                    ))

            if depth < self._config.max_depth:
                for link in new_links:
                    if link not in visited:
                        queue.append((link, depth + 1))

        return endpoints


# ---------------------------------------------------------------------------
# Authentication handler
# ---------------------------------------------------------------------------

class AuthHandler:
    """Establishes and maintains authenticated sessions."""

    def __init__(self, config: ScanConfig) -> None:
        self._config = config

    def authenticate(self) -> Dict[str, str]:
        """Perform auth flow and return session cookies."""
        auth = self._config.auth
        if auth.auth_type == AuthType.NONE:
            return {}
        if auth.auth_type == AuthType.COOKIE:
            if auth.cookie_name and auth.cookie_value:
                return {auth.cookie_name: auth.cookie_value}
            return {}
        if auth.auth_type in (AuthType.JWT_BEARER, AuthType.API_KEY_HEADER, AuthType.BASIC_AUTH):
            # Token passed via headers — no cookie session needed
            return {}
        if auth.auth_type == AuthType.OAUTH2:
            return self._oauth2_flow()
        if auth.auth_type == AuthType.COOKIE and auth.login_url:
            return self._form_login()
        return {}

    def _oauth2_flow(self) -> Dict[str, str]:
        """Client credentials flow — returns bearer token in cookies dict sentinel."""
        auth = self._config.auth
        if not auth.token_url:
            return {}
        try:
            body = urllib.parse.urlencode({
                "grant_type": "client_credentials",
                "client_id": auth.client_id,
                "client_secret": auth.client_secret,
                "scope": auth.scope,
            }).encode()
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                auth.token_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                import json as _json
                data = _json.loads(resp.read())
                token = data.get("access_token", "")
                if token:
                    # Store as sentinel — _HttpClient will add Bearer header
                    self._config.auth.token = token
                    self._config.auth.auth_type = AuthType.JWT_BEARER
        except Exception as exc:
            _log.warning("oauth2_flow_failed", error=str(exc))
        return {}

    def _form_login(self) -> Dict[str, str]:
        """Submit login form and capture session cookies."""
        auth = self._config.auth
        body = urllib.parse.urlencode({
            auth.login_username_field: auth.username,
            auth.login_password_field: auth.password,
        }).encode()
        cookies: Dict[str, str] = {}
        try:
            req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                auth.login_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                for sc in resp.headers.get_all("Set-Cookie") or []:
                    if "=" in sc:
                        name, _, rest = sc.partition("=")
                        value = rest.split(";")[0]
                        cookies[name.strip()] = value.strip()
        except Exception as exc:
            _log.warning("form_login_failed", error=str(exc))
        return cookies


# ---------------------------------------------------------------------------
# Security headers analyser
# ---------------------------------------------------------------------------

class SecurityHeadersAnalyser:
    """Check HTTP security response headers and TLS config."""

    def analyse(self, url: str, client: _HttpClient) -> SecurityHeadersResult:
        probe = client.request("GET", url)
        headers = probe.response_headers

        present: Dict[str, str] = {}
        missing: List[str] = []
        warnings: List[str] = []

        for h in _SECURITY_HEADERS:
            if h in headers:
                present[h] = headers[h]
            else:
                missing.append(h)

        # HSTS checks
        hsts_enabled = "strict-transport-security" in headers
        hsts_value = headers.get("strict-transport-security", "")
        if hsts_enabled:
            max_age_match = re.search(r"max-age=(\d+)", hsts_value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    warnings.append(f"HSTS max-age too short: {max_age}s (recommend >= 31536000)")
            if "includeSubDomains" not in hsts_value:
                warnings.append("HSTS missing includeSubDomains directive")

        # CSP checks
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                warnings.append("CSP allows 'unsafe-inline' scripts — XSS risk")
            if "unsafe-eval" in csp:
                warnings.append("CSP allows 'unsafe-eval' — code injection risk")
        else:
            warnings.append("Content-Security-Policy header missing — XSS risk")

        # X-Frame-Options
        xfo = headers.get("x-frame-options", "").upper()
        if xfo and xfo not in ("DENY", "SAMEORIGIN"):
            warnings.append(f"X-Frame-Options value '{xfo}' may allow clickjacking")

        # TLS detection
        tls_version = ""
        if url.startswith("https://"):
            try:
                ctx = ssl.create_default_context()
                parsed = urllib.parse.urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port or 443
                with ctx.wrap_socket(
                    __import__("socket").create_connection((host, port), timeout=5),
                    server_hostname=host,
                ) as sock:
                    tls_version = sock.version() or ""
            except Exception:
                tls_version = "unknown"

        # Score: start 100, deduct per missing header
        score = 100
        score -= len(missing) * 10
        score -= len(warnings) * 5
        score = max(0, score)

        return SecurityHeadersResult(
            url=url,
            present=present,
            missing=missing,
            warnings=warnings,
            score=score,
            tls_version=tls_version,
            hsts_enabled=hsts_enabled,
        )


# ---------------------------------------------------------------------------
# OWASP test modules
# ---------------------------------------------------------------------------

def _make_finding(
    title: str,
    severity: FindingSeverity,
    owasp: OwaspCategory,
    cwe_id: str,
    url: str,
    parameter: str,
    payload: str,
    description: str,
    recommendation: str,
    probe: HttpProbe,
    reproduction_steps: List[str],
    confidence: float = 0.8,
) -> DastFinding:
    return DastFinding(
        finding_id=str(uuid.uuid4()),
        title=title,
        severity=severity,
        owasp_category=owasp,
        cwe_id=cwe_id,
        url=url,
        parameter=parameter,
        payload=payload,
        description=description,
        recommendation=recommendation,
        proof_of_concept=probe,
        reproduction_steps=reproduction_steps,
        confidence=confidence,
    )


class OwaspTestSuite:
    """Run OWASP Top 10 dynamic tests against discovered endpoints."""

    def __init__(self, client: _HttpClient, profile: ScanProfile) -> None:
        self._client = client
        self._profile = profile

    # ── A01: Broken Access Control ─────────────────────────────────────────

    def test_a01_broken_access_control(
        self, endpoints: List[DiscoveredEndpoint]
    ) -> List[DastFinding]:
        findings: List[DastFinding] = []

        for ep in endpoints:
            url = ep.url
            # Test: access admin/privileged paths without auth
            admin_patterns = ["/admin", "/management", "/internal", "/private", "/debug"]
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            if any(p in path for p in admin_patterns):
                probe = self._client.request("GET", url, headers={"Authorization": "invalid"})
                if probe.response_status in (200, 201, 202):
                    findings.append(_make_finding(
                        title="Broken Access Control — Privileged Path Accessible",
                        severity=FindingSeverity.HIGH,
                        owasp=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
                        cwe_id="CWE-284",
                        url=url,
                        parameter="",
                        payload="invalid auth token",
                        description=f"Admin/privileged endpoint {url} returned HTTP {probe.response_status} with invalid credentials.",
                        recommendation="Enforce authentication and authorisation on all privileged endpoints.",
                        probe=probe,
                        reproduction_steps=[
                            f"Send GET {url}",
                            'Add header: Authorization: invalid',
                            f"Observe HTTP {probe.response_status} response — endpoint is accessible.",
                        ],
                        confidence=0.9,
                    ))

            # Test: IDOR — increment/decrement numeric IDs in path
            id_match = re.search(r"/(\d+)(?:/|$)", url)
            if id_match:
                original_id = int(id_match.group(1))
                for offset in (1, -1, 0):
                    test_id = original_id + offset
                    test_url = url.replace(f"/{original_id}", f"/{test_id}", 1)
                    probe = self._client.request("GET", test_url)
                    if probe.response_status == 200 and test_id != original_id:
                        findings.append(_make_finding(
                            title="Broken Access Control — Potential IDOR",
                            severity=FindingSeverity.MEDIUM,
                            owasp=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
                            cwe_id="CWE-639",
                            url=test_url,
                            parameter="id",
                            payload=str(test_id),
                            description=f"Resource ID manipulation ({original_id} → {test_id}) returned HTTP 200.",
                            recommendation="Validate that authenticated user owns the requested resource.",
                            probe=probe,
                            reproduction_steps=[
                                "Authenticate as a low-privilege user.",
                                f"Send GET {test_url}",
                                "Observe HTTP 200 — may expose another user's data.",
                            ],
                            confidence=0.6,
                        ))
                        break  # one IDOR finding per URL

        return findings

    # ── A02: Cryptographic Failures ────────────────────────────────────────

    def test_a02_crypto_failures(self, base_url: str) -> List[DastFinding]:
        findings: List[DastFinding] = []

        # TLS: check if site serves over HTTP (no HTTPS redirect)
        if base_url.startswith("http://"):
            base_url.replace("http://", "https://", 1)
            probe_http = self._client.request("GET", base_url)
            # If HTTP returns 200 without redirect to HTTPS — cleartext data
            if probe_http.response_status == 200:
                location = probe_http.response_headers.get("location", "")
                if not location.startswith("https://"):
                    findings.append(_make_finding(
                        title="Cryptographic Failure — No HTTPS Redirect",
                        severity=FindingSeverity.HIGH,
                        owasp=OwaspCategory.A02_CRYPTO_FAILURES,
                        cwe_id="CWE-319",
                        url=base_url,
                        parameter="",
                        payload="",
                        description="Site serves content over plain HTTP without redirecting to HTTPS.",
                        recommendation="Configure HTTP → HTTPS permanent redirect (301) and enable HSTS.",
                        probe=probe_http,
                        reproduction_steps=[
                            f"Send GET {base_url}",
                            "Observe HTTP 200 — no HTTPS redirect present.",
                        ],
                        confidence=0.95,
                    ))

        # HSTS check
        probe = self._client.request("GET", base_url)
        if "strict-transport-security" not in probe.response_headers and base_url.startswith("https://"):
            findings.append(_make_finding(
                title="Cryptographic Failure — HSTS Not Set",
                severity=FindingSeverity.MEDIUM,
                owasp=OwaspCategory.A02_CRYPTO_FAILURES,
                cwe_id="CWE-319",
                url=base_url,
                parameter="",
                payload="",
                description="Strict-Transport-Security header is missing. Browsers may accept downgrade attacks.",
                recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                probe=probe,
                reproduction_steps=[
                    f"Send GET {base_url}",
                    "Inspect response headers.",
                    "Observe: Strict-Transport-Security header is absent.",
                ],
                confidence=0.9,
            ))

        return findings

    # ── A03: Injection ─────────────────────────────────────────────────────

    def test_a03_injection(self, endpoints: List[DiscoveredEndpoint]) -> List[DastFinding]:
        findings: List[DastFinding] = []

        for ep in endpoints:
            url = ep.url
            parsed = urllib.parse.urlparse(url)

            # Test query parameters
            params = urllib.parse.parse_qs(parsed.query)
            for param_name in list(params.keys())[:5]:  # cap per endpoint
                findings.extend(self._test_sql_injection(url, param_name))
                findings.extend(self._test_nosql_injection(url, param_name))
                findings.extend(self._test_cmd_injection(url, param_name))

            # Test form inputs
            for form in ep.forms[:3]:
                for inp in form.get("inputs", [])[:5]:
                    param_name = inp.get("name", "")
                    if not param_name:
                        continue
                    form_url = form.get("action", url)
                    findings.extend(self._test_sql_injection_form(form_url, form, param_name))

        return findings

    def _test_sql_injection(self, url: str, param: str) -> List[DastFinding]:
        findings: List[DastFinding] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for payload in _SQL_PAYLOADS[:3]:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs, doseq=True)
            ))
            probe = self._client.request("GET", test_url)
            body = probe.response_body_snippet.lower()
            error_patterns = [
                "sql syntax", "mysql_fetch", "ora-", "pg_query",
                "sqlite3", "syntax error", "unclosed quotation",
                "odbc", "jdbc", "sqlstate",
            ]
            if any(p in body for p in error_patterns):
                findings.append(_make_finding(
                    title="SQL Injection — Error-Based",
                    severity=FindingSeverity.CRITICAL,
                    owasp=OwaspCategory.A03_INJECTION,
                    cwe_id="CWE-89",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    description=f"SQL error message detected in response to injection payload in parameter '{param}'.",
                    recommendation="Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                    probe=probe,
                    reproduction_steps=[
                        f"Send GET {test_url}",
                        "Observe SQL error in response body.",
                    ],
                    confidence=0.85,
                ))
                break
        return findings

    def _test_sql_injection_form(
        self, form_url: str, form: Dict[str, Any], param: str
    ) -> List[DastFinding]:
        findings: List[DastFinding] = []
        for payload in _SQL_PAYLOADS[:2]:
            body_data: Dict[str, str] = {}
            for inp in form.get("inputs", []):
                body_data[inp["name"]] = inp.get("value") or "test"
            body_data[param] = payload
            body = urllib.parse.urlencode(body_data)
            probe = self._client.request(
                form.get("method", "POST"),
                form_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            )
            body_lower = probe.response_body_snippet.lower()
            if any(p in body_lower for p in ["sql syntax", "mysql", "ora-", "sqlstate"]):
                findings.append(_make_finding(
                    title="SQL Injection — Form Input",
                    severity=FindingSeverity.CRITICAL,
                    owasp=OwaspCategory.A03_INJECTION,
                    cwe_id="CWE-89",
                    url=form_url,
                    parameter=param,
                    payload=payload,
                    description=f"SQL error in response to injection payload in form field '{param}'.",
                    recommendation="Use parameterised queries. Validate and sanitise all form inputs.",
                    probe=probe,
                    reproduction_steps=[
                        f"Submit form at {form_url}",
                        f"Set '{param}' = '{payload}'",
                        "Observe SQL error in response.",
                    ],
                    confidence=0.85,
                ))
                break
        return findings

    def _test_nosql_injection(self, url: str, param: str) -> List[DastFinding]:
        findings: List[DastFinding] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for payload in _NOSQL_PAYLOADS[:2]:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs, doseq=True)
            ))
            probe = self._client.request("GET", test_url)
            # NoSQL injection often returns 200 with all records
            if probe.response_status == 200:
                body = probe.response_body_snippet
                # Heuristic: unusually large JSON array
                if body.count("{") > 5 and probe.response_headers.get("content-type", "").startswith("application/json"):
                    findings.append(_make_finding(
                        title="NoSQL Injection — Potential Operator Injection",
                        severity=FindingSeverity.HIGH,
                        owasp=OwaspCategory.A03_INJECTION,
                        cwe_id="CWE-943",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                        description=f"NoSQL operator payload in parameter '{param}' returned potentially expanded result set.",
                        recommendation="Validate and sanitise inputs. Use an ODM/ORM with type-safe queries.",
                        probe=probe,
                        reproduction_steps=[
                            f"Send GET {test_url}",
                            "Observe: large JSON result set — possible authentication bypass or data dump.",
                        ],
                        confidence=0.55,
                    ))
                    break
        return findings

    def _test_cmd_injection(self, url: str, param: str) -> List[DastFinding]:
        findings: List[DastFinding] = []
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        for payload in _CMD_PAYLOADS[:2]:
            test_qs = dict(qs)
            test_qs[param] = [payload]
            test_url = urllib.parse.urlunparse(parsed._replace(
                query=urllib.parse.urlencode(test_qs, doseq=True)
            ))
            probe = self._client.request("GET", test_url)
            if "DAST_PROBE" in probe.response_body_snippet:
                findings.append(_make_finding(
                    title="OS Command Injection",
                    severity=FindingSeverity.CRITICAL,
                    owasp=OwaspCategory.A03_INJECTION,
                    cwe_id="CWE-78",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    description=f"OS command injection confirmed — probe string 'DAST_PROBE' echoed in response for parameter '{param}'.",
                    recommendation="Never pass user input to shell commands. Use subprocess with argument lists, not shell=True.",
                    probe=probe,
                    reproduction_steps=[
                        f"Send GET {test_url}",
                        "Observe 'DAST_PROBE' in response — command executed on server.",
                    ],
                    confidence=0.99,
                ))
                break
        return findings

    # ── A04: Insecure Design ───────────────────────────────────────────────

    def test_a04_insecure_design(self, endpoints: List[DiscoveredEndpoint]) -> List[DastFinding]:
        findings: List[DastFinding] = []

        for ep in endpoints:
            url = ep.url
            # Rate limit bypass test: send rapid requests
            probes = [self._client.request("GET", url) for _ in range(3)]
            statuses = [p.response_status for p in probes]
            if all(s == 200 for s in statuses):
                # No rate limiting observed
                has_sensitive = any(kw in url.lower() for kw in ["/login", "/register", "/reset", "/forgot", "/verify"])
                if has_sensitive:
                    findings.append(_make_finding(
                        title="Insecure Design — No Rate Limiting on Sensitive Endpoint",
                        severity=FindingSeverity.MEDIUM,
                        owasp=OwaspCategory.A04_INSECURE_DESIGN,
                        cwe_id="CWE-770",
                        url=url,
                        parameter="",
                        payload="",
                        description=f"Sensitive endpoint {url} does not appear to rate-limit repeated requests.",
                        recommendation="Implement rate limiting, CAPTCHA, and account lockout on sensitive endpoints.",
                        probe=probes[-1],
                        reproduction_steps=[
                            f"Send 3+ rapid GET requests to {url}",
                            "Observe: all return HTTP 200 — no rate limit enforced.",
                        ],
                        confidence=0.6,
                    ))

        return findings

    # ── A05: Security Misconfiguration ─────────────────────────────────────

    def test_a05_security_misconfiguration(
        self, base_url: str, endpoints: List[DiscoveredEndpoint]
    ) -> List[DastFinding]:
        findings: List[DastFinding] = []
        base = base_url.rstrip("/")

        # Directory listing
        dir_paths = ["/", "/static/", "/uploads/", "/backup/", "/files/", "/images/"]
        for path in dir_paths:
            probe = self._client.request("GET", base + path)
            body = probe.response_body_snippet.lower()
            if probe.response_status == 200 and ("index of" in body or "parent directory" in body):
                findings.append(_make_finding(
                    title="Security Misconfiguration — Directory Listing Enabled",
                    severity=FindingSeverity.MEDIUM,
                    owasp=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    cwe_id="CWE-548",
                    url=base + path,
                    parameter="",
                    payload="",
                    description=f"Directory listing is enabled at {base + path}.",
                    recommendation="Disable directory listing in web server config. Add index files.",
                    probe=probe,
                    reproduction_steps=[
                        f"Send GET {base + path}",
                        "Observe directory listing in response body.",
                    ],
                    confidence=0.9,
                ))

        # Verbose errors
        for ep in endpoints[:10]:
            probe = self._client.request("GET", ep.url + "?id=INVALID_TEST_VAL")
            body = probe.response_body_snippet
            error_patterns = ["traceback", "stack trace", "exception in", "at line", "file \"", "Traceback (most recent"]
            if any(p.lower() in body.lower() for p in error_patterns):
                findings.append(_make_finding(
                    title="Security Misconfiguration — Stack Trace in Error Response",
                    severity=FindingSeverity.MEDIUM,
                    owasp=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    cwe_id="CWE-209",
                    url=ep.url,
                    parameter="id",
                    payload="INVALID_TEST_VAL",
                    description="Application returns full stack trace in error response, leaking internal paths and tech stack.",
                    recommendation="Configure production error handling to return generic messages. Log details server-side.",
                    probe=probe,
                    reproduction_steps=[
                        f"Send GET {ep.url}?id=INVALID_TEST_VAL",
                        "Observe stack trace / exception details in HTTP response.",
                    ],
                    confidence=0.85,
                ))

        # Unnecessary HTTP methods
        for ep in endpoints[:5]:
            for method in ("TRACE", "OPTIONS", "CONNECT"):
                probe = self._client.request(method, ep.url)
                if probe.response_status not in (405, 501, 0):
                    findings.append(_make_finding(
                        title=f"Security Misconfiguration — HTTP {method} Enabled",
                        severity=FindingSeverity.LOW,
                        owasp=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                        cwe_id="CWE-16",
                        url=ep.url,
                        parameter="",
                        payload=method,
                        description=f"HTTP method {method} returned HTTP {probe.response_status} instead of 405.",
                        recommendation=f"Disable {method} method in web server configuration.",
                        probe=probe,
                        reproduction_steps=[
                            f"Send {method} {ep.url}",
                            f"Observe HTTP {probe.response_status} — method is accepted.",
                        ],
                        confidence=0.75,
                    ))

        # Default credentials
        for ep in endpoints:
            if "/admin" in ep.url.lower() or "/login" in ep.url.lower():
                for username, password in _DEFAULT_CREDENTIALS[:3]:
                    body_str = urllib.parse.urlencode({"username": username, "password": password})
                    probe = self._client.request(
                        "POST", ep.url,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        body=body_str,
                    )
                    if probe.response_status in (200, 302) and "location" in probe.response_headers:
                        findings.append(_make_finding(
                            title="Security Misconfiguration — Default Credentials Accepted",
                            severity=FindingSeverity.CRITICAL,
                            owasp=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                            cwe_id="CWE-1392",
                            url=ep.url,
                            parameter="username/password",
                            payload=f"{username}:{password}",
                            description=f"Default credentials '{username}/{password}' accepted at {ep.url}.",
                            recommendation="Change all default credentials. Enforce strong password policy.",
                            probe=probe,
                            reproduction_steps=[
                                f"POST {ep.url}",
                                f"Body: username={username}&password={password}",
                                "Observe redirect/200 — login successful.",
                            ],
                            confidence=0.95,
                        ))
                        break

        return findings

    # ── A06: Vulnerable Components ─────────────────────────────────────────

    def test_a06_vulnerable_components(self, base_url: str) -> List[DastFinding]:
        findings: List[DastFinding] = []
        probe = self._client.request("GET", base_url)
        headers = probe.response_headers

        # Server version disclosure
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        if server:
            # Check for version number in Server header
            if re.search(r"\d+\.\d+", server):
                findings.append(_make_finding(
                    title="Vulnerable Components — Server Version Disclosed",
                    severity=FindingSeverity.LOW,
                    owasp=OwaspCategory.A06_VULNERABLE_COMPONENTS,
                    cwe_id="CWE-200",
                    url=base_url,
                    parameter="",
                    payload="",
                    description=f"Server header discloses version: '{server}'. Attackers can target known CVEs.",
                    recommendation="Configure web server to suppress version information in Server header.",
                    probe=probe,
                    reproduction_steps=[
                        f"Send GET {base_url}",
                        f"Observe response header: Server: {server}",
                    ],
                    confidence=0.85,
                ))

        if x_powered:
            findings.append(_make_finding(
                title="Vulnerable Components — Technology Stack Disclosed",
                severity=FindingSeverity.LOW,
                owasp=OwaspCategory.A06_VULNERABLE_COMPONENTS,
                cwe_id="CWE-200",
                url=base_url,
                parameter="",
                payload="",
                description=f"X-Powered-By header discloses tech stack: '{x_powered}'.",
                recommendation="Remove or spoof X-Powered-By header in web server configuration.",
                probe=probe,
                reproduction_steps=[
                    f"Send GET {base_url}",
                    f"Observe response header: X-Powered-By: {x_powered}",
                ],
                confidence=0.9,
            ))

        return findings

    # ── A07: Authentication Failures ───────────────────────────────────────

    def test_a07_auth_failures(self, endpoints: List[DiscoveredEndpoint]) -> List[DastFinding]:
        findings: List[DastFinding] = []

        for ep in endpoints:
            # Session fixation: check if session ID changes after login-like POST
            if "/login" in ep.url.lower() or "/signin" in ep.url.lower():
                probe_before = self._client.request("GET", ep.url)
                cookie_before = probe_before.response_headers.get("set-cookie", "")
                probe_after = self._client.request(
                    "POST", ep.url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body="username=test&password=test",
                )
                cookie_after = probe_after.response_headers.get("set-cookie", "")
                if cookie_before and cookie_before == cookie_after:
                    findings.append(_make_finding(
                        title="Authentication Failure — Session Fixation",
                        severity=FindingSeverity.HIGH,
                        owasp=OwaspCategory.A07_AUTH_FAILURES,
                        cwe_id="CWE-384",
                        url=ep.url,
                        parameter="session",
                        payload="",
                        description="Session cookie does not change after authentication — session fixation possible.",
                        recommendation="Regenerate session ID immediately after successful authentication.",
                        probe=probe_after,
                        reproduction_steps=[
                            f"GET {ep.url} — observe session cookie value.",
                            f"POST {ep.url} with credentials.",
                            "Observe: same session cookie value — session was not regenerated.",
                        ],
                        confidence=0.75,
                    ))

        return findings

    # ── A08: Data Integrity Failures ───────────────────────────────────────

    def test_a08_data_integrity(self, base_url: str) -> List[DastFinding]:
        findings: List[DastFinding] = []
        probe = self._client.request("GET", base_url)
        headers = probe.response_headers

        # Clickjacking check (X-Frame-Options + CSP frame-ancestors)
        xfo = headers.get("x-frame-options", "").upper()
        csp = headers.get("content-security-policy", "")
        has_frame_protection = xfo in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp
        if not has_frame_protection:
            findings.append(_make_finding(
                title="Data Integrity Failure — Clickjacking Possible",
                severity=FindingSeverity.MEDIUM,
                owasp=OwaspCategory.A08_DATA_INTEGRITY,
                cwe_id="CWE-1021",
                url=base_url,
                parameter="",
                payload="",
                description="No X-Frame-Options or CSP frame-ancestors directive. Page can be embedded in an iframe for clickjacking.",
                recommendation="Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'.",
                probe=probe,
                reproduction_steps=[
                    f"GET {base_url}",
                    "Inspect headers: X-Frame-Options and Content-Security-Policy absent or permissive.",
                    "Embed page in iframe — clickjacking attack possible.",
                ],
                confidence=0.85,
            ))

        # Missing CSP
        if not csp:
            findings.append(_make_finding(
                title="Data Integrity Failure — Content-Security-Policy Missing",
                severity=FindingSeverity.MEDIUM,
                owasp=OwaspCategory.A08_DATA_INTEGRITY,
                cwe_id="CWE-345",
                url=base_url,
                parameter="",
                payload="",
                description="Content-Security-Policy header is absent. Injected scripts will execute.",
                recommendation="Implement a strict Content-Security-Policy with 'default-src' and nonce-based scripts.",
                probe=probe,
                reproduction_steps=[
                    f"GET {base_url}",
                    "Inspect headers: Content-Security-Policy absent.",
                ],
                confidence=0.9,
            ))

        return findings

    # ── A09: Logging Failures ──────────────────────────────────────────────

    def test_a09_logging_failures(self, endpoints: List[DiscoveredEndpoint]) -> List[DastFinding]:
        findings: List[DastFinding] = []
        # Heuristic: check if /health, /metrics, /status endpoints expose sensitive data
        for ep in endpoints:
            path = urllib.parse.urlparse(ep.url).path.lower()
            if any(kw in path for kw in ["/metrics", "/actuator", "/debug", "/health/detailed"]):
                probe = self._client.request("GET", ep.url)
                if probe.response_status == 200:
                    body = probe.response_body_snippet
                    if any(kw in body.lower() for kw in ["password", "secret", "token", "key", "credential"]):
                        findings.append(_make_finding(
                            title="Logging/Monitoring Failure — Sensitive Data in Metrics Endpoint",
                            severity=FindingSeverity.HIGH,
                            owasp=OwaspCategory.A09_LOGGING_FAILURES,
                            cwe_id="CWE-532",
                            url=ep.url,
                            parameter="",
                            payload="",
                            description=f"Monitoring endpoint {ep.url} exposes sensitive data (tokens/secrets/passwords).",
                            recommendation="Restrict access to monitoring endpoints. Never log or expose secrets.",
                            probe=probe,
                            reproduction_steps=[
                                f"GET {ep.url}",
                                "Observe sensitive fields (password/token/secret) in response body.",
                            ],
                            confidence=0.75,
                        ))
        return findings

    # ── A10: SSRF ──────────────────────────────────────────────────────────

    def test_a10_ssrf(self, endpoints: List[DiscoveredEndpoint]) -> List[DastFinding]:
        findings: List[DastFinding] = []

        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep.url)
            params = urllib.parse.parse_qs(parsed.query)

            # Look for URL-like parameters
            url_params = [
                p for p in params.keys()
                if any(kw in p.lower() for kw in ["url", "uri", "href", "src", "redirect", "target", "proxy", "host"])
            ]

            for param in url_params[:3]:
                for payload in _SSRF_PAYLOADS[:2]:
                    test_qs = dict(params)
                    test_qs[param] = [payload]
                    test_url = urllib.parse.urlunparse(parsed._replace(
                        query=urllib.parse.urlencode(test_qs, doseq=True)
                    ))
                    probe = self._client.request("GET", test_url)
                    # SSRF indicators: internal IP disclosure, AWS metadata
                    body = probe.response_body_snippet.lower()
                    if any(kw in body for kw in ["ami-id", "instance-id", "root:x:0", "127.0.0.1", "localhost"]):
                        findings.append(_make_finding(
                            title="SSRF — Server-Side Request Forgery Confirmed",
                            severity=FindingSeverity.CRITICAL,
                            owasp=OwaspCategory.A10_SSRF,
                            cwe_id="CWE-918",
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            description=f"SSRF confirmed: internal content returned when '{param}' set to '{payload}'.",
                            recommendation="Validate and allowlist URL parameters. Block requests to private/loopback addresses.",
                            probe=probe,
                            reproduction_steps=[
                                f"Send GET {test_url}",
                                f"Observe internal content in response — server fetched {payload}.",
                            ],
                            confidence=0.95,
                        ))
                        break

                    # Blind SSRF: check if request was attempted (connection refused vs timeout)
                    if probe.response_status == 0 and "connection refused" in probe.response_body_snippet.lower():
                        findings.append(_make_finding(
                            title="SSRF — Blind SSRF Possible",
                            severity=FindingSeverity.HIGH,
                            owasp=OwaspCategory.A10_SSRF,
                            cwe_id="CWE-918",
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            description=f"Blind SSRF suspected: server attempted to connect to '{payload}' (connection refused).",
                            recommendation="Block server-side URL fetching from user input. Use allowlists.",
                            probe=probe,
                            reproduction_steps=[
                                f"Send GET {test_url}",
                                "Observe error indicating server attempted to connect to the SSRF payload URL.",
                            ],
                            confidence=0.65,
                        ))

        return findings


# ---------------------------------------------------------------------------
# Main DAST engine
# ---------------------------------------------------------------------------

class DastScanner:
    """Orchestrates a full DAST scan lifecycle."""

    def __init__(self) -> None:
        self._scans: Dict[str, ScanResult] = {}
        self._lock = threading.Lock()

    def _validate_target(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Only http/https targets supported, got: {parsed.scheme}")
        if not parsed.netloc:
            raise ValueError("Invalid target URL — no hostname")

    def start_scan(self, config: ScanConfig) -> str:
        """Start a DAST scan in the background. Returns scan_id."""
        self._validate_target(config.target_url)
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        result = ScanResult(
            scan_id=scan_id,
            target_url=config.target_url,
            profile=config.profile,
            status=ScanStatus.PENDING,
            started_at=now,
            completed_at=None,
            endpoints_discovered=0,
            endpoints_tested=0,
            total_findings=0,
            findings=[],
            security_headers=None,
            by_severity={s.value: 0 for s in FindingSeverity},
            by_owasp={},
            duration_ms=0.0,
        )
        with self._lock:
            self._scans[scan_id] = result

        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, config),
            daemon=True,
            name=f"dast-{scan_id[:8]}",
        )
        thread.start()
        _log.info("dast_scan_started", scan_id=scan_id, target=config.target_url, profile=config.profile.value)
        return scan_id

    def _run_scan(self, scan_id: str, config: ScanConfig) -> None:
        t0 = time.monotonic()
        with self._lock:
            self._scans[scan_id].status = ScanStatus.RUNNING

        all_findings: List[DastFinding] = []
        endpoints: List[DiscoveredEndpoint] = []
        headers_result: Optional[SecurityHeadersResult] = None

        try:
            # Auth
            auth_handler = AuthHandler(config)
            session_cookies = auth_handler.authenticate()

            client = _HttpClient(config, session_cookies)
            owasp = OwaspTestSuite(client, config.profile)
            headers_analyser = SecurityHeadersAnalyser()

            # Always check security headers
            headers_result = headers_analyser.analyse(config.target_url, client)

            if config.profile == ScanProfile.QUICK:
                # Quick: headers + config only
                all_findings.extend(owasp.test_a02_crypto_failures(config.target_url))
                all_findings.extend(owasp.test_a05_security_misconfiguration(config.target_url, []))
                all_findings.extend(owasp.test_a06_vulnerable_components(config.target_url))
                all_findings.extend(owasp.test_a08_data_integrity(config.target_url))

            elif config.profile == ScanProfile.API_ONLY:
                # API-only: OpenAPI-driven
                if config.openapi_spec:
                    endpoints = self._endpoints_from_openapi(config.openapi_spec, config.target_url)
                    all_findings.extend(owasp.test_a01_broken_access_control(endpoints))
                    all_findings.extend(owasp.test_a03_injection(endpoints))
                    all_findings.extend(owasp.test_a10_ssrf(endpoints))
                all_findings.extend(owasp.test_a06_vulnerable_components(config.target_url))

            else:
                # Standard / Full: crawl first
                disallowed: Set[str] = set()
                if config.respect_robots_txt:
                    disallowed = _fetch_robots_txt(config.target_url, config.timeout)

                crawler = WebCrawler(config, client)
                endpoints = crawler.crawl(disallowed)
                _log.info("crawl_complete", scan_id=scan_id, endpoints=len(endpoints))

                # Supplement with OpenAPI if provided
                if config.openapi_spec:
                    endpoints.extend(self._endpoints_from_openapi(config.openapi_spec, config.target_url))

                # Run all OWASP tests
                all_findings.extend(owasp.test_a01_broken_access_control(endpoints))
                all_findings.extend(owasp.test_a02_crypto_failures(config.target_url))
                all_findings.extend(owasp.test_a03_injection(endpoints))
                all_findings.extend(owasp.test_a04_insecure_design(endpoints))
                all_findings.extend(owasp.test_a05_security_misconfiguration(config.target_url, endpoints))
                all_findings.extend(owasp.test_a06_vulnerable_components(config.target_url))
                all_findings.extend(owasp.test_a08_data_integrity(config.target_url))
                all_findings.extend(owasp.test_a09_logging_failures(endpoints))
                all_findings.extend(owasp.test_a10_ssrf(endpoints))

                if config.profile == ScanProfile.FULL:
                    # Full: include auth testing
                    all_findings.extend(owasp.test_a07_auth_failures(endpoints))

            # Aggregate
            by_severity: Dict[str, int] = {s.value: 0 for s in FindingSeverity}
            by_owasp: Dict[str, int] = {}
            for f in all_findings:
                by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
                cat = f.owasp_category.value
                by_owasp[cat] = by_owasp.get(cat, 0) + 1

            duration_ms = (time.monotonic() - t0) * 1000

            with self._lock:
                result = self._scans[scan_id]
                result.status = ScanStatus.COMPLETED
                result.completed_at = datetime.now(timezone.utc)
                result.endpoints_discovered = len(endpoints)
                result.endpoints_tested = len(endpoints)
                result.total_findings = len(all_findings)
                result.findings = all_findings
                result.security_headers = headers_result
                result.by_severity = by_severity
                result.by_owasp = by_owasp
                result.duration_ms = duration_ms

            _log.info(
                "dast_scan_completed",
                scan_id=scan_id,
                findings=len(all_findings),
                duration_ms=round(duration_ms, 2),
            )

        except Exception as exc:
            _log.exception("dast_scan_failed", scan_id=scan_id, error=str(exc))
            with self._lock:
                result = self._scans[scan_id]
                result.status = ScanStatus.FAILED
                result.completed_at = datetime.now(timezone.utc)
                result.error = str(exc)
                result.duration_ms = (time.monotonic() - t0) * 1000

    def _endpoints_from_openapi(
        self, spec: Dict[str, Any], base_url: str
    ) -> List[DiscoveredEndpoint]:
        endpoints: List[DiscoveredEndpoint] = []
        base = base_url.rstrip("/")
        for path, methods in spec.get("paths", {}).items():
            for method in methods:
                if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                details = methods[method]
                params = [
                    p.get("name", "")
                    for p in details.get("parameters", [])
                    if p.get("in") == "query"
                ]
                endpoints.append(DiscoveredEndpoint(
                    url=base + path,
                    method=method.upper(),
                    parameters=params,
                    source="openapi",
                ))
        return endpoints

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        with self._lock:
            return self._scans.get(scan_id)

    def get_all_findings(self, severity_filter: Optional[str] = None) -> List[DastFinding]:
        findings: List[DastFinding] = []
        with self._lock:
            for result in self._scans.values():
                for f in result.findings:
                    if severity_filter is None or f.severity.value == severity_filter:
                        findings.append(f)
        return findings


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_engine: Optional[DastScanner] = None
_engine_lock = threading.Lock()


def get_dast_scanner() -> DastScanner:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = DastScanner()
    return _engine
