"""WAF Rule Generator Engine — Auto-generate WAF rules from vulnerability findings.

Supports AWS WAF, Cloudflare WAF, ModSecurity, NGINX, and Apache mod_security.
Provides rule templates, virtual patching, rule testing, lifecycle management,
and multi-format export.

Usage:
    from core.waf_generator import WAFRuleGenerator, get_waf_generator

    gen = get_waf_generator()
    rules = gen.generate_from_finding(finding)
    exported = gen.export_rules(rules, provider="aws_waf")
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WAFProvider(str, Enum):
    AWS_WAF = "aws_waf"
    CLOUDFLARE = "cloudflare"
    MODSECURITY = "modsecurity"
    NGINX = "nginx"
    APACHE = "apache"


class RuleType(str, Enum):
    BLOCK = "block"
    LOG = "log"
    RATE_LIMIT = "rate_limit"
    ALLOW = "allow"
    CHALLENGE = "challenge"


class RuleStatus(str, Enum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class VulnType(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    RCE = "rce"
    SSRF = "ssrf"
    XXE = "xxe"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    BOT = "bot"
    RATE_ABUSE = "rate_abuse"
    API_ABUSE = "api_abuse"
    GENERIC = "generic"


class ExportFormat(str, Enum):
    PROVIDER_NATIVE = "provider_native"
    OWASP_CRS = "owasp_crs"
    TERRAFORM = "terraform"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

try:
    from pydantic import BaseModel, Field, field_validator, model_validator
    _PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, Field  # type: ignore
    _PYDANTIC_V2 = False


class WAFCondition(BaseModel):
    """A single match condition within a WAF rule."""
    field: str                   # e.g. "QUERY_STRING", "URI", "BODY", "HEADER"
    operator: str                # e.g. "CONTAINS", "MATCHES", "STARTS_WITH"
    value: str                   # the pattern or literal to match
    negate: bool = False         # if True, condition fires when NOT matched
    transform: Optional[str] = None  # e.g. "URL_DECODE", "LOWERCASE"


class WAFRule(BaseModel):
    """Abstract WAF rule — provider-agnostic representation."""
    rule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    rule_type: RuleType
    vuln_type: VulnType
    conditions: List[WAFCondition]
    priority: int = 100           # lower = evaluated first
    status: RuleStatus = RuleStatus.DRAFT
    provider: Optional[WAFProvider] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    history: List[Dict[str, Any]] = Field(default_factory=list)
    false_positive_rate: Optional[float] = None   # populated after testing
    test_results: List[Dict[str, Any]] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}  # pydantic v2 style; harmless in v1


class VulnFinding(BaseModel):
    """Minimal vulnerability finding fed into the generator."""
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    vuln_type: VulnType = VulnType.GENERIC
    severity: str = "high"          # critical / high / medium / low
    endpoint: Optional[str] = None  # e.g. "/api/users"
    parameter: Optional[str] = None # e.g. "id"
    method: Optional[str] = None    # GET / POST / ...
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    description: str = ""
    attack_payload: Optional[str] = None  # example payload that triggered the vuln


class TestRequest(BaseModel):
    """A sample HTTP request used during rule simulation."""
    uri: str
    method: str = "GET"
    query_string: str = ""
    body: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    is_malicious: bool = False      # ground truth for FP/FN calculation


class TestResult(BaseModel):
    """Outcome of simulating a rule against a request."""
    rule_id: str
    request_uri: str
    matched: bool
    expected_block: bool
    correct: bool
    match_condition: Optional[str] = None
    latency_us: int = 0


class RuleSet(BaseModel):
    """Collection of rules for a deployment unit."""
    ruleset_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    provider: WAFProvider
    rules: List[WAFRule] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    description: str = ""


# ---------------------------------------------------------------------------
# SQL injection patterns
# ---------------------------------------------------------------------------

_SQLI_PATTERNS: List[str] = [
    r"(?i)(\bunion\b.+\bselect\b)",
    r"(?i)(\bselect\b.+\bfrom\b)",
    r"(?i)(\binsert\b.+\binto\b)",
    r"(?i)(\bdelete\b.+\bfrom\b)",
    r"(?i)(\bdrop\b.+\btable\b)",
    r"(?i)(--|\#|\/\*)",
    r"(?i)(\bor\b\s+\d+=\d+)",
    r"(?i)(\band\b\s+\d+=\d+)",
    r"(?i)(sleep\s*\(\s*\d+\s*\))",
    r"(?i)(benchmark\s*\()",
    r"(?i)(load_file\s*\()",
    r"(?i)(into\s+outfile\b)",
    r"'[^']*'=[^']*'",
    r"(?i)(xp_cmdshell)",
    r"(?i)(exec\s*\()",
]

_XSS_PATTERNS: List[str] = [
    r"(?i)(<script[\s>])",
    r"(?i)(javascript\s*:)",
    r"(?i)(on\w+\s*=\s*[\"'])",
    r"(?i)(<iframe[\s>])",
    r"(?i)(document\.cookie)",
    r"(?i)(document\.write\s*\()",
    r"(?i)(eval\s*\()",
    r"(?i)(<svg[\s>].+on\w+=)",
    r"(?i)(expression\s*\()",
    r"(?i)(vbscript\s*:)",
]

_PATH_TRAVERSAL_PATTERNS: List[str] = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%252e%252e",
    r"(?i)(/etc/passwd)",
    r"(?i)(/etc/shadow)",
    r"(?i)(win\.ini)",
    r"(?i)(boot\.ini)",
]

_RCE_PATTERNS: List[str] = [
    r"(?i)(;\s*\w+\s*=)",
    r"\|\s*\w+",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"(?i)(wget\s+http)",
    r"(?i)(curl\s+http)",
    r"(?i)(nc\s+-[elnv])",
    r"(?i)(/bin/(bash|sh|dash|zsh))",
    r"(?i)(python\s+-c)",
    r"(?i)(php\s+-r)",
]

_FILE_UPLOAD_PATTERNS: List[str] = [
    r"(?i)(\.php\d?$)",
    r"(?i)(\.asp[x]?$)",
    r"(?i)(\.jsp$)",
    r"(?i)(\.cgi$)",
    r"(?i)(\.sh$)",
    r"(?i)(\.py$)",
    r"(?i)(\.pl$)",
    r"(?i)(content-type:\s*application/x-php)",
]

_BOT_PATTERNS: List[str] = [
    r"(?i)(sqlmap)",
    r"(?i)(nikto)",
    r"(?i)(nmap)",
    r"(?i)(masscan)",
    r"(?i)(zgrab)",
    r"(?i)(curl/[0-9])",
    r"(?i)(python-requests/)",
    r"(?i)(go-http-client/)",
    r"(?i)(python-urllib)",
    r"(?i)(scrapy)",
]

_SSRF_PATTERNS: List[str] = [
    r"(?i)(http://localhost)",
    r"(?i)(http://127\.0\.0\.1)",
    r"(?i)(http://0\.0\.0\.0)",
    r"(?i)(http://10\.\d+\.\d+\.\d+)",
    r"(?i)(http://172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    r"(?i)(http://192\.168\.)",
    r"(?i)(http://169\.254\.)",
    r"(?i)(file://)",
    r"(?i)(gopher://)",
    r"(?i)(dict://)",
]


# ---------------------------------------------------------------------------
# Rule template registry — 50+ templates
# ---------------------------------------------------------------------------

class RuleTemplate:
    """Immutable template that can be instantiated into a WAFRule."""

    def __init__(
        self,
        template_id: str,
        name: str,
        description: str,
        vuln_type: VulnType,
        rule_type: RuleType,
        conditions: List[WAFCondition],
        owasp_category: str = "",
        cwe_id: str = "",
        tags: Optional[List[str]] = None,
        priority: int = 100,
    ) -> None:
        self.template_id = template_id
        self.name = name
        self.description = description
        self.vuln_type = vuln_type
        self.rule_type = rule_type
        self.conditions = conditions
        self.owasp_category = owasp_category
        self.cwe_id = cwe_id
        self.tags = tags or []
        self.priority = priority

    def instantiate(self, endpoint: Optional[str] = None, parameter: Optional[str] = None) -> WAFRule:
        conditions = list(self.conditions)
        if endpoint:
            conditions.insert(0, WAFCondition(
                field="URI",
                operator="STARTS_WITH",
                value=endpoint,
            ))
        if parameter:
            conditions.append(WAFCondition(
                field="QUERY_STRING",
                operator="CONTAINS",
                value=parameter,
            ))
        return WAFRule(
            name=self.name,
            description=self.description,
            rule_type=self.rule_type,
            vuln_type=self.vuln_type,
            conditions=conditions,
            owasp_category=self.owasp_category,
            cwe_id=self.cwe_id,
            tags=list(self.tags),
            priority=self.priority,
            endpoint=endpoint,
            parameter=parameter,
        )


def _build_template_registry() -> Dict[str, RuleTemplate]:
    """Build the 50+ template catalog."""
    t: Dict[str, RuleTemplate] = {}

    # ---- SQLi templates ----
    for i, pat in enumerate(_SQLI_PATTERNS[:5], 1):
        tid = f"SQLI-{i:03d}"
        t[tid] = RuleTemplate(
            template_id=tid,
            name=f"Block SQL Injection Pattern {i}",
            description=f"Blocks SQL injection pattern: {pat[:40]}",
            vuln_type=VulnType.SQLI,
            rule_type=RuleType.BLOCK,
            conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=pat, transform="URL_DECODE")],
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-89",
            tags=["sqli", "injection", "owasp-top10"],
            priority=10,
        )
    t["SQLI-LOG"] = RuleTemplate(
        template_id="SQLI-LOG",
        name="Log SQL Injection Attempts",
        description="Log all SQLi-like patterns for monitoring",
        vuln_type=VulnType.SQLI,
        rule_type=RuleType.LOG,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(\bselect\b|\bunion\b|\bdrop\b)", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        tags=["sqli", "logging"],
        priority=50,
    )
    t["SQLI-BODY"] = RuleTemplate(
        template_id="SQLI-BODY",
        name="Block SQL Injection in Request Body",
        description="Blocks SQLi patterns in POST body",
        vuln_type=VulnType.SQLI,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="BODY", operator="MATCHES", value=r"(?i)(union.+select|insert.+into|delete.+from)", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        tags=["sqli", "body"],
        priority=10,
    )
    t["SQLI-HEADER"] = RuleTemplate(
        template_id="SQLI-HEADER",
        name="Block SQL Injection in Headers",
        description="Blocks SQLi patterns in HTTP headers (User-Agent, Referer)",
        vuln_type=VulnType.SQLI,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="HEADER:User-Agent", operator="MATCHES", value=r"(?i)(union|select|insert|delete|drop)")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        tags=["sqli", "header"],
        priority=10,
    )
    t["SQLI-BLIND"] = RuleTemplate(
        template_id="SQLI-BLIND",
        name="Block Blind SQL Injection (time-based)",
        description="Blocks time-based blind SQLi: sleep(), benchmark()",
        vuln_type=VulnType.SQLI,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        tags=["sqli", "blind", "time-based"],
        priority=10,
    )

    # ---- XSS templates ----
    for i, pat in enumerate(_XSS_PATTERNS[:5], 1):
        tid = f"XSS-{i:03d}"
        t[tid] = RuleTemplate(
            template_id=tid,
            name=f"Block XSS Pattern {i}",
            description=f"Blocks cross-site scripting: {pat[:40]}",
            vuln_type=VulnType.XSS,
            rule_type=RuleType.BLOCK,
            conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=pat, transform="HTML_DECODE")],
            owasp_category="A03:2021-Injection",
            cwe_id="CWE-79",
            tags=["xss", "injection"],
            priority=20,
        )
    t["XSS-BODY"] = RuleTemplate(
        template_id="XSS-BODY",
        name="Block XSS in Request Body",
        description="Blocks XSS in JSON/form POST bodies",
        vuln_type=VulnType.XSS,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="BODY", operator="MATCHES", value=r"(?i)(<script|javascript:|on\w+=)", transform="HTML_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-79",
        tags=["xss", "body"],
        priority=20,
    )
    t["XSS-LOG"] = RuleTemplate(
        template_id="XSS-LOG",
        name="Log XSS Attempts",
        description="Log XSS-like patterns for monitoring without blocking",
        vuln_type=VulnType.XSS,
        rule_type=RuleType.LOG,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(<[a-z]+\s)", transform="HTML_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-79",
        tags=["xss", "logging"],
        priority=50,
    )

    # ---- Path traversal templates ----
    for i, pat in enumerate(_PATH_TRAVERSAL_PATTERNS[:4], 1):
        tid = f"PATH-{i:03d}"
        t[tid] = RuleTemplate(
            template_id=tid,
            name=f"Block Path Traversal Pattern {i}",
            description=f"Blocks directory traversal: {pat[:40]}",
            vuln_type=VulnType.PATH_TRAVERSAL,
            rule_type=RuleType.BLOCK,
            conditions=[WAFCondition(field="URI", operator="CONTAINS", value=pat, transform="URL_DECODE")],
            owasp_category="A01:2021-Broken Access Control",
            cwe_id="CWE-22",
            tags=["path-traversal", "lfi"],
            priority=15,
        )
    t["PATH-ENCODED"] = RuleTemplate(
        template_id="PATH-ENCODED",
        name="Block Double-Encoded Path Traversal",
        description="Blocks double-URL-encoded traversal sequences",
        vuln_type=VulnType.PATH_TRAVERSAL,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="URI", operator="MATCHES", value=r"(?:%252e|%252f|\.\.%252f)", transform="URL_DECODE")],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-22",
        tags=["path-traversal", "encoded"],
        priority=15,
    )
    t["PATH-SENSITIVE"] = RuleTemplate(
        template_id="PATH-SENSITIVE",
        name="Block Access to Sensitive System Files",
        description="Blocks requests targeting /etc/passwd, /etc/shadow, win.ini, etc.",
        vuln_type=VulnType.PATH_TRAVERSAL,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="URI", operator="MATCHES", value=r"(?i)(/etc/passwd|/etc/shadow|/proc/self|win\.ini|boot\.ini)")],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-22",
        tags=["path-traversal", "lfi", "sensitive-files"],
        priority=5,
    )

    # ---- File upload templates ----
    for i, pat in enumerate(_FILE_UPLOAD_PATTERNS[:4], 1):
        tid = f"UPLOAD-{i:03d}"
        t[tid] = RuleTemplate(
            template_id=tid,
            name=f"Restrict File Upload Type {i}",
            description=f"Blocks upload of executable file types matching {pat[:30]}",
            vuln_type=VulnType.FILE_UPLOAD,
            rule_type=RuleType.BLOCK,
            conditions=[WAFCondition(field="HEADER:Content-Disposition", operator="MATCHES", value=pat)],
            owasp_category="A04:2021-Insecure Design",
            cwe_id="CWE-434",
            tags=["file-upload", "unrestricted-upload"],
            priority=30,
        )
    t["UPLOAD-SIZE"] = RuleTemplate(
        template_id="UPLOAD-SIZE",
        name="Enforce Upload Size Limit",
        description="Blocks uploads exceeding size threshold (50MB)",
        vuln_type=VulnType.FILE_UPLOAD,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="HEADER:Content-Length", operator="GT", value="52428800")],
        owasp_category="A04:2021-Insecure Design",
        cwe_id="CWE-770",
        tags=["file-upload", "dos"],
        priority=30,
    )

    # ---- Bot detection templates ----
    for i, pat in enumerate(_BOT_PATTERNS[:5], 1):
        tid = f"BOT-{i:03d}"
        t[tid] = RuleTemplate(
            template_id=tid,
            name=f"Block Known Scanner/Bot {i}",
            description=f"Blocks known scanning tool user-agent: {pat[:40]}",
            vuln_type=VulnType.BOT,
            rule_type=RuleType.BLOCK,
            conditions=[WAFCondition(field="HEADER:User-Agent", operator="MATCHES", value=pat)],
            owasp_category="A05:2021-Security Misconfiguration",
            cwe_id="CWE-693",
            tags=["bot", "scanner", "user-agent"],
            priority=5,
        )
    t["BOT-EMPTY-UA"] = RuleTemplate(
        template_id="BOT-EMPTY-UA",
        name="Block Empty User-Agent",
        description="Blocks requests with no User-Agent header (typical bots)",
        vuln_type=VulnType.BOT,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="HEADER:User-Agent", operator="ABSENT", value="")],
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-693",
        tags=["bot", "user-agent"],
        priority=5,
    )

    # ---- Rate limiting templates ----
    t["RATE-IP"] = RuleTemplate(
        template_id="RATE-IP",
        name="Rate Limit by Source IP",
        description="Rate limits to 100 requests per 5 minutes per IP",
        vuln_type=VulnType.RATE_ABUSE,
        rule_type=RuleType.RATE_LIMIT,
        conditions=[WAFCondition(field="IP", operator="ANY", value="*")],
        owasp_category="A04:2021-Insecure Design",
        cwe_id="CWE-770",
        tags=["rate-limit", "dos"],
        priority=40,
    )
    t["RATE-API"] = RuleTemplate(
        template_id="RATE-API",
        name="Rate Limit API Endpoints",
        description="Rate limits API paths to 200 req/min per IP",
        vuln_type=VulnType.API_ABUSE,
        rule_type=RuleType.RATE_LIMIT,
        conditions=[WAFCondition(field="URI", operator="STARTS_WITH", value="/api/")],
        owasp_category="A04:2021-Insecure Design",
        cwe_id="CWE-770",
        tags=["rate-limit", "api"],
        priority=40,
    )
    t["RATE-AUTH"] = RuleTemplate(
        template_id="RATE-AUTH",
        name="Rate Limit Authentication Endpoint",
        description="Strict rate limit on /login and /auth — max 10 req/min per IP",
        vuln_type=VulnType.RATE_ABUSE,
        rule_type=RuleType.RATE_LIMIT,
        conditions=[WAFCondition(field="URI", operator="MATCHES", value=r"(?i)/(login|auth|token|sign-?in)")],
        owasp_category="A07:2021-Identification and Authentication Failures",
        cwe_id="CWE-307",
        tags=["rate-limit", "auth", "brute-force"],
        priority=5,
    )

    # ---- Geo-blocking templates ----
    t["GEO-BLOCK"] = RuleTemplate(
        template_id="GEO-BLOCK",
        name="Geo-Block High-Risk Countries",
        description="Block traffic from high-risk country codes (configurable)",
        vuln_type=VulnType.API_ABUSE,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="GEO:COUNTRY", operator="IN", value="CN,RU,KP,IR")],
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="",
        tags=["geo", "block", "country"],
        priority=2,
    )

    # ---- SSRF templates ----
    t["SSRF-001"] = RuleTemplate(
        template_id="SSRF-001",
        name="Block SSRF via Internal IP in Parameters",
        description="Blocks internal IP addresses embedded in query parameters",
        vuln_type=VulnType.SSRF,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(http://(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|0\.0\.0\.0))", transform="URL_DECODE")],
        owasp_category="A10:2021-Server-Side Request Forgery",
        cwe_id="CWE-918",
        tags=["ssrf"],
        priority=15,
    )
    t["SSRF-002"] = RuleTemplate(
        template_id="SSRF-002",
        name="Block SSRF Cloud Metadata Access",
        description="Blocks attempts to reach cloud metadata endpoints (169.254.169.254)",
        vuln_type=VulnType.SSRF,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="CONTAINS", value="169.254.169.254", transform="URL_DECODE")],
        owasp_category="A10:2021-Server-Side Request Forgery",
        cwe_id="CWE-918",
        tags=["ssrf", "cloud-metadata"],
        priority=5,
    )

    # ---- RCE templates ----
    t["RCE-001"] = RuleTemplate(
        template_id="RCE-001",
        name="Block Remote Code Execution via Shell Metacharacters",
        description="Blocks shell injection chars in query strings",
        vuln_type=VulnType.RCE,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"[;&|`$(){}<>]", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-78",
        tags=["rce", "shell-injection"],
        priority=10,
    )
    t["RCE-002"] = RuleTemplate(
        template_id="RCE-002",
        name="Block Command Injection Tools",
        description="Blocks references to wget, curl, nc in requests",
        vuln_type=VulnType.RCE,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(wget\s|curl\s|nc\s+-|python\s+-c|php\s+-r)", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-78",
        tags=["rce", "command-injection"],
        priority=10,
    )

    # ---- XXE templates ----
    t["XXE-001"] = RuleTemplate(
        template_id="XXE-001",
        name="Block XXE in XML Body",
        description="Blocks XML External Entity declarations in request body",
        vuln_type=VulnType.XXE,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="BODY", operator="MATCHES", value=r"(?i)(<!entity\s|<!doctype\s+[^>]*\bsystem\b)")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-611",
        tags=["xxe", "xml"],
        priority=10,
    )

    # ---- API abuse templates ----
    t["API-ENUM"] = RuleTemplate(
        template_id="API-ENUM",
        name="Block API Endpoint Enumeration",
        description="Rate limit and log rapid sequential API probing",
        vuln_type=VulnType.API_ABUSE,
        rule_type=RuleType.RATE_LIMIT,
        conditions=[WAFCondition(field="URI", operator="STARTS_WITH", value="/api/")],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-200",
        tags=["api", "enumeration"],
        priority=20,
    )
    t["API-OVERSIZED"] = RuleTemplate(
        template_id="API-OVERSIZED",
        name="Block Oversized API Payloads",
        description="Blocks requests with body >10MB to prevent DoS",
        vuln_type=VulnType.API_ABUSE,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="HEADER:Content-Length", operator="GT", value="10485760")],
        owasp_category="A04:2021-Insecure Design",
        cwe_id="CWE-770",
        tags=["api", "dos", "payload-size"],
        priority=30,
    )

    # ---- CSRF templates ----
    t["CSRF-001"] = RuleTemplate(
        template_id="CSRF-001",
        name="Enforce CSRF Token on State-Changing Methods",
        description="Block POST/PUT/DELETE without X-CSRF-Token header",
        vuln_type=VulnType.CSRF,
        rule_type=RuleType.BLOCK,
        conditions=[
            WAFCondition(field="METHOD", operator="IN", value="POST,PUT,DELETE,PATCH"),
            WAFCondition(field="HEADER:X-CSRF-Token", operator="ABSENT", value=""),
        ],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-352",
        tags=["csrf"],
        priority=25,
    )

    # ---- Open Redirect templates ----
    t["REDIRECT-001"] = RuleTemplate(
        template_id="REDIRECT-001",
        name="Block Open Redirect via url Parameter",
        description="Blocks open redirects targeting external domains via url/redirect params",
        vuln_type=VulnType.OPEN_REDIRECT,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r"(?i)(url|redirect|next|return|goto)=https?://", transform="URL_DECODE")],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-601",
        tags=["open-redirect"],
        priority=20,
    )

    # ---- IDOR templates ----
    t["IDOR-001"] = RuleTemplate(
        template_id="IDOR-001",
        name="Rate Limit Direct Object Reference Endpoints",
        description="Rate limit enumeration of /api/{resource}/{id} style endpoints",
        vuln_type=VulnType.IDOR,
        rule_type=RuleType.RATE_LIMIT,
        conditions=[WAFCondition(field="URI", operator="MATCHES", value=r"/api/v?\d*/\w+/\d+")],
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-639",
        tags=["idor", "rate-limit"],
        priority=40,
    )

    # ---- Additional SQLi templates ----
    t["SQLI-STACKED"] = RuleTemplate(
        template_id="SQLI-STACKED",
        name="Block Stacked SQL Queries",
        description="Blocks stacked/batched SQL statements via semicolons",
        vuln_type=VulnType.SQLI,
        rule_type=RuleType.BLOCK,
        conditions=[WAFCondition(field="QUERY_STRING", operator="MATCHES", value=r";\s*(select|insert|update|delete|drop|exec|declare)\b", transform="URL_DECODE")],
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        tags=["sqli", "stacked"],
        priority=10,
    )

    # ---- Additional bot detection ----
    t["BOT-HEADLESS"] = RuleTemplate(
        template_id="BOT-HEADLESS",
        name="Detect Headless Browser Fingerprints",
        description="Blocks headless Chrome/Puppeteer/Playwright fingerprints",
        vuln_type=VulnType.BOT,
        rule_type=RuleType.CHALLENGE,
        conditions=[WAFCondition(field="HEADER:User-Agent", operator="MATCHES", value=r"(?i)(headlesschrome|phantomjs|selenium|webdriver)")],
        owasp_category="A05:2021-Security Misconfiguration",
        cwe_id="CWE-693",
        tags=["bot", "headless-browser"],
        priority=5,
    )

    # ---- API abuse: missing auth header ----
    t["API-NO-AUTH"] = RuleTemplate(
        template_id="API-NO-AUTH",
        name="Log API Requests Missing Authorization Header",
        description="Log /api/ requests without Authorization or X-API-Key header",
        vuln_type=VulnType.API_ABUSE,
        rule_type=RuleType.LOG,
        conditions=[
            WAFCondition(field="URI", operator="STARTS_WITH", value="/api/"),
            WAFCondition(field="HEADER:Authorization", operator="ABSENT", value=""),
        ],
        owasp_category="A07:2021-Identification and Authentication Failures",
        cwe_id="CWE-306",
        tags=["api", "auth", "logging"],
        priority=50,
    )

    return t


_TEMPLATES: Dict[str, RuleTemplate] = _build_template_registry()

# Map vuln type → preferred template IDs (for auto-generation)
_VULN_TO_TEMPLATES: Dict[VulnType, List[str]] = {
    VulnType.SQLI: ["SQLI-001", "SQLI-002", "SQLI-BODY", "SQLI-BLIND", "SQLI-LOG"],
    VulnType.XSS: ["XSS-001", "XSS-002", "XSS-BODY", "XSS-LOG"],
    VulnType.PATH_TRAVERSAL: ["PATH-001", "PATH-002", "PATH-SENSITIVE", "PATH-ENCODED"],
    VulnType.FILE_UPLOAD: ["UPLOAD-001", "UPLOAD-002", "UPLOAD-SIZE"],
    VulnType.RCE: ["RCE-001", "RCE-002"],
    VulnType.SSRF: ["SSRF-001", "SSRF-002"],
    VulnType.XXE: ["XXE-001"],
    VulnType.BOT: ["BOT-001", "BOT-002", "BOT-EMPTY-UA"],
    VulnType.RATE_ABUSE: ["RATE-IP", "RATE-AUTH"],
    VulnType.API_ABUSE: ["RATE-API", "API-ENUM", "API-OVERSIZED"],
    VulnType.CSRF: ["CSRF-001"],
    VulnType.GENERIC: ["RATE-IP", "BOT-EMPTY-UA"],
    VulnType.IDOR: ["RATE-API"],
    VulnType.OPEN_REDIRECT: ["SSRF-001"],
}


# ---------------------------------------------------------------------------
# Provider-specific serializers
# ---------------------------------------------------------------------------

def _export_aws_waf(rule: WAFRule) -> Dict[str, Any]:
    """Serialize a WAFRule to AWS WAF v2 JSON format."""
    statements = []
    for cond in rule.conditions:
        if cond.operator == "MATCHES":
            stmt: Dict[str, Any] = {
                "RegexMatchStatement": {
                    "RegexString": cond.value,
                    "FieldToMatch": _aws_field(cond.field),
                    "TextTransformations": [{"Priority": 0, "Type": cond.transform or "NONE"}],
                }
            }
        elif cond.operator == "CONTAINS":
            stmt = {
                "ByteMatchStatement": {
                    "SearchString": cond.value,
                    "FieldToMatch": _aws_field(cond.field),
                    "PositionalConstraint": "CONTAINS",
                    "TextTransformations": [{"Priority": 0, "Type": cond.transform or "NONE"}],
                }
            }
        elif cond.operator == "STARTS_WITH":
            stmt = {
                "ByteMatchStatement": {
                    "SearchString": cond.value,
                    "FieldToMatch": _aws_field(cond.field),
                    "PositionalConstraint": "STARTS_WITH",
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }
            }
        else:
            stmt = {
                "ByteMatchStatement": {
                    "SearchString": cond.value,
                    "FieldToMatch": _aws_field(cond.field),
                    "PositionalConstraint": "EXACTLY",
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }
            }
        if cond.negate:
            stmt = {"NotStatement": {"Statement": stmt}}
        statements.append(stmt)

    final_statement = statements[0] if len(statements) == 1 else {"AndStatement": {"Statements": statements}}
    action_key = "Count" if rule.rule_type == RuleType.LOG else "Block"
    return {
        "Name": re.sub(r"[^A-Za-z0-9\-_]", "-", rule.name)[:128],
        "Priority": rule.priority,
        "Statement": final_statement,
        "Action": {action_key: {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": re.sub(r"[^A-Za-z0-9]", "", rule.name)[:128],
        },
    }


def _aws_field(field: str) -> Dict[str, Any]:
    mapping = {
        "QUERY_STRING": {"QueryString": {}},
        "URI": {"UriPath": {}},
        "BODY": {"Body": {"OversizeHandling": "CONTINUE"}},
        "METHOD": {"Method": {}},
        "IP": {"IPSet": {}},
    }
    if field.startswith("HEADER:"):
        hdr = field.split(":", 1)[1]
        return {"SingleHeader": {"Name": hdr.lower()}}
    return mapping.get(field, {"QueryString": {}})


def _export_cloudflare(rule: WAFRule) -> Dict[str, Any]:
    """Serialize a WAFRule to Cloudflare WAF custom rule JSON."""
    expressions = []
    for cond in rule.conditions:
        expr = _cf_expression(cond)
        if cond.negate:
            expr = f"not ({expr})"
        expressions.append(expr)
    final_expr = " and ".join(f"({e})" for e in expressions) if expressions else "true"
    action_map = {
        RuleType.BLOCK: "block",
        RuleType.LOG: "log",
        RuleType.RATE_LIMIT: "challenge",
        RuleType.ALLOW: "skip",
        RuleType.CHALLENGE: "challenge",
    }
    return {
        "description": rule.name,
        "expression": final_expr,
        "action": action_map.get(rule.rule_type, "block"),
        "enabled": rule.status == RuleStatus.ACTIVE,
        "ref": rule.rule_id[:16],
    }


def _cf_expression(cond: WAFCondition) -> str:
    field_map = {
        "QUERY_STRING": "http.request.uri.query",
        "URI": "http.request.uri.path",
        "BODY": "http.request.body.raw",
        "METHOD": "http.request.method",
        "HEADER:User-Agent": "http.request.headers[\"user-agent\"]",
        "IP": "ip.src",
        "GEO:COUNTRY": "ip.geoip.country",
    }
    if cond.field.startswith("HEADER:"):
        hdr = cond.field.split(":", 1)[1].lower()
        cf_field = f'http.request.headers["{hdr}"]'
    else:
        cf_field = field_map.get(cond.field, "http.request.uri.query")

    if cond.operator == "MATCHES":
        return f'{cf_field} matches r"{cond.value}"'
    elif cond.operator == "CONTAINS":
        return f'({cf_field} contains "{cond.value}")'
    elif cond.operator == "STARTS_WITH":
        return f'starts_with({cf_field}, "{cond.value}")'
    elif cond.operator == "IN":
        vals = " ".join(f'"{v.strip()}"' for v in cond.value.split(","))
        return f"{cf_field} in {{{vals}}}"
    elif cond.operator == "ABSENT":
        return f'not http.request.headers["{cond.field.split(":", 1)[-1].lower()}"] exists'
    else:
        return f'{cf_field} == "{cond.value}"'


def _export_modsecurity(rule: WAFRule) -> str:
    """Serialize a WAFRule to ModSecurity SecRule format."""
    lines = [f"# Rule: {rule.name}", f"# {rule.description}"]
    rule_num = int(hashlib.md5(rule.rule_id.encode(), usedforsecurity=False).hexdigest(), 16) % 900000 + 100000

    action_map = {
        RuleType.BLOCK: "deny,status:403",
        RuleType.LOG: "pass,log",
        RuleType.RATE_LIMIT: "pass,log,setenv:rate_limit=1",
        RuleType.ALLOW: "allow",
        RuleType.CHALLENGE: "deny,status:429",
    }
    action = action_map.get(rule.rule_type, "deny,status:403")

    for i, cond in enumerate(rule.conditions):
        modsec_var = _modsec_variable(cond.field)
        op = "rx" if cond.operator == "MATCHES" else "pm" if cond.operator == "IN" else "contains" if cond.operator == "CONTAINS" else "beginsWith" if cond.operator == "STARTS_WITH" else "rx"
        negate = "!" if cond.negate else ""
        sec_action = action if i == len(rule.conditions) - 1 else "chain"
        transform = f",t:{cond.transform.lower()}" if cond.transform else ""
        lines.append(
            f'SecRule {modsec_var} "{negate}@{op} {cond.value}" '
            f'"id:{rule_num + i},phase:2,{sec_action}{transform},'
            f'msg:\'{rule.name}\',tag:\'{rule.vuln_type.value}\'"'
        )
    return "\n".join(lines)


def _modsec_variable(field: str) -> str:
    mapping = {
        "QUERY_STRING": "QUERY_STRING",
        "URI": "REQUEST_URI",
        "BODY": "REQUEST_BODY",
        "METHOD": "REQUEST_METHOD",
        "IP": "REMOTE_ADDR",
    }
    if field.startswith("HEADER:"):
        hdr = field.split(":", 1)[1]
        return f"REQUEST_HEADERS:{hdr}"
    return mapping.get(field, "QUERY_STRING")


def _export_nginx(rule: WAFRule) -> str:
    """Serialize a WAFRule to NGINX location/if blocks."""
    lines = [f"# WAF Rule: {rule.name}", f"# Type: {rule.rule_type.value} | Vuln: {rule.vuln_type.value}"]
    if rule.endpoint:
        lines.append(f"location ~* {re.escape(rule.endpoint)} {{")
        indent = "    "
    else:
        lines.append("# Apply in relevant server/location block:")
        indent = ""

    for cond in rule.conditions:
        var = _nginx_variable(cond.field)
        negate = "!" if cond.negate else ""
        if cond.operator in ("MATCHES", "CONTAINS"):
            lines.append(f"{indent}if ({var} ~{negate}* \"{cond.value}\") {{")
        elif cond.operator == "STARTS_WITH":
            lines.append(f"{indent}if ({var} ~{negate}* \"^{re.escape(cond.value)}\") {{")
        else:
            lines.append(f"{indent}if ({var} ~{negate}* \"{re.escape(cond.value)}\") {{")
        if rule.rule_type == RuleType.BLOCK:
            lines.append(f"{indent}    return 403;")
        elif rule.rule_type == RuleType.RATE_LIMIT:
            lines.append(f"{indent}    return 429;")
        else:
            lines.append(f"{indent}    # log only")
        lines.append(f"{indent}}}")

    if rule.endpoint:
        lines.append("}")
    return "\n".join(lines)


def _nginx_variable(field: str) -> str:
    mapping = {
        "QUERY_STRING": "$query_string",
        "URI": "$request_uri",
        "BODY": "$request_body",
        "METHOD": "$request_method",
        "IP": "$remote_addr",
    }
    if field.startswith("HEADER:"):
        hdr = field.split(":", 1)[1].replace("-", "_").lower()
        return f"$http_{hdr}"
    return mapping.get(field, "$query_string")


def _export_apache(rule: WAFRule) -> str:
    """Serialize a WAFRule to Apache mod_security / mod_rewrite format."""
    lines = [f"# WAF Rule: {rule.name}", f"# Description: {rule.description}"]
    for cond in rule.conditions:
        var = _apache_variable(cond.field)
        lines.append("<IfModule mod_rewrite.c>")
        lines.append("  RewriteEngine On")
        if cond.operator in ("MATCHES", "CONTAINS"):
            flag = "NC" if not cond.negate else "NC"
            lines.append(f"  RewriteCond {var} {cond.value} [{flag}]")
        elif cond.operator == "STARTS_WITH":
            lines.append(f"  RewriteCond {var} ^{re.escape(cond.value)}")
        if rule.rule_type == RuleType.BLOCK:
            lines.append("  RewriteRule ^ - [F,L]")
        else:
            lines.append("  # Log condition matched — no block action")
        lines.append("</IfModule>")
    return "\n".join(lines)


def _apache_variable(field: str) -> str:
    mapping = {
        "QUERY_STRING": "%{QUERY_STRING}",
        "URI": "%{REQUEST_URI}",
        "BODY": "%{THE_REQUEST}",
        "METHOD": "%{REQUEST_METHOD}",
        "IP": "%{REMOTE_ADDR}",
    }
    if field.startswith("HEADER:"):
        hdr = field.split(":", 1)[1]
        return f"%{{HTTP:{hdr}}}"
    return mapping.get(field, "%{QUERY_STRING}")


def _export_owasp_crs(rule: WAFRule) -> Dict[str, Any]:
    """Export as OWASP CRS-compatible format."""
    return {
        "id": int(hashlib.md5(rule.rule_id.encode(), usedforsecurity=False).hexdigest(), 16) % 900000 + 900000,
        "phase": 2,
        "ver": "OWASP_CRS/4.0",
        "rev": str(rule.version),
        "maturity": 1,
        "accuracy": 8,
        "tag": ["language-multi", f"OWASP_{rule.owasp_category or 'A03'}", rule.vuln_type.value],
        "msg": rule.name,
        "logdata": rule.description,
        "severity": "CRITICAL" if rule.rule_type == RuleType.BLOCK else "WARNING",
        "conditions": [
            {
                "variable": _modsec_variable(c.field),
                "operator": c.operator,
                "value": c.value,
                "negate": c.negate,
            }
            for c in rule.conditions
        ],
    }


def _export_terraform(rule: WAFRule, provider: WAFProvider) -> str:
    """Export as Terraform HCL WAF resource block."""
    safe_name = re.sub(r"[^a-z0-9_]", "_", rule.name.lower())[:64]
    if provider == WAFProvider.AWS_WAF:
        aws_json = json.dumps(_export_aws_waf(rule), indent=2)
        return (
            f'resource "aws_wafv2_rule_group" "{safe_name}" {{\n'
            f'  name     = "{re.sub(r"[^A-Za-z0-9-]", "-", rule.name)[:128]}"\n'
            f'  scope    = "REGIONAL"\n'
            f'  capacity = 10\n\n'
            f'  # Generated rule body (JSON):\n'
            f'  # {aws_json.replace(chr(10), chr(10) + "  # ")}\n'
            f'}}\n'
        )
    elif provider == WAFProvider.CLOUDFLARE:
        cf = _export_cloudflare(rule)
        return (
            f'resource "cloudflare_ruleset" "{safe_name}" {{\n'
            f'  zone_id     = var.zone_id\n'
            f'  name        = "{rule.name[:64]}"\n'
            f'  description = "{rule.description[:128]}"\n'
            f'  kind        = "zone"\n'
            f'  phase       = "http_request_firewall_custom"\n\n'
            f'  rules {{\n'
            f'    action      = "{cf["action"]}"\n'
            f'    expression  = "{cf["expression"]}"\n'
            f'    description = "{rule.description[:128]}"\n'
            f'    enabled     = {str(cf["enabled"]).lower()}\n'
            f'  }}\n'
            f'}}\n'
        )
    else:
        return f"# Terraform export not yet supported for provider: {provider.value}\n"


# ---------------------------------------------------------------------------
# Regex-based rule tester
# ---------------------------------------------------------------------------

def _matches_condition(cond: WAFCondition, req: TestRequest) -> bool:
    """Check if a single condition matches a test request."""
    field_value = _extract_field(cond.field, req)
    val = cond.value

    if cond.transform == "URL_DECODE":
        from urllib.parse import unquote
        field_value = unquote(field_value)
    elif cond.transform == "LOWERCASE":
        field_value = field_value.lower()
    elif cond.transform == "HTML_DECODE":
        import html
        field_value = html.unescape(field_value)

    if cond.operator == "MATCHES":
        matched = bool(re.search(val, field_value))
    elif cond.operator == "CONTAINS":
        matched = val.lower() in field_value.lower()
    elif cond.operator == "STARTS_WITH":
        matched = field_value.startswith(val)
    elif cond.operator == "IN":
        matched = field_value.upper() in [v.strip().upper() for v in val.split(",")]
    elif cond.operator == "ABSENT":
        matched = not bool(field_value)
    elif cond.operator == "GT":
        try:
            matched = int(field_value) > int(val)
        except ValueError:
            matched = False
    elif cond.operator == "ANY":
        matched = True
    else:
        matched = field_value == val

    return (not matched) if cond.negate else matched


def _extract_field(field: str, req: TestRequest) -> str:
    mapping = {
        "QUERY_STRING": req.query_string,
        "URI": req.uri,
        "BODY": req.body,
        "METHOD": req.method,
        "IP": req.headers.get("X-Forwarded-For", ""),
    }
    if field.startswith("HEADER:"):
        hdr = field.split(":", 1)[1]
        return req.headers.get(hdr, req.headers.get(hdr.lower(), ""))
    if field.startswith("GEO:"):
        return req.headers.get("CF-IPCountry", req.headers.get("X-Country-Code", ""))
    return mapping.get(field, "")


def _rule_matches_request(rule: WAFRule, req: TestRequest) -> Tuple[bool, Optional[str]]:
    """Return (matched, which_condition_matched)."""
    for cond in rule.conditions:
        if not _matches_condition(cond, req):
            return False, None
    if rule.conditions:
        return True, f"{rule.conditions[0].field}:{rule.conditions[0].operator}"
    return False, None


# ---------------------------------------------------------------------------
# Core generator class
# ---------------------------------------------------------------------------

class WAFRuleGenerator:
    """Main WAF Rule Generator engine."""

    def __init__(self) -> None:
        self._rules: Dict[str, WAFRule] = {}
        self._rulesets: Dict[str, RuleSet] = {}
        self._lock = Lock()
        logger.info("WAFRuleGenerator initialized", template_count=len(_TEMPLATES))

    # ---- Template access ----

    def list_templates(self, vuln_type: Optional[VulnType] = None) -> List[RuleTemplate]:
        if vuln_type is not None:
            ids = _VULN_TO_TEMPLATES.get(vuln_type, [])
            return [_TEMPLATES[tid] for tid in ids if tid in _TEMPLATES]
        return list(_TEMPLATES.values())

    def get_template(self, template_id: str) -> Optional[RuleTemplate]:
        return _TEMPLATES.get(template_id)

    # ---- Generate from finding ----

    def generate_from_finding(self, finding: VulnFinding) -> List[WAFRule]:
        """Auto-generate block + log + rate-limit rules from a vulnerability finding."""
        rules: List[WAFRule] = []
        template_ids = _VULN_TO_TEMPLATES.get(finding.vuln_type, _VULN_TO_TEMPLATES[VulnType.GENERIC])

        for tid in template_ids:
            tmpl = _TEMPLATES.get(tid)
            if tmpl is None:
                continue
            rule = tmpl.instantiate(endpoint=finding.endpoint, parameter=finding.parameter)
            rule.cve_id = finding.cve_id
            rule.cwe_id = finding.cwe_id or rule.cwe_id
            rule.status = RuleStatus.DRAFT
            rules.append(rule)

        # Always add a logging rule if not already included
        has_log = any(r.rule_type == RuleType.LOG for r in rules)
        if not has_log:
            log_rule = WAFRule(
                name=f"Log: {finding.title}",
                description=f"Logging rule for finding: {finding.finding_id}",
                rule_type=RuleType.LOG,
                vuln_type=finding.vuln_type,
                conditions=[
                    WAFCondition(
                        field="URI",
                        operator="STARTS_WITH",
                        value=finding.endpoint or "/",
                    )
                ],
                endpoint=finding.endpoint,
                cve_id=finding.cve_id,
                tags=["auto-generated", "logging"],
            )
            rules.append(log_rule)

        # Always add a rate-limit rule
        has_rate = any(r.rule_type == RuleType.RATE_LIMIT for r in rules)
        if not has_rate and finding.endpoint:
            rate_rule = WAFRule(
                name=f"Rate Limit: {finding.endpoint}",
                description=f"Rate limit for vulnerable endpoint {finding.endpoint}",
                rule_type=RuleType.RATE_LIMIT,
                vuln_type=VulnType.RATE_ABUSE,
                conditions=[
                    WAFCondition(field="URI", operator="STARTS_WITH", value=finding.endpoint)
                ],
                endpoint=finding.endpoint,
                tags=["auto-generated", "rate-limit"],
            )
            rules.append(rate_rule)

        with self._lock:
            for r in rules:
                self._rules[r.rule_id] = r

        logger.info("Generated WAF rules from finding",
                    finding_id=finding.finding_id,
                    vuln_type=finding.vuln_type.value,
                    rule_count=len(rules))
        _emit_event("waf.rules_generated", {"finding_id": finding.finding_id, "vuln_type": finding.vuln_type.value, "rule_count": len(rules)})
        return rules

    # ---- Virtual patching ----

    def generate_virtual_patch(self, cve_id: str, endpoint: str, attack_vector: str, description: str) -> WAFRule:
        """Create a virtual patch WAF rule for a CVE that cannot be patched immediately."""
        # Choose conditions based on attack_vector content
        conditions: List[WAFCondition] = []
        if re.search(r"(?i)sql|inject", attack_vector):
            conditions.append(WAFCondition(
                field="QUERY_STRING",
                operator="MATCHES",
                value=r"(?i)(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|'[^']*'=[^']*')",
                transform="URL_DECODE",
            ))
        elif re.search(r"(?i)xss|script|html", attack_vector):
            conditions.append(WAFCondition(
                field="QUERY_STRING",
                operator="MATCHES",
                value=r"(?i)(<script|javascript:|on\w+=)",
                transform="HTML_DECODE",
            ))
        elif re.search(r"(?i)path|traversal|lfi", attack_vector):
            conditions.append(WAFCondition(
                field="URI",
                operator="MATCHES",
                value=r"\.\./|%2e%2e%2f",
                transform="URL_DECODE",
            ))
        else:
            # Generic block on the endpoint
            conditions.append(WAFCondition(
                field="URI",
                operator="STARTS_WITH",
                value=endpoint,
            ))

        rule = WAFRule(
            name=f"Virtual Patch: {cve_id}",
            description=f"Virtual patch for {cve_id}: {description}",
            rule_type=RuleType.BLOCK,
            vuln_type=VulnType.GENERIC,
            conditions=conditions,
            endpoint=endpoint,
            cve_id=cve_id,
            priority=1,  # highest priority
            tags=["virtual-patch", cve_id],
            status=RuleStatus.DRAFT,
        )

        with self._lock:
            self._rules[rule.rule_id] = rule

        logger.info("Generated virtual patch", cve_id=cve_id, rule_id=rule.rule_id)
        _emit_event("waf.virtual_patch_generated", {"cve_id": cve_id, "rule_id": rule.rule_id, "endpoint": endpoint})
        return rule

    # ---- Rule store CRUD ----

    def get_rule(self, rule_id: str) -> Optional[WAFRule]:
        return self._rules.get(rule_id)

    def list_rules(self, status: Optional[RuleStatus] = None, vuln_type: Optional[VulnType] = None) -> List[WAFRule]:
        with self._lock:
            rules = list(self._rules.values())
        if status:
            rules = [r for r in rules if r.status == status]
        if vuln_type:
            rules = [r for r in rules if r.vuln_type == vuln_type]
        return sorted(rules, key=lambda r: r.priority)

    def update_rule_status(self, rule_id: str, new_status: RuleStatus) -> Optional[WAFRule]:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                return None
            old_status = rule.status
            rule.history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": "status_change",
                "from": old_status.value,
                "to": new_status.value,
            })
            rule.status = new_status
            rule.updated_at = datetime.now(timezone.utc)
            rule.version += 1
        logger.info("Rule status updated", rule_id=rule_id, old=old_status.value, new=new_status.value)
        return rule

    def rollback_rule(self, rule_id: str) -> Optional[WAFRule]:
        """Roll back rule to previous status using history."""
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None or not rule.history:
                return None
            last = rule.history[-1]
            if last.get("event") == "status_change":
                prev_status = RuleStatus(last["from"])
                rule.history.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "rollback",
                    "from": rule.status.value,
                    "to": prev_status.value,
                })
                rule.status = prev_status
                rule.version += 1
                rule.updated_at = datetime.now(timezone.utc)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            existed = rule_id in self._rules
            self._rules.pop(rule_id, None)
        return existed

    # ---- Rule testing / simulation ----

    def test_rule(self, rule: WAFRule, test_requests: List[TestRequest]) -> List[TestResult]:
        """Simulate rule against a set of test requests; compute FP rate."""
        results: List[TestResult] = []
        for req in test_requests:
            t0 = time.perf_counter_ns()
            matched, which_cond = _rule_matches_request(rule, req)
            latency = (time.perf_counter_ns() - t0) // 1000

            expected_block = req.is_malicious
            correct = (matched == expected_block)
            results.append(TestResult(
                rule_id=rule.rule_id,
                request_uri=req.uri,
                matched=matched,
                expected_block=expected_block,
                correct=correct,
                match_condition=which_cond,
                latency_us=latency,
            ))

        # Compute FP rate and store in rule
        total = len(results)
        if total > 0:
            false_positives = sum(1 for r in results if r.matched and not r.expected_block)
            fp_rate = false_positives / total
            with self._lock:
                stored = self._rules.get(rule.rule_id)
                if stored:
                    stored.false_positive_rate = fp_rate
                    stored.test_results = [r.model_dump() if hasattr(r, "model_dump") else r.dict() for r in results]
        return results

    # ---- Export ----

    def export_rule(self, rule: WAFRule, provider: WAFProvider, fmt: ExportFormat = ExportFormat.PROVIDER_NATIVE) -> Any:
        """Export a single rule in provider-native, OWASP CRS, or Terraform format."""
        if fmt == ExportFormat.OWASP_CRS:
            return _export_owasp_crs(rule)
        if fmt == ExportFormat.TERRAFORM:
            return _export_terraform(rule, provider)
        # Provider-native
        if provider == WAFProvider.AWS_WAF:
            return _export_aws_waf(rule)
        elif provider == WAFProvider.CLOUDFLARE:
            return _export_cloudflare(rule)
        elif provider == WAFProvider.MODSECURITY:
            return _export_modsecurity(rule)
        elif provider == WAFProvider.NGINX:
            return _export_nginx(rule)
        elif provider == WAFProvider.APACHE:
            return _export_apache(rule)
        raise ValueError(f"Unsupported provider: {provider}")

    def export_ruleset(self, rules: List[WAFRule], provider: WAFProvider, fmt: ExportFormat = ExportFormat.PROVIDER_NATIVE) -> Any:
        """Export a list of rules as a complete ruleset."""
        if fmt == ExportFormat.PROVIDER_NATIVE and provider in (WAFProvider.AWS_WAF, WAFProvider.CLOUDFLARE):
            return [self.export_rule(r, provider, fmt) for r in rules]
        if fmt == ExportFormat.OWASP_CRS:
            return [_export_owasp_crs(r) for r in rules]
        if fmt == ExportFormat.TERRAFORM:
            return "\n\n".join(_export_terraform(r, provider) for r in rules)
        # Text-based formats (ModSecurity, NGINX, Apache)
        return "\n\n".join(self.export_rule(r, provider, fmt) for r in rules)  # type: ignore[arg-type]

    # ---- RuleSet management ----

    def create_ruleset(self, name: str, provider: WAFProvider, rules: List[WAFRule], description: str = "") -> RuleSet:
        rs = RuleSet(name=name, provider=provider, rules=rules, description=description)
        with self._lock:
            self._rulesets[rs.ruleset_id] = rs
        return rs

    def get_ruleset(self, ruleset_id: str) -> Optional[RuleSet]:
        return self._rulesets.get(ruleset_id)

    def list_rulesets(self) -> List[RuleSet]:
        return list(self._rulesets.values())


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_instance: Optional[WAFRuleGenerator] = None
_instance_lock = Lock()


def get_waf_generator() -> WAFRuleGenerator:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = WAFRuleGenerator()
    return _instance
