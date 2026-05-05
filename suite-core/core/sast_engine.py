"""ALdeci SAST Engine — Static Application Security Testing.

Real pattern-based code analysis with taint tracking, CWE mapping,
and multi-language support (Python, JavaScript, TypeScript, Java, Go,
Ruby, PHP, C, C++, Rust).

New in v2:
- TypeScript, C, C++, Rust language support
- Semgrep-format YAML rule parsing and execution
- Incremental scanning: file hash cache skips unchanged files
- Structured fix suggestions with CWE/OWASP references per finding
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import uuid

logger = logging.getLogger(__name__)
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
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

try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    RUBY = "ruby"
    PHP = "php"
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    CSHARP = "csharp"
    UNKNOWN = "unknown"


class SastSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SastFinding:
    rule_id: str
    title: str
    severity: SastSeverity
    cwe_id: str
    language: Language
    file_path: str
    line_number: int
    column: int = 0
    snippet: str = ""
    message: str = ""
    fix_suggestion: str = ""
    confidence: float = 0.9
    finding_id: str = field(default_factory=lambda: f"SAST-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "cwe_id": self.cwe_id,
            "language": self.language.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "snippet": self.snippet,
            "message": self.message,
            "fix_suggestion": self.fix_suggestion,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


# ── SAST Rules ─────────────────────────────────────────────────────
# Each rule: (rule_id, title, severity, cwe, pattern_regex, message, fix, languages)
SAST_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    (
        "SAST-001",
        "SQL Injection",
        "critical",
        "CWE-89",
        r"""(execute|cursor\.execute|query)\s*\(\s*[f"\']+.*\{.*\}""",
        "String interpolation in SQL query",
        "Use parameterized queries",
        ["python", "ruby"],
    ),
    (
        "SAST-002",
        "SQL Injection (concatenation)",
        "critical",
        "CWE-89",
        r"""(execute|query)\s*\(.*["\']\s*\+""",
        "String concatenation in SQL",
        "Use prepared statements",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-003",
        "XSS — Unescaped Output",
        "high",
        "CWE-79",
        r"""(innerHTML|outerHTML|document\.write|v-html)\s*[=(]""",
        "Direct DOM manipulation with user input",
        "Use textContent or sanitize",
        ["javascript"],
    ),
    (
        "SAST-004",
        "Command Injection",
        "critical",
        "CWE-78",
        r"""(os\.system|subprocess\.call|subprocess\.Popen|exec|child_process\.exec)\s*\(.*(\+|f["\']|\{|request|params)""",
        "OS command built from user input",
        "Use subprocess with list args, validate input",
        ["python", "javascript", "ruby"],
    ),
    (
        "SAST-005",
        "Path Traversal",
        "high",
        "CWE-22",
        r"""(open|readFile|read_file|send_file)\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "File path built from user input",
        "Validate and sanitize paths, use allowlists",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-006",
        "Hardcoded Secret",
        "high",
        "CWE-798",
        r"""(password|secret|api_key|apikey|token|private_key)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']""",
        "Hardcoded credential in source code",
        "Use environment variables or secret manager",
        ["python", "javascript", "java", "go", "ruby", "php"],
    ),
    (
        "SAST-007",
        "Insecure Deserialization",
        "critical",
        "CWE-502",
        r"""(pickle\.loads?|yaml\.load\s*\((?!.*Loader)|unserialize|eval\s*\(|JSON\.parse.*eval)""",
        "Unsafe deserialization of untrusted data",
        "Use safe loaders (yaml.safe_load), avoid pickle on untrusted data",
        ["python", "php", "javascript"],
    ),
    (
        "SAST-008",
        "Weak Cryptography",
        "medium",
        "CWE-327",
        r"""(md5|sha1|DES|RC4|ECB)\s*[\(.]""",
        "Use of weak cryptographic algorithm",
        "Use SHA-256+ or AES-GCM",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-009",
        "Missing CSRF Protection",
        "medium",
        "CWE-352",
        r"""@(app|router)\.(post|put|patch|delete)\s*\((?!.*csrf)""",
        "State-changing endpoint without CSRF token",
        "Add CSRF middleware or token validation",
        ["python"],
    ),
    (
        "SAST-010",
        "Open Redirect",
        "medium",
        "CWE-601",
        r"""redirect\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "Redirect URL from user input",
        "Validate redirect URL against allowlist",
        ["python", "javascript", "java", "ruby"],
    ),
    (
        "SAST-011",
        "SSRF",
        "high",
        "CWE-918",
        r"""(requests\.get|httpx\.|fetch|http\.get|urllib\.request)\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "HTTP request URL from user input",
        "Validate URLs against allowlist, block internal IPs",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-012",
        "XXE Injection",
        "high",
        "CWE-611",
        r"""(etree\.parse|XMLParser|xml\.sax|DocumentBuilder|SAXParser)\s*\((?!.*resolve_entities\s*=\s*False)""",
        "XML parser without entity resolution disabled",
        "Disable external entity processing",
        ["python", "java"],
    ),
    (
        "SAST-013",
        "Insecure Random",
        "medium",
        "CWE-330",
        r"""(random\.random|Math\.random|rand\(\))\s*""",
        "Non-cryptographic random for security context",
        "Use secrets module or crypto.randomBytes",
        ["python", "javascript", "ruby", "php"],
    ),
    (
        "SAST-014",
        "Logging Sensitive Data",
        "medium",
        "CWE-532",
        r"""(log(ger)?(\.\w+)?|console\.\w+|print)\s*\(.*\b(password|token|secret|credit_card|ssn)\b""",
        "Sensitive data in log output",
        "Mask or redact sensitive fields before logging",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-015",
        "Prototype Pollution",
        "high",
        "CWE-1321",
        r"""(Object\.assign|_\.merge|_\.extend|_\.defaultsDeep)\s*\(.*req\.(body|query|params)""",
        "Object merge with unsanitized user input",
        "Validate and sanitize input, use Map",
        ["javascript"],
    ),
    (
        "SAST-016",
        "LDAP Injection",
        "high",
        "CWE-90",
        r"""(ldap\.search|search_s)\s*\(.*(\+|f["\']|\{|request|params)""",
        "LDAP query built from user input",
        "Escape LDAP special characters",
        ["python", "java"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A01 — Broken Access Control (OWASP #1)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-017",
        "Missing Auth Decorator",
        "high",
        "CWE-862",
        r"""@(app|router)\.(get|post|put|delete|patch)\s*\([^)]*\)\s*\n\s*(async\s+)?def\s+\w+\([^)]*\)(?!.*Depends\()""",
        "Endpoint without authentication dependency",
        "Add Depends(verify_auth) or require_auth dependency",
        ["python"],
    ),
    (
        "SAST-018",
        "IDOR — Direct Object Reference",
        "high",
        "CWE-639",
        r"""(get|find|delete|update).*\(\s*(request\.(args|params|query)|req\.(params|query))\s*\.\s*(id|user_id|account_id|order_id)""",
        "Object accessed by user-supplied ID without ownership check",
        "Verify object ownership before access",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-019",
        "CORS Wildcard Origin",
        "medium",
        "CWE-942",
        r"""(allow_origins|Access-Control-Allow-Origin|cors)\s*[:=]\s*\[?\s*["\*"'\*']""",
        "CORS allows all origins",
        "Restrict to specific trusted domains",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-020",
        "Unrestricted File Upload",
        "high",
        "CWE-434",
        r"""(upload|file|multipart).*\.(save|write|copy).*(?!.*\.(allowed_ext|whitelist|mimetype))""",
        "File upload without extension/type validation",
        "Validate file extension, MIME type, and content",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-021",
        "JWT None Algorithm",
        "critical",
        "CWE-345",
        r"""(jwt\.decode|verify)\s*\(.*algorithms?\s*=\s*\[?["\']none["\']""",
        "JWT accepts 'none' algorithm — bypasses signature verification",
        "Enforce specific algorithms: algorithms=['HS256'] or ['RS256']",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-022",
        "Insecure Cookie — Missing Secure Flag",
        "medium",
        "CWE-614",
        r"""(set_cookie|cookie)\s*\((?!.*[Ss]ecure\s*=\s*True)(?!.*secure:\s*true)""",
        "Cookie set without Secure flag — transmitted over HTTP",
        "Set secure=True on session and auth cookies",
        ["python", "javascript"],
    ),
    (
        "SAST-023",
        "Insecure Cookie — Missing HttpOnly",
        "medium",
        "CWE-1004",
        r"""(set_cookie|cookie)\s*\((?!.*[Hh]ttp[Oo]nly\s*=\s*True)(?!.*httpOnly:\s*true)""",
        "Cookie accessible via JavaScript — XSS can steal it",
        "Set httponly=True on session and auth cookies",
        ["python", "javascript"],
    ),
    (
        "SAST-024",
        "Admin Route Without Auth",
        "critical",
        "CWE-306",
        r"""@(app|router)\.(get|post)\s*\(\s*["\'].*(admin|manage|config|internal)""",
        "Administrative endpoint may lack access control",
        "Require admin role verification on all admin routes",
        ["python", "javascript"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A02 — Cryptographic Failures (OWASP #2)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-025",
        "Weak RSA Key Size",
        "high",
        "CWE-326",
        r"""(rsa\.generate|generate_private_key|RSA\.generate)\s*\(.*\b(512|768|1024)\b""",
        "RSA key size below 2048 bits — cryptographically weak",
        "Use minimum 2048-bit RSA keys (4096 recommended)",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-026",
        "Hardcoded Cryptographic IV/Nonce",
        "high",
        "CWE-329",
        r"""(iv|nonce|IV|NONCE)\s*=\s*(b?["\'][^"\']{8,}["\']|bytes\()""",
        "Static initialization vector defeats encryption security",
        "Generate random IV/nonce per encryption operation",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-027",
        "ECB Mode Usage",
        "high",
        "CWE-327",
        r"""(ECB|MODE_ECB|AES\.ECB|Cipher\.ECB)""",
        "ECB mode preserves plaintext patterns — insecure for most data",
        "Use CBC, CTR, or GCM mode with random IV",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-028",
        "Disabled SSL/TLS Verification",
        "critical",
        "CWE-295",
        r"""(verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']0|InsecureRequestWarning|CERT_NONE|ssl\._create_unverified_context)""",
        "TLS certificate verification disabled — MitM possible",
        "Enable certificate verification; use trusted CA bundle",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-029",
        "Cleartext Password Storage",
        "critical",
        "CWE-256",
        r"""(password|passwd|pass_?word)\s*=\s*(request|req|params|form|body)\b""",
        "Password stored or compared in cleartext",
        "Hash passwords with bcrypt/argon2/scrypt before storage",
        ["python", "javascript", "java", "php", "ruby"],
    ),
    (
        "SAST-030",
        "Weak TLS Version",
        "high",
        "CWE-326",
        r"""(SSLv2|SSLv3|TLSv1[^.23]|PROTOCOL_TLS(?!v1_[23])|ssl\.PROTOCOL_SSLv)""",
        "TLS version below 1.2 is cryptographically weak",
        "Enforce TLS 1.2 or 1.3 minimum",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-031",
        "Hardcoded Encryption Key",
        "critical",
        "CWE-321",
        r"""(encrypt|cipher|aes|fernet|SECRET_KEY|ENCRYPTION_KEY)\s*[=(]\s*[b]?["\'][A-Za-z0-9+/=]{16,}["\']""",
        "Cryptographic key hardcoded in source code",
        "Load encryption keys from environment variables or key vault",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-032",
        "Static/Predictable Salt",
        "medium",
        "CWE-760",
        r"""salt\s*=\s*[b]?["\'][^"\']+["\']""",
        "Password salt is static — identical passwords produce identical hashes",
        "Generate unique random salt per password (bcrypt does this automatically)",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-033",
        "Plaintext Password Comparison",
        "critical",
        "CWE-261",
        r"""(password|passwd)\s*==\s*(request|req|params|user|data)\b""",
        "Password compared as plaintext — timing attack and storage risk",
        "Use hmac.compare_digest() or bcrypt.checkpw()",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-034",
        "Missing HSTS Header",
        "medium",
        "CWE-319",
        r"""(Strict-Transport-Security|HSTS)\s*[:=]\s*["\']\s*["\']\s*$""",
        "Empty or missing Strict-Transport-Security header",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
        ["python", "javascript"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A03 — Injection (OWASP #3) — Expanding beyond existing SQLi/XSS
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-035",
        "NoSQL Injection (MongoDB)",
        "critical",
        "CWE-943",
        r"""(find|findOne|aggregate|update|delete)\s*\(\s*\{.*(\$where|\$gt|\$ne|\$regex).*(\+|f["\']|\{|request|params|req\.)""",
        "MongoDB query operator built from user input",
        "Validate/sanitize input; avoid $where; use MongoDB driver parameterization",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-036",
        "Server-Side Template Injection (SSTI)",
        "critical",
        "CWE-1336",
        r"""(render_template_string|Template\(|Jinja2|Environment\(\)|from_string)\s*\(.*(\+|f["\']|\{|request|params)""",
        "Template rendered from user input — allows code execution",
        "Use static templates; never pass user input to template engine directly",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-037",
        "Expression Language Injection",
        "critical",
        "CWE-917",
        r"""(\$\{|#\{|@\{).*(\+|request|params|user_input)""",
        "Expression Language evaluated with user-controlled data",
        "Sanitize EL input; avoid dynamic EL expression evaluation",
        ["java"],
    ),
    (
        "SAST-038",
        "HTTP Header Injection",
        "high",
        "CWE-113",
        r"""(set_header|add_header|setHeader|response\.headers)\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "HTTP header value built from user input — CRLF injection possible",
        "Validate and encode header values; reject newlines",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-039",
        "CRLF Injection",
        "high",
        "CWE-93",
        r"""(redirect|Location|Set-Cookie)\s*[:=].*(\+|f["\']|\{|request|params).*(?!.*replace.*\\r|\\n)""",
        "Response header built with user input — CRLF injection risk",
        "Strip \\r\\n from all header values",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-040",
        "XPath Injection",
        "high",
        "CWE-643",
        r"""(xpath|evaluate|selectNodes|XPathExpression)\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "XPath query built from user input",
        "Use parameterized XPath queries or XPathVariableResolver",
        ["python", "java"],
    ),
    (
        "SAST-041",
        "ReDoS — Regular Expression Denial of Service",
        "medium",
        "CWE-1333",
        r"""re\.(compile|search|match|findall)\s*\(["\'].*(\.\*\+|\.\+\*|\(.+\)\+\+|\(.+\)\*\+)""",
        "Regex with catastrophic backtracking potential",
        "Use atomic groups, possessive quantifiers, or re2/regex module",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-042",
        "Format String Vulnerability",
        "high",
        "CWE-134",
        r"""(\.format\s*\(|%\s*\().*(\+|request|params|user|input|req\.)""",
        "Format string with user-controlled input",
        "Use parameterized formatting; validate format specifiers",
        ["python", "java"],
    ),
    (
        "SAST-043",
        "Shell Injection via Backticks",
        "critical",
        "CWE-78",
        r"""`.*(\$\{|\$\(|request|params|user_input)""",
        "Shell command with user input in backtick execution",
        "Use subprocess with list arguments; escape shell metacharacters",
        ["ruby", "php", "javascript"],
    ),
    (
        "SAST-044",
        "DOM-based XSS via Location",
        "high",
        "CWE-79",
        r"""(document\.location|window\.location|location\.(hash|search|href)).*innerHTML""",
        "DOM property from URL used in innerHTML — DOM XSS",
        "Use textContent; sanitize via DOMPurify",
        ["javascript"],
    ),
    (
        "SAST-045",
        "React dangerouslySetInnerHTML",
        "high",
        "CWE-79",
        r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{.*__html""",
        "React dangerouslySetInnerHTML — XSS if data is user-controlled",
        "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML",
        ["javascript"],
    ),
    (
        "SAST-046",
        "SQL Injection via ORM Raw Query",
        "critical",
        "CWE-89",
        r"""(\.raw|rawQuery|execute_sql|\.text|RawSQL|raw_sql|\.extra)\s*\(.*(\+|f["\']|\{|request|params|%s)""",
        "ORM raw query method with user input",
        "Use ORM parameterized queries; avoid raw SQL",
        ["python", "javascript", "java", "ruby"],
    ),
    (
        "SAST-047",
        "GraphQL Injection",
        "high",
        "CWE-89",
        r"""(graphql|gql)\s*\(.*(\+|f["\']|\{|request|params|req\.)""",
        "GraphQL query built from user input",
        "Use GraphQL variables for parameterization",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-048",
        "Email Header Injection",
        "medium",
        "CWE-93",
        r"""(sendmail|send_mail|MIMEText|smtplib)\s*\(.*(\+|f["\']|\{|request|params)""",
        "Email header or body built from user input",
        "Validate email addresses; strip newlines from headers",
        ["python", "php"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A04 — Insecure Design (OWASP #4)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-049",
        "Missing Input Length Validation",
        "medium",
        "CWE-20",
        r"""(request|req)\.(body|data|json|form|args)\s*\[?["\']?\w+["\']?\]?\s*(?!.*len|.*max_length|.*[:]\d)""",
        "User input consumed without length/size validation",
        "Validate input length with Pydantic max_length or manual checks",
        ["python", "javascript"],
    ),
    (
        "SAST-050",
        "Race Condition — TOCTOU",
        "medium",
        "CWE-367",
        r"""(os\.path\.exists|os\.access|Path\(.*\)\.exists)\s*\(.*\)[\s\S]{0,50}(open|write|unlink|remove)\s*\(""",
        "Time-of-check-time-of-use race condition in file operations",
        "Use atomic file operations or file locking",
        ["python", "java", "go"],
    ),
    (
        "SAST-051",
        "Unbounded Resource Allocation",
        "medium",
        "CWE-770",
        r"""(while\s+True|for\s+\w+\s+in\s+range\s*\(.*request|\.read\(\)(?!.*limit|.*max))""",
        "Resource allocation without bounds — DoS risk",
        "Set maximum limits on loops, reads, and allocations",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-052",
        "Unsafe Type Casting",
        "medium",
        "CWE-704",
        r"""(int|float|Integer\.parseInt|Number)\s*\(\s*(request|req|params|user_input)""",
        "Type conversion of user input without error handling",
        "Wrap type conversions in try/except and validate ranges",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-053",
        "Missing Rate Limiting",
        "medium",
        "CWE-770",
        r"""@(app|router)\.(post|put)\s*\(\s*["\'].*(login|auth|password|register|signup|token)""",
        "Authentication endpoint without rate limiting",
        "Add rate limiting middleware (e.g., slowapi, express-rate-limit)",
        ["python", "javascript"],
    ),
    (
        "SAST-054",
        "Integer Overflow Potential",
        "low",
        "CWE-190",
        r"""(int|long|Integer)\s*\(.*\*.*\*""",
        "Multiplication chain may cause integer overflow",
        "Validate arithmetic bounds; use big integer libraries for large values",
        ["python", "java", "go"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A05 — Security Misconfiguration (OWASP #5)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-055",
        "Debug Mode Enabled",
        "high",
        "CWE-489",
        r"""(DEBUG\s*=\s*True|app\.debug\s*=\s*True|debug:\s*true|FLASK_DEBUG\s*=\s*1)""",
        "Debug mode enabled — exposes stack traces and internals",
        "Disable debug mode in production; use environment variable toggle",
        ["python", "javascript"],
    ),
    (
        "SAST-056",
        "Default Credentials",
        "critical",
        "CWE-798",
        r"""(admin|root|default|test)["\']\s*,\s*["\'](admin|root|password|123456|default|test)["\']""",
        "Default or test credentials in code",
        "Remove default credentials; use environment-based secrets",
        ["python", "javascript", "java", "php", "ruby", "go"],
    ),
    (
        "SAST-057",
        "Verbose Error Exposure",
        "medium",
        "CWE-209",
        r"""(traceback\.format_exc|traceback\.print_exc|\.stack|console\.error\(err|str\(e\)).*return""",
        "Exception details returned to client — information disclosure",
        "Log errors server-side; return generic error messages to clients",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-058",
        "Exposed Stack Trace in Response",
        "medium",
        "CWE-209",
        r"""(JSONResponse|Response|jsonify|res\.json)\s*\(.*(traceback|\.stack|\bexception\b|str\((e|exc|err)\))""",
        "Stack trace included in HTTP response",
        "Return error codes/messages; never expose stack traces in production",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-059",
        "Binding to All Interfaces",
        "medium",
        "CWE-668",
        r"""(host\s*=\s*["\']0\.0\.0\.0|bind\s*=\s*["\']0\.0\.0\.0|listen\s*\(\s*0\.0\.0\.0)""",
        "Server binds to all network interfaces — accessible externally",
        "Bind to 127.0.0.1 in development; use reverse proxy in production",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-060",
        "Missing Content-Security-Policy",
        "medium",
        "CWE-693",
        r"""(Content-Security-Policy|CSP)\s*[:=]\s*["\'].*unsafe-inline.*unsafe-eval""",
        "CSP allows unsafe-inline and unsafe-eval — defeats XSS protection",
        "Remove unsafe-inline/unsafe-eval; use nonce-based CSP",
        ["python", "javascript"],
    ),
    (
        "SAST-061",
        "Secret in URL/Query String",
        "high",
        "CWE-598",
        r"""(token|api_key|password|secret|auth)\s*=.*(&|\?|params\[|query\[|url\.)""",
        "Sensitive data passed in URL query string — logged by proxies/servers",
        "Send secrets in headers (Authorization) or request body",
        ["python", "javascript", "java", "php", "go"],
    ),
    (
        "SAST-062",
        "Missing X-Frame-Options",
        "medium",
        "CWE-1021",
        r"""(X-Frame-Options|frame-ancestors)\s*[:=]\s*["\'].*ALLOW""",
        "Permissive framing policy — clickjacking risk",
        "Set X-Frame-Options: DENY or SAMEORIGIN",
        ["python", "javascript"],
    ),
    (
        "SAST-063",
        "Exposed Metrics/Health Without Auth",
        "low",
        "CWE-200",
        r"""@(app|router)\.(get)\s*\(\s*["\']\s*/(metrics|health|status|debug|info|env)""",
        "Internal endpoint potentially exposed without authentication",
        "Add authentication to internal endpoints or restrict to internal network",
        ["python", "javascript"],
    ),
    (
        "SAST-064",
        "GraphQL Introspection Enabled",
        "medium",
        "CWE-200",
        r"""(introspection\s*[:=]\s*True|introspection:\s*true|__schema\s*\{)""",
        "GraphQL introspection enabled — exposes full API schema",
        "Disable introspection in production",
        ["python", "javascript", "java"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A06 — Vulnerable and Outdated Components (OWASP #6)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-065",
        "Unsafe yaml.load Without Loader",
        "critical",
        "CWE-502",
        r"""yaml\.load\s*\((?!.*Loader\s*=)""",
        "yaml.load without Loader param — arbitrary code execution",
        "Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)",
        ["python"],
    ),
    (
        "SAST-066",
        "Deprecated API Usage — urllib",
        "low",
        "CWE-477",
        r"""(urllib2|urlopen\s*\(|urllib\.urlopen|httplib\.HTTP[^S])""",
        "Deprecated HTTP library — may lack security features",
        "Use requests or httpx with TLS verification",
        ["python"],
    ),
    (
        "SAST-067",
        "Subprocess with shell=True",
        "high",
        "CWE-78",
        r"""subprocess\.(call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True""",
        "Subprocess with shell=True — command injection if input unsanitized",
        "Use subprocess with list arguments and shell=False",
        ["python"],
    ),
    (
        "SAST-068",
        "Using exec/compile with External Input",
        "critical",
        "CWE-95",
        r"""(?<!re\.)(exec|compile|execfile)\s*\(.*(\+|f["\']|\{|request|params|input\(|\.read)""",
        "Dynamic code execution with potentially untrusted input",
        "Avoid exec(); use safe alternatives (ast.literal_eval, json.loads)",
        ["python"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A07 — Identification and Authentication Failures (OWASP #7)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-069",
        "Weak Password Policy",
        "medium",
        "CWE-521",
        r"""(min.?length|password.?len|minlength)\s*[=<:]\s*[0-7][^0-9]""",
        "Password minimum length below 8 characters",
        "Enforce minimum 12-character passwords per NIST 800-63B",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-070",
        "Password Hash with MD5/SHA1",
        "critical",
        "CWE-916",
        r"""(md5|sha1)\s*\(.*password""",
        "Password hashed with weak algorithm — easily crackable",
        "Use bcrypt, argon2, or scrypt for password hashing",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-071",
        "Session Fixation",
        "high",
        "CWE-384",
        r"""(session|SESSION)\s*\[.*\]\s*=.*request""",
        "Session ID set from request — session fixation possible",
        "Regenerate session ID after authentication",
        ["python", "php", "java"],
    ),
    (
        "SAST-072",
        "Credential in URL",
        "high",
        "CWE-522",
        r"""(https?://)\w+:\w+@""",
        "Credentials embedded in URL — visible in logs, history, referer",
        "Use authentication headers or environment-based credentials",
        ["python", "javascript", "java", "go", "ruby", "php"],
    ),
    (
        "SAST-073",
        "Basic Auth Without TLS",
        "high",
        "CWE-319",
        r"""(http://.*@|Authorization.*Basic.*http://|http://.*Authorization.*Basic|basic_auth.*http://|http://.*basic_auth)""",
        "Basic authentication over unencrypted HTTP",
        "Use HTTPS for all authenticated endpoints",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-074",
        "Missing Brute-Force Protection",
        "medium",
        "CWE-307",
        r"""def\s+(login|authenticate|sign_in)\s*\((?!.*rate_limit|.*throttle|.*lockout)""",
        "Login function without brute-force protection",
        "Implement account lockout or exponential backoff",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-075",
        "Token Without Expiration",
        "medium",
        "CWE-613",
        r"""(jwt\.encode|create_token|sign)\s*\((?!.*exp|.*expires|.*ttl|.*lifetime)""",
        "Token created without expiration — indefinitely valid",
        "Set token expiration (exp claim for JWT)",
        ["python", "javascript"],
    ),
    (
        "SAST-076",
        "Hardcoded JWT Secret",
        "critical",
        "CWE-321",
        r"""(jwt|JWT).*(secret|key|SECRET|KEY)\s*=\s*["\'][A-Za-z0-9]{8,}["\']""",
        "JWT signing secret hardcoded — token forgery possible",
        "Load JWT secrets from environment variables or key vault",
        ["python", "javascript", "java"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A08 — Software and Data Integrity Failures (OWASP #8)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-077",
        "Unsafe eval() in Python",
        "critical",
        "CWE-95",
        r"""\beval\s*\((?!.*literal_eval)""",
        "eval() executes arbitrary Python code — code injection risk",
        "Use ast.literal_eval() for safe evaluation of literals",
        ["python"],
    ),
    (
        "SAST-078",
        "Dynamic Code Import",
        "high",
        "CWE-502",
        r"""(__import__|importlib\.import_module)\s*\(.*(\+|f["\']|\{|request|params|input)""",
        "Dynamic module loading with user-controlled name",
        "Use explicit imports; validate module names against allowlist",
        ["python"],
    ),
    (
        "SAST-079",
        "Insecure Tempfile",
        "medium",
        "CWE-377",
        r"""(tempfile\.mktemp|tmpnam|tempnam|os\.tmpnam)\s*\(""",
        "Insecure temporary file creation — race condition",
        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
        ["python"],
    ),
    (
        "SAST-080",
        "Mass Assignment",
        "high",
        "CWE-915",
        r"""(\*\*request\.(json|data|body|form)|\.update\s*\(\s*request\.(json|data|body))""",
        "Mass assignment — all user input fields applied to model",
        "Explicitly whitelist allowed fields",
        ["python", "javascript", "ruby"],
    ),
    (
        "SAST-081",
        "Pickle Load from Network/File",
        "critical",
        "CWE-502",
        r"""pickle\.(load|loads)\s*\((?!.*trusted)""",
        "Pickle deserialization — arbitrary code execution on untrusted data",
        "Use JSON or protobuf; if pickle required, sign data and verify before loading",
        ["python"],
    ),
    (
        "SAST-082",
        "XML External Entity via lxml",
        "high",
        "CWE-611",
        r"""(lxml\.etree\.parse|lxml\.etree\.fromstring)\s*\((?!.*resolve_entities\s*=\s*False)""",
        "lxml XML parsing with external entities enabled by default",
        "Set resolve_entities=False and no_network=True",
        ["python"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A09 — Security Logging and Monitoring Failures (OWASP #9)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-083",
        "Bare Except — Swallowed Exceptions",
        "medium",
        "CWE-754",
        r"""except\s*:\s*$""",
        "Bare except clause — catches all exceptions including SystemExit",
        "Catch specific exceptions (except ValueError, except OSError)",
        ["python"],
    ),
    (
        "SAST-084",
        "Silenced Exception — Pass in Except",
        "low",
        "CWE-390",
        r"""except.*:\s*\n\s*pass\s*$""",
        "Exception caught and silenced — errors become invisible",
        "Log exceptions before continuing; raise or handle properly",
        ["python"],
    ),
    (
        "SAST-085",
        "Log Forging/Injection",
        "medium",
        "CWE-117",
        r"""(log|logger)\.(info|debug|warning|error)\s*\(.*(\+|f["\']|\{).*request""",
        "User input directly in log message — log injection/forging",
        "Sanitize user input before logging; use structured logging",
        ["python", "javascript", "java"],
    ),
    (
        "SAST-086",
        "Excessive Data Exposure in API Response",
        "medium",
        "CWE-200",
        r"""(?:return\b|jsonify\s*\(|JSONResponse\s*\(|json\.dumps\s*\()[^\n]*(?:\.__dict__|\.to_dict\(\))""",
        "Full object serialized to response — may include sensitive fields",
        "Use explicit response schemas; exclude sensitive fields",
        ["python", "javascript"],
    ),
    (
        "SAST-087",
        "Missing Error Handling in IO",
        "low",
        "CWE-755",
        r"""(open|connect|socket|requests\.get)\s*\([^)]+\)\s*(?!\s*#)(?!.*try|.*except|.*catch|.*finally)""",
        "IO operation without error handling — may crash on failure",
        "Wrap IO operations in try/except blocks",
        ["python"],
    ),
    (
        "SAST-088",
        "PII in Log Output",
        "high",
        "CWE-532",
        r"""(log(ger)?(\.\w+)?|print|console\.\w+)\s*\(.*\b(email|phone|ssn|social_security|credit_card|card_number|birth_?date)\b""",
        "Personally Identifiable Information in log output",
        "Mask PII fields before logging; use structured logging with redaction",
        ["python", "javascript", "java", "go"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # A10 — Server-Side Request Forgery (OWASP #10) — Expanding SSRF
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-089",
        "SSRF — Cloud Metadata Access",
        "critical",
        "CWE-918",
        r"""(169\.254\.169\.254|metadata\.google|metadata\.azure|100\.100\.100\.200)""",
        "Cloud metadata endpoint accessed — SSRF to steal credentials",
        "Block cloud metadata IPs in egress firewall; validate request URLs",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-090",
        "SSRF — Internal IP Access",
        "high",
        "CWE-918",
        r"""(127\.0\.0\.1|localhost|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+).*(\+|f["\']|\{|request|params)""",
        "Internal IP address in dynamic URL — SSRF to internal services",
        "Validate URLs against blocklist; use allow-only external domains",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-091",
        "SSRF — URL Scheme Bypass",
        "high",
        "CWE-918",
        r"""(file://|gopher://|dict://|ftp://|ldap://|tftp://)""",
        "Non-HTTP URL scheme — may bypass SSRF protections",
        "Allow only https:// and http:// schemes; block file/gopher/dict",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-092",
        "DNS Rebinding Pattern",
        "medium",
        "CWE-350",
        r"""(urlopen|requests\.(get|post)|httpx\.(get|post)|fetch)\s*\(.*resolve.*0""",
        "URL resolution may be vulnerable to DNS rebinding",
        "Pin DNS resolution; verify resolved IP against blocklist before connecting",
        ["python", "javascript", "java", "go"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # Language-Specific Rules
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-093",
        "PHP Include Injection",
        "critical",
        "CWE-98",
        r"""(include|require|include_once|require_once)\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)""",
        "PHP file inclusion from user input — remote code execution",
        "Use allowlist of includable files; never include user-supplied paths",
        ["php"],
    ),
    (
        "SAST-094",
        "PHP Type Juggling",
        "medium",
        "CWE-697",
        r"""==\s*["\']\s*["\']|==\s*0\b|==\s*NULL|strcmp\s*\(""",
        "Loose comparison (==) — type juggling bypass possible",
        "Use strict comparison (===) in PHP",
        ["php"],
    ),
    (
        "SAST-095",
        "Java Spring — Unvalidated Controller Input",
        "high",
        "CWE-20",
        r"""@(GetMapping|PostMapping|RequestMapping)\s*\(.*\)\s*\n.*public\s+\w+\s+\w+\s*\((?!.*@Valid|.*@Validated)""",
        "Spring controller method without input validation annotations",
        "Add @Valid annotation to request body parameters",
        ["java"],
    ),
    (
        "SAST-096",
        "Java Null Pointer Risk",
        "low",
        "CWE-476",
        r"""(\w+)\.(\w+)\s*\((?!.*if\s*\(\s*\1\s*!=\s*null|.*Optional|.*Objects\.requireNonNull)""",
        "Method call on potentially null object",
        "Add null checks or use Optional",
        ["java"],
    ),
    (
        "SAST-097",
        "Go — Error Not Checked",
        "medium",
        "CWE-252",
        r"""(\w+)\s*,\s*_\s*:?=|_\s*=.*\.(Read|Write|Close|Open|Dial|Query)""",
        "Error return value discarded — may miss critical failures",
        "Always check error return values: if err != nil",
        ["go"],
    ),
    (
        "SAST-098",
        "Ruby Mass Assignment",
        "high",
        "CWE-915",
        r"""(params\.permit!|\.attributes\s*=\s*params|\.update_attributes?\s*\(params)""",
        "Ruby mass assignment — all params applied to model",
        "Use strong params: params.require(:model).permit(:field1, :field2)",
        ["ruby"],
    ),
    (
        "SAST-099",
        "JS postMessage Without Origin Check",
        "high",
        "CWE-346",
        r"""(addEventListener|onmessage)\s*\(\s*["\']message["\'].*(?!.*origin\s*[!=]==)""",
        "postMessage handler without origin verification — message injection",
        "Verify event.origin against expected domain before processing",
        ["javascript"],
    ),
    (
        "SAST-100",
        "Python Pickle from Network",
        "critical",
        "CWE-502",
        r"""pickle\.(loads?)\s*\(.*\.(recv|read|content|text|data)\b""",
        "Pickle deserialization of network data — arbitrary code execution",
        "Use JSON/protobuf for network serialization; never pickle untrusted data",
        ["python"],
    ),
    # ══════════════════════════════════════════════════════════════════
    # Cross-Cutting Security Rules (101–110)
    # ══════════════════════════════════════════════════════════════════
    (
        "SAST-101",
        "Timing Attack in String Comparison",
        "medium",
        "CWE-208",
        r"""(==\s*|!=\s*)(token|api_key|secret|password|signature|hmac|hash)\b""",
        "Non-constant-time comparison of security token — timing side-channel",
        "Use hmac.compare_digest() or crypto.timingSafeEqual()",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-102",
        "IP Spoofing via X-Forwarded-For",
        "medium",
        "CWE-290",
        r"""(X-Forwarded-For|X-Real-IP|request\.remote_addr|req\.ip).*trust""",
        "Client IP from spoofable header used for access control",
        "Validate X-Forwarded-For chain; use trusted proxy configuration",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-103",
        "Insufficient Token Entropy",
        "high",
        "CWE-330",
        r"""(token|session_id|nonce|csrf)\s*=\s*(str\(uuid|random\.\w+|Math\.random|time\.\w+|str\(int)""",
        "Security token generated with insufficient entropy",
        "Use secrets.token_urlsafe(32) or crypto.randomBytes(32)",
        ["python", "javascript"],
    ),
    (
        "SAST-104",
        "File Permission — World-Readable",
        "medium",
        "CWE-732",
        r"""(chmod|os\.chmod)\s*\(.*0?o?7[0-7][4567]""",
        "File permissions too permissive — world-readable",
        "Set restrictive permissions: 0o600 for secrets, 0o644 for public files",
        ["python", "ruby"],
    ),
    (
        "SAST-105",
        "Docker — Running as Root",
        "medium",
        "CWE-250",
        r"""(USER\s+root|--privileged|privileged:\s*true|securityContext.*privileged)""",
        "Container running as root — privilege escalation risk",
        "Run as non-root user: USER 1000:1000",
        ["python", "javascript", "java", "go"],
    ),
    (
        "SAST-106",
        "Unsafe JSON.parse",
        "medium",
        "CWE-502",
        r"""JSON\.parse\s*\(.*(\+|request|req\.|params|body|query)(?!.*try|.*catch)""",
        "JSON.parse on user input without error handling",
        "Wrap JSON.parse in try/catch; validate schema before use",
        ["javascript"],
    ),
    (
        "SAST-107",
        "SQL LIKE Injection",
        "medium",
        "CWE-89",
        r"""LIKE\s*["\']%.*(\+|f["\']|\{|request|params)""",
        "SQL LIKE pattern from user input — wildcard injection",
        "Escape % and _ characters in user-supplied LIKE patterns",
        ["python", "javascript", "java", "php"],
    ),
    (
        "SAST-108",
        "Hardcoded AWS Credentials",
        "critical",
        "CWE-798",
        r"""(AKIA[0-9A-Z]{16}|aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\'])""",
        "AWS access key or secret key hardcoded in source",
        "Use IAM roles, environment variables, or AWS Secrets Manager",
        ["python", "javascript", "java", "go", "ruby", "php"],
    ),
    (
        "SAST-109",
        "Private Key in Source Code",
        "critical",
        "CWE-321",
        r"""-----BEGIN\s*(RSA\s*)?PRIVATE KEY-----""",
        "Private key embedded in source code",
        "Store private keys in secure vault; load from environment or file at runtime",
        ["python", "javascript", "java", "go", "ruby", "php"],
    ),
    (
        "SAST-110",
        "Unvalidated Redirect Target",
        "high",
        "CWE-601",
        r"""(redirect|sendRedirect|header\s*\(\s*["\']Location|res\.redirect)\s*\(?\s*(\$|request|req\.|params)""",
        "Redirect URL entirely from user input — open redirect",
        "Validate redirect URL against allowlist of internal paths",
        ["python", "javascript", "java", "php"],
    ),
]


# ── OWASP Category Mapping ─────────────────────────────────────────
OWASP_CATEGORIES: Dict[str, List[str]] = {
    "A01:BrokenAccessControl": [
        "SAST-005", "SAST-009", "SAST-010", "SAST-017", "SAST-018",
        "SAST-019", "SAST-020", "SAST-021", "SAST-022", "SAST-023",
        "SAST-024", "SAST-104", "SAST-110",
    ],
    "A02:CryptographicFailures": [
        "SAST-008", "SAST-025", "SAST-026", "SAST-027", "SAST-028",
        "SAST-029", "SAST-030", "SAST-031", "SAST-032", "SAST-033",
        "SAST-034", "SAST-101",
    ],
    "A03:Injection": [
        "SAST-001", "SAST-002", "SAST-003", "SAST-004", "SAST-012",
        "SAST-015", "SAST-016", "SAST-035", "SAST-036", "SAST-037",
        "SAST-038", "SAST-039", "SAST-040", "SAST-041", "SAST-042",
        "SAST-043", "SAST-044", "SAST-045", "SAST-046", "SAST-047",
        "SAST-048", "SAST-093", "SAST-094", "SAST-095", "SAST-098",
        "SAST-099", "SAST-107",
    ],
    "A04:InsecureDesign": [
        "SAST-049", "SAST-050", "SAST-051", "SAST-052", "SAST-053",
        "SAST-054",
    ],
    "A05:SecurityMisconfiguration": [
        "SAST-055", "SAST-056", "SAST-057", "SAST-058", "SAST-059",
        "SAST-060", "SAST-061", "SAST-062", "SAST-063", "SAST-064",
        "SAST-105",
    ],
    "A06:VulnerableComponents": [
        "SAST-065", "SAST-066", "SAST-067", "SAST-068",
    ],
    "A07:AuthenticationFailures": [
        "SAST-006", "SAST-013", "SAST-069", "SAST-070", "SAST-071",
        "SAST-072", "SAST-073", "SAST-074", "SAST-075", "SAST-076",
        "SAST-103", "SAST-108", "SAST-109",
    ],
    "A08:IntegrityFailures": [
        "SAST-007", "SAST-077", "SAST-078", "SAST-079", "SAST-080",
        "SAST-081", "SAST-082", "SAST-100", "SAST-106",
    ],
    "A09:LoggingFailures": [
        "SAST-014", "SAST-083", "SAST-084", "SAST-085", "SAST-086",
        "SAST-087", "SAST-088", "SAST-096", "SAST-097",
    ],
    "A10:SSRF": [
        "SAST-011", "SAST-089", "SAST-090", "SAST-091", "SAST-092",
        "SAST-102",
    ],
}


# ── Taint Sources / Sinks ──────────────────────────────────────────
TAINT_SOURCES = {
    "python": [
        r"request\.(args|form|json|data|values|files|cookies|headers)",
        r"input\(",
        r"sys\.argv",
        r"os\.environ",
        r"FastAPI.*Path|Query|Body|Header|Cookie",
        r"websocket\.receive",
    ],
    "javascript": [
        r"req\.(body|query|params|headers|cookies)",
        r"process\.argv",
        r"window\.location",
        r"document\.(cookie|URL|referrer|location)",
        r"event\.data",
        r"localStorage|sessionStorage",
    ],
    "java": [
        r"request\.getParameter",
        r"request\.getHeader",
        r"request\.getCookies",
        r"Scanner\.next",
        r"@RequestParam|@PathVariable|@RequestBody",
    ],
    "go": [
        r"r\.FormValue",
        r"r\.URL\.Query",
        r"os\.Args",
        r"r\.Header\.Get",
        r"r\.Body",
    ],
    "php": [
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES|SESSION)",
        r"file_get_contents\s*\(\s*[\"']php://input",
    ],
    "ruby": [
        r"params\[",
        r"request\.(body|env|headers)",
    ],
    "typescript": [
        r"req\.(body|query|params|headers|cookies)",
        r"process\.env\b",
        r"localStorage\b|sessionStorage\b",
        r"window\.location\.(search|hash|href)\b",
    ],
    "c": [
        r"\bgets\s*\(|\bfgets\s*\(|\bscanf\s*\(|\bfscanf\s*\(",
        r"\bgetenv\s*\(",
        r"\bargv\b",
    ],
    "cpp": [
        r"std::cin\b|\bgetline\s*\(|\bfgets\s*\(",
        r"\bgetenv\s*\(",
        r"\bargv\b",
    ],
    "rust": [
        r"std::env::args\(\)|std::env::var\(",
        r"stdin\(\)\.lock\(\)|read_to_string\b",
        r"fs::read_to_string\b|File::open\b",
    ],
}

TAINT_SINKS = {
    "sql": [r"execute\(", r"query\(", r"cursor\.", r"db\.run", r"\.raw\(", r"text\("],
    "command": [r"os\.system", r"subprocess\.", r"exec\(", r"child_process", r"shell_exec", r"system\("],
    "file": [r"open\(", r"readFile", r"writeFile", r"send_file", r"include\(", r"require\("],
    "network": [r"requests\.", r"httpx\.", r"fetch\(", r"http\.get", r"urlopen", r"urllib"],
    "ldap": [r"ldap\.search", r"search_s\("],
    "xpath": [r"xpath\(", r"evaluate\(", r"selectNodes"],
    "template": [r"render_template_string", r"Template\(", r"from_string\("],
    "deserialization": [r"pickle\.load", r"yaml\.load", r"unserialize\(", r"JSON\.parse"],
}


EXT_TO_LANG = {
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".java": Language.JAVA,
    ".go": Language.GO,
    ".rb": Language.RUBY,
    ".php": Language.PHP,
    ".php3": Language.PHP,
    ".php4": Language.PHP,
    ".php5": Language.PHP,
    ".c": Language.C,
    ".h": Language.C,
    ".cc": Language.CPP,
    ".cpp": Language.CPP,
    ".cxx": Language.CPP,
    ".hpp": Language.CPP,
    ".rs": Language.RUST,
    ".cs": Language.CSHARP,
}

# ── Extra rules for TypeScript, C, C++, Rust ──────────────────────────
# Same tuple shape: (rule_id, title, severity, cwe, pattern_regex, message, fix, languages)
_EXTRA_RULES: List[Tuple[str, str, str, str, str, str, str, List[str]]] = [
    # TypeScript
    (
        "SAST-TS-001",
        "TypeScript — SQL Injection via template literal",
        "critical",
        "CWE-89",
        r"""(query|execute)\s*\(\s*`[^`]*\$\{""",
        "SQL query built from template literal with user-controlled expression",
        "Use parameterized queries: db.query('SELECT ... WHERE id = $1', [id])",
        ["typescript"],
    ),
    (
        "SAST-TS-002",
        "TypeScript — eval usage",
        "critical",
        "CWE-95",
        r"""\beval\s*\(""",
        "eval() executes arbitrary code",
        "Remove eval(); use JSON.parse or explicit logic",
        ["typescript"],
    ),
    (
        "SAST-TS-003",
        "TypeScript — DOM XSS via innerHTML",
        "high",
        "CWE-79",
        r"""innerHTML\s*=|document\.write\s*\(""",
        "Direct DOM write with potentially user-controlled data",
        "Use textContent or DOMPurify.sanitize()",
        ["typescript"],
    ),
    (
        "SAST-TS-004",
        "TypeScript — Hardcoded Secret",
        "critical",
        "CWE-798",
        r"""(password|secret|apiKey|api_key|token)\s*[=:]\s*["\'][^"\']{8,}["\']""",
        "Credential hardcoded in TypeScript source",
        "Use process.env.SECRET or a secrets manager",
        ["typescript"],
    ),
    # C
    (
        "SAST-C-001",
        "C — gets() Buffer Overflow",
        "critical",
        "CWE-120",
        r"""\bgets\s*\(""",
        "gets() has no bounds checking — guaranteed buffer overflow",
        "Use fgets(buf, sizeof(buf), stdin) instead",
        ["c"],
    ),
    (
        "SAST-C-002",
        "C — strcpy/strcat unsafe",
        "high",
        "CWE-120",
        r"""\b(strcpy|strcat|sprintf|vsprintf)\s*\(""",
        "Unbounded string copy/format — buffer overflow risk",
        "Use strlcpy, strlcat, or snprintf with explicit size",
        ["c"],
    ),
    (
        "SAST-C-003",
        "C — system() command injection",
        "critical",
        "CWE-78",
        r"""\bsystem\s*\(|\bpopen\s*\(""",
        "Arbitrary OS command execution",
        "Use execve() with a fixed path and validated argument list",
        ["c"],
    ),
    (
        "SAST-C-004",
        "C — Hardcoded Secret",
        "critical",
        "CWE-798",
        r'(password|secret|key)\s*=\s*"[^"]{8,}"',
        "Credential hardcoded in C source",
        'Load secrets from environment: getenv("MY_SECRET")',
        ["c"],
    ),
    (
        "SAST-C-005",
        "C — Weak Hash (MD5/SHA1)",
        "medium",
        "CWE-328",
        r"""\b(MD5_Init|SHA1_Init|EVP_md5|EVP_sha1)\b""",
        "MD5/SHA1 are cryptographically weak",
        "Use EVP_sha256() or stronger",
        ["c"],
    ),
    (
        "SAST-C-006",
        "C — Insecure Random (rand)",
        "medium",
        "CWE-330",
        r"""\brand\s*\(|\bsrand\s*\(""",
        "rand() is not cryptographically secure",
        "Use getrandom() or /dev/urandom for security tokens",
        ["c"],
    ),
    # C++
    (
        "SAST-CPP-001",
        "C++ — system() command injection",
        "critical",
        "CWE-78",
        r"""\bsystem\s*\(|\bpopen\s*\(""",
        "Shell command execution — injection risk",
        "Use execve() or boost::process with argument arrays",
        ["cpp"],
    ),
    (
        "SAST-CPP-002",
        "C++ — gets/strcpy unsafe",
        "high",
        "CWE-120",
        r"""\b(gets|strcpy|strcat)\s*\(""",
        "Unsafe C string functions in C++ code",
        "Use std::string or bounded functions",
        ["cpp"],
    ),
    (
        "SAST-CPP-003",
        "C++ — Hardcoded Secret",
        "critical",
        "CWE-798",
        r'(password|secret|key)\s*=\s*"[^"]{8,}"',
        "Credential hardcoded in C++ source",
        'Load from environment: std::getenv("MY_SECRET")',
        ["cpp"],
    ),
    (
        "SAST-CPP-004",
        "C++ — Weak Hash (MD5/SHA1)",
        "medium",
        "CWE-328",
        r"""\b(MD5|SHA1|EVP_md5|EVP_sha1)\b""",
        "Weak cryptographic hash",
        "Use EVP_sha256() or stronger",
        ["cpp"],
    ),
    (
        "SAST-CPP-005",
        "C++ — std::rand insecure",
        "medium",
        "CWE-330",
        r"""\bstd::rand\s*\(|\bsrand\s*\(""",
        "std::rand is not cryptographically secure",
        "Use std::random_device or getrandom()",
        ["cpp"],
    ),
    # Rust
    (
        "SAST-RS-001",
        "Rust — SQL Injection via format!",
        "high",
        "CWE-89",
        r"""format!\s*\(["\'].*SELECT.*\{\}|format!\s*\(["\'].*INSERT.*\{\}""",
        "SQL query built with format! macro — injection risk",
        "Use sqlx query! macro or diesel parameterized queries",
        ["rust"],
    ),
    (
        "SAST-RS-002",
        "Rust — Hardcoded Secret",
        "critical",
        "CWE-798",
        r'(password|secret|api_key)\s*=\s*"[^"]{8,}"',
        "Credential hardcoded in Rust source",
        'Use std::env::var("MY_SECRET") or a secrets crate',
        ["rust"],
    ),
    (
        "SAST-RS-003",
        "Rust — Weak Hash (MD5/SHA1)",
        "medium",
        "CWE-328",
        r"""use\s+md5\b|Md5::new\(\)|use\s+sha1\b|Sha1::new\(\)""",
        "MD5/SHA1 are cryptographically weak",
        "Use sha2 crate: Sha256::digest(data)",
        ["rust"],
    ),
    (
        "SAST-RS-004",
        "Rust — Command Injection via user-controlled arg",
        "high",
        "CWE-78",
        r"""Command::new\s*\([^)]*\.arg\s*\(\s*&?user|Command::new\s*\([^)]*format!""",
        "OS command argument from user-controlled data",
        "Validate and allowlist arguments; avoid shell=true equivalents",
        ["rust"],
    ),
    (
        "SAST-RS-005",
        "Rust — unsafe block",
        "low",
        "CWE-119",
        r"""\bunsafe\s*\{""",
        "Unsafe Rust block — manual memory safety audit required",
        "Minimize unsafe blocks; document all invariants",
        ["rust"],
    ),
]


# ── Semgrep-format custom rule support ────────────────────────────────

@dataclass
class SemgrepRule:
    """A parsed Semgrep-format YAML rule mapped to ALDECI format."""
    rule_id: str
    message: str
    severity: str
    languages: List[str]
    pattern: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity,
            "languages": self.languages,
            "pattern": self.pattern,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "fix": self.fix,
        }


def parse_semgrep_yaml(yaml_text: str) -> List[SemgrepRule]:
    """Parse a Semgrep-format YAML string into SemgrepRule objects.

    Supports ``pattern``, ``pattern-regex``, and the first entry of
    ``patterns`` as the matching expression.
    """
    if not _YAML_AVAILABLE:
        return []
    try:
        doc = _yaml.safe_load(yaml_text)
    except Exception:
        return []
    rules: List[SemgrepRule] = []
    for raw in doc.get("rules", []):
        pattern = (
            raw.get("pattern")
            or raw.get("pattern-regex")
            or (raw.get("patterns", [{}]) or [{}])[0].get("pattern", "")
            or ""
        )
        meta = raw.get("metadata", {})
        langs = raw.get("languages", ["unknown"])
        sev = (
            raw.get("severity", "WARNING")
            .lower()
            .replace("warning", "medium")
            .replace("error", "high")
            .replace("info", "low")
        )
        rules.append(SemgrepRule(
            rule_id=raw.get("id", f"custom-{uuid.uuid4().hex[:8]}"),
            message=raw.get("message", "Custom rule finding"),
            severity=sev,
            languages=langs,
            pattern=str(pattern),
            cwe=meta.get("cwe"),
            owasp=meta.get("owasp"),
            fix=raw.get("fix"),
        ))
    return rules


def detect_language(filename: str) -> Language:
    for ext, lang in EXT_TO_LANG.items():
        if filename.endswith(ext):
            return lang
    return Language.UNKNOWN


@dataclass
class TaintFlow:
    source_line: int
    source_pattern: str
    sink_line: int
    sink_pattern: str
    sink_category: str
    variable: str = ""


@dataclass
class SastScanResult:
    scan_id: str
    files_scanned: int
    total_findings: int
    findings: List[SastFinding]
    taint_flows: List[Dict[str, Any]]
    by_severity: Dict[str, int]
    by_cwe: Dict[str, int]
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
            "taint_flows": self.taint_flows,
            "by_severity": self.by_severity,
            "by_cwe": self.by_cwe,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class SASTEngine:
    """Static Application Security Testing engine.

    Performs real pattern-based analysis with:
    - 110 built-in rules + extra rules for TypeScript/C/C++/Rust
    - Full OWASP Top 10 (2021) coverage
    - Taint source→sink flow tracking
    - CWE mapping for every finding
    - Confidence scoring
    - Semgrep-format YAML custom rule support
    - Incremental scanning via SHA-256 file hash cache
    - Air-gapped capable — no external dependencies

    OWASP Coverage:
    - A01 Broken Access Control:    SAST-017..024 (8 rules)
    - A02 Cryptographic Failures:   SAST-008, 025..034 (11 rules)
    - A03 Injection:                SAST-001..004, 012, 016, 035..048 (20 rules)
    - A04 Insecure Design:          SAST-049..054 (6 rules)
    - A05 Security Misconfiguration:SAST-055..064 (10 rules)
    - A06 Vulnerable Components:    SAST-065..068 (4 rules)
    - A07 Auth Failures:            SAST-006, 013, 069..076 (10 rules)
    - A08 Integrity Failures:       SAST-007, 077..082 (7 rules)
    - A09 Logging Failures:         SAST-014, 083..088 (7 rules)
    - A10 SSRF:                     SAST-011, 089..092 (5 rules)
    - Cross-cutting:                SAST-005, 009..010, 015, 093..110 (22 rules)
    """

    # Security limits to prevent DoS via excessive input
    MAX_CODE_SIZE = 10 * 1024 * 1024  # 10 MB max per code string
    MAX_LINE_LENGTH = 10_000  # Skip lines longer than this (likely minified/binary)
    MAX_FILES = 500  # Max files per scan_files() call
    MAX_FINDINGS_PER_SCAN = 5_000  # Cap findings to prevent memory exhaustion

    def __init__(self):
        self._lock = Lock()
        self._compiled_rules: List[
            Tuple[str, str, str, str, re.Pattern, str, str, List[str]]
        ] = []
        # Built-in rules (110 OWASP rules + extra language rules)
        all_rules = list(SAST_RULES) + list(_EXTRA_RULES)
        for r in all_rules:
            rid, title, sev, cwe, pat, msg, fix, langs = r
            try:
                self._compiled_rules.append(
                    (rid, title, sev, cwe, re.compile(pat, re.IGNORECASE), msg, fix, langs)
                )
            except re.error:
                pass  # Skip malformed patterns gracefully

        # Custom Semgrep rules (added at runtime via add_semgrep_rules)
        self._custom_rules: List[SemgrepRule] = []
        self._compiled_custom: List[Tuple[SemgrepRule, re.Pattern]] = []

        # Incremental scan cache: filename → (sha256_hash, SastScanResult)
        self._file_cache: Dict[str, Tuple[str, "SastScanResult"]] = {}

        # Accumulated results store: scan_id → SastScanResult
        self._scan_store: Dict[str, "SastScanResult"] = {}
        self._latest_scan_id: Optional[str] = None

        # PERF: Pre-compiled taint patterns (avoid re.compile on every scan_code call)
        # Structure: {lang: [compiled_pattern, ...]}
        self._compiled_taint_sources: Dict[str, List[re.Pattern]] = {
            lang: [re.compile(p, re.IGNORECASE) for p in pats]
            for lang, pats in TAINT_SOURCES.items()
        }
        # Structure: {category: [compiled_pattern, ...]}
        self._compiled_taint_sinks: Dict[str, List[re.Pattern]] = {
            cat: [re.compile(p, re.IGNORECASE) for p in pats]
            for cat, pats in TAINT_SINKS.items()
        }

    # ── Semgrep / Custom Rule Management ─────────────────────────────

    def add_semgrep_rules(self, yaml_text: str) -> List[SemgrepRule]:
        """Parse and register Semgrep-format YAML rules. Returns added rules."""
        rules = parse_semgrep_yaml(yaml_text)
        with self._lock:
            for rule in rules:
                self._custom_rules.append(rule)
                try:
                    compiled = re.compile(rule.pattern, re.IGNORECASE)
                    self._compiled_custom.append((rule, compiled))
                except re.error:
                    pass
        return rules

    def get_custom_rules(self) -> List[SemgrepRule]:
        """Return all registered custom Semgrep rules."""
        with self._lock:
            return list(self._custom_rules)

    def clear_custom_rules(self) -> None:
        """Remove all custom rules."""
        with self._lock:
            self._custom_rules.clear()
            self._compiled_custom.clear()

    # ── Incremental Scan Cache ────────────────────────────────────────

    def clear_cache(self) -> None:
        """Clear the incremental scan file-hash cache."""
        with self._lock:
            self._file_cache.clear()

    def _file_hash(self, code: str) -> str:
        return hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()

    # ── Supported Languages ───────────────────────────────────────────

    @staticmethod
    def get_supported_languages() -> Dict[str, Any]:
        """Return supported languages with rule counts and file extensions."""
        lang_rules: Dict[str, int] = {}
        for r in list(SAST_RULES) + list(_EXTRA_RULES):
            for lang in r[7]:
                lang_rules[lang] = lang_rules.get(lang, 0) + 1
        lang_exts: Dict[str, List[str]] = {}
        for ext, lang in EXT_TO_LANG.items():
            lang_exts.setdefault(lang.value, []).append(ext)
        result = {}
        for lang in Language:
            if lang == Language.UNKNOWN:
                continue
            result[lang.value] = {
                "rule_count": lang_rules.get(lang.value, 0),
                "extensions": lang_exts.get(lang.value, []),
            }
        return result

    # ── Latest Scan Summary ───────────────────────────────────────────

    def get_summary(self) -> Dict[str, Any]:
        """Return summary of the most recent scan (all-time aggregated)."""
        with self._lock:
            sid = self._latest_scan_id
            if sid is None or sid not in self._scan_store:
                # Emit canonical "no scans yet" telemetry so dashboards can
                # show the engine is alive but idle. Do NOT emit FINDING_CREATED
                # here — that was a semantic bug (no findings exist).
                _emit_event(
                    "sast.summary.requested",
                    {
                        "status": "no_scan",
                        "source_engine": "sast_engine",
                        "entity_type": "sast_summary",
                    },
                )
                return {"status": "no_scan", "message": "No scans have been run yet"}
            result = self._scan_store[sid]
        return {
            "scan_id": result.scan_id,
            "files_scanned": result.files_scanned,
            "total_findings": result.total_findings,
            "by_severity": result.by_severity,
            "by_cwe": result.by_cwe,
            "duration_ms": result.duration_ms,
            "timestamp": result.timestamp.isoformat(),
        }

    def get_all_findings(
        self,
        severity: Optional[str] = None,
        cwe: Optional[str] = None,
        language: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return findings from the most recent scan, optionally filtered."""
        with self._lock:
            sid = self._latest_scan_id
            if sid is None or sid not in self._scan_store:
                return []
            result = self._scan_store[sid]
        out = []
        for f in result.findings:
            if severity and f.severity.value != severity.lower():
                continue
            if cwe and f.cwe_id != cwe:
                continue
            if language and f.language.value != language.lower():
                continue
            out.append(f.to_dict())
        return out

    def _self_scan_skip_lines(self, lines: List[str], filename: str) -> set[int]:
        """Skip metadata-only rule blocks when the engine scans its own source.

        This avoids reporting false positives from the scanner's own regex rule
        literals and taint-pattern tables while leaving normal scanning behavior
        unchanged for every other file.
        """
        normalized = filename.replace("\\", "/")
        if not normalized.endswith("suite-core/core/sast_engine.py"):
            return set()

        skip_lines: set[int] = set()
        in_metadata_block = False
        block_starts = (
            "SAST_RULES:",
            "TAINT_SOURCES =",
            "TAINT_SINKS =",
        )
        block_end = "EXT_TO_LANG ="

        for line_num, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if any(stripped.startswith(marker) for marker in block_starts):
                in_metadata_block = True
            if in_metadata_block:
                skip_lines.add(line_num)
            if in_metadata_block and stripped.startswith(block_end):
                in_metadata_block = False

        return skip_lines

    # ── Public API ──────────────────────────────────────────────────
    def scan_code(
        self,
        code: str,
        filename: str = "input.py",
        incremental: bool = False,
    ) -> "SastScanResult":
        """Scan a single code string and return findings.

        Args:
            code: Source code string to scan.
            filename: Filename used for language detection and in findings.
            incremental: If True, return cached result when file hash is unchanged.

        Input limits:
        - Code size: MAX_CODE_SIZE (10 MB)
        - Line length: MAX_LINE_LENGTH (10,000 chars) — skips longer lines
        - Total findings capped at MAX_FINDINGS_PER_SCAN
        """
        # Input validation: reject oversized code
        if len(code) > self.MAX_CODE_SIZE:
            raise ValueError(
                f"Code size {len(code)} exceeds maximum {self.MAX_CODE_SIZE} bytes"
            )

        # Incremental: return cached result if file hash unchanged
        if incremental:
            fhash = self._file_hash(code)
            with self._lock:
                cached = self._file_cache.get(filename)
            if cached is not None and cached[0] == fhash:
                return cached[1]

        t0 = time.time()
        lang = detect_language(filename)
        lines = code.split("\n")
        skip_lines = self._self_scan_skip_lines(lines, filename)
        findings: List[SastFinding] = []
        taint_flows: List[Dict[str, Any]] = []

        # PERF: Filter applicable rules once per file (not per line × rule)
        if lang == Language.UNKNOWN:
            applicable_rules = self._compiled_rules
        else:
            applicable_rules = [
                r for r in self._compiled_rules if lang.value in r[7]
            ]

        # Rule-based scanning
        for line_num, line in enumerate(lines, 1):
            if line_num in skip_lines:
                continue
            # Skip overly long lines (likely minified JS/CSS or binary data)
            if len(line) > self.MAX_LINE_LENGTH:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            # Cap total findings to prevent memory exhaustion
            if len(findings) >= self.MAX_FINDINGS_PER_SCAN:
                break
            for rid, title, sev, cwe, pattern, msg, fix, langs in applicable_rules:
                if pattern.search(line):
                    # Redact secret values in snippets for CWE-798 (hardcoded
                    # secrets) to prevent accidental leakage in API responses,
                    # logs, or evidence bundles.
                    snippet_text = stripped[:200]
                    if cwe == "CWE-798":
                        snippet_text = re.sub(
                            r"""(=\s*['"])[A-Za-z0-9+/=_\-]{4}[A-Za-z0-9+/=_\-]*(['"])""",
                            r"\1****...\2",
                            snippet_text,
                        )
                    findings.append(
                        SastFinding(
                            rule_id=rid,
                            title=title,
                            severity=SastSeverity(sev),
                            cwe_id=cwe,
                            language=lang,
                            file_path=filename,
                            line_number=line_num,
                            snippet=snippet_text,
                            message=msg,
                            fix_suggestion=fix,
                        )
                    )

        # Custom Semgrep rules
        with self._lock:
            custom_compiled = list(self._compiled_custom)
        for rule, pattern in custom_compiled:
            if lang.value not in rule.languages and "generic" not in rule.languages:
                if lang != Language.UNKNOWN:
                    continue
            for line_num, line in enumerate(lines, 1):
                if line_num in skip_lines:
                    continue
                if len(line) > self.MAX_LINE_LENGTH:
                    continue
                stripped_line = line.strip()
                if not stripped_line:
                    continue
                if len(findings) >= self.MAX_FINDINGS_PER_SCAN:
                    break
                if pattern.search(line):
                    try:
                        sev_val = SastSeverity(rule.severity)
                    except ValueError:
                        sev_val = SastSeverity.MEDIUM
                    findings.append(
                        SastFinding(
                            rule_id=rule.rule_id,
                            title=f"[Custom] {rule.rule_id}",
                            severity=sev_val,
                            cwe_id=rule.cwe or "CWE-0",
                            language=lang,
                            file_path=filename,
                            line_number=line_num,
                            snippet=stripped_line[:200],
                            message=rule.message,
                            fix_suggestion=rule.fix or "Review per custom rule",
                        )
                    )

        # Taint flow analysis
        taint_flows = self._analyze_taint_flows(lines, lang)

        # Build result
        by_sev: Dict[str, int] = {}
        by_cwe: Dict[str, int] = {}
        for f in findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cwe[f.cwe_id] = by_cwe.get(f.cwe_id, 0) + 1

        elapsed = (time.time() - t0) * 1000
        result = SastScanResult(
            scan_id=f"sast-{uuid.uuid4().hex[:12]}",
            files_scanned=1,
            total_findings=len(findings),
            findings=findings,
            taint_flows=taint_flows,
            by_severity=by_sev,
            by_cwe=by_cwe,
            duration_ms=round(elapsed, 2),
        )

        # Store result and update incremental cache
        with self._lock:
            self._scan_store[result.scan_id] = result
            self._latest_scan_id = result.scan_id
            if incremental:
                fhash = self._file_hash(code)
                self._file_cache[filename] = (fhash, result)

        _emit_event("sast.scan.completed", {
            "scan_id": result.scan_id,
            "filename": filename,
            "language": lang.value if hasattr(lang, "value") else str(lang),
            "findings_count": result.total_findings,
            "duration_ms": result.duration_ms,
        })

        return result

    def scan_path(
        self,
        path: str,
        file_list: Optional[List[str]] = None,
        incremental: bool = False,
    ) -> "SastScanResult":
        """Scan all supported files under ``path``.

        Args:
            path: Root directory to walk recursively.
            file_list: If provided, scan only these specific file paths.
            incremental: Skip files whose SHA-256 hash is unchanged.
        """
        base = Path(path)
        if file_list:
            targets = [Path(f) for f in file_list]
        else:
            targets = [
                p for p in base.rglob("*")
                if p.is_file() and p.suffix.lower() in EXT_TO_LANG
            ]

        file_contents: Dict[str, str] = {}
        for target in targets:
            try:
                code = target.read_text(encoding="utf-8", errors="replace")
                if len(code) <= self.MAX_CODE_SIZE:
                    file_contents[str(target)] = code
            except OSError:
                continue

        return self.scan_files(file_contents, incremental=incremental)

    def scan_files(
        self,
        file_contents: Dict[str, str],
        incremental: bool = False,
    ) -> "SastScanResult":
        """Scan multiple files. Keys are filenames, values are code strings.

        Args:
            file_contents: Mapping of filename → source code.
            incremental: If True, skip files whose SHA-256 hash is unchanged.

        Limits: MAX_FILES (500) files per call. Each file subject to
        MAX_CODE_SIZE. Aggregated findings capped at MAX_FINDINGS_PER_SCAN.

        For oversized batches we now auto-cap at MAX_FILES rather than
        raising — large repos (e.g. juice-shop @ 883 files) were causing
        opaque 500s during onboarding; truncation + warning is more useful
        for a customer than a stack trace they can't see.
        """
        original_count = len(file_contents)
        if original_count > self.MAX_FILES:
            # Deterministic truncation: sort by path so the same files are
            # picked across runs (avoids flaky scan-coverage drift).
            sorted_keys = sorted(file_contents.keys())[: self.MAX_FILES]
            file_contents = {k: file_contents[k] for k in sorted_keys}
            logger.warning(
                "scan_files: input had %d files, truncating to MAX_FILES=%d (capacity-limited)",
                original_count,
                self.MAX_FILES,
            )

        t0 = time.time()
        all_findings: List[SastFinding] = []
        all_taint: List[Dict[str, Any]] = []

        # PERF: Scan files in parallel — each scan_code call is CPU-bound regex
        # work with no shared mutable state (findings are per-file). Worker count
        # capped at 4 to avoid overwhelming the GIL on very large batches; regex
        # re.search releases the GIL so threads yield real concurrency here.
        _workers = min(4, len(file_contents))
        if _workers <= 1:
            # Fast path: avoid thread overhead for tiny batches
            for fname, code in file_contents.items():
                if len(all_findings) >= self.MAX_FINDINGS_PER_SCAN:
                    break
                r = self.scan_code(code, fname, incremental=incremental)
                all_findings.extend(r.findings)
                all_taint.extend(r.taint_flows)
        else:
            with ThreadPoolExecutor(max_workers=_workers) as pool:
                futures = {
                    pool.submit(self.scan_code, code, fname, incremental): fname
                    for fname, code in file_contents.items()
                }
                for fut in as_completed(futures):
                    if len(all_findings) >= self.MAX_FINDINGS_PER_SCAN:
                        fut.cancel()
                        continue
                    try:
                        r = fut.result()
                        all_findings.extend(r.findings)
                        all_taint.extend(r.taint_flows)
                    except Exception as _exc:  # noqa: BLE001
                        logger.warning("scan_files worker error for %r: %s", futures[fut], _exc)

        by_sev: Dict[str, int] = {}
        by_cwe: Dict[str, int] = {}
        for f in all_findings:
            by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
            by_cwe[f.cwe_id] = by_cwe.get(f.cwe_id, 0) + 1

        elapsed = (time.time() - t0) * 1000
        result = SastScanResult(
            scan_id=f"sast-{uuid.uuid4().hex[:12]}",
            files_scanned=len(file_contents),
            total_findings=len(all_findings),
            findings=all_findings,
            taint_flows=all_taint,
            by_severity=by_sev,
            by_cwe=by_cwe,
            duration_ms=round(elapsed, 2),
        )
        with self._lock:
            self._scan_store[result.scan_id] = result
            self._latest_scan_id = result.scan_id
        return result

    # ── Taint Analysis ──────────────────────────────────────────────
    def _analyze_taint_flows(
        self, lines: List[str], lang: Language
    ) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        # PERF: Use pre-compiled taint patterns (compiled once at __init__)
        compiled_sources = self._compiled_taint_sources.get(lang.value, [])
        raw_sources = TAINT_SOURCES.get(lang.value, [])
        source_hits: List[Tuple[int, str]] = []
        for i, line in enumerate(lines, 1):
            for compiled_pat, raw_pat in zip(compiled_sources, raw_sources):
                if compiled_pat.search(line):
                    source_hits.append((i, raw_pat))
        if not source_hits:
            return flows
        sink_items = [
            (cat, list(zip(self._compiled_taint_sinks[cat], TAINT_SINKS[cat])))
            for cat in TAINT_SINKS
        ]
        for i, line in enumerate(lines, 1):
            for cat, sink_pairs in sink_items:
                for compiled_sink, raw_sink in sink_pairs:
                    if compiled_sink.search(line):
                        for src_line, src_pat in source_hits:
                            if src_line < i:
                                flows.append(
                                    {
                                        "source_line": src_line,
                                        "source_pattern": src_pat,
                                        "sink_line": i,
                                        "sink_pattern": raw_sink,
                                        "sink_category": cat,
                                    }
                                )
        return flows


    # ── OWASP Reporting ──────────────────────────────────────────────
    @staticmethod
    def get_rule_count() -> int:
        """Return total number of SAST rules."""
        return len(SAST_RULES)

    @staticmethod
    def get_owasp_coverage() -> Dict[str, Any]:
        """Return OWASP Top 10 coverage summary."""
        coverage: Dict[str, Any] = {}
        for cat, rule_ids in OWASP_CATEGORIES.items():
            coverage[cat] = {
                "rule_count": len(rule_ids),
                "rule_ids": rule_ids,
            }
        return {
            "total_rules": len(SAST_RULES),
            "owasp_categories_covered": len(OWASP_CATEGORIES),
            "categories": coverage,
        }

    def get_findings_by_owasp(
        self, result: SastScanResult
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group scan findings by OWASP Top 10 category."""
        owasp_findings: Dict[str, List[Dict[str, Any]]] = {
            cat: [] for cat in OWASP_CATEGORIES
        }
        rule_to_owasp: Dict[str, str] = {}
        for cat, rule_ids in OWASP_CATEGORIES.items():
            for rid in rule_ids:
                rule_to_owasp[rid] = cat
        for finding in result.findings:
            cat = rule_to_owasp.get(finding.rule_id, "Uncategorized")
            if cat not in owasp_findings:
                owasp_findings[cat] = []
            owasp_findings[cat].append(finding.to_dict())
        return owasp_findings


_engine: Optional[SASTEngine] = None


def get_sast_engine() -> SASTEngine:
    global _engine
    if _engine is None:
        _engine = SASTEngine()
    return _engine


# ---------------------------------------------------------------------------
# GAP-019: Snippet scanner (AI-generated code / keystroke-time scanning)
# ---------------------------------------------------------------------------

import json as _snippet_json
import sqlite3 as _snippet_sqlite3
import threading as _snippet_threading

_SNIPPET_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"
_SNIPPET_DB_LOCK = _snippet_threading.RLock()
_SNIPPET_DB_PATH: Optional[str] = None
_SNIPPET_CONN: Optional[_snippet_sqlite3.Connection] = None  # PERF: persistent connection

_SNIPPET_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS snippet_scans (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    snippet_sha256   TEXT NOT NULL,
    language         TEXT NOT NULL,
    source_hint      TEXT NOT NULL DEFAULT 'ai_generated',
    findings_json    TEXT NOT NULL DEFAULT '[]',
    scanned_at       TEXT NOT NULL,
    UNIQUE(org_id, snippet_sha256)
);

CREATE INDEX IF NOT EXISTS idx_snippet_scans_org ON snippet_scans(org_id);
CREATE INDEX IF NOT EXISTS idx_snippet_scans_lang ON snippet_scans(org_id, language);
CREATE INDEX IF NOT EXISTS idx_snippet_scans_date ON snippet_scans(org_id, scanned_at);
"""


def _snippet_db_path() -> str:
    global _SNIPPET_DB_PATH
    if _SNIPPET_DB_PATH is None:
        _SNIPPET_DB_DIR.mkdir(parents=True, exist_ok=True)
        _SNIPPET_DB_PATH = str(_SNIPPET_DB_DIR / "snippet_scans.db")
    return _SNIPPET_DB_PATH


def _snippet_conn() -> _snippet_sqlite3.Connection:
    """Return the persistent module-level connection, creating it if needed.

    PERF: Opening sqlite3.connect() on every call costs ~0.5 ms of file-open
    + header-read overhead. A single persistent connection with WAL mode
    eliminates that overhead entirely; the RLock still serialises writers.
    """
    global _SNIPPET_CONN
    if _SNIPPET_CONN is None:
        conn = _snippet_sqlite3.connect(_snippet_db_path(), check_same_thread=False)
        conn.row_factory = _snippet_sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _SNIPPET_CONN = conn
    return _SNIPPET_CONN


def _snippet_init_db() -> None:
    with _SNIPPET_DB_LOCK:
        conn = _snippet_conn()
        conn.executescript(_SNIPPET_DDL)


def _language_to_extension(language: str) -> str:
    """Map a language name to a representative filename extension."""
    mapping = {
        "python": "py",
        "py": "py",
        "javascript": "js",
        "js": "js",
        "typescript": "ts",
        "ts": "ts",
        "java": "java",
        "go": "go",
        "ruby": "rb",
        "rb": "rb",
        "php": "php",
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
        "rust": "rs",
        "rs": "rs",
        "csharp": "cs",
        "cs": "cs",
    }
    return mapping.get(language.lower(), "txt")


# Reset DB path helper (used by tests)
def _snippet_set_db_path(path: str) -> None:
    global _SNIPPET_DB_PATH, _SNIPPET_CONN
    _SNIPPET_DB_PATH = path
    # Close and drop the cached connection so the next _snippet_conn() call
    # opens against the new path (important for test isolation).
    if _SNIPPET_CONN is not None:
        try:
            _SNIPPET_CONN.close()
        except Exception:
            pass
        _SNIPPET_CONN = None
    _snippet_init_db()


def scan_snippet(
    org_id: str,
    code: str,
    language: str,
    source_hint: str = "ai_generated",
) -> Dict[str, Any]:
    """Scan a single code snippet (not a full repo) — e.g. AI-generated code at keystroke time.

    Applies the existing SAST ruleset to a single snippet and persists an audit record.
    Idempotent: if the same (org_id, sha256) was scanned before, cached findings are returned.

    Args:
        org_id: Organization identifier (tenant isolation).
        code: Raw source code snippet (string).
        language: Language name (python/javascript/go/java/ruby/php/typescript/c/cpp/rust/csharp).
        source_hint: Provenance tag (default 'ai_generated'). Examples: 'copilot', 'claude', 'manual'.

    Returns:
        {
          "snippet_sha256": str,
          "org_id": str,
          "language": str,
          "source_hint": str,
          "findings": [finding_dict, ...],
          "findings_count": int,
          "cached": bool,          # True if re-served from audit cache
          "scanned_at": iso8601,
        }
    """
    if not isinstance(org_id, str) or not org_id:
        raise ValueError("org_id must be a non-empty string")
    if not isinstance(code, str):
        raise ValueError("code must be a string")
    if not isinstance(language, str) or not language:
        raise ValueError("language must be a non-empty string")

    snippet_sha256 = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()
    _snippet_init_db()

    # Idempotency cache — reuse prior scan for identical snippet
    with _SNIPPET_DB_LOCK:
        with _snippet_conn() as conn:
            cached_row = conn.execute(
                "SELECT findings_json, scanned_at, language, source_hint "
                "FROM snippet_scans WHERE org_id=? AND snippet_sha256=?",
                (org_id, snippet_sha256),
            ).fetchone()

    if cached_row is not None:
        try:
            cached_findings = _snippet_json.loads(cached_row["findings_json"])
        except (_snippet_json.JSONDecodeError, TypeError, ValueError):
            cached_findings = []
        return {
            "snippet_sha256": snippet_sha256,
            "org_id": org_id,
            "language": cached_row["language"],
            "source_hint": cached_row["source_hint"],
            "findings": cached_findings,
            "findings_count": len(cached_findings),
            "cached": True,
            "scanned_at": cached_row["scanned_at"],
        }

    # Run SAST: build a pseudo-filename so detect_language picks up the extension
    ext = _language_to_extension(language)
    filename = f"snippet.{ext}"

    engine = get_sast_engine()
    try:
        result = engine.scan_code(code=code, filename=filename, incremental=False)
        findings = [f.to_dict() for f in result.findings]
    except ValueError:
        # Oversized / invalid input — surface zero findings (no crash)
        findings = []

    scanned_at = datetime.now(timezone.utc).isoformat()

    # Persist audit row (idempotent via UNIQUE constraint)
    with _SNIPPET_DB_LOCK:
        with _snippet_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO snippet_scans "
                "(id, org_id, snippet_sha256, language, source_hint, findings_json, scanned_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    f"snip-{uuid.uuid4().hex[:12]}",
                    org_id,
                    snippet_sha256,
                    language,
                    source_hint,
                    _snippet_json.dumps(findings),
                    scanned_at,
                ),
            )

    return {
        "snippet_sha256": snippet_sha256,
        "org_id": org_id,
        "language": language,
        "source_hint": source_hint,
        "findings": findings,
        "findings_count": len(findings),
        "cached": False,
        "scanned_at": scanned_at,
    }


def list_snippet_scans(
    org_id: str,
    language: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Return snippet scan history for an org, optionally filtered by language."""
    if not isinstance(org_id, str) or not org_id:
        raise ValueError("org_id must be a non-empty string")
    limit = max(1, min(int(limit), 1000))
    _snippet_init_db()
    with _SNIPPET_DB_LOCK:
        with _snippet_conn() as conn:
            if language:
                rows = conn.execute(
                    "SELECT * FROM snippet_scans WHERE org_id=? AND language=? "
                    "ORDER BY scanned_at DESC LIMIT ?",
                    (org_id, language, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM snippet_scans WHERE org_id=? "
                    "ORDER BY scanned_at DESC LIMIT ?",
                    (org_id, limit),
                ).fetchall()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["findings"] = _snippet_json.loads(d.pop("findings_json", "[]"))
        except (_snippet_json.JSONDecodeError, TypeError, ValueError):
            d["findings"] = []
            d.pop("findings_json", None)
        d["findings_count"] = len(d["findings"])
        out.append(d)
    return out


def snippet_scan_stats(org_id: str) -> Dict[str, Any]:
    """Return aggregated snippet-scan stats for an org."""
    if not isinstance(org_id, str) or not org_id:
        raise ValueError("org_id must be a non-empty string")
    _snippet_init_db()
    with _SNIPPET_DB_LOCK:
        with _snippet_conn() as conn:
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM snippet_scans WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]
            by_lang_rows = conn.execute(
                "SELECT language, COUNT(*) AS cnt FROM snippet_scans WHERE org_id=? GROUP BY language",
                (org_id,),
            ).fetchall()
            by_source_rows = conn.execute(
                "SELECT source_hint, COUNT(*) AS cnt FROM snippet_scans WHERE org_id=? GROUP BY source_hint",
                (org_id,),
            ).fetchall()
            all_findings_rows = conn.execute(
                "SELECT findings_json FROM snippet_scans WHERE org_id=?",
                (org_id,),
            ).fetchall()

    total_findings = 0
    scans_with_findings = 0
    for row in all_findings_rows:
        try:
            fs = _snippet_json.loads(row["findings_json"])
        except (_snippet_json.JSONDecodeError, TypeError, ValueError):
            fs = []
        if fs:
            scans_with_findings += 1
        total_findings += len(fs)

    return {
        "org_id": org_id,
        "total_scans": total_scans,
        "scans_with_findings": scans_with_findings,
        "clean_scans": max(0, total_scans - scans_with_findings),
        "total_findings": total_findings,
        "by_language": {row["language"]: row["cnt"] for row in by_lang_rows},
        "by_source_hint": {row["source_hint"]: row["cnt"] for row in by_source_rows},
    }
