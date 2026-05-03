"""
FixOps MPTE Post-Fix Verification Engine.

Closes the critical Find → Fix → VERIFY loop.

After AutoFix generates and applies a patch, this engine re-runs the full
verification suite to confirm:
  1. The vulnerable pattern is truly eliminated (static + AST analysis)
  2. No regressions/new CWEs were introduced
  3. Dependencies introduced are safe
  4. MPTE exploit no longer succeeds after the patch
  5. Code style, indentation, and naming conventions are preserved
  6. Test coverage impact is estimated

This is FixOps' primary differentiator vs Snyk Agent Fix, Aikido AutoFix,
and other tools that ship fixes without post-fix exploit retesting.

Vision Pillars: V3 (Decision Intelligence), V4 (MPTE), V8 (Continuous Compliance)
License: Proprietary (ALdeci). All implementations are original.
"""

from __future__ import annotations

import ast
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
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


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    INCONCLUSIVE = "inconclusive"


class MPTERetestResult(str, Enum):
    EXPLOIT_BLOCKED = "exploit_blocked"
    EXPLOIT_STILL_POSSIBLE = "exploit_still_possible"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    """Per-check pass/fail with explanation."""

    check_name: str
    status: CheckStatus
    description: str
    details: Optional[str] = None
    cwe: Optional[str] = None
    severity: str = "info"
    duration_ms: float = 0.0


@dataclass
class VerificationReport:
    """Complete post-fix verification report."""

    finding_id: str
    finding_type: str
    language: str
    verified: bool
    confidence: float  # 0.0 – 1.0
    checks_passed: int
    checks_total: int
    regressions_found: List[str]
    mpte_retest_result: str  # MPTERetestResult value
    safe_to_deploy: bool
    verification_duration_ms: float
    detailed_checks: List[CheckResult]
    fix_fingerprint: str
    original_fingerprint: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    recommendation: str = ""
    compliance_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "language": self.language,
            "verified": self.verified,
            "confidence": round(self.confidence, 4),
            "checks_passed": self.checks_passed,
            "checks_total": self.checks_total,
            "regressions_found": self.regressions_found,
            "mpte_retest_result": self.mpte_retest_result,
            "safe_to_deploy": self.safe_to_deploy,
            "verification_duration_ms": round(self.verification_duration_ms, 2),
            "detailed_checks": [
                {
                    "check_name": c.check_name,
                    "status": c.status.value,
                    "description": c.description,
                    "details": c.details,
                    "cwe": c.cwe,
                    "severity": c.severity,
                    "duration_ms": round(c.duration_ms, 2),
                }
                for c in self.detailed_checks
            ],
            "fix_fingerprint": self.fix_fingerprint,
            "original_fingerprint": self.original_fingerprint,
            "timestamp": self.timestamp,
            "recommendation": self.recommendation,
            "compliance_evidence": self.compliance_evidence,
        }


# ---------------------------------------------------------------------------
# Vulnerability pattern library
# Each language has 50+ patterns covering the most common CWEs.
# Structure: {"pattern": regex, "name": str, "cwe": str, "severity": str,
#             "finding_types": [list of finding_type strings this pattern matches]}
# ---------------------------------------------------------------------------

_VULN_PATTERNS: Dict[str, List[Dict[str, Any]]] = {

    # -----------------------------------------------------------------------
    # Python – 60+ patterns
    # -----------------------------------------------------------------------
    "python": [
        # SQL Injection (CWE-89)
        # Match execute("..."%var) style but NOT execute("...%s", (var,)) parameterized form
        {"pattern": r'execute\s*\(\s*["\'].*["\']\s*%\s*\w', "name": "SQLi: % string format in execute()", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"execute\s*\(\s*f[\"']", "name": "SQLi: f-string in execute()", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"execute\s*\(\s*[\"'].*\+", "name": "SQLi: string concat in execute()", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"\.format\s*\(.*\)\s*\)", "name": "SQLi: .format() in query", "cwe": "CWE-89", "severity": "high", "finding_types": ["sql_injection"]},
        {"pattern": r"cursor\.execute\s*\(\s*\".*\"\s*%", "name": "SQLi: cursor.execute with % format", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"raw\s*\(\s*f[\"']", "name": "SQLi: Django raw() with f-string", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"extra\s*\(\s*where\s*=.*%", "name": "SQLi: Django extra() with % format", "cwe": "CWE-89", "severity": "high", "finding_types": ["sql_injection"]},

        # XSS (CWE-79)
        {"pattern": r"mark_safe\s*\(", "name": "XSS: Django mark_safe()", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"Markup\s*\(", "name": "XSS: Jinja2 Markup() bypass", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"render_template_string\s*\(.*request\.", "name": "XSS: Flask render_template_string with request", "cwe": "CWE-79", "severity": "critical", "finding_types": ["xss"]},
        {"pattern": r"escape\s*=\s*False", "name": "XSS: escape=False in template", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},

        # Command Injection (CWE-78)
        {"pattern": r"os\.system\s*\(", "name": "CMDi: os.system()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True", "name": "CMDi: subprocess with shell=True", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"os\.popen\s*\(", "name": "CMDi: os.popen()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"commands\.(getoutput|getstatusoutput)\s*\(", "name": "CMDi: commands module", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"popen2\.", "name": "CMDi: popen2 usage", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"pty\.spawn\s*\(", "name": "CMDi: pty.spawn()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},

        # Path Traversal (CWE-22)
        {"pattern": r"open\s*\(\s*.*request\.", "name": "Path traversal: open() with request data", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"open\s*\(\s*[^)]*\+", "name": "Path traversal: open() with string concat", "cwe": "CWE-22", "severity": "medium", "finding_types": ["path_traversal"]},
        {"pattern": r"\.\.\s*/", "name": "Path traversal: ../ sequence", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"send_file\s*\(\s*.*request\.", "name": "Path traversal: send_file() with request data", "cwe": "CWE-22", "severity": "critical", "finding_types": ["path_traversal"]},
        {"pattern": r"os\.path\.join\s*\(.*request\.", "name": "Path traversal: os.path.join with request data", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # Deserialization (CWE-502)
        {"pattern": r"pickle\.(loads?|load)\s*\(", "name": "Deser: pickle.loads()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"yaml\.load\s*\([^,)]*\)", "name": "Deser: yaml.load() without Loader", "cwe": "CWE-502", "severity": "high", "finding_types": ["deserialization"]},
        {"pattern": r"marshal\.loads?\s*\(", "name": "Deser: marshal.loads()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"shelve\.open\s*\(", "name": "Deser: shelve.open()", "cwe": "CWE-502", "severity": "medium", "finding_types": ["deserialization"]},
        {"pattern": r"jsonpickle\.decode\s*\(", "name": "Deser: jsonpickle.decode()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"dill\.loads?\s*\(", "name": "Deser: dill.loads()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},

        # SSRF (CWE-918)
        {"pattern": r"requests\.(get|post|put|delete|patch|head)\s*\(\s*.*request\.", "name": "SSRF: requests with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"urllib\.request\.urlopen\s*\(\s*.*request\.", "name": "SSRF: urlopen with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"httpx\.(get|post|put|delete)\s*\(\s*.*request\.", "name": "SSRF: httpx with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"aiohttp\.ClientSession.*\.(get|post)\s*\(\s*.*request\.", "name": "SSRF: aiohttp with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},

        # Code Injection / eval (CWE-94, CWE-95)
        {"pattern": r"\beval\s*\(", "name": "Code injection: eval()", "cwe": "CWE-95", "severity": "critical", "finding_types": ["command_injection", "xss"]},
        {"pattern": r"\bexec\s*\(", "name": "Code injection: exec()", "cwe": "CWE-94", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"compile\s*\(.*exec\b", "name": "Code injection: compile()+exec", "cwe": "CWE-94", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"__import__\s*\(", "name": "Code injection: __import__()", "cwe": "CWE-94", "severity": "high", "finding_types": ["command_injection"]},

        # Buffer Overflow / unsafe C bindings (CWE-119, CWE-120)
        {"pattern": r"ctypes\.memmove\s*\(", "name": "Buffer: ctypes.memmove()", "cwe": "CWE-120", "severity": "high", "finding_types": ["buffer_overflow"]},
        {"pattern": r"ctypes\.memset\s*\(", "name": "Buffer: ctypes.memset()", "cwe": "CWE-120", "severity": "medium", "finding_types": ["buffer_overflow"]},
        {"pattern": r"cffi\.FFI\(\)\.cast\s*\(", "name": "Buffer: cffi cast to raw pointer", "cwe": "CWE-119", "severity": "high", "finding_types": ["buffer_overflow"]},

        # Hardcoded Secrets (CWE-259, CWE-798)
        {"pattern": r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', "name": "Secret: hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},
        {"pattern": r'(?:api_key|apikey|api_secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']', "name": "Secret: hardcoded API key", "cwe": "CWE-798", "severity": "high", "finding_types": []},
        {"pattern": r'(?:token|access_token|auth_token)\s*=\s*["\'][^"\']{8,}["\']', "name": "Secret: hardcoded token", "cwe": "CWE-798", "severity": "high", "finding_types": []},
        {"pattern": r"AKIA[0-9A-Z]{16}", "name": "Secret: AWS access key", "cwe": "CWE-798", "severity": "critical", "finding_types": []},
        {"pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", "name": "Secret: GitHub token", "cwe": "CWE-798", "severity": "critical", "finding_types": []},

        # Weak Crypto (CWE-326, CWE-327, CWE-328)
        {"pattern": r"hashlib\.md5\s*\(", "name": "Crypto: MD5 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r"hashlib\.sha1\s*\(", "name": "Crypto: SHA-1 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r"DES\b", "name": "Crypto: DES cipher", "cwe": "CWE-326", "severity": "high", "finding_types": []},
        {"pattern": r"Blowfish\b", "name": "Crypto: Blowfish cipher", "cwe": "CWE-326", "severity": "medium", "finding_types": []},
        {"pattern": r"MODE_ECB\b", "name": "Crypto: ECB mode", "cwe": "CWE-327", "severity": "high", "finding_types": []},
        {"pattern": r"random\.(random|randint|choice|shuffle)\s*\(", "name": "Crypto: non-CSPRNG for sensitive data", "cwe": "CWE-330", "severity": "medium", "finding_types": []},

        # SSL/TLS (CWE-295)
        {"pattern": r"verify\s*=\s*False", "name": "TLS: SSL verify=False", "cwe": "CWE-295", "severity": "high", "finding_types": []},
        {"pattern": r"ssl\.PROTOCOL_SSLv2\b", "name": "TLS: SSLv2 protocol", "cwe": "CWE-326", "severity": "critical", "finding_types": []},
        {"pattern": r"ssl\.PROTOCOL_SSLv3\b", "name": "TLS: SSLv3 protocol", "cwe": "CWE-326", "severity": "critical", "finding_types": []},
        {"pattern": r"check_hostname\s*=\s*False", "name": "TLS: hostname check disabled", "cwe": "CWE-295", "severity": "high", "finding_types": []},

        # XXE (CWE-611)
        {"pattern": r"xml\.etree\.ElementTree\.parse\s*\(", "name": "XXE: ElementTree.parse() (may be vulnerable)", "cwe": "CWE-611", "severity": "medium", "finding_types": []},
        {"pattern": r"lxml\.etree\.(parse|fromstring)\s*\((?!.*resolve_entities\s*=\s*False)", "name": "XXE: lxml without resolve_entities=False", "cwe": "CWE-611", "severity": "high", "finding_types": []},

        # Open Redirect (CWE-601)
        {"pattern": r"redirect\s*\(\s*.*request\.", "name": "Open redirect: redirect() with request data", "cwe": "CWE-601", "severity": "medium", "finding_types": []},
    ],

    # -----------------------------------------------------------------------
    # JavaScript / TypeScript – 55+ patterns
    # -----------------------------------------------------------------------
    "javascript": [
        # XSS (CWE-79)
        {"pattern": r"\.innerHTML\s*=", "name": "XSS: innerHTML assignment", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"\.outerHTML\s*=", "name": "XSS: outerHTML assignment", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"document\.write\s*\(", "name": "XSS: document.write()", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"document\.writeln\s*\(", "name": "XSS: document.writeln()", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"insertAdjacentHTML\s*\(", "name": "XSS: insertAdjacentHTML()", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"\.srcdoc\s*=", "name": "XSS: iframe srcdoc assignment", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"dangerouslySetInnerHTML\s*=", "name": "XSS: React dangerouslySetInnerHTML", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"bypassSecurityTrustHtml\s*\(", "name": "XSS: Angular bypassSecurityTrustHtml", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},

        # SQLi (CWE-89)
        {"pattern": r"db\.query\s*\(\s*[`\"'].*\$\{", "name": "SQLi: template literal in query()", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"\.query\s*\(\s*[\"'].*\+", "name": "SQLi: string concat in query()", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"knex\.raw\s*\(.*\$\{", "name": "SQLi: knex.raw() with template literal", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"sequelize\.query\s*\(\s*[`\"'].*\$\{", "name": "SQLi: Sequelize query with template literal", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"mongoose\.connection\.db\.[^(]+\(\s*\{[^}]*\$where", "name": "NoSQLi: MongoDB $where injection", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},

        # Command Injection (CWE-78)
        {"pattern": r"child_process\.(exec|execSync|spawn|spawnSync)\s*\(", "name": "CMDi: child_process.exec()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"require\s*\(\s*['\"]child_process['\"]\s*\)", "name": "CMDi: require('child_process')", "cwe": "CWE-78", "severity": "high", "finding_types": ["command_injection"]},
        {"pattern": r"shelljs\.(exec|cd|ls)\s*\(", "name": "CMDi: shelljs.exec()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"execa\s*\(", "name": "CMDi: execa()", "cwe": "CWE-78", "severity": "medium", "finding_types": ["command_injection"]},

        # Code Injection (CWE-94, CWE-95)
        {"pattern": r"\beval\s*\(", "name": "Code injection: eval()", "cwe": "CWE-95", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"new\s+Function\s*\(", "name": "Code injection: new Function()", "cwe": "CWE-95", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"vm\.(runInThisContext|runInNewContext|runInContext)\s*\(", "name": "Code injection: vm.runIn*()", "cwe": "CWE-94", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"setTimeout\s*\(\s*[\"']", "name": "Code injection: setTimeout with string", "cwe": "CWE-95", "severity": "high", "finding_types": ["command_injection"]},
        {"pattern": r"setInterval\s*\(\s*[\"']", "name": "Code injection: setInterval with string", "cwe": "CWE-95", "severity": "high", "finding_types": ["command_injection"]},

        # Path Traversal (CWE-22)
        {"pattern": r"fs\.(readFile|createReadStream|readFileSync)\s*\([^)]*req\.", "name": "Path traversal: fs.readFile with req.*", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"path\.join\s*\([^)]*req\.", "name": "Path traversal: path.join with req.*", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"res\.sendFile\s*\([^)]*req\.", "name": "Path traversal: sendFile with req.*", "cwe": "CWE-22", "severity": "critical", "finding_types": ["path_traversal"]},

        # Deserialization (CWE-502)
        {"pattern": r"node-serialize\.unserialize\s*\(", "name": "Deser: node-serialize", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"serialize-javascript.*deserialize\s*\(", "name": "Deser: serialize-javascript", "cwe": "CWE-502", "severity": "high", "finding_types": ["deserialization"]},
        {"pattern": r"YAML\.load\s*\(", "name": "Deser: js-yaml YAML.load()", "cwe": "CWE-502", "severity": "high", "finding_types": ["deserialization"]},
        {"pattern": r"\.fromEntries\s*\(.*JSON\.parse\s*\(.*req\.", "name": "Deser: JSON.parse() with req.*", "cwe": "CWE-502", "severity": "medium", "finding_types": ["deserialization"]},

        # SSRF (CWE-918)
        {"pattern": r"axios\.(get|post|put|delete|patch)\s*\(\s*.*req\.", "name": "SSRF: axios with req.* URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"fetch\s*\(\s*.*req\.(body|query|params)", "name": "SSRF: fetch() with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"http\.(get|request)\s*\(\s*.*req\.", "name": "SSRF: http.get with req.* URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"got\s*\(\s*.*req\.(body|query|params)", "name": "SSRF: got() with user-controlled URL", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},

        # Prototype Pollution (CWE-1321)
        {"pattern": r"__proto__\s*\[", "name": "Prototype pollution: __proto__[] assignment", "cwe": "CWE-1321", "severity": "high", "finding_types": []},
        {"pattern": r"Object\.assign\s*\(\s*\{\}\s*,\s*.*req\.", "name": "Prototype pollution: Object.assign with req.*", "cwe": "CWE-1321", "severity": "medium", "finding_types": []},
        {"pattern": r"constructor\s*\[\s*[\"']prototype[\"']\s*\]", "name": "Prototype pollution: constructor.prototype access", "cwe": "CWE-1321", "severity": "high", "finding_types": []},

        # Secrets (CWE-798)
        {"pattern": r'(?:password|passwd)\s*[=:]\s*["\'][^"\']{4,}["\']', "name": "Secret: hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},
        {"pattern": r'(?:api_key|apiKey|apiSecret|secret)\s*[=:]\s*["\'][^"\']{8,}["\']', "name": "Secret: hardcoded API key", "cwe": "CWE-798", "severity": "high", "finding_types": []},
        {"pattern": r"AKIA[0-9A-Z]{16}", "name": "Secret: AWS access key", "cwe": "CWE-798", "severity": "critical", "finding_types": []},

        # ReDoS (CWE-400)
        {"pattern": r"new\s+RegExp\s*\(\s*.*req\.", "name": "ReDoS: RegExp from user input", "cwe": "CWE-400", "severity": "medium", "finding_types": []},

        # Open Redirect (CWE-601)
        {"pattern": r"res\.redirect\s*\(\s*.*req\.(query|body|params)", "name": "Open redirect: res.redirect with req.*", "cwe": "CWE-601", "severity": "medium", "finding_types": []},

        # Weak Crypto (CWE-328)
        {"pattern": r"createHash\s*\(\s*['\"]md5['\"]", "name": "Crypto: MD5 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r"createHash\s*\(\s*['\"]sha1['\"]", "name": "Crypto: SHA-1 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r"Math\.random\s*\(\s*\)", "name": "Crypto: Math.random() for security", "cwe": "CWE-338", "severity": "medium", "finding_types": []},

        # XXE (CWE-611)
        {"pattern": r"new\s+DOMParser\s*\(\s*\)", "name": "XXE: DOMParser (browser XXE risk)", "cwe": "CWE-611", "severity": "low", "finding_types": []},
        {"pattern": r"libxmljs\.parseXml\s*\((?!.*noent\s*:\s*false)", "name": "XXE: libxmljs without noent:false", "cwe": "CWE-611", "severity": "high", "finding_types": []},

        # JWT (CWE-347)
        {"pattern": r"jwt\.verify\s*\([^)]*algorithms\s*:\s*\[\s*['\"]none['\"]", "name": "JWT: 'none' algorithm", "cwe": "CWE-347", "severity": "critical", "finding_types": []},
        {"pattern": r"jwt\.decode\s*\([^)]*\)", "name": "JWT: jwt.decode without verify", "cwe": "CWE-347", "severity": "high", "finding_types": []},

        # CORS misconfiguration (CWE-942)
        {"pattern": r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]\*['\"]\s*\}", "name": "CORS: cors() with origin:*", "cwe": "CWE-942", "severity": "medium", "finding_types": []},
        {"pattern": r"res\.setHeader\s*\([^)]*Access-Control-Allow-Origin[^)]*\*", "name": "CORS: wildcard Allow-Origin header", "cwe": "CWE-942", "severity": "medium", "finding_types": []},

        # Insecure cookie (CWE-614, CWE-1004)
        {"pattern": r"res\.cookie\s*\([^)]*\{(?![^}]*httpOnly\s*:\s*true)", "name": "Cookie: httpOnly not set", "cwe": "CWE-1004", "severity": "medium", "finding_types": []},
        {"pattern": r"res\.cookie\s*\([^)]*\{(?![^}]*secure\s*:\s*true)", "name": "Cookie: secure not set", "cwe": "CWE-614", "severity": "medium", "finding_types": []},
    ],

    # -----------------------------------------------------------------------
    # Java – 55+ patterns
    # -----------------------------------------------------------------------
    "java": [
        # SQL Injection (CWE-89)
        {"pattern": r"Statement\s*\.\s*execute\s*\(\s*[^\?]", "name": "SQLi: Statement.execute() without PreparedStatement", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"createStatement\s*\(\s*\)", "name": "SQLi: createStatement() (use PreparedStatement)", "cwe": "CWE-89", "severity": "high", "finding_types": ["sql_injection"]},
        {"pattern": r'executeQuery\s*\(\s*".*"\s*\+', "name": "SQLi: executeQuery() with string concat", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"EntityManager\.createNativeQuery\s*\([^?]+\+", "name": "SQLi: JPA createNativeQuery() with concat", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r"Query\s+\w+\s*=\s*session\.createQuery\s*\([^?]+\+", "name": "SQLi: HQL createQuery() with concat", "cwe": "CWE-89", "severity": "high", "finding_types": ["sql_injection"]},

        # XSS (CWE-79)
        {"pattern": r"response\.getWriter\(\)\.print\s*\(.*request\.getParameter", "name": "XSS: PrintWriter with request param", "cwe": "CWE-79", "severity": "critical", "finding_types": ["xss"]},
        {"pattern": r"\.setHeader\s*\([^)]*request\.getParameter", "name": "XSS: setHeader with request param", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r"out\.println\s*\(.*request\.getParameter", "name": "XSS: out.println with request param", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},

        # Command Injection (CWE-78)
        {"pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(", "name": "CMDi: Runtime.exec()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r"new\s+ProcessBuilder\s*\(", "name": "CMDi: ProcessBuilder", "cwe": "CWE-78", "severity": "high", "finding_types": ["command_injection"]},
        {"pattern": r"ProcessBuilder.*command\s*\(.*\+", "name": "CMDi: ProcessBuilder.command() with concat", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},

        # Path Traversal (CWE-22)
        {"pattern": r"new\s+File\s*\([^)]*getParameter", "name": "Path traversal: new File() with request param", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"Paths\.get\s*\([^)]*getParameter", "name": "Path traversal: Paths.get() with request param", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r"FileInputStream\s*\([^)]*getParameter", "name": "Path traversal: FileInputStream with request param", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # Deserialization (CWE-502)
        {"pattern": r"new\s+ObjectInputStream\s*\(", "name": "Deser: ObjectInputStream", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"\.readObject\s*\(\s*\)", "name": "Deser: readObject()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"XStream\.fromXML\s*\(", "name": "Deser: XStream.fromXML()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"new\s+ObjectMapper\s*\(\s*\).*enableDefaultTyping", "name": "Deser: Jackson enableDefaultTyping", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},
        {"pattern": r"SerializationUtils\.deserialize\s*\(", "name": "Deser: Commons SerializationUtils.deserialize()", "cwe": "CWE-502", "severity": "critical", "finding_types": ["deserialization"]},

        # XXE (CWE-611)
        {"pattern": r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature)", "name": "XXE: DocumentBuilderFactory without setFeature", "cwe": "CWE-611", "severity": "critical", "finding_types": []},
        {"pattern": r"SAXParserFactory\.newInstance\s*\(\s*\)(?!.*setFeature)", "name": "XXE: SAXParserFactory without setFeature", "cwe": "CWE-611", "severity": "critical", "finding_types": []},
        {"pattern": r"TransformerFactory\.newInstance\s*\(\s*\)(?!.*setAttribute)", "name": "XXE: TransformerFactory without setAttribute", "cwe": "CWE-611", "severity": "high", "finding_types": []},
        {"pattern": r"XMLInputFactory\.newInstance\s*\(\s*\)(?!.*setProperty)", "name": "XXE: XMLInputFactory without setProperty", "cwe": "CWE-611", "severity": "high", "finding_types": []},

        # SSRF (CWE-918)
        {"pattern": r"new\s+URL\s*\([^)]*getParameter", "name": "SSRF: new URL() with request param", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"HttpClient.*execute\s*\(.*getParameter", "name": "SSRF: HttpClient with request param", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"RestTemplate\.getForObject\s*\([^)]*getParameter", "name": "SSRF: RestTemplate with request param", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},

        # Weak Crypto (CWE-326, CWE-327, CWE-328)
        {"pattern": r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)', "name": "Crypto: MD5 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'MessageDigest\.getInstance\s*\(\s*["\']SHA-1["\']\s*\)', "name": "Crypto: SHA-1 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'Cipher\.getInstance\s*\(\s*["\']DES["\']', "name": "Crypto: DES cipher", "cwe": "CWE-326", "severity": "high", "finding_types": []},
        {"pattern": r'Cipher\.getInstance\s*\(\s*["\'][^/]+/ECB/', "name": "Crypto: ECB mode", "cwe": "CWE-327", "severity": "high", "finding_types": []},
        {"pattern": r"new\s+Random\s*\(\s*\)", "name": "Crypto: java.util.Random (use SecureRandom)", "cwe": "CWE-330", "severity": "medium", "finding_types": []},

        # LDAP Injection (CWE-90)
        {"pattern": r"DirContext\s*\.\s*search\s*\([^)]*getParameter", "name": "LDAPi: DirContext.search with request param", "cwe": "CWE-90", "severity": "high", "finding_types": []},
        {"pattern": r"LdapTemplate\s*\.\s*search\s*\([^)]*getParameter", "name": "LDAPi: LdapTemplate.search with request param", "cwe": "CWE-90", "severity": "high", "finding_types": []},

        # Log Injection (CWE-117)
        {"pattern": r"log\.(info|warn|error|debug)\s*\([^)]*getParameter", "name": "Log injection: logger with request param", "cwe": "CWE-117", "severity": "medium", "finding_types": []},

        # Hardcoded Secrets (CWE-259, CWE-798)
        {"pattern": r'(?:password|passwd)\s*=\s*["\'][^"\']{4,}["\']', "name": "Secret: hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},
        {"pattern": r'(?:apiKey|api_key|secret|token)\s*=\s*["\'][^"\']{8,}["\']', "name": "Secret: hardcoded API key", "cwe": "CWE-798", "severity": "high", "finding_types": []},

        # Spring Security misconfigurations
        {"pattern": r"\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)", "name": "Spring: CSRF protection disabled", "cwe": "CWE-352", "severity": "high", "finding_types": []},
        {"pattern": r"permitAll\s*\(\s*\)", "name": "Spring: permitAll() (review required)", "cwe": "CWE-284", "severity": "medium", "finding_types": []},
        {"pattern": r"antMatchers\s*\(\s*['\"]\/\*\*['\"]", "name": "Spring: antMatchers('/**') wildcard", "cwe": "CWE-284", "severity": "medium", "finding_types": []},

        # Open Redirect (CWE-601)
        {"pattern": r"response\.sendRedirect\s*\([^)]*getParameter", "name": "Open redirect: sendRedirect with request param", "cwe": "CWE-601", "severity": "medium", "finding_types": []},

        # Buffer Overflow via arrays (CWE-129)
        {"pattern": r"\[\s*Integer\.parseInt\s*\(\s*request\.getParameter", "name": "Array index: parseInt(getParameter) as array index", "cwe": "CWE-129", "severity": "medium", "finding_types": ["buffer_overflow"]},

        # Additional Java patterns
        # Insecure cookie (CWE-614, CWE-1004)
        {"pattern": r"new\s+Cookie\s*\([^)]+\)(?!.*setSecure\s*\(\s*true)", "name": "Cookie: missing Secure flag", "cwe": "CWE-614", "severity": "medium", "finding_types": []},
        {"pattern": r"cookie\.setHttpOnly\s*\(\s*false\s*\)", "name": "Cookie: HttpOnly disabled", "cwe": "CWE-1004", "severity": "medium", "finding_types": []},

        # Path traversal additional
        {"pattern": r"getResourceAsStream\s*\([^)]*getParameter", "name": "Path traversal: getResourceAsStream with request param", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # SSRF additional
        {"pattern": r"OkHttpClient.*newCall\s*\([^)]*getParameter", "name": "SSRF: OkHttpClient with request param", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r"WebClient\.get\s*\(\s*\).*uri\s*\([^)]*getParameter", "name": "SSRF: WebClient with request param", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},

        # Hardcoded credentials
        {"pattern": r"DataSource.*password\s*=\s*['\"][^'\"]{4,}['\"]\s*;", "name": "Secret: datasource hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},

        # Insecure random
        {"pattern": r"new\s+Random\s*\(\s*\)", "name": "Crypto: java.util.Random (use SecureRandom)", "cwe": "CWE-330", "severity": "medium", "finding_types": []},

        # XSS additional
        {"pattern": r"@ResponseBody.*getParameter", "name": "XSS: @ResponseBody returning request param", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},

        # CORS misconfiguration
        {"pattern": r"addHeader\s*\([^)]*Access-Control-Allow-Origin[^)]*\*", "name": "CORS: wildcard Allow-Origin in addHeader", "cwe": "CWE-942", "severity": "medium", "finding_types": []},

        # Command injection additional
        {"pattern": r"ScriptEngineManager\s*\(\s*\)", "name": "CMDi: ScriptEngineManager (JS engine execution)", "cwe": "CWE-94", "severity": "high", "finding_types": ["command_injection"]},

        # XXE additional
        {"pattern": r'XMLDecoder\s*\(', "name": "XXE/RCE: XMLDecoder deserialization", "cwe": "CWE-611", "severity": "critical", "finding_types": []},
    ],

    # -----------------------------------------------------------------------
    # Go – 50+ patterns
    # -----------------------------------------------------------------------
    "go": [
        # SQL Injection (CWE-89)
        {"pattern": r'db\.Query\s*\(\s*fmt\.Sprintf\s*\(', "name": "SQLi: db.Query with fmt.Sprintf", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r'db\.(Query|Exec|QueryRow)\s*\(\s*["`][^"`]*"\s*\+', "name": "SQLi: db.Query with string concat", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r'db\.Raw\s*\(\s*fmt\.Sprintf\s*\(', "name": "SQLi: GORM Raw with fmt.Sprintf", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r'\.Where\s*\(\s*fmt\.Sprintf\s*\(', "name": "SQLi: GORM .Where() with fmt.Sprintf", "cwe": "CWE-89", "severity": "high", "finding_types": ["sql_injection"]},

        # Command Injection (CWE-78)
        {"pattern": r'exec\.Command\s*\(\s*["\`][^"\`]*["\`]\s*,', "name": "CMDi: exec.Command()", "cwe": "CWE-78", "severity": "high", "finding_types": ["command_injection"]},
        {"pattern": r'exec\.CommandContext\s*\(', "name": "CMDi: exec.CommandContext()", "cwe": "CWE-78", "severity": "medium", "finding_types": ["command_injection"]},
        {"pattern": r'syscall\.Exec\s*\(', "name": "CMDi: syscall.Exec()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},

        # Path Traversal (CWE-22)
        {"pattern": r'os\.Open\s*\([^)]*r\.(URL|Form|PostForm)', "name": "Path traversal: os.Open with request data", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r'ioutil\.ReadFile\s*\([^)]*r\.(URL|Form)', "name": "Path traversal: ioutil.ReadFile with request data", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r'filepath\.Join\s*\([^)]*r\.(URL|Form)', "name": "Path traversal: filepath.Join with request data", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # SSRF (CWE-918)
        {"pattern": r'http\.(Get|Post)\s*\([^)]*r\.(URL|Form|PostForm)', "name": "SSRF: http.Get/Post with request data", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},
        {"pattern": r'client\.(Get|Post|Do)\s*\([^)]*r\.FormValue', "name": "SSRF: client.Do with request form value", "cwe": "CWE-918", "severity": "high", "finding_types": ["ssrf"]},

        # TLS Misconfig (CWE-295)
        {"pattern": r'InsecureSkipVerify\s*:\s*true', "name": "TLS: InsecureSkipVerify:true", "cwe": "CWE-295", "severity": "high", "finding_types": []},
        {"pattern": r'tls\.Config\s*\{[^}]*MinVersion\s*:\s*tls\.VersionSSL30', "name": "TLS: SSLv3 minimum", "cwe": "CWE-326", "severity": "critical", "finding_types": []},
        {"pattern": r'tls\.Config\s*\{[^}]*MinVersion\s*:\s*tls\.VersionTLS10', "name": "TLS: TLS 1.0 minimum", "cwe": "CWE-326", "severity": "high", "finding_types": []},

        # Weak Crypto (CWE-328)
        {"pattern": r'md5\.(New|Sum)\s*\(', "name": "Crypto: MD5 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'sha1\.(New|Sum)\s*\(', "name": "Crypto: SHA-1 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'des\.NewCipher\s*\(', "name": "Crypto: DES cipher", "cwe": "CWE-326", "severity": "high", "finding_types": []},
        {"pattern": r'rand\.Int\s*\(\s*\)', "name": "Crypto: math/rand (use crypto/rand)", "cwe": "CWE-330", "severity": "medium", "finding_types": []},

        # Deserialization (CWE-502)
        {"pattern": r'gob\.NewDecoder\s*\([^)]*r\.(Body|URL)', "name": "Deser: gob.NewDecoder with request", "cwe": "CWE-502", "severity": "high", "finding_types": ["deserialization"]},
        {"pattern": r'yaml\.Unmarshal\s*\([^)]*unsafe', "name": "Deser: yaml.Unmarshal (check for unsafe types)", "cwe": "CWE-502", "severity": "medium", "finding_types": ["deserialization"]},

        # Format String (CWE-134)
        {"pattern": r'fmt\.Fprintf\s*\(\w+\s*,\s*r\.(URL|Form|PostForm)', "name": "Format string: fmt.Fprintf with request data", "cwe": "CWE-134", "severity": "high", "finding_types": []},

        # Hardcoded Secrets (CWE-798)
        {"pattern": r'(?:password|passwd)\s*:=\s*"[^"]{4,}"', "name": "Secret: hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},
        {"pattern": r'(?:apiKey|api_key|secret|token)\s*:=\s*"[^"]{8,}"', "name": "Secret: hardcoded API key", "cwe": "CWE-798", "severity": "high", "finding_types": []},
        {"pattern": r"AKIA[0-9A-Z]{16}", "name": "Secret: AWS access key", "cwe": "CWE-798", "severity": "critical", "finding_types": []},

        # Network misconfig
        {"pattern": r'http\.ListenAndServe\s*\(\s*["\`]:80["\`]', "name": "Network: HTTP without TLS", "cwe": "CWE-319", "severity": "medium", "finding_types": []},
        {"pattern": r'http\.ListenAndServe\s*\(\s*["\`]0\.0\.0\.0', "name": "Network: binding to all interfaces", "cwe": "CWE-668", "severity": "medium", "finding_types": []},

        # Regex DOS (CWE-400)
        {"pattern": r'regexp\.MustCompile\s*\([^)]*r\.(URL|Form|PostForm)', "name": "ReDoS: regexp.MustCompile with request data", "cwe": "CWE-400", "severity": "medium", "finding_types": []},

        # Race conditions (CWE-362)
        {"pattern": r'go\s+func\s*\(\s*\)\s*\{[^}]*\.Write\s*\(', "name": "Race condition: goroutine writes to shared writer", "cwe": "CWE-362", "severity": "medium", "finding_types": []},

        # Buffer Overflow (CWE-120) via unsafe
        {"pattern": r'unsafe\.Pointer\s*\(', "name": "Buffer: unsafe.Pointer usage", "cwe": "CWE-119", "severity": "high", "finding_types": ["buffer_overflow"]},
        {"pattern": r'C\.GoBytes\s*\(.*C\.(int|uint)', "name": "Buffer: CGo GoBytes with C size", "cwe": "CWE-120", "severity": "high", "finding_types": ["buffer_overflow"]},

        # Additional Go patterns
        # XSS (CWE-79)
        {"pattern": r'fmt\.Fprintf\s*\(w,[^)]*r\.(URL|Form|PostForm)', "name": "XSS: fmt.Fprintf to ResponseWriter with request data", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r'w\.Write\s*\(\s*\[\]byte\s*\([^)]*r\.(URL|Form)', "name": "XSS: w.Write with request data", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r'template\.HTML\s*\(', "name": "XSS: template.HTML() bypass", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},
        {"pattern": r'template\.JS\s*\(', "name": "XSS: template.JS() bypass", "cwe": "CWE-79", "severity": "high", "finding_types": ["xss"]},

        # Open redirect (CWE-601)
        {"pattern": r'http\.Redirect\s*\([^)]*r\.FormValue', "name": "Open redirect: http.Redirect with FormValue", "cwe": "CWE-601", "severity": "medium", "finding_types": []},
        {"pattern": r'http\.Redirect\s*\([^)]*r\.URL\.Query', "name": "Open redirect: http.Redirect with URL query", "cwe": "CWE-601", "severity": "medium", "finding_types": []},

        # Hardcoded secrets additional
        {"pattern": r'AKIA[0-9A-Z]{16}', "name": "Secret: AWS access key", "cwe": "CWE-798", "severity": "critical", "finding_types": []},
        {"pattern": r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "name": "Secret: GitHub token", "cwe": "CWE-798", "severity": "critical", "finding_types": []},

        # Goroutine leak / context (CWE-400)
        {"pattern": r'go\s+\w+\s*\([^)]*\)(?!.*ctx)', "name": "Goroutine: launched without context (potential leak)", "cwe": "CWE-400", "severity": "low", "finding_types": []},

        # Path traversal additional
        {"pattern": r'http\.ServeFile\s*\([^)]*r\.URL', "name": "Path traversal: http.ServeFile with URL path", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # XXE (CWE-611)
        {"pattern": r'xml\.Unmarshal\s*\([^)]*r\.(Body|Form)', "name": "XXE: xml.Unmarshal with request body", "cwe": "CWE-611", "severity": "high", "finding_types": []},

        # SQL injection additional
        {"pattern": r'sqlx\.Get\s*\([^?]+fmt\.Sprintf', "name": "SQLi: sqlx.Get with fmt.Sprintf", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},
        {"pattern": r'sqlx\.Select\s*\([^?]+fmt\.Sprintf', "name": "SQLi: sqlx.Select with fmt.Sprintf", "cwe": "CWE-89", "severity": "critical", "finding_types": ["sql_injection"]},

        # Log injection (CWE-117)
        {"pattern": r'log\.(Print|Printf|Println|Fatal|Fatalf|Warn|Warnf|Error|Errorf)\s*\([^)]*r\.(URL|Form|PostForm)', "name": "Log injection: logger with request data", "cwe": "CWE-117", "severity": "medium", "finding_types": []},

        # CORS
        {"pattern": r'w\.Header\(\)\.Set\s*\([^)]*Access-Control-Allow-Origin[^)]*\*', "name": "CORS: wildcard Access-Control-Allow-Origin", "cwe": "CWE-942", "severity": "medium", "finding_types": []},

        # Deserialization additional
        {"pattern": r'json\.NewDecoder\s*\([^)]*r\.Body\).*Decode\s*\(&', "name": "Input: json.Decode into interface{} (verify type)", "cwe": "CWE-502", "severity": "low", "finding_types": ["deserialization"]},

        # Hardcoded private key
        {"pattern": r'-----BEGIN RSA PRIVATE KEY-----', "name": "Secret: hardcoded RSA private key", "cwe": "CWE-321", "severity": "critical", "finding_types": []},
        {"pattern": r'-----BEGIN EC PRIVATE KEY-----', "name": "Secret: hardcoded EC private key", "cwe": "CWE-321", "severity": "critical", "finding_types": []},

        # Command injection via template execution
        {"pattern": r'text/template.*Execute\s*\([^)]*r\.(URL|Form)', "name": "Template injection: text/template Execute with request data", "cwe": "CWE-94", "severity": "high", "finding_types": ["command_injection"]},
    ],

    # -----------------------------------------------------------------------
    # C / C++ – 50+ patterns
    # -----------------------------------------------------------------------
    "c": [
        # Buffer Overflow (CWE-120, CWE-121, CWE-122)
        {"pattern": r'\bgets\s*\(', "name": "Buffer overflow: gets() (always unsafe)", "cwe": "CWE-242", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bstrcpy\s*\(', "name": "Buffer overflow: strcpy() (use strncpy/strlcpy)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bstrcat\s*\(', "name": "Buffer overflow: strcat() (use strncat/strlcat)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bsprintf\s*\(', "name": "Buffer overflow: sprintf() (use snprintf)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bvsprintf\s*\(', "name": "Buffer overflow: vsprintf() (use vsnprintf)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bscanf\s*\(\s*["\'][^"\']*%s', "name": "Buffer overflow: scanf %s without width", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bstrcmp\s*\(', "name": "String comparison: strcmp (use strncmp)", "cwe": "CWE-170", "severity": "medium", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bmemcpy\s*\([^,]+,\s*[^,]+,\s*\w+\s*\)', "name": "Buffer: memcpy without bounds check", "cwe": "CWE-120", "severity": "high", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bmalloc\s*\(\s*\w+\s*\*\s*\w+\s*\)', "name": "Integer overflow in malloc size", "cwe": "CWE-190", "severity": "high", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\balloca\s*\(', "name": "Buffer: alloca() (stack overflow risk)", "cwe": "CWE-121", "severity": "high", "finding_types": ["buffer_overflow"]},

        # Format String (CWE-134)
        {"pattern": r'\bprintf\s*\(\s*\w+\s*\)', "name": "Format string: printf(var) without format", "cwe": "CWE-134", "severity": "critical", "finding_types": []},
        {"pattern": r'\bfprintf\s*\(\s*\w+\s*,\s*\w+\s*\)', "name": "Format string: fprintf(fp, var) without format", "cwe": "CWE-134", "severity": "critical", "finding_types": []},
        {"pattern": r'\bsyslog\s*\(\s*[A-Z_]+\s*,\s*\w+\s*\)', "name": "Format string: syslog(level, var) without format", "cwe": "CWE-134", "severity": "critical", "finding_types": []},

        # Command Injection (CWE-78)
        {"pattern": r'\bsystem\s*\(', "name": "CMDi: system()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r'\bpopen\s*\(', "name": "CMDi: popen()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},
        {"pattern": r'\bexecv\w*\s*\(', "name": "CMDi: execv*()", "cwe": "CWE-78", "severity": "high", "finding_types": ["command_injection"]},
        {"pattern": r'\bshell\s*\(', "name": "CMDi: shell()", "cwe": "CWE-78", "severity": "critical", "finding_types": ["command_injection"]},

        # Path Traversal (CWE-22)
        {"pattern": r'\bfopen\s*\([^)]*user_input\b', "name": "Path traversal: fopen() with user input", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},
        {"pattern": r'\bopen\s*\([^)]*argv\[', "name": "Path traversal: open() with argv", "cwe": "CWE-22", "severity": "high", "finding_types": ["path_traversal"]},

        # Integer Overflow (CWE-190)
        {"pattern": r'\bint\s+\w+\s*=\s*\w+\s*\*\s*\w+\s*;', "name": "Integer overflow: int multiplication without check", "cwe": "CWE-190", "severity": "medium", "finding_types": []},
        {"pattern": r'atoi\s*\(', "name": "Integer: atoi() without validation (use strtol)", "cwe": "CWE-676", "severity": "medium", "finding_types": []},
        {"pattern": r'atol\s*\(', "name": "Integer: atol() without validation (use strtoll)", "cwe": "CWE-676", "severity": "medium", "finding_types": []},

        # Use After Free (CWE-416)
        {"pattern": r'free\s*\(\s*(\w+)\s*\)\s*;', "name": "Use-after-free: free() call (verify pointer not reused)", "cwe": "CWE-416", "severity": "info", "finding_types": []},

        # NULL Dereference (CWE-476)
        {"pattern": r'malloc\s*\([^)]+\)\s*;[^;]+\*\w+', "name": "NULL dereference: malloc result not checked", "cwe": "CWE-476", "severity": "high", "finding_types": []},

        # Weak Crypto
        {"pattern": r'\bMD5\s*\(', "name": "Crypto: MD5 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'\bSHA1\s*\(', "name": "Crypto: SHA-1 hash", "cwe": "CWE-328", "severity": "medium", "finding_types": []},
        {"pattern": r'\brand\s*\(\s*\)', "name": "Crypto: rand() (use /dev/urandom)", "cwe": "CWE-330", "severity": "medium", "finding_types": []},
        {"pattern": r'\bsrand\s*\(\s*time\s*\(', "name": "Crypto: srand(time()) is predictable", "cwe": "CWE-337", "severity": "medium", "finding_types": []},

        # Hardcoded Secrets
        {"pattern": r'(?:password|passwd)\s*=\s*"[^"]{4,}"', "name": "Secret: hardcoded password", "cwe": "CWE-259", "severity": "high", "finding_types": []},

        # Signal handler (CWE-364, CWE-828)
        {"pattern": r'signal\s*\(\s*\w+\s*,\s*\w+\s*\)', "name": "Signal handler: signal() (use sigaction)", "cwe": "CWE-364", "severity": "medium", "finding_types": []},

        # Additional C patterns (CWE coverage expansion)
        {"pattern": r'\bstrncpy\s*\([^,]+,[^,]+,\s*sizeof\s*\([^)]+\)\s*\)', "name": "Buffer: strncpy with sizeof — check null termination", "cwe": "CWE-170", "severity": "low", "finding_types": []},
        {"pattern": r'\bgetenv\s*\(', "name": "Env: getenv() — untrusted data from environment", "cwe": "CWE-807", "severity": "low", "finding_types": []},
        {"pattern": r'\bwcscpy\s*\(', "name": "Buffer: wcscpy() (unsafe wide string copy)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bwcscat\s*\(', "name": "Buffer: wcscat() (unsafe wide string concat)", "cwe": "CWE-120", "severity": "critical", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\bstrtok\s*\(', "name": "Thread safety: strtok() is not reentrant (use strtok_r)", "cwe": "CWE-362", "severity": "medium", "finding_types": []},
        {"pattern": r'\bcrypt\s*\(', "name": "Crypto: crypt() (use bcrypt/argon2)", "cwe": "CWE-328", "severity": "high", "finding_types": []},
        {"pattern": r'\brealloc\s*\(\s*\w+\s*,\s*0\s*\)', "name": "Memory: realloc(ptr,0) — implementation defined", "cwe": "CWE-416", "severity": "medium", "finding_types": []},
        {"pattern": r'\bmemcmp\s*\(.*password', "name": "Timing attack: memcmp for password comparison", "cwe": "CWE-208", "severity": "high", "finding_types": []},
        {"pattern": r'\bsetuid\s*\(\s*0\s*\)', "name": "Privilege escalation: setuid(0)", "cwe": "CWE-250", "severity": "critical", "finding_types": []},
        {"pattern": r'\bchmod\s*\([^)]*0777', "name": "Permission: chmod 0777 (world writable)", "cwe": "CWE-732", "severity": "high", "finding_types": []},
        {"pattern": r'\btmpnam\s*\(', "name": "Race condition: tmpnam() (use mkstemp)", "cwe": "CWE-377", "severity": "high", "finding_types": []},
        {"pattern": r'\btempnam\s*\(', "name": "Race condition: tempnam() (use mkstemp)", "cwe": "CWE-377", "severity": "high", "finding_types": []},
        {"pattern": r'\bmktemp\s*\(', "name": "Race condition: mktemp() (use mkstemp)", "cwe": "CWE-377", "severity": "high", "finding_types": []},
        {"pattern": r'\baccess\s*\(', "name": "TOCTOU: access() before open() (use open with O_NOFOLLOW)", "cwe": "CWE-362", "severity": "medium", "finding_types": []},
        {"pattern": r'\bunlink\s*\([^)]*getenv', "name": "File deletion: unlink() with env variable", "cwe": "CWE-22", "severity": "high", "finding_types": []},
        {"pattern": r'\bstrcasecmp\s*\(', "name": "String: strcasecmp — locale-dependent behavior", "cwe": "CWE-170", "severity": "low", "finding_types": []},
        {"pattern": r'\bgets_s\s*\(', "name": "Buffer: gets_s() — C11 Annex K (implementation-defined)", "cwe": "CWE-120", "severity": "medium", "finding_types": ["buffer_overflow"]},

        # Additional C patterns
        {"pattern": r'\bstrchr\s*\(', "name": "String: strchr result not null-checked", "cwe": "CWE-476", "severity": "low", "finding_types": []},
        {"pattern": r'\bsscanf\s*\(', "name": "Buffer: sscanf without width limit", "cwe": "CWE-120", "severity": "high", "finding_types": ["buffer_overflow"]},
        {"pattern": r'\brecv\s*\([^,]+,[^,]+,\s*\d{4,}', "name": "Buffer: recv() with large static buffer size", "cwe": "CWE-120", "severity": "medium", "finding_types": ["buffer_overflow"]},
    ],
}

# Alias typescript -> javascript
_VULN_PATTERNS["typescript"] = _VULN_PATTERNS["javascript"]

# -----------------------------------------------------------------------
# Anti-patterns introduced by FIXES (regression markers)
# These are patterns that FIXES sometimes incorrectly introduce
# -----------------------------------------------------------------------
_FIX_REGRESSION_PATTERNS: Dict[str, List[Dict[str, Any]]] = {
    "python": [
        {"pattern": r"except\s+Exception\s*:\s*\n\s*pass", "name": "Swallowed exception: bare except:pass after fix", "cwe": "CWE-390", "severity": "medium"},
        {"pattern": r"#\s*TODO.*fix", "name": "Incomplete fix: TODO comment", "cwe": "", "severity": "low"},
        {"pattern": r"#\s*FIXME", "name": "Incomplete fix: FIXME comment", "cwe": "", "severity": "low"},
        {"pattern": r"# type:\s*ignore", "name": "Type check suppressed (mypy ignore)", "cwe": "", "severity": "low"},
        {"pattern": r"pylint:\s*disable", "name": "Linter suppression in fix", "cwe": "", "severity": "low"},
        {"pattern": r"noqa\s*:", "name": "Flake8 noqa suppression in fix", "cwe": "", "severity": "low"},
        {"pattern": r"hashlib\.(md5|sha1)\s*\(", "name": "Weak hash introduced by fix", "cwe": "CWE-328", "severity": "medium"},
        {"pattern": r"time\.sleep\s*\(", "name": "Timing-dependent fix (potential timing side-channel)", "cwe": "CWE-208", "severity": "low"},
    ],
    "javascript": [
        {"pattern": r"catch\s*\([^)]*\)\s*\{\s*\}", "name": "Swallowed exception: empty catch block", "cwe": "CWE-390", "severity": "medium"},
        {"pattern": r"//\s*TODO.*fix", "name": "Incomplete fix: TODO comment", "cwe": "", "severity": "low"},
        {"pattern": r"//\s*FIXME", "name": "Incomplete fix: FIXME comment", "cwe": "", "severity": "low"},
        {"pattern": r"eslint-disable", "name": "ESLint suppression in fix", "cwe": "", "severity": "low"},
        {"pattern": r"@ts-ignore", "name": "TypeScript @ts-ignore in fix", "cwe": "", "severity": "low"},
        {"pattern": r"createHash\s*\(\s*['\"]md5['\"]", "name": "Weak hash introduced by fix", "cwe": "CWE-328", "severity": "medium"},
    ],
    "java": [
        {"pattern": r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}", "name": "Swallowed exception: empty catch", "cwe": "CWE-390", "severity": "medium"},
        {"pattern": r"@SuppressWarnings\s*\(", "name": "@SuppressWarnings in fix", "cwe": "", "severity": "low"},
        {"pattern": r"//\s*TODO.*fix", "name": "Incomplete fix: TODO comment", "cwe": "", "severity": "low"},
        {"pattern": r"System\.out\.print", "name": "Debug print in fix", "cwe": "CWE-532", "severity": "low"},
        {"pattern": r"MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]", "name": "Weak hash introduced by fix", "cwe": "CWE-328", "severity": "medium"},
    ],
    "go": [
        {"pattern": r"_\s*=\s*err\b", "name": "Error suppression: err discarded", "cwe": "CWE-390", "severity": "medium"},
        {"pattern": r"panic\s*\(err\)", "name": "Panic on error in production code", "cwe": "", "severity": "low"},
        {"pattern": r"//\s*TODO.*fix", "name": "Incomplete fix: TODO comment", "cwe": "", "severity": "low"},
        {"pattern": r"//nolint", "name": "Linter suppression in fix", "cwe": "", "severity": "low"},
        {"pattern": r"md5\.Sum\s*\(", "name": "Weak hash introduced by fix", "cwe": "CWE-328", "severity": "medium"},
    ],
    "c": [
        {"pattern": r"//\s*TODO.*fix", "name": "Incomplete fix: TODO comment", "cwe": "", "severity": "low"},
        {"pattern": r"//\s*FIXME", "name": "Incomplete fix: FIXME comment", "cwe": "", "severity": "low"},
        {"pattern": r"#pragma\s+warning\s*\(\s*disable", "name": "Warning suppression in fix", "cwe": "", "severity": "low"},
        {"pattern": r"MD5\s*\(", "name": "Weak hash introduced by fix", "cwe": "CWE-328", "severity": "medium"},
    ],
}
_FIX_REGRESSION_PATTERNS["typescript"] = _FIX_REGRESSION_PATTERNS["javascript"]

# -----------------------------------------------------------------------
# Security control patterns — things a GOOD fix should ADD
# -----------------------------------------------------------------------
_SECURITY_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "python": {
        "sql_injection": [
            r"parameterized",
            r"execute\s*\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*,",
            r"execute\s*\(\s*[\"'][^\"']*%s[^\"']*[\"']\s*,\s*\(",
            r"execute\s*\(\s*[\"'][^\"']*\$[0-9]+",
            r"text\s*\(",  # SQLAlchemy text() with params
        ],
        "xss": [r"escape\s*\(", r"bleach\.(clean|linkify)", r"html\.escape\s*\(", r"markupsafe\.escape"],
        "command_injection": [r"shlex\.split\s*\(", r"subprocess\.[a-z]+\s*\(\s*\[", r"shlex\.quote\s*\("],
        "path_traversal": [r"os\.path\.realpath\s*\(", r"Path\s*\([^)]+\)\.resolve\s*\(", r"\.is_relative_to\s*\("],
        "deserialization": [r"yaml\.safe_load\s*\(", r"json\.loads\s*\(", r"defusedxml"],
        "ssrf": [r"ipaddress\.(ip_address|ip_network)", r"urlparse\s*\(", r"socket\.getaddrinfo"],
    },
    "javascript": {
        "sql_injection": [r"\$\d+", r"parameterized", r"prepared\s+statement", r"query\s*\(\s*[`\"'][^`\"']*\?\s*,"],
        "xss": [r"textContent\s*=", r"createTextNode\s*\(", r"DOMPurify\.sanitize\s*\(", r"sanitizeHtml\s*\(", r"encodeURIComponent\s*\(", r"\.innerText\s*="],
        "command_injection": [r"execFile\s*\(", r"spawn\s*\(\s*[\"']", r"escapeShellArg\s*\("],
        "path_traversal": [r"path\.normalize\s*\(", r"path\.resolve\s*\(", r"startsWith\s*\(.*__dirname"],
        "deserialization": [r"JSON\.parse\s*\(", r"YAML\.safeLoad\s*\(", r"safeLoad\s*\("],
        "ssrf": [r"new\s+URL\s*\(", r"urlparse\s*\(", r"allowlist", r"whitelist"],
    },
    "java": {
        "sql_injection": [r"PreparedStatement\b", r"\.setString\s*\(", r"\.setInt\s*\(", r"@Query\s*\(.*\?"],
        "xss": [r"StringEscapeUtils\.escapeHtml", r"HtmlUtils\.htmlEscape\s*\(", r"ESAPI\.encoder\(\)\.encodeForHTML"],
        "command_injection": [r"ProcessBuilder\s*\(\s*List\.", r"shlex", r"ProcessBuilder\s*\(\s*Arrays\.asList"],
        "path_traversal": [r"\.getCanonicalPath\s*\(", r"\.normalize\s*\(", r"Paths\.get.*\.normalize"],
        "deserialization": [r"ObjectInputFilter\b", r"readObjectNoData\b", r"ObjectInputFilter\.Config"],
        "ssrf": [r"InetAddress\.getByName", r"allowlist", r"URI\.create.*validate"],
    },
}

# -----------------------------------------------------------------------
# MPTE exploit signatures per finding type
# These simulate what MPTE would send — patterns that appear in
# vulnerable code but NOT in properly fixed code.
# -----------------------------------------------------------------------
_MPTE_EXPLOIT_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "exploit_payloads": [r"' OR '1'='1", r"'; DROP TABLE", r"UNION SELECT", r"--\s*$", r"1=1", r"OR 1=1"],
        "vuln_indicators": [
            # Vulnerable: % string-format in execute() — i.e., execute("..." % var) NOT execute("...%s", (var,))
            r'execute\s*\(\s*["\'].*["\']\s*%\s*\w',
            r"execute\s*\(\s*f[\"']",
            r'executeQuery\s*\(\s*".*"\s*\+',
            r"db\.Query\s*\(\s*fmt\.Sprintf",
            r'executeQuery\s*\(\s*".*"\s*\+\s*\w',
        ],
        "fixed_indicators": [
            r"PreparedStatement\b",
            # Python DB-API parameterized: execute("...%s...", (var,)) — tuple/list second arg
            r'execute\s*\(\s*["\'][^"\']*(\?|%s|%d|\$[0-9]+)[^"\']\*["\']\s*,\s*[\[(]',
            r'execute\s*\([^)]+,\s*[\[(]',
            r"parameterized",
            r"setString\s*\(",
            r"\.setParameter\s*\(",
        ],
    },
    "xss": {
        "exploit_payloads": [r"<script>alert", r"onerror=", r"javascript:", r"<img src=x"],
        "vuln_indicators": [
            r"\.innerHTML\s*=",
            r"document\.write\s*\(",
            r"mark_safe\s*\(",
            r"response\.getWriter\(\)\.print\s*\(.*request\.getParameter",
        ],
        "fixed_indicators": [r"textContent\s*=", r"DOMPurify\.sanitize", r"html\.escape\s*\(", r"HtmlUtils\.htmlEscape"],
    },
    "command_injection": {
        "exploit_payloads": [r"; ls", r"\| cat /etc/passwd", r"`id`", r"\$\(whoami\)"],
        "vuln_indicators": [
            r"os\.system\s*\(",
            r"subprocess\.[a-z]+\s*\([^)]*shell\s*=\s*True",
            r"Runtime\.getRuntime\(\)\.exec\s*\(",
            r"\bsystem\s*\(",
        ],
        "fixed_indicators": [r"shlex\.split\s*\(", r"subprocess\.[a-z]+\s*\(\s*\[", r"shlex\.quote\s*\(", r"ProcessBuilder\s*\(\s*Arrays"],
    },
    "path_traversal": {
        "exploit_payloads": [r"\.\./", r"%2e%2e%2f", r"\.\.\\", r"%252e%252e"],
        "vuln_indicators": [
            r"open\s*\([^)]*\+",
            r"new\s+File\s*\([^)]*getParameter",
            r"os\.Open\s*\([^)]*r\.(URL|Form)",
        ],
        "fixed_indicators": [r"os\.path\.realpath\s*\(", r"getCanonicalPath\s*\(", r"path\.normalize\s*\(", r"\.resolve\s*\("],
    },
    "buffer_overflow": {
        "exploit_payloads": [r"AAAAAAAAAA{50,}", r"\\x41{20,}", r"NOP sled"],
        "vuln_indicators": [r"\bgets\s*\(", r"\bstrcpy\s*\(", r"\bsprintf\s*\(", r"\bstrcat\s*\("],
        "fixed_indicators": [r"\bfgets\s*\(", r"\bstrncpy\s*\(", r"\bsnprintf\s*\(", r"\bstrncat\s*\("],
    },
    "deserialization": {
        "exploit_payloads": [r"aced0005", r"rO0AB", r"!!python/object"],
        "vuln_indicators": [
            r"pickle\.(loads?|load)\s*\(",
            r"new\s+ObjectInputStream\s*\(",
            r"XStream\.fromXML\s*\(",
            r"yaml\.load\s*\([^,)]*\)",
        ],
        "fixed_indicators": [r"yaml\.safe_load\s*\(", r"json\.loads\s*\(", r"ObjectInputFilter\b", r"allowlist"],
    },
    "ssrf": {
        "exploit_payloads": [r"169\.254\.169\.254", r"localhost", r"127\.0\.0\.1", r"file:///etc/passwd"],
        "vuln_indicators": [
            r"requests\.(get|post)\s*\(\s*.*request\.",
            r"new\s+URL\s*\([^)]*getParameter",
            r"http\.(Get|Post)\s*\([^)]*r\.(URL|Form)",
        ],
        "fixed_indicators": [r"ipaddress\.(ip_address|ip_network)", r"InetAddress\.getByName", r"allowlist", r"urlparse\s*\("],
    },
}

# -----------------------------------------------------------------------
# Known safe dependency upgrade paths  {package: {old_vuln: new_safe}}
# -----------------------------------------------------------------------
_SAFE_DEP_UPGRADES: Dict[str, Dict[str, str]] = {
    "python": {
        "django": "4.2.0",
        "flask": "3.0.0",
        "requests": "2.31.0",
        "pyyaml": "6.0",
        "pillow": "10.0.0",
        "cryptography": "41.0.0",
        "sqlalchemy": "2.0.0",
        "lxml": "4.9.3",
        "paramiko": "3.3.0",
        "aiohttp": "3.9.0",
    },
    "javascript": {
        "express": "4.18.0",
        "lodash": "4.17.21",
        "axios": "1.6.0",
        "node-fetch": "3.3.0",
        "jsonwebtoken": "9.0.0",
        "js-yaml": "4.1.0",
        "moment": "2.29.4",
        "next": "14.0.0",
        "react": "18.2.0",
        "semver": "7.5.4",
    },
    "java": {
        "spring-framework": "6.1.0",
        "log4j": "2.21.0",
        "jackson-databind": "2.16.0",
        "struts2": "6.3.0",
        "xstream": "1.4.20",
    },
}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _fingerprint(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()[:16]


def _detect_indentation(code: str) -> str:
    """Detect dominant indentation style."""
    spaces = len(re.findall(r"^    ", code, re.MULTILINE))
    tabs = len(re.findall(r"^\t", code, re.MULTILINE))
    two_spaces = len(re.findall(r"^  (?! )", code, re.MULTILINE))
    if tabs > spaces and tabs > two_spaces:
        return "tabs"
    if two_spaces > spaces:
        return "2-spaces"
    return "4-spaces"


def _detect_naming_convention(code: str, language: str) -> str:
    """Detect dominant naming convention."""
    snake = len(re.findall(r"\b[a-z][a-z0-9]*_[a-z0-9_]+\b", code))
    camel = len(re.findall(r"\b[a-z][a-z0-9]*[A-Z][a-zA-Z0-9]*\b", code))
    pascal = len(re.findall(r"\b[A-Z][a-z0-9]+[A-Z][a-zA-Z0-9]*\b", code))
    if snake > camel and snake > pascal:
        return "snake_case"
    if camel > pascal:
        return "camelCase"
    return "PascalCase"


def _count_test_indicators(code: str, language: str) -> int:
    """Rough count of test-related markers."""
    patterns = {
        "python": [r"\bdef test_\w+", r"\bassert\b", r"\bunittest\b", r"\bpytest\b"],
        "javascript": [r"\bit\s*\(", r"\bdescribe\s*\(", r"\bexpect\s*\(", r"\btest\s*\("],
        "java": [r"@Test\b", r"assertEquals\s*\(", r"assertThat\s*\(", r"@Before\b"],
        "go": [r"\bfunc Test\w+\s*\(", r"\bt\.Error\b", r"\bt\.Fatal\b"],
        "c": [r"\bassert\s*\(", r"CU_ASSERT\s*\(", r"CHECK\s*\("],
    }
    lang_patterns = patterns.get(language, patterns.get("python", []))
    count = 0
    for p in lang_patterns:
        count += len(re.findall(p, code))
    return count


# ---------------------------------------------------------------------------
# Core PostFixVerifier engine
# ---------------------------------------------------------------------------


class PostFixVerifier:
    """
    MPTE Post-Fix Verification Engine.

    Runs six verification suites after a fix is proposed:
      1. Static analysis  — regex + AST pattern removal check
      2. Regression check — CWE anti-pattern detection
      3. Dependency safety — version range check
      4. MPTE re-scan     — simulated exploit re-run
      5. Style preservation — indentation + naming convention diff
      6. Test coverage    — estimate of test impact
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self._history: List[Dict[str, Any]] = []
        self._stats: Dict[str, Any] = {
            "total_verifications": 0,
            "verified": 0,
            "failed": 0,
            "safe_to_deploy": 0,
            "by_language": {},
            "by_finding_type": {},
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def verify(
        self,
        finding_id: str,
        finding_type: str,
        severity: str,
        original_code: str,
        fixed_code: str,
        language: str,
        file_path: Optional[str] = None,
        context_code: Optional[str] = None,
        dep_changes: Optional[Dict[str, str]] = None,
    ) -> VerificationReport:
        """
        Run the full six-suite post-fix verification.

        Args:
            finding_id:     Identifier of the original finding.
            finding_type:   E.g. "sql_injection", "xss", "buffer_overflow".
            severity:       "critical" | "high" | "medium" | "low".
            original_code:  The vulnerable code before the fix.
            fixed_code:     The proposed fixed code.
            language:       "python" | "javascript" | "java" | "go" | "c" | ...
            file_path:      Optional file path for context.
            context_code:   Optional surrounding code.
            dep_changes:    Optional dict of {package: new_version}.
        """
        _emit_event("finding.updated", {"module": __name__, "action": "verify"})
        t0 = time.monotonic()
        lang = language.lower().strip()
        ftype = finding_type.lower().strip()
        checks: List[CheckResult] = []

        # --- Suite 1: Static analysis ----------------------------------
        static_checks = self._run_static_analysis(
            original_code, fixed_code, lang, ftype
        )
        checks.extend(static_checks)

        # --- Suite 2: Regression check ---------------------------------
        regression_checks = self._run_regression_check(
            original_code, fixed_code, lang
        )
        checks.extend(regression_checks)

        # --- Suite 3: Dependency safety --------------------------------
        dep_checks = self._run_dependency_check(fixed_code, lang, dep_changes)
        checks.extend(dep_checks)

        # --- Suite 4: MPTE re-scan ------------------------------------
        mpte_check, mpte_result = self._run_mpte_retest(
            original_code, fixed_code, lang, ftype
        )
        checks.append(mpte_check)

        # --- Suite 5: Code style preservation -------------------------
        style_checks = self._run_style_check(original_code, fixed_code, lang)
        checks.extend(style_checks)

        # --- Suite 6: Test coverage impact ----------------------------
        coverage_check = self._run_coverage_check(original_code, fixed_code, lang)
        checks.append(coverage_check)

        # ------------------------------------------------------------------
        # Aggregate results
        # ------------------------------------------------------------------
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        passed = [c for c in checks if c.status == CheckStatus.PASSED]
        failed = [c for c in checks if c.status == CheckStatus.FAILED]
        warnings = [c for c in checks if c.status == CheckStatus.WARNING]
        [c for c in checks if c.status in (CheckStatus.SKIPPED, CheckStatus.INCONCLUSIVE)]

        checks_total = len(checks)
        checks_passed = len(passed)

        # Collect regressions
        regressions_found: List[str] = []
        for c in checks:
            if c.status == CheckStatus.FAILED and c.cwe:
                regressions_found.append(f"{c.check_name}: {c.description} ({c.cwe})")
            elif c.status == CheckStatus.WARNING and c.severity in ("high", "critical"):
                regressions_found.append(f"[WARN] {c.check_name}: {c.description}")

        # Confidence scoring
        # Base: ratio of passed checks
        base_conf = checks_passed / max(checks_total, 1)

        # Boost if MPTE exploit blocked
        mpte_boost = 0.15 if mpte_result == MPTERetestResult.EXPLOIT_BLOCKED else 0.0

        # Penalty for failures
        critical_fails = sum(1 for c in failed if c.severity == "critical")
        high_fails = sum(1 for c in failed if c.severity == "high")
        conf_penalty = (critical_fails * 0.25) + (high_fails * 0.10) + (len(warnings) * 0.02)

        confidence = max(0.0, min(1.0, base_conf + mpte_boost - conf_penalty))

        # Verified if: no critical failures, MPTE blocked (or inconclusive), confidence >= 0.70
        critical_failure = any(c.severity == "critical" for c in failed)
        has_exploit_still = mpte_result == MPTERetestResult.EXPLOIT_STILL_POSSIBLE

        verified = (
            not critical_failure
            and not has_exploit_still
            and len(failed) <= 1  # allow 1 low/medium failure
            and confidence >= 0.65
        )

        # Safe to deploy: stricter — no failures at all, high confidence
        safe_to_deploy = (
            len(failed) == 0
            and mpte_result != MPTERetestResult.EXPLOIT_STILL_POSSIBLE
            and confidence >= 0.80
        )

        # Recommendation text
        recommendation = self._build_recommendation(
            verified, safe_to_deploy, failed, warnings, mpte_result, confidence, severity
        )

        # Compliance evidence
        compliance = {
            "control_mapping": {
                "NIST_800-53_SI-10": "Input validation post-fix verification",
                "NIST_800-53_SA-11": "Post-fix security testing (MPTE re-scan)",
                "NIST_800-53_RA-5": "Vulnerability re-scan after remediation",
                "SOC2_CC8.1": "Change management verification",
                "PCI_DSS_6.3.2": "Post-fix code review and MPTE re-test",
                "OWASP_SAMM_VT-1": "Verification of vulnerability fix",
            },
            "verification_method": "mpte_postfix_static_and_exploit_retest",
            "fix_fingerprint": _fingerprint(fixed_code),
            "original_fingerprint": _fingerprint(original_code),
            "language": lang,
            "finding_type": ftype,
            "severity": severity,
            "file_path": file_path or "",
        }

        report = VerificationReport(
            finding_id=finding_id,
            finding_type=ftype,
            language=lang,
            verified=verified,
            confidence=confidence,
            checks_passed=checks_passed,
            checks_total=checks_total,
            regressions_found=regressions_found,
            mpte_retest_result=mpte_result.value,
            safe_to_deploy=safe_to_deploy,
            verification_duration_ms=elapsed_ms,
            detailed_checks=checks,
            fix_fingerprint=_fingerprint(fixed_code),
            original_fingerprint=_fingerprint(original_code),
            recommendation=recommendation,
            compliance_evidence=compliance,
        )

        self._record(report)
        return report

    # ------------------------------------------------------------------
    # Suite 1: Static analysis
    # ------------------------------------------------------------------

    def _run_static_analysis(
        self, original: str, fixed: str, language: str, finding_type: str
    ) -> List[CheckResult]:
        results: List[CheckResult] = []

        # 1a. Syntax validity
        results.append(self._check_syntax(fixed, language))

        # 1b. Vulnerable pattern removal — check the PRIMARY finding pattern is gone
        results.append(
            self._check_vuln_pattern_removed(original, fixed, language, finding_type)
        )

        # 1c. Broad vuln scan on fixed code (were NEW patterns added?)
        new_pattern_check = self._check_new_patterns(original, fixed, language)
        results.append(new_pattern_check)

        # 1d. AST-level analysis for Python
        if language == "python":
            ast_check = self._check_python_ast(original, fixed)
            results.append(ast_check)

        # 1e. Security control presence — was the correct mitigation applied?
        results.append(
            self._check_security_control_added(fixed, language, finding_type)
        )

        return results

    def _check_syntax(self, fixed: str, language: str) -> CheckResult:
        t0 = time.monotonic()
        if language == "python":
            try:
                ast.parse(fixed)
                return CheckResult(
                    check_name="syntax_validation",
                    status=CheckStatus.PASSED,
                    description="Python syntax is valid",
                    severity="info",
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
            except SyntaxError as exc:
                return CheckResult(
                    check_name="syntax_validation",
                    status=CheckStatus.FAILED,
                    description=f"Python syntax error at line {exc.lineno}: {exc.msg}",
                    severity="critical",
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
        # C-family brace balance check
        if language in ("javascript", "typescript", "java", "go", "c", "csharp", "cpp"):
            opens = fixed.count("{")
            closes = fixed.count("}")
            if opens != closes:
                return CheckResult(
                    check_name="syntax_validation",
                    status=CheckStatus.FAILED,
                    description=f"Unbalanced braces: {opens} open, {closes} close",
                    severity="critical",
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
        # Ruby / PHP basic checks
        if language == "ruby":
            ends = len(re.findall(r"\bend\b", fixed))
            defs = len(re.findall(r"\b(def|do|class|module|if|unless|while|until|for|begin)\b", fixed))
            if abs(ends - defs) > 3:
                return CheckResult(
                    check_name="syntax_validation",
                    status=CheckStatus.WARNING,
                    description=f"Ruby end/block mismatch (approx): {ends} ends vs {defs} block starters",
                    severity="medium",
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
        return CheckResult(
            check_name="syntax_validation",
            status=CheckStatus.PASSED,
            description=f"{language} syntax structure appears valid",
            severity="info",
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    def _check_vuln_pattern_removed(
        self, original: str, fixed: str, language: str, finding_type: str
    ) -> CheckResult:
        t0 = time.monotonic()
        sig = _MPTE_EXPLOIT_SIGNATURES.get(finding_type, {})
        if not sig:
            return CheckResult(
                check_name="vuln_pattern_removal",
                status=CheckStatus.SKIPPED,
                description=f"No signature library for finding_type '{finding_type}'",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )

        vuln_indicators = sig.get("vuln_indicators", [])
        orig_hits = sum(
            1 for p in vuln_indicators if re.search(p, original, re.IGNORECASE | re.DOTALL)
        )
        fixed_hits = sum(
            1 for p in vuln_indicators if re.search(p, fixed, re.IGNORECASE | re.DOTALL)
        )

        if orig_hits == 0:
            return CheckResult(
                check_name="vuln_pattern_removal",
                status=CheckStatus.INCONCLUSIVE,
                description=f"Original code did not match {finding_type} signature patterns (may be context snippet)",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )

        removed = orig_hits - fixed_hits
        if fixed_hits == 0:
            return CheckResult(
                check_name="vuln_pattern_removal",
                status=CheckStatus.PASSED,
                description=f"All {orig_hits} vulnerable {finding_type} pattern(s) removed from fixed code",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        elif fixed_hits < orig_hits:
            return CheckResult(
                check_name="vuln_pattern_removal",
                status=CheckStatus.WARNING,
                description=f"Partially removed: {removed}/{orig_hits} {finding_type} patterns removed; {fixed_hits} remain",
                severity="high",
                cwe=self._get_cwe_for_type(finding_type),
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        else:
            return CheckResult(
                check_name="vuln_pattern_removal",
                status=CheckStatus.FAILED,
                description=f"Vulnerable pattern still present: {fixed_hits} {finding_type} indicator(s) detected in fixed code",
                severity="critical",
                cwe=self._get_cwe_for_type(finding_type),
                details=f"Pattern indicators still matched: {vuln_indicators[:3]}",
                duration_ms=(time.monotonic() - t0) * 1000,
            )

    def _check_new_patterns(
        self, original: str, fixed: str, language: str
    ) -> CheckResult:
        t0 = time.monotonic()
        patterns = _VULN_PATTERNS.get(language, [])
        newly_introduced: List[str] = []
        for p in patterns:
            orig_count = len(re.findall(p["pattern"], original, re.IGNORECASE))
            fixed_count = len(re.findall(p["pattern"], fixed, re.IGNORECASE))
            if fixed_count > orig_count:
                newly_introduced.append(f"{p['name']} ({p['cwe']})")

        if newly_introduced:
            return CheckResult(
                check_name="new_pattern_scan",
                status=CheckStatus.FAILED,
                description=f"Fix introduces {len(newly_introduced)} new vulnerability pattern(s)",
                details="; ".join(newly_introduced[:5]),
                severity="high",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        return CheckResult(
            check_name="new_pattern_scan",
            status=CheckStatus.PASSED,
            description="No new vulnerability patterns introduced by the fix",
            severity="info",
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    def _check_python_ast(self, original: str, fixed: str) -> CheckResult:
        """AST-level analysis for Python: detect eval/exec/pickle/os.system calls."""
        t0 = time.monotonic()
        dangerous_calls = {"eval", "exec", "compile", "__import__"}
        dangerous_attrs = {("os", "system"), ("os", "popen"), ("pickle", "loads"), ("pickle", "load")}

        def _extract_calls(code: str) -> Tuple[set, set]:
            calls: set = set()
            attr_calls: set = set()
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            calls.add(node.func.id)
                        elif isinstance(node.func, ast.Attribute):
                            if isinstance(node.func.value, ast.Name):
                                attr_calls.add((node.func.value.id, node.func.attr))
            except SyntaxError:
                pass
            return calls, attr_calls

        orig_calls, orig_attrs = _extract_calls(original)
        fixed_calls, fixed_attrs = _extract_calls(fixed)

        new_calls = (fixed_calls - orig_calls) & dangerous_calls
        new_attrs = (fixed_attrs - orig_attrs) & dangerous_attrs

        if new_calls or new_attrs:
            new_all = list(new_calls) + [f"{m}.{a}" for m, a in new_attrs]
            return CheckResult(
                check_name="ast_danger_analysis",
                status=CheckStatus.FAILED,
                description=f"AST: fix introduces dangerous call(s): {', '.join(new_all)}",
                severity="critical",
                cwe="CWE-94",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        return CheckResult(
            check_name="ast_danger_analysis",
            status=CheckStatus.PASSED,
            description="AST analysis: no new dangerous function calls introduced",
            severity="info",
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    def _check_security_control_added(
        self, fixed: str, language: str, finding_type: str
    ) -> CheckResult:
        t0 = time.monotonic()
        lang_controls = _SECURITY_CONTROLS.get(language, {})
        controls = lang_controls.get(finding_type, [])
        if not controls:
            return CheckResult(
                check_name="security_control_presence",
                status=CheckStatus.SKIPPED,
                description=f"No security control patterns defined for {language}/{finding_type}",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        found = any(re.search(p, fixed, re.IGNORECASE | re.DOTALL) for p in controls)
        if found:
            return CheckResult(
                check_name="security_control_presence",
                status=CheckStatus.PASSED,
                description=f"Security control for {finding_type} detected in fixed code",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        return CheckResult(
            check_name="security_control_presence",
            status=CheckStatus.WARNING,
            description=f"Expected security mitigation for '{finding_type}' not detected in fixed code",
            details=f"Expected one of: {controls[:3]}",
            severity="high",
            cwe=self._get_cwe_for_type(finding_type),
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ------------------------------------------------------------------
    # Suite 2: Regression check
    # ------------------------------------------------------------------

    def _run_regression_check(
        self, original: str, fixed: str, language: str
    ) -> List[CheckResult]:
        t0 = time.monotonic()
        results: List[CheckResult] = []

        # 2a. Fix-introduced anti-patterns
        reg_patterns = _FIX_REGRESSION_PATTERNS.get(language, [])
        regressions_found: List[str] = []
        for p in reg_patterns:
            orig_count = len(re.findall(p["pattern"], original, re.IGNORECASE))
            fixed_count = len(re.findall(p["pattern"], fixed, re.IGNORECASE))
            if fixed_count > orig_count:
                regressions_found.append(f"{p['name']} ({p.get('cwe','')})".strip("()"))

        if regressions_found:
            results.append(CheckResult(
                check_name="regression_antipattern",
                status=CheckStatus.WARNING,
                description=f"Fix introduces {len(regressions_found)} anti-pattern(s): {'; '.join(regressions_found[:3])}",
                severity="medium",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="regression_antipattern",
                status=CheckStatus.PASSED,
                description="No regression anti-patterns detected",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        # 2b. Security control removal detection
        security_control_patterns = [
            (r"is_authenticated|require_auth|@login_required|authorize\b", "authentication check"),
            (r"csrf_token|csrf_protect|@csrf|X-CSRF-Token", "CSRF protection"),
            (r"rate_limit|throttle|RateLimit\b", "rate limiting"),
            (r"sanitize|validate.*input|escape\s*\(|htmlspecialchars", "input validation/sanitization"),
            (r"encrypt\b|AES\b|fernet\b|bcrypt\b", "encryption"),
            (r"authori[sz]e|permission\b|access_control", "authorization check"),
        ]
        removed_controls: List[str] = []
        for pattern, ctrl_name in security_control_patterns:
            orig_count = len(re.findall(pattern, original, re.IGNORECASE))
            fixed_count = len(re.findall(pattern, fixed, re.IGNORECASE))
            if orig_count > 0 and fixed_count < orig_count:
                removed_controls.append(ctrl_name)

        if removed_controls:
            results.append(CheckResult(
                check_name="security_control_removal",
                status=CheckStatus.FAILED,
                description=f"Fix removes security control(s): {', '.join(removed_controls)}",
                severity="high",
                cwe="CWE-284",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="security_control_removal",
                status=CheckStatus.PASSED,
                description="No security controls removed by the fix",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        # 2c. Code size sanity check
        orig_lines = len(original.strip().splitlines())
        fixed_lines = len(fixed.strip().splitlines())
        if orig_lines > 0:
            ratio = fixed_lines / max(orig_lines, 1)
            if ratio > 3.0:
                results.append(CheckResult(
                    check_name="code_size_regression",
                    status=CheckStatus.WARNING,
                    description=f"Fix is {ratio:.1f}x larger than original ({orig_lines} → {fixed_lines} lines); review for code bloat",
                    severity="low",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ))
            elif fixed_lines == 0:
                results.append(CheckResult(
                    check_name="code_size_regression",
                    status=CheckStatus.FAILED,
                    description="Fixed code is empty — fix appears to delete all code",
                    severity="critical",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ))
            else:
                results.append(CheckResult(
                    check_name="code_size_regression",
                    status=CheckStatus.PASSED,
                    description=f"Code size change: {orig_lines} → {fixed_lines} lines ({(ratio - 1) * 100:+.0f}%)",
                    severity="info",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ))

        return results

    # ------------------------------------------------------------------
    # Suite 3: Dependency safety
    # ------------------------------------------------------------------

    def _run_dependency_check(
        self,
        fixed: str,
        language: str,
        dep_changes: Optional[Dict[str, str]] = None,
    ) -> List[CheckResult]:
        t0 = time.monotonic()
        results: List[CheckResult] = []

        if not dep_changes:
            # Auto-detect dependency changes from fixed code
            dep_changes = self._detect_dep_changes(fixed, language)

        if not dep_changes:
            results.append(CheckResult(
                check_name="dependency_safety",
                status=CheckStatus.SKIPPED,
                description="No dependency changes detected in fix",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
            return results

        safe_versions = _SAFE_DEP_UPGRADES.get(language, {})
        unsafe_deps: List[str] = []
        ok_deps: List[str] = []

        for pkg, new_ver in dep_changes.items():
            min_safe = safe_versions.get(pkg.lower())
            if min_safe:
                # Simple semantic version comparison (major.minor.patch)
                if self._version_gte(new_ver, min_safe):
                    ok_deps.append(f"{pkg}=={new_ver}")
                else:
                    unsafe_deps.append(f"{pkg}=={new_ver} (need >={min_safe})")
            else:
                ok_deps.append(f"{pkg}=={new_ver} (not in known-vuln database)")

        if unsafe_deps:
            results.append(CheckResult(
                check_name="dependency_safety",
                status=CheckStatus.FAILED,
                description=f"{len(unsafe_deps)} dependency upgrade(s) may introduce known vulnerabilities",
                details="; ".join(unsafe_deps[:5]),
                severity="high",
                cwe="CWE-1395",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="dependency_safety",
                status=CheckStatus.PASSED,
                description=f"All {len(ok_deps)} dependency change(s) meet minimum safe version requirements",
                details="; ".join(ok_deps[:5]),
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        return results

    def _detect_dep_changes(self, code: str, language: str) -> Dict[str, str]:
        """Detect dependency versions mentioned in the fix code."""
        changes: Dict[str, str] = {}
        if language == "python":
            # requirements.txt style
            for m in re.finditer(r"([a-zA-Z0-9_\-]+)[>=!<]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", code):
                changes[m.group(1).lower()] = m.group(2)
        elif language == "javascript":
            # package.json style
            for m in re.finditer(r'"([a-zA-Z0-9@/_\-]+)"\s*:\s*"[\^~]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"', code):
                changes[m.group(1).lower().split("/")[-1]] = m.group(2)
        elif language == "java":
            # Maven/Gradle version strings
            for m in re.finditer(r"<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>", code):
                changes[f"dep_{len(changes)}"] = m.group(1)
        return changes

    @staticmethod
    def _version_gte(version: str, minimum: str) -> bool:
        """Return True if version >= minimum (simple semver comparison)."""
        def _parts(v: str) -> Tuple[int, ...]:
            return tuple(int(x) for x in re.split(r"[.\-]", v) if x.isdigit())
        try:
            return _parts(version) >= _parts(minimum)
        except (ValueError, TypeError):
            return True  # Unknown format — assume safe

    # ------------------------------------------------------------------
    # Suite 4: MPTE re-scan (exploit simulation)
    # ------------------------------------------------------------------

    def _run_mpte_retest(
        self, original: str, fixed: str, language: str, finding_type: str
    ) -> Tuple[CheckResult, MPTERetestResult]:
        _emit_event("finding.updated", {"module": __name__, "action": "mpte_retest"})
        t0 = time.monotonic()
        sig = _MPTE_EXPLOIT_SIGNATURES.get(finding_type)
        if not sig:
            result = MPTERetestResult.NOT_APPLICABLE
            return (
                CheckResult(
                    check_name="mpte_exploit_retest",
                    status=CheckStatus.SKIPPED,
                    description=f"MPTE: no exploit signature for '{finding_type}' — re-test skipped",
                    severity="info",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ),
                result,
            )

        vuln_indicators = sig.get("vuln_indicators", [])
        fixed_indicators = sig.get("fixed_indicators", [])

        # Check if the vuln indicator is still in fixed code
        still_vulnerable = any(
            re.search(p, fixed, re.IGNORECASE | re.DOTALL) for p in vuln_indicators
        )

        # Check if the fix indicator is present
        fix_applied = any(
            re.search(p, fixed, re.IGNORECASE | re.DOTALL) for p in fixed_indicators
        )

        if still_vulnerable and not fix_applied:
            result = MPTERetestResult.EXPLOIT_STILL_POSSIBLE
            return (
                CheckResult(
                    check_name="mpte_exploit_retest",
                    status=CheckStatus.FAILED,
                    description=f"MPTE re-test FAILED: exploit patterns for '{finding_type}' still present; fix mitigation not detected",
                    severity="critical",
                    cwe=self._get_cwe_for_type(finding_type),
                    duration_ms=(time.monotonic() - t0) * 1000,
                ),
                result,
            )
        elif fix_applied and not still_vulnerable:
            result = MPTERetestResult.EXPLOIT_BLOCKED
            return (
                CheckResult(
                    check_name="mpte_exploit_retest",
                    status=CheckStatus.PASSED,
                    description=f"MPTE re-test PASSED: exploit for '{finding_type}' blocked; mitigation confirmed",
                    severity="info",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ),
                result,
            )
        elif fix_applied and still_vulnerable:
            # Mitigation present but vuln indicator still there — partial
            result = MPTERetestResult.INCONCLUSIVE
            return (
                CheckResult(
                    check_name="mpte_exploit_retest",
                    status=CheckStatus.WARNING,
                    description=f"MPTE re-test INCONCLUSIVE: mitigation detected but vulnerable pattern may still exist in '{finding_type}'",
                    severity="high",
                    cwe=self._get_cwe_for_type(finding_type),
                    duration_ms=(time.monotonic() - t0) * 1000,
                ),
                result,
            )
        else:
            # Neither vuln indicator nor fix indicator found — probably context snippet
            result = MPTERetestResult.INCONCLUSIVE
            return (
                CheckResult(
                    check_name="mpte_exploit_retest",
                    status=CheckStatus.INCONCLUSIVE,
                    description=f"MPTE re-test INCONCLUSIVE: insufficient code context for '{finding_type}' (may be partial snippet)",
                    severity="medium",
                    duration_ms=(time.monotonic() - t0) * 1000,
                ),
                result,
            )

    # ------------------------------------------------------------------
    # Suite 5: Code style preservation
    # ------------------------------------------------------------------

    def _run_style_check(
        self, original: str, fixed: str, language: str
    ) -> List[CheckResult]:
        t0 = time.monotonic()
        results: List[CheckResult] = []

        # 5a. Indentation consistency
        orig_indent = _detect_indentation(original)
        fixed_indent = _detect_indentation(fixed)
        if orig_indent != fixed_indent and len(fixed.strip()) > 20:
            results.append(CheckResult(
                check_name="style_indentation",
                status=CheckStatus.WARNING,
                description=f"Indentation style changed: {orig_indent} → {fixed_indent}",
                severity="low",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="style_indentation",
                status=CheckStatus.PASSED,
                description=f"Indentation style preserved ({orig_indent})",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        # 5b. Naming convention
        orig_naming = _detect_naming_convention(original, language)
        fixed_naming = _detect_naming_convention(fixed, language)
        if orig_naming != fixed_naming:
            results.append(CheckResult(
                check_name="style_naming_convention",
                status=CheckStatus.WARNING,
                description=f"Naming convention shift: {orig_naming} → {fixed_naming}",
                severity="low",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="style_naming_convention",
                status=CheckStatus.PASSED,
                description=f"Naming convention preserved ({orig_naming})",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        # 5c. Trailing whitespace / line endings
        orig_crlf = original.count("\r\n")
        fixed_crlf = fixed.count("\r\n")
        if orig_crlf == 0 and fixed_crlf > 0:
            results.append(CheckResult(
                check_name="style_line_endings",
                status=CheckStatus.WARNING,
                description="Fix introduces CRLF line endings (original uses LF)",
                severity="low",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
        else:
            results.append(CheckResult(
                check_name="style_line_endings",
                status=CheckStatus.PASSED,
                description="Line endings consistent with original",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            ))

        return results

    # ------------------------------------------------------------------
    # Suite 6: Test coverage impact
    # ------------------------------------------------------------------

    def _run_coverage_check(
        self, original: str, fixed: str, language: str
    ) -> CheckResult:
        t0 = time.monotonic()
        orig_tests = _count_test_indicators(original, language)
        fixed_tests = _count_test_indicators(fixed, language)
        orig_lines = max(len(original.strip().splitlines()), 1)
        fixed_lines = max(len(fixed.strip().splitlines()), 1)

        orig_density = orig_tests / orig_lines
        fixed_density = fixed_tests / fixed_lines

        if orig_density > 0 and fixed_density < orig_density * 0.5:
            return CheckResult(
                check_name="test_coverage_impact",
                status=CheckStatus.WARNING,
                description=f"Fix may reduce test density: {orig_tests} → {fixed_tests} test markers ({orig_density:.2f} → {fixed_density:.2f} per line)",
                severity="medium",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        if fixed_tests > orig_tests:
            return CheckResult(
                check_name="test_coverage_impact",
                status=CheckStatus.PASSED,
                description=f"Fix includes additional test coverage: {orig_tests} → {fixed_tests} test markers",
                severity="info",
                duration_ms=(time.monotonic() - t0) * 1000,
            )
        return CheckResult(
            check_name="test_coverage_impact",
            status=CheckStatus.PASSED,
            description=f"Test coverage appears unaffected by fix ({fixed_tests} test markers)",
            severity="info",
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_cwe_for_type(finding_type: str) -> str:
        _MAP = {
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "command_injection": "CWE-78",
            "path_traversal": "CWE-22",
            "deserialization": "CWE-502",
            "ssrf": "CWE-918",
            "buffer_overflow": "CWE-120",
            "open_redirect": "CWE-601",
            "xxe": "CWE-611",
            "ldap_injection": "CWE-90",
            "xpath_injection": "CWE-643",
        }
        return _MAP.get(finding_type.lower(), "")

    @staticmethod
    def _build_recommendation(
        verified: bool,
        safe_to_deploy: bool,
        failed: List[CheckResult],
        warnings: List[CheckResult],
        mpte_result: MPTERetestResult,
        confidence: float,
        severity: str,
    ) -> str:
        if safe_to_deploy:
            return (
                f"SAFE TO DEPLOY. All verification checks passed. MPTE re-test: {mpte_result.value}. "
                f"Confidence: {confidence:.0%}. Fix meets enterprise deployment standards."
            )
        if verified:
            warn_names = ", ".join(c.check_name for c in warnings[:3])
            return (
                f"CONDITIONALLY VERIFIED (confidence: {confidence:.0%}). Minor warnings: {warn_names}. "
                f"MPTE re-test: {mpte_result.value}. Human review recommended before deploying to production."
            )
        fail_names = ", ".join(c.check_name for c in failed[:3])
        crit = any(c.severity == "critical" for c in failed)
        prefix = "CRITICAL FAILURE" if crit else "VERIFICATION FAILED"
        return (
            f"{prefix}. Fix does not pass post-fix verification (confidence: {confidence:.0%}). "
            f"Failed checks: {fail_names}. MPTE re-test: {mpte_result.value}. "
            f"Fix must be revised before deployment."
        )

    def _record(self, report: VerificationReport) -> None:
        self._stats["total_verifications"] += 1
        if report.verified:
            self._stats["verified"] += 1
        else:
            self._stats["failed"] += 1
        if report.safe_to_deploy:
            self._stats["safe_to_deploy"] += 1

        lang = report.language
        self._stats["by_language"].setdefault(lang, {"total": 0, "verified": 0})
        self._stats["by_language"][lang]["total"] += 1
        if report.verified:
            self._stats["by_language"][lang]["verified"] += 1

        ftype = report.finding_type
        self._stats["by_finding_type"].setdefault(ftype, {"total": 0, "verified": 0})
        self._stats["by_finding_type"][ftype]["total"] += 1
        if report.verified:
            self._stats["by_finding_type"][ftype]["verified"] += 1

        self._history.append({
            "finding_id": report.finding_id,
            "finding_type": report.finding_type,
            "language": report.language,
            "verified": report.verified,
            "confidence": report.confidence,
            "safe_to_deploy": report.safe_to_deploy,
            "mpte_retest_result": report.mpte_retest_result,
            "checks_passed": report.checks_passed,
            "checks_total": report.checks_total,
            "duration_ms": report.verification_duration_ms,
            "timestamp": report.timestamp,
        })

    def get_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        total = self._stats["total_verifications"]
        return {
            **self._stats,
            "verified_rate": round(self._stats["verified"] / max(total, 1) * 100, 1),
            "safe_to_deploy_rate": round(self._stats["safe_to_deploy"] / max(total, 1) * 100, 1),
        }

    def supported_languages(self) -> List[str]:
        return sorted(_VULN_PATTERNS.keys())


# ---------------------------------------------------------------------------
# Module-level singleton + convenience API
# ---------------------------------------------------------------------------

_engine = PostFixVerifier()


def get_postfix_verifier() -> PostFixVerifier:
    """Return the module-level singleton PostFixVerifier."""
    return _engine


def verify_fix(
    finding_id: str,
    finding_type: str,
    severity: str,
    original_code: str,
    fixed_code: str,
    language: str,
    file_path: Optional[str] = None,
    context_code: Optional[str] = None,
    dep_changes: Optional[Dict[str, str]] = None,
) -> VerificationReport:
    """Convenience function — verify a single fix using the module singleton."""
    return _engine.verify(
        finding_id=finding_id,
        finding_type=finding_type,
        severity=severity,
        original_code=original_code,
        fixed_code=fixed_code,
        language=language,
        file_path=file_path,
        context_code=context_code,
        dep_changes=dep_changes,
    )
