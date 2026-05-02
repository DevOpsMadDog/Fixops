"""AI Code Guardian Engine — Apiiro Guardian Agent Parity.

Detects risks in AI-generated code (Copilot, ChatGPT, Cursor, vibe coding).
Performs enhanced scanning for AI-common mistakes: hardcoded secrets, insecure
defaults, missing input validation, overly permissive permissions.

Usage:
    from core.ai_code_guardian import AICodeGuardian, get_ai_code_guardian

    guardian = get_ai_code_guardian()
    result = guardian.scan_code(code="...", filename="app.py", language="python")
"""

from __future__ import annotations

import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


class RiskCategory(str, Enum):
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_DEFAULT = "insecure_default"
    MISSING_VALIDATION = "missing_validation"
    INJECTION_SINK = "injection_sink"
    OVERLY_PERMISSIVE = "overly_permissive"
    INSECURE_CRYPTO = "insecure_crypto"
    DEBUG_CODE = "debug_code"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    PATH_TRAVERSAL = "path_traversal"
    SSRF_POTENTIAL = "ssrf_potential"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CodeFinding:
    finding_id: str
    category: str
    severity: str
    title: str
    description: str
    line_number: int
    code_snippet: str
    cwe_id: str
    owasp: str
    recommendation: str
    confidence: float  # 0.0 - 1.0


@dataclass
class AIDetectionResult:
    is_ai_generated: bool
    confidence: float  # 0.0 - 1.0
    indicators: List[str]
    entropy_score: float
    pattern_score: float


@dataclass
class GuardianScanResult:
    scan_id: str
    filename: str
    language: str
    scanned_at: str
    lines_scanned: int
    ai_detection: AIDetectionResult
    findings: List[CodeFinding]
    risk_score: float
    summary: Dict[str, Any]



# ---------------------------------------------------------------------------
# AI-generated code detection patterns
# ---------------------------------------------------------------------------
_AI_MARKERS = [
    r"(?i)generated\s+by\s+(copilot|chatgpt|gpt|claude|cursor|ai|codewhisperer)",
    r"(?i)#\s*ai[\-_]?generated",
    r"(?i)//\s*auto[\-_]?generated\s+by\s+ai",
    r"(?i)TODO:\s*(implement|add|fix)\s+this",
    r"(?i)#\s*copilot\s+suggestion",
]

# Secret patterns (AI often hardcodes these)
_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "API Key", "CWE-798"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Password/Secret", "CWE-798"),
    (r"(?i)(aws_access_key_id|aws_secret)\s*[=:]\s*['\"][A-Z0-9]{16,}['\"]", "AWS Credential", "CWE-798"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "CWE-798"),
    (r"(?i)(token|bearer)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{20,}['\"]", "Token", "CWE-798"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Private Key", "CWE-321"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub Token", "CWE-798"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI API Key", "CWE-798"),
    (r"(?i)(stripe|sk_live|sk_test)_[A-Za-z0-9]{24,}", "Stripe Key", "CWE-798"),
]

# Insecure defaults AI commonly produces
_INSECURE_DEFAULTS: List[Tuple[str, str, str, str]] = [
    (r"(?i)debug\s*[=:]\s*True", "Debug mode enabled", "CWE-489", "A05:2021"),
    (r"(?i)verify\s*[=:]\s*False", "SSL verification disabled", "CWE-295", "A07:2021"),
    (r"(?i)allow_all_origins|AllowAnyOrigin|cors.*\*", "CORS wildcard", "CWE-942", "A05:2021"),
    (r"(?i)secure\s*[=:]\s*False", "Insecure cookie flag", "CWE-614", "A05:2021"),
    (r"(?i)httponly\s*[=:]\s*False", "Missing HttpOnly flag", "CWE-1004", "A05:2021"),
    (r"(?i)disabled?\s*[=:]\s*True.*(?:auth|security|csrf)", "Security feature disabled", "CWE-693", "A07:2021"),
    (r"0\.0\.0\.0", "Binding to all interfaces", "CWE-668", "A05:2021"),
]

# Injection sinks
_INJECTION_PATTERNS: List[Tuple[str, str, str, str]] = [
    (r"(?i)execute\s*\(\s*f['\"]|\.format\s*\(.*\)\s*\)", "SQL injection via f-string/format", "CWE-89", "A03:2021"),
    (r"(?i)os\.system\s*\(|subprocess\.\w+\s*\(\s*[^\\[]", "Command injection risk", "CWE-78", "A03:2021"),
    (r"(?i)eval\s*\(|exec\s*\(", "Code injection via eval/exec", "CWE-95", "A03:2021"),
    (r"(?i)innerHTML\s*=|document\.write\s*\(|\.html\s*\(", "DOM XSS sink", "CWE-79", "A03:2021"),
    (r"(?i)pickle\.loads?\s*\(|yaml\.load\s*\([^,]*\)$", "Unsafe deserialization", "CWE-502", "A08:2021"),
    (r"(?i)open\s*\(\s*(request|req|params|input|user)", "Path traversal risk", "CWE-22", "A01:2021"),
    (r"(?i)requests?\.(get|post|put|delete)\s*\(\s*(request|req|params|user)", "SSRF potential", "CWE-918", "A10:2021"),
]

# Insecure crypto
_CRYPTO_PATTERNS: List[Tuple[str, str, str]] = [
    (r"(?i)(md5|sha1)\s*\(", "Weak hash algorithm", "CWE-328"),
    (r"(?i)(DES|RC4|Blowfish)\b", "Weak cipher", "CWE-327"),
    (r"(?i)random\.(random|randint|choice|sample)\s*\(", "Insecure randomness for security", "CWE-330"),
]


class AICodeGuardian:
    """Scans code for AI-generated patterns and security risks."""

    def __init__(self) -> None:
        self._scans: Dict[str, GuardianScanResult] = {}
        self._lock = Lock()
        self._total_scans = 0
        self._total_findings = 0
        logger.info("AICodeGuardian initialised")

    def scan_code(
        self, code: str, filename: str = "unknown",
        language: str = "auto",
    ) -> GuardianScanResult:
        """Scan code for AI-generation indicators and security risks."""
        scan_id = f"gs-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        lines = code.split("\n")

        if language == "auto":
            language = self._detect_language(filename)

        ai_detection = self._detect_ai_generated(code, lines)
        findings: List[CodeFinding] = []

        # Secret scanning
        for pattern, name, cwe in _SECRET_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(CodeFinding(
                        finding_id=f"f-{uuid.uuid4().hex[:8]}",
                        category=RiskCategory.HARDCODED_SECRET.value,
                        severity=Severity.CRITICAL.value, title=f"Hardcoded {name}",
                        description=f"Hardcoded {name} found — AI often embeds credentials directly",
                        line_number=i, code_snippet=line.strip()[:120],
                        cwe_id=cwe, owasp="A07:2021",
                        recommendation=f"Use environment variables or a secrets manager for {name}",
                        confidence=0.95,
                    ))

        # Insecure defaults
        for pattern, name, cwe, owasp in _INSECURE_DEFAULTS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(CodeFinding(
                        finding_id=f"f-{uuid.uuid4().hex[:8]}",
                        category=RiskCategory.INSECURE_DEFAULT.value,
                        severity=Severity.HIGH.value, title=name,
                        description=f"{name} — common in AI-generated boilerplate",
                        line_number=i, code_snippet=line.strip()[:120],
                        cwe_id=cwe, owasp=owasp,
                        recommendation=f"Fix: {name.lower()} should use secure defaults",
                        confidence=0.85,
                    ))

        # Injection sinks
        for pattern, name, cwe, owasp in _INJECTION_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(CodeFinding(
                        finding_id=f"f-{uuid.uuid4().hex[:8]}",
                        category=RiskCategory.INJECTION_SINK.value,
                        severity=Severity.HIGH.value, title=name,
                        description=f"{name} — AI models frequently produce injectable code",
                        line_number=i, code_snippet=line.strip()[:120],
                        cwe_id=cwe, owasp=owasp,
                        recommendation="Use parameterized queries or safe APIs instead",
                        confidence=0.80,
                    ))

        # Insecure crypto
        for pattern, name, cwe in _CRYPTO_PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(CodeFinding(
                        finding_id=f"f-{uuid.uuid4().hex[:8]}",
                        category=RiskCategory.INSECURE_CRYPTO.value,
                        severity=Severity.MEDIUM.value, title=name,
                        description=f"{name} — AI often uses deprecated algorithms",
                        line_number=i, code_snippet=line.strip()[:120],
                        cwe_id=cwe, owasp="A02:2021",
                        recommendation="Use SHA-256+ for hashing, AES-256 for encryption, secrets module for randomness",
                        confidence=0.75,
                    ))

        # Boost severity if AI-generated
        if ai_detection.is_ai_generated:
            for f in findings:
                f.confidence = min(1.0, f.confidence + 0.1)

        risk_score = self._calc_risk_score(findings, ai_detection)

        result = GuardianScanResult(
            scan_id=scan_id, filename=filename, language=language,
            scanned_at=now, lines_scanned=len(lines),
            ai_detection=ai_detection, findings=findings,
            risk_score=risk_score,
            summary=self._build_summary(findings, ai_detection),
        )

        with self._lock:
            self._scans[scan_id] = result
            self._total_scans += 1
            self._total_findings += len(findings)

        logger.info("Guardian scan complete", scan_id=scan_id,
                     findings=len(findings), ai_detected=ai_detection.is_ai_generated)
        return result

    def get_scan(self, scan_id: str) -> Optional[GuardianScanResult]:
        with self._lock:
            return self._scans.get(scan_id)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_scans": self._total_scans,
                "total_findings": self._total_findings,
                "stored_scans": len(self._scans),
            }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _detect_ai_generated(self, code: str, lines: List[str]) -> AIDetectionResult:
        """Detect if code is AI-generated using heuristics."""
        indicators: List[str] = []

        # Check for AI markers in comments
        marker_score = 0.0
        for marker in _AI_MARKERS:
            if re.search(marker, code):
                indicators.append(f"AI marker found: {marker[:40]}")
                marker_score += 0.3

        # Shannon entropy analysis (AI tends to produce uniform entropy)
        entropy = self._shannon_entropy(code)
        entropy_normalized = min(entropy / 5.0, 1.0)
        if 3.5 < entropy < 4.5:
            indicators.append(f"Entropy {entropy:.2f} in AI-typical range (3.5-4.5)")
            marker_score += 0.15

        # Repetitive structure (AI often produces very uniform code)
        pattern_score = self._structural_uniformity(lines)
        if pattern_score > 0.7:
            indicators.append(f"High structural uniformity: {pattern_score:.2f}")
            marker_score += 0.2

        # Generic variable names (AI tendency)
        generic_names = len(re.findall(r"\b(data|result|response|temp|tmp|val|item|obj)\b", code))
        generic_ratio = generic_names / max(len(lines), 1)
        if generic_ratio > 0.1:
            indicators.append(f"High generic variable ratio: {generic_ratio:.2f}")
            marker_score += 0.1

        # Missing error handling (AI often skips it)
        has_try = "try:" in code or "try {" in code
        if not has_try and len(lines) > 20:
            indicators.append("No error handling in 20+ line code")
            marker_score += 0.1

        confidence = min(marker_score, 1.0)
        return AIDetectionResult(
            is_ai_generated=confidence >= 0.4,
            confidence=round(confidence, 2),
            indicators=indicators,
            entropy_score=round(entropy_normalized, 2),
            pattern_score=round(pattern_score, 2),
        )

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    @staticmethod
    def _structural_uniformity(lines: List[str]) -> float:
        """Measure how uniform the line structure is (indentation patterns)."""
        if len(lines) < 5:
            return 0.0
        indents = [len(line) - len(line.lstrip()) for line in lines if line.strip()]
        if not indents:
            return 0.0
        # Coefficient of variation (lower = more uniform = more AI-like)
        mean_indent = sum(indents) / len(indents)
        if mean_indent == 0:
            return 0.5
        variance = sum((i - mean_indent) ** 2 for i in indents) / len(indents)
        cv = (variance ** 0.5) / mean_indent
        return round(max(0.0, 1.0 - cv), 2)

    @staticmethod
    def _detect_language(filename: str) -> str:
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "typescript",
            ".java": "java", ".go": "go", ".rs": "rust", ".rb": "ruby",
            ".php": "php", ".cs": "csharp", ".cpp": "cpp", ".c": "c",
            ".jsx": "javascript", ".tsx": "typescript",
        }
        for ext, lang in ext_map.items():
            if filename.endswith(ext):
                return lang
        return "unknown"

    @staticmethod
    def _calc_risk_score(findings: List[CodeFinding], ai: AIDetectionResult) -> float:
        if not findings:
            return 0.0
        sev_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.05}
        total = sum(sev_weights.get(f.severity, 0.3) * f.confidence for f in findings)
        base = min(total / 5.0, 1.0)  # Normalize
        if ai.is_ai_generated:
            base = min(base * 1.3, 1.0)  # 30% boost for AI-generated
        return round(base, 2)

    @staticmethod
    def _build_summary(findings: List[CodeFinding], ai: AIDetectionResult) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_cat[f.category] = by_cat.get(f.category, 0) + 1
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "total_findings": len(findings),
            "ai_generated": ai.is_ai_generated,
            "ai_confidence": ai.confidence,
            "by_category": by_cat,
            "by_severity": by_sev,
            "critical_count": by_sev.get("critical", 0),
            "high_count": by_sev.get("high", 0),
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_guardian: Optional[AICodeGuardian] = None
_guardian_lock = Lock()


def get_ai_code_guardian() -> AICodeGuardian:
    global _guardian
    if _guardian is None:
        with _guardian_lock:
            if _guardian is None:
                _guardian = AICodeGuardian()
    return _guardian