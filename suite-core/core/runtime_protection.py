"""Runtime Protection Engine — Aikido Zen Parity.

Integrates RASP rule engine with advanced bot detection, zero-day pattern
blocking, SSRF prevention, and behavioural fingerprinting.  Designed for
in-app deployment as FastAPI middleware or standalone inspection service.

Usage:
    from core.runtime_protection import RuntimeProtectionEngine, ProtectionConfig

    engine = RuntimeProtectionEngine()
    verdict = engine.inspect_request(
        source_ip="1.2.3.4",
        path="/api/v1/users",
        method="POST",
        headers={"User-Agent": "curl/7.88"},
        body='{"name": "test"}',
    )
    if verdict["blocked"]:
        return JSONResponse(status_code=403, content=verdict)
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Enums & config
# ---------------------------------------------------------------------------

class ThreatCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    BOT = "bot"
    RATE_LIMIT = "rate_limit"
    ZERO_DAY = "zero_day"
    DESERIALIZATION = "deserialization"


class EngineMode(str, Enum):
    BLOCKING = "blocking"
    MONITORING = "monitoring"
    LEARNING = "learning"


@dataclass
class ProtectionConfig:
    """Runtime protection configuration."""
    mode: EngineMode = EngineMode.BLOCKING
    block_sqli: bool = True
    block_xss: bool = True
    block_cmdi: bool = True
    block_path_traversal: bool = True
    block_ssrf: bool = True
    block_prototype_pollution: bool = True
    block_deserialization: bool = True
    block_bots: bool = True
    block_zero_day_patterns: bool = True
    rate_limit_rpm: int = 120
    ip_allowlist: List[str] = field(default_factory=list)
    ip_denylist: List[str] = field(default_factory=list)
    # Bot detection thresholds
    bot_score_threshold: float = 0.7
    # Zero-day pattern update interval (seconds)
    pattern_refresh_interval: int = 3600


@dataclass
class ProtectionEvent:
    """A recorded protection event."""
    timestamp: str
    source_ip: str
    path: str
    method: str
    category: str
    blocked: bool
    details: str
    fingerprint: str = ""
    severity: str = "medium"


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

_SQLI_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(\bunion\b\s+\bselect\b)", r"(\bor\b\s+1\s*=\s*1)", r"(\bor\b\s+'1'\s*=\s*'1')",
        r"(';\s*(drop|delete|insert|update|alter)\b)", r"(\bwaitfor\b\s+\bdelay\b)",
        r"(\bbenchmark\s*\()", r"(\bsleep\s*\()", r"(--\s*$)", r"(/\*.*\*/)",
        r"(\bexec\b\s*\()", r"(\bload_file\s*\()", r"(\binto\s+outfile\b)",
        r"(\bchar\s*\(\s*\d+)", r"(\bhaving\b\s+1\s*=\s*1)",
    ]
]

_XSS_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"<script[^>]*>", r"javascript\s*:", r"on(error|load|click|mouseover)\s*=",
        r"<img[^>]+onerror", r"<svg[^>]+onload", r"<iframe", r"<object",
        r"document\.(cookie|location|write)", r"eval\s*\(", r"atob\s*\(",
        r"String\.fromCharCode", r"<embed", r"<link[^>]+rel\s*=\s*['\"]import",
    ]
]

_CMDI_PATTERNS = [
    re.compile(p) for p in [
        r";\s*(ls|cat|rm|wget|curl|nc|bash|sh|python|perl|ruby)\b",
        r"\|\s*(whoami|id|uname|ifconfig|env)\b", r"`[^`]+`",
        r"\$\([^)]+\)", r"&&\s*(ls|cat|rm|wget)", r"\|\|\s*(ls|cat|rm)",
    ]
]

_PATH_TRAVERSAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\.\./", r"\.\.\\", r"%2e%2e[/\\%]", r"etc/passwd", r"etc/shadow",
        r"windows/system32", r"proc/self", r"%00",
    ]
]

_SSRF_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(127\.0\.0\.1|localhost|0\.0\.0\.0)", r"(169\.254\.169\.254)",
        r"(metadata\.google\.internal)", r"(10\.\d+\.\d+\.\d+)",
        r"(172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)", r"(192\.168\.\d+\.\d+)",
        r"(fd[0-9a-f]{2}:)", r"(\[::1\])", r"(file://)",
    ]
]

_PROTO_POLLUTION_PATTERNS = [
    re.compile(p) for p in [
        r"__proto__", r"constructor\s*\[", r"prototype\s*\[",
    ]
]

_DESERIALIZATION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(java\.lang\.Runtime)", r"(ObjectInputStream)", r"(pickle\.loads)",
        r"(yaml\.unsafe_load)", r"(unserialize\s*\()", r"(Marshal\.load)",
        r"(readObject\s*\()", r"(ysoserial)", r"(rO0AB)",
    ]
]

# Zero-day signatures — patterns for recently disclosed CVEs
_ZERO_DAY_PATTERNS = [
    re.compile(r"\$\{jndi:", re.IGNORECASE),       # Log4Shell
    re.compile(r"class\.module\.classLoader", re.IGNORECASE),  # Spring4Shell
    re.compile(r"(X-siLock-Comment|guestaccess\.aspx)", re.IGNORECASE),  # MOVEit
    re.compile(r"\$\{script:", re.IGNORECASE),      # Text4Shell
    re.compile(r"(%\{|#cmd=|#iswin=)", re.IGNORECASE),  # Confluence OGNL
]

# Known bot User-Agent fragments
_BOT_UA_FRAGMENTS = [
    "bot", "crawl", "spider", "scrape", "scan", "harvest", "extract",
    "headless", "phantom", "selenium", "puppeteer", "playwright",
    "httpie", "python-requests", "go-http-client", "java/",
    "okhttp", "apache-httpclient", "wget", "libwww",
]


# ---------------------------------------------------------------------------
# RuntimeProtectionEngine
# ---------------------------------------------------------------------------

class RuntimeProtectionEngine:
    """In-app runtime protection engine (Aikido Zen parity).

    Inspects HTTP requests for injection, XSS, SSRF, bot behaviour,
    zero-day patterns, and rate-limit violations.  Returns structured
    verdicts that can be used by middleware or an API gateway.
    """

    def __init__(self, config: ProtectionConfig | None = None):
        self.config = config or ProtectionConfig()
        self._events: List[ProtectionEvent] = []
        self._rate_tracker: Dict[str, List[float]] = defaultdict(list)
        self._request_history: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()
        self._started_at = datetime.now(timezone.utc)
        logger.info(
            "RuntimeProtectionEngine initialised",
            mode=self.config.mode.value,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect_request(
        self,
        source_ip: str,
        path: str,
        method: str = "GET",
        headers: Dict[str, str] | None = None,
        body: str | None = None,
        user_id: str | None = None,
    ) -> Dict[str, Any]:
        """Inspect a single request.  Returns a verdict dict."""
        headers = headers or {}
        combined_text = f"{path} {body or ''}"
        ua = headers.get("User-Agent", headers.get("user-agent", ""))

        # IP allowlist / denylist
        if source_ip in self.config.ip_allowlist:
            return self._ok()
        if source_ip in self.config.ip_denylist:
            return self._block(source_ip, path, method, ThreatCategory.RATE_LIMIT,
                               "IP in denylist", severity="high")

        detections: List[Tuple[ThreatCategory, str, str]] = []

        # 1. Rate limiting
        if self._check_rate_limit(source_ip):
            detections.append((ThreatCategory.RATE_LIMIT, "Rate limit exceeded", "high"))

        # 2. SQL injection
        if self.config.block_sqli:
            for p in _SQLI_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.SQL_INJECTION,
                                       f"SQLi pattern: {p.pattern[:40]}", "critical"))
                    break

        # 3. XSS
        if self.config.block_xss:
            for p in _XSS_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.XSS,
                                       f"XSS pattern: {p.pattern[:40]}", "high"))
                    break

        # 4. Command injection
        if self.config.block_cmdi:
            for p in _CMDI_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.COMMAND_INJECTION,
                                       f"CMDi pattern: {p.pattern[:40]}", "critical"))
                    break

        # 5. Path traversal
        if self.config.block_path_traversal:
            for p in _PATH_TRAVERSAL_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.PATH_TRAVERSAL,
                                       f"Path traversal: {p.pattern[:40]}", "high"))
                    break

        # 6. SSRF
        if self.config.block_ssrf and body:
            for p in _SSRF_PATTERNS:
                if p.search(body):
                    detections.append((ThreatCategory.SSRF,
                                       f"SSRF pattern: {p.pattern[:40]}", "critical"))
                    break

        # 7. Prototype pollution
        if self.config.block_prototype_pollution:
            for p in _PROTO_POLLUTION_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.PROTOTYPE_POLLUTION,
                                       f"Proto pollution: {p.pattern[:40]}", "high"))
                    break

        # 8. Deserialization
        if self.config.block_deserialization:
            for p in _DESERIALIZATION_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.DESERIALIZATION,
                                       f"Deserialization: {p.pattern[:40]}", "critical"))
                    break

        # 9. Zero-day patterns
        if self.config.block_zero_day_patterns:
            for p in _ZERO_DAY_PATTERNS:
                if p.search(combined_text):
                    detections.append((ThreatCategory.ZERO_DAY,
                                       f"Zero-day: {p.pattern[:40]}", "critical"))
                    break

        # 10. Bot detection
        if self.config.block_bots:
            bot_score = self._compute_bot_score(ua, headers, source_ip)
            if bot_score >= self.config.bot_score_threshold:
                detections.append((ThreatCategory.BOT,
                                   f"Bot score {bot_score:.2f}", "medium"))

        if not detections:
            return self._ok()

        # Pick highest-severity detection
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        detections.sort(key=lambda d: severity_order.get(d[2], 99))
        cat, detail, sev = detections[0]

        should_block = self.config.mode == EngineMode.BLOCKING
        fp = hashlib.sha256(f"{source_ip}:{cat.value}:{path}".encode()).hexdigest()[:16]

        event = ProtectionEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip, path=path, method=method,
            category=cat.value, blocked=should_block,
            details=detail, fingerprint=fp, severity=sev,
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > 10000:
                self._events = self._events[-5000:]

        logger.warning("Runtime threat detected",
                        category=cat.value, ip=source_ip, path=path,
                        blocked=should_block)

        return {
            "blocked": should_block,
            "category": cat.value,
            "severity": sev,
            "detail": detail,
            "fingerprint": fp,
            "detections": len(detections),
            "all_categories": [d[0].value for d in detections],
        }

    def get_events(self, limit: int = 100, category: str | None = None) -> List[Dict[str, Any]]:
        """Return recent protection events."""
        with self._lock:
            events = list(self._events)
        if category:
            events = [e for e in events if e.category == category]
        return [e.__dict__ for e in events[-limit:]]

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate protection statistics."""
        with self._lock:
            events = list(self._events)
        by_cat: Dict[str, int] = defaultdict(int)
        blocked = 0
        for e in events:
            by_cat[e.category] += 1
            if e.blocked:
                blocked += 1
        return {
            "mode": self.config.mode.value,
            "total_events": len(events),
            "blocked_events": blocked,
            "monitored_events": len(events) - blocked,
            "by_category": dict(by_cat),
            "uptime_seconds": (datetime.now(timezone.utc) - self._started_at).total_seconds(),
            "config": {
                "rate_limit_rpm": self.config.rate_limit_rpm,
                "bot_score_threshold": self.config.bot_score_threshold,
                "block_sqli": self.config.block_sqli,
                "block_xss": self.config.block_xss,
                "block_ssrf": self.config.block_ssrf,
                "block_zero_day_patterns": self.config.block_zero_day_patterns,
            },
        }

    def update_config(self, **kwargs) -> ProtectionConfig:
        """Update configuration at runtime."""
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)
        logger.info("RuntimeProtectionEngine config updated", **kwargs)
        return self.config

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ok(self) -> Dict[str, Any]:
        return {"blocked": False}

    def _block(self, ip, path, method, cat, detail, severity="high") -> Dict[str, Any]:
        fp = hashlib.sha256(f"{ip}:{cat.value}:{path}".encode()).hexdigest()[:16]
        event = ProtectionEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=ip, path=path, method=method,
            category=cat.value, blocked=True,
            details=detail, fingerprint=fp, severity=severity,
        )
        with self._lock:
            self._events.append(event)
        return {"blocked": True, "category": cat.value, "severity": severity,
                "detail": detail, "fingerprint": fp}

    def _check_rate_limit(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._rate_tracker[ip] = [
                t for t in self._rate_tracker[ip] if now - t < 60
            ]
            if len(self._rate_tracker[ip]) >= self.config.rate_limit_rpm:
                return True
            self._rate_tracker[ip].append(now)
        return False

    def _compute_bot_score(self, ua: str, headers: Dict[str, str], ip: str) -> float:
        """Heuristic bot score 0.0–1.0."""
        score = 0.0
        ua_lower = ua.lower()

        # Known bot UA fragments
        if any(frag in ua_lower for frag in _BOT_UA_FRAGMENTS):
            score += 0.5

        # Missing common browser headers
        if not ua:
            score += 0.3
        if "Accept-Language" not in headers and "accept-language" not in headers:
            score += 0.1
        if "Accept" not in headers and "accept" not in headers:
            score += 0.1

        # Suspicious request velocity (> 30 req/10s from same IP)
        now = time.time()
        with self._lock:
            self._request_history[ip] = [
                t for t in self._request_history[ip] if now - t < 10
            ]
            self._request_history[ip].append(now)
            if len(self._request_history[ip]) > 30:
                score += 0.3

        return min(score, 1.0)


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine: RuntimeProtectionEngine | None = None


def get_runtime_protection_engine(
    config: ProtectionConfig | None = None,
) -> RuntimeProtectionEngine:
    """Get or create the global RuntimeProtectionEngine."""
    global _engine
    if _engine is None:
        _engine = RuntimeProtectionEngine(config)
    return _engine
