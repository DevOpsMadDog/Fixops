"""Runtime Protection Engine — Aikido Zen Parity + Host EDR.

Two layers of runtime security:

1. RASP / HTTP layer (Aikido Zen parity):
   Integrates RASP rule engine with advanced bot detection, zero-day pattern
   blocking, SSRF prevention, and behavioural fingerprinting. Designed for
   in-app deployment as FastAPI middleware or standalone inspection service.

2. Host EDR layer (CrowdStrike replacement):
   SQLite-backed host-based runtime monitoring: process execution, file access,
   network connections, privilege escalation, container escape. Provides
   ThreatLevel enum, RuntimeEvent/RuntimePolicy/RuntimeAlert Pydantic models,
   and HostRuntimeEngine for ingestion, policy evaluation, and analytics.

Usage (RASP):
    from core.runtime_protection import RuntimeProtectionEngine, ProtectionConfig
    engine = RuntimeProtectionEngine()
    verdict = engine.inspect_request(source_ip="1.2.3.4", path="/api/v1/users",
        method="POST", headers={"User-Agent": "curl/7.88"}, body='{"name": "test"}')
    if verdict["blocked"]:
        return JSONResponse(status_code=403, content=verdict)

Usage (EDR):
    from core.runtime_protection import HostRuntimeEngine, RuntimeEvent, EventType
    engine = HostRuntimeEngine()
    event = RuntimeEvent(event_type=EventType.PROCESS_EXEC,
        source_host="web-01", process_name="xmrig", user="www-data")
    engine.ingest_event(event)
    alerts = engine.evaluate_policies(event, org_id="org_123")
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Tuple

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


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


# ===========================================================================
# HOST EDR LAYER — CrowdStrike Falcon replacement
# ===========================================================================


class ThreatLevel(str, Enum):
    """Severity of a detected runtime threat."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    """Categories of host-level runtime events."""
    PROCESS_EXEC = "process_exec"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECT = "network_connect"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTAINER_ESCAPE = "container_escape"


class PolicyAction(str, Enum):
    """Action to take when a policy matches."""
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RuntimeEvent(BaseModel):
    """A runtime security event observed on a host."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: EventType
    source_host: str
    process_name: str
    user: str
    details: Dict[str, Any] = Field(default_factory=dict)
    threat_level: ThreatLevel = ThreatLevel.NONE
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"


class RuntimePolicy(BaseModel):
    """A policy that matches events and triggers actions."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    event_type: EventType
    conditions: Dict[str, Any] = Field(default_factory=dict)
    action: PolicyAction = PolicyAction.ALERT
    enabled: bool = True
    org_id: str = "default"


class RuntimeAlert(BaseModel):
    """An alert generated when a policy matches an event."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_id: str
    policy_id: str
    threat_level: ThreatLevel
    message: str
    acknowledged: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Built-in policy definitions
# ---------------------------------------------------------------------------

_EDR_BUILTIN_POLICIES: List[Dict[str, Any]] = [
    {
        "id": "builtin-crypto-mining",
        "name": "Crypto Mining Detection",
        "event_type": EventType.PROCESS_EXEC,
        "conditions": {
            "process_names": ["xmrig", "minerd", "cpuminer", "bfgminer", "cgminer",
                              "nbminer", "t-rex", "phoenixminer"],
            "cmdline_contains": ["--pool", "stratum+tcp", "stratum+ssl",
                                  "xmr.", "monero", "--donate-level"],
        },
        "action": PolicyAction.QUARANTINE,
        "threat_level": ThreatLevel.CRITICAL,
    },
    {
        "id": "builtin-reverse-shell",
        "name": "Reverse Shell Detection",
        "event_type": EventType.NETWORK_CONNECT,
        "conditions": {
            "process_names": ["bash", "sh", "zsh", "nc", "ncat", "socat",
                              "python", "python3", "perl", "ruby"],
            "cmdline_contains": ["/dev/tcp/", "nc -e", "ncat -e", "bash -i",
                                  "socat exec", "mkfifo"],
        },
        "action": PolicyAction.BLOCK,
        "threat_level": ThreatLevel.CRITICAL,
    },
    {
        "id": "builtin-privilege-escalation",
        "name": "Privilege Escalation Detection",
        "event_type": EventType.PRIVILEGE_ESCALATION,
        "conditions": {
            "uid_transition": "non-root-to-root",
            "suspicious_binaries": ["sudo", "su", "pkexec", "dbus-daemon", "polkit"],
        },
        "action": PolicyAction.ALERT,
        "threat_level": ThreatLevel.HIGH,
    },
    {
        "id": "builtin-container-escape",
        "name": "Container Escape Detection",
        "event_type": EventType.CONTAINER_ESCAPE,
        "conditions": {
            "indicators": [
                "host_pid_namespace",
                "privileged_container",
                "docker_socket_access",
                "cgroup_release_agent",
                "runc_overwrite",
            ],
        },
        "action": PolicyAction.BLOCK,
        "threat_level": ThreatLevel.CRITICAL,
    },
    {
        "id": "builtin-data-exfiltration",
        "name": "Data Exfiltration Pattern Detection",
        "event_type": EventType.NETWORK_CONNECT,
        "conditions": {
            "large_outbound_bytes_threshold": 104857600,  # 100 MB
            "sensitive_file_paths": [
                "/etc/passwd", "/etc/shadow", "/root/.ssh",
                "id_rsa", ".env", "credentials",
            ],
        },
        "action": PolicyAction.ALERT,
        "threat_level": ThreatLevel.HIGH,
    },
    {
        "id": "builtin-suspicious-file-access",
        "name": "Suspicious Sensitive File Access",
        "event_type": EventType.FILE_ACCESS,
        "conditions": {
            "paths": ["/etc/shadow", "/etc/sudoers", "/proc/mem",
                      "/dev/kmem", "/root/.ssh/"],
        },
        "action": PolicyAction.ALERT,
        "threat_level": ThreatLevel.MEDIUM,
    },
]


# ---------------------------------------------------------------------------
# HostRuntimeEngine
# ---------------------------------------------------------------------------


class HostRuntimeEngine:
    """
    SQLite-backed host runtime security monitoring engine.

    Replaces CrowdStrike Falcon EDR at $50K+/yr with a self-hosted
    SQLite-backed solution. Ingests host events, evaluates policies,
    generates alerts, and provides threat analytics.

    Compliance: SOC2 CC6.8, NIST CSF DE.CM-1, CIS Controls 8.
    """

    def __init__(self, db_path: str = ":memory:"):
        """
        Initialise the engine.

        Args:
            db_path: SQLite database file path. Use ":memory:" for tests.
        """
        self.db_path = db_path
        self._lock = threading.RLock()
        # Use a single persistent connection so :memory: databases share state
        # across all method calls. check_same_thread=False is safe here because
        # all access is serialised through self._lock.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._seed_builtin_policies()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        """Initialise SQLite schema."""
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS runtime_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    source_host TEXT NOT NULL,
                    process_name TEXT NOT NULL,
                    user TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '{}',
                    threat_level TEXT NOT NULL DEFAULT 'none',
                    detected_at TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_re_org_time
                    ON runtime_events (org_id, detected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_re_host
                    ON runtime_events (source_host, detected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_re_threat
                    ON runtime_events (org_id, threat_level, detected_at DESC);

                CREATE TABLE IF NOT EXISTS runtime_policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    conditions TEXT NOT NULL DEFAULT '{}',
                    action TEXT NOT NULL DEFAULT 'alert',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    org_id TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_rp_org_type
                    ON runtime_policies (org_id, event_type);

                CREATE TABLE IF NOT EXISTS runtime_alerts (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    org_id TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_ra_org_time
                    ON runtime_alerts (org_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ra_ack
                    ON runtime_alerts (org_id, acknowledged, created_at DESC);
            """)
            # executescript issues implicit COMMIT; connection stays open.

    def _seed_builtin_policies(self) -> None:
        """Insert built-in policies once (idempotent)."""
        with self._lock:
            cur = self._conn.cursor()
            for p in _EDR_BUILTIN_POLICIES:
                cur.execute("SELECT 1 FROM runtime_policies WHERE id = ?", (p["id"],))
                if not cur.fetchone():
                    cur.execute(
                        """
                        INSERT INTO runtime_policies
                            (id, name, event_type, conditions, action, enabled, org_id)
                        VALUES (?, ?, ?, ?, ?, 1, 'default')
                        """,
                        (
                            p["id"],
                            p["name"],
                            p["event_type"].value,
                            json.dumps(p["conditions"]),
                            p["action"].value,
                        ),
                    )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_event(self, event: RuntimeEvent) -> RuntimeEvent:
        """
        Persist a runtime event.

        Args:
            event: The RuntimeEvent to store.

        Returns:
            The stored event (unchanged).
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO runtime_events
                    (id, event_type, source_host, process_name, user,
                     details, threat_level, detected_at, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.id,
                    event.event_type.value,
                    event.source_host,
                    event.process_name,
                    event.user,
                    json.dumps(event.details),
                    event.threat_level.value,
                    event.detected_at.isoformat(),
                    event.org_id,
                ),
            )
            self._conn.commit()
        logger.debug("edr.event.ingested", event_id=event.id,
                     event_type=event.event_type.value, host=event.source_host)

        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("runtime_protection.event_ingested", {
                    "event_id": event.id,
                    "event_type": event.event_type.value,
                    "source_host": event.source_host,
                    "threat_level": event.threat_level.value,
                    "org_id": event.org_id,
                })
            except Exception:  # noqa: BLE001
                pass

        return event

    def evaluate_policies(self, event: RuntimeEvent, org_id: str) -> List[RuntimeAlert]:
        """
        Evaluate enabled policies against an event and generate alerts.

        Applies org-specific and built-in (default org) policies.

        Args:
            event: The event to evaluate.
            org_id: The org context.

        Returns:
            List of generated RuntimeAlert objects (also persisted).
        """
        policies = self._load_policies_for_event(event.event_type, org_id)
        alerts: List[RuntimeAlert] = []
        for policy in policies:
            if not policy.enabled:
                continue
            matched, threat_level = self._match_policy(event, policy)
            if matched:
                alert = RuntimeAlert(
                    event_id=event.id,
                    policy_id=policy.id,
                    threat_level=threat_level,
                    message=(
                        f"Policy '{policy.name}' triggered on {event.source_host}: "
                        f"process={event.process_name} user={event.user} "
                        f"type={event.event_type.value}"
                    ),
                )
                self._persist_alert(alert, org_id)
                alerts.append(alert)
                logger.warning("edr.alert.generated", policy=policy.name,
                               event_id=event.id, host=event.source_host,
                               threat=threat_level)

        if alerts and _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("runtime_protection.alerts_generated", {
                    "event_id": event.id,
                    "org_id": org_id,
                    "alert_count": len(alerts),
                    "threat_levels": [a.threat_level.value for a in alerts],
                })
            except Exception:  # noqa: BLE001
                pass

        return alerts

    def create_policy(self, policy: RuntimePolicy) -> RuntimePolicy:
        """
        Create a new runtime policy.

        Args:
            policy: The policy to create.

        Returns:
            The created policy.
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO runtime_policies
                    (id, name, event_type, conditions, action, enabled, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.id,
                    policy.name,
                    policy.event_type.value,
                    json.dumps(policy.conditions),
                    policy.action.value,
                    1 if policy.enabled else 0,
                    policy.org_id,
                ),
            )
            self._conn.commit()
        return policy

    def list_policies(self, org_id: str) -> List[RuntimePolicy]:
        """
        List all policies for an org (includes built-in default policies).

        Args:
            org_id: Organization ID.

        Returns:
            List of RuntimePolicy objects.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT id, name, event_type, conditions, action, enabled, org_id
                FROM runtime_policies
                WHERE org_id = ? OR org_id = 'default'
                ORDER BY name
                """,
                (org_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_policy(r) for r in rows]

    def get_active_alerts(self, org_id: str) -> List[RuntimeAlert]:
        """
        Get unacknowledged alerts for an org.

        Args:
            org_id: Organization ID.

        Returns:
            List of unacknowledged RuntimeAlert objects, newest first.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT id, event_id, policy_id, threat_level, message,
                       acknowledged, created_at
                FROM runtime_alerts
                WHERE org_id = ? AND acknowledged = 0
                ORDER BY created_at DESC
                """,
                (org_id,),
            )
            rows = cur.fetchall()
        return [self._row_to_alert(r) for r in rows]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """
        Mark an alert as acknowledged.

        Args:
            alert_id: The alert ID.

        Returns:
            True if found and updated, False if not found.
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                "UPDATE runtime_alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_threat_timeline(self, org_id: str, hours: int = 24) -> List[RuntimeEvent]:
        """
        Get recent threat events (non-NONE threat level) within a time window.

        Args:
            org_id: Organization ID.
            hours: How many hours back to look.

        Returns:
            List of RuntimeEvent objects with non-none threat levels.
        """
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT id, event_type, source_host, process_name, user,
                       details, threat_level, detected_at, org_id
                FROM runtime_events
                WHERE org_id = ? AND threat_level != 'none' AND detected_at >= ?
                ORDER BY detected_at DESC
                """,
                (org_id, since),
            )
            rows = cur.fetchall()
        return [self._row_to_event(r) for r in rows]

    def get_runtime_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Get aggregate statistics for an org.

        Returns:
            Dict with events_total, alerts_total, alerts_active,
            events_by_type, threats_by_level, top_hosts.
        """
        with self._lock:
            cur = self._conn.cursor()

            cur.execute("SELECT COUNT(*) FROM runtime_events WHERE org_id = ?", (org_id,))
            events_total = cur.fetchone()[0]

            cur.execute(
                "SELECT event_type, COUNT(*) FROM runtime_events "
                "WHERE org_id = ? GROUP BY event_type", (org_id,)
            )
            events_by_type = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute(
                "SELECT threat_level, COUNT(*) FROM runtime_events "
                "WHERE org_id = ? AND threat_level != 'none' GROUP BY threat_level",
                (org_id,),
            )
            threats_by_level = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("SELECT COUNT(*) FROM runtime_alerts WHERE org_id = ?", (org_id,))
            alerts_total = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM runtime_alerts WHERE org_id = ? AND acknowledged = 0",
                (org_id,),
            )
            alerts_active = cur.fetchone()[0]

            cur.execute(
                """
                SELECT source_host, COUNT(*) as cnt FROM runtime_events
                WHERE org_id = ? GROUP BY source_host ORDER BY cnt DESC LIMIT 10
                """,
                (org_id,),
            )
            top_hosts = [{"host": r[0], "event_count": r[1]} for r in cur.fetchall()]

        return {
            "org_id": org_id,
            "events_total": events_total,
            "alerts_total": alerts_total,
            "alerts_active": alerts_active,
            "events_by_type": events_by_type,
            "threats_by_level": threats_by_level,
            "top_hosts": top_hosts,
        }

    def detect_anomalies(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Detect unusual patterns in the last hour of event data.

        Detects:
        - High event volume per host (> 50 events/hr)
        - Lateral movement (same user on > 3 hosts)
        - High-threat processes (> 5 critical/high events/hr)

        Args:
            org_id: Organization ID.

        Returns:
            List of anomaly dicts with type, description, severity, details.
        """
        anomalies: List[Dict[str, Any]] = []
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        with self._lock:
            cur = self._conn.cursor()

            # High event volume per host
            cur.execute(
                """
                SELECT source_host, COUNT(*) as cnt FROM runtime_events
                WHERE org_id = ? AND detected_at >= ?
                GROUP BY source_host HAVING cnt > 50 ORDER BY cnt DESC
                """,
                (org_id, since),
            )
            for row in cur.fetchall():
                anomalies.append({
                    "type": "high_event_volume",
                    "description": f"Host {row[0]} generated {row[1]} events in the last hour",
                    "severity": "medium",
                    "details": {"host": row[0], "event_count": row[1], "window": "1h"},
                })

            # Lateral movement — user seen on many hosts
            cur.execute(
                """
                SELECT user, COUNT(DISTINCT source_host) as host_count FROM runtime_events
                WHERE org_id = ? AND detected_at >= ?
                GROUP BY user HAVING host_count > 3 ORDER BY host_count DESC
                """,
                (org_id, since),
            )
            for row in cur.fetchall():
                anomalies.append({
                    "type": "lateral_movement",
                    "description": f"User '{row[0]}' seen on {row[1]} hosts in last hour",
                    "severity": "high",
                    "details": {"user": row[0], "host_count": row[1], "window": "1h"},
                })

            # High-threat processes
            cur.execute(
                """
                SELECT process_name, COUNT(*) as cnt FROM runtime_events
                WHERE org_id = ? AND threat_level IN ('high', 'critical')
                  AND detected_at >= ?
                GROUP BY process_name HAVING cnt > 5 ORDER BY cnt DESC
                """,
                (org_id, since),
            )
            for row in cur.fetchall():
                anomalies.append({
                    "type": "high_threat_process",
                    "description": (
                        f"Process '{row[0]}' triggered {row[1]} "
                        "high/critical events in last hour"
                    ),
                    "severity": "high",
                    "details": {"process": row[0], "threat_count": row[1], "window": "1h"},
                })

        return anomalies

    def get_process_tree(self, host: str, org_id: str) -> List[Dict[str, Any]]:
        """
        Get the process execution chain for a host.

        Returns process_exec events ordered by time, with parent-child
        relationships reconstructed via pid/ppid in event details.

        Args:
            host: Source host to query.
            org_id: Organization ID.

        Returns:
            List of process tree nodes (roots at top level, children nested).
        """
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT id, process_name, user, details, threat_level, detected_at
                FROM runtime_events
                WHERE org_id = ? AND source_host = ? AND event_type = 'process_exec'
                ORDER BY detected_at ASC LIMIT 500
                """,
                (org_id, host),
            )
            rows = cur.fetchall()

        nodes: List[Dict[str, Any]] = []
        for row in rows:
            details = json.loads(row[3]) if row[3] else {}
            nodes.append({
                "event_id": row[0],
                "process_name": row[1],
                "user": row[2],
                "pid": details.get("pid"),
                "ppid": details.get("ppid"),
                "cmdline": details.get("cmdline", ""),
                "threat_level": row[4],
                "timestamp": row[5],
                "children": [],
            })

        # Wire parent-child by pid/ppid
        pid_map: Dict[Any, Dict[str, Any]] = {
            n["pid"]: n for n in nodes if n["pid"] is not None
        }
        roots: List[Dict[str, Any]] = []
        for node in nodes:
            ppid = node.get("ppid")
            if ppid and ppid in pid_map and pid_map[ppid] is not node:
                pid_map[ppid]["children"].append(node)
            else:
                roots.append(node)

        return roots if roots else nodes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_policies_for_event(
        self, event_type: EventType, org_id: str
    ) -> List[RuntimePolicy]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT id, name, event_type, conditions, action, enabled, org_id
                FROM runtime_policies
                WHERE (org_id = ? OR org_id = 'default')
                  AND event_type = ? AND enabled = 1
                """,
                (org_id, event_type.value),
            )
            return [self._row_to_policy(r) for r in cur.fetchall()]

    def _match_policy(
        self, event: RuntimeEvent, policy: RuntimePolicy
    ) -> Tuple[bool, ThreatLevel]:
        """Return (matched, threat_level) for an event against a policy."""
        conditions = policy.conditions
        details = event.details
        process = event.process_name.lower()

        # Determine threat level from built-in definition or event itself
        threat_level: ThreatLevel = ThreatLevel.MEDIUM
        for bp in _EDR_BUILTIN_POLICIES:
            if bp["id"] == policy.id:
                threat_level = bp.get("threat_level", ThreatLevel.MEDIUM)
                break
        if event.threat_level != ThreatLevel.NONE:
            threat_level = event.threat_level

        # --- Process name list ---
        process_names = [p.lower() for p in conditions.get("process_names", [])]
        cmdline_patterns = [c.lower() for c in conditions.get("cmdline_contains", [])]
        cmdline = details.get("cmdline", "").lower()

        if process_names or cmdline_patterns:
            process_hit = process in process_names if process_names else False
            cmdline_hit = any(pat in cmdline for pat in cmdline_patterns) if cmdline_patterns else False
            if not process_hit and not cmdline_hit:
                # Neither matched — skip unless other conditions apply
                if not conditions.get("paths") and not conditions.get("indicators") \
                        and conditions.get("large_outbound_bytes_threshold") is None \
                        and conditions.get("uid_transition") is None:
                    return False, ThreatLevel.NONE
            elif process_hit or cmdline_hit:
                return True, threat_level

        # --- File path matching ---
        sensitive_paths = conditions.get("paths", []) + conditions.get("sensitive_file_paths", [])
        if sensitive_paths:
            accessed = details.get("path", details.get("file", "")).lower()
            if any(sp.lower() in accessed for sp in sensitive_paths if sp):
                return True, threat_level

        # --- Container escape indicators ---
        indicators = conditions.get("indicators", [])
        if indicators:
            event_indicators = details.get("indicators", [])
            if any(ind in event_indicators for ind in indicators):
                return True, threat_level
            if any(details.get(ind) for ind in indicators):
                return True, threat_level

        # --- Large outbound bytes ---
        threshold = conditions.get("large_outbound_bytes_threshold")
        if threshold is not None and details.get("bytes_out", 0) >= threshold:
            return True, threat_level

        # --- Privilege escalation ---
        if conditions.get("uid_transition") == "non-root-to-root":
            if (details.get("uid_before", -1) != 0 and details.get("uid_after") == 0) \
                    or details.get("escalated") is True:
                return True, threat_level

        return False, ThreatLevel.NONE

    def _persist_alert(self, alert: RuntimeAlert, org_id: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO runtime_alerts
                    (id, event_id, policy_id, threat_level, message,
                     acknowledged, created_at, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    alert.event_id,
                    alert.policy_id,
                    alert.threat_level.value,
                    alert.message,
                    1 if alert.acknowledged else 0,
                    alert.created_at.isoformat(),
                    org_id,
                ),
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Row converters
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row: tuple) -> RuntimeEvent:
        return RuntimeEvent(
            id=row[0],
            event_type=EventType(row[1]),
            source_host=row[2],
            process_name=row[3],
            user=row[4],
            details=json.loads(row[5]) if row[5] else {},
            threat_level=ThreatLevel(row[6]),
            detected_at=datetime.fromisoformat(row[7]),
            org_id=row[8],
        )

    @staticmethod
    def _row_to_policy(row: tuple) -> RuntimePolicy:
        return RuntimePolicy(
            id=row[0],
            name=row[1],
            event_type=EventType(row[2]),
            conditions=json.loads(row[3]) if row[3] else {},
            action=PolicyAction(row[4]),
            enabled=bool(row[5]),
            org_id=row[6],
        )

    @staticmethod
    def _row_to_alert(row: tuple) -> RuntimeAlert:
        return RuntimeAlert(
            id=row[0],
            event_id=row[1],
            policy_id=row[2],
            threat_level=ThreatLevel(row[3]),
            message=row[4],
            acknowledged=bool(row[5]),
            created_at=datetime.fromisoformat(row[6]),
        )
