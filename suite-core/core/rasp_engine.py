"""
Runtime Application Self-Protection (RASP) Engine — ALDECI.

Inspects every inbound HTTP request for attack patterns at runtime:
- SQL injection (SQLi)
- Cross-site scripting (XSS)
- Command injection (CMDi)
- Path traversal / LFI / RFI
- XML external entity injection (XXE)
- Server-side request forgery (SSRF)

Operating modes: monitor-only, block (403), redirect (honeypot).
Per-IP and per-API-key sliding-window rate limiting with auto-block.
Session anomaly detection: fixation, concurrent sessions, impossible travel.
Runtime metrics with TrustGraph integration stubs.

Compliance: OWASP ASVS v4.0, CWE-89/79/78/22/611/918.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


def _emit_event(event_type: str, payload) -> None:  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises.

    RASP is a hot-path runtime engine — telemetry MUST be best-effort.
    Mirrors the canonical pattern from sast_engine / ctem_engine /
    cloud_connectors / llm_council._enrich_with_trustgraph.
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
    except Exception:  # pragma: no cover - best-effort telemetry
        pass


# Module-load heartbeat — fires once per process so rasp_engine
# is observable in the TrustGraph second-brain.
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "rasp_engine.db")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RaspMode(str, Enum):
    """Operating mode for the RASP engine."""

    MONITOR = "monitor"    # log + allow — no blocking
    BLOCK = "block"        # reject with HTTP 403
    REDIRECT = "redirect"  # forward to honeypot URL


class ThreatCategory(str, Enum):
    """OWASP-aligned threat categories."""

    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class DetectionPattern(BaseModel):
    """A single detection rule."""

    rule_id: str
    category: ThreatCategory
    name: str
    description: str
    pattern: str          # raw regex string
    severity: ThreatSeverity
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    enabled: bool = True


class ThreatEvent(BaseModel):
    """A detected threat event."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float
    client_ip: str
    api_key: Optional[str] = None
    method: str
    path: str
    matched_value: str        # sanitised excerpt of the malicious value
    matched_field: str        # query param name, header name, body field, etc.
    action_taken: RaspMode    # what the engine did (monitor/block/redirect)
    org_id: str = "default"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    window_seconds: int = 60
    max_requests: int = 200
    max_violations: int = 5       # auto-block after N threat events in window
    auto_block_duration: int = 300  # seconds to block after N violations


class SessionRecord(BaseModel):
    """Tracks a single authenticated session."""

    session_id: str
    user_id: str
    client_ip: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    geo_country: str = "unknown"


class RaspConfig(BaseModel):
    """Full RASP engine configuration."""

    mode: RaspMode = RaspMode.MONITOR
    honeypot_url: str = "http://honeypot.internal/trap"
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    max_body_inspect_bytes: int = 65536   # 64 KB
    inspect_request_body: bool = True
    inspect_headers: bool = True
    inspect_query_params: bool = True
    trusted_ips: List[str] = Field(default_factory=list)
    enabled_categories: List[ThreatCategory] = Field(
        default_factory=lambda: list(ThreatCategory)
    )


class RaspMetrics(BaseModel):
    """Runtime metrics snapshot."""

    requests_inspected: int = 0
    threats_detected: int = 0
    threats_blocked: int = 0
    threats_allowed_monitor: int = 0
    threats_redirected: int = 0
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    top_attacker_ips: Dict[str, int] = Field(default_factory=dict)
    false_positive_rate: float = 0.0   # updated externally via feedback
    engine_uptime_seconds: float = 0.0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AttackerStats(BaseModel):
    """Per-IP attacker summary."""

    ip: str
    total_threats: int
    categories: Dict[str, int]
    first_seen: datetime
    last_seen: datetime
    is_blocked: bool
    block_expires_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Detection patterns (compiled once at module load)
# ---------------------------------------------------------------------------

_RAW_PATTERNS: List[Dict[str, Any]] = [
    # ---- SQL injection ----
    {
        "rule_id": "SQLI-001",
        "category": ThreatCategory.SQLI,
        "name": "Union-based SQLi",
        "description": "UNION SELECT injection attempt",
        "pattern": r"(?i)\bunion\b.{0,20}\bselect\b",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.95,
    },
    {
        "rule_id": "SQLI-002",
        "category": ThreatCategory.SQLI,
        "name": "Tautology SQLi",
        "description": "Boolean tautology (or 1=1) injection",
        "pattern": r"(?i)\bor\b\s+['\"0-9]+\s*=\s*['\"0-9]+",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.92,
    },
    {
        "rule_id": "SQLI-003",
        "category": ThreatCategory.SQLI,
        "name": "Comment truncation SQLi",
        "description": "Inline comment used to truncate SQL",
        "pattern": r"(?i)(--|#|\/\*).{0,50}",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.75,
    },
    {
        "rule_id": "SQLI-004",
        "category": ThreatCategory.SQLI,
        "name": "Stacked queries",
        "description": "Semicolon-separated SQL stacking",
        "pattern": r"(?i);\s*(drop|insert|update|delete|create|alter|exec)\b",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.93,
    },
    {
        "rule_id": "SQLI-005",
        "category": ThreatCategory.SQLI,
        "name": "Sleep-based blind SQLi",
        "description": "Time-based blind injection using SLEEP/WAITFOR",
        "pattern": r"(?i)\b(sleep|waitfor\s+delay|benchmark)\s*\(",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.90,
    },
    # ---- XSS ----
    {
        "rule_id": "XSS-001",
        "category": ThreatCategory.XSS,
        "name": "Script tag XSS",
        "description": "Raw <script> tag injection",
        "pattern": r"(?i)<\s*script[\s>]",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.95,
    },
    {
        "rule_id": "XSS-002",
        "category": ThreatCategory.XSS,
        "name": "Inline event handler XSS",
        "description": "on* event handler attribute injection",
        "pattern": r"(?i)\bon\w+\s*=\s*['\"]?[^'\">\s]",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.90,
    },
    {
        "rule_id": "XSS-003",
        "category": ThreatCategory.XSS,
        "name": "javascript: URI XSS",
        "description": "javascript: protocol in href/src",
        "pattern": r"(?i)javascript\s*:",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.90,
    },
    {
        "rule_id": "XSS-004",
        "category": ThreatCategory.XSS,
        "name": "vbscript: URI XSS",
        "description": "vbscript: protocol injection",
        "pattern": r"(?i)vbscript\s*:",
        "severity": ThreatSeverity.MEDIUM,
        "confidence": 0.85,
    },
    {
        "rule_id": "XSS-005",
        "category": ThreatCategory.XSS,
        "name": "Data URI XSS",
        "description": "data: URI with html/javascript MIME",
        "pattern": r"(?i)data\s*:\s*text/(html|javascript)",
        "severity": ThreatSeverity.MEDIUM,
        "confidence": 0.80,
    },
    # ---- Command injection ----
    {
        "rule_id": "CMDI-001",
        "category": ThreatCategory.CMDI,
        "name": "Shell pipe injection",
        "description": "Pipe character used to chain shell commands",
        "pattern": r"\|\s*\w+",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.80,
    },
    {
        "rule_id": "CMDI-002",
        "category": ThreatCategory.CMDI,
        "name": "Semicolon command chaining",
        "description": "Semicolon-separated shell command execution",
        "pattern": r";\s*(ls|cat|id|whoami|uname|curl|wget|nc|bash|sh|python|perl|ruby|php)\b",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.88,
    },
    {
        "rule_id": "CMDI-003",
        "category": ThreatCategory.CMDI,
        "name": "Backtick command substitution",
        "description": "Backtick shell substitution",
        "pattern": r"`[^`]+`",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.85,
    },
    {
        "rule_id": "CMDI-004",
        "category": ThreatCategory.CMDI,
        "name": "$() command substitution",
        "description": "Dollar-paren shell substitution",
        "pattern": r"\$\([^)]+\)",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.88,
    },
    # ---- Path traversal ----
    {
        "rule_id": "PATHT-001",
        "category": ThreatCategory.PATH_TRAVERSAL,
        "name": "Dot-dot-slash traversal",
        "description": "../ directory traversal",
        "pattern": r"\.\./",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.90,
    },
    {
        "rule_id": "PATHT-002",
        "category": ThreatCategory.PATH_TRAVERSAL,
        "name": "URL-encoded dot-dot traversal",
        "description": "%2e%2e URL-encoded traversal",
        "pattern": r"(?i)%2e%2e[%2f/\\]",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.92,
    },
    {
        "rule_id": "PATHT-003",
        "category": ThreatCategory.PATH_TRAVERSAL,
        "name": "Double-encoded traversal",
        "description": "Double URL-encoded traversal",
        "pattern": r"(?i)%252e%252e",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.92,
    },
    {
        "rule_id": "PATHT-004",
        "category": ThreatCategory.PATH_TRAVERSAL,
        "name": "Windows path traversal",
        "description": "..\\ Windows-style traversal",
        "pattern": r"\.\.[/\\]",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.90,
    },
    # ---- XXE ----
    {
        "rule_id": "XXE-001",
        "category": ThreatCategory.XXE,
        "name": "DOCTYPE entity declaration",
        "description": "XML DOCTYPE with ENTITY declaration",
        "pattern": r"(?i)<!DOCTYPE\b.{0,50}<!ENTITY",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.95,
        "multiline": True,
    },
    {
        "rule_id": "XXE-002",
        "category": ThreatCategory.XXE,
        "name": "SYSTEM entity reference",
        "description": "SYSTEM keyword in XML entity",
        "pattern": r"(?i)ENTITY\s+\w+\s+SYSTEM\s+['\"]",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.95,
    },
    # ---- SSRF ----
    {
        "rule_id": "SSRF-001",
        "category": ThreatCategory.SSRF,
        "name": "Internal IP in URL param",
        "description": "Private RFC1918 address in URL parameter",
        "pattern": r"(?i)(https?://)?(127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.85,
    },
    {
        "rule_id": "SSRF-002",
        "category": ThreatCategory.SSRF,
        "name": "Metadata service URL",
        "description": "Cloud metadata endpoint access attempt",
        "pattern": r"(?i)(169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2)",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.97,
    },
    # ---- LFI ----
    {
        "rule_id": "LFI-001",
        "category": ThreatCategory.LFI,
        "name": "Sensitive file access",
        "description": "Attempt to read sensitive system files",
        "pattern": r"(?i)(etc/passwd|etc/shadow|etc/hosts|proc/self|windows/system32|boot\.ini|win\.ini)",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.95,
    },
    {
        "rule_id": "LFI-002",
        "category": ThreatCategory.LFI,
        "name": "PHP wrapper LFI",
        "description": "PHP stream wrapper used for LFI",
        "pattern": r"(?i)php://(filter|input|stdin|data|file|zip|phar)",
        "severity": ThreatSeverity.HIGH,
        "confidence": 0.93,
    },
    # ---- RFI ----
    {
        "rule_id": "RFI-001",
        "category": ThreatCategory.RFI,
        "name": "Remote file include via URL",
        "description": "HTTP/FTP URL in file include context",
        "pattern": r"(?i)(include|require|include_once|require_once)\s*\(?\s*['\"]?(https?|ftp)://",
        "severity": ThreatSeverity.CRITICAL,
        "confidence": 0.93,
    },
]


def _compile_patterns(raw: List[Dict[str, Any]]) -> List[Tuple[DetectionPattern, re.Pattern]]:  # type: ignore[type-arg]
    """Compile raw pattern dicts into (DetectionPattern, compiled regex) pairs."""
    compiled: List[Tuple[DetectionPattern, re.Pattern]] = []  # type: ignore[type-arg]
    for p in raw:
        flags = re.DOTALL if p.get("multiline") else 0
        try:
            regex = re.compile(p["pattern"], flags)
            dp = DetectionPattern(**{k: v for k, v in p.items() if k != "multiline"})
            compiled.append((dp, regex))
        except re.error as exc:
            _logger.warning("rasp: could not compile pattern %s: %s", p.get("rule_id"), exc)
    return compiled


_COMPILED_PATTERNS: List[Tuple[DetectionPattern, re.Pattern]] = _compile_patterns(_RAW_PATTERNS)  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# Sliding-window counter (in-memory, thread-safe)
# ---------------------------------------------------------------------------


class _SlidingWindow:
    """Fixed-size sliding window counter keyed by (key, bucket)."""

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        # key -> deque of timestamps
        self._data: Dict[str, Deque[float]] = defaultdict(deque)

    def increment(self, key: str) -> int:
        """Add an event and return current count within window."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            dq = self._data[key]
            dq.append(now)
            # prune old
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def count(self, key: str) -> int:
        """Return current count for a key without adding a new event."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            dq = self._data[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)

    def reset(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


# ---------------------------------------------------------------------------
# Session store (in-memory)
# ---------------------------------------------------------------------------


class _SessionStore:
    """Thread-safe in-memory session registry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # session_id -> SessionRecord
        self._sessions: Dict[str, SessionRecord] = {}
        # user_id -> set of active session_ids
        self._user_sessions: Dict[str, Set[str]] = defaultdict(set)

    def register(self, session: SessionRecord) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._user_sessions[session.user_id].add(session.session_id)

    def touch(self, session_id: str, client_ip: str) -> Optional[str]:
        """Update last_seen; return 'fixation' if IP changed on existing session."""
        with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                return None
            if rec.client_ip != client_ip:
                anomaly = "session_fixation"
                rec.client_ip = client_ip
                rec.last_seen = datetime.now(timezone.utc)
                return anomaly
            rec.last_seen = datetime.now(timezone.utc)
            return None

    def concurrent_count(self, user_id: str) -> int:
        with self._lock:
            return len(self._user_sessions.get(user_id, set()))

    def remove(self, session_id: str) -> None:
        with self._lock:
            rec = self._sessions.pop(session_id, None)
            if rec:
                self._user_sessions[rec.user_id].discard(session_id)

    def all_for_user(self, user_id: str) -> List[SessionRecord]:
        with self._lock:
            ids = self._user_sessions.get(user_id, set())
            return [self._sessions[s] for s in ids if s in self._sessions]


# ---------------------------------------------------------------------------
# Core RASP Engine
# ---------------------------------------------------------------------------


class RaspEngine:
    """
    Runtime Application Self-Protection engine.

    Usage (FastAPI middleware integration):

        rasp = RaspEngine()

        @app.middleware("http")
        async def rasp_middleware(request: Request, call_next):
            result = await rasp.inspect_request(request)
            if result.blocked:
                return JSONResponse(status_code=403, content={"detail": "Blocked"})
            return await call_next(request)

    All public methods are thread-safe via RLock.
    """

    def __init__(
        self,
        config: Optional[RaspConfig] = None,
        db_path: str = _DEFAULT_DB,
    ) -> None:
        self._config = config or RaspConfig()
        self._db_path = db_path
        self._lock = threading.RLock()
        self._started_at = time.monotonic()

        # Pattern store (mutable — rules can be toggled)
        self._patterns: List[Tuple[DetectionPattern, re.Pattern]] = list(_COMPILED_PATTERNS)  # type: ignore[type-arg]

        # Rate limiting windows
        self._req_window = _SlidingWindow(self._config.rate_limit.window_seconds)
        self._viol_window = _SlidingWindow(self._config.rate_limit.window_seconds)

        # Auto-blocked IPs: ip -> unblock_monotonic_timestamp
        self._blocked_ips: Dict[str, float] = {}

        # Session protection
        self._sessions = _SessionStore()

        # Metrics (in-memory)
        self._metrics = RaspMetrics()

        # Recent threat log (ring buffer, max 1000)
        self._threat_log: Deque[ThreatEvent] = deque(maxlen=1000)

        # Persistent storage
        self._init_db()

        _logger.info("rasp: engine initialised (mode=%s, db=%s)", self._config.mode, self._db_path)

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    event_id     TEXT PRIMARY KEY,
                    timestamp    DATETIME NOT NULL,
                    rule_id      TEXT NOT NULL,
                    category     TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    confidence   REAL NOT NULL,
                    client_ip    TEXT NOT NULL,
                    api_key      TEXT,
                    method       TEXT NOT NULL,
                    path         TEXT NOT NULL,
                    matched_value TEXT NOT NULL,
                    matched_field TEXT NOT NULL,
                    action_taken  TEXT NOT NULL,
                    org_id        TEXT NOT NULL DEFAULT 'default'
                );

                CREATE INDEX IF NOT EXISTS idx_te_ip_time
                    ON threat_events (client_ip, timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_te_category
                    ON threat_events (category, timestamp DESC);

                CREATE TABLE IF NOT EXISTS false_positive_feedback (
                    event_id  TEXT PRIMARY KEY,
                    reported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reporter  TEXT
                );
            """)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @property
    def config(self) -> RaspConfig:
        with self._lock:
            return self._config.model_copy()

    def set_mode(self, mode: RaspMode) -> None:
        with self._lock:
            self._config.mode = mode
        _logger.info("rasp: mode changed to %s", mode)

    def update_config(self, **kwargs: Any) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self._config, k):
                    setattr(self._config, k, v)

    # ------------------------------------------------------------------
    # Pattern / rule management
    # ------------------------------------------------------------------

    def get_rules(self) -> List[DetectionPattern]:
        with self._lock:
            return [p for p, _ in self._patterns]

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule by ID. Returns True if found."""
        with self._lock:
            for i, (dp, regex) in enumerate(self._patterns):
                if dp.rule_id == rule_id:
                    updated = dp.model_copy(update={"enabled": enabled})
                    self._patterns[i] = (updated, regex)
                    _logger.info("rasp: rule %s enabled=%s", rule_id, enabled)
                    return True
        return False

    # ------------------------------------------------------------------
    # Core inspection logic
    # ------------------------------------------------------------------

    def inspect_values(
        self,
        values: Dict[str, str],
        *,
        client_ip: str,
        method: str,
        path: str,
        api_key: Optional[str] = None,
        org_id: str = "default",
    ) -> List[ThreatEvent]:
        """
        Inspect a dict of field-name->value pairs for attack patterns.

        Returns list of ThreatEvents (may be empty).
        """
        events: List[ThreatEvent] = []
        enabled_cats = set(self._config.enabled_categories)

        with self._lock:
            patterns = list(self._patterns)

        for field_name, raw_value in values.items():
            # URL-decode to catch encoded payloads
            decoded = urllib.parse.unquote_plus(raw_value)

            for dp, regex in patterns:
                if not dp.enabled:
                    continue
                if dp.category not in enabled_cats:
                    continue
                if regex.search(decoded):
                    # Truncate matched excerpt to 200 chars for safety
                    excerpt = decoded[:200]
                    event = ThreatEvent(
                        rule_id=dp.rule_id,
                        category=dp.category,
                        severity=dp.severity,
                        confidence=dp.confidence,
                        client_ip=client_ip,
                        api_key=api_key,
                        method=method,
                        path=path,
                        matched_value=excerpt,
                        matched_field=field_name,
                        action_taken=self._config.mode,
                        org_id=org_id,
                    )
                    events.append(event)
                    # One event per field per pattern — stop at first match per pattern
                    break
        return events

    def inspect_request_sync(
        self,
        *,
        client_ip: str,
        method: str,
        path: str,
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body_text: Optional[str] = None,
        api_key: Optional[str] = None,
        org_id: str = "default",
    ) -> Tuple[bool, List[ThreatEvent]]:
        """
        Synchronous inspection entry point.

        Returns (blocked: bool, threats: List[ThreatEvent]).
        blocked=True means the engine decided to block (mode=BLOCK).
        In MONITOR mode blocked is always False.
        In REDIRECT mode blocked is True (caller should redirect).
        """
        with self._lock:
            self._metrics.requests_inspected += 1

        # --- Trusted IP bypass ---
        if client_ip in self._config.trusted_ips:
            return False, []

        # --- Auto-block check ---
        if self._is_ip_blocked(client_ip):
            _logger.warning("rasp: auto-blocked IP %s — request rejected", client_ip)
            return True, []

        # --- Rate limiting (requests per window) ---
        req_count = self._req_window.increment(client_ip)
        if req_count > self._config.rate_limit.max_requests:
            _logger.warning("rasp: rate limit exceeded for IP %s (%d req)", client_ip, req_count)
            # Count as a violation
            self._record_violation(client_ip)
            return True, []

        # --- Build field map for inspection ---
        fields: Dict[str, str] = {}

        if self._config.inspect_query_params and query_params:
            for k, v in query_params.items():
                fields[f"query:{k}"] = v

        if self._config.inspect_headers and headers:
            # Only inspect user-controlled headers
            _safe_header_names = {
                "user-agent", "referer", "x-forwarded-for", "x-real-ip",
                "accept", "accept-language", "cookie", "authorization",
                "x-api-key", "content-type",
            }
            for k, v in headers.items():
                if k.lower() in _safe_header_names:
                    fields[f"header:{k.lower()}"] = v

        if self._config.inspect_request_body and body_text:
            trimmed = body_text[: self._config.max_body_inspect_bytes]
            fields["body"] = trimmed

        # Also inspect the path itself
        fields["path"] = path

        # --- Pattern matching ---
        events = self.inspect_values(
            fields,
            client_ip=client_ip,
            method=method,
            path=path,
            api_key=api_key,
            org_id=org_id,
        )

        if not events:
            return False, []

        # --- Record threats ---
        for ev in events:
            self._record_threat(ev)

        # --- Violation counting for auto-block ---
        self._record_violation(client_ip)

        # --- Decide action ---
        mode = self._config.mode
        blocked = mode in (RaspMode.BLOCK, RaspMode.REDIRECT)

        with self._lock:
            if blocked:
                self._metrics.threats_blocked += len(events)
                if mode == RaspMode.REDIRECT:
                    self._metrics.threats_redirected += len(events)
            else:
                self._metrics.threats_allowed_monitor += len(events)

        return blocked, events

    # ------------------------------------------------------------------
    # Rate limiting & auto-block
    # ------------------------------------------------------------------

    def _is_ip_blocked(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            unblock_at = self._blocked_ips.get(ip)
            if unblock_at is None:
                return False
            if now >= unblock_at:
                del self._blocked_ips[ip]
                _logger.info("rasp: auto-block expired for %s", ip)
                return False
            return True

    def _record_violation(self, ip: str) -> None:
        count = self._viol_window.increment(f"viol:{ip}")
        if count >= self._config.rate_limit.max_violations:
            duration = self._config.rate_limit.auto_block_duration
            with self._lock:
                self._blocked_ips[ip] = time.monotonic() + duration
            _logger.warning(
                "rasp: auto-blocked IP %s for %ds after %d violations",
                ip, duration, count,
            )

    def block_ip(self, ip: str, duration_seconds: int = 3600) -> None:
        """Manually block an IP for a fixed duration."""
        with self._lock:
            self._blocked_ips[ip] = time.monotonic() + duration_seconds
        _logger.info("rasp: manually blocked %s for %ds", ip, duration_seconds)

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP. Returns True if it was blocked."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                _logger.info("rasp: manually unblocked %s", ip)
                return True
        return False

    def get_blocked_ips(self) -> Dict[str, float]:
        """Return dict of ip -> seconds remaining until unblock."""
        now = time.monotonic()
        with self._lock:
            return {
                ip: max(0.0, unblock_at - now)
                for ip, unblock_at in self._blocked_ips.items()
            }

    # ------------------------------------------------------------------
    # Threat recording
    # ------------------------------------------------------------------

    def _record_threat(self, event: ThreatEvent) -> None:
        with self._lock:
            self._metrics.threats_detected += 1
            cat_key = event.category.value
            sev_key = event.severity.value
            self._metrics.by_category[cat_key] = self._metrics.by_category.get(cat_key, 0) + 1
            self._metrics.by_severity[sev_key] = self._metrics.by_severity.get(sev_key, 0) + 1
            self._metrics.top_attacker_ips[event.client_ip] = (
                self._metrics.top_attacker_ips.get(event.client_ip, 0) + 1
            )
            self._threat_log.append(event)

        _logger.warning(
            "rasp: threat detected rule=%s cat=%s sev=%s ip=%s path=%s",
            event.rule_id, event.category, event.severity, event.client_ip, event.path,
        )

        # Persist to SQLite (non-blocking — best-effort)
        try:
            self._persist_threat(event)
        except Exception:
            _logger.debug("rasp: failed to persist threat event %s", event.event_id, exc_info=True)

        # TrustGraph stub
        self._index_in_trustgraph(event)

    def _persist_threat(self, event: ThreatEvent) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO threat_events
                (event_id, timestamp, rule_id, category, severity, confidence,
                 client_ip, api_key, method, path, matched_value, matched_field,
                 action_taken, org_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.rule_id,
                    event.category.value,
                    event.severity.value,
                    event.confidence,
                    event.client_ip,
                    event.api_key,
                    event.method,
                    event.path,
                    event.matched_value,
                    event.matched_field,
                    event.action_taken.value,
                    event.org_id,
                ),
            )

    # ------------------------------------------------------------------
    # Session protection
    # ------------------------------------------------------------------

    def register_session(self, session: SessionRecord) -> None:
        """Register a new authenticated session."""
        self._sessions.register(session)
        _logger.debug("rasp: session registered %s user=%s", session.session_id, session.user_id)

    def check_session(
        self,
        session_id: str,
        client_ip: str,
        user_id: Optional[str] = None,
        max_concurrent: int = 5,
    ) -> List[str]:
        """
        Validate a session. Returns list of anomaly strings (empty = clean).

        Detected anomalies:
        - session_fixation   — IP changed within the same session
        - too_many_sessions  — user has > max_concurrent active sessions
        """
        anomalies: List[str] = []

        fixation = self._sessions.touch(session_id, client_ip)
        if fixation:
            anomalies.append(fixation)
            _logger.warning("rasp: session fixation detected sid=%s ip=%s", session_id, client_ip)

        if user_id:
            count = self._sessions.concurrent_count(user_id)
            if count > max_concurrent:
                anomalies.append("too_many_sessions")
                _logger.warning(
                    "rasp: too many concurrent sessions user=%s count=%d", user_id, count
                )

        return anomalies

    def terminate_session(self, session_id: str) -> None:
        self._sessions.remove(session_id)

    def detect_impossible_travel(
        self,
        user_id: str,
        new_ip: str,
        new_country: str,
        max_speed_kmh: float = 900.0,
    ) -> bool:
        """
        Detect if user appears to be in two geographically impossible locations.

        This is a stub that detects simple country-mismatch anomalies
        (full geo-IP lookup integration would supply real lat/lon).

        Returns True if impossible travel is detected.
        """
        sessions = self._sessions.all_for_user(user_id)
        now = datetime.now(timezone.utc)
        for sess in sessions:
            if sess.client_ip == new_ip:
                continue
            # Different country AND last seen within 1 hour
            age_seconds = (now - sess.last_seen).total_seconds()
            if sess.geo_country != new_country and age_seconds < 3600:
                _logger.warning(
                    "rasp: impossible travel user=%s was=%s now=%s last_seen=%ds ago",
                    user_id, sess.geo_country, new_country, age_seconds,
                )
                return True
        return False

    # ------------------------------------------------------------------
    # Metrics & reporting
    # ------------------------------------------------------------------

    def get_metrics(self) -> RaspMetrics:
        with self._lock:
            m = self._metrics.model_copy()
            m.engine_uptime_seconds = time.monotonic() - self._started_at
            # Keep top 10 attacker IPs
            top10 = dict(
                sorted(m.top_attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            )
            m.top_attacker_ips = top10
            return m

    def get_recent_threats(self, limit: int = 100, category: Optional[ThreatCategory] = None) -> List[ThreatEvent]:
        with self._lock:
            events = list(self._threat_log)

        if category:
            events = [e for e in events if e.category == category]

        # Most recent first
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[:limit]

    def get_attacker_stats(self, limit: int = 20) -> List[AttackerStats]:
        """Summarise top attacker IPs from the persistent DB."""
        try:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT client_ip,
                           COUNT(*) as total,
                           MIN(timestamp) as first_seen,
                           MAX(timestamp) as last_seen,
                           category
                    FROM threat_events
                    GROUP BY client_ip
                    ORDER BY total DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()

            stats: List[AttackerStats] = []
            for row in rows:
                ip = row["client_ip"]
                # category breakdown
                cat_rows = self._get_conn().execute(
                    "SELECT category, COUNT(*) as n FROM threat_events WHERE client_ip=? GROUP BY category",
                    (ip,),
                ).fetchall()
                categories = {r["category"]: r["n"] for r in cat_rows}

                now = time.monotonic()
                with self._lock:
                    unblock_at = self._blocked_ips.get(ip)
                is_blocked = unblock_at is not None and now < unblock_at
                block_exp = None
                if is_blocked and unblock_at:
                    delta = unblock_at - now
                    block_exp = datetime.now(timezone.utc) + timedelta(seconds=delta)

                stats.append(AttackerStats(
                    ip=ip,
                    total_threats=row["total"],
                    categories=categories,
                    first_seen=datetime.fromisoformat(row["first_seen"]),
                    last_seen=datetime.fromisoformat(row["last_seen"]),
                    is_blocked=is_blocked,
                    block_expires_at=block_exp,
                ))
            return stats
        except Exception:
            _logger.debug("rasp: get_attacker_stats failed", exc_info=True)
            return []

    def report_false_positive(self, event_id: str, reporter: str = "system") -> bool:
        """Mark an event as a false positive and update the FP rate.

        Returns False if the event_id does not exist in threat_events.
        """
        try:
            with self._get_conn() as conn:
                exists = conn.execute(
                    "SELECT 1 FROM threat_events WHERE event_id = ?", (event_id,)
                ).fetchone()
                if not exists:
                    return False
                conn.execute(
                    "INSERT OR IGNORE INTO false_positive_feedback (event_id, reporter) VALUES (?,?)",
                    (event_id, reporter),
                )
                fp_count = conn.execute(
                    "SELECT COUNT(*) FROM false_positive_feedback"
                ).fetchone()[0]
                total_count = conn.execute(
                    "SELECT COUNT(*) FROM threat_events"
                ).fetchone()[0]

            if total_count > 0:
                with self._lock:
                    self._metrics.false_positive_rate = fp_count / total_count
            return True
        except Exception:
            _logger.debug("rasp: report_false_positive failed", exc_info=True)
            return False

    # ------------------------------------------------------------------
    # TrustGraph integration (FEATURE-2 wired 2026-05-02)
    # ------------------------------------------------------------------

    def _index_in_trustgraph(self, event: ThreatEvent) -> None:
        """Index a blocked/observed attack into TrustGraph via the event bus.

        Emits ``rasp.attack_detected`` (canonical) so downstream handlers
        (KnowledgeBrainAdapter, AgentDB dual-write, alert broadcaster)
        can correlate the IP, rule, CWE category, and asset across cores.

        Best-effort — never raises (RASP is a hot path).
        """
        try:
            payload: Dict[str, Any] = {
                "event_id": event.event_id,
                "rule_id": event.rule_id,
                "category": event.category.value if hasattr(event.category, "value") else str(event.category),
                "severity": event.severity.value if hasattr(event.severity, "value") else str(event.severity),
                "confidence": event.confidence,
                "attacker_ip": event.client_ip,
                "request_path": event.path,
                "request_method": event.method,
                "matched_field": event.matched_field,
                "action_taken": event.action_taken,
                "asset_id": getattr(event, "asset_id", None) or event.path,
                "org_id": event.org_id,
                "timestamp": event.timestamp.isoformat(),
                "source_engine": "rasp_engine",
                "entity_type": "rasp_threat_event",
            }
            _emit_event("rasp.attack_detected", payload)
        except Exception:  # pragma: no cover - best-effort
            _logger.debug("rasp: trustgraph emit failed for event_id=%s", event.event_id, exc_info=True)

    def trustgraph_query_attacker(self, ip: str) -> Dict[str, Any]:
        """Query TrustGraph for correlated intelligence on an attacker IP.

        Real wiring: emits ``rasp.attacker_query`` (so the query is also
        recorded in the second-brain), then asks the bus's backbone /
        KnowledgeBrainAdapter for correlated entities. Falls back to local
        SQLite stats if the adapter is unavailable.
        """
        # Emit the query itself — useful for hunters to see what's been asked
        try:
            _emit_event(
                "rasp.attacker_query",
                {"attacker_ip": ip, "source_engine": "rasp_engine", "entity_type": "rasp_query"},
            )
        except Exception:  # pragma: no cover
            pass

        # Try real backbone correlation
        correlated_entities: List[Dict[str, Any]] = []
        adapter_available = False
        try:
            if _get_tg_bus is not None:
                bus = _get_tg_bus()
                backbone = getattr(bus, "backbone", None) if bus is not None else None
                adapter = getattr(backbone, "adapter", None) if backbone is not None else None
                query_fn = getattr(adapter, "query", None) if adapter is not None else None
                if callable(query_fn):
                    adapter_available = True
                    try:
                        result = query_fn({"attacker_ip": ip, "limit": 25})
                        if isinstance(result, list):
                            correlated_entities = result
                        elif isinstance(result, dict):
                            correlated_entities = result.get("entities", []) or []
                    except Exception:  # pragma: no cover
                        adapter_available = False
        except Exception:  # pragma: no cover
            adapter_available = False

        # Local SQLite fallback — counts past sightings of this IP
        local_hits = 0
        local_rules: List[str] = []
        try:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "SELECT rule_id, COUNT(*) FROM threat_events WHERE client_ip = ? GROUP BY rule_id",
                    (ip,),
                )
                for rule_id, count in cur.fetchall():
                    local_hits += int(count)
                    local_rules.append(rule_id)
        except Exception:  # pragma: no cover
            pass

        return {
            "ip": ip,
            "trustgraph_correlated": adapter_available and bool(correlated_entities),
            "correlated_entities": correlated_entities,
            "local_sightings": local_hits,
            "local_rules": local_rules,
            "known_threat_actor": None,
            "related_cves": [],
            "source": "trustgraph_backbone" if adapter_available else "local_sqlite",
        }

    def trustgraph_correlate_campaign(self, events: List[ThreatEvent]) -> Dict[str, Any]:
        """Correlate a set of events to identify attack campaigns via TrustGraph.

        Emits ``rasp.campaign_correlated`` with the rolled-up IP/rule/category
        buckets so the second-brain can stitch this campaign together with
        prior campaigns sharing the same IP cluster or rule signatures.
        """
        ips = sorted({e.client_ip for e in events})
        rules = sorted({e.rule_id for e in events})
        cats = sorted({(e.category.value if hasattr(e.category, "value") else str(e.category)) for e in events})
        sevs = sorted({(e.severity.value if hasattr(e.severity, "value") else str(e.severity)) for e in events})

        # Heuristic: campaign = same rule + 3+ unique IPs OR 5+ unique rules from same IP
        campaign_detected = False
        if len(events) >= 3 and (len(ips) >= 3 or len(rules) >= 5):
            campaign_detected = True

        try:
            _emit_event(
                "rasp.campaign_correlated",
                {
                    "campaign_detected": campaign_detected,
                    "event_count": len(events),
                    "ips": ips,
                    "rules": rules,
                    "categories": cats,
                    "severities": sevs,
                    "source_engine": "rasp_engine",
                    "entity_type": "rasp_campaign",
                },
            )
        except Exception:  # pragma: no cover
            pass

        return {
            "campaign_detected": campaign_detected,
            "event_count": len(events),
            "ips": ips,
            "rules": rules,
            "categories": cats,
            "severities": sevs,
            "source": "trustgraph_event_bus",
        }


# ---------------------------------------------------------------------------
# FastAPI middleware helper (synchronous wrapper for use in starlette middleware)
# ---------------------------------------------------------------------------


class RaspMiddlewareHelper:
    """
    Thin wrapper that adapts RaspEngine to FastAPI/Starlette middleware.

    Usage in app.py:
        _rasp_helper = RaspMiddlewareHelper(rasp_engine)

        @app.middleware("http")
        async def rasp_middleware(request: Request, call_next):
            blocked, threats = _rasp_helper.process(request)
            if blocked:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})
            return await call_next(request)
    """

    def __init__(self, engine: Optional[RaspEngine] = None) -> None:
        self.engine = engine or RaspEngine()

    def process(
        self,
        client_ip: str,
        method: str,
        path: str,
        query_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body_text: Optional[str] = None,
        api_key: Optional[str] = None,
        org_id: str = "default",
    ) -> Tuple[bool, List[ThreatEvent]]:
        return self.engine.inspect_request_sync(
            client_ip=client_ip,
            method=method,
            path=path,
            query_params=query_params,
            headers=headers,
            body_text=body_text,
            api_key=api_key,
            org_id=org_id,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[RaspEngine] = None
_engine_lock = threading.Lock()


def get_rasp_engine() -> RaspEngine:
    """Return the module-level singleton RaspEngine, creating it on first call."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = RaspEngine()
    return _engine
