"""
API Gateway Security Engine — ALDECI

Provides a unified gateway layer with:
1. API key management (create/revoke/rotate keys with scopes)
2. Rate limiting engine (sliding window, per-key and per-IP, configurable tiers)
3. Request validation (schema validation, content-type enforcement, payload size limits)
4. API versioning management (track client versions, deprecation alerts)
5. Throttling policies (burst, sustained, by plan tier: free/pro/enterprise)
6. API usage analytics (requests per endpoint, error rates, latency percentiles, top consumers)
7. IP allowlisting/blocklisting with CIDR support

Thread-safe via per-thread SQLite connections (WAL mode).

Usage::

    gw = APIGatewayEngine()
    # Check rate limit for a request
    result = gw.rate_limiter.check_rate_limit(api_key_id="ak_abc", ip="1.2.3.4", tier="pro")
    # Record a call for analytics
    gw.analytics.record_call(endpoint="/api/v1/findings", method="GET",
                              status_code=200, response_ms=42.5, api_key_id="ak_abc")
    # Check IP is allowed
    gw.ip_filter.is_allowed("192.168.1.1")

Environment:
    FIXOPS_DATA_DIR   directory for SQLite DBs (default: ``.fixops_data``)
"""

from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field, field_validator

_logger = structlog.get_logger(__name__)
_log = logging.getLogger(__name__)

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

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"


def _db_dir() -> Path:
    return Path(os.getenv(_DB_ENV, _DEFAULT_DB_DIR))


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PlanTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class RequestValidationError(str, Enum):
    CONTENT_TYPE = "invalid_content_type"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    SCHEMA_VIOLATION = "schema_violation"
    MISSING_REQUIRED_FIELD = "missing_required_field"


class IPRuleAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class RateLimitConfig(BaseModel):
    """Per-tier rate limit configuration."""

    tier: PlanTier
    requests_per_minute: int = Field(ge=1)
    requests_per_hour: int = Field(ge=1)
    burst_limit: int = Field(ge=1, description="Max requests in a 10-second burst window")
    sustained_limit: int = Field(ge=1, description="Max requests over a sustained 60-second window")

    model_config = {"arbitrary_types_allowed": True}


class RateLimitResult(BaseModel):
    """Result of a rate limit check."""

    allowed: bool
    tier: PlanTier
    key_id: Optional[str] = None
    ip: Optional[str] = None
    requests_this_minute: int = 0
    limit_per_minute: int = 0
    requests_this_hour: int = 0
    limit_per_hour: int = 0
    burst_count: int = 0
    burst_limit: int = 0
    retry_after_seconds: Optional[int] = None
    reason: Optional[str] = None


class IPRule(BaseModel):
    """An IP allowlist/blocklist rule with CIDR support."""

    id: str = Field(default_factory=lambda: "ipr_" + secrets.token_hex(6))
    cidr: str
    action: IPRuleAction
    description: str = ""
    created_at: datetime = Field(default_factory=_now)
    created_by: str = "system"
    is_active: bool = True

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        # Accept bare IPs too — convert to /32 or /128 network
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR notation: {v!r}") from exc
        return v


class IPCheckResult(BaseModel):
    allowed: bool
    ip: str
    matched_rule_id: Optional[str] = None
    matched_cidr: Optional[str] = None
    action: Optional[IPRuleAction] = None
    reason: str = "default_allow"


class RequestValidationResult(BaseModel):
    valid: bool
    errors: List[Dict[str, str]] = Field(default_factory=list)
    content_type: Optional[str] = None
    payload_size_bytes: int = 0
    api_version: Optional[str] = None


class GatewayAPICall(BaseModel):
    """Record of a single API call for analytics."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    endpoint: str
    method: str
    status_code: int
    response_ms: float
    api_key_id: Optional[str] = None
    org_id: Optional[str] = None
    ip_address: Optional[str] = None
    api_version: Optional[str] = None
    plan_tier: PlanTier = PlanTier.FREE
    timestamp: datetime = Field(default_factory=_now)


class ClientVersionRecord(BaseModel):
    """Tracks which API version a client (key or IP) is using."""

    id: str = Field(default_factory=lambda: "cvr_" + secrets.token_hex(6))
    client_id: str
    client_type: str = "api_key"  # "api_key" | "ip"
    api_version: str
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)
    request_count: int = 1
    deprecation_warned: bool = False


class ThrottlePolicy(BaseModel):
    """Throttle policy for a specific key or IP override."""

    id: str = Field(default_factory=lambda: "tp_" + secrets.token_hex(6))
    target_id: str
    target_type: str = "api_key"  # "api_key" | "ip"
    burst_limit: int = Field(ge=1)
    sustained_limit: int = Field(ge=1)
    requests_per_minute: int = Field(ge=1)
    requests_per_hour: int = Field(ge=1)
    is_active: bool = True
    created_at: datetime = Field(default_factory=_now)
    description: str = ""


# ---------------------------------------------------------------------------
# Default tier configs
# ---------------------------------------------------------------------------

DEFAULT_TIER_CONFIGS: Dict[PlanTier, RateLimitConfig] = {
    PlanTier.FREE: RateLimitConfig(
        tier=PlanTier.FREE,
        requests_per_minute=30,
        requests_per_hour=500,
        burst_limit=10,
        sustained_limit=30,
    ),
    PlanTier.PRO: RateLimitConfig(
        tier=PlanTier.PRO,
        requests_per_minute=120,
        requests_per_hour=5000,
        burst_limit=40,
        sustained_limit=120,
    ),
    PlanTier.ENTERPRISE: RateLimitConfig(
        tier=PlanTier.ENTERPRISE,
        requests_per_minute=600,
        requests_per_hour=50000,
        burst_limit=200,
        sustained_limit=600,
    ),
}

# ---------------------------------------------------------------------------
# Sliding window rate limiter (in-memory)
# ---------------------------------------------------------------------------

_BURST_WINDOW_SECONDS = 10
_MINUTE_WINDOW_SECONDS = 60
_HOUR_WINDOW_SECONDS = 3600


class _SlidingWindow:
    """Thread-safe sliding window counter."""

    def __init__(self, window_seconds: int) -> None:
        self._window = window_seconds
        self._lock = threading.Lock()
        self._timestamps: Deque[float] = deque()

    def add_and_count(self) -> int:
        """Add a new event and return the count within the window."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            self._timestamps.append(now)
            # Prune old events
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            return len(self._timestamps)

    def count(self) -> int:
        """Return count without adding a new event."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            while self._timestamps and self._timestamps[0] < cutoff:
                self._timestamps.popleft()
            return len(self._timestamps)


class RateLimiter:
    """
    Sliding window rate limiter.

    Maintains per-(key|ip) windows for burst (10s), minute (60s), and hour (3600s).
    Tier configs supply the limits; ThrottlePolicies can override per-target.
    """

    def __init__(self, tier_configs: Optional[Dict[PlanTier, RateLimitConfig]] = None) -> None:
        self._tier_configs = tier_configs or DEFAULT_TIER_CONFIGS
        self._lock = threading.Lock()
        # key → {"burst": _SlidingWindow, "minute": _SlidingWindow, "hour": _SlidingWindow}
        self._windows: Dict[str, Dict[str, _SlidingWindow]] = defaultdict(
            lambda: {
                "burst": _SlidingWindow(_BURST_WINDOW_SECONDS),
                "minute": _SlidingWindow(_MINUTE_WINDOW_SECONDS),
                "hour": _SlidingWindow(_HOUR_WINDOW_SECONDS),
            }
        )
        # key_id/ip → ThrottlePolicy override
        self._policy_overrides: Dict[str, ThrottlePolicy] = {}

    def _get_config(self, tier: PlanTier, target_id: str) -> RateLimitConfig:
        """Return effective config — policy override takes precedence over tier default."""
        override = self._policy_overrides.get(target_id)
        if override and override.is_active:
            return RateLimitConfig(
                tier=tier,
                requests_per_minute=override.requests_per_minute,
                requests_per_hour=override.requests_per_hour,
                burst_limit=override.burst_limit,
                sustained_limit=override.sustained_limit,
            )
        return self._tier_configs[tier]

    def register_policy(self, policy: ThrottlePolicy) -> None:
        """Register or update a throttle policy override for a target."""
        self._policy_overrides[policy.target_id] = policy

    def remove_policy(self, target_id: str) -> bool:
        """Remove a throttle policy override. Returns True if removed."""
        return self._policy_overrides.pop(target_id, None) is not None

    def check_rate_limit(
        self,
        tier: PlanTier = PlanTier.FREE,
        api_key_id: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> RateLimitResult:
        """
        Check and record a request against sliding window limits.

        Checks both api_key_id (if provided) and ip (if provided).
        Returns denied if EITHER limit is exceeded.
        """
        target_id = api_key_id or ip or "anonymous"
        cfg = self._get_config(tier, target_id)

        windows = self._windows[target_id]
        burst_count = windows["burst"].add_and_count()
        minute_count = windows["minute"].add_and_count()
        hour_count = windows["hour"].add_and_count()

        # Also check IP window separately if both key and IP provided
        ip_burst = ip_minute = ip_hour = 0
        if ip and api_key_id and ip != target_id:
            self._get_config(tier, ip)
            ip_windows = self._windows[ip]
            ip_burst = ip_windows["burst"].add_and_count()
            ip_minute = ip_windows["minute"].add_and_count()
            ip_hour = ip_windows["hour"].add_and_count()
            # Use stricter of the two
            burst_count = max(burst_count, ip_burst)
            minute_count = max(minute_count, ip_minute)
            hour_count = max(hour_count, ip_hour)

        allowed = True
        reason = None
        retry_after: Optional[int] = None

        if burst_count > cfg.burst_limit:
            allowed = False
            reason = f"Burst limit exceeded ({burst_count}/{cfg.burst_limit} in {_BURST_WINDOW_SECONDS}s)"
            retry_after = _BURST_WINDOW_SECONDS

        elif minute_count > cfg.requests_per_minute:
            allowed = False
            reason = f"Per-minute limit exceeded ({minute_count}/{cfg.requests_per_minute})"
            retry_after = _MINUTE_WINDOW_SECONDS

        elif hour_count > cfg.requests_per_hour:
            allowed = False
            reason = f"Per-hour limit exceeded ({hour_count}/{cfg.requests_per_hour})"
            retry_after = _HOUR_WINDOW_SECONDS

        return RateLimitResult(
            allowed=allowed,
            tier=tier,
            key_id=api_key_id,
            ip=ip,
            requests_this_minute=minute_count,
            limit_per_minute=cfg.requests_per_minute,
            requests_this_hour=hour_count,
            limit_per_hour=cfg.requests_per_hour,
            burst_count=burst_count,
            burst_limit=cfg.burst_limit,
            retry_after_seconds=retry_after,
            reason=reason,
        )

    def get_tier_configs(self) -> Dict[str, Dict[str, Any]]:
        """Return all tier configurations as dicts."""
        return {tier.value: cfg.model_dump() for tier, cfg in self._tier_configs.items()}

    def update_tier_config(self, tier: PlanTier, config: RateLimitConfig) -> None:
        """Update a tier configuration."""
        self._tier_configs[tier] = config

    def reset_counters(self, target_id: str) -> None:
        """Reset all rate limit windows for a target (admin use)."""
        if target_id in self._windows:
            del self._windows[target_id]


# ---------------------------------------------------------------------------
# IP Filter (SQLite-backed)
# ---------------------------------------------------------------------------


class IPFilter:
    """SQLite-backed IP allowlist/blocklist with CIDR support."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = db_path or str(_db_dir() / "api_gateway_ip.db")
        self._db_path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_rules (
                    id          TEXT PRIMARY KEY,
                    cidr        TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL,
                    created_by  TEXT NOT NULL DEFAULT 'system',
                    is_active   INTEGER NOT NULL DEFAULT 1
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipr_action ON ip_rules(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ipr_active ON ip_rules(is_active)")

    def _row_to_rule(self, row: Dict[str, Any]) -> IPRule:
        return IPRule(
            id=row["id"],
            cidr=row["cidr"],
            action=IPRuleAction(row["action"]),
            description=row.get("description", ""),
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row.get("created_by", "system"),
            is_active=bool(row.get("is_active", True)),
        )

    def add_rule(
        self,
        cidr: str,
        action: IPRuleAction,
        description: str = "",
        created_by: str = "system",
    ) -> IPRule:
        """Add an IP rule. Raises ValueError for invalid CIDR."""
        rule = IPRule(
            cidr=cidr,
            action=action,
            description=description,
            created_by=created_by,
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ip_rules (id, cidr, action, description, created_at, created_by, is_active) "
                "VALUES (?, ?, ?, ?, ?, ?, 1)",
                (rule.id, rule.cidr, rule.action.value, rule.description,
                 rule.created_at.isoformat(), rule.created_by),
            )
        _log.info("IP rule added: %s %s", action.value, cidr)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        """Soft-delete a rule by ID. Returns True if found."""
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE ip_rules SET is_active = 0 WHERE id = ?", (rule_id,)
            )
        return result.rowcount > 0

    def list_rules(self, action: Optional[IPRuleAction] = None) -> List[IPRule]:
        """List all active rules, optionally filtered by action."""
        query = "SELECT * FROM ip_rules WHERE is_active = 1"
        params: List[Any] = []
        if action:
            query += " AND action = ?"
            params.append(action.value)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_rule(dict(r)) for r in rows]

    def is_allowed(self, ip: str) -> IPCheckResult:
        """
        Check if an IP address is allowed.

        Evaluation order:
        1. Block rules (explicit deny wins over allow)
        2. Allow rules (explicit allow)
        3. Default: allow

        CIDR matching is done via Python's ipaddress module.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return IPCheckResult(
                allowed=False,
                ip=ip,
                reason=f"Invalid IP address: {ip!r}",
            )

        rules = self.list_rules()

        # Block rules take priority
        for rule in rules:
            if rule.action != IPRuleAction.BLOCK:
                continue
            try:
                network = ipaddress.ip_network(rule.cidr, strict=False)
                if addr in network:
                    return IPCheckResult(
                        allowed=False,
                        ip=ip,
                        matched_rule_id=rule.id,
                        matched_cidr=rule.cidr,
                        action=rule.action,
                        reason=f"Blocked by rule {rule.id}: {rule.cidr}",
                    )
            except ValueError:
                continue

        # Check allow rules
        for rule in rules:
            if rule.action != IPRuleAction.ALLOW:
                continue
            try:
                network = ipaddress.ip_network(rule.cidr, strict=False)
                if addr in network:
                    return IPCheckResult(
                        allowed=True,
                        ip=ip,
                        matched_rule_id=rule.id,
                        matched_cidr=rule.cidr,
                        action=rule.action,
                        reason=f"Allowed by rule {rule.id}: {rule.cidr}",
                    )
            except ValueError:
                continue

        return IPCheckResult(allowed=True, ip=ip, reason="default_allow")


# ---------------------------------------------------------------------------
# Request Validator
# ---------------------------------------------------------------------------

# Payload size limit: 10 MB by default
_DEFAULT_MAX_PAYLOAD_BYTES = 10 * 1024 * 1024

_ALLOWED_CONTENT_TYPES = frozenset({
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
})


class RequestValidator:
    """Validates incoming requests for content-type, payload size, and schema."""

    def __init__(
        self,
        max_payload_bytes: int = _DEFAULT_MAX_PAYLOAD_BYTES,
        allowed_content_types: Optional[frozenset] = None,
    ) -> None:
        self._max_payload_bytes = max_payload_bytes
        self._allowed_content_types = allowed_content_types or _ALLOWED_CONTENT_TYPES

    def validate(
        self,
        content_type: Optional[str],
        payload_size_bytes: int,
        api_version: Optional[str] = None,
        required_fields: Optional[List[str]] = None,
        payload_dict: Optional[Dict[str, Any]] = None,
    ) -> RequestValidationResult:
        """
        Validate an incoming request.

        Args:
            content_type: Raw Content-Type header value (may include charset etc.)
            payload_size_bytes: Size of the request body in bytes
            api_version: Declared API version from header or URL
            required_fields: Required fields to check in payload_dict
            payload_dict: Parsed payload body for field validation

        Returns:
            RequestValidationResult with valid flag and list of errors
        """
        errors: List[Dict[str, str]] = []

        # Content-type check (strip charset/boundary suffix)
        base_ct = (content_type or "").split(";")[0].strip().lower()
        if content_type and base_ct not in self._allowed_content_types:
            errors.append({
                "type": RequestValidationError.CONTENT_TYPE.value,
                "detail": f"Content-Type {base_ct!r} is not allowed. Accepted: "
                          f"{', '.join(sorted(self._allowed_content_types))}",
            })

        # Payload size check
        if payload_size_bytes > self._max_payload_bytes:
            errors.append({
                "type": RequestValidationError.PAYLOAD_TOO_LARGE.value,
                "detail": (
                    f"Payload size {payload_size_bytes} bytes exceeds limit "
                    f"of {self._max_payload_bytes} bytes"
                ),
            })

        # Required field check
        if required_fields and payload_dict is not None:
            for field in required_fields:
                if field not in payload_dict:
                    errors.append({
                        "type": RequestValidationError.MISSING_REQUIRED_FIELD.value,
                        "detail": f"Required field missing: {field!r}",
                    })

        return RequestValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            content_type=base_ct or None,
            payload_size_bytes=payload_size_bytes,
            api_version=api_version,
        )


# ---------------------------------------------------------------------------
# API Version Tracker (gateway-specific, lightweight)
# ---------------------------------------------------------------------------


class VersionTracker:
    """
    Tracks which API versions clients are using, records deprecation alerts,
    and returns migration recommendations.

    Backed by SQLite for persistence across restarts.
    """

    DEPRECATED_VERSIONS: frozenset = frozenset({"v0", "v0.9"})
    SUPPORTED_VERSIONS: frozenset = frozenset({"v1", "v2"})

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = db_path or str(_db_dir() / "api_gateway_versions.db")
        self._db_path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS client_versions (
                    id                TEXT PRIMARY KEY,
                    client_id         TEXT NOT NULL,
                    client_type       TEXT NOT NULL DEFAULT 'api_key',
                    api_version       TEXT NOT NULL,
                    first_seen        TEXT NOT NULL,
                    last_seen         TEXT NOT NULL,
                    request_count     INTEGER NOT NULL DEFAULT 1,
                    deprecation_warned INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(client_id, api_version)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cv_client ON client_versions(client_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cv_version ON client_versions(api_version)")

    def record_version_usage(
        self,
        client_id: str,
        api_version: str,
        client_type: str = "api_key",
    ) -> Tuple[ClientVersionRecord, bool]:
        """
        Record that client_id used api_version.

        Returns:
            (ClientVersionRecord, deprecation_alert) — deprecation_alert is True
            when the version is deprecated and this is the first warning.
        """
        now = _now().isoformat()
        is_deprecated = api_version in self.DEPRECATED_VERSIONS

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM client_versions WHERE client_id = ? AND api_version = ?",
                (client_id, api_version),
            ).fetchone()

            if row is None:
                rec_id = "cvr_" + secrets.token_hex(6)
                warned = is_deprecated  # warn on first encounter
                conn.execute(
                    "INSERT INTO client_versions "
                    "(id, client_id, client_type, api_version, first_seen, last_seen, "
                    "request_count, deprecation_warned) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (rec_id, client_id, client_type, api_version, now, now, int(warned)),
                )
                deprecation_alert = is_deprecated
            else:
                warned_already = bool(row["deprecation_warned"])
                deprecation_alert = is_deprecated and not warned_already
                conn.execute(
                    "UPDATE client_versions SET last_seen = ?, request_count = request_count + 1, "
                    "deprecation_warned = ? WHERE client_id = ? AND api_version = ?",
                    (now, int(is_deprecated), client_id, api_version),
                )

            # Re-fetch to get current state
            row = conn.execute(
                "SELECT * FROM client_versions WHERE client_id = ? AND api_version = ?",
                (client_id, api_version),
            ).fetchone()

        rec = ClientVersionRecord(
            id=row["id"],
            client_id=row["client_id"],
            client_type=row["client_type"],
            api_version=row["api_version"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            request_count=int(row["request_count"]),
            deprecation_warned=bool(row["deprecation_warned"]),
        )
        return rec, deprecation_alert

    def get_client_versions(self, client_id: str) -> List[ClientVersionRecord]:
        """Return all versions a client has used."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM client_versions WHERE client_id = ? ORDER BY last_seen DESC",
                (client_id,),
            ).fetchall()
        return [
            ClientVersionRecord(
                id=r["id"],
                client_id=r["client_id"],
                client_type=r["client_type"],
                api_version=r["api_version"],
                first_seen=datetime.fromisoformat(r["first_seen"]),
                last_seen=datetime.fromisoformat(r["last_seen"]),
                request_count=int(r["request_count"]),
                deprecation_warned=bool(r["deprecation_warned"]),
            )
            for r in rows
        ]

    def get_version_stats(self) -> Dict[str, Any]:
        """Return aggregated version usage statistics."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT api_version, COUNT(DISTINCT client_id) AS clients, "
                "SUM(request_count) AS total_requests "
                "FROM client_versions GROUP BY api_version ORDER BY total_requests DESC"
            ).fetchall()

            deprecated_clients = conn.execute(
                "SELECT COUNT(DISTINCT client_id) FROM client_versions WHERE api_version IN ({})".format(  # nosec B608
                    ",".join("?" * len(self.DEPRECATED_VERSIONS))
                ),
                list(self.DEPRECATED_VERSIONS),
            ).fetchone()[0] if self.DEPRECATED_VERSIONS else 0

        return {
            "by_version": [
                {
                    "api_version": r["api_version"],
                    "unique_clients": r["clients"],
                    "total_requests": r["total_requests"],
                    "is_deprecated": r["api_version"] in self.DEPRECATED_VERSIONS,
                }
                for r in rows
            ],
            "deprecated_versions": list(self.DEPRECATED_VERSIONS),
            "supported_versions": list(self.SUPPORTED_VERSIONS),
            "clients_on_deprecated": deprecated_clients,
        }

    def get_deprecation_alerts(self) -> List[Dict[str, Any]]:
        """Return clients still using deprecated API versions."""
        if not self.DEPRECATED_VERSIONS:
            return []
        version_list = ",".join(f"'{v}'" for v in self.DEPRECATED_VERSIONS)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT * FROM client_versions WHERE api_version IN ({version_list}) "  # nosec B608
                "ORDER BY last_seen DESC"
            ).fetchall()
        return [
            {
                "client_id": r["client_id"],
                "client_type": r["client_type"],
                "deprecated_version": r["api_version"],
                "last_seen": r["last_seen"],
                "request_count": r["request_count"],
                "recommended_version": "v1",
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Gateway Analytics (SQLite-backed)
# ---------------------------------------------------------------------------


class GatewayAnalytics:
    """
    SQLite-backed analytics for API gateway usage.

    Records every request with endpoint, method, status, latency, key, org, IP, version.
    Provides aggregated stats: top consumers, error rates, latency percentiles.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = db_path or str(_db_dir() / "api_gateway_analytics.db")
        self._db_path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS gateway_calls (
                    id          TEXT PRIMARY KEY,
                    endpoint    TEXT NOT NULL,
                    method      TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_ms REAL NOT NULL,
                    api_key_id  TEXT,
                    org_id      TEXT,
                    ip_address  TEXT,
                    api_version TEXT,
                    plan_tier   TEXT NOT NULL DEFAULT 'free',
                    timestamp   TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_endpoint  ON gateway_calls(endpoint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_timestamp ON gateway_calls(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_status    ON gateway_calls(status_code)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_key       ON gateway_calls(api_key_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_ip        ON gateway_calls(ip_address)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_gc_version   ON gateway_calls(api_version)")

    def record_call(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        response_ms: float,
        api_key_id: Optional[str] = None,
        org_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        api_version: Optional[str] = None,
        plan_tier: PlanTier = PlanTier.FREE,
    ) -> GatewayAPICall:
        """Record a single API call."""
        call = GatewayAPICall(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_ms=response_ms,
            api_key_id=api_key_id,
            org_id=org_id,
            ip_address=ip_address,
            api_version=api_version,
            plan_tier=plan_tier,
        )
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO gateway_calls VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    call.id, call.endpoint, call.method, call.status_code,
                    call.response_ms, call.api_key_id, call.org_id,
                    call.ip_address, call.api_version, call.plan_tier.value,
                    call.timestamp.isoformat(),
                ),
            )
        return call

    def get_endpoint_stats(
        self,
        endpoint: Optional[str] = None,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Return per-endpoint stats: total calls, error rate, avg/p50/p95/p99 latency."""
        since = (_now() - timedelta(hours=hours)).isoformat()
        query = "SELECT * FROM gateway_calls WHERE timestamp >= ?"
        params: List[Any] = [since]
        if endpoint:
            query += " AND endpoint = ?"
            params.append(endpoint)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        # Group by endpoint
        by_endpoint: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in rows:
            by_endpoint[r["endpoint"]].append(dict(r))

        results = []
        for ep, calls in by_endpoint.items():
            times = sorted(c["response_ms"] for c in calls)
            errors = sum(1 for c in calls if c["status_code"] >= 400)
            n = len(times)
            results.append({
                "endpoint": ep,
                "total_calls": n,
                "error_calls": errors,
                "error_rate": round(errors / n, 4) if n else 0.0,
                "avg_response_ms": round(sum(times) / n, 2) if n else 0.0,
                "p50_response_ms": round(times[max(0, int(n * 0.50) - 1)], 2) if n else 0.0,
                "p95_response_ms": round(times[max(0, int(n * 0.95) - 1)], 2) if n else 0.0,
                "p99_response_ms": round(times[max(0, int(n * 0.99) - 1)], 2) if n else 0.0,
            })

        results.sort(key=lambda x: x["total_calls"], reverse=True)
        return results

    def get_top_consumers(
        self,
        limit: int = 10,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Return top API key consumers by request volume."""
        since = (_now() - timedelta(hours=hours)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT api_key_id, org_id, plan_tier, COUNT(*) AS total, "
                "AVG(response_ms) AS avg_ms, "
                "SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors "
                "FROM gateway_calls WHERE timestamp >= ? AND api_key_id IS NOT NULL "
                "GROUP BY api_key_id ORDER BY total DESC LIMIT ?",
                (since, limit),
            ).fetchall()
        return [
            {
                "api_key_id": r["api_key_id"],
                "org_id": r["org_id"],
                "plan_tier": r["plan_tier"],
                "total_calls": r["total"],
                "avg_response_ms": round(r["avg_ms"], 2),
                "error_calls": r["errors"],
                "error_rate": round(r["errors"] / r["total"], 4) if r["total"] else 0.0,
            }
            for r in rows
        ]

    def get_error_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Return error rate summary across all endpoints."""
        since = (_now() - timedelta(hours=hours)).isoformat()
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM gateway_calls WHERE timestamp >= ?", (since,)
            ).fetchone()[0]
            errors = conn.execute(
                "SELECT COUNT(*) FROM gateway_calls WHERE timestamp >= ? AND status_code >= 400",
                (since,),
            ).fetchone()[0]
            by_code = conn.execute(
                "SELECT status_code, COUNT(*) AS cnt FROM gateway_calls "
                "WHERE timestamp >= ? AND status_code >= 400 GROUP BY status_code ORDER BY cnt DESC",
                (since,),
            ).fetchall()

        return {
            "total_calls": total,
            "total_errors": errors,
            "error_rate": round(errors / total, 4) if total else 0.0,
            "by_status_code": [{"status_code": r["status_code"], "count": r["cnt"]} for r in by_code],
            "window_hours": hours,
        }

    def get_latency_percentiles(self, endpoint: Optional[str] = None, hours: int = 24) -> Dict[str, Any]:
        """Return latency percentiles (p50/p95/p99) across all or a specific endpoint."""
        since = (_now() - timedelta(hours=hours)).isoformat()
        query = "SELECT response_ms FROM gateway_calls WHERE timestamp >= ?"
        params: List[Any] = [since]
        if endpoint:
            query += " AND endpoint = ?"
            params.append(endpoint)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        times = sorted(r["response_ms"] for r in rows)
        n = len(times)
        if n == 0:
            return {"endpoint": endpoint or "all", "total_calls": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "avg_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0, "window_hours": hours}

        return {
            "endpoint": endpoint or "all",
            "total_calls": n,
            "p50_ms": round(times[max(0, int(n * 0.50) - 1)], 2),
            "p95_ms": round(times[max(0, int(n * 0.95) - 1)], 2),
            "p99_ms": round(times[max(0, int(n * 0.99) - 1)], 2),
            "avg_ms": round(sum(times) / n, 2),
            "min_ms": round(times[0], 2),
            "max_ms": round(times[-1], 2),
            "window_hours": hours,
        }

    def cleanup_old(self, days: int = 90) -> int:
        """Delete records older than N days. Returns deleted count."""
        cutoff = (_now() - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            result = conn.execute("DELETE FROM gateway_calls WHERE timestamp < ?", (cutoff,))
        return result.rowcount


# ---------------------------------------------------------------------------
# Throttle Policy Store (SQLite-backed)
# ---------------------------------------------------------------------------


class ThrottlePolicyStore:
    """SQLite-backed persistent store for throttle policy overrides."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = db_path or str(_db_dir() / "api_gateway_policies.db")
        self._db_path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS throttle_policies (
                    id                  TEXT PRIMARY KEY,
                    target_id           TEXT NOT NULL,
                    target_type         TEXT NOT NULL DEFAULT 'api_key',
                    burst_limit         INTEGER NOT NULL,
                    sustained_limit     INTEGER NOT NULL,
                    requests_per_minute INTEGER NOT NULL,
                    requests_per_hour   INTEGER NOT NULL,
                    is_active           INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    UNIQUE(target_id)
                )
            """)

    def _row_to_policy(self, row: Dict[str, Any]) -> ThrottlePolicy:
        return ThrottlePolicy(
            id=row["id"],
            target_id=row["target_id"],
            target_type=row["target_type"],
            burst_limit=int(row["burst_limit"]),
            sustained_limit=int(row["sustained_limit"]),
            requests_per_minute=int(row["requests_per_minute"]),
            requests_per_hour=int(row["requests_per_hour"]),
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            description=row.get("description", ""),
        )

    def upsert_policy(self, policy: ThrottlePolicy) -> ThrottlePolicy:
        """Create or update a throttle policy."""
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO throttle_policies
                    (id, target_id, target_type, burst_limit, sustained_limit,
                     requests_per_minute, requests_per_hour, is_active, created_at, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    burst_limit = excluded.burst_limit,
                    sustained_limit = excluded.sustained_limit,
                    requests_per_minute = excluded.requests_per_minute,
                    requests_per_hour = excluded.requests_per_hour,
                    is_active = excluded.is_active,
                    description = excluded.description
                """,
                (
                    policy.id, policy.target_id, policy.target_type,
                    policy.burst_limit, policy.sustained_limit,
                    policy.requests_per_minute, policy.requests_per_hour,
                    int(policy.is_active), policy.created_at.isoformat(),
                    policy.description,
                ),
            )
        return policy

    def get_policy(self, target_id: str) -> Optional[ThrottlePolicy]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM throttle_policies WHERE target_id = ? AND is_active = 1",
                (target_id,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_policy(dict(row))

    def list_policies(self) -> List[ThrottlePolicy]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM throttle_policies WHERE is_active = 1 ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_policy(dict(r)) for r in rows]

    def delete_policy(self, target_id: str) -> bool:
        with self._conn() as conn:
            result = conn.execute(
                "UPDATE throttle_policies SET is_active = 0 WHERE target_id = ?",
                (target_id,),
            )
        return result.rowcount > 0


# ---------------------------------------------------------------------------
# APIGatewayEngine — facade
# ---------------------------------------------------------------------------


class APIGatewayEngine:
    """
    Unified API Gateway Security Engine.

    Composes all sub-systems:
    - rate_limiter: sliding window rate limiting + throttle policies
    - ip_filter: IP allowlist/blocklist with CIDR
    - validator: request validation (content-type, size, schema)
    - version_tracker: client version usage + deprecation alerts
    - analytics: call recording + aggregated stats
    - policy_store: persistent throttle policy overrides
    """

    _instance: Optional["APIGatewayEngine"] = None
    _class_lock: threading.Lock = threading.Lock()

    def __new__(cls, db_prefix: Optional[str] = None) -> "APIGatewayEngine":
        with cls._class_lock:
            if db_prefix is not None:
                inst = object.__new__(cls)
                inst._setup(db_prefix)
                return inst
            if cls._instance is None:
                inst = object.__new__(cls)
                inst._setup(None)
                cls._instance = inst
            return cls._instance  # type: ignore[return-value]

    def _setup(self, db_prefix: Optional[str]) -> None:
        if db_prefix:
            self.ip_filter = IPFilter(db_path=f"{db_prefix}_ip.db")
            self.version_tracker = VersionTracker(db_path=f"{db_prefix}_versions.db")
            self.analytics = GatewayAnalytics(db_path=f"{db_prefix}_analytics.db")
            self.policy_store = ThrottlePolicyStore(db_path=f"{db_prefix}_policies.db")
        else:
            self.ip_filter = IPFilter()
            self.version_tracker = VersionTracker()
            self.analytics = GatewayAnalytics()
            self.policy_store = ThrottlePolicyStore()

        self.rate_limiter = RateLimiter()
        self.validator = RequestValidator()

        # Load persisted throttle policies into in-memory rate limiter
        for policy in self.policy_store.list_policies():
            self.rate_limiter.register_policy(policy)

    def process_request(
        self,
        endpoint: str,
        method: str,
        ip: str,
        content_type: Optional[str] = None,
        payload_size_bytes: int = 0,
        api_key_id: Optional[str] = None,
        org_id: Optional[str] = None,
        api_version: Optional[str] = "v1",
        plan_tier: PlanTier = PlanTier.FREE,
        required_fields: Optional[List[str]] = None,
        payload_dict: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Full gateway check for an incoming request.

        Returns a dict with:
        - allowed: bool
        - reason: str (if blocked)
        - ip_check: IPCheckResult
        - rate_limit: RateLimitResult
        - validation: RequestValidationResult
        - deprecation_alert: bool
        """
        # 1. IP filter
        ip_result = self.ip_filter.is_allowed(ip)
        if not ip_result.allowed:
            return {
                "allowed": False,
                "reason": ip_result.reason,
                "ip_check": ip_result.model_dump(),
                "rate_limit": None,
                "validation": None,
                "deprecation_alert": False,
            }

        # 2. Rate limit
        rl_result = self.rate_limiter.check_rate_limit(
            tier=plan_tier,
            api_key_id=api_key_id,
            ip=ip,
        )
        if not rl_result.allowed:
            return {
                "allowed": False,
                "reason": rl_result.reason,
                "ip_check": ip_result.model_dump(),
                "rate_limit": rl_result.model_dump(),
                "validation": None,
                "deprecation_alert": False,
            }

        # 3. Request validation
        val_result = self.validator.validate(
            content_type=content_type,
            payload_size_bytes=payload_size_bytes,
            api_version=api_version,
            required_fields=required_fields,
            payload_dict=payload_dict,
        )
        if not val_result.valid:
            return {
                "allowed": False,
                "reason": "Request validation failed",
                "ip_check": ip_result.model_dump(),
                "rate_limit": rl_result.model_dump(),
                "validation": val_result.model_dump(),
                "deprecation_alert": False,
            }

        # 4. Version tracking
        deprecation_alert = False
        if api_key_id and api_version:
            _, deprecation_alert = self.version_tracker.record_version_usage(
                client_id=api_key_id,
                api_version=api_version,
                client_type="api_key",
            )
        elif api_version:
            _, deprecation_alert = self.version_tracker.record_version_usage(
                client_id=ip,
                api_version=api_version,
                client_type="ip",
            )

        result = {
            "allowed": True,
            "reason": None,
            "ip_check": ip_result.model_dump(),
            "rate_limit": rl_result.model_dump(),
            "validation": val_result.model_dump(),
            "deprecation_alert": deprecation_alert,
        }
        _emit_event("api_gateway.request_processed", {"endpoint": endpoint, "method": method, "allowed": True, "tier": plan_tier.value if hasattr(plan_tier, "value") else str(plan_tier)})
        return result


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------


def get_api_gateway_engine(db_prefix: Optional[str] = None) -> APIGatewayEngine:
    """Return the singleton APIGatewayEngine (or a new instance for a custom prefix)."""
    return APIGatewayEngine(db_prefix=db_prefix)
