"""
Per-tenant API rate limiting — sliding window, multi-tier, SQLite-backed.

Tiers and their built-in defaults:
  free        60 req/min,    1_000 req/hr,   10_000 req/day,  burst 10
  starter    300 req/min,    5_000 req/hr,   50_000 req/day,  burst 50
  pro      1_000 req/min,   20_000 req/hr,  200_000 req/day,  burst 200
  enterprise 5_000 req/min, 100_000 req/hr, 1_000_000 req/day, burst 500

Thread-safe: per-thread SQLite connections (WAL mode).
Singleton: ``TenantRateLimiter()`` with no args returns the shared instance;
pass an explicit ``db_path`` for testing.

Usage::

    limiter = TenantRateLimiter()
    limiter.set_quota("acme", "pro")

    result = limiter.check_limit("acme")
    if result["allowed"]:
        limiter.record_request("acme")

Environment:
    FIXOPS_DATA_DIR   directory for the SQLite DB (default: ``.fixops_data``)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DB_ENV = "FIXOPS_DATA_DIR"
_DEFAULT_DB_DIR = ".fixops_data"

TierName = Literal["free", "starter", "pro", "enterprise"]

# ---------------------------------------------------------------------------
# Built-in tier defaults
# ---------------------------------------------------------------------------

_TIER_DEFAULTS: Dict[str, Dict[str, int]] = {
    "free":       {"requests_per_minute": 60,    "requests_per_hour": 1_000,    "requests_per_day": 10_000,    "burst_limit": 10},
    "starter":    {"requests_per_minute": 300,   "requests_per_hour": 5_000,    "requests_per_day": 50_000,    "burst_limit": 50},
    "pro":        {"requests_per_minute": 1_000, "requests_per_hour": 20_000,   "requests_per_day": 200_000,   "burst_limit": 200},
    "enterprise": {"requests_per_minute": 5_000, "requests_per_hour": 100_000,  "requests_per_day": 1_000_000, "burst_limit": 500},
}


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class TenantQuota(BaseModel):
    """Rate-limit quota for a single tenant org."""

    org_id: str
    tier: str = "free"
    requests_per_minute: int = Field(60, ge=1)
    requests_per_hour: int = Field(1_000, ge=1)
    requests_per_day: int = Field(10_000, ge=1)
    burst_limit: int = Field(10, ge=1)
    current_usage: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_ts() -> float:
    return _now().timestamp()


def _window_start(window_seconds: int) -> float:
    """Return the Unix timestamp marking the start of the current window."""
    now = _now_ts()
    return now - window_seconds


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class TenantRateLimiter:
    """
    SQLite-backed per-tenant rate limiter using sliding windows.

    Three windows tracked: minute (60 s), hour (3600 s), day (86400 s).
    Each request is stored as a timestamped row; counts are derived by
    querying rows within the relevant window.
    """

    _instance: Optional["TenantRateLimiter"] = None
    _class_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Singleton / constructor
    # ------------------------------------------------------------------

    def __new__(cls, db_path: Optional[str] = None) -> "TenantRateLimiter":
        with cls._class_lock:
            if db_path is not None:
                inst = object.__new__(cls)
                inst._init(db_path)
                return inst
            if cls._instance is None:
                inst = object.__new__(cls)
                default_path = os.path.join(
                    os.getenv(_DB_ENV, _DEFAULT_DB_DIR), "tenant_rate_limits.db"
                )
                inst._init(default_path)
                cls._instance = inst
            return cls._instance  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
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
        conn = self._conn()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_quotas (
                    org_id               TEXT PRIMARY KEY,
                    tier                 TEXT NOT NULL DEFAULT 'free',
                    requests_per_minute  INTEGER NOT NULL DEFAULT 60,
                    requests_per_hour    INTEGER NOT NULL DEFAULT 1000,
                    requests_per_day     INTEGER NOT NULL DEFAULT 10000,
                    burst_limit          INTEGER NOT NULL DEFAULT 10,
                    created_at           TEXT NOT NULL,
                    updated_at           TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS request_log (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id    TEXT NOT NULL,
                    ts        REAL NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_request_log_org_ts
                ON request_log (org_id, ts)
            """)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_quota_row(self, org_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn().execute(
            "SELECT * FROM tenant_quotas WHERE org_id = ?", (org_id,)
        )
        return cur.fetchone()

    def _count_requests(self, org_id: str, window_seconds: int) -> int:
        cutoff = _window_start(window_seconds)
        cur = self._conn().execute(
            "SELECT COUNT(*) FROM request_log WHERE org_id = ? AND ts >= ?",
            (org_id, cutoff),
        )
        return int(cur.fetchone()[0])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_quota(self, org_id: str, tier: str) -> TenantQuota:
        """Configure rate-limit quota for an org, applying tier defaults.

        Calling again with the same org updates the tier and limits.
        """
        tier = tier.lower()
        if tier not in _TIER_DEFAULTS:
            raise ValueError(f"Unknown tier {tier!r}. Valid: {list(_TIER_DEFAULTS)}")

        defaults = _TIER_DEFAULTS[tier]
        now = _now().isoformat()

        conn = self._conn()
        with conn:
            conn.execute(
                """
                INSERT INTO tenant_quotas
                    (org_id, tier, requests_per_minute, requests_per_hour,
                     requests_per_day, burst_limit, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(org_id) DO UPDATE SET
                    tier                = excluded.tier,
                    requests_per_minute = excluded.requests_per_minute,
                    requests_per_hour   = excluded.requests_per_hour,
                    requests_per_day    = excluded.requests_per_day,
                    burst_limit         = excluded.burst_limit,
                    updated_at          = excluded.updated_at
                """,
                (
                    org_id,
                    tier,
                    defaults["requests_per_minute"],
                    defaults["requests_per_hour"],
                    defaults["requests_per_day"],
                    defaults["burst_limit"],
                    now,
                    now,
                ),
            )

        _logger.info("set_quota org=%s tier=%s", org_id, tier)
        return self.get_quota(org_id)  # type: ignore[return-value]

    def get_quota(self, org_id: str) -> Optional[TenantQuota]:
        """Return the TenantQuota for org_id, or None if not configured."""
        row = self._get_quota_row(org_id)
        if row is None:
            return None
        usage = self.get_usage(org_id)
        return TenantQuota(
            org_id=row["org_id"],
            tier=row["tier"],
            requests_per_minute=row["requests_per_minute"],
            requests_per_hour=row["requests_per_hour"],
            requests_per_day=row["requests_per_day"],
            burst_limit=row["burst_limit"],
            current_usage=usage,
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def check_limit(self, org_id: str) -> Dict[str, Any]:
        """Check whether org_id is within all rate limits.

        Returns a dict with:
          allowed (bool), denied_reason (str|None),
          remaining_minute, remaining_hour, remaining_day,
          limit_minute, limit_hour, limit_day
        """
        row = self._get_quota_row(org_id)
        if row is None:
            # Unknown org — apply free-tier defaults, auto-register
            self.set_quota(org_id, "free")
            row = self._get_quota_row(org_id)

        rpm = row["requests_per_minute"]
        rph = row["requests_per_hour"]
        rpd = row["requests_per_day"]

        used_min = self._count_requests(org_id, 60)
        used_hr = self._count_requests(org_id, 3600)
        used_day = self._count_requests(org_id, 86400)

        denied_reason: Optional[str] = None
        if used_day >= rpd:
            denied_reason = "daily limit exceeded"
        elif used_hr >= rph:
            denied_reason = "hourly limit exceeded"
        elif used_min >= rpm:
            denied_reason = "per-minute limit exceeded"

        return {
            "allowed": denied_reason is None,
            "denied_reason": denied_reason,
            "org_id": org_id,
            "tier": row["tier"],
            "remaining_minute": max(0, rpm - used_min),
            "remaining_hour": max(0, rph - used_hr),
            "remaining_day": max(0, rpd - used_day),
            "limit_minute": rpm,
            "limit_hour": rph,
            "limit_day": rpd,
            "burst_limit": row["burst_limit"],
        }

    def record_request(self, org_id: str) -> None:
        """Increment request counters for org_id."""
        conn = self._conn()
        with conn:
            conn.execute(
                "INSERT INTO request_log (org_id, ts) VALUES (?, ?)",
                (org_id, _now_ts()),
            )

    def get_usage(self, org_id: str) -> Dict[str, Any]:
        """Return current usage counters for org_id."""
        return {
            "requests_last_minute": self._count_requests(org_id, 60),
            "requests_last_hour": self._count_requests(org_id, 3600),
            "requests_last_day": self._count_requests(org_id, 86400),
            "window_end_minute": _now().isoformat(),
            "window_end_hour": _now().isoformat(),
            "window_end_day": _now().isoformat(),
        }

    def get_all_quotas(self) -> List[TenantQuota]:
        """Admin view — return all configured tenant quotas."""
        cur = self._conn().execute("SELECT org_id FROM tenant_quotas ORDER BY org_id")
        rows = cur.fetchall()
        result = []
        for row in rows:
            quota = self.get_quota(row["org_id"])
            if quota is not None:
                result.append(quota)
        return result

    def reset_usage(self, org_id: str) -> Dict[str, Any]:
        """Delete all request log entries for org_id (manual reset)."""
        conn = self._conn()
        with conn:
            cur = conn.execute(
                "DELETE FROM request_log WHERE org_id = ?", (org_id,)
            )
        deleted = cur.rowcount
        _logger.info("reset_usage org=%s deleted=%d rows", org_id, deleted)
        return {"org_id": org_id, "deleted_entries": deleted, "status": "reset"}

    def cleanup_expired_windows(self) -> Dict[str, Any]:
        """Delete request log entries older than 24 hours (housekeeping)."""
        cutoff = _now_ts() - 86400
        conn = self._conn()
        with conn:
            cur = conn.execute(
                "DELETE FROM request_log WHERE ts < ?", (cutoff,)
            )
        deleted = cur.rowcount
        _logger.info("cleanup_expired_windows deleted=%d rows", deleted)
        return {"deleted_entries": deleted, "cutoff_ts": cutoff}

    def get_top_consumers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Return the heaviest API consumers in the last 24 hours."""
        cutoff = _now_ts() - 86400
        cur = self._conn().execute(
            """
            SELECT org_id, COUNT(*) as request_count
            FROM request_log
            WHERE ts >= ?
            GROUP BY org_id
            ORDER BY request_count DESC
            LIMIT ?
            """,
            (cutoff, limit),
        )
        rows = cur.fetchall()
        result = []
        for row in rows:
            quota_row = self._get_quota_row(row["org_id"])
            result.append({
                "org_id": row["org_id"],
                "requests_last_24h": row["request_count"],
                "tier": quota_row["tier"] if quota_row else "unknown",
            })
        return result
