"""
User Activity Analytics Engine — ALDECI.

Tracks user sessions, feature usage, and API call patterns for admin dashboards.
SQLite-backed with per-org multi-tenancy.

Compliance: SOC2 CC6.2 (Logical access controls and monitoring)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class ActivityType(str, Enum):
    """Types of user activity events."""

    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    API_CALL = "API_CALL"
    PAGE_VIEW = "PAGE_VIEW"
    FEATURE_USE = "FEATURE_USE"
    SEARCH = "SEARCH"
    EXPORT = "EXPORT"
    CONFIG_CHANGE = "CONFIG_CHANGE"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class Activity(BaseModel):
    """A single recorded user activity event."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    activity_type: ActivityType
    endpoint: Optional[str] = None
    feature: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    ip_address: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str


class UserSession(BaseModel):
    """Aggregated session record for a user within a time window."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    started_at: datetime
    last_active: datetime
    duration_minutes: float
    activity_count: int
    org_id: str


# ============================================================================
# ENGINE
# ============================================================================

# Session window: consider a session active if last activity was within this many minutes
_SESSION_WINDOW_MINUTES = 30
# Feature considered underutilized below this threshold
_UNDERUTILIZED_THRESHOLD = 5


class UserAnalyticsEngine:
    """
    SQLite-backed engine for recording and querying user activity analytics.

    All public methods are thread-safe (new connection per call using
    sqlite3's WAL mode).
    """

    def __init__(self, db_path: str = "data/user_analytics.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        _logger.info("UserAnalyticsEngine initialised — db=%s", self.db_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_tables(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS activities (
                    id          TEXT PRIMARY KEY,
                    user_email  TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    endpoint    TEXT,
                    feature     TEXT,
                    metadata    TEXT NOT NULL DEFAULT '{}',
                    ip_address  TEXT NOT NULL DEFAULT '',
                    timestamp   TEXT NOT NULL,
                    org_id      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_activities_org_ts
                    ON activities (org_id, timestamp);

                CREATE INDEX IF NOT EXISTS idx_activities_user
                    ON activities (user_email, org_id);

                CREATE INDEX IF NOT EXISTS idx_activities_type
                    ON activities (activity_type, org_id);
                """
            )

    def _row_to_activity(self, row: sqlite3.Row) -> Activity:
        return Activity(
            id=row["id"],
            user_email=row["user_email"],
            activity_type=ActivityType(row["activity_type"]),
            endpoint=row["endpoint"],
            feature=row["feature"],
            metadata=json.loads(row["metadata"] or "{}"),
            ip_address=row["ip_address"] or "",
            timestamp=datetime.fromisoformat(row["timestamp"]),
            org_id=row["org_id"],
        )

    def _since_iso(self, days: int) -> str:
        """Return ISO timestamp string for N days ago."""
        return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_activity(
        self,
        user_email: str,
        activity_type: ActivityType,
        endpoint: Optional[str] = None,
        feature: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip: str = "",
        org_id: str = "default",
    ) -> Activity:
        """Record a new user activity event."""
        activity = Activity(
            user_email=user_email,
            activity_type=activity_type,
            endpoint=endpoint,
            feature=feature,
            metadata=metadata or {},
            ip_address=ip,
            org_id=org_id,
        )
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO activities
                    (id, user_email, activity_type, endpoint, feature,
                     metadata, ip_address, timestamp, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    activity.id,
                    activity.user_email,
                    activity.activity_type.value,
                    activity.endpoint,
                    activity.feature,
                    json.dumps(activity.metadata),
                    activity.ip_address,
                    activity.timestamp.isoformat(),
                    activity.org_id,
                ),
            )
        _logger.debug(
            "Recorded %s for %s in org=%s", activity_type.value, user_email, org_id
        )
        return activity

    def get_user_activities(
        self,
        user_email: str,
        org_id: str = "default",
        limit: int = 100,
    ) -> List[Activity]:
        """Return recent activities for a specific user."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM activities
                WHERE user_email = ? AND org_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (user_email, org_id, limit),
            ).fetchall()
        return [self._row_to_activity(r) for r in rows]

    def get_active_sessions(self, org_id: str = "default") -> List[UserSession]:
        """
        Return one aggregated session per user who was active within the last
        SESSION_WINDOW_MINUTES minutes.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(minutes=_SESSION_WINDOW_MINUTES)
        ).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    user_email,
                    MIN(timestamp) AS started_at,
                    MAX(timestamp) AS last_active,
                    COUNT(*)       AS activity_count
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                GROUP BY user_email
                """,
                (org_id, cutoff),
            ).fetchall()

        sessions: List[UserSession] = []
        for row in rows:
            started = datetime.fromisoformat(row["started_at"])
            last = datetime.fromisoformat(row["last_active"])
            duration = (last - started).total_seconds() / 60.0
            sessions.append(
                UserSession(
                    user_email=row["user_email"],
                    started_at=started,
                    last_active=last,
                    duration_minutes=round(duration, 2),
                    activity_count=row["activity_count"],
                    org_id=org_id,
                )
            )
        return sessions

    def get_most_active_users(
        self,
        org_id: str = "default",
        days: int = 30,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Return top users by activity count over the last N days."""
        since = self._since_iso(days)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT user_email, COUNT(*) AS activity_count
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                GROUP BY user_email
                ORDER BY activity_count DESC
                LIMIT ?
                """,
                (org_id, since, limit),
            ).fetchall()
        return [
            {"user_email": r["user_email"], "activity_count": r["activity_count"]}
            for r in rows
        ]

    def get_feature_usage(
        self,
        org_id: str = "default",
        days: int = 30,
    ) -> Dict[str, int]:
        """Return feature → usage count over the last N days."""
        since = self._since_iso(days)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT feature, COUNT(*) AS cnt
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                  AND feature IS NOT NULL
                GROUP BY feature
                ORDER BY cnt DESC
                """,
                (org_id, since),
            ).fetchall()
        return {r["feature"]: r["cnt"] for r in rows}

    def get_endpoint_usage(
        self,
        org_id: str = "default",
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Return most-called API endpoints over the last N days."""
        since = self._since_iso(days)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT endpoint, COUNT(*) AS call_count
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                  AND endpoint IS NOT NULL
                GROUP BY endpoint
                ORDER BY call_count DESC
                LIMIT 50
                """,
                (org_id, since),
            ).fetchall()
        return [
            {"endpoint": r["endpoint"], "call_count": r["call_count"]}
            for r in rows
        ]

    def get_peak_hours(
        self,
        org_id: str = "default",
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Return activity count grouped by hour of day (0-23)."""
        since = self._since_iso(days)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    CAST(strftime('%H', timestamp) AS INTEGER) AS hour,
                    COUNT(*) AS activity_count
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                GROUP BY hour
                ORDER BY hour
                """,
                (org_id, since),
            ).fetchall()

        # Fill in missing hours with 0
        counts: Dict[int, int] = {r["hour"]: r["activity_count"] for r in rows}
        return [
            {"hour": h, "activity_count": counts.get(h, 0)} for h in range(24)
        ]

    def get_daily_active_users(
        self,
        org_id: str = "default",
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Return distinct active user count per calendar day over the last N days."""
        since = self._since_iso(days)
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    strftime('%Y-%m-%d', timestamp) AS date,
                    COUNT(DISTINCT user_email)       AS dau
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                GROUP BY date
                ORDER BY date
                """,
                (org_id, since),
            ).fetchall()
        return [{"date": r["date"], "dau": r["dau"]} for r in rows]

    def get_underutilized_features(self, org_id: str = "default") -> List[str]:
        """Return features that have fewer than 5 total uses across all time."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT feature, COUNT(*) AS cnt
                FROM activities
                WHERE org_id = ? AND feature IS NOT NULL
                GROUP BY feature
                HAVING cnt < ?
                ORDER BY cnt ASC
                """,
                (org_id, _UNDERUTILIZED_THRESHOLD),
            ).fetchall()
        return [r["feature"] for r in rows]

    def get_usage_dashboard(self, org_id: str = "default") -> Dict[str, Any]:
        """Return all key metrics combined for dashboard consumption."""
        return {
            "active_sessions": [s.model_dump() for s in self.get_active_sessions(org_id)],
            "most_active_users": self.get_most_active_users(org_id, days=30),
            "feature_usage": self.get_feature_usage(org_id, days=30),
            "endpoint_usage": self.get_endpoint_usage(org_id, days=30),
            "peak_hours": self.get_peak_hours(org_id, days=30),
            "daily_active_users": self.get_daily_active_users(org_id, days=30),
            "underutilized_features": self.get_underutilized_features(org_id),
            "user_stats": self.get_user_stats(org_id),
        }

    def cleanup_old_activities(self, days: int = 90) -> int:
        """Delete activity records older than N days. Returns row count deleted."""
        cutoff = self._since_iso(days)
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM activities WHERE timestamp < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount
        _logger.info("Cleaned up %d old activity records (older than %d days)", deleted, days)
        return deleted

    def get_user_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for all users in an org."""
        with self._conn() as conn:
            total_activities = conn.execute(
                "SELECT COUNT(*) AS cnt FROM activities WHERE org_id = ?",
                (org_id,),
            ).fetchone()["cnt"]

            total_users = conn.execute(
                "SELECT COUNT(DISTINCT user_email) AS cnt FROM activities WHERE org_id = ?",
                (org_id,),
            ).fetchone()["cnt"]

            last_7_dau_rows = conn.execute(
                """
                SELECT COUNT(DISTINCT user_email) AS dau
                FROM activities
                WHERE org_id = ? AND timestamp >= ?
                """,
                (org_id, self._since_iso(7)),
            ).fetchone()
            dau_7d = last_7_dau_rows["dau"] if last_7_dau_rows else 0

            activity_type_breakdown = conn.execute(
                """
                SELECT activity_type, COUNT(*) AS cnt
                FROM activities
                WHERE org_id = ?
                GROUP BY activity_type
                """,
                (org_id,),
            ).fetchall()

        return {
            "total_activities": total_activities,
            "total_users": total_users,
            "active_users_last_7d": dau_7d,
            "activity_type_breakdown": {
                r["activity_type"]: r["cnt"] for r in activity_type_breakdown
            },
        }
