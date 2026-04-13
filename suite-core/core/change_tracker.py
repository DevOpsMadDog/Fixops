"""
ALDECI Change Management Tracker — security-posture-aware change tracking.

Provides:
- ChangeType enum: CODE_CHANGE, CONFIG_CHANGE, INFRA_CHANGE, ACCESS_CHANGE,
                   POLICY_CHANGE, VENDOR_CHANGE
- ChangeRisk enum: NONE, LOW, MEDIUM, HIGH, CRITICAL
- Change Pydantic model
- ChangeTracker class (thread-safe, SQLite-backed)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ChangeType(str, Enum):
    """Category of a tracked change."""

    CODE_CHANGE = "code_change"
    CONFIG_CHANGE = "config_change"
    INFRA_CHANGE = "infra_change"
    ACCESS_CHANGE = "access_change"
    POLICY_CHANGE = "policy_change"
    VENDOR_CHANGE = "vendor_change"


class ChangeRisk(str, Enum):
    """Risk level assigned to a change."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class Change(BaseModel):
    """A single tracked change entry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ChangeType
    description: str
    author: str
    risk_level: ChangeRisk = ChangeRisk.NONE
    affected_assets: List[str] = Field(default_factory=list)
    review_status: str = Field("pending", pattern="^(pending|approved|rejected)$")
    security_impact: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    org_id: str = "default"

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS changes (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    type            TEXT NOT NULL,
    description     TEXT NOT NULL,
    author          TEXT NOT NULL,
    risk_level      TEXT NOT NULL DEFAULT 'none',
    affected_assets TEXT NOT NULL DEFAULT '[]',
    review_status   TEXT NOT NULL DEFAULT 'pending',
    security_impact TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ch_org        ON changes (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ch_risk       ON changes (org_id, risk_level);
CREATE INDEX IF NOT EXISTS idx_ch_review     ON changes (org_id, review_status);
CREATE INDEX IF NOT EXISTS idx_ch_type       ON changes (org_id, type);

CREATE TABLE IF NOT EXISTS change_reviews (
    id          TEXT PRIMARY KEY,
    change_id   TEXT NOT NULL,
    reviewer    TEXT NOT NULL,
    action      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    reviewed_at TEXT NOT NULL,
    FOREIGN KEY (change_id) REFERENCES changes(id)
);
CREATE INDEX IF NOT EXISTS idx_rev_change ON change_reviews (change_id);
"""

# ---------------------------------------------------------------------------
# Risk assessment rules
# ---------------------------------------------------------------------------

# Risk keywords → risk level
_RISK_KEYWORDS: List[tuple[str, ChangeRisk]] = [
    # CRITICAL
    ("root", ChangeRisk.CRITICAL),
    ("admin credential", ChangeRisk.CRITICAL),
    ("production database", ChangeRisk.CRITICAL),
    ("firewall rule", ChangeRisk.CRITICAL),
    ("encryption key", ChangeRisk.CRITICAL),
    ("private key", ChangeRisk.CRITICAL),
    ("secret", ChangeRisk.CRITICAL),
    # HIGH
    ("authentication", ChangeRisk.HIGH),
    ("authorization", ChangeRisk.HIGH),
    ("access control", ChangeRisk.HIGH),
    ("privilege", ChangeRisk.HIGH),
    ("security group", ChangeRisk.HIGH),
    ("network policy", ChangeRisk.HIGH),
    ("iam", ChangeRisk.HIGH),
    ("rbac", ChangeRisk.HIGH),
    ("ssl", ChangeRisk.HIGH),
    ("tls", ChangeRisk.HIGH),
    ("certificate", ChangeRisk.HIGH),
    # MEDIUM
    ("configuration", ChangeRisk.MEDIUM),
    ("dependency", ChangeRisk.MEDIUM),
    ("library", ChangeRisk.MEDIUM),
    ("package", ChangeRisk.MEDIUM),
    ("api", ChangeRisk.MEDIUM),
    ("endpoint", ChangeRisk.MEDIUM),
    ("database", ChangeRisk.MEDIUM),
    # LOW
    ("documentation", ChangeRisk.LOW),
    ("readme", ChangeRisk.LOW),
    ("comment", ChangeRisk.LOW),
    ("style", ChangeRisk.LOW),
    ("format", ChangeRisk.LOW),
    ("test", ChangeRisk.LOW),
]

# ChangeType baseline risk
_TYPE_BASELINE: Dict[str, ChangeRisk] = {
    ChangeType.CODE_CHANGE: ChangeRisk.LOW,
    ChangeType.CONFIG_CHANGE: ChangeRisk.MEDIUM,
    ChangeType.INFRA_CHANGE: ChangeRisk.HIGH,
    ChangeType.ACCESS_CHANGE: ChangeRisk.HIGH,
    ChangeType.POLICY_CHANGE: ChangeRisk.MEDIUM,
    ChangeType.VENDOR_CHANGE: ChangeRisk.MEDIUM,
}

_RISK_ORDER = {
    ChangeRisk.NONE: 0,
    ChangeRisk.LOW: 1,
    ChangeRisk.MEDIUM: 2,
    ChangeRisk.HIGH: 3,
    ChangeRisk.CRITICAL: 4,
}


def _max_risk(*risks: ChangeRisk) -> ChangeRisk:
    return max(risks, key=lambda r: _RISK_ORDER[r])


def _auto_assess_risk(change: Change) -> tuple[ChangeRisk, str]:
    """Return (risk_level, security_impact) based on heuristics."""
    text = (change.description + " " + " ".join(change.affected_assets)).lower()

    keyword_risk = ChangeRisk.NONE
    matched: List[str] = []
    for kw, risk in _RISK_KEYWORDS:
        if kw in text:
            keyword_risk = _max_risk(keyword_risk, risk)
            matched.append(kw)

    baseline = _TYPE_BASELINE.get(change.type, ChangeRisk.LOW)
    final_risk = _max_risk(keyword_risk, baseline)

    if matched:
        impact = (
            f"Auto-assessed {final_risk.upper()} risk. "
            f"Triggered by keywords: {', '.join(matched[:5])}. "
            f"Type baseline: {baseline.upper()}."
        )
    else:
        impact = (
            f"Auto-assessed {final_risk.upper()} risk based on change type "
            f"'{change.type}' (baseline: {baseline.upper()}). No high-risk keywords detected."
        )

    return final_risk, impact


# ---------------------------------------------------------------------------
# ChangeTracker
# ---------------------------------------------------------------------------


class ChangeTracker:
    """Thread-safe, SQLite-backed change management tracker.

    Usage::

        tracker = ChangeTracker()
        change = tracker.record_change(
            type=ChangeType.CODE_CHANGE,
            description="Updated auth middleware",
            author="alice@example.com",
            affected_assets=["suite-api/apps/api/auth.py"],
            org_id="acme",
        )
        tracker.assess_risk(change.id)
        tracker.approve_change(change.id, approver="bob@example.com")
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._db_path = Path(str(db_path))
        self._lock = threading.RLock()
        self._mem_conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if str(self._db_path) == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem_conn.row_factory = sqlite3.Row
            return self._mem_conn
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(_SCHEMA)
            conn.commit()

    @staticmethod
    def _row_to_change(row: sqlite3.Row) -> Change:
        d = dict(row)
        d["affected_assets"] = json.loads(d.get("affected_assets") or "[]")
        return Change(**d)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def record_change(
        self,
        *,
        type: ChangeType,  # noqa: A002
        description: str,
        author: str,
        affected_assets: Optional[List[str]] = None,
        risk_level: ChangeRisk = ChangeRisk.NONE,
        security_impact: str = "",
        org_id: str = "default",
    ) -> Change:
        """Record a new change and return it."""
        change = Change(
            type=type,
            description=description,
            author=author,
            affected_assets=affected_assets or [],
            risk_level=risk_level,
            security_impact=security_impact,
            org_id=org_id,
        )
        with self._lock:
            conn = self._connect()
            conn.execute(
                """
                INSERT INTO changes
                    (id, org_id, type, description, author, risk_level,
                     affected_assets, review_status, security_impact, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    change.id,
                    change.org_id,
                    change.type,
                    change.description,
                    change.author,
                    change.risk_level,
                    json.dumps(change.affected_assets),
                    change.review_status,
                    change.security_impact,
                    change.created_at.isoformat(),
                ),
            )
            conn.commit()
        _logger.debug("change_tracker: recorded %s (%s)", change.id, change.type)
        return change

    def assess_risk(self, change_id: str) -> Change:
        """Auto-assess security risk for a change and persist the result."""
        change = self.get_change(change_id)
        if change is None:
            raise KeyError(f"Change not found: {change_id}")

        risk, impact = _auto_assess_risk(change)

        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE changes SET risk_level = ?, security_impact = ? WHERE id = ?",
                (risk.value, impact, change_id),
            )
            conn.commit()

        return self.get_change(change_id)  # type: ignore[return-value]

    def approve_change(self, change_id: str, *, approver: str) -> Change:
        """Approve a change after review."""
        change = self.get_change(change_id)
        if change is None:
            raise KeyError(f"Change not found: {change_id}")
        if change.review_status == "rejected":
            raise ValueError(f"Change {change_id} is already rejected and cannot be approved.")

        review_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE changes SET review_status = 'approved' WHERE id = ?",
                (change_id,),
            )
            conn.execute(
                """
                INSERT INTO change_reviews (id, change_id, reviewer, action, reason, reviewed_at)
                VALUES (?, ?, ?, 'approved', '', ?)
                """,
                (review_id, change_id, approver, now),
            )
            conn.commit()

        _logger.info("change_tracker: approved %s by %s", change_id, approver)
        return self.get_change(change_id)  # type: ignore[return-value]

    def reject_change(self, change_id: str, *, reviewer: str, reason: str) -> Change:
        """Reject a change with a stated reason."""
        change = self.get_change(change_id)
        if change is None:
            raise KeyError(f"Change not found: {change_id}")
        if change.review_status == "approved":
            raise ValueError(f"Change {change_id} is already approved and cannot be rejected.")

        review_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE changes SET review_status = 'rejected' WHERE id = ?",
                (change_id,),
            )
            conn.execute(
                """
                INSERT INTO change_reviews (id, change_id, reviewer, action, reason, reviewed_at)
                VALUES (?, ?, ?, 'rejected', ?, ?)
                """,
                (review_id, change_id, reviewer, reason, now),
            )
            conn.commit()

        _logger.info("change_tracker: rejected %s by %s — %s", change_id, reviewer, reason)
        return self.get_change(change_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_change(self, change_id: str) -> Optional[Change]:
        """Fetch a single change by ID."""
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT * FROM changes WHERE id = ?", (change_id,)
            ).fetchone()
        return self._row_to_change(row) if row else None

    def get_pending_reviews(self, org_id: str = "default") -> List[Change]:
        """Return all changes awaiting review for an organisation."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM changes WHERE org_id = ? AND review_status = 'pending' "
                "ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_change(r) for r in rows]

    def get_high_risk_changes(self, org_id: str = "default") -> List[Change]:
        """Return changes flagged as HIGH or CRITICAL risk."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM changes WHERE org_id = ? AND risk_level IN ('high', 'critical') "
                "ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_change(r) for r in rows]

    def get_change_velocity(
        self, org_id: str = "default", days: int = 30
    ) -> Dict[str, Any]:
        """Return change velocity stats (changes per day) over the last N days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT date(created_at) AS day, COUNT(*) AS count FROM changes "
                "WHERE org_id = ? AND created_at >= ? "
                "GROUP BY day ORDER BY day ASC",
                (org_id, since),
            ).fetchall()

        daily: Dict[str, int] = {r["day"]: r["count"] for r in rows}
        total = sum(daily.values())
        avg = total / days if days else 0.0

        return {
            "org_id": org_id,
            "days": days,
            "total_changes": total,
            "avg_changes_per_day": round(avg, 2),
            "daily_breakdown": daily,
        }

    def get_change_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate stats: counts by type, risk, and approval rate."""
        with self._lock:
            conn = self._connect()

            by_type_rows = conn.execute(
                "SELECT type, COUNT(*) AS count FROM changes WHERE org_id = ? GROUP BY type",
                (org_id,),
            ).fetchall()

            by_risk_rows = conn.execute(
                "SELECT risk_level, COUNT(*) AS count FROM changes WHERE org_id = ? GROUP BY risk_level",
                (org_id,),
            ).fetchall()

            totals = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN review_status='approved' THEN 1 ELSE 0 END) AS approved, "
                "SUM(CASE WHEN review_status='rejected' THEN 1 ELSE 0 END) AS rejected, "
                "SUM(CASE WHEN review_status='pending'  THEN 1 ELSE 0 END) AS pending "
                "FROM changes WHERE org_id = ?",
                (org_id,),
            ).fetchone()

        total = totals["total"] or 0
        approved = totals["approved"] or 0
        approval_rate = round(approved / total * 100, 1) if total else 0.0

        return {
            "org_id": org_id,
            "total_changes": total,
            "by_type": {r["type"]: r["count"] for r in by_type_rows},
            "by_risk": {r["risk_level"]: r["count"] for r in by_risk_rows},
            "review": {
                "approved": approved,
                "rejected": totals["rejected"] or 0,
                "pending": totals["pending"] or 0,
                "approval_rate_pct": approval_rate,
            },
        }

    def correlate_with_incidents(
        self, org_id: str = "default", window_hours: int = 72
    ) -> List[Dict[str, Any]]:
        """Link changes to likely related incidents within a time window.

        Without a live incident store, this returns high/critical risk changes
        with correlation metadata so callers can join against their own incident
        data.  A 'correlation_window_hours' field indicates the look-ahead
        window used for matching.
        """
        high_risk = self.get_high_risk_changes(org_id=org_id)
        result: List[Dict[str, Any]] = []
        for change in high_risk:
            correlation_end = change.created_at + timedelta(hours=window_hours)
            result.append(
                {
                    "change_id": change.id,
                    "change_type": change.type,
                    "description": change.description,
                    "author": change.author,
                    "risk_level": change.risk_level,
                    "created_at": change.created_at.isoformat(),
                    "correlation_window_start": change.created_at.isoformat(),
                    "correlation_window_end": correlation_end.isoformat(),
                    "correlation_window_hours": window_hours,
                    "security_impact": change.security_impact,
                    "affected_assets": change.affected_assets,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Review history
    # ------------------------------------------------------------------

    def get_review_history(self, change_id: str) -> List[Dict[str, Any]]:
        """Return the review audit trail for a change."""
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM change_reviews WHERE change_id = ? ORDER BY reviewed_at ASC",
                (change_id,),
            ).fetchall()
        return [dict(r) for r in rows]


__all__ = [
    "Change",
    "ChangeRisk",
    "ChangeTracker",
    "ChangeType",
]
