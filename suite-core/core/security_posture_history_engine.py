"""Security Posture History Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Tracks historical security posture scores across domains:
  - Point-in-time snapshots with per-domain scoring
  - Trend computation (improving/declining/stable) over configurable periods
  - Baseline and target score management
  - Delta analysis and domain-level summaries

Compliance: NIST CSF, CIS Controls, ISO 27001 A.18
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_history.db"
)

_VALID_DOMAINS = {
    "network", "endpoint", "cloud", "identity",
    "application", "data", "compliance", "physical",
}
_VALID_PERIODS = {"weekly", "monthly", "quarterly"}
_VALID_TREND_DIRECTIONS = {"improving", "declining", "stable"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _days_ago_iso(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


class SecurityPostureHistoryEngine:
    """SQLite WAL-backed Security Posture History engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_posture_history.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS posture_snapshots (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    snapshot_date   TEXT NOT NULL,
                    overall_score   REAL NOT NULL DEFAULT 0.0,
                    domain          TEXT NOT NULL DEFAULT '',
                    score           REAL NOT NULL DEFAULT 0.0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    source          TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ps_org_domain
                    ON posture_snapshots (org_id, domain, snapshot_date);

                CREATE TABLE IF NOT EXISTS posture_trends (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL DEFAULT '',
                    period          TEXT NOT NULL DEFAULT 'monthly',
                    avg_score       REAL NOT NULL DEFAULT 0.0,
                    min_score       REAL NOT NULL DEFAULT 0.0,
                    max_score       REAL NOT NULL DEFAULT 0.0,
                    trend_direction TEXT NOT NULL DEFAULT 'stable',
                    computed_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pt_org_domain
                    ON posture_trends (org_id, domain, period);

                CREATE TABLE IF NOT EXISTS posture_baselines (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL DEFAULT '',
                    baseline_score  REAL NOT NULL DEFAULT 0.0,
                    target_score    REAL NOT NULL DEFAULT 0.0,
                    set_by          TEXT NOT NULL DEFAULT '',
                    set_at          TEXT NOT NULL,
                    UNIQUE (org_id, domain)
                );

                CREATE INDEX IF NOT EXISTS idx_pb_org_domain
                    ON posture_baselines (org_id, domain);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def record_snapshot(
        self,
        org_id: str,
        domain: str,
        score: float,
        findings_count: int = 0,
        critical_count: int = 0,
        high_count: int = 0,
        source: str = "",
    ) -> Dict[str, Any]:
        """Record a posture snapshot. overall_score = avg of last 7 days per org."""
        domain = domain or "network"
        if domain not in _VALID_DOMAINS:
            raise ValueError(
                f"Invalid domain '{domain}'. "
                f"Must be one of {sorted(_VALID_DOMAINS)}"
            )
        score = max(0.0, min(100.0, float(score)))
        now = _now_iso()
        cutoff = _days_ago_iso(7)

        with self._lock:
            with self._conn() as conn:
                # Compute overall_score = avg of last 7 days for this org (excluding new record)
                row = conn.execute(
                    "SELECT AVG(score) as avg_score FROM posture_snapshots "
                    "WHERE org_id=? AND snapshot_date >= ?",
                    (org_id, cutoff),
                ).fetchone()
                existing_avg = row["avg_score"] if row and row["avg_score"] is not None else None
                # Include the new score in overall
                if existing_avg is not None:
                    overall_score = round((existing_avg + score) / 2, 2)
                else:
                    overall_score = score

                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "snapshot_date": now,
                    "overall_score": overall_score,
                    "domain": domain,
                    "score": score,
                    "findings_count": findings_count,
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "source": source or "",
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO posture_snapshots
                       (id, org_id, snapshot_date, overall_score, domain, score,
                        findings_count, critical_count, high_count, source, created_at)
                       VALUES (:id, :org_id, :snapshot_date, :overall_score, :domain,
                               :score, :findings_count, :critical_count, :high_count,
                               :source, :created_at)""",
                    record,
                )
        return record

    def get_snapshots(
        self,
        org_id: str,
        domain: Optional[str] = None,
        days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get snapshots filtered by date range (last N days), optionally by domain."""
        cutoff = _days_ago_iso(days)
        with self._lock:
            with self._conn() as conn:
                if domain:
                    rows = conn.execute(
                        "SELECT * FROM posture_snapshots "
                        "WHERE org_id=? AND domain=? AND snapshot_date >= ? "
                        "ORDER BY snapshot_date DESC",
                        (org_id, domain, cutoff),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM posture_snapshots "
                        "WHERE org_id=? AND snapshot_date >= ? "
                        "ORDER BY snapshot_date DESC",
                        (org_id, cutoff),
                    ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Trends
    # ------------------------------------------------------------------

    def compute_trend(
        self, org_id: str, domain: str, period: str = "monthly"
    ) -> Dict[str, Any]:
        """Compute trend for a domain/period; determine improving/declining/stable."""
        period = period or "monthly"
        if period not in _VALID_PERIODS:
            raise ValueError(
                f"Invalid period '{period}'. Must be one of {sorted(_VALID_PERIODS)}"
            )
        domain = domain or "network"
        if domain not in _VALID_DOMAINS:
            raise ValueError(
                f"Invalid domain '{domain}'. Must be one of {sorted(_VALID_DOMAINS)}"
            )

        # Map period to days
        period_days = {"weekly": 7, "monthly": 30, "quarterly": 90}
        days = period_days[period]
        cutoff = _days_ago_iso(days)
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT score, snapshot_date FROM posture_snapshots "
                    "WHERE org_id=? AND domain=? AND snapshot_date >= ? "
                    "ORDER BY snapshot_date ASC",
                    (org_id, domain, cutoff),
                ).fetchall()

                scores = [r["score"] for r in rows]
                if not scores:
                    avg_score = 0.0
                    min_score = 0.0
                    max_score = 0.0
                    trend_direction = "stable"
                else:
                    avg_score = round(sum(scores) / len(scores), 2)
                    min_score = round(min(scores), 2)
                    max_score = round(max(scores), 2)

                    # Compare first half avg vs second half avg
                    mid = len(scores) // 2
                    if mid == 0:
                        trend_direction = "stable"
                    else:
                        first_half = scores[:mid]
                        second_half = scores[mid:]
                        first_avg = sum(first_half) / len(first_half)
                        second_avg = sum(second_half) / len(second_half)
                        diff = second_avg - first_avg
                        if diff > 2.0:
                            trend_direction = "improving"
                        elif diff < -2.0:
                            trend_direction = "declining"
                        else:
                            trend_direction = "stable"

                trend_id = str(uuid.uuid4())
                record: Dict[str, Any] = {
                    "id": trend_id,
                    "org_id": org_id,
                    "domain": domain,
                    "period": period,
                    "avg_score": avg_score,
                    "min_score": min_score,
                    "max_score": max_score,
                    "trend_direction": trend_direction,
                    "computed_at": now,
                }
                conn.execute(
                    """INSERT INTO posture_trends
                       (id, org_id, domain, period, avg_score, min_score, max_score,
                        trend_direction, computed_at)
                       VALUES (:id, :org_id, :domain, :period, :avg_score, :min_score,
                               :max_score, :trend_direction, :computed_at)""",
                    record,
                )
        return record

    def get_trends(
        self, org_id: str, domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get computed trends, optionally filtered by domain."""
        with self._lock:
            with self._conn() as conn:
                if domain:
                    rows = conn.execute(
                        "SELECT * FROM posture_trends "
                        "WHERE org_id=? AND domain=? "
                        "ORDER BY computed_at DESC",
                        (org_id, domain),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM posture_trends "
                        "WHERE org_id=? "
                        "ORDER BY computed_at DESC",
                        (org_id,),
                    ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def set_baseline(
        self,
        org_id: str,
        domain: str,
        baseline_score: float,
        target_score: float,
        set_by: str = "",
    ) -> Dict[str, Any]:
        """Upsert a baseline for a domain."""
        domain = domain or "network"
        if domain not in _VALID_DOMAINS:
            raise ValueError(
                f"Invalid domain '{domain}'. Must be one of {sorted(_VALID_DOMAINS)}"
            )
        baseline_score = max(0.0, min(100.0, float(baseline_score)))
        target_score = max(0.0, min(100.0, float(target_score)))
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM posture_baselines WHERE org_id=? AND domain=?",
                    (org_id, domain),
                ).fetchone()
                if existing:
                    record_id = existing["id"]
                    conn.execute(
                        "UPDATE posture_baselines "
                        "SET baseline_score=?, target_score=?, set_by=?, set_at=? "
                        "WHERE org_id=? AND domain=?",
                        (baseline_score, target_score, set_by or "", now, org_id, domain),
                    )
                else:
                    record_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO posture_baselines
                           (id, org_id, domain, baseline_score, target_score, set_by, set_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (record_id, org_id, domain, baseline_score, target_score,
                         set_by or "", now),
                    )
        return {
            "id": record_id,
            "org_id": org_id,
            "domain": domain,
            "baseline_score": baseline_score,
            "target_score": target_score,
            "set_by": set_by or "",
            "set_at": now,
        }

    def get_baseline(self, org_id: str, domain: str) -> Optional[Dict[str, Any]]:
        """Get baseline for a specific domain."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM posture_baselines WHERE org_id=? AND domain=?",
                    (org_id, domain),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Delta & Summary
    # ------------------------------------------------------------------

    def get_posture_delta(
        self, org_id: str, domain: str, days: int = 30
    ) -> Dict[str, Any]:
        """Score change from oldest to newest snapshot in the window."""
        cutoff = _days_ago_iso(days)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT score, snapshot_date FROM posture_snapshots "
                    "WHERE org_id=? AND domain=? AND snapshot_date >= ? "
                    "ORDER BY snapshot_date ASC",
                    (org_id, domain, cutoff),
                ).fetchall()
        if not rows:
            return {
                "org_id": org_id,
                "domain": domain,
                "days": days,
                "oldest_score": None,
                "newest_score": None,
                "delta": None,
            }
        oldest = rows[0]["score"]
        newest = rows[-1]["score"]
        return {
            "org_id": org_id,
            "domain": domain,
            "days": days,
            "oldest_score": oldest,
            "newest_score": newest,
            "delta": round(newest - oldest, 2),
        }

    def get_domain_summary(self, org_id: str) -> List[Dict[str, Any]]:
        """Per-domain: latest score, trend direction, baseline gap."""
        with self._lock:
            with self._conn() as conn:
                # Latest score per domain
                latest_rows = conn.execute(
                    """SELECT domain, score, snapshot_date
                       FROM posture_snapshots
                       WHERE org_id=? AND (domain, snapshot_date) IN (
                           SELECT domain, MAX(snapshot_date)
                           FROM posture_snapshots
                           WHERE org_id=?
                           GROUP BY domain
                       )""",
                    (org_id, org_id),
                ).fetchall()

                # Latest trend per domain
                trend_rows = conn.execute(
                    """SELECT domain, trend_direction, computed_at
                       FROM posture_trends
                       WHERE org_id=? AND (domain, computed_at) IN (
                           SELECT domain, MAX(computed_at)
                           FROM posture_trends
                           WHERE org_id=?
                           GROUP BY domain
                       )""",
                    (org_id, org_id),
                ).fetchall()

                # Baselines
                baseline_rows = conn.execute(
                    "SELECT domain, baseline_score, target_score "
                    "FROM posture_baselines WHERE org_id=?",
                    (org_id,),
                ).fetchall()

        trend_map = {r["domain"]: r["trend_direction"] for r in trend_rows}
        baseline_map = {
            r["domain"]: {"baseline_score": r["baseline_score"], "target_score": r["target_score"]}
            for r in baseline_rows
        }

        summary = []
        for row in latest_rows:
            domain = row["domain"]
            latest_score = row["score"]
            bl = baseline_map.get(domain, {})
            baseline_score = bl.get("baseline_score")
            target_score = bl.get("target_score")
            gap_from_baseline = (
                round(latest_score - baseline_score, 2)
                if baseline_score is not None else None
            )
            gap_from_target = (
                round(latest_score - target_score, 2)
                if target_score is not None else None
            )
            summary.append({
                "domain": domain,
                "latest_score": latest_score,
                "latest_snapshot_date": row["snapshot_date"],
                "trend_direction": trend_map.get(domain, "stable"),
                "baseline_score": baseline_score,
                "target_score": target_score,
                "gap_from_baseline": gap_from_baseline,
                "gap_from_target": gap_from_target,
            })
        return summary
