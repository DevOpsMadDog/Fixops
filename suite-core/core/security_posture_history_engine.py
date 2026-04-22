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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


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

                -- GAP-063 lifecycle daily snapshot — one row per (org_id, day)
                CREATE TABLE IF NOT EXISTS lifecycle_daily_snapshots (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    day             TEXT NOT NULL,
                    new_count       INTEGER NOT NULL DEFAULT 0,
                    unchanged_count INTEGER NOT NULL DEFAULT 0,
                    resolved_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    UNIQUE (org_id, day)
                );

                CREATE INDEX IF NOT EXISTS idx_lds_org_day
                    ON lifecycle_daily_snapshots (org_id, day DESC);

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
            # Idempotent migration — ensure lifecycle snapshot table exists on
            # pre-existing DBs created before GAP-063.
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS lifecycle_daily_snapshots (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    day             TEXT NOT NULL,
                    new_count       INTEGER NOT NULL DEFAULT 0,
                    unchanged_count INTEGER NOT NULL DEFAULT 0,
                    resolved_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    UNIQUE (org_id, day)
                );
                CREATE INDEX IF NOT EXISTS idx_lds_org_day
                    ON lifecycle_daily_snapshots (org_id, day DESC);
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

    # ------------------------------------------------------------------
    # GAP-060 Posture timeseries
    # ------------------------------------------------------------------

    def posture_timeseries(
        self, org_id: str, days: int = 90
    ) -> Dict[str, Any]:
        """Return daily-bucketed posture_score series for an org.

        Output matches `export_timeseries` shape but fixed to key=posture_score.
        When multiple snapshots hit the same day the AVG of their scores is
        used. Missing days are filled with ``None`` so the UI can draw gaps.
        """
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ValueError("days must be an integer")
        if days <= 0:
            raise ValueError("days must be >= 1")
        if days > 365:
            raise ValueError("days exceeds limit of 365")

        now = datetime.now(timezone.utc)
        end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        start = (now - timedelta(days=days)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        buckets: List[str] = []
        cur = start
        while cur <= end:
            buckets.append(cur.isoformat())
            cur = cur + timedelta(days=1)

        bucket_index = {b: i for i, b in enumerate(buckets)}
        accum: List[List[float]] = [[] for _ in buckets]

        cutoff = start.isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT snapshot_date, score FROM posture_snapshots "
                    "WHERE org_id=? AND snapshot_date >= ?",
                    (org_id, cutoff),
                ).fetchall()

        for row in rows:
            raw = row["snapshot_date"]
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                dt = dt.astimezone(timezone.utc)
            except (ValueError, TypeError):
                continue
            day_iso = dt.replace(
                hour=0, minute=0, second=0, microsecond=0
            ).isoformat()
            idx = bucket_index.get(day_iso)
            if idx is None:
                continue
            try:
                accum[idx].append(float(row["score"]))
            except (TypeError, ValueError):
                continue

        out_vals: List[Optional[float]] = []
        for slot in accum:
            if not slot:
                out_vals.append(None)
            else:
                out_vals.append(round(sum(slot) / len(slot), 4))

        return {
            "metric_keys": ["posture_score"],
            "buckets": buckets,
            "series": {"posture_score": out_vals},
            "bucket": "daily",
            "days": days,
        }

    # ------------------------------------------------------------------
    # GAP-063 Lifecycle daily snapshot
    # ------------------------------------------------------------------

    def record_lifecycle_snapshot(
        self,
        org_id: str,
        day: Optional[str] = None,
        new_count: Optional[int] = None,
        unchanged_count: Optional[int] = None,
        resolved_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Snapshot `{new, unchanged, resolved}` counts for an org for a day.

        If ``day`` is None the current UTC date is used. Counts may be passed
        directly (e.g. by a scheduler/reconciler); when omitted we pull them
        from ``SecurityFindingsEngine.count_lifecycle_by_day`` so the snapshot
        self-populates.
        """
        if not day:
            day = datetime.now(timezone.utc).date().isoformat()
        day = day[:10]

        if new_count is None or unchanged_count is None or resolved_count is None:
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                sfe = SecurityFindingsEngine()
                counts = sfe.count_lifecycle_by_day(org_id=org_id, day_iso=day)
                if new_count is None:
                    new_count = counts.get("new", 0)
                if unchanged_count is None:
                    unchanged_count = counts.get("unchanged", 0)
                if resolved_count is None:
                    resolved_count = counts.get("resolved", 0)
            except Exception as exc:  # pragma: no cover — defensive
                _logger.warning("lifecycle snapshot fallback due to %s", exc)
                new_count = new_count or 0
                unchanged_count = unchanged_count or 0
                resolved_count = resolved_count or 0

        now = _now_iso()
        record_id = str(uuid.uuid4())
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM lifecycle_daily_snapshots WHERE org_id = ? AND day = ?",
                    (org_id, day),
                ).fetchone()
                if existing:
                    record_id = existing["id"]
                    conn.execute(
                        """UPDATE lifecycle_daily_snapshots
                           SET new_count = ?, unchanged_count = ?, resolved_count = ?,
                               created_at = ?
                           WHERE org_id = ? AND day = ?""",
                        (int(new_count), int(unchanged_count), int(resolved_count),
                         now, org_id, day),
                    )
                else:
                    conn.execute(
                        """INSERT INTO lifecycle_daily_snapshots
                           (id, org_id, day, new_count, unchanged_count, resolved_count, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (record_id, org_id, day, int(new_count),
                         int(unchanged_count), int(resolved_count), now),
                    )
        return {
            "id": record_id,
            "org_id": org_id,
            "day": day,
            "new_count": int(new_count),
            "unchanged_count": int(unchanged_count),
            "resolved_count": int(resolved_count),
            "created_at": now,
        }

    def get_lifecycle_history(
        self, org_id: str, days: int = 30
    ) -> List[Dict[str, Any]]:
        """Return the last N days of lifecycle snapshots for an org, newest-first."""
        if days <= 0:
            days = 30
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM lifecycle_daily_snapshots
                       WHERE org_id = ? AND day >= ?
                       ORDER BY day DESC""",
                    (org_id, cutoff),
                ).fetchall()
        return [self._row(r) for r in rows]
