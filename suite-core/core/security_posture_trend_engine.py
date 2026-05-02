"""Security Posture Trend Engine — ALDECI.

Analyzes security posture changes over time with predictive insights.
Tracks improvement velocity, predicts future posture, and identifies
stagnating areas across 8 security metric categories.

Compliance: NIST CSF ID.RM, ISO/IEC 27001 A.5.31, SOC 2 CC9.1
"""

from __future__ import annotations

import logging
import math
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_trend.db"
)

_VALID_CATEGORIES = {
    "vulnerability", "compliance", "identity", "network",
    "endpoint", "cloud", "data", "awareness",
}
_VALID_UNITS = {"score", "percentage", "count", "days", "hours"}
_VALID_TREND_LABELS = {"improving", "declining", "stable"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityPostureTrendEngine:
    """SQLite WAL-backed Security Posture Trend engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS posture_datapoints (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    metric_name     TEXT NOT NULL,
                    metric_category TEXT NOT NULL DEFAULT 'vulnerability',
                    value           REAL NOT NULL,
                    unit            TEXT NOT NULL DEFAULT 'score',
                    recorded_at     TEXT NOT NULL,
                    source          TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pdp_org_metric
                    ON posture_datapoints (org_id, metric_name, recorded_at);

                CREATE TABLE IF NOT EXISTS trend_analyses (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    metric_name  TEXT NOT NULL,
                    period_days  INTEGER NOT NULL,
                    start_value  REAL NOT NULL,
                    end_value    REAL NOT NULL,
                    change_pct   REAL NOT NULL,
                    velocity     REAL NOT NULL,
                    trend_label  TEXT NOT NULL DEFAULT 'stable',
                    confidence   REAL NOT NULL,
                    analyzed_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ta_org_metric
                    ON trend_analyses (org_id, metric_name, analyzed_at);

                CREATE TABLE IF NOT EXISTS posture_targets (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    metric_name   TEXT NOT NULL,
                    target_value  REAL NOT NULL,
                    current_value REAL NOT NULL,
                    gap           REAL NOT NULL,
                    eta_days      INTEGER,
                    set_by        TEXT NOT NULL DEFAULT '',
                    created_at    TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_pt_org_metric
                    ON posture_targets (org_id, metric_name);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Datapoints
    # ------------------------------------------------------------------

    def record_datapoint(
        self,
        org_id: str,
        metric_name: str,
        metric_category: str,
        value: float,
        unit: str,
        source: str = "",
    ) -> Dict[str, Any]:
        """Record a new security posture data point."""
        if metric_category not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid metric_category '{metric_category}'. "
                f"Valid: {sorted(_VALID_CATEGORIES)}"
            )
        if unit not in _VALID_UNITS:
            raise ValueError(
                f"Invalid unit '{unit}'. Valid: {sorted(_VALID_UNITS)}"
            )

        dp_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO posture_datapoints
                        (id, org_id, metric_name, metric_category, value, unit,
                         recorded_at, source, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (dp_id, org_id, metric_name, metric_category, value, unit,
                     now, source, now),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM posture_datapoints WHERE id = ?", (dp_id,)
            ).fetchone()
        return self._row(row)

    def _get_datapoints_in_period(
        self, org_id: str, metric_name: str, period_days: int
    ) -> List[Dict[str, Any]]:
        """Fetch datapoints for a metric within the last period_days days, oldest first."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=period_days)
        ).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM posture_datapoints
                WHERE org_id = ? AND metric_name = ? AND recorded_at >= ?
                ORDER BY recorded_at ASC
                """,
                (org_id, metric_name, cutoff),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Trend Analysis
    # ------------------------------------------------------------------

    def analyze_trend(
        self, org_id: str, metric_name: str, period_days: int
    ) -> Dict[str, Any]:
        """Compute trend for a metric over the given period and persist results."""
        datapoints = self._get_datapoints_in_period(org_id, metric_name, period_days)

        if len(datapoints) < 2:
            raise ValueError(
                f"Insufficient datapoints for metric '{metric_name}' "
                f"(need ≥2, got {len(datapoints)})"
            )

        start_value = datapoints[0]["value"]
        end_value = datapoints[-1]["value"]

        if start_value == 0:
            change_pct = 0.0
        else:
            change_pct = ((end_value - start_value) / abs(start_value)) * 100.0

        velocity = change_pct / period_days if period_days > 0 else 0.0

        if velocity > 0.5:
            trend_label = "improving"
        elif velocity < -0.5:
            trend_label = "declining"
        else:
            trend_label = "stable"

        n = len(datapoints)
        if n >= 10:
            confidence = 0.9
        elif n >= 5:
            confidence = 0.7
        elif n >= 2:
            confidence = 0.5
        else:
            confidence = 0.3

        analysis_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO trend_analyses
                        (id, org_id, metric_name, period_days, start_value,
                         end_value, change_pct, velocity, trend_label, confidence,
                         analyzed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        analysis_id, org_id, metric_name, period_days,
                        start_value, end_value, change_pct, velocity,
                        trend_label, confidence, now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM trend_analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        return self._row(row)

    def get_trend(
        self, org_id: str, metric_name: str
    ) -> Optional[Dict[str, Any]]:
        """Return the latest trend analysis for a metric."""
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM trend_analyses
                WHERE org_id = ? AND metric_name = ?
                ORDER BY analyzed_at DESC
                LIMIT 1
                """,
                (org_id, metric_name),
            ).fetchone()
        return self._row(row) if row else None

    def list_trends(
        self, org_id: str, trend_label: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List latest trend analysis per metric, optionally filtered by label."""
        # Subquery: get latest analyzed_at per org+metric
        query = """
            SELECT t.*
            FROM trend_analyses t
            INNER JOIN (
                SELECT org_id, metric_name, MAX(analyzed_at) AS max_at
                FROM trend_analyses
                WHERE org_id = ?
                GROUP BY org_id, metric_name
            ) latest
            ON t.org_id = latest.org_id
               AND t.metric_name = latest.metric_name
               AND t.analyzed_at = latest.max_at
            WHERE t.org_id = ?
        """
        params: List[Any] = [org_id, org_id]

        if trend_label:
            query += " AND t.trend_label = ?"
            params.append(trend_label)

        query += " ORDER BY t.analyzed_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def _latest_velocity(self, org_id: str, metric_name: str) -> Optional[float]:
        """Return velocity from the latest trend analysis, or None."""
        trend = self.get_trend(org_id, metric_name)
        return trend["velocity"] if trend else None

    def _compute_eta(self, gap: float, velocity: Optional[float]) -> Optional[int]:
        """Compute ETA in days. Returns None if velocity <= 0."""
        if velocity is None or velocity <= 0:
            return None
        # velocity is change_pct/day; gap is absolute value units difference
        # eta_days = ceil(gap / velocity_per_day) where velocity is %/day
        # We interpret eta as: days until gap closed assuming constant velocity
        if gap <= 0:
            return 0
        return math.ceil(gap / velocity)

    def set_target(
        self,
        org_id: str,
        metric_name: str,
        target_value: float,
        current_value: float,
        set_by: str = "",
    ) -> Dict[str, Any]:
        """Create or replace a posture target for a metric."""
        gap = target_value - current_value
        velocity = self._latest_velocity(org_id, metric_name)
        eta_days = self._compute_eta(gap, velocity)

        target_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                # Upsert by org+metric
                existing = conn.execute(
                    "SELECT id FROM posture_targets WHERE org_id = ? AND metric_name = ?",
                    (org_id, metric_name),
                ).fetchone()
                if existing:
                    conn.execute(
                        """
                        UPDATE posture_targets
                        SET target_value = ?, current_value = ?, gap = ?,
                            eta_days = ?, set_by = ?
                        WHERE org_id = ? AND metric_name = ?
                        """,
                        (target_value, current_value, gap, eta_days, set_by,
                         org_id, metric_name),
                    )
                    target_id = existing["id"]
                else:
                    conn.execute(
                        """
                        INSERT INTO posture_targets
                            (id, org_id, metric_name, target_value, current_value,
                             gap, eta_days, set_by, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (target_id, org_id, metric_name, target_value, current_value,
                         gap, eta_days, set_by, now),
                    )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM posture_targets WHERE org_id = ? AND metric_name = ?",
                (org_id, metric_name),
            ).fetchone()
        return self._row(row)

    def update_target_progress(
        self, org_id: str, metric_name: str, current_value: float
    ) -> Dict[str, Any]:
        """Update current_value, recompute gap and eta_days."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM posture_targets WHERE org_id = ? AND metric_name = ?",
                (org_id, metric_name),
            ).fetchone()
        if row is None:
            raise KeyError(f"No target for metric '{metric_name}' in org '{org_id}'")

        target = self._row(row)
        target_value = target["target_value"]
        gap = target_value - current_value
        velocity = self._latest_velocity(org_id, metric_name)
        eta_days = self._compute_eta(gap, velocity)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE posture_targets
                    SET current_value = ?, gap = ?, eta_days = ?
                    WHERE org_id = ? AND metric_name = ?
                    """,
                    (current_value, gap, eta_days, org_id, metric_name),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM posture_targets WHERE org_id = ? AND metric_name = ?",
                (org_id, metric_name),
            ).fetchone()
        return self._row(row)

    def get_targets(self, org_id: str) -> List[Dict[str, Any]]:
        """List all targets for org with on_track boolean (gap > 0 and eta_days not None)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM posture_targets WHERE org_id = ? ORDER BY metric_name",
                (org_id,),
            ).fetchall()

        results = []
        for row in rows:
            t = self._row(row)
            # on_track: target is above current (gap > 0) and eta exists (velocity positive)
            on_track = (t["eta_days"] is not None) and (t["gap"] > 0)
            t["on_track"] = on_track
            results.append(t)
        return results

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_stagnating_metrics(
        self, org_id: str, threshold_days: int
    ) -> List[str]:
        """Return metric names with no datapoints in the last threshold_days days."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=threshold_days)
        ).isoformat()

        with self._conn() as conn:
            # All known metrics for org
            all_metrics_rows = conn.execute(
                "SELECT DISTINCT metric_name FROM posture_datapoints WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            all_metrics = {r["metric_name"] for r in all_metrics_rows}

            # Metrics with recent datapoints
            recent_rows = conn.execute(
                """
                SELECT DISTINCT metric_name FROM posture_datapoints
                WHERE org_id = ? AND recorded_at >= ?
                """,
                (org_id, cutoff),
            ).fetchall()
            recent_metrics = {r["metric_name"] for r in recent_rows}

        stagnating = sorted(all_metrics - recent_metrics)
        return stagnating

    def get_posture_velocity_summary(self, org_id: str) -> Dict[str, Any]:
        """Return avg velocity per metric_category, fastest improving/declining metric."""
        trends = self.list_trends(org_id)

        if not trends:
            return {
                "avg_velocity_by_category": {},
                "fastest_improving": None,
                "fastest_declining": None,
            }

        # Join trend data with datapoints to get category
        with self._conn() as conn:
            category_rows = conn.execute(
                """
                SELECT metric_name, metric_category
                FROM posture_datapoints
                WHERE org_id = ?
                GROUP BY metric_name
                """,
                (org_id,),
            ).fetchall()
        metric_category_map = {r["metric_name"]: r["metric_category"] for r in category_rows}

        category_velocities: Dict[str, List[float]] = {}
        for trend in trends:
            cat = metric_category_map.get(trend["metric_name"], "unknown")
            category_velocities.setdefault(cat, []).append(trend["velocity"])

        avg_velocity_by_category = {
            cat: round(sum(vels) / len(vels), 4)
            for cat, vels in category_velocities.items()
        }

        # Fastest improving = max positive velocity
        sorted_by_velocity = sorted(trends, key=lambda t: t["velocity"])
        fastest_declining = sorted_by_velocity[0]["metric_name"] if sorted_by_velocity else None
        fastest_improving = sorted_by_velocity[-1]["metric_name"] if sorted_by_velocity else None

        return {
            "avg_velocity_by_category": avg_velocity_by_category,
            "fastest_improving": fastest_improving,
            "fastest_declining": fastest_declining,
        }
