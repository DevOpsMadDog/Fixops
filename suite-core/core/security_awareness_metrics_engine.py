"""Security Awareness Metrics Engine — ALDECI.

Tracks phishing click rates, training completion, quiz scores,
policy acknowledgement, incident report rates, and password strength
metrics per department. Supports industry benchmarking and trend analysis.

Compliance: NIST CSF PR.AT, ISO/IEC 27001 A.7.2.2, SOC 2 CC1.4
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_awareness_metrics.db"
)

_VALID_METRIC_TYPES = {
    "phishing_click_rate",
    "training_completion",
    "quiz_score",
    "policy_acknowledgement",
    "incident_report_rate",
    "password_strength",
}


class SecurityAwarenessMetricsEngine:
    """SQLite WAL-backed Security Awareness Metrics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS sam_metrics (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    metric_type TEXT NOT NULL DEFAULT 'training_completion',
                    department  TEXT NOT NULL DEFAULT 'all',
                    value       REAL NOT NULL DEFAULT 0.0,
                    period      TEXT NOT NULL DEFAULT '',
                    sample_size INTEGER NOT NULL DEFAULT 0,
                    recorded_at DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_sam_org_type
                    ON sam_metrics (org_id, metric_type, department, recorded_at);

                CREATE TABLE IF NOT EXISTS sam_benchmarks (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    metric_type      TEXT NOT NULL DEFAULT 'training_completion',
                    target_value     REAL NOT NULL DEFAULT 0.0,
                    industry_average REAL NOT NULL DEFAULT 0.0,
                    period           TEXT NOT NULL DEFAULT '',
                    updated_at       DATETIME,
                    UNIQUE(org_id, metric_type)
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_metric(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new awareness metric data point."""
        metric_type = data.get("metric_type", "training_completion")
        if metric_type not in _VALID_METRIC_TYPES:
            raise ValueError(
                f"Invalid metric_type '{metric_type}'. "
                f"Valid: {sorted(_VALID_METRIC_TYPES)}"
            )

        metric_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO sam_metrics
                        (id, org_id, metric_type, department, value, period, sample_size, recorded_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        metric_id,
                        org_id,
                        metric_type,
                        data.get("department", "all"),
                        float(data.get("value", 0.0)),
                        data.get("period", ""),
                        int(data.get("sample_size", 0)),
                        now,
                    ),
                )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sam_metrics WHERE id = ?", (metric_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_awareness_metrics", "org_id": org_id, "source_engine": "security_awareness_metrics"})
            except Exception:
                pass

        return self._row(row)

    def list_metrics(
        self,
        org_id: str,
        metric_type: Optional[str] = None,
        department: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List metrics with optional filters, newest first."""
        query = "SELECT * FROM sam_metrics WHERE org_id = ?"
        params: List[Any] = [org_id]

        if metric_type:
            query += " AND metric_type = ?"
            params.append(metric_type)
        if department:
            query += " AND department = ?"
            params.append(department)

        query += " ORDER BY recorded_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_latest_metric(
        self,
        org_id: str,
        metric_type: str,
        department: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return the most recent metric record for a given type and department."""
        query = (
            "SELECT * FROM sam_metrics WHERE org_id = ? AND metric_type = ?"
        )
        params: List[Any] = [org_id, metric_type]

        if department is not None:
            query += " AND department = ?"
            params.append(department)

        query += " ORDER BY recorded_at DESC LIMIT 1"

        with self._conn() as conn:
            row = conn.execute(query, params).fetchone()
        return self._row(row) if row else None

    def get_trend(
        self,
        org_id: str,
        metric_type: str,
        department: Optional[str] = None,
        periods: int = 4,
    ) -> Dict[str, Any]:
        """Return last N records and computed trend (improving/declining/stable)."""
        query = (
            "SELECT * FROM sam_metrics WHERE org_id = ? AND metric_type = ?"
        )
        params: List[Any] = [org_id, metric_type]

        if department is not None:
            query += " AND department = ?"
            params.append(department)

        query += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(periods)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        records = [self._row(r) for r in rows]

        trend = "stable"
        if len(records) >= 2:
            # records[0] is latest, records[-1] is oldest
            latest_value = records[0]["value"]
            earliest_value = records[-1]["value"]
            if latest_value > earliest_value:
                trend = "improving"
            elif latest_value < earliest_value:
                trend = "declining"

        return {
            "metric_type": metric_type,
            "department": department,
            "periods": len(records),
            "records": records,
            "trend": trend,
        }

    def set_benchmark(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a benchmark for a metric type (UPSERT)."""
        metric_type = data.get("metric_type", "training_completion")
        if metric_type not in _VALID_METRIC_TYPES:
            raise ValueError(
                f"Invalid metric_type '{metric_type}'. "
                f"Valid: {sorted(_VALID_METRIC_TYPES)}"
            )

        now = self._now()

        with self._lock:
            with self._conn() as conn:
                # Check if exists
                existing = conn.execute(
                    "SELECT id FROM sam_benchmarks WHERE org_id = ? AND metric_type = ?",
                    (org_id, metric_type),
                ).fetchone()

                if existing:
                    bm_id = existing["id"]
                    conn.execute(
                        """
                        UPDATE sam_benchmarks
                        SET target_value = ?, industry_average = ?, period = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            float(data.get("target_value", 0.0)),
                            float(data.get("industry_average", 0.0)),
                            data.get("period", ""),
                            now,
                            bm_id,
                        ),
                    )
                else:
                    bm_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO sam_benchmarks
                            (id, org_id, metric_type, target_value, industry_average, period, updated_at)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            bm_id,
                            org_id,
                            metric_type,
                            float(data.get("target_value", 0.0)),
                            float(data.get("industry_average", 0.0)),
                            data.get("period", ""),
                            now,
                        ),
                    )

        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM sam_benchmarks WHERE id = ?", (bm_id,)
            ).fetchone()
        return self._row(row)

    def list_benchmarks(self, org_id: str) -> List[Dict[str, Any]]:
        """List all benchmarks for the org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM sam_benchmarks WHERE org_id = ? ORDER BY metric_type",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_awareness_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate awareness statistics for the org."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM sam_metrics WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unique_depts = conn.execute(
                "SELECT COUNT(DISTINCT department) FROM sam_metrics WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                """
                SELECT metric_type, COUNT(*) as cnt
                FROM sam_metrics WHERE org_id = ?
                GROUP BY metric_type
                """,
                (org_id,),
            ).fetchall()
            metrics_by_type = {r["metric_type"]: r["cnt"] for r in type_rows}

            # best/worst: type with highest/lowest avg value
            avg_rows = conn.execute(
                """
                SELECT metric_type, AVG(value) as avg_val
                FROM sam_metrics WHERE org_id = ?
                GROUP BY metric_type
                ORDER BY avg_val DESC
                """,
                (org_id,),
            ).fetchall()

            best_metric = avg_rows[0]["metric_type"] if avg_rows else None
            worst_metric = avg_rows[-1]["metric_type"] if avg_rows else None

            # departments below benchmark
            benchmarks = self.list_benchmarks(org_id)
            depts_below: List[str] = []
            for bm in benchmarks:
                mt = bm["metric_type"]
                target = bm["target_value"]
                # get latest value per department for this metric_type
                dept_rows = conn.execute(
                    """
                    SELECT department, value
                    FROM sam_metrics
                    WHERE org_id = ? AND metric_type = ?
                    ORDER BY recorded_at DESC
                    """,
                    (org_id, mt),
                ).fetchall()
                seen: set = set()
                for dr in dept_rows:
                    dept = dr["department"]
                    if dept not in seen:
                        seen.add(dept)
                        if dr["value"] < target:
                            entry = f"{dept}:{mt}"
                            if entry not in depts_below:
                                depts_below.append(entry)

        return {
            "total_metrics": total,
            "unique_departments": unique_depts,
            "metrics_by_type": metrics_by_type,
            "best_metric": best_metric,
            "worst_metric": worst_metric,
            "departments_below_benchmark": depts_below,
        }
