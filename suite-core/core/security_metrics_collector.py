"""Security Metrics Collector Engine — ALDECI.

Define security metrics, record readings, compute aggregates, and surface
threshold-based alerts. Covers vulnerability, threat, compliance, incident,
identity, endpoint, cloud, and training categories.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_metrics.db"
)

_VALID_CATEGORIES = {
    "vulnerability", "threat", "compliance", "incident",
    "identity", "endpoint", "cloud", "training",
}
_VALID_PERIOD_TYPES = {"daily", "weekly", "monthly"}
_VALID_ALERT_TYPES = {"threshold_breach", "anomaly", "missing_data"}
_VALID_SEVERITIES = {"critical", "high", "medium"}


class SecurityMetricsCollector:
    """SQLite WAL-backed security metrics collector.

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
                CREATE TABLE IF NOT EXISTS metric_definitions (
                    metric_id          TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    name               TEXT NOT NULL,
                    description        TEXT NOT NULL DEFAULT '',
                    category           TEXT NOT NULL DEFAULT 'vulnerability',
                    unit               TEXT NOT NULL DEFAULT '',
                    target_value       REAL,
                    critical_threshold REAL,
                    warning_threshold  REAL,
                    enabled            INTEGER NOT NULL DEFAULT 1,
                    created_at         DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_md_org
                    ON metric_definitions (org_id, category, enabled);

                CREATE TABLE IF NOT EXISTS metric_readings (
                    reading_id    TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    metric_id     TEXT NOT NULL,
                    value         REAL NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'normal',
                    source_system TEXT NOT NULL DEFAULT 'manual',
                    period_start  DATETIME,
                    period_end    DATETIME,
                    recorded_at   DATETIME NOT NULL,
                    FOREIGN KEY (metric_id) REFERENCES metric_definitions (metric_id)
                );

                CREATE INDEX IF NOT EXISTS idx_mr_org_metric
                    ON metric_readings (org_id, metric_id, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS metric_aggregates (
                    agg_id          TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    metric_id       TEXT NOT NULL,
                    period_type     TEXT NOT NULL DEFAULT 'daily',
                    period_label    TEXT NOT NULL,
                    avg_value       REAL NOT NULL DEFAULT 0,
                    min_value       REAL NOT NULL DEFAULT 0,
                    max_value       REAL NOT NULL DEFAULT 0,
                    readings_count  INTEGER NOT NULL DEFAULT 0,
                    calculated_at   DATETIME NOT NULL,
                    FOREIGN KEY (metric_id) REFERENCES metric_definitions (metric_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ma_org_metric
                    ON metric_aggregates (org_id, metric_id, period_type);

                CREATE TABLE IF NOT EXISTS metric_alerts (
                    alert_id     TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    metric_id    TEXT NOT NULL,
                    reading_id   TEXT NOT NULL,
                    alert_type   TEXT NOT NULL DEFAULT 'threshold_breach',
                    message      TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at   DATETIME NOT NULL,
                    FOREIGN KEY (metric_id) REFERENCES metric_definitions (metric_id),
                    FOREIGN KEY (reading_id) REFERENCES metric_readings (reading_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ma_org_ack
                    ON metric_alerts (org_id, acknowledged, created_at DESC);
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
    # Metric definitions
    # ------------------------------------------------------------------

    def define_metric(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Define a new security metric. Returns the created definition."""
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required.")

        category = data.get("category", "vulnerability")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}. Must be one of {_VALID_CATEGORIES}")

        metric_id = str(uuid.uuid4())
        now = self._now()

        record = {
            "metric_id": metric_id,
            "org_id": org_id,
            "name": name,
            "description": data.get("description", ""),
            "category": category,
            "unit": data.get("unit", ""),
            "target_value": data.get("target_value"),
            "critical_threshold": data.get("critical_threshold"),
            "warning_threshold": data.get("warning_threshold"),
            "enabled": int(data.get("enabled", 1)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO metric_definitions
                        (metric_id, org_id, name, description, category, unit,
                         target_value, critical_threshold, warning_threshold,
                         enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        metric_id, org_id, name, record["description"], category,
                        record["unit"], record["target_value"], record["critical_threshold"],
                        record["warning_threshold"], record["enabled"], now,
                    ),
                )
        return record

    def list_metrics(
        self,
        org_id: str,
        category: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List metric definitions with optional category filter."""
        query = "SELECT * FROM metric_definitions WHERE org_id=?"
        params: list = [org_id]
        if category:
            query += " AND category=?"
            params.append(category)
        if enabled_only:
            query += " AND enabled=1"
        query += " ORDER BY category, name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def _get_metric_def(self, conn: sqlite3.Connection, org_id: str, metric_id: str) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM metric_definitions WHERE org_id=? AND metric_id=?",
            (org_id, metric_id),
        ).fetchone()

    # ------------------------------------------------------------------
    # Readings
    # ------------------------------------------------------------------

    def record_reading(
        self,
        org_id: str,
        metric_id: str,
        value: float,
        source_system: str = "manual",
        period_start: Optional[str] = None,
        period_end: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record a metric reading. Auto-determines status from thresholds.

        Creates a threshold_breach alert if status is critical or warning.
        Returns the created reading record.
        """
        reading_id = str(uuid.uuid4())
        now = self._now()

        with self._conn() as conn:
            defn_row = self._get_metric_def(conn, org_id, metric_id)

        if not defn_row:
            raise ValueError(f"Metric {metric_id} not found for org {org_id}")

        defn = dict(defn_row)
        critical_threshold = defn.get("critical_threshold")
        warning_threshold = defn.get("warning_threshold")

        # Determine status
        status = "normal"
        alert_severity: Optional[str] = None
        if critical_threshold is not None and value >= critical_threshold:
            status = "critical"
            alert_severity = "critical"
        elif warning_threshold is not None and value >= warning_threshold:
            status = "warning"
            alert_severity = "high"

        record = {
            "reading_id": reading_id,
            "org_id": org_id,
            "metric_id": metric_id,
            "value": value,
            "status": status,
            "source_system": source_system,
            "period_start": period_start,
            "period_end": period_end,
            "recorded_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO metric_readings
                        (reading_id, org_id, metric_id, value, status,
                         source_system, period_start, period_end, recorded_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        reading_id, org_id, metric_id, value, status,
                        source_system, period_start, period_end, now,
                    ),
                )

                if alert_severity:
                    alert_id = str(uuid.uuid4())
                    message = (
                        f"Metric '{defn['name']}' value {value} "
                        f"{'exceeded critical threshold' if status == 'critical' else 'exceeded warning threshold'} "
                        f"({critical_threshold if status == 'critical' else warning_threshold})"
                    )
                    conn.execute(
                        """
                        INSERT INTO metric_alerts
                            (alert_id, org_id, metric_id, reading_id, alert_type,
                             message, severity, acknowledged, created_at)
                        VALUES (?,?,?,?,?,?,?,0,?)
                        """,
                        (
                            alert_id, org_id, metric_id, reading_id,
                            "threshold_breach", message, alert_severity, now,
                        ),
                    )

        return record

    def list_readings(
        self,
        org_id: str,
        metric_id: str,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """List recent readings for a metric, newest first."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM metric_readings
                WHERE org_id=? AND metric_id=?
                ORDER BY recorded_at DESC LIMIT ?
                """,
                (org_id, metric_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Aggregates
    # ------------------------------------------------------------------

    def calculate_aggregate(
        self,
        org_id: str,
        metric_id: str,
        period_type: str,
    ) -> Dict[str, Any]:
        """Compute avg/min/max over all readings, save an aggregate record, return it."""
        if period_type not in _VALID_PERIOD_TYPES:
            raise ValueError(f"Invalid period_type: {period_type}. Must be one of {_VALID_PERIOD_TYPES}")

        with self._conn() as conn:
            defn_row = self._get_metric_def(conn, org_id, metric_id)
            if not defn_row:
                raise ValueError(f"Metric {metric_id} not found for org {org_id}")

            agg_row = conn.execute(
                """
                SELECT AVG(value) AS avg_val, MIN(value) AS min_val,
                       MAX(value) AS max_val, COUNT(*) AS cnt
                FROM metric_readings
                WHERE org_id=? AND metric_id=?
                """,
                (org_id, metric_id),
            ).fetchone()

        now = self._now()
        # Period label: e.g. "2026-04-16" for daily, "2026-W16" for weekly, "2026-04" for monthly
        dt = datetime.now(timezone.utc)
        if period_type == "daily":
            period_label = dt.strftime("%Y-%m-%d")
        elif period_type == "weekly":
            period_label = f"{dt.year}-W{dt.isocalendar()[1]:02d}"
        else:
            period_label = dt.strftime("%Y-%m")

        agg_id = str(uuid.uuid4())
        avg_val = agg_row["avg_val"] if agg_row and agg_row["avg_val"] is not None else 0.0
        min_val = agg_row["min_val"] if agg_row and agg_row["min_val"] is not None else 0.0
        max_val = agg_row["max_val"] if agg_row and agg_row["max_val"] is not None else 0.0
        cnt = agg_row["cnt"] if agg_row else 0

        record = {
            "agg_id": agg_id,
            "org_id": org_id,
            "metric_id": metric_id,
            "period_type": period_type,
            "period_label": period_label,
            "avg_value": avg_val,
            "min_value": min_val,
            "max_value": max_val,
            "readings_count": cnt,
            "calculated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO metric_aggregates
                        (agg_id, org_id, metric_id, period_type, period_label,
                         avg_value, min_value, max_value, readings_count, calculated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        agg_id, org_id, metric_id, period_type, period_label,
                        avg_val, min_val, max_val, cnt, now,
                    ),
                )
        return record

    def list_aggregates(
        self,
        org_id: str,
        metric_id: Optional[str] = None,
        period_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List aggregates with optional metric_id and period_type filters."""
        query = "SELECT * FROM metric_aggregates WHERE org_id=?"
        params: list = [org_id]
        if metric_id:
            query += " AND metric_id=?"
            params.append(metric_id)
        if period_type:
            query += " AND period_type=?"
            params.append(period_type)
        query += " ORDER BY calculated_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        org_id: str,
        acknowledged: bool = False,
    ) -> List[Dict[str, Any]]:
        """List metric alerts. By default returns only unacknowledged alerts."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM metric_alerts
                WHERE org_id=? AND acknowledged=?
                ORDER BY created_at DESC
                """,
                (org_id, int(acknowledged)),
            ).fetchall()
        return [self._row(r) for r in rows]

    def acknowledge_alert(self, org_id: str, alert_id: str) -> bool:
        """Mark an alert as acknowledged. Returns True if found and updated."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE metric_alerts SET acknowledged=1
                    WHERE org_id=? AND alert_id=? AND acknowledged=0
                    """,
                    (org_id, alert_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self, org_id: str) -> Dict[str, Any]:
        """Return a summary dashboard for all metrics in an org."""
        metrics = self.list_metrics(org_id, enabled_only=True)
        total_metrics = len(metrics)

        # Build by-category dict with latest reading value for each metric
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        metric_distances: List[Dict[str, Any]] = []  # for top-5-worst

        with self._conn() as conn:
            for m in metrics:
                cat = m["category"]
                mid = m["metric_id"]
                # Latest reading
                row = conn.execute(
                    """
                    SELECT value, status, recorded_at FROM metric_readings
                    WHERE org_id=? AND metric_id=?
                    ORDER BY recorded_at DESC LIMIT 1
                    """,
                    (org_id, mid),
                ).fetchone()

                entry = {
                    "metric_id": mid,
                    "name": m["name"],
                    "unit": m["unit"],
                    "target_value": m["target_value"],
                    "latest_value": row["value"] if row else None,
                    "latest_status": row["status"] if row else "no_data",
                    "latest_recorded_at": row["recorded_at"] if row else None,
                }
                by_category.setdefault(cat, []).append(entry)

                # Distance from target (for worst-metric ranking)
                if row and m["target_value"] is not None:
                    distance = abs(row["value"] - m["target_value"])
                    metric_distances.append({
                        "metric_id": mid,
                        "name": m["name"],
                        "category": cat,
                        "latest_value": row["value"],
                        "target_value": m["target_value"],
                        "distance_from_target": distance,
                        "status": row["status"],
                    })

            # Alert counts
            critical_alerts = conn.execute(
                "SELECT COUNT(*) FROM metric_alerts WHERE org_id=? AND severity='critical' AND acknowledged=0",
                (org_id,),
            ).fetchone()[0]

            warning_alerts = conn.execute(
                "SELECT COUNT(*) FROM metric_alerts WHERE org_id=? AND severity='high' AND acknowledged=0",
                (org_id,),
            ).fetchone()[0]

            unacknowledged_alerts = conn.execute(
                "SELECT COUNT(*) FROM metric_alerts WHERE org_id=? AND acknowledged=0",
                (org_id,),
            ).fetchone()[0]

        # Top 5 worst metrics (furthest from target)
        metric_distances.sort(key=lambda x: x["distance_from_target"], reverse=True)
        top_5_worst = metric_distances[:5]

        return {
            "total_metrics": total_metrics,
            "by_category": by_category,
            "critical_alerts": critical_alerts,
            "warning_alerts": warning_alerts,
            "unacknowledged_alerts": unacknowledged_alerts,
            "top_5_worst_metrics": top_5_worst,
        }
