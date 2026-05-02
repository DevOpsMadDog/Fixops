"""Security Operations Metrics Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Tracks SOC operational metrics: MTTD, MTTR, alert volume, analyst workload.
  - Create and lifecycle-manage SOC alerts (open → acknowledged → resolved)
  - Daily snapshots with MTTD/MTTR computed via julianday arithmetic
  - Analyst workload tracking with resolution performance
  - False positive rate and resolution rate metrics

Compliance: NIST SP 800-61r2, ISO 27001 A.16, SOC2 CC7.2
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_operations_metrics_engine.db"
)

_VALID_ALERT_SOURCES = {"SIEM", "EDR", "IDS", "WAF", "CASB", "TIP", "manual", "email"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CATEGORIES = {
    "malware", "phishing", "intrusion", "data_exfil",
    "policy_violation", "recon", "lateral_movement", "other",
}
_VALID_STATUSES = {"open", "acknowledged", "resolved", "false_positive"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_str() -> str:
    return date.today().isoformat()


class SecurityOperationsMetricsEngine:
    """SQLite WAL-backed Security Operations Metrics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_operations_metrics_engine.db
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
                CREATE TABLE IF NOT EXISTS soc_alerts (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    alert_source     TEXT NOT NULL DEFAULT 'SIEM',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    category         TEXT NOT NULL DEFAULT 'other',
                    detected_at      TEXT NOT NULL DEFAULT '',
                    acknowledged_at  TEXT,
                    resolved_at      TEXT,
                    assigned_to      TEXT,
                    status           TEXT NOT NULL DEFAULT 'open',
                    false_positive   INTEGER NOT NULL DEFAULT 0,
                    created_at       TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_som_alerts_org
                    ON soc_alerts (org_id, status, severity, detected_at);

                CREATE TABLE IF NOT EXISTS analyst_workload (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    analyst_name         TEXT NOT NULL DEFAULT '',
                    date                 TEXT NOT NULL DEFAULT '',
                    alerts_assigned      INTEGER NOT NULL DEFAULT 0,
                    alerts_resolved      INTEGER NOT NULL DEFAULT 0,
                    avg_resolution_mins  REAL NOT NULL DEFAULT 0.0,
                    created_at           TEXT NOT NULL DEFAULT '',
                    UNIQUE (org_id, analyst_name, date)
                );

                CREATE INDEX IF NOT EXISTS idx_som_workload_org
                    ON analyst_workload (org_id, date, analyst_name);

                CREATE TABLE IF NOT EXISTS soc_daily_snapshots (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    snapshot_date       TEXT NOT NULL DEFAULT '',
                    total_alerts        INTEGER NOT NULL DEFAULT 0,
                    critical_alerts     INTEGER NOT NULL DEFAULT 0,
                    mttd_mins           REAL NOT NULL DEFAULT 0.0,
                    mttr_mins           REAL NOT NULL DEFAULT 0.0,
                    false_positive_rate REAL NOT NULL DEFAULT 0.0,
                    resolution_rate     REAL NOT NULL DEFAULT 0.0,
                    created_at          TEXT NOT NULL DEFAULT '',
                    UNIQUE (org_id, snapshot_date)
                );

                CREATE INDEX IF NOT EXISTS idx_som_snapshots_org
                    ON soc_daily_snapshots (org_id, snapshot_date DESC);
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
    # Alert lifecycle
    # ------------------------------------------------------------------

    def create_alert(
        self,
        org_id: str,
        alert_source: str,
        severity: str,
        category: str,
        detected_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new SOC alert. detected_at defaults to now."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "alert_source": alert_source,
            "severity": severity,
            "category": category,
            "detected_at": detected_at or now,
            "acknowledged_at": None,
            "resolved_at": None,
            "assigned_to": None,
            "status": "open",
            "false_positive": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO soc_alerts
                       (id, org_id, alert_source, severity, category, detected_at,
                        acknowledged_at, resolved_at, assigned_to, status,
                        false_positive, created_at)
                       VALUES (:id, :org_id, :alert_source, :severity, :category,
                               :detected_at, :acknowledged_at, :resolved_at,
                               :assigned_to, :status, :false_positive, :created_at)""",
                    record,
                )
        return record

    def acknowledge_alert(
        self,
        alert_id: str,
        org_id: str,
        analyst: str,
    ) -> Optional[Dict[str, Any]]:
        """Acknowledge an alert: set acknowledged_at=now, assigned_to=analyst, status=acknowledged."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM soc_alerts WHERE id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()
                if not row:
                    return None
                conn.execute(
                    """UPDATE soc_alerts
                       SET acknowledged_at = ?, assigned_to = ?, status = 'acknowledged'
                       WHERE id = ? AND org_id = ?""",
                    (now, analyst, alert_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM soc_alerts WHERE id = ?", (alert_id,)
                ).fetchone()
                return self._row(updated)

    def resolve_alert(
        self,
        alert_id: str,
        org_id: str,
        false_positive: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Resolve an alert: set resolved_at=now, status=resolved, false_positive flag."""
        now = _now_iso()
        fp_val = 1 if false_positive else 0
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM soc_alerts WHERE id = ? AND org_id = ?",
                    (alert_id, org_id),
                ).fetchone()
                if not row:
                    return None
                conn.execute(
                    """UPDATE soc_alerts
                       SET resolved_at = ?, status = 'resolved', false_positive = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, fp_val, alert_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM soc_alerts WHERE id = ?", (alert_id,)
                ).fetchone()
                return self._row(updated)

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def take_daily_snapshot(
        self,
        org_id: str,
        snapshot_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Compute and INSERT OR REPLACE a daily snapshot for org_id.

        Metrics computed from soc_alerts WHERE detected_at starts with snapshot_date.
        """
        snap_date = snapshot_date or _today_str()
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                # total and critical counts
                totals = conn.execute(
                    """SELECT
                         COUNT(*) AS total_alerts,
                         SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_alerts,
                         AVG(CASE WHEN acknowledged_at IS NOT NULL
                                  THEN (julianday(acknowledged_at) - julianday(detected_at)) * 1440
                                  ELSE NULL END) AS mttd_mins,
                         AVG(CASE WHEN resolved_at IS NOT NULL
                                  THEN (julianday(resolved_at) - julianday(detected_at)) * 1440
                                  ELSE NULL END) AS mttr_mins,
                         SUM(false_positive) * 1.0 / NULLIF(COUNT(*), 0) * 100 AS false_positive_rate,
                         SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) * 1.0
                             / NULLIF(COUNT(*), 0) * 100 AS resolution_rate
                       FROM soc_alerts
                       WHERE org_id = ? AND detected_at LIKE ?""",
                    (org_id, snap_date + "%"),
                ).fetchone()

                total_alerts = totals["total_alerts"] or 0
                critical_alerts = totals["critical_alerts"] or 0
                mttd_mins = round(totals["mttd_mins"] or 0.0, 4)
                mttr_mins = round(totals["mttr_mins"] or 0.0, 4)
                false_positive_rate = round(totals["false_positive_rate"] or 0.0, 4)
                resolution_rate = round(totals["resolution_rate"] or 0.0, 4)

                snap_id = str(uuid.uuid4())
                record: Dict[str, Any] = {
                    "id": snap_id,
                    "org_id": org_id,
                    "snapshot_date": snap_date,
                    "total_alerts": total_alerts,
                    "critical_alerts": critical_alerts,
                    "mttd_mins": mttd_mins,
                    "mttr_mins": mttr_mins,
                    "false_positive_rate": false_positive_rate,
                    "resolution_rate": resolution_rate,
                    "created_at": now,
                }

                conn.execute(
                    """INSERT OR REPLACE INTO soc_daily_snapshots
                       (id, org_id, snapshot_date, total_alerts, critical_alerts,
                        mttd_mins, mttr_mins, false_positive_rate, resolution_rate, created_at)
                       VALUES (:id, :org_id, :snapshot_date, :total_alerts, :critical_alerts,
                               :mttd_mins, :mttr_mins, :false_positive_rate,
                               :resolution_rate, :created_at)""",
                    record,
                )

        return record

    # ------------------------------------------------------------------
    # Analyst workload
    # ------------------------------------------------------------------

    def update_analyst_workload(
        self,
        org_id: str,
        analyst_name: str,
        date_str: str,
        alerts_assigned: int,
        alerts_resolved: int,
        avg_resolution_mins: float,
    ) -> Dict[str, Any]:
        """INSERT OR REPLACE analyst workload record for a given date."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "analyst_name": analyst_name,
            "date": date_str,
            "alerts_assigned": int(alerts_assigned),
            "alerts_resolved": int(alerts_resolved),
            "avg_resolution_mins": float(avg_resolution_mins),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO analyst_workload
                       (id, org_id, analyst_name, date, alerts_assigned,
                        alerts_resolved, avg_resolution_mins, created_at)
                       VALUES (:id, :org_id, :analyst_name, :date, :alerts_assigned,
                               :alerts_resolved, :avg_resolution_mins, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_soc_summary(self, org_id: str) -> Dict[str, Any]:
        """Return total open alerts, by_severity, by_status, last 7 snapshots, top analysts."""
        with self._conn() as conn:
            # Open alert count
            open_count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM soc_alerts WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()["cnt"]

            # By severity (all statuses)
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) AS cnt FROM soc_alerts
                   WHERE org_id = ? GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity: Dict[str, int] = {r["severity"]: r["cnt"] for r in sev_rows}

            # By status
            stat_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt FROM soc_alerts
                   WHERE org_id = ? GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status: Dict[str, int] = {r["status"]: r["cnt"] for r in stat_rows}

            # Last 7 daily snapshots
            snap_rows = conn.execute(
                """SELECT * FROM soc_daily_snapshots WHERE org_id = ?
                   ORDER BY snapshot_date DESC LIMIT 7""",
                (org_id,),
            ).fetchall()
            last_7_days = [self._row(r) for r in snap_rows]

            # Top analysts by total resolved count
            analyst_rows = conn.execute(
                """SELECT analyst_name, SUM(alerts_resolved) AS total_resolved
                   FROM analyst_workload WHERE org_id = ?
                   GROUP BY analyst_name
                   ORDER BY total_resolved DESC LIMIT 5""",
                (org_id,),
            ).fetchall()
            top_analysts = [self._row(r) for r in analyst_rows]

        return {
            "total_open_alerts": open_count,
            "by_severity": by_severity,
            "by_status": by_status,
            "last_7_days_snapshots": last_7_days,
            "top_analysts": top_analysts,
        }

    def get_mttd_trend(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Return snapshots ordered by date with mttd_mins + mttr_mins (last N days)."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT snapshot_date, mttd_mins, mttr_mins
                   FROM soc_daily_snapshots WHERE org_id = ?
                   ORDER BY snapshot_date ASC
                   LIMIT ?""",
                (org_id, int(days)),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_analyst_performance(
        self,
        org_id: str,
        date_str: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return analyst workload records, optionally filtered by date."""
        sql = "SELECT * FROM analyst_workload WHERE org_id = ?"
        params: List[Any] = [org_id]
        if date_str:
            sql += " AND date = ?"
            params.append(date_str)
        sql += " ORDER BY alerts_resolved DESC, analyst_name ASC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]
