"""Security Metrics Dashboard Engine — ALDECI.

Dashboard registry with widget management and metric snapshot tracking.

Capabilities:
  - Dashboard CRUD with type filtering and org isolation
  - Widget management per dashboard (chart/table/gauge/counter/heatmap/timeline)
  - Metric snapshot ingestion and time-series history
  - Stats: total dashboards, by type, total widgets, snapshots in last 24h

Compliance: SOC2 CC7.2, NIST SP 800-137 (continuous monitoring)
"""

from __future__ import annotations

import json
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_DASHBOARD_TYPES = {"executive", "operational", "tactical", "compliance", "threat"}
_VALID_WIDGET_TYPES = {"chart", "table", "gauge", "counter", "heatmap", "timeline"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityMetricsDashboardEngine:
    """SQLite WAL-backed Security Metrics Dashboard engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_metrics_dashboard.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_metrics_dashboard.db")
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
                CREATE TABLE IF NOT EXISTS dashboards (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL,
                    dashboard_type   TEXT NOT NULL DEFAULT 'operational',
                    refresh_interval INTEGER NOT NULL DEFAULT 60,
                    widgets          TEXT NOT NULL DEFAULT '[]',
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dashboards_org
                    ON dashboards (org_id, dashboard_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS widgets (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    dashboard_id TEXT NOT NULL,
                    widget_type  TEXT NOT NULL,
                    metric_name  TEXT NOT NULL,
                    data_source  TEXT NOT NULL,
                    config       TEXT NOT NULL DEFAULT '{}',
                    position_x   INTEGER NOT NULL DEFAULT 0,
                    position_y   INTEGER NOT NULL DEFAULT 0,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_widgets_dashboard
                    ON widgets (org_id, dashboard_id, created_at ASC);

                CREATE TABLE IF NOT EXISTS metric_snapshots (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    dashboard_id TEXT NOT NULL,
                    metric_name  TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_unit  TEXT NOT NULL DEFAULT '',
                    tags         TEXT NOT NULL DEFAULT '{}',
                    snapshot_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_snapshots_dashboard_metric
                    ON metric_snapshots (org_id, dashboard_id, metric_name, snapshot_at DESC);
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
    # Dashboards
    # ------------------------------------------------------------------

    def create_dashboard(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new dashboard."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        dashboard_type = data.get("dashboard_type", "operational")
        if dashboard_type not in _VALID_DASHBOARD_TYPES:
            raise ValueError(
                f"Invalid dashboard_type: {dashboard_type}. "
                f"Must be one of {_VALID_DASHBOARD_TYPES}"
            )

        refresh_interval = data.get("refresh_interval", 60)
        try:
            refresh_interval = int(refresh_interval)
        except (TypeError, ValueError):
            raise ValueError("refresh_interval must be an integer.")

        widgets = data.get("widgets", [])
        if not isinstance(widgets, list):
            widgets = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "dashboard_type": dashboard_type,
            "refresh_interval": refresh_interval,
            "widgets": json.dumps(widgets),
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dashboards
                       (id, org_id, name, dashboard_type, refresh_interval,
                        widgets, status, created_at)
                       VALUES (:id, :org_id, :name, :dashboard_type, :refresh_interval,
                               :widgets, :status, :created_at)""",
                    record,
                )
        result = dict(record)
        result["widgets"] = widgets
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_metrics_dashboard", "org_id": org_id, "source_engine": "security_metrics_dashboard"})
            except Exception:
                pass

        return result

    def list_dashboards(
        self,
        org_id: str,
        dashboard_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List dashboards with optional type filter."""
        sql = "SELECT * FROM dashboards WHERE org_id = ?"
        params: list = [org_id]
        if dashboard_type:
            sql += " AND dashboard_type = ?"
            params.append(dashboard_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            d = self._row(row)
            try:
                d["widgets"] = json.loads(d["widgets"])
            except Exception:
                d["widgets"] = []
            result.append(d)
        return result

    def get_dashboard(self, org_id: str, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single dashboard by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dashboards WHERE org_id = ? AND id = ?",
                (org_id, dashboard_id),
            ).fetchone()
        if not row:
            return None
        d = self._row(row)
        try:
            d["widgets"] = json.loads(d["widgets"])
        except Exception:
            d["widgets"] = []
        return d

    # ------------------------------------------------------------------
    # Widgets
    # ------------------------------------------------------------------

    def add_widget(
        self, org_id: str, dashboard_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Add a widget to a dashboard. Returns None if dashboard not found."""
        dashboard = self.get_dashboard(org_id, dashboard_id)
        if not dashboard:
            return None

        widget_type = (data.get("widget_type") or "").strip()
        if not widget_type:
            raise ValueError("widget_type is required.")
        if widget_type not in _VALID_WIDGET_TYPES:
            raise ValueError(
                f"Invalid widget_type: {widget_type}. "
                f"Must be one of {_VALID_WIDGET_TYPES}"
            )

        metric_name = (data.get("metric_name") or "").strip()
        if not metric_name:
            raise ValueError("metric_name is required.")

        data_source = (data.get("data_source") or "").strip()
        if not data_source:
            raise ValueError("data_source is required.")

        config = data.get("config", {})
        if not isinstance(config, dict):
            config = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "dashboard_id": dashboard_id,
            "widget_type": widget_type,
            "metric_name": metric_name,
            "data_source": data_source,
            "config": json.dumps(config),
            "position_x": int(data.get("position_x", 0)),
            "position_y": int(data.get("position_y", 0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO widgets
                       (id, org_id, dashboard_id, widget_type, metric_name,
                        data_source, config, position_x, position_y, created_at)
                       VALUES (:id, :org_id, :dashboard_id, :widget_type, :metric_name,
                               :data_source, :config, :position_x, :position_y, :created_at)""",
                    record,
                )
        result = dict(record)
        result["config"] = config
        return result

    def list_widgets(self, org_id: str, dashboard_id: str) -> List[Dict[str, Any]]:
        """List all widgets for a dashboard ordered by position."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM widgets WHERE org_id = ? AND dashboard_id = ? "
                "ORDER BY position_y ASC, position_x ASC",
                (org_id, dashboard_id),
            ).fetchall()
        result = []
        for row in rows:
            w = self._row(row)
            try:
                w["config"] = json.loads(w["config"])
            except Exception:
                w["config"] = {}
            result.append(w)
        return result

    # ------------------------------------------------------------------
    # Metric Snapshots
    # ------------------------------------------------------------------

    def record_metric_snapshot(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a metric snapshot."""
        dashboard_id = (data.get("dashboard_id") or "").strip()
        if not dashboard_id:
            raise ValueError("dashboard_id is required.")

        metric_name = (data.get("metric_name") or "").strip()
        if not metric_name:
            raise ValueError("metric_name is required.")

        metric_value = data.get("metric_value")
        if metric_value is None:
            raise ValueError("metric_value is required.")
        try:
            metric_value = float(metric_value)
        except (TypeError, ValueError):
            raise ValueError("metric_value must be a number.")

        tags = data.get("tags", {})
        if not isinstance(tags, dict):
            tags = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "dashboard_id": dashboard_id,
            "metric_name": metric_name,
            "metric_value": metric_value,
            "metric_unit": data.get("metric_unit", ""),
            "tags": json.dumps(tags),
            "snapshot_at": data.get("snapshot_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO metric_snapshots
                       (id, org_id, dashboard_id, metric_name, metric_value,
                        metric_unit, tags, snapshot_at)
                       VALUES (:id, :org_id, :dashboard_id, :metric_name, :metric_value,
                               :metric_unit, :tags, :snapshot_at)""",
                    record,
                )
        result = dict(record)
        result["tags"] = tags
        return result

    def get_metric_history(
        self,
        org_id: str,
        dashboard_id: str,
        metric_name: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return metric snapshot history ordered by snapshot_at DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM metric_snapshots
                   WHERE org_id = ? AND dashboard_id = ? AND metric_name = ?
                   ORDER BY snapshot_at DESC LIMIT ?""",
                (org_id, dashboard_id, metric_name, limit),
            ).fetchall()
        result = []
        for row in rows:
            s = self._row(row)
            try:
                s["tags"] = json.loads(s["tags"])
            except Exception:
                s["tags"] = {}
            result.append(s)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_dashboard_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated dashboard statistics for an org."""
        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._conn() as conn:
            total_dashboards = conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            active_dashboards = conn.execute(
                "SELECT COUNT(*) FROM dashboards WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT dashboard_type, COUNT(*) as cnt FROM dashboards "
                "WHERE org_id = ? GROUP BY dashboard_type",
                (org_id,),
            ).fetchall()
            by_type = {r["dashboard_type"]: r["cnt"] for r in type_rows}

            total_widgets = conn.execute(
                "SELECT COUNT(*) FROM widgets WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            total_snapshots_24h = conn.execute(
                "SELECT COUNT(*) FROM metric_snapshots "
                "WHERE org_id = ? AND snapshot_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

        return {
            "total_dashboards": total_dashboards,
            "active_dashboards": active_dashboards,
            "by_type": by_type,
            "total_widgets": total_widgets,
            "total_snapshots_24h": total_snapshots_24h,
        }
