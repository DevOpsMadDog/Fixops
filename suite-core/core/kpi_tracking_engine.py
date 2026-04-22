"""KPI Tracking Engine — ALDECI.

Track organizational KPIs with measurement history and performance analysis.

Capabilities:
  - KPI registry: create, list, get with category/status filtering and org isolation
  - Measurement recording with achievement % and on_target/near_target/off_target status
  - KPI performance: last measurement, avg achievement, trend (improving/declining/stable)
  - Stats: totals, by category, on/off target counts, avg achievement

Compliance: ISO 27001 A.5.36 (performance evaluation), SOC2 CC1.2
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_CATEGORIES = {"security", "compliance", "operational", "financial", "risk"}
_VALID_DIRECTIONS = {"higher_better", "lower_better"}
_VALID_FREQUENCIES = {"daily", "weekly", "monthly", "quarterly"}
_VALID_STATUSES = {"active", "inactive", "archived"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _compute_achievement(
    value: float, target_value: float, direction: str
) -> float:
    """Compute achievement percentage clamped to 0-200."""
    if target_value == 0:
        return 0.0
    if direction == "higher_better":
        pct = (value / target_value) * 100.0
    else:
        if value <= 0:
            return 0.0
        pct = (target_value / value) * 100.0
    return max(0.0, min(200.0, pct))


def _achievement_status(achievement_pct: float) -> str:
    if achievement_pct >= 100.0:
        return "on_target"
    if achievement_pct >= 80.0:
        return "near_target"
    return "off_target"


class KPITrackingEngine:
    """SQLite WAL-backed KPI Tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/kpi_tracking.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "kpi_tracking.db")
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
                CREATE TABLE IF NOT EXISTS kpis (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    kpi_category TEXT NOT NULL DEFAULT 'operational',
                    direction    TEXT NOT NULL DEFAULT 'higher_better',
                    target_value REAL NOT NULL,
                    unit         TEXT NOT NULL DEFAULT '',
                    frequency    TEXT NOT NULL DEFAULT 'monthly',
                    description  TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'active',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_kpis_org
                    ON kpis (org_id, kpi_category, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS measurements (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    kpi_id          TEXT NOT NULL,
                    value           REAL NOT NULL,
                    achievement_pct REAL NOT NULL,
                    status          TEXT NOT NULL,
                    notes           TEXT NOT NULL DEFAULT '',
                    measured_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_measurements_kpi
                    ON measurements (org_id, kpi_id, measured_at DESC);
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
    # KPIs
    # ------------------------------------------------------------------

    def create_kpi(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new KPI."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        kpi_category = data.get("kpi_category", "operational")
        if kpi_category not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid kpi_category: {kpi_category}. "
                f"Must be one of {_VALID_CATEGORIES}"
            )

        direction = data.get("direction", "higher_better")
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"Invalid direction: {direction}. "
                f"Must be one of {_VALID_DIRECTIONS}"
            )

        target_value = data.get("target_value")
        if target_value is None:
            raise ValueError("target_value is required.")
        try:
            target_value = float(target_value)
        except (TypeError, ValueError):
            raise ValueError("target_value must be a number.")

        frequency = data.get("frequency", "monthly")
        if frequency not in _VALID_FREQUENCIES:
            raise ValueError(
                f"Invalid frequency: {frequency}. "
                f"Must be one of {_VALID_FREQUENCIES}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "kpi_category": kpi_category,
            "direction": direction,
            "target_value": target_value,
            "unit": data.get("unit", ""),
            "frequency": frequency,
            "description": data.get("description", ""),
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO kpis
                       (id, org_id, name, kpi_category, direction, target_value,
                        unit, frequency, description, status, created_at)
                       VALUES (:id, :org_id, :name, :kpi_category, :direction, :target_value,
                               :unit, :frequency, :description, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "kpi_tracking", "org_id": org_id, "source_engine": "kpi_tracking"})
            except Exception:
                pass

        return record

    def list_kpis(
        self,
        org_id: str,
        kpi_category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List KPIs with optional category and status filters."""
        sql = "SELECT * FROM kpis WHERE org_id = ?"
        params: list = [org_id]
        if kpi_category:
            sql += " AND kpi_category = ?"
            params.append(kpi_category)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_kpi(self, org_id: str, kpi_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single KPI by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM kpis WHERE org_id = ? AND id = ?",
                (org_id, kpi_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Measurements
    # ------------------------------------------------------------------

    def record_measurement(
        self,
        org_id: str,
        kpi_id: str,
        value: float,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Record a measurement for a KPI. Returns None if KPI not found."""
        kpi = self.get_kpi(org_id, kpi_id)
        if not kpi:
            return None

        try:
            value = float(value)
        except (TypeError, ValueError):
            raise ValueError("value must be a number.")

        achievement_pct = _compute_achievement(
            value, kpi["target_value"], kpi["direction"]
        )
        mstatus = _achievement_status(achievement_pct)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "kpi_id": kpi_id,
            "value": value,
            "achievement_pct": round(achievement_pct, 4),
            "status": mstatus,
            "notes": notes or "",
            "measured_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO measurements
                       (id, org_id, kpi_id, value, achievement_pct, status, notes, measured_at)
                       VALUES (:id, :org_id, :kpi_id, :value, :achievement_pct,
                               :status, :notes, :measured_at)""",
                    record,
                )
        return record

    def list_measurements(
        self,
        org_id: str,
        kpi_id: str,
        limit: int = 30,
    ) -> List[Dict[str, Any]]:
        """List measurements for a KPI ordered by measured_at DESC."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM measurements WHERE org_id = ? AND kpi_id = ? "
                "ORDER BY measured_at DESC LIMIT ?",
                (org_id, kpi_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_kpi_performance(self, org_id: str, kpi_id: str) -> Optional[Dict[str, Any]]:
        """Return performance summary for a KPI.

        Includes last measurement, avg achievement_pct, and trend
        (improving/declining/stable based on last 2 measurements).
        Returns None if KPI not found.
        """
        kpi = self.get_kpi(org_id, kpi_id)
        if not kpi:
            return None

        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM measurements WHERE org_id = ? AND kpi_id = ? "
                "ORDER BY measured_at DESC LIMIT 2",
                (org_id, kpi_id),
            ).fetchall()

            avg_row = conn.execute(
                "SELECT AVG(achievement_pct) as avg_pct FROM measurements "
                "WHERE org_id = ? AND kpi_id = ?",
                (org_id, kpi_id),
            ).fetchone()

        last_measurement = self._row(rows[0]) if rows else None

        avg_achievement_pct = (
            round(avg_row["avg_pct"], 4)
            if avg_row and avg_row["avg_pct"] is not None
            else None
        )

        # Trend based on last 2 measurements
        if len(rows) >= 2:
            latest_pct = rows[0]["achievement_pct"]
            prev_pct = rows[1]["achievement_pct"]
            diff = latest_pct - prev_pct
            if diff > 1.0:
                trend = "improving"
            elif diff < -1.0:
                trend = "declining"
            else:
                trend = "stable"
        elif len(rows) == 1:
            trend = "stable"
        else:
            trend = None

        return {
            "kpi": kpi,
            "last_measurement": last_measurement,
            "avg_achievement_pct": avg_achievement_pct,
            "trend": trend,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Available metrics registry (GAP-060)
    # ------------------------------------------------------------------

    def list_available_metrics(
        self,
        org_id: str,
        aggregator: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Return all metric keys aggregatable across KPI + metrics aggregator.

        Precedence: kpi_tracking wins when the same key exists in both. Output:
          {"metric_keys": [...],
           "keys_by_source": {"kpi_tracking": [...], "security_metrics_aggregator": [...]},
           "available_count": N}

        Pass ``aggregator`` to reuse a pre-instantiated
        :class:`SecurityMetricsAggregatorEngine` (e.g. for tests or shared
        engine singletons). When omitted a default instance is constructed.
        """
        with self._conn() as conn:
            kpi_rows = conn.execute(
                "SELECT DISTINCT name FROM kpis WHERE org_id = ? ORDER BY name",
                (org_id,),
            ).fetchall()
        kpi_keys = [r["name"] for r in kpi_rows]

        aggregator_keys: List[str] = []
        try:
            if aggregator is None:
                from core.security_metrics_aggregator_engine import (
                    SecurityMetricsAggregatorEngine,
                )
                aggregator = SecurityMetricsAggregatorEngine()
            aggregator_keys = aggregator.list_metric_keys(org_id)
        except Exception as exc:  # pragma: no cover — defensive
            _logger.warning("aggregator metric key lookup failed: %s", exc)

        merged: List[str] = []
        seen = set()
        # KPI takes precedence — append first
        for k in kpi_keys:
            if k and k not in seen:
                seen.add(k)
                merged.append(k)
        for k in aggregator_keys:
            if k and k not in seen:
                seen.add(k)
                merged.append(k)

        return {
            "metric_keys": merged,
            "keys_by_source": {
                "kpi_tracking": kpi_keys,
                "security_metrics_aggregator": aggregator_keys,
            },
            "available_count": len(merged),
        }

    def get_kpi_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated KPI statistics for an org."""
        with self._conn() as conn:
            total_kpis = conn.execute(
                "SELECT COUNT(*) FROM kpis WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            active_kpis = conn.execute(
                "SELECT COUNT(*) FROM kpis WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            cat_rows = conn.execute(
                "SELECT kpi_category, COUNT(*) as cnt FROM kpis "
                "WHERE org_id = ? GROUP BY kpi_category",
                (org_id,),
            ).fetchall()
            by_category = {r["kpi_category"]: r["cnt"] for r in cat_rows}

            # Latest measurement per KPI
            kpi_ids_rows = conn.execute(
                "SELECT id FROM kpis WHERE org_id = ?", (org_id,)
            ).fetchall()

            on_target = 0
            off_target = 0
            achievement_sum = 0.0
            achievement_count = 0

            for kpi_row in kpi_ids_rows:
                kpi_id = kpi_row["id"]
                m_row = conn.execute(
                    "SELECT achievement_pct, status FROM measurements "
                    "WHERE org_id = ? AND kpi_id = ? "
                    "ORDER BY measured_at DESC LIMIT 1",
                    (org_id, kpi_id),
                ).fetchone()
                if m_row:
                    pct = m_row["achievement_pct"]
                    achievement_sum += pct
                    achievement_count += 1
                    if pct >= 100.0:
                        on_target += 1
                    elif pct < 80.0:
                        off_target += 1

        avg_achievement_pct = (
            round(achievement_sum / achievement_count, 4)
            if achievement_count > 0
            else None
        )

        return {
            "total_kpis": total_kpis,
            "active_kpis": active_kpis,
            "by_category": by_category,
            "on_target_kpis": on_target,
            "off_target_kpis": off_target,
            "avg_achievement_pct": avg_achievement_pct,
        }
