"""Executive Reporting Engine — ALDECI.

Generates executive security briefings, board presentations, and KPI dashboards.

Capabilities:
  - Executive report lifecycle (draft/published/archived) with metrics
  - KPI management with trend tracking (on_track/at_risk/off_track)
  - Board presentation creation for board/audit_committee/executive/investor audiences
  - Aggregated exec summary view across all data

Compliance: NIST CSF, ISO/IEC 27001 A.18, SOC 2 CC9.2, COSO ERM
"""

from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "exec_reporting.db"
)

_VALID_REPORT_TYPES = {"weekly", "monthly", "quarterly", "board", "ciso"}
_VALID_REPORT_STATUSES = {"draft", "published", "archived"}
_VALID_KPI_STATUSES = {"on_track", "at_risk", "off_track"}
_VALID_KPI_TRENDS = {"improving", "stable", "declining"}
_VALID_METRIC_TRENDS = {"up", "down", "stable"}
_VALID_AUDIENCES = {"board", "audit_committee", "executive", "investor"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecutiveReportingEngine:
    """SQLite WAL-backed executive reporting engine.

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
                CREATE TABLE IF NOT EXISTS exec_reports (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    report_type  TEXT NOT NULL DEFAULT 'monthly',
                    title        TEXT NOT NULL DEFAULT '',
                    period_start TEXT NOT NULL DEFAULT '',
                    period_end   TEXT NOT NULL DEFAULT '',
                    status       TEXT NOT NULL DEFAULT 'draft',
                    sections     TEXT NOT NULL DEFAULT '[]',
                    created_by   TEXT NOT NULL DEFAULT '',
                    published_at TEXT,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_er_org_type
                    ON exec_reports (org_id, report_type, status);

                CREATE TABLE IF NOT EXISTS report_metrics (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    report_id         TEXT NOT NULL,
                    metric_name       TEXT NOT NULL DEFAULT '',
                    metric_value      REAL NOT NULL DEFAULT 0.0,
                    metric_unit       TEXT NOT NULL DEFAULT '',
                    trend             TEXT NOT NULL DEFAULT 'stable',
                    comparison_value  REAL NOT NULL DEFAULT 0.0,
                    comparison_period TEXT NOT NULL DEFAULT '',
                    narrative         TEXT NOT NULL DEFAULT '',
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rm_org_report
                    ON report_metrics (org_id, report_id);

                CREATE TABLE IF NOT EXISTS exec_kpis (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    kpi_name     TEXT NOT NULL,
                    kpi_value    REAL NOT NULL DEFAULT 0.0,
                    kpi_unit     TEXT NOT NULL DEFAULT '',
                    target_value REAL NOT NULL DEFAULT 0.0,
                    status       TEXT NOT NULL DEFAULT 'on_track',
                    trend        TEXT NOT NULL DEFAULT 'stable',
                    last_updated TEXT NOT NULL,
                    created_at   TEXT NOT NULL,
                    UNIQUE (org_id, kpi_name)
                );

                CREATE INDEX IF NOT EXISTS idx_kpi_org
                    ON exec_kpis (org_id, status);

                CREATE TABLE IF NOT EXISTS board_presentations (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    title         TEXT NOT NULL DEFAULT '',
                    presentation_date TEXT NOT NULL DEFAULT '',
                    audience      TEXT NOT NULL DEFAULT 'board',
                    risk_summary  TEXT NOT NULL DEFAULT '',
                    key_metrics   TEXT NOT NULL DEFAULT '{}',
                    action_items  TEXT NOT NULL DEFAULT '[]',
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bp_org
                    ON board_presentations (org_id, presentation_date DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("sections", "action_items", "recommendations"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        for field in ("key_metrics",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    pass
        return d

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def create_report(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an executive report."""
        report_type = data.get("report_type", "monthly")
        if report_type not in _VALID_REPORT_TYPES:
            raise ValueError(f"Invalid report_type: {report_type}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "report_type": report_type,
            "title": data.get("title", ""),
            "period_start": data.get("period_start", ""),
            "period_end": data.get("period_end", ""),
            "status": "draft",
            "sections": json.dumps(data.get("sections", [])),
            "created_by": data.get("created_by", ""),
            "published_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO exec_reports
                       (id, org_id, report_type, title, period_start, period_end,
                        status, sections, created_by, published_at, created_at)
                       VALUES (:id, :org_id, :report_type, :title, :period_start, :period_end,
                               :status, :sections, :created_by, :published_at, :created_at)""",
                    record,
                )
        result = dict(record)
        result["sections"] = data.get("sections", [])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "executive_reporting", "org_id": org_id, "source_engine": "executive_reporting"})
            except Exception:
                pass

        return result

    def list_reports(
        self,
        org_id: str,
        report_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List executive reports with optional filters."""
        sql = "SELECT * FROM exec_reports WHERE org_id = ?"
        params: list = [org_id]
        if report_type:
            sql += " AND report_type = ?"
            params.append(report_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_report(self, org_id: str, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a report with its metrics."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM exec_reports WHERE org_id = ? AND id = ?",
                (org_id, report_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            metrics = [
                self._row(r) for r in conn.execute(
                    "SELECT * FROM report_metrics WHERE org_id = ? AND report_id = ? ORDER BY created_at",
                    (org_id, report_id),
                ).fetchall()
            ]
            result["metrics"] = metrics
        return result

    def add_metric(self, org_id: str, report_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a metric to a report."""
        trend = data.get("trend", "stable")
        if trend not in _VALID_METRIC_TRENDS:
            raise ValueError(f"Invalid trend: {trend}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "report_id": report_id,
            "metric_name": data.get("metric_name", ""),
            "metric_value": float(data.get("metric_value", 0.0)),
            "metric_unit": data.get("metric_unit", ""),
            "trend": trend,
            "comparison_value": float(data.get("comparison_value", 0.0)),
            "comparison_period": data.get("comparison_period", ""),
            "narrative": data.get("narrative", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO report_metrics
                       (id, org_id, report_id, metric_name, metric_value, metric_unit,
                        trend, comparison_value, comparison_period, narrative, created_at)
                       VALUES (:id, :org_id, :report_id, :metric_name, :metric_value,
                               :metric_unit, :trend, :comparison_value, :comparison_period,
                               :narrative, :created_at)""",
                    record,
                )
        return record

    def publish_report(self, org_id: str, report_id: str) -> bool:
        """Publish a report (draft → published)."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE exec_reports SET status = 'published', published_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, report_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # KPIs
    # ------------------------------------------------------------------

    def set_kpi(
        self,
        org_id: str,
        kpi_name: str,
        value: float,
        target: float,
        unit: str,
        trend: str,
    ) -> Dict[str, Any]:
        """Upsert a KPI. Computes status from value vs target."""
        if trend not in _VALID_KPI_TRENDS:
            raise ValueError(f"Invalid trend: {trend}")

        # Determine status
        if target > 0:
            ratio = value / target
            if ratio >= 0.9:
                status = "on_track"
            elif ratio >= 0.7:
                status = "at_risk"
            else:
                status = "off_track"
        else:
            status = "on_track"

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id, created_at FROM exec_kpis WHERE org_id = ? AND kpi_name = ?",
                    (org_id, kpi_name),
                ).fetchone()

                if existing:
                    kpi_id = existing["id"]
                    created_at = existing["created_at"]
                    conn.execute(
                        """UPDATE exec_kpis
                           SET kpi_value = ?, kpi_unit = ?, target_value = ?,
                               status = ?, trend = ?, last_updated = ?
                           WHERE org_id = ? AND kpi_name = ?""",
                        (value, unit, target, status, trend, now, org_id, kpi_name),
                    )
                else:
                    kpi_id = str(uuid.uuid4())
                    created_at = now
                    conn.execute(
                        """INSERT INTO exec_kpis
                           (id, org_id, kpi_name, kpi_value, kpi_unit, target_value,
                            status, trend, last_updated, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (kpi_id, org_id, kpi_name, value, unit, target,
                         status, trend, now, created_at),
                    )

        return {
            "id": kpi_id,
            "org_id": org_id,
            "kpi_name": kpi_name,
            "kpi_value": value,
            "kpi_unit": unit,
            "target_value": target,
            "status": status,
            "trend": trend,
            "last_updated": now,
            "created_at": created_at,
        }

    def list_kpis(self, org_id: str) -> List[Dict[str, Any]]:
        """List all KPIs for org."""
        with self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM exec_kpis WHERE org_id = ? ORDER BY kpi_name",
                (org_id,),
            ).fetchall()]

    def get_kpi(self, org_id: str, kpi_name: str) -> Optional[Dict[str, Any]]:
        """Get a single KPI by name."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM exec_kpis WHERE org_id = ? AND kpi_name = ?",
                (org_id, kpi_name),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Board presentations
    # ------------------------------------------------------------------

    def create_board_presentation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a board presentation."""
        audience = data.get("audience", "board")
        if audience not in _VALID_AUDIENCES:
            raise ValueError(f"Invalid audience: {audience}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": data.get("title", ""),
            "presentation_date": data.get("presentation_date", now),
            "audience": audience,
            "risk_summary": data.get("risk_summary", ""),
            "key_metrics": json.dumps(data.get("key_metrics", {})),
            "action_items": json.dumps(data.get("action_items", [])),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO board_presentations
                       (id, org_id, title, presentation_date, audience, risk_summary,
                        key_metrics, action_items, created_at)
                       VALUES (:id, :org_id, :title, :presentation_date, :audience,
                               :risk_summary, :key_metrics, :action_items, :created_at)""",
                    record,
                )
        result = dict(record)
        result["key_metrics"] = data.get("key_metrics", {})
        result["action_items"] = data.get("action_items", [])
        return result

    def list_board_presentations(self, org_id: str) -> List[Dict[str, Any]]:
        """List all board presentations for org."""
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(
                "SELECT * FROM board_presentations WHERE org_id = ? ORDER BY presentation_date DESC",
                (org_id,),
            ).fetchall()]

    # ------------------------------------------------------------------
    # TrustGraph context
    # ------------------------------------------------------------------

    def get_trustgraph_context(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context to enrich executive reports.

        Returns related assets, findings, and incidents for a given entity.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=entity_id, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=entity_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    # ------------------------------------------------------------------
    # Exec summary
    # ------------------------------------------------------------------

    def get_exec_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregated executive summary view."""
        with self._conn() as conn:
            # Recent reports (last 5)
            recent_reports = [
                self._row(r) for r in conn.execute(
                    """SELECT id, report_type, title, status, period_start, period_end, created_at
                       FROM exec_reports WHERE org_id = ?
                       ORDER BY created_at DESC LIMIT 5""",
                    (org_id,),
                ).fetchall()
            ]

            # KPI summary counts
            on_track = conn.execute(
                "SELECT COUNT(*) FROM exec_kpis WHERE org_id = ? AND status = 'on_track'",
                (org_id,),
            ).fetchone()[0]
            at_risk = conn.execute(
                "SELECT COUNT(*) FROM exec_kpis WHERE org_id = ? AND status = 'at_risk'",
                (org_id,),
            ).fetchone()[0]
            off_track = conn.execute(
                "SELECT COUNT(*) FROM exec_kpis WHERE org_id = ? AND status = 'off_track'",
                (org_id,),
            ).fetchone()[0]

            # Board presentations count
            board_count = conn.execute(
                "SELECT COUNT(*) FROM board_presentations WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

        return {
            "recent_reports": recent_reports,
            "kpi_summary": {
                "on_track": on_track,
                "at_risk": at_risk,
                "off_track": off_track,
            },
            "top_risks": [],  # Populated by caller from risk engine
            "recent_incidents_count": 0,  # Populated by caller from incident engine
            "posture_trend": "stable",
            "board_presentations_count": board_count,
        }
