"""
SecurityPostureReportingEngine — ALDECI.

Automated security posture reports for executives, boards, and auditors.
Supports draft→published lifecycle, section scoring, metric trend detection,
and cross-report trend summaries.

SQLite WAL + threading.RLock + org_id multi-tenant.

Compliance: SOC2 CC9.2, NIST SP 800-53 PM-6 (information security measures).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_posture_reporting.db"
)

VALID_REPORT_TYPES = frozenset({
    "executive", "board", "audit", "compliance", "operational", "monthly", "quarterly", "annual"
})
VALID_AUDIENCES = frozenset({
    "ciso", "board", "executives", "auditors", "regulators", "team"
})
VALID_SECTION_TYPES = frozenset({
    "summary", "risk", "compliance", "incidents", "vulnerabilities", "recommendations", "kpis"
})
VALID_STATUSES = frozenset({"draft", "published", "archived"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _grade_from_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _section_status(score: float) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "amber"
    return "red"


def _metric_trend(metric_value: float, previous_value: float) -> str:
    if previous_value == 0:
        return "stable"
    if metric_value > previous_value * 1.05:
        return "improving"
    if metric_value < previous_value * 0.95:
        return "declining"
    return "stable"


class SecurityPostureReportingEngine:
    """
    SQLite-backed security posture reporting engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to
                 .fixops_data/security_posture_reporting.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS posture_reports (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    report_name     TEXT NOT NULL,
                    report_type     TEXT NOT NULL,
                    audience        TEXT NOT NULL,
                    period_start    TEXT NOT NULL,
                    period_end      TEXT NOT NULL,
                    overall_score   REAL DEFAULT 0.0,
                    grade           TEXT DEFAULT 'F',
                    status          TEXT DEFAULT 'draft',
                    generated_by    TEXT NOT NULL DEFAULT '',
                    published_at    TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS report_sections (
                    id              TEXT PRIMARY KEY,
                    report_id       TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    section_name    TEXT NOT NULL,
                    section_type    TEXT NOT NULL,
                    content         TEXT NOT NULL DEFAULT '',
                    score           REAL DEFAULT 0.0,
                    status          TEXT DEFAULT 'green',
                    sort_order      INTEGER DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS report_metrics (
                    id              TEXT PRIMARY KEY,
                    report_id       TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    metric_name     TEXT NOT NULL,
                    metric_value    REAL NOT NULL,
                    metric_unit     TEXT NOT NULL DEFAULT '',
                    previous_value  REAL DEFAULT 0.0,
                    trend           TEXT DEFAULT 'stable',
                    benchmark_value REAL DEFAULT 0.0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reports_org
                    ON posture_reports(org_id, report_type, status);
                CREATE INDEX IF NOT EXISTS idx_sections_report
                    ON report_sections(report_id, org_id);
                CREATE INDEX IF NOT EXISTS idx_metrics_report
                    ON report_metrics(report_id, org_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _recompute_report_score(self, conn: sqlite3.Connection, report_id: str, org_id: str) -> None:
        """Recompute overall_score and grade from all sections."""
        row = conn.execute(
            "SELECT AVG(score) FROM report_sections WHERE report_id = ? AND org_id = ?",
            (report_id, org_id),
        ).fetchone()
        avg_score: float = row[0] if row[0] is not None else 0.0
        grade = _grade_from_score(avg_score)
        conn.execute(
            "UPDATE posture_reports SET overall_score = ?, grade = ? WHERE id = ? AND org_id = ?",
            (avg_score, grade, report_id, org_id),
        )

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def create_report(
        self,
        org_id: str,
        report_name: str,
        report_type: str,
        audience: str,
        period_start: str,
        period_end: str,
        generated_by: str = "",
    ) -> Dict[str, Any]:
        """Create a new posture report in draft status."""
        report_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO posture_reports
                        (id, org_id, report_name, report_type, audience,
                         period_start, period_end, overall_score, grade,
                         status, generated_by, published_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0.0, 'F', 'draft', ?, NULL, ?)
                    """,
                    (report_id, org_id, report_name, report_type, audience,
                     period_start, period_end, generated_by, now),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_posture_reporting_engine", "org_id": org_id, "source_engine": "security_posture_reporting_engine"})
            except Exception:
                pass
        return {
            "id": report_id,
            "org_id": org_id,
            "report_name": report_name,
            "report_type": report_type,
            "audience": audience,
            "period_start": period_start,
            "period_end": period_end,
            "overall_score": 0.0,
            "grade": "F",
            "status": "draft",
            "generated_by": generated_by,
            "published_at": None,
            "created_at": now,
        }

    def add_section(
        self,
        report_id: str,
        org_id: str,
        section_name: str,
        section_type: str,
        content: str = "",
        score: float = 0.0,
        sort_order: int = 0,
    ) -> Dict[str, Any]:
        """Add a section to a report, auto-computing status and recomputing overall score."""
        section_id = str(uuid.uuid4())
        now = _now_iso()
        status = _section_status(score)
        with self._lock:
            with self._get_conn() as conn:
                # Verify report belongs to org
                report_row = conn.execute(
                    "SELECT id FROM posture_reports WHERE id = ? AND org_id = ?",
                    (report_id, org_id),
                ).fetchone()
                if not report_row:
                    raise ValueError(f"Report {report_id} not found for org {org_id}")

                conn.execute(
                    """
                    INSERT INTO report_sections
                        (id, report_id, org_id, section_name, section_type,
                         content, score, status, sort_order, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (section_id, report_id, org_id, section_name, section_type,
                     content, score, status, sort_order, now),
                )
                self._recompute_report_score(conn, report_id, org_id)
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_posture_reporting_engine", "org_id": org_id, "source_engine": "security_posture_reporting_engine"})
            except Exception:
                pass
        return {
            "id": section_id,
            "report_id": report_id,
            "org_id": org_id,
            "section_name": section_name,
            "section_type": section_type,
            "content": content,
            "score": score,
            "status": status,
            "sort_order": sort_order,
            "created_at": now,
        }

    def add_metric(
        self,
        report_id: str,
        org_id: str,
        metric_name: str,
        metric_value: float,
        metric_unit: str = "",
        previous_value: float = 0.0,
        benchmark_value: float = 0.0,
    ) -> Dict[str, Any]:
        """Add a metric to a report with auto-computed trend."""
        metric_id = str(uuid.uuid4())
        now = _now_iso()
        trend = _metric_trend(metric_value, previous_value)
        with self._lock:
            with self._get_conn() as conn:
                report_row = conn.execute(
                    "SELECT id FROM posture_reports WHERE id = ? AND org_id = ?",
                    (report_id, org_id),
                ).fetchone()
                if not report_row:
                    raise ValueError(f"Report {report_id} not found for org {org_id}")

                conn.execute(
                    """
                    INSERT INTO report_metrics
                        (id, report_id, org_id, metric_name, metric_value,
                         metric_unit, previous_value, trend, benchmark_value, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (metric_id, report_id, org_id, metric_name, metric_value,
                     metric_unit, previous_value, trend, benchmark_value, now),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_posture_reporting_engine", "org_id": org_id, "source_engine": "security_posture_reporting_engine"})
            except Exception:
                pass
        return {
            "id": metric_id,
            "report_id": report_id,
            "org_id": org_id,
            "metric_name": metric_name,
            "metric_value": metric_value,
            "metric_unit": metric_unit,
            "previous_value": previous_value,
            "trend": trend,
            "benchmark_value": benchmark_value,
            "created_at": now,
        }

    def publish_report(self, report_id: str, org_id: str) -> Dict[str, Any]:
        """Publish a report: set status=published and published_at=now."""
        now = _now_iso()
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM posture_reports WHERE id = ? AND org_id = ?",
                    (report_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Report {report_id} not found for org {org_id}")
                conn.execute(
                    "UPDATE posture_reports SET status = 'published', published_at = ? WHERE id = ? AND org_id = ?",
                    (now, report_id, org_id),
                )
        return {"report_id": report_id, "status": "published", "published_at": now}

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_report_detail(self, report_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return report + sections (ordered by sort_order) + metrics."""
        with self._lock:
            with self._get_conn() as conn:
                report_row = conn.execute(
                    "SELECT * FROM posture_reports WHERE id = ? AND org_id = ?",
                    (report_id, org_id),
                ).fetchone()
                if not report_row:
                    return None
                report = dict(report_row)

                sections = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM report_sections WHERE report_id = ? AND org_id = ? ORDER BY sort_order ASC",
                        (report_id, org_id),
                    ).fetchall()
                ]
                metrics = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM report_metrics WHERE report_id = ? AND org_id = ?",
                        (report_id, org_id),
                    ).fetchall()
                ]
                report["sections"] = sections
                report["metrics"] = metrics
                return report

    def list_reports(
        self,
        org_id: str,
        report_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List reports filtered by optional report_type and/or status, newest first."""
        with self._lock:
            with self._get_conn() as conn:
                query = "SELECT * FROM posture_reports WHERE org_id = ?"
                params: list = [org_id]
                if report_type:
                    query += " AND report_type = ?"
                    params.append(report_type)
                if status:
                    query += " AND status = ?"
                    params.append(status)
                query += " ORDER BY created_at DESC"
                return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_latest_report(self, org_id: str, report_type: str) -> Optional[Dict[str, Any]]:
        """Return the most recent report of given type for org."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM posture_reports
                    WHERE org_id = ? AND report_type = ?
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (org_id, report_type),
                ).fetchone()
                return dict(row) if row else None

    def get_trend_summary(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Per metric_name: latest value, previous_value, trend, benchmark_value —
        across all published reports for this org.
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT
                        m.metric_name,
                        m.metric_value,
                        m.previous_value,
                        m.trend,
                        m.benchmark_value,
                        m.metric_unit,
                        r.created_at AS report_created_at
                    FROM report_metrics m
                    JOIN posture_reports r ON m.report_id = r.id
                    WHERE m.org_id = ? AND r.status = 'published'
                    ORDER BY m.metric_name, r.created_at DESC
                    """,
                    (org_id,),
                ).fetchall()

                # Keep only the latest row per metric_name
                seen: set = set()
                result: List[Dict[str, Any]] = []
                for row in rows:
                    name = row["metric_name"]
                    if name not in seen:
                        seen.add(name)
                        result.append(dict(row))
                return result
