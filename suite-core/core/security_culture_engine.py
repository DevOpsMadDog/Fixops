"""Security Culture Engine — ALDECI.

Measures and improves organizational security culture through metrics,
initiatives, and assessments.

Capabilities:
  - Record culture metrics (phishing resilience, training, policy compliance)
  - Track initiatives (campaigns, gamification, champions programs)
  - Culture maturity assessments with 5-level scoring
  - Department-level breakdown and trend analysis
  - Culture summary with active initiatives and benchmark comparison

Compliance: NIST CSF PR.AT, ISO 27001 A.6.3
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_METRIC_CATEGORIES = {
    "phishing-resilience",
    "training",
    "policy-compliance",
    "reporting",
    "champions",
    "awareness",
    "incident-response",
}

_VALID_INITIATIVE_TYPES = {
    "training",
    "campaign",
    "gamification",
    "champions-program",
    "simulation",
    "workshop",
    "communication",
}

_VALID_STATUSES = {"planned", "in-progress", "completed", "overdue", "cancelled"}

_MATURITY_LEVELS = [
    (80, "optimized"),
    (60, "managed"),
    (40, "defined"),
    (20, "developing"),
    (0, "initial"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _maturity_level(score: float) -> str:
    for threshold, level in _MATURITY_LEVELS:
        if score >= threshold:
            return level
    return "initial"


class SecurityCultureEngine:
    """SQLite WAL-backed Security Culture engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_culture.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_culture.db")
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
                CREATE TABLE IF NOT EXISTS culture_metrics (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    metric_name      TEXT NOT NULL,
                    metric_category  TEXT NOT NULL,
                    value            REAL NOT NULL DEFAULT 0,
                    target_value     REAL NOT NULL DEFAULT 0,
                    department       TEXT NOT NULL DEFAULT '',
                    measurement_date TEXT NOT NULL,
                    source           TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cm_org_metric
                    ON culture_metrics (org_id, metric_name, measurement_date DESC);

                CREATE INDEX IF NOT EXISTS idx_cm_org_dept
                    ON culture_metrics (org_id, department);

                CREATE TABLE IF NOT EXISTS culture_initiatives (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    initiative_name TEXT NOT NULL,
                    initiative_type TEXT NOT NULL,
                    target_audience TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'planned',
                    start_date      TEXT NOT NULL DEFAULT '',
                    end_date        TEXT NOT NULL DEFAULT '',
                    participants    INTEGER NOT NULL DEFAULT 0,
                    completion_rate REAL NOT NULL DEFAULT 0,
                    impact_score    REAL NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org
                    ON culture_initiatives (org_id, status);

                CREATE TABLE IF NOT EXISTS culture_assessments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    assessment_date  TEXT NOT NULL,
                    overall_score    REAL NOT NULL DEFAULT 0,
                    maturity_level   TEXT NOT NULL DEFAULT 'initial',
                    strengths        TEXT NOT NULL DEFAULT '[]',
                    weaknesses       TEXT NOT NULL DEFAULT '[]',
                    recommendations  TEXT NOT NULL DEFAULT '[]',
                    assessed_by      TEXT NOT NULL DEFAULT '',
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org
                    ON culture_assessments (org_id, assessment_date DESC);
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
    # Metrics
    # ------------------------------------------------------------------

    def record_metric(
        self,
        org_id: str,
        metric_name: str,
        metric_category: str,
        value: float,
        target_value: float,
        department: str = "",
        source: str = "",
    ) -> Dict[str, Any]:
        """Record a security culture metric data point."""
        if metric_category not in _VALID_METRIC_CATEGORIES:
            raise ValueError(
                f"Invalid metric_category: {metric_category!r}. "
                f"Must be one of {sorted(_VALID_METRIC_CATEGORIES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "metric_name": metric_name,
            "metric_category": metric_category,
            "value": float(value),
            "target_value": float(target_value),
            "department": department,
            "measurement_date": now,
            "source": source,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO culture_metrics
                       (id, org_id, metric_name, metric_category, value, target_value,
                        department, measurement_date, source, created_at)
                       VALUES (:id, :org_id, :metric_name, :metric_category, :value, :target_value,
                               :department, :measurement_date, :source, :created_at)""",
                    record,
                )
        return record

    def get_metric_trend(
        self,
        org_id: str,
        metric_name: str,
        department: Optional[str] = None,
        days: int = 90,
    ) -> Dict[str, Any]:
        """Return metric history and trend direction.

        Trend: compare avg of first half vs second half.
        If diff > 5% of first-half avg → improving/declining.
        Otherwise → stable.
        """
        query = (
            "SELECT * FROM culture_metrics "
            "WHERE org_id=? AND metric_name=?"
        )
        params: List[Any] = [org_id, metric_name]
        if department is not None:
            query += " AND department=?"
            params.append(department)
        query += " ORDER BY measurement_date ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        metrics = [self._row(r) for r in rows]

        trend = "stable"
        if len(metrics) >= 2:
            mid = len(metrics) // 2
            first_half = metrics[:mid]
            second_half = metrics[mid:]
            first_avg = sum(m["value"] for m in first_half) / len(first_half)
            second_avg = sum(m["value"] for m in second_half) / len(second_half)
            if first_avg != 0:
                change_pct = (second_avg - first_avg) / abs(first_avg)
                if change_pct > 0.05:
                    trend = "improving"
                elif change_pct < -0.05:
                    trend = "declining"

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_culture_engine", "org_id": org_id, "source_engine": "security_culture_engine"})
            except Exception:
                pass
        return {
            "metric_name": metric_name,
            "department": department,
            "days": days,
            "trend": trend,
            "data_points": metrics,
        }

    # ------------------------------------------------------------------
    # Initiatives
    # ------------------------------------------------------------------

    def create_initiative(
        self,
        org_id: str,
        initiative_name: str,
        initiative_type: str,
        target_audience: str,
        start_date: str,
        end_date: str,
    ) -> Dict[str, Any]:
        """Create a new culture initiative."""
        if initiative_type not in _VALID_INITIATIVE_TYPES:
            raise ValueError(
                f"Invalid initiative_type: {initiative_type!r}. "
                f"Must be one of {sorted(_VALID_INITIATIVE_TYPES)}"
            )
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "initiative_name": initiative_name,
            "initiative_type": initiative_type,
            "target_audience": target_audience,
            "status": "planned",
            "start_date": start_date,
            "end_date": end_date,
            "participants": 0,
            "completion_rate": 0.0,
            "impact_score": 0.0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO culture_initiatives
                       (id, org_id, initiative_name, initiative_type, target_audience,
                        status, start_date, end_date, participants, completion_rate,
                        impact_score, created_at)
                       VALUES (:id, :org_id, :initiative_name, :initiative_type, :target_audience,
                               :status, :start_date, :end_date, :participants, :completion_rate,
                               :impact_score, :created_at)""",
                    record,
                )
        return record

    def update_initiative_progress(
        self,
        initiative_id: str,
        org_id: str,
        participants: int,
        completion_rate: float,
        impact_score: float,
    ) -> Dict[str, Any]:
        """Update progress on an initiative. Auto-transitions status."""
        # Clamp impact_score
        impact_score = max(0.0, min(10.0, float(impact_score)))
        participants = max(0, int(participants))
        completion_rate = float(completion_rate)

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM culture_initiatives WHERE id=? AND org_id=?",
                    (initiative_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Initiative {initiative_id!r} not found.")

                initiative = self._row(row)

                # Determine status
                if completion_rate >= 100:
                    status = "completed"
                elif completion_rate > 0:
                    # Check if overdue
                    end_date = initiative.get("end_date", "")
                    today = _today()
                    if end_date and today > end_date:
                        status = "overdue"
                    else:
                        status = "in-progress"
                else:
                    # completion_rate == 0 — check if past end_date
                    end_date = initiative.get("end_date", "")
                    today = _today()
                    current_status = initiative.get("status", "planned")
                    if end_date and today > end_date and current_status != "completed":
                        status = "overdue"
                    else:
                        status = current_status  # keep existing

                conn.execute(
                    """UPDATE culture_initiatives
                       SET participants=?, completion_rate=?, impact_score=?, status=?
                       WHERE id=? AND org_id=?""",
                    (participants, completion_rate, impact_score, status, initiative_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM culture_initiatives WHERE id=? AND org_id=?",
                    (initiative_id, org_id),
                ).fetchone()
        return self._row(updated)

    def list_initiatives(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List initiatives with optional status filter."""
        query = "SELECT * FROM culture_initiatives WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        overall_score: float,
        strengths: List[str],
        weaknesses: List[str],
        recommendations: List[str],
        assessed_by: str,
    ) -> Dict[str, Any]:
        """Create a culture maturity assessment."""
        overall_score = max(0.0, min(100.0, float(overall_score)))
        maturity = _maturity_level(overall_score)
        now = _now()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "assessment_date": now,
            "overall_score": overall_score,
            "maturity_level": maturity,
            "strengths": json.dumps(strengths if isinstance(strengths, list) else [strengths]),
            "weaknesses": json.dumps(weaknesses if isinstance(weaknesses, list) else [weaknesses]),
            "recommendations": json.dumps(
                recommendations if isinstance(recommendations, list) else [recommendations]
            ),
            "assessed_by": assessed_by,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO culture_assessments
                       (id, org_id, assessment_date, overall_score, maturity_level,
                        strengths, weaknesses, recommendations, assessed_by, created_at)
                       VALUES (:id, :org_id, :assessment_date, :overall_score, :maturity_level,
                               :strengths, :weaknesses, :recommendations, :assessed_by, :created_at)""",
                    record,
                )
        result = dict(record)
        result["strengths"] = strengths if isinstance(strengths, list) else [strengths]
        result["weaknesses"] = weaknesses if isinstance(weaknesses, list) else [weaknesses]
        result["recommendations"] = (
            recommendations if isinstance(recommendations, list) else [recommendations]
        )
        return result

    def get_latest_assessment(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Return the most recent assessment for the org."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM culture_assessments
                   WHERE org_id=?
                   ORDER BY assessment_date DESC LIMIT 1""",
                (org_id,),
            ).fetchone()
        if not row:
            return None
        result = self._row(row)
        for field in ("strengths", "weaknesses", "recommendations"):
            try:
                result[field] = json.loads(result[field])
            except Exception:
                result[field] = []
        return result

    # ------------------------------------------------------------------
    # Department analytics
    # ------------------------------------------------------------------

    def get_department_culture_scores(self, org_id: str) -> Dict[str, Any]:
        """Return per-department avg metric values and best/worst departments."""
        with self._conn() as conn:
            dept_rows = conn.execute(
                """SELECT department, AVG(value) as avg_score, COUNT(*) as metric_count
                   FROM culture_metrics
                   WHERE org_id=? AND department != ''
                   GROUP BY department
                   ORDER BY avg_score DESC""",
                (org_id,),
            ).fetchall()

        departments = {
            r["department"]: {
                "avg_score": r["avg_score"],
                "metric_count": r["metric_count"],
            }
            for r in dept_rows
        }

        best_department = None
        worst_department = None
        if dept_rows:
            best_department = dept_rows[0]["department"]
            worst_department = dept_rows[-1]["department"]

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "security_culture_engine", "org_id": org_id, "source_engine": "security_culture_engine"})
            except Exception:
                pass
        return {
            "departments": departments,
            "best_department": best_department,
            "worst_department": worst_department,
        }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_culture_summary(self, org_id: str) -> Dict[str, Any]:
        """Return overall culture health summary."""
        latest = self.get_latest_assessment(org_id)

        with self._conn() as conn:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM culture_initiatives WHERE org_id=? AND status='in-progress'",
                (org_id,),
            ).fetchone()[0]

            above_target = conn.execute(
                "SELECT COUNT(*) FROM culture_metrics WHERE org_id=? AND value >= target_value",
                (org_id,),
            ).fetchone()[0]

            below_target = conn.execute(
                "SELECT COUNT(*) FROM culture_metrics WHERE org_id=? AND value < target_value",
                (org_id,),
            ).fetchone()[0]

            # Trend: compare last 2 assessments
            assessment_rows = conn.execute(
                """SELECT overall_score FROM culture_assessments
                   WHERE org_id=?
                   ORDER BY assessment_date DESC LIMIT 2""",
                (org_id,),
            ).fetchall()

        culture_trend = "stable"
        if len(assessment_rows) >= 2:
            latest_score = assessment_rows[0]["overall_score"]
            prev_score = assessment_rows[1]["overall_score"]
            if prev_score > 0:
                change = (latest_score - prev_score) / abs(prev_score)
                if change > 0.05:
                    culture_trend = "improving"
                elif change < -0.05:
                    culture_trend = "declining"

        return {
            "latest_score": latest["overall_score"] if latest else None,
            "maturity_level": latest["maturity_level"] if latest else None,
            "active_initiatives": active_count,
            "metrics_above_target": above_target,
            "metrics_below_target": below_target,
            "culture_trend": culture_trend,
        }
