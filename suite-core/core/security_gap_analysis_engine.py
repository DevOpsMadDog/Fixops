"""Security Gap Analysis Engine — ALDECI.

Framework-based gap analysis, control coverage tracking, and remediation planning.

Capabilities:
  - Assessment lifecycle per compliance framework
  - Control gap tracking with priority/effort classification
  - Coverage percentage auto-recompute on status changes
  - Risk level thresholds: <40%=critical, <60%=high, <80%=medium, else low
  - Remediation plan management with completion tracking
  - Overdue gap detection
  - Per-framework coverage reporting
  - Org-scoped isolation — org_a data never visible from org_b

Compliance: SOC2, ISO27001, PCI-DSS, HIPAA, NIST-CSF, NIST-800-53, CIS,
            FedRAMP, GDPR, SOX
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_gap_analysis.db"
)

_VALID_FRAMEWORKS = {
    "SOC2", "ISO27001", "PCI-DSS", "HIPAA", "NIST-CSF",
    "NIST-800-53", "CIS", "FedRAMP", "GDPR", "SOX",
}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_EFFORTS = {"low", "medium", "high", "very-high"}
_VALID_STATUSES = {"open", "in_progress", "implemented", "accepted"}
_VALID_RISK_IMPACTS = {"critical", "high", "medium", "low"}
_VALID_PLAN_STATUSES = {"planned", "in_progress", "completed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _risk_level_from_pct(pct: float) -> str:
    if pct < 40.0:
        return "critical"
    if pct < 60.0:
        return "high"
    if pct < 80.0:
        return "medium"
    return "low"


class SecurityGapAnalysisEngine:
    """SQLite WAL-backed Security Gap Analysis engine.

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
                CREATE TABLE IF NOT EXISTS gap_assessments (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    framework            TEXT NOT NULL,
                    assessment_name      TEXT NOT NULL,
                    total_controls       INTEGER NOT NULL DEFAULT 0,
                    implemented_controls INTEGER NOT NULL DEFAULT 0,
                    partial_controls     INTEGER NOT NULL DEFAULT 0,
                    not_implemented      INTEGER NOT NULL DEFAULT 0,
                    coverage_pct         REAL NOT NULL DEFAULT 0.0,
                    risk_level           TEXT NOT NULL DEFAULT 'critical',
                    assessed_at          TEXT NOT NULL,
                    next_review          TEXT NOT NULL DEFAULT '',
                    assessor             TEXT NOT NULL DEFAULT '',
                    created_at           TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS control_gaps (
                    id              TEXT PRIMARY KEY,
                    assessment_id   TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    control_id      TEXT NOT NULL,
                    control_name    TEXT NOT NULL,
                    domain          TEXT NOT NULL DEFAULT '',
                    requirement     TEXT NOT NULL DEFAULT '',
                    current_state   TEXT NOT NULL DEFAULT '',
                    gap_description TEXT NOT NULL DEFAULT '',
                    risk_impact     TEXT NOT NULL DEFAULT 'medium',
                    effort          TEXT NOT NULL DEFAULT 'medium',
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    owner           TEXT NOT NULL DEFAULT '',
                    due_date        TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS gap_remediation_plans (
                    id                 TEXT PRIMARY KEY,
                    gap_id             TEXT NOT NULL,
                    org_id             TEXT NOT NULL,
                    action             TEXT NOT NULL,
                    resource_required  TEXT NOT NULL DEFAULT '',
                    estimated_days     INTEGER NOT NULL DEFAULT 0,
                    actual_days        INTEGER NOT NULL DEFAULT 0,
                    status             TEXT NOT NULL DEFAULT 'planned',
                    completed_at       TEXT NOT NULL DEFAULT '',
                    created_at         TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _recompute_assessment(self, conn: sqlite3.Connection, assessment_id: str) -> None:
        """Recompute coverage_pct, not_implemented, and risk_level for an assessment."""
        assess = conn.execute(
            "SELECT total_controls FROM gap_assessments WHERE id = ?",
            (assessment_id,),
        ).fetchone()
        if assess is None:
            return

        total = assess["total_controls"]

        not_impl = conn.execute(
            """SELECT COUNT(*) as c FROM control_gaps
               WHERE assessment_id = ? AND status = 'open'""",
            (assessment_id,),
        ).fetchone()["c"]

        partial = conn.execute(
            """SELECT COUNT(*) as c FROM control_gaps
               WHERE assessment_id = ? AND status = 'in_progress'""",
            (assessment_id,),
        ).fetchone()["c"]

        implemented = conn.execute(
            """SELECT COUNT(*) as c FROM control_gaps
               WHERE assessment_id = ? AND status IN ('implemented', 'accepted')""",
            (assessment_id,),
        ).fetchone()["c"]

        if total > 0:
            coverage_pct = (total - not_impl - partial) / total * 100.0
        else:
            coverage_pct = 0.0

        coverage_pct = max(0.0, min(100.0, coverage_pct))
        risk_level = _risk_level_from_pct(coverage_pct)

        conn.execute(
            """UPDATE gap_assessments
               SET not_implemented = ?,
                   partial_controls = ?,
                   implemented_controls = ?,
                   coverage_pct = ?,
                   risk_level = ?
               WHERE id = ?""",
            (not_impl, partial, implemented, round(coverage_pct, 2), risk_level, assessment_id),
        )

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        framework: str,
        assessment_name: str,
        total_controls: int,
        assessor: str,
        next_review: str,
    ) -> Dict[str, Any]:
        """Create a new gap assessment."""
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"framework must be one of: {sorted(_VALID_FRAMEWORKS)}"
            )
        if not assessment_name.strip():
            raise ValueError("assessment_name is required")

        now = _now_iso()
        assessment_id = str(uuid.uuid4())
        row = {
            "id": assessment_id,
            "org_id": org_id,
            "framework": framework,
            "assessment_name": assessment_name,
            "total_controls": total_controls,
            "implemented_controls": 0,
            "partial_controls": 0,
            "not_implemented": 0,
            "coverage_pct": 0.0,
            "risk_level": "critical",
            "assessed_at": now,
            "next_review": next_review,
            "assessor": assessor,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO gap_assessments
                       (id, org_id, framework, assessment_name, total_controls,
                        implemented_controls, partial_controls, not_implemented,
                        coverage_pct, risk_level, assessed_at, next_review,
                        assessor, created_at)
                       VALUES (:id, :org_id, :framework, :assessment_name, :total_controls,
                               :implemented_controls, :partial_controls, :not_implemented,
                               :coverage_pct, :risk_level, :assessed_at, :next_review,
                               :assessor, :created_at)""",
                    row,
                )
        return row

    def get_assessment(self, assessment_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return a single assessment or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM gap_assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_assessments(
        self,
        org_id: str,
        framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments for an org."""
        sql = "SELECT * FROM gap_assessments WHERE org_id = ?"
        params: list = [org_id]
        if framework is not None:
            sql += " AND framework = ?"
            params.append(framework)
        sql += " ORDER BY assessed_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Control Gaps
    # ------------------------------------------------------------------

    def add_control_gap(
        self,
        assessment_id: str,
        org_id: str,
        control_id: str,
        control_name: str,
        domain: str,
        requirement: str,
        current_state: str,
        gap_description: str,
        risk_impact: str,
        effort: str,
        priority: str,
        owner: str,
        due_date: str,
    ) -> Dict[str, Any]:
        """Add a control gap and recompute assessment coverage."""
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"priority must be one of: {sorted(_VALID_PRIORITIES)}")
        if effort not in _VALID_EFFORTS:
            raise ValueError(f"effort must be one of: {sorted(_VALID_EFFORTS)}")
        if risk_impact not in _VALID_RISK_IMPACTS:
            raise ValueError(f"risk_impact must be one of: {sorted(_VALID_RISK_IMPACTS)}")

        gap_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": gap_id,
            "assessment_id": assessment_id,
            "org_id": org_id,
            "control_id": control_id,
            "control_name": control_name,
            "domain": domain,
            "requirement": requirement,
            "current_state": current_state,
            "gap_description": gap_description,
            "risk_impact": risk_impact,
            "effort": effort,
            "priority": priority,
            "status": "open",
            "owner": owner,
            "due_date": due_date,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO control_gaps
                       (id, assessment_id, org_id, control_id, control_name, domain,
                        requirement, current_state, gap_description, risk_impact,
                        effort, priority, status, owner, due_date, created_at)
                       VALUES (:id, :assessment_id, :org_id, :control_id, :control_name,
                               :domain, :requirement, :current_state, :gap_description,
                               :risk_impact, :effort, :priority, :status, :owner,
                               :due_date, :created_at)""",
                    row,
                )
                self._recompute_assessment(conn, assessment_id)
        return row

    def update_control_status(
        self, gap_id: str, org_id: str, status: str
    ) -> Dict[str, Any]:
        """Update a control gap status and recompute parent assessment."""
        if status not in _VALID_STATUSES:
            raise ValueError(f"status must be one of: {sorted(_VALID_STATUSES)}")
        with self._lock:
            with self._conn() as conn:
                gap = conn.execute(
                    "SELECT * FROM control_gaps WHERE id = ? AND org_id = ?",
                    (gap_id, org_id),
                ).fetchone()
                if gap is None:
                    raise ValueError(f"Gap {gap_id} not found for org {org_id}")
                conn.execute(
                    "UPDATE control_gaps SET status = ? WHERE id = ? AND org_id = ?",
                    (status, gap_id, org_id),
                )
                self._recompute_assessment(conn, gap["assessment_id"])
                updated = conn.execute(
                    "SELECT * FROM control_gaps WHERE id = ?",
                    (gap_id,),
                ).fetchone()
        return self._row(updated)

    def list_gaps(
        self,
        org_id: str,
        assessment_id: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List control gaps with optional filters."""
        sql = "SELECT * FROM control_gaps WHERE org_id = ?"
        params: list = [org_id]
        if assessment_id is not None:
            sql += " AND assessment_id = ?"
            params.append(assessment_id)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        if priority is not None:
            sql += " AND priority = ?"
            params.append(priority)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Remediation Plans
    # ------------------------------------------------------------------

    def add_remediation_plan(
        self,
        gap_id: str,
        org_id: str,
        action: str,
        resource_required: str,
        estimated_days: int,
    ) -> Dict[str, Any]:
        """Add a remediation plan for a gap."""
        plan_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": plan_id,
            "gap_id": gap_id,
            "org_id": org_id,
            "action": action,
            "resource_required": resource_required,
            "estimated_days": estimated_days,
            "actual_days": 0,
            "status": "planned",
            "completed_at": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO gap_remediation_plans
                       (id, gap_id, org_id, action, resource_required,
                        estimated_days, actual_days, status, completed_at, created_at)
                       VALUES (:id, :gap_id, :org_id, :action, :resource_required,
                               :estimated_days, :actual_days, :status, :completed_at, :created_at)""",
                    row,
                )
        return row

    def complete_remediation(
        self, plan_id: str, org_id: str, actual_days: int
    ) -> Dict[str, Any]:
        """Mark a remediation plan as completed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                plan = conn.execute(
                    "SELECT * FROM gap_remediation_plans WHERE id = ? AND org_id = ?",
                    (plan_id, org_id),
                ).fetchone()
                if plan is None:
                    raise ValueError(f"Plan {plan_id} not found for org {org_id}")
                conn.execute(
                    """UPDATE gap_remediation_plans
                       SET status = 'completed', completed_at = ?, actual_days = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, actual_days, plan_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM gap_remediation_plans WHERE id = ?",
                    (plan_id,),
                ).fetchone()
        return self._row(updated)

    def list_remediation_plans(
        self, org_id: str, gap_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List remediation plans."""
        sql = "SELECT * FROM gap_remediation_plans WHERE org_id = ?"
        params: list = [org_id]
        if gap_id is not None:
            sql += " AND gap_id = ?"
            params.append(gap_id)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Summary & Analytics
    # ------------------------------------------------------------------

    def get_gap_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated gap summary for an org."""
        with self._conn() as conn:
            assess_count = conn.execute(
                "SELECT COUNT(*) as c FROM gap_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchone()["c"]

            total_gaps = conn.execute(
                "SELECT COUNT(*) as c FROM control_gaps WHERE org_id = ?",
                (org_id,),
            ).fetchone()["c"]

            open_gaps = conn.execute(
                "SELECT COUNT(*) as c FROM control_gaps WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()["c"]

            by_framework_rows = conn.execute(
                """SELECT a.framework, COUNT(g.id) as cnt
                   FROM gap_assessments a
                   LEFT JOIN control_gaps g ON g.assessment_id = a.id AND g.org_id = a.org_id
                   WHERE a.org_id = ?
                   GROUP BY a.framework""",
                (org_id,),
            ).fetchall()

            by_priority_rows = conn.execute(
                """SELECT priority, COUNT(*) as cnt
                   FROM control_gaps WHERE org_id = ?
                   GROUP BY priority""",
                (org_id,),
            ).fetchall()

            critical_gaps = conn.execute(
                """SELECT COUNT(*) as c FROM control_gaps
                   WHERE org_id = ? AND priority = 'critical' AND status = 'open'""",
                (org_id,),
            ).fetchone()["c"]

        return {
            "assessments": assess_count,
            "total_gaps": total_gaps,
            "open_gaps": open_gaps,
            "by_framework": {r["framework"]: r["cnt"] for r in by_framework_rows},
            "by_priority": {r["priority"]: r["cnt"] for r in by_priority_rows},
            "critical_gaps": critical_gaps,
        }

    def get_assessment_detail(
        self, assessment_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return assessment + all gaps + remediation plans."""
        assessment = self.get_assessment(assessment_id, org_id)
        if assessment is None:
            return None

        gaps = self.list_gaps(org_id, assessment_id=assessment_id)

        with self._conn() as conn:
            gap_ids = [g["id"] for g in gaps]
            plans: list = []
            if gap_ids:
                placeholders = ",".join("?" * len(gap_ids))
                plans = conn.execute(
                    f"SELECT * FROM gap_remediation_plans WHERE gap_id IN ({placeholders}) AND org_id = ?",  # nosec B608
                    gap_ids + [org_id],
                ).fetchall()

        return {
            "assessment": assessment,
            "gaps": gaps,
            "remediation_plans": [self._row(p) for p in plans],
        }

    def get_overdue_gaps(self, org_id: str) -> List[Dict[str, Any]]:
        """Return open/in_progress gaps where due_date < now."""
        now = _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM control_gaps
                   WHERE org_id = ?
                     AND status IN ('open', 'in_progress')
                     AND due_date != ''
                     AND due_date < ?
                   ORDER BY due_date ASC""",
                (org_id, now),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_framework_coverage(self, org_id: str) -> List[Dict[str, Any]]:
        """Return per-framework latest assessment coverage_pct, risk_level, gap_count."""
        with self._conn() as conn:
            frameworks = conn.execute(
                "SELECT DISTINCT framework FROM gap_assessments WHERE org_id = ?",
                (org_id,),
            ).fetchall()

            result = []
            for fw_row in frameworks:
                fw = fw_row["framework"]
                # Latest assessment for this framework
                latest = conn.execute(
                    """SELECT * FROM gap_assessments
                       WHERE org_id = ? AND framework = ?
                       ORDER BY assessed_at DESC LIMIT 1""",
                    (org_id, fw),
                ).fetchone()
                if latest is None:
                    continue
                gap_count = conn.execute(
                    """SELECT COUNT(*) as c FROM control_gaps
                       WHERE org_id = ? AND assessment_id = ?""",
                    (org_id, latest["id"]),
                ).fetchone()["c"]
                result.append({
                    "framework": fw,
                    "coverage_pct": latest["coverage_pct"],
                    "risk_level": latest["risk_level"],
                    "gap_count": gap_count,
                    "assessment_id": latest["id"],
                    "assessed_at": latest["assessed_at"],
                })
        return result
