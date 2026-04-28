"""Compliance Gap Engine — ALDECI.

Identifies and tracks compliance gaps — the delta between current security
posture and required framework controls.  Supports full assessment lifecycle,
gap severity tracking, and remediation plan management.

Compliance: NIST CSF, ISO/IEC 27001, SOC 2, PCI-DSS, HIPAA, GDPR, CIS
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_gap.db"
)

_VALID_FRAMEWORKS = {"SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA", "GDPR", "CIS"}
_VALID_ASSESSMENT_STATUSES = {"in_progress", "completed", "archived"}
_VALID_GAP_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_GAP_STATUSES = {"open", "in_remediation", "remediated", "accepted"}
_VALID_PLAN_STATUSES = {"planned", "active", "completed", "cancelled"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ComplianceGapEngine:
    """SQLite WAL-backed Compliance Gap engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    framework         TEXT NOT NULL,
                    assessment_name   TEXT NOT NULL,
                    status            TEXT NOT NULL DEFAULT 'in_progress',
                    total_controls    INTEGER NOT NULL DEFAULT 0,
                    compliant_controls INTEGER NOT NULL DEFAULT 0,
                    compliance_pct    REAL NOT NULL DEFAULT 0.0,
                    created_at        TEXT NOT NULL,
                    completed_at      TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS control_gaps (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    assessment_id       TEXT NOT NULL,
                    control_id          TEXT NOT NULL,
                    control_name        TEXT NOT NULL,
                    domain              TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL,
                    gap_description     TEXT NOT NULL DEFAULT '',
                    current_state       TEXT NOT NULL DEFAULT '',
                    required_state      TEXT NOT NULL DEFAULT '',
                    remediation_effort  INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'open',
                    identified_at       TEXT NOT NULL,
                    remediated_at       TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS remediation_plans (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    gap_id           TEXT NOT NULL,
                    plan_description TEXT NOT NULL,
                    owner            TEXT NOT NULL,
                    target_date      TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'planned',
                    created_at       TEXT NOT NULL
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

    def _recalculate_compliance_pct(
        self, conn: sqlite3.Connection, assessment_id: str
    ) -> float:
        """Recalculate and persist compliance_pct for an assessment."""
        row = conn.execute(
            "SELECT total_controls, compliant_controls FROM gap_assessments WHERE id = ?",
            (assessment_id,),
        ).fetchone()
        if row is None:
            return 0.0
        total = row["total_controls"]
        compliant = row["compliant_controls"]
        pct = (compliant / total * 100) if total > 0 else 0.0
        conn.execute(
            "UPDATE gap_assessments SET compliance_pct = ? WHERE id = ?",
            (round(pct, 2), assessment_id),
        )
        return pct

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a new compliance gap assessment."""
        assessment_name = data.get("assessment_name", "").strip()
        if not assessment_name:
            raise ValueError("assessment_name is required")
        framework = data.get("framework", "")
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(
                f"framework must be one of: {sorted(_VALID_FRAMEWORKS)}"
            )

        assessment_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": assessment_id,
            "org_id": org_id,
            "framework": framework,
            "assessment_name": assessment_name,
            "status": "in_progress",
            "total_controls": data.get("total_controls", 0),
            "compliant_controls": 0,
            "compliance_pct": 0.0,
            "created_at": now,
            "completed_at": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO gap_assessments
                       (id, org_id, framework, assessment_name, status,
                        total_controls, compliant_controls, compliance_pct,
                        created_at, completed_at)
                       VALUES (:id, :org_id, :framework, :assessment_name, :status,
                               :total_controls, :compliant_controls, :compliance_pct,
                               :created_at, :completed_at)""",
                    row,
                )
        return row

    def list_assessments(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List assessments with optional filters."""
        sql = "SELECT * FROM gap_assessments WHERE org_id = ?"
        params: list = [org_id]
        if framework is not None:
            sql += " AND framework = ?"
            params.append(framework)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_assessment(
        self, org_id: str, assessment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return a single assessment or None if not found / wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM gap_assessments WHERE id = ? AND org_id = ?",
                (assessment_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def complete_assessment(
        self, org_id: str, assessment_id: str
    ) -> Dict[str, Any]:
        """Mark an assessment as completed and recalculate compliance_pct."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM gap_assessments WHERE id = ? AND org_id = ?",
                    (assessment_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"Assessment {assessment_id} not found for org {org_id}"
                    )
                now = _now_iso()
                conn.execute(
                    """UPDATE gap_assessments
                       SET status = 'completed', completed_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, assessment_id, org_id),
                )
                self._recalculate_compliance_pct(conn, assessment_id)
                updated = conn.execute(
                    "SELECT * FROM gap_assessments WHERE id = ?",
                    (assessment_id,),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Control Gaps
    # ------------------------------------------------------------------

    def add_control_gap(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a control gap to an assessment."""
        assessment_id = data.get("assessment_id", "").strip()
        if not assessment_id:
            raise ValueError("assessment_id is required")

        # Verify assessment belongs to org
        assessment = self.get_assessment(org_id, assessment_id)
        if assessment is None:
            raise ValueError(
                f"Assessment {assessment_id} not found for org {org_id}"
            )

        control_id = data.get("control_id", "").strip()
        if not control_id:
            raise ValueError("control_id is required")
        control_name = data.get("control_name", "").strip()
        if not control_name:
            raise ValueError("control_name is required")

        severity = data.get("severity", "")
        if severity not in _VALID_GAP_SEVERITIES:
            raise ValueError(
                f"severity must be one of: {sorted(_VALID_GAP_SEVERITIES)}"
            )

        remediation_effort = data.get("remediation_effort", 0)
        try:
            remediation_effort = int(remediation_effort)
        except (TypeError, ValueError):
            remediation_effort = 0

        gap_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": gap_id,
            "org_id": org_id,
            "assessment_id": assessment_id,
            "control_id": control_id,
            "control_name": control_name,
            "domain": data.get("domain", ""),
            "severity": severity,
            "gap_description": data.get("gap_description", ""),
            "current_state": data.get("current_state", ""),
            "required_state": data.get("required_state", ""),
            "remediation_effort": remediation_effort,
            "status": "open",
            "identified_at": now,
            "remediated_at": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO control_gaps
                       (id, org_id, assessment_id, control_id, control_name,
                        domain, severity, gap_description, current_state,
                        required_state, remediation_effort, status,
                        identified_at, remediated_at)
                       VALUES (:id, :org_id, :assessment_id, :control_id,
                               :control_name, :domain, :severity,
                               :gap_description, :current_state,
                               :required_state, :remediation_effort, :status,
                               :identified_at, :remediated_at)""",
                    row,
                )
                # Increment total_controls on the parent assessment
                conn.execute(
                    """UPDATE gap_assessments
                       SET total_controls = total_controls + 1
                       WHERE id = ? AND org_id = ?""",
                    (assessment_id, org_id),
                )
        return row

    def update_gap_status(
        self, org_id: str, gap_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a control gap."""
        if new_status not in _VALID_GAP_STATUSES:
            raise ValueError(
                f"new_status must be one of: {sorted(_VALID_GAP_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM control_gaps WHERE id = ? AND org_id = ?",
                    (gap_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"Gap {gap_id} not found for org {org_id}"
                    )
                old_status = row["status"]
                assessment_id = row["assessment_id"]

                remediated_at = ""
                if new_status == "remediated":
                    remediated_at = _now_iso()

                conn.execute(
                    """UPDATE control_gaps
                       SET status = ?, remediated_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (new_status, remediated_at, gap_id, org_id),
                )

                # If newly remediated, increment compliant_controls
                if new_status == "remediated" and old_status != "remediated":
                    conn.execute(
                        """UPDATE gap_assessments
                           SET compliant_controls = compliant_controls + 1
                           WHERE id = ? AND org_id = ?""",
                        (assessment_id, org_id),
                    )
                    self._recalculate_compliance_pct(conn, assessment_id)
                # If un-remediating (was remediated, now something else), decrement
                elif old_status == "remediated" and new_status != "remediated":
                    conn.execute(
                        """UPDATE gap_assessments
                           SET compliant_controls = MAX(0, compliant_controls - 1)
                           WHERE id = ? AND org_id = ?""",
                        (assessment_id, org_id),
                    )
                    self._recalculate_compliance_pct(conn, assessment_id)

                updated = conn.execute(
                    "SELECT * FROM control_gaps WHERE id = ?", (gap_id,)
                ).fetchone()
        return self._row(updated)

    def list_gaps(
        self,
        org_id: str,
        assessment_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List control gaps with optional filters."""
        sql = "SELECT * FROM control_gaps WHERE org_id = ?"
        params: list = [org_id]
        if assessment_id is not None:
            sql += " AND assessment_id = ?"
            params.append(assessment_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY identified_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Remediation Plans
    # ------------------------------------------------------------------

    def create_remediation_plan(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a remediation plan for a control gap."""
        gap_id = data.get("gap_id", "").strip()
        if not gap_id:
            raise ValueError("gap_id is required")

        # Verify gap belongs to org
        with self._conn() as conn:
            gap_row = conn.execute(
                "SELECT id FROM control_gaps WHERE id = ? AND org_id = ?",
                (gap_id, org_id),
            ).fetchone()
        if gap_row is None:
            raise ValueError(f"Gap {gap_id} not found for org {org_id}")

        plan_description = data.get("plan_description", "").strip()
        if not plan_description:
            raise ValueError("plan_description is required")
        owner = data.get("owner", "").strip()
        if not owner:
            raise ValueError("owner is required")
        target_date = data.get("target_date", "").strip()
        if not target_date:
            raise ValueError("target_date is required")

        plan_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": plan_id,
            "org_id": org_id,
            "gap_id": gap_id,
            "plan_description": plan_description,
            "owner": owner,
            "target_date": target_date,
            "status": "planned",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO remediation_plans
                       (id, org_id, gap_id, plan_description, owner,
                        target_date, status, created_at)
                       VALUES (:id, :org_id, :gap_id, :plan_description, :owner,
                               :target_date, :status, :created_at)""",
                    row,
                )
        return row

    def update_plan_status(
        self, org_id: str, plan_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a remediation plan."""
        if new_status not in _VALID_PLAN_STATUSES:
            raise ValueError(
                f"new_status must be one of: {sorted(_VALID_PLAN_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM remediation_plans WHERE id = ? AND org_id = ?",
                    (plan_id, org_id),
                ).fetchone()
                if row is None:
                    raise ValueError(
                        f"Plan {plan_id} not found for org {org_id}"
                    )
                conn.execute(
                    "UPDATE remediation_plans SET status = ? WHERE id = ? AND org_id = ?",
                    (new_status, plan_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM remediation_plans WHERE id = ?", (plan_id,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_gap_stats(self, org_id: str) -> Dict[str, Any]:
        """Return gap statistics for an org."""
        with self._conn() as conn:
            assessment_totals = conn.execute(
                """SELECT
                       COUNT(*) AS total_assessments,
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_assessments
                   FROM gap_assessments WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            gap_totals = conn.execute(
                """SELECT
                       COUNT(*) AS total_gaps,
                       SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_gaps,
                       SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_gaps,
                       COALESCE(AVG(remediation_effort), 0.0) AS avg_remediation_hours
                   FROM control_gaps WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            by_framework_rows = conn.execute(
                """SELECT framework, AVG(compliance_pct) AS avg_pct
                   FROM gap_assessments WHERE org_id = ?
                   GROUP BY framework""",
                (org_id,),
            ).fetchall()

        by_framework: Dict[str, float] = {}
        for r in by_framework_rows:
            by_framework[r["framework"]] = round(r["avg_pct"], 2)

        return {
            "total_assessments": assessment_totals["total_assessments"] or 0,
            "completed_assessments": assessment_totals["completed_assessments"] or 0,
            "total_gaps": gap_totals["total_gaps"] or 0,
            "open_gaps": gap_totals["open_gaps"] or 0,
            "critical_gaps": gap_totals["critical_gaps"] or 0,
            "by_framework": by_framework,
            "avg_remediation_hours": round(
                gap_totals["avg_remediation_hours"] or 0.0, 2
            ),
        }
