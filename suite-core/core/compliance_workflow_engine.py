"""Compliance Workflow Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages compliance workflows from assessment to remediation:
  - Workflow lifecycle: draft → active → in-progress → pending-approval → completed
  - Task management with evidence tracking and completion rate auto-computation
  - Approval workflow: approve → completed, reject → needs-rework
  - Overdue detection, framework readiness, and workflow summary

Compliance: SOC2, ISO27001, NIST, PCI-DSS, HIPAA, GDPR, CIS, FedRAMP
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "compliance_workflow_engine.db"
)

_VALID_FRAMEWORKS = {"SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA", "GDPR", "CIS", "FedRAMP"}
_VALID_WORKFLOW_TYPES = {
    "assessment", "remediation", "audit-prep", "certification", "review", "gap-analysis"
}
_VALID_STATUSES = {
    "draft", "active", "in-progress", "pending-approval", "needs-rework", "completed", "cancelled"
}
_VALID_TASK_TYPES = {
    "documentation", "evidence-collection", "control-testing", "remediation", "review", "approval"
}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ComplianceWorkflowEngine:
    """SQLite WAL-backed Compliance Workflow engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/compliance_workflow_engine.db
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
                CREATE TABLE IF NOT EXISTS compliance_workflows (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    workflow_name   TEXT NOT NULL DEFAULT '',
                    framework       TEXT NOT NULL DEFAULT 'SOC2',
                    workflow_type   TEXT NOT NULL DEFAULT 'assessment',
                    status          TEXT NOT NULL DEFAULT 'draft',
                    owner           TEXT NOT NULL DEFAULT '',
                    due_date        TEXT NOT NULL DEFAULT '',
                    completion_rate REAL NOT NULL DEFAULT 0.0,
                    created_at      TEXT NOT NULL,
                    completed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cw_workflows_org
                    ON compliance_workflows (org_id, framework, status);

                CREATE TABLE IF NOT EXISTS workflow_tasks (
                    id                TEXT PRIMARY KEY,
                    workflow_id       TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    task_name         TEXT NOT NULL DEFAULT '',
                    task_type         TEXT NOT NULL DEFAULT 'documentation',
                    assignee          TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'pending',
                    priority          TEXT NOT NULL DEFAULT 'medium',
                    evidence_required INTEGER NOT NULL DEFAULT 0,
                    evidence_provided INTEGER NOT NULL DEFAULT 0,
                    due_date          TEXT NOT NULL DEFAULT '',
                    completed_at      TEXT,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cw_tasks_workflow
                    ON workflow_tasks (workflow_id, org_id, status);

                CREATE TABLE IF NOT EXISTS workflow_approvals (
                    id          TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    approver    TEXT NOT NULL DEFAULT '',
                    decision    TEXT NOT NULL DEFAULT 'pending',
                    comments    TEXT NOT NULL DEFAULT '',
                    decided_at  TEXT,
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cw_approvals_workflow
                    ON workflow_approvals (workflow_id, org_id);
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
    # Workflows
    # ------------------------------------------------------------------

    def create_workflow(
        self,
        org_id: str,
        workflow_name: str,
        framework: str,
        workflow_type: str,
        owner: str,
        due_date: str,
    ) -> Dict[str, Any]:
        """Create a new compliance workflow."""
        if framework not in _VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework '{framework}'. Must be one of {sorted(_VALID_FRAMEWORKS)}")
        if workflow_type not in _VALID_WORKFLOW_TYPES:
            raise ValueError(f"Invalid workflow_type '{workflow_type}'. Must be one of {sorted(_VALID_WORKFLOW_TYPES)}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "workflow_name": workflow_name,
            "framework": framework,
            "workflow_type": workflow_type,
            "status": "draft",
            "owner": owner,
            "due_date": due_date,
            "completion_rate": 0.0,
            "created_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO compliance_workflows
                       (id, org_id, workflow_name, framework, workflow_type, status,
                        owner, due_date, completion_rate, created_at, completed_at)
                       VALUES (:id, :org_id, :workflow_name, :framework, :workflow_type,
                               :status, :owner, :due_date, :completion_rate, :created_at, :completed_at)""",
                    record,
                )
        return record

    def add_task(
        self,
        workflow_id: str,
        org_id: str,
        task_name: str,
        task_type: str,
        assignee: str,
        priority: str,
        evidence_required: int,
        due_date: str,
    ) -> Dict[str, Any]:
        """Add a task to a workflow."""
        if task_type not in _VALID_TASK_TYPES:
            raise ValueError(f"Invalid task_type '{task_type}'. Must be one of {sorted(_VALID_TASK_TYPES)}")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'. Must be one of {sorted(_VALID_PRIORITIES)}")

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "workflow_id": workflow_id,
            "org_id": org_id,
            "task_name": task_name,
            "task_type": task_type,
            "assignee": assignee,
            "status": "pending",
            "priority": priority,
            "evidence_required": evidence_required,
            "evidence_provided": 0,
            "due_date": due_date,
            "completed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO workflow_tasks
                       (id, workflow_id, org_id, task_name, task_type, assignee, status,
                        priority, evidence_required, evidence_provided, due_date, completed_at, created_at)
                       VALUES (:id, :workflow_id, :org_id, :task_name, :task_type, :assignee,
                               :status, :priority, :evidence_required, :evidence_provided,
                               :due_date, :completed_at, :created_at)""",
                    record,
                )
        return record

    def complete_task(
        self,
        workflow_id: str,
        task_id: str,
        org_id: str,
        evidence_provided: int,
    ) -> Optional[Dict[str, Any]]:
        """Mark a task completed; recompute workflow completion_rate; auto-transition workflow."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                # Mark task completed
                conn.execute(
                    """UPDATE workflow_tasks
                       SET status = 'completed', evidence_provided = ?, completed_at = ?
                       WHERE id = ? AND workflow_id = ? AND org_id = ?""",
                    (evidence_provided, now, task_id, workflow_id, org_id),
                )

                # Recompute completion_rate
                counts = conn.execute(
                    """SELECT
                           COUNT(*) AS total,
                           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed
                       FROM workflow_tasks
                       WHERE workflow_id = ? AND org_id = ?""",
                    (workflow_id, org_id),
                ).fetchone()

                total = counts["total"] or 0
                completed = counts["completed"] or 0
                rate = (completed / total * 100.0) if total > 0 else 0.0

                # Check pending approvals
                pending_approvals = conn.execute(
                    """SELECT COUNT(*) FROM workflow_approvals
                       WHERE workflow_id = ? AND org_id = ? AND decision = 'pending'""",
                    (workflow_id, org_id),
                ).fetchone()[0]

                new_status = None
                if rate == 100.0 and pending_approvals == 0:
                    new_status = "pending-approval"

                if new_status:
                    conn.execute(
                        "UPDATE compliance_workflows SET completion_rate = ?, status = ? WHERE id = ? AND org_id = ?",
                        (rate, new_status, workflow_id, org_id),
                    )
                else:
                    conn.execute(
                        "UPDATE compliance_workflows SET completion_rate = ? WHERE id = ? AND org_id = ?",
                        (rate, workflow_id, org_id),
                    )

                row = conn.execute(
                    "SELECT * FROM workflow_tasks WHERE id = ? AND org_id = ?",
                    (task_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def submit_approval(
        self,
        workflow_id: str,
        org_id: str,
        approver: str,
        decision: str,
        comments: str,
    ) -> Dict[str, Any]:
        """Submit an approval decision; update workflow status accordingly."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "workflow_id": workflow_id,
            "org_id": org_id,
            "approver": approver,
            "decision": decision,
            "comments": comments,
            "decided_at": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO workflow_approvals
                       (id, workflow_id, org_id, approver, decision, comments, decided_at, created_at)
                       VALUES (:id, :workflow_id, :org_id, :approver, :decision, :comments, :decided_at, :created_at)""",
                    record,
                )
                if decision == "approved":
                    conn.execute(
                        "UPDATE compliance_workflows SET status = 'completed', completed_at = ? WHERE id = ? AND org_id = ?",
                        (now, workflow_id, org_id),
                    )
                elif decision == "rejected":
                    conn.execute(
                        "UPDATE compliance_workflows SET status = 'needs-rework' WHERE id = ? AND org_id = ?",
                        (workflow_id, org_id),
                    )
        return record

    def get_workflow(self, workflow_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Get a workflow with its tasks and approvals."""
        with self._conn() as conn:
            wf_row = conn.execute(
                "SELECT * FROM compliance_workflows WHERE id = ? AND org_id = ?",
                (workflow_id, org_id),
            ).fetchone()
            if not wf_row:
                return None
            wf = self._row(wf_row)

            task_rows = conn.execute(
                "SELECT * FROM workflow_tasks WHERE workflow_id = ? AND org_id = ? ORDER BY created_at",
                (workflow_id, org_id),
            ).fetchall()
            wf["tasks"] = [self._row(r) for r in task_rows]

            approval_rows = conn.execute(
                "SELECT * FROM workflow_approvals WHERE workflow_id = ? AND org_id = ? ORDER BY created_at",
                (workflow_id, org_id),
            ).fetchall()
            wf["approvals"] = [self._row(r) for r in approval_rows]

        return wf

    def list_workflows(
        self,
        org_id: str,
        framework: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List workflows with optional framework and status filters."""
        sql = "SELECT * FROM compliance_workflows WHERE org_id = ?"
        params: List[Any] = [org_id]
        if framework:
            sql += " AND framework = ?"
            params.append(framework)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_overdue_tasks(self, org_id: str) -> List[Dict[str, Any]]:
        """Return tasks past their due_date that are not completed."""
        now = _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM workflow_tasks
                   WHERE org_id = ? AND status != 'completed' AND due_date < ?
                   ORDER BY due_date ASC""",
                (org_id, now),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_framework_readiness(self, org_id: str, framework: str) -> Dict[str, Any]:
        """Return avg completion_rate and workflow counts for a framework."""
        with self._conn() as conn:
            row = conn.execute(
                """SELECT
                       COUNT(*) AS total_workflows,
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed_workflows,
                       AVG(completion_rate) AS avg_completion_rate
                   FROM compliance_workflows
                   WHERE org_id = ? AND framework = ?""",
                (org_id, framework),
            ).fetchone()

        total = row["total_workflows"] or 0
        completed = row["completed_workflows"] or 0
        avg_rate = round(row["avg_completion_rate"], 2) if row["avg_completion_rate"] is not None else 0.0

        return {
            "framework": framework,
            "total_workflows": total,
            "completed_workflows": completed,
            "avg_completion_rate": avg_rate,
        }

    def get_workflow_summary(self, org_id: str) -> Dict[str, Any]:
        """Return workflow counts by status and framework."""
        with self._conn() as conn:
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM compliance_workflows WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

            framework_rows = conn.execute(
                "SELECT framework, COUNT(*) AS cnt FROM compliance_workflows WHERE org_id = ? GROUP BY framework",
                (org_id,),
            ).fetchall()
            by_framework = {r["framework"]: r["cnt"] for r in framework_rows}

            total = conn.execute(
                "SELECT COUNT(*) FROM compliance_workflows WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

        return {
            "total_workflows": total,
            "by_status": by_status,
            "by_framework": by_framework,
        }
