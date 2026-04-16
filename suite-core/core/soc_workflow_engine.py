"""SOC Workflow Engine — ALDECI.

Workflow automation and execution tracking for SOC operations.

Capabilities:
  - Workflow registry: create, list, get with full org isolation
  - Workflow types: alert_triage, incident_response, threat_hunt, change_mgmt, vulnerability_mgmt
  - Execution lifecycle: running → completed/failed
  - Step-by-step execution logging
  - Stats: counts, avg duration, breakdown by type and status

Compliance: NIST SP 800-61 (incident handling), ISO/IEC 27001 (ISMS procedures)
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

_VALID_WORKFLOW_TYPES = {
    "alert_triage", "incident_response", "threat_hunt",
    "change_mgmt", "vulnerability_mgmt",
}
_VALID_TRIGGERS = {"manual", "scheduled", "automated"}
_VALID_EXEC_STATUSES = {"running", "completed", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SOCWorkflowEngine:
    """SQLite WAL-backed SOC Workflow engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/soc_workflow.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "soc_workflow.db")
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
                CREATE TABLE IF NOT EXISTS workflows (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    workflow_type TEXT NOT NULL,
                    trigger       TEXT NOT NULL DEFAULT 'manual',
                    steps         TEXT NOT NULL DEFAULT '[]',
                    description   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'active',
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_workflows_org
                    ON workflows (org_id, workflow_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS executions (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    workflow_id   TEXT NOT NULL,
                    initiated_by  TEXT NOT NULL DEFAULT '',
                    context       TEXT NOT NULL DEFAULT '{}',
                    current_step  INTEGER NOT NULL DEFAULT 0,
                    execution_log TEXT NOT NULL DEFAULT '[]',
                    status        TEXT NOT NULL DEFAULT 'running',
                    outcome       TEXT NOT NULL DEFAULT '',
                    started_at    TEXT NOT NULL,
                    completed_at  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_executions_org
                    ON executions (org_id, workflow_id, started_at DESC);
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
    # Workflows
    # ------------------------------------------------------------------

    def create_workflow(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new SOC workflow."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        workflow_type = data.get("workflow_type", "")
        if workflow_type not in _VALID_WORKFLOW_TYPES:
            raise ValueError(
                f"Invalid workflow_type: {workflow_type}. Must be one of {_VALID_WORKFLOW_TYPES}"
            )

        trigger = data.get("trigger", "manual")
        if trigger not in _VALID_TRIGGERS:
            raise ValueError(
                f"Invalid trigger: {trigger}. Must be one of {_VALID_TRIGGERS}"
            )

        steps = data.get("steps", [])
        if not isinstance(steps, list):
            steps = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "workflow_type": workflow_type,
            "trigger": trigger,
            "steps": json.dumps(steps),
            "description": data.get("description", ""),
            "status": "active",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO workflows
                       (id, org_id, name, workflow_type, trigger, steps,
                        description, status, created_at)
                       VALUES (:id, :org_id, :name, :workflow_type, :trigger, :steps,
                               :description, :status, :created_at)""",
                    record,
                )
        result = dict(record)
        result["steps"] = steps
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ALERT_CREATED", {"entity_type": "soc_workflow", "org_id": org_id, "source_engine": "soc_workflow"})
            except Exception:
                pass

        return result

    def list_workflows(
        self,
        org_id: str,
        workflow_type: Optional[str] = None,
        trigger: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List workflows with optional filters."""
        sql = "SELECT * FROM workflows WHERE org_id = ?"
        params: list = [org_id]
        if workflow_type:
            sql += " AND workflow_type = ?"
            params.append(workflow_type)
        if trigger:
            sql += " AND trigger = ?"
            params.append(trigger)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            r = self._row(row)
            try:
                r["steps"] = json.loads(r["steps"])
            except Exception:
                r["steps"] = []
            result.append(r)
        return result

    def get_workflow(self, org_id: str, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single workflow by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM workflows WHERE org_id = ? AND id = ?",
                (org_id, workflow_id),
            ).fetchone()
        if not row:
            return None
        r = self._row(row)
        try:
            r["steps"] = json.loads(r["steps"])
        except Exception:
            r["steps"] = []
        return r

    # ------------------------------------------------------------------
    # Executions
    # ------------------------------------------------------------------

    def start_execution(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Start a workflow execution."""
        workflow_id = (data.get("workflow_id") or "").strip()
        if not workflow_id:
            raise ValueError("workflow_id is required.")

        initiated_by = data.get("initiated_by", "")
        context = data.get("context", {})
        if not isinstance(context, dict):
            context = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "workflow_id": workflow_id,
            "initiated_by": initiated_by,
            "context": json.dumps(context),
            "current_step": 0,
            "execution_log": json.dumps([]),
            "status": "running",
            "outcome": "",
            "started_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO executions
                       (id, org_id, workflow_id, initiated_by, context, current_step,
                        execution_log, status, outcome, started_at, completed_at)
                       VALUES (:id, :org_id, :workflow_id, :initiated_by, :context,
                               :current_step, :execution_log, :status, :outcome,
                               :started_at, :completed_at)""",
                    record,
                )
        result = dict(record)
        result["context"] = context
        result["execution_log"] = []
        return result

    def update_execution(
        self,
        org_id: str,
        execution_id: str,
        step_name: str,
        step_status: str,
        step_output: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Append a step result to an execution log and advance current_step.

        If step_status is 'failed', the execution status becomes 'failed'.
        Returns None if not found.
        """
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM executions WHERE org_id = ? AND id = ?",
                    (org_id, execution_id),
                ).fetchone()
                if not row:
                    return None

                r = self._row(row)
                try:
                    log = json.loads(r["execution_log"])
                except Exception:
                    log = []

                log.append({
                    "step_name": step_name,
                    "step_status": step_status,
                    "step_output": step_output,
                    "timestamp": now,
                })

                new_step = r["current_step"] + 1
                new_status = r["status"]
                completed_at = r.get("completed_at")

                if step_status == "failed":
                    new_status = "failed"
                    completed_at = now

                conn.execute(
                    """UPDATE executions
                       SET execution_log = ?, current_step = ?, status = ?, completed_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (json.dumps(log), new_step, new_status, completed_at, org_id, execution_id),
                )
                updated = conn.execute(
                    "SELECT * FROM executions WHERE org_id = ? AND id = ?",
                    (org_id, execution_id),
                ).fetchone()

        if not updated:
            return None
        result = self._row(updated)
        try:
            result["execution_log"] = json.loads(result["execution_log"])
        except Exception:
            result["execution_log"] = []
        try:
            result["context"] = json.loads(result["context"])
        except Exception:
            result["context"] = {}
        return result

    def complete_execution(
        self, org_id: str, execution_id: str, outcome: str
    ) -> Optional[Dict[str, Any]]:
        """Mark an execution as completed. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    """UPDATE executions
                       SET status = 'completed', completed_at = ?, outcome = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, outcome, org_id, execution_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM executions WHERE org_id = ? AND id = ?",
                    (org_id, execution_id),
                ).fetchone()

        if not row:
            return None
        result = self._row(row)
        try:
            result["execution_log"] = json.loads(result["execution_log"])
        except Exception:
            result["execution_log"] = []
        try:
            result["context"] = json.loads(result["context"])
        except Exception:
            result["context"] = {}
        return result

    def list_executions(
        self,
        org_id: str,
        workflow_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List executions with optional filters, ordered by started_at DESC."""
        sql = "SELECT * FROM executions WHERE org_id = ?"
        params: list = [org_id]
        if workflow_id:
            sql += " AND workflow_id = ?"
            params.append(workflow_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            r = self._row(row)
            try:
                r["execution_log"] = json.loads(r["execution_log"])
            except Exception:
                r["execution_log"] = []
            try:
                r["context"] = json.loads(r["context"])
            except Exception:
                r["context"] = {}
            result.append(r)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_soc_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated SOC workflow stats for an org."""
        with self._conn() as conn:
            total_workflows = conn.execute(
                "SELECT COUNT(*) FROM workflows WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT workflow_type, COUNT(*) as cnt FROM workflows "
                "WHERE org_id = ? GROUP BY workflow_type",
                (org_id,),
            ).fetchall()
            by_type = {r["workflow_type"]: r["cnt"] for r in type_rows}

            total_executions = conn.execute(
                "SELECT COUNT(*) FROM executions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            running_executions = conn.execute(
                "SELECT COUNT(*) FROM executions WHERE org_id = ? AND status = 'running'",
                (org_id,),
            ).fetchone()[0]

            completed_executions = conn.execute(
                "SELECT COUNT(*) FROM executions WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            failed_executions = conn.execute(
                "SELECT COUNT(*) FROM executions WHERE org_id = ? AND status = 'failed'",
                (org_id,),
            ).fetchone()[0]

            # avg_duration_seconds for completed executions only
            done_rows = conn.execute(
                """SELECT started_at, completed_at FROM executions
                   WHERE org_id = ? AND status = 'completed' AND completed_at IS NOT NULL""",
                (org_id,),
            ).fetchall()

        avg_duration_seconds = 0.0
        if done_rows:
            total_secs = 0.0
            count = 0
            for r in done_rows:
                try:
                    started = datetime.fromisoformat(
                        r["started_at"].replace("Z", "+00:00")
                    )
                    completed = datetime.fromisoformat(
                        r["completed_at"].replace("Z", "+00:00")
                    )
                    total_secs += (completed - started).total_seconds()
                    count += 1
                except Exception:
                    pass
            avg_duration_seconds = round(total_secs / count, 2) if count else 0.0

        return {
            "total_workflows": total_workflows,
            "by_type": by_type,
            "total_executions": total_executions,
            "running_executions": running_executions,
            "completed_executions": completed_executions,
            "failed_executions": failed_executions,
            "avg_duration_seconds": avg_duration_seconds,
        }
