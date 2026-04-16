"""Autonomous Remediation Engine — ALDECI.

Manages automated remediation workflows: trigger-based execution, playbooks,
and execution tracking with success/failure metrics.

Capabilities:
  - Create and manage remediation workflows (draft → active)
  - Execution tracking with status lifecycle
  - Playbook management with run history
  - Remediation statistics by trigger/action type

Compliance: NIST SP 800-40, CIS Control 7 (continuous vulnerability management)
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

_VALID_TRIGGER_TYPES = {
    "vulnerability", "alert", "anomaly", "policy_violation", "incident", "manual"
}
_VALID_ACTION_TYPES = {
    "patch", "isolate", "block", "notify", "script", "api_call", "rollback", "quarantine"
}
_VALID_TARGET_TYPES = {
    "host", "container", "network", "identity", "application", "cloud_resource"
}
_VALID_AUTOMATION_LEVELS = {"full", "semi", "manual"}
_VALID_WORKFLOW_STATUSES = {"active", "inactive", "draft"}
_VALID_EXECUTION_STATUSES = {
    "pending", "running", "succeeded", "failed", "rolled_back", "skipped"
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AutonomousRemediationEngine:
    """SQLite WAL-backed Autonomous Remediation engine.

    Thread-safe via RLock. Multi-tenant via org_id isolation.
    """

    def __init__(self, db_path: str = "") -> None:
        if not db_path:
            db_path = str(Path(_DEFAULT_DB_DIR) / "autonomous_remediation.db")
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
                CREATE TABLE IF NOT EXISTS ar_workflows (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    trigger_type        TEXT NOT NULL DEFAULT 'manual',
                    trigger_condition   TEXT NOT NULL DEFAULT '{}',
                    action_type         TEXT NOT NULL DEFAULT 'notify',
                    target_type         TEXT NOT NULL DEFAULT 'host',
                    automation_level    TEXT NOT NULL DEFAULT 'manual',
                    status              TEXT NOT NULL DEFAULT 'draft',
                    success_count       INTEGER NOT NULL DEFAULT 0,
                    failure_count       INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ar_executions (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    workflow_id     TEXT NOT NULL,
                    trigger_event   TEXT NOT NULL DEFAULT '',
                    target_id       TEXT NOT NULL DEFAULT '',
                    target_type     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    started_at      TEXT NOT NULL DEFAULT '',
                    completed_at    TEXT NOT NULL DEFAULT '',
                    result          TEXT NOT NULL DEFAULT '',
                    error_message   TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ar_playbooks (
                    id                          TEXT PRIMARY KEY,
                    org_id                      TEXT NOT NULL,
                    playbook_name               TEXT NOT NULL,
                    steps                       TEXT NOT NULL DEFAULT '[]',
                    target_type                 TEXT NOT NULL DEFAULT 'host',
                    estimated_duration_minutes  INTEGER NOT NULL DEFAULT 0,
                    last_run                    TEXT NOT NULL DEFAULT '',
                    run_count                   INTEGER NOT NULL DEFAULT 0,
                    created_at                  TEXT NOT NULL
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------

    def create_workflow(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        name = str(data.get("name", "")).strip()
        if not name:
            raise ValueError("name is required")

        trigger_type = data.get("trigger_type", "manual")
        if trigger_type not in _VALID_TRIGGER_TYPES:
            raise ValueError(
                f"Invalid trigger_type '{trigger_type}'. Valid: {sorted(_VALID_TRIGGER_TYPES)}"
            )

        action_type = data.get("action_type", "notify")
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type '{action_type}'. Valid: {sorted(_VALID_ACTION_TYPES)}"
            )

        target_type = data.get("target_type", "host")
        if target_type not in _VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type '{target_type}'. Valid: {sorted(_VALID_TARGET_TYPES)}"
            )

        automation_level = data.get("automation_level", "manual")
        if automation_level not in _VALID_AUTOMATION_LEVELS:
            raise ValueError(
                f"Invalid automation_level '{automation_level}'. Valid: {sorted(_VALID_AUTOMATION_LEVELS)}"
            )

        trigger_condition = data.get("trigger_condition", {})
        if isinstance(trigger_condition, dict):
            trigger_condition = json.dumps(trigger_condition)

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "trigger_type": trigger_type,
            "trigger_condition": trigger_condition,
            "action_type": action_type,
            "target_type": target_type,
            "automation_level": automation_level,
            "status": "draft",
            "success_count": 0,
            "failure_count": 0,
            "created_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ar_workflows
                        (id, org_id, name, trigger_type, trigger_condition, action_type,
                         target_type, automation_level, status, success_count, failure_count, created_at)
                    VALUES
                        (:id, :org_id, :name, :trigger_type, :trigger_condition, :action_type,
                         :target_type, :automation_level, :status, :success_count, :failure_count, :created_at)
                    """,
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "autonomous_remediation", "org_id": org_id, "source_engine": "autonomous_remediation"})
            except Exception:
                pass

        return record

    def list_workflows(
        self,
        org_id: str,
        trigger_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM ar_workflows WHERE org_id = ?"
        params: list = [org_id]
        if trigger_type:
            sql += " AND trigger_type = ?"
            params.append(trigger_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_workflow(self, org_id: str, workflow_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ar_workflows WHERE id = ? AND org_id = ?",
                    (workflow_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    def activate_workflow(self, org_id: str, workflow_id: str) -> Dict[str, Any]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ar_workflows WHERE id = ? AND org_id = ?",
                    (workflow_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Workflow {workflow_id} not found")
                conn.execute(
                    "UPDATE ar_workflows SET status = 'active' WHERE id = ? AND org_id = ?",
                    (workflow_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM ar_workflows WHERE id = ? AND org_id = ?",
                    (workflow_id, org_id),
                ).fetchone()
        return dict(updated)

    # ------------------------------------------------------------------
    # Executions
    # ------------------------------------------------------------------

    def record_execution(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        workflow_id = str(data.get("workflow_id", "")).strip()
        if not workflow_id:
            raise ValueError("workflow_id is required")

        status = data.get("status", "pending")
        if status not in _VALID_EXECUTION_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Valid: {sorted(_VALID_EXECUTION_STATUSES)}"
            )

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "workflow_id": workflow_id,
            "trigger_event": str(data.get("trigger_event", "")),
            "target_id": str(data.get("target_id", "")),
            "target_type": str(data.get("target_type", "")),
            "status": status,
            "started_at": str(data.get("started_at", _now_iso())),
            "completed_at": str(data.get("completed_at", "")),
            "result": str(data.get("result", "")),
            "error_message": str(data.get("error_message", "")),
            "created_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ar_executions
                        (id, org_id, workflow_id, trigger_event, target_id, target_type,
                         status, started_at, completed_at, result, error_message, created_at)
                    VALUES
                        (:id, :org_id, :workflow_id, :trigger_event, :target_id, :target_type,
                         :status, :started_at, :completed_at, :result, :error_message, :created_at)
                    """,
                    record,
                )
                # Update workflow counters
                if status == "succeeded":
                    conn.execute(
                        "UPDATE ar_workflows SET success_count = success_count + 1 WHERE id = ? AND org_id = ?",
                        (workflow_id, org_id),
                    )
                elif status == "failed":
                    conn.execute(
                        "UPDATE ar_workflows SET failure_count = failure_count + 1 WHERE id = ? AND org_id = ?",
                        (workflow_id, org_id),
                    )
        return record

    def list_executions(
        self,
        org_id: str,
        workflow_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM ar_executions WHERE org_id = ?"
        params: list = [org_id]
        if workflow_id:
            sql += " AND workflow_id = ?"
            params.append(workflow_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def create_playbook(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        playbook_name = str(data.get("playbook_name", "")).strip()
        if not playbook_name:
            raise ValueError("playbook_name is required")

        target_type = data.get("target_type", "host")
        if target_type not in _VALID_TARGET_TYPES:
            raise ValueError(
                f"Invalid target_type '{target_type}'. Valid: {sorted(_VALID_TARGET_TYPES)}"
            )

        steps = data.get("steps", [])
        if not isinstance(steps, list):
            steps = []

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "playbook_name": playbook_name,
            "steps": json.dumps(steps),
            "target_type": target_type,
            "estimated_duration_minutes": int(data.get("estimated_duration_minutes", 0)),
            "last_run": "",
            "run_count": 0,
            "created_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ar_playbooks
                        (id, org_id, playbook_name, steps, target_type,
                         estimated_duration_minutes, last_run, run_count, created_at)
                    VALUES
                        (:id, :org_id, :playbook_name, :steps, :target_type,
                         :estimated_duration_minutes, :last_run, :run_count, :created_at)
                    """,
                    record,
                )
        record["steps"] = steps
        return record

    def list_playbooks(
        self,
        org_id: str,
        target_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM ar_playbooks WHERE org_id = ?"
        params: list = [org_id]
        if target_type:
            sql += " AND target_type = ?"
            params.append(target_type)
        sql += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()

        results = []
        for r in rows:
            d = dict(r)
            try:
                d["steps"] = json.loads(d["steps"])
            except (json.JSONDecodeError, TypeError):
                d["steps"] = []
            results.append(d)
        return results

    def run_playbook(self, org_id: str, playbook_id: str) -> Dict[str, Any]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ar_playbooks WHERE id = ? AND org_id = ?",
                    (playbook_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Playbook {playbook_id} not found")
                now = _now_iso()
                conn.execute(
                    """
                    UPDATE ar_playbooks
                    SET run_count = run_count + 1, last_run = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, playbook_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM ar_playbooks WHERE id = ? AND org_id = ?",
                    (playbook_id, org_id),
                ).fetchone()
        d = dict(updated)
        try:
            d["steps"] = json.loads(d["steps"])
        except (json.JSONDecodeError, TypeError):
            d["steps"] = []
        return d

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_remediation_stats(self, org_id: str) -> Dict[str, Any]:
        with self._lock:
            with self._conn() as conn:
                total_workflows = conn.execute(
                    "SELECT COUNT(*) FROM ar_workflows WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_workflows = conn.execute(
                    "SELECT COUNT(*) FROM ar_workflows WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]
                total_executions = conn.execute(
                    "SELECT COUNT(*) FROM ar_executions WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                succeeded_executions = conn.execute(
                    "SELECT COUNT(*) FROM ar_executions WHERE org_id = ? AND status = 'succeeded'",
                    (org_id,),
                ).fetchone()[0]
                failed_executions = conn.execute(
                    "SELECT COUNT(*) FROM ar_executions WHERE org_id = ? AND status = 'failed'",
                    (org_id,),
                ).fetchone()[0]
                total_playbooks = conn.execute(
                    "SELECT COUNT(*) FROM ar_playbooks WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                trigger_rows = conn.execute(
                    "SELECT trigger_type, COUNT(*) as cnt FROM ar_workflows WHERE org_id = ? GROUP BY trigger_type",
                    (org_id,),
                ).fetchall()
                action_rows = conn.execute(
                    "SELECT action_type, COUNT(*) as cnt FROM ar_workflows WHERE org_id = ? GROUP BY action_type",
                    (org_id,),
                ).fetchall()

        by_trigger_type = {r["trigger_type"]: r["cnt"] for r in trigger_rows}
        by_action_type = {r["action_type"]: r["cnt"] for r in action_rows}
        success_rate = (
            succeeded_executions / total_executions if total_executions > 0 else 0.0
        )

        return {
            "total_workflows": total_workflows,
            "active_workflows": active_workflows,
            "total_executions": total_executions,
            "succeeded_executions": succeeded_executions,
            "failed_executions": failed_executions,
            "total_playbooks": total_playbooks,
            "by_trigger_type": by_trigger_type,
            "by_action_type": by_action_type,
            "success_rate": success_rate,
        }
