"""
Workflow database manager using SQLite.
"""
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.workflow_models import Workflow, WorkflowExecution, WorkflowStatus


class WorkflowDB:
    """Database manager for workflow records."""

    def __init__(self, db_path: str = "data/workflows.db"):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        """Initialize database tables."""
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workflows (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    steps TEXT NOT NULL,
                    triggers TEXT,
                    enabled INTEGER NOT NULL,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS workflow_executions (
                    id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    triggered_by TEXT,
                    input_data TEXT,
                    output_data TEXT,
                    error_message TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    FOREIGN KEY (workflow_id) REFERENCES workflows(id)
                );

                CREATE INDEX IF NOT EXISTS idx_workflows_enabled ON workflows(enabled);
                CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow ON workflow_executions(workflow_id);
                CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status);
            """
            )
            conn.commit()
        finally:
            conn.close()

    def create_workflow(self, workflow: Workflow) -> Workflow:
        """Create new workflow."""
        if not workflow.id:
            workflow.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO workflows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    workflow.id,
                    workflow.name,
                    workflow.description,
                    json.dumps(workflow.steps),
                    json.dumps(workflow.triggers),
                    1 if workflow.enabled else 0,
                    workflow.created_by,
                    workflow.created_at.isoformat(),
                    workflow.updated_at.isoformat(),
                ),
            )
            conn.commit()
            return workflow
        finally:
            conn.close()

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get workflow by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM workflows WHERE id = ?", (workflow_id,)
            ).fetchone()
            if row:
                return self._row_to_workflow(row)
            return None
        finally:
            conn.close()

    def list_workflows(self, limit: int = 100, offset: int = 0) -> List[Workflow]:
        """List workflows."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM workflows ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_workflow(row) for row in rows]
        finally:
            conn.close()

    def update_workflow(self, workflow: Workflow) -> Workflow:
        """Update workflow."""
        workflow.updated_at = datetime.utcnow()
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE workflows SET name=?, description=?, steps=?, triggers=?, enabled=?, updated_at=? WHERE id=?""",
                (
                    workflow.name,
                    workflow.description,
                    json.dumps(workflow.steps),
                    json.dumps(workflow.triggers),
                    1 if workflow.enabled else 0,
                    workflow.updated_at.isoformat(),
                    workflow.id,
                ),
            )
            conn.commit()
            return workflow
        finally:
            conn.close()

    def delete_workflow(self, workflow_id: str) -> bool:
        """Delete workflow."""
        conn = self._get_connection()
        try:
            conn.execute(
                "DELETE FROM workflow_executions WHERE workflow_id = ?", (workflow_id,)
            )
            conn.execute("DELETE FROM workflows WHERE id = ?", (workflow_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def create_execution(self, execution: WorkflowExecution) -> WorkflowExecution:
        """Create workflow execution record."""
        if not execution.id:
            execution.id = str(uuid.uuid4())
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO workflow_executions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    execution.id,
                    execution.workflow_id,
                    execution.status.value,
                    execution.triggered_by,
                    json.dumps(execution.input_data),
                    json.dumps(execution.output_data),
                    execution.error_message,
                    execution.started_at.isoformat(),
                    execution.completed_at.isoformat()
                    if execution.completed_at
                    else None,
                ),
            )
            conn.commit()
            return execution
        finally:
            conn.close()

    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get workflow execution by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM workflow_executions WHERE id = ?", (execution_id,)
            ).fetchone()
            if row:
                return self._row_to_execution(row)
            return None
        finally:
            conn.close()

    def list_executions(
        self, workflow_id: Optional[str] = None, limit: int = 100, offset: int = 0
    ) -> List[WorkflowExecution]:
        """List workflow executions."""
        conn = self._get_connection()
        try:
            if workflow_id:
                rows = conn.execute(
                    "SELECT * FROM workflow_executions WHERE workflow_id = ? ORDER BY started_at DESC LIMIT ? OFFSET ?",
                    (workflow_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM workflow_executions ORDER BY started_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_execution(row) for row in rows]
        finally:
            conn.close()

    def update_execution(self, execution: WorkflowExecution) -> WorkflowExecution:
        """Update workflow execution."""
        conn = self._get_connection()
        try:
            conn.execute(
                """UPDATE workflow_executions SET status=?, output_data=?, error_message=?, completed_at=? WHERE id=?""",
                (
                    execution.status.value,
                    json.dumps(execution.output_data),
                    execution.error_message,
                    execution.completed_at.isoformat()
                    if execution.completed_at
                    else None,
                    execution.id,
                ),
            )
            conn.commit()
            return execution
        finally:
            conn.close()

    def _row_to_workflow(self, row) -> Workflow:
        """Convert database row to Workflow object."""
        return Workflow(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            steps=json.loads(row["steps"]) if row["steps"] else [],
            triggers=json.loads(row["triggers"]) if row["triggers"] else {},
            enabled=bool(row["enabled"]),
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _row_to_execution(self, row) -> WorkflowExecution:
        """Convert database row to WorkflowExecution object."""
        return WorkflowExecution(
            id=row["id"],
            workflow_id=row["workflow_id"],
            status=WorkflowStatus(row["status"]),
            triggered_by=row["triggered_by"],
            input_data=json.loads(row["input_data"]) if row["input_data"] else {},
            output_data=json.loads(row["output_data"]) if row["output_data"] else {},
            error_message=row["error_message"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"]
                else None
            ),
        )
