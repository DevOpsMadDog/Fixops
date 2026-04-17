"""Workflow automation engine for ALDECI — trigger→condition→action chains.

Provides:
- TriggerType enum: canonical workflow trigger types
- ConditionOperator enum: condition evaluation operators
- ActionType enum: supported action types
- WorkflowCondition Pydantic model
- WorkflowAction Pydantic model
- Workflow Pydantic model
- WorkflowExecution Pydantic model
- WorkflowEngine class (SQLite-backed)

Usage:
    from core.workflow_engine import WorkflowEngine, Workflow, TriggerType, ActionType

    engine = WorkflowEngine()
    wf = engine.create_workflow(Workflow(
        name="Critical Finding Alert",
        trigger=TriggerType.FINDING_CREATED,
        conditions=[WorkflowCondition(field="severity", operator=ConditionOperator.EQUALS, value="critical")],
        actions=[WorkflowAction(type=ActionType.SEND_SLACK_MESSAGE, config={"channel": "#security"})],
    ))
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "data", "workflow_engine.db",
    )
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS workflows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    trigger TEXT NOT NULL,
    conditions TEXT NOT NULL DEFAULT '[]',
    actions TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1,
    org_id TEXT NOT NULL DEFAULT 'default',
    created_by TEXT NOT NULL DEFAULT 'system',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wf_org ON workflows(org_id);
CREATE INDEX IF NOT EXISTS idx_wf_trigger ON workflows(trigger);
CREATE INDEX IF NOT EXISTS idx_wf_enabled ON workflows(enabled);

CREATE TABLE IF NOT EXISTS workflow_executions (
    id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL,
    trigger_event TEXT NOT NULL,
    conditions_met INTEGER NOT NULL DEFAULT 0,
    actions_executed TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'success',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT,
    org_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_exec_workflow ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_exec_org ON workflow_executions(org_id);
CREATE INDEX IF NOT EXISTS idx_exec_started ON workflow_executions(started_at DESC);
"""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TriggerType(str, Enum):
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    SLA_BREACH = "sla.breach"
    COMPLIANCE_GAP = "compliance.gap"
    SCAN_COMPLETED = "scan.completed"
    RISK_SCORE_CHANGED = "risk.score_changed"
    ASSET_DISCOVERED = "asset.discovered"
    INCIDENT_CREATED = "incident.created"


class ConditionOperator(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    CONTAINS = "contains"
    IN = "in"
    NOT_IN = "not_in"
    AND = "and"
    OR = "or"


class ActionType(str, Enum):
    CREATE_JIRA_TICKET = "create_jira_ticket"
    SEND_SLACK_MESSAGE = "send_slack_message"
    SEND_EMAIL = "send_email"
    BLOCK_DEPLOY = "block_deploy"
    ESCALATE = "escalate"
    RUN_PLAYBOOK = "run_playbook"
    UPDATE_FINDING = "update_finding"
    WEBHOOK = "webhook"
    LOG = "log"


# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------


class WorkflowCondition(BaseModel):
    field: str
    operator: ConditionOperator
    value: Any

    model_config = {"use_enum_values": True}


class WorkflowAction(BaseModel):
    type: ActionType
    config: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"use_enum_values": True}


class Workflow(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    trigger: TriggerType
    conditions: List[WorkflowCondition] = Field(default_factory=list)
    actions: List[WorkflowAction] = Field(default_factory=list)
    enabled: bool = True
    org_id: str = "default"
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}


class WorkflowExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: str
    trigger_event: Dict[str, Any] = Field(default_factory=dict)
    conditions_met: bool = False
    actions_executed: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "success"  # success | partial | failed
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    org_id: str = "default"

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


def _workflow_from_row(row: sqlite3.Row) -> Workflow:
    d = dict(row)
    d["conditions"] = json.loads(d["conditions"]) if d.get("conditions") else []
    d["actions"] = json.loads(d["actions"]) if d.get("actions") else []
    d["enabled"] = bool(d.get("enabled", 1))
    return Workflow(**d)


def _execution_from_row(row: sqlite3.Row) -> WorkflowExecution:
    d = dict(row)
    d["trigger_event"] = json.loads(d["trigger_event"]) if d.get("trigger_event") else {}
    d["actions_executed"] = json.loads(d["actions_executed"]) if d.get("actions_executed") else []
    d["conditions_met"] = bool(d.get("conditions_met", 0))
    # Remove org_id if not in WorkflowExecution model fields to avoid validation issues
    return WorkflowExecution(**d)


# ---------------------------------------------------------------------------
# Built-in Templates
# ---------------------------------------------------------------------------

_TEMPLATES: List[Dict[str, Any]] = [
    {
        "id": "tpl-critical-finding-alert",
        "name": "Critical Finding Alert",
        "description": "Send Slack alert when a critical severity finding is created",
        "trigger": TriggerType.FINDING_CREATED.value,
        "conditions": [
            {"field": "severity", "operator": ConditionOperator.EQUALS.value, "value": "critical"}
        ],
        "actions": [
            {
                "type": ActionType.SEND_SLACK_MESSAGE.value,
                "config": {"channel": "#security-alerts", "template": "critical_finding"},
            }
        ],
        "enabled": True,
        "org_id": "template",
        "created_by": "system",
        "created_at": "2026-01-01T00:00:00+00:00",
    },
    {
        "id": "tpl-sla-breach-escalation",
        "name": "SLA Breach Escalation",
        "description": "Escalate and create Jira ticket when SLA is breached",
        "trigger": TriggerType.SLA_BREACH.value,
        "conditions": [
            {"field": "days_overdue", "operator": ConditionOperator.GREATER_THAN.value, "value": 0}
        ],
        "actions": [
            {
                "type": ActionType.ESCALATE.value,
                "config": {"assignee": "security-lead", "priority": "urgent"},
            },
            {
                "type": ActionType.CREATE_JIRA_TICKET.value,
                "config": {"project": "SEC", "issue_type": "Bug", "priority": "High"},
            },
        ],
        "enabled": True,
        "org_id": "template",
        "created_by": "system",
        "created_at": "2026-01-01T00:00:00+00:00",
    },
    {
        "id": "tpl-compliance-gap-ticket",
        "name": "Compliance Gap Ticket",
        "description": "Create Jira ticket for compliance gaps above medium severity",
        "trigger": TriggerType.COMPLIANCE_GAP.value,
        "conditions": [
            {"field": "severity", "operator": ConditionOperator.IN.value, "value": ["high", "critical"]}
        ],
        "actions": [
            {
                "type": ActionType.CREATE_JIRA_TICKET.value,
                "config": {"project": "COMP", "issue_type": "Task", "assignee": "compliance-team"},
            }
        ],
        "enabled": True,
        "org_id": "template",
        "created_by": "system",
        "created_at": "2026-01-01T00:00:00+00:00",
    },
    {
        "id": "tpl-new-asset-review",
        "name": "New Asset Review",
        "description": "Log and send email when a new asset is discovered",
        "trigger": TriggerType.ASSET_DISCOVERED.value,
        "conditions": [],
        "actions": [
            {
                "type": ActionType.LOG.value,
                "config": {"level": "info", "message": "New asset discovered"},
            },
            {
                "type": ActionType.SEND_EMAIL.value,
                "config": {"to": "asset-team@example.com", "subject": "New Asset Discovered"},
            },
        ],
        "enabled": True,
        "org_id": "template",
        "created_by": "system",
        "created_at": "2026-01-01T00:00:00+00:00",
    },
    {
        "id": "tpl-scan-complete-report",
        "name": "Scan Complete Report",
        "description": "Send Slack notification when a scan completes",
        "trigger": TriggerType.SCAN_COMPLETED.value,
        "conditions": [],
        "actions": [
            {
                "type": ActionType.SEND_SLACK_MESSAGE.value,
                "config": {"channel": "#scan-results", "template": "scan_summary"},
            },
            {
                "type": ActionType.LOG.value,
                "config": {"level": "info", "message": "Scan completed"},
            },
        ],
        "enabled": True,
        "org_id": "template",
        "created_by": "system",
        "created_at": "2026-01-01T00:00:00+00:00",
    },
]


# ---------------------------------------------------------------------------
# WorkflowEngine
# ---------------------------------------------------------------------------


class WorkflowEngine:
    """SQLite-backed workflow automation engine.

    Evaluates security events against trigger→condition→action chains.
    Thread-safe. Persists executions for audit history.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # Initialize schema
        with self._lock:
            conn = _get_db(self._db_path)
            conn.close()

    # ------------------------------------------------------------------
    # Workflow CRUD
    # ------------------------------------------------------------------

    def create_workflow(self, workflow: Workflow) -> Workflow:
        """Persist a new workflow. Returns the workflow with assigned id."""
        now_iso = datetime.now(timezone.utc).isoformat()
        workflow = workflow.model_copy(update={"created_at": datetime.now(timezone.utc)})

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "INSERT INTO workflows (id, name, description, trigger, conditions, actions, enabled, org_id, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        workflow.id,
                        workflow.name,
                        workflow.description,
                        workflow.trigger if isinstance(workflow.trigger, str) else workflow.trigger.value,
                        json.dumps([c.model_dump() if hasattr(c, "model_dump") else c for c in workflow.conditions]),
                        json.dumps([a.model_dump() if hasattr(a, "model_dump") else a for a in workflow.actions]),
                        1 if workflow.enabled else 0,
                        workflow.org_id,
                        workflow.created_by,
                        now_iso,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        logger.info("Created workflow '%s' (id=%s, trigger=%s)", workflow.name, workflow.id, workflow.trigger)
        return workflow

    def update_workflow(self, workflow_id: str, updates: Dict[str, Any]) -> Workflow:
        """Update fields on an existing workflow. Raises KeyError if not found."""
        set_clauses: List[str] = []
        params: List[Any] = []

        for key, val in updates.items():
            if key in ("conditions", "actions"):
                set_clauses.append(f"{key}=?")
                params.append(json.dumps(val))
            elif key == "enabled":
                set_clauses.append(f"{key}=?")
                params.append(1 if val else 0)
            else:
                set_clauses.append(f"{key}=?")
                params.append(val)

        if not set_clauses:
            return self.get_workflow(workflow_id)

        params.append(workflow_id)
        sql = f"UPDATE workflows SET {', '.join(set_clauses)} WHERE id=?"  # nosec B608

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                cur = conn.execute(sql, params)
                if cur.rowcount == 0:
                    raise KeyError(f"Workflow {workflow_id} not found")
                conn.commit()
                row = conn.execute("SELECT * FROM workflows WHERE id=?", (workflow_id,)).fetchone()
            finally:
                conn.close()

        return _workflow_from_row(row)

    def delete_workflow(self, workflow_id: str) -> bool:
        """Remove a workflow by id. Returns True if deleted, False if not found."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                cur = conn.execute("DELETE FROM workflows WHERE id=?", (workflow_id,))
                conn.commit()
                found = cur.rowcount > 0
            finally:
                conn.close()

        if found:
            logger.info("Deleted workflow %s", workflow_id)
        return found

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Return a single workflow by id, or None."""
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                row = conn.execute("SELECT * FROM workflows WHERE id=?", (workflow_id,)).fetchone()
            finally:
                conn.close()
        return _workflow_from_row(row) if row else None

    def list_workflows(
        self,
        org_id: Optional[str] = None,
        trigger_filter: Optional[str] = None,
    ) -> List[Workflow]:
        """Return workflows, optionally filtered by org_id and trigger type."""
        clauses: List[str] = []
        params: List[Any] = []

        if org_id is not None:
            clauses.append("org_id=?")
            params.append(org_id)
        if trigger_filter is not None:
            clauses.append("trigger=?")
            params.append(trigger_filter)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM workflows {where} ORDER BY name"  # nosec B608

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()

        return [_workflow_from_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Event evaluation
    # ------------------------------------------------------------------

    def evaluate_event(
        self, event: Dict[str, Any], org_id: str = "default"
    ) -> List[WorkflowExecution]:
        """Match event against all enabled workflows, execute matching ones.

        Args:
            event: dict with at least 'event_type' and payload fields
            org_id: organization scope

        Returns:
            List of WorkflowExecution records for each matched workflow
        """
        event_type = event.get("event_type", "")

        # Find workflows matching trigger and org
        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute(
                    "SELECT * FROM workflows WHERE enabled=1 AND (org_id=? OR org_id='default') AND trigger=?",
                    (org_id, event_type),
                ).fetchall()
            finally:
                conn.close()

        workflows = [_workflow_from_row(r) for r in rows]
        executions: List[WorkflowExecution] = []

        for workflow in workflows:
            execution = self._execute_workflow(workflow, event, org_id)
            executions.append(execution)

        return executions

    def _execute_workflow(
        self, workflow: Workflow, event: Dict[str, Any], org_id: str
    ) -> WorkflowExecution:
        """Execute a single workflow against an event. Persists execution record."""
        started_at = datetime.now(timezone.utc)
        execution = WorkflowExecution(
            workflow_id=workflow.id,
            trigger_event=event,
            org_id=org_id,
            started_at=started_at,
        )

        try:
            # Deserialize conditions
            conditions = []
            for c in workflow.conditions:
                if isinstance(c, dict):
                    conditions.append(WorkflowCondition(**c))
                else:
                    conditions.append(c)

            conditions_met = self._check_conditions(event, conditions)
            execution.conditions_met = conditions_met

            if not conditions_met:
                execution.status = "success"
                execution.completed_at = datetime.now(timezone.utc)
                self._persist_execution(execution)
                return execution

            # Deserialize actions
            actions = []
            for a in workflow.actions:
                if isinstance(a, dict):
                    actions.append(WorkflowAction(**a))
                else:
                    actions.append(a)

            action_results = self._execute_actions(actions, event)
            execution.actions_executed = action_results

            # Determine status based on action results
            if not action_results:
                execution.status = "success"
            else:
                failed = [r for r in action_results if r.get("status") == "failed"]
                if len(failed) == 0:
                    execution.status = "success"
                elif len(failed) == len(action_results):
                    execution.status = "failed"
                else:
                    execution.status = "partial"

        except Exception as exc:
            logger.error("Workflow %s execution error: %s", workflow.id, exc)
            execution.status = "failed"
            execution.error = str(exc)

        execution.completed_at = datetime.now(timezone.utc)
        self._persist_execution(execution)
        return execution

    def _check_conditions(
        self, event: Dict[str, Any], conditions: List[WorkflowCondition]
    ) -> bool:
        """Evaluate all conditions against the event. All conditions must pass (AND logic)."""
        if not conditions:
            return True

        for condition in conditions:
            op = condition.operator if isinstance(condition.operator, str) else condition.operator.value
            field = condition.field
            expected = condition.value

            # Resolve field value from event (supports nested dot notation)
            actual = self._resolve_field(event, field)

            if not self._evaluate_condition(actual, op, expected):
                return False

        return True

    def _resolve_field(self, event: Dict[str, Any], field: str) -> Any:
        """Resolve a field path (supports dot notation) from event dict."""
        parts = field.split(".")
        current: Any = event
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _evaluate_condition(self, actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate a single condition operator."""
        try:
            if operator == ConditionOperator.EQUALS.value:
                return actual == expected
            elif operator == ConditionOperator.NOT_EQUALS.value:
                return actual != expected
            elif operator == ConditionOperator.GREATER_THAN.value:
                return actual is not None and actual > expected
            elif operator == ConditionOperator.LESS_THAN.value:
                return actual is not None and actual < expected
            elif operator == ConditionOperator.CONTAINS.value:
                if actual is None:
                    return False
                return expected in actual
            elif operator == ConditionOperator.IN.value:
                if not isinstance(expected, list):
                    expected = [expected]
                return actual in expected
            elif operator == ConditionOperator.NOT_IN.value:
                if not isinstance(expected, list):
                    expected = [expected]
                return actual not in expected
            else:
                logger.warning("Unknown operator: %s", operator)
                return False
        except TypeError:
            return False

    def _execute_actions(
        self, actions: List[WorkflowAction], event: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute each action, return results list."""
        results: List[Dict[str, Any]] = []

        for action in actions:
            action_type = action.type if isinstance(action.type, str) else action.type.value
            result: Dict[str, Any] = {
                "action_type": action_type,
                "config": action.config,
                "status": "success",
                "error": None,
            }

            try:
                self._dispatch_action(action_type, action.config, event)
            except Exception as exc:
                logger.error("Action %s failed: %s", action_type, exc)
                result["status"] = "failed"
                result["error"] = str(exc)

            results.append(result)

        return results

    def _dispatch_action(
        self, action_type: str, config: Dict[str, Any], event: Dict[str, Any]
    ) -> None:
        """Dispatch a single action. Logs or delegates to integrations."""
        if action_type == ActionType.LOG.value:
            level = config.get("level", "info")
            message = config.get("message", "Workflow action triggered")
            getattr(logger, level, logger.info)("Workflow action LOG: %s | event=%s", message, event.get("event_type"))

        elif action_type == ActionType.SEND_SLACK_MESSAGE.value:
            channel = config.get("channel", "#general")
            template = config.get("template", "default")
            logger.info("Workflow action SLACK: channel=%s template=%s", channel, template)
            # Integration: delegate to NotificationEngine or SlackConnector if configured
            slack_token = os.environ.get("SLACK_BOT_TOKEN", "")
            if slack_token:
                try:
                    from core.connectors import SlackConnector
                    connector = SlackConnector(bot_token=slack_token)
                    msg = f"[ALDECI Workflow] {event.get('event_type', 'event')} triggered workflow action"
                    connector.post_message(channel_id=channel, text=msg)
                except Exception as exc:
                    logger.warning("Slack dispatch failed: %s", exc)

        elif action_type == ActionType.SEND_EMAIL.value:
            to = config.get("to", "")
            subject = config.get("subject", "ALDECI Workflow Alert")
            logger.info("Workflow action EMAIL: to=%s subject=%s", to, subject)
            smtp_host = os.environ.get("SMTP_HOST", "")
            if smtp_host and to:
                try:
                    from core.notifications import NotificationEngine
                    engine = NotificationEngine()
                    body = f"Workflow triggered for event: {event.get('event_type', 'unknown')}"
                    engine.send_email(to, subject, body)
                except Exception as exc:
                    logger.warning("Email dispatch failed: %s", exc)

        elif action_type == ActionType.CREATE_JIRA_TICKET.value:
            project = config.get("project", "SEC")
            issue_type = config.get("issue_type", "Bug")
            logger.info("Workflow action JIRA: project=%s issue_type=%s", project, issue_type)

        elif action_type == ActionType.ESCALATE.value:
            assignee = config.get("assignee", "")
            priority = config.get("priority", "high")
            logger.info("Workflow action ESCALATE: assignee=%s priority=%s", assignee, priority)

        elif action_type == ActionType.BLOCK_DEPLOY.value:
            reason = config.get("reason", "Security workflow block")
            logger.warning("Workflow action BLOCK_DEPLOY: reason=%s", reason)

        elif action_type == ActionType.RUN_PLAYBOOK.value:
            playbook_id = config.get("playbook_id", "")
            logger.info("Workflow action RUN_PLAYBOOK: playbook_id=%s", playbook_id)

        elif action_type == ActionType.UPDATE_FINDING.value:
            finding_id = config.get("finding_id", event.get("finding_id", ""))
            updates = config.get("updates", {})
            logger.info("Workflow action UPDATE_FINDING: finding_id=%s updates=%s", finding_id, updates)

        elif action_type == ActionType.WEBHOOK.value:
            url = config.get("url", "")
            logger.info("Workflow action WEBHOOK: url=%s", url)
            if url:
                try:
                    import requests

                    payload = {"event": event, "config": config}
                    requests.post(url, json=payload, timeout=10)  # nosemgrep: dynamic-urllib-use-detected
                except Exception as exc:
                    logger.warning("Webhook dispatch failed: %s", exc)
                    raise

        else:
            logger.warning("Unknown action type: %s", action_type)

    # ------------------------------------------------------------------
    # Execution history
    # ------------------------------------------------------------------

    def get_execution_history(
        self,
        org_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[WorkflowExecution]:
        """Return execution history, optionally filtered by org and workflow."""
        clauses: List[str] = []
        params: List[Any] = []

        if org_id is not None:
            clauses.append("org_id=?")
            params.append(org_id)
        if workflow_id is not None:
            clauses.append("workflow_id=?")
            params.append(workflow_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        sql = f"SELECT * FROM workflow_executions {where} ORDER BY started_at DESC LIMIT ?"  # nosec B608

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                rows = conn.execute(sql, params).fetchall()
            finally:
                conn.close()

        return [_execution_from_row(r) for r in rows]

    def _persist_execution(self, execution: WorkflowExecution) -> None:
        """Save execution record to SQLite."""
        started_iso = (
            execution.started_at.isoformat()
            if isinstance(execution.started_at, datetime)
            else execution.started_at
        )
        completed_iso = None
        if execution.completed_at:
            completed_iso = (
                execution.completed_at.isoformat()
                if isinstance(execution.completed_at, datetime)
                else execution.completed_at
            )

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO workflow_executions "
                    "(id, workflow_id, trigger_event, conditions_met, actions_executed, status, started_at, completed_at, error, org_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        execution.id,
                        execution.workflow_id,
                        json.dumps(execution.trigger_event, default=str),
                        1 if execution.conditions_met else 0,
                        json.dumps(execution.actions_executed, default=str),
                        execution.status,
                        started_iso,
                        completed_iso,
                        execution.error,
                        execution.org_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def get_templates(self) -> List[Workflow]:
        """Return built-in workflow templates."""
        result = []
        for tpl in _TEMPLATES:
            wf = Workflow(
                id=tpl["id"],
                name=tpl["name"],
                description=tpl.get("description"),
                trigger=tpl["trigger"],
                conditions=[WorkflowCondition(**c) for c in tpl.get("conditions", [])],
                actions=[WorkflowAction(**a) for a in tpl.get("actions", [])],
                enabled=tpl.get("enabled", True),
                org_id=tpl.get("org_id", "template"),
                created_by=tpl.get("created_by", "system"),
            )
            result.append(wf)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_workflow_stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Return workflow statistics for an org."""
        clauses: List[str] = []
        params: List[Any] = []

        if org_id is not None:
            clauses.append("org_id=?")
            params.append(org_id)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            conn = _get_db(self._db_path)
            try:
                wf_rows = conn.execute(
                    f"SELECT enabled, COUNT(*) as cnt FROM workflows {where} GROUP BY enabled",  # nosec B608
                    params,
                ).fetchall()

                exec_rows = conn.execute(
                    f"SELECT status, COUNT(*) as cnt FROM workflow_executions {where} GROUP BY status",  # nosec B608
                    params,
                ).fetchall()

                trigger_rows = conn.execute(
                    f"SELECT trigger, COUNT(*) as cnt FROM workflows {where} GROUP BY trigger",  # nosec B608
                    params,
                ).fetchall()
            finally:
                conn.close()

        total_workflows = sum(r["cnt"] for r in wf_rows)
        enabled_count = next((r["cnt"] for r in wf_rows if r["enabled"] == 1), 0)
        disabled_count = next((r["cnt"] for r in wf_rows if r["enabled"] == 0), 0)

        exec_stats: Dict[str, int] = {}
        total_executions = 0
        for r in exec_rows:
            exec_stats[r["status"]] = r["cnt"]
            total_executions += r["cnt"]

        trigger_breakdown: Dict[str, int] = {r["trigger"]: r["cnt"] for r in trigger_rows}

        return {
            "total_workflows": total_workflows,
            "enabled_workflows": enabled_count,
            "disabled_workflows": disabled_count,
            "total_executions": total_executions,
            "executions_by_status": exec_stats,
            "workflows_by_trigger": trigger_breakdown,
            "templates_available": len(_TEMPLATES),
        }
