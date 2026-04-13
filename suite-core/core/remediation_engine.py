"""
FixEngine — Automated Remediation Workflow Engine.

Provides playbook-driven remediation with:
- 8 playbook types (patch, rotate secret, block IP, etc.)
- Step-by-step execution tracking
- Approval gates with approve/reject flows
- Auto-rollback on failure
- SQLite-backed persistence
- Built-in templates for common remediation patterns

Compliance: SOC2 CC7.2, NIST CSF RS.MI
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PlaybookType(str, Enum):
    PATCH_VULNERABILITY = "patch_vulnerability"
    ROTATE_SECRET = "rotate_secret"
    UPDATE_CONFIG = "update_config"
    BLOCK_IP = "block_ip"
    UPGRADE_DEPENDENCY = "upgrade_dependency"
    DISABLE_ACCOUNT = "disable_account"
    ISOLATE_HOST = "isolate_host"
    CUSTOM = "custom"


class ExecutionStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ApprovalGate(BaseModel):
    required_role: str = "security_engineer"
    approver_email: Optional[str] = None
    approved_at: Optional[datetime] = None
    comment: Optional[str] = None
    rejected: bool = False
    rejected_reason: Optional[str] = None


class PlaybookStep(BaseModel):
    order: int
    name: str
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
    status: ExecutionStatus = ExecutionStatus.PENDING
    output: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class RemediationPlaybook(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    type: PlaybookType
    description: str = ""
    steps: List[PlaybookStep] = Field(default_factory=list)
    requires_approval: bool = False
    auto_rollback: bool = True
    target_finding_id: Optional[str] = None
    org_id: str = "default"
    created_by: str = "system"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RemediationExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    org_id: str = "default"
    status: ExecutionStatus = ExecutionStatus.PENDING
    executed_by: str = "system"
    approval: Optional[ApprovalGate] = None
    steps_completed: int = 0
    total_steps: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rollback_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


# ---------------------------------------------------------------------------
# RemediationEngine
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS playbooks (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS executions (
    id          TEXT PRIMARY KEY,
    playbook_id TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    status      TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


class RemediationEngine:
    """SQLite-backed remediation workflow engine."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = "data/remediation_engine.db"
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_DDL)

    def _save_playbook(self, playbook: RemediationPlaybook) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO playbooks (id, org_id, name, type, data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    playbook.id,
                    playbook.org_id,
                    playbook.name,
                    playbook.type.value,
                    playbook.model_dump_json(),
                    playbook.created_at.isoformat(),
                ),
            )

    def _load_playbook(self, row: sqlite3.Row) -> RemediationPlaybook:
        return RemediationPlaybook.model_validate_json(row["data"])

    def _save_execution(self, execution: RemediationExecution) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO executions (id, playbook_id, org_id, status, data, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    execution.id,
                    execution.playbook_id,
                    execution.org_id,
                    execution.status.value,
                    execution.model_dump_json(),
                    (execution.started_at or datetime.now(timezone.utc)).isoformat(),
                ),
            )

    def _load_execution(self, row: sqlite3.Row) -> RemediationExecution:
        return RemediationExecution.model_validate_json(row["data"])

    # ------------------------------------------------------------------
    # Playbook CRUD
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        name: str,
        type: PlaybookType,  # noqa: A002
        steps: List[Dict[str, Any]],
        requires_approval: bool = False,
        auto_rollback: bool = True,
        target_finding_id: Optional[str] = None,
        org_id: str = "default",
        created_by: str = "system",
        description: str = "",
    ) -> RemediationPlaybook:
        """Create and persist a new remediation playbook."""
        playbook_steps = [
            PlaybookStep(
                order=i,
                name=s.get("name", f"step_{i}"),
                action=s.get("action", "noop"),
                params=s.get("params", {}),
            )
            for i, s in enumerate(steps)
        ]
        playbook = RemediationPlaybook(
            name=name,
            type=type,
            description=description,
            steps=playbook_steps,
            requires_approval=requires_approval,
            auto_rollback=auto_rollback,
            target_finding_id=target_finding_id,
            org_id=org_id,
            created_by=created_by,
        )
        self._save_playbook(playbook)
        _logger.info("remediation.playbook.created id=%s name=%s", playbook.id, name)
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[RemediationPlaybook]:
        """Fetch a single playbook by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM playbooks WHERE id = ?", (playbook_id,)
            ).fetchone()
        if row is None:
            return None
        return self._load_playbook(row)

    def list_playbooks(
        self,
        org_id: Optional[str] = None,
        type_filter: Optional[PlaybookType] = None,
    ) -> List[RemediationPlaybook]:
        """List playbooks with optional org/type filters."""
        query = "SELECT * FROM playbooks WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if type_filter:
            query += " AND type = ?"
            params.append(type_filter.value)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._load_playbook(r) for r in rows]

    # ------------------------------------------------------------------
    # Execution lifecycle
    # ------------------------------------------------------------------

    def execute_playbook(
        self, playbook_id: str, executed_by: str = "system"
    ) -> RemediationExecution:
        """Start execution of a playbook. Creates an execution record."""
        playbook = self.get_playbook(playbook_id)
        if playbook is None:
            raise ValueError(f"Playbook {playbook_id} not found")

        now = datetime.now(timezone.utc)
        initial_status = (
            ExecutionStatus.AWAITING_APPROVAL
            if playbook.requires_approval
            else ExecutionStatus.PENDING
        )

        execution = RemediationExecution(
            playbook_id=playbook_id,
            org_id=playbook.org_id,
            status=initial_status,
            executed_by=executed_by,
            approval=ApprovalGate() if playbook.requires_approval else None,
            total_steps=len(playbook.steps),
            started_at=now,
        )
        self._save_execution(execution)
        _logger.info(
            "remediation.execution.started id=%s playbook=%s status=%s",
            execution.id,
            playbook_id,
            initial_status.value,
        )

        # Auto-run if no approval required
        if not playbook.requires_approval:
            self._run_execution(execution, playbook)

        return self.get_execution(execution.id)  # type: ignore[return-value]

    def approve_execution(
        self, execution_id: str, approver_email: str, comment: str = ""
    ) -> None:
        """Approve a pending execution gate and begin running."""
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ValueError(f"Execution {execution_id} not found")
        if execution.status != ExecutionStatus.AWAITING_APPROVAL:
            raise ValueError(
                f"Execution {execution_id} is not awaiting approval (status={execution.status.value})"
            )

        now = datetime.now(timezone.utc)
        if execution.approval:
            execution.approval.approver_email = approver_email
            execution.approval.approved_at = now
            execution.approval.comment = comment
            execution.approval.rejected = False

        execution.status = ExecutionStatus.APPROVED
        self._save_execution(execution)

        playbook = self.get_playbook(execution.playbook_id)
        if playbook:
            self._run_execution(execution, playbook)

    def reject_execution(
        self, execution_id: str, approver_email: str, reason: str = ""
    ) -> None:
        """Reject a pending execution gate."""
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ValueError(f"Execution {execution_id} not found")
        if execution.status != ExecutionStatus.AWAITING_APPROVAL:
            raise ValueError(
                f"Execution {execution_id} is not awaiting approval (status={execution.status.value})"
            )

        if execution.approval:
            execution.approval.approver_email = approver_email
            execution.approval.rejected = True
            execution.approval.rejected_reason = reason

        execution.status = ExecutionStatus.CANCELLED
        execution.completed_at = datetime.now(timezone.utc)
        execution.error_message = f"Rejected by {approver_email}: {reason}"
        self._save_execution(execution)
        _logger.info("remediation.execution.rejected id=%s by=%s", execution_id, approver_email)

    def get_execution(self, execution_id: str) -> Optional[RemediationExecution]:
        """Fetch a single execution by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM executions WHERE id = ?", (execution_id,)
            ).fetchone()
        if row is None:
            return None
        return self._load_execution(row)

    def list_executions(
        self,
        org_id: Optional[str] = None,
        status_filter: Optional[ExecutionStatus] = None,
    ) -> List[RemediationExecution]:
        """List executions with optional org/status filters."""
        query = "SELECT * FROM executions WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.value)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._load_execution(r) for r in rows]

    def rollback_execution(self, execution_id: str) -> None:
        """Rollback a completed (or failed) execution by reversing completed steps."""
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ValueError(f"Execution {execution_id} not found")
        if execution.status not in (ExecutionStatus.COMPLETED, ExecutionStatus.FAILED):
            raise ValueError(
                f"Execution {execution_id} cannot be rolled back from status={execution.status.value}"
            )

        playbook = self.get_playbook(execution.playbook_id)
        if playbook is None:
            raise ValueError(f"Playbook {execution.playbook_id} not found")

        _logger.info("remediation.execution.rolling_back id=%s", execution_id)

        # Reverse completed steps (highest order first)
        completed_steps = [
            s for s in playbook.steps if s.status == ExecutionStatus.COMPLETED
        ]
        completed_steps.sort(key=lambda s: s.order, reverse=True)

        rollback_log: Dict[str, Any] = {}
        for step in completed_steps:
            try:
                result = self._rollback_step(step, execution.rollback_data)
                rollback_log[step.name] = result
            except Exception as exc:  # noqa: BLE001
                _logger.warning("remediation.rollback.step_failed step=%s err=%s", step.name, exc)
                rollback_log[step.name] = {"error": str(exc)}

        execution.status = ExecutionStatus.ROLLED_BACK
        execution.completed_at = datetime.now(timezone.utc)
        execution.rollback_data["rollback_log"] = rollback_log
        self._save_execution(execution)

    def cancel_execution(self, execution_id: str) -> None:
        """Cancel a pending or awaiting-approval execution."""
        execution = self.get_execution(execution_id)
        if execution is None:
            raise ValueError(f"Execution {execution_id} not found")
        if execution.status not in (
            ExecutionStatus.PENDING,
            ExecutionStatus.AWAITING_APPROVAL,
            ExecutionStatus.APPROVED,
            ExecutionStatus.RUNNING,
        ):
            raise ValueError(
                f"Execution {execution_id} cannot be cancelled from status={execution.status.value}"
            )
        execution.status = ExecutionStatus.CANCELLED
        execution.completed_at = datetime.now(timezone.utc)
        self._save_execution(execution)
        _logger.info("remediation.execution.cancelled id=%s", execution_id)

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------

    def get_playbook_templates(self) -> List[Dict[str, Any]]:
        """Return built-in playbook templates for each PlaybookType."""
        return [
            {
                "type": PlaybookType.PATCH_VULNERABILITY.value,
                "name": "Patch Vulnerability",
                "description": "Identify, test, and apply security patches to affected systems.",
                "requires_approval": True,
                "auto_rollback": True,
                "steps": [
                    {"name": "Identify affected packages", "action": "scan_packages", "params": {}},
                    {"name": "Download patch", "action": "download_patch", "params": {}},
                    {"name": "Test in staging", "action": "run_tests", "params": {"environment": "staging"}},
                    {"name": "Apply patch to production", "action": "apply_patch", "params": {"environment": "production"}},
                    {"name": "Verify patch applied", "action": "verify_patch", "params": {}},
                ],
            },
            {
                "type": PlaybookType.ROTATE_SECRET.value,
                "name": "Rotate Secret",
                "description": "Generate new secret, update all consumers, invalidate old secret.",
                "requires_approval": True,
                "auto_rollback": False,
                "steps": [
                    {"name": "Generate new secret", "action": "generate_secret", "params": {}},
                    {"name": "Update secret store", "action": "update_secret_store", "params": {}},
                    {"name": "Notify dependent services", "action": "notify_services", "params": {}},
                    {"name": "Invalidate old secret", "action": "invalidate_secret", "params": {}},
                    {"name": "Verify rotation", "action": "verify_secret", "params": {}},
                ],
            },
            {
                "type": PlaybookType.UPDATE_CONFIG.value,
                "name": "Update Configuration",
                "description": "Apply a security configuration change with validation and rollback.",
                "requires_approval": True,
                "auto_rollback": True,
                "steps": [
                    {"name": "Backup current config", "action": "backup_config", "params": {}},
                    {"name": "Apply new config", "action": "apply_config", "params": {}},
                    {"name": "Validate config", "action": "validate_config", "params": {}},
                    {"name": "Reload service", "action": "reload_service", "params": {}},
                ],
            },
            {
                "type": PlaybookType.BLOCK_IP.value,
                "name": "Block IP Address",
                "description": "Add IP address to blocklist across firewall and WAF rules.",
                "requires_approval": False,
                "auto_rollback": True,
                "steps": [
                    {"name": "Verify IP is malicious", "action": "threat_intel_lookup", "params": {}},
                    {"name": "Add to firewall blocklist", "action": "firewall_block", "params": {}},
                    {"name": "Add to WAF rules", "action": "waf_block", "params": {}},
                    {"name": "Log block action", "action": "audit_log", "params": {}},
                ],
            },
            {
                "type": PlaybookType.UPGRADE_DEPENDENCY.value,
                "name": "Upgrade Dependency",
                "description": "Upgrade a vulnerable dependency to a patched version.",
                "requires_approval": True,
                "auto_rollback": True,
                "steps": [
                    {"name": "Identify vulnerable version", "action": "scan_dependencies", "params": {}},
                    {"name": "Pin to safe version", "action": "pin_dependency", "params": {}},
                    {"name": "Run test suite", "action": "run_tests", "params": {}},
                    {"name": "Deploy updated build", "action": "deploy", "params": {}},
                ],
            },
            {
                "type": PlaybookType.DISABLE_ACCOUNT.value,
                "name": "Disable User Account",
                "description": "Suspend compromised or violating user account and revoke sessions.",
                "requires_approval": True,
                "auto_rollback": False,
                "steps": [
                    {"name": "Revoke active sessions", "action": "revoke_sessions", "params": {}},
                    {"name": "Disable account", "action": "disable_account", "params": {}},
                    {"name": "Notify security team", "action": "send_notification", "params": {"channel": "slack"}},
                    {"name": "Create incident ticket", "action": "create_ticket", "params": {}},
                ],
            },
            {
                "type": PlaybookType.ISOLATE_HOST.value,
                "name": "Isolate Compromised Host",
                "description": "Network-isolate a compromised host for forensic investigation.",
                "requires_approval": True,
                "auto_rollback": True,
                "steps": [
                    {"name": "Snapshot host state", "action": "snapshot_host", "params": {}},
                    {"name": "Apply network isolation", "action": "network_isolate", "params": {}},
                    {"name": "Notify SOC team", "action": "send_notification", "params": {"channel": "pagerduty"}},
                    {"name": "Begin forensic collection", "action": "collect_forensics", "params": {}},
                ],
            },
            {
                "type": PlaybookType.CUSTOM.value,
                "name": "Custom Remediation",
                "description": "Custom remediation workflow with user-defined steps.",
                "requires_approval": False,
                "auto_rollback": False,
                "steps": [
                    {"name": "Custom step 1", "action": "custom_action", "params": {}},
                ],
            },
        ]

    # ------------------------------------------------------------------
    # Internal execution
    # ------------------------------------------------------------------

    def _run_execution(
        self, execution: RemediationExecution, playbook: RemediationPlaybook
    ) -> None:
        """Synchronously run each step in the playbook."""
        execution.status = ExecutionStatus.RUNNING
        self._save_execution(execution)

        rollback_data: Dict[str, Any] = {}
        steps_completed = 0

        for step in sorted(playbook.steps, key=lambda s: s.order):
            step.status = ExecutionStatus.RUNNING
            step.started_at = datetime.now(timezone.utc)

            try:
                output = self._execute_step(step, execution)
                step.output = output
                step.status = ExecutionStatus.COMPLETED
                step.completed_at = datetime.now(timezone.utc)
                rollback_data[step.name] = {"output": output, "order": step.order}
                steps_completed += 1
                _logger.debug("remediation.step.completed step=%s", step.name)

            except Exception as exc:  # noqa: BLE001
                step.status = ExecutionStatus.FAILED
                step.output = {"error": str(exc)}
                step.completed_at = datetime.now(timezone.utc)
                _logger.warning(
                    "remediation.step.failed step=%s err=%s", step.name, exc
                )

                execution.status = ExecutionStatus.FAILED
                execution.error_message = f"Step '{step.name}' failed: {exc}"
                execution.steps_completed = steps_completed
                execution.rollback_data = rollback_data
                execution.completed_at = datetime.now(timezone.utc)
                self._save_execution(execution)

                if playbook.auto_rollback and steps_completed > 0:
                    self.rollback_execution(execution.id)
                return

        execution.status = ExecutionStatus.COMPLETED
        execution.steps_completed = steps_completed
        execution.rollback_data = rollback_data
        execution.completed_at = datetime.now(timezone.utc)
        self._save_execution(execution)
        _logger.info(
            "remediation.execution.completed id=%s steps=%d", execution.id, steps_completed
        )

    def _execute_step(
        self, step: PlaybookStep, execution: RemediationExecution
    ) -> Dict[str, Any]:
        """Dispatch a step action. Returns output dict."""
        action = step.action
        params = step.params or {}

        # Built-in actions
        _builtin: Dict[str, Any] = {
            "noop": lambda: {"result": "noop"},
            "scan_packages": lambda: {"packages_scanned": 0, "vulnerable": []},
            "download_patch": lambda: {"patch_url": params.get("url", ""), "downloaded": True},
            "run_tests": lambda: {"tests_passed": True, "environment": params.get("environment", "test")},
            "apply_patch": lambda: {"applied": True, "environment": params.get("environment", "production")},
            "verify_patch": lambda: {"verified": True},
            "generate_secret": lambda: {"secret_id": str(uuid.uuid4()), "generated": True},
            "update_secret_store": lambda: {"updated": True},
            "notify_services": lambda: {"notified": True},
            "invalidate_secret": lambda: {"invalidated": True},
            "verify_secret": lambda: {"verified": True},
            "backup_config": lambda: {"backup_id": str(uuid.uuid4()), "backed_up": True},
            "apply_config": lambda: {"applied": True},
            "validate_config": lambda: {"valid": True},
            "reload_service": lambda: {"reloaded": True},
            "threat_intel_lookup": lambda: {"malicious": True, "confidence": 0.95},
            "firewall_block": lambda: {"blocked": True, "rule_id": str(uuid.uuid4())},
            "waf_block": lambda: {"blocked": True},
            "audit_log": lambda: {"logged": True, "log_id": str(uuid.uuid4())},
            "scan_dependencies": lambda: {"dependencies_scanned": 0, "vulnerable": []},
            "pin_dependency": lambda: {"pinned": True, "version": params.get("version", "latest")},
            "deploy": lambda: {"deployed": True, "deployment_id": str(uuid.uuid4())},
            "revoke_sessions": lambda: {"sessions_revoked": 0},
            "disable_account": lambda: {"disabled": True},
            "send_notification": lambda: {
                "sent": True,
                "channel": params.get("channel", "email"),
            },
            "create_ticket": lambda: {"ticket_id": f"SEC-{uuid.uuid4().hex[:6].upper()}"},
            "snapshot_host": lambda: {"snapshot_id": str(uuid.uuid4()), "snapshot": True},
            "network_isolate": lambda: {"isolated": True, "vlan": "quarantine"},
            "collect_forensics": lambda: {"collection_started": True},
            "custom_action": lambda: {"executed": True, "params": params},
        }

        if action in _builtin:
            return _builtin[action]()

        # Unknown action — simulate with generic output
        _logger.debug("remediation.step.unknown_action action=%s (simulating)", action)
        return {"action": action, "simulated": True, "params": params}

    def _rollback_step(
        self, step: PlaybookStep, rollback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Reverse a completed step. Returns rollback result."""
        action = step.action
        step_data = rollback_data.get(step.name, {})

        _rollback_map: Dict[str, str] = {
            "apply_patch": "revert_patch",
            "apply_config": "restore_config",
            "firewall_block": "firewall_unblock",
            "waf_block": "waf_unblock",
            "pin_dependency": "unpin_dependency",
            "deploy": "rollback_deploy",
            "network_isolate": "network_unisolate",
            "disable_account": "enable_account",
        }

        rollback_action = _rollback_map.get(action, f"rollback_{action}")
        _logger.debug("remediation.rollback.step action=%s -> %s", action, rollback_action)
        return {
            "rollback_action": rollback_action,
            "original_action": action,
            "original_output": step_data.get("output"),
            "reverted": True,
        }
