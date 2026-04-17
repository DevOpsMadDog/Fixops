"""
SOAR Engine — Security Orchestration, Automation and Response for ALDECI.

Provides automated playbook execution triggered by security events:
- 7 trigger types: FINDING_CRITICAL, FINDING_HIGH, INCIDENT_CREATED, SLA_BREACH,
  ANOMALY_DETECTED, INSIDER_THREAT, COMPLIANCE_GAP
- 9 action types: CREATE_TICKET, SEND_ALERT, BLOCK_IP, QUARANTINE_HOST,
  ROTATE_CREDENTIALS, RUN_SCAN, ESCALATE, UPDATE_FIREWALL, COLLECT_EVIDENCE
- SQLite-backed, thread-safe, multi-tenant (per org_id)
- 7 built-in default playbooks (one per trigger type)
- MTTR (Mean Time To Respond) tracking

Compliance: NIST CSF RS.AN-1, SOC2 CC7.2, ISO 27035
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

# Default DB path (data/ directory alongside the running process)
_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "soar_engine.db")


# ============================================================================
# ENUMS
# ============================================================================


class PlaybookTrigger(str, Enum):
    """Events that can trigger a SOAR playbook."""

    FINDING_CRITICAL = "finding_critical"
    FINDING_HIGH = "finding_high"
    INCIDENT_CREATED = "incident_created"
    SLA_BREACH = "sla_breach"
    ANOMALY_DETECTED = "anomaly_detected"
    INSIDER_THREAT = "insider_threat"
    COMPLIANCE_GAP = "compliance_gap"


class SOARAction(str, Enum):
    """Actions that a SOAR playbook can execute."""

    CREATE_TICKET = "create_ticket"
    SEND_ALERT = "send_alert"
    BLOCK_IP = "block_ip"
    QUARANTINE_HOST = "quarantine_host"
    ROTATE_CREDENTIALS = "rotate_credentials"
    RUN_SCAN = "run_scan"
    ESCALATE = "escalate"
    UPDATE_FIREWALL = "update_firewall"
    COLLECT_EVIDENCE = "collect_evidence"


class ExecutionStatus(str, Enum):
    """Status of a SOAR playbook execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class SOARPlaybook(BaseModel):
    """A SOAR playbook definition with trigger, conditions, and actions."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    trigger: PlaybookTrigger
    conditions: Dict[str, Any] = Field(default_factory=dict)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True
    execution_count: int = 0
    avg_response_seconds: float = 0.0
    org_id: str = "default"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SOARExecution(BaseModel):
    """A record of a SOAR playbook execution."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    playbook_id: str
    trigger_event: Dict[str, Any] = Field(default_factory=dict)
    actions_taken: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    org_id: str = "default"
    error_message: Optional[str] = None


class PlaybookStats(BaseModel):
    """Aggregate statistics for SOAR playbooks in an org."""

    org_id: str
    total_playbooks: int
    enabled_playbooks: int
    total_executions: int
    completed_executions: int
    failed_executions: int
    avg_response_seconds: float
    executions_by_trigger: Dict[str, int]


# ============================================================================
# SOAR ENGINE
# ============================================================================


class SOAREngine:
    """
    SQLite-backed SOAR engine for automated security response.

    Thread-safe via a per-instance lock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_playbooks()

    # -----------------------------------------------------------------------
    # DB INIT
    # -----------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS soar_playbooks (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    trigger     TEXT NOT NULL,
                    conditions  TEXT NOT NULL DEFAULT '{}',
                    actions     TEXT NOT NULL DEFAULT '[]',
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    execution_count INTEGER NOT NULL DEFAULT 0,
                    avg_response_seconds REAL NOT NULL DEFAULT 0.0,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS soar_executions (
                    id              TEXT PRIMARY KEY,
                    playbook_id     TEXT NOT NULL,
                    trigger_event   TEXT NOT NULL DEFAULT '{}',
                    actions_taken   TEXT NOT NULL DEFAULT '[]',
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    org_id          TEXT NOT NULL DEFAULT 'default',
                    error_message   TEXT,
                    FOREIGN KEY (playbook_id) REFERENCES soar_playbooks(id)
                );

                CREATE INDEX IF NOT EXISTS idx_soar_playbooks_org_trigger
                    ON soar_playbooks(org_id, trigger);
                CREATE INDEX IF NOT EXISTS idx_soar_executions_org
                    ON soar_executions(org_id, started_at);
                CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook
                    ON soar_executions(playbook_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # -----------------------------------------------------------------------
    # DEFAULT PLAYBOOKS
    # -----------------------------------------------------------------------

    def _seed_default_playbooks(self) -> None:
        """Insert built-in playbooks if none exist yet (idempotent, global scope)."""
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT COUNT(*) FROM soar_playbooks WHERE org_id = 'default'"
            ).fetchone()[0]
            if existing > 0:
                return

        defaults = [
            SOARPlaybook(
                id="soar-default-critical",
                name="Critical Finding Response",
                trigger=PlaybookTrigger.FINDING_CRITICAL,
                conditions={"severity": "critical"},
                actions=[
                    {"action": SOARAction.CREATE_TICKET, "priority": "P1", "assignee": "soc-team"},
                    {"action": SOARAction.SEND_ALERT, "channel": "pagerduty", "escalation": True},
                    {"action": SOARAction.COLLECT_EVIDENCE, "scope": "full"},
                    {"action": SOARAction.ESCALATE, "to": "ciso"},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-high",
                name="High Finding Response",
                trigger=PlaybookTrigger.FINDING_HIGH,
                conditions={"severity": "high"},
                actions=[
                    {"action": SOARAction.CREATE_TICKET, "priority": "P2", "assignee": "soc-team"},
                    {"action": SOARAction.SEND_ALERT, "channel": "slack", "urgency": "high"},
                    {"action": SOARAction.RUN_SCAN, "scope": "targeted"},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-incident",
                name="Incident Created Response",
                trigger=PlaybookTrigger.INCIDENT_CREATED,
                conditions={},
                actions=[
                    {"action": SOARAction.CREATE_TICKET, "priority": "P1", "template": "incident"},
                    {"action": SOARAction.SEND_ALERT, "channel": "all", "message": "Incident opened"},
                    {"action": SOARAction.COLLECT_EVIDENCE, "scope": "full"},
                    {"action": SOARAction.ESCALATE, "to": "incident-commander"},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-sla",
                name="SLA Breach Response",
                trigger=PlaybookTrigger.SLA_BREACH,
                conditions={"breach_type": "deadline"},
                actions=[
                    {"action": SOARAction.SEND_ALERT, "channel": "managers", "urgency": "critical"},
                    {"action": SOARAction.ESCALATE, "to": "vp-engineering"},
                    {"action": SOARAction.CREATE_TICKET, "priority": "P1", "label": "sla-breach"},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-anomaly",
                name="Anomaly Detected Response",
                trigger=PlaybookTrigger.ANOMALY_DETECTED,
                conditions={"severity": ["high", "critical"]},
                actions=[
                    {"action": SOARAction.RUN_SCAN, "scope": "affected-systems"},
                    {"action": SOARAction.COLLECT_EVIDENCE, "scope": "network-logs"},
                    {"action": SOARAction.SEND_ALERT, "channel": "soc", "urgency": "high"},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-insider",
                name="Insider Threat Response",
                trigger=PlaybookTrigger.INSIDER_THREAT,
                conditions={},
                actions=[
                    {"action": SOARAction.COLLECT_EVIDENCE, "scope": "user-activity"},
                    {"action": SOARAction.QUARANTINE_HOST, "method": "network-isolation"},
                    {"action": SOARAction.ROTATE_CREDENTIALS, "scope": "affected-user"},
                    {"action": SOARAction.ESCALATE, "to": "hr-legal"},
                    {"action": SOARAction.CREATE_TICKET, "priority": "P1", "confidential": True},
                ],
                org_id="default",
            ),
            SOARPlaybook(
                id="soar-default-compliance",
                name="Compliance Gap Response",
                trigger=PlaybookTrigger.COMPLIANCE_GAP,
                conditions={},
                actions=[
                    {"action": SOARAction.CREATE_TICKET, "priority": "P2", "label": "compliance"},
                    {"action": SOARAction.SEND_ALERT, "channel": "compliance-team"},
                    {"action": SOARAction.COLLECT_EVIDENCE, "scope": "compliance-artifacts"},
                ],
                org_id="default",
            ),
        ]

        for pb in defaults:
            self._insert_playbook(pb)

    # -----------------------------------------------------------------------
    # INTERNAL HELPERS
    # -----------------------------------------------------------------------

    def _insert_playbook(self, pb: SOARPlaybook) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO soar_playbooks
                        (id, name, trigger, conditions, actions, enabled,
                         execution_count, avg_response_seconds, org_id, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pb.id, pb.name, pb.trigger.value,
                        json.dumps(pb.conditions), json.dumps(pb.actions),
                        int(pb.enabled), pb.execution_count, pb.avg_response_seconds,
                        pb.org_id,
                        pb.created_at.isoformat(),
                        pb.updated_at.isoformat(),
                    ),
                )

    def _row_to_playbook(self, row: sqlite3.Row) -> SOARPlaybook:
        return SOARPlaybook(
            id=row["id"],
            name=row["name"],
            trigger=PlaybookTrigger(row["trigger"]),
            conditions=json.loads(row["conditions"]),
            actions=json.loads(row["actions"]),
            enabled=bool(row["enabled"]),
            execution_count=row["execution_count"],
            avg_response_seconds=row["avg_response_seconds"],
            org_id=row["org_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    def _row_to_execution(self, row: sqlite3.Row) -> SOARExecution:
        return SOARExecution(
            id=row["id"],
            playbook_id=row["playbook_id"],
            trigger_event=json.loads(row["trigger_event"]),
            actions_taken=json.loads(row["actions_taken"]),
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=(
                datetime.fromisoformat(row["completed_at"])
                if row["completed_at"] else None
            ),
            status=ExecutionStatus(row["status"]),
            org_id=row["org_id"],
            error_message=row["error_message"],
        )

    def _conditions_match(self, conditions: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Return True if all conditions match event fields (subset check)."""
        for key, expected in conditions.items():
            actual = event.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            else:
                if actual != expected:
                    return False
        return True

    def _simulate_action(self, action_def: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate executing a single action. Returns result dict."""
        action_type = action_def.get("action", "")
        result: Dict[str, Any] = {
            "action": action_type,
            "status": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        # Simulate action-specific outcomes
        if action_type == SOARAction.CREATE_TICKET:
            result["ticket_id"] = f"TKT-{uuid.uuid4().hex[:8].upper()}"
        elif action_type == SOARAction.SEND_ALERT:
            result["delivered_to"] = action_def.get("channel", "default")
        elif action_type == SOARAction.BLOCK_IP:
            result["blocked_ip"] = context.get("ip_address", "unknown")
        elif action_type == SOARAction.QUARANTINE_HOST:
            result["quarantined_host"] = context.get("host", "unknown")
        elif action_type == SOARAction.ROTATE_CREDENTIALS:
            result["rotated_for"] = context.get("user", "unknown")
        elif action_type == SOARAction.RUN_SCAN:
            result["scan_id"] = f"SCAN-{uuid.uuid4().hex[:8].upper()}"
        elif action_type == SOARAction.ESCALATE:
            result["escalated_to"] = action_def.get("to", "soc-team")
        elif action_type == SOARAction.UPDATE_FIREWALL:
            result["rule_id"] = f"FW-{uuid.uuid4().hex[:6].upper()}"
        elif action_type == SOARAction.COLLECT_EVIDENCE:
            result["evidence_id"] = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        return result

    def _run_playbook_actions(
        self,
        playbook: SOARPlaybook,
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Execute all actions in a playbook and return results."""
        results = []
        for action_def in playbook.actions:
            try:
                result = self._simulate_action(action_def, context)
                results.append(result)
            except Exception as exc:
                _logger.warning("Action %s failed: %s", action_def.get("action"), exc)
                results.append({
                    "action": action_def.get("action", "unknown"),
                    "status": "failed",
                    "error": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return results

    def _update_playbook_stats(
        self, playbook_id: str, elapsed_seconds: float
    ) -> None:
        """Incrementally update execution_count and rolling avg_response_seconds."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT execution_count, avg_response_seconds FROM soar_playbooks WHERE id = ?",
                    (playbook_id,),
                ).fetchone()
                if not row:
                    return
                count = row["execution_count"]
                old_avg = row["avg_response_seconds"]
                new_count = count + 1
                new_avg = ((old_avg * count) + elapsed_seconds) / new_count
                conn.execute(
                    """
                    UPDATE soar_playbooks
                       SET execution_count = ?,
                           avg_response_seconds = ?,
                           updated_at = ?
                     WHERE id = ?
                    """,
                    (new_count, new_avg, datetime.now(timezone.utc).isoformat(), playbook_id),
                )

    # -----------------------------------------------------------------------
    # PUBLIC API
    # -----------------------------------------------------------------------

    def create_playbook(
        self,
        name: str,
        trigger: PlaybookTrigger,
        actions: List[Dict[str, Any]],
        conditions: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
        org_id: str = "default",
    ) -> SOARPlaybook:
        """Define a new automated response playbook."""
        pb = SOARPlaybook(
            name=name,
            trigger=trigger,
            conditions=conditions or {},
            actions=actions,
            enabled=enabled,
            org_id=org_id,
        )
        self._insert_playbook(pb)
        _logger.info("Created SOAR playbook %s (%s) for org %s", pb.id, name, org_id)
        return pb

    def get_playbook(self, playbook_id: str, org_id: str = "default") -> Optional[SOARPlaybook]:
        """Retrieve a single playbook by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM soar_playbooks WHERE id = ? AND org_id = ?",
                (playbook_id, org_id),
            ).fetchone()
        return self._row_to_playbook(row) if row else None

    def list_playbooks(self, org_id: str = "default") -> List[SOARPlaybook]:
        """List all playbooks for an org."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM soar_playbooks WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def evaluate_trigger(
        self, event: Dict[str, Any], org_id: str = "default"
    ) -> List[SOARExecution]:
        """
        Match an incoming event against enabled playbooks and execute matches.

        event must contain a 'trigger' key with a PlaybookTrigger value.
        Returns list of SOARExecution records for all playbooks that fired.
        """
        trigger_value = event.get("trigger")
        if not trigger_value:
            _logger.warning("evaluate_trigger called without 'trigger' in event")
            return []

        try:
            trigger = PlaybookTrigger(trigger_value)
        except ValueError:
            _logger.warning("Unknown trigger value: %s", trigger_value)
            return []

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM soar_playbooks
                 WHERE org_id = ? AND trigger = ? AND enabled = 1
                """,
                (org_id, trigger.value),
            ).fetchall()

        playbooks = [self._row_to_playbook(r) for r in rows]
        executions = []

        for pb in playbooks:
            if not self._conditions_match(pb.conditions, event):
                _logger.debug("Playbook %s conditions not met for event", pb.id)
                continue
            execution = self._execute_playbook_internal(pb, context=event, org_id=org_id)
            executions.append(execution)

        return executions

    def execute_playbook(
        self,
        playbook_id: str,
        context: Optional[Dict[str, Any]] = None,
        org_id: str = "default",
    ) -> SOARExecution:
        """
        Manually execute a playbook by ID regardless of trigger conditions.

        Raises ValueError if the playbook does not exist or is not enabled.
        """
        pb = self.get_playbook(playbook_id, org_id=org_id)
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found for org '{org_id}'")
        if not pb.enabled:
            raise ValueError(f"Playbook '{playbook_id}' is disabled")
        return self._execute_playbook_internal(pb, context=context or {}, org_id=org_id)

    def _execute_playbook_internal(
        self,
        playbook: SOARPlaybook,
        context: Dict[str, Any],
        org_id: str,
    ) -> SOARExecution:
        """Internal: run a playbook and persist the execution record."""
        started_at = datetime.now(timezone.utc)
        exec_id = str(uuid.uuid4())

        # Insert pending execution record
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO soar_executions
                        (id, playbook_id, trigger_event, actions_taken,
                         started_at, completed_at, status, org_id, error_message)
                    VALUES (?, ?, ?, ?, ?, NULL, ?, ?, NULL)
                    """,
                    (
                        exec_id, playbook.id,
                        json.dumps(context), json.dumps([]),
                        started_at.isoformat(),
                        ExecutionStatus.RUNNING.value,
                        org_id,
                    ),
                )

        # Execute actions
        t0 = time.monotonic()
        actions_taken: List[Dict[str, Any]] = []
        final_status = ExecutionStatus.COMPLETED
        error_msg: Optional[str] = None

        try:
            actions_taken = self._run_playbook_actions(playbook, context)
            failed = [a for a in actions_taken if a.get("status") == "failed"]
            if failed and len(failed) < len(actions_taken):
                final_status = ExecutionStatus.PARTIAL
            elif failed:
                final_status = ExecutionStatus.FAILED
        except Exception as exc:
            _logger.exception("Playbook %s execution failed", playbook.id)
            final_status = ExecutionStatus.FAILED
            error_msg = str(exc)

        completed_at = datetime.now(timezone.utc)
        elapsed = time.monotonic() - t0

        # Persist final execution state
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE soar_executions
                       SET actions_taken = ?,
                           completed_at = ?,
                           status = ?,
                           error_message = ?
                     WHERE id = ?
                    """,
                    (
                        json.dumps(actions_taken),
                        completed_at.isoformat(),
                        final_status.value,
                        error_msg,
                        exec_id,
                    ),
                )

        # Update playbook stats
        self._update_playbook_stats(playbook.id, elapsed)

        _logger.info(
            "SOAR execution %s for playbook %s finished in %.3fs (%s)",
            exec_id, playbook.id, elapsed, final_status.value,
        )

        return SOARExecution(
            id=exec_id,
            playbook_id=playbook.id,
            trigger_event=context,
            actions_taken=actions_taken,
            started_at=started_at,
            completed_at=completed_at,
            status=final_status,
            org_id=org_id,
            error_message=error_msg,
        )

    def get_execution_history(
        self,
        org_id: str = "default",
        limit: int = 100,
        playbook_id: Optional[str] = None,
    ) -> List[SOARExecution]:
        """Return past executions for an org, optionally filtered by playbook."""
        query = "SELECT * FROM soar_executions WHERE org_id = ?"
        params: list = [org_id]
        if playbook_id:
            query += " AND playbook_id = ?"
            params.append(playbook_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_execution(r) for r in rows]

    def get_playbook_stats(self, org_id: str = "default") -> PlaybookStats:
        """Return aggregate playbook statistics for an org."""
        with self._connect() as conn:
            pb_row = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) as enabled_count,
                    COALESCE(AVG(avg_response_seconds), 0.0) as avg_resp
                FROM soar_playbooks WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()

            exec_row = conn.execute(
                """
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
                FROM soar_executions WHERE org_id = ?
                """,
                (org_id,),
            ).fetchone()

            trigger_rows = conn.execute(
                """
                SELECT p.trigger, COUNT(e.id) as cnt
                FROM soar_executions e
                JOIN soar_playbooks p ON p.id = e.playbook_id
                WHERE e.org_id = ?
                GROUP BY p.trigger
                """,
                (org_id,),
            ).fetchall()

        executions_by_trigger = {r["trigger"]: r["cnt"] for r in trigger_rows}

        return PlaybookStats(
            org_id=org_id,
            total_playbooks=pb_row["total"] or 0,
            enabled_playbooks=pb_row["enabled_count"] or 0,
            total_executions=exec_row["total"] or 0,
            completed_executions=exec_row["completed"] or 0,
            failed_executions=exec_row["failed"] or 0,
            avg_response_seconds=pb_row["avg_resp"] or 0.0,
            executions_by_trigger=executions_by_trigger,
        )

    def get_mean_time_to_respond(self, org_id: str = "default") -> float:
        """
        Return MTTR in seconds — average time from started_at to completed_at
        across all completed/partial executions for the org.

        Returns 0.0 if no executions exist.
        """
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT AVG(
                    (julianday(completed_at) - julianday(started_at)) * 86400.0
                ) as mttr
                FROM soar_executions
                WHERE org_id = ?
                  AND completed_at IS NOT NULL
                  AND status IN ('completed', 'partial')
                """,
                (org_id,),
            ).fetchone()
        return row["mttr"] if row and row["mttr"] is not None else 0.0

    def disable_playbook(self, playbook_id: str, org_id: str = "default") -> bool:
        """Disable a playbook. Returns True if found and updated."""
        with self._lock:
            with self._connect() as conn:
                result = conn.execute(
                    "UPDATE soar_playbooks SET enabled = 0, updated_at = ? WHERE id = ? AND org_id = ?",
                    (datetime.now(timezone.utc).isoformat(), playbook_id, org_id),
                )
        return result.rowcount > 0

    def enable_playbook(self, playbook_id: str, org_id: str = "default") -> bool:
        """Enable a playbook. Returns True if found and updated."""
        with self._lock:
            with self._connect() as conn:
                result = conn.execute(
                    "UPDATE soar_playbooks SET enabled = 1, updated_at = ? WHERE id = ? AND org_id = ?",
                    (datetime.now(timezone.utc).isoformat(), playbook_id, org_id),
                )
        return result.rowcount > 0
