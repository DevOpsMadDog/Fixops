"""
Security Playbook Engine — ALDECI.

Automated response playbooks for common security scenarios.

Features:
- SQLite WAL-mode persistence at data/playbooks.db
- Multi-tenant (per org_id) playbook library
- 5 built-in playbooks: Ransomware, Phishing, Credential Stuffing,
  Data Exfiltration, Privilege Escalation
- Step simulation (no real external calls)
- Full execution history with per-step outcomes

Compliance: NIST SP 800-61 (Computer Security Incident Handling),
            SOC2 CC7.3 (Incident response actions).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "playbooks.db")

VALID_TRIGGER_TYPES = {"manual", "auto_alert", "scheduled"}

VALID_ACTION_TYPES = {
    "send_alert",
    "block_ip",
    "isolate_host",
    "create_ticket",
    "run_scan",
    "notify_slack",
    "update_asset_status",
}


# ---------------------------------------------------------------------------
# Built-in playbook templates
# ---------------------------------------------------------------------------

_BUILTIN_PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "name": "Ransomware Response",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "ransomware_detected"},
        "severity_filter": "critical",
        "enabled": True,
        "steps": [
            {
                "step_id": "step-rw-1",
                "name": "Isolate affected host",
                "action_type": "isolate_host",
                "params": {"reason": "ransomware_containment", "simulate_success": True},
                "on_success": "step-rw-2",
                "on_failure": "step-rw-3",
            },
            {
                "step_id": "step-rw-2",
                "name": "Collect forensic artifacts",
                "action_type": "run_scan",
                "params": {"scan_type": "forensic_collection", "simulate_success": True},
                "on_success": "step-rw-3",
                "on_failure": "step-rw-3",
            },
            {
                "step_id": "step-rw-3",
                "name": "Alert security team",
                "action_type": "send_alert",
                "params": {
                    "channel": "email",
                    "recipients": ["security-team@example.com"],
                    "simulate_success": True,
                },
                "on_success": None,
                "on_failure": None,
            },
        ],
    },
    {
        "name": "Phishing Response",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "phishing_detected"},
        "severity_filter": "high",
        "enabled": True,
        "steps": [
            {
                "step_id": "step-ph-1",
                "name": "Block sender domain",
                "action_type": "block_ip",
                "params": {"reason": "phishing_sender", "simulate_success": True},
                "on_success": "step-ph-2",
                "on_failure": "step-ph-2",
            },
            {
                "step_id": "step-ph-2",
                "name": "Force password reset for affected users",
                "action_type": "update_asset_status",
                "params": {"status": "password_reset_required", "simulate_success": True},
                "on_success": "step-ph-3",
                "on_failure": "step-ph-3",
            },
            {
                "step_id": "step-ph-3",
                "name": "Scan email attachments",
                "action_type": "run_scan",
                "params": {"scan_type": "attachment_analysis", "simulate_success": True},
                "on_success": None,
                "on_failure": None,
            },
        ],
    },
    {
        "name": "Credential Stuffing",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "credential_stuffing_detected"},
        "severity_filter": "high",
        "enabled": True,
        "steps": [
            {
                "step_id": "step-cs-1",
                "name": "Block attacking IPs",
                "action_type": "block_ip",
                "params": {"reason": "credential_stuffing_source", "simulate_success": True},
                "on_success": "step-cs-2",
                "on_failure": "step-cs-2",
            },
            {
                "step_id": "step-cs-2",
                "name": "Enforce MFA on targeted accounts",
                "action_type": "update_asset_status",
                "params": {"status": "mfa_enforced", "simulate_success": True},
                "on_success": "step-cs-3",
                "on_failure": "step-cs-3",
            },
            {
                "step_id": "step-cs-3",
                "name": "Notify affected account owners",
                "action_type": "notify_slack",
                "params": {"channel": "#security-alerts", "simulate_success": True},
                "on_success": None,
                "on_failure": None,
            },
        ],
    },
    {
        "name": "Data Exfiltration Alert",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "data_exfiltration_detected"},
        "severity_filter": "critical",
        "enabled": True,
        "steps": [
            {
                "step_id": "step-de-1",
                "name": "Throttle suspicious connection",
                "action_type": "block_ip",
                "params": {"reason": "exfiltration_throttle", "simulate_success": True},
                "on_success": "step-de-2",
                "on_failure": "step-de-2",
            },
            {
                "step_id": "step-de-2",
                "name": "Capture packet trace",
                "action_type": "run_scan",
                "params": {"scan_type": "pcap_capture", "simulate_success": True},
                "on_success": "step-de-3",
                "on_failure": "step-de-3",
            },
            {
                "step_id": "step-de-3",
                "name": "Escalate to CISO",
                "action_type": "send_alert",
                "params": {
                    "channel": "email",
                    "recipients": ["ciso@example.com"],
                    "simulate_success": True,
                },
                "on_success": None,
                "on_failure": None,
            },
        ],
    },
    {
        "name": "Privilege Escalation",
        "trigger_type": "auto_alert",
        "trigger_conditions": {"alert_type": "privilege_escalation_detected"},
        "severity_filter": "high",
        "enabled": True,
        "steps": [
            {
                "step_id": "step-pe-1",
                "name": "Revoke elevated access",
                "action_type": "update_asset_status",
                "params": {"status": "access_revoked", "simulate_success": True},
                "on_success": "step-pe-2",
                "on_failure": "step-pe-2",
            },
            {
                "step_id": "step-pe-2",
                "name": "Investigate account activity",
                "action_type": "run_scan",
                "params": {"scan_type": "account_audit", "simulate_success": True},
                "on_success": "step-pe-3",
                "on_failure": "step-pe-3",
            },
            {
                "step_id": "step-pe-3",
                "name": "Create incident ticket",
                "action_type": "create_ticket",
                "params": {
                    "priority": "high",
                    "title": "Privilege escalation investigation",
                    "simulate_success": True,
                },
                "on_success": None,
                "on_failure": None,
            },
        ],
    },
]


class SecurityPlaybookEngine:
    """
    SQLite-backed security playbook engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to data/playbooks.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS playbooks (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    trigger_conditions TEXT DEFAULT '{}',
                    steps        TEXT DEFAULT '[]',
                    severity_filter TEXT DEFAULT 'medium',
                    enabled      INTEGER DEFAULT 1,
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pb_org
                    ON playbooks (org_id, enabled);

                CREATE TABLE IF NOT EXISTS executions (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    playbook_id  TEXT NOT NULL,
                    status       TEXT NOT NULL,
                    steps_completed INTEGER DEFAULT 0,
                    steps_failed    INTEGER DEFAULT 0,
                    duration_ms     INTEGER DEFAULT 0,
                    output       TEXT DEFAULT '{}',
                    started_at   DATETIME NOT NULL,
                    finished_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_exec_org
                    ON executions (org_id, started_at DESC);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Playbook CRUD
    # ------------------------------------------------------------------

    def create_playbook(self, org_id: str, playbook: Dict[str, Any]) -> str:
        """
        Create a new playbook. Returns playbook_id.

        playbook keys: name, trigger_type, trigger_conditions, steps,
                       severity_filter, enabled
        """
        trigger_type = playbook.get("trigger_type", "manual")
        if trigger_type not in VALID_TRIGGER_TYPES:
            raise ValueError(
                f"trigger_type must be one of {sorted(VALID_TRIGGER_TYPES)}, got '{trigger_type}'"
            )

        playbook_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO playbooks
                        (id, org_id, name, trigger_type, trigger_conditions,
                         steps, severity_filter, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        playbook_id,
                        org_id,
                        playbook.get("name", "Unnamed Playbook"),
                        trigger_type,
                        json.dumps(playbook.get("trigger_conditions", {})),
                        json.dumps(playbook.get("steps", [])),
                        playbook.get("severity_filter", "medium"),
                        1 if playbook.get("enabled", True) else 0,
                        now,
                    ),
                )
        _logger.info("Created playbook %s for org %s", playbook_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("PLAYBOOK_EXECUTED", {"entity_type": "security_playbook", "org_id": org_id, "source_engine": "security_playbook"})
            except Exception:
                pass

        return playbook_id

    def list_playbooks(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all playbooks for the given org_id."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM playbooks WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def get_playbook(self, playbook_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return a single playbook or None if not found / wrong org."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM playbooks WHERE id = ? AND org_id = ?",
                    (playbook_id, org_id),
                ).fetchone()
        return self._row_to_playbook(row) if row else None

    @staticmethod
    def _row_to_playbook(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["trigger_conditions"] = json.loads(d["trigger_conditions"])
        d["steps"] = json.loads(d["steps"])
        d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute_playbook(
        self, playbook_id: str, org_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a playbook sequentially, simulating each step.

        Returns:
            {execution_id, status, steps_completed, steps_failed, duration_ms, output}
        """
        playbook = self.get_playbook(playbook_id, org_id)
        if playbook is None:
            raise ValueError(f"Playbook {playbook_id!r} not found for org {org_id!r}")

        execution_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        t_start = time.monotonic()

        steps_completed = 0
        steps_failed = 0
        step_outputs: List[Dict[str, Any]] = []
        overall_status = "completed"

        steps: List[Dict[str, Any]] = playbook.get("steps", [])
        current_step_id: Optional[str] = steps[0]["step_id"] if steps else None
        steps_by_id = {s["step_id"]: s for s in steps}

        while current_step_id is not None:
            step = steps_by_id.get(current_step_id)
            if step is None:
                break

            success = bool(step.get("params", {}).get("simulate_success", True))
            step_result = self._simulate_step(step, context, success)
            step_outputs.append(step_result)

            if success:
                steps_completed += 1
                current_step_id = step.get("on_success")
            else:
                steps_failed += 1
                overall_status = "partial"
                current_step_id = step.get("on_failure")

        if steps_failed > 0 and steps_completed == 0:
            overall_status = "failed"

        duration_ms = int((time.monotonic() - t_start) * 1000)
        finished_at = datetime.now(timezone.utc).isoformat()

        output = {
            "steps": step_outputs,
            "context_keys": list(context.keys()),
        }

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO executions
                        (id, org_id, playbook_id, status, steps_completed,
                         steps_failed, duration_ms, output, started_at, finished_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        execution_id,
                        org_id,
                        playbook_id,
                        overall_status,
                        steps_completed,
                        steps_failed,
                        duration_ms,
                        json.dumps(output),
                        now.isoformat(),
                        finished_at,
                    ),
                )

        _logger.info(
            "Executed playbook %s (exec %s): status=%s completed=%d failed=%d",
            playbook_id,
            execution_id,
            overall_status,
            steps_completed,
            steps_failed,
        )

        return {
            "execution_id": execution_id,
            "status": overall_status,
            "steps_completed": steps_completed,
            "steps_failed": steps_failed,
            "duration_ms": duration_ms,
            "output": output,
        }

    @staticmethod
    def _simulate_step(
        step: Dict[str, Any], context: Dict[str, Any], success: bool
    ) -> Dict[str, Any]:
        """Produce a simulated step result dict."""
        action_type = step.get("action_type", "unknown")
        base: Dict[str, Any] = {
            "step_id": step.get("step_id"),
            "name": step.get("name"),
            "action_type": action_type,
            "status": "completed" if success else "failed",
        }
        if action_type == "block_ip":
            base["result"] = {"blocked": success, "ip": context.get("ip", "unknown")}
        elif action_type == "isolate_host":
            base["result"] = {"isolated": success, "host": context.get("host", "unknown")}
        elif action_type == "send_alert":
            base["result"] = {"sent": success, "channel": step.get("params", {}).get("channel")}
        elif action_type == "create_ticket":
            base["result"] = {
                "ticket_id": f"TKT-{uuid.uuid4().hex[:8].upper()}" if success else None
            }
        elif action_type == "run_scan":
            base["result"] = {
                "scan_type": step.get("params", {}).get("scan_type"),
                "findings": 0,
            }
        elif action_type == "notify_slack":
            base["result"] = {
                "channel": step.get("params", {}).get("channel"),
                "delivered": success,
            }
        elif action_type == "update_asset_status":
            base["result"] = {
                "status": step.get("params", {}).get("status"),
                "updated": success,
            }
        else:
            base["result"] = {"success": success}
        return base

    # ------------------------------------------------------------------
    # Execution history
    # ------------------------------------------------------------------

    def list_executions(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return execution history for org_id, newest first."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM executions
                    WHERE org_id = ?
                    ORDER BY started_at DESC
                    LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
        return [self._row_to_execution(r) for r in rows]

    def get_execution(self, execution_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return a single execution record or None."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM executions WHERE id = ? AND org_id = ?",
                    (execution_id, org_id),
                ).fetchone()
        return self._row_to_execution(row) if row else None

    @staticmethod
    def _row_to_execution(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["output"] = json.loads(d["output"])
        return d

    # ------------------------------------------------------------------
    # Built-in templates
    # ------------------------------------------------------------------

    def get_builtin_playbooks(self) -> List[Dict[str, Any]]:
        """Return the 5 built-in security response playbook templates."""
        return [dict(p) for p in _BUILTIN_PLAYBOOKS]
