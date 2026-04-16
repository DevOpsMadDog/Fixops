"""Security Automation Engine — ALDECI.

Manages automation rules that trigger on alerts, schedules, or webhooks,
executes those rules, and tracks execution history with stats.

Capabilities:
  - Rule registry (trigger_type: alert/schedule/webhook) with per-org isolation
  - Rule lifecycle: create, enable, disable
  - Rule execution with multi-action dispatch and timing
  - Execution history with status tracking (success/partial/failed)
  - Aggregated stats: total rules, executions today, success rate, avg duration

Compliance: SOAR best-practices, NIST SP 800-61 (incident response automation)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_TRIGGER_TYPES = {"alert", "schedule", "webhook"}
_VALID_EXECUTION_STATUSES = {"success", "partial", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class SecurityAutomationEngine:
    """SQLite WAL-backed Security Automation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_automation.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_automation.db")
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
                CREATE TABLE IF NOT EXISTS automation_rules (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    trigger_type      TEXT NOT NULL DEFAULT 'alert',
                    trigger_condition TEXT NOT NULL DEFAULT '',
                    actions           TEXT NOT NULL DEFAULT '[]',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    created_at        TEXT NOT NULL,
                    updated_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rules_org
                    ON automation_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS rule_executions (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    rule_id       TEXT NOT NULL,
                    context       TEXT NOT NULL DEFAULT '{}',
                    actions_taken TEXT NOT NULL DEFAULT '[]',
                    status        TEXT NOT NULL DEFAULT 'success',
                    duration_ms   INTEGER NOT NULL DEFAULT 0,
                    executed_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_executions_org_rule
                    ON rule_executions (org_id, rule_id, executed_at DESC);

                CREATE INDEX IF NOT EXISTS idx_executions_org_status
                    ON rule_executions (org_id, status, executed_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("actions", "actions_taken", "context"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = [] if field != "context" else {}
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_automation_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new automation rule."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        trigger_type = data.get("trigger_type", "alert")
        if trigger_type not in _VALID_TRIGGER_TYPES:
            raise ValueError(
                f"Invalid trigger_type: {trigger_type}. Must be one of {_VALID_TRIGGER_TYPES}"
            )

        actions = data.get("actions", [])
        if not isinstance(actions, list):
            actions = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "trigger_type": trigger_type,
            "trigger_condition": data.get("trigger_condition", ""),
            "actions": json.dumps(actions),
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO automation_rules
                       (id, org_id, name, trigger_type, trigger_condition,
                        actions, enabled, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :trigger_type, :trigger_condition,
                               :actions, :enabled, :created_at, :updated_at)""",
                    record,
                )
        record["actions"] = actions
        record["enabled"] = bool(record["enabled"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("PLAYBOOK_EXECUTED", {"entity_type": "security_automation", "org_id": org_id, "source_engine": "security_automation"})
            except Exception:
                pass

        return record

    def list_automation_rules(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List automation rules, optionally filtered by enabled state."""
        sql = "SELECT * FROM automation_rules WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        sql += " ORDER BY name ASC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single rule by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM automation_rules WHERE org_id = ? AND id = ?",
                (org_id, rule_id),
            ).fetchone()
        return self._row(row) if row else None

    def enable_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Enable an automation rule. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    "UPDATE automation_rules SET enabled = 1, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (now, org_id, rule_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM automation_rules WHERE org_id = ? AND id = ?",
                    (org_id, rule_id),
                ).fetchone()
        return self._row(row) if row else None

    def disable_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Disable an automation rule. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    "UPDATE automation_rules SET enabled = 0, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (now, org_id, rule_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM automation_rules WHERE org_id = ? AND id = ?",
                    (org_id, rule_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute_rule(
        self, org_id: str, rule_id: str, context: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Execute a rule against a context dict.

        Returns an execution record with:
          - execution_id
          - actions_taken: list of action results
          - status: success / partial / failed
          - duration_ms

        Returns None if the rule is not found for the org.
        """
        rule = self.get_rule(org_id, rule_id)
        if not rule:
            return None

        t_start = time.monotonic()
        actions = rule.get("actions", [])
        actions_taken: list = []
        failed_count = 0

        for action in actions:
            action_type = action.get("type", "unknown") if isinstance(action, dict) else str(action)
            try:
                # Simulate action dispatch (real implementations would call
                # external systems; here we record the attempted action).
                actions_taken.append({
                    "action": action_type,
                    "result": "executed",
                    "context_keys": list(context.keys()) if context else [],
                })
            except Exception as exc:
                failed_count += 1
                actions_taken.append({"action": action_type, "result": "error", "detail": str(exc)})

        duration_ms = int((time.monotonic() - t_start) * 1000)

        total = len(actions)
        if total == 0 or failed_count == 0:
            status = "success"
        elif failed_count == total:
            status = "failed"
        else:
            status = "partial"

        now = _now_iso()
        execution_id = str(uuid.uuid4())
        record = {
            "id": execution_id,
            "org_id": org_id,
            "rule_id": rule_id,
            "context": json.dumps(context or {}),
            "actions_taken": json.dumps(actions_taken),
            "status": status,
            "duration_ms": duration_ms,
            "executed_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO rule_executions
                       (id, org_id, rule_id, context, actions_taken, status, duration_ms, executed_at)
                       VALUES (:id, :org_id, :rule_id, :context, :actions_taken,
                               :status, :duration_ms, :executed_at)""",
                    record,
                )

        record["execution_id"] = execution_id
        record["context"] = context or {}
        record["actions_taken"] = actions_taken
        return record

    def list_executions(
        self,
        org_id: str,
        rule_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List execution history for an org, with optional filters."""
        sql = "SELECT * FROM rule_executions WHERE org_id = ?"
        params: list = [org_id]
        if rule_id:
            sql += " AND rule_id = ?"
            params.append(rule_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY executed_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_automation_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated automation statistics for an org."""
        today = _today_iso()
        with self._conn() as conn:
            total_rules = conn.execute(
                "SELECT COUNT(*) FROM automation_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            enabled_rules = conn.execute(
                "SELECT COUNT(*) FROM automation_rules WHERE org_id = ? AND enabled = 1",
                (org_id,),
            ).fetchone()[0]

            executions_today = conn.execute(
                "SELECT COUNT(*) FROM rule_executions "
                "WHERE org_id = ? AND date(executed_at) = ?",
                (org_id, today),
            ).fetchone()[0]

            total_executions = conn.execute(
                "SELECT COUNT(*) FROM rule_executions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            success_count = conn.execute(
                "SELECT COUNT(*) FROM rule_executions WHERE org_id = ? AND status = 'success'",
                (org_id,),
            ).fetchone()[0]

            success_rate = round(
                (success_count / total_executions * 100) if total_executions else 0.0, 1
            )

            avg_duration_row = conn.execute(
                "SELECT AVG(duration_ms) FROM rule_executions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_duration_ms = round(float(avg_duration_row or 0.0), 1)

        return {
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "executions_today": executions_today,
            "total_executions": total_executions,
            "success_rate": success_rate,
            "avg_duration_ms": avg_duration_ms,
        }
