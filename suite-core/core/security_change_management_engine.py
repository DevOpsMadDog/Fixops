"""Security Change Management Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages security change requests with full approval workflow:
  - Change lifecycle from draft through completion or rollback
  - Approver decision tracking (approved/rejected/pending)
  - Aggregated stats with daily completion counts and type/status breakdowns

Compliance: ITIL v4, ISO 20000, SOC2 CC8.1, NIST SP 800-128
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "security_change_management.db"
)

_VALID_CHANGE_TYPES = {
    "patch", "configuration", "architecture", "access_control",
    "firewall_rule", "certificate", "policy", "emergency",
}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}
_VALID_CHANGE_STATUSES = {
    "draft", "review", "approved", "scheduled", "implementing",
    "completed", "rejected", "rolled_back",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_DECISIONS = {"approved", "rejected", "pending"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_prefix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class SecurityChangeManagementEngine:
    """SQLite WAL-backed Security Change Management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_change_management.db
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
                CREATE TABLE IF NOT EXISTS scm_changes (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    change_type      TEXT NOT NULL DEFAULT 'patch',
                    description      TEXT NOT NULL DEFAULT '',
                    priority         TEXT NOT NULL DEFAULT 'medium',
                    risk_level       TEXT NOT NULL DEFAULT 'medium',
                    requested_by     TEXT NOT NULL DEFAULT '',
                    assigned_to      TEXT NOT NULL DEFAULT '',
                    affected_systems TEXT NOT NULL DEFAULT '',
                    rollback_plan    TEXT NOT NULL DEFAULT '',
                    status           TEXT NOT NULL DEFAULT 'draft',
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME,
                    scheduled_at     DATETIME,
                    completed_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_scm_changes_org
                    ON scm_changes (org_id, change_type, status, priority);

                CREATE TABLE IF NOT EXISTS scm_approvals (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    change_id   TEXT NOT NULL,
                    approver    TEXT NOT NULL DEFAULT '',
                    decision    TEXT NOT NULL DEFAULT 'pending',
                    comments    TEXT NOT NULL DEFAULT '',
                    decided_at  DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_scm_approvals_org
                    ON scm_approvals (org_id, change_id);
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
    # Changes
    # ------------------------------------------------------------------

    def create_change(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security change request in draft status."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        change_type = data.get("change_type", "patch")
        if change_type not in _VALID_CHANGE_TYPES:
            raise ValueError(
                f"Invalid change_type '{change_type}'. "
                f"Must be one of {sorted(_VALID_CHANGE_TYPES)}"
            )

        priority = data.get("priority", "medium")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority '{priority}'. "
                f"Must be one of {sorted(_VALID_PRIORITIES)}"
            )

        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "change_type": change_type,
            "description": data.get("description", ""),
            "priority": priority,
            "risk_level": risk_level,
            "requested_by": data.get("requested_by", ""),
            "assigned_to": data.get("assigned_to", ""),
            "affected_systems": data.get("affected_systems", ""),
            "rollback_plan": data.get("rollback_plan", ""),
            "status": "draft",
            "notes": "",
            "created_at": now,
            "scheduled_at": data.get("scheduled_at", None),
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scm_changes
                       (id, org_id, title, change_type, description, priority,
                        risk_level, requested_by, assigned_to, affected_systems,
                        rollback_plan, status, notes, created_at, scheduled_at, completed_at)
                       VALUES (:id, :org_id, :title, :change_type, :description, :priority,
                               :risk_level, :requested_by, :assigned_to, :affected_systems,
                               :rollback_plan, :status, :notes, :created_at, :scheduled_at,
                               :completed_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_change_management", "org_id": org_id, "source_engine": "security_change_management"})
            except Exception:
                pass

        return record

    def list_changes(
        self,
        org_id: str,
        change_type: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List changes with optional filters."""
        sql = "SELECT * FROM scm_changes WHERE org_id = ?"
        params: List[Any] = [org_id]
        if change_type:
            sql += " AND change_type = ?"
            params.append(change_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if priority:
            sql += " AND priority = ?"
            params.append(priority)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_change(self, org_id: str, change_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single change by ID within the org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scm_changes WHERE org_id = ? AND id = ?",
                (org_id, change_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_change_status(
        self,
        org_id: str,
        change_id: str,
        status: str,
        notes: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update change status. Sets completed_at if status=completed."""
        if status not in _VALID_CHANGE_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. "
                f"Must be one of {sorted(_VALID_CHANGE_STATUSES)}"
            )
        now = _now_iso()
        completed_at = now if status == "completed" else None
        with self._lock:
            with self._conn() as conn:
                if completed_at is not None:
                    conn.execute(
                        """UPDATE scm_changes
                           SET status = ?, notes = ?, completed_at = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, notes, completed_at, org_id, change_id),
                    )
                else:
                    conn.execute(
                        """UPDATE scm_changes
                           SET status = ?, notes = ?
                           WHERE org_id = ? AND id = ?""",
                        (status, notes, org_id, change_id),
                    )
        return self.get_change(org_id, change_id)

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def add_approver(
        self,
        org_id: str,
        change_id: str,
        approver_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add an approval record for a change."""
        decision = approver_data.get("decision", "pending")
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{decision}'. "
                f"Must be one of {sorted(_VALID_DECISIONS)}"
            )

        now = _now_iso()
        decided_at = None if decision == "pending" else now

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "change_id": change_id,
            "approver": approver_data.get("approver", ""),
            "decision": decision,
            "comments": approver_data.get("comments", ""),
            "decided_at": decided_at,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scm_approvals
                       (id, org_id, change_id, approver, decision, comments, decided_at)
                       VALUES (:id, :org_id, :change_id, :approver, :decision,
                               :comments, :decided_at)""",
                    record,
                )
        return record

    def list_approvals(
        self,
        org_id: str,
        change_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List approvals, optionally filtered by change_id."""
        sql = "SELECT * FROM scm_approvals WHERE org_id = ?"
        params: List[Any] = [org_id]
        if change_id:
            sql += " AND change_id = ?"
            params.append(change_id)
        sql += " ORDER BY decided_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_change_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated change management statistics for an org."""
        today = _today_prefix()
        with self._conn() as conn:
            total_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            pending_review = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? AND status = 'review'",
                (org_id,),
            ).fetchone()[0]

            approved_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? AND status = 'approved'",
                (org_id,),
            ).fetchone()[0]

            completed_today = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? "
                "AND status = 'completed' AND completed_at LIKE ?",
                (org_id, f"{today}%"),
            ).fetchone()[0]

            emergency_changes = conn.execute(
                "SELECT COUNT(*) FROM scm_changes WHERE org_id = ? "
                "AND change_type = 'emergency'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT change_type, COUNT(*) as cnt FROM scm_changes "
                "WHERE org_id = ? GROUP BY change_type",
                (org_id,),
            ).fetchall()
            by_type = {r["change_type"]: r["cnt"] for r in type_rows}

            status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM scm_changes "
                "WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in status_rows}

        return {
            "total_changes": total_changes,
            "pending_review": pending_review,
            "approved_changes": approved_changes,
            "completed_today": completed_today,
            "emergency_changes": emergency_changes,
            "by_type": by_type,
            "by_status": by_status,
        }
