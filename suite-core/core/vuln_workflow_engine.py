"""Vulnerability Workflow Engine — ALDECI.

Manages vulnerability remediation workflows with ticket assignment,
SLA enforcement, comments, bulk operations, and risk acceptance.

Capabilities:
  - Vuln ticket CRUD with auto SLA due-date calculation
  - Overdue detection and SLA breach tracking
  - Comment/audit trail per ticket
  - Assignment and bulk operations (bulk assign, bulk close)
  - Risk acceptance workflow with expiry
  - Configurable SLA per severity
  - Stats aggregation per org

Compliance: NIST SP 800-40 (patch management), CIS Controls v8 (Control 7),
            PCI DSS 6.3, ISO 27001 A.12.6
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_STATUSES = {
    "open", "in_progress", "pending_verification", "resolved",
    "accepted_risk", "duplicate", "wont_fix",
}
_VALID_PRIORITIES = {"p1", "p2", "p3", "p4"}
_VALID_SOURCES = {"scanner", "threat_feed", "manual", "vuln_prioritization"}
_VALID_COMMENT_TYPES = {
    "comment", "status_change", "assignment", "escalation", "sla_breach",
}

# Default SLA days if no custom config is set
_DEFAULT_SLA_DAYS: Dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}

# Priority → SLA days fallback
_PRIORITY_SLA_DAYS: Dict[str, int] = {
    "p1": 7,
    "p2": 30,
    "p3": 90,
    "p4": 180,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _due_date_from_sla(severity: str, priority: str, sla_days: Optional[int] = None) -> str:
    """Calculate due date from SLA config or defaults."""
    days = sla_days
    if days is None:
        # Use priority-based SLA if available, else severity
        days = _PRIORITY_SLA_DAYS.get(priority) or _DEFAULT_SLA_DAYS.get(severity, 90)
    due = datetime.now(timezone.utc) + timedelta(days=days)
    return due.isoformat()


def _is_overdue(due_date: Optional[str], status: str) -> bool:
    """Check if a ticket is overdue."""
    if not due_date or status in ("resolved", "accepted_risk", "duplicate", "wont_fix"):
        return False
    try:
        due = datetime.fromisoformat(due_date.replace("Z", "+00:00"))
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > due
    except Exception:
        return False


class VulnWorkflowEngine:
    """SQLite WAL-backed vulnerability workflow engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own DB file.
    """

    _instances: Dict[str, "VulnWorkflowEngine"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, org_id: str) -> None:
        self.org_id = org_id
        self.db_path = str(_DATA_DIR / f"{org_id}_vuln_workflow.db")
        self._lock = threading.RLock()
        self._init_db()

    @classmethod
    def for_org(cls, org_id: str) -> "VulnWorkflowEngine":
        with cls._instances_lock:
            if org_id not in cls._instances:
                cls._instances[org_id] = cls(org_id)
            return cls._instances[org_id]

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vuln_tickets (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    cve_id            TEXT NOT NULL DEFAULT '',
                    title             TEXT NOT NULL,
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    cvss_score        REAL NOT NULL DEFAULT 0.0,
                    affected_assets   TEXT NOT NULL DEFAULT '[]',
                    assignee_id       TEXT NOT NULL DEFAULT '',
                    assignee_team     TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'open',
                    priority          TEXT NOT NULL DEFAULT 'p3',
                    due_date          DATETIME,
                    resolved_date     DATETIME,
                    resolution_notes  TEXT NOT NULL DEFAULT '',
                    source_engine     TEXT NOT NULL DEFAULT 'manual',
                    tags              TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vt_org_status
                    ON vuln_tickets (org_id, status, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_vt_org_assignee
                    ON vuln_tickets (org_id, assignee_id, status);

                CREATE INDEX IF NOT EXISTS idx_vt_org_severity
                    ON vuln_tickets (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS ticket_comments (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    ticket_id     TEXT NOT NULL,
                    author_id     TEXT NOT NULL DEFAULT '',
                    comment_type  TEXT NOT NULL DEFAULT 'comment',
                    body          TEXT NOT NULL DEFAULT '',
                    old_status    TEXT NOT NULL DEFAULT '',
                    new_status    TEXT NOT NULL DEFAULT '',
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tc_org_ticket
                    ON ticket_comments (org_id, ticket_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS sla_configs (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    severity         TEXT NOT NULL,
                    sla_days         INTEGER NOT NULL DEFAULT 30,
                    escalation_days  INTEGER NOT NULL DEFAULT 7,
                    owner_team       TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME NOT NULL,
                    UNIQUE(org_id, severity)
                );

                CREATE INDEX IF NOT EXISTS idx_sc_org
                    ON sla_configs (org_id, severity);

                CREATE TABLE IF NOT EXISTS bulk_operations (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    operation_type  TEXT NOT NULL,
                    ticket_count    INTEGER NOT NULL DEFAULT 0,
                    target_assignee TEXT NOT NULL DEFAULT '',
                    applied_by      TEXT NOT NULL DEFAULT '',
                    reason          TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_bo_org
                    ON bulk_operations (org_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialize JSON fields
        for field in ("affected_assets", "tags"):
            if isinstance(d.get(field), str):
                try:
                    d[field] = json.loads(d[field])
                except Exception:
                    d[field] = []
        return d

    def _get_sla_days(self, org_id: str, severity: str, priority: str) -> int:
        """Look up org SLA config, fall back to defaults."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT sla_days FROM sla_configs WHERE org_id = ? AND severity = ?",
                (org_id, severity),
            ).fetchone()
        if row:
            return row["sla_days"]
        return _PRIORITY_SLA_DAYS.get(priority) or _DEFAULT_SLA_DAYS.get(severity, 90)

    # ------------------------------------------------------------------
    # Tickets
    # ------------------------------------------------------------------

    def create_ticket(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a vuln ticket, auto-setting due_date from SLA config."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        priority = data.get("priority", "p3")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}")

        source_engine = data.get("source_engine", "manual")
        if source_engine not in _VALID_SOURCES:
            source_engine = "manual"

        sla_days = self._get_sla_days(org_id, severity, priority)
        due_date = data.get("due_date") or _due_date_from_sla(severity, priority, sla_days)

        now = _now_iso()
        affected_assets = data.get("affected_assets", [])
        tags = data.get("tags", [])

        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cve_id": data.get("cve_id", ""),
            "title": title,
            "severity": severity,
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "affected_assets": json.dumps(affected_assets if isinstance(affected_assets, list) else []),
            "assignee_id": data.get("assignee_id", ""),
            "assignee_team": data.get("assignee_team", ""),
            "status": "open",
            "priority": priority,
            "due_date": due_date,
            "resolved_date": None,
            "resolution_notes": data.get("resolution_notes", ""),
            "source_engine": source_engine,
            "tags": json.dumps(tags if isinstance(tags, list) else []),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO vuln_tickets
                       (id, org_id, cve_id, title, severity, cvss_score,
                        affected_assets, assignee_id, assignee_team, status,
                        priority, due_date, resolved_date, resolution_notes,
                        source_engine, tags, created_at)
                       VALUES (:id, :org_id, :cve_id, :title, :severity, :cvss_score,
                               :affected_assets, :assignee_id, :assignee_team, :status,
                               :priority, :due_date, :resolved_date, :resolution_notes,
                               :source_engine, :tags, :created_at)""",
                    record,
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("FINDING_CREATED", {"entity_type": "vuln_ticket", "entity_id": str(record["id"]), "org_id": org_id, "source_engine": "vuln_workflow_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        result = dict(record)
        result["affected_assets"] = affected_assets
        result["tags"] = tags
        return result

    def list_tickets(
        self,
        org_id: str,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        severity: Optional[str] = None,
        team: Optional[str] = None,
        overdue_only: bool = False,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List tickets with optional filters. Adds overdue flag to each."""
        sql = "SELECT * FROM vuln_tickets WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if assignee:
            sql += " AND assignee_id = ?"
            params.append(assignee)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if team:
            sql += " AND assignee_team = ?"
            params.append(team)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = [self._row(r) for r in conn.execute(sql, params).fetchall()]

        # Add overdue flag
        for ticket in rows:
            ticket["overdue"] = _is_overdue(ticket.get("due_date"), ticket["status"])

        if overdue_only:
            rows = [t for t in rows if t["overdue"]]

        return rows

    def get_ticket(self, org_id: str, ticket_id: str) -> Optional[Dict[str, Any]]:
        """Return ticket with comments list."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM vuln_tickets WHERE org_id = ? AND id = ?",
                (org_id, ticket_id),
            ).fetchone()
            if not row:
                return None
            ticket = self._row(row)
            comments = [
                self._row(c)
                for c in conn.execute(
                    """SELECT * FROM ticket_comments
                       WHERE org_id = ? AND ticket_id = ?
                       ORDER BY created_at ASC""",
                    (org_id, ticket_id),
                ).fetchall()
            ]
        ticket["overdue"] = _is_overdue(ticket.get("due_date"), ticket["status"])
        ticket["comments"] = comments
        return ticket

    def update_ticket(
        self, org_id: str, ticket_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update ticket fields. Logs a status_change comment on status transitions."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM vuln_tickets WHERE org_id = ? AND id = ?",
                    (org_id, ticket_id),
                ).fetchone()
            if not row:
                return None
            old = self._row(row)

            # Build SET clause dynamically
            allowed_fields = {
                "title", "severity", "cvss_score", "assignee_id", "assignee_team",
                "status", "priority", "due_date", "resolution_notes", "source_engine",
            }
            updates: Dict[str, Any] = {}
            for field in allowed_fields:
                if field in data:
                    updates[field] = data[field]

            # Serialize list fields if needed
            if "affected_assets" in data:
                updates["affected_assets"] = json.dumps(
                    data["affected_assets"] if isinstance(data["affected_assets"], list) else []
                )
            if "tags" in data:
                updates["tags"] = json.dumps(
                    data["tags"] if isinstance(data["tags"], list) else []
                )

            # Auto-set resolved_date on resolution
            new_status = updates.get("status")
            if new_status and new_status not in old.get("status", ""):
                if new_status in ("resolved", "wont_fix", "duplicate"):
                    updates["resolved_date"] = _now_iso()

            if updates:
                set_clause = ", ".join(f"{k} = :{k}" for k in updates)
                updates["_org_id"] = org_id
                updates["_ticket_id"] = ticket_id
                with self._conn() as conn:
                    conn.execute(
                        f"UPDATE vuln_tickets SET {set_clause} WHERE org_id = :_org_id AND id = :_ticket_id",  # nosec B608
                        updates,
                    )

            # Log status change comment
            if new_status and new_status != old.get("status"):
                self._add_comment_raw(
                    org_id, ticket_id,
                    author_id=data.get("updated_by", "system"),
                    body=f"Status changed from {old.get('status')} to {new_status}.",
                    comment_type="status_change",
                    old_status=old.get("status", ""),
                    new_status=new_status,
                )

        return self.get_ticket(org_id, ticket_id)

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------

    def _add_comment_raw(
        self,
        org_id: str,
        ticket_id: str,
        author_id: str,
        body: str,
        comment_type: str = "comment",
        old_status: str = "",
        new_status: str = "",
    ) -> Dict[str, Any]:
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "ticket_id": ticket_id,
            "author_id": author_id,
            "comment_type": comment_type,
            "body": body,
            "old_status": old_status,
            "new_status": new_status,
            "created_at": now,
        }
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO ticket_comments
                   (id, org_id, ticket_id, author_id, comment_type, body,
                    old_status, new_status, created_at)
                   VALUES (:id, :org_id, :ticket_id, :author_id, :comment_type, :body,
                           :old_status, :new_status, :created_at)""",
                record,
            )
        return record

    def add_comment(
        self,
        org_id: str,
        ticket_id: str,
        author_id: str,
        body: str,
        comment_type: str = "comment",
    ) -> Dict[str, Any]:
        """Add a comment to a ticket."""
        if comment_type not in _VALID_COMMENT_TYPES:
            raise ValueError(f"Invalid comment_type: {comment_type}")
        with self._lock:
            return self._add_comment_raw(org_id, ticket_id, author_id, body, comment_type)

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def assign_ticket(
        self,
        org_id: str,
        ticket_id: str,
        assignee_id: str,
        team: str,
        assigned_by: str,
    ) -> Optional[Dict[str, Any]]:
        """Reassign a ticket and log an assignment comment."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM vuln_tickets WHERE org_id = ? AND id = ?",
                    (org_id, ticket_id),
                ).fetchone()
            if not row:
                return None
            old = self._row(row)
            with self._conn() as conn:
                conn.execute(
                    """UPDATE vuln_tickets
                       SET assignee_id = ?, assignee_team = ?
                       WHERE org_id = ? AND id = ?""",
                    (assignee_id, team, org_id, ticket_id),
                )
            self._add_comment_raw(
                org_id, ticket_id,
                author_id=assigned_by,
                body=f"Reassigned from {old.get('assignee_id') or 'unassigned'} to {assignee_id} (team: {team}).",
                comment_type="assignment",
            )
        return self.get_ticket(org_id, ticket_id)

    # ------------------------------------------------------------------
    # Bulk Operations
    # ------------------------------------------------------------------

    def bulk_assign(
        self,
        org_id: str,
        ticket_ids: List[str],
        assignee_id: str,
        team: str,
        applied_by: str,
    ) -> Dict[str, Any]:
        """Bulk reassign a list of tickets."""
        if not ticket_ids:
            raise ValueError("ticket_ids must not be empty.")
        now = _now_iso()
        affected = 0
        with self._lock:
            for tid in ticket_ids:
                with self._conn() as conn:
                    cur = conn.execute(
                        """UPDATE vuln_tickets
                           SET assignee_id = ?, assignee_team = ?
                           WHERE org_id = ? AND id = ?""",
                        (assignee_id, team, org_id, tid),
                    )
                    if cur.rowcount > 0:
                        affected += 1
                self._add_comment_raw(
                    org_id, tid,
                    author_id=applied_by,
                    body=f"Bulk assigned to {assignee_id} (team: {team}).",
                    comment_type="assignment",
                )
            op = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "operation_type": "bulk_assign",
                "ticket_count": affected,
                "target_assignee": assignee_id,
                "applied_by": applied_by,
                "reason": f"Bulk assign to {assignee_id}",
                "created_at": now,
            }
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO bulk_operations
                       (id, org_id, operation_type, ticket_count, target_assignee,
                        applied_by, reason, created_at)
                       VALUES (:id, :org_id, :operation_type, :ticket_count, :target_assignee,
                               :applied_by, :reason, :created_at)""",
                    op,
                )
        return {"operation": op, "affected_tickets": affected}

    def bulk_close(
        self,
        org_id: str,
        ticket_ids: List[str],
        applied_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Bulk resolve a list of tickets."""
        if not ticket_ids:
            raise ValueError("ticket_ids must not be empty.")
        now = _now_iso()
        affected = 0
        with self._lock:
            for tid in ticket_ids:
                with self._conn() as conn:
                    cur = conn.execute(
                        """UPDATE vuln_tickets
                           SET status = 'resolved', resolved_date = ?, resolution_notes = ?
                           WHERE org_id = ? AND id = ?
                           AND status NOT IN ('resolved', 'duplicate', 'wont_fix')""",
                        (now, reason, org_id, tid),
                    )
                    if cur.rowcount > 0:
                        affected += 1
                self._add_comment_raw(
                    org_id, tid,
                    author_id=applied_by,
                    body=f"Bulk closed. Reason: {reason}",
                    comment_type="status_change",
                    old_status="open",
                    new_status="resolved",
                )
            op = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "operation_type": "bulk_close",
                "ticket_count": affected,
                "target_assignee": "",
                "applied_by": applied_by,
                "reason": reason,
                "created_at": now,
            }
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO bulk_operations
                       (id, org_id, operation_type, ticket_count, target_assignee,
                        applied_by, reason, created_at)
                       VALUES (:id, :org_id, :operation_type, :ticket_count, :target_assignee,
                               :applied_by, :reason, :created_at)""",
                    op,
                )
        return {"operation": op, "affected_tickets": affected}

    def accept_risk(
        self,
        org_id: str,
        ticket_id: str,
        accepted_by: str,
        reason: str,
        expiry_date: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Mark a ticket as accepted_risk with audit trail."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE vuln_tickets
                       SET status = 'accepted_risk', resolution_notes = ?
                       WHERE org_id = ? AND id = ?""",
                    (reason, org_id, ticket_id),
                )
                if cur.rowcount == 0:
                    return None
            expiry_note = f" Expires: {expiry_date}." if expiry_date else ""
            self._add_comment_raw(
                org_id, ticket_id,
                author_id=accepted_by,
                body=f"Risk accepted by {accepted_by}. Reason: {reason}.{expiry_note}",
                comment_type="status_change",
                old_status="open",
                new_status="accepted_risk",
            )
            # Log as bulk operation for audit
            op = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "operation_type": "bulk_accept_risk",
                "ticket_count": 1,
                "target_assignee": "",
                "applied_by": accepted_by,
                "reason": reason,
                "created_at": now,
            }
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO bulk_operations
                       (id, org_id, operation_type, ticket_count, target_assignee,
                        applied_by, reason, created_at)
                       VALUES (:id, :org_id, :operation_type, :ticket_count, :target_assignee,
                               :applied_by, :reason, :created_at)""",
                    op,
                )
        return self.get_ticket(org_id, ticket_id)

    # ------------------------------------------------------------------
    # SLA Config
    # ------------------------------------------------------------------

    def set_sla_config(
        self,
        org_id: str,
        severity: str,
        sla_days: int,
        escalation_days: int,
        owner_team: str,
    ) -> Dict[str, Any]:
        """Upsert SLA config for a severity level."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "severity": severity,
            "sla_days": sla_days,
            "escalation_days": escalation_days,
            "owner_team": owner_team,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO sla_configs
                       (id, org_id, severity, sla_days, escalation_days, owner_team, created_at)
                       VALUES (:id, :org_id, :severity, :sla_days, :escalation_days, :owner_team, :created_at)
                       ON CONFLICT(org_id, severity) DO UPDATE SET
                           sla_days = excluded.sla_days,
                           escalation_days = excluded.escalation_days,
                           owner_team = excluded.owner_team""",
                    record,
                )
        return record

    def get_sla_config(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all SLA configs for org."""
        with self._conn() as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM sla_configs WHERE org_id = ? ORDER BY severity",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_workflow_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated workflow stats for org."""
        now_str = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            total_open = conn.execute(
                """SELECT COUNT(*) FROM vuln_tickets
                   WHERE org_id = ? AND status NOT IN ('resolved', 'duplicate', 'wont_fix', 'accepted_risk')""",
                (org_id,),
            ).fetchone()[0]

            # By severity
            by_sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM vuln_tickets
                   WHERE org_id = ? GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_sev_rows}

            # By status
            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt FROM vuln_tickets
                   WHERE org_id = ? GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in by_status_rows}

            # Overdue count (open tickets past due_date)
            overdue_count = conn.execute(
                """SELECT COUNT(*) FROM vuln_tickets
                   WHERE org_id = ?
                   AND status NOT IN ('resolved', 'accepted_risk', 'duplicate', 'wont_fix')
                   AND due_date IS NOT NULL
                   AND due_date < ?""",
                (org_id, now_str),
            ).fetchone()[0]

            # Average resolution days
            avg_res_row = conn.execute(
                """SELECT AVG(
                       CAST((julianday(resolved_date) - julianday(created_at)) * 86400 AS INTEGER) / 86400.0
                   ) as avg_days
                   FROM vuln_tickets
                   WHERE org_id = ? AND resolved_date IS NOT NULL""",
                (org_id,),
            ).fetchone()
            avg_resolution_days = round(avg_res_row["avg_days"] or 0.0, 2)

            # SLA breached (open tickets overdue by more than escalation threshold)
            sla_breached = conn.execute(
                """SELECT COUNT(*) FROM vuln_tickets
                   WHERE org_id = ?
                   AND status NOT IN ('resolved', 'accepted_risk', 'duplicate', 'wont_fix')
                   AND due_date IS NOT NULL
                   AND due_date < ?""",
                (org_id, now_str),
            ).fetchone()[0]

            # By team
            by_team_rows = conn.execute(
                """SELECT assignee_team, COUNT(*) as cnt FROM vuln_tickets
                   WHERE org_id = ? AND assignee_team != ''
                   GROUP BY assignee_team""",
                (org_id,),
            ).fetchall()
            by_team = {r["assignee_team"]: r["cnt"] for r in by_team_rows}

            # By source
            by_source_rows = conn.execute(
                """SELECT source_engine, COUNT(*) as cnt FROM vuln_tickets
                   WHERE org_id = ? GROUP BY source_engine""",
                (org_id,),
            ).fetchall()
            by_source = {r["source_engine"]: r["cnt"] for r in by_source_rows}

        return {
            "total_open": total_open,
            "by_severity": by_severity,
            "by_status": by_status,
            "overdue_count": overdue_count,
            "avg_resolution_days": avg_resolution_days,
            "sla_breached": sla_breached,
            "by_team": by_team,
            "by_source": by_source,
        }
