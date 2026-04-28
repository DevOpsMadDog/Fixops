"""Incident Response Management Engine — ALDECI.

Tracks security incidents end-to-end: creation, task management, timeline,
artifact collection, and SLA compliance reporting.

Compliance: NIST SP 800-61r2, ISO/IEC 27035, SANS Incident Handling.
"""

from __future__ import annotations

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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "incident_response.db"
)

# SLA deadlines by severity (hours from detection)
_SLA_HOURS: Dict[str, int] = {
    "p1": 4,
    "p2": 8,
    "p3": 24,
    "p4": 72,
}

_VALID_TYPES = {
    "ransomware", "data_breach", "ddos", "insider_threat",
    "phishing", "malware", "apt", "zero_day", "supply_chain",
}
_VALID_SEVERITIES = {"p1", "p2", "p3", "p4"}
_VALID_STATUSES = {"new", "triage", "containment", "eradication", "recovery", "closed"}
_VALID_TASK_STATUSES = {"pending", "in_progress", "completed", "blocked"}


class IncidentResponseEngine:
    """SQLite WAL-backed incident response management engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS incidents (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    incident_type   TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'new',
                    assigned_to     TEXT NOT NULL DEFAULT '',
                    detected_at     DATETIME NOT NULL,
                    reported_at     DATETIME NOT NULL,
                    sla_deadline    DATETIME NOT NULL,
                    resolved_at     DATETIME,
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_inc_org
                    ON incidents (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS incident_tasks (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL,
                    title           TEXT NOT NULL,
                    assignee        TEXT NOT NULL DEFAULT '',
                    priority        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    due_by          DATETIME,
                    completed_at    DATETIME,
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_task_incident
                    ON incident_tasks (org_id, incident_id);

                CREATE TABLE IF NOT EXISTS incident_timeline (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    description     TEXT NOT NULL,
                    actor           TEXT NOT NULL DEFAULT '',
                    timestamp       DATETIME NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_timeline_incident
                    ON incident_timeline (org_id, incident_id, timestamp);

                CREATE TABLE IF NOT EXISTS incident_artifacts (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL,
                    artifact_type   TEXT NOT NULL,
                    filename        TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );

                CREATE INDEX IF NOT EXISTS idx_artifact_incident
                    ON incident_artifacts (org_id, incident_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _compute_sla(severity: str, detected_at: str) -> str:
        hours = _SLA_HOURS.get(severity.lower(), 24)
        try:
            base = datetime.fromisoformat(detected_at)
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
        except Exception:
            base = datetime.now(timezone.utc)
        return (base + timedelta(hours=hours)).isoformat()

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident. Returns the full incident record."""
        incident_id = str(uuid.uuid4())
        now = self._now()
        detected_at = data.get("detected_at") or now
        reported_at = data.get("reported_at") or now
        severity = str(data.get("severity", "p3")).lower()
        sla_deadline = self._compute_sla(severity, detected_at)

        record = {
            "id": incident_id,
            "org_id": org_id,
            "title": str(data.get("title", "")),
            "description": str(data.get("description", "")),
            "incident_type": str(data.get("incident_type", "malware")),
            "severity": severity,
            "status": str(data.get("status", "new")),
            "assigned_to": str(data.get("assigned_to", "")),
            "detected_at": detected_at,
            "reported_at": reported_at,
            "sla_deadline": sla_deadline,
            "resolved_at": data.get("resolved_at"),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO incidents
                        (id, org_id, title, description, incident_type, severity,
                         status, assigned_to, detected_at, reported_at, sla_deadline,
                         resolved_at, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["title"],
                        record["description"], record["incident_type"],
                        record["severity"], record["status"], record["assigned_to"],
                        record["detected_at"], record["reported_at"],
                        record["sla_deadline"], record["resolved_at"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        _logger.info("Created incident %s for org %s", incident_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("INCIDENT_CREATED", {"entity_type": "incident_response", "org_id": org_id, "source_engine": "incident_response"})
            except Exception:
                pass

        return record

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents for an org, optionally filtered by status/severity."""
        query = "SELECT * FROM incidents WHERE org_id = ?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single incident by ID, enforcing org isolation."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE id = ? AND org_id = ?",
                    (incident_id, org_id),
                ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_incident(
        self, org_id: str, incident_id: str, data: Dict[str, Any]
    ) -> bool:
        """Update mutable incident fields. Returns True if a row was updated."""
        allowed = {
            "title", "description", "incident_type", "severity", "status",
            "assigned_to", "detected_at", "reported_at", "resolved_at",
        }
        updates = {k: v for k, v in data.items() if k in allowed}
        if not updates:
            return False

        # Recalculate SLA if severity or detected_at changed
        if "severity" in updates or "detected_at" in updates:
            existing = self.get_incident(org_id, incident_id)
            if existing:
                severity = updates.get("severity", existing["severity"])
                detected_at = updates.get("detected_at", existing["detected_at"])
                updates["sla_deadline"] = self._compute_sla(severity, detected_at)

        updates["updated_at"] = self._now()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [incident_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE incidents SET {set_clause} WHERE id = ? AND org_id = ?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    def add_task(
        self, org_id: str, incident_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a task to an incident. Returns the full task record."""
        task_id = str(uuid.uuid4())
        now = self._now()
        record = {
            "id": task_id,
            "org_id": org_id,
            "incident_id": incident_id,
            "title": str(data.get("title", "")),
            "assignee": str(data.get("assignee", "")),
            "priority": str(data.get("priority", "medium")),
            "status": str(data.get("status", "pending")),
            "due_by": data.get("due_by"),
            "completed_at": None,
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO incident_tasks
                        (id, org_id, incident_id, title, assignee, priority,
                         status, due_by, completed_at, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["incident_id"],
                        record["title"], record["assignee"], record["priority"],
                        record["status"], record["due_by"], record["completed_at"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        return record

    def list_tasks(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """List all tasks for an incident."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM incident_tasks
                    WHERE org_id = ? AND incident_id = ?
                    ORDER BY created_at ASC
                    """,
                    (org_id, incident_id),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def complete_task(self, org_id: str, task_id: str) -> bool:
        """Mark a task as completed. Returns True if updated."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE incident_tasks
                    SET status = 'completed', completed_at = ?, updated_at = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (now, now, task_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def add_timeline_event(
        self,
        org_id: str,
        incident_id: str,
        event_type: str,
        description: str,
        actor: str = "",
    ) -> Dict[str, Any]:
        """Record a timeline event for an incident."""
        event_id = str(uuid.uuid4())
        timestamp = self._now()
        record = {
            "id": event_id,
            "org_id": org_id,
            "incident_id": incident_id,
            "event_type": event_type,
            "description": description,
            "actor": actor,
            "timestamp": timestamp,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO incident_timeline
                        (id, org_id, incident_id, event_type, description, actor, timestamp)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["incident_id"],
                        record["event_type"], record["description"],
                        record["actor"], record["timestamp"],
                    ),
                )
        return record

    def get_timeline(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch timeline events sorted by timestamp descending."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM incident_timeline
                    WHERE org_id = ? AND incident_id = ?
                    ORDER BY timestamp DESC
                    """,
                    (org_id, incident_id),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def add_artifact(
        self,
        org_id: str,
        incident_id: str,
        artifact_type: str,
        filename: str,
        description: str = "",
    ) -> Dict[str, Any]:
        """Attach an artifact reference to an incident."""
        artifact_id = str(uuid.uuid4())
        now = self._now()
        record = {
            "id": artifact_id,
            "org_id": org_id,
            "incident_id": incident_id,
            "artifact_type": artifact_type,
            "filename": filename,
            "description": description,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO incident_artifacts
                        (id, org_id, incident_id, artifact_type, filename,
                         description, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        record["id"], record["org_id"], record["incident_id"],
                        record["artifact_type"], record["filename"],
                        record["description"], record["created_at"],
                    ),
                )
        return record

    def list_artifacts(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """List artifacts attached to an incident."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM incident_artifacts
                    WHERE org_id = ? AND incident_id = ?
                    ORDER BY created_at DESC
                    """,
                    (org_id, incident_id),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_incident_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate incident statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                # by_severity
                sev_rows = conn.execute(
                    """
                    SELECT severity, COUNT(*) as cnt
                    FROM incidents WHERE org_id = ?
                    GROUP BY severity
                    """,
                    (org_id,),
                ).fetchall()

                # by_status
                st_rows = conn.execute(
                    """
                    SELECT status, COUNT(*) as cnt
                    FROM incidents WHERE org_id = ?
                    GROUP BY status
                    """,
                    (org_id,),
                ).fetchall()

                # by_type
                type_rows = conn.execute(
                    """
                    SELECT incident_type, COUNT(*) as cnt
                    FROM incidents WHERE org_id = ?
                    GROUP BY incident_type
                    """,
                    (org_id,),
                ).fetchall()

                # avg resolution hours (closed incidents with resolved_at)
                avg_row = conn.execute(
                    """
                    SELECT AVG(
                        (JULIANDAY(resolved_at) - JULIANDAY(detected_at)) * 24
                    ) as avg_hours
                    FROM incidents
                    WHERE org_id = ? AND status = 'closed' AND resolved_at IS NOT NULL
                    """,
                    (org_id,),
                ).fetchone()

                # P1 SLA compliance — closed P1s resolved before sla_deadline
                p1_total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM incidents WHERE org_id = ? AND severity = 'p1' AND status = 'closed'",
                    (org_id,),
                ).fetchone()
                p1_compliant_row = conn.execute(
                    """
                    SELECT COUNT(*) as cnt FROM incidents
                    WHERE org_id = ? AND severity = 'p1' AND status = 'closed'
                      AND resolved_at IS NOT NULL AND resolved_at <= sla_deadline
                    """,
                    (org_id,),
                ).fetchone()

        p1_total = p1_total_row["cnt"] if p1_total_row else 0
        p1_compliant = p1_compliant_row["cnt"] if p1_compliant_row else 0
        p1_sla = (p1_compliant / p1_total * 100) if p1_total > 0 else None

        return {
            "by_severity": {r["severity"]: r["cnt"] for r in sev_rows},
            "by_status": {r["status"]: r["cnt"] for r in st_rows},
            "by_type": {r["incident_type"]: r["cnt"] for r in type_rows},
            "avg_resolution_hours": round(avg_row["avg_hours"], 2) if avg_row and avg_row["avg_hours"] else None,
            "p1_sla_compliance": round(p1_sla, 1) if p1_sla is not None else None,
        }
