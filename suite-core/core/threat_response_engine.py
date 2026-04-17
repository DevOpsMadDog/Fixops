"""Threat Response Engine — ALDECI.

Orchestrates incident response via playbooks, actions, and timelines.

Capabilities:
  - Create and manage response playbooks per threat type
  - Add ordered actions to playbooks
  - Trigger incidents linked to playbooks
  - Log and complete individual actions
  - Resolve incidents with auto-computed resolution_mins and rolling avg
  - Timeline reconstruction and performance analytics
  - Multi-tenant org_id isolation

Compliance: NIST CSF RS.*, ISO 27001 A.5.26
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_THREAT_TYPES = {
    "ransomware", "phishing", "insider_threat", "ddos", "data_breach",
    "malware", "apt", "supply_chain", "zero_day", "other",
}

_VALID_SEVERITY_SCOPES = {"critical", "high", "medium", "low", "all"}

_VALID_ACTION_TYPES = {
    "containment", "eradication", "recovery", "notification",
    "investigation", "escalation", "documentation",
}

_VALID_ACTION_LOG_STATUSES = {"pending", "in_progress", "completed", "failed"}

_VALID_INCIDENT_STATUSES = {"active", "resolved", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatResponseEngine:
    """SQLite WAL-backed Threat Response engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_response.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "threat_response.db")
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
                CREATE TABLE IF NOT EXISTS response_playbooks (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    playbook_name       TEXT NOT NULL,
                    threat_type         TEXT NOT NULL,
                    severity_scope      TEXT NOT NULL DEFAULT 'all',
                    description         TEXT NOT NULL DEFAULT '',
                    step_count          INTEGER NOT NULL DEFAULT 0,
                    avg_resolution_mins REAL NOT NULL DEFAULT 0.0,
                    execution_count     INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'active',
                    created_by          TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rp_org
                    ON response_playbooks (org_id, threat_type);

                CREATE TABLE IF NOT EXISTS response_actions (
                    id            TEXT PRIMARY KEY,
                    playbook_id   TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    step_number   INTEGER NOT NULL DEFAULT 1,
                    action_name   TEXT NOT NULL,
                    action_type   TEXT NOT NULL,
                    description   TEXT NOT NULL DEFAULT '',
                    automated     INTEGER NOT NULL DEFAULT 0,
                    timeout_mins  INTEGER NOT NULL DEFAULT 30,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ra_playbook
                    ON response_actions (playbook_id, org_id);

                CREATE TABLE IF NOT EXISTS response_incidents (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    playbook_id     TEXT NOT NULL,
                    incident_name   TEXT NOT NULL,
                    threat_type     TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'high',
                    status          TEXT NOT NULL DEFAULT 'active',
                    started_at      TEXT NOT NULL,
                    resolved_at     TEXT,
                    resolution_mins REAL NOT NULL DEFAULT 0.0,
                    triggered_by    TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ri_org
                    ON response_incidents (org_id, status);

                CREATE TABLE IF NOT EXISTS incident_action_log (
                    id           TEXT PRIMARY KEY,
                    incident_id  TEXT NOT NULL,
                    org_id       TEXT NOT NULL,
                    action_id    TEXT NOT NULL DEFAULT '',
                    action_name  TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    executed_by  TEXT NOT NULL DEFAULT '',
                    started_at   TEXT,
                    completed_at TEXT,
                    notes        TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ial_incident
                    ON incident_action_log (incident_id, org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        org_id: str,
        playbook_name: str,
        threat_type: str,
        severity_scope: str,
        description: str,
        created_by: str,
    ) -> Dict[str, Any]:
        """Create a new response playbook."""
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: {threat_type!r}. "
                f"Must be one of {sorted(_VALID_THREAT_TYPES)}"
            )
        if severity_scope not in _VALID_SEVERITY_SCOPES:
            raise ValueError(
                f"Invalid severity_scope: {severity_scope!r}. "
                f"Must be one of {sorted(_VALID_SEVERITY_SCOPES)}"
            )
        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "playbook_name": playbook_name,
            "threat_type": threat_type,
            "severity_scope": severity_scope,
            "description": description,
            "step_count": 0,
            "avg_resolution_mins": 0.0,
            "execution_count": 0,
            "status": "active",
            "created_by": created_by,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO response_playbooks
                       (id, org_id, playbook_name, threat_type, severity_scope,
                        description, step_count, avg_resolution_mins, execution_count,
                        status, created_by, created_at)
                       VALUES (:id, :org_id, :playbook_name, :threat_type, :severity_scope,
                               :description, :step_count, :avg_resolution_mins, :execution_count,
                               :status, :created_by, :created_at)""",
                    record,
                )
        return record

    def add_action(
        self,
        playbook_id: str,
        org_id: str,
        action_name: str,
        action_type: str,
        description: str,
        automated: bool = False,
        timeout_mins: int = 30,
    ) -> Dict[str, Any]:
        """Add an action to a playbook. step_number = MAX(existing)+1."""
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(
                f"Invalid action_type: {action_type!r}. "
                f"Must be one of {sorted(_VALID_ACTION_TYPES)}"
            )
        now = _now()
        with self._lock:
            with self._conn() as conn:
                # Verify playbook exists and belongs to org
                pb_row = conn.execute(
                    "SELECT id FROM response_playbooks WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                ).fetchone()
                if not pb_row:
                    raise KeyError(f"Playbook {playbook_id!r} not found.")

                max_row = conn.execute(
                    "SELECT COALESCE(MAX(step_number), 0) as mx FROM response_actions WHERE playbook_id=? AND org_id=?",
                    (playbook_id, org_id),
                ).fetchone()
                step_number = int(max_row["mx"]) + 1

                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "playbook_id": playbook_id,
                    "org_id": org_id,
                    "step_number": step_number,
                    "action_name": action_name,
                    "action_type": action_type,
                    "description": description,
                    "automated": 1 if automated else 0,
                    "timeout_mins": int(timeout_mins),
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO response_actions
                       (id, playbook_id, org_id, step_number, action_name, action_type,
                        description, automated, timeout_mins, created_at)
                       VALUES (:id, :playbook_id, :org_id, :step_number, :action_name,
                               :action_type, :description, :automated, :timeout_mins, :created_at)""",
                    record,
                )
                conn.execute(
                    "UPDATE response_playbooks SET step_count=step_count+1 WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                )
        return record

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def trigger_incident(
        self,
        org_id: str,
        playbook_id: str,
        incident_name: str,
        threat_type: str,
        severity: str,
        triggered_by: str,
    ) -> Dict[str, Any]:
        """Trigger a new incident, linking it to a playbook."""
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type: {threat_type!r}. "
                f"Must be one of {sorted(_VALID_THREAT_TYPES)}"
            )
        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "playbook_id": playbook_id,
            "incident_name": incident_name,
            "threat_type": threat_type,
            "severity": severity,
            "status": "active",
            "started_at": now,
            "resolved_at": None,
            "resolution_mins": 0.0,
            "triggered_by": triggered_by,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO response_incidents
                       (id, org_id, playbook_id, incident_name, threat_type, severity,
                        status, started_at, resolved_at, resolution_mins, triggered_by, created_at)
                       VALUES (:id, :org_id, :playbook_id, :incident_name, :threat_type, :severity,
                               :status, :started_at, :resolved_at, :resolution_mins, :triggered_by, :created_at)""",
                    record,
                )
                # Increment playbook execution_count
                conn.execute(
                    "UPDATE response_playbooks SET execution_count=execution_count+1 WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                )
        return record

    def log_action(
        self,
        incident_id: str,
        org_id: str,
        action_id: str,
        action_name: str,
        executed_by: str,
    ) -> Dict[str, Any]:
        """Log the start of an action on an incident (status=in_progress)."""
        now = _now()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "org_id": org_id,
            "action_id": action_id,
            "action_name": action_name,
            "status": "in_progress",
            "executed_by": executed_by,
            "started_at": now,
            "completed_at": None,
            "notes": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_action_log
                       (id, incident_id, org_id, action_id, action_name, status,
                        executed_by, started_at, completed_at, notes, created_at)
                       VALUES (:id, :incident_id, :org_id, :action_id, :action_name, :status,
                               :executed_by, :started_at, :completed_at, :notes, :created_at)""",
                    record,
                )
        return record

    def complete_action(
        self,
        log_id: str,
        org_id: str,
        status: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Complete or fail a logged action."""
        if status not in {"completed", "failed"}:
            raise ValueError(
                f"Invalid completion status: {status!r}. Must be 'completed' or 'failed'."
            )
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incident_action_log WHERE id=? AND org_id=?",
                    (log_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Action log {log_id!r} not found.")
                conn.execute(
                    """UPDATE incident_action_log
                       SET status=?, completed_at=?, notes=?
                       WHERE id=? AND org_id=?""",
                    (status, now, notes, log_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM incident_action_log WHERE id=? AND org_id=?",
                    (log_id, org_id),
                ).fetchone()
        return self._row(updated)

    def resolve_incident(
        self,
        incident_id: str,
        org_id: str,
    ) -> Dict[str, Any]:
        """Resolve an incident and update playbook avg_resolution_mins."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM response_incidents WHERE id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Incident {incident_id!r} not found.")

                incident = self._row(row)
                started_at = incident["started_at"]
                playbook_id = incident["playbook_id"]

                # Compute resolution_mins
                try:
                    started_dt = datetime.fromisoformat(started_at)
                    resolved_dt = datetime.fromisoformat(now)
                    resolution_mins = (resolved_dt - started_dt).total_seconds() / 60.0
                except Exception:
                    resolution_mins = 0.0

                conn.execute(
                    """UPDATE response_incidents
                       SET status='resolved', resolved_at=?, resolution_mins=?
                       WHERE id=? AND org_id=?""",
                    (now, resolution_mins, incident_id, org_id),
                )

                # Recompute avg_resolution_mins for playbook from all resolved incidents
                avg_row = conn.execute(
                    """SELECT AVG(resolution_mins) as avg_mins
                       FROM response_incidents
                       WHERE org_id=? AND playbook_id=? AND status='resolved'""",
                    (org_id, playbook_id),
                ).fetchone()
                avg_mins = avg_row["avg_mins"] if avg_row["avg_mins"] is not None else 0.0

                conn.execute(
                    "UPDATE response_playbooks SET avg_resolution_mins=? WHERE id=? AND org_id=?",
                    (avg_mins, playbook_id, org_id),
                )

                updated = conn.execute(
                    "SELECT * FROM response_incidents WHERE id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_active_incidents(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all active incidents with their action logs."""
        with self._conn() as conn:
            inc_rows = conn.execute(
                "SELECT * FROM response_incidents WHERE org_id=? AND status='active' ORDER BY started_at DESC",
                (org_id,),
            ).fetchall()
        incidents = [self._row(r) for r in inc_rows]
        for inc in incidents:
            with self._conn() as conn:
                log_rows = conn.execute(
                    "SELECT * FROM incident_action_log WHERE incident_id=? AND org_id=? ORDER BY started_at ASC",
                    (inc["id"], org_id),
                ).fetchall()
            inc["action_log"] = [self._row(r) for r in log_rows]
        return incidents

    def get_playbook_performance(self, org_id: str) -> List[Dict[str, Any]]:
        """Return playbooks with execution_count, avg_resolution_mins, step_count."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM response_playbooks WHERE org_id=?
                   ORDER BY execution_count DESC""",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_incident_timeline(
        self, incident_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Return incident details with action log ordered by started_at."""
        with self._conn() as conn:
            inc_row = conn.execute(
                "SELECT * FROM response_incidents WHERE id=? AND org_id=?",
                (incident_id, org_id),
            ).fetchone()
            if not inc_row:
                raise KeyError(f"Incident {incident_id!r} not found.")
            log_rows = conn.execute(
                """SELECT * FROM incident_action_log
                   WHERE incident_id=? AND org_id=?
                   ORDER BY COALESCE(started_at, created_at) ASC""",
                (incident_id, org_id),
            ).fetchall()
        result = self._row(inc_row)
        result["timeline"] = [self._row(r) for r in log_rows]
        return result

    def get_response_summary(self, org_id: str) -> Dict[str, Any]:
        """Return org-level response summary statistics."""
        with self._conn() as conn:
            total_playbooks = conn.execute(
                "SELECT COUNT(*) as cnt FROM response_playbooks WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

            total_incidents = conn.execute(
                "SELECT COUNT(*) as cnt FROM response_incidents WHERE org_id=?",
                (org_id,),
            ).fetchone()["cnt"]

            active_incidents = conn.execute(
                "SELECT COUNT(*) as cnt FROM response_incidents WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()["cnt"]

            resolved_incidents = conn.execute(
                "SELECT COUNT(*) as cnt FROM response_incidents WHERE org_id=? AND status='resolved'",
                (org_id,),
            ).fetchone()["cnt"]

            avg_row = conn.execute(
                "SELECT AVG(resolution_mins) as avg_mins FROM response_incidents WHERE org_id=? AND status='resolved'",
                (org_id,),
            ).fetchone()
            avg_resolution_mins = avg_row["avg_mins"] if avg_row["avg_mins"] is not None else 0.0

            type_rows = conn.execute(
                """SELECT threat_type, COUNT(*) as cnt
                   FROM response_incidents WHERE org_id=?
                   GROUP BY threat_type""",
                (org_id,),
            ).fetchall()
            by_threat_type = {r["threat_type"]: r["cnt"] for r in type_rows}

        return {
            "total_playbooks": total_playbooks,
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "resolved_incidents": resolved_incidents,
            "avg_resolution_mins": avg_resolution_mins,
            "by_threat_type": by_threat_type,
        }
