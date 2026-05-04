"""Incident Orchestration Engine — ALDECI.

Full incident lifecycle management with timeline events and MTTR metrics.

Capabilities:
  - Incident registry: create, list, get with full org isolation
  - Status lifecycle: open → investigating → contained → resolved → closed
  - Assignee tracking per incident
  - Timeline events: ordered log of actions/observations per incident
  - Metrics: open count, avg MTTR hours, breakdown by severity and type

Compliance: NIST SP 800-61 Rev 2 (incident handling), ISO/IEC 27035 (incident management)
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

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_TYPES = {"breach", "malware", "phishing", "ddos", "insider", "other"}
_VALID_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
_VALID_EVENT_TYPES = {
    "detection", "triage", "containment", "eradication",
    "recovery", "communication", "note", "escalation",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentOrchestrationEngine:
    """SQLite WAL-backed Incident Orchestration engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/incident_orchestration.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "incident_orchestration.db")
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
                CREATE TABLE IF NOT EXISTS incidents (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    type        TEXT NOT NULL DEFAULT 'other',
                    source      TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    assignee    TEXT NOT NULL DEFAULT '',
                    notes       TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    resolved_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_org
                    ON incidents (org_id, status, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_incidents_severity
                    ON incidents (org_id, severity);

                CREATE TABLE IF NOT EXISTS timeline_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    event_type  TEXT NOT NULL DEFAULT 'note',
                    description TEXT NOT NULL DEFAULT '',
                    actor       TEXT NOT NULL DEFAULT '',
                    occurred_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_timeline_incident
                    ON timeline_events (org_id, incident_id, occurred_at ASC);
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
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident."""
        title = (data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}"
            )

        incident_type = data.get("type", "other")
        if incident_type not in _VALID_TYPES:
            raise ValueError(
                f"Invalid type: {incident_type}. Must be one of {_VALID_TYPES}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "title": title,
            "severity": severity,
            "type": incident_type,
            "source": data.get("source", ""),
            "status": "open",
            "assignee": "",
            "notes": "",
            "created_at": now,
            "updated_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incidents
                       (id, org_id, title, severity, type, source, status,
                        assignee, notes, created_at, updated_at, resolved_at)
                       VALUES (:id, :org_id, :title, :severity, :type, :source, :status,
                               :assignee, :notes, :created_at, :updated_at, :resolved_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("INCIDENT_CREATED", {"entity_type": "incident", "entity_id": str(record["id"]), "org_id": org_id, "source_engine": "incident_orchestration_engine"})
            except Exception:
                pass  # Event emission should never break the main operation
        return record

    def list_incidents(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List incidents with optional filters."""
        sql = "SELECT * FROM incidents WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single incident by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                (org_id, incident_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_incident_status(
        self, org_id: str, incident_id: str, status: str, notes: str = ""
    ) -> Optional[Dict[str, Any]]:
        """Update incident status and optionally append notes.

        Returns None if the incident is not found.
        """
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status}. Must be one of {_VALID_STATUSES}"
            )

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
                if not row:
                    return None

                resolved_at = None
                if status in ("resolved", "closed"):
                    resolved_at = now

                updates: Dict[str, Any] = {
                    "status": status,
                    "updated_at": now,
                    "resolved_at": resolved_at,
                }
                if notes:
                    updates["notes"] = notes

                set_clauses = ", ".join(f"{k} = ?" for k in updates)
                values = list(updates.values()) + [org_id, incident_id]
                conn.execute(
                    f"UPDATE incidents SET {set_clauses} WHERE org_id = ? AND id = ?",  # nosec B608
                    values,
                )
                updated = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
        return self._row(updated) if updated else None

    def assign_incident(
        self, org_id: str, incident_id: str, assignee: str
    ) -> Optional[Dict[str, Any]]:
        """Assign an incident to a user/team. Returns None if not found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                affected = conn.execute(
                    "UPDATE incidents SET assignee = ?, updated_at = ? "
                    "WHERE org_id = ? AND id = ?",
                    (assignee, now, org_id, incident_id),
                ).rowcount
                if not affected:
                    return None
                row = conn.execute(
                    "SELECT * FROM incidents WHERE org_id = ? AND id = ?",
                    (org_id, incident_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def add_timeline_event(
        self, org_id: str, incident_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Add a timeline event to an incident. Returns None if incident not found."""
        incident = self.get_incident(org_id, incident_id)
        if not incident:
            return None

        event_type = data.get("event_type", "note")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type}. Must be one of {_VALID_EVENT_TYPES}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "event_type": event_type,
            "description": data.get("description", ""),
            "actor": data.get("actor", ""),
            "occurred_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO timeline_events
                       (id, org_id, incident_id, event_type, description, actor, occurred_at)
                       VALUES (:id, :org_id, :incident_id, :event_type,
                               :description, :actor, :occurred_at)""",
                    record,
                )
        return record

    def get_timeline(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """Get the full ordered timeline for an incident."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM timeline_events WHERE org_id = ? AND incident_id = ? "
                "ORDER BY occurred_at ASC",
                (org_id, incident_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # TrustGraph context
    # ------------------------------------------------------------------

    def get_incident_context(self, org_id: str, incident_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context about an incident.

        Returns related alerts, affected assets, and similar past incidents.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_alerts": [],
            "similar_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            incident = self.get_incident(org_id, incident_id)
            search_term = incident.get("title", incident_id) if incident else incident_id

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=search_term, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("alert", "finding"):
                            context["related_alerts"].append(entry)
                        elif etype in ("incident", "breach"):
                            if entry["id"] != incident_id:
                                context["similar_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=incident_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("alert", "finding"):
                    if entry not in context["related_alerts"]:
                        context["related_alerts"].append(entry)
                elif etype in ("incident", "breach"):
                    if entry["id"] != incident_id and entry not in context["similar_incidents"]:
                        context["similar_incidents"].append(entry)
        except Exception:
            pass
        return context

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_incident_metrics(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated incident metrics for an org."""
        with self._conn() as conn:
            open_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            total_count = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # MTTR: mean time to resolve via SQL (no Python datetime loop)
            mttr_row = conn.execute(
                """SELECT AVG((JULIANDAY(resolved_at) - JULIANDAY(created_at)) * 24) AS avg_hours
                   FROM incidents
                   WHERE org_id = ? AND resolved_at IS NOT NULL""",
                (org_id,),
            ).fetchone()
            avg_mttr_hours = (
                round(mttr_row["avg_hours"], 2)
                if mttr_row and mttr_row["avg_hours"] is not None
                else 0.0
            )

            # By severity
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM incidents "
                "WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # By type
            type_rows = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM incidents "
                "WHERE org_id = ? GROUP BY type",
                (org_id,),
            ).fetchall()
            by_type = {r["type"]: r["cnt"] for r in type_rows}

        return {
            "open_count": open_count,
            "total_count": total_count,
            "avg_mttr_hours": avg_mttr_hours,
            "by_severity": by_severity,
            "by_type": by_type,
        }
