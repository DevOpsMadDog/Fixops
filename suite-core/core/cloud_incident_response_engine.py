"""Cloud Incident Response Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Cloud-specific incident response with automated containment tracking:
  - Full incident lifecycle: detected → investigating → contained → resolved → closed
  - Containment and resolution time computed via SQL julianday arithmetic
  - Containment actions with automated flag and status transitions
  - IR playbooks per cloud_provider + incident_type with execution_count tracking
  - Metrics: MTTR, avg containment time, by_status/by_provider breakdowns

Compliance: NIST SP 800-61 Rev 2, CSA CCM, CIS Controls v8
"""
from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_incident_response.db"
)

VALID_PROVIDERS = frozenset({
    "aws", "azure", "gcp", "oci", "alibaba", "ibm", "multi-cloud",
})
VALID_INCIDENT_TYPES = frozenset({
    "data-breach", "ransomware", "account-compromise", "resource-abuse",
    "ddos", "insider", "misconfiguration", "supply-chain",
})
VALID_ACTION_TYPES = frozenset({
    "isolate", "revoke-access", "snapshot", "block-ip",
    "disable-account", "quarantine", "alert", "escalate",
})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_STATUSES = frozenset({"detected", "investigating", "contained", "resolved", "closed"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_list(v: Optional[List[str]]) -> str:
    return json.dumps(v or [])


class CloudIncidentResponseEngine:
    """SQLite WAL-backed Cloud Incident Response engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cloud_incident_response.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
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
                CREATE TABLE IF NOT EXISTS cloud_incidents (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    incident_name           TEXT NOT NULL,
                    cloud_provider          TEXT NOT NULL DEFAULT 'aws',
                    incident_type           TEXT NOT NULL,
                    severity                TEXT NOT NULL DEFAULT 'medium',
                    status                  TEXT NOT NULL DEFAULT 'detected',
                    affected_services       TEXT NOT NULL DEFAULT '[]',
                    affected_regions        TEXT NOT NULL DEFAULT '[]',
                    root_cause              TEXT NOT NULL DEFAULT '',
                    blast_radius            TEXT NOT NULL DEFAULT 'unknown',
                    containment_time_mins   REAL NOT NULL DEFAULT 0.0,
                    resolution_time_mins    REAL NOT NULL DEFAULT 0.0,
                    detected_at             TEXT NOT NULL,
                    contained_at            TEXT NOT NULL DEFAULT '',
                    resolved_at             TEXT NOT NULL DEFAULT '',
                    created_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org
                    ON cloud_incidents (org_id);
                CREATE INDEX IF NOT EXISTS idx_ci_status
                    ON cloud_incidents (org_id, status);

                CREATE TABLE IF NOT EXISTS containment_actions (
                    id              TEXT PRIMARY KEY,
                    incident_id     TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    action_type     TEXT NOT NULL,
                    resource_id     TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    automated       INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    executed_at     TEXT NOT NULL DEFAULT '',
                    executed_by     TEXT NOT NULL DEFAULT '',
                    result          TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ca_incident
                    ON containment_actions (incident_id);
                CREATE INDEX IF NOT EXISTS idx_ca_org
                    ON containment_actions (org_id);

                CREATE TABLE IF NOT EXISTS ir_playbooks (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    playbook_name   TEXT NOT NULL,
                    cloud_provider  TEXT NOT NULL,
                    incident_type   TEXT NOT NULL,
                    steps           TEXT NOT NULL DEFAULT '[]',
                    estimated_mins  INTEGER NOT NULL DEFAULT 30,
                    execution_count INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pb_org
                    ON ir_playbooks (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialise JSON list columns if present
        for col in ("affected_services", "affected_regions", "steps"):
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(
        self,
        org_id: str,
        incident_name: str,
        cloud_provider: str = "aws",
        incident_type: str = "misconfiguration",
        severity: str = "medium",
        affected_services: Optional[List[str]] = None,
        affected_regions: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if cloud_provider not in VALID_PROVIDERS:
            raise ValueError(f"cloud_provider must be one of {sorted(VALID_PROVIDERS)}")
        if incident_type not in VALID_INCIDENT_TYPES:
            raise ValueError(f"incident_type must be one of {sorted(VALID_INCIDENT_TYPES)}")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_name": incident_name,
            "cloud_provider": cloud_provider,
            "incident_type": incident_type,
            "severity": severity,
            "status": "detected",
            "affected_services": _json_list(affected_services),
            "affected_regions": _json_list(affected_regions),
            "root_cause": "",
            "blast_radius": "unknown",
            "containment_time_mins": 0.0,
            "resolution_time_mins": 0.0,
            "detected_at": now,
            "contained_at": "",
            "resolved_at": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_incidents
                       (id, org_id, incident_name, cloud_provider, incident_type,
                        severity, status, affected_services, affected_regions,
                        root_cause, blast_radius, containment_time_mins,
                        resolution_time_mins, detected_at, contained_at,
                        resolved_at, created_at)
                       VALUES (:id, :org_id, :incident_name, :cloud_provider,
                               :incident_type, :severity, :status,
                               :affected_services, :affected_regions,
                               :root_cause, :blast_radius, :containment_time_mins,
                               :resolution_time_mins, :detected_at, :contained_at,
                               :resolved_at, :created_at)""",
                    record,
                )
        # Return with parsed JSON fields
        record["affected_services"] = affected_services or []
        record["affected_regions"] = affected_regions or []
        _logger.info("incident created id=%s org=%s type=%s", record["id"], org_id, incident_type)
        return record

    def contain_incident(
        self, incident_id: str, org_id: str, blast_radius: str = "unknown"
    ) -> Dict[str, Any]:
        """Mark incident as contained; compute containment_time_mins via julianday."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cloud_incidents WHERE id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"incident {incident_id!r} not found")
                conn.execute(
                    """UPDATE cloud_incidents
                       SET status='contained',
                           contained_at=?,
                           blast_radius=?,
                           containment_time_mins=(julianday(?) - julianday(detected_at)) * 1440.0
                       WHERE id=? AND org_id=?""",
                    (now, blast_radius, now, incident_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM cloud_incidents WHERE id=?", (incident_id,)
                ).fetchone()
        return self._row(updated)

    def resolve_incident(
        self, incident_id: str, org_id: str, root_cause: str = ""
    ) -> Dict[str, Any]:
        """Mark incident as resolved; compute resolution_time_mins via julianday."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cloud_incidents WHERE id=? AND org_id=?",
                    (incident_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"incident {incident_id!r} not found")
                conn.execute(
                    """UPDATE cloud_incidents
                       SET status='resolved',
                           resolved_at=?,
                           root_cause=?,
                           resolution_time_mins=(julianday(?) - julianday(detected_at)) * 1440.0
                       WHERE id=? AND org_id=?""",
                    (now, root_cause, now, incident_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM cloud_incidents WHERE id=?", (incident_id,)
                ).fetchone()
        return self._row(updated)

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        cloud_provider: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM cloud_incidents WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if cloud_provider:
            query += " AND cloud_provider=?"
            params.append(cloud_provider)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_incident(self, incident_id: str, org_id: str) -> Dict[str, Any]:
        """Return incident dict + actions list + matching playbooks (same provider+type)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cloud_incidents WHERE id=? AND org_id=?",
                (incident_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"incident {incident_id!r} not found")
            incident = self._row(row)

            actions = conn.execute(
                "SELECT * FROM containment_actions WHERE incident_id=? AND org_id=? ORDER BY created_at",
                (incident_id, org_id),
            ).fetchall()
            incident["actions"] = [self._row(a) for a in actions]

            playbooks = conn.execute(
                """SELECT * FROM ir_playbooks
                   WHERE org_id=? AND cloud_provider=? AND incident_type=?""",
                (org_id, incident["cloud_provider"], incident["incident_type"]),
            ).fetchall()
            incident["playbooks"] = [self._row(p) for p in playbooks]

        return incident

    # ------------------------------------------------------------------
    # Containment Actions
    # ------------------------------------------------------------------

    def add_containment_action(
        self,
        incident_id: str,
        org_id: str,
        action_type: str,
        resource_id: str = "",
        description: str = "",
        automated: bool = False,
        executed_by: str = "",
    ) -> Dict[str, Any]:
        if action_type not in VALID_ACTION_TYPES:
            raise ValueError(f"action_type must be one of {sorted(VALID_ACTION_TYPES)}")
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "incident_id": incident_id,
            "org_id": org_id,
            "action_type": action_type,
            "resource_id": resource_id,
            "description": description,
            "automated": 1 if automated else 0,
            "status": "pending",
            "executed_at": "",
            "executed_by": executed_by,
            "result": "",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO containment_actions
                       (id, incident_id, org_id, action_type, resource_id, description,
                        automated, status, executed_at, executed_by, result, created_at)
                       VALUES (:id, :incident_id, :org_id, :action_type, :resource_id,
                               :description, :automated, :status, :executed_at,
                               :executed_by, :result, :created_at)""",
                    record,
                )
        return record

    def complete_action(
        self, action_id: str, org_id: str, result: str = ""
    ) -> Dict[str, Any]:
        """Mark containment action as completed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM containment_actions WHERE id=? AND org_id=?",
                    (action_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"action {action_id!r} not found")
                conn.execute(
                    """UPDATE containment_actions
                       SET status='completed', executed_at=?, result=?
                       WHERE id=? AND org_id=?""",
                    (now, result, action_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM containment_actions WHERE id=?", (action_id,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Playbooks
    # ------------------------------------------------------------------

    def create_playbook(
        self,
        org_id: str,
        playbook_name: str,
        cloud_provider: str,
        incident_type: str,
        steps: Optional[List[str]] = None,
        estimated_mins: int = 30,
    ) -> Dict[str, Any]:
        if cloud_provider not in VALID_PROVIDERS:
            raise ValueError(f"cloud_provider must be one of {sorted(VALID_PROVIDERS)}")
        if incident_type not in VALID_INCIDENT_TYPES:
            raise ValueError(f"incident_type must be one of {sorted(VALID_INCIDENT_TYPES)}")
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "playbook_name": playbook_name,
            "cloud_provider": cloud_provider,
            "incident_type": incident_type,
            "steps": _json_list(steps),
            "estimated_mins": max(1, int(estimated_mins)),
            "execution_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ir_playbooks
                       (id, org_id, playbook_name, cloud_provider, incident_type,
                        steps, estimated_mins, execution_count, created_at)
                       VALUES (:id, :org_id, :playbook_name, :cloud_provider,
                               :incident_type, :steps, :estimated_mins,
                               :execution_count, :created_at)""",
                    record,
                )
        record["steps"] = steps or []
        return record

    def execute_playbook(self, playbook_id: str, org_id: str) -> Dict[str, Any]:
        """Increment execution_count and return the playbook with parsed steps."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ir_playbooks WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"playbook {playbook_id!r} not found")
                conn.execute(
                    "UPDATE ir_playbooks SET execution_count=execution_count+1 WHERE id=? AND org_id=?",
                    (playbook_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM ir_playbooks WHERE id=?", (playbook_id,)
                ).fetchone()
        return self._row(updated)

    def list_playbooks(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM ir_playbooks WHERE org_id=? ORDER BY playbook_name",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def get_ir_metrics(self, org_id: str) -> Dict[str, Any]:
        """Aggregate IR metrics for the org."""
        with self._conn() as conn:
            totals = conn.execute(
                "SELECT COUNT(*) AS total FROM cloud_incidents WHERE org_id=?",
                (org_id,),
            ).fetchone()

            status_rows = conn.execute(
                """SELECT status, COUNT(*) AS cnt
                   FROM cloud_incidents WHERE org_id=?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()

            provider_rows = conn.execute(
                """SELECT cloud_provider, COUNT(*) AS cnt
                   FROM cloud_incidents WHERE org_id=?
                   GROUP BY cloud_provider""",
                (org_id,),
            ).fetchall()

            containment_agg = conn.execute(
                """SELECT AVG(containment_time_mins) AS avg_contain
                   FROM cloud_incidents
                   WHERE org_id=? AND status IN ('contained','resolved','closed')
                     AND containment_time_mins > 0""",
                (org_id,),
            ).fetchone()

            resolution_agg = conn.execute(
                """SELECT AVG(resolution_time_mins) AS avg_resolve
                   FROM cloud_incidents
                   WHERE org_id=? AND status IN ('resolved','closed')
                     AND resolution_time_mins > 0""",
                (org_id,),
            ).fetchone()

            open_critical = conn.execute(
                """SELECT COUNT(*) AS cnt
                   FROM cloud_incidents
                   WHERE org_id=? AND severity='critical'
                     AND status NOT IN ('resolved','closed')""",
                (org_id,),
            ).fetchone()

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("INCIDENT_CREATED", {"entity_type": "cloud_incident_response_engine", "org_id": org_id, "source_engine": "cloud_incident_response_engine"})
            except Exception:
                pass
        return {
            "total_incidents": int(totals["total"] or 0),
            "by_status": {r["status"]: r["cnt"] for r in status_rows},
            "by_provider": {r["cloud_provider"]: r["cnt"] for r in provider_rows},
            "avg_containment_mins": float(containment_agg["avg_contain"] or 0.0),
            "avg_resolution_mins": float(resolution_agg["avg_resolve"] or 0.0),
            "open_critical": int(open_critical["cnt"] or 0),
        }
