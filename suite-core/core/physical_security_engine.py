"""Physical Security Engine — ALDECI.

Manages physical locations, access events, and security incidents.

Features:
- Location registration (office/datacenter/warehouse/facility/remote)
- Access event logging (entry/exit/attempt/denied via badge/biometric/pin/key/tailgate)
- Incident lifecycle (open → resolved) with severity tracking
- Stats: location counts, 24h events, denied attempts, open incidents

Compliance: ISO 27001 A.11 (Physical Security), NIST SP 800-53 PE controls,
            SOC 2 CC6.4 (Physical Access Controls)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "physical_security.db"
)

_VALID_LOCATION_TYPES = {"office", "datacenter", "warehouse", "facility", "remote"}
_VALID_SECURITY_LEVELS = {"low", "medium", "high", "critical"}
_VALID_ACCESS_TYPES = {"entry", "exit", "attempt", "denied"}
_VALID_ACCESS_METHODS = {"badge", "biometric", "pin", "key", "tailgate"}
_VALID_INCIDENT_TYPES = {
    "tailgating", "unauthorized_access", "theft", "vandalism", "fire", "flood", "other"
}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class LocationCreate(BaseModel):
    name: str
    location_type: str  # office/datacenter/warehouse/facility/remote
    address: Optional[str] = None
    security_level: str = "medium"
    capacity: Optional[int] = None


class AccessEventCreate(BaseModel):
    location_id: str
    person_id: str
    access_type: str  # entry/exit/attempt/denied
    method: str  # badge/biometric/pin/key/tailgate
    timestamp: Optional[str] = None


class IncidentCreate(BaseModel):
    location_id: str
    incident_type: str
    severity: str
    description: Optional[str] = None


class IncidentResolve(BaseModel):
    resolution: str


# ============================================================================
# PHYSICAL SECURITY ENGINE
# ============================================================================


class PhysicalSecurityEngine:
    """Physical security engine — locations, access events, incidents."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS locations (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL,
                    address        TEXT,
                    location_type  TEXT NOT NULL,
                    security_level TEXT NOT NULL DEFAULT 'medium',
                    capacity       INTEGER,
                    status         TEXT NOT NULL DEFAULT 'active',
                    created_at     TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    location_id TEXT NOT NULL,
                    person_id   TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    method      TEXT NOT NULL,
                    timestamp   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    location_id   TEXT NOT NULL,
                    incident_type TEXT NOT NULL,
                    severity      TEXT NOT NULL,
                    description   TEXT,
                    status        TEXT NOT NULL DEFAULT 'open',
                    detected_at   TEXT NOT NULL,
                    resolved_at   TEXT,
                    resolution    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_locations_org    ON locations(org_id);
                CREATE INDEX IF NOT EXISTS idx_events_org       ON access_events(org_id);
                CREATE INDEX IF NOT EXISTS idx_events_loc       ON access_events(location_id);
                CREATE INDEX IF NOT EXISTS idx_incidents_org    ON incidents(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # LOCATION MANAGEMENT
    # ------------------------------------------------------------------

    def register_location(self, org_id: str, data: LocationCreate) -> Dict[str, Any]:
        """Register a new physical location. Returns the location record."""
        if data.location_type not in _VALID_LOCATION_TYPES:
            raise ValueError(
                f"Invalid location_type '{data.location_type}'. "
                f"Must be one of {sorted(_VALID_LOCATION_TYPES)}"
            )
        if data.security_level not in _VALID_SECURITY_LEVELS:
            raise ValueError(
                f"Invalid security_level '{data.security_level}'. "
                f"Must be one of {sorted(_VALID_SECURITY_LEVELS)}"
            )

        location_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO locations
                   (id, org_id, name, address, location_type, security_level,
                    capacity, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    location_id, org_id, data.name, data.address,
                    data.location_type, data.security_level,
                    data.capacity, "active", now,
                ),
            )
        _logger.info(
            "physical_security.location_registered org=%s location_id=%s",
            org_id, location_id,
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "physical_security", "org_id": org_id, "source_engine": "physical_security"})
            except Exception:
                pass

        return self.get_location(org_id, location_id)

    def list_locations(
        self,
        org_id: str,
        location_type: Optional[str] = None,
        security_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List locations for org, optionally filtered by type or security level."""
        query = "SELECT * FROM locations WHERE org_id=?"
        params: List[Any] = [org_id]
        if location_type:
            query += " AND location_type=?"
            params.append(location_type)
        if security_level:
            query += " AND security_level=?"
            params.append(security_level)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_location(self, org_id: str, location_id: str) -> Dict[str, Any]:
        """Fetch a single location, scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM locations WHERE org_id=? AND id=?",
                (org_id, location_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Location {location_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # ACCESS EVENTS
    # ------------------------------------------------------------------

    def record_access_event(self, org_id: str, data: AccessEventCreate) -> Dict[str, Any]:
        """Record a physical access event."""
        if data.access_type not in _VALID_ACCESS_TYPES:
            raise ValueError(
                f"Invalid access_type '{data.access_type}'. "
                f"Must be one of {sorted(_VALID_ACCESS_TYPES)}"
            )
        if data.method not in _VALID_ACCESS_METHODS:
            raise ValueError(
                f"Invalid method '{data.method}'. "
                f"Must be one of {sorted(_VALID_ACCESS_METHODS)}"
            )

        # Verify location belongs to org
        self.get_location(org_id, data.location_id)

        event_id = str(uuid.uuid4())
        timestamp = data.timestamp or self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO access_events
                   (id, org_id, location_id, person_id, access_type, method, timestamp)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    event_id, org_id, data.location_id, data.person_id,
                    data.access_type, data.method, timestamp,
                ),
            )
        _logger.info(
            "physical_security.access_event org=%s event_id=%s type=%s",
            org_id, event_id, data.access_type,
        )
        return {
            "id": event_id,
            "org_id": org_id,
            "location_id": data.location_id,
            "person_id": data.person_id,
            "access_type": data.access_type,
            "method": data.method,
            "timestamp": timestamp,
        }

    def list_access_events(
        self,
        org_id: str,
        location_id: Optional[str] = None,
        access_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access events for org, optionally filtered, ordered by timestamp DESC."""
        query = "SELECT * FROM access_events WHERE org_id=?"
        params: List[Any] = [org_id]
        if location_id:
            query += " AND location_id=?"
            params.append(location_id)
        if access_type:
            query += " AND access_type=?"
            params.append(access_type)
        query += " ORDER BY timestamp DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # INCIDENT MANAGEMENT
    # ------------------------------------------------------------------

    def record_incident(self, org_id: str, data: IncidentCreate) -> Dict[str, Any]:
        """Record a new physical security incident."""
        if data.incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type '{data.incident_type}'. "
                f"Must be one of {sorted(_VALID_INCIDENT_TYPES)}"
            )
        if data.severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{data.severity}'. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        # Verify location belongs to org
        self.get_location(org_id, data.location_id)

        incident_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (id, org_id, location_id, incident_type, severity,
                    description, status, detected_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    incident_id, org_id, data.location_id, data.incident_type,
                    data.severity, data.description, "open", now,
                ),
            )
        _logger.info(
            "physical_security.incident_recorded org=%s incident_id=%s type=%s sev=%s",
            org_id, incident_id, data.incident_type, data.severity,
        )
        return self.get_incident(org_id, incident_id)

    def get_incident(self, org_id: str, incident_id: str) -> Dict[str, Any]:
        """Fetch a single incident, scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE org_id=? AND id=?",
                (org_id, incident_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Incident {incident_id} not found for org {org_id}")
        return dict(row)

    def resolve_incident(
        self, org_id: str, incident_id: str, resolution: str
    ) -> Dict[str, Any]:
        """Resolve an open incident."""
        # Verify incident belongs to org
        self.get_incident(org_id, incident_id)

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE incidents
                   SET status='resolved', resolved_at=?, resolution=?
                   WHERE org_id=? AND id=?""",
                (now, resolution, org_id, incident_id),
            )
        _logger.info(
            "physical_security.incident_resolved org=%s incident_id=%s",
            org_id, incident_id,
        )
        return self.get_incident(org_id, incident_id)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_physical_stats(self, org_id: str) -> Dict[str, Any]:
        """Return physical security overview stats for org_id."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._connect() as conn:
            total_locations = conn.execute(
                "SELECT COUNT(*) FROM locations WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT location_type, COUNT(*) as cnt FROM locations "
                "WHERE org_id=? GROUP BY location_type",
                (org_id,),
            ).fetchall()
            by_type = {r["location_type"]: r["cnt"] for r in type_rows}

            events_today = conn.execute(
                "SELECT COUNT(*) FROM access_events WHERE org_id=? AND timestamp>=?",
                (org_id, cutoff),
            ).fetchone()[0]

            denied_attempts = conn.execute(
                "SELECT COUNT(*) FROM access_events WHERE org_id=? AND access_type='denied'",
                (org_id,),
            ).fetchone()[0]

            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM incidents "
                "WHERE org_id=? AND status='open' GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_locations": total_locations,
            "by_type": by_type,
            "total_events_today": events_today,
            "denied_attempts": denied_attempts,
            "open_incidents": open_incidents,
            "by_severity": by_severity,
        }
