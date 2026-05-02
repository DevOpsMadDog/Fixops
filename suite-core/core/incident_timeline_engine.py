"""Incident Timeline Builder Engine — ALDECI.

Tracks security incidents across their full lifecycle with structured timelines,
events, affected systems, and derived metrics (MTTD/MTTR/MTTC).

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "incident_timeline.db"
)

_VALID_INCIDENT_TYPES = {
    "breach", "ransomware", "phishing", "insider", "ddos", "supply_chain", "unknown",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "contained", "resolved", "closed"}
_VALID_EVENT_TYPES = {
    "detection", "alert", "escalation", "action", "communication",
    "containment", "eradication", "recovery", "lesson_learned",
}


class IncidentTimelineEngine:
    """SQLite WAL-backed incident timeline engine.

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
                CREATE TABLE IF NOT EXISTS timelines (
                    timeline_id   TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    title         TEXT NOT NULL,
                    incident_type TEXT NOT NULL DEFAULT 'unknown',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    status        TEXT NOT NULL DEFAULT 'active',
                    summary       TEXT NOT NULL DEFAULT '',
                    started_at    DATETIME NOT NULL,
                    contained_at  DATETIME,
                    resolved_at   DATETIME,
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tl_org
                    ON timelines (org_id, status);

                CREATE TABLE IF NOT EXISTS timeline_events (
                    event_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    timeline_id   TEXT NOT NULL,
                    event_time    DATETIME NOT NULL,
                    event_type    TEXT NOT NULL DEFAULT 'action',
                    title         TEXT NOT NULL,
                    description   TEXT NOT NULL DEFAULT '',
                    actor         TEXT NOT NULL DEFAULT '',
                    source_system TEXT NOT NULL DEFAULT '',
                    evidence_refs TEXT NOT NULL DEFAULT '[]',
                    severity      TEXT NOT NULL DEFAULT 'info',
                    created_at    DATETIME NOT NULL,
                    FOREIGN KEY (timeline_id) REFERENCES timelines (timeline_id)
                );

                CREATE INDEX IF NOT EXISTS idx_te_org_timeline
                    ON timeline_events (org_id, timeline_id, event_time ASC);

                CREATE TABLE IF NOT EXISTS affected_systems (
                    system_id          TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    timeline_id        TEXT NOT NULL,
                    hostname           TEXT NOT NULL DEFAULT '',
                    ip_address         TEXT NOT NULL DEFAULT '',
                    system_type        TEXT NOT NULL DEFAULT '',
                    affected_at        DATETIME NOT NULL,
                    restored_at        DATETIME,
                    impact_description TEXT NOT NULL DEFAULT '',
                    FOREIGN KEY (timeline_id) REFERENCES timelines (timeline_id)
                );

                CREATE INDEX IF NOT EXISTS idx_as_org_timeline
                    ON affected_systems (org_id, timeline_id);

                CREATE TABLE IF NOT EXISTS timeline_metrics (
                    metric_id              TEXT PRIMARY KEY,
                    org_id                 TEXT NOT NULL,
                    timeline_id            TEXT NOT NULL,
                    mttd_minutes           REAL,
                    mttr_minutes           REAL,
                    mttc_minutes           REAL,
                    total_events           INTEGER NOT NULL DEFAULT 0,
                    affected_systems_count INTEGER NOT NULL DEFAULT 0,
                    calculated_at          DATETIME NOT NULL,
                    FOREIGN KEY (timeline_id) REFERENCES timelines (timeline_id)
                );

                CREATE INDEX IF NOT EXISTS idx_tm_org_timeline
                    ON timeline_metrics (org_id, timeline_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _minutes_between(start_iso: Optional[str], end_iso: Optional[str]) -> Optional[float]:
        """Return minutes between two ISO timestamps, or None if either is missing."""
        if not start_iso or not end_iso:
            return None
        try:
            def _parse(s: str) -> datetime:
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S.%f+00:00",
                    "%Y-%m-%dT%H:%M:%S+00:00",
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%S",
                ):
                    try:
                        return datetime.strptime(s, fmt)
                    except ValueError:
                        continue
                raise ValueError(f"Cannot parse datetime: {s}")

            delta = _parse(end_iso) - _parse(start_iso)
            return max(0.0, delta.total_seconds() / 60.0)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Timelines
    # ------------------------------------------------------------------

    def create_timeline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new incident timeline. Returns the created record."""
        title = data.get("title", "")
        if not title:
            raise ValueError("title is required.")

        incident_type = data.get("incident_type", "unknown")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(f"Invalid incident_type: {incident_type}. Must be one of {_VALID_INCIDENT_TYPES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        timeline_id = str(uuid.uuid4())
        now = self._now()
        started_at = data.get("started_at", now)

        record = {
            "timeline_id": timeline_id,
            "org_id": org_id,
            "title": title,
            "incident_type": incident_type,
            "severity": severity,
            "status": "active",
            "summary": data.get("summary", ""),
            "started_at": started_at,
            "contained_at": None,
            "resolved_at": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO timelines
                        (timeline_id, org_id, title, incident_type, severity, status,
                         summary, started_at, contained_at, resolved_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["timeline_id"], org_id, title, incident_type, severity,
                        "active", record["summary"], started_at,
                        None, None, now,
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("INCIDENT_CREATED", {"entity_type": "incident_timeline", "org_id": org_id, "source_engine": "incident_timeline"})
            except Exception:
                pass

        return record

    def list_timelines(
        self,
        org_id: str,
        status: Optional[str] = None,
        incident_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List timelines with optional status/incident_type filters."""
        query = "SELECT * FROM timelines WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if incident_type:
            query += " AND incident_type=?"
            params.append(incident_type)
        query += " ORDER BY started_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_timeline(self, org_id: str, timeline_id: str) -> Optional[Dict[str, Any]]:
        """Get a single timeline by ID, scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM timelines WHERE org_id=? AND timeline_id=?",
                (org_id, timeline_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_timeline_status(
        self,
        org_id: str,
        timeline_id: str,
        status: str,
        timestamp_field: Optional[str] = None,
    ) -> bool:
        """Update timeline status and optionally set contained_at/resolved_at.

        If status is 'contained' and timestamp_field is not explicitly given,
        auto-sets contained_at. If status is 'resolved' or 'closed', auto-sets
        resolved_at. Returns True if the record was found and updated.
        """
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_STATUSES}")

        now = self._now()

        # Determine which timestamp column to set
        ts_col = timestamp_field  # caller override
        if ts_col is None:
            if status == "contained":
                ts_col = "contained_at"
            elif status in ("resolved", "closed"):
                ts_col = "resolved_at"

        with self._lock:
            with self._conn() as conn:
                if ts_col in ("contained_at", "resolved_at"):
                    cur = conn.execute(
                        f"UPDATE timelines SET status=?, {ts_col}=? WHERE org_id=? AND timeline_id=?",  # nosec B608
                        (status, now, org_id, timeline_id),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE timelines SET status=? WHERE org_id=? AND timeline_id=?",
                        (status, org_id, timeline_id),
                    )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def add_event(self, org_id: str, timeline_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an event to a timeline. Returns the created event record."""
        event_type = data.get("event_type", "action")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}. Must be one of {_VALID_EVENT_TYPES}")

        severity = data.get("severity", "info")
        if severity not in (_VALID_SEVERITIES | {"info"}):
            raise ValueError(f"Invalid severity: {severity}")

        # Normalize evidence_refs: accept list or JSON string
        evidence_refs = data.get("evidence_refs", [])
        if isinstance(evidence_refs, str):
            try:
                evidence_refs = json.loads(evidence_refs)
            except (json.JSONDecodeError, ValueError):
                evidence_refs = []
        evidence_refs_json = json.dumps(evidence_refs)

        event_id = str(uuid.uuid4())
        now = self._now()
        event_time = data.get("event_time", now)

        record = {
            "event_id": event_id,
            "org_id": org_id,
            "timeline_id": timeline_id,
            "event_time": event_time,
            "event_type": event_type,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "actor": data.get("actor", ""),
            "source_system": data.get("source_system", ""),
            "evidence_refs": evidence_refs,
            "severity": severity,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO timeline_events
                        (event_id, org_id, timeline_id, event_time, event_type,
                         title, description, actor, source_system,
                         evidence_refs, severity, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event_id, org_id, timeline_id, event_time, event_type,
                        record["title"], record["description"], record["actor"],
                        record["source_system"], evidence_refs_json, severity, now,
                    ),
                )
        return record

    def list_events(
        self,
        org_id: str,
        timeline_id: str,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List events for a timeline ordered by event_time ascending."""
        query = "SELECT * FROM timeline_events WHERE org_id=? AND timeline_id=?"
        params: list = [org_id, timeline_id]
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)
        query += " ORDER BY event_time ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            try:
                d["evidence_refs"] = json.loads(d.get("evidence_refs") or "[]")
            except (json.JSONDecodeError, ValueError):
                d["evidence_refs"] = []
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Affected systems
    # ------------------------------------------------------------------

    def add_affected_system(
        self, org_id: str, timeline_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an affected system record to a timeline."""
        system_id = str(uuid.uuid4())
        now = self._now()
        affected_at = data.get("affected_at", now)

        record = {
            "system_id": system_id,
            "org_id": org_id,
            "timeline_id": timeline_id,
            "hostname": data.get("hostname", ""),
            "ip_address": data.get("ip_address", ""),
            "system_type": data.get("system_type", ""),
            "affected_at": affected_at,
            "restored_at": data.get("restored_at"),
            "impact_description": data.get("impact_description", ""),
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO affected_systems
                        (system_id, org_id, timeline_id, hostname, ip_address,
                         system_type, affected_at, restored_at, impact_description)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        system_id, org_id, timeline_id,
                        record["hostname"], record["ip_address"], record["system_type"],
                        affected_at, record["restored_at"], record["impact_description"],
                    ),
                )
        return record

    def list_affected_systems(self, org_id: str, timeline_id: str) -> List[Dict[str, Any]]:
        """List affected systems for a timeline."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM affected_systems WHERE org_id=? AND timeline_id=? ORDER BY affected_at ASC",
                (org_id, timeline_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def calculate_metrics(self, org_id: str, timeline_id: str) -> Dict[str, Any]:
        """Calculate and persist metrics for a timeline.

        MTTD = minutes from started_at to first 'detection' event.
        MTTC = minutes from started_at to contained_at.
        MTTR = minutes from started_at to resolved_at.
        Returns the metrics record.
        """
        timeline = self.get_timeline(org_id, timeline_id)
        if not timeline:
            raise ValueError(f"Timeline {timeline_id} not found for org {org_id}")

        started_at = timeline.get("started_at")
        contained_at = timeline.get("contained_at")
        resolved_at = timeline.get("resolved_at")

        # MTTD: time from start to first detection event
        events = self.list_events(org_id, timeline_id)
        detection_events = [e for e in events if e.get("event_type") == "detection"]
        first_detection_time = detection_events[0]["event_time"] if detection_events else None

        mttd = self._minutes_between(started_at, first_detection_time)
        mttc = self._minutes_between(started_at, contained_at)
        mttr = self._minutes_between(started_at, resolved_at)

        systems = self.list_affected_systems(org_id, timeline_id)

        metric_id = str(uuid.uuid4())
        now = self._now()

        record = {
            "metric_id": metric_id,
            "org_id": org_id,
            "timeline_id": timeline_id,
            "mttd_minutes": mttd,
            "mttr_minutes": mttr,
            "mttc_minutes": mttc,
            "total_events": len(events),
            "affected_systems_count": len(systems),
            "calculated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO timeline_metrics
                        (metric_id, org_id, timeline_id, mttd_minutes, mttr_minutes,
                         mttc_minutes, total_events, affected_systems_count, calculated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        metric_id, org_id, timeline_id,
                        mttd, mttr, mttc,
                        len(events), len(systems), now,
                    ),
                )
        return record

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_timeline_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate timeline statistics for an org."""
        with self._conn() as conn:
            total_timelines = conn.execute(
                "SELECT COUNT(*) FROM timelines WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_incidents = conn.execute(
                "SELECT COUNT(*) FROM timelines WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]

            resolved_incidents = conn.execute(
                "SELECT COUNT(*) FROM timelines WHERE org_id=? AND status IN ('resolved','closed')",
                (org_id,),
            ).fetchone()[0]

            # Avg MTTD / MTTR from metrics (latest per timeline)
            mttd_row = conn.execute(
                """
                SELECT AVG(m.mttd_minutes) FROM timeline_metrics m
                INNER JOIN (
                    SELECT timeline_id, MAX(calculated_at) AS latest
                    FROM timeline_metrics WHERE org_id=? GROUP BY timeline_id
                ) sub ON m.timeline_id=sub.timeline_id AND m.calculated_at=sub.latest
                WHERE m.org_id=?
                """,
                (org_id, org_id),
            ).fetchone()
            avg_mttd = mttd_row[0] if mttd_row and mttd_row[0] is not None else None

            mttr_row = conn.execute(
                """
                SELECT AVG(m.mttr_minutes) FROM timeline_metrics m
                INNER JOIN (
                    SELECT timeline_id, MAX(calculated_at) AS latest
                    FROM timeline_metrics WHERE org_id=? GROUP BY timeline_id
                ) sub ON m.timeline_id=sub.timeline_id AND m.calculated_at=sub.latest
                WHERE m.org_id=?
                """,
                (org_id, org_id),
            ).fetchone()
            avg_mttr = mttr_row[0] if mttr_row and mttr_row[0] is not None else None

            # By type
            type_rows = conn.execute(
                "SELECT incident_type, COUNT(*) as cnt FROM timelines WHERE org_id=? GROUP BY incident_type",
                (org_id,),
            ).fetchall()
            by_type = {r["incident_type"]: r["cnt"] for r in type_rows}

            # By severity
            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM timelines WHERE org_id=? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "total_timelines": total_timelines,
            "active_incidents": active_incidents,
            "resolved_incidents": resolved_incidents,
            "avg_mttd": avg_mttd,
            "avg_mttr": avg_mttr,
            "by_type": by_type,
            "by_severity": by_severity,
        }
