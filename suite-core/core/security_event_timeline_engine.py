"""Security Event Timeline Engine — ALDECI.

Reconstructs security event timelines for incident investigation.

Capabilities:
  - Timeline creation and management per incident
  - Event ingestion with start/end time tracking and duration computation
  - Event correlation (same_actor, causal, temporal, ioc_match, etc.)
  - Actor activity drill-down
  - Time-range filtering
  - Full-text search across actor/target/action/raw_data
  - Multi-tenant isolation via org_id
  - org-level summary

Compliance: NIST SP 800-61 (incident handling), ISO 27001 A.5.28
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

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_VALID_EVENT_TYPES = {
    "authentication",
    "authorization",
    "network",
    "file_access",
    "process_execution",
    "registry",
    "email",
    "web_request",
    "database",
    "lateral_movement",
    "data_access",
    "privilege_escalation",
}

_VALID_CORRELATION_TYPES = {
    "same_actor",
    "same_target",
    "causal",
    "temporal",
    "ioc_match",
}

_VALID_OUTCOMES = {"success", "failure", "blocked", "unknown"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"open", "closed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityEventTimelineEngine:
    """SQLite WAL-backed Security Event Timeline engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB: .fixops_data/security_event_timeline.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_event_timeline.db")
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
                CREATE TABLE IF NOT EXISTS timeline_events (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    incident_id   TEXT NOT NULL,
                    event_time    TEXT NOT NULL,
                    event_type    TEXT NOT NULL,
                    source_system TEXT NOT NULL,
                    actor         TEXT NOT NULL DEFAULT '',
                    target        TEXT NOT NULL DEFAULT '',
                    action        TEXT NOT NULL,
                    outcome       TEXT NOT NULL DEFAULT 'unknown',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    raw_data      TEXT NOT NULL DEFAULT '',
                    tags          TEXT NOT NULL DEFAULT '[]',
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tevt_org_inc
                    ON timeline_events (org_id, incident_id, event_time);

                CREATE TABLE IF NOT EXISTS timeline_correlations (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    incident_id        TEXT NOT NULL,
                    primary_event_id   TEXT NOT NULL,
                    correlated_event_id TEXT NOT NULL,
                    correlation_type   TEXT NOT NULL,
                    confidence         REAL NOT NULL DEFAULT 0.5,
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tcorr_org_inc
                    ON timeline_correlations (org_id, incident_id);

                CREATE TABLE IF NOT EXISTS incident_timelines (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    incident_id    TEXT NOT NULL,
                    title          TEXT NOT NULL,
                    event_count    INTEGER NOT NULL DEFAULT 0,
                    start_time     TEXT,
                    end_time       TEXT,
                    duration_mins  REAL NOT NULL DEFAULT 0.0,
                    status         TEXT NOT NULL DEFAULT 'open',
                    created_at     TEXT NOT NULL,
                    UNIQUE(org_id, incident_id)
                );

                CREATE INDEX IF NOT EXISTS idx_itl_org
                    ON incident_timelines (org_id, status, created_at DESC);
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
    # Timeline management
    # ------------------------------------------------------------------

    def create_timeline(
        self, org_id: str, incident_id: str, title: str
    ) -> Dict[str, Any]:
        """Create a new incident timeline. Returns status=open, event_count=0."""
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "title": title,
            "event_count": 0,
            "start_time": None,
            "end_time": None,
            "duration_mins": 0.0,
            "status": "open",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO incident_timelines
                       (id, org_id, incident_id, title, event_count, start_time,
                        end_time, duration_mins, status, created_at)
                       VALUES (:id, :org_id, :incident_id, :title, :event_count,
                               :start_time, :end_time, :duration_mins, :status, :created_at)""",
                    record,
                )
        return record

    def close_timeline(self, timeline_id: str, org_id: str) -> Dict[str, Any]:
        """Set timeline status to closed."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM incident_timelines WHERE id=? AND org_id=?",
                    (timeline_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Timeline {timeline_id!r} not found for org {org_id!r}.")
                conn.execute(
                    "UPDATE incident_timelines SET status='closed' WHERE id=? AND org_id=?",
                    (timeline_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM incident_timelines WHERE id=? AND org_id=?",
                    (timeline_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def add_event(
        self,
        org_id: str,
        incident_id: str,
        event_time: str,
        event_type: str,
        source_system: str,
        actor: str,
        target: str,
        action: str,
        outcome: str,
        severity: str,
        raw_data: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Add a security event to the incident timeline.

        Updates the timeline header:
          - event_count += 1
          - start_time = MIN(event_time, current_start)
          - end_time   = MAX(event_time, current_end)
          - duration_mins computed via julianday arithmetic in SQL
        """
        if tags is None:
            tags = []
        tags_json = json.dumps(tags)
        now = _now_iso()
        event = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "event_time": event_time,
            "event_type": event_type,
            "source_system": source_system,
            "actor": actor,
            "target": target,
            "action": action,
            "outcome": outcome if outcome in _VALID_OUTCOMES else "unknown",
            "severity": severity if severity in _VALID_SEVERITIES else "medium",
            "raw_data": raw_data,
            "tags": tags_json,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                # Verify timeline exists
                tl_row = conn.execute(
                    "SELECT * FROM incident_timelines WHERE org_id=? AND incident_id=?",
                    (org_id, incident_id),
                ).fetchone()
                if not tl_row:
                    raise KeyError(
                        f"No timeline found for incident {incident_id!r} in org {org_id!r}."
                    )

                conn.execute(
                    """INSERT INTO timeline_events
                       (id, org_id, incident_id, event_time, event_type, source_system,
                        actor, target, action, outcome, severity, raw_data, tags, created_at)
                       VALUES (:id, :org_id, :incident_id, :event_time, :event_type,
                               :source_system, :actor, :target, :action, :outcome,
                               :severity, :raw_data, :tags, :created_at)""",
                    event,
                )

                # Update timeline header using julianday arithmetic for duration
                conn.execute(
                    """UPDATE incident_timelines SET
                           event_count = event_count + 1,
                           start_time  = CASE
                               WHEN start_time IS NULL THEN :event_time
                               WHEN :event_time < start_time THEN :event_time
                               ELSE start_time
                           END,
                           end_time    = CASE
                               WHEN end_time IS NULL THEN :event_time
                               WHEN :event_time > end_time THEN :event_time
                               ELSE end_time
                           END,
                           duration_mins = CASE
                               WHEN start_time IS NULL OR end_time IS NULL THEN 0.0
                               WHEN (julianday(CASE WHEN :event_time > COALESCE(end_time, '') THEN :event_time ELSE end_time END)
                                    - julianday(CASE WHEN :event_time < COALESCE(start_time, :event_time) THEN :event_time ELSE start_time END)) * 1440.0 < 0
                                    THEN 0.0
                               ELSE (julianday(CASE WHEN :event_time > COALESCE(end_time, '') THEN :event_time ELSE end_time END)
                                    - julianday(CASE WHEN :event_time < COALESCE(start_time, :event_time) THEN :event_time ELSE start_time END)) * 1440.0
                           END
                       WHERE org_id=:org_id AND incident_id=:incident_id""",
                    {
                        "event_time": event_time,
                        "org_id": org_id,
                        "incident_id": incident_id,
                    },
                )

                # Recompute duration_mins cleanly after update
                tl_updated = conn.execute(
                    "SELECT * FROM incident_timelines WHERE org_id=? AND incident_id=?",
                    (org_id, incident_id),
                ).fetchone()
                if tl_updated and tl_updated["start_time"] and tl_updated["end_time"]:
                    conn.execute(
                        """UPDATE incident_timelines SET
                               duration_mins = (julianday(end_time) - julianday(start_time)) * 1440.0
                           WHERE org_id=? AND incident_id=?""",
                        (org_id, incident_id),
                    )

        return event

    def correlate_events(
        self,
        org_id: str,
        incident_id: str,
        primary_event_id: str,
        correlated_event_id: str,
        correlation_type: str,
        confidence: float,
    ) -> Dict[str, Any]:
        """Create a correlation between two events. Confidence clamped 0.0-1.0."""
        confidence = max(0.0, min(1.0, float(confidence)))
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "primary_event_id": primary_event_id,
            "correlated_event_id": correlated_event_id,
            "correlation_type": correlation_type,
            "confidence": confidence,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO timeline_correlations
                       (id, org_id, incident_id, primary_event_id, correlated_event_id,
                        correlation_type, confidence, created_at)
                       VALUES (:id, :org_id, :incident_id, :primary_event_id,
                               :correlated_event_id, :correlation_type, :confidence, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_timeline(self, org_id: str, incident_id: str) -> Dict[str, Any]:
        """Return timeline header + events ordered by event_time + correlations."""
        with self._conn() as conn:
            tl_row = conn.execute(
                "SELECT * FROM incident_timelines WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            ).fetchone()
            if not tl_row:
                return {}

            events = conn.execute(
                """SELECT * FROM timeline_events
                   WHERE org_id=? AND incident_id=?
                   ORDER BY event_time ASC""",
                (org_id, incident_id),
            ).fetchall()

            correlations = conn.execute(
                """SELECT * FROM timeline_correlations
                   WHERE org_id=? AND incident_id=?""",
                (org_id, incident_id),
            ).fetchall()

        result = self._row(tl_row)
        result["events"] = [self._row(e) for e in events]
        result["correlations"] = [self._row(c) for c in correlations]
        return result

    def get_event_sequence(
        self,
        org_id: str,
        incident_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return events filtered by optional time range, ordered by event_time."""
        query = "SELECT * FROM timeline_events WHERE org_id=? AND incident_id=?"
        params: List[Any] = [org_id, incident_id]
        if start_time:
            query += " AND event_time >= ?"
            params.append(start_time)
        if end_time:
            query += " AND event_time <= ?"
            params.append(end_time)
        query += " ORDER BY event_time ASC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_actor_activity(
        self, org_id: str, incident_id: str, actor: str
    ) -> List[Dict[str, Any]]:
        """Return all events where actor matches, ordered by event_time."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM timeline_events
                   WHERE org_id=? AND incident_id=? AND actor=?
                   ORDER BY event_time ASC""",
                (org_id, incident_id, actor),
            ).fetchall()
        return [self._row(r) for r in rows]

    def get_timeline_summary(self, org_id: str) -> Dict[str, Any]:
        """Return org-level summary: totals, open count, by_event_type, recent_timelines."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM incident_timelines WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_count = conn.execute(
                "SELECT COUNT(*) FROM incident_timelines WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM timeline_events WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                """SELECT event_type, COUNT(*) as cnt
                   FROM timeline_events WHERE org_id=?
                   GROUP BY event_type""",
                (org_id,),
            ).fetchall()
            by_event_type = {r["event_type"]: r["cnt"] for r in by_type_rows}

            recent_rows = conn.execute(
                """SELECT * FROM incident_timelines WHERE org_id=?
                   ORDER BY created_at DESC LIMIT 5""",
                (org_id,),
            ).fetchall()

        return {
            "total_timelines": total,
            "open_count": open_count,
            "total_events": total_events,
            "by_event_type": by_event_type,
            "recent_timelines": [self._row(r) for r in recent_rows],
        }

    def search_events(self, org_id: str, query: str) -> List[Dict[str, Any]]:
        """LIKE search on actor, target, action, raw_data fields."""
        pattern = f"%{query}%"
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM timeline_events
                   WHERE org_id=?
                     AND (actor LIKE ? OR target LIKE ? OR action LIKE ? OR raw_data LIKE ?)
                   ORDER BY event_time ASC""",
                (org_id, pattern, pattern, pattern, pattern),
            ).fetchall()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_event_timeline", "org_id": org_id, "source_engine": "security_event_timeline"})
            except Exception:
                pass

        return [self._row(r) for r in rows]
