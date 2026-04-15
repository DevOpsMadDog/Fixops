"""SIEM Integration Engine — ALDECI.

Receives, normalizes, and correlates events from Splunk, QRadar,
Elastic SIEM, and Microsoft Sentinel.

Compliance: NIST CSF DE.CM, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "siem_integration.db"
)

_VALID_SIEM_TYPES = {"splunk", "qradar", "elastic", "sentinel", "generic"}
_VALID_EVENT_TYPES = {"auth", "network", "endpoint", "application"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_ALERT_STATUSES = {"open", "acknowledged", "resolved"}


class SIEMIntegrationEngine:
    """SQLite WAL-backed SIEM Integration engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Supports Splunk, QRadar, Elastic SIEM, and Microsoft Sentinel.
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
                CREATE TABLE IF NOT EXISTS siem_integrations (
                    siem_id         TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    siem_name       TEXT NOT NULL DEFAULT '',
                    siem_type       TEXT NOT NULL DEFAULT 'generic',
                    host            TEXT NOT NULL DEFAULT '',
                    port            INTEGER NOT NULL DEFAULT 0,
                    api_token_hash  TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    index_name      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_org
                    ON siem_integrations (org_id, enabled);

                CREATE TABLE IF NOT EXISTS siem_events (
                    event_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    siem_id             TEXT NOT NULL,
                    raw_event           TEXT NOT NULL DEFAULT '{}',
                    event_type          TEXT NOT NULL DEFAULT 'application',
                    severity            TEXT NOT NULL DEFAULT 'info',
                    source_ip           TEXT NOT NULL DEFAULT '',
                    destination_ip      TEXT NOT NULL DEFAULT '',
                    user                TEXT NOT NULL DEFAULT '',
                    timestamp           TEXT NOT NULL,
                    normalized_fields   TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_evt_org_siem
                    ON siem_events (org_id, siem_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_evt_org_type_sev
                    ON siem_events (org_id, event_type, severity, timestamp);

                CREATE TABLE IF NOT EXISTS siem_alerts (
                    alert_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    title               TEXT NOT NULL DEFAULT '',
                    description         TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    status              TEXT NOT NULL DEFAULT 'open',
                    source_event_ids    TEXT NOT NULL DEFAULT '[]',
                    assignee            TEXT NOT NULL DEFAULT '',
                    resolved_by         TEXT NOT NULL DEFAULT '',
                    resolution_notes    TEXT NOT NULL DEFAULT '',
                    created_at          TEXT NOT NULL,
                    resolved_at         TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_alert_org_status
                    ON siem_alerts (org_id, status, severity);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # SIEM management
    # ------------------------------------------------------------------

    def register_siem(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new SIEM integration."""
        siem_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        siem_type = data.get("siem_type", "generic")
        if siem_type not in _VALID_SIEM_TYPES:
            siem_type = "generic"

        raw_token = data.get("api_token", "")
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest() if raw_token else ""

        row = {
            "siem_id": siem_id,
            "org_id": org_id,
            "siem_name": data.get("siem_name", ""),
            "siem_type": siem_type,
            "host": data.get("host", ""),
            "port": int(data.get("port", 0)),
            "api_token_hash": token_hash,
            "enabled": 1 if data.get("enabled", True) else 0,
            "index_name": data.get("index_name", ""),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_integrations
                   (siem_id, org_id, siem_name, siem_type, host, port,
                    api_token_hash, enabled, index_name, created_at, updated_at)
                   VALUES (:siem_id, :org_id, :siem_name, :siem_type, :host, :port,
                    :api_token_hash, :enabled, :index_name, :created_at, :updated_at)""",
                row,
            )
        result = dict(row)
        result["enabled"] = bool(result["enabled"])
        return result

    def list_siems(self, org_id: str) -> List[Dict[str, Any]]:
        """List all registered SIEMs for an org."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM siem_integrations WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._siem_row(r) for r in rows]

    def get_siem(self, org_id: str, siem_id: str) -> Optional[Dict[str, Any]]:
        """Get a single SIEM integration."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM siem_integrations WHERE org_id = ? AND siem_id = ?",
                (org_id, siem_id),
            ).fetchone()
        return self._siem_row(row) if row else None

    def update_siem_status(self, org_id: str, siem_id: str, enabled: bool) -> bool:
        """Enable or disable a SIEM integration."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as conn:
            result = conn.execute(
                "UPDATE siem_integrations SET enabled = ?, updated_at = ? WHERE org_id = ? AND siem_id = ?",
                (1 if enabled else 0, now, org_id, siem_id),
            )
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize and store a SIEM event."""
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        event_type = data.get("event_type", "application")
        if event_type not in _VALID_EVENT_TYPES:
            event_type = "application"

        severity = data.get("severity", "info")
        if severity not in _VALID_SEVERITIES:
            severity = "info"

        # Normalize raw event fields
        raw_event = data.get("raw_event", {})
        if isinstance(raw_event, str):
            try:
                raw_event = json.loads(raw_event)
            except (json.JSONDecodeError, ValueError):
                raw_event = {"raw": raw_event}

        normalized_fields = self._normalize_event(event_type, raw_event, data)

        timestamp = data.get("timestamp", now)

        row = {
            "event_id": event_id,
            "org_id": org_id,
            "siem_id": data.get("siem_id", ""),
            "raw_event": json.dumps(raw_event),
            "event_type": event_type,
            "severity": severity,
            "source_ip": data.get("source_ip", ""),
            "destination_ip": data.get("destination_ip", ""),
            "user": data.get("user", ""),
            "timestamp": timestamp,
            "normalized_fields": json.dumps(normalized_fields),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_events
                   (event_id, org_id, siem_id, raw_event, event_type, severity,
                    source_ip, destination_ip, user, timestamp, normalized_fields, created_at)
                   VALUES (:event_id, :org_id, :siem_id, :raw_event, :event_type, :severity,
                    :source_ip, :destination_ip, :user, :timestamp, :normalized_fields, :created_at)""",
                row,
            )
        result = dict(row)
        result["raw_event"] = raw_event
        result["normalized_fields"] = normalized_fields
        return result

    def list_events(
        self,
        org_id: str,
        siem_id: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """List events with optional filters."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        query = "SELECT * FROM siem_events WHERE org_id = ? AND timestamp >= ?"
        params: List[Any] = [org_id, cutoff]

        if siem_id:
            query += " AND siem_id = ?"
            params.append(siem_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._event_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate_events(
        self, org_id: str, correlation_rule: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Apply a correlation rule and return matched event groups.

        Supported rule fields:
          - event_type: filter by event type
          - severity: minimum severity to consider
          - field: which field to group by (e.g. 'user', 'source_ip')
          - threshold: minimum event count in the window
          - window_hours: time window in hours (default 1)
          - action: description of the detected behavior
        """
        event_type = correlation_rule.get("event_type")
        severity = correlation_rule.get("severity")
        group_field = correlation_rule.get("field", "user")
        threshold = int(correlation_rule.get("threshold", 5))
        window_hours = int(correlation_rule.get("window_hours", 1))
        action = correlation_rule.get("action", "repeated_event")

        events = self.list_events(
            org_id,
            event_type=event_type,
            severity=severity,
            limit=1000,
            hours=window_hours,
        )

        # Group events by the specified field
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for evt in events:
            key = evt.get(group_field, "") or evt.get("normalized_fields", {}).get(group_field, "")
            if not key:
                continue
            groups.setdefault(key, []).append(evt)

        matched = []
        for key, group_events in groups.items():
            if len(group_events) >= threshold:
                matched.append({
                    "group_key": key,
                    "group_field": group_field,
                    "event_count": len(group_events),
                    "threshold": threshold,
                    "action": action,
                    "window_hours": window_hours,
                    "event_ids": [e["event_id"] for e in group_events],
                    "events": group_events,
                })
        return matched

    # ------------------------------------------------------------------
    # Alert management
    # ------------------------------------------------------------------

    def create_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a SIEM alert."""
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        source_event_ids = data.get("source_event_ids", [])
        if not isinstance(source_event_ids, list):
            source_event_ids = []

        row = {
            "alert_id": alert_id,
            "org_id": org_id,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "severity": severity,
            "status": "open",
            "source_event_ids": json.dumps(source_event_ids),
            "assignee": data.get("assignee", ""),
            "resolved_by": "",
            "resolution_notes": "",
            "created_at": now,
            "resolved_at": "",
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_alerts
                   (alert_id, org_id, title, description, severity, status,
                    source_event_ids, assignee, resolved_by, resolution_notes,
                    created_at, resolved_at)
                   VALUES (:alert_id, :org_id, :title, :description, :severity, :status,
                    :source_event_ids, :assignee, :resolved_by, :resolution_notes,
                    :created_at, :resolved_at)""",
                row,
            )
        result = dict(row)
        result["source_event_ids"] = source_event_ids
        return result

    def list_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filters."""
        query = "SELECT * FROM siem_alerts WHERE org_id = ?"
        params: List[Any] = [org_id]

        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._alert_row(r) for r in rows]

    def resolve_alert(
        self,
        org_id: str,
        alert_id: str,
        resolved_by: str,
        resolution_notes: str = "",
    ) -> bool:
        """Resolve an alert."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as conn:
            result = conn.execute(
                """UPDATE siem_alerts
                   SET status = 'resolved', resolved_by = ?, resolution_notes = ?, resolved_at = ?
                   WHERE org_id = ? AND alert_id = ?""",
                (resolved_by, resolution_notes, now, org_id, alert_id),
            )
        return result.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_siem_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for the org."""
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        cutoff_7d = (now - timedelta(days=7)).isoformat()

        with self._lock, self._conn() as conn:
            total_siems = conn.execute(
                "SELECT COUNT(*) FROM siem_integrations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_siems = conn.execute(
                "SELECT COUNT(*) FROM siem_integrations WHERE org_id = ? AND enabled = 1",
                (org_id,),
            ).fetchone()[0]

            events_24h = conn.execute(
                "SELECT COUNT(*) FROM siem_events WHERE org_id = ? AND timestamp >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            events_7d = conn.execute(
                "SELECT COUNT(*) FROM siem_events WHERE org_id = ? AND timestamp >= ?",
                (org_id, cutoff_7d),
            ).fetchone()[0]

            # By SIEM type
            type_rows = conn.execute(
                """SELECT si.siem_type, COUNT(se.event_id) as cnt
                   FROM siem_integrations si
                   LEFT JOIN siem_events se ON si.siem_id = se.siem_id AND se.org_id = ?
                   WHERE si.org_id = ?
                   GROUP BY si.siem_type""",
                (org_id, org_id),
            ).fetchall()
            by_siem_type = {r["siem_type"]: r["cnt"] for r in type_rows}

            # By severity (24h)
            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM siem_events
                   WHERE org_id = ? AND timestamp >= ?
                   GROUP BY severity""",
                (org_id, cutoff_24h),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            alert_count = conn.execute(
                "SELECT COUNT(*) FROM siem_alerts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM siem_alerts WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_siems": total_siems,
            "active_siems": active_siems,
            "events_24h": events_24h,
            "events_7d": events_7d,
            "by_siem_type": by_siem_type,
            "by_severity": by_severity,
            "alert_count": alert_count,
            "open_alerts": open_alerts,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalize_event(
        self,
        event_type: str,
        raw_event: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Extract normalized fields from a raw event based on event type."""
        normalized: Dict[str, Any] = {}

        if event_type == "auth":
            normalized["action"] = raw_event.get("action", data.get("action", ""))
            normalized["outcome"] = raw_event.get("outcome", data.get("outcome", ""))
            normalized["auth_method"] = raw_event.get("auth_method", "")
            normalized["target_resource"] = raw_event.get("target_resource", "")
        elif event_type == "network":
            normalized["protocol"] = raw_event.get("protocol", "")
            normalized["bytes_sent"] = raw_event.get("bytes_sent", 0)
            normalized["bytes_received"] = raw_event.get("bytes_received", 0)
            normalized["direction"] = raw_event.get("direction", "")
            normalized["action"] = raw_event.get("action", "")
        elif event_type == "endpoint":
            normalized["process_name"] = raw_event.get("process_name", "")
            normalized["process_id"] = raw_event.get("process_id", "")
            normalized["file_path"] = raw_event.get("file_path", "")
            normalized["action"] = raw_event.get("action", "")
            normalized["hash"] = raw_event.get("hash", "")
        elif event_type == "application":
            normalized["app_name"] = raw_event.get("app_name", "")
            normalized["error_code"] = raw_event.get("error_code", "")
            normalized["message"] = raw_event.get("message", "")
            normalized["url"] = raw_event.get("url", "")

        # Common normalized fields
        normalized["raw_timestamp"] = raw_event.get("timestamp", data.get("timestamp", ""))
        return normalized

    def _siem_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    def _event_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("raw_event", "normalized_fields"):
            if isinstance(d.get(field), str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, ValueError):
                    d[field] = {}
        return d

    def _alert_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if isinstance(d.get("source_event_ids"), str):
            try:
                d["source_event_ids"] = json.loads(d["source_event_ids"])
            except (json.JSONDecodeError, ValueError):
                d["source_event_ids"] = []
        return d
