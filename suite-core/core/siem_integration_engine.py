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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "siem_integration.db"
)

_VALID_SIEM_TYPES = {"splunk", "qradar", "elastic", "sentinel", "generic", "chronicle", "datadog"}
_VALID_EVENT_TYPES = {"auth", "network", "endpoint", "application"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_ALERT_STATUSES = {"open", "acknowledged", "resolved"}

# New source-based schema constants
_VALID_SOURCE_TYPES = {
    "syslog", "windows_event", "cloudtrail", "azure_monitor", "gcp_logging", "custom"
}
_VALID_EVENT_SEVERITIES = {"info", "low", "medium", "high", "critical"}


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

                CREATE TABLE IF NOT EXISTS siem_sources (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    source_type  TEXT NOT NULL,
                    host         TEXT,
                    port         INTEGER,
                    status       TEXT NOT NULL DEFAULT 'active',
                    events_per_day INTEGER NOT NULL DEFAULT 0,
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_sources_org
                    ON siem_sources (org_id);

                CREATE TABLE IF NOT EXISTS siem_source_events (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    source_id     TEXT NOT NULL,
                    event_type    TEXT NOT NULL,
                    severity      TEXT NOT NULL,
                    raw_data      TEXT NOT NULL,
                    parsed_fields TEXT,
                    timestamp     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_source_events_org
                    ON siem_source_events (org_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_siem_source_events_src
                    ON siem_source_events (org_id, source_id);

                CREATE TABLE IF NOT EXISTS siem_correlation_alerts (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    title            TEXT NOT NULL,
                    rule_name        TEXT NOT NULL,
                    severity         TEXT NOT NULL,
                    matched_events   TEXT NOT NULL DEFAULT '[]',
                    status           TEXT NOT NULL DEFAULT 'open',
                    created_at       TEXT NOT NULL,
                    acknowledged_at  TEXT,
                    acknowledged_by  TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_siem_corr_alerts_org
                    ON siem_correlation_alerts (org_id, status);

                CREATE TABLE IF NOT EXISTS siem_correlation_rules (
                    rule_id      TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    description  TEXT NOT NULL DEFAULT '',
                    event_type   TEXT,
                    severity     TEXT,
                    field        TEXT NOT NULL DEFAULT 'user',
                    threshold    INTEGER NOT NULL DEFAULT 5,
                    window_hours INTEGER NOT NULL DEFAULT 1,
                    action       TEXT NOT NULL DEFAULT 'repeated_event',
                    enabled      INTEGER NOT NULL DEFAULT 1,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_siem_corr_rules_org
                    ON siem_correlation_rules (org_id, enabled);
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
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "siem_integration", "org_id": org_id, "source_engine": "siem_integration"})
            except Exception:
                pass

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
    # Correlation rules CRUD
    # ------------------------------------------------------------------

    def create_correlation_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a named correlation rule."""
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        severity = data.get("severity") or None
        if severity and severity not in _VALID_SEVERITIES:
            severity = None
        event_type = data.get("event_type") or None
        if event_type and event_type not in _VALID_EVENT_TYPES:
            event_type = None

        row = {
            "rule_id": rule_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "event_type": event_type,
            "severity": severity,
            "field": data.get("field", "user"),
            "threshold": int(data.get("threshold", 5)),
            "window_hours": int(data.get("window_hours", 1)),
            "action": data.get("action", "repeated_event"),
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_correlation_rules
                   (rule_id, org_id, name, description, event_type, severity,
                    field, threshold, window_hours, action, enabled, created_at, updated_at)
                   VALUES (:rule_id, :org_id, :name, :description, :event_type, :severity,
                    :field, :threshold, :window_hours, :action, :enabled, :created_at, :updated_at)""",
                row,
            )
        result = dict(row)
        result["enabled"] = bool(result["enabled"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {
                        "entity_type": "siem_correlation_rule",
                        "org_id": org_id,
                        "source_engine": "siem_integration",
                    })
            except Exception:
                pass
        return result

    def list_correlation_rules(
        self,
        org_id: str,
        enabled_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """List correlation rules for an org."""
        query = "SELECT * FROM siem_correlation_rules WHERE org_id = ?"
        params: List[Any] = [org_id]
        if enabled_only:
            query += " AND enabled = 1"
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._rule_row(r) for r in rows]

    def get_correlation_rule(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get a single correlation rule."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM siem_correlation_rules WHERE org_id = ? AND rule_id = ?",
                (org_id, rule_id),
            ).fetchone()
        return self._rule_row(row) if row else None

    def delete_correlation_rule(self, org_id: str, rule_id: str) -> bool:
        """Delete a correlation rule. Returns True if a row was deleted."""
        with self._lock, self._conn() as conn:
            result = conn.execute(
                "DELETE FROM siem_correlation_rules WHERE org_id = ? AND rule_id = ?",
                (org_id, rule_id),
            )
        return result.rowcount > 0

    def run_correlation_rule(self, org_id: str, rule_id: str) -> Dict[str, Any]:
        """Execute a stored correlation rule and return matched groups."""
        rule = self.get_correlation_rule(org_id, rule_id)
        if not rule:
            raise ValueError(f"Correlation rule not found: {rule_id}")
        if not rule.get("enabled"):
            raise ValueError(f"Correlation rule is disabled: {rule_id}")

        matched = self.correlate_events(org_id, {
            "event_type": rule.get("event_type"),
            "severity": rule.get("severity"),
            "field": rule.get("field", "user"),
            "threshold": rule.get("threshold", 5),
            "window_hours": rule.get("window_hours", 1),
            "action": rule.get("action", "repeated_event"),
        })
        return {
            "rule_id": rule_id,
            "rule_name": rule["name"],
            "matched_groups": len(matched),
            "matches": matched,
        }

    def _rule_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        r = dict(row)
        r["enabled"] = bool(r.get("enabled", 1))
        return r

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Syslog / CEF ingestion
    # ------------------------------------------------------------------

    @staticmethod
    def parse_syslog(raw: str) -> Dict[str, Any]:
        """Parse a syslog-format line (RFC 3164/5424) into a dict.

        Handles:
          - RFC 3164: <PRI>Mmm DD HH:MM:SS hostname tag: message
          - RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
          - Plain text fallback

        Returns a dict with keys: priority, severity_level, facility,
        timestamp, hostname, app_name, process_id, message.
        """
        import re as _re

        result: Dict[str, Any] = {"raw": raw, "format": "syslog"}

        # PRI field: <N>
        pri_match = _re.match(r"^<(\d+)>", raw)
        priority = 0
        if pri_match:
            priority = int(pri_match.group(1))
            raw = raw[pri_match.end():]

        facility = priority >> 3
        sev_level = priority & 0x07
        _sev_map = {0: "critical", 1: "critical", 2: "critical", 3: "high",
                    4: "high", 5: "medium", 6: "info", 7: "info"}
        result["priority"] = priority
        result["facility"] = facility
        result["severity_level"] = sev_level
        result["syslog_severity"] = _sev_map.get(sev_level, "info")

        # RFC 5424: VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
        r5424 = _re.match(
            r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)",
            raw,
        )
        if r5424:
            result["format"] = "syslog_rfc5424"
            result["version"] = r5424.group(1)
            result["timestamp"] = r5424.group(2)
            result["hostname"] = r5424.group(3)
            result["app_name"] = r5424.group(4)
            result["process_id"] = r5424.group(5)
            result["message_id"] = r5424.group(6)
            result["message"] = r5424.group(7).lstrip("- ")
            return result

        # RFC 3164: Mmm DD HH:MM:SS hostname tag: message
        r3164 = _re.match(
            r"^(\w{3}\s+\d+\s+[\d:]+)\s+(\S+)\s+([^:]+):\s*(.*)",
            raw,
        )
        if r3164:
            result["format"] = "syslog_rfc3164"
            result["timestamp"] = r3164.group(1)
            result["hostname"] = r3164.group(2)
            result["app_name"] = r3164.group(3).strip()
            result["message"] = r3164.group(4)
            return result

        # Fallback: treat entire string as message
        result["message"] = raw
        return result

    @staticmethod
    def parse_cef(raw: str) -> Dict[str, Any]:
        """Parse a CEF (Common Event Format) string.

        CEF:Version|Device Vendor|Device Product|Device Version|
            Signature ID|Name|Severity|Extensions

        Returns a dict with all CEF header fields plus parsed extension
        key=value pairs.
        """
        import re as _re

        result: Dict[str, Any] = {"raw": raw, "format": "cef"}

        # Strip optional syslog prefix before CEF:
        cef_start = raw.find("CEF:")
        if cef_start < 0:
            result["message"] = raw
            return result

        cef_body = raw[cef_start:]
        # Split on unescaped pipes (up to 8 parts: CEF:0|v|p|pv|sig|name|sev|ext)
        parts = _re.split(r"(?<!\\)\|", cef_body)

        if len(parts) < 7:
            result["message"] = cef_body
            return result

        # CEF:Version
        ver_match = _re.match(r"CEF:(\d+)", parts[0])
        result["cef_version"] = ver_match.group(1) if ver_match else "0"
        result["device_vendor"] = parts[1]
        result["device_product"] = parts[2]
        result["device_version"] = parts[3]
        result["signature_id"] = parts[4]
        result["name"] = parts[5]

        raw_sev = parts[6].strip()
        result["cef_severity_raw"] = raw_sev
        # Map numeric or text severity to ALDECI levels
        _num_sev_map = {
            "0": "info", "1": "info", "2": "info", "3": "low",
            "4": "low", "5": "medium", "6": "medium", "7": "high",
            "8": "high", "9": "critical", "10": "critical",
        }
        _txt_sev_map = {
            "low": "low", "medium": "medium", "high": "high",
            "critical": "critical", "unknown": "info", "very-high": "critical",
        }
        result["severity"] = (
            _num_sev_map.get(raw_sev)
            or _txt_sev_map.get(raw_sev.lower(), "info")
        )

        # Parse extensions: key=value (values may contain spaces before next key=)
        extensions: Dict[str, str] = {}
        if len(parts) > 7:
            ext_str = "|".join(parts[7:])
            # Match key=value pairs where value runs until next key=
            for m in _re.finditer(r"(\w+)=(.*?)(?=\s+\w+=|$)", ext_str):
                extensions[m.group(1)] = m.group(2).strip()
        result["extensions"] = extensions

        # Promote common extension fields
        result["source_ip"] = extensions.get("src", extensions.get("sourceAddress", ""))
        result["destination_ip"] = extensions.get("dst", extensions.get("destinationAddress", ""))
        result["user"] = extensions.get("suser", extensions.get("duser", ""))
        result["message"] = extensions.get("msg", result["name"])

        return result

    def ingest_raw(self, org_id: str, raw: str, fmt: str = "auto") -> Dict[str, Any]:
        """Parse a raw syslog or CEF string and ingest it as a SIEM event.

        Args:
            org_id: Organisation identifier.
            raw:    Raw log line (syslog RFC 3164/5424 or CEF).
            fmt:    "syslog" | "cef" | "auto" (default — auto-detected).

        Returns the ingested event record.
        """
        raw = (raw or "").strip()

        # Auto-detect format
        if fmt == "auto":
            fmt = "cef" if "CEF:" in raw else "syslog"

        if fmt == "cef":
            parsed = self.parse_cef(raw)
        else:
            parsed = self.parse_syslog(raw)

        severity = parsed.get("severity") or parsed.get("syslog_severity", "info")
        if severity not in _VALID_SEVERITIES:
            severity = "info"

        # Map parsed fields to ingest_event schema
        event_data: Dict[str, Any] = {
            "org_id": org_id,
            "siem_id": "",
            "event_type": "application",
            "severity": severity,
            "source_ip": parsed.get("source_ip", ""),
            "destination_ip": parsed.get("destination_ip", ""),
            "user": parsed.get("user", ""),
            "timestamp": parsed.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "raw_event": parsed,
            "normalized_fields": {
                "app_name": parsed.get("app_name", parsed.get("device_product", "")),
                "message": parsed.get("message", ""),
                "format": parsed.get("format", fmt),
            },
        }
        return self.ingest_event(org_id, event_data)

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

    # ==================================================================
    # SOURCE-BASED API (new schema: siem_sources / siem_source_events /
    # siem_correlation_alerts)
    # ==================================================================

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # SIEM Sources
    # ------------------------------------------------------------------

    def register_siem_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new SIEM source. Validates name and source_type."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")
        source_type = data.get("source_type", "")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(
                f"source_type must be one of {sorted(_VALID_SOURCE_TYPES)}, got '{source_type}'"
            )
        source_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_sources
                   (id, org_id, name, source_type, host, port, status, events_per_day, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    source_id, org_id, name, source_type,
                    data.get("host"), data.get("port"),
                    "active", 0, now,
                ),
            )
        _logger.info("siem.source_registered org=%s id=%s type=%s", org_id, source_id, source_type)
        return self.get_siem_source(org_id, source_id)

    def list_siem_sources(
        self,
        org_id: str,
        source_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SIEM sources for org, optionally filtered by source_type or status."""
        query = "SELECT * FROM siem_sources WHERE org_id=?"
        params: List[Any] = [org_id]
        if source_type:
            query += " AND source_type=?"
            params.append(source_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_siem_source(self, org_id: str, source_id: str) -> Dict[str, Any]:
        """Fetch a single SIEM source scoped to org_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM siem_sources WHERE org_id=? AND id=?",
                (org_id, source_id),
            ).fetchone()
        if not row:
            raise ValueError(f"SIEM source {source_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # SIEM Source Events
    # ------------------------------------------------------------------

    def ingest_siem_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a raw event for a SIEM source. Increments the source events_per_day counter."""
        source_id = data.get("source_id", "")
        event_type = data.get("event_type", "")
        severity = data.get("severity", "info")
        if severity not in _VALID_EVENT_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_EVENT_SEVERITIES)}")

        raw_data = data.get("raw_data", {})
        if isinstance(raw_data, dict):
            raw_data_str = json.dumps(raw_data)
        else:
            raw_data_str = str(raw_data)

        parsed_fields = data.get("parsed_fields")
        parsed_fields_str = json.dumps(parsed_fields) if parsed_fields is not None else None

        event_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_source_events
                   (id, org_id, source_id, event_type, severity, raw_data, parsed_fields, timestamp)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (event_id, org_id, source_id, event_type, severity, raw_data_str, parsed_fields_str, now),
            )
            # Increment events_per_day on the source (best-effort)
            conn.execute(
                """UPDATE siem_sources SET events_per_day = events_per_day + 1
                   WHERE org_id=? AND id=?""",
                (org_id, source_id),
            )
        _logger.info("siem.event_ingested org=%s source_id=%s severity=%s", org_id, source_id, severity)
        result: Dict[str, Any] = {
            "id": event_id,
            "org_id": org_id,
            "source_id": source_id,
            "event_type": event_type,
            "severity": severity,
            "raw_data": raw_data,
            "parsed_fields": parsed_fields,
            "timestamp": now,
        }
        return result

    def list_siem_events(
        self,
        org_id: str,
        source_id: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List SIEM source events, ordered by timestamp DESC, limit 100."""
        query = "SELECT * FROM siem_source_events WHERE org_id=?"
        params: List[Any] = [org_id]
        if source_id:
            query += " AND source_id=?"
            params.append(source_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)
        query += " ORDER BY timestamp DESC LIMIT 100"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        results = []
        for r in rows:
            row = dict(r)
            for field in ("raw_data", "parsed_fields"):
                if isinstance(row.get(field), str):
                    try:
                        row[field] = json.loads(row[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            results.append(row)
        return results

    def search_events(
        self,
        org_id: str,
        q: str,
        source_id: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Full-text keyword search across raw_data and parsed_fields columns.

        SQLite LIKE search is case-insensitive for ASCII characters.
        ``q`` is matched as a substring against ``raw_data`` and
        ``parsed_fields``; events matching either column are returned.
        An empty ``q`` falls back to ``list_siem_events``.

        Args:
            org_id:     Tenant scope.
            q:          Search keyword / phrase.
            source_id:  Optional filter to a specific SIEM source.
            severity:   Optional severity filter (info/low/medium/high/critical).
            event_type: Optional event-type filter.
            limit:      Maximum rows to return (default 100, max 500).

        Returns:
            List of matching event dicts, ordered newest-first.
        """
        q = (q or "").strip()
        if not q:
            return self.list_siem_events(
                org_id,
                source_id=source_id,
                severity=severity,
                event_type=event_type,
            )

        limit = max(1, min(int(limit), 500))
        pattern = f"%{q}%"

        query = (
            "SELECT * FROM siem_source_events "
            "WHERE org_id=? AND (raw_data LIKE ? OR parsed_fields LIKE ?)"
        )
        params: List[Any] = [org_id, pattern, pattern]

        if source_id:
            query += " AND source_id=?"
            params.append(source_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for r in rows:
            row = dict(r)
            for field in ("raw_data", "parsed_fields"):
                if isinstance(row.get(field), str):
                    try:
                        row[field] = json.loads(row[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            results.append(row)
        return results

    # ------------------------------------------------------------------
    # Correlation Alerts
    # ------------------------------------------------------------------

    def create_correlation_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlation alert for org_id."""
        title = data.get("title", "").strip()
        rule_name = data.get("rule_name", "").strip()
        severity = data.get("severity", "medium")
        if not title:
            raise ValueError("title is required")
        if not rule_name:
            raise ValueError("rule_name is required")
        matched_events = data.get("matched_events", [])
        if not isinstance(matched_events, list):
            matched_events = []

        alert_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO siem_correlation_alerts
                   (id, org_id, title, rule_name, severity, matched_events, status, created_at,
                    acknowledged_at, acknowledged_by)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    alert_id, org_id, title, rule_name, severity,
                    json.dumps(matched_events), "open", now, None, None,
                ),
            )
        _logger.info("siem.corr_alert_created org=%s id=%s rule=%s", org_id, alert_id, rule_name)
        return self._get_correlation_alert(org_id, alert_id)

    def list_correlation_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List correlation alerts for org, optionally filtered."""
        query = "SELECT * FROM siem_correlation_alerts WHERE org_id=?"
        params: List[Any] = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._deserialize_corr_alert(dict(r)) for r in rows]

    def acknowledge_alert(
        self, org_id: str, alert_id: str, acknowledged_by: str
    ) -> Dict[str, Any]:
        """Acknowledge a correlation alert."""
        now = self._now()
        with self._lock, self._conn() as conn:
            result = conn.execute(
                """UPDATE siem_correlation_alerts
                   SET status='acknowledged', acknowledged_at=?, acknowledged_by=?
                   WHERE org_id=? AND id=?""",
                (now, acknowledged_by, org_id, alert_id),
            )
            if result.rowcount == 0:
                raise ValueError(f"Correlation alert {alert_id} not found for org {org_id}")
        return self._get_correlation_alert(org_id, alert_id)

    def _get_correlation_alert(self, org_id: str, alert_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM siem_correlation_alerts WHERE org_id=? AND id=?",
                (org_id, alert_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Correlation alert {alert_id} not found for org {org_id}")
        return self._deserialize_corr_alert(dict(row))

    @staticmethod
    def _deserialize_corr_alert(row: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(row.get("matched_events"), str):
            try:
                row["matched_events"] = json.loads(row["matched_events"])
            except (json.JSONDecodeError, TypeError):
                row["matched_events"] = []
        return row

    # ------------------------------------------------------------------
    # Source-based Stats
    # ------------------------------------------------------------------

    def get_siem_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate statistics for the org (combines legacy + new source-based stats)."""
        now_dt = datetime.now(timezone.utc)
        cutoff_24h = (now_dt - timedelta(hours=24)).isoformat()
        cutoff_7d = (now_dt - timedelta(days=7)).isoformat()

        with self._lock, self._conn() as conn:
            # Legacy stats
            total_siems = conn.execute(
                "SELECT COUNT(*) FROM siem_integrations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_siems = conn.execute(
                "SELECT COUNT(*) FROM siem_integrations WHERE org_id = ? AND enabled = 1",
                (org_id,),
            ).fetchone()[0]

            events_24h_legacy = conn.execute(
                "SELECT COUNT(*) FROM siem_events WHERE org_id = ? AND timestamp >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            events_7d = conn.execute(
                "SELECT COUNT(*) FROM siem_events WHERE org_id = ? AND timestamp >= ?",
                (org_id, cutoff_7d),
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT si.siem_type, COUNT(se.event_id) as cnt
                   FROM siem_integrations si
                   LEFT JOIN siem_events se ON si.siem_id = se.siem_id AND se.org_id = ?
                   WHERE si.org_id = ?
                   GROUP BY si.siem_type""",
                (org_id, org_id),
            ).fetchall()
            by_siem_type = {r["siem_type"]: r["cnt"] for r in type_rows}

            sev_rows_legacy = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM siem_events
                   WHERE org_id = ? AND timestamp >= ?
                   GROUP BY severity""",
                (org_id, cutoff_24h),
            ).fetchall()

            alert_count = conn.execute(
                "SELECT COUNT(*) FROM siem_alerts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_alerts_legacy = conn.execute(
                "SELECT COUNT(*) FROM siem_alerts WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            # New source-based stats
            total_sources = conn.execute(
                "SELECT COUNT(*) FROM siem_sources WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_sources = conn.execute(
                "SELECT COUNT(*) FROM siem_sources WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            total_events_24h = conn.execute(
                "SELECT COUNT(*) FROM siem_source_events WHERE org_id=? AND timestamp>=?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            sev_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM siem_source_events
                   WHERE org_id=? AND timestamp>=?
                   GROUP BY severity""",
                (org_id, cutoff_24h),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # Merge legacy severity counts
            for r in sev_rows_legacy:
                by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + r["cnt"]

            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM siem_correlation_alerts WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            critical_alerts = conn.execute(
                "SELECT COUNT(*) FROM siem_correlation_alerts WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]

        return {
            # Legacy fields (kept for backward compat)
            "total_siems": total_siems,
            "active_siems": active_siems,
            "events_24h": events_24h_legacy + total_events_24h,
            "events_7d": events_7d,
            "by_siem_type": by_siem_type,
            "by_severity": by_severity,
            "alert_count": alert_count,
            "open_alerts": open_alerts_legacy,
            # New source-based fields
            "total_sources": total_sources,
            "active_sources": active_sources,
            "total_events_24h": total_events_24h,
            "open_alerts_count": open_alerts,
            "critical_alerts": critical_alerts,
        }


# ======================================================================
# GAP-035 — SIEM forwarding adapter registry
# Mock HTTP forwarders for Chronicle, Datadog (and legacy Splunk/QRadar/Elastic).
# These do NOT perform real network I/O; they return a deterministic
# success envelope suitable for pipeline integration tests.
# ======================================================================


class _BaseSIEMAdapter:
    """Base class — subclasses set ``adapter_name`` and optionally override
    ``_endpoint_hint`` to label the mocked request target."""

    adapter_name: str = "generic"
    _endpoint_hint: str = "siem://generic"

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    def forward_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        if event is None or not isinstance(event, dict):
            return {
                "adapter": self.adapter_name,
                "success": False,
                "status": "error",
                "error": "event must be a non-null dict",
                "endpoint": self._endpoint_hint,
            }
        event_id = event.get("event_id") or event.get("id") or str(uuid.uuid4())
        return {
            "adapter": self.adapter_name,
            "success": True,
            "status": "forwarded",
            "event_id": event_id,
            "endpoint": self._endpoint_hint,
            "bytes": len(json.dumps(event, default=str)),
            "forwarded_at": datetime.now(timezone.utc).isoformat(),
        }


class ChronicleAdapter(_BaseSIEMAdapter):
    """Google Chronicle SIEM forwarding adapter (mocked HTTP)."""

    adapter_name = "chronicle"
    _endpoint_hint = "https://chronicle.googleapis.com/v1/events:batchCreate"


class DatadogAdapter(_BaseSIEMAdapter):
    """Datadog SIEM / Logs forwarding adapter (mocked HTTP)."""

    adapter_name = "datadog"
    _endpoint_hint = "https://http-intake.logs.datadoghq.com/api/v2/logs"


class SplunkAdapter(_BaseSIEMAdapter):
    adapter_name = "splunk"
    _endpoint_hint = "https://splunk.local:8088/services/collector"


class QRadarAdapter(_BaseSIEMAdapter):
    adapter_name = "qradar"
    _endpoint_hint = "https://qradar.local/api/siem/offenses"


class ElasticAdapter(_BaseSIEMAdapter):
    adapter_name = "elastic"
    _endpoint_hint = "https://elastic.local:9200/_bulk"


class SentinelAdapter(_BaseSIEMAdapter):
    adapter_name = "sentinel"
    _endpoint_hint = "https://sentinel.azure.com/api/logs"


# Registry — adapters keyed by lowercase name.  Callers should treat this
# dict as a read-mostly singleton; additional adapters may register here.
SIEM_ADAPTERS: Dict[str, type] = {
    "chronicle": ChronicleAdapter,
    "datadog": DatadogAdapter,
    "splunk": SplunkAdapter,
    "qradar": QRadarAdapter,
    "elastic": ElasticAdapter,
    "sentinel": SentinelAdapter,
}


def forward_to_siem(
    adapter_name: str,
    event: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience function: look up an adapter by name and forward one event.

    Returns a result envelope with ``adapter``, ``success``, ``status``.  If the
    adapter name is unknown, returns a failure envelope (does not raise).
    """
    key = (adapter_name or "").strip().lower()
    cls = SIEM_ADAPTERS.get(key)
    if cls is None:
        return {
            "adapter": adapter_name,
            "success": False,
            "status": "error",
            "error": f"unknown adapter '{adapter_name}'",
            "available": sorted(SIEM_ADAPTERS.keys()),
        }
    return cls(config).forward_event(event)
