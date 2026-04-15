"""
Threat Correlation Engine — ALDECI.

Correlates security events across sources using configurable rules to surface
high-confidence alerts with reduced alert fatigue.

- Configurable rules: event_types, time_window, threshold, severity
- Event ingestion: 6 event types (login_failure, malware_detected, etc.)
- Correlation: BFS over recent events; creates alert when rule threshold met
- Alert lifecycle: open → investigating → closed
- Multi-tenant via org_id, SQLite WAL, thread-safe

Compliance: NIST CSF DE.AE-2, SOC2 CC7.1, MITRE ATT&CK correlation layer
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

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_correlation.db"
)

# Valid event types
EVENT_TYPES = {
    "login_failure",
    "malware_detected",
    "network_anomaly",
    "data_exfil",
    "lateral_movement",
    "privilege_escalation",
}

# Valid alert statuses
ALERT_STATUSES = {"open", "investigating", "closed"}


class ThreatCorrelationEngine:
    """
    SQLite WAL-backed threat correlation engine.

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
                CREATE TABLE IF NOT EXISTS correlation_rules (
                    rule_id             TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    event_types         TEXT NOT NULL DEFAULT '[]',
                    time_window_minutes INTEGER NOT NULL DEFAULT 60,
                    threshold           INTEGER NOT NULL DEFAULT 3,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    correlation_logic   TEXT NOT NULL DEFAULT '{}',
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_corr_rules_org
                    ON correlation_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS correlation_events (
                    event_id    TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    event_type  TEXT NOT NULL,
                    source_ip   TEXT NOT NULL DEFAULT '',
                    user_id     TEXT NOT NULL DEFAULT '',
                    asset_id    TEXT NOT NULL DEFAULT '',
                    timestamp   DATETIME NOT NULL,
                    raw_data    TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_corr_events_org_type
                    ON correlation_events (org_id, event_type, timestamp);

                CREATE TABLE IF NOT EXISTS correlation_alerts (
                    corr_alert_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    rule_id         TEXT NOT NULL,
                    matched_events  TEXT NOT NULL DEFAULT '[]',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    resolution      TEXT,
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL,
                    FOREIGN KEY (rule_id) REFERENCES correlation_rules(rule_id)
                );

                CREATE INDEX IF NOT EXISTS idx_corr_alerts_org_status
                    ON correlation_alerts (org_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlation rule. Returns the created rule dict."""
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        event_types = data.get("event_types", [])
        time_window = int(data.get("time_window_minutes", 60))
        threshold = int(data.get("threshold", 3))
        severity = data.get("severity", "medium")
        correlation_logic = data.get("correlation_logic", {})
        enabled = bool(data.get("enabled", True))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO correlation_rules
                        (rule_id, org_id, name, description, event_types,
                         time_window_minutes, threshold, severity,
                         correlation_logic, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule_id,
                        org_id,
                        data.get("name", "Unnamed Rule"),
                        data.get("description", ""),
                        json.dumps(event_types),
                        time_window,
                        threshold,
                        severity,
                        json.dumps(correlation_logic),
                        1 if enabled else 0,
                        now,
                    ),
                )

        rule = {
            "rule_id": rule_id,
            "org_id": org_id,
            "name": data.get("name", "Unnamed Rule"),
            "description": data.get("description", ""),
            "event_types": event_types,
            "time_window_minutes": time_window,
            "threshold": threshold,
            "severity": severity,
            "correlation_logic": correlation_logic,
            "enabled": enabled,
            "created_at": now,
        }
        _logger.info("Created correlation rule %s (%s) for org %s", rule_id, rule["name"], org_id)
        return rule

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all correlation rules for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM correlation_rules WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()

        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["event_types"] = json.loads(d.get("event_types") or "[]")
            d["correlation_logic"] = json.loads(d.get("correlation_logic") or "{}")
            d["enabled"] = bool(d["enabled"])
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def ingest_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingest a security event. Returns the stored event dict.

        event_type must be one of: login_failure, malware_detected,
        network_anomaly, data_exfil, lateral_movement, privilege_escalation.
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        timestamp = data.get("timestamp", now)

        event_type = data.get("event_type", "")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO correlation_events
                        (event_id, org_id, event_type, source_ip, user_id,
                         asset_id, timestamp, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        org_id,
                        event_type,
                        data.get("source_ip", ""),
                        data.get("user_id", ""),
                        data.get("asset_id", ""),
                        timestamp,
                        json.dumps(data.get("raw_data", {})),
                    ),
                )

        event = {
            "event_id": event_id,
            "org_id": org_id,
            "event_type": event_type,
            "source_ip": data.get("source_ip", ""),
            "user_id": data.get("user_id", ""),
            "asset_id": data.get("asset_id", ""),
            "timestamp": timestamp,
            "raw_data": data.get("raw_data", {}),
        }
        _logger.debug("Ingested event %s (%s) for org %s", event_id, event_type, org_id)
        return event

    def list_events(
        self,
        org_id: str,
        event_type: Optional[str] = None,
        hours_back: int = 24,
    ) -> List[Dict[str, Any]]:
        """List recent events for an org, optionally filtered by event_type."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()

        if event_type:
            query = (
                "SELECT * FROM correlation_events "
                "WHERE org_id = ? AND event_type = ? AND timestamp >= ? "
                "ORDER BY timestamp DESC"
            )
            params = [org_id, event_type, cutoff]
        else:
            query = (
                "SELECT * FROM correlation_events "
                "WHERE org_id = ? AND timestamp >= ? "
                "ORDER BY timestamp DESC"
            )
            params = [org_id, cutoff]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["raw_data"] = json.loads(d.get("raw_data") or "{}")
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate(self, org_id: str) -> List[Dict[str, Any]]:
        """
        Run all enabled rules against recent events.

        For each rule: count events matching any of the rule's event_types
        within the rule's time_window_minutes. If count >= threshold, create
        a correlation alert.

        Returns list of newly created alert dicts.
        """
        rules = self.list_rules(org_id)
        enabled_rules = [r for r in rules if r.get("enabled")]

        new_alerts: List[Dict[str, Any]] = []

        for rule in enabled_rules:
            event_types = rule.get("event_types", [])
            if not event_types:
                continue

            time_window = int(rule.get("time_window_minutes", 60))
            threshold = int(rule.get("threshold", 3))
            cutoff = (
                datetime.now(timezone.utc) - timedelta(minutes=time_window)
            ).isoformat()

            with self._conn() as conn:
                placeholders = ",".join("?" * len(event_types))
                rows = conn.execute(
                    f"""
                    SELECT event_id FROM correlation_events
                    WHERE org_id = ?
                      AND event_type IN ({placeholders})
                      AND timestamp >= ?
                    ORDER BY timestamp DESC
                    """,
                    [org_id, *event_types, cutoff],
                ).fetchall()

            matched_event_ids = [r["event_id"] for r in rows]
            count = len(matched_event_ids)

            if count >= threshold:
                alert = self.create_alert(
                    org_id=org_id,
                    data={
                        "rule_id": rule["rule_id"],
                        "matched_events": matched_event_ids,
                        "severity": rule.get("severity", "medium"),
                    },
                )
                new_alerts.append(alert)
                _logger.info(
                    "Correlation alert created for rule %s (org %s): %d events matched",
                    rule["rule_id"], org_id, count,
                )

        return new_alerts

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def create_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlation alert directly. Returns the alert dict."""
        corr_alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        rule_id = data.get("rule_id", "")
        matched_events = data.get("matched_events", [])
        severity = data.get("severity", "medium")
        status = data.get("status", "open")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO correlation_alerts
                        (corr_alert_id, org_id, rule_id, matched_events,
                         severity, status, resolution, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        corr_alert_id,
                        org_id,
                        rule_id,
                        json.dumps(matched_events),
                        severity,
                        status,
                        now,
                        now,
                    ),
                )

        alert = {
            "corr_alert_id": corr_alert_id,
            "org_id": org_id,
            "rule_id": rule_id,
            "matched_events": matched_events,
            "severity": severity,
            "status": status,
            "resolution": None,
            "created_at": now,
            "updated_at": now,
        }
        return alert

    def list_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List correlation alerts for an org, optionally filtered by status."""
        if status:
            query = (
                "SELECT * FROM correlation_alerts "
                "WHERE org_id = ? AND status = ? ORDER BY created_at DESC"
            )
            params = [org_id, status]
        else:
            query = (
                "SELECT * FROM correlation_alerts "
                "WHERE org_id = ? ORDER BY created_at DESC"
            )
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for row in rows:
            d = self._row_to_dict(row)
            d["matched_events"] = json.loads(d.get("matched_events") or "[]")
            result.append(d)
        return result

    def close_alert(self, org_id: str, alert_id: str, resolution: str) -> bool:
        """
        Close an alert with a resolution string.

        Returns True if the alert was found and updated, False otherwise.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE correlation_alerts
                       SET status = 'closed',
                           resolution = ?,
                           updated_at = ?
                     WHERE corr_alert_id = ? AND org_id = ?
                    """,
                    (resolution, now, alert_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_correlation_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for an org's correlation data."""
        with self._conn() as conn:
            total_rules = conn.execute(
                "SELECT COUNT(*) FROM correlation_rules WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            enabled_rules = conn.execute(
                "SELECT COUNT(*) FROM correlation_rules WHERE org_id = ? AND enabled = 1",
                (org_id,),
            ).fetchone()[0]

            total_events = conn.execute(
                "SELECT COUNT(*) FROM correlation_events WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            total_alerts = conn.execute(
                "SELECT COUNT(*) FROM correlation_alerts WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM correlation_alerts WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            investigating_alerts = conn.execute(
                "SELECT COUNT(*) FROM correlation_alerts WHERE org_id = ? AND status = 'investigating'",
                (org_id,),
            ).fetchone()[0]

            closed_alerts = conn.execute(
                "SELECT COUNT(*) FROM correlation_alerts WHERE org_id = ? AND status = 'closed'",
                (org_id,),
            ).fetchone()[0]

            # Breakdown of events by type
            event_type_rows = conn.execute(
                """
                SELECT event_type, COUNT(*) as cnt
                FROM correlation_events
                WHERE org_id = ?
                GROUP BY event_type
                ORDER BY cnt DESC
                """,
                (org_id,),
            ).fetchall()

        events_by_type = {r["event_type"]: r["cnt"] for r in event_type_rows}

        return {
            "org_id": org_id,
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "total_events": total_events,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "investigating_alerts": investigating_alerts,
            "closed_alerts": closed_alerts,
            "events_by_type": events_by_type,
        }
