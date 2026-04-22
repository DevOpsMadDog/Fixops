"""Security Event Correlation Engine — ALDECI.

Correlates security events across multiple source systems using
pattern-based rules, time-windowed matching, and automated incident creation.

Capabilities:
  - Multi-source event ingestion (SIEM, EDR, NDR, WAF, etc.)
  - Correlation rule management (pattern + time window + count threshold)
  - Automated correlation run to detect rule matches
  - Correlated incident lifecycle management
  - Per-org stats aggregation

Compliance: MITRE ATT&CK, NIST SP 800-61, SOC 2
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_INCIDENT_STATUSES = {"open", "investigating", "resolved", "false_positive"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityEventCorrelationEngine:
    """SQLite WAL-backed Security Event Correlation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB files stored at .fixops_data/{org_id}_sec_event_correlation.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._db_dir = Path(db_path).parent
            self._db_suffix = Path(db_path).name
            self._single_path = db_path
        else:
            self._db_dir = _DEFAULT_DB_DIR
            self._single_path = None
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._lock_lock = threading.Lock()

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._lock_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        if self._single_path:
            return self._single_path
        return str(self._db_dir / f"{org_id}_sec_event_correlation.db")

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_system   TEXT NOT NULL DEFAULT '',
                    event_type      TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    entity_id       TEXT NOT NULL DEFAULT '',
                    entity_type     TEXT NOT NULL DEFAULT '',
                    raw_data        TEXT NOT NULL DEFAULT '{}',
                    timestamp       TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_org_type
                    ON security_events (org_id, event_type);

                CREATE INDEX IF NOT EXISTS idx_events_org_severity
                    ON security_events (org_id, severity);

                CREATE INDEX IF NOT EXISTS idx_events_org_source
                    ON security_events (org_id, source_system);

                CREATE INDEX IF NOT EXISTS idx_events_org_ts
                    ON security_events (org_id, timestamp);

                CREATE TABLE IF NOT EXISTS correlation_rules (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    pattern             TEXT NOT NULL DEFAULT '[]',
                    time_window_seconds INTEGER NOT NULL DEFAULT 300,
                    min_count           INTEGER NOT NULL DEFAULT 2,
                    output_severity     TEXT NOT NULL DEFAULT 'high',
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rules_org
                    ON correlation_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS correlated_incidents (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    rule_id             TEXT NOT NULL DEFAULT '',
                    matched_event_ids   TEXT NOT NULL DEFAULT '[]',
                    title               TEXT NOT NULL DEFAULT '',
                    severity            TEXT NOT NULL DEFAULT 'high',
                    status              TEXT NOT NULL DEFAULT 'open',
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_org_status
                    ON correlated_incidents (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_incidents_org_rule
                    ON correlated_incidents (org_id, rule_id);
            """)

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("raw_data", "pattern", "matched_event_ids"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def ingest_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a security event from any source system."""
        self._ensure_db(org_id)

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {_VALID_SEVERITIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_system": str(data.get("source_system", "")),
            "event_type": str(data.get("event_type", "")),
            "severity": severity,
            "entity_id": str(data.get("entity_id", "")),
            "entity_type": str(data.get("entity_type", "")),
            "raw_data": json.dumps(data.get("raw_data", {})),
            "timestamp": str(data.get("timestamp", now)),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO security_events
                       (id, org_id, source_system, event_type, severity,
                        entity_id, entity_type, raw_data, timestamp, created_at)
                       VALUES (:id, :org_id, :source_system, :event_type, :severity,
                               :entity_id, :entity_type, :raw_data, :timestamp, :created_at)""",
                    record,
                )
        record["raw_data"] = data.get("raw_data", {})
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_event_correlation", "org_id": org_id, "source_engine": "security_event_correlation"})
            except Exception:
                pass

        return record

    def list_events(
        self,
        org_id: str,
        source_system: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List security events with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM security_events WHERE org_id = ?"
        params: list = [org_id]
        if source_system:
            sql += " AND source_system = ?"
            params.append(source_system)
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Correlation Rules
    # ------------------------------------------------------------------

    def create_correlation_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlation rule based on event type patterns."""
        self._ensure_db(org_id)

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        pattern = data.get("pattern", [])
        if not isinstance(pattern, list):
            raise ValueError("pattern must be a list of event_type strings.")

        output_severity = data.get("output_severity", "high")
        if output_severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid output_severity '{output_severity}'.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "pattern": json.dumps(pattern),
            "time_window_seconds": int(data.get("time_window_seconds", 300)),
            "min_count": int(data.get("min_count", 2)),
            "output_severity": output_severity,
            "enabled": 1,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO correlation_rules
                       (id, org_id, name, pattern, time_window_seconds, min_count,
                        output_severity, enabled, created_at)
                       VALUES (:id, :org_id, :name, :pattern, :time_window_seconds, :min_count,
                               :output_severity, :enabled, :created_at)""",
                    record,
                )
        record["pattern"] = pattern
        record["enabled"] = True
        return record

    def list_correlation_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all correlation rules for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM correlation_rules WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Correlation Run
    # ------------------------------------------------------------------

    def run_correlation(self, org_id: str) -> List[Dict[str, Any]]:
        """Run all enabled rules against recent events, return matched incidents.

        De-dup: signals that are already members of a composite group (via
        ``anomaly_ml_engine``) are filtered out of the match set so the
        composite group is the single source of truth for SOC triage.
        """
        self._ensure_db(org_id)
        matched: List[Dict[str, Any]] = []

        # Collect composite member signal_ids to filter (best-effort; no-op
        # if the anomaly engine is unavailable).
        composite_signal_ids: set = set()
        try:
            from core.anomaly_ml_engine import AnomalyMLEngine  # local import
            _ml = AnomalyMLEngine()
            composite_signal_ids = _ml.get_composite_signal_ids(org_id)
        except Exception:
            composite_signal_ids = set()

        with self._conn(org_id) as conn:
            rules = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM correlation_rules WHERE org_id = ? AND enabled = 1",
                    (org_id,),
                ).fetchall()
            ]

        for rule in rules:
            pattern: List[str] = rule["pattern"] if isinstance(rule["pattern"], list) else []
            if not pattern:
                continue

            window_secs = rule["time_window_seconds"]
            min_count = rule["min_count"]

            # Fetch events matching any event_type in the pattern within the time window
            placeholders = ",".join("?" * len(pattern))
            sql = f"""SELECT * FROM security_events WHERE org_id = ?
                  AND event_type IN ({placeholders})
                  AND timestamp >= datetime('now', ? || ' seconds')
                ORDER BY timestamp ASC
            """  # nosec B608
            params = [org_id] + pattern + [f"-{window_secs}"]

            with self._conn(org_id) as conn:
                events = [self._row(r) for r in conn.execute(sql, params).fetchall()]

            # Filter out events whose entity_id is a composite-grouped signal.
            if composite_signal_ids:
                events = [
                    e for e in events
                    if str(e.get("entity_id") or "") not in composite_signal_ids
                    and str(e.get("id") or "") not in composite_signal_ids
                ]

            if len(events) >= min_count:
                matched.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["output_severity"],
                    "matched_event_ids": [e["id"] for e in events],
                    "matched_events": events,
                    "event_count": len(events),
                })

        return matched

    # ------------------------------------------------------------------
    # Composite-alert ingest (GAP-052)
    # ------------------------------------------------------------------

    def ingest_composite_group(
        self, group_id: str, org_id: str
    ) -> Dict[str, Any]:
        """Write a single ``security_events`` row of type ``composite`` that
        references a composite_alert_groups row.

        Idempotent: if an event already exists for (org_id, composite, group_id)
        it is returned unchanged.

        Returns a dict with keys: event_id, created, group_id, signal_count,
        correlation_score.
        """
        if not group_id:
            raise ValueError("group_id is required")
        if not org_id:
            raise ValueError("org_id is required")

        self._ensure_db(org_id)

        # Resolve composite group via anomaly_ml_engine. We do not raise if the
        # engine is unavailable — we still record a minimal event so the SOC
        # pipeline is not silently broken.
        group: Optional[Dict[str, Any]] = None
        try:
            from core.anomaly_ml_engine import AnomalyMLEngine
            _ml = AnomalyMLEngine()
            group = _ml.get_composite_group(group_id)
        except Exception:
            group = None

        if group is not None and str(group.get("org_id")) != str(org_id):
            raise ValueError("composite group does not belong to this org")

        signal_count = int(group["signal_count"]) if group else 0
        correlation_score = float(group["correlation_score"]) if group else 0.0
        member_ids = list(group.get("member_ids", [])) if group else []
        group_name = group.get("group_name", "composite") if group else "composite"

        now = _now_iso()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                existing = conn.execute(
                    """SELECT id FROM security_events
                       WHERE org_id = ? AND event_type = 'composite'
                       AND entity_id = ?""",
                    (org_id, group_id),
                ).fetchone()
                if existing:
                    return {
                        "event_id": existing["id"],
                        "created": False,
                        "group_id": group_id,
                        "signal_count": signal_count,
                        "correlation_score": correlation_score,
                    }

                event_id = str(uuid.uuid4())
                raw = {
                    "composite_group_id": group_id,
                    "group_name": group_name,
                    "signal_count": signal_count,
                    "correlation_score": correlation_score,
                    "member_ids": member_ids,
                }
                severity = "critical" if correlation_score >= 0.8 else "high"
                conn.execute(
                    """INSERT INTO security_events
                       (id, org_id, source_system, event_type, severity,
                        entity_id, entity_type, raw_data, timestamp, created_at)
                       VALUES (?, ?, 'anomaly_ml_engine', 'composite',
                               ?, ?, 'composite_alert_group', ?, ?, ?)""",
                    (
                        event_id,
                        org_id,
                        severity,
                        group_id,
                        json.dumps(raw),
                        now,
                        now,
                    ),
                )

        return {
            "event_id": event_id,
            "created": True,
            "group_id": group_id,
            "signal_count": signal_count,
            "correlation_score": correlation_score,
        }

    # ------------------------------------------------------------------
    # Correlated Incidents
    # ------------------------------------------------------------------

    def create_correlated_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlated incident from matched events."""
        self._ensure_db(org_id)

        severity = data.get("severity", "high")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'.")

        matched_event_ids = data.get("matched_event_ids", [])
        if not isinstance(matched_event_ids, list):
            raise ValueError("matched_event_ids must be a list.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_id": str(data.get("rule_id", "")),
            "matched_event_ids": json.dumps(matched_event_ids),
            "title": str(data.get("title", "Correlated Security Incident")),
            "severity": severity,
            "status": "open",
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO correlated_incidents
                       (id, org_id, rule_id, matched_event_ids, title, severity, status, created_at)
                       VALUES (:id, :org_id, :rule_id, :matched_event_ids, :title, :severity, :status, :created_at)""",
                    record,
                )
        record["matched_event_ids"] = matched_event_ids
        return record

    def list_correlated_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List correlated incidents, optionally filtered by status."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM correlated_incidents WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_correlation_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated correlation statistics for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            events_ingested = conn.execute(
                "SELECT COUNT(*) FROM security_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            rules_count = conn.execute(
                "SELECT COUNT(*) FROM correlation_rules WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            incidents_created = conn.execute(
                "SELECT COUNT(*) FROM correlated_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            open_incidents = conn.execute(
                "SELECT COUNT(*) FROM correlated_incidents WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

        correlation_rate = (
            round(incidents_created / events_ingested, 4) if events_ingested > 0 else 0.0
        )

        return {
            "org_id": org_id,
            "events_ingested": events_ingested,
            "rules": rules_count,
            "incidents_created": incidents_created,
            "open_incidents": open_incidents,
            "correlation_rate": correlation_rate,
        }

    # ------------------------------------------------------------------
    # Toxic-combo subscriber (GAP-021)
    # ------------------------------------------------------------------

    def on_toxic_combo_matched(
        self, org_id: str, match: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Subscriber hook: when a toxic-combo match is written upstream,
        emit a correlated security event so existing SOC pipelines see it.

        - Writes a synthetic event into ``security_events`` with
          ``event_type="toxic_combo_matched"``.
        - Creates a ``correlated_incidents`` row pointing at it so analysts
          have a tracked incident to triage.

        Idempotency: per-(org_id, match.id) — repeat calls produce a single
        event and single incident.
        """
        if not isinstance(match, dict):
            raise TypeError("match must be a dict")
        match_id = str(match.get("id") or "").strip()
        if not match_id:
            raise ValueError("match.id is required")

        self._ensure_db(org_id)

        combo_id = str(match.get("combo_id") or "")
        entity_ref = str(match.get("entity_ref") or "")
        severity = str(match.get("severity") or "high")
        if severity not in _VALID_SEVERITIES:
            severity = "high"
        satisfied = match.get("matched_attributes") or []

        # Dedup: does an event already exist for this match?
        now = _now_iso()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                existing_event = conn.execute(
                    """SELECT id FROM security_events
                       WHERE org_id = ? AND event_type = 'toxic_combo_matched'
                       AND entity_id = ?""",
                    (org_id, match_id),
                ).fetchone()

        if existing_event:
            event_id = existing_event["id"]
            created_event = False
        else:
            event_id = str(uuid.uuid4())
            created_event = True
            raw_data = {
                "toxic_combo_match_id": match_id,
                "combo_id": combo_id,
                "entity_ref": entity_ref,
                "matched_attributes": satisfied,
            }
            with self._get_lock(org_id):
                with self._conn(org_id) as conn:
                    conn.execute(
                        """INSERT INTO security_events
                           (id, org_id, source_system, event_type, severity,
                            entity_id, entity_type, raw_data, timestamp, created_at)
                           VALUES (?, ?, 'threat_correlation_engine', 'toxic_combo_matched',
                                   ?, ?, 'toxic_combo_match', ?, ?, ?)""",
                        (
                            event_id,
                            org_id,
                            severity,
                            match_id,
                            json.dumps(raw_data),
                            now,
                            now,
                        ),
                    )

        # Create a correlated incident (dedup on matched_event_ids containing event_id).
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                rows = conn.execute(
                    """SELECT id, matched_event_ids FROM correlated_incidents
                       WHERE org_id = ? AND rule_id = 'toxic_combo'""",
                    (org_id,),
                ).fetchall()

        incident_id: Optional[str] = None
        for row in rows:
            try:
                ids = json.loads(row["matched_event_ids"] or "[]")
            except Exception:
                ids = []
            if match_id in ids or event_id in ids:
                incident_id = row["id"]
                break

        created_incident = False
        if incident_id is None:
            incident_id = str(uuid.uuid4())
            created_incident = True
            title = f"Toxic combo: {combo_id} on {entity_ref}"
            with self._get_lock(org_id):
                with self._conn(org_id) as conn:
                    conn.execute(
                        """INSERT INTO correlated_incidents
                           (id, org_id, rule_id, matched_event_ids, title, severity, status, created_at)
                           VALUES (?, ?, 'toxic_combo', ?, ?, ?, 'open', ?)""",
                        (
                            incident_id,
                            org_id,
                            json.dumps([event_id, match_id]),
                            title,
                            severity,
                            now,
                        ),
                    )

        return {
            "event_id": event_id,
            "incident_id": incident_id,
            "created_event": created_event,
            "created_incident": created_incident,
            "severity": severity,
        }
