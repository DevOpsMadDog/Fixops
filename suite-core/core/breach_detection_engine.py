"""
BreachDetectionEngine — ALDECI.

Tracks detection rules (behavioral/signature/anomaly/heuristic/ml_based) and
detection events with full lifecycle: open → investigating → closed.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC7.2, NIST SP 800-53 IR-4 (incident handling), SI-4 (monitoring).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "breach_detection.db"
)

VALID_RULE_TYPES = frozenset({"behavioral", "signature", "anomaly", "heuristic", "ml_based"})
VALID_DATA_SOURCES = frozenset({"endpoint", "network", "cloud", "email", "identity", "application"})
VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
VALID_VERDICTS = frozenset({"true_positive", "false_positive", "benign"})


class BreachDetectionEngine:
    """
    SQLite-backed breach detection rules and event tracking engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/breach_detection.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS detection_rules (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    rule_type     TEXT NOT NULL,
                    data_source   TEXT NOT NULL DEFAULT 'endpoint',
                    threshold     INTEGER NOT NULL DEFAULT 5,
                    trigger_count INTEGER NOT NULL DEFAULT 0,
                    status        TEXT NOT NULL DEFAULT 'active',
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rules_org
                    ON detection_rules (org_id);

                CREATE INDEX IF NOT EXISTS idx_rules_org_type
                    ON detection_rules (org_id, rule_type);

                CREATE TABLE IF NOT EXISTS detection_events (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    rule_id                 TEXT NOT NULL,
                    severity                TEXT NOT NULL,
                    entity                  TEXT NOT NULL,
                    indicators              TEXT NOT NULL DEFAULT '[]',
                    matched_count           INTEGER NOT NULL DEFAULT 1,
                    status                  TEXT NOT NULL DEFAULT 'open',
                    verdict                 TEXT,
                    investigator            TEXT,
                    investigation_started_at DATETIME,
                    investigation_notes     TEXT,
                    detected_at             DATETIME NOT NULL,
                    closed_at               DATETIME,
                    resolution              TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_org
                    ON detection_events (org_id);

                CREATE INDEX IF NOT EXISTS idx_events_org_detected
                    ON detection_events (org_id, detected_at);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Detection Rules
    # ------------------------------------------------------------------

    def create_detection_rule(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a detection rule.

        data keys: name (required), rule_type (required), data_source (default=endpoint),
                   threshold (int, default=5), status (default=active).
        Returns the created rule record.
        """
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        rule_type = data.get("rule_type", "")
        if rule_type not in VALID_RULE_TYPES:
            raise ValueError(f"rule_type must be one of {sorted(VALID_RULE_TYPES)}")

        data_source = data.get("data_source", "endpoint")
        if data_source not in VALID_DATA_SOURCES:
            raise ValueError(f"data_source must be one of {sorted(VALID_DATA_SOURCES)}")

        threshold = int(data.get("threshold", 5))
        status = data.get("status", "active")
        now = datetime.now(timezone.utc).isoformat()
        rule_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO detection_rules
                        (id, org_id, name, rule_type, data_source, threshold, trigger_count, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (rule_id, org_id, name, rule_type, data_source, threshold, status, now),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "breach_detection_engine", "org_id": org_id, "source_engine": "breach_detection_engine"})
            except Exception:
                pass
        return {
            "id": rule_id,
            "org_id": org_id,
            "name": name,
            "rule_type": rule_type,
            "data_source": data_source,
            "threshold": threshold,
            "trigger_count": 0,
            "status": status,
            "created_at": now,
        }

    def list_detection_rules(
        self,
        org_id: str,
        rule_type: Optional[str] = None,
        data_source: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return detection rules for the org, optionally filtered by rule_type and/or data_source."""
        query = "SELECT * FROM detection_rules WHERE org_id = ?"
        params: List[Any] = [org_id]

        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if data_source:
            query += " AND data_source = ?"
            params.append(data_source)

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Detection Events
    # ------------------------------------------------------------------

    def record_detection_event(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Record a detection event.

        data keys: rule_id (required), severity (required), entity (required),
                   indicators (JSON list), matched_count (int, default=1), status=open.
        Also increments the rule's trigger_count.
        Returns the created event record.
        """
        rule_id = data.get("rule_id", "").strip()
        if not rule_id:
            raise ValueError("rule_id is required")

        severity = data.get("severity", "")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        entity = data.get("entity", "").strip()
        if not entity:
            raise ValueError("entity is required")

        indicators = data.get("indicators", [])
        indicators_json = json.dumps(indicators) if isinstance(indicators, list) else indicators
        matched_count = int(data.get("matched_count", 1))
        status = data.get("status", "open")
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO detection_events
                        (id, org_id, rule_id, severity, entity, indicators,
                         matched_count, status, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, org_id, rule_id, severity, entity,
                     indicators_json, matched_count, status, now),
                )
                # Increment trigger_count on the rule (org-scoped)
                conn.execute(
                    """
                    UPDATE detection_rules
                    SET trigger_count = trigger_count + 1
                    WHERE id = ? AND org_id = ?
                    """,
                    (rule_id, org_id),
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "breach_detection_engine", "org_id": org_id, "source_engine": "breach_detection_engine"})
            except Exception:
                pass
        return {
            "id": event_id,
            "org_id": org_id,
            "rule_id": rule_id,
            "severity": severity,
            "entity": entity,
            "indicators": indicators,
            "matched_count": matched_count,
            "status": status,
            "verdict": None,
            "investigator": None,
            "investigation_started_at": None,
            "investigation_notes": None,
            "detected_at": now,
            "closed_at": None,
            "resolution": None,
        }

    def list_detection_events(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return detection events for the org, ordered by detected_at DESC, limit 100."""
        query = "SELECT * FROM detection_events WHERE org_id = ?"
        params: List[Any] = [org_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        query += " ORDER BY detected_at DESC LIMIT 100"

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            row = dict(r)
            row["indicators"] = json.loads(row.get("indicators") or "[]")
            result.append(row)
        return result

    def investigate_event(
        self,
        org_id: str,
        event_id: str,
        investigator: str,
        notes: str,
    ) -> Dict[str, Any]:
        """
        Mark an event as investigating.

        Sets status=investigating, investigator, investigation_started_at, investigation_notes.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE detection_events
                    SET status = 'investigating',
                        investigator = ?,
                        investigation_started_at = ?,
                        investigation_notes = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (investigator, now, notes, event_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Event {event_id} not found for org {org_id}")
                row = conn.execute(
                    "SELECT * FROM detection_events WHERE id = ?", (event_id,)
                ).fetchone()

        result = dict(row)
        result["indicators"] = json.loads(result.get("indicators") or "[]")
        return result

    def close_event(
        self,
        org_id: str,
        event_id: str,
        verdict: str,
        resolution: str,
    ) -> Dict[str, Any]:
        """
        Close a detection event.

        Sets verdict (true_positive/false_positive/benign), status=closed,
        closed_at, resolution.
        """
        if verdict not in VALID_VERDICTS:
            raise ValueError(f"verdict must be one of {sorted(VALID_VERDICTS)}")

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE detection_events
                    SET status = 'closed',
                        verdict = ?,
                        closed_at = ?,
                        resolution = ?
                    WHERE id = ? AND org_id = ?
                    """,
                    (verdict, now, resolution, event_id, org_id),
                )
                if cursor.rowcount == 0:
                    raise ValueError(f"Event {event_id} not found for org {org_id}")
                row = conn.execute(
                    "SELECT * FROM detection_events WHERE id = ?", (event_id,)
                ).fetchone()

        result = dict(row)
        result["indicators"] = json.loads(result.get("indicators") or "[]")
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_detection_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregate detection statistics for the org.

        Keys: total_rules, active_rules, by_rule_type, total_events_24h, open_events,
              critical_events, false_positive_rate, avg_response_time_hours.
        """
        from datetime import timedelta


        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                # Rule stats
                total_rules = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                active_rules = conn.execute(
                    "SELECT COUNT(*) FROM detection_rules WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]

                rule_type_rows = conn.execute(
                    "SELECT rule_type, COUNT(*) as cnt FROM detection_rules WHERE org_id = ? GROUP BY rule_type",
                    (org_id,),
                ).fetchall()

                # Event stats
                total_events_24h = conn.execute(
                    "SELECT COUNT(*) FROM detection_events WHERE org_id = ? AND detected_at >= ?",
                    (org_id, cutoff_24h),
                ).fetchone()[0]

                open_events = conn.execute(
                    "SELECT COUNT(*) FROM detection_events WHERE org_id = ? AND status = 'open'",
                    (org_id,),
                ).fetchone()[0]

                critical_events = conn.execute(
                    "SELECT COUNT(*) FROM detection_events WHERE org_id = ? AND severity = 'critical'",
                    (org_id,),
                ).fetchone()[0]

                # False positive rate
                total_closed = conn.execute(
                    "SELECT COUNT(*) FROM detection_events WHERE org_id = ? AND status = 'closed'",
                    (org_id,),
                ).fetchone()[0]

                fp_count = conn.execute(
                    "SELECT COUNT(*) FROM detection_events WHERE org_id = ? AND verdict = 'false_positive'",
                    (org_id,),
                ).fetchone()[0]

                # Average response time (closed events)
                closed_rows = conn.execute(
                    """
                    SELECT detected_at, closed_at
                    FROM detection_events
                    WHERE org_id = ? AND status = 'closed'
                      AND detected_at IS NOT NULL AND closed_at IS NOT NULL
                    """,
                    (org_id,),
                ).fetchall()

        by_rule_type: Dict[str, int] = {}
        for r in rule_type_rows:
            by_rule_type[r["rule_type"]] = r["cnt"]

        false_positive_rate = round(
            (fp_count / total_closed * 100) if total_closed > 0 else 0.0, 2
        )

        # Compute avg response time in hours
        total_hours = 0.0
        count_timed = 0
        for r in closed_rows:
            try:
                detected = datetime.fromisoformat(r["detected_at"])
                closed = datetime.fromisoformat(r["closed_at"])
                diff_hours = (closed - detected).total_seconds() / 3600
                total_hours += diff_hours
                count_timed += 1
            except (ValueError, TypeError):
                pass

        avg_response_time_hours = round(
            total_hours / count_timed if count_timed > 0 else 0.0, 2
        )

        return {
            "total_rules": total_rules,
            "active_rules": active_rules,
            "by_rule_type": by_rule_type,
            "total_events_24h": total_events_24h,
            "open_events": open_events,
            "critical_events": critical_events,
            "false_positive_rate": false_positive_rate,
            "avg_response_time_hours": avg_response_time_hours,
        }
