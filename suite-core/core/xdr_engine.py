"""XDR Correlation Engine (Extended Detection & Response) — ALDECI.

Cross-domain threat correlation: ingests signals from endpoint, network,
cloud, identity, email, and application sources; auto-correlates into
incidents; supports correlation rules.

Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
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

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "xdr.db"
)

_VALID_SOURCE_TYPES = {
    "endpoint", "network", "cloud", "identity", "email", "application", "threat_intel",
}
_VALID_SIGNAL_TYPES = {
    "malware", "lateral_movement", "credential_theft", "exfiltration",
    "c2", "anomaly", "policy_violation",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_ENTITY_TYPES = {"host", "ip", "user", "file", "process", "domain"}
_VALID_ATTACK_STAGES = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "impact",
}
_VALID_INCIDENT_STATUSES = {"new", "investigating", "contained", "resolved"}


class XDREngine:
    """SQLite WAL-backed XDR Correlation Engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS xdr_signals (
                    signal_id     TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    source_type   TEXT NOT NULL DEFAULT 'endpoint',
                    source_system TEXT NOT NULL DEFAULT '',
                    signal_type   TEXT NOT NULL DEFAULT 'anomaly',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    entity_id     TEXT NOT NULL DEFAULT '',
                    entity_type   TEXT NOT NULL DEFAULT 'host',
                    raw_data      TEXT NOT NULL DEFAULT '{}',
                    confidence    REAL NOT NULL DEFAULT 0.8,
                    ingested_at   DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_xs_org
                    ON xdr_signals (org_id, ingested_at DESC);
                CREATE INDEX IF NOT EXISTS idx_xs_entity
                    ON xdr_signals (org_id, entity_id, ingested_at DESC);

                CREATE TABLE IF NOT EXISTS xdr_incidents (
                    incident_id       TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    title             TEXT NOT NULL DEFAULT '',
                    description       TEXT NOT NULL DEFAULT '',
                    attack_stage      TEXT NOT NULL DEFAULT 'initial_access',
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    status            TEXT NOT NULL DEFAULT 'new',
                    assigned_to       TEXT NOT NULL DEFAULT '',
                    first_seen        DATETIME,
                    last_seen         DATETIME,
                    signal_count      INTEGER NOT NULL DEFAULT 0,
                    affected_entities TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_xi_org
                    ON xdr_incidents (org_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS incident_signals (
                    link_id     TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    signal_id   TEXT NOT NULL,
                    linked_at   DATETIME,
                    UNIQUE(org_id, incident_id, signal_id)
                );
                CREATE INDEX IF NOT EXISTS idx_is_incident
                    ON incident_signals (org_id, incident_id);

                CREATE TABLE IF NOT EXISTS correlation_rules (
                    rule_id           TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL DEFAULT '',
                    description       TEXT NOT NULL DEFAULT '',
                    conditions        TEXT NOT NULL DEFAULT '{}',
                    incident_severity TEXT NOT NULL DEFAULT 'medium',
                    mitre_tactic      TEXT NOT NULL DEFAULT '',
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    created_at        DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_cr_org
                    ON correlation_rules (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auto_correlate(self, org_id: str, signal: Dict[str, Any]) -> None:
        """If entity has 2+ signals in the past 24h, auto-create/update incident."""
        entity_id = signal.get("entity_id", "")
        if not entity_id:
            return

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT signal_id, signal_type, severity, entity_id, entity_type
                FROM xdr_signals
                WHERE org_id=? AND entity_id=? AND ingested_at >= ?
                ORDER BY ingested_at DESC
                """,
                (org_id, entity_id, cutoff),
            ).fetchall()

        if len(rows) < 2:
            return

        signals_data = [self._row(r) for r in rows]

        # Check if an open incident already covers this entity
        with self._conn() as conn:
            existing = conn.execute(
                """
                SELECT * FROM xdr_incidents
                WHERE org_id=? AND status NOT IN ('resolved')
                  AND affected_entities LIKE ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (org_id, f"%{entity_id}%"),
            ).fetchone()

        if existing:
            incident = self._row(existing)
            incident_id = incident["incident_id"]
            # Link the new signal and update
            self.link_signal_to_incident(
                org_id, incident_id, signal["signal_id"]
            )
        else:
            # Infer severity from max of signals
            sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            max_sev = max(
                signals_data,
                key=lambda s: sev_rank.get(s.get("severity", "low"), 1),
            )
            inferred_sev = max_sev.get("severity", "medium")

            # Infer attack stage from signal_types
            type_to_stage: Dict[str, str] = {
                "malware": "execution",
                "lateral_movement": "lateral_movement",
                "credential_theft": "credential_access",
                "exfiltration": "exfiltration",
                "c2": "impact",
                "anomaly": "discovery",
                "policy_violation": "defense_evasion",
            }
            first_type = signals_data[0].get("signal_type", "anomaly")
            attack_stage = type_to_stage.get(first_type, "initial_access")

            incident_data = {
                "title": f"Auto-correlated incident for entity {entity_id}",
                "description": (
                    f"Auto-created from {len(signals_data)} correlated signals "
                    f"for entity {entity_id} within 24h window."
                ),
                "attack_stage": attack_stage,
                "severity": inferred_sev,
                "affected_entities": [entity_id],
            }
            incident = self.create_incident(org_id, incident_data)
            incident_id = incident["incident_id"]

            # Link all signals found in window
            for sig in signals_data:
                try:
                    self.link_signal_to_incident(org_id, incident_id, sig["signal_id"])
                except Exception:
                    pass  # may already be linked

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def ingest_signal(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a signal, persist it, then run auto-correlation."""
        signal_id = str(uuid.uuid4())
        now = data.get("ingested_at") or datetime.now(timezone.utc).isoformat()
        raw_data = data.get("raw_data", {})

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO xdr_signals
                        (signal_id, org_id, source_type, source_system,
                         signal_type, severity, entity_id, entity_type,
                         raw_data, confidence, ingested_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        signal_id, org_id,
                        data.get("source_type", "endpoint"),
                        data.get("source_system", ""),
                        data.get("signal_type", "anomaly"),
                        data.get("severity", "medium"),
                        data.get("entity_id", ""),
                        data.get("entity_type", "host"),
                        json.dumps(raw_data) if isinstance(raw_data, dict) else raw_data,
                        float(data.get("confidence", 0.8)),
                        now,
                    ),
                )

        signal = {
            "signal_id": signal_id,
            "org_id": org_id,
            "source_type": data.get("source_type", "endpoint"),
            "source_system": data.get("source_system", ""),
            "signal_type": data.get("signal_type", "anomaly"),
            "severity": data.get("severity", "medium"),
            "entity_id": data.get("entity_id", ""),
            "entity_type": data.get("entity_type", "host"),
            "raw_data": raw_data,
            "confidence": float(data.get("confidence", 0.8)),
            "ingested_at": now,
        }

        # Run auto-correlation outside the write lock
        try:
            self._auto_correlate(org_id, signal)
        except Exception as exc:
            _logger.warning("Auto-correlation error: %s", exc)

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "xdr", "org_id": org_id, "source_engine": "xdr"})
            except Exception:
                pass

        return signal

    def list_signals(
        self,
        org_id: str,
        source_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM xdr_signals WHERE org_id=?"
        params: list = [org_id]
        if source_type:
            query += " AND source_type=?"
            params.append(source_type)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY ingested_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            d["raw_data"] = json.loads(d.get("raw_data") or "{}")
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        affected_entities = data.get("affected_entities", [])

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO xdr_incidents
                        (incident_id, org_id, title, description, attack_stage,
                         severity, status, assigned_to, first_seen, last_seen,
                         signal_count, affected_entities, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        incident_id, org_id,
                        data.get("title", ""),
                        data.get("description", ""),
                        data.get("attack_stage", "initial_access"),
                        data.get("severity", "medium"),
                        data.get("status", "new"),
                        data.get("assigned_to", ""),
                        now, now,
                        int(data.get("signal_count", 0)),
                        json.dumps(affected_entities)
                        if isinstance(affected_entities, list)
                        else affected_entities,
                        now,
                    ),
                )

        return {
            "incident_id": incident_id,
            "org_id": org_id,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "attack_stage": data.get("attack_stage", "initial_access"),
            "severity": data.get("severity", "medium"),
            "status": data.get("status", "new"),
            "assigned_to": data.get("assigned_to", ""),
            "first_seen": now,
            "last_seen": now,
            "signal_count": int(data.get("signal_count", 0)),
            "affected_entities": affected_entities,
            "created_at": now,
        }

    def link_signal_to_incident(
        self, org_id: str, incident_id: str, signal_id: str
    ) -> bool:
        """Link a signal to an incident, update signal_count, last_seen, affected_entities."""
        link_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                # Check incident belongs to org
                inc_row = conn.execute(
                    "SELECT * FROM xdr_incidents WHERE org_id=? AND incident_id=?",
                    (org_id, incident_id),
                ).fetchone()
                if not inc_row:
                    return False

                # Get signal entity_id
                sig_row = conn.execute(
                    "SELECT entity_id FROM xdr_signals WHERE org_id=? AND signal_id=?",
                    (org_id, signal_id),
                ).fetchone()

                try:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO incident_signals
                            (link_id, org_id, incident_id, signal_id, linked_at)
                        VALUES (?,?,?,?,?)
                        """,
                        (link_id, org_id, incident_id, signal_id, now),
                    )
                except Exception:
                    return False

                # Update signal_count and last_seen
                inc = self._row(inc_row)
                current_entities: List[str] = json.loads(
                    inc.get("affected_entities") or "[]"
                )
                if sig_row:
                    eid = sig_row["entity_id"]
                    if eid and eid not in current_entities:
                        current_entities.append(eid)

                conn.execute(
                    """
                    UPDATE xdr_incidents
                    SET signal_count = signal_count + 1,
                        last_seen = ?,
                        affected_entities = ?
                    WHERE org_id=? AND incident_id=?
                    """,
                    (now, json.dumps(current_entities), org_id, incident_id),
                )

        return True

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        attack_stage: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM xdr_incidents WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if attack_stage:
            query += " AND attack_stage=?"
            params.append(attack_stage)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            d["affected_entities"] = json.loads(d.get("affected_entities") or "[]")
            result.append(d)
        return result

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Return incident dict with linked signals list."""
        with self._conn() as conn:
            inc_row = conn.execute(
                "SELECT * FROM xdr_incidents WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            ).fetchone()
            if not inc_row:
                return None

            link_rows = conn.execute(
                """
                SELECT s.* FROM xdr_signals s
                JOIN incident_signals ls ON s.signal_id = ls.signal_id
                WHERE ls.org_id=? AND ls.incident_id=?
                ORDER BY s.ingested_at DESC
                """,
                (org_id, incident_id),
            ).fetchall()

        d = self._row(inc_row)
        d["affected_entities"] = json.loads(d.get("affected_entities") or "[]")

        signals = []
        for r in link_rows:
            sd = self._row(r)
            sd["raw_data"] = json.loads(sd.get("raw_data") or "{}")
            signals.append(sd)
        d["signals"] = signals

        return d

    def update_incident_status(
        self,
        org_id: str,
        incident_id: str,
        status: str,
        assigned_to: Optional[str] = None,
    ) -> bool:
        if status not in _VALID_INCIDENT_STATUSES:
            raise ValueError(f"Invalid incident status: {status!r}")

        with self._lock:
            with self._conn() as conn:
                if assigned_to is not None:
                    cur = conn.execute(
                        """
                        UPDATE xdr_incidents SET status=?, assigned_to=?
                        WHERE org_id=? AND incident_id=?
                        """,
                        (status, assigned_to, org_id, incident_id),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE xdr_incidents SET status=? WHERE org_id=? AND incident_id=?",
                        (status, org_id, incident_id),
                    )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Correlation rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        conditions = data.get("conditions", {})

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO correlation_rules
                        (rule_id, org_id, name, description, conditions,
                         incident_severity, mitre_tactic, enabled, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rule_id, org_id,
                        data.get("name", ""),
                        data.get("description", ""),
                        json.dumps(conditions) if isinstance(conditions, dict) else conditions,
                        data.get("incident_severity", "medium"),
                        data.get("mitre_tactic", ""),
                        int(data.get("enabled", 1)),
                        now,
                    ),
                )

        return {
            "rule_id": rule_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "conditions": conditions,
            "incident_severity": data.get("incident_severity", "medium"),
            "mitre_tactic": data.get("mitre_tactic", ""),
            "enabled": int(data.get("enabled", 1)),
            "created_at": now,
        }

    def list_rules(self, org_id: str, enabled_only: bool = True) -> List[Dict[str, Any]]:
        query = "SELECT * FROM correlation_rules WHERE org_id=?"
        params: list = [org_id]
        if enabled_only:
            query += " AND enabled=1"
        query += " ORDER BY name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            d["conditions"] = json.loads(d.get("conditions") or "{}")
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_xdr_stats(self, org_id: str) -> Dict[str, Any]:
        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()

        with self._conn() as conn:
            total_signals = conn.execute(
                "SELECT COUNT(*) FROM xdr_signals WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            source_rows = conn.execute(
                """
                SELECT source_type, COUNT(*) AS cnt
                FROM xdr_signals WHERE org_id=?
                GROUP BY source_type
                """,
                (org_id,),
            ).fetchall()

            new_incidents = conn.execute(
                "SELECT COUNT(*) FROM xdr_incidents WHERE org_id=? AND status='new'",
                (org_id,),
            ).fetchone()[0]

            active_incidents = conn.execute(
                """
                SELECT COUNT(*) FROM xdr_incidents
                WHERE org_id=? AND status NOT IN ('resolved')
                """,
                (org_id,),
            ).fetchone()[0]

            critical_incidents = conn.execute(
                "SELECT COUNT(*) FROM xdr_incidents WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]

            stage_rows = conn.execute(
                """
                SELECT attack_stage, COUNT(*) AS cnt
                FROM xdr_incidents WHERE org_id=?
                GROUP BY attack_stage
                """,
                (org_id,),
            ).fetchall()

            signals_24h = conn.execute(
                "SELECT COUNT(*) FROM xdr_signals WHERE org_id=? AND ingested_at>=?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

        by_source = {r["source_type"]: r["cnt"] for r in source_rows}
        by_attack_stage = {r["attack_stage"]: r["cnt"] for r in stage_rows}

        return {
            "total_signals": total_signals,
            "by_source": by_source,
            "new_incidents": new_incidents,
            "active_incidents": active_incidents,
            "critical_incidents": critical_incidents,
            "by_attack_stage": by_attack_stage,
            "signals_last_24h": signals_24h,
        }
