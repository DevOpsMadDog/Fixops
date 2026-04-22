"""Threat Correlation Engine — ALDECI.

Correlates threat signals across multiple feeds and engines to surface
correlated incidents automatically.

Capabilities:
  - Signal ingestion from any source engine (EDR, NDR, XDR, SIEM, threat feeds, DLP)
  - Rule-based correlation: count matching signals within a time window
  - Auto-incident creation when signal count meets threshold
  - Incident lifecycle management with full signal timeline
  - Stats aggregation per org

Compliance: MITRE ATT&CK, NIST SP 800-61, SOC 2 Type II
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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SIGNAL_TYPES = {"alert", "ioc", "anomaly", "vulnerability", "log_event"}
_VALID_SOURCE_ENGINES = {"edr", "ndr", "xdr", "siem", "threat_feed", "dlp"}
_VALID_ENTITY_TYPES = {"ip", "domain", "user", "hostname", "hash", "email"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_INCIDENT_STATUSES = {"new", "investigating", "contained", "resolved"}
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _minutes_ago_iso(minutes: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.isoformat()


class ThreatCorrelationEngine:
    """SQLite WAL-backed Threat Correlation engine.

    Thread-safe via RLock. Multi-tenant via org_id — each org gets its own DB.
    """

    _instances: Dict[str, "ThreatCorrelationEngine"] = {}
    _instances_lock = threading.Lock()

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    @classmethod
    def for_org(cls, org_id: str) -> "ThreatCorrelationEngine":
        with cls._instances_lock:
            if org_id not in cls._instances:
                db_path = str(_DATA_DIR / f"{org_id}_threat_correlation.db")
                cls._instances[org_id] = cls(db_path)
            return cls._instances[org_id]

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
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    rule_name             TEXT NOT NULL,
                    signal_types          TEXT NOT NULL DEFAULT '[]',
                    time_window_minutes   INTEGER NOT NULL DEFAULT 60,
                    min_signals           INTEGER NOT NULL DEFAULT 3,
                    severity_threshold    TEXT NOT NULL DEFAULT 'medium',
                    correlation_field     TEXT NOT NULL DEFAULT 'src_ip',
                    auto_create_incident  INTEGER NOT NULL DEFAULT 1,
                    mitre_tactic          TEXT NOT NULL DEFAULT '',
                    enabled               INTEGER NOT NULL DEFAULT 1,
                    hit_count             INTEGER NOT NULL DEFAULT 0,
                    created_at            TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cr_org_enabled
                    ON correlation_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS threat_signals (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    signal_type           TEXT NOT NULL DEFAULT 'alert',
                    source_engine         TEXT NOT NULL DEFAULT 'siem',
                    signal_id             TEXT NOT NULL DEFAULT '',
                    entity_type           TEXT NOT NULL DEFAULT 'ip',
                    entity_value          TEXT NOT NULL DEFAULT '',
                    severity              TEXT NOT NULL DEFAULT 'medium',
                    description           TEXT NOT NULL DEFAULT '',
                    timestamp             TEXT NOT NULL,
                    ttl_minutes           INTEGER NOT NULL DEFAULT 1440,
                    expires_at            TEXT NOT NULL,
                    correlated_incident_id TEXT,
                    created_at            TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ts_org_entity
                    ON threat_signals (org_id, entity_value, timestamp DESC);

                CREATE INDEX IF NOT EXISTS idx_ts_org_type
                    ON threat_signals (org_id, signal_type, timestamp DESC);

                CREATE TABLE IF NOT EXISTS correlated_incidents (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    title               TEXT NOT NULL,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    status              TEXT NOT NULL DEFAULT 'new',
                    signal_count        INTEGER NOT NULL DEFAULT 1,
                    entity_value        TEXT NOT NULL DEFAULT '',
                    entity_type         TEXT NOT NULL DEFAULT 'ip',
                    correlation_rule_id TEXT NOT NULL DEFAULT '',
                    mitre_tactic        TEXT NOT NULL DEFAULT '',
                    first_signal_at     TEXT NOT NULL,
                    last_signal_at      TEXT NOT NULL,
                    confidence          REAL NOT NULL DEFAULT 0.8,
                    auto_created        INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL,
                    resolved_at         TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org_status
                    ON correlated_incidents (org_id, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS correlation_timeline (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    incident_id   TEXT NOT NULL,
                    signal_id     TEXT NOT NULL,
                    signal_type   TEXT NOT NULL DEFAULT '',
                    source_engine TEXT NOT NULL DEFAULT '',
                    entity_value  TEXT NOT NULL DEFAULT '',
                    severity      TEXT NOT NULL DEFAULT '',
                    timestamp     TEXT NOT NULL,
                    created_at    TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ct_org_incident
                    ON correlation_timeline (org_id, incident_id, timestamp DESC);

                CREATE TABLE IF NOT EXISTS toxic_combo_matches (
                    id                       TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    combo_id                 TEXT NOT NULL,
                    entity_ref               TEXT NOT NULL,
                    matched_attributes_json  TEXT NOT NULL DEFAULT '[]',
                    severity                 TEXT NOT NULL DEFAULT 'medium',
                    attack_chain_id          TEXT,
                    created_at               TEXT NOT NULL,
                    UNIQUE(org_id, combo_id, entity_ref)
                );

                CREATE INDEX IF NOT EXISTS idx_tcm_org_combo
                    ON toxic_combo_matches (org_id, combo_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_tcm_org_entity
                    ON toxic_combo_matches (org_id, entity_ref);

                CREATE TABLE IF NOT EXISTS toxic_combo_entities (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    entity_ref         TEXT NOT NULL,
                    attributes_json    TEXT NOT NULL DEFAULT '{}',
                    created_at         TEXT NOT NULL,
                    updated_at         TEXT NOT NULL,
                    UNIQUE(org_id, entity_ref)
                );

                CREATE INDEX IF NOT EXISTS idx_tce_org
                    ON toxic_combo_entities (org_id, entity_ref);
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
    # Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a correlation rule."""
        rule_name = (data.get("rule_name") or "").strip()
        if not rule_name:
            raise ValueError("rule_name is required.")
        sev_threshold = data.get("severity_threshold", "medium")
        if sev_threshold not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity_threshold: {sev_threshold}")

        signal_types = data.get("signal_types", [])
        if isinstance(signal_types, list):
            signal_types_json = json.dumps(signal_types)
        else:
            signal_types_json = json.dumps([signal_types])

        now = _now_iso()
        rule = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_name": rule_name,
            "signal_types": signal_types_json,
            "time_window_minutes": int(data.get("time_window_minutes", 60)),
            "min_signals": int(data.get("min_signals", 3)),
            "severity_threshold": sev_threshold,
            "correlation_field": data.get("correlation_field", "src_ip"),
            "auto_create_incident": 1 if data.get("auto_create_incident", True) else 0,
            "mitre_tactic": data.get("mitre_tactic", ""),
            "enabled": 1 if data.get("enabled", True) else 0,
            "hit_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO correlation_rules
                       (id, org_id, rule_name, signal_types, time_window_minutes, min_signals,
                        severity_threshold, correlation_field, auto_create_incident, mitre_tactic,
                        enabled, hit_count, created_at)
                       VALUES (:id, :org_id, :rule_name, :signal_types, :time_window_minutes,
                               :min_signals, :severity_threshold, :correlation_field,
                               :auto_create_incident, :mitre_tactic, :enabled, :hit_count, :created_at)""",
                    rule,
                )
        rule["signal_types"] = json.loads(rule["signal_types"])
        rule["auto_create_incident"] = bool(rule["auto_create_incident"])
        rule["enabled"] = bool(rule["enabled"])
        return rule

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM correlation_rules WHERE org_id = ? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        result = []
        for row in rows:
            r = self._row(row)
            try:
                r["signal_types"] = json.loads(r["signal_types"])
            except Exception:
                r["signal_types"] = []
            result.append(r)
        return result

    # ------------------------------------------------------------------
    # Signal ingestion
    # ------------------------------------------------------------------

    def ingest_signal(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a threat signal, then attempt correlation."""
        signal_type = data.get("signal_type", "alert")
        if signal_type not in _VALID_SIGNAL_TYPES:
            raise ValueError(f"Invalid signal_type: {signal_type}")

        source_engine = data.get("source_engine", "siem")
        entity_type = data.get("entity_type", "ip")
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        ttl_minutes = int(data.get("ttl_minutes", 1440))
        now = _now_iso()
        timestamp = data.get("timestamp", now)
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        ).isoformat()

        signal = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "signal_type": signal_type,
            "source_engine": source_engine,
            "signal_id": data.get("signal_id", ""),
            "entity_type": entity_type,
            "entity_value": data.get("entity_value", ""),
            "severity": severity,
            "description": data.get("description", ""),
            "timestamp": timestamp,
            "ttl_minutes": ttl_minutes,
            "expires_at": expires_at,
            "correlated_incident_id": None,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_signals
                       (id, org_id, signal_type, source_engine, signal_id, entity_type,
                        entity_value, severity, description, timestamp, ttl_minutes, expires_at,
                        correlated_incident_id, created_at)
                       VALUES (:id, :org_id, :signal_type, :source_engine, :signal_id, :entity_type,
                               :entity_value, :severity, :description, :timestamp, :ttl_minutes,
                               :expires_at, :correlated_incident_id, :created_at)""",
                    signal,
                )

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("THREAT_DETECTED", {"entity_type": "threat_signal", "entity_id": str(signal["id"]), "org_id": org_id, "source_engine": "threat_correlation_engine"})
            except Exception:
                pass  # Event emission should never break the main operation

        # Attempt correlation
        try:
            incident_id = self._correlate(org_id, signal)
            if incident_id:
                signal["correlated_incident_id"] = incident_id
        except Exception as exc:
            _logger.warning("Correlation failed for signal %s: %s", signal["id"], exc)

        return signal

    def _correlate(self, org_id: str, signal: Dict[str, Any]) -> Optional[str]:
        """Check all enabled rules; create/update incident if thresholds met."""
        entity_value = signal.get("entity_value", "")
        if not entity_value:
            return None

        with self._lock:
            with self._conn() as conn:
                rules = conn.execute(
                    "SELECT * FROM correlation_rules WHERE org_id = ? AND enabled = 1",
                    (org_id,),
                ).fetchall()

            for rule_row in rules:
                rule = self._row(rule_row)
                sev_threshold = rule["severity_threshold"]
                signal_sev_order = _SEVERITY_ORDER.get(signal["severity"], 0)
                threshold_order = _SEVERITY_ORDER.get(sev_threshold, 0)
                if signal_sev_order < threshold_order:
                    continue

                # Check signal types filter
                try:
                    allowed_types = json.loads(rule["signal_types"])
                except Exception:
                    allowed_types = []
                if allowed_types and signal["signal_type"] not in allowed_types:
                    continue

                # Count signals for same entity_value within time_window
                window_start = _minutes_ago_iso(rule["time_window_minutes"])
                with self._conn() as conn:
                    count_row = conn.execute(
                        """SELECT COUNT(*) as cnt FROM threat_signals
                           WHERE org_id = ? AND entity_value = ? AND timestamp >= ?""",
                        (org_id, entity_value, window_start),
                    ).fetchone()
                count = count_row["cnt"] if count_row else 0

                if count < rule["min_signals"]:
                    continue

                if not rule["auto_create_incident"]:
                    continue

                # Check for existing active incident for this entity + rule
                with self._conn() as conn:
                    existing = conn.execute(
                        """SELECT id FROM correlated_incidents
                           WHERE org_id = ? AND entity_value = ? AND correlation_rule_id = ?
                           AND status NOT IN ('resolved')
                           ORDER BY created_at DESC LIMIT 1""",
                        (org_id, entity_value, rule["id"]),
                    ).fetchone()

                now = _now_iso()
                if existing:
                    incident_id = existing["id"]
                    with self._conn() as conn:
                        conn.execute(
                            """UPDATE correlated_incidents
                               SET signal_count = signal_count + 1, last_signal_at = ?
                               WHERE org_id = ? AND id = ?""",
                            (now, org_id, incident_id),
                        )
                else:
                    incident_id = str(uuid.uuid4())
                    incident = {
                        "id": incident_id,
                        "org_id": org_id,
                        "title": f"Correlated: {rule['rule_name']} — {entity_value}",
                        "severity": signal["severity"],
                        "status": "new",
                        "signal_count": count,
                        "entity_value": entity_value,
                        "entity_type": signal.get("entity_type", "ip"),
                        "correlation_rule_id": rule["id"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "first_signal_at": signal["timestamp"],
                        "last_signal_at": now,
                        "confidence": min(0.5 + (count / 10.0), 0.99),
                        "auto_created": 1,
                        "created_at": now,
                        "resolved_at": None,
                    }
                    with self._conn() as conn:
                        conn.execute(
                            """INSERT INTO correlated_incidents
                               (id, org_id, title, severity, status, signal_count, entity_value,
                                entity_type, correlation_rule_id, mitre_tactic, first_signal_at,
                                last_signal_at, confidence, auto_created, created_at, resolved_at)
                               VALUES (:id, :org_id, :title, :severity, :status, :signal_count,
                                       :entity_value, :entity_type, :correlation_rule_id, :mitre_tactic,
                                       :first_signal_at, :last_signal_at, :confidence, :auto_created,
                                       :created_at, :resolved_at)""",
                            incident,
                        )

                # Bump rule hit count
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE correlation_rules SET hit_count = hit_count + 1 WHERE org_id = ? AND id = ?",
                        (org_id, rule["id"]),
                    )

                # Update signal correlation reference
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE threat_signals SET correlated_incident_id = ? WHERE org_id = ? AND id = ?",
                        (incident_id, org_id, signal["id"]),
                    )

                # Add to timeline
                timeline_entry = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "incident_id": incident_id,
                    "signal_id": signal["id"],
                    "signal_type": signal.get("signal_type", ""),
                    "source_engine": signal.get("source_engine", ""),
                    "entity_value": entity_value,
                    "severity": signal.get("severity", ""),
                    "timestamp": signal.get("timestamp", now),
                    "created_at": now,
                }
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO correlation_timeline
                           (id, org_id, incident_id, signal_id, signal_type, source_engine,
                            entity_value, severity, timestamp, created_at)
                           VALUES (:id, :org_id, :incident_id, :signal_id, :signal_type,
                                   :source_engine, :entity_value, :severity, :timestamp, :created_at)""",
                        timeline_entry,
                    )

                return incident_id  # Return first matched incident

        return None

    # ------------------------------------------------------------------
    # Signals
    # ------------------------------------------------------------------

    def list_signals(
        self,
        org_id: str,
        signal_type: Optional[str] = None,
        entity_value: Optional[str] = None,
        source_engine: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM threat_signals WHERE org_id = ?"
        params: list = [org_id]
        if signal_type:
            sql += " AND signal_type = ?"
            params.append(signal_type)
        if entity_value:
            sql += " AND entity_value = ?"
            params.append(entity_value)
        if source_engine:
            sql += " AND source_engine = ?"
            params.append(source_engine)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def list_incidents(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM correlated_incidents WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_incident(
        self, org_id: str, incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return incident with full signal timeline."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM correlated_incidents WHERE org_id = ? AND id = ?",
                (org_id, incident_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            timeline = [
                self._row(r)
                for r in conn.execute(
                    """SELECT * FROM correlation_timeline
                       WHERE org_id = ? AND incident_id = ?
                       ORDER BY timestamp ASC""",
                    (org_id, incident_id),
                ).fetchall()
            ]
        result["timeline"] = timeline
        return result

    def resolve_incident(self, org_id: str, incident_id: str) -> bool:
        """Mark incident as resolved. Returns True if found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE correlated_incidents
                       SET status = 'resolved', resolved_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, incident_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_trustgraph_context(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context to enrich threat correlation.

        Returns related assets, findings, and incidents for correlation analysis.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=entity_id, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=entity_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    def get_correlation_stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            total_signals = conn.execute(
                "SELECT COUNT(*) FROM threat_signals WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT signal_type, COUNT(*) as cnt FROM threat_signals WHERE org_id = ? GROUP BY signal_type",
                (org_id,),
            ).fetchall()
            signals_by_type = {r["signal_type"]: r["cnt"] for r in by_type_rows}

            incidents_created = conn.execute(
                "SELECT COUNT(*) FROM correlated_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            auto_created = conn.execute(
                "SELECT COUNT(*) FROM correlated_incidents WHERE org_id = ? AND auto_created = 1",
                (org_id,),
            ).fetchone()[0]

            by_sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM correlated_incidents WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_sev_rows}

            top_entity_rows = conn.execute(
                """SELECT entity_value, COUNT(*) as cnt FROM threat_signals
                   WHERE org_id = ? GROUP BY entity_value ORDER BY cnt DESC LIMIT 10""",
                (org_id,),
            ).fetchall()
            top_entities = [{"entity": r["entity_value"], "count": r["cnt"]} for r in top_entity_rows]

            correlated_signals = conn.execute(
                "SELECT COUNT(*) FROM threat_signals WHERE org_id = ? AND correlated_incident_id IS NOT NULL",
                (org_id,),
            ).fetchone()[0]

        correlation_rate = (
            round(correlated_signals / total_signals * 100, 2) if total_signals > 0 else 0.0
        )

        return {
            "total_signals": total_signals,
            "signals_by_type": signals_by_type,
            "incidents_created": incidents_created,
            "auto_created": auto_created,
            "by_severity": by_severity,
            "top_entities": top_entities,
            "correlation_rate": correlation_rate,
        }

    # ------------------------------------------------------------------
    # Toxic-combo correlation (GAP-021 — Wiz parity)
    # ------------------------------------------------------------------

    def upsert_entity_attributes(
        self,
        org_id: str,
        entity_ref: str,
        attributes: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Idempotent upsert of an entity + its attributes used by toxic-combo eval.

        ``entity_ref`` must be globally-unique-per-org (e.g. ``asset:ec2-123``,
        ``identity:alice``). ``attributes`` is a flat dict consumed by
        ``toxic_combo_rules.evaluate_combo``.
        """
        if not entity_ref or not entity_ref.strip():
            raise ValueError("entity_ref is required.")
        if not isinstance(attributes, dict):
            raise TypeError("attributes must be a dict.")
        now = _now_iso()
        attrs_json = json.dumps(attributes, sort_keys=True, default=str)
        with self._lock:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM toxic_combo_entities WHERE org_id = ? AND entity_ref = ?",
                    (org_id, entity_ref),
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE toxic_combo_entities
                           SET attributes_json = ?, updated_at = ?
                           WHERE org_id = ? AND entity_ref = ?""",
                        (attrs_json, now, org_id, entity_ref),
                    )
                    record_id = existing["id"]
                else:
                    record_id = str(uuid.uuid4())
                    conn.execute(
                        """INSERT INTO toxic_combo_entities
                           (id, org_id, entity_ref, attributes_json, created_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (record_id, org_id, entity_ref, attrs_json, now, now),
                    )
        return {
            "id": record_id,
            "org_id": org_id,
            "entity_ref": entity_ref,
            "attributes": attributes,
            "updated_at": now,
        }

    def list_entities(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all entities registered for toxic-combo evaluation."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM toxic_combo_entities WHERE org_id = ? ORDER BY updated_at DESC",
                (org_id,),
            ).fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            d = self._row(row)
            try:
                d["attributes"] = json.loads(d.get("attributes_json") or "{}")
            except Exception:
                d["attributes"] = {}
            d.pop("attributes_json", None)
            result.append(d)
        return result

    def correlate_toxic_combos(
        self,
        org_id: str,
        rules: Optional[List[Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluate every registered entity against every toxic-combo rule.

        Returns a list of match records. Matches are persisted idempotently via
        the ``UNIQUE(org_id, combo_id, entity_ref)`` constraint — re-running on
        the same data produces the same rows.
        """
        from core.toxic_combo_rules import (
            BUILTIN_RULES,
            evaluate_combo,
        )

        rule_set = list(rules) if rules is not None else list(BUILTIN_RULES)
        now = _now_iso()
        matches: List[Dict[str, Any]] = []

        entities = self.list_entities(org_id)
        if not entities:
            return matches

        with self._lock:
            with self._conn() as conn:
                for entity in entities:
                    attrs = entity.get("attributes") or {}
                    entity_ref = entity["entity_ref"]
                    for rule in rule_set:
                        matched, satisfied = evaluate_combo(rule, attrs)
                        if not matched:
                            continue
                        existing = conn.execute(
                            """SELECT id, matched_attributes_json FROM toxic_combo_matches
                               WHERE org_id = ? AND combo_id = ? AND entity_ref = ?""",
                            (org_id, rule.id, entity_ref),
                        ).fetchone()
                        matched_json = json.dumps(satisfied)
                        if existing:
                            match_id = existing["id"]
                            conn.execute(
                                """UPDATE toxic_combo_matches
                                   SET matched_attributes_json = ?, severity = ?
                                   WHERE org_id = ? AND id = ?""",
                                (matched_json, rule.severity, org_id, match_id),
                            )
                        else:
                            match_id = str(uuid.uuid4())
                            conn.execute(
                                """INSERT INTO toxic_combo_matches
                                   (id, org_id, combo_id, entity_ref, matched_attributes_json,
                                    severity, attack_chain_id, created_at)
                                   VALUES (?, ?, ?, ?, ?, ?, NULL, ?)""",
                                (
                                    match_id,
                                    org_id,
                                    rule.id,
                                    entity_ref,
                                    matched_json,
                                    rule.severity,
                                    now,
                                ),
                            )
                        matches.append(
                            {
                                "id": match_id,
                                "org_id": org_id,
                                "combo_id": rule.id,
                                "combo_name": rule.name,
                                "entity_ref": entity_ref,
                                "severity": rule.severity,
                                "matched_attributes": satisfied,
                            }
                        )

        # Best-effort: notify event bus
        if _get_tg_bus and matches:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit(
                        "TOXIC_COMBO_MATCHED",
                        {
                            "entity_type": "toxic_combo",
                            "org_id": org_id,
                            "match_count": len(matches),
                            "source_engine": "threat_correlation_engine",
                        },
                    )
            except Exception:
                pass

        # Best-effort: mirror into security event correlation stream.
        try:
            from core.security_event_correlation_engine import (
                SecurityEventCorrelationEngine,
            )
            sec_engine = SecurityEventCorrelationEngine()
            for m in matches:
                try:
                    sec_engine.on_toxic_combo_matched(org_id, m)
                except Exception as exc:
                    _logger.warning(
                        "security_event_correlation on_toxic_combo_matched failed: %s",
                        exc,
                    )
        except Exception:
            pass

        return matches

    def list_toxic_combo_matches(
        self,
        org_id: str,
        combo_id: Optional[str] = None,
        entity_ref: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List toxic-combo matches, optionally filtered by combo_id/entity_ref."""
        sql = "SELECT * FROM toxic_combo_matches WHERE org_id = ?"
        params: list = [org_id]
        if combo_id:
            sql += " AND combo_id = ?"
            params.append(combo_id)
        if entity_ref:
            sql += " AND entity_ref = ?"
            params.append(entity_ref)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(int(limit))
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result: List[Dict[str, Any]] = []
        for row in rows:
            d = self._row(row)
            try:
                d["matched_attributes"] = json.loads(
                    d.get("matched_attributes_json") or "[]"
                )
            except Exception:
                d["matched_attributes"] = []
            d.pop("matched_attributes_json", None)
            result.append(d)
        return result

    def get_toxic_combo_match(
        self, org_id: str, match_id: str
    ) -> Optional[Dict[str, Any]]:
        """Return a single toxic-combo match by id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM toxic_combo_matches WHERE org_id = ? AND id = ?",
                (org_id, match_id),
            ).fetchone()
            if not row:
                return None
            d = self._row(row)
        try:
            d["matched_attributes"] = json.loads(d.get("matched_attributes_json") or "[]")
        except Exception:
            d["matched_attributes"] = []
        d.pop("matched_attributes_json", None)
        return d

    def set_match_attack_chain(
        self, org_id: str, match_id: str, chain_id: str
    ) -> bool:
        """Attach an attack_chain id to a toxic-combo match. Returns True on update."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE toxic_combo_matches
                       SET attack_chain_id = ?
                       WHERE org_id = ? AND id = ?""",
                    (chain_id, org_id, match_id),
                )
                return cur.rowcount > 0
