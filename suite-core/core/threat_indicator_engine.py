"""Threat Indicator Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

IOC lifecycle management with enrichment pipeline and TTL:
  - Indicator creation with confidence clamping and JSON tags
  - Enrichment pipeline tracking
  - Sighting recording with counter increment
  - False positive and expiry management
  - Active/expired queries with TTL awareness
  - LIKE-based value search
  - Aggregated summary with expiring-soon detection

Compliance: STIX 2.1, MISP, OpenIOC
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
    Path(__file__).resolve().parents[2]
    / ".fixops_data"
    / "threat_indicator_engine.db"
)

_VALID_INDICATOR_TYPES = {
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
    "email", "registry_key", "mutex", "user_agent", "certificate",
}
_VALID_TLP = {"white", "green", "amber", "red"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _soon_iso() -> str:
    """ISO timestamp 7 days from now."""
    return (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()


class ThreatIndicatorEngine:
    """SQLite WAL-backed Threat Indicator (IOC) engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_indicator_engine.db
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
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    indicator_value TEXT NOT NULL DEFAULT '',
                    indicator_type  TEXT NOT NULL DEFAULT 'ip',
                    source          TEXT NOT NULL DEFAULT '',
                    confidence      REAL NOT NULL DEFAULT 0.5,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    tlp             TEXT NOT NULL DEFAULT 'amber',
                    tags            TEXT NOT NULL DEFAULT '[]',
                    first_seen      TEXT,
                    last_seen       TEXT,
                    expiry_at       TEXT,
                    active          INTEGER NOT NULL DEFAULT 1,
                    false_positive  INTEGER NOT NULL DEFAULT 0,
                    sighting_count  INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ti_indicators_org
                    ON threat_indicators (org_id, indicator_type, severity, active);

                CREATE TABLE IF NOT EXISTS indicator_enrichments (
                    id                TEXT PRIMARY KEY,
                    indicator_id      TEXT NOT NULL,
                    org_id            TEXT NOT NULL,
                    enrichment_source TEXT NOT NULL DEFAULT '',
                    enrichment_data   TEXT NOT NULL DEFAULT '{}',
                    enriched_at       TEXT,
                    created_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ti_enrichments_org
                    ON indicator_enrichments (org_id, indicator_id);

                CREATE TABLE IF NOT EXISTS indicator_sightings (
                    id            TEXT PRIMARY KEY,
                    indicator_id  TEXT NOT NULL,
                    org_id        TEXT NOT NULL,
                    sighted_at    TEXT,
                    source_system TEXT NOT NULL DEFAULT '',
                    context       TEXT NOT NULL DEFAULT '',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    created_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_ti_sightings_org
                    ON indicator_sightings (org_id, indicator_id);
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
    # Indicators
    # ------------------------------------------------------------------

    def add_indicator(
        self,
        org_id: str,
        indicator_value: str,
        indicator_type: str,
        source: str = "",
        confidence: float = 0.5,
        severity: str = "medium",
        tlp: str = "amber",
        tags: Optional[List[str]] = None,
        expiry_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a new threat indicator (IOC)."""
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type '{indicator_type}'. "
                f"Must be one of {sorted(_VALID_INDICATOR_TYPES)}"
            )
        if tlp not in _VALID_TLP:
            raise ValueError(
                f"Invalid tlp '{tlp}'. Must be one of {sorted(_VALID_TLP)}"
            )
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        # Clamp confidence to [0.0, 1.0]
        confidence = max(0.0, min(1.0, float(confidence)))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "indicator_value": indicator_value,
            "indicator_type": indicator_type,
            "source": source,
            "confidence": confidence,
            "severity": severity,
            "tlp": tlp,
            "tags": json.dumps(tags or []),
            "first_seen": now,
            "last_seen": now,
            "expiry_at": expiry_at,
            "active": 1,
            "false_positive": 0,
            "sighting_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO threat_indicators
                       (id, org_id, indicator_value, indicator_type, source, confidence,
                        severity, tlp, tags, first_seen, last_seen, expiry_at, active,
                        false_positive, sighting_count, created_at)
                       VALUES (:id, :org_id, :indicator_value, :indicator_type, :source,
                               :confidence, :severity, :tlp, :tags, :first_seen,
                               :last_seen, :expiry_at, :active, :false_positive,
                               :sighting_count, :created_at)""",
                    record,
                )
        return record

    def get_indicator(
        self, indicator_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get indicator with its enrichments and sightings."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_indicators WHERE id = ? AND org_id = ?",
                (indicator_id, org_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            enrichments = conn.execute(
                "SELECT * FROM indicator_enrichments WHERE indicator_id = ? AND org_id = ? ORDER BY created_at",
                (indicator_id, org_id),
            ).fetchall()
            sightings = conn.execute(
                "SELECT * FROM indicator_sightings WHERE indicator_id = ? AND org_id = ? ORDER BY sighted_at DESC",
                (indicator_id, org_id),
            ).fetchall()
        result["enrichments"] = [self._row(e) for e in enrichments]
        result["sightings"] = [self._row(s) for s in sightings]
        return result

    def get_active_indicators(
        self,
        org_id: str,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return active indicators not yet expired."""
        now = _now_iso()
        sql = (
            "SELECT * FROM threat_indicators WHERE org_id = ? AND active = 1 "
            "AND (expiry_at IS NULL OR expiry_at > ?)"
        )
        params: List[Any] = [org_id, now]
        if indicator_type:
            sql += " AND indicator_type = ?"
            params.append(indicator_type)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_expired_indicators(self, org_id: str) -> List[Dict[str, Any]]:
        """Return indicators that are active but past their expiry_at timestamp."""
        now = _now_iso()
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM threat_indicators
                   WHERE org_id = ? AND active = 1
                     AND expiry_at IS NOT NULL AND expiry_at < ?
                   ORDER BY expiry_at""",
                (org_id, now),
            ).fetchall()
        return [self._row(r) for r in rows]

    def search_indicators(self, org_id: str, query: str) -> List[Dict[str, Any]]:
        """LIKE search on indicator_value."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM threat_indicators
                   WHERE org_id = ? AND indicator_value LIKE ?
                   ORDER BY created_at DESC""",
                (org_id, f"%{query}%"),
            ).fetchall()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_indicator", "org_id": org_id, "source_engine": "threat_indicator"})
            except Exception:
                pass

        return [self._row(r) for r in rows]

    def mark_false_positive(
        self, indicator_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Mark an indicator as a false positive and deactivate it."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """UPDATE threat_indicators
                       SET false_positive = 1, active = 0
                       WHERE id = ? AND org_id = ?""",
                    (indicator_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM threat_indicators WHERE id = ? AND org_id = ?",
                    (indicator_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def expire_indicator(
        self, indicator_id: str, org_id: str
    ) -> Optional[Dict[str, Any]]:
        """Manually expire (deactivate) an indicator."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE threat_indicators SET active = 0 WHERE id = ? AND org_id = ?",
                    (indicator_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM threat_indicators WHERE id = ? AND org_id = ?",
                    (indicator_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated indicator summary for the org."""
        now = _now_iso()
        soon = _soon_iso()
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM threat_indicators WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_count = conn.execute(
                "SELECT COUNT(*) FROM threat_indicators WHERE org_id = ? AND active = 1",
                (org_id,),
            ).fetchone()[0]

            fp_count = conn.execute(
                "SELECT COUNT(*) FROM threat_indicators WHERE org_id = ? AND false_positive = 1",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT indicator_type, COUNT(*) as cnt FROM threat_indicators WHERE org_id = ? GROUP BY indicator_type",
                (org_id,),
            ).fetchall()
            by_type = {r["indicator_type"]: r["cnt"] for r in type_rows}

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM threat_indicators WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            high_conf = conn.execute(
                "SELECT COUNT(*) FROM threat_indicators WHERE org_id = ? AND confidence > 0.8",
                (org_id,),
            ).fetchone()[0]

            expiring_soon = conn.execute(
                """SELECT COUNT(*) FROM threat_indicators
                   WHERE org_id = ? AND active = 1
                     AND expiry_at IS NOT NULL AND expiry_at > ? AND expiry_at <= ?""",
                (org_id, now, soon),
            ).fetchone()[0]

        return {
            "total": total,
            "active_count": active_count,
            "false_positive_count": fp_count,
            "by_type": by_type,
            "by_severity": by_severity,
            "high_confidence_count": high_conf,
            "expiring_soon": expiring_soon,
        }

    # ------------------------------------------------------------------
    # Enrichments
    # ------------------------------------------------------------------

    def enrich_indicator(
        self,
        indicator_id: str,
        org_id: str,
        enrichment_source: str,
        enrichment_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add enrichment data for an indicator and update last_seen."""
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "indicator_id": indicator_id,
            "org_id": org_id,
            "enrichment_source": enrichment_source,
            "enrichment_data": json.dumps(enrichment_data or {}),
            "enriched_at": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO indicator_enrichments
                       (id, indicator_id, org_id, enrichment_source, enrichment_data,
                        enriched_at, created_at)
                       VALUES (:id, :indicator_id, :org_id, :enrichment_source,
                               :enrichment_data, :enriched_at, :created_at)""",
                    record,
                )
                conn.execute(
                    "UPDATE threat_indicators SET last_seen = ? WHERE id = ? AND org_id = ?",
                    (now, indicator_id, org_id),
                )
        return record

    # ------------------------------------------------------------------
    # Sightings
    # ------------------------------------------------------------------

    def record_sighting(
        self,
        indicator_id: str,
        org_id: str,
        source_system: str = "",
        context: str = "",
        severity: str = "medium",
    ) -> Dict[str, Any]:
        """Record a sighting of an indicator and increment sighting_count."""
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{severity}'. Must be one of {sorted(_VALID_SEVERITIES)}"
            )
        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "indicator_id": indicator_id,
            "org_id": org_id,
            "sighted_at": now,
            "source_system": source_system,
            "context": context,
            "severity": severity,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO indicator_sightings
                       (id, indicator_id, org_id, sighted_at, source_system,
                        context, severity, created_at)
                       VALUES (:id, :indicator_id, :org_id, :sighted_at, :source_system,
                               :context, :severity, :created_at)""",
                    record,
                )
                conn.execute(
                    """UPDATE threat_indicators
                       SET sighting_count = sighting_count + 1, last_seen = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, indicator_id, org_id),
                )
        return record
