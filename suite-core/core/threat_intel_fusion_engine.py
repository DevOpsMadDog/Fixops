"""Threat Intelligence Fusion Engine — ALDECI.

Aggregates and fuses threat intelligence indicators from multiple sources,
computing consensus confidence scores across all contributing sources.

Capabilities:
  - Multi-source intel registry (osint/commercial/isac/internal/government)
  - Indicator lifecycle management with expiry
  - Multi-source fusion with consensus confidence computation
  - High-confidence indicator retrieval
  - Indicator search by value or type
  - Automatic expiry management
  - Per-org stats aggregation

Compliance: MITRE ATT&CK, STIX 2.1, TLP protocol, NIST SP 800-150
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SOURCE_TYPES = {"osint", "commercial", "isac", "internal", "government"}
_VALID_TLP_LEVELS = {"white", "green", "amber", "red"}
_VALID_INDICATOR_TYPES = {"ip", "domain", "hash", "url", "email"}
_VALID_STATUSES = {"active", "expired"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatIntelFusionEngine:
    """SQLite WAL-backed Threat Intelligence Fusion engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB files stored at .fixops_data/{org_id}_threat_intel_fusion.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path:
            self._db_dir = Path(db_path).parent
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
        return str(self._db_dir / f"{org_id}_threat_intel_fusion.db")

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS fusion_sources (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    source_type     TEXT NOT NULL DEFAULT 'osint',
                    reliability     INTEGER NOT NULL DEFAULT 5,
                    tlp_level       TEXT NOT NULL DEFAULT 'white',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fusion_sources_org
                    ON fusion_sources (org_id, enabled);

                CREATE TABLE IF NOT EXISTS fusion_indicators (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_id       TEXT NOT NULL DEFAULT '',
                    indicator_type  TEXT NOT NULL DEFAULT 'ip',
                    value           TEXT NOT NULL,
                    confidence      INTEGER NOT NULL DEFAULT 50,
                    tags            TEXT NOT NULL DEFAULT '[]',
                    expiry_date     TEXT,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fusion_indicators_org_type
                    ON fusion_indicators (org_id, indicator_type, status);

                CREATE INDEX IF NOT EXISTS idx_fusion_indicators_org_value
                    ON fusion_indicators (org_id, value);

                CREATE INDEX IF NOT EXISTS idx_fusion_indicators_org_conf
                    ON fusion_indicators (org_id, confidence, status);
            """)

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("tags",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Intel Sources
    # ------------------------------------------------------------------

    def add_intel_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new threat intelligence source."""
        self._ensure_db(org_id)

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        source_type = data.get("source_type", "osint")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"Invalid source_type '{source_type}'. Must be one of {_VALID_SOURCE_TYPES}")

        tlp_level = data.get("tlp_level", "white")
        if tlp_level not in _VALID_TLP_LEVELS:
            raise ValueError(f"Invalid tlp_level '{tlp_level}'. Must be one of {_VALID_TLP_LEVELS}")

        reliability = int(data.get("reliability", 5))
        reliability = max(1, min(10, reliability))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "source_type": source_type,
            "reliability": reliability,
            "tlp_level": tlp_level,
            "enabled": 1,
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO fusion_sources
                       (id, org_id, name, source_type, reliability, tlp_level, enabled, created_at)
                       VALUES (:id, :org_id, :name, :source_type, :reliability, :tlp_level, :enabled, :created_at)""",
                    record,
                )
        record["enabled"] = True
        return record

    def list_intel_sources(self, org_id: str) -> List[Dict[str, Any]]:
        """List all intel sources for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM fusion_sources WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def ingest_indicator(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a threat indicator from a source."""
        self._ensure_db(org_id)

        indicator_type = data.get("indicator_type", "ip")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator_type '{indicator_type}'. Must be one of {_VALID_INDICATOR_TYPES}")

        value = (data.get("value") or "").strip()
        if not value:
            raise ValueError("value is required.")

        confidence = int(data.get("confidence", 50))
        confidence = max(0, min(100, confidence))

        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = []

        expiry_days = int(data.get("expiry_days", 30))
        now_dt = datetime.now(timezone.utc)
        expiry_date = (now_dt + timedelta(days=expiry_days)).isoformat()

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_id": str(data.get("source_id", "")),
            "indicator_type": indicator_type,
            "value": value,
            "confidence": confidence,
            "tags": json.dumps(tags),
            "expiry_date": expiry_date,
            "status": "active",
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO fusion_indicators
                       (id, org_id, source_id, indicator_type, value, confidence,
                        tags, expiry_date, status, created_at)
                       VALUES (:id, :org_id, :source_id, :indicator_type, :value, :confidence,
                               :tags, :expiry_date, :status, :created_at)""",
                    record,
                )
        record["tags"] = tags
        return record

    def search_indicators(
        self,
        org_id: str,
        query: str,
        indicator_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search indicators by value substring, optionally filtered by type."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM fusion_indicators WHERE org_id = ? AND value LIKE ?"
        params: list = [org_id, f"%{query}%"]
        if indicator_type:
            sql += " AND indicator_type = ?"
            params.append(indicator_type)
        sql += " ORDER BY confidence DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def fuse_indicator(self, org_id: str, indicator_value: str) -> Dict[str, Any]:
        """Aggregate all records for an indicator value, return consensus confidence."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            records = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM fusion_indicators WHERE org_id = ? AND value = ?",
                    (org_id, indicator_value),
                ).fetchall()
            ]

        if not records:
            return {
                "indicator_value": indicator_value,
                "found": False,
                "consensus_confidence": 0,
                "source_count": 0,
                "records": [],
            }

        confidences = [r["confidence"] for r in records]
        # Consensus: weighted average, capped at 100
        consensus_confidence = min(100, round(sum(confidences) / len(confidences)))

        # Collect unique types
        types_seen = list({r["indicator_type"] for r in records})

        return {
            "indicator_value": indicator_value,
            "found": True,
            "consensus_confidence": consensus_confidence,
            "source_count": len(records),
            "indicator_types": types_seen,
            "records": records,
        }

    def get_high_confidence_indicators(
        self,
        org_id: str,
        min_confidence: int = 80,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Return active indicators meeting the minimum confidence threshold."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    """SELECT * FROM fusion_indicators
                       WHERE org_id = ? AND confidence >= ? AND status = 'active'
                       ORDER BY confidence DESC
                       LIMIT ?""",
                    (org_id, min_confidence, limit),
                ).fetchall()
            ]

    def expire_old_indicators(self, org_id: str) -> Dict[str, Any]:
        """Mark indicators past their expiry_date as expired."""
        self._ensure_db(org_id)
        now = _now_iso()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cursor = conn.execute(
                    """UPDATE fusion_indicators
                       SET status = 'expired'
                       WHERE org_id = ? AND status = 'active' AND expiry_date IS NOT NULL
                         AND expiry_date < ?""",
                    (org_id, now),
                )
                expired_count = cursor.rowcount
        return {
            "org_id": org_id,
            "expired": expired_count,
            "timestamp": now,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_fusion_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated fusion statistics for an org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            sources = conn.execute(
                "SELECT COUNT(*) FROM fusion_sources WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            total = conn.execute(
                "SELECT COUNT(*) FROM fusion_indicators WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            high_conf = conn.execute(
                "SELECT COUNT(*) FROM fusion_indicators WHERE org_id = ? AND confidence >= 80 AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM fusion_indicators WHERE org_id = ? AND status = 'expired'",
                (org_id,),
            ).fetchone()[0]

            # Count by type
            by_type_rows = conn.execute(
                """SELECT indicator_type, COUNT(*) as cnt
                   FROM fusion_indicators
                   WHERE org_id = ?
                   GROUP BY indicator_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["indicator_type"]: r["cnt"] for r in by_type_rows}

        return {
            "org_id": org_id,
            "sources": sources,
            "total_indicators": total,
            "high_confidence": high_conf,
            "expired": expired,
            "by_type": by_type,
        }
