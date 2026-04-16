"""Threat Intelligence Platform (TIP) Engine — ALDECI.

Aggregates and correlates intelligence from all threat sources.

Capabilities:
  - Multi-source intel source registry (commercial/OSINT/ISAC/internal/government/partner)
  - IOC/indicator lifecycle management with deduplication
  - Relationship graph between indicators
  - Intel report generation and management
  - Quick indicator lookup (check_indicator)
  - Bulk ingestion with duplicate detection
  - Indicator expiry management
  - Stats aggregation per org

Compliance: MITRE ATT&CK, STIX 2.1, TLP protocol, NIST SP 800-150
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

_VALID_SOURCE_TYPES = {"commercial", "osint", "isac", "internal", "government", "partner"}
_VALID_SOURCE_STATUSES = {"active", "inactive", "error"}
_VALID_INDICATOR_TYPES = {
    "ip", "domain", "url", "file_hash", "email", "asn", "cidr",
    "cve", "mutex", "registry_key",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_THREAT_CATEGORIES = {
    "malware", "ransomware", "apt", "phishing", "c2",
    "scanner", "botnet", "exploit",
}
_VALID_TLP_LEVELS = {"red", "amber", "green", "white"}
_VALID_RELATIONSHIP_TYPES = {
    "resolves_to", "hosted_on", "used_by", "distributes",
    "communicates_with", "drops",
}
_VALID_REPORT_TYPES = {"flash", "strategic", "tactical", "vulnerability"}
_VALID_CLASSIFICATIONS = {"secret", "confidential", "internal", "public"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatIntelPlatformEngine:
    """SQLite WAL-backed Threat Intelligence Platform engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own database file at .fixops_data/{org_id}_tip.db
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}
        self._lock_lock = threading.Lock()

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._lock_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        return str(self._db_dir / f"{org_id}_tip.db")

    def _conn(self, org_id: str) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(org_id), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS intel_sources (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    source_name             TEXT NOT NULL,
                    source_type             TEXT NOT NULL DEFAULT 'osint',
                    feed_url                TEXT NOT NULL DEFAULT '',
                    api_key_masked          TEXT NOT NULL DEFAULT '',
                    status                  TEXT NOT NULL DEFAULT 'active',
                    reliability_score       REAL NOT NULL DEFAULT 0.5,
                    update_frequency_hours  INTEGER NOT NULL DEFAULT 24,
                    last_updated            DATETIME,
                    total_indicators        INTEGER NOT NULL DEFAULT 0,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sources_org_status
                    ON intel_sources (org_id, status);

                CREATE TABLE IF NOT EXISTS intel_indicators (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    source_id           TEXT NOT NULL DEFAULT '',
                    indicator_type      TEXT NOT NULL,
                    value               TEXT NOT NULL,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    confidence          REAL NOT NULL DEFAULT 0.5,
                    threat_category     TEXT NOT NULL DEFAULT 'malware',
                    tags                TEXT NOT NULL DEFAULT '[]',
                    first_seen          DATETIME NOT NULL,
                    last_seen           DATETIME NOT NULL,
                    expiry_date         DATETIME,
                    active              INTEGER NOT NULL DEFAULT 1,
                    tlp_level           TEXT NOT NULL DEFAULT 'amber',
                    hit_count           INTEGER NOT NULL DEFAULT 0,
                    mitre_techniques    TEXT NOT NULL DEFAULT '[]',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_indicators_org_type
                    ON intel_indicators (org_id, indicator_type, active);

                CREATE INDEX IF NOT EXISTS idx_indicators_org_value
                    ON intel_indicators (org_id, value, indicator_type);

                CREATE INDEX IF NOT EXISTS idx_indicators_org_category
                    ON intel_indicators (org_id, threat_category);

                CREATE TABLE IF NOT EXISTS intel_relationships (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    indicator_a_id      TEXT NOT NULL,
                    indicator_b_id      TEXT NOT NULL,
                    relationship_type   TEXT NOT NULL DEFAULT 'communicates_with',
                    confidence          REAL NOT NULL DEFAULT 0.5,
                    source_id           TEXT NOT NULL DEFAULT '',
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_relationships_org_a
                    ON intel_relationships (org_id, indicator_a_id);

                CREATE INDEX IF NOT EXISTS idx_relationships_org_b
                    ON intel_relationships (org_id, indicator_b_id);

                CREATE TABLE IF NOT EXISTS intel_reports (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    report_name         TEXT NOT NULL,
                    report_type         TEXT NOT NULL DEFAULT 'tactical',
                    classification      TEXT NOT NULL DEFAULT 'internal',
                    tlp_level           TEXT NOT NULL DEFAULT 'amber',
                    summary             TEXT NOT NULL DEFAULT '',
                    ioc_count           INTEGER NOT NULL DEFAULT 0,
                    threat_actors       TEXT NOT NULL DEFAULT '[]',
                    affected_sectors    TEXT NOT NULL DEFAULT '[]',
                    source_ids          TEXT NOT NULL DEFAULT '[]',
                    published_date      DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reports_org_type
                    ON intel_reports (org_id, report_type);
            """)

    def _ensure_db(self, org_id: str) -> None:
        """Ensure DB exists and is initialized for this org."""
        db_path = Path(self._db_path(org_id))
        if not db_path.exists():
            self._init_db(org_id)
        else:
            # Ensure tables exist (idempotent)
            self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialize JSON fields
        for field in ("tags", "mitre_techniques", "threat_actors", "affected_sectors", "source_ids", "target_scope"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Convert active int to bool
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def add_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new intel source."""
        self._ensure_db(org_id)
        source_name = (data.get("source_name") or "").strip()
        if not source_name:
            raise ValueError("source_name is required.")

        source_type = data.get("source_type", "osint")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(f"Invalid source_type: {source_type}. Must be one of {_VALID_SOURCE_TYPES}")

        reliability = float(data.get("reliability_score", 0.5))
        reliability = max(0.0, min(1.0, reliability))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_name": source_name,
            "source_type": source_type,
            "feed_url": data.get("feed_url", ""),
            "api_key_masked": data.get("api_key_masked", ""),
            "status": data.get("status", "active"),
            "reliability_score": reliability,
            "update_frequency_hours": int(data.get("update_frequency_hours", 24)),
            "last_updated": data.get("last_updated"),
            "total_indicators": int(data.get("total_indicators", 0)),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO intel_sources
                       (id, org_id, source_name, source_type, feed_url, api_key_masked,
                        status, reliability_score, update_frequency_hours, last_updated,
                        total_indicators, created_at)
                       VALUES (:id, :org_id, :source_name, :source_type, :feed_url,
                               :api_key_masked, :status, :reliability_score,
                               :update_frequency_hours, :last_updated, :total_indicators,
                               :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_intel_platform", "org_id": org_id, "source_engine": "threat_intel_platform"})
            except Exception:
                pass

        return record

    def list_sources(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List intel sources, optionally filtered by status."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM intel_sources WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def add_indicator(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IOC/indicator, checking for duplicates by value+type."""
        self._ensure_db(org_id)
        indicator_type = data.get("indicator_type", "ip")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(f"Invalid indicator_type: {indicator_type}.")

        value = (data.get("value") or "").strip()
        if not value:
            raise ValueError("value is required.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}.")

        threat_category = data.get("threat_category", "malware")
        if threat_category not in _VALID_THREAT_CATEGORIES:
            raise ValueError(f"Invalid threat_category: {threat_category}.")

        tlp_level = data.get("tlp_level", "amber")
        if tlp_level not in _VALID_TLP_LEVELS:
            raise ValueError(f"Invalid tlp_level: {tlp_level}.")

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        now = _now_iso()

        with self._get_lock(org_id):
            # Check for duplicate
            with self._conn(org_id) as conn:
                existing = conn.execute(
                    "SELECT * FROM intel_indicators WHERE org_id = ? AND value = ? AND indicator_type = ?",
                    (org_id, value, indicator_type),
                ).fetchone()
                if existing:
                    # Update last_seen and hit_count
                    conn.execute(
                        "UPDATE intel_indicators SET last_seen = ?, hit_count = hit_count + 1 WHERE id = ?",
                        (now, existing["id"]),
                    )
                    result = self._row(existing)
                    result["_duplicate"] = True
                    return result

            record = {
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "source_id": data.get("source_id", ""),
                "indicator_type": indicator_type,
                "value": value,
                "severity": severity,
                "confidence": confidence,
                "threat_category": threat_category,
                "tags": json.dumps(data.get("tags", [])),
                "first_seen": data.get("first_seen", now),
                "last_seen": data.get("last_seen", now),
                "expiry_date": data.get("expiry_date"),
                "active": 1,
                "tlp_level": tlp_level,
                "hit_count": int(data.get("hit_count", 0)),
                "mitre_techniques": json.dumps(data.get("mitre_techniques", [])),
                "created_at": now,
            }
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO intel_indicators
                       (id, org_id, source_id, indicator_type, value, severity, confidence,
                        threat_category, tags, first_seen, last_seen, expiry_date, active,
                        tlp_level, hit_count, mitre_techniques, created_at)
                       VALUES (:id, :org_id, :source_id, :indicator_type, :value, :severity,
                               :confidence, :threat_category, :tags, :first_seen, :last_seen,
                               :expiry_date, :active, :tlp_level, :hit_count,
                               :mitre_techniques, :created_at)""",
                    record,
                )
        result = dict(record)
        result["tags"] = json.loads(record["tags"])
        result["mitre_techniques"] = json.loads(record["mitre_techniques"])
        result["active"] = True
        return result

    def search_indicators(
        self,
        org_id: str,
        query: str,
        indicator_type: Optional[str] = None,
        threat_category: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Full-text search on value + tags."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM intel_indicators WHERE org_id = ? AND (value LIKE ? OR tags LIKE ?)"
        pattern = f"%{query}%"
        params: list = [org_id, pattern, pattern]
        if indicator_type:
            sql += " AND indicator_type = ?"
            params.append(indicator_type)
        if threat_category:
            sql += " AND threat_category = ?"
            params.append(threat_category)
        sql += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_indicator(self, org_id: str, indicator_id: str) -> Optional[Dict[str, Any]]:
        """Get a single indicator with its relationships."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM intel_indicators WHERE org_id = ? AND id = ?",
                (org_id, indicator_id),
            ).fetchone()
            if not row:
                return None
            result = self._row(row)
            rels = conn.execute(
                """SELECT * FROM intel_relationships
                   WHERE org_id = ? AND (indicator_a_id = ? OR indicator_b_id = ?)""",
                (org_id, indicator_id, indicator_id),
            ).fetchall()
            result["relationships"] = [self._row(r) for r in rels]
        return result

    def bulk_ingest(
        self,
        org_id: str,
        source_id: str,
        indicators_list: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Batch add indicators. Returns {added, duplicates, errors}."""
        self._ensure_db(org_id)
        added = 0
        duplicates = 0
        errors = 0
        for item in indicators_list:
            try:
                item["source_id"] = source_id
                result = self.add_indicator(org_id, item)
                if result.get("_duplicate"):
                    duplicates += 1
                else:
                    added += 1
            except Exception as exc:
                _logger.warning("bulk_ingest error for item %s: %s", item, exc)
                errors += 1

        # Update source total_indicators count
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    "UPDATE intel_sources SET total_indicators = total_indicators + ?, last_updated = ? WHERE org_id = ? AND id = ?",
                    (added, _now_iso(), org_id, source_id),
                )
        return {"added": added, "duplicates": duplicates, "errors": errors}

    def add_relationship(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a relationship between two indicators."""
        self._ensure_db(org_id)
        rel_type = data.get("relationship_type", "communicates_with")
        if rel_type not in _VALID_RELATIONSHIP_TYPES:
            raise ValueError(f"Invalid relationship_type: {rel_type}.")

        indicator_a_id = (data.get("indicator_a_id") or "").strip()
        indicator_b_id = (data.get("indicator_b_id") or "").strip()
        if not indicator_a_id or not indicator_b_id:
            raise ValueError("indicator_a_id and indicator_b_id are required.")

        confidence = float(data.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "indicator_a_id": indicator_a_id,
            "indicator_b_id": indicator_b_id,
            "relationship_type": rel_type,
            "confidence": confidence,
            "source_id": data.get("source_id", ""),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO intel_relationships
                       (id, org_id, indicator_a_id, indicator_b_id, relationship_type,
                        confidence, source_id, created_at)
                       VALUES (:id, :org_id, :indicator_a_id, :indicator_b_id,
                               :relationship_type, :confidence, :source_id, :created_at)""",
                    record,
                )
        return record

    def get_relationships(self, org_id: str, indicator_id: str) -> List[Dict[str, Any]]:
        """Get all relationships for an indicator."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                """SELECT * FROM intel_relationships
                   WHERE org_id = ? AND (indicator_a_id = ? OR indicator_b_id = ?)
                   ORDER BY created_at DESC""",
                (org_id, indicator_id, indicator_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def create_report(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an intel report."""
        self._ensure_db(org_id)
        report_name = (data.get("report_name") or "").strip()
        if not report_name:
            raise ValueError("report_name is required.")

        report_type = data.get("report_type", "tactical")
        if report_type not in _VALID_REPORT_TYPES:
            raise ValueError(f"Invalid report_type: {report_type}.")

        classification = data.get("classification", "internal")
        if classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(f"Invalid classification: {classification}.")

        tlp_level = data.get("tlp_level", "amber")
        if tlp_level not in _VALID_TLP_LEVELS:
            raise ValueError(f"Invalid tlp_level: {tlp_level}.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "report_name": report_name,
            "report_type": report_type,
            "classification": classification,
            "tlp_level": tlp_level,
            "summary": data.get("summary", ""),
            "ioc_count": int(data.get("ioc_count", 0)),
            "threat_actors": json.dumps(data.get("threat_actors", [])),
            "affected_sectors": json.dumps(data.get("affected_sectors", [])),
            "source_ids": json.dumps(data.get("source_ids", [])),
            "published_date": data.get("published_date"),
            "created_at": now,
        }
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO intel_reports
                       (id, org_id, report_name, report_type, classification, tlp_level,
                        summary, ioc_count, threat_actors, affected_sectors, source_ids,
                        published_date, created_at)
                       VALUES (:id, :org_id, :report_name, :report_type, :classification,
                               :tlp_level, :summary, :ioc_count, :threat_actors,
                               :affected_sectors, :source_ids, :published_date, :created_at)""",
                    record,
                )
        result = dict(record)
        result["threat_actors"] = json.loads(record["threat_actors"])
        result["affected_sectors"] = json.loads(record["affected_sectors"])
        result["source_ids"] = json.loads(record["source_ids"])
        return result

    def list_reports(
        self,
        org_id: str,
        report_type: Optional[str] = None,
        tlp_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List intel reports with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM intel_reports WHERE org_id = ?"
        params: list = [org_id]
        if report_type:
            sql += " AND report_type = ?"
            params.append(report_type)
        if tlp_level:
            sql += " AND tlp_level = ?"
            params.append(tlp_level)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Quick lookup
    # ------------------------------------------------------------------

    def check_indicator(
        self,
        org_id: str,
        value: str,
        indicator_type: str,
    ) -> Dict[str, Any]:
        """Quick lookup: is this IP/domain/hash known bad?"""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                """SELECT * FROM intel_indicators
                   WHERE org_id = ? AND value = ? AND indicator_type = ? AND active = 1
                   ORDER BY severity DESC, confidence DESC LIMIT 1""",
                (org_id, value, indicator_type),
            ).fetchone()
        if row:
            result = self._row(row)
            # Bump hit count
            with self._get_lock(org_id):
                with self._conn(org_id) as conn:
                    conn.execute(
                        "UPDATE intel_indicators SET hit_count = hit_count + 1, last_seen = ? WHERE id = ?",
                        (_now_iso(), result["id"]),
                    )
            return {"known_bad": True, "indicator": result}
        return {"known_bad": False, "indicator": None}

    def expire_indicators(self, org_id: str) -> int:
        """Mark expired indicators as active=false. Returns count expired."""
        self._ensure_db(org_id)
        now = _now_iso()
        with self._get_lock(org_id):
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE intel_indicators
                       SET active = 0
                       WHERE org_id = ? AND active = 1 AND expiry_date IS NOT NULL AND expiry_date < ?""",
                    (org_id, now),
                )
                return cur.rowcount

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_tip_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated TIP stats for org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM intel_indicators WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM intel_indicators WHERE org_id = ? AND active = 1", (org_id,)
            ).fetchone()[0]
            sources_active = conn.execute(
                "SELECT COUNT(*) FROM intel_sources WHERE org_id = ? AND status = 'active'", (org_id,)
            ).fetchone()[0]
            reports_count = conn.execute(
                "SELECT COUNT(*) FROM intel_reports WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            relationships_count = conn.execute(
                "SELECT COUNT(*) FROM intel_relationships WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT indicator_type, COUNT(*) as cnt FROM intel_indicators WHERE org_id = ? GROUP BY indicator_type",
                (org_id,),
            ).fetchall()
            by_category_rows = conn.execute(
                "SELECT threat_category, COUNT(*) as cnt FROM intel_indicators WHERE org_id = ? GROUP BY threat_category",
                (org_id,),
            ).fetchall()
            by_severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM intel_indicators WHERE org_id = ? GROUP BY severity",
                (org_id,),
            ).fetchall()
            top_cat_rows = conn.execute(
                """SELECT threat_category, COUNT(*) as cnt
                   FROM intel_indicators WHERE org_id = ? AND active = 1
                   GROUP BY threat_category ORDER BY cnt DESC LIMIT 5""",
                (org_id,),
            ).fetchall()

        return {
            "total_indicators": total,
            "active_indicators": active,
            "sources_active": sources_active,
            "reports_count": reports_count,
            "relationships_count": relationships_count,
            "by_type": {r["indicator_type"]: r["cnt"] for r in by_type_rows},
            "by_category": {r["threat_category"]: r["cnt"] for r in by_category_rows},
            "by_severity": {r["severity"]: r["cnt"] for r in by_severity_rows},
            "top_threat_categories": [
                {"category": r["threat_category"], "count": r["cnt"]} for r in top_cat_rows
            ],
        }
