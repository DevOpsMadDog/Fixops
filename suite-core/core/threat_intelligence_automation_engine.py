"""Threat Intelligence Automation Engine — ALDECI.

Automates threat intelligence collection, enrichment, and response actions.

Capabilities:
  - Feed registry with SHA-256 API key hashing (OSINT/commercial/ISAC/government/dark_web/honeypot/internal)
  - Automation rule lifecycle (trigger/action/condition)
  - IOC enrichment store with confidence scoring
  - Multi-tenant org_id isolation
  - SQLite WAL + threading.RLock

Compliance: NIST SP 800-150, STIX 2.1, TLP protocol
"""

from __future__ import annotations

import hashlib
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

_VALID_FEED_TYPES = {"osint", "commercial", "isac", "government", "dark_web", "honeypot", "internal"}
_VALID_FORMATS = {"stix", "misp", "csv", "json", "xml", "taxii"}
_VALID_FEED_STATUSES = {"active", "inactive", "error"}
_VALID_TRIGGER_TYPES = {"new_ioc", "confidence_threshold", "feed_update", "scheduled", "manual"}
_VALID_ACTION_TYPES = {"block_ip", "alert", "enrich", "correlate", "notify", "update_watchlist", "create_ticket"}
_VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "asn", "cve"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ThreatIntelligenceAutomationEngine:
    """SQLite WAL-backed Threat Intelligence Automation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB at .fixops_data/threat_intelligence_automation.db (shared, org_id column).
    """

    def __init__(self, db_dir: Optional[str] = None) -> None:
        self._db_dir = Path(db_dir) if db_dir else _DEFAULT_DB_DIR
        self._db_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialized = False

    def _db_path(self) -> str:
        return str(self._db_dir / "threat_intelligence_automation.db")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path(), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tia_feeds (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    feed_name               TEXT NOT NULL,
                    feed_type               TEXT NOT NULL DEFAULT 'osint',
                    url                     TEXT NOT NULL DEFAULT '',
                    api_key_hash            TEXT NOT NULL DEFAULT '',
                    format                  TEXT NOT NULL DEFAULT 'json',
                    status                  TEXT NOT NULL DEFAULT 'active',
                    last_polled             DATETIME,
                    poll_interval_minutes   INTEGER NOT NULL DEFAULT 60,
                    ioc_count               INTEGER NOT NULL DEFAULT 0,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tia_feeds_org
                    ON tia_feeds (org_id, feed_type, status);

                CREATE TABLE IF NOT EXISTS tia_automations (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    automation_name     TEXT NOT NULL,
                    trigger_type        TEXT NOT NULL DEFAULT 'manual',
                    action_type         TEXT NOT NULL DEFAULT 'alert',
                    condition           TEXT NOT NULL DEFAULT '{}',
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    execution_count     INTEGER NOT NULL DEFAULT 0,
                    last_executed       DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tia_automations_org
                    ON tia_automations (org_id, trigger_type, enabled);

                CREATE TABLE IF NOT EXISTS tia_enrichments (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    ioc_value           TEXT NOT NULL,
                    ioc_type            TEXT NOT NULL DEFAULT 'ip',
                    sources             TEXT NOT NULL DEFAULT '[]',
                    confidence_score    REAL NOT NULL DEFAULT 0.0,
                    threat_categories   TEXT NOT NULL DEFAULT '[]',
                    is_malicious        INTEGER NOT NULL DEFAULT 0,
                    first_seen          DATETIME NOT NULL,
                    last_seen           DATETIME NOT NULL,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tia_enrichments_org_ioc
                    ON tia_enrichments (org_id, ioc_value);

                CREATE INDEX IF NOT EXISTS idx_tia_enrichments_org_type
                    ON tia_enrichments (org_id, ioc_type, is_malicious);
            """)

    def _ensure_db(self) -> None:
        if not self._initialized:
            with self._lock:
                if not self._initialized:
                    self._init_db()
                    self._initialized = True

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("sources", "threat_categories"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "condition" in d and isinstance(d["condition"], str):
            try:
                d["condition"] = json.loads(d["condition"])
            except (json.JSONDecodeError, TypeError):
                pass
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        if "is_malicious" in d:
            d["is_malicious"] = bool(d["is_malicious"])
        return d

    # ------------------------------------------------------------------
    # Feeds
    # ------------------------------------------------------------------

    def register_feed(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new threat intelligence feed."""
        self._ensure_db()
        feed_name = data.get("feed_name", "").strip()
        if not feed_name:
            raise ValueError("feed_name is required")

        feed_type = data.get("feed_type", "osint")
        if feed_type not in _VALID_FEED_TYPES:
            raise ValueError(f"feed_type must be one of {sorted(_VALID_FEED_TYPES)}")

        fmt = data.get("format", "json")
        if fmt not in _VALID_FORMATS:
            raise ValueError(f"format must be one of {sorted(_VALID_FORMATS)}")

        # Hash API key if provided, never store plaintext
        api_key = data.get("api_key", "")
        api_key_hash = _sha256(api_key) if api_key else ""

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "feed_name": feed_name,
            "feed_type": feed_type,
            "url": data.get("url", ""),
            "api_key_hash": api_key_hash,
            "format": fmt,
            "status": data.get("status", "active"),
            "last_polled": data.get("last_polled"),
            "poll_interval_minutes": int(data.get("poll_interval_minutes", 60)),
            "ioc_count": int(data.get("ioc_count", 0)),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tia_feeds
                       (id, org_id, feed_name, feed_type, url, api_key_hash, format,
                        status, last_polled, poll_interval_minutes, ioc_count, created_at)
                       VALUES (:id,:org_id,:feed_name,:feed_type,:url,:api_key_hash,:format,
                               :status,:last_polled,:poll_interval_minutes,:ioc_count,:created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_intelligence_automation", "org_id": org_id, "source_engine": "threat_intelligence_automation"})
            except Exception:
                pass

        return record

    def list_feeds(
        self,
        org_id: str,
        feed_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List feeds for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM tia_feeds WHERE org_id = ?"
        params: list = [org_id]
        if feed_type:
            query += " AND feed_type = ?"
            params.append(feed_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_feed_stats(
        self,
        org_id: str,
        feed_id: str,
        ioc_count_delta: int,
        last_polled: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Increment ioc_count by delta and optionally update last_polled."""
        self._ensure_db()
        lp = last_polled or _now_iso()
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "SELECT id FROM tia_feeds WHERE id = ? AND org_id = ?",
                    (feed_id, org_id),
                ).fetchone()
                if not result:
                    raise KeyError(f"Feed {feed_id!r} not found for org {org_id!r}")
                conn.execute(
                    """UPDATE tia_feeds
                       SET ioc_count = ioc_count + ?, last_polled = ?
                       WHERE id = ? AND org_id = ?""",
                    (ioc_count_delta, lp, feed_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM tia_feeds WHERE id = ?", (feed_id,)
                ).fetchone()
        return dict(row)

    # ------------------------------------------------------------------
    # Automations
    # ------------------------------------------------------------------

    def create_automation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an automation rule."""
        self._ensure_db()
        automation_name = data.get("automation_name", "").strip()
        if not automation_name:
            raise ValueError("automation_name is required")

        trigger_type = data.get("trigger_type", "manual")
        if trigger_type not in _VALID_TRIGGER_TYPES:
            raise ValueError(f"trigger_type must be one of {sorted(_VALID_TRIGGER_TYPES)}")

        action_type = data.get("action_type", "alert")
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(f"action_type must be one of {sorted(_VALID_ACTION_TYPES)}")

        condition = data.get("condition", {})
        if isinstance(condition, dict):
            condition_json = json.dumps(condition)
        else:
            condition_json = str(condition)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "automation_name": automation_name,
            "trigger_type": trigger_type,
            "action_type": action_type,
            "condition": condition_json,
            "enabled": 1 if data.get("enabled", True) else 0,
            "execution_count": int(data.get("execution_count", 0)),
            "last_executed": data.get("last_executed"),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tia_automations
                       (id, org_id, automation_name, trigger_type, action_type, condition,
                        enabled, execution_count, last_executed, created_at)
                       VALUES (:id,:org_id,:automation_name,:trigger_type,:action_type,:condition,
                               :enabled,:execution_count,:last_executed,:created_at)""",
                    record,
                )
        record["enabled"] = bool(record["enabled"])
        record["condition"] = condition
        return record

    def execute_automation(self, org_id: str, automation_id: str) -> Dict[str, Any]:
        """Increment execution_count and update last_executed."""
        self._ensure_db()
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "SELECT id FROM tia_automations WHERE id = ? AND org_id = ?",
                    (automation_id, org_id),
                ).fetchone()
                if not result:
                    raise KeyError(f"Automation {automation_id!r} not found for org {org_id!r}")
                conn.execute(
                    """UPDATE tia_automations
                       SET execution_count = execution_count + 1, last_executed = ?
                       WHERE id = ? AND org_id = ?""",
                    (now, automation_id, org_id),
                )
                row = conn.execute(
                    "SELECT * FROM tia_automations WHERE id = ?", (automation_id,)
                ).fetchone()
        return self._row(row)

    def list_automations(
        self,
        org_id: str,
        trigger_type: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List automations for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM tia_automations WHERE org_id = ?"
        params: list = [org_id]
        if trigger_type:
            query += " AND trigger_type = ?"
            params.append(trigger_type)
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Enrichments
    # ------------------------------------------------------------------

    def store_enrichment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Store an IOC enrichment record."""
        self._ensure_db()
        ioc_value = data.get("ioc_value", "").strip()
        if not ioc_value:
            raise ValueError("ioc_value is required")

        ioc_type = data.get("ioc_type", "ip")
        if ioc_type not in _VALID_IOC_TYPES:
            raise ValueError(f"ioc_type must be one of {sorted(_VALID_IOC_TYPES)}")

        # Clamp confidence 0-100
        confidence_score = min(100.0, max(0.0, float(data.get("confidence_score", 0.0))))

        sources = data.get("sources", [])
        if not isinstance(sources, list):
            sources = list(sources)

        threat_categories = data.get("threat_categories", [])
        if not isinstance(threat_categories, list):
            threat_categories = list(threat_categories)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "sources": json.dumps(sources),
            "confidence_score": confidence_score,
            "threat_categories": json.dumps(threat_categories),
            "is_malicious": 1 if data.get("is_malicious", False) else 0,
            "first_seen": data.get("first_seen", now),
            "last_seen": data.get("last_seen", now),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO tia_enrichments
                       (id, org_id, ioc_value, ioc_type, sources, confidence_score,
                        threat_categories, is_malicious, first_seen, last_seen, created_at)
                       VALUES (:id,:org_id,:ioc_value,:ioc_type,:sources,:confidence_score,
                               :threat_categories,:is_malicious,:first_seen,:last_seen,:created_at)""",
                    record,
                )
        record["sources"] = sources
        record["threat_categories"] = threat_categories
        record["is_malicious"] = bool(record["is_malicious"])
        return record

    def get_enrichment(self, org_id: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Return most recent enrichment for ioc_value in org, or None."""
        self._ensure_db()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """SELECT * FROM tia_enrichments
                       WHERE org_id = ? AND ioc_value = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (org_id, ioc_value),
                ).fetchone()
        if not row:
            return None
        return self._row(row)

    def list_enrichments(
        self,
        org_id: str,
        ioc_type: Optional[str] = None,
        is_malicious: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List enrichments for an org, optionally filtered."""
        self._ensure_db()
        query = "SELECT * FROM tia_enrichments WHERE org_id = ?"
        params: list = [org_id]
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
        if is_malicious is not None:
            query += " AND is_malicious = ?"
            params.append(1 if is_malicious else 0)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ti_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated stats for an org."""
        self._ensure_db()
        with self._lock:
            with self._conn() as conn:
                feeds_total = conn.execute(
                    "SELECT COUNT(*) FROM tia_feeds WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_feeds = conn.execute(
                    "SELECT COUNT(*) FROM tia_feeds WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]
                total_iocs = conn.execute(
                    "SELECT COALESCE(SUM(ioc_count),0) FROM tia_feeds WHERE org_id = ?",
                    (org_id,),
                ).fetchone()[0]
                total_automations = conn.execute(
                    "SELECT COUNT(*) FROM tia_automations WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active_automations = conn.execute(
                    "SELECT COUNT(*) FROM tia_automations WHERE org_id = ? AND enabled = 1",
                    (org_id,),
                ).fetchone()[0]
                total_enrichments = conn.execute(
                    "SELECT COUNT(*) FROM tia_enrichments WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                malicious_enrichments = conn.execute(
                    "SELECT COUNT(*) FROM tia_enrichments WHERE org_id = ? AND is_malicious = 1",
                    (org_id,),
                ).fetchone()[0]

                # By feed_type
                by_feed_type: Dict[str, int] = {}
                for row in conn.execute(
                    "SELECT feed_type, COUNT(*) AS cnt FROM tia_feeds WHERE org_id = ? GROUP BY feed_type",
                    (org_id,),
                ).fetchall():
                    by_feed_type[row["feed_type"]] = row["cnt"]

                # By ioc_type
                by_ioc_type: Dict[str, int] = {}
                for row in conn.execute(
                    "SELECT ioc_type, COUNT(*) AS cnt FROM tia_enrichments WHERE org_id = ? GROUP BY ioc_type",
                    (org_id,),
                ).fetchall():
                    by_ioc_type[row["ioc_type"]] = row["cnt"]

        return {
            "total_feeds": feeds_total,
            "active_feeds": active_feeds,
            "total_iocs": int(total_iocs),
            "total_automations": total_automations,
            "active_automations": active_automations,
            "total_enrichments": total_enrichments,
            "malicious_enrichments": malicious_enrichments,
            "by_feed_type": by_feed_type,
            "by_ioc_type": by_ioc_type,
        }
