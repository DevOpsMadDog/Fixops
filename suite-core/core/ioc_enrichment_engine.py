"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates hash-derived IOC enrichment data for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- _seed() (line 153) derives enrichment from MD5 hash of IOC value — not from
  real threat intel feeds (VirusTotal, AbuseIPDB, Shodan, MISP, OTX).
- Campaign/malware attribution uses hardcoded _SAMPLE_CAMPAIGNS / _SAMPLE_ACTORS lists.
- Real implementation requires: VirusTotal API, AbuseIPDB, Shodan, MISP instance,
  or OpenCTI integration. Configure via /api/v1/connectors/threat-intel/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

IOC Enrichment Engine — ALDECI.

Manage indicators of compromise (IOCs): add, list, enrich, watchlist,
bulk-import, and summarise statistics.

Multi-tenant via org_id. SQLite WAL-backed. Thread-safe via RLock.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
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
_logger.warning(
    "⚠️  %s loaded in SIMULATION mode — IOC enrichment is hash-derived from indicator value; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/threat-intel/configure",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ioc_enrichment.db"
)

_VALID_IOC_TYPES = {"ip", "domain", "hash", "url", "email"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_VERDICTS = {"malicious", "suspicious", "benign", "unknown"}

# Simulated campaign/malware data for enrichment
_SAMPLE_CAMPAIGNS = [
    "APT29-Cozy Bear", "Lazarus Group", "FIN7", "Emotet Campaign",
    "RedLine Stealer", "Cobalt Strike C2", "BlackCat Ransomware",
]
_SAMPLE_MALWARE = [
    "Emotet", "TrickBot", "QakBot", "RedLine", "Raccoon", "AgentTesla",
    "AsyncRAT", "NjRAT", "Formbook", "SnakeKeylogger",
]
_SAMPLE_ACTORS = [
    "APT28", "APT29", "APT41", "Lazarus", "FIN7", "FIN11", "TA505",
    "Sandworm", "Cozy Bear", "Unknown",
]
_SAMPLE_GEOS = [
    "RU", "CN", "KP", "IR", "US", "UA", "DE", "NL", "BR", "Unknown",
]


class IOCEnrichmentEngine:
    """SQLite WAL-backed IOC management and enrichment engine.

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
                CREATE TABLE IF NOT EXISTS ioc_indicators (
                    ioc_id      TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    ioc_type    TEXT NOT NULL DEFAULT 'ip',
                    value       TEXT NOT NULL DEFAULT '',
                    source      TEXT NOT NULL DEFAULT '',
                    confidence  INTEGER NOT NULL DEFAULT 50,
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    tags        TEXT NOT NULL DEFAULT '[]',
                    first_seen  DATETIME NOT NULL,
                    last_seen   DATETIME NOT NULL,
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ioc_org
                    ON ioc_indicators (org_id, ioc_type);

                CREATE INDEX IF NOT EXISTS idx_ioc_sev
                    ON ioc_indicators (org_id, severity);

                CREATE INDEX IF NOT EXISTS idx_ioc_value
                    ON ioc_indicators (value);

                CREATE TABLE IF NOT EXISTS ioc_enrichments (
                    enrichment_id        TEXT PRIMARY KEY,
                    ioc_id               TEXT NOT NULL,
                    org_id               TEXT NOT NULL,
                    reputation_score     INTEGER NOT NULL DEFAULT 0,
                    geo_location         TEXT NOT NULL DEFAULT '',
                    associated_campaigns TEXT NOT NULL DEFAULT '[]',
                    malware_families     TEXT NOT NULL DEFAULT '[]',
                    threat_actor         TEXT NOT NULL DEFAULT '',
                    verdict              TEXT NOT NULL DEFAULT 'unknown',
                    enriched_at          DATETIME NOT NULL,
                    UNIQUE (ioc_id, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_enrich_ioc
                    ON ioc_enrichments (ioc_id, org_id);

                CREATE TABLE IF NOT EXISTS ioc_watchlists (
                    watchlist_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    watchlist_name  TEXT NOT NULL,
                    ioc_id          TEXT NOT NULL,
                    added_at        DATETIME NOT NULL,
                    UNIQUE (org_id, watchlist_name, ioc_id)
                );

                CREATE INDEX IF NOT EXISTS idx_watch_org
                    ON ioc_watchlists (org_id, watchlist_name);
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
    def _ioc_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        return d

    @staticmethod
    def _enrich_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["associated_campaigns"] = json.loads(d.get("associated_campaigns") or "[]")
        d["malware_families"] = json.loads(d.get("malware_families") or "[]")
        return d

    def _seed(self, value: str) -> random.Random:
        """Deterministic RNG seeded from IOC value for consistent simulation."""
        seed = int(hashlib.md5(value.encode(), usedforsecurity=False).hexdigest(), 16) % (2 ** 32)
        return random.Random(seed)

    # ------------------------------------------------------------------
    # IOC CRUD
    # ------------------------------------------------------------------

    def add_ioc(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IOC indicator. Returns the created IOC dict."""
        ioc_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        ioc_type = data.get("ioc_type", "ip")
        if ioc_type not in _VALID_IOC_TYPES:
            ioc_type = "ip"

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        confidence = max(0, min(100, int(data.get("confidence", 50))))
        tags = json.dumps(data.get("tags") or [])
        first_seen = data.get("first_seen", now)
        last_seen = data.get("last_seen", now)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ioc_indicators
                        (ioc_id, org_id, ioc_type, value, source, confidence,
                         severity, tags, first_seen, last_seen, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ioc_id, org_id, ioc_type,
                        data.get("value", ""),
                        data.get("source", ""),
                        confidence, severity, tags,
                        first_seen, last_seen, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "ioc_enrichment", "org_id": org_id, "source_engine": "ioc_enrichment"})
            except Exception:
                pass

        return {
            "ioc_id": ioc_id,
            "org_id": org_id,
            "ioc_type": ioc_type,
            "value": data.get("value", ""),
            "source": data.get("source", ""),
            "confidence": confidence,
            "severity": severity,
            "tags": data.get("tags") or [],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "created_at": now,
        }

    def list_iocs(
        self,
        org_id: str,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List IOCs for an org, optionally filtered by type or severity."""
        query = "SELECT * FROM ioc_indicators WHERE org_id=?"
        params: list = [org_id]

        if ioc_type:
            query += " AND ioc_type=?"
            params.append(ioc_type)
        if severity:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY severity, last_seen DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._ioc_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Enrichment
    # ------------------------------------------------------------------

    def enrich_ioc(self, org_id: str, ioc_id: str) -> Dict[str, Any]:
        """Simulate enrichment for an IOC: reputation, geo, campaigns, verdict.

        Uses a deterministic simulation based on the IOC value so results are
        stable across calls for the same IOC. Returns the enrichment dict.
        """
        # Fetch the IOC to get its value
        with self._conn() as conn:
            ioc_row = conn.execute(
                "SELECT * FROM ioc_indicators WHERE ioc_id=? AND org_id=?",
                (ioc_id, org_id),
            ).fetchone()

        if not ioc_row:
            return {"error": "IOC not found", "ioc_id": ioc_id}

        ioc = self._ioc_to_dict(ioc_row)
        rng = self._seed(ioc["value"])

        reputation_score = rng.randint(0, 100)
        geo_location = rng.choice(_SAMPLE_GEOS)
        num_campaigns = rng.randint(0, 3)
        associated_campaigns = rng.sample(_SAMPLE_CAMPAIGNS, k=min(num_campaigns, len(_SAMPLE_CAMPAIGNS)))
        num_malware = rng.randint(0, 2)
        malware_families = rng.sample(_SAMPLE_MALWARE, k=min(num_malware, len(_SAMPLE_MALWARE)))
        threat_actor = rng.choice(_SAMPLE_ACTORS)

        # Verdict based on reputation score
        if reputation_score >= 70:
            verdict = "malicious"
        elif reputation_score >= 40:
            verdict = "suspicious"
        elif reputation_score >= 10:
            verdict = "benign"
        else:
            verdict = "unknown"

        enrichment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO ioc_enrichments
                        (enrichment_id, ioc_id, org_id, reputation_score,
                         geo_location, associated_campaigns, malware_families,
                         threat_actor, verdict, enriched_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(ioc_id, org_id) DO UPDATE SET
                        reputation_score=excluded.reputation_score,
                        geo_location=excluded.geo_location,
                        associated_campaigns=excluded.associated_campaigns,
                        malware_families=excluded.malware_families,
                        threat_actor=excluded.threat_actor,
                        verdict=excluded.verdict,
                        enriched_at=excluded.enriched_at
                    """,
                    (
                        enrichment_id, ioc_id, org_id,
                        reputation_score, geo_location,
                        json.dumps(associated_campaigns),
                        json.dumps(malware_families),
                        threat_actor, verdict, now,
                    ),
                )

        return {
            "ioc_id": ioc_id,
            "org_id": org_id,
            "reputation_score": reputation_score,
            "geo_location": geo_location,
            "associated_campaigns": associated_campaigns,
            "malware_families": malware_families,
            "threat_actor": threat_actor,
            "verdict": verdict,
            "enriched_at": now,
        }

    def get_enrichment(self, org_id: str, ioc_id: str) -> Dict[str, Any]:
        """Fetch stored enrichment for an IOC, or empty dict if not yet enriched."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_enrichments WHERE ioc_id=? AND org_id=?",
                (ioc_id, org_id),
            ).fetchone()
        if not row:
            return {}
        return self._enrich_to_dict(row)

    # ------------------------------------------------------------------
    # Watchlists
    # ------------------------------------------------------------------

    def add_to_watchlist(self, org_id: str, watchlist_name: str, ioc_id: str) -> bool:
        """Add an IOC to a named watchlist. Returns True on success."""
        watchlist_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        try:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO ioc_watchlists
                            (watchlist_id, org_id, watchlist_name, ioc_id, added_at)
                        VALUES (?,?,?,?,?)
                        """,
                        (watchlist_id, org_id, watchlist_name, ioc_id, now),
                    )
            return True
        except Exception as exc:
            _logger.error("add_to_watchlist error: %s", exc)
            return False

    def get_watchlist(self, org_id: str, watchlist_name: str) -> List[Dict[str, Any]]:
        """Return all IOC records on a named watchlist for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT i.* FROM ioc_indicators i
                JOIN ioc_watchlists w ON i.ioc_id = w.ioc_id
                WHERE w.org_id=? AND w.watchlist_name=? AND i.org_id=?
                ORDER BY w.added_at DESC
                """,
                (org_id, watchlist_name, org_id),
            ).fetchall()
        return [self._ioc_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Bulk import
    # ------------------------------------------------------------------

    def bulk_import(self, org_id: str, iocs: List[Dict[str, Any]]) -> Dict[str, int]:
        """Import a list of IOC dicts. Returns {"imported": N, "failed": M}."""
        imported = 0
        failed = 0
        for ioc_data in iocs:
            try:
                self.add_ioc(org_id, ioc_data)
                imported += 1
            except Exception as exc:
                _logger.warning("bulk_import skip: %s", exc)
                failed += 1
        return {"imported": imported, "failed": failed}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ioc_stats(self, org_id: str) -> Dict[str, Any]:
        """Return summary statistics for an org's IOC inventory."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ioc_indicators WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM ioc_indicators "
                "WHERE org_id=? GROUP BY ioc_type",
                (org_id,),
            ).fetchall()

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM ioc_indicators "
                "WHERE org_id=? GROUP BY severity",
                (org_id,),
            ).fetchall()

            enriched_count = conn.execute(
                "SELECT COUNT(*) FROM ioc_enrichments WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            watchlist_count = conn.execute(
                "SELECT COUNT(DISTINCT ioc_id) FROM ioc_watchlists WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

        return {
            "total": total,
            "by_type": {r[0]: r[1] for r in type_rows},
            "by_severity": {r[0]: r[1] for r in sev_rows},
            "enriched_count": enriched_count,
            "watchlist_count": watchlist_count,
        }
