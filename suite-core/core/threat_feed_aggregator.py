"""Threat Feed Aggregator Engine — ALDECI.

Manages threat intelligence feed sources, ingests feed items (IOCs, CVEs,
malware, APT campaigns), and supports cross-feed IOC search.

Compliance: NIST SP 800-150, MISP, STIX 2.1
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
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_feeds.db"
)

VALID_FEED_TYPES = {
    "cve",
    "malware",
    "ip_blocklist",
    "domain_blocklist",
    "vulnerability",
    "apt_campaign",
    "osint",
}

VALID_FORMATS = {"json", "xml", "csv", "stix"}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class ThreatFeedAggregator:
    """SQLite WAL-backed threat feed aggregator.

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
                CREATE TABLE IF NOT EXISTS feed_sources (
                    source_id               TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    feed_type               TEXT NOT NULL,
                    url                     TEXT NOT NULL DEFAULT '',
                    format                  TEXT NOT NULL DEFAULT 'json',
                    update_frequency_minutes INTEGER NOT NULL DEFAULT 60,
                    enabled                 INTEGER NOT NULL DEFAULT 1,
                    last_fetched            DATETIME,
                    item_count              INTEGER NOT NULL DEFAULT 0,
                    reliability_score       INTEGER NOT NULL DEFAULT 80,
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fsrc_org
                    ON feed_sources (org_id, enabled);

                CREATE TABLE IF NOT EXISTS feed_items (
                    item_id          TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    source_id        TEXT NOT NULL,
                    feed_type        TEXT NOT NULL,
                    title            TEXT NOT NULL DEFAULT '',
                    description      TEXT NOT NULL DEFAULT '',
                    severity         TEXT NOT NULL DEFAULT 'info',
                    iocs             TEXT NOT NULL DEFAULT '[]',
                    published_at     DATETIME NOT NULL,
                    expires_at       DATETIME,
                    source_reliability INTEGER NOT NULL DEFAULT 80,
                    ingested_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fitem_org
                    ON feed_items (org_id, feed_type, ingested_at DESC);

                CREATE INDEX IF NOT EXISTS idx_fitem_severity
                    ON feed_items (org_id, severity);

                CREATE TABLE IF NOT EXISTS feed_subscriptions (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    source_id   TEXT NOT NULL,
                    subscribed_at DATETIME NOT NULL,
                    UNIQUE(org_id, source_id)
                );

                CREATE INDEX IF NOT EXISTS idx_fsub_org
                    ON feed_subscriptions (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "iocs" in d:
            d["iocs"] = json.loads(d["iocs"] or "[]")
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Feed sources
    # ------------------------------------------------------------------

    def add_feed_source(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new threat intel feed source."""
        source_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        feed_type = data.get("feed_type", "osint")
        if feed_type not in VALID_FEED_TYPES:
            feed_type = "osint"

        fmt = data.get("format", "json")
        if fmt not in VALID_FORMATS:
            fmt = "json"

        reliability = int(data.get("reliability_score", 80))
        reliability = max(0, min(100, reliability))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO feed_sources
                        (source_id, org_id, name, feed_type, url, format,
                         update_frequency_minutes, enabled, last_fetched,
                         item_count, reliability_score, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        source_id,
                        org_id,
                        data.get("name", ""),
                        feed_type,
                        data.get("url", ""),
                        fmt,
                        int(data.get("update_frequency_minutes", 60)),
                        1 if data.get("enabled", True) else 0,
                        data.get("last_fetched"),
                        int(data.get("item_count", 0)),
                        reliability,
                        now,
                    ),
                )
        result = {
            "source_id": source_id,
            "org_id": org_id,
            "created_at": now,
            **data,
            "feed_type": feed_type,
            "format": fmt,
            "reliability_score": reliability,
        }
        self._emit_event(
            "threat_feed.source.added",
            {
                "source_id": source_id,
                "org_id": org_id,
                "feed_type": feed_type,
                "name": data.get("name", ""),
            },
        )
        return result

    def list_feed_sources(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List feed sources for an org, optionally filtered by enabled state."""
        if enabled is None:
            query = "SELECT * FROM feed_sources WHERE org_id=? ORDER BY name"
            params = (org_id,)
        else:
            query = "SELECT * FROM feed_sources WHERE org_id=? AND enabled=? ORDER BY name"
            params = (org_id, 1 if enabled else 0)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Feed items
    # ------------------------------------------------------------------

    def ingest_feed_item(
        self, org_id: str, source_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Ingest a single feed item (IOC, CVE, malware indicator, etc.)."""
        item_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        feed_type = data.get("feed_type", "osint")
        if feed_type not in VALID_FEED_TYPES:
            feed_type = "osint"

        severity = data.get("severity", "info").lower()
        if severity not in VALID_SEVERITIES:
            severity = "info"

        iocs = data.get("iocs", [])
        if not isinstance(iocs, list):
            iocs = []

        # Get source reliability if not provided
        source_reliability = int(data.get("source_reliability", 80))
        if "source_reliability" not in data:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT reliability_score FROM feed_sources WHERE source_id=? AND org_id=?",
                    (source_id, org_id),
                ).fetchone()
            if row:
                source_reliability = row["reliability_score"]

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO feed_items
                        (item_id, org_id, source_id, feed_type, title, description,
                         severity, iocs, published_at, expires_at,
                         source_reliability, ingested_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        item_id,
                        org_id,
                        source_id,
                        feed_type,
                        data.get("title", ""),
                        data.get("description", ""),
                        severity,
                        json.dumps(iocs),
                        data.get("published_at", now),
                        data.get("expires_at"),
                        source_reliability,
                        now,
                    ),
                )
                # Bump item_count on source
                conn.execute(
                    "UPDATE feed_sources SET item_count = item_count + 1, last_fetched=? WHERE source_id=? AND org_id=?",
                    (now, source_id, org_id),
                )
        result = {
            "item_id": item_id,
            "org_id": org_id,
            "source_id": source_id,
            "feed_type": feed_type,
            "severity": severity,
            "iocs": iocs,
            "source_reliability": source_reliability,
            "ingested_at": now,
            **{k: v for k, v in data.items() if k not in ("iocs", "feed_type", "severity", "source_reliability")},
        }
        self._emit_event(
            "threat_feed.item.ingested",
            {
                "item_id": item_id,
                "org_id": org_id,
                "source_id": source_id,
                "feed_type": feed_type,
                "severity": severity,
                "ioc_count": len(iocs),
            },
        )
        return result

    def list_feed_items(
        self,
        org_id: str,
        feed_type: Optional[str] = None,
        severity: Optional[str] = None,
        hours_back: int = 24,
    ) -> List[Dict[str, Any]]:
        """List feed items for an org, optionally filtered by type/severity."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
        params: list = [org_id, cutoff]
        conditions = ["org_id=?", "ingested_at >= ?"]

        if feed_type:
            conditions.append("feed_type=?")
            params.append(feed_type)
        if severity:
            conditions.append("severity=?")
            params.append(severity.lower())

        where = " AND ".join(conditions)
        query = f"SELECT * FROM feed_items WHERE {where} ORDER BY ingested_at DESC"  # nosec B608

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def search_iocs(self, org_id: str, query: str) -> List[Dict[str, Any]]:
        """Full-text search across all feed items' IOC lists."""
        if not query:
            return []
        query_lower = query.lower()
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM feed_items WHERE org_id=? ORDER BY ingested_at DESC",
                (org_id,),
            ).fetchall()

        results = []
        for r in rows:
            d = self._row_to_dict(r)
            iocs = d.get("iocs", [])
            matched = [ioc for ioc in iocs if query_lower in str(ioc).lower()]
            if matched:
                d["matched_iocs"] = matched
                results.append(d)
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_feed_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated stats across all feeds for an org."""
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).isoformat()
        cutoff_7d = (now - timedelta(days=7)).isoformat()

        with self._conn() as conn:
            total_sources = conn.execute(
                "SELECT COUNT(*) FROM feed_sources WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_sources = conn.execute(
                "SELECT COUNT(*) FROM feed_sources WHERE org_id=? AND enabled=1", (org_id,)
            ).fetchone()[0]

            items_24h = conn.execute(
                "SELECT COUNT(*) FROM feed_items WHERE org_id=? AND ingested_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            items_7d = conn.execute(
                "SELECT COUNT(*) FROM feed_items WHERE org_id=? AND ingested_at >= ?",
                (org_id, cutoff_7d),
            ).fetchone()[0]

            by_type_rows = conn.execute(
                "SELECT feed_type, COUNT(*) as cnt FROM feed_items WHERE org_id=? GROUP BY feed_type",
                (org_id,),
            ).fetchall()

            avg_rel_row = conn.execute(
                "SELECT AVG(reliability_score) FROM feed_sources WHERE org_id=? AND enabled=1",
                (org_id,),
            ).fetchone()

        by_feed_type = {r["feed_type"]: r["cnt"] for r in by_type_rows}
        avg_reliability = round(avg_rel_row[0] or 0.0, 1)

        return {
            "total_sources": total_sources,
            "active_sources": active_sources,
            "items_24h": items_24h,
            "items_7d": items_7d,
            "by_feed_type": by_feed_type,
            "avg_reliability": avg_reliability,
        }

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass

