"""Feed Manager — lifecycle management for 28+ threat intelligence feed sources.

Provides:
- Feed registration, update, deletion
- Health monitoring and reliability scoring
- IOC normalization, ingestion, search, deduplication
- Stale feed detection
- Per-org statistics

Storage: SQLite via direct sqlite3 (same pattern as analytics_db.py).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
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
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import hashlib
import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DEFAULT_DB = "data/feed_manager.db"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FeedStatus(str, Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    STALE = "stale"
    ERROR = "error"
    DISABLED = "disabled"


class FeedType(str, Enum):
    CVE = "cve"
    EXPLOIT = "exploit"
    MALWARE = "malware"
    IOC = "ioc"
    ADVISORY = "advisory"
    VULNERABILITY = "vulnerability"
    THREAT_ACTOR = "threat_actor"


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE_ID = "cve_id"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class IOC(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: IOCType
    value: str
    source_feed: str
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = Field(default_factory=list)


class FeedConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    url: str
    type: FeedType
    enabled: bool = True
    refresh_interval_minutes: int = 60
    api_key: Optional[str] = None
    last_refresh: Optional[datetime] = None
    last_success: Optional[datetime] = None
    error_count: int = 0
    reliability_score: float = Field(1.0, ge=0.0, le=1.0)
    ioc_count: int = 0
    org_id: str = "default"


class FeedHealth(BaseModel):
    feed_id: str
    status: FeedStatus
    uptime_pct: float = Field(0.0, ge=0.0, le=100.0)
    avg_response_ms: float = 0.0
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    iocs_last_24h: int = 0


# ---------------------------------------------------------------------------
# FeedManager
# ---------------------------------------------------------------------------


class FeedManager:
    """SQLite-backed manager for threat intelligence feed lifecycle."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS feeds (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                type TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                refresh_interval_minutes INTEGER NOT NULL DEFAULT 60,
                api_key TEXT,
                last_refresh TEXT,
                last_success TEXT,
                error_count INTEGER NOT NULL DEFAULT 0,
                reliability_score REAL NOT NULL DEFAULT 1.0,
                ioc_count INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS feed_refresh_log (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                refreshed_at TEXT NOT NULL,
                success INTEGER NOT NULL,
                ioc_count INTEGER NOT NULL DEFAULT 0,
                response_ms REAL NOT NULL DEFAULT 0,
                error TEXT,
                FOREIGN KEY (feed_id) REFERENCES feeds(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                feed_id TEXT NOT NULL,
                org_id TEXT NOT NULL DEFAULT 'default',
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source_feed TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.5,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tags TEXT NOT NULL DEFAULT '[]',
                dedup_hash TEXT NOT NULL,
                FOREIGN KEY (feed_id) REFERENCES feeds(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_feeds_org ON feeds(org_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_feed ON iocs(feed_id);
            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
            CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS idx_iocs_dedup ON iocs(dedup_hash);
            CREATE INDEX IF NOT EXISTS idx_refresh_log_feed ON feed_refresh_log(feed_id);
            CREATE INDEX IF NOT EXISTS idx_refresh_log_at ON feed_refresh_log(refreshed_at);
        """)
        conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row_to_feed(row: sqlite3.Row) -> FeedConfig:
        d = dict(row)
        d["enabled"] = bool(d["enabled"])
        d["type"] = FeedType(d["type"])
        return FeedConfig(**d)

    @staticmethod
    def _ioc_dedup_hash(feed_id: str, ioc_type: str, value: str) -> str:
        raw = f"{feed_id}:{ioc_type}:{value.lower().strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Feed CRUD
    # ------------------------------------------------------------------

    def register_feed(self, config: FeedConfig) -> FeedConfig:
        """Register a new feed, returning the persisted config."""
        conn = self._conn()
        conn.execute(
            """INSERT INTO feeds
               (id, org_id, name, url, type, enabled, refresh_interval_minutes,
                api_key, last_refresh, last_success, error_count, reliability_score, ioc_count)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                config.id,
                config.org_id,
                config.name,
                config.url,
                config.type.value,
                int(config.enabled),
                config.refresh_interval_minutes,
                config.api_key,
                config.last_refresh.isoformat() if config.last_refresh else None,
                config.last_success.isoformat() if config.last_success else None,
                config.error_count,
                config.reliability_score,
                config.ioc_count,
            ),
        )
        conn.commit()
        logger.info("Registered feed %s (%s)", config.id, config.name)
        _emit_event("feed_manager.feed_registered", {
            "feed_id": config.id,
            "org_id": config.org_id,
            "name": config.name,
            "type": config.type.value if hasattr(config.type, "value") else str(config.type),
        })
        return config

    def update_feed(self, feed_id: str, updates: Dict[str, Any]) -> FeedConfig:
        """Update feed config fields. Returns updated FeedConfig."""
        feed = self.get_feed(feed_id)

        allowed = {
            "name", "url", "type", "enabled", "refresh_interval_minutes",
            "api_key", "reliability_score", "org_id",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed}

        if not filtered:
            return feed

        set_clauses = ", ".join(f"{k} = ?" for k in filtered)
        values = []
        for k, v in filtered.items():
            if k == "type" and isinstance(v, FeedType):
                values.append(v.value)
            elif k == "enabled":
                values.append(int(bool(v)))
            else:
                values.append(v)
        values.append(feed_id)

        conn = self._conn()
        conn.execute(f"UPDATE feeds SET {set_clauses} WHERE id = ?", values)  # nosemgrep: formatted-sql-query  # nosec B608
        conn.commit()
        return self.get_feed(feed_id)

    def delete_feed(self, feed_id: str) -> None:
        """Remove a feed and all its associated data."""
        conn = self._conn()
        conn.execute("DELETE FROM iocs WHERE feed_id = ?", (feed_id,))
        conn.execute("DELETE FROM feed_refresh_log WHERE feed_id = ?", (feed_id,))
        conn.execute("DELETE FROM feeds WHERE id = ?", (feed_id,))
        conn.commit()
        logger.info("Deleted feed %s", feed_id)

    def list_feeds(
        self,
        org_id: str = "default",
        status_filter: Optional[FeedStatus] = None,
    ) -> List[FeedConfig]:
        """List feeds for an org, optionally filtered by computed status."""
        conn = self._conn()
        rows = conn.execute(
            "SELECT * FROM feeds WHERE org_id = ?", (org_id,)
        ).fetchall()

        feeds = [self._row_to_feed(r) for r in rows]

        if status_filter is not None:
            # Compute status for each and filter
            filtered = []
            for f in feeds:
                health = self.get_feed_health(f.id)
                if health.status == status_filter:
                    filtered.append(f)
            return filtered

        return feeds

    def get_feed(self, feed_id: str) -> FeedConfig:
        """Get a single feed by id. Raises ValueError if not found."""
        conn = self._conn()
        row = conn.execute("SELECT * FROM feeds WHERE id = ?", (feed_id,)).fetchone()
        if row is None:
            raise ValueError(f"Feed not found: {feed_id}")
        return self._row_to_feed(row)

    # ------------------------------------------------------------------
    # Refresh lifecycle
    # ------------------------------------------------------------------

    def refresh_feed(self, feed_id: str) -> Dict[str, Any]:
        """Trigger a manual refresh. Returns stats dict.

        In production this would call the external feed URL; here it records
        a successful refresh event and returns metadata.
        """
        feed = self.get_feed(feed_id)
        start = time.monotonic()

        # Record as a successful manual refresh with 0 new IOCs
        response_ms = (time.monotonic() - start) * 1000
        self.record_refresh(
            feed_id=feed_id,
            success=True,
            ioc_count=0,
            response_ms=response_ms,
            error=None,
        )

        return {
            "feed_id": feed_id,
            "feed_name": feed.name,
            "refreshed_at": self._now_iso(),
            "response_ms": response_ms,
            "ioc_count": 0,
            "status": "ok",
        }

    def record_refresh(
        self,
        feed_id: str,
        success: bool,
        ioc_count: int = 0,
        response_ms: float = 0.0,
        error: Optional[str] = None,
    ) -> None:
        """Log one refresh attempt and update feed counters."""
        now = self._now_iso()
        conn = self._conn()

        conn.execute(
            """INSERT INTO feed_refresh_log (id, feed_id, refreshed_at, success, ioc_count, response_ms, error)
               VALUES (?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), feed_id, now, int(success), ioc_count, response_ms, error),
        )

        if success:
            conn.execute(
                """UPDATE feeds
                   SET last_refresh = ?,
                       last_success = ?,
                       ioc_count = ioc_count + ?,
                       error_count = 0
                   WHERE id = ?""",
                (now, now, ioc_count, feed_id),
            )
        else:
            conn.execute(
                """UPDATE feeds
                   SET last_refresh = ?,
                       error_count = error_count + 1
                   WHERE id = ?""",
                (now, feed_id),
            )

        conn.commit()

        # Recompute reliability score after each refresh
        score = self.calculate_reliability(feed_id)
        conn.execute(
            "UPDATE feeds SET reliability_score = ? WHERE id = ?",
            (score, feed_id),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Health & reliability
    # ------------------------------------------------------------------

    def get_feed_health(self, feed_id: str) -> FeedHealth:
        """Compute health metrics for a feed from its refresh log."""
        feed = self.get_feed(feed_id)
        conn = self._conn()

        logs = conn.execute(
            "SELECT * FROM feed_refresh_log WHERE feed_id = ? ORDER BY refreshed_at DESC LIMIT 100",
            (feed_id,),
        ).fetchall()

        total = len(logs)
        successes = sum(1 for r in logs if r["success"])
        uptime_pct = (successes / total * 100.0) if total > 0 else 0.0

        avg_response_ms = 0.0
        if total > 0:
            avg_response_ms = sum(r["response_ms"] for r in logs) / total

        last_error: Optional[str] = None
        consecutive_failures = 0
        for r in logs:
            if r["success"]:
                break
            consecutive_failures += 1
            if last_error is None and r["error"]:
                last_error = r["error"]

        # IOCs ingested in last 24h
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        iocs_last_24h = conn.execute(
            """SELECT COALESCE(SUM(ioc_count), 0)
               FROM feed_refresh_log
               WHERE feed_id = ? AND refreshed_at >= ? AND success = 1""",
            (feed_id, cutoff),
        ).fetchone()[0]

        # Determine status
        if not feed.enabled:
            status = FeedStatus.DISABLED
        elif consecutive_failures >= 5:
            status = FeedStatus.ERROR
        elif consecutive_failures >= 2:
            status = FeedStatus.DEGRADED
        elif feed.last_success is None:
            status = FeedStatus.STALE
        else:
            # Stale if not refreshed within 2x the interval
            threshold = timedelta(minutes=feed.refresh_interval_minutes * 2)
            last_ok = feed.last_success
            if isinstance(last_ok, str):
                last_ok = datetime.fromisoformat(last_ok)
            if last_ok.tzinfo is None:
                last_ok = last_ok.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - last_ok
            status = FeedStatus.STALE if age > threshold else FeedStatus.ACTIVE

        return FeedHealth(
            feed_id=feed_id,
            status=status,
            uptime_pct=uptime_pct,
            avg_response_ms=avg_response_ms,
            last_error=last_error,
            consecutive_failures=consecutive_failures,
            iocs_last_24h=int(iocs_last_24h),
        )

    def get_all_health(self, org_id: str = "default") -> List[FeedHealth]:
        """Return health for every feed in an org."""
        feeds = self.list_feeds(org_id)
        return [self.get_feed_health(f.id) for f in feeds]

    def calculate_reliability(self, feed_id: str) -> float:
        """Reliability = success_rate * data_quality * timeliness (0-1)."""
        conn = self._conn()
        logs = conn.execute(
            "SELECT * FROM feed_refresh_log WHERE feed_id = ? ORDER BY refreshed_at DESC LIMIT 20",
            (feed_id,),
        ).fetchall()

        if not logs:
            return 1.0

        total = len(logs)
        successes = sum(1 for r in logs if r["success"])
        success_rate = successes / total

        # Data quality: proportion of refreshes that returned > 0 IOCs
        with_data = sum(1 for r in logs if r["success"] and r["ioc_count"] > 0)
        data_quality = (with_data / successes) if successes > 0 else 0.0

        # Timeliness: based on feed's staleness
        try:
            feed = self.get_feed(feed_id)
            if feed.last_success:
                last_ok = feed.last_success
                if isinstance(last_ok, str):
                    last_ok = datetime.fromisoformat(last_ok)
                if last_ok.tzinfo is None:
                    last_ok = last_ok.replace(tzinfo=timezone.utc)
                age_minutes = (datetime.now(timezone.utc) - last_ok).total_seconds() / 60
                expected = max(feed.refresh_interval_minutes, 1)
                timeliness = max(0.0, 1.0 - (age_minutes / (expected * 3)))
            else:
                timeliness = 0.0
        except Exception:
            timeliness = 0.5

        score = success_rate * max(data_quality, 0.5) * max(timeliness, 0.1)
        return round(min(max(score, 0.0), 1.0), 4)

    # ------------------------------------------------------------------
    # IOC management
    # ------------------------------------------------------------------

    def ingest_iocs(self, feed_id: str, iocs: List[IOC]) -> None:
        """Store normalized IOCs, skipping exact duplicates."""
        feed = self.get_feed(feed_id)
        conn = self._conn()

        inserted = 0
        for ioc in iocs:
            dedup_hash = self._ioc_dedup_hash(feed_id, ioc.type.value, ioc.value)
            existing = conn.execute(
                "SELECT id FROM iocs WHERE dedup_hash = ?", (dedup_hash,)
            ).fetchone()

            if existing:
                # Update last_seen
                conn.execute(
                    "UPDATE iocs SET last_seen = ? WHERE dedup_hash = ?",
                    (ioc.last_seen.isoformat(), dedup_hash),
                )
            else:
                conn.execute(
                    """INSERT INTO iocs
                       (id, feed_id, org_id, type, value, source_feed, confidence,
                        first_seen, last_seen, tags, dedup_hash)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        ioc.id,
                        feed_id,
                        feed.org_id,
                        ioc.type.value,
                        ioc.value,
                        ioc.source_feed,
                        ioc.confidence,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        json.dumps(ioc.tags),
                        dedup_hash,
                    ),
                )
                inserted += 1

        conn.commit()
        logger.info("Ingested %d new IOCs for feed %s", inserted, feed_id)

    def search_iocs(
        self,
        query: Optional[str] = None,
        ioc_type: Optional[IOCType] = None,
        source_feed: Optional[str] = None,
        min_confidence: float = 0.0,
    ) -> List[IOC]:
        """Search IOCs with optional filters."""
        conn = self._conn()
        sql = "SELECT * FROM iocs WHERE confidence >= ?"
        params: List[Any] = [min_confidence]

        if query:
            sql += " AND value LIKE ?"
            params.append(f"%{query}%")

        if ioc_type is not None:
            sql += " AND type = ?"
            params.append(ioc_type.value)

        if source_feed:
            sql += " AND source_feed = ?"
            params.append(source_feed)

        sql += " ORDER BY last_seen DESC LIMIT 1000"
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    @staticmethod
    def _row_to_ioc(row: sqlite3.Row) -> IOC:
        d = dict(row)
        d["type"] = IOCType(d["type"])
        d["tags"] = json.loads(d.get("tags", "[]"))
        # Remove DB-only fields
        for k in ("feed_id", "org_id", "dedup_hash"):
            d.pop(k, None)
        return IOC(**d)

    def dedup_iocs(self, org_id: str = "default") -> int:
        """Remove duplicate IOCs across feeds for an org. Returns count removed."""
        conn = self._conn()

        # Find duplicates: same (type, value) across different feeds — keep newest
        rows = conn.execute(
            """SELECT type, value, COUNT(*) as cnt, MIN(id) as oldest_id
               FROM iocs
               WHERE org_id = ?
               GROUP BY type, value
               HAVING cnt > 1""",
            (org_id,),
        ).fetchall()

        removed = 0
        for row in rows:
            ioc_type = row["type"]
            value = row["value"]
            # Keep the one with highest confidence, remove the rest
            dupes = conn.execute(
                """SELECT id FROM iocs
                   WHERE org_id = ? AND type = ? AND value = ?
                   ORDER BY confidence DESC, last_seen DESC""",
                (org_id, ioc_type, value),
            ).fetchall()

            ids_to_remove = [r["id"] for r in dupes[1:]]
            for rid in ids_to_remove:
                conn.execute("DELETE FROM iocs WHERE id = ?", (rid,))
                removed += 1

        conn.commit()
        logger.info("Deduped %d IOCs for org %s", removed, org_id)
        return removed

    # ------------------------------------------------------------------
    # Analytics & alerting
    # ------------------------------------------------------------------

    def get_stale_feeds(self, threshold_hours: int = 24) -> List[FeedConfig]:
        """Return feeds that haven't been successfully refreshed within threshold_hours."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=threshold_hours)).isoformat()
        conn = self._conn()
        rows = conn.execute(
            """SELECT * FROM feeds
               WHERE enabled = 1
               AND (last_success IS NULL OR last_success < ?)""",
            (cutoff,),
        ).fetchall()
        return [self._row_to_feed(r) for r in rows]

    def get_feed_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for an org's feeds."""
        conn = self._conn()

        total_feeds = conn.execute(
            "SELECT COUNT(*) FROM feeds WHERE org_id = ?", (org_id,)
        ).fetchone()[0]

        active_count = 0
        stale_count = 0
        feeds = self.list_feeds(org_id)
        for f in feeds:
            health = self.get_feed_health(f.id)
            if health.status == FeedStatus.ACTIVE:
                active_count += 1
            elif health.status == FeedStatus.STALE:
                stale_count += 1

        total_iocs = conn.execute(
            "SELECT COALESCE(SUM(ioc_count), 0) FROM feeds WHERE org_id = ?", (org_id,)
        ).fetchone()[0]

        # Top feeds by IOC count
        top_rows = conn.execute(
            """SELECT name, ioc_count FROM feeds
               WHERE org_id = ?
               ORDER BY ioc_count DESC LIMIT 5""",
            (org_id,),
        ).fetchall()
        top_feeds = [{"name": r["name"], "ioc_count": r["ioc_count"]} for r in top_rows]

        return {
            "org_id": org_id,
            "total_feeds": total_feeds,
            "active": active_count,
            "stale": stale_count,
            "total_iocs": int(total_iocs),
            "top_feeds": top_feeds,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: Optional[FeedManager] = None
_manager_lock = threading.Lock()


def get_feed_manager(db_path: str = _DEFAULT_DB) -> FeedManager:
    """Return the module-level FeedManager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = FeedManager(db_path=db_path)
    return _manager
