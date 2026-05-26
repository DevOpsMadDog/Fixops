"""
IOC Enrichment Engine — ALDECI.

DATA SOURCE: abuse.ch Feodo Tracker botnet C2 IP blocklist
  https://feodotracker.abuse.ch/downloads/ipblocklist.json
  No API key required. Cached in-memory for 15 minutes per process.

STATUS: REAL (as of 2026-05-27)
  - enrich_ioc() queries the abuse.ch Feodo Tracker blocklist for IP IOCs.
    Verdict is derived from actual blocklist membership — not hashes, not
    random numbers, not simulation.
  - IP IOCs: verdict "malicious" if the IP appears in the live C2 blocklist,
    "unknown" if not listed (may be clean or just not in this feed).
  - Non-IP IOC types (domain, hash, url, email): verdict "unknown" — the
    Feodo Tracker only covers IPs; fabricating enrichment for other types
    would be dishonest.
  - Feed unreachable: raises IocEnrichmentError (caught by router → HTTP 422).
  - IOC CRUD (add_ioc, list_iocs, bulk_import, add_to_watchlist, get_watchlist,
    get_enrichment, get_ioc_stats) are production-ready (SQLite WAL).

Multi-tenant via org_id. SQLite WAL-backed. Thread-safe via RLock.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.request
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ioc_enrichment.db"
)

_VALID_IOC_TYPES = {"ip", "domain", "hash", "url", "email"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_VERDICTS = {"malicious", "suspicious", "benign", "unknown"}

# ---------------------------------------------------------------------------
# Feodo Tracker in-memory cache
# ---------------------------------------------------------------------------

_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
_FEODO_CACHE_TTL = 900  # 15 minutes

# Cache state — guarded by _FEODO_LOCK
_feodo_blocklist: Optional[Dict[str, Dict[str, Any]]] = None  # ip -> entry dict
_feodo_fetched_at: float = 0.0
_FEODO_LOCK = threading.Lock()


class IocEnrichmentError(ValueError):
    """Raised when real enrichment cannot be performed (feed unreachable, IOC not found, etc.)."""


def _fetch_feodo_blocklist() -> Dict[str, Dict[str, Any]]:
    """Fetch the abuse.ch Feodo Tracker blocklist and return a dict keyed by IP address.

    Raises IocEnrichmentError if the feed cannot be reached or parsed.
    """
    req = urllib.request.Request(
        _FEODO_URL,
        headers={"User-Agent": "ALdeci-CTEM/1.0 (ioc-enrichment; abuse.ch Feodo Tracker)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
    except Exception as exc:
        raise IocEnrichmentError(
            f"abuse.ch Feodo Tracker feed unreachable: {exc}"
        ) from exc

    try:
        entries: List[Dict[str, Any]] = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IocEnrichmentError(
            f"abuse.ch Feodo Tracker feed returned unparseable JSON: {exc}"
        ) from exc

    if not isinstance(entries, list):
        raise IocEnrichmentError(
            "abuse.ch Feodo Tracker feed: unexpected top-level type "
            f"(expected list, got {type(entries).__name__})"
        )

    blocklist: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        ip = entry.get("ip_address")
        if ip and isinstance(ip, str):
            blocklist[ip.strip()] = entry

    _logger.info(
        "ioc_enrichment: loaded %d C2 IPs from abuse.ch Feodo Tracker",
        len(blocklist),
    )
    return blocklist


def _get_feodo_blocklist() -> Dict[str, Dict[str, Any]]:
    """Return the cached Feodo Tracker blocklist, refreshing if stale.

    Thread-safe. TTL is _FEODO_CACHE_TTL seconds. Raises IocEnrichmentError
    if the feed cannot be fetched and no cache is available.
    """
    global _feodo_blocklist, _feodo_fetched_at

    now = time.monotonic()
    with _FEODO_LOCK:
        if _feodo_blocklist is not None and (now - _feodo_fetched_at) < _FEODO_CACHE_TTL:
            return _feodo_blocklist
        # Cache miss or expired — fetch fresh
        fresh = _fetch_feodo_blocklist()  # may raise IocEnrichmentError
        _feodo_blocklist = fresh
        _feodo_fetched_at = now
        return _feodo_blocklist


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class IOCEnrichmentEngine:
    """SQLite WAL-backed IOC management and enrichment engine.

    Thread-safe via RLock. Multi-tenant via org_id.

    enrich_ioc() uses the abuse.ch Feodo Tracker C2 IP blocklist (no API key).
    Non-IP IOC types return verdict "unknown" — no fabrication.
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
                    _bus.emit(
                        "ENTITY_UPDATED",
                        {
                            "entity_type": "ioc_enrichment",
                            "org_id": org_id,
                            "source_engine": "ioc_enrichment",
                        },
                    )
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
        """Enrich an IOC using the abuse.ch Feodo Tracker C2 IP blocklist.

        For IP IOCs: fetches the live Feodo Tracker blocklist (cached 15 min),
        checks if the IP appears, and stores a real verdict (malicious/unknown)
        with metadata from the blocklist entry (malware family, country, ASN).

        For non-IP IOC types (domain, hash, url, email): stores verdict
        "unknown" with a note that no no-auth feed covers this type — no
        fabrication.

        Raises:
            IocEnrichmentError: if the IOC does not exist, or if the feed is
                unreachable (for IP IOCs). Router maps this to HTTP 422.
        """
        # Fetch the IOC record from DB
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_indicators WHERE ioc_id=? AND org_id=?",
                (ioc_id, org_id),
            ).fetchone()

        if not row:
            raise IocEnrichmentError(
                f"IOC {ioc_id!r} not found for org {org_id!r}"
            )

        ioc = self._ioc_to_dict(row)
        ioc_type = ioc.get("ioc_type", "ip")
        ioc_value = ioc.get("value", "").strip()
        now = datetime.now(timezone.utc).isoformat()

        if ioc_type == "ip":
            # Real enrichment: query the Feodo Tracker blocklist
            blocklist = _get_feodo_blocklist()  # raises IocEnrichmentError if unreachable
            entry = blocklist.get(ioc_value)

            if entry:
                # IP is a known Feodo Tracker C2 server
                malware = entry.get("malware") or ""
                country = entry.get("country") or ""
                as_name = entry.get("as_name") or ""
                port = entry.get("port")
                status = entry.get("status") or "unknown"
                first_seen_feed = entry.get("first_seen") or ""

                verdict = "malicious"
                reputation_score = 95
                geo_location = country
                malware_families = [malware] if malware else []
                associated_campaigns = []
                if malware:
                    associated_campaigns = [f"{malware} C2 Campaign"]
                threat_actor = "Unknown"
                source_note = (
                    f"abuse.ch Feodo Tracker (C2 botnet; malware={malware}; "
                    f"status={status}; port={port}; asn={as_name}; "
                    f"feed_first_seen={first_seen_feed})"
                )
            else:
                # IP not on the C2 blocklist — unknown (may be clean)
                verdict = "unknown"
                reputation_score = 0
                geo_location = ""
                malware_families = []
                associated_campaigns = []
                threat_actor = ""
                source_note = (
                    "abuse.ch Feodo Tracker: IP not in C2 blocklist "
                    "(may be clean or not tracked by this feed)"
                )

        else:
            # Non-IP types: no no-auth feed available — honest unknown
            verdict = "unknown"
            reputation_score = 0
            geo_location = ""
            malware_families = []
            associated_campaigns = []
            threat_actor = ""
            source_note = (
                f"No no-auth public feed available for ioc_type={ioc_type!r}. "
                "Configure a threat intel connector for domain/hash/url/email enrichment."
            )

        # Persist enrichment
        enrichment_id = str(uuid.uuid4())
        enrichment = {
            "enrichment_id": enrichment_id,
            "ioc_id": ioc_id,
            "org_id": org_id,
            "reputation_score": reputation_score,
            "geo_location": geo_location,
            "associated_campaigns": associated_campaigns,
            "malware_families": malware_families,
            "threat_actor": threat_actor,
            "verdict": verdict,
            "enriched_at": now,
            "source": source_note,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO ioc_enrichments
                        (enrichment_id, ioc_id, org_id, reputation_score,
                         geo_location, associated_campaigns, malware_families,
                         threat_actor, verdict, enriched_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        enrichment_id, ioc_id, org_id,
                        reputation_score,
                        geo_location,
                        json.dumps(associated_campaigns),
                        json.dumps(malware_families),
                        threat_actor,
                        verdict,
                        now,
                    ),
                )

        _logger.info(
            "ioc_enrichment: enriched ioc_id=%s type=%s value=%s verdict=%s source=%s",
            ioc_id, ioc_type, ioc_value if ioc_type == "ip" else "<redacted>",
            verdict, "abuse.ch Feodo Tracker" if ioc_type == "ip" else "none",
        )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "ENTITY_UPDATED",
                        {
                            "entity_type": "ioc_enrichment",
                            "org_id": org_id,
                            "ioc_id": ioc_id,
                            "verdict": verdict,
                            "source_engine": "ioc_enrichment",
                        },
                    )
            except Exception:
                pass

        return enrichment

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
