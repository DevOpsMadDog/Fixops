"""Threat Intel Enrichment Engine — ALDECI.

Enriches indicators of compromise (IOCs) with reputation, context,
and attribution data from multiple threat intelligence sources.

Capabilities:
  - Enrichment request lifecycle: pending → completed
  - Multi-source result aggregation per IOC
  - Source registry with SHA-256 API key hashing
  - Indicator summary: avg reputation, combined tags, malicious flag
  - Bulk enrichment for IOC lists
  - Stats: totals, completed/pending, top malicious indicator types

Compliance: NIST CSF ID.RA-2, ISO 27001 A.5.7 (Threat Intelligence)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_INDICATOR_TYPES = {
    "ip", "domain", "url", "hash", "email", "cve", "asn", "certificate"
}

_VALID_SOURCE_TYPES = {
    "commercial", "open-source", "isac", "internal", "government", "community"
}

_VALID_STATUSES = {"pending", "completed", "failed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clamp_confidence(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def _clamp_reputation(v: float) -> float:
    return max(0.0, min(100.0, float(v)))


class ThreatIntelEnrichmentEngine:
    """SQLite WAL-backed Threat Intel Enrichment engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_intel_enrichment.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "threat_intel_enrichment.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS enrichment_requests (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    indicator           TEXT NOT NULL,
                    indicator_type      TEXT NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'pending',
                    sources_queried     INTEGER NOT NULL DEFAULT 0,
                    sources_responded   INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    completed_at        TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_er_org
                    ON enrichment_requests (org_id, status, indicator_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS enrichment_results (
                    id              TEXT PRIMARY KEY,
                    request_id      TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    source          TEXT NOT NULL,
                    reputation_score REAL NOT NULL DEFAULT 0.0,
                    malicious       INTEGER NOT NULL DEFAULT 0,
                    tags            TEXT NOT NULL DEFAULT '[]',
                    context         TEXT NOT NULL DEFAULT '',
                    first_seen      TEXT,
                    last_seen       TEXT,
                    confidence      REAL NOT NULL DEFAULT 0.0,
                    enriched_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_res_org
                    ON enrichment_results (org_id, request_id, source, enriched_at DESC);

                CREATE TABLE IF NOT EXISTS enrichment_sources (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    source_type     TEXT NOT NULL,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    api_key_hash    TEXT NOT NULL DEFAULT '',
                    request_count   INTEGER NOT NULL DEFAULT 0,
                    success_rate    REAL NOT NULL DEFAULT 0.0,
                    last_used       TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_src_org
                    ON enrichment_sources (org_id, source_type, enabled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Enrichment Requests
    # ------------------------------------------------------------------

    def create_enrichment_request(
        self,
        org_id: str,
        indicator: str,
        indicator_type: str,
        sources_queried: int = 0,
    ) -> Dict[str, Any]:
        """Create a new enrichment request with status=pending."""
        indicator = (indicator or "").strip()
        if not indicator:
            raise ValueError("indicator is required.")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type: {indicator_type!r}. "
                f"Must be one of {sorted(_VALID_INDICATOR_TYPES)}"
            )
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "status": "pending",
            "sources_queried": max(0, int(sources_queried)),
            "sources_responded": 0,
            "created_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO enrichment_requests
                       (id, org_id, indicator, indicator_type, status,
                        sources_queried, sources_responded, created_at, completed_at)
                       VALUES (:id, :org_id, :indicator, :indicator_type, :status,
                               :sources_queried, :sources_responded, :created_at, :completed_at)""",
                    record,
                )
        return record

    def list_enrichment_requests(
        self,
        org_id: str,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List enrichment requests for an org, optionally filtered by status."""
        with self._lock:
            with self._conn() as conn:
                if status:
                    rows = conn.execute(
                        """SELECT * FROM enrichment_requests
                           WHERE org_id = ? AND status = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (org_id, status, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM enrichment_requests
                           WHERE org_id = ?
                           ORDER BY created_at DESC LIMIT ?""",
                        (org_id, limit),
                    ).fetchall()
        return [self._row(r) for r in rows]

    def add_enrichment_result(
        self,
        request_id: str,
        org_id: str,
        source: str,
        reputation_score: float,
        malicious: bool,
        tags: List[str],
        context: str,
        confidence: float,
        first_seen: Optional[str] = None,
        last_seen: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add an enrichment result; auto-update request sources_responded.

        If sources_responded >= sources_queried → status=completed.
        """
        source = (source or "").strip()
        if not source:
            raise ValueError("source is required.")

        reputation_score = _clamp_reputation(reputation_score)
        confidence = _clamp_confidence(confidence)
        tags_json = json.dumps(tags if isinstance(tags, list) else [])

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "request_id": request_id,
            "org_id": org_id,
            "source": source,
            "reputation_score": reputation_score,
            "malicious": 1 if malicious else 0,
            "tags": tags_json,
            "context": context or "",
            "first_seen": first_seen,
            "last_seen": last_seen,
            "confidence": confidence,
            "enriched_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO enrichment_results
                       (id, request_id, org_id, source, reputation_score, malicious,
                        tags, context, first_seen, last_seen, confidence, enriched_at)
                       VALUES (:id, :request_id, :org_id, :source, :reputation_score,
                               :malicious, :tags, :context, :first_seen, :last_seen,
                               :confidence, :enriched_at)""",
                    record,
                )
                # Increment sources_responded on the parent request
                conn.execute(
                    """UPDATE enrichment_requests
                       SET sources_responded = sources_responded + 1
                       WHERE id = ? AND org_id = ?""",
                    (request_id, org_id),
                )
                # Auto-complete if sources_responded >= sources_queried (and queried > 0)
                req_row = conn.execute(
                    "SELECT sources_queried, sources_responded FROM enrichment_requests "
                    "WHERE id = ? AND org_id = ?",
                    (request_id, org_id),
                ).fetchone()
                if req_row:
                    sq = req_row["sources_queried"]
                    sr = req_row["sources_responded"]
                    if sq > 0 and sr >= sq:
                        conn.execute(
                            """UPDATE enrichment_requests
                               SET status = 'completed', completed_at = ?
                               WHERE id = ? AND org_id = ? AND status != 'completed'""",
                            (now, request_id, org_id),
                        )

        # Return with malicious as bool-like int
        return record

    def get_enrichment(self, request_id: str, org_id: str) -> Optional[Dict[str, Any]]:
        """Return request dict with nested results list."""
        with self._conn() as conn:
            req_row = conn.execute(
                "SELECT * FROM enrichment_requests WHERE id = ? AND org_id = ?",
                (request_id, org_id),
            ).fetchone()
            if not req_row:
                return None
            result = self._row(req_row)
            res_rows = conn.execute(
                "SELECT * FROM enrichment_results WHERE request_id = ? AND org_id = ? "
                "ORDER BY enriched_at DESC",
                (request_id, org_id),
            ).fetchall()
        results = []
        for r in res_rows:
            rd = self._row(r)
            try:
                rd["tags"] = json.loads(rd.get("tags") or "[]")
            except (json.JSONDecodeError, TypeError):
                rd["tags"] = []
            results.append(rd)
        result["results"] = results
        return result

    def get_indicator_summary(self, org_id: str, indicator: str) -> Dict[str, Any]:
        """Aggregate enrichment results for an indicator across all requests."""
        with self._conn() as conn:
            req_rows = conn.execute(
                "SELECT id FROM enrichment_requests WHERE org_id = ? AND indicator = ?",
                (org_id, indicator),
            ).fetchall()
            request_ids = [r["id"] for r in req_rows]

            if not request_ids:
                return {
                    "indicator": indicator,
                    "org_id": org_id,
                    "avg_reputation_score": None,
                    "malicious": False,
                    "combined_tags": [],
                    "max_confidence": None,
                    "result_count": 0,
                }

            placeholders = ",".join("?" * len(request_ids))
            res_rows = conn.execute(
                f"SELECT reputation_score, malicious, tags, confidence "  # nosec B608
                f"FROM enrichment_results WHERE org_id = ? AND request_id IN ({placeholders})",
                [org_id] + request_ids,
            ).fetchall()

        if not res_rows:
            return {
                "indicator": indicator,
                "org_id": org_id,
                "avg_reputation_score": None,
                "malicious": False,
                "combined_tags": [],
                "max_confidence": None,
                "result_count": 0,
            }

        rep_scores = [r["reputation_score"] for r in res_rows]
        any_malicious = any(r["malicious"] == 1 for r in res_rows)
        max_conf = max(r["confidence"] for r in res_rows)
        all_tags: set = set()
        for r in res_rows:
            try:
                tag_list = json.loads(r["tags"] or "[]")
                all_tags.update(tag_list)
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "indicator": indicator,
            "org_id": org_id,
            "avg_reputation_score": sum(rep_scores) / len(rep_scores),
            "malicious": any_malicious,
            "combined_tags": sorted(all_tags),
            "max_confidence": max_conf,
            "result_count": len(res_rows),
        }

    # ------------------------------------------------------------------
    # Sources
    # ------------------------------------------------------------------

    def register_source(
        self,
        org_id: str,
        source_name: str,
        source_type: str,
        api_key: str = "",
    ) -> Dict[str, Any]:
        """Register a new enrichment source. API key stored as SHA-256 hash."""
        source_name = (source_name or "").strip()
        if not source_name:
            raise ValueError("source_name is required.")
        if source_type not in _VALID_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type: {source_type!r}. "
                f"Must be one of {sorted(_VALID_SOURCE_TYPES)}"
            )
        api_key_hash = hashlib.sha256((api_key or "").encode()).hexdigest() if api_key else ""
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "source_name": source_name,
            "source_type": source_type,
            "enabled": 1,
            "api_key_hash": api_key_hash,
            "request_count": 0,
            "success_rate": 0.0,
            "last_used": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO enrichment_sources
                       (id, org_id, source_name, source_type, enabled, api_key_hash,
                        request_count, success_rate, last_used, created_at)
                       VALUES (:id, :org_id, :source_name, :source_type, :enabled,
                               :api_key_hash, :request_count, :success_rate,
                               :last_used, :created_at)""",
                    record,
                )
        return record

    def update_source_stats(
        self, source_id: str, org_id: str, success: bool
    ) -> Dict[str, Any]:
        """Increment request_count and recompute success_rate."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM enrichment_sources WHERE id = ? AND org_id = ?",
                    (source_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Source not found: {source_id}")

                old_count = row["request_count"]
                old_rate = row["success_rate"]
                new_count = old_count + 1
                # Recompute as running average
                old_successes = round(old_rate * old_count)
                new_successes = old_successes + (1 if success else 0)
                new_rate = new_successes / new_count

                conn.execute(
                    """UPDATE enrichment_sources
                       SET request_count = ?, success_rate = ?, last_used = ?
                       WHERE id = ? AND org_id = ?""",
                    (new_count, new_rate, now, source_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM enrichment_sources WHERE id = ? AND org_id = ?",
                    (source_id, org_id),
                ).fetchone()
        return self._row(updated)

    def list_sources(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List registered enrichment sources."""
        sql = "SELECT * FROM enrichment_sources WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            sql += " AND enabled = ?"
            params.append(1 if enabled else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_enrichment_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated enrichment statistics."""
        with self._conn() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM enrichment_requests WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            completed_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM enrichment_requests "
                "WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()
            pending_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM enrichment_requests "
                "WHERE org_id = ? AND status = 'pending'",
                (org_id,),
            ).fetchone()
            avg_row = conn.execute(
                "SELECT AVG(sources_responded) AS avg_sr FROM enrichment_requests "
                "WHERE org_id = ? AND sources_responded > 0",
                (org_id,),
            ).fetchone()
            malicious_rows = conn.execute(
                """SELECT er.indicator_type, COUNT(*) AS cnt
                   FROM enrichment_requests er
                   JOIN enrichment_results res ON res.request_id = er.id
                   WHERE er.org_id = ? AND res.malicious = 1
                   GROUP BY er.indicator_type
                   ORDER BY cnt DESC
                   LIMIT 5""",
                (org_id,),
            ).fetchall()

        top_malicious_types = [
            {"indicator_type": r["indicator_type"], "count": r["cnt"]}
            for r in malicious_rows
        ]
        return {
            "org_id": org_id,
            "total_requests": total_row["cnt"] if total_row else 0,
            "completed": completed_row["cnt"] if completed_row else 0,
            "pending": pending_row["cnt"] if pending_row else 0,
            "avg_sources_per_request": round(avg_row["avg_sr"] or 0.0, 2),
            "top_malicious_types": top_malicious_types,
        }

    # ------------------------------------------------------------------
    # Bulk Enrich
    # ------------------------------------------------------------------

    def bulk_enrich(
        self,
        org_id: str,
        indicators: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Create enrichment requests for a list of indicators.

        Each entry: {"indicator": str, "indicator_type": str, "sources_queried": int}
        Returns list of created request dicts.

        perf fix #3: replaced N serial create_enrichment_request() calls (each
        opening its own connection + RLock acquisition) with a single
        executemany() inside one connection+transaction — O(N) DB round-trips
        → O(1).
        """
        if not indicators:
            return []

        now = _now_iso()
        records = []
        for item in indicators:
            indicator = (item.get("indicator") or "").strip()
            if not indicator:
                raise ValueError("indicator is required.")
            indicator_type = item.get("indicator_type", "ip")
            if indicator_type not in _VALID_INDICATOR_TYPES:
                raise ValueError(
                    f"Invalid indicator_type: {indicator_type!r}. "
                    f"Must be one of {sorted(_VALID_INDICATOR_TYPES)}"
                )
            records.append({
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "indicator": indicator,
                "indicator_type": indicator_type,
                "status": "pending",
                "sources_queried": max(0, int(item.get("sources_queried", 0))),
                "sources_responded": 0,
                "created_at": now,
                "completed_at": None,
            })

        with self._lock:
            with self._conn() as conn:
                conn.executemany(
                    """INSERT INTO enrichment_requests
                       (id, org_id, indicator, indicator_type, status,
                        sources_queried, sources_responded, created_at, completed_at)
                       VALUES (:id, :org_id, :indicator, :indicator_type, :status,
                               :sources_queried, :sources_responded, :created_at, :completed_at)""",
                    records,
                )
        return records
