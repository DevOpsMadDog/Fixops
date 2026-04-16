"""Threat Intelligence Confidence Engine — ALDECI.

IOC confidence scoring and source reliability tracking.

Capabilities:
  - Score IOCs from multiple sources with weighted confidence
  - Track source reliability (confirmed / false positive rates)
  - Expire stale IOCs automatically
  - Multi-tenant via org_id, thread-safe via RLock, SQLite WAL

Compliance: NIST CSF ID.RA-2, MITRE ATT&CK CTI, STIX 2.1
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_intelligence_confidence.db"
)

_VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "asn", "cidr", "user_agent"}
_VALID_THREAT_LEVELS = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"active", "expired", "false_positive", "revoked"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expires_iso(days: int = 30) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _threat_level(score: float) -> str:
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


class ThreatIntelligenceConfidenceEngine:
    """SQLite WAL-backed IOC confidence scoring engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_intelligence_confidence.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ioc_scores (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    ioc_value            TEXT NOT NULL,
                    ioc_type             TEXT NOT NULL DEFAULT 'ip',
                    confidence_score     REAL NOT NULL DEFAULT 0.0,
                    threat_level         TEXT NOT NULL DEFAULT 'low',
                    source_count         INTEGER NOT NULL DEFAULT 0,
                    corroboration_count  INTEGER NOT NULL DEFAULT 0,
                    first_seen           TEXT NOT NULL,
                    last_seen            TEXT NOT NULL,
                    expires_at           TEXT NOT NULL,
                    status               TEXT NOT NULL DEFAULT 'active',
                    created_at           TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS source_reliability (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    source_name          TEXT NOT NULL,
                    reliability_score    REAL NOT NULL DEFAULT 0.5,
                    total_iocs           INTEGER NOT NULL DEFAULT 0,
                    confirmed_iocs       INTEGER NOT NULL DEFAULT 0,
                    false_positive_iocs  INTEGER NOT NULL DEFAULT 0,
                    last_updated         TEXT NOT NULL,
                    created_at           TEXT NOT NULL,
                    UNIQUE(org_id, source_name)
                );

                CREATE TABLE IF NOT EXISTS ioc_corroborations (
                    id              TEXT PRIMARY KEY,
                    ioc_id          TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    source_name     TEXT NOT NULL,
                    confidence      REAL NOT NULL DEFAULT 0.0,
                    corroborated_at TEXT NOT NULL
                );
                """
            )

    # ------------------------------------------------------------------
    # Source reliability helpers
    # ------------------------------------------------------------------

    def _get_or_create_source(self, conn, org_id: str, source_name: str) -> Dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM source_reliability WHERE org_id=? AND source_name=?",
            (org_id, source_name),
        ).fetchone()
        if row:
            return dict(row)
        now = _now_iso()
        sid = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO source_reliability
               (id, org_id, source_name, reliability_score, total_iocs,
                confirmed_iocs, false_positive_iocs, last_updated, created_at)
               VALUES (?,?,?,0.5,0,0,0,?,?)""",
            (sid, org_id, source_name, now, now),
        )
        return {
            "id": sid,
            "org_id": org_id,
            "source_name": source_name,
            "reliability_score": 0.5,
            "total_iocs": 0,
            "confirmed_iocs": 0,
            "false_positive_iocs": 0,
        }

    def _recompute_ioc_confidence(self, conn, ioc_id: str, org_id: str) -> float:
        """Weighted average of corroboration confidences × source reliability."""
        rows = conn.execute(
            """SELECT c.confidence, COALESCE(s.reliability_score, 0.5) AS rel
               FROM ioc_corroborations c
               LEFT JOIN source_reliability s
                 ON s.org_id = c.org_id AND s.source_name = c.source_name
               WHERE c.ioc_id=? AND c.org_id=?""",
            (ioc_id, org_id),
        ).fetchall()
        if not rows:
            return 0.0
        total_weight = sum(r["rel"] for r in rows)
        if total_weight == 0:
            return 0.0
        weighted_sum = sum(r["confidence"] * r["rel"] for r in rows)
        return min(1.0, weighted_sum / total_weight)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score_ioc(
        self,
        org_id: str,
        ioc_value: str,
        ioc_type: str,
        source_name: str,
        source_confidence: float,
    ) -> Dict[str, Any]:
        """Score or re-score an IOC from a source."""
        ioc_type = ioc_type if ioc_type in _VALID_IOC_TYPES else "ip"
        source_confidence = max(0.0, min(1.0, float(source_confidence)))
        now = _now_iso()

        with self._lock, self._conn() as conn:
            # Ensure source exists and get reliability
            src = self._get_or_create_source(conn, org_id, source_name)
            reliability = src["reliability_score"]

            # Bump total_iocs for source
            conn.execute(
                """UPDATE source_reliability
                   SET total_iocs=total_iocs+1, last_updated=?
                   WHERE org_id=? AND source_name=?""",
                (now, org_id, source_name),
            )

            # Check if IOC already exists
            existing = conn.execute(
                "SELECT * FROM ioc_scores WHERE org_id=? AND ioc_value=?",
                (org_id, ioc_value),
            ).fetchone()

            if existing:
                ioc_id = existing["id"]
                # Insert corroboration
                conn.execute(
                    """INSERT INTO ioc_corroborations
                       (id, ioc_id, org_id, source_name, confidence, corroborated_at)
                       VALUES (?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), ioc_id, org_id, source_name, source_confidence, now),
                )
                # Recompute confidence
                new_score = self._recompute_ioc_confidence(conn, ioc_id, org_id)
                level = _threat_level(new_score)
                corr_count = conn.execute(
                    "SELECT COUNT(*) FROM ioc_corroborations WHERE ioc_id=? AND org_id=?",
                    (ioc_id, org_id),
                ).fetchone()[0]
                conn.execute(
                    """UPDATE ioc_scores
                       SET confidence_score=?, threat_level=?, source_count=source_count+1,
                           corroboration_count=?, last_seen=?, expires_at=?
                       WHERE id=?""",
                    (new_score, level, corr_count, now, _expires_iso(), ioc_id),
                )
                row = conn.execute("SELECT * FROM ioc_scores WHERE id=?", (ioc_id,)).fetchone()
            else:
                ioc_id = str(uuid.uuid4())
                initial_score = source_confidence * reliability
                level = _threat_level(initial_score)
                conn.execute(
                    """INSERT INTO ioc_scores
                       (id, org_id, ioc_value, ioc_type, confidence_score, threat_level,
                        source_count, corroboration_count, first_seen, last_seen,
                        expires_at, status, created_at)
                       VALUES (?,?,?,?,?,?,1,0,?,?,?,'active',?)""",
                    (ioc_id, org_id, ioc_value, ioc_type, initial_score, level,
                     now, now, _expires_iso(), now),
                )
                # Insert first corroboration
                conn.execute(
                    """INSERT INTO ioc_corroborations
                       (id, ioc_id, org_id, source_name, confidence, corroborated_at)
                       VALUES (?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), ioc_id, org_id, source_name, source_confidence, now),
                )
                row = conn.execute("SELECT * FROM ioc_scores WHERE id=?", (ioc_id,)).fetchone()

            return dict(row)

    def confirm_ioc(self, ioc_id: str, org_id: str, source_name: str) -> Dict[str, Any]:
        """Mark IOC as confirmed by a source; increase source reliability."""
        now = _now_iso()
        with self._lock, self._conn() as conn:
            self._get_or_create_source(conn, org_id, source_name)
            src = conn.execute(
                "SELECT * FROM source_reliability WHERE org_id=? AND source_name=?",
                (org_id, source_name),
            ).fetchone()
            confirmed = src["confirmed_iocs"] + 1
            total = src["total_iocs"]
            new_reliability = confirmed / max(1, total + 1)
            conn.execute(
                """UPDATE source_reliability
                   SET confirmed_iocs=confirmed_iocs+1, reliability_score=?, last_updated=?
                   WHERE org_id=? AND source_name=?""",
                (new_reliability, now, org_id, source_name),
            )
            row = conn.execute(
                "SELECT * FROM ioc_scores WHERE id=? AND org_id=?", (ioc_id, org_id)
            ).fetchone()
            return dict(row) if row else {"error": "not_found"}

    def report_false_positive(self, ioc_id: str, org_id: str, source_name: str) -> Dict[str, Any]:
        """Mark IOC as false positive; decrease source reliability (floor 0.1)."""
        now = _now_iso()
        with self._lock, self._conn() as conn:
            self._get_or_create_source(conn, org_id, source_name)
            src = conn.execute(
                "SELECT * FROM source_reliability WHERE org_id=? AND source_name=?",
                (org_id, source_name),
            ).fetchone()
            confirmed = src["confirmed_iocs"]
            total = src["total_iocs"]
            fp = src["false_positive_iocs"] + 1
            denom = max(1, total - fp)
            new_reliability = max(0.1, confirmed / denom)
            conn.execute(
                """UPDATE source_reliability
                   SET false_positive_iocs=false_positive_iocs+1, reliability_score=?, last_updated=?
                   WHERE org_id=? AND source_name=?""",
                (new_reliability, now, org_id, source_name),
            )
            conn.execute(
                "UPDATE ioc_scores SET status='false_positive' WHERE id=? AND org_id=?",
                (ioc_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM ioc_scores WHERE id=? AND org_id=?", (ioc_id, org_id)
            ).fetchone()
            return dict(row) if row else {"error": "not_found"}

    def expire_stale_iocs(self, org_id: str) -> int:
        """Expire IOCs past their expires_at date. Returns count expired."""
        now = _now_iso()
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """UPDATE ioc_scores SET status='expired'
                   WHERE org_id=? AND status='active' AND expires_at < ?""",
                (org_id, now),
            )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_intelligence_confidence", "org_id": org_id, "source_engine": "threat_intelligence_confidence"})
            except Exception:
                pass

            return cur.rowcount

    def get_ioc_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary stats: totals, by_type, by_threat_level, active, expired, top10."""
        with self._lock, self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ioc_scores WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            active_count = conn.execute(
                "SELECT COUNT(*) FROM ioc_scores WHERE org_id=? AND status='active'", (org_id,)
            ).fetchone()[0]
            expired_count = conn.execute(
                "SELECT COUNT(*) FROM ioc_scores WHERE org_id=? AND status='expired'", (org_id,)
            ).fetchone()[0]

            by_type = {}
            for row in conn.execute(
                "SELECT ioc_type, COUNT(*) as cnt FROM ioc_scores WHERE org_id=? GROUP BY ioc_type",
                (org_id,),
            ):
                by_type[row["ioc_type"]] = row["cnt"]

            by_threat_level = {}
            for row in conn.execute(
                "SELECT threat_level, COUNT(*) as cnt FROM ioc_scores WHERE org_id=? GROUP BY threat_level",
                (org_id,),
            ):
                by_threat_level[row["threat_level"]] = row["cnt"]

            top10 = [
                dict(r)
                for r in conn.execute(
                    """SELECT * FROM ioc_scores WHERE org_id=? AND status='active'
                       ORDER BY confidence_score DESC LIMIT 10""",
                    (org_id,),
                )
            ]

            return {
                "total": total,
                "active_count": active_count,
                "expired_count": expired_count,
                "by_type": by_type,
                "by_threat_level": by_threat_level,
                "top_10_confidence": top10,
            }

    def get_source_rankings(self, org_id: str) -> List[Dict[str, Any]]:
        """All sources ordered by reliability_score DESC."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM source_reliability WHERE org_id=? ORDER BY reliability_score DESC",
                    (org_id,),
                )
            ]

    def get_high_confidence_iocs(self, org_id: str, min_confidence: float = 0.7) -> List[Dict[str, Any]]:
        """Active IOCs with confidence_score >= min_confidence."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    """SELECT * FROM ioc_scores
                       WHERE org_id=? AND status='active' AND confidence_score >= ?
                       ORDER BY confidence_score DESC""",
                    (org_id, min_confidence),
                )
            ]

    def search_ioc(self, org_id: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Exact match on ioc_value within org."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ioc_scores WHERE org_id=? AND ioc_value=?",
                (org_id, ioc_value),
            ).fetchone()
            return dict(row) if row else None
