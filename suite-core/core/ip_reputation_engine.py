"""
IPReputationEngine — ALDECI.

Tracks IP reputation scores, categories (spam/botnet/proxy/tor/scanner/malware),
and maintains a per-org blocklist.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC6.6, NIST SP 800-53 SI-3 (malicious code protection).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ip_reputation.db"
)

VALID_CATEGORIES = frozenset({"spam", "botnet", "proxy", "tor", "scanner", "malware"})

_RISK_THRESHOLDS = {
    "critical": 20,
    "high": 40,
    "medium": 60,
}


def _score_to_risk(score: int) -> str:
    """Map reputation score (0-100, lower=worse) to risk level."""
    if score < _RISK_THRESHOLDS["critical"]:
        return "critical"
    if score < _RISK_THRESHOLDS["high"]:
        return "high"
    if score < _RISK_THRESHOLDS["medium"]:
        return "medium"
    return "low"


class IPReputationEngine:
    """
    SQLite-backed IP reputation tracking engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/ip_reputation.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS ip_reputation (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    ip            TEXT NOT NULL,
                    score         INTEGER NOT NULL DEFAULT 50,
                    categories    TEXT DEFAULT '[]',
                    source        TEXT DEFAULT '',
                    report_count  INTEGER DEFAULT 1,
                    last_seen     DATETIME NOT NULL,
                    created_at    DATETIME NOT NULL,
                    UNIQUE (org_id, ip)
                );

                CREATE INDEX IF NOT EXISTS idx_rep_org_ip
                    ON ip_reputation (org_id, ip);

                CREATE INDEX IF NOT EXISTS idx_rep_org_score
                    ON ip_reputation (org_id, score);

                CREATE TABLE IF NOT EXISTS ip_blocklist (
                    id         TEXT PRIMARY KEY,
                    org_id     TEXT NOT NULL,
                    ip         TEXT NOT NULL,
                    reason     TEXT DEFAULT '',
                    created_at DATETIME NOT NULL,
                    UNIQUE (org_id, ip)
                );

                CREATE INDEX IF NOT EXISTS idx_block_org_ip
                    ON ip_blocklist (org_id, ip);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Reputation Management
    # ------------------------------------------------------------------

    def submit_reputation(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Submit or update an IP reputation entry.

        data keys: ip (required), reputation_score (0-100), categories (list), source.
        Returns the upserted reputation record.
        """
        now = datetime.now(timezone.utc).isoformat()
        ip = data.get("ip", "")
        score = int(data.get("reputation_score", 50))
        score = max(0, min(100, score))
        raw_cats = data.get("categories", [])
        categories = [c for c in raw_cats if c in VALID_CATEGORIES]
        source = data.get("source", "")

        categories_json = json.dumps(categories)

        with self._lock:
            with self._get_conn() as conn:
                existing = conn.execute(
                    "SELECT id, report_count FROM ip_reputation WHERE org_id = ? AND ip = ?",
                    (org_id, ip),
                ).fetchone()

                if existing:
                    rec_id = existing["id"]
                    new_count = existing["report_count"] + 1
                    conn.execute(
                        """
                        UPDATE ip_reputation
                        SET score = ?, categories = ?, source = ?,
                            report_count = ?, last_seen = ?
                        WHERE org_id = ? AND ip = ?
                        """,
                        (score, categories_json, source, new_count, now, org_id, ip),
                    )
                    report_count = new_count
                    created_at = now
                else:
                    rec_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO ip_reputation
                            (id, org_id, ip, score, categories, source,
                             report_count, last_seen, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                        """,
                        (rec_id, org_id, ip, score, categories_json, source, now, now),
                    )
                    report_count = 1
                    created_at = now

        return {
            "id": rec_id,
            "org_id": org_id,
            "ip": ip,
            "score": score,
            "risk_level": _score_to_risk(score),
            "categories": categories,
            "source": source,
            "report_count": report_count,
            "last_seen": now,
            "created_at": created_at,
        }

    def get_reputation(self, org_id: str, ip: str) -> Dict[str, Any]:
        """
        Retrieve reputation info for a single IP.

        Returns dict with ip, score, categories, last_seen, report_count.
        Returns empty dict if not found.
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ip_reputation WHERE org_id = ? AND ip = ?",
                    (org_id, ip),
                ).fetchone()

        if not row:
            return {}

        return {
            "ip": row["ip"],
            "score": row["score"],
            "risk_level": _score_to_risk(row["score"]),
            "categories": json.loads(row["categories"] or "[]"),
            "last_seen": row["last_seen"],
            "report_count": row["report_count"],
            "source": row["source"],
        }

    def bulk_check(self, org_id: str, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Check reputation for multiple IPs at once.

        Returns list of {ip, score, risk_level} for each IP.
        IPs not in the database get score=100 (unknown, low risk).
        """
        if not ips:
            return []

        placeholders = ",".join("?" * len(ips))
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    f"SELECT ip, score FROM ip_reputation WHERE org_id = ? AND ip IN ({placeholders})",  # nosec B608
                    [org_id] + list(ips),
                ).fetchall()

        known = {r["ip"]: r["score"] for r in rows}
        result = []
        for ip in ips:
            score = known.get(ip, 100)
            result.append({"ip": ip, "score": score, "risk_level": _score_to_risk(score)})
        return result

    # ------------------------------------------------------------------
    # Blocklist
    # ------------------------------------------------------------------

    def add_to_blocklist(self, org_id: str, ip: str, reason: str = "") -> Dict[str, Any]:
        """Add an IP to the org blocklist. Returns the blocklist entry."""
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM ip_blocklist WHERE org_id = ? AND ip = ?",
                    (org_id, ip),
                ).fetchone()

                if existing:
                    entry_id = existing["id"]
                    conn.execute(
                        "UPDATE ip_blocklist SET reason = ? WHERE org_id = ? AND ip = ?",
                        (reason, org_id, ip),
                    )
                else:
                    conn.execute(
                        "INSERT INTO ip_blocklist (id, org_id, ip, reason, created_at) VALUES (?, ?, ?, ?, ?)",
                        (entry_id, org_id, ip, reason, now),
                    )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "ip_reputation", "org_id": org_id, "source_engine": "ip_reputation"})
            except Exception:
                pass

        return {"id": entry_id, "org_id": org_id, "ip": ip, "reason": reason, "created_at": now}

    def remove_from_blocklist(self, org_id: str, ip: str) -> Dict[str, Any]:
        """Remove an IP from the org blocklist. Returns {removed: bool, ip: str}."""
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    "DELETE FROM ip_blocklist WHERE org_id = ? AND ip = ?",
                    (org_id, ip),
                )
                removed = cursor.rowcount > 0

        return {"removed": removed, "ip": ip}

    def is_blocked(self, org_id: str, ip: str) -> bool:
        """Return True if the IP is on the org blocklist."""
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT 1 FROM ip_blocklist WHERE org_id = ? AND ip = ? LIMIT 1",
                    (org_id, ip),
                ).fetchone()
        return row is not None

    def get_blocklist(self, org_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Return the org blocklist, most recently added first."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM ip_blocklist WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
                    (org_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_reputation_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return aggregate reputation statistics for the org.

        Keys: total_ips_tracked, blocked_ips, avg_score, by_category.
        """
        with self._lock:
            with self._get_conn() as conn:
                agg = conn.execute(
                    "SELECT COUNT(*) as total, AVG(score) as avg_score FROM ip_reputation WHERE org_id = ?",
                    (org_id,),
                ).fetchone()

                blocked = conn.execute(
                    "SELECT COUNT(*) FROM ip_blocklist WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                all_cats = conn.execute(
                    "SELECT categories FROM ip_reputation WHERE org_id = ?", (org_id,)
                ).fetchall()

        # Count per category
        cat_counts: Dict[str, int] = {c: 0 for c in VALID_CATEGORIES}
        for row in all_cats:
            try:
                cats = json.loads(row["categories"] or "[]")
                for c in cats:
                    if c in cat_counts:
                        cat_counts[c] += 1
            except (json.JSONDecodeError, TypeError):
                pass

        avg = round(float(agg["avg_score"] or 0.0), 2)

        return {
            "total_ips_tracked": agg["total"] or 0,
            "blocked_ips": blocked,
            "avg_score": avg,
            "by_category": cat_counts,
        }
