"""IP Reputation Scoring Engine.

Tracks and scores IP reputation from findings, threat intel, and historical
activity. Backed by SQLite with multi-tenant support.

ReputationLevel progression:
  CLEAN (0-24) → SUSPICIOUS (25-49) → MALICIOUS (50-74) → BLOCKLISTED (75-100)
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class ReputationLevel(str, Enum):
    """IP reputation classification."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    BLOCKLISTED = "BLOCKLISTED"


def _level_from_score(score: float) -> ReputationLevel:
    """Derive ReputationLevel from numeric score (0-100, higher = worse)."""
    if score >= 75:
        return ReputationLevel.BLOCKLISTED
    if score >= 50:
        return ReputationLevel.MALICIOUS
    if score >= 25:
        return ReputationLevel.SUSPICIOUS
    return ReputationLevel.CLEAN


class IPRecord(BaseModel):
    """Persisted record for a tracked IP address."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: str
    score: float = Field(default=0.0, ge=0.0, le=100.0, description="0=clean, 100=worst")
    level: ReputationLevel = ReputationLevel.CLEAN
    country_code: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    first_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finding_count: int = 0
    threat_intel_hits: int = 0
    blocklist_hits: int = 0
    tags: List[str] = Field(default_factory=list)
    org_id: str


class ReputationFactor(BaseModel):
    """A single weighted factor contributing to a reputation score."""

    name: str
    weight: float = Field(ge=0.0, le=1.0)
    value: float = Field(ge=0.0, le=100.0)
    source: str


# ---------------------------------------------------------------------------
# Built-in blocklist patterns (CIDR ranges / known-bad ranges)
# ---------------------------------------------------------------------------

# Private/reserved ranges are NOT blocklisted — only known-malicious public ranges.
_BUILTIN_BLOCKLIST_CIDRS: List[str] = [
    # Bogon / martian (non-routable that should never originate traffic)
    "0.0.0.0/8",
    "100.64.0.0/10",  # Shared address space
    "192.0.0.0/24",
    "198.18.0.0/15",  # Benchmarking
    "198.51.100.0/24",  # Documentation TEST-NET-2
    "203.0.113.0/24",  # Documentation TEST-NET-3
    "240.0.0.0/4",  # Reserved
    # Known Tor exit node ranges (illustrative - real deployments use live feeds)
    "185.220.101.0/24",  # Tor exit relays
    "185.220.102.0/24",
    "185.220.103.0/24",
    # Known bulletproof hosting ranges
    "5.188.86.0/24",
    "45.142.212.0/24",
    "185.234.218.0/24",
]

# Pre-parse for fast lookup
_BUILTIN_NETWORKS: List[ipaddress.IPv4Network] = []
for _cidr in _BUILTIN_BLOCKLIST_CIDRS:
    try:
        _BUILTIN_NETWORKS.append(ipaddress.IPv4Network(_cidr, strict=False))
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class IPReputationEngine:
    """SQLite-backed IP reputation scoring engine with multi-tenant support."""

    def __init__(self, db_path: str = "data/ip_reputation.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ip_records (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    score REAL NOT NULL DEFAULT 0.0,
                    level TEXT NOT NULL DEFAULT 'CLEAN',
                    country_code TEXT,
                    asn TEXT,
                    isp TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    threat_intel_hits INTEGER NOT NULL DEFAULT 0,
                    blocklist_hits INTEGER NOT NULL DEFAULT 0,
                    tags TEXT NOT NULL DEFAULT '[]',
                    org_id TEXT NOT NULL,
                    UNIQUE(ip_address, org_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ip_org ON ip_records(ip_address, org_id);
                CREATE INDEX IF NOT EXISTS idx_org_level ON ip_records(org_id, level);

                CREATE TABLE IF NOT EXISTS ip_blocklist (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    added_at TEXT NOT NULL,
                    UNIQUE(ip_address, org_id)
                );

                CREATE TABLE IF NOT EXISTS ip_history (
                    id TEXT PRIMARY KEY,
                    ip_address TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT,
                    score_at_event REAL,
                    details TEXT,
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_history_ip ON ip_history(ip_address, org_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _row_to_record(self, row: sqlite3.Row) -> IPRecord:
        return IPRecord(
            id=row["id"],
            ip_address=row["ip_address"],
            score=row["score"],
            level=ReputationLevel(row["level"]),
            country_code=row["country_code"],
            asn=row["asn"],
            isp=row["isp"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            finding_count=row["finding_count"],
            threat_intel_hits=row["threat_intel_hits"],
            blocklist_hits=row["blocklist_hits"],
            tags=json.loads(row["tags"]),
            org_id=row["org_id"],
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _record_history(
        self,
        conn: sqlite3.Connection,
        ip: str,
        org_id: str,
        event_type: str,
        source: Optional[str] = None,
        score: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        conn.execute(
            """INSERT INTO ip_history (id, ip_address, org_id, event_type, source,
               score_at_event, details, recorded_at) VALUES (?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                ip,
                org_id,
                event_type,
                source,
                score,
                json.dumps(details) if details else None,
                self._now(),
            ),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_ip(self, ip: str, source: str, org_id: str) -> IPRecord:
        """Add or update an IP record, then recalculate its score."""
        now = self._now()
        conn = self._get_connection()
        try:
            existing = conn.execute(
                "SELECT * FROM ip_records WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()

            if existing is None:
                record_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO ip_records
                       (id, ip_address, score, level, first_seen, last_seen,
                        finding_count, threat_intel_hits, blocklist_hits, tags, org_id)
                       VALUES (?,?,0.0,'CLEAN',?,?,1,0,0,'[]',?)""",
                    (record_id, ip, now, now, org_id),
                )
            else:
                conn.execute(
                    "UPDATE ip_records SET last_seen=?, finding_count=finding_count+1 WHERE ip_address=? AND org_id=?",
                    (now, ip, org_id),
                )

            self._record_history(conn, ip, org_id, "recorded", source=source)
            conn.commit()
        finally:
            conn.close()

        return self.score_ip(ip, org_id)

    def score_ip(self, ip: str, org_id: str) -> IPRecord:
        """Recalculate reputation score for an IP and persist the result."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM ip_records WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()

            if row is None:
                # Auto-create with zero score
                record_id = str(uuid.uuid4())
                now = self._now()
                conn.execute(
                    """INSERT INTO ip_records
                       (id, ip_address, score, level, first_seen, last_seen,
                        finding_count, threat_intel_hits, blocklist_hits, tags, org_id)
                       VALUES (?,?,0.0,'CLEAN',?,?,0,0,0,'[]',?)""",
                    (record_id, ip, now, now, org_id),
                )
                conn.commit()
                row = conn.execute(
                    "SELECT * FROM ip_records WHERE ip_address=? AND org_id=?",
                    (ip, org_id),
                ).fetchone()

            bl_row = conn.execute(
                "SELECT 1 FROM ip_blocklist WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()
            manual_blocked = bl_row is not None

            factors: List[ReputationFactor] = []

            # Factor: findings
            finding_count = row["finding_count"]
            finding_score = min(finding_count * 10.0, 100.0)
            factors.append(
                ReputationFactor(
                    name="finding_count",
                    weight=0.35,
                    value=finding_score,
                    source="findings",
                )
            )

            # Factor: threat intel hits
            ti_hits = row["threat_intel_hits"]
            ti_score = min(ti_hits * 20.0, 100.0)
            factors.append(
                ReputationFactor(
                    name="threat_intel_hits",
                    weight=0.30,
                    value=ti_score,
                    source="threat_intel",
                )
            )

            # Factor: blocklist hits (external feeds)
            bl_hits = row["blocklist_hits"]
            bl_score = min(bl_hits * 25.0, 100.0)
            factors.append(
                ReputationFactor(
                    name="blocklist_hits",
                    weight=0.25,
                    value=bl_score,
                    source="blocklist_feeds",
                )
            )

            # Factor: built-in CIDR range match
            builtin_hit = self.check_blocklist(ip)
            factors.append(
                ReputationFactor(
                    name="builtin_blocklist",
                    weight=0.10,
                    value=100.0 if builtin_hit else 0.0,
                    source="builtin",
                )
            )

            score = self._calculate_score(factors)

            # Manual block override → max score
            if manual_blocked:
                score = 100.0

            level = _level_from_score(score)

            conn.execute(
                "UPDATE ip_records SET score=?, level=?, last_seen=? WHERE ip_address=? AND org_id=?",
                (score, level.value, self._now(), ip, org_id),
            )
            self._record_history(conn, ip, org_id, "scored", score=score)
            conn.commit()

            row = conn.execute(
                "SELECT * FROM ip_records WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()
            return self._row_to_record(row)
        finally:
            conn.close()

    def get_ip(self, ip: str, org_id: str) -> Optional[IPRecord]:
        """Retrieve a stored IP record without rescoring."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM ip_records WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()
            return self._row_to_record(row) if row else None
        finally:
            conn.close()

    def list_ips(
        self,
        org_id: str,
        level_filter: Optional[ReputationLevel] = None,
        limit: int = 100,
    ) -> List[IPRecord]:
        """List IP records for an org, optionally filtered by level."""
        conn = self._get_connection()
        try:
            if level_filter:
                rows = conn.execute(
                    "SELECT * FROM ip_records WHERE org_id=? AND level=? ORDER BY score DESC LIMIT ?",
                    (org_id, level_filter.value, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM ip_records WHERE org_id=? ORDER BY score DESC LIMIT ?",
                    (org_id, limit),
                ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def get_malicious(self, org_id: str) -> List[IPRecord]:
        """Return all MALICIOUS and BLOCKLISTED IPs for an org."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM ip_records WHERE org_id=? AND level IN ('MALICIOUS','BLOCKLISTED') ORDER BY score DESC",
                (org_id,),
            ).fetchall()
            return [self._row_to_record(r) for r in rows]
        finally:
            conn.close()

    def check_blocklist(self, ip: str) -> bool:
        """Check if an IP matches any built-in known-malicious CIDR range."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            # IPv6 or invalid — not matched by built-in list
            return False
        return any(addr in net for net in _BUILTIN_NETWORKS)

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Return geo/ASN/ISP enrichment for an IP (mock-safe stub).

        In production this would call MaxMind GeoIP2, ipinfo.io, or similar.
        Returns a dict with the fields that would be populated; callers can
        pass the result to record updates.
        """
        # Deterministic mock based on first octet — real enrichment is pluggable
        enrichment: Dict[str, Any] = {
            "ip": ip,
            "country_code": None,
            "asn": None,
            "isp": None,
            "is_tor": False,
            "is_vpn": False,
            "is_datacenter": False,
            "enriched_at": self._now(),
        }
        try:
            addr = ipaddress.IPv4Address(ip)
            first_octet = int(str(addr).split(".")[0])
            # Deterministic mock buckets (illustrative, not real GeoIP)
            if first_octet in range(1, 50):
                enrichment.update({"country_code": "US", "asn": "AS15169", "isp": "Google LLC"})
            elif first_octet in range(50, 100):
                enrichment.update({"country_code": "CN", "asn": "AS4134", "isp": "CHINANET"})
            elif first_octet in range(100, 150):
                enrichment.update({"country_code": "RU", "asn": "AS8359", "isp": "MTS PJSC"})
            elif first_octet in range(150, 200):
                enrichment.update({"country_code": "DE", "asn": "AS3320", "isp": "Deutsche Telekom"})
            else:
                enrichment.update({"country_code": "NL", "asn": "AS20940", "isp": "Akamai"})
            # Flag known Tor-exit range
            enrichment["is_tor"] = any(addr in net for net in _BUILTIN_NETWORKS[:3])
        except ValueError:
            pass
        return enrichment

    def get_ip_history(self, ip: str, org_id: str) -> List[Dict[str, Any]]:
        """Return all recorded events for an IP within an org."""
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM ip_history WHERE ip_address=? AND org_id=? ORDER BY recorded_at DESC",
                (ip, org_id),
            ).fetchall()
            return [
                {
                    "id": r["id"],
                    "event_type": r["event_type"],
                    "source": r["source"],
                    "score_at_event": r["score_at_event"],
                    "details": json.loads(r["details"]) if r["details"] else None,
                    "recorded_at": r["recorded_at"],
                }
                for r in rows
            ]
        finally:
            conn.close()

    def bulk_check(self, ips: List[str], org_id: str) -> List[IPRecord]:
        """Score multiple IPs in one call, auto-creating records as needed."""
        results: List[IPRecord] = []
        for ip in ips:
            existing = self.get_ip(ip, org_id)
            if existing is None:
                record = self.record_ip(ip, source="bulk_check", org_id=org_id)
            else:
                record = self.score_ip(ip, org_id)
            results.append(record)
        return results

    def add_to_blocklist(self, ip: str, reason: str, org_id: str) -> None:
        """Manually add an IP to the org blocklist and force-score it."""
        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT OR REPLACE INTO ip_blocklist (id, ip_address, reason, org_id, added_at)
                   VALUES (?,?,?,?,?)""",
                (str(uuid.uuid4()), ip, reason, org_id, self._now()),
            )
            # Ensure record exists
            existing = conn.execute(
                "SELECT 1 FROM ip_records WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            ).fetchone()
            if existing is None:
                now = self._now()
                conn.execute(
                    """INSERT INTO ip_records
                       (id, ip_address, score, level, first_seen, last_seen,
                        finding_count, threat_intel_hits, blocklist_hits, tags, org_id)
                       VALUES (?,?,0.0,'CLEAN',?,?,0,0,0,'[]',?)""",
                    (str(uuid.uuid4()), ip, now, now, org_id),
                )
            self._record_history(
                conn, ip, org_id, "blocklisted", details={"reason": reason}
            )
            conn.commit()
        finally:
            conn.close()
        # Rescore to BLOCKLISTED
        self.score_ip(ip, org_id)

    def remove_from_blocklist(self, ip: str, org_id: str) -> None:
        """Remove an IP from the manual blocklist and rescore."""
        conn = self._get_connection()
        try:
            conn.execute(
                "DELETE FROM ip_blocklist WHERE ip_address=? AND org_id=?",
                (ip, org_id),
            )
            self._record_history(conn, ip, org_id, "unblocked")
            conn.commit()
        finally:
            conn.close()
        self.score_ip(ip, org_id)

    def get_reputation_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate reputation statistics for an org."""
        conn = self._get_connection()
        try:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM ip_records WHERE org_id=?", (org_id,)
            ).fetchone()["cnt"]

            by_level = {}
            for level in ReputationLevel:
                cnt = conn.execute(
                    "SELECT COUNT(*) as cnt FROM ip_records WHERE org_id=? AND level=?",
                    (org_id, level.value),
                ).fetchone()["cnt"]
                by_level[level.value] = cnt

            avg_score_row = conn.execute(
                "SELECT AVG(score) as avg_score FROM ip_records WHERE org_id=?",
                (org_id,),
            ).fetchone()
            avg_score = avg_score_row["avg_score"] or 0.0

            blocklist_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM ip_blocklist WHERE org_id=?", (org_id,)
            ).fetchone()["cnt"]

            top_malicious = conn.execute(
                """SELECT ip_address, score FROM ip_records
                   WHERE org_id=? AND level IN ('MALICIOUS','BLOCKLISTED')
                   ORDER BY score DESC LIMIT 5""",
                (org_id,),
            ).fetchall()

            return {
                "total_tracked": total,
                "by_level": by_level,
                "average_score": round(avg_score, 2),
                "manual_blocklist_count": blocklist_count,
                "top_malicious": [
                    {"ip": r["ip_address"], "score": r["score"]} for r in top_malicious
                ],
            }
        finally:
            conn.close()

    def _calculate_score(self, factors: List[ReputationFactor]) -> float:
        """Weighted average of factor values, clamped to [0, 100]."""
        if not factors:
            return 0.0
        total_weight = sum(f.weight for f in factors)
        if total_weight == 0.0:
            return 0.0
        weighted_sum = sum(f.weight * f.value for f in factors)
        score = weighted_sum / total_weight
        return max(0.0, min(100.0, score))
