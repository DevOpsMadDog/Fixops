"""
Passive DNS Engine — ALDECI.

Tracks historical DNS resolutions for threat hunting:
- Records domain→IP resolution history
- Detects fast-flux patterns (>5 distinct IPs or TTL <300)
- Marks domains as malicious with threat type and confidence
- Checks domain reputation against known threats

Multi-tenant via org_id. Thread-safe via RLock. SQLite WAL for concurrency.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "passive_dns.db"
)

_VALID_RECORD_TYPES = {"A", "AAAA", "MX", "NS", "CNAME", "TXT"}
_VALID_SOURCES = {"sensor", "feed", "query"}
_VALID_THREAT_TYPES = {"c2", "phishing", "malware", "spam", "botnet"}

_FAST_FLUX_IP_THRESHOLD = 5
_FAST_FLUX_TTL_THRESHOLD = 300


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_minus(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


class PassiveDNSEngine:
    """SQLite WAL-backed Passive DNS tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: dns_resolutions, domain_threats.
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
                CREATE TABLE IF NOT EXISTS dns_resolutions (
                    resolution_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL,
                    resolved_ip     TEXT NOT NULL,
                    record_type     TEXT NOT NULL DEFAULT 'A',
                    ttl             INTEGER NOT NULL DEFAULT 3600,
                    first_seen      DATETIME NOT NULL,
                    last_seen       DATETIME NOT NULL,
                    source          TEXT NOT NULL DEFAULT 'query'
                );

                CREATE INDEX IF NOT EXISTS idx_dr_org
                    ON dns_resolutions(org_id);
                CREATE INDEX IF NOT EXISTS idx_dr_domain
                    ON dns_resolutions(org_id, domain);
                CREATE INDEX IF NOT EXISTS idx_dr_ip
                    ON dns_resolutions(org_id, resolved_ip);
                CREATE INDEX IF NOT EXISTS idx_dr_last_seen
                    ON dns_resolutions(org_id, last_seen);

                CREATE TABLE IF NOT EXISTS domain_threats (
                    threat_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    domain          TEXT NOT NULL,
                    threat_type     TEXT NOT NULL,
                    confidence      REAL NOT NULL DEFAULT 0.5,
                    source          TEXT NOT NULL DEFAULT 'manual',
                    iocs            TEXT NOT NULL DEFAULT '[]',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dt_org
                    ON domain_threats(org_id);
                CREATE INDEX IF NOT EXISTS idx_dt_domain
                    ON domain_threats(org_id, domain);
                CREATE INDEX IF NOT EXISTS idx_dt_threat_type
                    ON domain_threats(org_id, threat_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # DNS Resolution CRUD
    # ------------------------------------------------------------------

    def record_resolution(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record or update a DNS resolution for a domain→IP pair."""
        import uuid

        domain = str(data.get("domain", "")).strip().lower()
        resolved_ip = str(data.get("resolved_ip", "")).strip()
        record_type = str(data.get("record_type", "A")).upper()
        ttl = int(data.get("ttl", 3600))
        source = str(data.get("source", "query")).lower()
        first_seen = str(data.get("first_seen", _now()))
        last_seen = str(data.get("last_seen", _now()))

        if not domain:
            raise ValueError("domain is required")
        if not resolved_ip:
            raise ValueError("resolved_ip is required")
        if record_type not in _VALID_RECORD_TYPES:
            raise ValueError(f"record_type must be one of {_VALID_RECORD_TYPES}")
        if source not in _VALID_SOURCES:
            raise ValueError(f"source must be one of {_VALID_SOURCES}")

        with self._lock:
            with self._conn() as conn:
                # Check if this domain+IP pair already exists for this org
                row = conn.execute(
                    "SELECT resolution_id FROM dns_resolutions "
                    "WHERE org_id=? AND domain=? AND resolved_ip=? AND record_type=?",
                    (org_id, domain, resolved_ip, record_type),
                ).fetchone()

                if row:
                    resolution_id = row["resolution_id"]
                    conn.execute(
                        "UPDATE dns_resolutions SET last_seen=?, ttl=?, source=? "
                        "WHERE resolution_id=?",
                        (last_seen, ttl, source, resolution_id),
                    )
                else:
                    resolution_id = str(uuid.uuid4())
                    conn.execute(
                        "INSERT INTO dns_resolutions "
                        "(resolution_id, org_id, domain, resolved_ip, record_type, ttl, first_seen, last_seen, source) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (resolution_id, org_id, domain, resolved_ip, record_type,
                         ttl, first_seen, last_seen, source),
                    )

                rec = conn.execute(
                    "SELECT * FROM dns_resolutions WHERE resolution_id=?",
                    (resolution_id,),
                ).fetchone()
                return dict(rec)

    def list_resolutions(
        self,
        org_id: str,
        domain: Optional[str] = None,
        resolved_ip: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List DNS resolutions with optional domain or IP filter."""
        query = "SELECT * FROM dns_resolutions WHERE org_id=?"
        params: List[Any] = [org_id]

        if domain:
            query += " AND domain=?"
            params.append(domain.strip().lower())
        if resolved_ip:
            query += " AND resolved_ip=?"
            params.append(resolved_ip.strip())

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]

    def get_domain_history(self, org_id: str, domain: str) -> List[Dict[str, Any]]:
        """Return all historical IPs for a domain, ordered by last_seen desc."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM dns_resolutions "
                    "WHERE org_id=? AND domain=? "
                    "ORDER BY last_seen DESC",
                    (org_id, domain.strip().lower()),
                ).fetchall()
                return [dict(r) for r in rows]

    def get_ip_history(self, org_id: str, ip_address: str) -> List[Dict[str, Any]]:
        """Return all domains that ever resolved to this IP."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM dns_resolutions "
                    "WHERE org_id=? AND resolved_ip=? "
                    "ORDER BY last_seen DESC",
                    (org_id, ip_address.strip()),
                ).fetchall()
                return [dict(r) for r in rows]

    def detect_fast_flux(self, org_id: str, domain: str) -> Dict[str, Any]:
        """Detect fast-flux DNS patterns for a domain.

        Fast flux = >5 distinct IPs OR average TTL < 300 seconds.
        Returns {is_fast_flux, distinct_ips, avg_ttl, reason}.
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT COUNT(DISTINCT resolved_ip) AS distinct_ips, "
                    "AVG(ttl) AS avg_ttl "
                    "FROM dns_resolutions "
                    "WHERE org_id=? AND domain=?",
                    (org_id, domain.strip().lower()),
                ).fetchone()

        distinct_ips = row["distinct_ips"] or 0
        avg_ttl = row["avg_ttl"] or 0.0

        reasons = []
        if distinct_ips > _FAST_FLUX_IP_THRESHOLD:
            reasons.append(f"{distinct_ips} distinct IPs exceeds threshold of {_FAST_FLUX_IP_THRESHOLD}")
        if avg_ttl > 0 and avg_ttl < _FAST_FLUX_TTL_THRESHOLD:
            reasons.append(f"avg TTL {avg_ttl:.1f}s is below threshold of {_FAST_FLUX_TTL_THRESHOLD}s")

        is_fast_flux = bool(reasons)
        reason = "; ".join(reasons) if reasons else "No fast-flux indicators detected"

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "passive_dns", "org_id": org_id, "source_engine": "passive_dns"})
            except Exception:
                pass

        return {
            "domain": domain.strip().lower(),
            "is_fast_flux": is_fast_flux,
            "distinct_ips": distinct_ips,
            "avg_ttl": float(avg_ttl),
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Domain Threats
    # ------------------------------------------------------------------

    def add_domain_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Mark a domain as malicious with threat classification."""
        import json
        import uuid

        domain = str(data.get("domain", "")).strip().lower()
        threat_type = str(data.get("threat_type", "")).lower()
        confidence = float(data.get("confidence", 0.5))
        source = str(data.get("source", "manual"))
        iocs = data.get("iocs", [])

        if not domain:
            raise ValueError("domain is required")
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(f"threat_type must be one of {_VALID_THREAT_TYPES}")
        if not (0.0 <= confidence <= 1.0):
            raise ValueError("confidence must be between 0 and 1")

        threat_id = str(uuid.uuid4())
        now = _now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO domain_threats "
                    "(threat_id, org_id, domain, threat_type, confidence, source, iocs, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (threat_id, org_id, domain, threat_type, confidence,
                     source, json.dumps(iocs), now),
                )
                rec = conn.execute(
                    "SELECT * FROM domain_threats WHERE threat_id=?",
                    (threat_id,),
                ).fetchone()
                result = dict(rec)
                result["iocs"] = json.loads(result["iocs"])
                return result

    def list_domain_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        min_confidence: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """List domain threats with optional filters."""
        import json

        query = "SELECT * FROM domain_threats WHERE org_id=?"
        params: List[Any] = [org_id]

        if threat_type:
            query += " AND threat_type=?"
            params.append(threat_type.lower())
        if min_confidence is not None:
            query += " AND confidence>=?"
            params.append(float(min_confidence))

        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
                results = []
                for r in rows:
                    d = dict(r)
                    d["iocs"] = json.loads(d["iocs"])
                    results.append(d)
                return results

    def check_domain_reputation(self, org_id: str, domain: str) -> Dict[str, Any]:
        """Check domain reputation against recorded threats and resolution history."""

        domain = domain.strip().lower()

        with self._lock:
            with self._conn() as conn:
                # Get threats for this domain
                threat_rows = conn.execute(
                    "SELECT threat_type, confidence FROM domain_threats "
                    "WHERE org_id=? AND domain=?",
                    (org_id, domain),
                ).fetchall()

                # Get resolution stats
                res_row = conn.execute(
                    "SELECT COUNT(*) AS cnt, MAX(last_seen) AS last_seen "
                    "FROM dns_resolutions WHERE org_id=? AND domain=?",
                    (org_id, domain),
                ).fetchone()

        threat_types = list({r["threat_type"] for r in threat_rows})
        max_confidence = max((r["confidence"] for r in threat_rows), default=0.0)
        is_malicious = len(threat_rows) > 0

        return {
            "domain": domain,
            "is_malicious": is_malicious,
            "threat_types": threat_types,
            "confidence": max_confidence,
            "resolutions_count": res_row["cnt"] if res_row else 0,
            "last_seen": res_row["last_seen"] if res_row else None,
        }

    # ------------------------------------------------------------------
    # GAP-030: Subsidiary domain discovery
    # ------------------------------------------------------------------

    def find_subsidiary_domains(
        self,
        org_id: str,
        parent_domain: str,
        seed_patterns: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Heuristic discovery of candidate subsidiary domains from pdns records.

        Scans recorded DNS resolutions for the org and returns domains that
        (a) contain the parent-org naming token, or (b) match any supplied
        seed_patterns substring. Returns candidate list with heuristic confidence.
        """
        parent_domain = (parent_domain or "").strip().lower()
        if not parent_domain:
            raise ValueError("parent_domain is required")

        # Extract the naming token (strip TLD / subdomain prefix).
        # e.g. "acmecorp.com" -> "acmecorp"
        token = parent_domain.split(".")[0]
        if not token:
            token = parent_domain

        patterns = [p.strip().lower() for p in (seed_patterns or []) if p and p.strip()]

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT domain FROM dns_resolutions WHERE org_id = ?",
                    (org_id,),
                ).fetchall()

        candidates: List[Dict[str, Any]] = []
        for r in rows:
            d = r["domain"]
            if not d or d == parent_domain:
                continue
            confidence = 0.0
            reasons: List[str] = []
            # (a) Parent naming token embedded in candidate
            if token and token in d:
                confidence = max(confidence, 0.75)
                reasons.append(f"contains parent token '{token}'")
            # (b) Seed pattern match
            for p in patterns:
                if p and p in d:
                    confidence = max(confidence, 0.85)
                    reasons.append(f"matches seed pattern '{p}'")
            # (c) Shares parent apex domain (e.g. acmecorp.co.uk vs parent acmecorp.com)
            #     naive suffix compare on the token portion
            if token and d != parent_domain:
                d_token = d.split(".")[0] if "." in d else d
                if d_token == token:
                    confidence = max(confidence, 0.9)
                    reasons.append("shares parent apex token")
            if confidence > 0.0:
                candidates.append({
                    "domain": d,
                    "confidence": round(confidence, 2),
                    "reasons": reasons,
                    "parent_domain": parent_domain,
                })
        # Deterministic order: highest confidence first, then alpha
        candidates.sort(key=lambda c: (-c["confidence"], c["domain"]))
        return candidates

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_dns_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate DNS statistics for an org."""
        cutoff_24h = _now_minus(24)

        with self._lock:
            with self._conn() as conn:
                res_row = conn.execute(
                    "SELECT "
                    "  COUNT(*) AS total_resolutions, "
                    "  COUNT(DISTINCT domain) AS unique_domains, "
                    "  COUNT(DISTINCT resolved_ip) AS unique_ips "
                    "FROM dns_resolutions WHERE org_id=?",
                    (org_id,),
                ).fetchone()

                threat_row = conn.execute(
                    "SELECT COUNT(DISTINCT domain) AS threat_domains "
                    "FROM domain_threats WHERE org_id=?",
                    (org_id,),
                ).fetchone()

                queries_24h_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM dns_resolutions "
                    "WHERE org_id=? AND last_seen>=?",
                    (org_id, cutoff_24h),
                ).fetchone()

                # Count fast-flux domains (domains with >5 distinct IPs)
                ff_row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM ("
                    "  SELECT domain FROM dns_resolutions "
                    "  WHERE org_id=? "
                    "  GROUP BY domain "
                    "  HAVING COUNT(DISTINCT resolved_ip) > ?"
                    ")",
                    (org_id, _FAST_FLUX_IP_THRESHOLD),
                ).fetchone()

        return {
            "total_resolutions": res_row["total_resolutions"] if res_row else 0,
            "unique_domains": res_row["unique_domains"] if res_row else 0,
            "unique_ips": res_row["unique_ips"] if res_row else 0,
            "threat_domains": threat_row["threat_domains"] if threat_row else 0,
            "fast_flux_detected": ff_row["cnt"] if ff_row else 0,
            "queries_24h": queries_24h_row["cnt"] if queries_24h_row else 0,
        }
