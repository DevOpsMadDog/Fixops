"""
ThreatGeolocationEngine — ALDECI.

Tracks geographic threat events, detects impossible travel, and manages
country-level block rules for multi-tenant security analysis.

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC6.1, NIST SP 800-53 AC-20 (geographic access control).
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_geolocation.db"
)

EVENT_TYPES = ("login", "scan", "attack", "access")
RISK_LEVELS = ("low", "medium", "high", "critical")

# Approximate km/h max travel speed threshold for impossible travel detection
_MAX_TRAVEL_SPEED_KMH = 900.0  # commercial aircraft top speed


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return great-circle distance in kilometres between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class ThreatGeolocationEngine:
    """
    SQLite-backed geographic threat event tracker.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to .fixops_data/threat_geolocation.db.
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

                CREATE TABLE IF NOT EXISTS geo_events (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    ip           TEXT NOT NULL,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    city         TEXT DEFAULT '',
                    lat          REAL DEFAULT 0.0,
                    lon          REAL DEFAULT 0.0,
                    event_type   TEXT NOT NULL,
                    risk_level   TEXT NOT NULL,
                    user_id      TEXT DEFAULT '',
                    created_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_geo_org_ts
                    ON geo_events (org_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_geo_org_country
                    ON geo_events (org_id, country_code);

                CREATE INDEX IF NOT EXISTS idx_geo_org_risk
                    ON geo_events (org_id, risk_level);

                CREATE TABLE IF NOT EXISTS geo_block_rules (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    country_code TEXT NOT NULL,
                    reason       TEXT DEFAULT '',
                    severity     TEXT DEFAULT 'high',
                    created_at   DATETIME NOT NULL,
                    UNIQUE (org_id, country_code)
                );

                CREATE INDEX IF NOT EXISTS idx_block_org
                    ON geo_block_rules (org_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Geo Events
    # ------------------------------------------------------------------

    def record_geo_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record a geographic threat event.

        Required keys in data: ip, country_code, country_name.
        Optional: city, lat, lon, event_type, risk_level, user_id.

        Returns the created event dict.
        """
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        ip = data.get("ip", "")
        country_code = data.get("country_code", "")
        country_name = data.get("country_name", "")
        city = data.get("city", "")
        lat = float(data.get("lat", 0.0))
        lon = float(data.get("lon", 0.0))
        event_type = data.get("event_type", "access")
        risk_level = data.get("risk_level", "low")
        user_id = data.get("user_id", "")

        if event_type not in EVENT_TYPES:
            event_type = "access"
        if risk_level not in RISK_LEVELS:
            risk_level = "low"

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO geo_events
                        (id, org_id, ip, country_code, country_name, city,
                         lat, lon, event_type, risk_level, user_id, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id, org_id, ip, country_code, country_name, city,
                        lat, lon, event_type, risk_level, user_id, now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_geolocation", "org_id": org_id, "source_engine": "threat_geolocation"})
            except Exception:
                pass

        return {
            "id": event_id,
            "org_id": org_id,
            "ip": ip,
            "country_code": country_code,
            "country_name": country_name,
            "city": city,
            "lat": lat,
            "lon": lon,
            "event_type": event_type,
            "risk_level": risk_level,
            "user_id": user_id,
            "created_at": now,
        }

    def list_geo_events(
        self,
        org_id: str,
        country_code: Optional[str] = None,
        risk_level: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return geo events filtered by optional country_code and/or risk_level."""
        query = "SELECT * FROM geo_events WHERE org_id = ?"
        params: List[Any] = [org_id]

        if country_code:
            query += " AND country_code = ?"
            params.append(country_code)
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [dict(r) for r in rows]

    def get_country_heatmap(
        self, org_id: str, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Aggregate geo events by country for the last N hours.

        Returns list of: {country_code, country_name, event_count, risk_score}.
        risk_score = weighted sum (critical=4, high=3, medium=2, low=1) / event_count * 25.
        """
        since = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).isoformat()

        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT country_code, country_name, risk_level, COUNT(*) as cnt
                    FROM geo_events
                    WHERE org_id = ? AND created_at >= ?
                    GROUP BY country_code, country_name, risk_level
                    ORDER BY country_code
                    """,
                    (org_id, since),
                ).fetchall()

        # Aggregate per country
        agg: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            cc = r["country_code"]
            if cc not in agg:
                agg[cc] = {
                    "country_code": cc,
                    "country_name": r["country_name"],
                    "event_count": 0,
                    "weighted_sum": 0,
                }
            agg[cc]["event_count"] += r["cnt"]
            agg[cc]["weighted_sum"] += weights.get(r["risk_level"], 1) * r["cnt"]

        result = []
        for entry in agg.values():
            ec = entry["event_count"]
            raw_score = (entry["weighted_sum"] / ec) * 25.0 if ec else 0.0
            result.append(
                {
                    "country_code": entry["country_code"],
                    "country_name": entry["country_name"],
                    "event_count": ec,
                    "risk_score": round(min(raw_score, 100.0), 2),
                }
            )

        result.sort(key=lambda x: x["event_count"], reverse=True)
        return result

    def detect_impossible_travel(
        self, org_id: str, user_id: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Detect impossible travel in a list of geo events for a user.

        events: list of dicts with keys: lat, lon, created_at (ISO string).
        Returns: {detected: bool, pairs: list of suspicious event pairs}.
        """
        # Sort by time
        timed: List[Dict[str, Any]] = []
        for e in events:
            try:
                ts = datetime.fromisoformat(e["created_at"].replace("Z", "+00:00"))
                timed.append({**e, "_ts": ts})
            except (KeyError, ValueError):
                continue

        timed.sort(key=lambda x: x["_ts"])

        pairs: List[Dict[str, Any]] = []
        for i in range(len(timed) - 1):
            a, b = timed[i], timed[i + 1]
            dist_km = _haversine_km(
                float(a.get("lat", 0)),
                float(a.get("lon", 0)),
                float(b.get("lat", 0)),
                float(b.get("lon", 0)),
            )
            delta_h = (b["_ts"] - a["_ts"]).total_seconds() / 3600.0
            if delta_h <= 0:
                continue
            speed_kmh = dist_km / delta_h
            if speed_kmh > _MAX_TRAVEL_SPEED_KMH and dist_km > 500:
                pairs.append(
                    {
                        "event_a": {k: v for k, v in a.items() if k != "_ts"},
                        "event_b": {k: v for k, v in b.items() if k != "_ts"},
                        "distance_km": round(dist_km, 1),
                        "time_hours": round(delta_h, 2),
                        "speed_kmh": round(speed_kmh, 1),
                    }
                )

        return {"detected": len(pairs) > 0, "pairs": pairs}

    # ------------------------------------------------------------------
    # Geo Block Rules
    # ------------------------------------------------------------------

    def create_geo_block_rule(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create a country-level block rule.

        data keys: country_code (required), reason, severity.
        Returns the created rule dict.
        """
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        country_code = data.get("country_code", "")
        reason = data.get("reason", "")
        severity = data.get("severity", "high")

        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO geo_block_rules
                        (id, org_id, country_code, reason, severity, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (org_id, country_code) DO UPDATE SET
                        reason = excluded.reason,
                        severity = excluded.severity
                    """,
                    (rule_id, org_id, country_code, reason, severity, now),
                )

        return {
            "id": rule_id,
            "org_id": org_id,
            "country_code": country_code,
            "reason": reason,
            "severity": severity,
            "created_at": now,
        }

    def list_geo_block_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all block rules for the org."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM geo_block_rules WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    def check_ip_allowed(
        self, org_id: str, ip: str, country_code: str
    ) -> Dict[str, Any]:
        """
        Check whether an IP from a given country is allowed under block rules.

        Returns: {allowed: bool, rule_matched: dict or None}.
        """
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    """
                    SELECT * FROM geo_block_rules
                    WHERE org_id = ? AND country_code = ?
                    LIMIT 1
                    """,
                    (org_id, country_code),
                ).fetchone()

        if row:
            return {"allowed": False, "rule_matched": dict(row)}
        return {"allowed": True, "rule_matched": None}

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_geo_stats(self, org_id: str) -> Dict[str, Any]:
        """
        Return summary statistics for the org.

        Keys: total_events, top_countries, blocked_countries, impossible_travel_alerts.
        """
        with self._lock:
            with self._get_conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM geo_events WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                top_rows = conn.execute(
                    """
                    SELECT country_code, country_name, COUNT(*) as cnt
                    FROM geo_events
                    WHERE org_id = ?
                    GROUP BY country_code, country_name
                    ORDER BY cnt DESC
                    LIMIT 5
                    """,
                    (org_id,),
                ).fetchall()

                blocked = conn.execute(
                    "SELECT COUNT(*) FROM geo_block_rules WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

        top_countries = [
            {"country_code": r["country_code"], "country_name": r["country_name"], "event_count": r["cnt"]}
            for r in top_rows
        ]

        return {
            "total_events": total,
            "top_countries": top_countries,
            "blocked_countries": blocked,
            "impossible_travel_alerts": 0,  # computed on demand via detect_impossible_travel
        }
