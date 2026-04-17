"""ThreatActorTrackingEngine — ALDECI.

Monitors specific threat actors targeting the organization: observed activities,
targeting patterns, intelligence, and defensive recommendations.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
Compliance: MITRE ATT&CK, STIX 2.1, NIST SP 800-150.
"""

from __future__ import annotations

import contextlib
import json
import logging
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


logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_actor_tracking.db"
)

ACTOR_TYPES = frozenset({
    "nation-state", "criminal", "hacktivist", "insider",
    "espionage", "ransomware", "apt", "unknown",
})
THREAT_LEVELS = frozenset({"critical", "high", "medium", "low", "monitoring"})
ACTIVITY_TYPES = frozenset({
    "campaign", "attack", "reconnaissance", "data-theft",
    "infrastructure-setup", "tool-release", "exploitation",
})
INTEL_TYPES = frozenset({"technical", "strategic", "operational", "tactical", "contextual"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatActorTrackingEngine:
    """SQLite WAL-backed threat actor tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self):
        @contextlib.contextmanager
        def _ctx():
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()
        return _ctx()

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS tracked_actors (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    actor_name              TEXT NOT NULL,
                    actor_alias             TEXT NOT NULL DEFAULT '',
                    nation_state            TEXT NOT NULL DEFAULT '',
                    actor_type              TEXT NOT NULL DEFAULT 'unknown',
                    threat_level            TEXT NOT NULL DEFAULT 'medium',
                    targeting_our_sector    INTEGER NOT NULL DEFAULT 0,
                    first_tracked           TEXT NOT NULL,
                    last_activity           TEXT,
                    attribution_confidence  REAL NOT NULL DEFAULT 0.5,
                    mitre_groups            TEXT NOT NULL DEFAULT '[]',
                    created_at              TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS actor_activities (
                    id                  TEXT PRIMARY KEY,
                    actor_id            TEXT NOT NULL,
                    org_id              TEXT NOT NULL,
                    activity_type       TEXT NOT NULL DEFAULT 'campaign',
                    description         TEXT NOT NULL DEFAULT '',
                    affected_sectors    TEXT NOT NULL DEFAULT '',
                    ttps_used           TEXT NOT NULL DEFAULT '[]',
                    indicators          TEXT NOT NULL DEFAULT '[]',
                    observed_at         TEXT NOT NULL,
                    source              TEXT NOT NULL DEFAULT '',
                    verified            INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS actor_intelligence (
                    id          TEXT PRIMARY KEY,
                    actor_id    TEXT NOT NULL,
                    org_id      TEXT NOT NULL,
                    intel_type  TEXT NOT NULL DEFAULT 'technical',
                    content     TEXT NOT NULL DEFAULT '',
                    confidence  REAL NOT NULL DEFAULT 0.5,
                    source      TEXT NOT NULL DEFAULT '',
                    valid_until TEXT,
                    created_at  TEXT NOT NULL
                );
            """)

    @staticmethod
    def _row_to_dict(row) -> Dict[str, Any]:
        if not row:
            return {}
        d = dict(row)
        # Deserialize JSON fields for actor rows
        for field in ("mitre_groups", "ttps_used", "indicators"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track_actor(
        self,
        org_id: str,
        actor_name: str,
        actor_alias: str = "",
        nation_state: str = "",
        actor_type: str = "unknown",
        threat_level: str = "medium",
        targeting_our_sector: bool = False,
        mitre_groups: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a new threat actor for tracking."""
        actor_id = str(uuid.uuid4())
        now = _now()
        mitre_json = json.dumps(mitre_groups or [])
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO tracked_actors
                   (id, org_id, actor_name, actor_alias, nation_state, actor_type,
                    threat_level, targeting_our_sector, first_tracked, last_activity,
                    attribution_confidence, mitre_groups, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,NULL,0.5,?,?)""",
                (actor_id, org_id, actor_name, actor_alias, nation_state, actor_type,
                 threat_level, 1 if targeting_our_sector else 0, now, mitre_json, now),
            )
            row = conn.execute(
                "SELECT * FROM tracked_actors WHERE id=?", (actor_id,)
            ).fetchone()
        return self._row_to_dict(row)

    def update_actor_activity(self, actor_id: str, org_id: str) -> Dict[str, Any]:
        """Update last_activity timestamp for an actor."""
        now = _now()
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE tracked_actors SET last_activity=? WHERE id=? AND org_id=?",
                (now, actor_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM tracked_actors WHERE id=? AND org_id=?",
                (actor_id, org_id),
            ).fetchone()
        return self._row_to_dict(row)

    def record_activity(
        self,
        actor_id: str,
        org_id: str,
        activity_type: str,
        description: str = "",
        affected_sectors: str = "",
        ttps_used: Optional[List[str]] = None,
        indicators: Optional[List[str]] = None,
        source: str = "",
        verified: bool = False,
    ) -> Dict[str, Any]:
        """Record an observed activity for a threat actor."""
        activity_id = str(uuid.uuid4())
        now = _now()
        ttps_json = json.dumps(ttps_used or [])
        indicators_json = json.dumps(indicators or [])
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO actor_activities
                   (id, actor_id, org_id, activity_type, description, affected_sectors,
                    ttps_used, indicators, observed_at, source, verified, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (activity_id, actor_id, org_id, activity_type, description,
                 affected_sectors, ttps_json, indicators_json, now, source,
                 1 if verified else 0, now),
            )
            # Update actor last_activity
            conn.execute(
                "UPDATE tracked_actors SET last_activity=? WHERE id=? AND org_id=?",
                (now, actor_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM actor_activities WHERE id=?", (activity_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("THREAT_DETECTED", {"entity_type": "threat_actor_tracking_engine", "org_id": org_id, "source_engine": "threat_actor_tracking_engine"})
            except Exception:
                pass
        return self._row_to_dict(row)

    def add_intelligence(
        self,
        actor_id: str,
        org_id: str,
        intel_type: str,
        content: str,
        confidence: float,
        source: str = "",
        valid_until: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add intelligence entry for a threat actor. Confidence clamped 0-1."""
        intel_id = str(uuid.uuid4())
        now = _now()
        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO actor_intelligence
                   (id, actor_id, org_id, intel_type, content, confidence,
                    source, valid_until, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (intel_id, actor_id, org_id, intel_type, content, confidence,
                 source, valid_until, now),
            )
            row = conn.execute(
                "SELECT * FROM actor_intelligence WHERE id=?", (intel_id,)
            ).fetchone()
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("THREAT_DETECTED", {"entity_type": "threat_actor_tracking_engine", "org_id": org_id, "source_engine": "threat_actor_tracking_engine"})
            except Exception:
                pass
        return self._row_to_dict(row)

    def get_actor(self, actor_id: str, org_id: str) -> Dict[str, Any]:
        """Get actor with recent activities (last 10) and all intelligence."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tracked_actors WHERE id=? AND org_id=?",
                (actor_id, org_id),
            ).fetchone()
            if not row:
                return {}
            result = self._row_to_dict(row)

            activities = conn.execute(
                """SELECT * FROM actor_activities WHERE actor_id=? AND org_id=?
                   ORDER BY observed_at DESC LIMIT 10""",
                (actor_id, org_id),
            ).fetchall()
            result["recent_activities"] = [self._row_to_dict(a) for a in activities]

            intelligence = conn.execute(
                "SELECT * FROM actor_intelligence WHERE actor_id=? AND org_id=? ORDER BY created_at DESC",
                (actor_id, org_id),
            ).fetchall()
            result["intelligence"] = [self._row_to_dict(i) for i in intelligence]
        return result

    def list_actors(
        self,
        org_id: str,
        actor_type: Optional[str] = None,
        threat_level: Optional[str] = None,
        targeting_our_sector: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List tracked actors with optional filters."""
        query = "SELECT * FROM tracked_actors WHERE org_id=?"
        params: List[Any] = [org_id]
        if actor_type is not None:
            query += " AND actor_type=?"
            params.append(actor_type)
        if threat_level is not None:
            query += " AND threat_level=?"
            params.append(threat_level)
        if targeting_our_sector is not None:
            query += " AND targeting_our_sector=?"
            params.append(1 if targeting_our_sector else 0)
        query += " ORDER BY created_at DESC"

        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_active_threats(self, org_id: str) -> List[Dict[str, Any]]:
        """Get actors with last_activity within the past 90 days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM tracked_actors
                   WHERE org_id=? AND last_activity IS NOT NULL AND last_activity >= ?
                   ORDER BY last_activity DESC""",
                (org_id, cutoff),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_actor_ttp_summary(self, org_id: str) -> Dict[str, Any]:
        """Aggregate TTPs across all actors, frequency count per TTP, top 10."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT ttps_used FROM actor_activities WHERE org_id=?",
                (org_id,),
            ).fetchall()

        ttp_counts: Dict[str, int] = {}
        for row in rows:
            ttps_raw = row["ttps_used"] if isinstance(row, sqlite3.Row) else row[0]
            try:
                ttps = json.loads(ttps_raw) if isinstance(ttps_raw, str) else ttps_raw
                if isinstance(ttps, list):
                    for ttp in ttps:
                        ttp_counts[ttp] = ttp_counts.get(ttp, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass

        sorted_ttps = sorted(ttp_counts.items(), key=lambda x: x[1], reverse=True)
        top_10 = [{"ttp": t, "count": c} for t, c in sorted_ttps[:10]]

        return {
            "org_id": org_id,
            "total_unique_ttps": len(ttp_counts),
            "ttp_frequency": ttp_counts,
            "most_common_ttps": top_10,
        }

    def get_tracking_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: total tracked, by threat_level, targeting_our_sector, active (90d), nation_state."""
        cutoff_90 = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        with self._lock, self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as cnt FROM tracked_actors WHERE org_id=?", (org_id,)
            ).fetchone()["cnt"]

            level_rows = conn.execute(
                "SELECT threat_level, COUNT(*) as cnt FROM tracked_actors WHERE org_id=? GROUP BY threat_level",
                (org_id,),
            ).fetchall()
            by_threat_level = {r["threat_level"]: r["cnt"] for r in level_rows}

            targeting_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM tracked_actors WHERE org_id=? AND targeting_our_sector=1",
                (org_id,),
            ).fetchone()["cnt"]

            active_count = conn.execute(
                """SELECT COUNT(*) as cnt FROM tracked_actors
                   WHERE org_id=? AND last_activity IS NOT NULL AND last_activity >= ?""",
                (org_id, cutoff_90),
            ).fetchone()["cnt"]

            nation_rows = conn.execute(
                """SELECT nation_state, COUNT(*) as cnt FROM tracked_actors
                   WHERE org_id=? AND nation_state != ''
                   GROUP BY nation_state""",
                (org_id,),
            ).fetchall()
            nation_breakdown = {r["nation_state"]: r["cnt"] for r in nation_rows}

        return {
            "org_id": org_id,
            "total_tracked": total,
            "by_threat_level": by_threat_level,
            "targeting_our_sector": targeting_count,
            "active_last_90_days": active_count,
            "nation_state_breakdown": nation_breakdown,
        }
