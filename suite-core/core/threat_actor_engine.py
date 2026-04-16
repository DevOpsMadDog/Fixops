"""Threat Actor Engine — ALDECI.

Tracks advanced persistent threats, cybercriminal groups, nation-state actors,
their campaigns, indicators of compromise (IOCs), and watchlist management.

Capabilities:
  - Threat actor registry with MITRE ATT&CK group mapping
  - Campaign tracking with TTP and malware family attribution
  - IOC management (IP, domain, hash, email, URL, mutex, registry)
  - Watchlist with alerting on IOC match
  - Stats aggregation per org

Compliance: MITRE ATT&CK, STIX 2.1, NIST SP 800-150, ISO/IEC 27035
"""

from __future__ import annotations

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

_VALID_ACTOR_TYPES = {
    "nation_state", "cybercriminal", "hacktivist", "insider", "apt", "ransomware_group",
}
_VALID_MOTIVATIONS = {
    "financial", "espionage", "disruption", "ideology", "revenge",
}
_VALID_SOPHISTICATION = {"low", "medium", "high", "advanced"}
_VALID_IMPACT_LEVELS = {"low", "medium", "high", "critical"}
_VALID_CAMPAIGN_STATUSES = {"active", "dormant", "concluded"}
_VALID_IOC_TYPES = {"ip", "domain", "hash", "email", "url", "mutex", "registry"}
_VALID_PRIORITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatActorEngine:
    """SQLite WAL-backed Threat Actor engine.

    Thread-safe via RLock. Multi-tenant via org_id. Each org gets its own DB file.
    """

    def __init__(self, data_dir: str = ".fixops_data") -> None:
        self._data_dir = Path(data_dir)
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        return str(self._data_dir / f"{org_id}_threat_actors.db")

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._locks_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        db_path = self._db_path(org_id)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS actors (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    aliases         TEXT NOT NULL DEFAULT '[]',
                    actor_type      TEXT NOT NULL DEFAULT 'apt',
                    origin_country  TEXT NOT NULL DEFAULT '',
                    motivation      TEXT NOT NULL DEFAULT 'espionage',
                    sophistication  TEXT NOT NULL DEFAULT 'high',
                    first_observed  TEXT NOT NULL DEFAULT '',
                    last_observed   TEXT NOT NULL DEFAULT '',
                    active          INTEGER NOT NULL DEFAULT 1,
                    threat_score    REAL NOT NULL DEFAULT 0.0,
                    mitre_group_id  TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_actors_org_type
                    ON actors (org_id, actor_type);

                CREATE INDEX IF NOT EXISTS idx_actors_org_active
                    ON actors (org_id, active);

                CREATE TABLE IF NOT EXISTS campaigns (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    actor_id        TEXT NOT NULL,
                    campaign_name   TEXT NOT NULL,
                    start_date      TEXT NOT NULL DEFAULT '',
                    end_date        TEXT NOT NULL DEFAULT '',
                    target_sectors  TEXT NOT NULL DEFAULT '[]',
                    target_regions  TEXT NOT NULL DEFAULT '[]',
                    ttps_used       TEXT NOT NULL DEFAULT '[]',
                    malware_families TEXT NOT NULL DEFAULT '[]',
                    status          TEXT NOT NULL DEFAULT 'active',
                    impact_level    TEXT NOT NULL DEFAULT 'medium',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_campaigns_org_actor
                    ON campaigns (org_id, actor_id);

                CREATE INDEX IF NOT EXISTS idx_campaigns_org_status
                    ON campaigns (org_id, status);

                CREATE TABLE IF NOT EXISTS iocs (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    actor_id    TEXT NOT NULL,
                    ioc_type    TEXT NOT NULL DEFAULT 'ip',
                    value       TEXT NOT NULL,
                    confidence  REAL NOT NULL DEFAULT 0.8,
                    first_seen  TEXT NOT NULL DEFAULT '',
                    last_seen   TEXT NOT NULL DEFAULT '',
                    active      INTEGER NOT NULL DEFAULT 1,
                    source      TEXT NOT NULL DEFAULT '',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_iocs_org_actor
                    ON iocs (org_id, actor_id);

                CREATE INDEX IF NOT EXISTS idx_iocs_org_type
                    ON iocs (org_id, ioc_type, active);

                CREATE TABLE IF NOT EXISTS watchlist (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    actor_id          TEXT NOT NULL,
                    added_at          TEXT NOT NULL,
                    added_by          TEXT NOT NULL DEFAULT '',
                    reason            TEXT NOT NULL DEFAULT '',
                    priority          TEXT NOT NULL DEFAULT 'high',
                    alert_on_ioc_match INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_watchlist_org
                    ON watchlist (org_id, actor_id);
                """
            )

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("aliases", "target_sectors", "target_regions", "ttps_used", "malware_families"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "active" in d:
            d["active"] = bool(d["active"])
        if "alert_on_ioc_match" in d:
            d["alert_on_ioc_match"] = bool(d["alert_on_ioc_match"])
        return d

    # ------------------------------------------------------------------
    # Actors
    # ------------------------------------------------------------------

    def add_actor(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new threat actor. Returns the created record."""
        self._ensure_db(org_id)

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        actor_type = data.get("actor_type", "apt")
        if actor_type not in _VALID_ACTOR_TYPES:
            raise ValueError(f"Invalid actor_type: {actor_type}. Must be one of {_VALID_ACTOR_TYPES}")

        motivation = data.get("motivation", "espionage")
        if motivation not in _VALID_MOTIVATIONS:
            raise ValueError(f"Invalid motivation: {motivation}. Must be one of {_VALID_MOTIVATIONS}")

        sophistication = data.get("sophistication", "high")
        if sophistication not in _VALID_SOPHISTICATION:
            raise ValueError(f"Invalid sophistication: {sophistication}. Must be one of {_VALID_SOPHISTICATION}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "aliases": data.get("aliases", []),
            "actor_type": actor_type,
            "origin_country": data.get("origin_country", ""),
            "motivation": motivation,
            "sophistication": sophistication,
            "first_observed": data.get("first_observed", ""),
            "last_observed": data.get("last_observed", ""),
            "active": bool(data.get("active", True)),
            "threat_score": float(data.get("threat_score", 0.0)),
            "mitre_group_id": data.get("mitre_group_id", ""),
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO actors
                       (id, org_id, name, aliases, actor_type, origin_country,
                        motivation, sophistication, first_observed, last_observed,
                        active, threat_score, mitre_group_id, created_at)
                       VALUES (:id, :org_id, :name, :aliases, :actor_type, :origin_country,
                               :motivation, :sophistication, :first_observed, :last_observed,
                               :active, :threat_score, :mitre_group_id, :created_at)""",
                    {**record,
                     "aliases": json.dumps(record["aliases"]),
                     "active": 1 if record["active"] else 0},
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_actor", "org_id": org_id, "source_engine": "threat_actor"})
            except Exception:
                pass

        return record

    def list_actors(
        self,
        org_id: str,
        actor_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List threat actors, optionally filtered by type and/or active status."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM actors WHERE org_id = ?"
        params: list = [org_id]
        if actor_type:
            sql += " AND actor_type = ?"
            params.append(actor_type)
        if active is not None:
            sql += " AND active = ?"
            params.append(1 if active else 0)
        sql += " ORDER BY threat_score DESC, created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_actor(self, org_id: str, actor_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single actor with campaign list and IOC count."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM actors WHERE org_id = ? AND id = ?",
                (org_id, actor_id),
            ).fetchone()
            if not row:
                return None
            actor = self._row(row)

            campaigns = [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM campaigns WHERE org_id = ? AND actor_id = ? ORDER BY created_at DESC",
                    (org_id, actor_id),
                ).fetchall()
            ]
            ioc_count = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE org_id = ? AND actor_id = ?",
                (org_id, actor_id),
            ).fetchone()[0]

        actor["campaigns"] = campaigns
        actor["ioc_count"] = ioc_count
        return actor

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def add_campaign(self, org_id: str, actor_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a campaign attributed to an actor."""
        self._ensure_db(org_id)

        campaign_name = (data.get("campaign_name") or "").strip()
        if not campaign_name:
            raise ValueError("campaign_name is required.")

        status = data.get("status", "active")
        if status not in _VALID_CAMPAIGN_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_CAMPAIGN_STATUSES}")

        impact_level = data.get("impact_level", "medium")
        if impact_level not in _VALID_IMPACT_LEVELS:
            raise ValueError(f"Invalid impact_level: {impact_level}. Must be one of {_VALID_IMPACT_LEVELS}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "actor_id": actor_id,
            "campaign_name": campaign_name,
            "start_date": data.get("start_date", ""),
            "end_date": data.get("end_date", ""),
            "target_sectors": data.get("target_sectors", []),
            "target_regions": data.get("target_regions", []),
            "ttps_used": data.get("ttps_used", []),
            "malware_families": data.get("malware_families", []),
            "status": status,
            "impact_level": impact_level,
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO campaigns
                       (id, org_id, actor_id, campaign_name, start_date, end_date,
                        target_sectors, target_regions, ttps_used, malware_families,
                        status, impact_level, created_at)
                       VALUES (:id, :org_id, :actor_id, :campaign_name, :start_date, :end_date,
                               :target_sectors, :target_regions, :ttps_used, :malware_families,
                               :status, :impact_level, :created_at)""",
                    {**record,
                     "target_sectors": json.dumps(record["target_sectors"]),
                     "target_regions": json.dumps(record["target_regions"]),
                     "ttps_used": json.dumps(record["ttps_used"]),
                     "malware_families": json.dumps(record["malware_families"])},
                )
        return record

    def list_campaigns(
        self,
        org_id: str,
        actor_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List campaigns with optional actor_id and/or status filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM campaigns WHERE org_id = ?"
        params: list = [org_id]
        if actor_id:
            sql += " AND actor_id = ?"
            params.append(actor_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def add_ioc(self, org_id: str, actor_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an IOC attributed to an actor."""
        self._ensure_db(org_id)

        ioc_type = data.get("ioc_type", "ip")
        if ioc_type not in _VALID_IOC_TYPES:
            raise ValueError(f"Invalid ioc_type: {ioc_type}. Must be one of {_VALID_IOC_TYPES}")

        value = (data.get("value") or "").strip()
        if not value:
            raise ValueError("value is required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "actor_id": actor_id,
            "ioc_type": ioc_type,
            "value": value,
            "confidence": float(data.get("confidence", 0.8)),
            "first_seen": data.get("first_seen", now),
            "last_seen": data.get("last_seen", now),
            "active": bool(data.get("active", True)),
            "source": data.get("source", ""),
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO iocs
                       (id, org_id, actor_id, ioc_type, value, confidence,
                        first_seen, last_seen, active, source, created_at)
                       VALUES (:id, :org_id, :actor_id, :ioc_type, :value, :confidence,
                               :first_seen, :last_seen, :active, :source, :created_at)""",
                    {**record, "active": 1 if record["active"] else 0},
                )
        return record

    def list_iocs(
        self,
        org_id: str,
        actor_id: Optional[str] = None,
        ioc_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List IOCs with optional filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM iocs WHERE org_id = ?"
        params: list = [org_id]
        if actor_id:
            sql += " AND actor_id = ?"
            params.append(actor_id)
        if ioc_type:
            sql += " AND ioc_type = ?"
            params.append(ioc_type)
        if active is not None:
            sql += " AND active = ?"
            params.append(1 if active else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Watchlist
    # ------------------------------------------------------------------

    def add_to_watchlist(self, org_id: str, actor_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an actor to the org watchlist."""
        self._ensure_db(org_id)

        priority = data.get("priority", "high")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}. Must be one of {_VALID_PRIORITIES}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "actor_id": actor_id,
            "added_at": now,
            "added_by": data.get("added_by", ""),
            "reason": data.get("reason", ""),
            "priority": priority,
            "alert_on_ioc_match": bool(data.get("alert_on_ioc_match", True)),
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO watchlist
                       (id, org_id, actor_id, added_at, added_by, reason, priority, alert_on_ioc_match)
                       VALUES (:id, :org_id, :actor_id, :added_at, :added_by, :reason,
                               :priority, :alert_on_ioc_match)""",
                    {**record, "alert_on_ioc_match": 1 if record["alert_on_ioc_match"] else 0},
                )
        return record

    def get_watchlist(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all watchlist entries for the org, ordered by priority."""
        self._ensure_db(org_id)
        priority_order = "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    f"SELECT * FROM watchlist WHERE org_id = ? ORDER BY {priority_order}, added_at DESC",  # nosec B608
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated threat actor stats for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            actor_count = conn.execute(
                "SELECT COUNT(*) FROM actors WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_campaigns = conn.execute(
                "SELECT COUNT(*) FROM campaigns WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            total_iocs = conn.execute(
                "SELECT COUNT(*) FROM iocs WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            watchlist_size = conn.execute(
                "SELECT COUNT(*) FROM watchlist WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # By sophistication
            soph_rows = conn.execute(
                """SELECT sophistication, COUNT(*) as cnt
                   FROM actors WHERE org_id = ?
                   GROUP BY sophistication""",
                (org_id,),
            ).fetchall()
            by_sophistication = {r["sophistication"]: r["cnt"] for r in soph_rows}

            # Top targeted sectors across all campaigns
            sector_rows = conn.execute(
                "SELECT target_sectors FROM campaigns WHERE org_id = ?",
                (org_id,),
            ).fetchall()
            sector_counts: Dict[str, int] = {}
            for r in sector_rows:
                try:
                    sectors = json.loads(r["target_sectors"]) if isinstance(r["target_sectors"], str) else r["target_sectors"]
                    for s in (sectors or []):
                        sector_counts[s] = sector_counts.get(s, 0) + 1
                except (json.JSONDecodeError, TypeError):
                    pass
            top_targeted_sectors = sorted(sector_counts.items(), key=lambda x: -x[1])[:5]
            top_targeted_sectors = [{"sector": k, "count": v} for k, v in top_targeted_sectors]

        return {
            "actor_count": actor_count,
            "active_campaigns": active_campaigns,
            "total_iocs": total_iocs,
            "watchlist_size": watchlist_size,
            "by_sophistication": by_sophistication,
            "top_targeted_sectors": top_targeted_sectors,
        }
