"""Threat Attribution Engine — ALDECI.

Tracks threat actors, manages attribution of incidents to actors,
and records supporting indicators (TTPs, IOCs, infrastructure, malware, victimology).

Capabilities:
  - Threat actor registry with type, sophistication, origin, motivation
  - Attribution lifecycle: investigating → attributed / disputed / closed
  - Indicator recording per attribution
  - Stats: actor counts, attribution totals, by actor type, nation-state count

Compliance: NIST CSF RS.AN-1, ISO 27001 A.5.7, MITRE ATT&CK Attribution
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_attribution.db"
)

_VALID_ACTOR_TYPES = {
    "nation_state", "criminal_group", "hacktivist", "insider", "competitor", "unknown"
}

_VALID_CONFIDENCE = {"confirmed", "likely", "possible", "unlikely"}

_VALID_ATTRIBUTION_STATUSES = {"investigating", "attributed", "disputed", "closed"}

_VALID_INDICATOR_TYPES = {"ttps", "iocs", "infrastructure", "malware", "victimology"}

_VALID_SOPHISTICATION = {"advanced", "moderate", "basic"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatAttributionEngine:
    """SQLite WAL-backed Threat Attribution engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_attribution.db
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
                CREATE TABLE IF NOT EXISTS ta_actors (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    actor_type      TEXT NOT NULL DEFAULT 'unknown',
                    aliases_json    TEXT NOT NULL DEFAULT '[]',
                    origin_country  TEXT NOT NULL DEFAULT '',
                    motivation      TEXT NOT NULL DEFAULT '',
                    sophistication  TEXT NOT NULL DEFAULT 'basic',
                    active          INTEGER NOT NULL DEFAULT 1,
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ta_actors_org
                    ON ta_actors (org_id, actor_type, active, created_at DESC);

                CREATE TABLE IF NOT EXISTS ta_attributions (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    incident_id      TEXT NOT NULL DEFAULT '',
                    actor_id         TEXT NOT NULL DEFAULT '',
                    confidence       TEXT NOT NULL DEFAULT 'possible',
                    status           TEXT NOT NULL DEFAULT 'investigating',
                    evidence_json    TEXT NOT NULL DEFAULT '{}',
                    analyst          TEXT NOT NULL DEFAULT '',
                    attribution_date DATETIME,
                    notes            TEXT NOT NULL DEFAULT '',
                    created_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ta_attributions_org
                    ON ta_attributions (org_id, status, confidence, created_at DESC);

                CREATE TABLE IF NOT EXISTS ta_indicators (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    attribution_id  TEXT NOT NULL,
                    indicator_type  TEXT NOT NULL DEFAULT 'iocs',
                    value           TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    first_seen      DATETIME,
                    last_seen       DATETIME,
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_ta_indicators_org
                    ON ta_indicators (org_id, attribution_id, indicator_type, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def create_threat_actor(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new threat actor record."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required for a threat actor.")

        actor_type = data.get("actor_type", "unknown")
        if actor_type not in _VALID_ACTOR_TYPES:
            raise ValueError(
                f"Invalid actor_type: {actor_type!r}. Must be one of {sorted(_VALID_ACTOR_TYPES)}"
            )

        sophistication = data.get("sophistication", "basic")
        if sophistication not in _VALID_SOPHISTICATION:
            sophistication = "basic"

        aliases = data.get("aliases", [])
        if isinstance(aliases, str):
            aliases = [aliases]

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "actor_type": actor_type,
            "aliases_json": json.dumps(aliases),
            "origin_country": (data.get("origin_country") or "").strip(),
            "motivation": (data.get("motivation") or "").strip(),
            "sophistication": sophistication,
            "active": 1 if data.get("active", True) else 0,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ta_actors
                       (id, org_id, name, actor_type, aliases_json, origin_country,
                        motivation, sophistication, active, created_at)
                       VALUES (:id, :org_id, :name, :actor_type, :aliases_json, :origin_country,
                               :motivation, :sophistication, :active, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_attribution", "org_id": org_id, "source_engine": "threat_attribution"})
            except Exception:
                pass

        return record

    def list_threat_actors(
        self,
        org_id: str,
        actor_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List threat actors with optional filters."""
        query = "SELECT * FROM ta_actors WHERE org_id = ?"
        params: List[Any] = [org_id]

        if actor_type is not None:
            query += " AND actor_type = ?"
            params.append(actor_type)
        if active is not None:
            query += " AND active = ?"
            params.append(1 if active else 0)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_threat_actor(self, org_id: str, actor_id: str) -> Optional[Dict[str, Any]]:
        """Get a single threat actor by id (org-isolated)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM ta_actors WHERE id = ? AND org_id = ?",
                (actor_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Attributions
    # ------------------------------------------------------------------

    def create_attribution(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new attribution linking an incident to a threat actor."""
        incident_id = (data.get("incident_id") or "").strip()
        if not incident_id:
            raise ValueError("incident_id is required for an attribution.")

        confidence = data.get("confidence", "possible")
        if confidence not in _VALID_CONFIDENCE:
            raise ValueError(
                f"Invalid confidence: {confidence!r}. Must be one of {sorted(_VALID_CONFIDENCE)}"
            )

        evidence = data.get("evidence", data.get("evidence_json", {}))
        if isinstance(evidence, dict):
            evidence_json = json.dumps(evidence)
        else:
            evidence_json = str(evidence)

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "incident_id": incident_id,
            "actor_id": (data.get("actor_id") or "").strip(),
            "confidence": confidence,
            "status": "investigating",
            "evidence_json": evidence_json,
            "analyst": (data.get("analyst") or "").strip(),
            "attribution_date": data.get("attribution_date"),
            "notes": (data.get("notes") or "").strip(),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ta_attributions
                       (id, org_id, incident_id, actor_id, confidence, status,
                        evidence_json, analyst, attribution_date, notes, created_at)
                       VALUES (:id, :org_id, :incident_id, :actor_id, :confidence, :status,
                               :evidence_json, :analyst, :attribution_date, :notes, :created_at)""",
                    record,
                )
        return record

    def update_attribution_status(
        self,
        org_id: str,
        attribution_id: str,
        status: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Update the status (and optionally notes) of an attribution."""
        if status not in _VALID_ATTRIBUTION_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Must be one of {sorted(_VALID_ATTRIBUTION_STATUSES)}"
            )

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM ta_attributions WHERE id = ? AND org_id = ?",
                    (attribution_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(
                        f"Attribution {attribution_id!r} not found for org {org_id!r}"
                    )

                if notes:
                    conn.execute(
                        "UPDATE ta_attributions SET status=?, notes=? WHERE id=? AND org_id=?",
                        (status, notes, attribution_id, org_id),
                    )
                else:
                    conn.execute(
                        "UPDATE ta_attributions SET status=? WHERE id=? AND org_id=?",
                        (status, attribution_id, org_id),
                    )

                updated = conn.execute(
                    "SELECT * FROM ta_attributions WHERE id = ? AND org_id = ?",
                    (attribution_id, org_id),
                ).fetchone()
        return self._row(updated)

    def list_attributions(
        self,
        org_id: str,
        status: Optional[str] = None,
        confidence: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List attributions with optional filters."""
        query = "SELECT * FROM ta_attributions WHERE org_id = ?"
        params: List[Any] = [org_id]

        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if confidence is not None:
            query += " AND confidence = ?"
            params.append(confidence)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def add_indicator(
        self, org_id: str, attribution_id: str, indicator_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an indicator to an attribution."""
        indicator_type = indicator_data.get("indicator_type", "iocs")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type: {indicator_type!r}. "
                f"Must be one of {sorted(_VALID_INDICATOR_TYPES)}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "attribution_id": attribution_id,
            "indicator_type": indicator_type,
            "value": (indicator_data.get("value") or "").strip(),
            "description": (indicator_data.get("description") or "").strip(),
            "first_seen": indicator_data.get("first_seen"),
            "last_seen": indicator_data.get("last_seen"),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO ta_indicators
                       (id, org_id, attribution_id, indicator_type, value, description,
                        first_seen, last_seen, created_at)
                       VALUES (:id, :org_id, :attribution_id, :indicator_type, :value, :description,
                               :first_seen, :last_seen, :created_at)""",
                    record,
                )
        return record

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_attribution_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate threat attribution statistics."""
        with self._conn() as conn:
            actor_totals = conn.execute(
                """SELECT
                       COUNT(*) as total_actors,
                       SUM(CASE WHEN active=1 THEN 1 ELSE 0 END) as active_actors
                   FROM ta_actors WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            attr_totals = conn.execute(
                """SELECT
                       COUNT(*) as total_attributions,
                       SUM(CASE WHEN confidence='confirmed' THEN 1 ELSE 0 END) as confirmed_attributions
                   FROM ta_attributions WHERE org_id = ?""",
                (org_id,),
            ).fetchone()

            by_type_rows = conn.execute(
                """SELECT actor_type, COUNT(*) as cnt
                   FROM ta_actors WHERE org_id = ? GROUP BY actor_type""",
                (org_id,),
            ).fetchall()

            ns_count = conn.execute(
                "SELECT COUNT(*) as cnt FROM ta_actors WHERE org_id = ? AND actor_type='nation_state'",
                (org_id,),
            ).fetchone()

        return {
            "total_actors": actor_totals["total_actors"] or 0,
            "active_actors": actor_totals["active_actors"] or 0,
            "total_attributions": attr_totals["total_attributions"] or 0,
            "confirmed_attributions": attr_totals["confirmed_attributions"] or 0,
            "by_actor_type": {r["actor_type"]: r["cnt"] for r in by_type_rows},
            "nation_state_count": ns_count["cnt"] or 0,
        }
