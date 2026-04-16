"""Threat Deception Management Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Decoy asset lifecycle, attacker interaction recording, deception campaign orchestration.
Compliance: NIST CSF DE.AE, ISO/IEC 27001 A.12.1, MITRE ATT&CK Engage
"""

from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_deception_management.db"
)

_VALID_DECOY_TYPES = {"honeypot", "honeytoken", "honeydoc", "fake_service", "canary_endpoint"}
_VALID_INTERACTION_TYPES = {"scan", "login_attempt", "file_access", "network_probe", "data_exfil"}
_VALID_CAMPAIGN_STATUSES = {"active", "paused", "completed"}


class ThreatDeceptionManagementEngine:
    """SQLite WAL-backed Threat Deception Management engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS tdm_decoys (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL DEFAULT '',
                    decoy_type        TEXT NOT NULL DEFAULT 'honeypot',
                    ip_address        TEXT NOT NULL DEFAULT '',
                    port              INTEGER NOT NULL DEFAULT 0,
                    description       TEXT NOT NULL DEFAULT '',
                    active            INTEGER NOT NULL DEFAULT 1,
                    interaction_count INTEGER NOT NULL DEFAULT 0,
                    created_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tdm_decoys_org
                    ON tdm_decoys (org_id, decoy_type, active);

                CREATE TABLE IF NOT EXISTS tdm_interactions (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    decoy_id             TEXT NOT NULL,
                    interaction_type     TEXT NOT NULL DEFAULT 'scan',
                    source_ip            TEXT NOT NULL DEFAULT '',
                    user_agent           TEXT NOT NULL DEFAULT '',
                    payload_preview      TEXT NOT NULL DEFAULT '',
                    attacker_fingerprint TEXT NOT NULL DEFAULT '',
                    occurred_at          DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tdm_interactions_org
                    ON tdm_interactions (org_id, decoy_id, interaction_type);

                CREATE TABLE IF NOT EXISTS tdm_campaigns (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    decoy_ids_json  TEXT NOT NULL DEFAULT '[]',
                    objective       TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'active',
                    started_at      DATETIME,
                    ended_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_tdm_campaigns_org
                    ON tdm_campaigns (org_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    # ------------------------------------------------------------------
    # Decoys
    # ------------------------------------------------------------------

    def create_decoy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new deception decoy asset.

        Required: name
        Optional: decoy_type, ip_address, port, description, active
        """
        name = data.get("name", "")
        if not name:
            raise ValueError("name is required")

        decoy_type = data.get("decoy_type", "honeypot")
        if decoy_type not in _VALID_DECOY_TYPES:
            raise ValueError(f"decoy_type must be one of {_VALID_DECOY_TYPES}")

        decoy_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": decoy_id,
            "org_id": org_id,
            "name": name,
            "decoy_type": decoy_type,
            "ip_address": data.get("ip_address", ""),
            "port": int(data.get("port", 0)),
            "description": data.get("description", ""),
            "active": 1 if data.get("active", True) else 0,
            "interaction_count": 0,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO tdm_decoys
                    (id, org_id, name, decoy_type, ip_address, port,
                     description, active, interaction_count, created_at)
                VALUES
                    (:id, :org_id, :name, :decoy_type, :ip_address, :port,
                     :description, :active, :interaction_count, :created_at)
                """,
                row,
            )
        result = dict(row)
        result["active"] = bool(row["active"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_deception_management", "org_id": org_id, "source_engine": "threat_deception_management"})
            except Exception:
                pass

        return result

    def list_decoys(
        self,
        org_id: str,
        decoy_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List decoys with optional type/active filters."""
        query = "SELECT * FROM tdm_decoys WHERE org_id = ?"
        params: list = [org_id]
        if decoy_type is not None:
            query += " AND decoy_type = ?"
            params.append(decoy_type)
        if active is not None:
            query += " AND active = ?"
            params.append(1 if active else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_decoy(self, org_id: str, decoy_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single decoy by ID with org isolation."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tdm_decoys WHERE id = ? AND org_id = ?",
                (decoy_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    def record_interaction(
        self, org_id: str, decoy_id: str, interaction_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record an attacker interaction with a decoy.

        Required: interaction_type
        Optional: source_ip, user_agent, payload_preview, attacker_fingerprint, occurred_at
        """
        interaction_type = interaction_data.get("interaction_type", "scan")
        if interaction_type not in _VALID_INTERACTION_TYPES:
            raise ValueError(f"interaction_type must be one of {_VALID_INTERACTION_TYPES}")

        interaction_id = str(uuid.uuid4())
        now = self._now()
        occurred_at = interaction_data.get("occurred_at") or now
        row = {
            "id": interaction_id,
            "org_id": org_id,
            "decoy_id": decoy_id,
            "interaction_type": interaction_type,
            "source_ip": interaction_data.get("source_ip", ""),
            "user_agent": interaction_data.get("user_agent", ""),
            "payload_preview": interaction_data.get("payload_preview", ""),
            "attacker_fingerprint": interaction_data.get("attacker_fingerprint", ""),
            "occurred_at": occurred_at,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO tdm_interactions
                    (id, org_id, decoy_id, interaction_type, source_ip,
                     user_agent, payload_preview, attacker_fingerprint, occurred_at)
                VALUES
                    (:id, :org_id, :decoy_id, :interaction_type, :source_ip,
                     :user_agent, :payload_preview, :attacker_fingerprint, :occurred_at)
                """,
                row,
            )
            conn.execute(
                """
                UPDATE tdm_decoys
                SET interaction_count = interaction_count + 1
                WHERE id = ? AND org_id = ?
                """,
                (decoy_id, org_id),
            )
        return dict(row)

    def list_interactions(
        self,
        org_id: str,
        decoy_id: Optional[str] = None,
        interaction_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List interactions with optional filters, ordered by occurred_at DESC."""
        query = "SELECT * FROM tdm_interactions WHERE org_id = ?"
        params: list = [org_id]
        if decoy_id is not None:
            query += " AND decoy_id = ?"
            params.append(decoy_id)
        if interaction_type is not None:
            query += " AND interaction_type = ?"
            params.append(interaction_type)
        query += " ORDER BY occurred_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a deception campaign.

        Required: name
        Optional: description, decoy_ids_json, objective, status, started_at, ended_at
        """
        campaign_id = str(uuid.uuid4())
        now = self._now()
        status = data.get("status", "active")
        if status not in _VALID_CAMPAIGN_STATUSES:
            raise ValueError(f"status must be one of {_VALID_CAMPAIGN_STATUSES}")

        row = {
            "id": campaign_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "decoy_ids_json": data.get("decoy_ids_json", "[]"),
            "objective": data.get("objective", ""),
            "status": status,
            "started_at": data.get("started_at") or now,
            "ended_at": data.get("ended_at"),
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO tdm_campaigns
                    (id, org_id, name, description, decoy_ids_json,
                     objective, status, started_at, ended_at)
                VALUES
                    (:id, :org_id, :name, :description, :decoy_ids_json,
                     :objective, :status, :started_at, :ended_at)
                """,
                row,
            )
        return dict(row)

    def list_campaigns(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List campaigns with optional status filter."""
        query = "SELECT * FROM tdm_campaigns WHERE org_id = ?"
        params: list = [org_id]
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY started_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_deception_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated deception statistics for an org."""
        with self._lock, self._conn() as conn:
            total_decoys = conn.execute(
                "SELECT COUNT(*) FROM tdm_decoys WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_decoys = conn.execute(
                "SELECT COUNT(*) FROM tdm_decoys WHERE org_id = ? AND active = 1", (org_id,)
            ).fetchone()[0]

            total_interactions = conn.execute(
                "SELECT COUNT(*) FROM tdm_interactions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unique_attackers = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM tdm_interactions WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            hottest_row = conn.execute(
                """
                SELECT id, interaction_count
                FROM tdm_decoys
                WHERE org_id = ?
                ORDER BY interaction_count DESC
                LIMIT 1
                """,
                (org_id,),
            ).fetchone()
            hottest_decoy = hottest_row["id"] if hottest_row else None

            type_rows = conn.execute(
                """
                SELECT interaction_type, COUNT(*) AS cnt
                FROM tdm_interactions WHERE org_id = ?
                GROUP BY interaction_type
                """,
                (org_id,),
            ).fetchall()
            by_interaction_type = {r["interaction_type"]: r["cnt"] for r in type_rows}

        return {
            "org_id": org_id,
            "total_decoys": total_decoys,
            "active_decoys": active_decoys,
            "total_interactions": total_interactions,
            "unique_attackers": unique_attackers,
            "hottest_decoy": hottest_decoy,
            "by_interaction_type": by_interaction_type,
        }
