"""Deception Analytics Engine — ALDECI.

Deception asset management (honeypots, canary tokens, lure documents),
interaction recording, attacker profiling, and campaign orchestration.

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "deception_analytics.db"
)

_VALID_ASSET_TYPES = {
    "honeypot", "honeytoken", "canary_file", "canary_cred",
    "fake_service", "honey_user", "lure_document", "breadcrumb",
}
_VALID_DECOY_CATEGORIES = {"network", "endpoint", "cloud", "identity", "data", "application"}
_VALID_TECHNIQUES = {
    "recon", "lateral_movement", "credential_access", "execution",
    "persistence", "exfiltration", "discovery", "collection", "impact",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_OBJECTIVES = {
    "early_detection", "attacker_profiling", "threat_intelligence",
    "honeypot_network", "insider_threat",
}
_VALID_CAMPAIGN_STATUSES = {"active", "paused", "completed"}


class DeceptionAnalyticsEngine:
    """SQLite WAL-backed Deception Analytics engine.

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
                CREATE TABLE IF NOT EXISTS da_assets (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    asset_name        TEXT NOT NULL DEFAULT '',
                    asset_type        TEXT NOT NULL DEFAULT 'honeypot',
                    location          TEXT NOT NULL DEFAULT '',
                    decoy_category    TEXT NOT NULL DEFAULT 'network',
                    active            INTEGER NOT NULL DEFAULT 1,
                    interaction_count INTEGER NOT NULL DEFAULT 0,
                    last_interaction  TEXT,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_da_assets_org
                    ON da_assets (org_id, asset_type, active);

                CREATE TABLE IF NOT EXISTS da_interactions (
                    id                     TEXT PRIMARY KEY,
                    org_id                 TEXT NOT NULL,
                    asset_id               TEXT NOT NULL,
                    source_ip              TEXT NOT NULL DEFAULT '',
                    attacker_technique     TEXT NOT NULL DEFAULT 'recon',
                    confidence_score       REAL NOT NULL DEFAULT 0.0,
                    threat_actor_signature TEXT NOT NULL DEFAULT '',
                    severity               TEXT NOT NULL DEFAULT 'medium',
                    details                TEXT NOT NULL DEFAULT '',
                    detected_at            TEXT NOT NULL,
                    created_at             TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_da_interactions_org
                    ON da_interactions (org_id, asset_id, severity);

                CREATE TABLE IF NOT EXISTS da_campaigns (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    campaign_name       TEXT NOT NULL DEFAULT '',
                    objective           TEXT NOT NULL DEFAULT 'early_detection',
                    asset_count         INTEGER NOT NULL DEFAULT 0,
                    interaction_count   INTEGER NOT NULL DEFAULT 0,
                    unique_attacker_ips INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'active',
                    started_at          TEXT,
                    ended_at            TEXT,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_da_campaigns_org
                    ON da_campaigns (org_id, status);
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
    def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
        return max(lo, min(hi, float(value)))

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "active" in d:
            d["active"] = bool(d["active"])
        return d

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new deception asset.

        Required keys: asset_name
        Optional: asset_type, location, decoy_category, active
        """
        asset_type = data.get("asset_type", "honeypot")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"asset_type must be one of {_VALID_ASSET_TYPES}")

        decoy_category = data.get("decoy_category", "network")
        if decoy_category not in _VALID_DECOY_CATEGORIES:
            raise ValueError(f"decoy_category must be one of {_VALID_DECOY_CATEGORIES}")

        asset_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": asset_id,
            "org_id": org_id,
            "asset_name": data.get("asset_name", ""),
            "asset_type": asset_type,
            "location": data.get("location", ""),
            "decoy_category": decoy_category,
            "active": 1 if data.get("active", True) else 0,
            "interaction_count": 0,
            "last_interaction": None,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO da_assets
                    (id, org_id, asset_name, asset_type, location, decoy_category,
                     active, interaction_count, last_interaction, created_at)
                VALUES
                    (:id, :org_id, :asset_name, :asset_type, :location, :decoy_category,
                     :active, :interaction_count, :last_interaction, :created_at)
                """,
                row,
            )
        result = dict(row)
        result["active"] = bool(row["active"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "deception_analytics", "org_id": org_id, "source_engine": "deception_analytics"})
            except Exception:
                pass

        return result

    def list_assets(
        self,
        org_id: str,
        asset_type: Optional[str] = None,
        active: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List deception assets with optional filters."""
        query = "SELECT * FROM da_assets WHERE org_id = ?"
        params: list = [org_id]
        if asset_type:
            query += " AND asset_type = ?"
            params.append(asset_type)
        if active is not None:
            query += " AND active = ?"
            params.append(1 if active else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single asset by ID with org isolation."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM da_assets WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def deactivate_asset(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Deactivate a deception asset.

        Raises KeyError if not found.
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE da_assets SET active = 0 WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM da_assets WHERE id = ? AND org_id = ?",
                (asset_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Asset {asset_id} not found for org {org_id}")
        return self._row(row)

    # ------------------------------------------------------------------
    # Interactions
    # ------------------------------------------------------------------

    def record_interaction(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record an attacker interaction with a deception asset.

        Required keys: asset_id, source_ip
        Optional: attacker_technique, confidence_score, threat_actor_signature,
                  severity, details, detected_at
        """
        attacker_technique = data.get("attacker_technique", "recon")
        if attacker_technique not in _VALID_TECHNIQUES:
            raise ValueError(f"attacker_technique must be one of {_VALID_TECHNIQUES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        interaction_id = str(uuid.uuid4())
        now = self._now()
        detected_at = data.get("detected_at") or now
        row = {
            "id": interaction_id,
            "org_id": org_id,
            "asset_id": data.get("asset_id", ""),
            "source_ip": data.get("source_ip", ""),
            "attacker_technique": attacker_technique,
            "confidence_score": self._clamp(data.get("confidence_score", 0.0)),
            "threat_actor_signature": data.get("threat_actor_signature", ""),
            "severity": severity,
            "details": data.get("details", ""),
            "detected_at": detected_at,
            "created_at": now,
        }
        asset_id = row["asset_id"]
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO da_interactions
                    (id, org_id, asset_id, source_ip, attacker_technique,
                     confidence_score, threat_actor_signature, severity,
                     details, detected_at, created_at)
                VALUES
                    (:id, :org_id, :asset_id, :source_ip, :attacker_technique,
                     :confidence_score, :threat_actor_signature, :severity,
                     :details, :detected_at, :created_at)
                """,
                row,
            )
            # Update asset interaction count and last_interaction
            conn.execute(
                """
                UPDATE da_assets
                SET interaction_count = interaction_count + 1,
                    last_interaction  = ?
                WHERE id = ? AND org_id = ?
                """,
                (now, asset_id, org_id),
            )
        return dict(row)

    def list_interactions(
        self,
        org_id: str,
        asset_id: Optional[str] = None,
        severity: Optional[str] = None,
        attacker_technique: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List interactions with optional filters."""
        query = "SELECT * FROM da_interactions WHERE org_id = ?"
        params: list = [org_id]
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if attacker_technique:
            query += " AND attacker_technique = ?"
            params.append(attacker_technique)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a deception campaign.

        Required keys: campaign_name
        Optional: objective, started_at, ended_at, status
        """
        objective = data.get("objective", "early_detection")
        if objective not in _VALID_OBJECTIVES:
            raise ValueError(f"objective must be one of {_VALID_OBJECTIVES}")

        campaign_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": campaign_id,
            "org_id": org_id,
            "campaign_name": data.get("campaign_name", ""),
            "objective": objective,
            "asset_count": 0,
            "interaction_count": 0,
            "unique_attacker_ips": 0,
            "status": "active",
            "started_at": data.get("started_at"),
            "ended_at": data.get("ended_at"),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO da_campaigns
                    (id, org_id, campaign_name, objective, asset_count,
                     interaction_count, unique_attacker_ips, status,
                     started_at, ended_at, created_at)
                VALUES
                    (:id, :org_id, :campaign_name, :objective, :asset_count,
                     :interaction_count, :unique_attacker_ips, :status,
                     :started_at, :ended_at, :created_at)
                """,
                row,
            )
        return dict(row)

    def update_campaign_stats(
        self,
        org_id: str,
        campaign_id: str,
        asset_count: Optional[int] = None,
        interaction_count: Optional[int] = None,
        unique_attacker_ips: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Update campaign statistics (non-None fields only).

        Raises KeyError if campaign not found.
        """
        updates = []
        params: list = []
        if asset_count is not None:
            updates.append("asset_count = ?")
            params.append(asset_count)
        if interaction_count is not None:
            updates.append("interaction_count = ?")
            params.append(interaction_count)
        if unique_attacker_ips is not None:
            updates.append("unique_attacker_ips = ?")
            params.append(unique_attacker_ips)

        with self._lock, self._conn() as conn:
            if updates:
                params.extend([campaign_id, org_id])
                conn.execute(
                    f"UPDATE da_campaigns SET {', '.join(updates)} WHERE id = ? AND org_id = ?",  # nosec B608
                    params,
                )
            row = conn.execute(
                "SELECT * FROM da_campaigns WHERE id = ? AND org_id = ?",
                (campaign_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Campaign {campaign_id} not found for org {org_id}")
        return dict(row)

    def list_campaigns(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List campaigns with optional status filter."""
        query = "SELECT * FROM da_campaigns WHERE org_id = ?"
        params: list = [org_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_deception_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated deception statistics for an org."""
        with self._lock, self._conn() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM da_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            active_assets = conn.execute(
                "SELECT COUNT(*) FROM da_assets WHERE org_id = ? AND active = 1", (org_id,)
            ).fetchone()[0]

            total_interactions = conn.execute(
                "SELECT COUNT(*) FROM da_interactions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            unique_ips = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM da_interactions WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]

            critical_interactions = conn.execute(
                "SELECT COUNT(*) FROM da_interactions WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            total_campaigns = conn.execute(
                "SELECT COUNT(*) FROM da_campaigns WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            at_rows = conn.execute(
                """
                SELECT asset_type, COUNT(*) AS cnt
                FROM da_assets WHERE org_id = ?
                GROUP BY asset_type
                """,
                (org_id,),
            ).fetchall()
            by_asset_type = {r["asset_type"]: r["cnt"] for r in at_rows}

            tech_rows = conn.execute(
                """
                SELECT attacker_technique, COUNT(*) AS cnt
                FROM da_interactions WHERE org_id = ?
                GROUP BY attacker_technique
                """,
                (org_id,),
            ).fetchall()
            by_attacker_technique = {r["attacker_technique"]: r["cnt"] for r in tech_rows}

            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM da_interactions WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

        return {
            "org_id": org_id,
            "total_assets": total_assets,
            "active_assets": active_assets,
            "total_interactions": total_interactions,
            "unique_attacker_ips": unique_ips,
            "critical_interactions": critical_interactions,
            "total_campaigns": total_campaigns,
            "by_asset_type": by_asset_type,
            "by_attacker_technique": by_attacker_technique,
            "by_severity": by_severity,
        }
