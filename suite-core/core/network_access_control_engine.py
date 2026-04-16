"""NetworkAccessControlEngine — ALDECI.

Manages network endpoint enrollment, posture assessment, NAC status enforcement,
and access control policies.

Features:
- Endpoint registration with MAC address, device type, and posture tracking
- 5-check posture assessment (antivirus, firewall, os_patched, disk_encrypted, compliant_software)
- Posture-driven NAC status: allowed / restricted / quarantined
- Policy creation and management
- Stats: total endpoints, by device type, by NAC status, avg posture score, compliant %

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-82 (ICS NAC), CIS Control 1+2, ISO 27001 A.9.1.2.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_access_control.db"
)

VALID_DEVICE_TYPES = frozenset({"workstation", "laptop", "server", "mobile", "iot", "printer", "other"})
VALID_NAC_STATUSES = frozenset({"allowed", "restricted", "quarantined", "blocked"})
VALID_POLICY_ACTIONS = frozenset({"allow", "restrict", "quarantine", "block"})
VALID_APPLIES_TO = frozenset({"all", "workstation", "laptop", "server", "mobile", "iot"})

_POSTURE_CHECKS = ("antivirus", "firewall", "os_patched", "disk_encrypted", "compliant_software")


class NetworkAccessControlEngine:
    """SQLite-backed NAC engine. Thread-safe, multi-tenant."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS nac_endpoints (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    mac_address     TEXT NOT NULL,
                    ip_address      TEXT,
                    device_type     TEXT NOT NULL DEFAULT 'workstation',
                    posture_score   INTEGER NOT NULL DEFAULT 0,
                    posture_status  TEXT NOT NULL DEFAULT 'unknown',
                    nac_status      TEXT NOT NULL DEFAULT 'pending',
                    status_reason   TEXT,
                    assessed_at     TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_nac_ep_org ON nac_endpoints(org_id);

                CREATE TABLE IF NOT EXISTS nac_policies (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    name                  TEXT NOT NULL,
                    required_posture_score INTEGER NOT NULL DEFAULT 80,
                    action                TEXT NOT NULL DEFAULT 'allow',
                    applies_to            TEXT NOT NULL DEFAULT 'all',
                    status                TEXT NOT NULL DEFAULT 'active',
                    created_at            TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_nac_pol_org ON nac_policies(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # ENDPOINTS
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new network endpoint. Returns the endpoint record."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        mac_address = data.get("mac_address", "").strip()
        if not mac_address:
            raise ValueError("mac_address is required")

        device_type = data.get("device_type", "workstation").lower()
        if device_type not in VALID_DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {sorted(VALID_DEVICE_TYPES)}")

        endpoint_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_endpoints
                   (id, org_id, name, mac_address, ip_address, device_type,
                    posture_score, posture_status, nac_status, status_reason,
                    assessed_at, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    endpoint_id, org_id, name, mac_address,
                    data.get("ip_address"), device_type,
                    0, "unknown", "pending", None, None, now, now,
                ),
            )
        _logger.info("nac.endpoint_registered org=%s endpoint_id=%s", org_id, endpoint_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "network_access_control", "org_id": org_id, "source_engine": "network_access_control"})
            except Exception:
                pass

        return self.get_endpoint(org_id, endpoint_id)

    def list_endpoints(
        self,
        org_id: str,
        device_type: Optional[str] = None,
        nac_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List endpoints for org, optionally filtered by device_type or nac_status."""
        query = "SELECT * FROM nac_endpoints WHERE org_id=?"
        params: List[Any] = [org_id]
        if device_type:
            query += " AND device_type=?"
            params.append(device_type)
        if nac_status:
            query += " AND nac_status=?"
            params.append(nac_status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_endpoint(self, org_id: str, endpoint_id: str) -> Dict[str, Any]:
        """Fetch a single endpoint scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM nac_endpoints WHERE org_id=? AND id=?",
                (org_id, endpoint_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Endpoint {endpoint_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # POSTURE ASSESSMENT
    # ------------------------------------------------------------------

    def assess_posture(
        self,
        org_id: str,
        endpoint_id: str,
        posture_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Assess endpoint posture from 5 boolean checks.

        posture_data keys: antivirus, firewall, os_patched, disk_encrypted, compliant_software.
        Score = count of True values * 20 (max 100).
        posture_status: 100=compliant, 60-80=warning, <60=non_compliant.
        nac_status: compliant=allowed, warning=restricted, non_compliant=quarantined.
        """
        # Verify endpoint belongs to org
        self.get_endpoint(org_id, endpoint_id)

        score = sum(20 for check in _POSTURE_CHECKS if posture_data.get(check, False))

        if score == 100:
            posture_status = "compliant"
            nac_status = "allowed"
        elif score >= 60:
            posture_status = "warning"
            nac_status = "restricted"
        else:
            posture_status = "non_compliant"
            nac_status = "quarantined"

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE nac_endpoints
                   SET posture_score=?, posture_status=?, nac_status=?,
                       assessed_at=?, updated_at=?
                   WHERE org_id=? AND id=?""",
                (score, posture_status, nac_status, now, now, org_id, endpoint_id),
            )

        _logger.info(
            "nac.posture_assessed org=%s endpoint_id=%s score=%d status=%s",
            org_id, endpoint_id, score, posture_status,
        )
        return self.get_endpoint(org_id, endpoint_id)

    # ------------------------------------------------------------------
    # NAC STATUS UPDATE
    # ------------------------------------------------------------------

    def update_nac_status(
        self,
        org_id: str,
        endpoint_id: str,
        nac_status: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """Manually update NAC status for an endpoint."""
        if nac_status not in VALID_NAC_STATUSES:
            raise ValueError(f"nac_status must be one of {sorted(VALID_NAC_STATUSES)}")

        # Verify endpoint belongs to org
        self.get_endpoint(org_id, endpoint_id)

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE nac_endpoints
                   SET nac_status=?, status_reason=?, updated_at=?
                   WHERE org_id=? AND id=?""",
                (nac_status, reason, now, org_id, endpoint_id),
            )

        _logger.info("nac.status_updated org=%s endpoint_id=%s nac_status=%s", org_id, endpoint_id, nac_status)
        return self.get_endpoint(org_id, endpoint_id)

    # ------------------------------------------------------------------
    # POLICIES
    # ------------------------------------------------------------------

    def create_nac_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a NAC policy. Returns the policy record."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        required_posture_score = int(data.get("required_posture_score", 80))
        if not (0 <= required_posture_score <= 100):
            raise ValueError("required_posture_score must be between 0 and 100")

        action = data.get("action", "allow").lower()
        if action not in VALID_POLICY_ACTIONS:
            raise ValueError(f"action must be one of {sorted(VALID_POLICY_ACTIONS)}")

        applies_to = data.get("applies_to", "all").lower()
        if applies_to not in VALID_APPLIES_TO:
            raise ValueError(f"applies_to must be one of {sorted(VALID_APPLIES_TO)}")

        policy_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO nac_policies
                   (id, org_id, name, required_posture_score, action, applies_to, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (policy_id, org_id, name, required_posture_score, action, applies_to, "active", now),
            )
        _logger.info("nac.policy_created org=%s policy_id=%s", org_id, policy_id)
        return self._get_policy(org_id, policy_id)

    def list_nac_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List all NAC policies for org_id."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM nac_policies WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def _get_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM nac_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Policy {policy_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_nac_stats(self, org_id: str) -> Dict[str, Any]:
        """Return NAC overview stats for org_id."""
        with self._connect() as conn:
            total_endpoints = conn.execute(
                "SELECT COUNT(*) FROM nac_endpoints WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT device_type, COUNT(*) as cnt FROM nac_endpoints WHERE org_id=? GROUP BY device_type",
                (org_id,),
            ).fetchall()
            by_device_type = {r["device_type"]: r["cnt"] for r in type_rows}

            status_rows = conn.execute(
                "SELECT nac_status, COUNT(*) as cnt FROM nac_endpoints WHERE org_id=? GROUP BY nac_status",
                (org_id,),
            ).fetchall()
            by_nac_status = {r["nac_status"]: r["cnt"] for r in status_rows}

            avg_row = conn.execute(
                "SELECT AVG(posture_score) FROM nac_endpoints WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            avg_posture_score = round(float(avg_row or 0.0), 1)

            compliant_count = conn.execute(
                "SELECT COUNT(*) FROM nac_endpoints WHERE org_id=? AND nac_status='allowed'",
                (org_id,),
            ).fetchone()[0]

            quarantined_count = conn.execute(
                "SELECT COUNT(*) FROM nac_endpoints WHERE org_id=? AND nac_status='quarantined'",
                (org_id,),
            ).fetchone()[0]

        compliant_pct = round(compliant_count / total_endpoints * 100, 1) if total_endpoints > 0 else 0.0

        return {
            "total_endpoints": total_endpoints,
            "by_device_type": by_device_type,
            "by_nac_status": by_nac_status,
            "avg_posture_score": avg_posture_score,
            "compliant_pct": compliant_pct,
            "quarantined_count": quarantined_count,
        }
