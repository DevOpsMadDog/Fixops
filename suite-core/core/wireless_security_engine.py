"""WirelessSecurityEngine — ALDECI.

Manages wireless access points, threat detection, and wireless security posture.

Features:
- Access point registration with band and security protocol classification
- Wireless threat recording (rogue AP, evil twin, deauth, KRACK, PMKID, wardriving, eavesdropping)
- Threat resolution workflow with audit trail
- Stats: total APs, by band, insecure APs, threat counts

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: NIST SP 800-153 (WLAN Security), CIS Control 15 (Wireless Access Control).
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "wireless_security.db"
)

VALID_BANDS = frozenset({"2.4ghz", "5ghz", "6ghz", "dual_band"})
VALID_SECURITY_PROTOCOLS = frozenset({"open", "wep", "wpa", "wpa2", "wpa3"})
VALID_THREAT_TYPES = frozenset({
    "rogue_ap", "evil_twin", "deauth_attack", "krack", "pmkid", "wardriving", "eavesdropping"
})
VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
INSECURE_PROTOCOLS = frozenset({"open", "wep", "wpa"})


class WirelessSecurityEngine:
    """SQLite-backed wireless security engine. Thread-safe, multi-tenant."""

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

                CREATE TABLE IF NOT EXISTS wireless_aps (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    band              TEXT NOT NULL,
                    security_protocol TEXT NOT NULL DEFAULT 'wpa2',
                    ssid              TEXT,
                    bssid             TEXT,
                    location          TEXT,
                    status            TEXT NOT NULL DEFAULT 'active',
                    signal_strength   INTEGER NOT NULL DEFAULT 0,
                    connected_clients INTEGER NOT NULL DEFAULT 0,
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_wap_org ON wireless_aps(org_id);

                CREATE TABLE IF NOT EXISTS wireless_threats (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    ap_id        TEXT,
                    threat_type  TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    bssid        TEXT,
                    description  TEXT,
                    status       TEXT NOT NULL DEFAULT 'detected',
                    detected_at  TEXT NOT NULL,
                    resolved_at  TEXT,
                    resolution   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_wthreat_org ON wireless_threats(org_id);
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
    # ACCESS POINTS
    # ------------------------------------------------------------------

    def register_access_point(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new wireless access point. Returns the AP record."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        band = data.get("band", "").lower()
        if band not in VALID_BANDS:
            raise ValueError(f"band must be one of {sorted(VALID_BANDS)}, got '{band}'")

        security_protocol = data.get("security_protocol", "wpa2").lower()
        if security_protocol not in VALID_SECURITY_PROTOCOLS:
            raise ValueError(
                f"security_protocol must be one of {sorted(VALID_SECURITY_PROTOCOLS)}, "
                f"got '{security_protocol}'"
            )

        ap_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO wireless_aps
                   (id, org_id, name, band, security_protocol, ssid, bssid,
                    location, status, signal_strength, connected_clients, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ap_id, org_id, name, band, security_protocol,
                    data.get("ssid"), data.get("bssid"), data.get("location"),
                    "active", 0, 0, now,
                ),
            )
        _logger.info("wireless.ap_registered org=%s ap_id=%s", org_id, ap_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "wireless_security", "org_id": org_id, "source_engine": "wireless_security"})
            except Exception:
                pass

        return self.get_access_point(org_id, ap_id)

    def list_access_points(
        self,
        org_id: str,
        band: Optional[str] = None,
        security_protocol: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List access points for org, optionally filtered by band or security_protocol."""
        query = "SELECT * FROM wireless_aps WHERE org_id=?"
        params: List[Any] = [org_id]
        if band:
            query += " AND band=?"
            params.append(band)
        if security_protocol:
            query += " AND security_protocol=?"
            params.append(security_protocol)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_access_point(self, org_id: str, ap_id: str) -> Dict[str, Any]:
        """Fetch a single AP scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM wireless_aps WHERE org_id=? AND id=?",
                (org_id, ap_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Access point {ap_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # THREATS
    # ------------------------------------------------------------------

    def record_wireless_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a wireless threat event. Returns the threat record."""
        threat_type = data.get("threat_type", "").lower()
        if threat_type not in VALID_THREAT_TYPES:
            raise ValueError(f"threat_type must be one of {sorted(VALID_THREAT_TYPES)}")

        severity = data.get("severity", "").lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        ap_id = data.get("ap_id")
        if ap_id:
            # Verify AP belongs to org if provided
            self.get_access_point(org_id, ap_id)

        threat_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO wireless_threats
                   (id, org_id, ap_id, threat_type, severity, bssid,
                    description, status, detected_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    threat_id, org_id, ap_id, threat_type, severity,
                    data.get("bssid"), data.get("description"),
                    "detected", now,
                ),
            )
        _logger.info("wireless.threat_recorded org=%s threat_id=%s type=%s", org_id, threat_id, threat_type)
        return self._get_threat(org_id, threat_id)

    def list_wireless_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threats for org, optionally filtered by threat_type or status."""
        query = "SELECT * FROM wireless_threats WHERE org_id=?"
        params: List[Any] = [org_id]
        if threat_type:
            query += " AND threat_type=?"
            params.append(threat_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY detected_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def resolve_threat(
        self,
        org_id: str,
        threat_id: str,
        resolution: str,
    ) -> Dict[str, Any]:
        """Mark a threat as resolved with resolution text."""
        # Verify threat belongs to org
        self._get_threat(org_id, threat_id)
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE wireless_threats
                   SET status=?, resolved_at=?, resolution=?
                   WHERE org_id=? AND id=?""",
                ("resolved", now, resolution, org_id, threat_id),
            )
        _logger.info("wireless.threat_resolved org=%s threat_id=%s", org_id, threat_id)
        return self._get_threat(org_id, threat_id)

    def _get_threat(self, org_id: str, threat_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM wireless_threats WHERE org_id=? AND id=?",
                (org_id, threat_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Threat {threat_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_wireless_stats(self, org_id: str) -> Dict[str, Any]:
        """Return wireless security overview stats for org_id."""
        with self._connect() as conn:
            total_aps = conn.execute(
                "SELECT COUNT(*) FROM wireless_aps WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            band_rows = conn.execute(
                "SELECT band, COUNT(*) as cnt FROM wireless_aps WHERE org_id=? GROUP BY band",
                (org_id,),
            ).fetchall()
            by_band = {r["band"]: r["cnt"] for r in band_rows}

            insecure_aps = conn.execute(
                "SELECT COUNT(*) FROM wireless_aps WHERE org_id=? AND security_protocol IN ('open','wep','wpa')",
                (org_id,),
            ).fetchone()[0]

            total_threats = conn.execute(
                "SELECT COUNT(*) FROM wireless_threats WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_threats = conn.execute(
                "SELECT COUNT(*) FROM wireless_threats WHERE org_id=? AND status='detected'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt FROM wireless_threats WHERE org_id=? GROUP BY threat_type",
                (org_id,),
            ).fetchall()
            by_threat_type = {r["threat_type"]: r["cnt"] for r in type_rows}

        return {
            "total_aps": total_aps,
            "by_band": by_band,
            "insecure_aps": insecure_aps,
            "total_threats": total_threats,
            "open_threats": open_threats,
            "by_threat_type": by_threat_type,
        }
