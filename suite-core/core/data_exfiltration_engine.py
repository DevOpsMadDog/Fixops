"""Data Exfiltration Engine — DLP incident, policy, and indicator management for ALDECI.

Manages data exfiltration incidents across multiple channels (email, USB, cloud upload,
print, screenshot, API abuse, network tunnel, removable media), DLP policies, and
detection indicators.

Capabilities:
  - Incident CRUD with 5-state lifecycle (detected→investigating→confirmed/false_positive→remediated)
  - Policy management (block/alert/log/quarantine × data classification × channel)
  - Indicator tracking (keyword/regex/file_type/destination/volume_threshold/time_pattern)
  - Stats aggregation: volume, by type, by status, by classification

Compliance: NIST SP 800-53 SI-12, ISO 27001 A.8.2, GDPR Art 32, PCI-DSS 3.4
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "data_exfiltration.db"
)

_VALID_INCIDENT_TYPES = {
    "email",
    "usb",
    "cloud_upload",
    "print",
    "screenshot",
    "api_abuse",
    "network_tunnel",
    "removable_media",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CLASSIFICATIONS = {"top_secret", "confidential", "internal", "public"}
_VALID_DETECTION_METHODS = {"dlp", "ueba", "network", "endpoint", "manual"}
_VALID_STATUSES = {
    "detected",
    "investigating",
    "confirmed",
    "false_positive",
    "remediated",
}
_VALID_ACTIONS = {"block", "alert", "log", "quarantine"}
_VALID_CHANNELS = {"email", "usb", "cloud", "print", "network", "all"}
_VALID_INDICATOR_TYPES = {
    "keyword",
    "regex",
    "file_type",
    "destination",
    "volume_threshold",
    "time_pattern",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DataExfiltrationEngine:
    """SQLite WAL-backed data exfiltration management engine.

    Thread-safe via RLock. Multi-tenant via org_id filtering on a shared DB.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS exfil_incidents (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    incident_type       TEXT NOT NULL,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    user_id             TEXT NOT NULL DEFAULT '',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    estimated_volume_mb REAL NOT NULL DEFAULT 0.0,
                    destination         TEXT NOT NULL DEFAULT '',
                    detection_method    TEXT NOT NULL DEFAULT 'dlp',
                    status              TEXT NOT NULL DEFAULT 'detected',
                    blocked             INTEGER NOT NULL DEFAULT 0,
                    detected_at         TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ei_org_type
                    ON exfil_incidents (org_id, incident_type, severity);

                CREATE INDEX IF NOT EXISTS idx_ei_org_status
                    ON exfil_incidents (org_id, status);

                CREATE TABLE IF NOT EXISTS exfil_policies (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    policy_name         TEXT NOT NULL,
                    action              TEXT NOT NULL DEFAULT 'alert',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    channel             TEXT NOT NULL DEFAULT 'all',
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org
                    ON exfil_policies (org_id, enabled);

                CREATE TABLE IF NOT EXISTS exfil_indicators (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    incident_id     TEXT NOT NULL DEFAULT '',
                    indicator_type  TEXT NOT NULL,
                    value           TEXT NOT NULL DEFAULT '',
                    confidence_score REAL NOT NULL DEFAULT 50.0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_eind_org
                    ON exfil_indicators (org_id, incident_id, indicator_type);
                """
            )

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "blocked" in d:
            d["blocked"] = bool(d["blocked"])
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def record_incident(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a data exfiltration incident."""
        incident_type = data.get("incident_type", "")
        if incident_type not in _VALID_INCIDENT_TYPES:
            raise ValueError(
                f"Invalid incident_type: {incident_type!r}. Valid: {sorted(_VALID_INCIDENT_TYPES)}"
            )
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. Valid: {sorted(_VALID_SEVERITIES)}"
            )
        data_classification = data.get("data_classification", "internal")
        if data_classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification: {data_classification!r}. Valid: {sorted(_VALID_CLASSIFICATIONS)}"
            )
        detection_method = data.get("detection_method", "dlp")
        if detection_method not in _VALID_DETECTION_METHODS:
            raise ValueError(
                f"Invalid detection_method: {detection_method!r}. Valid: {sorted(_VALID_DETECTION_METHODS)}"
            )
        status = data.get("status", "detected")
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(_VALID_STATUSES)}"
            )

        now = _now_iso()
        incident_id = str(uuid.uuid4())
        blocked = bool(data.get("blocked", False))

        row: Dict[str, Any] = {
            "id": incident_id,
            "org_id": org_id,
            "incident_type": incident_type,
            "severity": severity,
            "user_id": data.get("user_id", ""),
            "data_classification": data_classification,
            "estimated_volume_mb": float(data.get("estimated_volume_mb", 0.0)),
            "destination": data.get("destination", ""),
            "detection_method": detection_method,
            "status": status,
            "blocked": 1 if blocked else 0,
            "detected_at": data.get("detected_at", now),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO exfil_incidents
                   (id, org_id, incident_type, severity, user_id, data_classification,
                    estimated_volume_mb, destination, detection_method, status,
                    blocked, detected_at, created_at)
                   VALUES (:id, :org_id, :incident_type, :severity, :user_id,
                           :data_classification, :estimated_volume_mb, :destination,
                           :detection_method, :status, :blocked, :detected_at, :created_at)""",
                row,
            )
        result = dict(row)
        result["blocked"] = blocked
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "data_exfiltration", "org_id": org_id, "source_engine": "data_exfiltration"})
            except Exception:
                pass

        return result

    def list_incidents(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        incident_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List exfiltration incidents for the org with optional filters."""
        query = "SELECT * FROM exfil_incidents WHERE org_id = ?"
        params: List[Any] = [org_id]
        if severity is not None:
            query += " AND severity = ?"
            params.append(severity)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        if incident_type is not None:
            query += " AND incident_type = ?"
            params.append(incident_type)
        query += " ORDER BY detected_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_incident(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Return a single incident or None (with org isolation)."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM exfil_incidents WHERE id = ? AND org_id = ?",
                (incident_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_incident_status(
        self, org_id: str, incident_id: str, status: str
    ) -> Optional[Dict[str, Any]]:
        """Update incident status. Returns updated record or None if not found."""
        if status not in _VALID_STATUSES:
            raise ValueError(
                f"Invalid status: {status!r}. Valid: {sorted(_VALID_STATUSES)}"
            )
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE exfil_incidents SET status = ? WHERE id = ? AND org_id = ?",
                (status, incident_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM exfil_incidents WHERE id = ? AND org_id = ?",
                (incident_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a DLP policy."""
        action = data.get("action", "alert")
        if action not in _VALID_ACTIONS:
            raise ValueError(
                f"Invalid action: {action!r}. Valid: {sorted(_VALID_ACTIONS)}"
            )
        data_classification = data.get("data_classification", "internal")
        if data_classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid data_classification: {data_classification!r}. Valid: {sorted(_VALID_CLASSIFICATIONS)}"
            )
        channel = data.get("channel", "all")
        if channel not in _VALID_CHANNELS:
            raise ValueError(
                f"Invalid channel: {channel!r}. Valid: {sorted(_VALID_CHANNELS)}"
            )

        now = _now_iso()
        policy_id = str(uuid.uuid4())
        enabled = bool(data.get("enabled", True))

        row: Dict[str, Any] = {
            "id": policy_id,
            "org_id": org_id,
            "policy_name": data.get("policy_name", "Unnamed Policy"),
            "action": action,
            "data_classification": data_classification,
            "channel": channel,
            "enabled": 1 if enabled else 0,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO exfil_policies
                   (id, org_id, policy_name, action, data_classification, channel, enabled, created_at)
                   VALUES (:id, :org_id, :policy_name, :action, :data_classification,
                           :channel, :enabled, :created_at)""",
                row,
            )
        result = dict(row)
        result["enabled"] = enabled
        return result

    def list_policies(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List DLP policies for the org with optional enabled filter."""
        query = "SELECT * FROM exfil_policies WHERE org_id = ?"
        params: List[Any] = [org_id]
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Indicators
    # ------------------------------------------------------------------

    def add_indicator(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an exfiltration indicator. Clamps confidence_score to 0-100."""
        indicator_type = data.get("indicator_type", "")
        if indicator_type not in _VALID_INDICATOR_TYPES:
            raise ValueError(
                f"Invalid indicator_type: {indicator_type!r}. Valid: {sorted(_VALID_INDICATOR_TYPES)}"
            )
        confidence_score = float(data.get("confidence_score", 50.0))
        confidence_score = max(0.0, min(100.0, confidence_score))

        now = _now_iso()
        ind_id = str(uuid.uuid4())

        row: Dict[str, Any] = {
            "id": ind_id,
            "org_id": org_id,
            "incident_id": data.get("incident_id", ""),
            "indicator_type": indicator_type,
            "value": data.get("value", ""),
            "confidence_score": confidence_score,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO exfil_indicators
                   (id, org_id, incident_id, indicator_type, value, confidence_score, created_at)
                   VALUES (:id, :org_id, :incident_id, :indicator_type, :value,
                           :confidence_score, :created_at)""",
                row,
            )
        return dict(row)

    def list_indicators(
        self,
        org_id: str,
        incident_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List indicators for the org with optional incident_id filter."""
        query = "SELECT * FROM exfil_indicators WHERE org_id = ?"
        params: List[Any] = [org_id]
        if incident_id is not None:
            query += " AND incident_id = ?"
            params.append(incident_id)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_exfil_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate data exfiltration statistics for the org."""
        with self._lock, self._conn() as conn:
            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM exfil_incidents WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            confirmed_incidents = conn.execute(
                "SELECT COUNT(*) FROM exfil_incidents WHERE org_id = ? AND status = 'confirmed'",
                (org_id,),
            ).fetchone()[0]

            blocked_incidents = conn.execute(
                "SELECT COUNT(*) FROM exfil_incidents WHERE org_id = ? AND blocked = 1",
                (org_id,),
            ).fetchone()[0]

            critical_incidents = conn.execute(
                "SELECT COUNT(*) FROM exfil_incidents WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            vol_row = conn.execute(
                "SELECT COALESCE(SUM(estimated_volume_mb), 0.0) FROM exfil_incidents WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            total_volume_mb = float(vol_row[0]) if vol_row else 0.0

            by_type_rows = conn.execute(
                "SELECT incident_type, COUNT(*) as cnt FROM exfil_incidents WHERE org_id = ? GROUP BY incident_type",
                (org_id,),
            ).fetchall()

            by_status_rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM exfil_incidents WHERE org_id = ? GROUP BY status",
                (org_id,),
            ).fetchall()

            by_class_rows = conn.execute(
                "SELECT data_classification, COUNT(*) as cnt FROM exfil_incidents WHERE org_id = ? GROUP BY data_classification",
                (org_id,),
            ).fetchall()

        return {
            "org_id": org_id,
            "total_incidents": total_incidents,
            "confirmed_incidents": confirmed_incidents,
            "blocked_incidents": blocked_incidents,
            "critical_incidents": critical_incidents,
            "total_volume_mb": total_volume_mb,
            "by_type": {r["incident_type"]: r["cnt"] for r in by_type_rows},
            "by_status": {r["status"]: r["cnt"] for r in by_status_rows},
            "by_classification": {r["data_classification"]: r["cnt"] for r in by_class_rows},
        }
