"""Endpoint Security / EDR Engine — ALDECI.

Track endpoint agents, EDR alerts, and endpoint policies.

Compliance: CIS Controls v8 (Controls 1, 4, 10), NIST SP 800-171 (3.14),
            MITRE ATT&CK (initial access, lateral movement, exfiltration)
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "endpoint_security.db"
)

_VALID_STATUSES = {"active", "inactive"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ALERT_TYPES = {
    "malware",
    "ransomware",
    "lateral_movement",
    "privilege_escalation",
    "data_exfil",
    "policy_violation",
}
_VALID_ALERT_STATUSES = {"open", "investigating", "resolved"}


class EndpointSecurityEngine:
    """SQLite WAL-backed Endpoint Security / EDR engine.

    Thread-safe via RLock. Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS endpoints (
                    endpoint_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    hostname        TEXT NOT NULL,
                    ip              TEXT NOT NULL DEFAULT '',
                    os              TEXT NOT NULL DEFAULT '',
                    agent_version   TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'active',
                    risk_score      INTEGER NOT NULL DEFAULT 0,
                    last_seen       DATETIME NOT NULL,
                    policy_id       TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org_status
                    ON endpoints (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_ep_org_id
                    ON endpoints (org_id, endpoint_id);

                CREATE TABLE IF NOT EXISTS edr_alerts (
                    alert_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    endpoint_id     TEXT NOT NULL,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    alert_type      TEXT NOT NULL DEFAULT 'policy_violation',
                    description     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    resolution_note TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL,
                    resolved_at     DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_alert_org_status
                    ON edr_alerts (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_alert_org_ep
                    ON edr_alerts (org_id, endpoint_id, created_at);

                CREATE TABLE IF NOT EXISTS edr_policies (
                    policy_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    rules           TEXT NOT NULL DEFAULT '{}',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_policy_org
                    ON edr_policies (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _policy_row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        try:
            d["rules"] = json.loads(d.get("rules") or "{}")
        except (json.JSONDecodeError, TypeError):
            d["rules"] = {}
        d["enabled"] = bool(d.get("enabled", 1))
        return d

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Endpoint CRUD
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new endpoint agent. Returns the full endpoint record."""
        endpoint_id = str(uuid.uuid4())
        now = self._now()
        status = data.get("status", "active")
        if status not in _VALID_STATUSES:
            status = "active"
        risk_score = max(0, min(100, int(data.get("risk_score", 0))))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO endpoints
                        (endpoint_id, org_id, hostname, ip, os, agent_version,
                         status, risk_score, last_seen, policy_id, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        endpoint_id,
                        org_id,
                        data.get("hostname", ""),
                        data.get("ip", ""),
                        data.get("os", ""),
                        data.get("agent_version", ""),
                        status,
                        risk_score,
                        data.get("last_seen", now),
                        data.get("policy_id", ""),
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM endpoints WHERE endpoint_id=?", (endpoint_id,)
                ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "endpoint_security", "org_id": org_id, "source_engine": "endpoint_security"})
            except Exception:
                pass

        return self._row(row)

    def list_endpoints(
        self, org_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List endpoints for an org, optionally filtered by status."""
        if status and status not in _VALID_STATUSES:
            status = None

        if status:
            query = "SELECT * FROM endpoints WHERE org_id=? AND status=? ORDER BY hostname ASC"
            params = (org_id, status)
        else:
            query = "SELECT * FROM endpoints WHERE org_id=? ORDER BY hostname ASC"
            params = (org_id,)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_endpoint_status(
        self, org_id: str, endpoint_id: str, status: str
    ) -> bool:
        """Update the status of an endpoint. Returns True if updated."""
        if status not in _VALID_STATUSES:
            return False
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE endpoints SET status=?, last_seen=? WHERE org_id=? AND endpoint_id=?",
                    (status, self._now(), org_id, endpoint_id),
                )
        return cur.rowcount > 0

    def get_endpoint(
        self, org_id: str, endpoint_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single endpoint by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM endpoints WHERE org_id=? AND endpoint_id=?",
                (org_id, endpoint_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Alert CRUD
    # ------------------------------------------------------------------

    def create_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an EDR alert. Returns the full alert record."""
        alert_id = str(uuid.uuid4())
        now = self._now()

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        alert_type = data.get("alert_type", "policy_violation")
        if alert_type not in _VALID_ALERT_TYPES:
            alert_type = "policy_violation"

        status = data.get("status", "open")
        if status not in _VALID_ALERT_STATUSES:
            status = "open"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO edr_alerts
                        (alert_id, org_id, endpoint_id, severity, alert_type,
                         description, status, resolution_note, created_at, resolved_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id,
                        org_id,
                        data.get("endpoint_id", ""),
                        severity,
                        alert_type,
                        data.get("description", ""),
                        status,
                        data.get("resolution_note", ""),
                        data.get("created_at", now),
                        None,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM edr_alerts WHERE alert_id=?", (alert_id,)
                ).fetchone()
        return self._row(row)

    def list_alerts(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List EDR alerts for an org, optionally filtered by status and/or severity."""
        conditions = ["org_id=?"]
        params: list = [org_id]

        if status and status in _VALID_ALERT_STATUSES:
            conditions.append("status=?")
            params.append(status)

        if severity and severity in _VALID_SEVERITIES:
            conditions.append("severity=?")
            params.append(severity)

        where = " AND ".join(conditions)
        query = f"SELECT * FROM edr_alerts WHERE {where} ORDER BY created_at DESC"  # nosec B608

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def resolve_alert(
        self, org_id: str, alert_id: str, resolution_note: str
    ) -> bool:
        """Mark an alert as resolved. Returns True if updated."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE edr_alerts
                    SET status='resolved', resolution_note=?, resolved_at=?
                    WHERE org_id=? AND alert_id=?
                    """,
                    (resolution_note, now, org_id, alert_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an EDR policy. Returns the full policy record."""
        policy_id = str(uuid.uuid4())
        now = self._now()
        rules = data.get("rules", {})
        if not isinstance(rules, dict):
            rules = {}

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO edr_policies
                        (policy_id, org_id, name, description, rules, enabled,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id,
                        org_id,
                        data.get("name", ""),
                        data.get("description", ""),
                        json.dumps(rules),
                        1 if data.get("enabled", True) else 0,
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM edr_policies WHERE policy_id=?", (policy_id,)
                ).fetchone()
        return self._policy_row(row)

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List EDR policies for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM edr_policies WHERE org_id=? ORDER BY name ASC",
                (org_id,),
            ).fetchall()
        return [self._policy_row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_edr_stats(self, org_id: str) -> Dict[str, Any]:
        """Return EDR summary statistics for an org."""
        with self._conn() as conn:
            total_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            inactive_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id=? AND status='inactive'",
                (org_id,),
            ).fetchone()[0]

            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM edr_alerts WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            severity_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM edr_alerts
                WHERE org_id=? AND status != 'resolved'
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()

            total_alerts = conn.execute(
                "SELECT COUNT(*) FROM edr_alerts WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            resolved_alerts = conn.execute(
                "SELECT COUNT(*) FROM edr_alerts WHERE org_id=? AND status='resolved'",
                (org_id,),
            ).fetchone()[0]

        alerts_by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

        # Compliance rate: % of endpoints with no open critical/high alerts
        # Simple proxy: (resolved / total) * 100, or 100 if no alerts
        if total_alerts > 0:
            compliance_rate = round((resolved_alerts / total_alerts) * 100, 1)
        else:
            compliance_rate = 100.0

        return {
            "total_endpoints": total_ep,
            "active": active_ep,
            "inactive": inactive_ep,
            "alerts_open": open_alerts,
            "alerts_by_severity": alerts_by_severity,
            "compliance_rate": compliance_rate,
        }

    # ------------------------------------------------------------------
    # Endpoint timeline
    # ------------------------------------------------------------------

    def get_endpoint_timeline(
        self, org_id: str, endpoint_id: str
    ) -> List[Dict[str, Any]]:
        """Return all alerts for an endpoint, sorted by created_at descending."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM edr_alerts
                WHERE org_id=? AND endpoint_id=?
                ORDER BY created_at DESC
                """,
                (org_id, endpoint_id),
            ).fetchall()
        return [self._row(r) for r in rows]
