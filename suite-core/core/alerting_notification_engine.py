"""Alerting & Notification Engine — ALDECI.

Policy-driven alert management with multi-channel delivery (email, Slack,
PagerDuty, webhook), full alert lifecycle (trigger → acknowledge → resolve),
and MTTR statistics.

Compliance: NIST CSF DE.AE, ISO/IEC 27001 A.16.1, SOC 2 CC7.2
"""

from __future__ import annotations

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


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "alerting_notification.db"
)

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_CONDITION_TYPES = {"threshold", "anomaly", "pattern", "schedule"}
_VALID_CHANNELS = {"email", "slack", "pagerduty", "webhook"}
_VALID_STATUSES = {"open", "acknowledged", "resolved"}


class AlertingNotificationEngine:
    """SQLite WAL-backed Alerting & Notification engine.

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
                CREATE TABLE IF NOT EXISTS alert_policies (
                    policy_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL DEFAULT '',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    condition_type TEXT NOT NULL DEFAULT 'threshold',
                    channels       TEXT NOT NULL DEFAULT '[]',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    created_at     TEXT NOT NULL,
                    updated_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ap_org
                    ON alert_policies (org_id, enabled);

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_id       TEXT NOT NULL DEFAULT '',
                    source_engine   TEXT NOT NULL DEFAULT '',
                    source_id       TEXT NOT NULL DEFAULT '',
                    title           TEXT NOT NULL DEFAULT '',
                    message         TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    context         TEXT NOT NULL DEFAULT '{}',
                    acknowledged_by TEXT,
                    acknowledged_at TEXT,
                    resolved_by     TEXT,
                    resolved_at     TEXT,
                    resolution      TEXT,
                    triggered_at    TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_org
                    ON alerts (org_id, severity, status);

                CREATE INDEX IF NOT EXISTS idx_alerts_policy
                    ON alerts (org_id, policy_id);
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
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("channels", "context"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    # ------------------------------------------------------------------
    # Alert Policies
    # ------------------------------------------------------------------

    def create_alert_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert policy.

        Required keys: name
        Optional keys: severity, condition_type, channels, enabled
        """
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        condition_type = data.get("condition_type", "threshold")
        if condition_type not in _VALID_CONDITION_TYPES:
            raise ValueError(f"condition_type must be one of {_VALID_CONDITION_TYPES}")

        channels = data.get("channels", ["email"])
        invalid_ch = set(channels) - _VALID_CHANNELS
        if invalid_ch:
            raise ValueError(f"Invalid channels: {invalid_ch}")

        policy_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "severity": severity,
            "condition_type": condition_type,
            "channels": json.dumps(channels),
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO alert_policies
                    (policy_id, org_id, name, severity, condition_type,
                     channels, enabled, created_at, updated_at)
                VALUES
                    (:policy_id, :org_id, :name, :severity, :condition_type,
                     :channels, :enabled, :created_at, :updated_at)
                """,
                row,
            )
        result = dict(row)
        result["channels"] = channels
        result["enabled"] = bool(row["enabled"])
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ALERT_CREATED", {"entity_type": "alerting_notification", "org_id": org_id, "source_engine": "alerting_notification"})
            except Exception:
                pass

        return result

    def list_alert_policies(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List alert policies for an org, optionally filtered by enabled state."""
        query = "SELECT * FROM alert_policies WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Alert Lifecycle
    # ------------------------------------------------------------------

    def trigger_alert(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger a new alert.

        Required keys: title, message
        Optional keys: policy_id, source_engine, source_id, severity, context
        """
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        alert_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "alert_id": alert_id,
            "org_id": org_id,
            "policy_id": data.get("policy_id", ""),
            "source_engine": data.get("source_engine", ""),
            "source_id": data.get("source_id", ""),
            "title": data.get("title", ""),
            "message": data.get("message", ""),
            "severity": severity,
            "status": "open",
            "context": json.dumps(data.get("context", {})),
            "acknowledged_by": None,
            "acknowledged_at": None,
            "resolved_by": None,
            "resolved_at": None,
            "resolution": None,
            "triggered_at": now,
            "updated_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO alerts
                    (alert_id, org_id, policy_id, source_engine, source_id,
                     title, message, severity, status, context,
                     acknowledged_by, acknowledged_at,
                     resolved_by, resolved_at, resolution,
                     triggered_at, updated_at)
                VALUES
                    (:alert_id, :org_id, :policy_id, :source_engine, :source_id,
                     :title, :message, :severity, :status, :context,
                     :acknowledged_by, :acknowledged_at,
                     :resolved_by, :resolved_at, :resolution,
                     :triggered_at, :updated_at)
                """,
                row,
            )
        result = dict(row)
        result["context"] = data.get("context", {})
        return result

    def list_alerts(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        acknowledged: bool = False,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List alerts with optional filters."""
        query = "SELECT * FROM alerts WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if acknowledged:
            query += " AND status = 'acknowledged'"
        query += " ORDER BY triggered_at DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def acknowledge_alert(
        self, org_id: str, alert_id: str, acknowledged_by: str
    ) -> Dict[str, Any]:
        """Acknowledge an open alert."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET status = 'acknowledged',
                    acknowledged_by = ?,
                    acknowledged_at = ?,
                    updated_at = ?
                WHERE alert_id = ? AND org_id = ? AND status = 'open'
                """,
                (acknowledged_by, now, now, alert_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Alert {alert_id} not found for org {org_id}")
        return self._row_to_dict(row)

    def resolve_alert(
        self,
        org_id: str,
        alert_id: str,
        resolved_by: str,
        resolution: str,
    ) -> Dict[str, Any]:
        """Resolve an open or acknowledged alert."""
        now = self._now()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE alerts
                SET status = 'resolved',
                    resolved_by = ?,
                    resolved_at = ?,
                    resolution = ?,
                    updated_at = ?
                WHERE alert_id = ? AND org_id = ? AND status IN ('open', 'acknowledged')
                """,
                (resolved_by, now, resolution, now, alert_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_id = ? AND org_id = ?",
                (alert_id, org_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Alert {alert_id} not found for org {org_id}")
        return self._row_to_dict(row)

    # ------------------------------------------------------------------
    # History & Stats
    # ------------------------------------------------------------------

    def get_alert_history(
        self,
        org_id: str,
        policy_id: Optional[str] = None,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Return alerts triggered within the last N hours."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).isoformat()
        query = "SELECT * FROM alerts WHERE org_id = ? AND triggered_at >= ?"
        params: list = [org_id, cutoff]
        if policy_id:
            query += " AND policy_id = ?"
            params.append(policy_id)
        query += " ORDER BY triggered_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_alerting_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated alerting statistics."""
        cutoff_24h = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        with self._lock, self._conn() as conn:
            policies_total = conn.execute(
                "SELECT COUNT(*) FROM alert_policies WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            alerts_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE org_id = ? AND triggered_at >= ?",
                (org_id, cutoff_24h),
            ).fetchone()[0]

            unacknowledged = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            # Severity breakdown
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM alerts
                WHERE org_id = ? AND triggered_at >= ?
                GROUP BY severity
                """,
                (org_id, cutoff_24h),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # MTTR: average hours between triggered_at and resolved_at
            mttr_rows = conn.execute(
                """
                SELECT triggered_at, resolved_at
                FROM alerts
                WHERE org_id = ? AND status = 'resolved' AND resolved_at IS NOT NULL
                """,
                (org_id,),
            ).fetchall()

        mttr_hours: Optional[float] = None
        if mttr_rows:
            total_secs = 0.0
            count = 0
            for r in mttr_rows:
                try:
                    t = datetime.fromisoformat(r["triggered_at"])
                    res = datetime.fromisoformat(r["resolved_at"])
                    diff = (res - t).total_seconds()
                    if diff >= 0:
                        total_secs += diff
                        count += 1
                except Exception:
                    pass
            if count:
                mttr_hours = round(total_secs / count / 3600, 2)

        return {
            "org_id": org_id,
            "policies": policies_total,
            "alerts_24h": alerts_24h,
            "unacknowledged": unacknowledged,
            "by_severity": by_severity,
            "mttr_hours": mttr_hours,
        }
