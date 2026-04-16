"""Network Monitoring Engine — ALDECI.

Tracks network interfaces, traffic samples, alert rules, and triggered alerts.
Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_monitoring.db"
)

_VALID_IF_TYPES = {"wan", "lan", "dmz"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_METRICS = {"bytes_in", "bytes_out", "packets_in", "packets_out", "bps_in", "bps_out"}


class NetworkMonitoringEngine:
    """SQLite WAL-backed Network Monitoring engine.

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
                CREATE TABLE IF NOT EXISTS nm_interfaces (
                    interface_id  TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL DEFAULT '',
                    ip            TEXT NOT NULL DEFAULT '',
                    if_type       TEXT NOT NULL DEFAULT 'lan',
                    description   TEXT NOT NULL DEFAULT '',
                    created_at    DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_nmi_org
                    ON nm_interfaces (org_id);

                CREATE TABLE IF NOT EXISTS nm_traffic_samples (
                    sample_id      TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    interface_id   TEXT NOT NULL,
                    bytes_in       INTEGER NOT NULL DEFAULT 0,
                    bytes_out      INTEGER NOT NULL DEFAULT 0,
                    packets_in     INTEGER NOT NULL DEFAULT 0,
                    packets_out    INTEGER NOT NULL DEFAULT 0,
                    sampled_at     DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_nmts_org_iface
                    ON nm_traffic_samples (org_id, interface_id, sampled_at DESC);

                CREATE TABLE IF NOT EXISTS nm_alert_rules (
                    rule_id        TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    interface_id   TEXT NOT NULL,
                    metric         TEXT NOT NULL DEFAULT 'bytes_in',
                    threshold      REAL NOT NULL DEFAULT 0.0,
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    created_at     DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_nmar_org
                    ON nm_alert_rules (org_id);

                CREATE TABLE IF NOT EXISTS nm_alerts (
                    alert_id       TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    rule_id        TEXT NOT NULL,
                    interface_id   TEXT NOT NULL,
                    metric         TEXT NOT NULL DEFAULT '',
                    value          REAL NOT NULL DEFAULT 0.0,
                    threshold      REAL NOT NULL DEFAULT 0.0,
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    triggered_at   DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_nma_org
                    ON nm_alerts (org_id, triggered_at DESC);
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
    # Interfaces
    # ------------------------------------------------------------------

    def register_interface(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new network interface for monitoring."""
        interface_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        if_type = data.get("type", data.get("if_type", "lan"))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO nm_interfaces
                        (interface_id, org_id, name, ip, if_type, description, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        interface_id, org_id,
                        data.get("name", ""),
                        data.get("ip", ""),
                        if_type,
                        data.get("description", ""),
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "network_monitoring", "org_id": org_id, "source_engine": "network_monitoring"})
            except Exception:
                pass

        return {
            "interface_id": interface_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "ip": data.get("ip", ""),
            "if_type": if_type,
            "description": data.get("description", ""),
            "created_at": now,
        }

    def list_interfaces(
        self, org_id: str, if_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List interfaces for an org with optional type filter."""
        query = "SELECT * FROM nm_interfaces WHERE org_id=?"
        params: list = [org_id]
        if if_type:
            query += " AND if_type=?"
            params.append(if_type)
        query += " ORDER BY name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Traffic samples
    # ------------------------------------------------------------------

    def record_traffic_sample(
        self, org_id: str, interface_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a traffic sample for a given interface."""
        sample_id = str(uuid.uuid4())
        sampled_at = data.get("timestamp") or datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO nm_traffic_samples
                        (sample_id, org_id, interface_id, bytes_in, bytes_out,
                         packets_in, packets_out, sampled_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        sample_id, org_id, interface_id,
                        int(data.get("bytes_in", 0)),
                        int(data.get("bytes_out", 0)),
                        int(data.get("packets_in", 0)),
                        int(data.get("packets_out", 0)),
                        sampled_at,
                    ),
                )

        return {
            "sample_id": sample_id,
            "org_id": org_id,
            "interface_id": interface_id,
            "bytes_in": int(data.get("bytes_in", 0)),
            "bytes_out": int(data.get("bytes_out", 0)),
            "packets_in": int(data.get("packets_in", 0)),
            "packets_out": int(data.get("packets_out", 0)),
            "sampled_at": sampled_at,
        }

    def get_traffic_stats(
        self, org_id: str, interface_id: str, hours: int = 24
    ) -> Dict[str, Any]:
        """Return avg_bps, peak_bps, and total_bytes over the last N hours."""
        with self._conn() as conn:
            agg = conn.execute(
                """
                SELECT
                    COUNT(*)                              AS sample_count,
                    COALESCE(SUM(bytes_in + bytes_out), 0) AS total_bytes,
                    COALESCE(MAX(bytes_in + bytes_out), 0) AS peak_bytes,
                    COALESCE(AVG(bytes_in + bytes_out), 0) AS avg_bytes
                FROM nm_traffic_samples
                WHERE org_id=? AND interface_id=?
                  AND sampled_at >= datetime('now', ? || ' hours')
                """,
                (org_id, interface_id, f"-{hours}"),
            ).fetchone()

        sample_count = int(agg["sample_count"])
        total_bytes = int(agg["total_bytes"])
        peak_bytes = int(agg["peak_bytes"])
        avg_bytes = float(agg["avg_bytes"])

        # bps assumes each sample covers 1-second window; callers can adjust
        return {
            "interface_id": interface_id,
            "org_id": org_id,
            "hours": hours,
            "sample_count": sample_count,
            "total_bytes": total_bytes,
            "avg_bps": round(avg_bytes * 8, 2),
            "peak_bps": peak_bytes * 8,
        }

    # ------------------------------------------------------------------
    # Alert rules
    # ------------------------------------------------------------------

    def create_alert_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert rule for an interface metric threshold."""
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        severity = data.get("severity", "medium")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO nm_alert_rules
                        (rule_id, org_id, interface_id, metric, threshold, severity, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        rule_id, org_id,
                        data.get("interface_id", ""),
                        data.get("metric", "bytes_in"),
                        float(data.get("threshold", 0.0)),
                        severity,
                        now,
                    ),
                )

        return {
            "rule_id": rule_id,
            "org_id": org_id,
            "interface_id": data.get("interface_id", ""),
            "metric": data.get("metric", "bytes_in"),
            "threshold": float(data.get("threshold", 0.0)),
            "severity": severity,
            "created_at": now,
        }

    def list_alert_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all alert rules for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM nm_alert_rules WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def trigger_alert(self, org_id: str, rule_id: str, value: float) -> Dict[str, Any]:
        """Trigger an alert for a rule when the observed value exceeds threshold."""
        alert_id = str(uuid.uuid4())
        triggered_at = datetime.now(timezone.utc).isoformat()

        # Fetch rule details
        with self._conn() as conn:
            rule_row = conn.execute(
                "SELECT * FROM nm_alert_rules WHERE org_id=? AND rule_id=?",
                (org_id, rule_id),
            ).fetchone()

        if not rule_row:
            return {
                "alert_id": alert_id,
                "org_id": org_id,
                "rule_id": rule_id,
                "error": "rule_not_found",
                "triggered_at": triggered_at,
            }

        rule = self._row(rule_row)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO nm_alerts
                        (alert_id, org_id, rule_id, interface_id, metric,
                         value, threshold, severity, triggered_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        alert_id, org_id, rule_id,
                        rule["interface_id"],
                        rule["metric"],
                        value,
                        rule["threshold"],
                        rule["severity"],
                        triggered_at,
                    ),
                )

        return {
            "alert_id": alert_id,
            "org_id": org_id,
            "rule_id": rule_id,
            "interface_id": rule["interface_id"],
            "metric": rule["metric"],
            "value": value,
            "threshold": rule["threshold"],
            "severity": rule["severity"],
            "triggered_at": triggered_at,
        }

    def list_alerts(
        self,
        org_id: str,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List triggered alerts for an org with optional severity filter."""
        query = "SELECT * FROM nm_alerts WHERE org_id=?"
        params: list = [org_id]
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY triggered_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_monitoring_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate monitoring stats for an org."""
        with self._conn() as conn:
            interface_count = conn.execute(
                "SELECT COUNT(*) FROM nm_interfaces WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            sample_count = conn.execute(
                "SELECT COUNT(*) FROM nm_traffic_samples WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            alert_count = conn.execute(
                "SELECT COUNT(*) FROM nm_alerts WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            rule_count = conn.execute(
                "SELECT COUNT(*) FROM nm_alert_rules WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            critical_alerts = conn.execute(
                "SELECT COUNT(*) FROM nm_alerts WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]

        return {
            "org_id": org_id,
            "interface_count": interface_count,
            "sample_count": sample_count,
            "alert_count": alert_count,
            "rule_count": rule_count,
            "critical_alerts": critical_alerts,
        }
