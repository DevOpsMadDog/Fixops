"""Network Detection & Response (NDR) Engine — ALDECI.

Ingests network flows, scores risk, auto-raises alerts, manages baselines
and segments, and detects anomalies against learned baselines.

Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ndr.db"
)

# Ports that raise risk score
_HIGH_RISK_PORTS = {22, 3389, 445, 1433, 3306, 5432}

_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SSH", "RDP"}
_VALID_FLOW_TYPES = {
    "internal", "external", "lateral", "exfiltration_suspect", "c2_suspect",
}
_VALID_ALERT_TYPES = {
    "port_scan", "data_exfil", "c2_beacon", "lateral_movement",
    "dns_tunneling", "brute_force", "anomaly",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ALERT_STATUSES = {"open", "investigating", "resolved", "false_positive"}
_VALID_SEGMENT_TYPES = {"dmz", "internal", "cloud", "ot", "guest"}
_VALID_SENSITIVITIES = {"critical", "high", "medium", "low"}


class NDREngine:
    """SQLite WAL-backed Network Detection & Response engine.

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
                CREATE TABLE IF NOT EXISTS network_flows (
                    flow_id       TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    src_ip        TEXT NOT NULL DEFAULT '',
                    dst_ip        TEXT NOT NULL DEFAULT '',
                    src_port      INTEGER NOT NULL DEFAULT 0,
                    dst_port      INTEGER NOT NULL DEFAULT 0,
                    protocol      TEXT NOT NULL DEFAULT 'TCP',
                    bytes_sent    INTEGER NOT NULL DEFAULT 0,
                    bytes_recv    INTEGER NOT NULL DEFAULT 0,
                    duration_ms   INTEGER NOT NULL DEFAULT 0,
                    flow_type     TEXT NOT NULL DEFAULT 'internal',
                    risk_score    REAL NOT NULL DEFAULT 0.0,
                    observed_at   DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_nf_org
                    ON network_flows (org_id, observed_at DESC);

                CREATE TABLE IF NOT EXISTS network_alerts (
                    alert_id        TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    flow_id         TEXT NOT NULL DEFAULT '',
                    alert_type      TEXT NOT NULL DEFAULT 'anomaly',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    src_ip          TEXT NOT NULL DEFAULT '',
                    dst_ip          TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    mitre_technique TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    detected_at     DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_na_org
                    ON network_alerts (org_id, detected_at DESC);

                CREATE TABLE IF NOT EXISTS network_baselines (
                    baseline_id              TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    asset_ip                 TEXT NOT NULL,
                    typical_protocols        TEXT NOT NULL DEFAULT '[]',
                    typical_ports            TEXT NOT NULL DEFAULT '[]',
                    typical_daily_bytes      INTEGER NOT NULL DEFAULT 0,
                    typical_connections_per_hr INTEGER NOT NULL DEFAULT 0,
                    last_updated             DATETIME,
                    UNIQUE(org_id, asset_ip)
                );
                CREATE INDEX IF NOT EXISTS idx_nb_org
                    ON network_baselines (org_id);

                CREATE TABLE IF NOT EXISTS network_segments (
                    segment_id   TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    cidr         TEXT NOT NULL DEFAULT '',
                    segment_type TEXT NOT NULL DEFAULT 'internal',
                    sensitivity  TEXT NOT NULL DEFAULT 'medium',
                    created_at   DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_ns_org
                    ON network_segments (org_id);
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
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_risk_score(data: Dict[str, Any]) -> float:
        """Calculate risk score from flow attributes (0.0 – 1.0)."""
        score = 0.0
        dst_port = int(data.get("dst_port", 0))
        bytes_sent = int(data.get("bytes_sent", 0))
        flow_type = data.get("flow_type", "internal")
        protocol = data.get("protocol", "TCP")

        if dst_port in _HIGH_RISK_PORTS:
            score += 0.3
        if bytes_sent > 1_000_000:  # > 1 MB
            score += 0.2
        if flow_type == "external":
            score += 0.1
        if protocol not in {"TCP", "UDP", "HTTPS", "HTTP"}:
            score += 0.2

        return min(round(score, 4), 1.0)

    @staticmethod
    def _infer_alert_type(data: Dict[str, Any], risk_score: float) -> str:
        flow_type = data.get("flow_type", "internal")
        dst_port = int(data.get("dst_port", 0))
        protocol = data.get("protocol", "TCP")
        bytes_sent = int(data.get("bytes_sent", 0))

        if flow_type == "c2_suspect":
            return "c2_beacon"
        if flow_type == "exfiltration_suspect" or bytes_sent > 5_000_000:
            return "data_exfil"
        if flow_type == "lateral":
            return "lateral_movement"
        if protocol == "DNS":
            return "dns_tunneling"
        if dst_port in {22, 3389, 445}:
            return "brute_force"
        if dst_port in _HIGH_RISK_PORTS:
            return "port_scan"
        return "anomaly"

    @staticmethod
    def _infer_severity(risk_score: float) -> str:
        if risk_score >= 0.9:
            return "critical"
        if risk_score >= 0.7:
            return "high"
        if risk_score >= 0.5:
            return "medium"
        return "low"

    def _auto_alert(
        self, org_id: str, flow_id: str, data: Dict[str, Any], risk_score: float
    ) -> None:
        """Create an alert automatically when risk_score > 0.7."""
        alert_type = self._infer_alert_type(data, risk_score)
        severity = self._infer_severity(risk_score)
        alert_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO network_alerts
                    (alert_id, org_id, flow_id, alert_type, severity,
                     src_ip, dst_ip, description, mitre_technique,
                     status, detected_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    alert_id, org_id, flow_id, alert_type, severity,
                    data.get("src_ip", ""),
                    data.get("dst_ip", ""),
                    f"Auto-detected {alert_type} from flow {flow_id} "
                    f"(risk={risk_score:.2f})",
                    data.get("mitre_technique", ""),
                    "open",
                    now,
                ),
            )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus:
                    bus.emit("THREAT_DETECTED", {"entity_type": "network_alert", "entity_id": str(alert_id), "org_id": org_id, "source_engine": "ndr_engine"})
            except Exception:
                pass  # Event emission should never break the main operation

    # ------------------------------------------------------------------
    # Flows
    # ------------------------------------------------------------------

    def ingest_flow(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a network flow, score it, and auto-alert if risky."""
        flow_id = str(uuid.uuid4())
        now = data.get("observed_at") or datetime.now(timezone.utc).isoformat()
        risk_score = self._calc_risk_score(data)

        protocol = data.get("protocol", "TCP")
        flow_type = data.get("flow_type", "internal")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO network_flows
                        (flow_id, org_id, src_ip, dst_ip, src_port, dst_port,
                         protocol, bytes_sent, bytes_recv, duration_ms,
                         flow_type, risk_score, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        flow_id, org_id,
                        data.get("src_ip", ""),
                        data.get("dst_ip", ""),
                        int(data.get("src_port", 0)),
                        int(data.get("dst_port", 0)),
                        protocol,
                        int(data.get("bytes_sent", 0)),
                        int(data.get("bytes_recv", 0)),
                        int(data.get("duration_ms", 0)),
                        flow_type,
                        risk_score,
                        now,
                    ),
                )
            if risk_score > 0.7:
                self._auto_alert(org_id, flow_id, data, risk_score)

        return {
            "flow_id": flow_id,
            "org_id": org_id,
            "src_ip": data.get("src_ip", ""),
            "dst_ip": data.get("dst_ip", ""),
            "src_port": int(data.get("src_port", 0)),
            "dst_port": int(data.get("dst_port", 0)),
            "protocol": protocol,
            "bytes_sent": int(data.get("bytes_sent", 0)),
            "bytes_recv": int(data.get("bytes_recv", 0)),
            "duration_ms": int(data.get("duration_ms", 0)),
            "flow_type": flow_type,
            "risk_score": risk_score,
            "observed_at": now,
            "alert_created": risk_score > 0.7,
        }

    def list_flows(
        self,
        org_id: str,
        flow_type: Optional[str] = None,
        min_risk: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List flows for an org with optional filters."""
        query = "SELECT * FROM network_flows WHERE org_id=?"
        params: list = [org_id]
        if flow_type:
            query += " AND flow_type=?"
            params.append(flow_type)
        if min_risk is not None:
            query += " AND risk_score>=?"
            params.append(float(min_risk))
        query += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def list_alerts(
        self,
        org_id: str,
        alert_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM network_alerts WHERE org_id=?"
        params: list = [org_id]
        if alert_type:
            query += " AND alert_type=?"
            params.append(alert_type)
        if status:
            query += " AND status=?"
            params.append(status)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY detected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_alert_status(self, org_id: str, alert_id: str, status: str) -> bool:
        if status not in _VALID_ALERT_STATUSES:
            raise ValueError(f"Invalid alert status: {status!r}")
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE network_alerts SET status=? WHERE org_id=? AND alert_id=?",
                    (status, org_id, alert_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def set_baseline(self, org_id: str, asset_ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Upsert a baseline for an asset IP."""
        existing = self.get_baseline(org_id, asset_ip)
        now = datetime.now(timezone.utc).isoformat()

        typical_protocols = data.get("typical_protocols", [])
        typical_ports = data.get("typical_ports", [])

        with self._lock:
            with self._conn() as conn:
                if existing:
                    conn.execute(
                        """
                        UPDATE network_baselines
                        SET typical_protocols=?, typical_ports=?,
                            typical_daily_bytes=?, typical_connections_per_hr=?,
                            last_updated=?
                        WHERE org_id=? AND asset_ip=?
                        """,
                        (
                            json.dumps(typical_protocols),
                            json.dumps(typical_ports),
                            int(data.get("typical_daily_bytes", 0)),
                            int(data.get("typical_connections_per_hr", 0)),
                            now,
                            org_id, asset_ip,
                        ),
                    )
                    baseline_id = existing["baseline_id"]
                else:
                    baseline_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO network_baselines
                            (baseline_id, org_id, asset_ip, typical_protocols,
                             typical_ports, typical_daily_bytes,
                             typical_connections_per_hr, last_updated)
                        VALUES (?,?,?,?,?,?,?,?)
                        """,
                        (
                            baseline_id, org_id, asset_ip,
                            json.dumps(typical_protocols),
                            json.dumps(typical_ports),
                            int(data.get("typical_daily_bytes", 0)),
                            int(data.get("typical_connections_per_hr", 0)),
                            now,
                        ),
                    )

        return {
            "baseline_id": baseline_id,
            "org_id": org_id,
            "asset_ip": asset_ip,
            "typical_protocols": typical_protocols,
            "typical_ports": typical_ports,
            "typical_daily_bytes": int(data.get("typical_daily_bytes", 0)),
            "typical_connections_per_hr": int(data.get("typical_connections_per_hr", 0)),
            "last_updated": now,
        }

    def get_baseline(self, org_id: str, asset_ip: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM network_baselines WHERE org_id=? AND asset_ip=?",
                (org_id, asset_ip),
            ).fetchone()
        if not row:
            return None
        d = self._row(row)
        d["typical_protocols"] = json.loads(d.get("typical_protocols") or "[]")
        d["typical_ports"] = json.loads(d.get("typical_ports") or "[]")
        return d

    # ------------------------------------------------------------------
    # Segments
    # ------------------------------------------------------------------

    def add_segment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        segment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO network_segments
                        (segment_id, org_id, name, cidr, segment_type, sensitivity, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        segment_id, org_id,
                        data.get("name", ""),
                        data.get("cidr", ""),
                        data.get("segment_type", "internal"),
                        data.get("sensitivity", "medium"),
                        now,
                    ),
                )

        return {
            "segment_id": segment_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "cidr": data.get("cidr", ""),
            "segment_type": data.get("segment_type", "internal"),
            "sensitivity": data.get("sensitivity", "medium"),
            "created_at": now,
        }

    def list_segments(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM network_segments WHERE org_id=? ORDER BY name",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_anomalies(self, org_id: str) -> List[Dict[str, Any]]:
        """Compare recent 24h flows against baselines.

        Flags IPs where:
        - bytes_sent sum > 2× typical_daily_bytes, or
        - flow destinations include ports not in typical_ports baseline.

        Returns a list of anomaly dicts.
        """
        anomalies: List[Dict[str, Any]] = []

        with self._conn() as conn:
            baselines = conn.execute(
                "SELECT * FROM network_baselines WHERE org_id=?", (org_id,)
            ).fetchall()

        for bl_row in baselines:
            bl = self._row(bl_row)
            asset_ip = bl["asset_ip"]
            typical_bytes = int(bl.get("typical_daily_bytes") or 0)
            typical_ports_raw = bl.get("typical_ports") or "[]"
            typical_ports: List[int] = json.loads(typical_ports_raw)

            with self._conn() as conn:
                # Flows in the last 24h from this IP
                agg = conn.execute(
                    """
                    SELECT COALESCE(SUM(bytes_sent),0) AS total_bytes,
                           COUNT(*) AS total_flows
                    FROM network_flows
                    WHERE org_id=? AND src_ip=?
                      AND observed_at >= datetime('now','-1 day')
                    """,
                    (org_id, asset_ip),
                ).fetchone()

                unusual_port_rows = conn.execute(
                    """
                    SELECT DISTINCT dst_port FROM network_flows
                    WHERE org_id=? AND src_ip=?
                      AND observed_at >= datetime('now','-1 day')
                    """,
                    (org_id, asset_ip),
                ).fetchall()

            total_bytes = int(agg["total_bytes"])
            total_flows = int(agg["total_flows"])

            if total_flows == 0:
                continue

            # Bytes anomaly
            if typical_bytes > 0 and total_bytes > 2 * typical_bytes:
                anomalies.append({
                    "org_id": org_id,
                    "asset_ip": asset_ip,
                    "anomaly_type": "excessive_bytes",
                    "detail": (
                        f"Sent {total_bytes:,} bytes in 24h "
                        f"(baseline: {typical_bytes:,}, threshold: {2*typical_bytes:,})"
                    ),
                    "observed_bytes": total_bytes,
                    "baseline_bytes": typical_bytes,
                })

            # Unusual ports
            if typical_ports:
                seen_ports = {int(r["dst_port"]) for r in unusual_port_rows}
                unusual = seen_ports - set(typical_ports)
                if unusual:
                    anomalies.append({
                        "org_id": org_id,
                        "asset_ip": asset_ip,
                        "anomaly_type": "unusual_ports",
                        "detail": (
                            f"Connected to unexpected ports: {sorted(unusual)}"
                        ),
                        "unusual_ports": sorted(unusual),
                        "baseline_ports": typical_ports,
                    })

        return anomalies

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_ndr_stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            total_flows = conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            external_flows = conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE org_id=? AND flow_type='external'",
                (org_id,),
            ).fetchone()[0]

            c2_suspects = conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE org_id=? AND flow_type='c2_suspect'",
                (org_id,),
            ).fetchone()[0]

            exfil_suspects = conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE org_id=? AND flow_type='exfiltration_suspect'",
                (org_id,),
            ).fetchone()[0]

            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM network_alerts WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            critical_alerts = conn.execute(
                "SELECT COUNT(*) FROM network_alerts WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]

            monitored_segments = conn.execute(
                "SELECT COUNT(*) FROM network_segments WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            high_risk_flows = conn.execute(
                "SELECT COUNT(*) FROM network_flows WHERE org_id=? AND risk_score>0.7",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_flows": total_flows,
            "external_flows": external_flows,
            "c2_suspects": c2_suspects,
            "exfil_suspects": exfil_suspects,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "monitored_segments": monitored_segments,
            "high_risk_flows": high_risk_flows,
        }
