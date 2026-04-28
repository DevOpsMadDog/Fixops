"""Network Traffic Engine — ALDECI.

Network flow analysis and anomaly detection.

Capabilities:
  - Traffic flow ingestion with per-org SQLite WAL storage
  - Rule-based anomaly detection (C2, data exfil, port scan, brute force, beacon)
  - Traffic rule management (allow/deny/monitor/alert)
  - Traffic anomaly lifecycle management
  - Baseline tracking per source IP
  - Stats aggregation (top talkers, anomaly rate, protocol breakdown)

Compliance: MITRE ATT&CK, CIS Controls v8 (Control 13), NIST SP 800-53 (SI-4)
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

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "http", "https", "dns", "smtp", "other"}
_VALID_DIRECTIONS = {"inbound", "outbound", "lateral"}
_VALID_ANOMALY_TYPES = {
    "beacon", "data_exfil", "port_scan", "brute_force",
    "c2_traffic", "lateral_movement", "normal",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ACTIONS = {"allow", "deny", "monitor", "alert"}
_VALID_ANOMALY_STATUSES = {"new", "investigating", "resolved"}

# C2 commonly-used ports
_C2_PORTS = {6667, 1234, 31337, 4444, 8080}
# Data exfiltration threshold (bytes)
_EXFIL_BYTES_THRESHOLD = 100_000_000
# Port scan: unique dst IPs in 60s window
_PORT_SCAN_UNIQUE_DST = 20
# Brute force: bytes_received threshold indicating failure
_BRUTE_FORCE_MAX_BYTES = 100
# Beacon: minimum occurrences at same minute
_BEACON_MIN_OCCURRENCES = 3


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path_for_org(org_id: str) -> str:
    return str(_DEFAULT_DATA_DIR / f"{org_id}_network_traffic.db")


class NetworkTrafficEngine:
    """SQLite WAL-backed network traffic analysis engine.

    Thread-safe via per-org RLock. Multi-tenant via org_id.
    Each org gets its own database file.
    """

    def __init__(self) -> None:
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_meta = threading.Lock()
        self._dbs: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._locks_meta:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _db_path(self, org_id: str) -> str:
        if org_id not in self._dbs:
            self._dbs[org_id] = _db_path_for_org(org_id)
        return self._dbs[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        db_path = self._db_path(org_id)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _ensure_schema(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS traffic_flows (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    src_ip          TEXT NOT NULL DEFAULT '',
                    src_port        INTEGER NOT NULL DEFAULT 0,
                    dst_ip          TEXT NOT NULL DEFAULT '',
                    dst_port        INTEGER NOT NULL DEFAULT 0,
                    protocol        TEXT NOT NULL DEFAULT 'tcp',
                    bytes_sent      INTEGER NOT NULL DEFAULT 0,
                    bytes_received  INTEGER NOT NULL DEFAULT 0,
                    packets         INTEGER NOT NULL DEFAULT 0,
                    duration_ms     INTEGER NOT NULL DEFAULT 0,
                    direction       TEXT NOT NULL DEFAULT 'outbound',
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    anomaly_type    TEXT,
                    flagged         INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tf_org_flagged
                    ON traffic_flows (org_id, flagged, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tf_org_src
                    ON traffic_flows (org_id, src_ip, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_tf_org_anomaly
                    ON traffic_flows (org_id, anomaly_type);

                CREATE TABLE IF NOT EXISTS traffic_rules (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    rule_name   TEXT NOT NULL,
                    src_cidr    TEXT NOT NULL DEFAULT '',
                    dst_cidr    TEXT NOT NULL DEFAULT '',
                    port_range  TEXT NOT NULL DEFAULT '',
                    protocol    TEXT NOT NULL DEFAULT 'tcp',
                    action      TEXT NOT NULL DEFAULT 'monitor',
                    priority    INTEGER NOT NULL DEFAULT 100,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    hit_count   INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_tr_org
                    ON traffic_rules (org_id, priority);

                CREATE TABLE IF NOT EXISTS traffic_anomalies (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    flow_id           TEXT NOT NULL,
                    anomaly_type      TEXT NOT NULL,
                    confidence        REAL NOT NULL DEFAULT 0.5,
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    description       TEXT NOT NULL DEFAULT '',
                    mitre_technique   TEXT NOT NULL DEFAULT '',
                    first_seen        TEXT NOT NULL,
                    last_seen         TEXT NOT NULL,
                    occurrence_count  INTEGER NOT NULL DEFAULT 1,
                    status            TEXT NOT NULL DEFAULT 'new',
                    created_at        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ta_org_status
                    ON traffic_anomalies (org_id, status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_ta_org_severity
                    ON traffic_anomalies (org_id, severity);

                CREATE TABLE IF NOT EXISTS traffic_baselines (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    src_ip      TEXT NOT NULL,
                    metric      TEXT NOT NULL,
                    value       TEXT NOT NULL DEFAULT '',
                    updated_at  TEXT NOT NULL,
                    UNIQUE(org_id, src_ip, metric)
                );
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def _analyze_flow(self, conn: sqlite3.Connection, flow: Dict[str, Any]) -> tuple:
        """Rule-based anomaly detection. Returns (anomaly_type, risk_score)."""
        org_id = flow["org_id"]
        src_ip = flow["src_ip"]
        dst_port = flow["dst_port"]
        bytes_sent = flow["bytes_sent"]
        bytes_received = flow["bytes_received"]
        direction = flow["direction"]
        created_at = flow["created_at"]

        # Rule 1: C2 traffic — suspicious port + outbound
        if dst_port in _C2_PORTS and direction == "outbound":
            return "c2_traffic", 0.85

        # Rule 2: Data exfiltration — large outbound transfer
        if bytes_sent > _EXFIL_BYTES_THRESHOLD and direction == "outbound":
            return "data_exfil", 0.80

        # Rule 3: Port scan — same src_ip to many unique dst_ips in 60s window
        # Use a 60-second window around the current flow's timestamp
        try:
            ts = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            ts = datetime.now(timezone.utc)
        window_start = ts.replace(second=max(0, ts.second - 60), microsecond=0).isoformat()
        unique_dst = conn.execute(
            """SELECT COUNT(DISTINCT dst_ip) FROM traffic_flows
               WHERE org_id = ? AND src_ip = ? AND created_at >= ?""",
            (org_id, src_ip, window_start),
        ).fetchone()[0]
        if unique_dst > _PORT_SCAN_UNIQUE_DST:
            return "port_scan", 0.70

        # Rule 4: Brute force — SSH port with tiny response (failed auth)
        if dst_port == 22 and bytes_received < _BRUTE_FORCE_MAX_BYTES:
            repeat_count = conn.execute(
                """SELECT COUNT(*) FROM traffic_flows
                   WHERE org_id = ? AND src_ip = ? AND dst_port = 22
                     AND bytes_received < ?""",
                (org_id, src_ip, _BRUTE_FORCE_MAX_BYTES),
            ).fetchone()[0]
            if repeat_count >= 3:
                return "brute_force", 0.65

        # Rule 5: Beacon — regular interval pattern (same minute, 3+ occurrences)
        try:
            minute_str = ts.strftime("%Y-%m-%dT%H:%M")
        except Exception:
            minute_str = ""
        if minute_str:
            beacon_count = conn.execute(
                """SELECT COUNT(*) FROM traffic_flows
                   WHERE org_id = ? AND src_ip = ? AND created_at LIKE ?""",
                (org_id, src_ip, f"{minute_str}%"),
            ).fetchone()[0]
            if beacon_count >= _BEACON_MIN_OCCURRENCES:
                return "beacon", 0.60

        return "normal", 0.0

    # ------------------------------------------------------------------
    # Flows
    # ------------------------------------------------------------------

    def record_flow(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a network flow. Runs anomaly detection. Returns saved flow dict."""
        self._ensure_schema(org_id)
        protocol = data.get("protocol", "tcp")
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(f"Invalid protocol: {protocol}. Must be one of {_VALID_PROTOCOLS}")
        direction = data.get("direction", "outbound")
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(f"Invalid direction: {direction}")

        now = _now_iso()
        flow: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "src_ip": data.get("src_ip", ""),
            "src_port": int(data.get("src_port", 0)),
            "dst_ip": data.get("dst_ip", ""),
            "dst_port": int(data.get("dst_port", 0)),
            "protocol": protocol,
            "bytes_sent": int(data.get("bytes_sent", 0)),
            "bytes_received": int(data.get("bytes_received", 0)),
            "packets": int(data.get("packets", 0)),
            "duration_ms": int(data.get("duration_ms", 0)),
            "direction": direction,
            "risk_score": 0.0,
            "anomaly_type": None,
            "flagged": 0,
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                anomaly_type, risk_score = self._analyze_flow(conn, flow)
                flow["anomaly_type"] = anomaly_type if anomaly_type != "normal" else None
                flow["risk_score"] = risk_score
                flow["flagged"] = 1 if anomaly_type != "normal" else 0

                conn.execute(
                    """INSERT INTO traffic_flows
                       (id, org_id, src_ip, src_port, dst_ip, dst_port, protocol,
                        bytes_sent, bytes_received, packets, duration_ms, direction,
                        risk_score, anomaly_type, flagged, created_at)
                       VALUES (:id, :org_id, :src_ip, :src_port, :dst_ip, :dst_port, :protocol,
                               :bytes_sent, :bytes_received, :packets, :duration_ms, :direction,
                               :risk_score, :anomaly_type, :flagged, :created_at)""",
                    flow,
                )

                # Create anomaly record if flagged
                if flow["flagged"]:
                    severity_map = {
                        "c2_traffic": "critical",
                        "data_exfil": "critical",
                        "port_scan": "high",
                        "brute_force": "high",
                        "beacon": "medium",
                        "lateral_movement": "high",
                    }
                    mitre_map = {
                        "c2_traffic": "T1071",
                        "data_exfil": "T1041",
                        "port_scan": "T1046",
                        "brute_force": "T1110",
                        "beacon": "T1071.001",
                        "lateral_movement": "T1021",
                    }
                    severity = severity_map.get(anomaly_type, "medium")
                    mitre = mitre_map.get(anomaly_type, "")
                    anomaly_rec = {
                        "id": str(uuid.uuid4()),
                        "org_id": org_id,
                        "flow_id": flow["id"],
                        "anomaly_type": anomaly_type,
                        "confidence": risk_score,
                        "severity": severity,
                        "description": f"Detected {anomaly_type} from {flow['src_ip']} to {flow['dst_ip']}:{flow['dst_port']}",
                        "mitre_technique": mitre,
                        "first_seen": now,
                        "last_seen": now,
                        "occurrence_count": 1,
                        "status": "new",
                        "created_at": now,
                    }
                    conn.execute(
                        """INSERT INTO traffic_anomalies
                           (id, org_id, flow_id, anomaly_type, confidence, severity,
                            description, mitre_technique, first_seen, last_seen,
                            occurrence_count, status, created_at)
                           VALUES (:id, :org_id, :flow_id, :anomaly_type, :confidence,
                                   :severity, :description, :mitre_technique, :first_seen,
                                   :last_seen, :occurrence_count, :status, :created_at)""",
                        anomaly_rec,
                    )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "network_traffic", "org_id": org_id, "source_engine": "network_traffic"})
            except Exception:
                pass

        return flow

    def list_flows(
        self,
        org_id: str,
        flagged: Optional[bool] = None,
        anomaly_type: Optional[str] = None,
        src_ip: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List traffic flows with optional filters."""
        self._ensure_schema(org_id)
        sql = "SELECT * FROM traffic_flows WHERE org_id = ?"
        params: list = [org_id]
        if flagged is not None:
            sql += " AND flagged = ?"
            params.append(1 if flagged else 0)
        if anomaly_type:
            sql += " AND anomaly_type = ?"
            params.append(anomaly_type)
        if src_ip:
            sql += " AND src_ip = ?"
            params.append(src_ip)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_flow(self, org_id: str, flow_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single flow by ID."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM traffic_flows WHERE org_id = ? AND id = ?",
                (org_id, flow_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def list_anomalies(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List traffic anomalies with optional filters."""
        self._ensure_schema(org_id)
        sql = "SELECT * FROM traffic_anomalies WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def resolve_anomaly(self, org_id: str, anomaly_id: str) -> bool:
        """Mark an anomaly as resolved. Returns True if found."""
        self._ensure_schema(org_id)
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    "UPDATE traffic_anomalies SET status = 'resolved' WHERE org_id = ? AND id = ?",
                    (org_id, anomaly_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a traffic rule. Returns the created record."""
        self._ensure_schema(org_id)
        rule_name = (data.get("rule_name") or "").strip()
        if not rule_name:
            raise ValueError("rule_name is required.")
        action = data.get("action", "monitor")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action: {action}. Must be one of {_VALID_ACTIONS}")
        protocol = data.get("protocol", "tcp")
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(f"Invalid protocol: {protocol}")

        now = _now_iso()
        rule: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_name": rule_name,
            "src_cidr": data.get("src_cidr", ""),
            "dst_cidr": data.get("dst_cidr", ""),
            "port_range": data.get("port_range", ""),
            "protocol": protocol,
            "action": action,
            "priority": int(data.get("priority", 100)),
            "enabled": 1 if data.get("enabled", True) else 0,
            "hit_count": 0,
            "created_at": now,
        }
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO traffic_rules
                       (id, org_id, rule_name, src_cidr, dst_cidr, port_range,
                        protocol, action, priority, enabled, hit_count, created_at)
                       VALUES (:id, :org_id, :rule_name, :src_cidr, :dst_cidr, :port_range,
                               :protocol, :action, :priority, :enabled, :hit_count, :created_at)""",
                    rule,
                )
        return rule

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all traffic rules for an org, ordered by priority."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM traffic_rules WHERE org_id = ? ORDER BY priority ASC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_traffic_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated traffic stats for org."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            total_flows = conn.execute(
                "SELECT COUNT(*) FROM traffic_flows WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            flagged_flows = conn.execute(
                "SELECT COUNT(*) FROM traffic_flows WHERE org_id = ? AND flagged = 1", (org_id,)
            ).fetchone()[0]

            avg_risk = conn.execute(
                "SELECT AVG(risk_score) FROM traffic_flows WHERE org_id = ?", (org_id,)
            ).fetchone()[0] or 0.0

            by_anomaly_rows = conn.execute(
                """SELECT anomaly_type, COUNT(*) as cnt
                   FROM traffic_flows
                   WHERE org_id = ? AND anomaly_type IS NOT NULL
                   GROUP BY anomaly_type""",
                (org_id,),
            ).fetchall()
            by_anomaly_type = {r["anomaly_type"]: r["cnt"] for r in by_anomaly_rows}

            by_protocol_rows = conn.execute(
                """SELECT protocol, COUNT(*) as cnt
                   FROM traffic_flows WHERE org_id = ?
                   GROUP BY protocol""",
                (org_id,),
            ).fetchall()
            by_protocol = {r["protocol"]: r["cnt"] for r in by_protocol_rows}

            top_talkers = self.get_top_talkers(org_id, limit=10)

        anomaly_rate = round(flagged_flows / total_flows, 4) if total_flows > 0 else 0.0

        return {
            "total_flows": total_flows,
            "flagged_flows": flagged_flows,
            "by_anomaly_type": by_anomaly_type,
            "by_protocol": by_protocol,
            "avg_risk_score": round(avg_risk, 4),
            "top_talkers": top_talkers,
            "anomaly_rate": anomaly_rate,
        }

    def get_top_talkers(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Return IPs with highest total bytes sent + received."""
        self._ensure_schema(org_id)
        with self._conn(org_id) as conn:
            rows = conn.execute(
                """SELECT src_ip,
                          COUNT(*) as connection_count,
                          SUM(bytes_sent) as total_bytes_sent,
                          SUM(bytes_received) as total_bytes_received,
                          SUM(bytes_sent + bytes_received) as total_bytes
                   FROM traffic_flows WHERE org_id = ?
                   GROUP BY src_ip
                   ORDER BY total_bytes DESC
                   LIMIT ?""",
                (org_id, limit),
            ).fetchall()
        return [self._row(r) for r in rows]
