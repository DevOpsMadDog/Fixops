"""Network Threat Engine — ALDECI.

Detects and manages network-layer threats including C2 communications,
lateral movement, exfiltration, port scans, DDoS, DNS tunneling, MITM,
and botnet activity. Supports rule management and baseline anomaly detection.

Compliance: NIST CSF DE.CM-1, ISO/IEC 27001 A.12.4, SOC 2 CC7.2
"""

from __future__ import annotations

import contextlib
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_threat.db"
)

_VALID_THREAT_TYPES = {
    "c2-communication", "lateral-movement", "exfiltration", "port-scan",
    "ddos", "dns-tunneling", "mitm", "botnet",
}
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "dns", "http", "https", "smtp", "ftp"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_RULE_TYPES = {"signature", "behavioral", "anomaly", "threshold", "correlation"}
_VALID_ACTIONS = {"block", "alert", "log", "quarantine", "throttle"}
_VALID_STATUSES = {"active", "resolved"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class NetworkThreatEngine:
    """SQLite WAL-backed Network Threat engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS network_threats (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    threat_name  TEXT NOT NULL DEFAULT '',
                    threat_type  TEXT NOT NULL DEFAULT 'port-scan',
                    source_ip    TEXT NOT NULL DEFAULT '',
                    dest_ip      TEXT NOT NULL DEFAULT '',
                    dest_port    INTEGER NOT NULL DEFAULT 0,
                    protocol     TEXT NOT NULL DEFAULT 'tcp',
                    severity     TEXT NOT NULL DEFAULT 'medium',
                    confidence   REAL NOT NULL DEFAULT 0.5,
                    status       TEXT NOT NULL DEFAULT 'active',
                    first_seen   TEXT NOT NULL DEFAULT '',
                    last_seen    TEXT NOT NULL DEFAULT '',
                    packet_count INTEGER NOT NULL DEFAULT 1,
                    created_at   TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS threat_rules (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    rule_name    TEXT NOT NULL DEFAULT '',
                    rule_type    TEXT NOT NULL DEFAULT 'signature',
                    pattern      TEXT NOT NULL DEFAULT '',
                    action       TEXT NOT NULL DEFAULT 'alert',
                    enabled      INTEGER NOT NULL DEFAULT 1,
                    match_count  INTEGER NOT NULL DEFAULT 0,
                    last_matched TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS network_baselines (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    metric_name    TEXT NOT NULL DEFAULT '',
                    baseline_value REAL NOT NULL DEFAULT 0.0,
                    current_value  REAL NOT NULL DEFAULT 0.0,
                    deviation_pct  REAL NOT NULL DEFAULT 0.0,
                    anomaly        INTEGER NOT NULL DEFAULT 0,
                    updated_at     TEXT NOT NULL DEFAULT '',
                    created_at     TEXT NOT NULL DEFAULT '',
                    UNIQUE(org_id, metric_name)
                );
            """)

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def record_threat(
        self,
        org_id: str,
        threat_name: str,
        threat_type: str,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        protocol: str,
        severity: str,
        confidence: float,
    ) -> Dict[str, Any]:
        """Record or update a network threat.

        If an active threat with the same (org_id, threat_type, source_ip, dest_ip)
        already exists, update last_seen and increment packet_count. Otherwise create
        a new threat record.
        """
        confidence = max(0.0, min(1.0, float(confidence)))
        now = _now()

        with self._lock, self._conn() as conn:
            # Check for existing active duplicate
            row = conn.execute(
                """
                SELECT id FROM network_threats
                WHERE org_id=? AND threat_type=? AND source_ip=? AND dest_ip=?
                  AND status='active'
                LIMIT 1
                """,
                (org_id, threat_type, source_ip, dest_ip),
            ).fetchone()

            if row:
                threat_id = row["id"]
                conn.execute(
                    """
                    UPDATE network_threats
                    SET last_seen=?, packet_count=packet_count+1
                    WHERE id=? AND org_id=?
                    """,
                    (now, threat_id, org_id),
                )
            else:
                threat_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO network_threats
                        (id, org_id, threat_name, threat_type, source_ip, dest_ip,
                         dest_port, protocol, severity, confidence, status,
                         first_seen, last_seen, packet_count, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        threat_id, org_id, threat_name, threat_type, source_ip,
                        dest_ip, int(dest_port), protocol, severity, confidence,
                        "active", now, now, 1, now,
                    ),
                )

            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("FINDING_CREATED", {"entity_type": "network_threat_engine", "org_id": org_id, "source_engine": "network_threat_engine"})
                except Exception:
                    pass
            return dict(
                conn.execute(
                    "SELECT * FROM network_threats WHERE id=?", (threat_id,)
                ).fetchone()
            )

    def resolve_threat(self, threat_id: str, org_id: str) -> Dict[str, Any]:
        """Resolve an active threat."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM network_threats WHERE id=? AND org_id=?",
                (threat_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Threat {threat_id} not found")
            conn.execute(
                "UPDATE network_threats SET status='resolved' WHERE id=? AND org_id=?",
                (threat_id, org_id),
            )
            updated = conn.execute(
                "SELECT * FROM network_threats WHERE id=?", (threat_id,)
            ).fetchone()
            return dict(updated)

    def get_active_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return active threats with optional filters."""
        query = "SELECT * FROM network_threats WHERE org_id=? AND status='active'"
        params: List[Any] = [org_id]
        if threat_type:
            query += " AND threat_type=?"
            params.append(threat_type)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def get_threat_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated threat statistics."""
        with self._lock, self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM network_threats WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM network_threats WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]
            resolved = conn.execute(
                "SELECT COUNT(*) FROM network_threats WHERE org_id=? AND status='resolved'",
                (org_id,),
            ).fetchone()[0]

            by_severity = {
                r["severity"]: r["cnt"]
                for r in conn.execute(
                    """
                    SELECT severity, COUNT(*) AS cnt
                    FROM network_threats WHERE org_id=? AND status='active'
                    GROUP BY severity
                    """,
                    (org_id,),
                ).fetchall()
            }

            by_type = {
                r["threat_type"]: r["cnt"]
                for r in conn.execute(
                    """
                    SELECT threat_type, COUNT(*) AS cnt
                    FROM network_threats WHERE org_id=? AND status='active'
                    GROUP BY threat_type
                    """,
                    (org_id,),
                ).fetchall()
            }

            top_sources = [
                {"source_ip": r["source_ip"], "packet_count": r["packet_count"]}
                for r in conn.execute(
                    """
                    SELECT source_ip, SUM(packet_count) AS packet_count
                    FROM network_threats WHERE org_id=?
                    GROUP BY source_ip
                    ORDER BY packet_count DESC
                    LIMIT 5
                    """,
                    (org_id,),
                ).fetchall()
            ]

        return {
            "total": total,
            "active": active,
            "resolved": resolved,
            "by_severity": by_severity,
            "by_type": by_type,
            "top_source_ips": top_sources,
        }

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def create_rule(
        self,
        org_id: str,
        rule_name: str,
        rule_type: str,
        pattern: str,
        action: str,
    ) -> Dict[str, Any]:
        """Create a new threat detection rule."""
        now = _now()
        rule_id = str(uuid.uuid4())
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO threat_rules
                    (id, org_id, rule_name, rule_type, pattern, action,
                     enabled, match_count, last_matched, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (rule_id, org_id, rule_name, rule_type, pattern, action,
                 1, 0, "", now),
            )
            if _get_tg_bus:
                try:
                    bus = _get_tg_bus()
                    if bus and getattr(bus, "enabled", False):
                        bus.emit("FINDING_CREATED", {"entity_type": "network_threat_engine", "org_id": org_id, "source_engine": "network_threat_engine"})
                except Exception:
                    pass
            return dict(
                conn.execute(
                    "SELECT * FROM threat_rules WHERE id=?", (rule_id,)
                ).fetchone()
            )

    def trigger_rule(self, rule_id: str, org_id: str) -> Dict[str, Any]:
        """Increment match_count and update last_matched for a rule."""
        now = _now()
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM threat_rules WHERE id=? AND org_id=?",
                (rule_id, org_id),
            ).fetchone()
            if not row:
                raise KeyError(f"Rule {rule_id} not found")
            conn.execute(
                """
                UPDATE threat_rules
                SET match_count=match_count+1, last_matched=?
                WHERE id=? AND org_id=?
                """,
                (now, rule_id, org_id),
            )
            return dict(
                conn.execute(
                    "SELECT * FROM threat_rules WHERE id=?", (rule_id,)
                ).fetchone()
            )

    def list_rules(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List rules with optional enabled filter."""
        query = "SELECT * FROM threat_rules WHERE org_id=?"
        params: List[Any] = [org_id]
        if enabled is not None:
            query += " AND enabled=?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def update_baseline(
        self,
        org_id: str,
        metric_name: str,
        baseline_value: float,
        current_value: float,
    ) -> Dict[str, Any]:
        """Upsert a network baseline metric and compute anomaly flag."""
        baseline_value = float(baseline_value)
        current_value = float(current_value)
        deviation_pct = (
            abs((current_value - baseline_value) / baseline_value) * 100
            if baseline_value != 0
            else 0.0
        )
        anomaly = 1 if deviation_pct > 25.0 else 0
        now = _now()

        with self._lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM network_baselines WHERE org_id=? AND metric_name=?",
                (org_id, metric_name),
            ).fetchone()

            if existing:
                baseline_id = existing["id"]
                conn.execute(
                    """
                    UPDATE network_baselines
                    SET baseline_value=?, current_value=?, deviation_pct=?,
                        anomaly=?, updated_at=?
                    WHERE id=? AND org_id=?
                    """,
                    (baseline_value, current_value, deviation_pct, anomaly,
                     now, baseline_id, org_id),
                )
            else:
                baseline_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO network_baselines
                        (id, org_id, metric_name, baseline_value, current_value,
                         deviation_pct, anomaly, updated_at, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (baseline_id, org_id, metric_name, baseline_value,
                     current_value, deviation_pct, anomaly, now, now),
                )

            return dict(
                conn.execute(
                    "SELECT * FROM network_baselines WHERE id=?", (baseline_id,)
                ).fetchone()
            )

    def get_anomalous_baselines(self, org_id: str) -> List[Dict[str, Any]]:
        """Return baselines where anomaly=1."""
        with self._lock, self._conn() as conn:
            return [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT * FROM network_baselines
                    WHERE org_id=? AND anomaly=1
                    ORDER BY deviation_pct DESC
                    """,
                    (org_id,),
                ).fetchall()
            ]
