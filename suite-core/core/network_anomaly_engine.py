"""
NetworkAnomalyEngine — ALDECI.

Network traffic anomaly detection using baseline deviation analysis.
Records traffic samples, maintains rolling baselines (avg + stdev),
detects spikes/drops beyond configurable thresholds, and tracks anomaly lifecycle.

SQLite WAL + threading.RLock + org_id multi-tenant.

Compliance: NIST SP 800-137 (continuous monitoring), SOC2 CC7.1.
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_anomaly.db"
)

VALID_PROTOCOLS = frozenset({
    "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMTP", "FTP", "SSH", "other"
})
VALID_DIRECTIONS = frozenset({"inbound", "outbound", "lateral"})
VALID_ANOMALY_TYPES = frozenset({"spike", "drop", "new_protocol", "new_segment"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_STATUSES = frozenset({"active", "resolved", "suppressed"})

_DEVIATION_THRESHOLD = 50.0   # % — minimum to flag
_HIGH_THRESHOLD = 100.0        # % — high severity
_CRITICAL_THRESHOLD = 200.0    # % — critical severity


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _today_iso() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _stdev(values: List[float]) -> float:
    """Population-style stdev (safe for small n)."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    return math.sqrt(variance)


class NetworkAnomalyEngine:
    """
    SQLite-backed network anomaly detection engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: Path to SQLite database. Defaults to
                 .fixops_data/network_anomaly.db.
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
        with self._get_conn() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS traffic_baselines (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    segment             TEXT NOT NULL,
                    protocol            TEXT NOT NULL,
                    direction           TEXT NOT NULL,
                    avg_bytes_per_min   REAL DEFAULT 0.0,
                    avg_packets_per_min REAL DEFAULT 0.0,
                    std_dev_bytes       REAL DEFAULT 0.0,
                    sample_count        INTEGER DEFAULT 0,
                    baseline_date       TEXT,
                    created_at          TEXT NOT NULL,
                    UNIQUE(org_id, segment, protocol, direction)
                );

                CREATE TABLE IF NOT EXISTS traffic_samples (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    segment             TEXT NOT NULL,
                    protocol            TEXT NOT NULL,
                    direction           TEXT NOT NULL,
                    bytes_per_min       REAL NOT NULL,
                    packets_per_min     REAL NOT NULL,
                    sampled_at          TEXT NOT NULL,
                    created_at          TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS network_anomalies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    segment         TEXT NOT NULL,
                    protocol        TEXT NOT NULL,
                    anomaly_type    TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    deviation_pct   REAL NOT NULL,
                    baseline_value  REAL NOT NULL,
                    observed_value  REAL NOT NULL,
                    detected_at     TEXT NOT NULL,
                    resolved_at     TEXT,
                    status          TEXT DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_samples_org_seg_proto
                    ON traffic_samples(org_id, segment, protocol, direction, sampled_at);
                CREATE INDEX IF NOT EXISTS idx_anomalies_org_status
                    ON network_anomalies(org_id, status);
                CREATE INDEX IF NOT EXISTS idx_baselines_org
                    ON traffic_baselines(org_id);
                """
            )

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Samples
    # ------------------------------------------------------------------

    def record_sample(
        self,
        org_id: str,
        segment: str,
        protocol: str,
        direction: str,
        bytes_per_min: float,
        packets_per_min: float,
    ) -> Dict[str, Any]:
        """Record a traffic sample."""
        sample_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO traffic_samples
                        (id, org_id, segment, protocol, direction,
                         bytes_per_min, packets_per_min, sampled_at, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (sample_id, org_id, segment, protocol, direction,
                     bytes_per_min, packets_per_min, now, now),
                )
        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("FINDING_CREATED", {"entity_type": "network_anomaly_engine", "org_id": org_id, "source_engine": "network_anomaly_engine"})
            except Exception:
                pass
        return {
            "id": sample_id,
            "org_id": org_id,
            "segment": segment,
            "protocol": protocol,
            "direction": direction,
            "bytes_per_min": bytes_per_min,
            "packets_per_min": packets_per_min,
            "sampled_at": now,
        }

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def update_baseline(
        self,
        org_id: str,
        segment: str,
        protocol: str,
        direction: str,
    ) -> Dict[str, Any]:
        """
        Recompute baseline from last 100 samples for this
        (org_id, segment, protocol, direction) tuple.
        Uses INSERT OR REPLACE on the UNIQUE constraint.
        """
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT bytes_per_min, packets_per_min
                    FROM traffic_samples
                    WHERE org_id = ? AND segment = ? AND protocol = ? AND direction = ?
                    ORDER BY sampled_at DESC LIMIT 100
                    """,
                    (org_id, segment, protocol, direction),
                ).fetchall()

                if not rows:
                    return {
                        "org_id": org_id, "segment": segment,
                        "protocol": protocol, "direction": direction,
                        "sample_count": 0,
                    }

                bytes_vals = [r["bytes_per_min"] for r in rows]
                packets_vals = [r["packets_per_min"] for r in rows]
                n = len(bytes_vals)
                avg_bytes = sum(bytes_vals) / n
                avg_packets = sum(packets_vals) / n
                std_bytes = _stdev(bytes_vals)
                today = _today_iso()
                now = _now_iso()

                # Check if baseline already exists
                existing = conn.execute(
                    "SELECT id FROM traffic_baselines WHERE org_id = ? AND segment = ? AND protocol = ? AND direction = ?",
                    (org_id, segment, protocol, direction),
                ).fetchone()

                if existing:
                    conn.execute(
                        """
                        UPDATE traffic_baselines
                        SET avg_bytes_per_min = ?, avg_packets_per_min = ?,
                            std_dev_bytes = ?, sample_count = ?, baseline_date = ?
                        WHERE org_id = ? AND segment = ? AND protocol = ? AND direction = ?
                        """,
                        (avg_bytes, avg_packets, std_bytes, n, today,
                         org_id, segment, protocol, direction),
                    )
                    baseline_id = existing["id"]
                else:
                    baseline_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO traffic_baselines
                            (id, org_id, segment, protocol, direction,
                             avg_bytes_per_min, avg_packets_per_min,
                             std_dev_bytes, sample_count, baseline_date, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (baseline_id, org_id, segment, protocol, direction,
                         avg_bytes, avg_packets, std_bytes, n, today, now),
                    )

                return {
                    "id": baseline_id,
                    "org_id": org_id,
                    "segment": segment,
                    "protocol": protocol,
                    "direction": direction,
                    "avg_bytes_per_min": avg_bytes,
                    "avg_packets_per_min": avg_packets,
                    "std_dev_bytes": std_bytes,
                    "sample_count": n,
                    "baseline_date": today,
                }

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_anomalies(
        self,
        org_id: str,
        segment: str,
        protocol: str,
        direction: str,
        bytes_per_min: float,
        packets_per_min: float,
    ) -> List[Dict[str, Any]]:
        """
        Compare observed traffic to baseline. Insert anomaly if deviation > 50%.
        Returns list of detected anomalies (may be empty).
        """
        now = _now_iso()
        detected: List[Dict[str, Any]] = []

        with self._lock:
            with self._get_conn() as conn:
                baseline_row = conn.execute(
                    """
                    SELECT avg_bytes_per_min, avg_packets_per_min
                    FROM traffic_baselines
                    WHERE org_id = ? AND segment = ? AND protocol = ? AND direction = ?
                    """,
                    (org_id, segment, protocol, direction),
                ).fetchone()

                if not baseline_row:
                    return []  # No baseline to compare against

                baseline_bytes = baseline_row["avg_bytes_per_min"]

                # Only check bytes deviation (primary metric)
                if baseline_bytes <= 0:
                    return []

                deviation_pct = (bytes_per_min - baseline_bytes) / baseline_bytes * 100.0
                abs_dev = abs(deviation_pct)

                if abs_dev <= _DEVIATION_THRESHOLD:
                    return []

                # Determine severity
                if abs_dev > _CRITICAL_THRESHOLD:
                    severity = "critical"
                elif abs_dev > _HIGH_THRESHOLD:
                    severity = "high"
                else:
                    severity = "medium"

                anomaly_type = "spike" if bytes_per_min > baseline_bytes else "drop"
                anomaly_id = str(uuid.uuid4())

                conn.execute(
                    """
                    INSERT INTO network_anomalies
                        (id, org_id, segment, protocol, anomaly_type, severity,
                         deviation_pct, baseline_value, observed_value,
                         detected_at, resolved_at, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'active', ?)
                    """,
                    (anomaly_id, org_id, segment, protocol, anomaly_type, severity,
                     deviation_pct, baseline_bytes, bytes_per_min, now, now),
                )

                detected.append({
                    "id": anomaly_id,
                    "org_id": org_id,
                    "segment": segment,
                    "protocol": protocol,
                    "anomaly_type": anomaly_type,
                    "severity": severity,
                    "deviation_pct": deviation_pct,
                    "baseline_value": baseline_bytes,
                    "observed_value": bytes_per_min,
                    "detected_at": now,
                    "status": "active",
                })

        return detected

    def resolve_anomaly(self, anomaly_id: str, org_id: str) -> Dict[str, Any]:
        """Resolve an anomaly: status=resolved, resolved_at=now."""
        now = _now_iso()
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT id FROM network_anomalies WHERE id = ? AND org_id = ?",
                    (anomaly_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Anomaly {anomaly_id} not found for org {org_id}")
                conn.execute(
                    "UPDATE network_anomalies SET status = 'resolved', resolved_at = ? WHERE id = ? AND org_id = ?",
                    (now, anomaly_id, org_id),
                )
        return {"anomaly_id": anomaly_id, "status": "resolved", "resolved_at": now}

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def get_anomaly_summary(self, org_id: str) -> Dict[str, Any]:
        """Return total, active, by_severity, by_segment, recent_anomalies (last 10)."""
        with self._lock:
            with self._get_conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) FROM network_anomalies WHERE org_id = ?", (org_id,)
                ).fetchone()[0]
                active = conn.execute(
                    "SELECT COUNT(*) FROM network_anomalies WHERE org_id = ? AND status = 'active'",
                    (org_id,),
                ).fetchone()[0]

                severity_rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM network_anomalies WHERE org_id = ? GROUP BY severity",
                    (org_id,),
                ).fetchall()
                by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

                segment_rows = conn.execute(
                    "SELECT segment, COUNT(*) as cnt FROM network_anomalies WHERE org_id = ? GROUP BY segment",
                    (org_id,),
                ).fetchall()
                by_segment = {r["segment"]: r["cnt"] for r in segment_rows}

                recent = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT * FROM network_anomalies WHERE org_id = ? ORDER BY detected_at DESC LIMIT 10",
                        (org_id,),
                    ).fetchall()
                ]

                return {
                    "total": total,
                    "active": active,
                    "by_severity": by_severity,
                    "by_segment": by_segment,
                    "recent_anomalies": recent,
                }

    def get_baseline_health(self, org_id: str) -> List[Dict[str, Any]]:
        """Return all baselines with sample_count, std_dev_bytes, baseline_date."""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM traffic_baselines WHERE org_id = ? ORDER BY segment, protocol",
                    (org_id,),
                ).fetchall()
                return [dict(r) for r in rows]

    def get_traffic_trend(
        self,
        org_id: str,
        segment: str,
        protocol: str,
        hours: int = 24,
    ) -> List[Dict[str, Any]]:
        """Return samples from last N hours ordered by sampled_at."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT * FROM traffic_samples
                    WHERE org_id = ? AND segment = ? AND protocol = ?
                      AND sampled_at >= ?
                    ORDER BY sampled_at ASC
                    """,
                    (org_id, segment, protocol, cutoff),
                ).fetchall()
                return [dict(r) for r in rows]
