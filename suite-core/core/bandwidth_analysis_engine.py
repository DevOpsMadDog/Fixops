"""Bandwidth Analysis Engine — ALDECI.

Tracks network links, utilization samples, QoS policies, and anomaly detection.
Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "bandwidth_analysis.db"
)

_VALID_LINK_TYPES = {"fiber", "vpn", "internet", "mpls"}
_VALID_DIRECTIONS = {"inbound", "outbound", "both"}

# Threshold above which a link is considered "high utilization"
_HIGH_UTIL_THRESHOLD = 80.0
# Z-score threshold for anomaly detection
_ANOMALY_ZSCORE = 2.5


class BandwidthAnalysisEngine:
    """SQLite WAL-backed Bandwidth Analysis engine.

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
                CREATE TABLE IF NOT EXISTS bw_links (
                    link_id        TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    name           TEXT NOT NULL DEFAULT '',
                    capacity_mbps  REAL NOT NULL DEFAULT 0.0,
                    link_type      TEXT NOT NULL DEFAULT 'internet',
                    created_at     DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_bwl_org
                    ON bw_links (org_id);

                CREATE TABLE IF NOT EXISTS bw_utilization (
                    util_id           TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    link_id           TEXT NOT NULL,
                    utilization_pct   REAL NOT NULL DEFAULT 0.0,
                    direction         TEXT NOT NULL DEFAULT 'both',
                    recorded_at       DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_bwu_org_link
                    ON bw_utilization (org_id, link_id, recorded_at DESC);

                CREATE TABLE IF NOT EXISTS bw_qos_policies (
                    policy_id           TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL DEFAULT '',
                    priority            INTEGER NOT NULL DEFAULT 4,
                    traffic_class       TEXT NOT NULL DEFAULT '',
                    bandwidth_limit_pct REAL NOT NULL DEFAULT 100.0,
                    created_at          DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_bwqos_org
                    ON bw_qos_policies (org_id);
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
    # Links
    # ------------------------------------------------------------------

    def register_link(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new network link for bandwidth analysis."""
        link_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        link_type = data.get("link_type", "internet")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO bw_links
                        (link_id, org_id, name, capacity_mbps, link_type, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (
                        link_id, org_id,
                        data.get("name", ""),
                        float(data.get("capacity_mbps", 0.0)),
                        link_type,
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "bandwidth_analysis", "org_id": org_id, "source_engine": "bandwidth_analysis"})
            except Exception:
                pass

        return {
            "link_id": link_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "capacity_mbps": float(data.get("capacity_mbps", 0.0)),
            "link_type": link_type,
            "created_at": now,
        }

    def list_links(self, org_id: str) -> List[Dict[str, Any]]:
        """List all links registered for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM bw_links WHERE org_id=? ORDER BY name",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Utilization
    # ------------------------------------------------------------------

    def record_utilization(
        self, org_id: str, link_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a utilization sample for a link."""
        util_id = str(uuid.uuid4())
        recorded_at = data.get("recorded_at") or datetime.now(timezone.utc).isoformat()
        utilization_pct = max(0.0, min(100.0, float(data.get("utilization_pct", 0.0))))
        direction = data.get("direction", "both")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO bw_utilization
                        (util_id, org_id, link_id, utilization_pct, direction, recorded_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (util_id, org_id, link_id, utilization_pct, direction, recorded_at),
                )

        return {
            "util_id": util_id,
            "org_id": org_id,
            "link_id": link_id,
            "utilization_pct": utilization_pct,
            "direction": direction,
            "recorded_at": recorded_at,
        }

    def get_utilization_trend(
        self, org_id: str, link_id: str, hours: int = 24
    ) -> Dict[str, Any]:
        """Return avg_pct, peak_pct, and sample list over the last N hours."""
        with self._conn() as conn:
            agg = conn.execute(
                """
                SELECT
                    COUNT(*)                          AS sample_count,
                    COALESCE(AVG(utilization_pct), 0) AS avg_pct,
                    COALESCE(MAX(utilization_pct), 0) AS peak_pct
                FROM bw_utilization
                WHERE org_id=? AND link_id=?
                  AND recorded_at >= datetime('now', ? || ' hours')
                """,
                (org_id, link_id, f"-{hours}"),
            ).fetchone()

            sample_rows = conn.execute(
                """
                SELECT utilization_pct, direction, recorded_at
                FROM bw_utilization
                WHERE org_id=? AND link_id=?
                  AND recorded_at >= datetime('now', ? || ' hours')
                ORDER BY recorded_at ASC
                """,
                (org_id, link_id, f"-{hours}"),
            ).fetchall()

        return {
            "link_id": link_id,
            "org_id": org_id,
            "hours": hours,
            "sample_count": int(agg["sample_count"]),
            "avg_pct": round(float(agg["avg_pct"]), 2),
            "peak_pct": round(float(agg["peak_pct"]), 2),
            "samples": [self._row(r) for r in sample_rows],
        }

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def detect_anomaly(self, org_id: str, link_id: str) -> Dict[str, Any]:
        """Detect utilization anomaly using z-score against recent 24h baseline.

        Returns anomaly_detected bool, score (z-score), and details.
        """
        with self._conn() as conn:
            # Latest sample by rowid
            latest = conn.execute(
                """
                SELECT rowid, utilization_pct, recorded_at
                FROM bw_utilization
                WHERE org_id=? AND link_id=?
                ORDER BY rowid DESC LIMIT 1
                """,
                (org_id, link_id),
            ).fetchone()

            if not latest:
                return {
                    "link_id": link_id,
                    "org_id": org_id,
                    "anomaly_detected": False,
                    "score": 0.0,
                    "details": "Insufficient data for anomaly detection",
                }

            latest_rowid = latest["rowid"]

            # Baseline: all samples except the latest row
            baseline = conn.execute(
                """
                SELECT
                    COUNT(*)                          AS n,
                    COALESCE(AVG(utilization_pct), 0) AS mean,
                    COALESCE(
                        AVG(utilization_pct * utilization_pct) -
                        AVG(utilization_pct) * AVG(utilization_pct),
                        0
                    ) AS variance
                FROM bw_utilization
                WHERE org_id=? AND link_id=?
                  AND rowid != ?
                """,
                (org_id, link_id, latest_rowid),
            ).fetchone()

        if not latest or int(baseline["n"]) < 2:
            return {
                "link_id": link_id,
                "org_id": org_id,
                "anomaly_detected": False,
                "score": 0.0,
                "details": "Insufficient data for anomaly detection",
            }

        mean = float(baseline["mean"])
        variance = float(baseline["variance"])
        std = variance ** 0.5 if variance > 0 else 0.0
        current = float(latest["utilization_pct"])

        if std == 0:
            # All baseline samples identical; any deviation is a perfect anomaly
            z_score = abs(current - mean) if current != mean else 0.0
        else:
            z_score = abs(current - mean) / std

        anomaly_detected = z_score > _ANOMALY_ZSCORE

        return {
            "link_id": link_id,
            "org_id": org_id,
            "anomaly_detected": anomaly_detected,
            "score": round(z_score, 4),
            "current_pct": current,
            "mean_pct": round(mean, 2),
            "std_pct": round(std, 2),
            "details": (
                f"Z-score {z_score:.2f} {'exceeds' if anomaly_detected else 'within'} "
                f"threshold {_ANOMALY_ZSCORE} "
                f"(current={current:.1f}%, mean={mean:.1f}%, std={std:.1f}%)"
            ),
        }

    # ------------------------------------------------------------------
    # QoS policies
    # ------------------------------------------------------------------

    def create_qos_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a QoS policy for traffic shaping."""
        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        priority = max(1, min(8, int(data.get("priority", 4))))
        bandwidth_limit_pct = max(0.0, min(100.0, float(data.get("bandwidth_limit_pct", 100.0))))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO bw_qos_policies
                        (policy_id, org_id, name, priority, traffic_class,
                         bandwidth_limit_pct, created_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        policy_id, org_id,
                        data.get("name", ""),
                        priority,
                        data.get("traffic_class", ""),
                        bandwidth_limit_pct,
                        now,
                    ),
                )

        return {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "priority": priority,
            "traffic_class": data.get("traffic_class", ""),
            "bandwidth_limit_pct": bandwidth_limit_pct,
            "created_at": now,
        }

    def list_qos_policies(self, org_id: str) -> List[Dict[str, Any]]:
        """List QoS policies for an org ordered by priority."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM bw_qos_policies WHERE org_id=? ORDER BY priority ASC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_bandwidth_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate bandwidth stats for an org."""
        with self._conn() as conn:
            total_links = conn.execute(
                "SELECT COUNT(*) FROM bw_links WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            avg_util = conn.execute(
                """
                SELECT COALESCE(AVG(u.utilization_pct), 0)
                FROM bw_utilization u
                WHERE u.org_id=?
                  AND u.recorded_at >= datetime('now', '-24 hours')
                """,
                (org_id,),
            ).fetchone()[0]

            # Links with avg utilization > threshold in last 24h
            high_util_links = conn.execute(
                """
                SELECT COUNT(DISTINCT link_id) FROM bw_utilization
                WHERE org_id=?
                  AND recorded_at >= datetime('now', '-24 hours')
                  AND utilization_pct >= ?
                """,
                (org_id, _HIGH_UTIL_THRESHOLD),
            ).fetchone()[0]

            qos_count = conn.execute(
                "SELECT COUNT(*) FROM bw_qos_policies WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_links": total_links,
            "avg_utilization_pct": round(float(avg_util), 2),
            "high_util_links": high_util_links,
            "qos_policy_count": qos_count,
        }
