"""Microsegmentation Policy Engine — ALDECI.

Manages network microsegments, inter-segment policies, and violation tracking.

Capabilities:
  - Segment registry with enforcement modes (enforcing/monitoring/disabled)
  - Policy management (allow/deny/inspect/log/rate_limit between segment pairs)
  - Violation recording with severity tracking
  - Stats aggregation per org (high-violation segment detection)

Compliance: NIST SP 800-207 (Zero Trust), CIS Controls v8 (Control 12)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "microsegmentation_policy.db")

_VALID_SEGMENT_TYPES = {"workload", "application", "database", "dmz", "iot", "management", "production", "development"}
_VALID_POLICY_ACTIONS = {"allow", "deny", "inspect", "log", "rate_limit"}
_VALID_PROTOCOLS = {"tcp", "udp", "icmp", "any", "http", "https", "dns", "smtp"}
_VALID_ENFORCEMENT_MODES = {"enforcing", "monitoring", "disabled"}
_VALID_VIOLATION_TYPES = {"blocked_traffic", "policy_mismatch", "unauthorized_lateral", "data_exfil_attempt"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MicrosegmentationPolicyEngine:
    """SQLite WAL-backed Microsegmentation Policy engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/microsegmentation_policy.db
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS msp_segments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL DEFAULT '',
                    segment_type     TEXT NOT NULL DEFAULT 'workload',
                    cidr_range       TEXT NOT NULL DEFAULT '',
                    description      TEXT NOT NULL DEFAULT '',
                    enforcement_mode TEXT NOT NULL DEFAULT 'monitoring',
                    policy_count     INTEGER NOT NULL DEFAULT 0,
                    violation_count  INTEGER NOT NULL DEFAULT 0,
                    created_at       DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_msp_segments_org
                    ON msp_segments(org_id, segment_type, enforcement_mode);

                CREATE TABLE IF NOT EXISTS msp_policies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    src_segment_id  TEXT NOT NULL,
                    dst_segment_id  TEXT NOT NULL,
                    policy_action   TEXT NOT NULL DEFAULT 'allow',
                    protocol        TEXT NOT NULL DEFAULT 'tcp',
                    port_range      TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    match_count     INTEGER NOT NULL DEFAULT 0,
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_msp_policies_org
                    ON msp_policies(org_id, src_segment_id, dst_segment_id, policy_action);

                CREATE TABLE IF NOT EXISTS msp_violations (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    segment_id     TEXT NOT NULL,
                    src_ip         TEXT NOT NULL DEFAULT '',
                    dst_ip         TEXT NOT NULL DEFAULT '',
                    protocol       TEXT NOT NULL DEFAULT 'tcp',
                    port           INTEGER NOT NULL DEFAULT 0,
                    violation_type TEXT NOT NULL DEFAULT 'blocked_traffic',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    detected_at    DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_msp_violations_org
                    ON msp_violations(org_id, segment_id, severity);
            """)

    @staticmethod
    def _row(row) -> dict:
        return dict(row)

    # ------------------------------------------------------------------
    # Segment CRUD
    # ------------------------------------------------------------------

    def create_segment(self, org_id: str, data: dict) -> dict:
        """Create a microsegment."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        segment_type = (data.get("segment_type") or "").strip().lower()
        if segment_type not in _VALID_SEGMENT_TYPES:
            raise ValueError(f"segment_type must be one of {sorted(_VALID_SEGMENT_TYPES)}")
        enforcement_mode = (data.get("enforcement_mode") or "monitoring").strip().lower()
        if enforcement_mode not in _VALID_ENFORCEMENT_MODES:
            raise ValueError(f"enforcement_mode must be one of {sorted(_VALID_ENFORCEMENT_MODES)}")

        seg_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": seg_id,
            "org_id": org_id,
            "name": name,
            "segment_type": segment_type,
            "cidr_range": (data.get("cidr_range") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "enforcement_mode": enforcement_mode,
            "policy_count": 0,
            "violation_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO msp_segments
                       (id, org_id, name, segment_type, cidr_range, description,
                        enforcement_mode, policy_count, violation_count, created_at)
                       VALUES (:id, :org_id, :name, :segment_type, :cidr_range, :description,
                               :enforcement_mode, :policy_count, :violation_count, :created_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "microsegmentation_policy", "org_id": org_id, "source_engine": "microsegmentation_policy"})
            except Exception:
                pass

        return row

    def list_segments(
        self,
        org_id: str,
        segment_type: Optional[str] = None,
        enforcement_mode: Optional[str] = None,
    ) -> List[dict]:
        """List segments with optional filters."""
        sql = "SELECT * FROM msp_segments WHERE org_id=?"
        params: list = [org_id]
        if segment_type:
            sql += " AND segment_type=?"
            params.append(segment_type)
        if enforcement_mode:
            sql += " AND enforcement_mode=?"
            params.append(enforcement_mode)
        sql += " ORDER BY created_at"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_segment(self, org_id: str, segment_id: str) -> Optional[dict]:
        """Get a single segment by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM msp_segments WHERE id=? AND org_id=?",
                    (segment_id, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: dict) -> dict:
        """Create a microsegmentation policy between two segments."""
        src_segment_id = (data.get("src_segment_id") or "").strip()
        if not src_segment_id:
            raise ValueError("src_segment_id is required")
        dst_segment_id = (data.get("dst_segment_id") or "").strip()
        if not dst_segment_id:
            raise ValueError("dst_segment_id is required")
        policy_action = (data.get("policy_action") or "allow").strip().lower()
        if policy_action not in _VALID_POLICY_ACTIONS:
            raise ValueError(f"policy_action must be one of {sorted(_VALID_POLICY_ACTIONS)}")
        protocol = (data.get("protocol") or "tcp").strip().lower()
        if protocol not in _VALID_PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOCOLS)}")

        policy_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": policy_id,
            "org_id": org_id,
            "src_segment_id": src_segment_id,
            "dst_segment_id": dst_segment_id,
            "policy_action": policy_action,
            "protocol": protocol,
            "port_range": (data.get("port_range") or "").strip(),
            "description": (data.get("description") or "").strip(),
            "enabled": 1,
            "match_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO msp_policies
                       (id, org_id, src_segment_id, dst_segment_id, policy_action, protocol,
                        port_range, description, enabled, match_count, created_at)
                       VALUES (:id, :org_id, :src_segment_id, :dst_segment_id, :policy_action, :protocol,
                               :port_range, :description, :enabled, :match_count, :created_at)""",
                    row,
                )
                # Increment policy_count for both segments
                conn.execute(
                    "UPDATE msp_segments SET policy_count = policy_count + 1 WHERE id=? AND org_id=?",
                    (src_segment_id, org_id),
                )
                conn.execute(
                    "UPDATE msp_segments SET policy_count = policy_count + 1 WHERE id=? AND org_id=?",
                    (dst_segment_id, org_id),
                )
        return row

    def list_policies(
        self,
        org_id: str,
        src_segment_id: Optional[str] = None,
        dst_segment_id: Optional[str] = None,
        policy_action: Optional[str] = None,
    ) -> List[dict]:
        """List policies with optional filters."""
        sql = "SELECT * FROM msp_policies WHERE org_id=?"
        params: list = [org_id]
        if src_segment_id:
            sql += " AND src_segment_id=?"
            params.append(src_segment_id)
        if dst_segment_id:
            sql += " AND dst_segment_id=?"
            params.append(dst_segment_id)
        if policy_action:
            sql += " AND policy_action=?"
            params.append(policy_action)
        sql += " ORDER BY created_at"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    def record_violation(self, org_id: str, data: dict) -> dict:
        """Record a microsegmentation policy violation."""
        segment_id = (data.get("segment_id") or "").strip()
        if not segment_id:
            raise ValueError("segment_id is required")

        violation_type = (data.get("violation_type") or "blocked_traffic").strip().lower()
        if violation_type not in _VALID_VIOLATION_TYPES:
            raise ValueError(f"violation_type must be one of {sorted(_VALID_VIOLATION_TYPES)}")

        violation_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": violation_id,
            "org_id": org_id,
            "segment_id": segment_id,
            "src_ip": (data.get("src_ip") or "").strip(),
            "dst_ip": (data.get("dst_ip") or "").strip(),
            "protocol": (data.get("protocol") or "tcp").strip().lower(),
            "port": int(data.get("port") or 0),
            "violation_type": violation_type,
            "severity": (data.get("severity") or "medium").strip().lower(),
            "detected_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO msp_violations
                       (id, org_id, segment_id, src_ip, dst_ip, protocol, port,
                        violation_type, severity, detected_at)
                       VALUES (:id, :org_id, :segment_id, :src_ip, :dst_ip, :protocol, :port,
                               :violation_type, :severity, :detected_at)""",
                    row,
                )
                # Increment violation_count for the segment
                conn.execute(
                    "UPDATE msp_segments SET violation_count = violation_count + 1 WHERE id=? AND org_id=?",
                    (segment_id, org_id),
                )
        return row

    def list_violations(
        self,
        org_id: str,
        segment_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[dict]:
        """List violations with optional filters."""
        sql = "SELECT * FROM msp_violations WHERE org_id=?"
        params: list = [org_id]
        if segment_id:
            sql += " AND segment_id=?"
            params.append(segment_id)
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_segmentation_stats(self, org_id: str) -> dict:
        """Return aggregated microsegmentation statistics for the org."""
        with self._lock:
            with self._conn() as conn:
                total_segments = conn.execute(
                    "SELECT COUNT(*) FROM msp_segments WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                total_policies = conn.execute(
                    "SELECT COUNT(*) FROM msp_policies WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                total_violations = conn.execute(
                    "SELECT COUNT(*) FROM msp_violations WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                enforcing_segments = conn.execute(
                    "SELECT COUNT(*) FROM msp_segments WHERE org_id=? AND enforcement_mode='enforcing'",
                    (org_id,),
                ).fetchone()[0]

                # By segment type counts
                type_rows = conn.execute(
                    "SELECT segment_type, COUNT(*) as cnt FROM msp_segments WHERE org_id=? GROUP BY segment_type",
                    (org_id,),
                ).fetchall()
                by_segment_type = {r["segment_type"]: r["cnt"] for r in type_rows}

                # High violation segments (violation_count > 5)
                high_violation_rows = conn.execute(
                    "SELECT * FROM msp_segments WHERE org_id=? AND violation_count > 5 ORDER BY violation_count DESC",
                    (org_id,),
                ).fetchall()
                high_violation_segments = [self._row(r) for r in high_violation_rows]

        return {
            "org_id": org_id,
            "total_segments": total_segments,
            "total_policies": total_policies,
            "total_violations": total_violations,
            "enforcing_segments": enforcing_segments,
            "by_segment_type": by_segment_type,
            "high_violation_segments": high_violation_segments,
        }
