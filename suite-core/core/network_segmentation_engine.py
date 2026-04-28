"""Network Segmentation Engine — ALDECI.

Manages network segments, inter-segment flow policies, and lateral movement risk.

Capabilities:
  - Segment registry (DMZ, internal, guest, management, prod, dev)
  - Flow policy management (allow/deny between segment pairs)
  - Flow lookup (is traffic from segment A to segment B on port P allowed?)
  - Lateral movement risk detection (risky allow-all between different trust levels)
  - Segmentation score (0-100, grade A-F) based on policy coverage and isolation
  - Stats aggregation per org

Compliance: NIST SP 800-125B, CIS Controls v8 (Control 12), Zero Trust principles
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_SEGMENT_TYPES = {"dmz", "internal", "guest", "management", "prod", "dev"}
_VALID_FLOW_ACTIONS = {"allow", "deny"}

# High-trust segments — lateral movement into these is particularly risky
_HIGH_TRUST_TYPES = {"management", "prod"}

# Trust level thresholds
_TRUST_GAP_THRESHOLD = 3  # segments more than this apart in trust level are risky if allow-all


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class NetworkSegmentationEngine:
    """SQLite WAL-backed Network Segmentation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Database stored at .fixops_data/network_segmentation.db (shared, org_id-scoped rows).
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        db_dir = _DEFAULT_DB_DIR
        db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = db_path or str(db_dir / "network_segmentation.db")
        self._lock = threading.RLock()
        self._initialized = False
        self._ensure_init()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            with self._conn() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS segments (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        name            TEXT NOT NULL,
                        cidr            TEXT NOT NULL DEFAULT '',
                        segment_type    TEXT NOT NULL,
                        trust_level     INTEGER NOT NULL DEFAULT 5,
                        description     TEXT NOT NULL DEFAULT '',
                        created_at      DATETIME NOT NULL,
                        updated_at      DATETIME NOT NULL
                    );

                    CREATE INDEX IF NOT EXISTS idx_segments_org
                        ON segments(org_id, segment_type);

                    CREATE TABLE IF NOT EXISTS flow_policies (
                        id              TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        src_segment_id  TEXT NOT NULL,
                        dst_segment_id  TEXT NOT NULL,
                        action          TEXT NOT NULL,
                        ports           TEXT NOT NULL DEFAULT '[]',
                        justification   TEXT NOT NULL DEFAULT '',
                        created_at      DATETIME NOT NULL,
                        updated_at      DATETIME NOT NULL,
                        FOREIGN KEY (src_segment_id) REFERENCES segments(id),
                        FOREIGN KEY (dst_segment_id) REFERENCES segments(id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_flow_policies_org
                        ON flow_policies(org_id, src_segment_id, dst_segment_id);
                """)
            self._initialized = True

    # ------------------------------------------------------------------
    # Segment CRUD
    # ------------------------------------------------------------------

    def create_segment(self, org_id: str, data: dict) -> dict:
        """Create a network segment."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")
        segment_type = (data.get("segment_type") or "").strip().lower()
        if segment_type not in _VALID_SEGMENT_TYPES:
            raise ValueError(f"segment_type must be one of {sorted(_VALID_SEGMENT_TYPES)}")
        trust_level = int(data.get("trust_level", 5))
        if not (0 <= trust_level <= 10):
            raise ValueError("trust_level must be between 0 and 10")

        seg_id = str(uuid.uuid4())
        now = _now_iso()
        row = {
            "id": seg_id,
            "org_id": org_id,
            "name": name,
            "cidr": (data.get("cidr") or "").strip(),
            "segment_type": segment_type,
            "trust_level": trust_level,
            "description": (data.get("description") or "").strip(),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO segments
                       (id, org_id, name, cidr, segment_type, trust_level, description, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :cidr, :segment_type, :trust_level, :description, :created_at, :updated_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "network_segmentation", "org_id": org_id, "source_engine": "network_segmentation"})
            except Exception:
                pass

        return row

    def list_segments(
        self,
        org_id: str,
        segment_type: Optional[str] = None,
    ) -> list:
        """List segments, optionally filtered by type."""
        sql = "SELECT * FROM segments WHERE org_id=?"
        params: list = [org_id]
        if segment_type:
            sql += " AND segment_type=?"
            params.append(segment_type)
        sql += " ORDER BY trust_level DESC, name"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def _get_segment(self, org_id: str, segment_id: str) -> Optional[dict]:
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM segments WHERE id=? AND org_id=?",
                    (segment_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Flow policy CRUD
    # ------------------------------------------------------------------

    def add_flow_policy(self, org_id: str, data: dict) -> dict:
        """Add a flow policy between two segments."""
        src_id = (data.get("src_segment_id") or "").strip()
        dst_id = (data.get("dst_segment_id") or "").strip()
        if not src_id:
            raise ValueError("src_segment_id is required")
        if not dst_id:
            raise ValueError("dst_segment_id is required")
        action = (data.get("action") or "").strip().lower()
        if action not in _VALID_FLOW_ACTIONS:
            raise ValueError(f"action must be one of {sorted(_VALID_FLOW_ACTIONS)}")

        # Verify both segments belong to org
        src_seg = self._get_segment(org_id, src_id)
        if not src_seg:
            raise ValueError(f"Source segment {src_id!r} not found")
        dst_seg = self._get_segment(org_id, dst_id)
        if not dst_seg:
            raise ValueError(f"Destination segment {dst_id!r} not found")

        policy_id = str(uuid.uuid4())
        now = _now_iso()
        ports = data.get("ports") or []
        row = {
            "id": policy_id,
            "org_id": org_id,
            "src_segment_id": src_id,
            "dst_segment_id": dst_id,
            "action": action,
            "ports": json.dumps([str(p) for p in ports]),
            "justification": (data.get("justification") or "").strip(),
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO flow_policies
                       (id, org_id, src_segment_id, dst_segment_id, action, ports, justification, created_at, updated_at)
                       VALUES (:id, :org_id, :src_segment_id, :dst_segment_id, :action, :ports, :justification, :created_at, :updated_at)""",
                    row,
                )
        return self._policy_to_dict(row)

    def list_flow_policies(self, org_id: str) -> list:
        """List all flow policies for the org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM flow_policies WHERE org_id=? ORDER BY created_at",
                    (org_id,),
                ).fetchall()
        return [self._policy_to_dict(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Flow check
    # ------------------------------------------------------------------

    def check_flow_allowed(
        self,
        org_id: str,
        src_segment_id: str,
        dst_segment_id: str,
        port: int,
    ) -> dict:
        """Check whether traffic from src to dst on the given port is allowed.

        Returns:
          allowed: bool
          policy_matched: dict or None
          reason: str
        """
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM flow_policies
                       WHERE org_id=? AND src_segment_id=? AND dst_segment_id=?
                       ORDER BY created_at""",
                    (org_id, src_segment_id, dst_segment_id),
                ).fetchall()

        policies = [self._policy_to_dict(dict(r)) for r in rows]
        str_port = str(port)

        for policy in policies:
            ports = policy["ports"]
            # Empty ports list means all ports
            if not ports or str_port in ports:
                allowed = policy["action"] == "allow"
                return {
                    "allowed": allowed,
                    "policy_matched": policy,
                    "reason": (
                        f"Matched policy '{policy['id']}' — {policy['action'].upper()} "
                        f"on port {port}"
                    ),
                }

        # No policy found — default deny
        return {
            "allowed": False,
            "policy_matched": None,
            "reason": "No matching flow policy — default deny",
        }

    # ------------------------------------------------------------------
    # Risk analysis
    # ------------------------------------------------------------------

    def detect_lateral_movement_risk(self, org_id: str) -> list:
        """Detect segment pairs with risky allow-all between different trust levels.

        Risk criteria:
        - Action is allow
        - No port restriction (empty ports list = all ports)
        - Trust level gap between src and dst exceeds threshold OR
          dst is a high-trust segment type
        """
        policies = self.list_flow_policies(org_id)
        segments_by_id: dict = {s["id"]: s for s in self.list_segments(org_id)}
        risks = []

        for policy in policies:
            if policy["action"] != "allow":
                continue
            ports = policy["ports"]
            is_allow_all_ports = not ports

            src = segments_by_id.get(policy["src_segment_id"])
            dst = segments_by_id.get(policy["dst_segment_id"])
            if not src or not dst:
                continue

            src_trust = src["trust_level"]
            dst_trust = dst["trust_level"]
            trust_gap = abs(dst_trust - src_trust)
            dst_high_trust = dst["segment_type"] in _HIGH_TRUST_TYPES

            if is_allow_all_ports and (trust_gap >= _TRUST_GAP_THRESHOLD or dst_high_trust):
                severity = "critical" if (dst_high_trust and trust_gap >= _TRUST_GAP_THRESHOLD) else "high"
                risks.append({
                    "policy_id": policy["id"],
                    "src_segment_id": src["id"],
                    "src_segment_name": src["name"],
                    "src_trust_level": src_trust,
                    "dst_segment_id": dst["id"],
                    "dst_segment_name": dst["name"],
                    "dst_trust_level": dst_trust,
                    "trust_gap": trust_gap,
                    "severity": severity,
                    "risk_description": (
                        f"Allow-all flow from '{src['name']}' (trust={src_trust}) "
                        f"to '{dst['name']}' (trust={dst_trust}, type={dst['segment_type']}) "
                        "enables lateral movement"
                    ),
                })

        return risks

    def get_segmentation_score(self, org_id: str) -> dict:
        """Compute a segmentation score (0-100) with grade and findings.

        Scoring:
        - Start at 100
        - -20 per critical lateral movement risk
        - -10 per high lateral movement risk
        - -5 per segment with no deny policies
        - -3 per segment pair with allow-all (all ports)
        - Bonus +5 if all high-trust segments have explicit deny policies
        """
        segments = self.list_segments(org_id)
        policies = self.list_flow_policies(org_id)
        risks = self.detect_lateral_movement_risk(org_id)
        findings = []
        score = 100

        # Penalize lateral movement risks
        for risk in risks:
            if risk["severity"] == "critical":
                score -= 20
                findings.append({
                    "severity": "critical",
                    "finding": risk["risk_description"],
                })
            else:
                score -= 10
                findings.append({
                    "severity": "high",
                    "finding": risk["risk_description"],
                })

        # Penalize segments with no deny policies (only if there are multiple segments)
        if len(segments) > 1:
            deny_dst_ids = {p["dst_segment_id"] for p in policies if p["action"] == "deny"}
            for seg in segments:
                if seg["id"] not in deny_dst_ids and seg["segment_type"] in _HIGH_TRUST_TYPES:
                    score -= 5
                    findings.append({
                        "severity": "medium",
                        "finding": f"Segment '{seg['name']}' ({seg['segment_type']}) has no explicit deny policies protecting it",
                    })

        # Penalize allow-all port policies
        allow_all_count = sum(
            1 for p in policies if p["action"] == "allow" and not p["ports"]
        )
        score -= allow_all_count * 3

        # Bonus: high-trust segments with deny policies
        if segments and len(segments) > 1:
            high_trust_segs = [s for s in segments if s["segment_type"] in _HIGH_TRUST_TYPES]
            if high_trust_segs:
                all_protected = all(
                    any(p["dst_segment_id"] == s["id"] and p["action"] == "deny" for p in policies)
                    for s in high_trust_segs
                )
                if all_protected:
                    score += 5
                    findings.append({
                        "severity": "info",
                        "finding": "All high-trust segments have explicit deny policies",
                    })

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return {
            "org_id": org_id,
            "score": score,
            "grade": grade,
            "segments_count": len(segments),
            "policies_count": len(policies),
            "lateral_movement_risks": len(risks),
            "findings": findings,
        }

    def get_segmentation_stats(self, org_id: str) -> dict:
        """Return segmentation stats for the org."""
        segments = self.list_segments(org_id)
        policies = self.list_flow_policies(org_id)
        risks = self.detect_lateral_movement_risk(org_id)
        return {
            "org_id": org_id,
            "segments": len(segments),
            "flow_policies": len(policies),
            "violations": len(risks),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _policy_to_dict(row: dict) -> dict:
        result = dict(row)
        if isinstance(result.get("ports"), str):
            try:
                result["ports"] = json.loads(result["ports"])
            except (json.JSONDecodeError, TypeError):
                result["ports"] = []
        return result
