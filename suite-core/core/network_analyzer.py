"""
Network Segmentation Analyzer for ALDECI.

Tracks network zones, observed flows, zone policies, and segmentation violations.
Provides lateral movement risk assessment and micro-segmentation scoring.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ZoneType(str, Enum):
    DMZ = "dmz"
    INTERNAL = "internal"
    EXTERNAL = "external"
    RESTRICTED = "restricted"
    MANAGEMENT = "management"


class FlowDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"


class ViolationSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class NetworkZone(BaseModel):
    """Network zone definition."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, description="Human-readable zone name")
    type: ZoneType = Field(..., description="Zone type classification")
    cidrs: List[str] = Field(default_factory=list, description="CIDR ranges in this zone")
    assets: List[str] = Field(default_factory=list, description="Asset IDs in this zone")
    trust_level: int = Field(
        ..., ge=0, le=100, description="Trust level 0 (untrusted) to 100 (fully trusted)"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "cidrs": self.cidrs,
            "assets": self.assets,
            "trust_level": self.trust_level,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }


class NetworkFlow(BaseModel):
    """Observed network flow between zones."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_zone: str = Field(..., description="Source zone ID")
    dest_zone: str = Field(..., description="Destination zone ID")
    ports: List[int] = Field(default_factory=list, description="Destination ports")
    protocol: str = Field("tcp", description="Network protocol")
    direction: FlowDirection = Field(..., description="Flow direction")
    allowed: bool = Field(..., description="Whether flow is explicitly allowed by policy")
    risk_score: float = Field(0.0, ge=0.0, le=100.0, description="Calculated risk score")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_zone": self.source_zone,
            "dest_zone": self.dest_zone,
            "ports": self.ports,
            "protocol": self.protocol,
            "direction": self.direction.value,
            "allowed": self.allowed,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
            "observed_at": self.observed_at.isoformat(),
        }


class SegmentationViolation(BaseModel):
    """Unauthorized or policy-violating cross-zone traffic."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    flow: NetworkFlow
    rule_violated: str = Field(..., description="Description of the policy rule violated")
    severity: ViolationSeverity = Field(..., description="Violation severity")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "flow": self.flow.to_dict(),
            "rule_violated": self.rule_violated,
            "severity": self.severity.value,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Zone policy rules — trust-level based
# ---------------------------------------------------------------------------

# (source_type, dest_type) -> allowed: bool, reason on deny
_ZONE_POLICY: Dict[Tuple[str, str], Tuple[bool, str]] = {
    # External -> anything inside is policy-controlled
    ("external", "dmz"): (True, ""),
    ("external", "internal"): (False, "External to internal traffic forbidden"),
    ("external", "restricted"): (False, "External to restricted traffic forbidden"),
    ("external", "management"): (False, "External to management traffic forbidden"),
    # DMZ -> internal OK for application traffic; restricted/mgmt not allowed
    ("dmz", "internal"): (True, ""),
    ("dmz", "restricted"): (False, "DMZ to restricted traffic forbidden"),
    ("dmz", "management"): (False, "DMZ to management traffic forbidden"),
    ("dmz", "external"): (True, ""),
    # Internal -> restricted OK; management not OK from general internal
    ("internal", "restricted"): (False, "Internal to restricted requires explicit approval"),
    ("internal", "management"): (False, "Internal to management traffic forbidden"),
    ("internal", "dmz"): (True, ""),
    ("internal", "external"): (True, ""),
    # Restricted -> only restricted-to-restricted allowed
    ("restricted", "internal"): (False, "Restricted to internal traffic forbidden"),
    ("restricted", "dmz"): (False, "Restricted to DMZ traffic forbidden"),
    ("restricted", "external"): (False, "Restricted to external traffic forbidden"),
    ("restricted", "management"): (False, "Restricted to management traffic forbidden"),
    # Management -> can reach anywhere (management plane)
    ("management", "internal"): (True, ""),
    ("management", "dmz"): (True, ""),
    ("management", "restricted"): (True, ""),
    ("management", "external"): (False, "Management to external traffic forbidden"),
}


def _policy_check(src_type: str, dst_type: str) -> Tuple[bool, str]:
    """Return (allowed, reason) for a zone-type pair."""
    if src_type == dst_type:
        return True, ""  # same-zone traffic is always allowed
    return _ZONE_POLICY.get((src_type, dst_type), (False, f"No policy defined for {src_type}->{dst_type}"))


def _flow_risk_score(src_zone: NetworkZone, dst_zone: NetworkZone, allowed: bool) -> float:
    """Compute risk score for a flow based on trust delta and policy."""
    trust_delta = src_zone.trust_level - dst_zone.trust_level
    base = 0.0
    # Higher risk when low-trust zone talks to high-trust zone
    if trust_delta < 0:
        base = min(abs(trust_delta), 80.0)
    # Denied flows carry extra risk
    if not allowed:
        base = min(base + 30.0, 100.0)
    # External source always risky
    if src_zone.type == ZoneType.EXTERNAL:
        base = min(base + 20.0, 100.0)
    return round(base, 2)


# ---------------------------------------------------------------------------
# NetworkAnalyzer — SQLite-backed
# ---------------------------------------------------------------------------


class NetworkAnalyzer:
    """
    Analyzes network segmentation across defined zones.

    Stores zones, flows, and violations in SQLite. Provides violation detection,
    zone communication matrix, lateral movement risk, and micro-segmentation scoring.
    """

    def __init__(self, db_path: str = "data/network_analyzer.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB internals
    # ------------------------------------------------------------------

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS zones (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    cidrs TEXT NOT NULL,
                    assets TEXT NOT NULL,
                    trust_level INTEGER NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    source_zone TEXT NOT NULL,
                    dest_zone TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    risk_score REAL NOT NULL,
                    metadata TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS violations (
                    id TEXT PRIMARY KEY,
                    flow_id TEXT NOT NULL,
                    flow_json TEXT NOT NULL,
                    rule_violated TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    metadata TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_flows_source ON flows(source_zone);
                CREATE INDEX IF NOT EXISTS idx_flows_dest ON flows(dest_zone);
                CREATE INDEX IF NOT EXISTS idx_flows_allowed ON flows(allowed);
                CREATE INDEX IF NOT EXISTS idx_violations_severity ON violations(severity);
                CREATE INDEX IF NOT EXISTS idx_violations_flow ON violations(flow_id);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Zone management
    # ------------------------------------------------------------------

    def define_zone(
        self,
        name: str,
        zone_type: ZoneType,
        cidrs: Optional[List[str]] = None,
        assets: Optional[List[str]] = None,
        trust_level: int = 50,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NetworkZone:
        """Create a network zone with CIDRs and trust level."""
        zone = NetworkZone(
            name=name,
            type=zone_type,
            cidrs=cidrs or [],
            assets=assets or [],
            trust_level=trust_level,
            metadata=metadata or {},
        )
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO zones VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    zone.id,
                    zone.name,
                    zone.type.value,
                    json.dumps(zone.cidrs),
                    json.dumps(zone.assets),
                    zone.trust_level,
                    json.dumps(zone.metadata),
                    zone.created_at.isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return zone

    def get_zone(self, zone_id: str) -> Optional[NetworkZone]:
        """Retrieve a zone by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM zones WHERE id = ?", (zone_id,)).fetchone()
            return self._row_to_zone(row) if row else None
        finally:
            conn.close()

    def list_zones(self) -> List[NetworkZone]:
        """List all defined zones."""
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT * FROM zones ORDER BY created_at").fetchall()
            return [self._row_to_zone(r) for r in rows]
        finally:
            conn.close()

    def _row_to_zone(self, row: sqlite3.Row) -> NetworkZone:
        return NetworkZone(
            id=row["id"],
            name=row["name"],
            type=ZoneType(row["type"]),
            cidrs=json.loads(row["cidrs"]),
            assets=json.loads(row["assets"]),
            trust_level=row["trust_level"],
            metadata=json.loads(row["metadata"]),
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    # ------------------------------------------------------------------
    # Flow management
    # ------------------------------------------------------------------

    def add_flow(
        self,
        source_zone: str,
        dest_zone: str,
        ports: Optional[List[int]] = None,
        protocol: str = "tcp",
        direction: Optional[FlowDirection] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NetworkFlow:
        """
        Record an observed network flow between two zones.

        Automatically determines if the flow is allowed per zone policy and
        calculates a risk score.
        """
        src = self.get_zone(source_zone)
        dst = self.get_zone(dest_zone)

        if src is None:
            raise ValueError(f"Source zone '{source_zone}' not found")
        if dst is None:
            raise ValueError(f"Destination zone '{dest_zone}' not found")

        allowed, _ = _policy_check(src.type.value, dst.type.value)

        if direction is None:
            if src.type == ZoneType.EXTERNAL:
                direction = FlowDirection.INBOUND
            elif dst.type == ZoneType.EXTERNAL:
                direction = FlowDirection.OUTBOUND
            elif src.type == dst.type:
                direction = FlowDirection.LATERAL
            else:
                direction = FlowDirection.LATERAL

        risk = _flow_risk_score(src, dst, allowed)

        flow = NetworkFlow(
            source_zone=source_zone,
            dest_zone=dest_zone,
            ports=ports or [],
            protocol=protocol,
            direction=direction,
            allowed=allowed,
            risk_score=risk,
            metadata=metadata or {},
        )

        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    flow.id,
                    flow.source_zone,
                    flow.dest_zone,
                    json.dumps(flow.ports),
                    flow.protocol,
                    flow.direction.value,
                    1 if flow.allowed else 0,
                    flow.risk_score,
                    json.dumps(flow.metadata),
                    flow.observed_at.isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return flow

    def get_flow(self, flow_id: str) -> Optional[NetworkFlow]:
        """Retrieve a flow by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
            return self._row_to_flow(row) if row else None
        finally:
            conn.close()

    def list_flows(self, allowed: Optional[bool] = None) -> List[NetworkFlow]:
        """List flows, optionally filtered by allowed status."""
        conn = self._get_connection()
        try:
            if allowed is None:
                rows = conn.execute("SELECT * FROM flows ORDER BY observed_at").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM flows WHERE allowed = ? ORDER BY observed_at",
                    (1 if allowed else 0,),
                ).fetchall()
            return [self._row_to_flow(r) for r in rows]
        finally:
            conn.close()

    def _row_to_flow(self, row: sqlite3.Row) -> NetworkFlow:
        return NetworkFlow(
            id=row["id"],
            source_zone=row["source_zone"],
            dest_zone=row["dest_zone"],
            ports=json.loads(row["ports"]),
            protocol=row["protocol"],
            direction=FlowDirection(row["direction"]),
            allowed=bool(row["allowed"]),
            risk_score=row["risk_score"],
            metadata=json.loads(row["metadata"]),
            observed_at=datetime.fromisoformat(row["observed_at"]),
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze_segmentation(self) -> Dict[str, Any]:
        """
        Check all recorded flows against zone policies.

        Returns a summary with total flows, policy-compliant flows, violations,
        and an overall compliance percentage.
        """
        flows = self.list_flows()
        zones = {z.id: z for z in self.list_zones()}

        total = len(flows)
        compliant = 0
        policy_violations: List[Dict[str, Any]] = []

        for flow in flows:
            src = zones.get(flow.source_zone)
            dst = zones.get(flow.dest_zone)
            if src is None or dst is None:
                continue
            allowed, reason = _policy_check(src.type.value, dst.type.value)
            if allowed:
                compliant += 1
            else:
                policy_violations.append(
                    {
                        "flow_id": flow.id,
                        "source_zone": flow.source_zone,
                        "dest_zone": flow.dest_zone,
                        "rule": reason,
                        "risk_score": flow.risk_score,
                    }
                )

        compliance_pct = round((compliant / total * 100) if total > 0 else 100.0, 2)

        return {
            "total_flows": total,
            "compliant_flows": compliant,
            "violation_count": len(policy_violations),
            "compliance_percentage": compliance_pct,
            "violations": policy_violations,
        }

    def detect_violations(self) -> List[SegmentationViolation]:
        """
        Find all unauthorized cross-zone flows and persist new violations.

        Returns the full list of violations (persisted + newly detected).
        """
        flows = self.list_flows()
        zones = {z.id: z for z in self.list_zones()}

        # Load already-persisted violation flow IDs to avoid duplicates
        existing_flow_ids = self._get_violation_flow_ids()

        new_violations: List[SegmentationViolation] = []

        for flow in flows:
            if flow.id in existing_flow_ids:
                continue
            src = zones.get(flow.source_zone)
            dst = zones.get(flow.dest_zone)
            if src is None or dst is None:
                continue
            allowed, reason = _policy_check(src.type.value, dst.type.value)
            if allowed:
                continue

            severity = self._compute_violation_severity(flow, src, dst)
            violation = SegmentationViolation(
                flow=flow,
                rule_violated=reason,
                severity=severity,
            )
            self._persist_violation(violation)
            new_violations.append(violation)

        return self._load_all_violations()

    def _get_violation_flow_ids(self) -> set:
        conn = self._get_connection()
        try:
            rows = conn.execute("SELECT flow_id FROM violations").fetchall()
            return {r["flow_id"] for r in rows}
        finally:
            conn.close()

    def _persist_violation(self, v: SegmentationViolation) -> None:
        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO violations VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    v.id,
                    v.flow.id,
                    json.dumps(v.flow.to_dict()),
                    v.rule_violated,
                    v.severity.value,
                    v.detected_at.isoformat(),
                    json.dumps(v.metadata),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _load_all_violations(self) -> List[SegmentationViolation]:
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT * FROM violations ORDER BY detected_at DESC"
            ).fetchall()
            result = []
            for row in rows:
                flow_dict = json.loads(row["flow_json"])
                flow = NetworkFlow(
                    id=flow_dict["id"],
                    source_zone=flow_dict["source_zone"],
                    dest_zone=flow_dict["dest_zone"],
                    ports=flow_dict["ports"],
                    protocol=flow_dict["protocol"],
                    direction=FlowDirection(flow_dict["direction"]),
                    allowed=flow_dict["allowed"],
                    risk_score=flow_dict["risk_score"],
                    metadata=flow_dict.get("metadata", {}),
                    observed_at=datetime.fromisoformat(flow_dict["observed_at"]),
                )
                violation = SegmentationViolation(
                    id=row["id"],
                    flow=flow,
                    rule_violated=row["rule_violated"],
                    severity=ViolationSeverity(row["severity"]),
                    detected_at=datetime.fromisoformat(row["detected_at"]),
                    metadata=json.loads(row["metadata"]),
                )
                result.append(violation)
            return result
        finally:
            conn.close()

    def _compute_violation_severity(
        self, flow: NetworkFlow, src: NetworkZone, dst: NetworkZone
    ) -> ViolationSeverity:
        """Derive violation severity from zone types and risk score."""
        # High-risk zone pairs get critical or high severity
        critical_pairs = {
            ("external", "restricted"),
            ("external", "management"),
            ("restricted", "internal"),
        }
        pair = (src.type.value, dst.type.value)
        if pair in critical_pairs or flow.risk_score >= 80:
            return ViolationSeverity.CRITICAL
        if flow.risk_score >= 60 or dst.type in (ZoneType.MANAGEMENT, ZoneType.RESTRICTED):
            return ViolationSeverity.HIGH
        if flow.risk_score >= 30:
            return ViolationSeverity.MEDIUM
        return ViolationSeverity.LOW

    # ------------------------------------------------------------------
    # Zone communication matrix
    # ------------------------------------------------------------------

    def get_zone_matrix(self) -> Dict[str, Any]:
        """
        Build a zone-to-zone communication matrix.

        Returns a dict keyed by (source_zone_name, dest_zone_name) with
        flow count, allowed count, and average risk score.
        """
        zones = {z.id: z for z in self.list_zones()}
        flows = self.list_flows()

        matrix: Dict[str, Dict[str, Any]] = {}

        for flow in flows:
            src = zones.get(flow.source_zone)
            dst = zones.get(flow.dest_zone)
            if src is None or dst is None:
                continue
            key = f"{src.name}->{dst.name}"
            if key not in matrix:
                matrix[key] = {
                    "source_zone_id": src.id,
                    "source_zone_name": src.name,
                    "dest_zone_id": dst.id,
                    "dest_zone_name": dst.name,
                    "flow_count": 0,
                    "allowed_count": 0,
                    "denied_count": 0,
                    "avg_risk_score": 0.0,
                    "_risk_sum": 0.0,
                }
            entry = matrix[key]
            entry["flow_count"] += 1
            if flow.allowed:
                entry["allowed_count"] += 1
            else:
                entry["denied_count"] += 1
            entry["_risk_sum"] += flow.risk_score

        # Compute averages and clean up internal fields
        for entry in matrix.values():
            if entry["flow_count"] > 0:
                entry["avg_risk_score"] = round(
                    entry["_risk_sum"] / entry["flow_count"], 2
                )
            del entry["_risk_sum"]

        return {
            "zones": [z.to_dict() for z in zones.values()],
            "matrix": list(matrix.values()),
            "total_zone_pairs": len(matrix),
        }

    # ------------------------------------------------------------------
    # Lateral movement risk
    # ------------------------------------------------------------------

    def get_lateral_movement_risk(self) -> Dict[str, Any]:
        """
        Assess lateral movement paths through the network.

        Identifies high-risk same-trust-level flows and multi-hop paths
        that could enable privilege escalation or data exfiltration.
        """
        zones = {z.id: z for z in self.list_zones()}
        flows = self.list_flows()

        lateral_flows = [f for f in flows if f.direction == FlowDirection.LATERAL]
        high_risk_paths: List[Dict[str, Any]] = []
        pivot_zones: Dict[str, int] = {}  # zone_id -> inbound lateral count

        for flow in lateral_flows:
            src = zones.get(flow.source_zone)
            dst = zones.get(flow.dest_zone)
            if src is None or dst is None:
                continue

            pivot_zones[flow.dest_zone] = pivot_zones.get(flow.dest_zone, 0) + 1

            if flow.risk_score >= 40 or not flow.allowed:
                high_risk_paths.append(
                    {
                        "flow_id": flow.id,
                        "source": src.name,
                        "destination": dst.name,
                        "risk_score": flow.risk_score,
                        "allowed": flow.allowed,
                        "ports": flow.ports,
                        "protocol": flow.protocol,
                    }
                )

        # Sort pivot zones by inbound lateral flow count (most pivotal first)
        sorted_pivots = sorted(pivot_zones.items(), key=lambda x: x[1], reverse=True)
        pivot_details = [
            {
                "zone_id": zid,
                "zone_name": zones[zid].name if zid in zones else zid,
                "zone_type": zones[zid].type.value if zid in zones else "unknown",
                "inbound_lateral_flows": count,
            }
            for zid, count in sorted_pivots[:10]
        ]

        overall_risk = min(
            round(
                sum(f.risk_score for f in lateral_flows) / max(len(lateral_flows), 1), 2
            ),
            100.0,
        )

        return {
            "total_lateral_flows": len(lateral_flows),
            "high_risk_paths": high_risk_paths,
            "pivot_zones": pivot_details,
            "overall_lateral_movement_risk": overall_risk,
            "risk_level": _risk_label(overall_risk),
        }

    # ------------------------------------------------------------------
    # Micro-segmentation score
    # ------------------------------------------------------------------

    def get_micro_segmentation_score(self) -> Dict[str, Any]:
        """
        Compute a 0-100 micro-segmentation score.

        Higher = better segmented network. Considers:
        - Ratio of compliant to total flows
        - Zone isolation (restricted/management zones with few connections)
        - Absence of high-risk lateral movement
        - Average trust differential between communicating zones
        """
        zones = self.list_zones()
        flows = self.list_flows()

        if not zones:
            return {
                "score": 100,
                "grade": "A",
                "details": "No zones defined — nothing to evaluate",
                "breakdown": {},
            }

        total_flows = len(flows)
        allowed_flows = sum(1 for f in flows if f.allowed)
        denied_flows = total_flows - allowed_flows

        # Component 1: Policy compliance (0-40 pts)
        compliance_ratio = allowed_flows / total_flows if total_flows > 0 else 1.0
        compliance_score = compliance_ratio * 40

        # Component 2: Isolation of sensitive zones (0-30 pts)
        sensitive_types = {ZoneType.RESTRICTED, ZoneType.MANAGEMENT}
        sensitive_zone_ids = {z.id for z in zones if z.type in sensitive_types}
        flows_to_sensitive = [
            f for f in flows if f.dest_zone in sensitive_zone_ids and not f.allowed
        ]
        isolation_score = max(0, 30 - len(flows_to_sensitive) * 5)

        # Component 3: Low lateral movement risk (0-20 pts)
        lateral_flows = [f for f in flows if f.direction == FlowDirection.LATERAL]
        unauthorized_lateral = sum(1 for f in lateral_flows if not f.allowed)
        lateral_score = max(0, 20 - unauthorized_lateral * 4)

        # Component 4: Zone granularity (0-10 pts) — more specific zones is better
        unique_zone_types = len({z.type for z in zones})
        granularity_score = min(unique_zone_types * 2, 10)

        total_score = round(
            compliance_score + isolation_score + lateral_score + granularity_score
        )
        total_score = max(0, min(100, total_score))

        return {
            "score": total_score,
            "grade": _score_grade(total_score),
            "breakdown": {
                "policy_compliance": round(compliance_score, 2),
                "zone_isolation": round(isolation_score, 2),
                "lateral_movement_control": round(lateral_score, 2),
                "zone_granularity": round(granularity_score, 2),
            },
            "details": {
                "total_flows": total_flows,
                "allowed_flows": allowed_flows,
                "denied_flows": denied_flows,
                "lateral_flows": len(lateral_flows),
                "unauthorized_lateral": unauthorized_lateral,
                "sensitive_zone_violations": len(flows_to_sensitive),
                "unique_zone_types": unique_zone_types,
            },
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_network_stats(self) -> Dict[str, Any]:
        """Return aggregate network statistics."""
        conn = self._get_connection()
        try:
            zone_count = conn.execute("SELECT COUNT(*) FROM zones").fetchone()[0]
            flow_count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            allowed_count = conn.execute(
                "SELECT COUNT(*) FROM flows WHERE allowed = 1"
            ).fetchone()[0]
            denied_count = conn.execute(
                "SELECT COUNT(*) FROM flows WHERE allowed = 0"
            ).fetchone()[0]
            violation_count = conn.execute("SELECT COUNT(*) FROM violations").fetchone()[0]
            avg_risk = conn.execute("SELECT AVG(risk_score) FROM flows").fetchone()[0] or 0.0

            zone_type_rows = conn.execute(
                "SELECT type, COUNT(*) as cnt FROM zones GROUP BY type"
            ).fetchall()
            zone_by_type = {r["type"]: r["cnt"] for r in zone_type_rows}

            severity_rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM violations GROUP BY severity"
            ).fetchall()
            violations_by_severity = {r["severity"]: r["cnt"] for r in severity_rows}

        finally:
            conn.close()

        return {
            "zone_count": zone_count,
            "flow_count": flow_count,
            "allowed_flow_count": allowed_count,
            "denied_flow_count": denied_count,
            "violation_count": violation_count,
            "avg_risk_score": round(avg_risk, 2),
            "zones_by_type": zone_by_type,
            "violations_by_severity": violations_by_severity,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _risk_label(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _score_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Singleton factory (matches AssetInventory pattern)
# ---------------------------------------------------------------------------

_analyzer: Optional[NetworkAnalyzer] = None


def get_network_analyzer(db_path: str = "data/network_analyzer.db") -> NetworkAnalyzer:
    """Return shared NetworkAnalyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = NetworkAnalyzer(db_path=db_path)
    return _analyzer
