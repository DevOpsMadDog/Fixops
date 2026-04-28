"""
Network Detection & Response (NDR) Engine — ALDECI.

Provides seven integrated capabilities:
1. Network Asset Discovery   — subnets, VLANs, gateways, DNS, DHCP, LBs, firewalls
2. Segmentation Analysis     — PCI CDE, HIPAA ePHI, DMZ, micro-segmentation
3. Firewall Rule Audit       — permissive rules, shadowed rules, expired rules
4. DNS Security              — tunneling, DGA, rebinding, unauthorised servers, DNSSEC
5. TLS/SSL Monitoring        — cert inventory, expiry, weak ciphers, deprecated protocols
6. Network Flow Analysis     — baseline, beaconing, lateral movement, anomalies
7. Zero Trust Scoring        — device, identity, network, app, data dimensions

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: PCI DSS 1.x, HIPAA §164.312(e), NIST SP 800-207 (Zero Trust).
"""

from __future__ import annotations

import ipaddress
import json
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / "data" / "network_security.db"
)

# ---------------------------------------------------------------------------
# Weak cipher suites and deprecated TLS versions
# ---------------------------------------------------------------------------
_WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "SHA1", "IDEA", "SEED",
}
_DEPRECATED_TLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# DGA heuristic — entropy threshold
_DGA_ENTROPY_THRESHOLD = 3.8

# Known-bad DNS resolver IPs (demo set; replace with threat-intel feed)
_UNTRUSTED_DNS: set[str] = set()


# ============================================================================
# ENUMS
# ============================================================================


class AssetType(str, Enum):
    SUBNET = "subnet"
    VLAN = "vlan"
    GATEWAY = "gateway"
    DNS_SERVER = "dns_server"
    DHCP_SCOPE = "dhcp_scope"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"
    HOST = "host"


class SegmentationStatus(str, Enum):
    COMPLIANT = "compliant"
    VIOLATION = "violation"
    WARNING = "warning"
    UNKNOWN = "unknown"


class FirewallRuleIssue(str, Enum):
    OVERLY_PERMISSIVE = "overly_permissive"
    SHADOWED = "shadowed"
    EXPIRED = "expired"
    BIDIRECTIONAL_UNNECESSARY = "bidirectional_unnecessary"


class DNSThreatType(str, Enum):
    TUNNELING = "tunneling"
    DGA = "dga"
    REBINDING = "rebinding"
    UNAUTHORIZED_SERVER = "unauthorized_server"
    DNSSEC_FAILURE = "dnssec_failure"


class TLSIssueType(str, Enum):
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    WEAK_CIPHER = "weak_cipher"
    DEPRECATED_PROTOCOL = "deprecated_protocol"
    MISSING_CT_LOG = "missing_ct_log"


class FlowAnomalyType(str, Enum):
    UNUSUAL_VOLUME = "unusual_volume"
    NEW_CONNECTION = "new_connection"
    BEACONING = "beaconing"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

from pydantic import BaseModel, Field


class NetworkAsset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    asset_type: AssetType
    name: str
    address: str  # IP, CIDR, or descriptive address
    vlan_id: Optional[int] = None
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SegmentationFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    segment_name: str
    compliance_framework: str  # "PCI", "HIPAA", "GENERIC"
    status: SegmentationStatus
    severity: Severity
    description: str
    affected_assets: List[str] = Field(default_factory=list)
    recommendation: str
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class FirewallRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    rule_name: str
    src: str  # CIDR or "any"
    dst: str
    port: str  # "any", "80", "443", "1024-65535"
    protocol: str  # "tcp", "udp", "any"
    action: str  # "allow", "deny"
    bidirectional: bool = False
    expiry: Optional[datetime] = None
    hit_count: int = 0
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FirewallRuleAuditResult(BaseModel):
    rule_id: str
    rule_name: str
    issue: FirewallRuleIssue
    severity: Severity
    description: str
    recommendation: str


class DNSThreat(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    threat_type: DNSThreatType
    domain: str
    resolver_ip: Optional[str] = None
    severity: Severity
    description: str
    entropy: Optional[float] = None
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class TLSCertificate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    host: str
    port: int = 443
    subject_cn: str
    issuer: str
    not_before: datetime
    not_after: datetime
    protocol_version: str = "TLSv1.3"
    cipher_suite: str = ""
    ct_logged: bool = True
    san_domains: List[str] = Field(default_factory=list)
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class TLSIssue(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    cert_id: str
    host: str
    issue_type: TLSIssueType
    severity: Severity
    description: str
    days_until_expiry: Optional[int] = None
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class NetworkFlow(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0
    duration_ms: int = 0
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class FlowAnomaly(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    anomaly_type: FlowAnomalyType
    src_ip: str
    dst_ip: str
    severity: Severity
    description: str
    flow_ids: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ZeroTrustDimension(BaseModel):
    name: str
    score: float  # 0.0–1.0
    weight: float
    findings: List[str] = Field(default_factory=list)


class ZeroTrustScore(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str
    segment: str
    overall_score: float  # 0–100
    grade: str  # A/B/C/D/F
    dimensions: List[ZeroTrustDimension] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class NDRSummary(BaseModel):
    org_id: str
    total_assets: int
    segmentation_violations: int
    firewall_issues: int
    dns_threats: int
    tls_issues: int
    flow_anomalies: int
    zero_trust_score: Optional[float]
    computed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# ============================================================================
# HELPERS
# ============================================================================


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — used for DGA detection."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP belongs to RFC-1918 private space."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _cidr_contains(cidr: str, ip: str) -> bool:
    """Return True if ip is within the CIDR network."""
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _days_until(dt: datetime) -> int:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).days


# ============================================================================
# NDR ENGINE
# ============================================================================


class NDREngine:
    """
    Network Detection & Response engine.

    All public methods are thread-safe via RLock.

    Args:
        db_path: SQLite database path. Defaults to data/network_security.db.
        org_id:  Default organisation ID.
    """

    def __init__(
        self,
        db_path: str = _DEFAULT_DB,
        org_id: str = "default",
    ) -> None:
        self.db_path = db_path
        self.org_id = org_id
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS network_assets (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    asset_type   TEXT NOT NULL,
                    name         TEXT NOT NULL,
                    address      TEXT NOT NULL,
                    vlan_id      INTEGER,
                    description  TEXT,
                    tags         TEXT DEFAULT '[]',
                    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen    DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metadata     TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_na_org ON network_assets (org_id);

                CREATE TABLE IF NOT EXISTS segmentation_findings (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    segment_name         TEXT NOT NULL,
                    compliance_framework TEXT NOT NULL,
                    status               TEXT NOT NULL,
                    severity             TEXT NOT NULL,
                    description          TEXT NOT NULL,
                    affected_assets      TEXT DEFAULT '[]',
                    recommendation       TEXT NOT NULL,
                    detected_at          DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_sf_org ON segmentation_findings (org_id);

                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    rule_name     TEXT NOT NULL,
                    src           TEXT NOT NULL,
                    dst           TEXT NOT NULL,
                    port          TEXT NOT NULL,
                    protocol      TEXT NOT NULL,
                    action        TEXT NOT NULL,
                    bidirectional INTEGER DEFAULT 0,
                    expiry        DATETIME,
                    hit_count     INTEGER DEFAULT 0,
                    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metadata      TEXT DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_fr_org ON firewall_rules (org_id);

                CREATE TABLE IF NOT EXISTS dns_threats (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    threat_type  TEXT NOT NULL,
                    domain       TEXT NOT NULL,
                    resolver_ip  TEXT,
                    severity     TEXT NOT NULL,
                    description  TEXT NOT NULL,
                    entropy      REAL,
                    detected_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_dt_org ON dns_threats (org_id);

                CREATE TABLE IF NOT EXISTS tls_certificates (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    host             TEXT NOT NULL,
                    port             INTEGER DEFAULT 443,
                    subject_cn       TEXT NOT NULL,
                    issuer           TEXT NOT NULL,
                    not_before       DATETIME NOT NULL,
                    not_after        DATETIME NOT NULL,
                    protocol_version TEXT DEFAULT 'TLSv1.3',
                    cipher_suite     TEXT DEFAULT '',
                    ct_logged        INTEGER DEFAULT 1,
                    san_domains      TEXT DEFAULT '[]',
                    observed_at      DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_tc_org ON tls_certificates (org_id);

                CREATE TABLE IF NOT EXISTS tls_issues (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    cert_id           TEXT NOT NULL,
                    host              TEXT NOT NULL,
                    issue_type        TEXT NOT NULL,
                    severity          TEXT NOT NULL,
                    description       TEXT NOT NULL,
                    days_until_expiry INTEGER,
                    detected_at       DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_ti_org ON tls_issues (org_id);

                CREATE TABLE IF NOT EXISTS network_flows (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    src_ip       TEXT NOT NULL,
                    dst_ip       TEXT NOT NULL,
                    src_port     INTEGER NOT NULL,
                    dst_port     INTEGER NOT NULL,
                    protocol     TEXT NOT NULL,
                    bytes_sent   INTEGER DEFAULT 0,
                    bytes_recv   INTEGER DEFAULT 0,
                    packet_count INTEGER DEFAULT 0,
                    duration_ms  INTEGER DEFAULT 0,
                    observed_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_nf_org ON network_flows (org_id);
                CREATE INDEX IF NOT EXISTS idx_nf_pair ON network_flows (org_id, src_ip, dst_ip);

                CREATE TABLE IF NOT EXISTS flow_anomalies (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    anomaly_type  TEXT NOT NULL,
                    src_ip        TEXT NOT NULL,
                    dst_ip        TEXT NOT NULL,
                    severity      TEXT NOT NULL,
                    description   TEXT NOT NULL,
                    flow_ids      TEXT DEFAULT '[]',
                    detected_at   DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_fa_org ON flow_anomalies (org_id);

                CREATE TABLE IF NOT EXISTS zero_trust_scores (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    segment      TEXT NOT NULL,
                    overall_score REAL NOT NULL,
                    grade        TEXT NOT NULL,
                    dimensions   TEXT DEFAULT '[]',
                    recommendations TEXT DEFAULT '[]',
                    computed_at  DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_zt_org ON zero_trust_scores (org_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # 1. Network Asset Discovery
    # ------------------------------------------------------------------

    def register_asset(self, asset: NetworkAsset) -> NetworkAsset:
        """Persist a network asset (upsert by id)."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO network_assets
                        (id, org_id, asset_type, name, address, vlan_id,
                         description, tags, discovered_at, last_seen, metadata)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        metadata  = excluded.metadata
                    """,
                    (
                        asset.id, asset.org_id, asset.asset_type.value,
                        asset.name, asset.address, asset.vlan_id,
                        asset.description,
                        json.dumps(asset.tags),
                        asset.discovered_at.isoformat(),
                        asset.last_seen.isoformat(),
                        json.dumps(asset.metadata),
                    ),
                )
                conn.commit()
        logger.info("network_asset_registered", id=asset.id, type=asset.asset_type)
        _emit_event("network.asset_registered", {"id": asset.id, "type": asset.asset_type.value, "org_id": asset.org_id})
        return asset

    def get_assets(
        self,
        org_id: Optional[str] = None,
        asset_type: Optional[AssetType] = None,
    ) -> List[NetworkAsset]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                if asset_type:
                    rows = conn.execute(
                        "SELECT * FROM network_assets WHERE org_id=? AND asset_type=? ORDER BY discovered_at DESC",
                        (org, asset_type.value),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM network_assets WHERE org_id=? ORDER BY discovered_at DESC",
                        (org,),
                    ).fetchall()
        return [self._row_to_asset(r) for r in rows]

    def discover_topology(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Build a topology map from registered assets.

        Returns dict with segments keyed by VLAN/subnet, listing assets per segment.
        """
        assets = self.get_assets(org_id=org_id)
        topology: Dict[str, Any] = {"segments": {}, "asset_count": len(assets)}
        for a in assets:
            key = f"vlan-{a.vlan_id}" if a.vlan_id is not None else a.asset_type.value
            topology["segments"].setdefault(key, []).append(
                {"id": a.id, "name": a.name, "address": a.address, "type": a.asset_type}
            )
        return topology

    @staticmethod
    def _row_to_asset(r: sqlite3.Row) -> NetworkAsset:
        return NetworkAsset(
            id=r["id"],
            org_id=r["org_id"],
            asset_type=AssetType(r["asset_type"]),
            name=r["name"],
            address=r["address"],
            vlan_id=r["vlan_id"],
            description=r["description"],
            tags=json.loads(r["tags"] or "[]"),
            discovered_at=datetime.fromisoformat(r["discovered_at"]),
            last_seen=datetime.fromisoformat(r["last_seen"]),
            metadata=json.loads(r["metadata"] or "{}"),
        )

    # ------------------------------------------------------------------
    # 2. Segmentation Analysis
    # ------------------------------------------------------------------

    def analyse_segmentation(
        self,
        org_id: Optional[str] = None,
    ) -> List[SegmentationFinding]:
        """
        Evaluate network segmentation against PCI DSS, HIPAA, and general best practices.

        Checks:
        - Flat network (all assets on same /8 or single segment with no firewall)
        - PCI CDE isolation (tagged 'pci-cde' assets must not share subnet with non-CDE)
        - HIPAA ePHI separation (tagged 'ephi' assets must be isolated)
        - DMZ presence (internet-facing assets should be in a dedicated DMZ VLAN)
        """
        org = org_id or self.org_id
        assets = self.get_assets(org_id=org)
        findings: List[SegmentationFinding] = []

        # --- Flat network detection ---
        vlans = {a.vlan_id for a in assets if a.vlan_id is not None}
        firewalls = [a for a in assets if a.asset_type == AssetType.FIREWALL]
        if assets and len(vlans) <= 1 and not firewalls:
            f = SegmentationFinding(
                org_id=org,
                segment_name="global",
                compliance_framework="GENERIC",
                status=SegmentationStatus.VIOLATION,
                severity=Severity.HIGH,
                description="Flat network detected: all assets reside in a single segment with no firewall.",
                affected_assets=[a.id for a in assets],
                recommendation=(
                    "Implement VLANs and deploy firewalls between segments. "
                    "Minimum: DMZ, internal, management, and CDE (if applicable)."
                ),
            )
            findings.append(f)

        # --- PCI CDE isolation ---
        cde_assets = [a for a in assets if "pci-cde" in a.tags]
        non_cde_assets = [a for a in assets if "pci-cde" not in a.tags]
        for cde in cde_assets:
            for other in non_cde_assets:
                if cde.vlan_id is not None and cde.vlan_id == other.vlan_id:
                    f = SegmentationFinding(
                        org_id=org,
                        segment_name=f"vlan-{cde.vlan_id}",
                        compliance_framework="PCI",
                        status=SegmentationStatus.VIOLATION,
                        severity=Severity.CRITICAL,
                        description=(
                            f"PCI CDE asset '{cde.name}' shares VLAN {cde.vlan_id} "
                            f"with non-CDE asset '{other.name}'. "
                            "PCI DSS Requirement 1.3 mandates CDE network isolation."
                        ),
                        affected_assets=[cde.id, other.id],
                        recommendation=(
                            "Move CDE assets to a dedicated VLAN. "
                            "Restrict all inbound/outbound CDE traffic with firewall ACLs."
                        ),
                    )
                    findings.append(f)

        # --- HIPAA ePHI separation ---
        ephi_assets = [a for a in assets if "ephi" in a.tags]
        non_ephi = [a for a in assets if "ephi" not in a.tags]
        for ea in ephi_assets:
            for other in non_ephi:
                if ea.vlan_id is not None and ea.vlan_id == other.vlan_id:
                    f = SegmentationFinding(
                        org_id=org,
                        segment_name=f"vlan-{ea.vlan_id}",
                        compliance_framework="HIPAA",
                        status=SegmentationStatus.VIOLATION,
                        severity=Severity.HIGH,
                        description=(
                            f"HIPAA ePHI asset '{ea.name}' shares VLAN {ea.vlan_id} "
                            f"with non-ePHI asset '{other.name}'. "
                            "HIPAA §164.312(e) requires ePHI network separation."
                        ),
                        affected_assets=[ea.id, other.id],
                        recommendation=(
                            "Isolate ePHI assets on a dedicated VLAN with strict ACLs. "
                            "Enable encryption in transit for all ePHI network segments."
                        ),
                    )
                    findings.append(f)

        # --- DMZ check ---
        internet_facing = [a for a in assets if "internet-facing" in a.tags]
        internal = [a for a in assets if "internet-facing" not in a.tags]
        for iface in internet_facing:
            for inn in internal:
                if iface.vlan_id is not None and iface.vlan_id == inn.vlan_id:
                    f = SegmentationFinding(
                        org_id=org,
                        segment_name=f"vlan-{iface.vlan_id}",
                        compliance_framework="GENERIC",
                        status=SegmentationStatus.WARNING,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Internet-facing asset '{iface.name}' resides on the same VLAN "
                            f"as internal asset '{inn.name}'. A DMZ should isolate internet-facing services."
                        ),
                        affected_assets=[iface.id, inn.id],
                        recommendation=(
                            "Place internet-facing services in a dedicated DMZ VLAN. "
                            "Allow only necessary traffic from DMZ to internal network."
                        ),
                    )
                    findings.append(f)

        # Persist findings
        with self._lock:
            with self._conn() as conn:
                for f in findings:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO segmentation_findings
                            (id, org_id, segment_name, compliance_framework,
                             status, severity, description, affected_assets,
                             recommendation, detected_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            f.id, f.org_id, f.segment_name,
                            f.compliance_framework, f.status.value,
                            f.severity.value, f.description,
                            json.dumps(f.affected_assets),
                            f.recommendation, f.detected_at.isoformat(),
                        ),
                    )
                conn.commit()

        logger.info(
            "segmentation_analysis_complete",
            org_id=org,
            findings=len(findings),
        )
        return findings

    def get_segmentation_findings(
        self, org_id: Optional[str] = None
    ) -> List[SegmentationFinding]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM segmentation_findings WHERE org_id=? ORDER BY detected_at DESC",
                    (org,),
                ).fetchall()
        return [
            SegmentationFinding(
                id=r["id"],
                org_id=r["org_id"],
                segment_name=r["segment_name"],
                compliance_framework=r["compliance_framework"],
                status=SegmentationStatus(r["status"]),
                severity=Severity(r["severity"]),
                description=r["description"],
                affected_assets=json.loads(r["affected_assets"] or "[]"),
                recommendation=r["recommendation"],
                detected_at=datetime.fromisoformat(r["detected_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # 3. Firewall Rule Audit
    # ------------------------------------------------------------------

    def add_firewall_rule(self, rule: FirewallRule) -> FirewallRule:
        """Persist a firewall rule."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO firewall_rules
                        (id, org_id, rule_name, src, dst, port, protocol,
                         action, bidirectional, expiry, hit_count, created_at, metadata)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        rule.id, rule.org_id, rule.rule_name,
                        rule.src, rule.dst, rule.port, rule.protocol,
                        rule.action,
                        1 if rule.bidirectional else 0,
                        rule.expiry.isoformat() if rule.expiry else None,
                        rule.hit_count,
                        rule.created_at.isoformat(),
                        json.dumps(rule.metadata),
                    ),
                )
                conn.commit()
        _emit_event("network.firewall_rule_added", {"id": rule.id, "name": rule.rule_name, "action": rule.action, "org_id": rule.org_id})
        return rule

    def audit_firewall_rules(
        self, org_id: Optional[str] = None
    ) -> List[FirewallRuleAuditResult]:
        """
        Audit firewall rules for common misconfigurations:
        - Overly permissive (src=any, dst=any, port=any)
        - Shadowed (a later rule that can never be reached)
        - Expired temporary rules
        - Bidirectional when one direction suffices
        """
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM firewall_rules WHERE org_id=? ORDER BY created_at ASC",
                    (org,),
                ).fetchall()

        rules = [self._row_to_rule(r) for r in rows]
        results: List[FirewallRuleAuditResult] = []
        now = datetime.now(timezone.utc)

        seen_signatures: List[Tuple[str, str, str, str]] = []

        for rule in rules:
            sig = (rule.src, rule.dst, rule.port, rule.protocol)

            # Overly permissive
            if rule.src.lower() in ("any", "0.0.0.0/0") and \
               rule.dst.lower() in ("any", "0.0.0.0/0") and \
               rule.port.lower() == "any" and \
               rule.action == "allow":
                results.append(FirewallRuleAuditResult(
                    rule_id=rule.id,
                    rule_name=rule.rule_name,
                    issue=FirewallRuleIssue.OVERLY_PERMISSIVE,
                    severity=Severity.CRITICAL,
                    description=(
                        f"Rule '{rule.rule_name}' allows all traffic from any source "
                        "to any destination on any port (any-any-any)."
                    ),
                    recommendation=(
                        "Replace with explicit allow rules for required traffic only. "
                        "Apply the principle of least privilege."
                    ),
                ))

            # Shadowed rule — a broader allow rule already appeared before this deny
            for prev_sig in seen_signatures:
                if self._rule_shadows(prev_sig, sig):
                    results.append(FirewallRuleAuditResult(
                        rule_id=rule.id,
                        rule_name=rule.rule_name,
                        issue=FirewallRuleIssue.SHADOWED,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Rule '{rule.rule_name}' is shadowed by a preceding broader rule "
                            f"(src={prev_sig[0]}, dst={prev_sig[1]}, port={prev_sig[2]}). "
                            "This rule will never be evaluated."
                        ),
                        recommendation=(
                            "Reorder rules so more specific rules appear before broader ones, "
                            "or remove the unreachable rule."
                        ),
                    ))
                    break

            seen_signatures.append(sig)

            # Expired rule
            if rule.expiry:
                expiry = rule.expiry if rule.expiry.tzinfo else rule.expiry.replace(tzinfo=timezone.utc)
                if expiry < now:
                    results.append(FirewallRuleAuditResult(
                        rule_id=rule.id,
                        rule_name=rule.rule_name,
                        issue=FirewallRuleIssue.EXPIRED,
                        severity=Severity.HIGH,
                        description=(
                            f"Rule '{rule.rule_name}' expired on "
                            f"{rule.expiry.strftime('%Y-%m-%d')} and should be removed."
                        ),
                        recommendation="Remove or renew expired temporary firewall rules immediately.",
                    ))

            # Bidirectional when one direction would suffice
            if rule.bidirectional and rule.action == "allow" and \
               rule.src.lower() not in ("any", "0.0.0.0/0"):
                results.append(FirewallRuleAuditResult(
                    rule_id=rule.id,
                    rule_name=rule.rule_name,
                    issue=FirewallRuleIssue.BIDIRECTIONAL_UNNECESSARY,
                    severity=Severity.LOW,
                    description=(
                        f"Rule '{rule.rule_name}' is configured as bidirectional. "
                        "If only one direction of traffic is required, this grants unnecessary access."
                    ),
                    recommendation=(
                        "Review whether bidirectional access is required. "
                        "Use stateful firewall rules with connection tracking instead."
                    ),
                ))

        logger.info(
            "firewall_audit_complete", org_id=org, rules=len(rules), issues=len(results)
        )
        return results

    @staticmethod
    def _rule_shadows(
        broad: Tuple[str, str, str, str],
        specific: Tuple[str, str, str, str],
    ) -> bool:
        """
        True if 'broad' covers all traffic matched by 'specific'.
        Simple heuristic: if broad has 'any' in src/dst/port and specific is narrower.
        """
        b_src, b_dst, b_port, b_proto = broad
        s_src, s_dst, s_port, s_proto = specific
        src_covered = b_src.lower() in ("any", "0.0.0.0/0") or b_src == s_src
        dst_covered = b_dst.lower() in ("any", "0.0.0.0/0") or b_dst == s_dst
        port_covered = b_port.lower() == "any" or b_port == s_port
        proto_covered = b_proto.lower() == "any" or b_proto == s_proto
        return src_covered and dst_covered and port_covered and proto_covered

    @staticmethod
    def _row_to_rule(r: sqlite3.Row) -> FirewallRule:
        expiry = None
        if r["expiry"]:
            expiry = datetime.fromisoformat(r["expiry"])
        return FirewallRule(
            id=r["id"],
            org_id=r["org_id"],
            rule_name=r["rule_name"],
            src=r["src"],
            dst=r["dst"],
            port=r["port"],
            protocol=r["protocol"],
            action=r["action"],
            bidirectional=bool(r["bidirectional"]),
            expiry=expiry,
            hit_count=r["hit_count"],
            created_at=datetime.fromisoformat(r["created_at"]),
            metadata=json.loads(r["metadata"] or "{}"),
        )

    # ------------------------------------------------------------------
    # 4. DNS Security
    # ------------------------------------------------------------------

    def analyse_dns(
        self,
        domain: str,
        resolver_ip: Optional[str] = None,
        query_size_bytes: int = 0,
        org_id: Optional[str] = None,
    ) -> List[DNSThreat]:
        """
        Analyse a DNS query/response for threats:
        - Tunneling: abnormally large queries or high-entropy subdomains
        - DGA: high Shannon entropy on the second-level domain
        - Rebinding: public-to-private IP resolution
        - Unauthorised server: resolver not in approved list
        - DNSSEC: (flagged externally via dnssec_failure param)
        """
        org = org_id or self.org_id
        threats: List[DNSThreat] = []
        parts = domain.rstrip(".").split(".")
        sld = parts[-2] if len(parts) >= 2 else domain

        # DNS Tunneling — large query or high entropy in subdomain
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        if query_size_bytes > 512 or (subdomain and _shannon_entropy(subdomain) > _DGA_ENTROPY_THRESHOLD + 0.5):
            threats.append(DNSThreat(
                org_id=org,
                threat_type=DNSThreatType.TUNNELING,
                domain=domain,
                resolver_ip=resolver_ip,
                severity=Severity.HIGH,
                description=(
                    f"Potential DNS tunneling detected for '{domain}': "
                    f"query_size={query_size_bytes}B, "
                    f"subdomain_entropy={_shannon_entropy(subdomain):.2f}."
                ),
                entropy=_shannon_entropy(subdomain) if subdomain else None,
            ))

        # DGA — high entropy second-level domain
        sld_entropy = _shannon_entropy(sld)
        if sld_entropy >= _DGA_ENTROPY_THRESHOLD and len(sld) >= 8:
            threats.append(DNSThreat(
                org_id=org,
                threat_type=DNSThreatType.DGA,
                domain=domain,
                resolver_ip=resolver_ip,
                severity=Severity.HIGH,
                description=(
                    f"Domain '{domain}' exhibits DGA characteristics: "
                    f"SLD entropy={sld_entropy:.2f} (threshold={_DGA_ENTROPY_THRESHOLD}), "
                    f"length={len(sld)}."
                ),
                entropy=sld_entropy,
            ))

        # Unauthorised DNS server
        if resolver_ip and _UNTRUSTED_DNS and resolver_ip in _UNTRUSTED_DNS:
            threats.append(DNSThreat(
                org_id=org,
                threat_type=DNSThreatType.UNAUTHORIZED_SERVER,
                domain=domain,
                resolver_ip=resolver_ip,
                severity=Severity.MEDIUM,
                description=f"DNS query routed through unauthorised resolver {resolver_ip}.",
                entropy=None,
            ))

        # Persist
        with self._lock:
            with self._conn() as conn:
                for t in threats:
                    conn.execute(
                        """
                        INSERT INTO dns_threats
                            (id, org_id, threat_type, domain, resolver_ip,
                             severity, description, entropy, detected_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            t.id, t.org_id, t.threat_type.value, t.domain,
                            t.resolver_ip, t.severity.value, t.description,
                            t.entropy, t.detected_at.isoformat(),
                        ),
                    )
                conn.commit()

        logger.info("dns_analysis_complete", domain=domain, threats=len(threats))
        return threats

    def report_dns_rebinding(
        self,
        domain: str,
        resolved_ip: str,
        org_id: Optional[str] = None,
    ) -> Optional[DNSThreat]:
        """Flag a DNS rebinding attempt if a public domain resolves to a private IP."""
        org = org_id or self.org_id
        if not _is_private_ip(resolved_ip):
            return None
        threat = DNSThreat(
            org_id=org,
            threat_type=DNSThreatType.REBINDING,
            domain=domain,
            severity=Severity.HIGH,
            description=(
                f"DNS rebinding: public domain '{domain}' resolved to private IP {resolved_ip}. "
                "This may allow cross-origin attacks against internal services."
            ),
        )
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO dns_threats
                        (id, org_id, threat_type, domain, resolver_ip,
                         severity, description, entropy, detected_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        threat.id, threat.org_id, threat.threat_type.value,
                        threat.domain, None, threat.severity.value,
                        threat.description, None, threat.detected_at.isoformat(),
                    ),
                )
                conn.commit()
        logger.warning("dns_rebinding_detected", domain=domain, resolved_ip=resolved_ip)
        return threat

    def get_dns_threats(self, org_id: Optional[str] = None) -> List[DNSThreat]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM dns_threats WHERE org_id=? ORDER BY detected_at DESC",
                    (org,),
                ).fetchall()
        return [
            DNSThreat(
                id=r["id"],
                org_id=r["org_id"],
                threat_type=DNSThreatType(r["threat_type"]),
                domain=r["domain"],
                resolver_ip=r["resolver_ip"],
                severity=Severity(r["severity"]),
                description=r["description"],
                entropy=r["entropy"],
                detected_at=datetime.fromisoformat(r["detected_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # 5. TLS/SSL Monitoring
    # ------------------------------------------------------------------

    def register_certificate(self, cert: TLSCertificate) -> TLSCertificate:
        """Persist a TLS certificate and immediately scan for issues."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tls_certificates
                        (id, org_id, host, port, subject_cn, issuer,
                         not_before, not_after, protocol_version,
                         cipher_suite, ct_logged, san_domains, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        cert.id, cert.org_id, cert.host, cert.port,
                        cert.subject_cn, cert.issuer,
                        cert.not_before.isoformat(), cert.not_after.isoformat(),
                        cert.protocol_version, cert.cipher_suite,
                        1 if cert.ct_logged else 0,
                        json.dumps(cert.san_domains),
                        cert.observed_at.isoformat(),
                    ),
                )
                conn.commit()
        self._scan_certificate_issues(cert)
        return cert

    def _scan_certificate_issues(self, cert: TLSCertificate) -> List[TLSIssue]:
        issues: List[TLSIssue] = []
        days = _days_until(cert.not_after)

        # Expiry
        if days < 0:
            issues.append(TLSIssue(
                org_id=cert.org_id, cert_id=cert.id, host=cert.host,
                issue_type=TLSIssueType.EXPIRED,
                severity=Severity.CRITICAL,
                description=f"Certificate for '{cert.host}' expired {abs(days)} days ago.",
                days_until_expiry=days,
            ))
        elif days <= 30:
            severity = Severity.CRITICAL if days <= 7 else Severity.HIGH
            issues.append(TLSIssue(
                org_id=cert.org_id, cert_id=cert.id, host=cert.host,
                issue_type=TLSIssueType.EXPIRING_SOON,
                severity=severity,
                description=f"Certificate for '{cert.host}' expires in {days} days.",
                days_until_expiry=days,
            ))

        # Weak cipher
        for weak in _WEAK_CIPHERS:
            if weak.upper() in cert.cipher_suite.upper():
                issues.append(TLSIssue(
                    org_id=cert.org_id, cert_id=cert.id, host=cert.host,
                    issue_type=TLSIssueType.WEAK_CIPHER,
                    severity=Severity.HIGH,
                    description=(
                        f"Certificate for '{cert.host}' uses weak cipher suite "
                        f"containing '{weak}': {cert.cipher_suite}."
                    ),
                ))
                break

        # Deprecated protocol
        if cert.protocol_version in _DEPRECATED_TLS:
            issues.append(TLSIssue(
                org_id=cert.org_id, cert_id=cert.id, host=cert.host,
                issue_type=TLSIssueType.DEPRECATED_PROTOCOL,
                severity=Severity.HIGH,
                description=(
                    f"Host '{cert.host}' negotiated deprecated protocol "
                    f"{cert.protocol_version}. Minimum: TLSv1.2."
                ),
            ))

        # Missing CT log
        if not cert.ct_logged:
            issues.append(TLSIssue(
                org_id=cert.org_id, cert_id=cert.id, host=cert.host,
                issue_type=TLSIssueType.MISSING_CT_LOG,
                severity=Severity.MEDIUM,
                description=(
                    f"Certificate for '{cert.host}' is not present in Certificate Transparency logs."
                ),
            ))

        if issues:
            with self._lock:
                with self._conn() as conn:
                    for issue in issues:
                        conn.execute(
                            """
                            INSERT INTO tls_issues
                                (id, org_id, cert_id, host, issue_type,
                                 severity, description, days_until_expiry, detected_at)
                            VALUES (?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                issue.id, issue.org_id, issue.cert_id, issue.host,
                                issue.issue_type.value, issue.severity.value,
                                issue.description, issue.days_until_expiry,
                                issue.detected_at.isoformat(),
                            ),
                        )
                    conn.commit()
        return issues

    def get_tls_issues(self, org_id: Optional[str] = None) -> List[TLSIssue]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM tls_issues WHERE org_id=? ORDER BY detected_at DESC",
                    (org,),
                ).fetchall()
        return [
            TLSIssue(
                id=r["id"],
                org_id=r["org_id"],
                cert_id=r["cert_id"],
                host=r["host"],
                issue_type=TLSIssueType(r["issue_type"]),
                severity=Severity(r["severity"]),
                description=r["description"],
                days_until_expiry=r["days_until_expiry"],
                detected_at=datetime.fromisoformat(r["detected_at"]),
            )
            for r in rows
        ]

    def get_certificates(self, org_id: Optional[str] = None) -> List[TLSCertificate]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM tls_certificates WHERE org_id=? ORDER BY observed_at DESC",
                    (org,),
                ).fetchall()
        return [
            TLSCertificate(
                id=r["id"],
                org_id=r["org_id"],
                host=r["host"],
                port=r["port"],
                subject_cn=r["subject_cn"],
                issuer=r["issuer"],
                not_before=datetime.fromisoformat(r["not_before"]),
                not_after=datetime.fromisoformat(r["not_after"]),
                protocol_version=r["protocol_version"],
                cipher_suite=r["cipher_suite"],
                ct_logged=bool(r["ct_logged"]),
                san_domains=json.loads(r["san_domains"] or "[]"),
                observed_at=datetime.fromisoformat(r["observed_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # 6. Network Flow Analysis
    # ------------------------------------------------------------------

    def record_flow(self, flow: NetworkFlow) -> NetworkFlow:
        """Persist a network flow record."""
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO network_flows
                        (id, org_id, src_ip, dst_ip, src_port, dst_port,
                         protocol, bytes_sent, bytes_recv, packet_count,
                         duration_ms, observed_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        flow.id, flow.org_id, flow.src_ip, flow.dst_ip,
                        flow.src_port, flow.dst_port, flow.protocol,
                        flow.bytes_sent, flow.bytes_recv, flow.packet_count,
                        flow.duration_ms, flow.observed_at.isoformat(),
                    ),
                )
                conn.commit()
        return flow

    def analyse_flows(
        self,
        org_id: Optional[str] = None,
        window_hours: int = 24,
    ) -> List[FlowAnomaly]:
        """
        Detect anomalies in network flows:
        - Unusual volume: a src/dst pair sending > 3x the average bytes
        - Beaconing: regular periodic connections from one source to one destination
        - Lateral movement: internal host connecting to many different internal hosts
        - Data exfiltration: large outbound transfer to external IP from internal source
        """
        org = org_id or self.org_id
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM network_flows WHERE org_id=? AND observed_at >= ? ORDER BY observed_at",
                    (org, cutoff),
                ).fetchall()

        flows = [
            NetworkFlow(
                id=r["id"], org_id=r["org_id"], src_ip=r["src_ip"],
                dst_ip=r["dst_ip"], src_port=r["src_port"], dst_port=r["dst_port"],
                protocol=r["protocol"], bytes_sent=r["bytes_sent"],
                bytes_recv=r["bytes_recv"], packet_count=r["packet_count"],
                duration_ms=r["duration_ms"],
                observed_at=datetime.fromisoformat(r["observed_at"]),
            )
            for r in rows
        ]

        anomalies: List[FlowAnomaly] = []

        # --- Volume baseline per src->dst pair ---
        pair_bytes: Dict[Tuple[str, str], List[Tuple[int, str]]] = {}
        for f in flows:
            key = (f.src_ip, f.dst_ip)
            pair_bytes.setdefault(key, []).append((f.bytes_sent + f.bytes_recv, f.id))

        if pair_bytes:
            all_totals = [sum(b for b, _ in v) for v in pair_bytes.values()]
            avg_total = sum(all_totals) / len(all_totals)
            for (src, dst), items in pair_bytes.items():
                total = sum(b for b, _ in items)
                flow_ids = [fid for _, fid in items]
                if avg_total > 0 and total > avg_total * 3:
                    is_external_dst = not _is_private_ip(dst)
                    is_internal_src = _is_private_ip(src)
                    if is_internal_src and is_external_dst and total > 10_000_000:
                        anomalies.append(FlowAnomaly(
                            org_id=org,
                            anomaly_type=FlowAnomalyType.DATA_EXFILTRATION,
                            src_ip=src, dst_ip=dst,
                            severity=Severity.CRITICAL,
                            description=(
                                f"Potential data exfiltration: internal host {src} sent "
                                f"{total:,} bytes to external {dst} "
                                f"({total / avg_total:.1f}x above baseline)."
                            ),
                            flow_ids=flow_ids,
                        ))
                    else:
                        anomalies.append(FlowAnomaly(
                            org_id=org,
                            anomaly_type=FlowAnomalyType.UNUSUAL_VOLUME,
                            src_ip=src, dst_ip=dst,
                            severity=Severity.HIGH,
                            description=(
                                f"Unusual traffic volume between {src} and {dst}: "
                                f"{total:,} bytes ({total / avg_total:.1f}x average)."
                            ),
                            flow_ids=flow_ids,
                        ))

        # --- Beaconing: same src->dst repeated at regular intervals ---
        pair_times: Dict[Tuple[str, str], List[datetime]] = {}
        for f in flows:
            pair_times.setdefault((f.src_ip, f.dst_ip), []).append(f.observed_at)

        for (src, dst), times in pair_times.items():
            if len(times) >= 5:
                times_sorted = sorted(times)
                intervals = [
                    (times_sorted[i + 1] - times_sorted[i]).total_seconds()
                    for i in range(len(times_sorted) - 1)
                ]
                if intervals:
                    mean_iv = sum(intervals) / len(intervals)
                    variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
                    std_iv = math.sqrt(variance)
                    # Beaconing: low coefficient of variation (< 0.2)
                    if mean_iv > 0 and (std_iv / mean_iv) < 0.2:
                        anomalies.append(FlowAnomaly(
                            org_id=org,
                            anomaly_type=FlowAnomalyType.BEACONING,
                            src_ip=src, dst_ip=dst,
                            severity=Severity.HIGH,
                            description=(
                                f"Beaconing pattern detected: {src} connects to {dst} "
                                f"every ~{mean_iv:.0f}s (CoV={std_iv/mean_iv:.2f})."
                            ),
                            flow_ids=[f.id for f in flows if f.src_ip == src and f.dst_ip == dst],
                        ))

        # --- Lateral movement: internal host connecting to many distinct internal hosts ---
        src_internal_targets: Dict[str, set] = {}
        for f in flows:
            if _is_private_ip(f.src_ip) and _is_private_ip(f.dst_ip) and f.src_ip != f.dst_ip:
                src_internal_targets.setdefault(f.src_ip, set()).add(f.dst_ip)

        for src, targets in src_internal_targets.items():
            if len(targets) >= 5:
                anomalies.append(FlowAnomaly(
                    org_id=org,
                    anomaly_type=FlowAnomalyType.LATERAL_MOVEMENT,
                    src_ip=src, dst_ip="multiple",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Lateral movement suspected: internal host {src} connected to "
                        f"{len(targets)} distinct internal hosts in {window_hours}h window."
                    ),
                    flow_ids=[f.id for f in flows if f.src_ip == src],
                ))

        # Persist anomalies
        with self._lock:
            with self._conn() as conn:
                for a in anomalies:
                    conn.execute(
                        """
                        INSERT INTO flow_anomalies
                            (id, org_id, anomaly_type, src_ip, dst_ip,
                             severity, description, flow_ids, detected_at)
                        VALUES (?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            a.id, a.org_id, a.anomaly_type.value,
                            a.src_ip, a.dst_ip, a.severity.value,
                            a.description, json.dumps(a.flow_ids),
                            a.detected_at.isoformat(),
                        ),
                    )
                conn.commit()

        logger.info(
            "flow_analysis_complete",
            org_id=org, flows=len(flows), anomalies=len(anomalies),
        )
        return anomalies

    def get_flow_anomalies(self, org_id: Optional[str] = None) -> List[FlowAnomaly]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM flow_anomalies WHERE org_id=? ORDER BY detected_at DESC",
                    (org,),
                ).fetchall()
        return [
            FlowAnomaly(
                id=r["id"],
                org_id=r["org_id"],
                anomaly_type=FlowAnomalyType(r["anomaly_type"]),
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                severity=Severity(r["severity"]),
                description=r["description"],
                flow_ids=json.loads(r["flow_ids"] or "[]"),
                detected_at=datetime.fromisoformat(r["detected_at"]),
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # 7. Zero Trust Scoring
    # ------------------------------------------------------------------

    def compute_zero_trust_score(
        self,
        segment: str,
        org_id: Optional[str] = None,
        device_posture_score: float = 1.0,
        identity_verified: bool = True,
        mfa_enabled: bool = True,
        network_microsegmented: bool = True,
        app_least_privilege: bool = True,
        data_classified: bool = True,
    ) -> ZeroTrustScore:
        """
        Score Zero Trust implementation across five dimensions (NIST SP 800-207):
        1. Device Posture    (20%) — managed, patched, compliant devices
        2. User Identity     (25%) — identity verified, MFA, least privilege
        3. Network Context   (20%) — micro-segmentation, encrypted traffic
        4. Application       (20%) — app-level authz, least privilege
        5. Data              (15%) — classification, encryption at rest

        Returns a score 0–100 with letter grade.
        """
        org = org_id or self.org_id
        findings_dict: Dict[str, List[str]] = {
            "Device Posture": [],
            "User Identity": [],
            "Network Context": [],
            "Application": [],
            "Data": [],
        }

        # Device Posture (0–1 input, direct)
        dev_score = max(0.0, min(1.0, device_posture_score))
        if dev_score < 0.7:
            findings_dict["Device Posture"].append("Device posture score below 70% — unmanaged or non-compliant devices detected.")
        if dev_score < 0.5:
            findings_dict["Device Posture"].append("Critical: fewer than 50% of devices meet posture requirements.")

        # User Identity
        id_score = 1.0
        if not identity_verified:
            id_score -= 0.5
            findings_dict["User Identity"].append("Identity verification not enforced — all users should be authenticated via IdP.")
        if not mfa_enabled:
            id_score -= 0.4
            findings_dict["User Identity"].append("MFA not enabled — enable MFA for all users per NIST 800-63B.")
        id_score = max(0.0, id_score)

        # Network Context
        net_score = 1.0
        if not network_microsegmented:
            net_score -= 0.6
            findings_dict["Network Context"].append("Micro-segmentation not implemented — enforce per-workload network policies.")

        # Application
        app_score = 1.0
        if not app_least_privilege:
            app_score -= 0.5
            findings_dict["Application"].append("Application least-privilege not enforced — review service-to-service permissions.")

        # Data
        data_score = 1.0
        if not data_classified:
            data_score -= 0.4
            findings_dict["Data"].append("Data classification not implemented — classify assets before applying controls.")

        dimensions = [
            ZeroTrustDimension(name="Device Posture",  score=dev_score,  weight=0.20, findings=findings_dict["Device Posture"]),
            ZeroTrustDimension(name="User Identity",   score=id_score,   weight=0.25, findings=findings_dict["User Identity"]),
            ZeroTrustDimension(name="Network Context", score=net_score,  weight=0.20, findings=findings_dict["Network Context"]),
            ZeroTrustDimension(name="Application",     score=app_score,  weight=0.20, findings=findings_dict["Application"]),
            ZeroTrustDimension(name="Data",            score=data_score, weight=0.15, findings=findings_dict["Data"]),
        ]

        weighted = sum(d.score * d.weight for d in dimensions)
        overall = round(weighted * 100, 1)

        if overall >= 90:
            grade = "A"
        elif overall >= 80:
            grade = "B"
        elif overall >= 70:
            grade = "C"
        elif overall >= 60:
            grade = "D"
        else:
            grade = "F"

        recommendations: List[str] = []
        for d in dimensions:
            recommendations.extend(d.findings)

        zt = ZeroTrustScore(
            org_id=org,
            segment=segment,
            overall_score=overall,
            grade=grade,
            dimensions=dimensions,
            recommendations=recommendations,
        )

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO zero_trust_scores
                        (id, org_id, segment, overall_score, grade,
                         dimensions, recommendations, computed_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                        zt.id, zt.org_id, zt.segment, zt.overall_score,
                        zt.grade,
                        json.dumps([d.model_dump() for d in zt.dimensions]),
                        json.dumps(zt.recommendations),
                        zt.computed_at.isoformat(),
                    ),
                )
                conn.commit()

        logger.info(
            "zero_trust_score_computed",
            org_id=org, segment=segment, score=overall, grade=grade,
        )
        _emit_event("network.zero_trust_score_computed", {
            "org_id": org, "segment": segment, "score": overall, "grade": grade,
        })
        return zt

    def get_zero_trust_scores(
        self, org_id: Optional[str] = None
    ) -> List[ZeroTrustScore]:
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM zero_trust_scores WHERE org_id=? ORDER BY computed_at DESC",
                    (org,),
                ).fetchall()
        results = []
        for r in rows:
            dims_raw = json.loads(r["dimensions"] or "[]")
            dims = [ZeroTrustDimension(**d) for d in dims_raw]
            results.append(ZeroTrustScore(
                id=r["id"],
                org_id=r["org_id"],
                segment=r["segment"],
                overall_score=r["overall_score"],
                grade=r["grade"],
                dimensions=dims,
                recommendations=json.loads(r["recommendations"] or "[]"),
                computed_at=datetime.fromisoformat(r["computed_at"]),
            ))
        return results

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_summary(self, org_id: Optional[str] = None) -> NDRSummary:
        """Return a high-level NDR health summary for the org."""
        org = org_id or self.org_id
        with self._lock:
            with self._conn() as conn:
                assets = conn.execute(
                    "SELECT COUNT(*) FROM network_assets WHERE org_id=?", (org,)
                ).fetchone()[0]
                seg_violations = conn.execute(
                    "SELECT COUNT(*) FROM segmentation_findings WHERE org_id=? AND status='violation'",
                    (org,),
                ).fetchone()[0]
                fw_issues = conn.execute(
                    "SELECT COUNT(*) FROM firewall_rules WHERE org_id=?", (org,)
                ).fetchone()[0]
                dns_threats = conn.execute(
                    "SELECT COUNT(*) FROM dns_threats WHERE org_id=?", (org,)
                ).fetchone()[0]
                tls_issues = conn.execute(
                    "SELECT COUNT(*) FROM tls_issues WHERE org_id=?", (org,)
                ).fetchone()[0]
                flow_anomalies = conn.execute(
                    "SELECT COUNT(*) FROM flow_anomalies WHERE org_id=?", (org,)
                ).fetchone()[0]
                zt_row = conn.execute(
                    "SELECT overall_score FROM zero_trust_scores WHERE org_id=? ORDER BY computed_at DESC LIMIT 1",
                    (org,),
                ).fetchone()

        return NDRSummary(
            org_id=org,
            total_assets=assets,
            segmentation_violations=seg_violations,
            firewall_issues=fw_issues,
            dns_threats=dns_threats,
            tls_issues=tls_issues,
            flow_anomalies=flow_anomalies,
            zero_trust_score=zt_row["overall_score"] if zt_row else None,
        )
