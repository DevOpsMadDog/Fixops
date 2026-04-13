"""
Network Security Router — ALDECI NDR Engine.

8 endpoints under /api/v1/network:
  POST   /api/v1/network/assets              register_asset
  GET    /api/v1/network/assets              list_assets
  GET    /api/v1/network/topology            network_topology
  POST   /api/v1/network/segmentation/scan   run_segmentation_scan
  GET    /api/v1/network/segmentation        list_segmentation_findings
  POST   /api/v1/network/firewall/rules      add_firewall_rule
  POST   /api/v1/network/firewall/audit      audit_firewall_rules
  POST   /api/v1/network/dns/analyse         analyse_dns
  POST   /api/v1/network/dns/rebinding       report_dns_rebinding
  GET    /api/v1/network/dns/threats         list_dns_threats
  POST   /api/v1/network/tls/certificates    register_certificate
  GET    /api/v1/network/tls/certificates    list_certificates
  GET    /api/v1/network/tls/issues          list_tls_issues
  POST   /api/v1/network/flows               record_flow
  POST   /api/v1/network/flows/analyse       analyse_flows
  GET    /api/v1/network/flows/anomalies     list_flow_anomalies
  POST   /api/v1/network/zerotrust/score     compute_zero_trust_score
  GET    /api/v1/network/zerotrust/scores    list_zero_trust_scores
  GET    /api/v1/network/summary             ndr_summary
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "network_security_router: auth_deps not available, relying on app-level auth"
    )
    _AUTH_DEP = []

from core.network_security import (
    AssetType,
    DNSThreat,
    FirewallRule,
    FirewallRuleAuditResult,
    FlowAnomaly,
    NDREngine,
    NDRSummary,
    NetworkAsset,
    NetworkFlow,
    SegmentationFinding,
    TLSCertificate,
    TLSIssue,
    ZeroTrustScore,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/network",
    tags=["network-security"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[NDREngine] = None


def _get_engine() -> NDREngine:
    global _engine
    if _engine is None:
        _engine = NDREngine()
    return _engine


# ============================================================================
# REQUEST MODELS
# ============================================================================


class RegisterAssetRequest(BaseModel):
    name: str = Field(..., description="Human-readable asset name")
    asset_type: AssetType = Field(..., description="Type of network asset")
    address: str = Field(..., description="IP address, CIDR, or descriptive address")
    org_id: str = Field("default", description="Organisation ID")
    vlan_id: Optional[int] = Field(None, description="VLAN identifier")
    description: Optional[str] = Field(None, description="Asset description")
    tags: List[str] = Field(default_factory=list, description="Tags e.g. ['pci-cde', 'internet-facing']")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AddFirewallRuleRequest(BaseModel):
    rule_name: str = Field(..., description="Descriptive rule name")
    src: str = Field(..., description="Source CIDR or 'any'")
    dst: str = Field(..., description="Destination CIDR or 'any'")
    port: str = Field(..., description="Port number, range, or 'any'")
    protocol: str = Field("tcp", description="Protocol: tcp, udp, or any")
    action: str = Field("allow", description="allow or deny")
    org_id: str = Field("default")
    bidirectional: bool = Field(False)
    expiry: Optional[datetime] = Field(None, description="Optional expiry timestamp for temporary rules")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AnalyseDNSRequest(BaseModel):
    domain: str = Field(..., description="DNS domain to analyse")
    resolver_ip: Optional[str] = Field(None, description="IP of the DNS resolver used")
    query_size_bytes: int = Field(0, description="Size of the DNS query payload in bytes")
    org_id: str = Field("default")


class ReportDNSRebindingRequest(BaseModel):
    domain: str = Field(..., description="Public domain that was resolved")
    resolved_ip: str = Field(..., description="IP address the domain resolved to")
    org_id: str = Field("default")


class RegisterCertificateRequest(BaseModel):
    host: str = Field(..., description="Hostname")
    port: int = Field(443, description="TLS port")
    subject_cn: str = Field(..., description="Certificate CN")
    issuer: str = Field(..., description="Certificate issuer")
    not_before: datetime = Field(..., description="Certificate validity start")
    not_after: datetime = Field(..., description="Certificate expiry")
    protocol_version: str = Field("TLSv1.3", description="TLS protocol version negotiated")
    cipher_suite: str = Field("", description="Cipher suite in use")
    ct_logged: bool = Field(True, description="Whether cert appears in CT logs")
    san_domains: List[str] = Field(default_factory=list, description="SAN domain list")
    org_id: str = Field("default")


class RecordFlowRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(..., description="Source port")
    dst_port: int = Field(..., description="Destination port")
    protocol: str = Field("tcp", description="Protocol: tcp or udp")
    bytes_sent: int = Field(0, description="Bytes from source to destination")
    bytes_recv: int = Field(0, description="Bytes from destination to source")
    packet_count: int = Field(0)
    duration_ms: int = Field(0)
    org_id: str = Field("default")


class ZeroTrustScoreRequest(BaseModel):
    segment: str = Field(..., description="Network segment name to score")
    org_id: str = Field("default")
    device_posture_score: float = Field(1.0, ge=0.0, le=1.0, description="Device posture ratio 0–1")
    identity_verified: bool = Field(True, description="All users authenticated via IdP")
    mfa_enabled: bool = Field(True, description="MFA enforced for all users")
    network_microsegmented: bool = Field(True, description="Micro-segmentation implemented")
    app_least_privilege: bool = Field(True, description="App-level least privilege enforced")
    data_classified: bool = Field(True, description="Data classification implemented")


# ============================================================================
# ASSET ENDPOINTS
# ============================================================================


@router.post(
    "/assets",
    response_model=NetworkAsset,
    summary="Register a network asset",
    status_code=201,
)
def register_asset(body: RegisterAssetRequest) -> NetworkAsset:
    """
    Register or update a network asset (subnet, VLAN, gateway, DNS server, etc.).

    Assets are upserted by ID. To update a known asset, include its ID in the request body.
    """
    engine = _get_engine()
    asset = NetworkAsset(
        org_id=body.org_id,
        asset_type=body.asset_type,
        name=body.name,
        address=body.address,
        vlan_id=body.vlan_id,
        description=body.description,
        tags=body.tags,
        metadata=body.metadata,
    )
    try:
        return engine.register_asset(asset)
    except Exception as exc:
        logger.exception("Failed to register asset %s", body.name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/assets",
    response_model=List[NetworkAsset],
    summary="List network assets",
)
def list_assets(
    org_id: str = Query("default", description="Organisation ID"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
) -> List[NetworkAsset]:
    """List all registered network assets, optionally filtered by type."""
    engine = _get_engine()
    try:
        at = AssetType(asset_type) if asset_type else None
    except ValueError:
        valid = [e.value for e in AssetType]
        raise HTTPException(
            status_code=422,
            detail=f"Invalid asset_type '{asset_type}'. Valid: {valid}",
        )
    try:
        return engine.get_assets(org_id=org_id, asset_type=at)
    except Exception as exc:
        logger.exception("Failed to list assets for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/topology",
    response_model=Dict[str, Any],
    summary="Network topology map",
)
def network_topology(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """
    Build and return a topology map from registered assets.

    Returns assets grouped by VLAN or asset type, with total asset count.
    """
    engine = _get_engine()
    try:
        return engine.discover_topology(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to build topology for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# SEGMENTATION ENDPOINTS
# ============================================================================


@router.post(
    "/segmentation/scan",
    response_model=List[SegmentationFinding],
    summary="Run segmentation analysis",
)
def run_segmentation_scan(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[SegmentationFinding]:
    """
    Analyse registered assets for segmentation violations.

    Checks PCI CDE isolation, HIPAA ePHI separation, DMZ configuration,
    and flat network detection. Findings are persisted and returned.
    """
    engine = _get_engine()
    try:
        return engine.analyse_segmentation(org_id=org_id)
    except Exception as exc:
        logger.exception("Segmentation scan failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/segmentation",
    response_model=List[SegmentationFinding],
    summary="List segmentation findings",
)
def list_segmentation_findings(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[SegmentationFinding]:
    """Retrieve all persisted segmentation findings for the org."""
    engine = _get_engine()
    try:
        return engine.get_segmentation_findings(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list segmentation findings for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# FIREWALL ENDPOINTS
# ============================================================================


@router.post(
    "/firewall/rules",
    response_model=FirewallRule,
    summary="Add a firewall rule",
    status_code=201,
)
def add_firewall_rule(body: AddFirewallRuleRequest) -> FirewallRule:
    """Register a firewall rule for audit analysis."""
    engine = _get_engine()
    rule = FirewallRule(
        org_id=body.org_id,
        rule_name=body.rule_name,
        src=body.src,
        dst=body.dst,
        port=body.port,
        protocol=body.protocol,
        action=body.action,
        bidirectional=body.bidirectional,
        expiry=body.expiry,
        metadata=body.metadata,
    )
    try:
        return engine.add_firewall_rule(rule)
    except Exception as exc:
        logger.exception("Failed to add firewall rule %s", body.rule_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/firewall/audit",
    response_model=List[FirewallRuleAuditResult],
    summary="Audit firewall rules",
)
def audit_firewall_rules(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[FirewallRuleAuditResult]:
    """
    Audit all registered firewall rules for:
    - Overly permissive (any-any-any allow)
    - Shadowed rules (never evaluated)
    - Expired temporary rules
    - Unnecessary bidirectional access
    """
    engine = _get_engine()
    try:
        return engine.audit_firewall_rules(org_id=org_id)
    except Exception as exc:
        logger.exception("Firewall audit failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# DNS ENDPOINTS
# ============================================================================


@router.post(
    "/dns/analyse",
    response_model=List[DNSThreat],
    summary="Analyse a DNS query for threats",
)
def analyse_dns(body: AnalyseDNSRequest) -> List[DNSThreat]:
    """
    Analyse a DNS domain for tunneling, DGA, and unauthorized resolver threats.

    Returns a list of detected threats (empty list if none found).
    """
    engine = _get_engine()
    try:
        return engine.analyse_dns(
            domain=body.domain,
            resolver_ip=body.resolver_ip,
            query_size_bytes=body.query_size_bytes,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("DNS analysis failed for domain %s", body.domain)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/dns/rebinding",
    response_model=Optional[DNSThreat],
    summary="Report a DNS rebinding attempt",
)
def report_dns_rebinding(body: ReportDNSRebindingRequest) -> Optional[DNSThreat]:
    """
    Report a DNS rebinding event: a public domain resolved to a private IP.

    Returns the threat record if the resolved IP is private, null otherwise.
    """
    engine = _get_engine()
    try:
        return engine.report_dns_rebinding(
            domain=body.domain,
            resolved_ip=body.resolved_ip,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("DNS rebinding report failed for domain %s", body.domain)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/dns/threats",
    response_model=List[DNSThreat],
    summary="List DNS threats",
)
def list_dns_threats(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[DNSThreat]:
    """Retrieve all persisted DNS threat records for the org."""
    engine = _get_engine()
    try:
        return engine.get_dns_threats(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list DNS threats for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# TLS ENDPOINTS
# ============================================================================


@router.post(
    "/tls/certificates",
    response_model=TLSCertificate,
    summary="Register a TLS certificate",
    status_code=201,
)
def register_certificate(body: RegisterCertificateRequest) -> TLSCertificate:
    """
    Register a TLS certificate observed in the environment.

    Issues (expiry, weak ciphers, deprecated protocols, missing CT) are
    automatically detected and persisted.
    """
    engine = _get_engine()
    cert = TLSCertificate(
        org_id=body.org_id,
        host=body.host,
        port=body.port,
        subject_cn=body.subject_cn,
        issuer=body.issuer,
        not_before=body.not_before,
        not_after=body.not_after,
        protocol_version=body.protocol_version,
        cipher_suite=body.cipher_suite,
        ct_logged=body.ct_logged,
        san_domains=body.san_domains,
    )
    try:
        return engine.register_certificate(cert)
    except Exception as exc:
        logger.exception("Failed to register certificate for host %s", body.host)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/tls/certificates",
    response_model=List[TLSCertificate],
    summary="List TLS certificates",
)
def list_certificates(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[TLSCertificate]:
    """Return all registered TLS certificates for the org."""
    engine = _get_engine()
    try:
        return engine.get_certificates(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list certificates for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/tls/issues",
    response_model=List[TLSIssue],
    summary="List TLS issues",
)
def list_tls_issues(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[TLSIssue]:
    """Return all detected TLS/SSL issues for the org."""
    engine = _get_engine()
    try:
        return engine.get_tls_issues(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list TLS issues for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# FLOW ENDPOINTS
# ============================================================================


@router.post(
    "/flows",
    response_model=NetworkFlow,
    summary="Record a network flow",
    status_code=201,
)
def record_flow(body: RecordFlowRequest) -> NetworkFlow:
    """Persist a network flow observation for baseline and anomaly analysis."""
    engine = _get_engine()
    flow = NetworkFlow(
        org_id=body.org_id,
        src_ip=body.src_ip,
        dst_ip=body.dst_ip,
        src_port=body.src_port,
        dst_port=body.dst_port,
        protocol=body.protocol,
        bytes_sent=body.bytes_sent,
        bytes_recv=body.bytes_recv,
        packet_count=body.packet_count,
        duration_ms=body.duration_ms,
    )
    try:
        return engine.record_flow(flow)
    except Exception as exc:
        logger.exception("Failed to record flow %s->%s", body.src_ip, body.dst_ip)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/flows/analyse",
    response_model=List[FlowAnomaly],
    summary="Analyse network flows for anomalies",
)
def analyse_flows(
    org_id: str = Query("default", description="Organisation ID"),
    window_hours: int = Query(24, ge=1, le=168, description="Look-back window in hours"),
) -> List[FlowAnomaly]:
    """
    Analyse network flows recorded in the look-back window for:
    - Unusual traffic volume (> 3x baseline for a src/dst pair)
    - Beaconing (regular periodic connections)
    - Lateral movement (host connecting to many internal targets)
    - Data exfiltration (large internal-to-external transfer)
    """
    engine = _get_engine()
    try:
        return engine.analyse_flows(org_id=org_id, window_hours=window_hours)
    except Exception as exc:
        logger.exception("Flow analysis failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/flows/anomalies",
    response_model=List[FlowAnomaly],
    summary="List flow anomalies",
)
def list_flow_anomalies(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[FlowAnomaly]:
    """Return all persisted network flow anomalies for the org."""
    engine = _get_engine()
    try:
        return engine.get_flow_anomalies(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list flow anomalies for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# ZERO TRUST ENDPOINTS
# ============================================================================


@router.post(
    "/zerotrust/score",
    response_model=ZeroTrustScore,
    summary="Compute Zero Trust score for a segment",
)
def compute_zero_trust_score(body: ZeroTrustScoreRequest) -> ZeroTrustScore:
    """
    Score Zero Trust implementation for a network segment across five dimensions:
    Device Posture, User Identity, Network Context, Application, and Data.

    Returns an overall score (0–100) with letter grade and per-dimension breakdown.
    """
    engine = _get_engine()
    try:
        return engine.compute_zero_trust_score(
            segment=body.segment,
            org_id=body.org_id,
            device_posture_score=body.device_posture_score,
            identity_verified=body.identity_verified,
            mfa_enabled=body.mfa_enabled,
            network_microsegmented=body.network_microsegmented,
            app_least_privilege=body.app_least_privilege,
            data_classified=body.data_classified,
        )
    except Exception as exc:
        logger.exception("Zero trust scoring failed for segment %s", body.segment)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/zerotrust/scores",
    response_model=List[ZeroTrustScore],
    summary="List Zero Trust scores",
)
def list_zero_trust_scores(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[ZeroTrustScore]:
    """Return all computed Zero Trust scores for the org, newest first."""
    engine = _get_engine()
    try:
        return engine.get_zero_trust_scores(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list ZT scores for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ============================================================================
# SUMMARY ENDPOINT
# ============================================================================


@router.get(
    "/summary",
    response_model=NDRSummary,
    summary="NDR health summary",
)
def ndr_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> NDRSummary:
    """
    Return a high-level NDR health summary:
    asset count, segmentation violations, firewall issue count, DNS threats,
    TLS issues, flow anomalies, and latest Zero Trust score.
    """
    engine = _get_engine()
    try:
        return engine.get_summary(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to generate NDR summary for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
