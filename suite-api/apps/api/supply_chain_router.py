"""
Supply Chain Security API Router.

8 endpoints:
  POST   /api/v1/supply-chain/sbom/upload       Upload SBOM (CycloneDX or SPDX JSON)
  GET    /api/v1/supply-chain/components         List all tracked components with risk scores
  GET    /api/v1/supply-chain/risks              Supply chain risk dashboard data
  POST   /api/v1/supply-chain/scan               Trigger dependency scan for a repo
  GET    /api/v1/supply-chain/policies           List active policies
  POST   /api/v1/supply-chain/policies           Create/update a policy
  GET    /api/v1/supply-chain/vendors            Vendor risk assessments
  POST   /api/v1/supply-chain/vendors            Create/update a vendor risk assessment
  GET    /api/v1/supply-chain/provenance/{component}  Provenance info for a component

Compliance: NIST SP 800-218 (SSDF), EO 14028, SLSA Framework
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "supply_chain_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.supply_chain_security import (
    PolicyAction,
    ProvenanceLevel,
    ProvenanceRecord,
    RiskDashboard,
    SupplyChainEngine,
    SupplyChainPolicy,
    VendorRiskAssessment,
    VendorTier,
)

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/supply-chain",
    tags=["Supply Chain Security"],
    dependencies=_AUTH_DEP,
)

# Shared engine singleton (SQLite-backed)
_engine: Optional[SupplyChainEngine] = None


def _get_engine() -> SupplyChainEngine:
    global _engine
    if _engine is None:
        _engine = SupplyChainEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class SBOMUploadRequest(BaseModel):
    """Request body for uploading an SBOM document."""

    sbom: Dict[str, Any] = Field(
        ..., description="Raw CycloneDX or SPDX SBOM as a JSON object"
    )
    org_id: str = Field("default", description="Organisation ID")
    source_repo: Optional[str] = Field(
        None, description="Git repository URL this SBOM was generated from"
    )


class SBOMUploadResponse(BaseModel):
    """Response after SBOM ingestion."""

    sbom_id: str
    format: str
    name: str
    version: str
    component_count: int
    sha256: str
    attack_signals_detected: int
    org_id: str


class ScanRequest(BaseModel):
    """Request body for triggering a repository dependency scan."""

    repo_url: str = Field(..., description="Git repository URL to scan")
    branch: str = Field("main", description="Branch to scan")
    org_id: str = Field("default", description="Organisation ID")


class CreatePolicyRequest(BaseModel):
    """Request body for creating or updating a supply chain policy."""

    name: str = Field(..., description="Policy name")
    description: str = Field("", description="Policy description")
    enabled: bool = Field(True)
    action: PolicyAction = Field(PolicyAction.WARN)
    org_id: str = Field("default")
    blocked_licenses: Optional[List[str]] = Field(
        None,
        description="SPDX license IDs to block. Defaults to GPL-2.0, GPL-3.0, AGPL-3.0, LGPL variants.",
    )
    require_sbom: bool = Field(False)
    max_transitive_depth: Optional[int] = Field(None, ge=0)
    required_provenance_level: ProvenanceLevel = Field(ProvenanceLevel.SLSA_0)
    max_critical_cves: int = Field(0, ge=0)
    max_overall_risk_score: float = Field(80.0, ge=0.0, le=100.0)


class CreateVendorRequest(BaseModel):
    """Request body for creating or updating a vendor risk assessment."""

    vendor_name: str = Field(..., description="Vendor / publisher name")
    vendor_url: Optional[str] = Field(None)
    tier: VendorTier = Field(VendorTier.MEDIUM)
    org_id: str = Field("default")
    security_score: float = Field(50.0, ge=0.0, le=100.0)
    sla_uptime_pct: Optional[float] = Field(None, ge=0.0, le=100.0)
    sla_response_hours: Optional[int] = Field(None, ge=0)
    sla_compliant: bool = Field(True)
    known_breaches: int = Field(0, ge=0)
    breach_details: List[str] = Field(default_factory=list)
    component_count: int = Field(0, ge=0)
    security_contact: Optional[str] = Field(None)
    bug_bounty: bool = Field(False)
    mfa_required: bool = Field(False)
    sbom_provided: bool = Field(False)
    notes: str = Field("")


class ProvenanceQueryResponse(BaseModel):
    """Response for a provenance lookup."""

    found: bool
    component_name: str
    component_version: Optional[str]
    provenance: Optional[ProvenanceRecord]


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/sbom/upload",
    response_model=SBOMUploadResponse,
    status_code=201,
    summary="Upload an SBOM (CycloneDX or SPDX JSON)",
)
def upload_sbom(body: SBOMUploadRequest) -> SBOMUploadResponse:
    """
    Ingest a Software Bill of Materials document.

    Accepts CycloneDX (v1.4-v1.6) or SPDX (v2.2-v2.3) JSON.
    On ingestion the engine:
    - Parses and stores all components
    - Computes dependency risk scores for each component
    - Runs supply chain attack detection (typosquatting, dependency confusion,
      version bump anomalies)

    Returns the SBOM record summary and count of attack signals detected.
    """
    engine = _get_engine()
    try:
        record, components, signals = engine.ingest_sbom(
            raw_payload=body.sbom,
            org_id=body.org_id,
            source_repo=body.source_repo,
        )
        return SBOMUploadResponse(
            sbom_id=record.id,
            format=record.format.value,
            name=record.name,
            version=record.version,
            component_count=record.component_count,
            sha256=record.sha256,
            attack_signals_detected=len(signals),
            org_id=record.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("SBOM upload failed for org=%s", body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/components",
    summary="List all tracked components with risk scores",
)
def list_components(
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(200, ge=1, le=1000, description="Maximum results"),
) -> List[Dict[str, Any]]:
    """
    Return all software components tracked across all uploaded SBOMs.

    Each entry includes the component metadata plus its computed risk score
    (CVE exposure, license risk, maintenance status, transitive depth, etc.).
    """
    engine = _get_engine()
    try:
        return engine.list_components(org_id=org_id, limit=limit)
    except Exception as exc:
        _logger.exception("list_components failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/risks",
    response_model=RiskDashboard,
    summary="Supply chain risk dashboard",
)
def get_risk_dashboard(
    org_id: str = Query("default", description="Organisation ID"),
) -> RiskDashboard:
    """
    Return an aggregated risk dashboard for the organisation's supply chain.

    Includes:
    - Component counts by risk level
    - Recent attack signals
    - Top-10 highest-risk components
    - Vendor risk summary
    - Policy violation counts
    """
    engine = _get_engine()
    try:
        return engine.get_risk_dashboard(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_risk_dashboard failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/scan",
    summary="Trigger a supply chain dependency scan for a repository",
)
def trigger_scan(body: ScanRequest) -> Dict[str, Any]:
    """
    Queue a supply chain scan for a Git repository.

    In production this integrates with pip-audit, npm audit, trivy, and grype
    to produce CVE findings for all dependencies. Returns a scan job record;
    results are available asynchronously.
    """
    engine = _get_engine()
    try:
        return engine.scan_repo(
            repo_url=body.repo_url,
            org_id=body.org_id,
            branch=body.branch,
        )
    except Exception as exc:
        _logger.exception("trigger_scan failed for repo=%s", body.repo_url)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/policies",
    response_model=List[SupplyChainPolicy],
    summary="List active supply chain policies",
)
def list_policies(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[SupplyChainPolicy]:
    """
    Return all supply chain security policies for the organisation.

    Policies control:
    - Which licenses are blocked (e.g. GPL in commercial products)
    - Whether SBOMs are required for all dependencies
    - Maximum transitive dependency depth
    - Required SLSA provenance level
    - CVE and risk score thresholds
    """
    engine = _get_engine()
    try:
        return engine.list_policies(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_policies failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/policies",
    response_model=SupplyChainPolicy,
    status_code=201,
    summary="Create or update a supply chain policy",
)
def create_policy(body: CreatePolicyRequest) -> SupplyChainPolicy:
    """
    Create a new supply chain security policy.

    Policies are evaluated against every component at SBOM ingestion time and
    during continuous monitoring scans. Violations trigger the configured action
    (BLOCK, WARN, or AUDIT).
    """
    engine = _get_engine()
    try:
        kwargs: Dict[str, Any] = body.model_dump()
        if kwargs.get("blocked_licenses") is None:
            del kwargs["blocked_licenses"]
        policy = SupplyChainPolicy(**kwargs)
        return engine.create_policy(policy)
    except Exception as exc:
        _logger.exception("create_policy failed name=%s org=%s", body.name, body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/vendors",
    response_model=List[VendorRiskAssessment],
    summary="List vendor risk assessments",
)
def list_vendors(
    org_id: str = Query("default", description="Organisation ID"),
) -> List[VendorRiskAssessment]:
    """
    Return all vendor risk assessments for the organisation.

    Each assessment captures:
    - Security posture score
    - SLA compliance
    - Known breach history
    - Concentration risk (how many components come from this vendor)
    - Bug bounty / MFA / SBOM availability signals
    """
    engine = _get_engine()
    try:
        return engine.list_vendors(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_vendors failed for org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/vendors",
    response_model=VendorRiskAssessment,
    status_code=201,
    summary="Create or update a vendor risk assessment",
)
def upsert_vendor(body: CreateVendorRequest) -> VendorRiskAssessment:
    """
    Create or update a vendor risk assessment.

    Concentration risk is automatically computed from component_count.
    """
    engine = _get_engine()
    try:
        vendor = VendorRiskAssessment(**body.model_dump())
        return engine.upsert_vendor(vendor)
    except Exception as exc:
        _logger.exception("upsert_vendor failed vendor=%s", body.vendor_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/provenance/{component_name}",
    response_model=ProvenanceQueryResponse,
    summary="Get provenance information for a component",
)
def get_provenance(
    component_name: str,
    version: Optional[str] = Query(None, description="Specific version to look up"),
) -> ProvenanceQueryResponse:
    """
    Return SLSA provenance and build attestation information for a component.

    Looks up the most recent verified provenance record. Returns SLSA level,
    builder identity, source URI, signature verification status, and any
    verification errors.
    """
    engine = _get_engine()
    try:
        record = engine.get_provenance(component_name=component_name, component_version=version)
        return ProvenanceQueryResponse(
            found=record is not None,
            component_name=component_name,
            component_version=version,
            provenance=record,
        )
    except Exception as exc:
        _logger.exception("get_provenance failed component=%s", component_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
