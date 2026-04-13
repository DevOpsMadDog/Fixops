"""
Vendor Risk Management (VRM) Router — ALDECI.

Endpoints:
  GET    /api/v1/vendors                   Vendor registry with risk scores
  POST   /api/v1/vendors                   Add new vendor
  GET    /api/v1/vendors/{id}/assessment   Vendor risk assessment result
  POST   /api/v1/vendors/{id}/questionnaire Submit questionnaire responses
  GET    /api/v1/vendors/{id}/monitoring   Continuous monitoring data
  GET    /api/v1/vendors/tiering           Vendor tiering overview
  GET    /api/v1/vendors/fourth-party      Fourth-party risk map

Auth: X-API-Key header or Authorization: Bearer <jwt>
Compliance: SOC2 CC9.2, ISO27001 A.15, PCI-DSS 12.8
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "vendor_risk_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.vendor_risk import (
    CertificationRecord,
    ComplianceCert,
    ContractRisk,
    DataAccessLevel,
    FourthPartyMap,
    FourthPartyRisk,
    QuestionnaireResponse,
    RiskSignal,
    RiskSignalSeverity,
    RiskSignalType,
    ServiceCategory,
    SLATerms,
    TieringOverview,
    Vendor,
    VendorAssessment,
    VendorContact,
    VendorScorecard,
    VendorTier,
    get_engine,
)
from core.vendor_risk_engine import get_vendor_risk_engine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vendors",
    tags=["Vendor Risk Management"],
    dependencies=_AUTH_DEP,
)

_engine = get_engine()
_risk_engine = get_vendor_risk_engine()


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class VendorCreateRequest(BaseModel):
    """Request body for registering a new vendor."""

    name: str = Field(..., min_length=1, description="Vendor name")
    service_category: ServiceCategory
    data_access_level: DataAccessLevel
    is_core_operations: bool = Field(False, description="True if vendor supports core operations")
    contract_start: str = Field(..., description="ISO-8601 contract start date (YYYY-MM-DD)")
    contract_end: str = Field(..., description="ISO-8601 contract expiry date (YYYY-MM-DD)")
    sla_terms: Optional[SLATerms] = None
    certifications: List[CertificationRecord] = Field(default_factory=list)
    primary_contact: Optional[VendorContact] = None
    description: str = Field("", description="Brief description of the vendor relationship")
    fourth_party_vendors: List[str] = Field(
        default_factory=list,
        description="Vendor IDs used by this vendor (fourth-party dependencies)",
    )


class VendorResponse(BaseModel):
    """Vendor record with computed risk score."""

    id: str
    name: str
    service_category: str
    data_access_level: str
    is_core_operations: bool
    tier: Optional[str]
    current_score: Optional[float]
    contract_start: str
    contract_end: str
    description: str
    created_at: str
    updated_at: str


class VendorListResponse(BaseModel):
    """Paginated vendor registry response."""

    total: int
    vendors: List[VendorResponse]


class QuestionnaireSubmitRequest(BaseModel):
    """Request body for submitting questionnaire responses."""

    responses: List[QuestionnaireResponse]
    assessed_by: str = Field("api", description="User or system submitting the responses")


class AssessmentResponse(BaseModel):
    """Vendor assessment result."""

    id: str
    vendor_id: str
    questionnaire_score: float
    category_scores: Dict[str, float]
    question_count: int
    submitted_at: str
    next_review_date: Optional[str]
    assessed_by: str


class MonitoringResponse(BaseModel):
    """Continuous monitoring data for a vendor."""

    vendor_id: str
    total_signals: int
    active_signals: int
    severity_breakdown: Dict[str, int]
    latest_security_rating: Optional[Dict[str, Any]]
    signals: List[Dict[str, Any]]


class ScorecardResponse(BaseModel):
    """Vendor scorecard with all component scores and trend."""

    vendor_id: str
    vendor_name: str
    tier: str
    overall_score: float
    grade: str
    questionnaire_score: float
    monitoring_score: float
    contract_score: float
    incident_score: float
    active_risks: int
    contract_gaps: int
    score_trend: List[Dict[str, Any]]
    calculated_at: str


class RecordSignalRequest(BaseModel):
    """Request body for recording a monitoring signal."""

    signal_type: RiskSignalType
    severity: RiskSignalSeverity
    title: str
    description: str
    source: str = "manual"
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# HELPER
# ============================================================================


def _to_vendor_response(vendor: Vendor) -> VendorResponse:
    return VendorResponse(
        id=vendor.id,
        name=vendor.name,
        service_category=vendor.service_category.value,
        data_access_level=vendor.data_access_level.value,
        is_core_operations=vendor.is_core_operations,
        tier=vendor.tier.value if vendor.tier else None,
        current_score=vendor.current_score,
        contract_start=vendor.contract_start,
        contract_end=vendor.contract_end,
        description=vendor.description,
        created_at=vendor.created_at,
        updated_at=vendor.updated_at,
    )


def _require_vendor(vendor_id: str) -> Vendor:
    """Retrieve vendor or raise 404."""
    vendor = _engine.get_vendor(vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail=f"Vendor '{vendor_id}' not found")
    return vendor


# ============================================================================
# ROUTES — order matters: static paths before parameterised ones
# ============================================================================


@router.get(
    "/tiering",
    response_model=TieringOverview,
    summary="Vendor tiering overview",
    description=(
        "Returns the distribution of vendors across risk tiers (Critical / High / Medium / Low) "
        "and the assessment requirements per tier."
    ),
)
def get_tiering_overview() -> TieringOverview:
    """Return vendor tiering breakdown and per-tier assessment requirements."""
    return _engine.get_tiering_overview()


@router.get(
    "/fourth-party",
    response_model=FourthPartyMap,
    summary="Fourth-party risk map",
    description=(
        "Returns the complete fourth-party (nth-party) dependency map showing which of your "
        "vendors' vendors carry transitive risk exposure."
    ),
)
def get_fourth_party_map() -> FourthPartyMap:
    """Return the fourth-party dependency and risk map."""
    return _engine.get_fourth_party_map()


@router.get(
    "",
    response_model=VendorListResponse,
    summary="List vendor registry",
    description="Returns all registered vendors with their current risk scores and tiers.",
)
def list_vendors(
    tier: Optional[VendorTier] = Query(None, description="Filter by vendor tier"),
    category: Optional[ServiceCategory] = Query(None, description="Filter by service category"),
) -> VendorListResponse:
    """List all vendors, optionally filtered by tier or service category."""
    vendors = _engine.list_vendors()

    if tier:
        vendors = [v for v in vendors if v.tier == tier]
    if category:
        vendors = [v for v in vendors if v.service_category == category]

    return VendorListResponse(
        total=len(vendors),
        vendors=[_to_vendor_response(v) for v in vendors],
    )


@router.post(
    "",
    response_model=VendorResponse,
    status_code=201,
    summary="Register a new vendor",
    description=(
        "Registers a new vendor in the VRM registry. Auto-computes tier from data access level "
        "and operational criticality. Automatically analyzes contract risks."
    ),
)
def create_vendor(body: VendorCreateRequest) -> VendorResponse:
    """Register a new vendor. Tier and contract risks are auto-computed."""
    vendor = Vendor(
        name=body.name,
        service_category=body.service_category,
        data_access_level=body.data_access_level,
        is_core_operations=body.is_core_operations,
        contract_start=body.contract_start,
        contract_end=body.contract_end,
        sla_terms=body.sla_terms or SLATerms(),
        certifications=body.certifications,
        primary_contact=body.primary_contact,
        description=body.description,
        fourth_party_vendors=body.fourth_party_vendors,
    )
    registered = _engine.register_vendor(vendor)
    return _to_vendor_response(registered)


@router.get(
    "/{vendor_id}/assessment",
    response_model=AssessmentResponse,
    summary="Get vendor risk assessment",
    description="Returns the latest completed risk assessment for the specified vendor.",
)
def get_assessment(vendor_id: str) -> AssessmentResponse:
    """Return the latest assessment for a vendor."""
    _require_vendor(vendor_id)
    assessment = _engine.get_assessment(vendor_id)
    if not assessment:
        raise HTTPException(
            status_code=404,
            detail=f"No assessment found for vendor '{vendor_id}'. Submit a questionnaire first.",
        )
    return AssessmentResponse(
        id=assessment.id,
        vendor_id=assessment.vendor_id,
        questionnaire_score=assessment.questionnaire_score,
        category_scores=assessment.category_scores,
        question_count=len(assessment.responses),
        submitted_at=assessment.submitted_at,
        next_review_date=assessment.next_review_date,
        assessed_by=assessment.assessed_by,
    )


@router.post(
    "/{vendor_id}/questionnaire",
    response_model=AssessmentResponse,
    summary="Submit questionnaire responses",
    description=(
        "Submit vendor questionnaire responses for scoring. Uses the SIG/SIG Lite-based "
        "questionnaire (100+ questions). Auto-scores responses against expected answers."
    ),
)
def submit_questionnaire(vendor_id: str, body: QuestionnaireSubmitRequest) -> AssessmentResponse:
    """Score and persist questionnaire responses for a vendor."""
    _require_vendor(vendor_id)
    if not body.responses:
        raise HTTPException(status_code=422, detail="At least one questionnaire response is required.")

    assessment = _engine.submit_questionnaire(
        vendor_id=vendor_id,
        responses=body.responses,
        assessed_by=body.assessed_by,
    )
    return AssessmentResponse(
        id=assessment.id,
        vendor_id=assessment.vendor_id,
        questionnaire_score=assessment.questionnaire_score,
        category_scores=assessment.category_scores,
        question_count=len(assessment.responses),
        submitted_at=assessment.submitted_at,
        next_review_date=assessment.next_review_date,
        assessed_by=assessment.assessed_by,
    )


@router.get(
    "/{vendor_id}/monitoring",
    response_model=MonitoringResponse,
    summary="Vendor monitoring data",
    description=(
        "Returns continuous monitoring data for a vendor: security rating history, "
        "active risk signals, breach events, and severity breakdown."
    ),
)
def get_monitoring(vendor_id: str) -> MonitoringResponse:
    """Return continuous monitoring data for a vendor."""
    _require_vendor(vendor_id)
    data = _engine.get_monitoring_data(vendor_id)
    return MonitoringResponse(**data)


@router.post(
    "/{vendor_id}/monitoring/signals",
    response_model=Dict[str, Any],
    status_code=201,
    summary="Record a monitoring signal",
    description=(
        "Record a new risk signal for a vendor. High/critical signals automatically "
        "propagate as transitive fourth-party risk to all dependent vendors."
    ),
)
def record_signal(vendor_id: str, body: RecordSignalRequest) -> Dict[str, Any]:
    """Record a monitoring signal and propagate fourth-party risk if severity warrants."""
    _require_vendor(vendor_id)
    signal = RiskSignal(
        vendor_id=vendor_id,
        signal_type=body.signal_type,
        severity=body.severity,
        title=body.title,
        description=body.description,
        source=body.source,
        metadata=body.metadata,
    )
    recorded = _engine.record_risk_signal(signal)
    return {"signal_id": recorded.id, "vendor_id": vendor_id, "status": "recorded"}


@router.get(
    "/{vendor_id}/scorecard",
    response_model=ScorecardResponse,
    summary="Vendor scorecard",
    description=(
        "Returns the composite 0-100 vendor scorecard with component breakdown "
        "(questionnaire, monitoring, contract, incident) and score trend history."
    ),
)
def get_scorecard(vendor_id: str) -> ScorecardResponse:
    """Compute and return the vendor scorecard."""
    _require_vendor(vendor_id)
    scorecard = _engine.compute_scorecard(vendor_id)
    if not scorecard:
        raise HTTPException(status_code=404, detail=f"Could not compute scorecard for vendor '{vendor_id}'")
    return ScorecardResponse(
        vendor_id=scorecard.vendor_id,
        vendor_name=scorecard.vendor_name,
        tier=scorecard.tier.value,
        overall_score=scorecard.overall_score,
        grade=scorecard.grade,
        questionnaire_score=scorecard.questionnaire_score,
        monitoring_score=scorecard.monitoring_score,
        contract_score=scorecard.contract_score,
        incident_score=scorecard.incident_score,
        active_risks=scorecard.active_risks,
        contract_gaps=scorecard.contract_gaps,
        score_trend=scorecard.score_trend,
        calculated_at=scorecard.calculated_at,
    )


@router.get(
    "/{vendor_id}/contract-risks",
    response_model=List[Dict[str, Any]],
    summary="Vendor contract risks",
    description=(
        "Returns detected contract risk gaps: missing security clauses, "
        "no breach notification requirement, no audit rights, expired certs, etc."
    ),
)
def get_contract_risks(vendor_id: str) -> List[Dict[str, Any]]:
    """Return contract risk gaps for a vendor."""
    _require_vendor(vendor_id)
    risks = _engine.get_contract_risks(vendor_id)
    return [r.model_dump() for r in risks]


@router.get(
    "/{vendor_id}",
    response_model=VendorResponse,
    summary="Get vendor details",
    description="Returns detailed vendor information including tier and current risk score.",
)
def get_vendor(vendor_id: str) -> VendorResponse:
    """Return a single vendor by ID."""
    vendor = _require_vendor(vendor_id)
    return _to_vendor_response(vendor)


# ============================================================================
# ENGINE-BACKED ENDPOINTS (VendorRiskEngine — automated assessment layer)
# ============================================================================


class AutoAssessRequest(BaseModel):
    """Request body for automated vendor risk assessment."""

    name: str = Field(..., min_length=1, description="Vendor name")
    domain: Optional[str] = Field(None, description="Vendor domain (e.g. acme.com)")
    data_access_level: str = Field(
        "none",
        description="Data access level: none/public/internal/confidential/restricted/secret",
    )
    fourth_party_vendors: List[str] = Field(
        default_factory=list,
        description="List of fourth-party vendor IDs used by this vendor",
    )
    vendor_id: Optional[str] = Field(None, description="Existing vendor ID (optional)")


class AutoAssessResponse(BaseModel):
    """Automated vendor risk assessment result."""

    vendor_id: str
    name: str
    domain: Optional[str]
    risk_score: float
    risk_level: str
    findings: List[Dict[str, Any]]
    last_assessed: str
    recommendations: List[str]
    cves: List[Dict[str, Any]]
    breach_matches: List[Dict[str, Any]]


class EngineScorecardResponse(BaseModel):
    """Engine-generated vendor scorecard."""

    vendor_id: str
    vendor_name: str
    overall_score: float
    risk_level: str
    grade: str
    domain_score: float
    cve_score: float
    breach_score: float
    data_handling_score: float
    fourth_party_score: float
    findings_count: int
    critical_findings: int
    calculated_at: str
    recommendations: List[str]


class QuestionnaireTrackRequest(BaseModel):
    """Request body for tracking a vendor security questionnaire."""

    questions: Dict[str, Any] = Field(
        ..., description="Map of question_id -> question text or response data"
    )


class QuestionnaireTrackResponse(BaseModel):
    """Response after creating a questionnaire tracking record."""

    questionnaire_id: str
    vendor_id: str
    status: str
    question_count: int


class FourthPartyRiskResponse(BaseModel):
    """Fourth-party risk score for a vendor."""

    vendor_id: str
    fourth_party_risk_score: float
    risk_label: str


@router.post(
    "/assess",
    response_model=AutoAssessResponse,
    status_code=200,
    summary="Auto-assess a vendor (engine)",
    description=(
        "Runs automated risk assessment for a vendor: domain reputation, NVD CVE lookup, "
        "known breach database, data handling classification, supply chain depth analysis. "
        "Returns composite risk score 0-100 (higher = safer)."
    ),
)
def auto_assess_vendor(body: AutoAssessRequest) -> AutoAssessResponse:
    """Run automated VendorRiskEngine assessment for a vendor."""
    vendor_dict: Dict[str, Any] = {
        "name": body.name,
        "domain": body.domain,
        "data_access_level": body.data_access_level,
        "fourth_party_vendors": body.fourth_party_vendors,
    }
    if body.vendor_id:
        vendor_dict["id"] = body.vendor_id

    result = _risk_engine.assess_vendor(vendor_dict)
    return AutoAssessResponse(
        vendor_id=result.vendor_id,
        name=result.name,
        domain=result.domain,
        risk_score=result.risk_score,
        risk_level=result.risk_level.value,
        findings=[f.to_dict() for f in result.findings],
        last_assessed=result.last_assessed,
        recommendations=result.recommendations,
        cves=result.cves,
        breach_matches=result.breach_matches,
    )


@router.get(
    "/high-risk",
    response_model=List[Dict[str, Any]],
    summary="List high-risk vendors (engine)",
    description=(
        "Returns all auto-assessed vendors with a risk score below the threshold "
        "(default 60). Higher score = safer — scores below 60 are high-risk."
    ),
)
def list_high_risk_vendors(
    threshold: float = Query(60.0, ge=0.0, le=100.0, description="Risk score threshold (0-100)"),
) -> List[Dict[str, Any]]:
    """Return all auto-assessed vendors flagged as high-risk."""
    return _risk_engine.list_high_risk_vendors(threshold=threshold)


@router.post(
    "/{vendor_id}/questionnaire-track",
    response_model=QuestionnaireTrackResponse,
    status_code=201,
    summary="Send and track security questionnaire (engine)",
    description=(
        "Creates a questionnaire tracking record for a vendor in the engine's SQLite store. "
        "Returns a questionnaire_id for status updates via PATCH."
    ),
)
def track_questionnaire(
    vendor_id: str,
    body: QuestionnaireTrackRequest,
) -> QuestionnaireTrackResponse:
    """Create a questionnaire record for tracking completion status."""
    if not body.questions:
        raise HTTPException(status_code=422, detail="Questionnaire must contain at least one question.")

    qid = _risk_engine.track_questionnaire(vendor_id, body.questions)
    return QuestionnaireTrackResponse(
        questionnaire_id=qid,
        vendor_id=vendor_id,
        status="pending",
        question_count=len(body.questions),
    )


@router.get(
    "/{vendor_id}/engine-scorecard",
    response_model=EngineScorecardResponse,
    summary="Get engine-generated vendor scorecard",
    description=(
        "Generates a composite vendor security scorecard from the automated assessment: "
        "domain score, CVE score, breach score, data handling score, fourth-party score. "
        "Requires assess endpoint to have been called first for this vendor."
    ),
)
def get_engine_scorecard(vendor_id: str) -> EngineScorecardResponse:
    """Generate and return the engine scorecard for an assessed vendor."""
    try:
        scorecard = _risk_engine.generate_vendor_scorecard(vendor_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return EngineScorecardResponse(
        vendor_id=scorecard.vendor_id,
        vendor_name=scorecard.vendor_name,
        overall_score=scorecard.overall_score,
        risk_level=scorecard.risk_level.value,
        grade=scorecard.grade,
        domain_score=scorecard.domain_score,
        cve_score=scorecard.cve_score,
        breach_score=scorecard.breach_score,
        data_handling_score=scorecard.data_handling_score,
        fourth_party_score=scorecard.fourth_party_score,
        findings_count=scorecard.findings_count,
        critical_findings=scorecard.critical_findings,
        calculated_at=scorecard.calculated_at,
        recommendations=scorecard.recommendations,
    )


@router.get(
    "/{vendor_id}/fourth-party-risk",
    response_model=FourthPartyRiskResponse,
    summary="Fourth-party risk score (engine)",
    description=(
        "Returns a 0.0-1.0 fourth-party risk score for the vendor based on supply chain "
        "depth analysis from the automated assessment. 0 = no exposure, 1 = maximum risk."
    ),
)
def get_fourth_party_risk(vendor_id: str) -> FourthPartyRiskResponse:
    """Return fourth-party risk score derived from engine assessment data."""
    score = _risk_engine.calculate_fourth_party_risk(vendor_id)
    if score < 0.3:
        label = "low"
    elif score < 0.6:
        label = "medium"
    elif score < 0.8:
        label = "high"
    else:
        label = "critical"
    return FourthPartyRiskResponse(
        vendor_id=vendor_id,
        fourth_party_risk_score=score,
        risk_label=label,
    )
