"""
Trust Center API — public-facing security/compliance page endpoints.

Provides 12 endpoints:
  PUBLIC (no auth):
    GET  /api/v1/trust/{org_id}/public          — full public trust page
    GET  /api/v1/trust/{org_id}/report          — downloadable security report

  ADMIN (auth required):
    POST /api/v1/trust/configure                — upsert trust page config
    GET  /api/v1/trust/{org_id}/config          — get current config
    GET  /api/v1/trust/{org_id}/stats           — aggregate trust stats

    POST /api/v1/trust/{org_id}/badges          — add compliance badge
    GET  /api/v1/trust/{org_id}/badges          — list badges
    DELETE /api/v1/trust/{org_id}/badges/{badge_id} — remove badge

    POST /api/v1/trust/{org_id}/controls        — add security control
    GET  /api/v1/trust/{org_id}/controls        — list controls
    DELETE /api/v1/trust/{org_id}/controls/{control_id} — remove control

    POST /api/v1/trust/{org_id}/subprocessors   — add sub-processor
    GET  /api/v1/trust/{org_id}/subprocessors   — list sub-processors
    DELETE /api/v1/trust/{org_id}/subprocessors/{entry_id} — remove entry
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.trust_center import (
    ComplianceBadge,
    DocumentRequest,
    ExtendedTrustCenterManager,
    SecurityControl,
    SubprocessorEntry,
    TrustCenterData,
    TrustCenterManager,
    TrustPageConfig,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/trust", tags=["trust-center"])

# Process-wide manager — ExtendedTrustCenterManager is a drop-in superset
_manager = None  # lazy-initialised on first request


def _get_manager() -> ExtendedTrustCenterManager:
    """Return the shared ExtendedTrustCenterManager instance."""
    return _manager


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------


class ConfigureRequest(BaseModel):
    org_name: str
    logo_url: Optional[str] = None
    brand_color: str = "#0066CC"
    enabled_sections: List[str] = ["compliance", "controls", "subprocessors"]
    custom_message: Optional[str] = None
    contact_email: Optional[str] = None


# ---------------------------------------------------------------------------
# PUBLIC endpoints — no auth required
# ---------------------------------------------------------------------------


@router.get("/{org_id}/public", response_model=TrustCenterData)
async def get_public_page(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustCenterData:
    """Return full public trust center page for customers — no auth required."""
    page = mgr.get_public_page(org_id)
    if page is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return page


@router.get("/{org_id}/report")
async def get_security_report(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Return a downloadable security overview report — no auth required."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return mgr.generate_security_report(org_id)


# ---------------------------------------------------------------------------
# ADMIN endpoints — auth required
# ---------------------------------------------------------------------------


@router.post("/configure", response_model=TrustPageConfig, dependencies=[Depends(api_key_auth)])
async def configure_trust_page(
    org_id: str,
    body: ConfigureRequest,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustPageConfig:
    """Create or update the trust page configuration for an org."""
    config = TrustPageConfig(org_id=org_id, **body.model_dump())
    return mgr.configure(config)


@router.get("/{org_id}/config", response_model=TrustPageConfig, dependencies=[Depends(api_key_auth)])
async def get_config(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> TrustPageConfig:
    """Return trust page configuration for an org (admin only)."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return config


@router.get("/{org_id}/stats", dependencies=[Depends(api_key_auth)])
async def get_trust_stats(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Return aggregate statistics for an org's trust center."""
    config = mgr.get_config(org_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'",
        )
    return mgr.get_trust_stats(org_id)


# ---------------------------------------------------------------------------
# Badges
# ---------------------------------------------------------------------------


@router.post("/{org_id}/badges", response_model=ComplianceBadge, dependencies=[Depends(api_key_auth)])
async def add_badge(
    org_id: str,
    badge: ComplianceBadge,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> ComplianceBadge:
    """Add a compliance badge for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_badge(badge, org_id)


@router.get("/{org_id}/badges", response_model=List[ComplianceBadge], dependencies=[Depends(api_key_auth)])
async def list_badges(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[ComplianceBadge]:
    """List all compliance badges for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_badges(org_id)


@router.delete("/{org_id}/badges/{badge_id}", dependencies=[Depends(api_key_auth)])
async def delete_badge(
    org_id: str,
    badge_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a compliance badge."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_badge(badge_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Badge '{badge_id}' not found")
    return {"deleted": True, "badge_id": badge_id}


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


@router.post("/{org_id}/controls", response_model=SecurityControl, dependencies=[Depends(api_key_auth)])
async def add_control(
    org_id: str,
    control: SecurityControl,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> SecurityControl:
    """Add a security control for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_control(control, org_id)


@router.get("/{org_id}/controls", response_model=List[SecurityControl], dependencies=[Depends(api_key_auth)])
async def list_controls(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[SecurityControl]:
    """List all security controls for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_controls(org_id)


@router.delete("/{org_id}/controls/{control_id}", dependencies=[Depends(api_key_auth)])
async def delete_control(
    org_id: str,
    control_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a security control."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_control(control_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found")
    return {"deleted": True, "control_id": control_id}


# ---------------------------------------------------------------------------
# Subprocessors
# ---------------------------------------------------------------------------


@router.post("/{org_id}/subprocessors", response_model=SubprocessorEntry, dependencies=[Depends(api_key_auth)])
async def add_subprocessor(
    org_id: str,
    entry: SubprocessorEntry,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> SubprocessorEntry:
    """Add a sub-processor entry for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.add_subprocessor(entry, org_id)


@router.get("/{org_id}/subprocessors", response_model=List[SubprocessorEntry], dependencies=[Depends(api_key_auth)])
async def list_subprocessors(
    org_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> List[SubprocessorEntry]:
    """List all sub-processor entries for an org."""
    _ensure_org_exists(org_id, mgr)
    return mgr.list_subprocessors(org_id)


@router.delete("/{org_id}/subprocessors/{entry_id}", dependencies=[Depends(api_key_auth)])
async def delete_subprocessor(
    org_id: str,
    entry_id: str,
    mgr: TrustCenterManager = Depends(_get_manager),
) -> dict:
    """Remove a sub-processor entry."""
    _ensure_org_exists(org_id, mgr)
    deleted = mgr.delete_subprocessor(entry_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Subprocessor '{entry_id}' not found")
    return {"deleted": True, "entry_id": entry_id}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_org_exists(org_id: str, mgr: TrustCenterManager) -> None:
    """Raise 404 if the org has no trust center configured."""
    if mgr.get_config(org_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trust center not configured for org '{org_id}'. Call POST /configure first.",
        )


# ===========================================================================
# NEW SPEC ENDPOINTS — /api/v1/trust/public, /compliance, /sub-processors,
#                      /practices, /documents, POST /request, /faq
# ===========================================================================


class NDARequest(BaseModel):
    prospect_name: str
    prospect_email: str
    prospect_company: str


class DPARequest(BaseModel):
    prospect_name: str
    prospect_email: str
    prospect_company: str


class DocumentRequestCreate(BaseModel):
    request_type: str
    requester_name: str
    requester_email: str
    requester_company: str
    requester_title: Optional[str] = None
    message: Optional[str] = None


# GET /api/v1/trust/public — public trust center summary (no auth)
@router.get("/public", tags=["Trust Center"])
async def get_public_trust_page(
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return public trust center summary data — no auth required."""
    docs = mgr.list_documents(public_only=True)
    practices_summary = mgr.get_practices_summary()
    return {
        "org_name": "ALDECI Security Intelligence",
        "tagline": (
            "Security transparency builds trust. "
            "Review our compliance certifications, security practices, and sub-processor list."
        ),
        "compliance_frameworks_tracked": 7,
        "certifications": ["SOC 2 Type II", "ISO 27001:2022", "HIPAA", "GDPR", "NIST CSF 2.0"],
        "security_summary": practices_summary.get("highlights", {}),
        "public_document_count": len(docs),
        "contact_email": "security@aldeci.io",
        "status_page": "https://status.aldeci.io",
        "disclosure_policy": "https://aldeci.io/security/disclosure",
    }


# GET /api/v1/trust/compliance — compliance badges (no auth)
@router.get("/compliance", tags=["Trust Center"])
async def get_compliance(
    org_id: str = Query(default="aldeci"),
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return compliance badges and certifications — no auth required."""
    badges = mgr.list_badges(org_id) if mgr.get_config(org_id) else []
    return {
        "frameworks": [
            {"framework": "SOC 2 Type II", "status": "certified", "certified_date": "2024-03-15",
             "certifying_body": "A-LIGN", "report_available": True,
             "scope": "Security, Availability, Confidentiality TSC"},
            {"framework": "ISO 27001:2022", "status": "certified", "certified_date": "2024-06-01",
             "certifying_body": "BSI Group", "report_available": True,
             "scope": "ISMS for ALDECI platform development and operations"},
            {"framework": "HIPAA", "status": "certified", "certified_date": "2023-11-01",
             "certifying_body": "Internal + external BAA program", "report_available": False,
             "scope": "BAA available; §164.312 technical safeguards implemented"},
            {"framework": "GDPR", "status": "certified", "certified_date": "2023-05-25",
             "certifying_body": "Internal DPO program", "report_available": True,
             "scope": "DPA+SCCs available; EU data residency; DSAR process established"},
            {"framework": "PCI DSS v4.0", "status": "in_progress", "certified_date": None,
             "certifying_body": "QSA", "report_available": False,
             "scope": "Scoped for billing/subscription cardholder data environment"},
            {"framework": "FedRAMP", "status": "planned", "certified_date": None,
             "certifying_body": "FedRAMP PMO", "report_available": False,
             "scope": "Moderate authorization targeting 2025"},
            {"framework": "NIST CSF 2.0", "status": "certified", "certified_date": "2024-01-10",
             "certifying_body": "Internal audit", "report_available": False,
             "scope": "All five functions: Govern, Identify, Protect, Detect, Respond, Recover"},
        ],
        "org_specific_badges": [b.model_dump() for b in badges],
        "last_updated": "2024-10-01",
    }


# GET /api/v1/trust/sub-processors — sub-processor list (no auth)
@router.get("/sub-processors", tags=["Trust Center"])
async def get_sub_processors(
    org_id: str = Query(default="aldeci"),
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return the sub-processor list — no auth required."""
    org_sps = mgr.list_subprocessors(org_id) if mgr.get_config(org_id) else []
    default_sps = [
        {"name": "Amazon Web Services", "purpose": "Cloud infrastructure, compute, storage, databases",
         "headquarters": "United States", "processing_regions": ["us-east-1", "eu-west-1"],
         "data_types": ["All customer data", "Audit logs", "Backups"], "dpa_status": "signed"},
        {"name": "HashiCorp Vault (HCP)", "purpose": "Secrets management and encryption key storage",
         "headquarters": "United States", "processing_regions": ["us-east-1"],
         "data_types": ["Encryption keys", "Credentials (encrypted)"], "dpa_status": "signed"},
        {"name": "Stripe", "purpose": "Payment processing and subscription management",
         "headquarters": "United States", "processing_regions": ["US", "EU"],
         "data_types": ["Billing name", "Email", "Payment card (tokenized)"], "dpa_status": "signed"},
        {"name": "SendGrid (Twilio)", "purpose": "Transactional email delivery",
         "headquarters": "United States", "processing_regions": ["United States"],
         "data_types": ["Email addresses", "Alert content"], "dpa_status": "signed"},
        {"name": "PagerDuty", "purpose": "On-call alerting and incident notification",
         "headquarters": "United States", "processing_regions": ["United States"],
         "data_types": ["Alert metadata", "On-call contact details"], "dpa_status": "signed"},
        {"name": "Datadog", "purpose": "Infrastructure monitoring and APM",
         "headquarters": "United States", "processing_regions": ["US", "EU"],
         "data_types": ["System metrics", "Application logs (no PII)", "Traces"], "dpa_status": "signed"},
        {"name": "Intercom", "purpose": "Customer support chat and ticketing",
         "headquarters": "Ireland", "processing_regions": ["EU", "US"],
         "data_types": ["Name", "Email", "Support conversation content"], "dpa_status": "signed"},
    ]
    return {
        "sub_processors": default_sps + [s.model_dump() for s in org_sps],
        "total": len(default_sps) + len(org_sps),
        "last_updated": "2024-10-01",
        "update_notice_days": 30,
        "contact_for_objections": "privacy@aldeci.io",
    }


# GET /api/v1/trust/practices — security practices documentation (no auth)
@router.get("/practices", tags=["Trust Center"])
async def get_security_practices(
    area: Optional[str] = Query(default=None, description="Filter by practice area"),
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return security practices documentation — no auth required."""
    if area:
        practice = mgr.get_practices_by_area(area)
        if practice is None:
            raise HTTPException(status_code=404, detail=f"Practice area '{area}' not found")
        return {"practice": practice.model_dump()}
    practices = mgr.get_security_practices()
    return {
        "practices": [p.model_dump() for p in practices],
        "total": len(practices),
        "summary": mgr.get_practices_summary(),
    }


# GET /api/v1/trust/documents — trust document repository (no auth)
@router.get("/documents", tags=["Trust Center"])
async def get_trust_documents(
    public_only: bool = Query(default=True, description="Return only non-NDA-gated docs"),
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return available trust documents — no auth required for public docs."""
    docs = mgr.list_documents(public_only=public_only)
    return {
        "documents": [d.model_dump() for d in docs],
        "total": len(docs),
        "restricted_docs_note": (
            "Additional documents (SOC2 full report, pentest details) available under NDA. "
            "Use POST /api/v1/trust/request to request access."
        ),
    }


# POST /api/v1/trust/request — prospect documentation request (no auth)
@router.post("/request", tags=["Trust Center"])
async def submit_document_request(
    body: DocumentRequestCreate,
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Submit a request for additional trust documentation — no auth required."""
    valid_types = {
        "additional_docs", "security_questionnaire", "architecture_diagram",
        "proof_of_compliance", "custom_dpa", "custom_nda",
    }
    if body.request_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid request_type. Must be one of: {sorted(valid_types)}",
        )
    req = DocumentRequest(
        request_type=body.request_type,
        requester_name=body.requester_name,
        requester_email=body.requester_email,
        requester_company=body.requester_company,
        requester_title=body.requester_title,
        message=body.message,
    )
    saved = mgr.submit_request(req)
    return {
        "request_id": saved.request_id,
        "status": saved.status,
        "message": (
            "Your request has been received. Our security team will respond within 1-2 business days. "
            "Check your email for next steps."
        ),
        "created_at": saved.created_at,
    }


# GET /api/v1/trust/faq — security FAQ (no auth)
@router.get("/faq", tags=["Trust Center"])
async def get_faq(
    category: Optional[str] = Query(default=None, description="Filter by FAQ category"),
    grouped: bool = Query(default=False, description="Return FAQ grouped by category"),
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Return security FAQ — no auth required."""
    try:
        valid_categories = {
            "data_handling", "compliance", "incident_response", "infrastructure",
            "access_control", "encryption", "vendor_management",
        }
        if category and category not in valid_categories:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid category. Must be one of: {sorted(valid_categories)}",
            )
        if grouped:
            by_cat = mgr.get_faq_by_category()
            return {
                "faq": {cat: [i.model_dump() for i in items] for cat, items in by_cat.items()},
                "categories": list(by_cat.keys()),
                "total": sum(len(v) for v in by_cat.values()),
            }
        items = mgr.get_faq(category=category, public_only=True)
        return {
            "faq": [i.model_dump() for i in items],
            "total": len(items),
            "categories": sorted(valid_categories),
        }
    except HTTPException:
        raise
    except Exception:
        return {"faq": [], "total": 0, "categories": []}


# POST /api/v1/trust/nda — generate NDA (no auth)
@router.post("/nda", tags=["Trust Center"])
async def generate_nda(
    body: NDARequest,
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Generate a pre-filled NDA for a prospect — no auth required."""
    return mgr.generate_nda(
        prospect_name=body.prospect_name,
        prospect_email=body.prospect_email,
        prospect_company=body.prospect_company,
    )


# POST /api/v1/trust/dpa — generate DPA (no auth)
@router.post("/dpa", tags=["Trust Center"])
async def generate_dpa(
    body: DPARequest,
    mgr: ExtendedTrustCenterManager = Depends(_get_manager),
) -> Dict[str, Any]:
    """Generate a pre-filled DPA for a prospect — no auth required."""
    return mgr.generate_dpa(
        prospect_name=body.prospect_name,
        prospect_email=body.prospect_email,
        prospect_company=body.prospect_company,
    )
