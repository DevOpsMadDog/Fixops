"""Email Security Router — ALDECI.

DMARC/SPF/DKIM domain analysis, email threat tracking, and DMARC aggregate
report ingestion.

Endpoints under /api/v1/email-security:
  GET    /domains                    list domains for org
  POST   /domains                    add domain
  PATCH  /domains/{domain_id}        update domain policy fields
  POST   /domains/{domain_id}/analyze  recompute compliance score
  GET    /threats                    list threats (optional type/status filter)
  POST   /threats                    create email threat
  PATCH  /threats/{threat_id}/status update threat status
  GET    /dmarc-reports              list DMARC reports (optional domain_id filter)
  POST   /dmarc-reports              ingest a DMARC aggregate report
  GET    /stats                      summary statistics
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
        "email_security_router: auth_deps not available, relying on app-level auth"
    )
    _AUTH_DEP = []

from core.email_security_engine import EmailSecurityEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/email-security",
    tags=["email-security"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[EmailSecurityEngine] = None


def _get_engine() -> EmailSecurityEngine:
    global _engine
    if _engine is None:
        _engine = EmailSecurityEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class AddDomainRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain: str = Field(..., description="Domain name (e.g. example.com)")
    spf_record: Optional[str] = Field(None, description="SPF TXT record value")
    dkim_selector: Optional[str] = Field(None, description="DKIM selector name")
    dmarc_policy: Optional[str] = Field(
        None, description="DMARC policy: none | quarantine | reject | missing"
    )


class UpdateDomainRequest(BaseModel):
    spf_record: Optional[str] = None
    spf_status: Optional[str] = None
    dkim_selector: Optional[str] = None
    dkim_status: Optional[str] = None
    dmarc_policy: Optional[str] = None


class CreateThreatRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain_id: Optional[str] = Field(None, description="Associated domain ID")
    threat_type: str = Field(
        "phishing", description="phishing | spoofing | bec | spam | malware"
    )
    source_ip: str = Field("", description="Source IP address of the threat")
    sender: str = Field("", description="Sender email address")
    subject_preview: str = Field("", description="Email subject preview (truncated)")
    similarity_score: float = Field(
        0.0, ge=0.0, le=1.0, description="Domain similarity score (0-1)"
    )
    status: str = Field(
        "detected", description="detected | blocked | quarantined | released"
    )


class UpdateThreatStatusRequest(BaseModel):
    status: str = Field(
        ..., description="New status: detected | blocked | quarantined | released"
    )


class AddDmarcReportRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    domain_id: str = Field(..., description="Domain ID the report covers")
    date: Optional[str] = Field(None, description="Report date (YYYY-MM-DD)")
    pass_count: int = Field(0, ge=0, description="Messages that passed DMARC")
    fail_count: int = Field(0, ge=0, description="Messages that failed DMARC")
    quarantine_count: int = Field(0, ge=0, description="Messages quarantined")
    reject_count: int = Field(0, ge=0, description="Messages rejected")
    source_ips: List[str] = Field(default_factory=list, description="Observed source IPs")


# ============================================================================
# DOMAIN ENDPOINTS
# ============================================================================


@router.get("/domains", response_model=List[Dict[str, Any]], summary="List domains")
def list_domains(
    org_id: str = Query("default", description="Organisation ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Return all email domains configured for an org, ordered by compliance score."""
    return engine.list_domains(org_id)


@router.post("/domains", response_model=Dict[str, Any], summary="Add domain")
def add_domain(
    body: AddDomainRequest,
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Add a domain to email security inventory. Computes initial compliance score."""
    return engine.add_domain(
        org_id=body.org_id,
        domain=body.domain,
        spf_record=body.spf_record,
        dkim_selector=body.dkim_selector,
        dmarc_policy=body.dmarc_policy,
    )


@router.patch(
    "/domains/{domain_id}",
    response_model=Dict[str, Any],
    summary="Update domain policy",
)
def update_domain_policy(
    domain_id: str,
    body: UpdateDomainRequest,
    org_id: str = Query("default", description="Organisation ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Update SPF/DKIM/DMARC fields for a domain and recompute compliance score."""
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = engine.update_domain_policy(org_id, domain_id, data)
    if not updated:
        raise HTTPException(status_code=404, detail="Domain not found or no valid fields to update")
    domain = engine.get_domain(org_id, domain_id)
    return domain or {"updated": True}


@router.post(
    "/domains/{domain_id}/analyze",
    response_model=Dict[str, Any],
    summary="Analyze domain compliance",
)
def analyze_domain(
    domain_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Recompute compliance score and issues for a domain based on current config."""
    try:
        return engine.analyze_domain(org_id, domain_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ============================================================================
# THREAT ENDPOINTS
# ============================================================================


@router.get("/threats", response_model=List[Dict[str, Any]], summary="List email threats")
def list_threats(
    org_id: str = Query("default", description="Organisation ID"),
    threat_type: Optional[str] = Query(
        None, description="Filter by type: phishing|spoofing|bec|spam|malware"
    ),
    status: Optional[str] = Query(
        None, description="Filter by status: detected|blocked|quarantined|released"
    ),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """List email threats for an org with optional type and status filters."""
    return engine.list_threats(org_id, threat_type=threat_type, status=status)


@router.post("/threats", response_model=Dict[str, Any], summary="Create email threat")
def create_threat(
    body: CreateThreatRequest,
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Record a new email threat (phishing, spoofing, BEC, spam, or malware)."""
    return engine.create_threat(body.org_id, body.model_dump(exclude={"org_id"}))


@router.patch(
    "/threats/{threat_id}/status",
    response_model=Dict[str, Any],
    summary="Update threat status",
)
def update_threat_status(
    threat_id: str,
    body: UpdateThreatStatusRequest,
    org_id: str = Query("default", description="Organisation ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Update the status of an email threat (e.g. detected → blocked)."""
    updated = engine.update_threat_status(org_id, threat_id, body.status)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Threat not found or invalid status value",
        )
    return {"threat_id": threat_id, "status": body.status, "updated": True}


# ============================================================================
# DMARC REPORT ENDPOINTS
# ============================================================================


@router.get(
    "/dmarc-reports",
    response_model=List[Dict[str, Any]],
    summary="List DMARC reports",
)
def list_dmarc_reports(
    org_id: str = Query("default", description="Organisation ID"),
    domain_id: Optional[str] = Query(None, description="Filter by domain ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """List DMARC aggregate reports, optionally filtered by domain."""
    return engine.list_dmarc_reports(org_id, domain_id=domain_id)


@router.post(
    "/dmarc-reports",
    response_model=Dict[str, Any],
    summary="Ingest DMARC report",
)
def add_dmarc_report(
    body: AddDmarcReportRequest,
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Ingest a DMARC aggregate report for pass/fail/quarantine/reject counts."""
    report_data = body.model_dump(exclude={"org_id", "domain_id"})
    return engine.add_dmarc_report(body.org_id, body.domain_id, report_data)


# ============================================================================
# STATS
# ============================================================================


@router.get("/stats", response_model=Dict[str, Any], summary="Email security statistics")
def get_email_stats(
    org_id: str = Query("default", description="Organisation ID"),
    engine: EmailSecurityEngine = Depends(_get_engine),
):
    """Return email security summary: domain count, compliance rate, threat counts."""
    return engine.get_email_stats(org_id)
