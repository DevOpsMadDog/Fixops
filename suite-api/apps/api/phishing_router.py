"""
FixOps Phishing Simulation API Router.

REST API for phishing simulation capabilities:
- Launch and manage phishing campaigns
- Track email opens, link clicks, and reports
- Query per-user susceptibility scores
- Get org-wide phishing risk posture
- Browse and add phishing templates

Compliance: NIST SP 800-50, ISO 27001 A.7.2.2
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/phishing", tags=["phishing-simulation"])


# ============================================================================
# LAZY SINGLETON
# ============================================================================


def _get_simulator():
    """Return the PhishingSimulator singleton (lazy import for startup speed)."""
    from core.phishing_simulator import PhishingSimulator

    return PhishingSimulator.get_instance()


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateCampaignRequest(BaseModel):
    """Request body for launching a phishing campaign."""

    name: str = Field(..., description="Display name for the campaign")
    template_id: str = Field(..., description="ID of the phishing template to use")
    target_emails: List[str] = Field(..., description="Employee email addresses to target")
    org_id: str = Field(..., description="Organisation identifier")


class InteractionRequest(BaseModel):
    """Request body for recording a user interaction with a campaign."""

    email: str = Field(..., description="Employee email address")


class AddTemplateRequest(BaseModel):
    """Request body for adding a custom phishing template."""

    name: str
    subject: str
    body_html: str
    category: str = Field(..., description="credential_harvest|malware_link|data_request|urgency|authority")
    difficulty: str = Field(..., description="easy|medium|hard")
    indicators: List[str] = Field(default_factory=list)


class CampaignResponse(BaseModel):
    """API response for a phishing campaign."""

    id: str
    name: str
    template_id: str
    target_emails: List[str]
    sent_count: int
    opened_count: int
    clicked_count: int
    reported_count: int
    started_at: str
    ended_at: Optional[str]
    org_id: str


class TemplateResponse(BaseModel):
    """API response for a phishing template."""

    id: str
    name: str
    subject: str
    body_html: str
    category: str
    difficulty: str
    indicators: List[str]


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/campaigns", response_model=CampaignResponse, status_code=201)
def create_campaign(req: CreateCampaignRequest):
    """
    Launch a new phishing simulation campaign.

    Emails are considered 'sent' immediately upon campaign creation.
    Use the interaction endpoints to track opens, clicks, and reports.
    """
    sim = _get_simulator()
    try:
        campaign = sim.create_campaign(
            name=req.name,
            template_id=req.template_id,
            targets=req.target_emails,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return campaign.model_dump()


@router.get("/campaigns/{campaign_id}", response_model=Dict[str, Any])
def get_campaign_results(campaign_id: str):
    """
    Return full campaign results including per-user event breakdown,
    click rate, and report rate.
    """
    sim = _get_simulator()
    try:
        return sim.get_campaign_results(campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/open", status_code=204)
def record_open(campaign_id: str, req: InteractionRequest):
    """Record that an employee opened the phishing email."""
    sim = _get_simulator()
    try:
        sim.record_open(campaign_id, req.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/click", status_code=204)
def record_click(campaign_id: str, req: InteractionRequest):
    """
    Record that an employee clicked the phishing link.

    This counts as a **failed** security awareness test.
    """
    sim = _get_simulator()
    try:
        sim.record_click(campaign_id, req.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/campaigns/{campaign_id}/report", status_code=204)
def record_report(campaign_id: str, req: InteractionRequest):
    """
    Record that an employee reported the email as phishing.

    This counts as a **passed** security awareness test.
    """
    sim = _get_simulator()
    try:
        sim.record_report(campaign_id, req.email)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/orgs/{org_id}/history", response_model=List[Dict[str, Any]])
def get_campaign_history(org_id: str):
    """Return all phishing campaigns for an organisation, newest first."""
    sim = _get_simulator()
    return sim.get_campaign_history(org_id)


@router.get("/orgs/{org_id}/risk", response_model=Dict[str, Any])
def get_org_risk(org_id: str):
    """
    Return org-wide phishing susceptibility metrics.

    Includes overall click rate, report rate, and a risk level classification
    (low / medium / high / critical).
    """
    sim = _get_simulator()
    return sim.get_org_phishing_risk(org_id)


@router.get("/users/susceptibility", response_model=Dict[str, Any])
def get_user_susceptibility(
    email: str = Query(..., description="Employee email address"),
    org_id: str = Query(..., description="Organisation identifier"),
):
    """
    Return an individual employee's phishing susceptibility score (0.0–1.0).

    Score is calculated as: clicks / campaigns_targeted.
    Risk levels: low (<0.25) / medium (0.25–0.5) / high (0.5–0.75) / critical (≥0.75).
    """
    sim = _get_simulator()
    return sim.get_user_susceptibility(email, org_id)


@router.get("/templates", response_model=List[TemplateResponse])
def list_templates():
    """Return all available phishing templates (10 built-in + any custom ones)."""
    sim = _get_simulator()
    return [
        {
            "id": t.id,
            "name": t.name,
            "subject": t.subject,
            "body_html": t.body_html,
            "category": t.category.value,
            "difficulty": t.difficulty.value,
            "indicators": t.indicators,
        }
        for t in sim.list_templates()
    ]


@router.post("/templates", response_model=TemplateResponse, status_code=201)
def add_template(req: AddTemplateRequest):
    """Add a custom phishing template to the library."""
    from core.phishing_simulator import (
        PhishingCategory,
        PhishingDifficulty,
        PhishingTemplate,
    )

    try:
        category = PhishingCategory(req.category)
        difficulty = PhishingDifficulty(req.difficulty)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    sim = _get_simulator()
    template = sim.add_custom_template(
        PhishingTemplate(
            name=req.name,
            subject=req.subject,
            body_html=req.body_html,
            category=category,
            difficulty=difficulty,
            indicators=req.indicators,
        )
    )
    return {
        "id": template.id,
        "name": template.name,
        "subject": template.subject,
        "body_html": template.body_html,
        "category": template.category.value,
        "difficulty": template.difficulty.value,
        "indicators": template.indicators,
    }


@router.get("/stats", response_model=Dict[str, Any], summary="Org-wide phishing stats")
def get_stats(org_id: str = Query("default", description="Organisation identifier")):
    """Return org-wide phishing susceptibility metrics (click rate, report rate, risk level)."""
    sim = _get_simulator()
    return sim.get_org_phishing_risk(org_id)


@router.get("/campaigns", response_model=List[Dict[str, Any]], summary="List campaigns")
def list_campaigns(org_id: str = Query("default", description="Organisation identifier")):
    """Return all phishing campaigns for an org, newest first."""
    sim = _get_simulator()
    return sim.get_campaign_history(org_id)


@router.get("/", summary="Phishing index", tags=["phishing-simulation"])
def phishing_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return phishing campaign summary for the org."""
    try:
        sim = _get_simulator()
        items = sim.get_campaign_history(org_id)
        count = len(items)
    except Exception:
        items, count = [], 0
    return {"router": "phishing", "org_id": org_id, "items": items, "count": count}
