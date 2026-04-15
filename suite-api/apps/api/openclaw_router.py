"""OpenClaw Autonomous Pentest Swarm Router — ALDECI.

Endpoints:
  GET    /api/v1/openclaw/campaigns                         list_campaigns
  POST   /api/v1/openclaw/campaigns                         create_campaign
  GET    /api/v1/openclaw/campaigns/{id}                    get_campaign
  POST   /api/v1/openclaw/campaigns/{id}/start              start_campaign
  POST   /api/v1/openclaw/campaigns/{id}/advance            advance_phase
  POST   /api/v1/openclaw/campaigns/{id}/pause              pause_campaign
  POST   /api/v1/openclaw/campaigns/{id}/complete           complete_campaign
  GET    /api/v1/openclaw/campaigns/{id}/tasks              list_tasks
  GET    /api/v1/openclaw/findings                          list_findings
  PATCH  /api/v1/openclaw/findings/{id}/status              update_finding_status
  GET    /api/v1/openclaw/stats                             get_stats
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
        "openclaw_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.openclaw_engine import OpenClawEngine, get_openclaw_engine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/openclaw",
    tags=["openclaw"],
    dependencies=_AUTH_DEP,
)

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    campaign_type: str = Field(
        default="network_pentest",
        description="network_pentest|web_app|cloud_security|social_engineering|physical_access|full_red_team",
    )
    target_scope: List[str] = Field(default_factory=list)
    attack_tactics: List[str] = Field(default_factory=list)
    operators_count: int = Field(default=3, ge=1, le=5)
    authorization_token: str = Field(
        ...,
        min_length=1,
        description="Required authorization token confirming written approval for this pentest",
    )
    authorized_by: str = Field(default="")
    authorized_until: str = Field(default="")


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="open|accepted|remediated")


# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engines: Dict[str, OpenClawEngine] = {}


def _get_engine(org_id: str) -> OpenClawEngine:
    if org_id not in _engines:
        _engines[org_id] = get_openclaw_engine(org_id)
    return _engines[org_id]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/campaigns")
def list_campaigns(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    campaign_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List pentest campaigns for an org."""
    engine = _get_engine(org_id)
    return engine.list_campaigns(org_id, status=status, campaign_type=campaign_type)


@router.post("/campaigns", status_code=201)
def create_campaign(
    body: CampaignCreate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Create a new pentest campaign. Requires authorization_token."""
    engine = _get_engine(org_id)
    try:
        return engine.create_campaign(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/campaigns/{campaign_id}")
def get_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a campaign with tasks, findings, and operators."""
    engine = _get_engine(org_id)
    result = engine.get_campaign(org_id, campaign_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Campaign {campaign_id} not found")
    return result


@router.post("/campaigns/{campaign_id}/start")
def start_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Start a staged campaign — queues and simulates initial tasks."""
    engine = _get_engine(org_id)
    try:
        return engine.start_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/advance")
def advance_phase(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Advance the campaign to the next MITRE ATT&CK phase."""
    engine = _get_engine(org_id)
    try:
        return engine.advance_phase(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/pause")
def pause_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Pause a running campaign."""
    engine = _get_engine(org_id)
    try:
        return engine.pause_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/campaigns/{campaign_id}/complete")
def complete_campaign(
    campaign_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Complete a campaign and calculate final risk score."""
    engine = _get_engine(org_id)
    try:
        return engine.complete_campaign(org_id, campaign_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/campaigns/{campaign_id}/tasks")
def list_tasks(
    campaign_id: str,
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List tasks for a campaign, optionally filtered by status."""
    engine = _get_engine(org_id)
    return engine.list_tasks(org_id, campaign_id, status=status)


@router.get("/findings")
def list_findings(
    org_id: str = Query(default="default"),
    campaign_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List findings across all campaigns or filtered by campaign/severity."""
    engine = _get_engine(org_id)
    return engine.list_findings(org_id, campaign_id=campaign_id, severity=severity)


@router.patch("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update a finding's status (open → accepted → remediated)."""
    engine = _get_engine(org_id)
    try:
        return engine.update_finding_status(org_id, finding_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/stats")
def get_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Aggregate pentest stats for an org."""
    engine = _get_engine(org_id)
    return engine.get_stats(org_id)
