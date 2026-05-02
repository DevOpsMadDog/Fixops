"""Threat Brief Router — ALDECI.

Manages threat intelligence brief lifecycle: authoring, distribution,
recipient tracking, and embedded threat records.

Prefix: /api/v1/threat-briefs
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-briefs/briefs                          create_brief
  GET    /api/v1/threat-briefs/briefs                          list_briefs
  GET    /api/v1/threat-briefs/briefs/{id}                     get_brief
  POST   /api/v1/threat-briefs/briefs/{id}/distribute          distribute_brief
  GET    /api/v1/threat-briefs/recipients                      list_recipients
  POST   /api/v1/threat-briefs/briefs/{id}/threats             add_threat
  GET    /api/v1/threat-briefs/threats                         list_threats
  GET    /api/v1/threat-briefs/stats                           get_brief_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-briefs",
    tags=["Threat Briefs"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_brief_engine import ThreatBriefEngine
        _engine = ThreatBriefEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateBriefRequest(BaseModel):
    title: str = Field(..., description="Brief title (required)")
    brief_type: str = Field(
        default="daily",
        description="daily | weekly | monthly | incident | executive | technical",
    )
    threat_level: str = Field(
        default="medium",
        description="critical | high | medium | low | informational",
    )
    summary: Optional[str] = Field(default=None, description="Executive summary")
    key_findings: Optional[List[str]] = Field(default=None, description="List of key findings")
    recommendations: Optional[List[str]] = Field(default=None, description="List of recommendations")
    distribution_status: str = Field(
        default="draft",
        description="draft | pending | distributed | recalled",
    )
    author: Optional[str] = Field(default=None, description="Author name or ID")
    period_start: Optional[str] = Field(default=None, description="Period start (ISO 8601)")
    period_end: Optional[str] = Field(default=None, description="Period end (ISO 8601)")


class RecipientItem(BaseModel):
    recipient_type: str = Field(
        default="individual",
        description="ciso | soc | executive | all_staff | team | individual",
    )
    recipient_id: Optional[str] = Field(default=None)
    recipient_email: Optional[str] = Field(default=None)


class DistributeBriefRequest(BaseModel):
    recipients: List[RecipientItem] = Field(
        default_factory=list,
        description="List of recipients to distribute to",
    )


class AddThreatRequest(BaseModel):
    threat_name: str = Field(..., description="Threat name (required)")
    threat_actor: Optional[str] = Field(default=None, description="Threat actor / APT group")
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low | informational",
    )
    affected_sectors: Optional[List[str]] = Field(default=None, description="Affected industry sectors")
    ioc_count: int = Field(default=0, ge=0, description="Number of IOCs associated")
    mitre_tactics: Optional[List[str]] = Field(default=None, description="MITRE ATT&CK tactics")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/briefs", dependencies=[Depends(api_key_auth)])
def create_brief(
    req: CreateBriefRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a new threat brief."""
    try:
        return _get_engine().create_brief(
            org_id,
            {
                "title": req.title,
                "brief_type": req.brief_type,
                "threat_level": req.threat_level,
                "summary": req.summary or "",
                "key_findings": req.key_findings or [],
                "recommendations": req.recommendations or [],
                "distribution_status": req.distribution_status,
                "author": req.author or "",
                "period_start": req.period_start or "",
                "period_end": req.period_end or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/briefs", dependencies=[Depends(api_key_auth)])
def list_briefs(
    org_id: str = Query(..., description="Organization ID"),
    brief_type: Optional[str] = Query(default=None),
    distribution_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat briefs with optional filters."""
    return _get_engine().list_briefs(
        org_id,
        brief_type=brief_type,
        distribution_status=distribution_status,
    )


@router.get("/briefs/{brief_id}", dependencies=[Depends(api_key_auth)])
def get_brief(
    brief_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single threat brief by ID."""
    brief = _get_engine().get_brief(org_id, brief_id)
    if brief is None:
        raise HTTPException(status_code=404, detail=f"Brief '{brief_id}' not found")
    return brief


@router.post("/briefs/{brief_id}/distribute", dependencies=[Depends(api_key_auth)])
def distribute_brief(
    brief_id: str,
    req: DistributeBriefRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Distribute a brief to a list of recipients."""
    try:
        recipient_data = [
            {
                "recipient_type": r.recipient_type,
                "recipient_id": r.recipient_id or "",
                "recipient_email": r.recipient_email or "",
            }
            for r in req.recipients
        ]
        return _get_engine().distribute_brief(org_id, brief_id, recipient_data)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/recipients", dependencies=[Depends(api_key_auth)])
def list_recipients(
    org_id: str = Query(..., description="Organization ID"),
    brief_id: Optional[str] = Query(default=None),
    recipient_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List brief recipients with optional filters."""
    return _get_engine().list_recipients(
        org_id,
        brief_id=brief_id,
        recipient_type=recipient_type,
    )


@router.post("/briefs/{brief_id}/threats", dependencies=[Depends(api_key_auth)])
def add_threat(
    brief_id: str,
    req: AddThreatRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add a threat record to a brief."""
    try:
        return _get_engine().add_threat(
            org_id,
            brief_id,
            {
                "threat_name": req.threat_name,
                "threat_actor": req.threat_actor or "",
                "severity": req.severity,
                "affected_sectors": req.affected_sectors or [],
                "ioc_count": req.ioc_count,
                "mitre_tactics": req.mitre_tactics or [],
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/threats", dependencies=[Depends(api_key_auth)])
def list_threats(
    org_id: str = Query(..., description="Organization ID"),
    brief_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat records with optional brief_id filter."""
    return _get_engine().list_threats(org_id, brief_id=brief_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_brief_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate threat brief statistics."""
    return _get_engine().get_brief_stats(org_id)


@router.get("", dependencies=[Depends(api_key_auth)])
def get_root(org_id: str = Query(default="default")):
    """Root endpoint — returns briefs list for dashboard health-checks."""
    return _get_engine().list_briefs(org_id)
