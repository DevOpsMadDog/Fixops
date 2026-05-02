"""AI Security Advisor Router — ALDECI.

LLM council-powered proactive security recommendations, incident analysis,
remediation plans, and threat briefings.

Prefix: /api/v1/ai-advisor
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/ai-advisor/posture-review              generate_posture_recommendations
  POST   /api/v1/ai-advisor/analyze-incident            analyze_incident
  POST   /api/v1/ai-advisor/remediation-plan            generate_remediation_plan
  POST   /api/v1/ai-advisor/threat-briefing             get_threat_briefing
  POST   /api/v1/ai-advisor/ask                         ask_advisor
  GET    /api/v1/ai-advisor/sessions                    list_sessions
  GET    /api/v1/ai-advisor/sessions/{session_id}       get_session
  GET    /api/v1/ai-advisor/recommendations             list_recommendations
  PATCH  /api/v1/ai-advisor/recommendations/{rec_id}/status   update_recommendation_status
  GET    /api/v1/ai-advisor/stats                       get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-advisor",
    tags=["AI Security Advisor"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ai_security_advisor_engine import AISecurityAdvisorEngine
        _engine = AISecurityAdvisorEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PostureReviewRequest(BaseModel):
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Security posture context: risk_score, critical_findings, top_vulnerabilities, compliance_status, etc.",
    )


class IncidentAnalysisRequest(BaseModel):
    incident_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Incident details: type, affected_systems, timeline, initial_iocs, severity, etc.",
    )


class RemediationPlanRequest(BaseModel):
    vulnerability_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Vulnerability details: cve_id, name, severity, affected_component, cvss_score, etc.",
    )


class ThreatBriefingRequest(BaseModel):
    threat_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Threat context: industry, active_campaigns, recent_iocs, threat_actor_ttps, etc.",
    )


class AskAdvisorRequest(BaseModel):
    question: str = Field(..., description="Free-form security question")
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional context to include with the question",
    )


class RecommendationStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        description="New status: pending | accepted | rejected | implemented",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/posture-review", dependencies=[Depends(api_key_auth)], status_code=201)
def generate_posture_recommendations(
    body: PostureReviewRequest,
    org_id: str = Query(default="default"),
):
    """Generate 5 prioritised security recommendations based on current posture."""
    try:
        return _get_engine().generate_posture_recommendations(org_id, body.context)
    except Exception as exc:
        _logger.exception("Error generating posture recommendations")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/analyze-incident", dependencies=[Depends(api_key_auth)], status_code=201)
def analyze_incident(
    body: IncidentAnalysisRequest,
    org_id: str = Query(default="default"),
):
    """Analyse a security incident: root cause, blast radius, immediate actions."""
    try:
        return _get_engine().analyze_incident(org_id, body.incident_data)
    except Exception as exc:
        _logger.exception("Error analysing incident")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/remediation-plan", dependencies=[Depends(api_key_auth)], status_code=201)
def generate_remediation_plan(
    body: RemediationPlanRequest,
    org_id: str = Query(default="default"),
):
    """Generate a step-by-step remediation plan for a vulnerability."""
    try:
        return _get_engine().generate_remediation_plan(org_id, body.vulnerability_data)
    except Exception as exc:
        _logger.exception("Error generating remediation plan")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/threat-briefing", dependencies=[Depends(api_key_auth)], status_code=201)
def get_threat_briefing(
    body: ThreatBriefingRequest,
    org_id: str = Query(default="default"),
):
    """Generate an executive threat briefing with top threats and recommended actions."""
    try:
        return _get_engine().get_threat_briefing(org_id, body.threat_context)
    except Exception as exc:
        _logger.exception("Error generating threat briefing")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/ask", dependencies=[Depends(api_key_auth)])
def ask_advisor(
    body: AskAdvisorRequest,
    org_id: str = Query(default="default"),
):
    """Ask the AI security advisor a free-form security question."""
    try:
        return _get_engine().ask_advisor(org_id, body.question, body.context)
    except Exception as exc:
        _logger.exception("Error asking advisor")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/sessions", dependencies=[Depends(api_key_auth)])
def list_sessions(
    org_id: str = Query(default="default"),
    session_type: Optional[str] = Query(default=None),
):
    """List advisor sessions, optionally filtered by session_type."""
    return _get_engine().list_sessions(org_id, session_type=session_type)


@router.get("/sessions/{session_id}", dependencies=[Depends(api_key_auth)])
def get_session(
    session_id: str,
    org_id: str = Query(default="default"),
):
    """Get a single advisor session with its recommendations."""
    session = _get_engine().get_session(org_id, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/recommendations", dependencies=[Depends(api_key_auth)])
def list_recommendations(
    org_id: str = Query(default="default"),
    priority: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
):
    """List recommendations with optional priority/category/status filters."""
    return _get_engine().list_recommendations(
        org_id, priority=priority, category=category, status=status
    )


@router.patch(
    "/recommendations/{rec_id}/status",
    dependencies=[Depends(api_key_auth)],
)
def update_recommendation_status(
    rec_id: str,
    body: RecommendationStatusUpdate,
    org_id: str = Query(default="default"),
):
    """Update the lifecycle status of a recommendation."""
    try:
        updated = _get_engine().update_recommendation_status(org_id, rec_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return {"updated": True, "recommendation_id": rec_id, "status": body.status}


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated AI advisor statistics for the org."""
    return _get_engine().get_stats(org_id)
