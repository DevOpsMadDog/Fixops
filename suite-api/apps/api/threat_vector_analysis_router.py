"""Threat Vector Analysis Router — ALDECI.

Tracks attack vectors, associated indicators, and mitigation plans.

Prefix: /api/v1/threat-vectors
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/threat-vectors/vectors                       record_vector
  GET    /api/v1/threat-vectors/vectors                       list_vectors
  GET    /api/v1/threat-vectors/vectors/{id}                  get_vector
  POST   /api/v1/threat-vectors/vectors/{id}/indicators       add_indicator
  GET    /api/v1/threat-vectors/indicators                    list_indicators
  POST   /api/v1/threat-vectors/vectors/{id}/mitigations      create_mitigation
  GET    /api/v1/threat-vectors/mitigations                   list_mitigations
  GET    /api/v1/threat-vectors/stats                         get_vector_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-vectors",
    tags=["Threat Vector Analysis"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_vector_analysis_engine import ThreatVectorAnalysisEngine
        _engine = ThreatVectorAnalysisEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RecordVectorRequest(BaseModel):
    name: str = Field(..., description="Short name for the threat vector")
    vector_type: str = Field(
        default="network",
        description=(
            "network | email | supply_chain | insider | "
            "physical | social_engineering | zero_day | credential_stuffing"
        ),
    )
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    description: Optional[str] = Field(default=None)
    frequency_score: Optional[float] = Field(default=50, ge=0, le=100)
    impact_score: Optional[float] = Field(default=50, ge=0, le=100)
    first_observed: Optional[str] = Field(default=None)
    last_observed: Optional[str] = Field(default=None)


class AddIndicatorRequest(BaseModel):
    indicator_type: str = Field(
        ..., description="ip | domain | url | hash | email | file"
    )
    value: str = Field(..., description="Indicator value (e.g. IP address, domain name)")
    confidence: Optional[float] = Field(default=50, ge=0, le=100)
    source: Optional[str] = Field(default=None)


class CreateMitigationRequest(BaseModel):
    title: str = Field(..., description="Short mitigation title")
    description: Optional[str] = Field(default=None)
    mitigation_status: str = Field(
        default="planned",
        description="planned | in_progress | completed | deferred",
    )
    assigned_to: Optional[str] = Field(default=None)
    due_date: Optional[str] = Field(default=None)
    completed_at: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/vectors", dependencies=[Depends(api_key_auth)])
def record_vector(
    req: RecordVectorRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record a new threat vector."""
    try:
        return _get_engine().record_vector(
            org_id,
            {
                "name": req.name,
                "vector_type": req.vector_type,
                "severity": req.severity,
                "description": req.description or "",
                "frequency_score": req.frequency_score,
                "impact_score": req.impact_score,
                "first_observed": req.first_observed,
                "last_observed": req.last_observed,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/vectors", dependencies=[Depends(api_key_auth)])
def list_vectors(
    org_id: str = Query(..., description="Organization ID"),
    vector_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat vectors with optional filters."""
    return _get_engine().list_vectors(org_id, vector_type=vector_type, severity=severity)


@router.get("/vectors/{vector_id}", dependencies=[Depends(api_key_auth)])
def get_vector(
    vector_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Retrieve a single threat vector by ID."""
    vec = _get_engine().get_vector(org_id, vector_id)
    if vec is None:
        raise HTTPException(status_code=404, detail=f"Vector '{vector_id}' not found")
    return vec


@router.post("/vectors/{vector_id}/indicators", dependencies=[Depends(api_key_auth)])
def add_indicator(
    vector_id: str,
    req: AddIndicatorRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Add an indicator to a threat vector."""
    try:
        return _get_engine().add_indicator(
            org_id,
            vector_id,
            {
                "indicator_type": req.indicator_type,
                "value": req.value,
                "confidence": req.confidence,
                "source": req.source or "",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/indicators", dependencies=[Depends(api_key_auth)])
def list_indicators(
    org_id: str = Query(..., description="Organization ID"),
    vector_id: Optional[str] = Query(default=None),
    indicator_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List indicators with optional filters."""
    return _get_engine().list_indicators(
        org_id, vector_id=vector_id, indicator_type=indicator_type
    )


@router.post("/vectors/{vector_id}/mitigations", dependencies=[Depends(api_key_auth)])
def create_mitigation(
    vector_id: str,
    req: CreateMitigationRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Create a mitigation plan for a threat vector."""
    try:
        return _get_engine().create_mitigation(
            org_id,
            vector_id,
            {
                "title": req.title,
                "description": req.description or "",
                "mitigation_status": req.mitigation_status,
                "assigned_to": req.assigned_to or "",
                "due_date": req.due_date or "",
                "completed_at": req.completed_at,
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/mitigations", dependencies=[Depends(api_key_auth)])
def list_mitigations(
    org_id: str = Query(..., description="Organization ID"),
    vector_id: Optional[str] = Query(default=None),
    mitigation_status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List mitigations with optional filters."""
    return _get_engine().list_mitigations(
        org_id, vector_id=vector_id, mitigation_status=mitigation_status
    )


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_vector_stats(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return aggregate threat vector statistics."""
    return _get_engine().get_vector_stats(org_id)
