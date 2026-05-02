"""AI Governance Router — ALDECI.

Endpoints for the AI Governance engine.

Prefix: /api/v1/ai-governance
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/ai-governance/models                       register_model
  GET  /api/v1/ai-governance/models                       list_models
  GET  /api/v1/ai-governance/models/{model_id}            get_model
  PUT  /api/v1/ai-governance/models/{model_id}/status     update_model_status
  POST /api/v1/ai-governance/assessments                  record_assessment
  GET  /api/v1/ai-governance/assessments                  list_assessments
  POST /api/v1/ai-governance/incidents                    report_incident
  PUT  /api/v1/ai-governance/incidents/{incident_id}/resolve  resolve_incident
  GET  /api/v1/ai-governance/incidents                    list_incidents
  GET  /api/v1/ai-governance/stats                        get_governance_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ai-governance",
    tags=["AI Governance"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ai_governance_engine import AIGovernanceEngine
        _engine = AIGovernanceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ModelCreate(BaseModel):
    model_name: str
    model_type: str = "llm"
    vendor: str = ""
    version: str = ""
    deployment_status: str = "development"
    risk_level: str = "medium"
    use_case: str = ""
    data_classification: str = "internal"


class ModelStatusUpdate(BaseModel):
    new_status: str


class AssessmentCreate(BaseModel):
    model_id: str
    assessment_type: str = "performance"
    score: float
    findings: List[str] = []
    assessor: str = ""


class IncidentCreate(BaseModel):
    model_id: str
    incident_type: str
    severity: str = "medium"
    description: str = ""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@router.post("/models", dependencies=[Depends(api_key_auth)], status_code=201)
def register_model(body: ModelCreate, org_id: str = Query(default="default")):
    """Register a new AI/ML model."""
    try:
        return _get_engine().register_model(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/models", dependencies=[Depends(api_key_auth)])
def list_models(
     org_id: str = Query(default="default"),
    model_type: Optional[str] = Query(None),
    deployment_status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List AI models with optional filters."""
    return _get_engine().list_models(
        org_id,
        model_type=model_type,
        deployment_status=deployment_status,
        risk_level=risk_level,
    )


@router.get("/models/{model_id}", dependencies=[Depends(api_key_auth)])
def get_model(model_id: str, org_id: str = Query(default="default")):
    """Get a single AI model by ID."""
    model = _get_engine().get_model(org_id, model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return model


@router.put("/models/{model_id}/status", dependencies=[Depends(api_key_auth)])
def update_model_status(model_id: str, body: ModelStatusUpdate, org_id: str = Query(default="default")):
    """Update the deployment status of a model."""
    try:
        return _get_engine().update_model_status(org_id, model_id, body.new_status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

@router.post("/assessments", dependencies=[Depends(api_key_auth)], status_code=201)
def record_assessment(body: AssessmentCreate, org_id: str = Query(default="default")):
    """Record a model risk assessment."""
    try:
        return _get_engine().record_assessment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/assessments", dependencies=[Depends(api_key_auth)])
def list_assessments(
     org_id: str = Query(default="default"),
    model_id: Optional[str] = Query(None),
    assessment_type: Optional[str] = Query(None),
):
    """List assessments with optional filters."""
    return _get_engine().list_assessments(
        org_id, model_id=model_id, assessment_type=assessment_type
    )


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.post("/incidents", dependencies=[Depends(api_key_auth)], status_code=201)
def report_incident(body: IncidentCreate, org_id: str = Query(default="default")):
    """Report an AI incident."""
    try:
        return _get_engine().report_incident(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/incidents/{incident_id}/resolve", dependencies=[Depends(api_key_auth)])
def resolve_incident(incident_id: str, org_id: str = Query(default="default")):
    """Resolve an AI incident."""
    try:
        return _get_engine().resolve_incident(org_id, incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/incidents", dependencies=[Depends(api_key_auth)])
def list_incidents(
     org_id: str = Query(default="default"),
    model_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
):
    """List incidents with optional filters."""
    return _get_engine().list_incidents(
        org_id, model_id=model_id, status=status, severity=severity
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_governance_stats(org_id: str = Query(default="default")):
    """Return aggregated AI governance statistics."""
    return _get_engine().get_governance_stats(org_id)


# ---------------------------------------------------------------------------
# Rule context requirements
# ---------------------------------------------------------------------------

class RuleContextRequirementCreate(BaseModel):
    rule_key: str
    tier: str = "metadata"
    max_tokens: int = 4096


@router.post("/rules/context-requirements", dependencies=[Depends(api_key_auth)], status_code=201)
def register_rule_context_requirement(
    body: RuleContextRequirementCreate,
    org_id: str = Query(default="default"),
):
    """Register or upsert a per-rule LLM context requirement (tier + token budget)."""
    try:
        return _get_engine().register_rule_context_requirement(
            org_id, body.rule_key, body.tier, body.max_tokens
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/rules/context-requirements", dependencies=[Depends(api_key_auth)])
def list_rule_context_requirements(org_id: str = Query(default="default")):
    """List all registered rule context requirements for the org."""
    return _get_engine().list_rule_context_requirements(org_id)


# ---------------------------------------------------------------------------
# LLM cost estimation
# ---------------------------------------------------------------------------

class CostEstimateRequest(BaseModel):
    rule_keys: List[str] = []
    file_count: int = 1


@router.post("/cost/estimate", dependencies=[Depends(api_key_auth)])
def estimate_llm_cost(body: CostEstimateRequest, org_id: str = Query(default="default")):
    """Estimate LLM token cost for a scan across supplied rules and file count."""
    try:
        return _get_engine().estimate_llm_cost(org_id, body.rule_keys, body.file_count)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cost/preflight", dependencies=[Depends(api_key_auth)])
def preflight_estimate(body: CostEstimateRequest, org_id: str = Query(default="default")):
    """Pre-flight cost estimate with human-readable summary and tier distribution."""
    try:
        return _get_engine().preflight_estimate(org_id, body.rule_keys, body.file_count)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
