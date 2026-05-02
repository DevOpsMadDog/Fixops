"""Threat Modeling Pipeline Router — ALDECI.

Automated threat modeling pipeline with STRIDE analysis and mitigation tracking.

Prefix: /api/v1/threat-modeling-pipeline
Auth: _verify_api_key

Routes:
  POST /models                              create_model
  POST /models/{id}/components              add_component
  POST /models/{id}/threats                 add_threat
  POST /models/{id}/threats/{t_id}/mitigate mitigate_threat
  POST /models/{id}/finalize                finalize_model
  GET  /models/{id}                         get_model
  GET  /models                              list_models
  GET  /models/{id}/stride-summary          get_stride_summary
  GET  /unmitigated                         get_unmitigated_threats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-modeling-pipeline",
    tags=["Threat Modeling Pipeline"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_modeling_pipeline_engine import ThreatModelingPipelineEngine
        _engine = ThreatModelingPipelineEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateModelRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    model_name: str = Field(..., description="Name of the threat model")
    system_description: str = Field(default="", description="Description of the system being modeled")
    methodology: str = Field(
        default="STRIDE",
        description="STRIDE|PASTA|VAST|attack-tree|OCTAVE|custom",
    )
    created_by: str = Field(default="", description="Creator username or ID")


class AddComponentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    component_name: str = Field(..., description="Name of the component")
    component_type: str = Field(
        ...,
        description="process|datastore|external-entity|data-flow|trust-boundary",
    )
    trust_boundary: str = Field(default="", description="Trust boundary this component belongs to")
    data_flows: List[str] = Field(default_factory=list, description="List of connected component names")


class AddThreatRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    threat_name: str = Field(..., description="Name of the threat")
    stride_category: str = Field(
        ...,
        description=(
            "S-Spoofing|T-Tampering|R-Repudiation|"
            "I-InfoDisclosure|D-DenialOfService|E-ElevationOfPrivilege"
        ),
    )
    description: str = Field(default="", description="Threat description")
    affected_component: str = Field(default="", description="Affected component name")
    likelihood: str = Field(default="medium", description="critical|high|medium|low")
    impact: str = Field(default="medium", description="critical|high|medium|low")


class MitigateThreatRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    mitigation_description: str = Field(default="", description="Description of the mitigation applied")


class OrgRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_threat_modeling_pipeline(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List threat models for the org."""
    return _get_engine().list_models(org_id=org_id)


@router.post("/models", summary="Create a new threat model")
def create_model(req: CreateModelRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_model(
            org_id=req.org_id,
            model_name=req.model_name,
            system_description=req.system_description,
            methodology=req.methodology,
            created_by=req.created_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/models/{model_id}/components", summary="Add a component to a threat model")
def add_component(model_id: str, req: AddComponentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_component(
            model_id=model_id,
            org_id=req.org_id,
            component_name=req.component_name,
            component_type=req.component_type,
            trust_boundary=req.trust_boundary,
            data_flows=req.data_flows,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/models/{model_id}/threats", summary="Add a threat to a model")
def add_threat(model_id: str, req: AddThreatRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_threat(
            model_id=model_id,
            org_id=req.org_id,
            threat_name=req.threat_name,
            stride_category=req.stride_category,
            description=req.description,
            affected_component=req.affected_component,
            likelihood=req.likelihood,
            impact=req.impact,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post(
    "/models/{model_id}/threats/{threat_id}/mitigate",
    summary="Mark a threat as mitigated",
)
def mitigate_threat(
    model_id: str,
    threat_id: str,
    req: MitigateThreatRequest,
) -> Dict[str, Any]:
    try:
        return _get_engine().mitigate_threat(
            model_id=model_id,
            threat_id=threat_id,
            org_id=req.org_id,
            mitigation_description=req.mitigation_description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/models/{model_id}/finalize", summary="Finalize a threat model")
def finalize_model(model_id: str, req: OrgRequest) -> Dict[str, Any]:
    try:
        return _get_engine().finalize_model(model_id=model_id, org_id=req.org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/models/{model_id}", summary="Get a threat model with components and threats")
def get_model(
    model_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_model(model_id=model_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/models", summary="List threat models")
def list_models(
    org_id: str = Query(..., description="Organisation ID"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    methodology: Optional[str] = Query(default=None, description="Filter by methodology"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_models(
        org_id=org_id,
        status=status,
        methodology=methodology,
    )


@router.get("/models/{model_id}/stride-summary", summary="Get STRIDE category summary")
def get_stride_summary(
    model_id: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_stride_summary(model_id=model_id, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/unmitigated", summary="Get all unmitigated threats across all models")
def get_unmitigated_threats(
    org_id: str = Query(..., description="Organisation ID"),
) -> List[Dict[str, Any]]:
    return _get_engine().get_unmitigated_threats(org_id=org_id)
