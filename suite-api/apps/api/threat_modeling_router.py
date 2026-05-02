"""STRIDE Threat Modeling REST API.

Endpoints for creating threat models, adding components and data flows,
running STRIDE analysis, recording mitigations, and reporting residual risk.

Prefix: /api/v1/threat-modeling
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.threat_modeling_engine import (
    COMPONENT_TYPES,
    STRIDE_CATEGORIES,
    ThreatModelingEngine,
)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-modeling", tags=["Threat Modeling"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = ThreatModelingEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateModelRequest(BaseModel):
    name: str = Field(..., min_length=1)
    description: str = ""
    scope: str = ""
    org_id: str = "default"


class AddComponentRequest(BaseModel):
    name: str = Field(..., min_length=1)
    component_type: str = Field(..., description=f"One of: {COMPONENT_TYPES}")
    trust_level: str = "internal"
    data_classification: str = "internal"


class AddFlowRequest(BaseModel):
    from_component: str = Field(..., min_length=1)
    to_component: str = Field(..., min_length=1)
    data_type: str = Field(..., min_length=1)
    protocol: str = "https"
    crosses_trust_boundary: bool = False


class AddMitigationRequest(BaseModel):
    mitigation: str = Field(..., min_length=1)
    status: str = "planned"
    owner: str = ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/models", summary="Create a threat model")
def create_model(req: CreateModelRequest) -> Dict[str, Any]:
    return _get_engine().create_model(
        name=req.name,
        description=req.description,
        scope=req.scope,
        org_id=req.org_id,
    )


@router.get("/models", summary="List threat models")
def list_models(org_id: str = "default") -> List[Dict[str, Any]]:
    return _get_engine().list_models(org_id=org_id)


@router.get("/models/{model_id}", summary="Get a threat model")
def get_model(model_id: str) -> Dict[str, Any]:
    model = _get_engine().get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    return model


@router.post("/models/{model_id}/components", summary="Add a component to a model")
def add_component(model_id: str, req: AddComponentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_component(
            model_id=model_id,
            name=req.name,
            component_type=req.component_type,
            trust_level=req.trust_level,
            data_classification=req.data_classification,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/models/{model_id}/flows", summary="Add a data flow to a model")
def add_data_flow(model_id: str, req: AddFlowRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_data_flow(
            model_id=model_id,
            from_component=req.from_component,
            to_component=req.to_component,
            data_type=req.data_type,
            protocol=req.protocol,
            crosses_trust_boundary=req.crosses_trust_boundary,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/models/{model_id}/analyze", summary="Run STRIDE analysis on a model")
def analyze_threats(model_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().analyze_threats(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post(
    "/models/{model_id}/threats/{threat_id}/mitigate",
    summary="Record a mitigation for a threat",
)
def add_mitigation(
    model_id: str, threat_id: str, req: AddMitigationRequest
) -> Dict[str, Any]:
    try:
        return _get_engine().add_mitigation(
            model_id=model_id,
            threat_id=threat_id,
            mitigation=req.mitigation,
            status=req.status,
            owner=req.owner,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/models/{model_id}/report", summary="Get full threat model report")
def get_report(model_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().get_model_report(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/models/{model_id}/residual-risk", summary="Get residual risk after mitigations")
def get_residual_risk(model_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().get_residual_risk(model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/stride-categories", summary="List STRIDE categories and mitigations")
def get_stride_categories() -> Dict[str, Any]:
    return STRIDE_CATEGORIES
