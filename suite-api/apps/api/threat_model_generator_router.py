"""Threat Model Generator Router — ALDECI.

Exposes CRUD for threat models, auto-generation, threats, mitigations, reviews, stats.
Prefix: /api/v1/threat-model-gen
Auth: api_key_auth dependency
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-model-gen",
    tags=["Threat Model Generator"],
)

# Lazy singleton
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_model_generator import ThreatModelGenerator
        _engine = ThreatModelGenerator()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ThreatModelCreate(BaseModel):
    name: str
    description: str = ""
    system_type: str = "web_app"
    methodology: str = "STRIDE"
    status: str = "draft"
    data_classification: str = "internal"
    trust_boundaries: List[str] = Field(default_factory=list)
    components: List[str] = Field(default_factory=list)


class ThreatCreate(BaseModel):
    stride_category: str = "Spoofing"
    title: str
    description: str = ""
    attack_vector: str = ""
    likelihood: str = "medium"
    impact: str = "medium"
    risk_rating: str = "medium"
    mitigations: List[str] = Field(default_factory=list)
    status: str = "open"


class ThreatStatusUpdate(BaseModel):
    status: str


class MitigationCreate(BaseModel):
    title: str
    mitigation_type: str = "preventive"
    status: str = "planned"
    effort: str = "medium"
    owner: str = ""
    due_date: str = ""


class ReviewCreate(BaseModel):
    reviewer: str
    verdict: str = "needs_revision"
    comments: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/{org_id}/models", summary="Create a threat model")
def create_model(org_id: str, body: ThreatModelCreate, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.create_model(org_id, body.model_dump())
    except Exception as exc:
        _logger.exception("create_model failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}/models", summary="List threat models")
def list_models(
    org_id: str,
    status: Optional[str] = Query(None),
    methodology: Optional[str] = Query(None),
    _=Depends(api_key_auth),
):
    engine = _get_engine()
    return engine.list_models(org_id, status=status, methodology=methodology)


@router.get("/{org_id}/models/{model_id}", summary="Get a threat model")
def get_model(org_id: str, model_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    result = engine.get_model(org_id, model_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return result


@router.post("/{org_id}/models/{model_id}/auto-generate", summary="Auto-generate STRIDE threats")
def auto_generate_threats(org_id: str, model_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.auto_generate_threats(org_id, model_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("auto_generate_threats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/{org_id}/models/{model_id}/threats", summary="Add a threat")
def add_threat(org_id: str, model_id: str, body: ThreatCreate, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.add_threat(org_id, model_id, body.model_dump())
    except Exception as exc:
        _logger.exception("add_threat failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}/models/{model_id}/threats", summary="List threats")
def list_threats(
    org_id: str,
    model_id: str,
    stride_category: Optional[str] = Query(None),
    _=Depends(api_key_auth),
):
    engine = _get_engine()
    return engine.list_threats(org_id, model_id, stride_category=stride_category)


@router.patch("/{org_id}/threats/{threat_id}/status", summary="Update threat status")
def update_threat_status(org_id: str, threat_id: str, body: ThreatStatusUpdate, _=Depends(api_key_auth)):
    engine = _get_engine()
    ok = engine.update_threat_status(org_id, threat_id, body.status)
    if not ok:
        raise HTTPException(status_code=404, detail="Threat not found")
    return {"updated": True}


@router.post("/{org_id}/threats/{threat_id}/mitigations", summary="Add a mitigation")
def add_mitigation(org_id: str, threat_id: str, body: MitigationCreate, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.add_mitigation(org_id, threat_id, body.model_dump())
    except Exception as exc:
        _logger.exception("add_mitigation failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}/threats/{threat_id}/mitigations", summary="List mitigations")
def list_mitigations(org_id: str, threat_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    return engine.list_mitigations(org_id, threat_id)


@router.post("/{org_id}/models/{model_id}/reviews", summary="Add a model review")
def add_review(org_id: str, model_id: str, body: ReviewCreate, _=Depends(api_key_auth)):
    engine = _get_engine()
    try:
        return engine.add_review(org_id, model_id, body.model_dump())
    except Exception as exc:
        _logger.exception("add_review failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/{org_id}/stats", summary="Get threat model stats")
def get_model_stats(org_id: str, _=Depends(api_key_auth)):
    engine = _get_engine()
    return engine.get_model_stats(org_id)
