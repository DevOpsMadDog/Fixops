"""Cyber Threat Modeling Router — ALDECI.

Attack tree threat modeling with FAIR risk scoring.

Prefix: /api/v1/cyber-threat-models
Auth: api_key_auth on ALL endpoints
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cyber-threat-models",
    tags=["Cyber Threat Modeling"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.cyber_threat_modeling_engine import CyberThreatModelingEngine
            _engine = CyberThreatModelingEngine()
        except Exception as exc:
            _logger.error("Failed to init CyberThreatModelingEngine: %s", exc)
            raise HTTPException(status_code=503, detail="Cyber threat modeling engine unavailable")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ModelCreate(BaseModel):
    model_name: str = Field(..., description="Threat model name")
    system_name: str = Field(..., description="System being modeled")
    model_type: str = Field("application", description="application/infrastructure/cloud/iot/supply_chain/data_flow")
    scope: str = Field("", description="Scope description")
    created_by: str = Field("", description="Creator identity")


class AttackTreeCreate(BaseModel):
    root_goal: str = Field(..., description="Root attack goal")
    attack_vector: str = Field(..., description="Attack vector")
    likelihood: str = Field("medium", description="critical/high/medium/low")
    impact: str = Field("medium", description="critical/high/medium/low")
    path_steps: List[str] = Field(default_factory=list, description="Attack path steps")


class MitigateRequest(BaseModel):
    mitigation: str = Field(..., description="Mitigation description")


class ThreatActorCreate(BaseModel):
    actor_name: str = Field(..., description="Actor name")
    actor_type: str = Field("criminal", description="nation_state/criminal/insider/hacktivist/competitor/researcher")
    motivation: str = Field("", description="Motivation")
    capability: str = Field("moderate", description="sophisticated/moderate/basic")
    target_assets: List[str] = Field(default_factory=list, description="Targeted assets")
    tactics: List[str] = Field(default_factory=list, description="TTPs/tactics")


class FinalizeRequest(BaseModel):
    reviewed_by: str = Field(..., description="Reviewer identity")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/models", status_code=201)
def create_model(
    payload: ModelCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a new cyber threat model."""
    try:
        return _get_engine().create_model(
            org_id=org_id,
            model_name=payload.model_name,
            system_name=payload.system_name,
            model_type=payload.model_type,
            scope=payload.scope,
            created_by=payload.created_by,
        )
    except Exception as exc:
        _logger.exception("Error creating threat model")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/models/{model_id}/trees", status_code=201)
def add_attack_tree(
    model_id: str,
    payload: AttackTreeCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add an attack tree to a threat model."""
    try:
        return _get_engine().add_attack_tree(
            model_id=model_id,
            org_id=org_id,
            root_goal=payload.root_goal,
            attack_vector=payload.attack_vector,
            likelihood=payload.likelihood,
            impact=payload.impact,
            path_steps=payload.path_steps,
        )
    except Exception as exc:
        _logger.exception("Error adding attack tree")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/trees/{tree_id}/mitigate")
def mitigate_tree(
    tree_id: str,
    payload: MitigateRequest,
    model_id: str = Query(..., description="Parent model ID"),
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Mark an attack tree as mitigated (idempotent)."""
    result = _get_engine().mitigate_tree(
        tree_id=tree_id,
        model_id=model_id,
        org_id=org_id,
        mitigation=payload.mitigation,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Attack tree not found")
    return result


@router.post("/models/{model_id}/actors", status_code=201)
def add_threat_actor(
    model_id: str,
    payload: ThreatActorCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a threat actor profile to a model."""
    try:
        return _get_engine().add_threat_actor(
            model_id=model_id,
            org_id=org_id,
            actor_name=payload.actor_name,
            actor_type=payload.actor_type,
            motivation=payload.motivation,
            capability=payload.capability,
            target_assets=payload.target_assets,
            tactics=payload.tactics,
        )
    except Exception as exc:
        _logger.exception("Error adding threat actor")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/models/{model_id}/finalize")
def finalize_model(
    model_id: str,
    payload: FinalizeRequest,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Finalize a threat model."""
    result = _get_engine().finalize_model(model_id, org_id, payload.reviewed_by)
    if result is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return result


@router.get("/models/{model_id}")
def get_model_detail(
    model_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return model with attack trees and threat actors."""
    result = _get_engine().get_model_detail(model_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Threat model not found")
    return result


@router.get("/unmitigated")
def get_unmitigated_threats(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return all unmitigated attack trees with model names."""
    return _get_engine().get_unmitigated_threats(org_id)


@router.get("/summary")
def get_model_summary(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate summary across all models."""
    return _get_engine().get_model_summary(org_id)
