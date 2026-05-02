"""Threat Modeling API — /api/v1/threat-model

STRIDE-based threat model generation, attack trees, and mitigation suggestions.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from core.threat_modeling import (
    STRIDECategory,
    get_threat_modeling_engine,
)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/threat-model", tags=["Threat Modeling"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class GenerateRequest(BaseModel):
    name: str = Field(..., description="Feature/system name")
    description: str = Field(..., description="Feature/system description")
    components: List[str] = Field(..., description="Component names (e.g. 'web-frontend', 'api-gateway', 'database')")
    data_flows: List[str] = Field(default_factory=list, description="Data flows (e.g. 'user->api->db')")
    stride_filter: Optional[List[str]] = Field(None, description="Filter to specific STRIDE categories")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/generate")
async def generate_threat_model(req: GenerateRequest) -> Dict[str, Any]:
    """Generate a STRIDE threat model for a feature or system."""
    engine = get_threat_modeling_engine()
    result = engine.generate_threat_model(
        name=req.name,
        description=req.description,
        components=req.components,
        data_flows=req.data_flows,
        stride_filter=req.stride_filter,
    )
    return asdict(result)


@router.get("/{model_id}")
async def get_threat_model(model_id: str) -> Dict[str, Any]:
    """Retrieve a previously generated threat model."""
    engine = get_threat_modeling_engine()
    result = engine.get_threat_model(model_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Threat model {model_id} not found")
    return asdict(result)


@router.get("/")
async def list_threat_models() -> Dict[str, Any]:
    """List all generated threat models."""
    engine = get_threat_modeling_engine()
    models = engine.list_threat_models()
    return {"models": models, "count": len(models)}


@router.get("/stride/categories")
async def list_stride_categories() -> Dict[str, Any]:
    """List all STRIDE threat categories."""
    return {
        "categories": [c.value for c in STRIDECategory],
        "descriptions": {
            "spoofing": "Impersonating something or someone else",
            "tampering": "Modifying data or code",
            "repudiation": "Claiming to have not performed an action",
            "information_disclosure": "Exposing information to unauthorized parties",
            "denial_of_service": "Deny or degrade service to users",
            "elevation_of_privilege": "Gain capabilities without proper authorization",
        },
    }


@router.get("/component-types")
async def list_component_types() -> Dict[str, Any]:
    """List supported component types for threat modeling."""
    from core.threat_modeling import ComponentType
    return {"component_types": [c.value for c in ComponentType]}

