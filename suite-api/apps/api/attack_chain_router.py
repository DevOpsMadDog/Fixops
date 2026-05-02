"""Attack Chain Router — ALDECI.

Multi-step attack chain (kill chain) management API.

Prefix: /api/v1/attack-chains
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/attack-chains/chains                    create_chain
  GET    /api/v1/attack-chains/chains                    list_chains
  GET    /api/v1/attack-chains/chains/{id}               get_chain
  PUT    /api/v1/attack-chains/chains/{id}/status        update_chain_status
  POST   /api/v1/attack-chains/chains/{id}/steps         add_chain_step
  GET    /api/v1/attack-chains/chains/{id}/steps         list_chain_steps
  POST   /api/v1/attack-chains/links                     link_chains
  GET    /api/v1/attack-chains/chains/{id}/links         get_chain_links
  GET    /api/v1/attack-chains/stats                     get_attack_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/attack-chains",
    tags=["Attack Chains"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.attack_chain_engine import AttackChainEngine
        _engine = AttackChainEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateChainRequest(BaseModel):
    org_id: str = Field(default="default")
    chain_name: str = Field(..., description="Name of the attack chain")
    threat_actor: str = Field(default="", description="Threat actor attribution")
    kill_chain_phase: str = Field(
        default="reconnaissance",
        description="reconnaissance/weaponization/delivery/exploitation/installation/c2/actions_on_objectives",
    )
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)
    iocs: List[str] = Field(default_factory=list, description="Indicators of compromise")


class UpdateStatusRequest(BaseModel):
    new_status: str = Field(..., description="active/contained/eradicated/recovered")


class AddStepRequest(BaseModel):
    org_id: str = Field(default="default")
    technique_id: str = Field(default="", description="MITRE technique ID e.g. T1059")
    technique_name: str = Field(..., description="Technique name")
    tactic: str = Field(..., description="ATT&CK tactic")
    asset_targeted: str = Field(default="", description="Asset targeted in this step")
    outcome: str = Field(default="unknown", description="success/failed/unknown")
    step_number: Optional[int] = Field(default=None, description="Step number (auto if omitted)")
    evidence: List[str] = Field(default_factory=list, description="Evidence items")


class LinkChainsRequest(BaseModel):
    org_id: str = Field(default="default")
    source_chain_id: str = Field(..., description="Source attack chain ID")
    target_chain_id: str = Field(..., description="Target attack chain ID")
    link_type: str = Field(
        default="lateral_movement",
        description="lateral_movement/persistence/escalation",
    )
    confidence: float = Field(default=50.0, ge=0.0, le=100.0)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/chains", dependencies=[Depends(api_key_auth)], status_code=201)
def create_chain(req: CreateChainRequest) -> Dict[str, Any]:
    """Create a new attack chain."""
    try:
        return _get_engine().create_chain(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_chain failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/chains", dependencies=[Depends(api_key_auth)])
def list_chains(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    kill_chain_phase: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List attack chains with optional filters."""
    try:
        return _get_engine().list_chains(org_id, status=status, kill_chain_phase=kill_chain_phase)
    except Exception as exc:
        _logger.exception("list_chains failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_attack_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregated attack chain statistics."""
    try:
        return _get_engine().get_attack_stats(org_id)
    except Exception as exc:
        _logger.exception("get_attack_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/chains/{chain_id}", dependencies=[Depends(api_key_auth)])
def get_chain(chain_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get a single attack chain by ID."""
    try:
        result = _get_engine().get_chain(org_id, chain_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Chain '{chain_id}' not found.")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_chain failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/chains/{chain_id}/status", dependencies=[Depends(api_key_auth)])
def update_chain_status(chain_id: str, body: UpdateStatusRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Update the status of an attack chain."""
    try:
        return _get_engine().update_chain_status(org_id, chain_id, body.new_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_chain_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/chains/{chain_id}/steps", dependencies=[Depends(api_key_auth)], status_code=201)
def add_chain_step(chain_id: str, req: AddStepRequest) -> Dict[str, Any]:
    """Add a step to an attack chain."""
    try:
        return _get_engine().add_chain_step(req.org_id, chain_id, req.model_dump(exclude={"org_id"}))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("add_chain_step failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/chains/{chain_id}/steps", dependencies=[Depends(api_key_auth)])
def list_chain_steps(chain_id: str, org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """List all steps for an attack chain ordered by step_number."""
    try:
        return _get_engine().list_chain_steps(org_id, chain_id)
    except Exception as exc:
        _logger.exception("list_chain_steps failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/links", dependencies=[Depends(api_key_auth)], status_code=201)
def link_chains(req: LinkChainsRequest) -> Dict[str, Any]:
    """Link two attack chains together."""
    try:
        return _get_engine().link_chains(req.org_id, req.model_dump(exclude={"org_id"}))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("link_chains failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/chains/{chain_id}/links", dependencies=[Depends(api_key_auth)])
def get_chain_links(chain_id: str, org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """Get all links for an attack chain (source or target)."""
    try:
        return _get_engine().get_chain_links(org_id, chain_id)
    except Exception as exc:
        _logger.exception("get_chain_links failed")
        raise HTTPException(status_code=500, detail=str(exc))
