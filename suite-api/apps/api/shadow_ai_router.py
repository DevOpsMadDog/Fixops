"""Shadow-AI Router — ALDECI (GAP-059).

Endpoints for the shadow-AI inventory built on top of the AI Governance
engine and the CMDB engine.

Prefix: /api/v1/shadow-ai
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/shadow-ai/discover        discover_shadow_ai across cmdb /
                                         cloud inventory / identity risk /
                                         caller-supplied sources
  POST /api/v1/shadow-ai/register        register an AI service (approved list)
  GET  /api/v1/shadow-ai/registry        list approved AI services
  POST /api/v1/shadow-ai/attack-paths    graph of identity → service → data
  GET  /api/v1/shadow-ai/stats           summary stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/shadow-ai",
    tags=["Shadow AI"],
)

_ai_engine = None
_cmdb_engine = None


def _get_ai_engine():
    global _ai_engine
    if _ai_engine is None:
        from core.ai_governance_engine import AIGovernanceEngine
        _ai_engine = AIGovernanceEngine()
    return _ai_engine


def _get_cmdb_engine():
    global _cmdb_engine
    if _cmdb_engine is None:
        from core.cmdb_engine import CMDBEngine
        _cmdb_engine = CMDBEngine()
    return _cmdb_engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DiscoverRequest(BaseModel):
    sources: Optional[List[Dict[str, Any]]] = Field(default=None)
    flag_unregistered: bool = False


class RegisterRequest(BaseModel):
    service_name: str
    provider: str = ""
    data_classification: str = "internal"
    approved_by: str = ""


class AttackPathsRequest(BaseModel):
    service_name: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/discover", dependencies=[Depends(api_key_auth)])
def discover(
    body: DiscoverRequest,
    org_id: str = Query(default="default"),
):
    """Discover shadow AI signals; optionally flag unregistered hits in CMDB."""
    try:
        result = _get_ai_engine().discover_shadow_ai(
            org_id, sources=body.sources or []
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if body.flag_unregistered and result.get("unregistered"):
        cmdb = _get_cmdb_engine()
        for entry in result["unregistered"]:
            asset_ref = entry.get("asset_ref") or entry.get("name") or ""
            if asset_ref:
                try:
                    cmdb.flag_as_shadow_ai(
                        org_id,
                        str(asset_ref),
                        reason=f"shadow_ai:{entry.get('signal','')}",
                    )
                except ValueError:
                    continue
    return result


@router.post("/register", dependencies=[Depends(api_key_auth)], status_code=201)
def register(body: RegisterRequest, org_id: str = Query(default="default")):
    """Register an AI service into the approved registry."""
    try:
        return _get_ai_engine().register_ai_service(
            org_id,
            service_name=body.service_name,
            provider=body.provider,
            data_classification=body.data_classification,
            approved_by=body.approved_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/registry", dependencies=[Depends(api_key_auth)])
def registry(org_id: str = Query(default="default")):
    """List approved AI services for the org."""
    return _get_ai_engine().list_ai_services(org_id)


@router.post("/attack-paths", dependencies=[Depends(api_key_auth)])
def attack_paths(
    body: AttackPathsRequest,
    org_id: str = Query(default="default"),
):
    """Return potential prompt-injection / data-exfiltration paths for a service."""
    try:
        return _get_ai_engine().ai_attack_paths(org_id, body.service_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(org_id: str = Query(default="default")):
    """Summary stats combining discovery + registry."""
    eng = _get_ai_engine()
    try:
        disc = eng.discover_shadow_ai(org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    registry_rows = eng.list_ai_services(org_id)
    return {
        "registered_services": len(registry_rows),
        "total_signals": disc["total_signals"],
        "unregistered_count": disc["unregistered_count"],
        "registered_count": disc["registered_count"],
        "coverage_pct": disc["coverage_pct"],
        "top_providers": sorted(
            {r["provider"] for r in registry_rows if r.get("provider")}
        ),
    }
