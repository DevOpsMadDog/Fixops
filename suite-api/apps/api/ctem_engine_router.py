"""CTEM Engine — Continuous Threat Exposure Management API endpoints.

Implements the Gartner CTEM 5-stage cycle via REST:
  POST /api/v1/ctem/cycles              — create a new cycle
  GET  /api/v1/ctem/cycles              — list cycles for org
  GET  /api/v1/ctem/cycles/{id}         — get cycle by id
  DELETE /api/v1/ctem/cycles/{id}       — (soft) delete cycle [stub]
  POST /api/v1/ctem/cycles/{id}/advance — advance to next stage
  GET  /api/v1/ctem/cycles/{id}/exposures — list exposures for cycle
  POST /api/v1/ctem/exposures           — add an exposure
  PUT  /api/v1/ctem/exposures/{id}      — update an exposure
  POST /api/v1/ctem/cycles/{id}/scope   — scope assets for stage 1
  POST /api/v1/ctem/cycles/{id}/discover — auto-discover exposures (stage 2)
  POST /api/v1/ctem/cycles/{id}/prioritize — risk-rank exposures (stage 3)
  POST /api/v1/ctem/exposures/{id}/validate — validate exploitability (stage 4)
  POST /api/v1/ctem/exposures/{id}/mobilize — assign owner + plan (stage 5)
  GET  /api/v1/ctem/dashboard           — org dashboard
  GET  /api/v1/ctem/stats               — aggregate stats

Auth: _verify_api_key dependency on each route.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

from apps.api.auth_deps import api_key_auth as _verify_api_key

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------

try:
    from core.ctem_engine import CTEMCycle, CTEMEngine, Exposure, get_ctem_engine

    _HAS_ENGINE = True
except ImportError as _exc:
    _logger.warning("ctem_engine_router: ctem_engine unavailable: %s", _exc)
    _HAS_ENGINE = False


def _get_engine() -> "CTEMEngine":
    if not _HAS_ENGINE:
        raise HTTPException(status_code=501, detail="CTEMEngine not available")
    return get_ctem_engine()


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/v1/ctem", tags=["ctem-engine"])

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class StartCycleRequest(BaseModel):
    name: str
    org_id: str = "default"


class ScopeAssetsRequest(BaseModel):
    asset_ids: List[str]


class AddExposureRequest(BaseModel):
    title: str
    description: str = ""
    assets: List[str] = Field(default_factory=list)
    findings: List[str] = Field(default_factory=list)
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    business_impact: str = ""
    org_id: str = "default"


class UpdateExposureRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    risk_score: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    business_impact: Optional[str] = None
    owner: Optional[str] = None
    remediation_plan: Optional[str] = None


class ValidateExposureRequest(BaseModel):
    validated: bool


class MobilizeRequest(BaseModel):
    owner: str
    plan: str


# ---------------------------------------------------------------------------
# Cycle endpoints
# ---------------------------------------------------------------------------


@router.post("/cycles", dependencies=[Depends(_verify_api_key)])
def create_cycle(request: StartCycleRequest) -> Dict[str, Any]:
    """Create a new CTEM cycle starting at SCOPING stage."""
    engine = _get_engine()
    try:
        cycle = engine.start_cycle(name=request.name, org_id=request.org_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return cycle.model_dump(mode="json")


@router.get("/cycles", dependencies=[Depends(_verify_api_key)])
def list_cycles(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """List all CTEM cycles for an org, newest first."""
    engine = _get_engine()
    cycles = engine.list_cycles(org_id=org_id)
    return {"cycles": [c.model_dump(mode="json") for c in cycles], "count": len(cycles)}


@router.get("/cycles/{cycle_id}", dependencies=[Depends(_verify_api_key)])
def get_cycle(cycle_id: str) -> Dict[str, Any]:
    """Get a CTEM cycle by ID."""
    engine = _get_engine()
    try:
        cycle = engine.get_cycle(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return cycle.model_dump(mode="json")


@router.delete("/cycles/{cycle_id}", dependencies=[Depends(_verify_api_key)])
def delete_cycle(cycle_id: str) -> Dict[str, Any]:
    """Delete a CTEM cycle and disassociate its exposures."""
    engine = _get_engine()
    try:
        engine.delete_cycle(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"deleted": True, "cycle_id": cycle_id}


@router.post("/cycles/{cycle_id}/advance", dependencies=[Depends(_verify_api_key)])
def advance_stage(cycle_id: str) -> Dict[str, Any]:
    """Advance cycle to the next CTEM stage."""
    engine = _get_engine()
    try:
        cycle = engine.advance_stage(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return cycle.model_dump(mode="json")


@router.get("/cycles/{cycle_id}/exposures", dependencies=[Depends(_verify_api_key)])
def get_cycle_exposures(cycle_id: str) -> Dict[str, Any]:
    """List all exposures linked to a cycle, sorted by risk_score descending."""
    engine = _get_engine()
    try:
        exposures = engine.get_exposures(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "exposures": [e.model_dump(mode="json") for e in exposures],
        "count": len(exposures),
        "cycle_id": cycle_id,
    }


# ---------------------------------------------------------------------------
# Scope / Discover / Prioritize (stage-specific cycle actions)
# ---------------------------------------------------------------------------


@router.post("/cycles/{cycle_id}/scope", dependencies=[Depends(_verify_api_key)])
def scope_assets(cycle_id: str, request: ScopeAssetsRequest) -> Dict[str, Any]:
    """Stage 1 — define the asset scope for this cycle."""
    engine = _get_engine()
    try:
        cycle = engine.scope_assets(cycle_id, asset_ids=request.asset_ids)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "cycle_id": cycle_id,
        "assets_scoped": len(request.asset_ids),
        "cycle": cycle.model_dump(mode="json"),
    }


@router.post("/cycles/{cycle_id}/discover", dependencies=[Depends(_verify_api_key)])
def discover_exposures(cycle_id: str) -> Dict[str, Any]:
    """Stage 2 — auto-discover exposures from scoped assets."""
    engine = _get_engine()
    try:
        discovered = engine.discover_exposures(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "cycle_id": cycle_id,
        "discovered": [e.model_dump(mode="json") for e in discovered],
        "count": len(discovered),
    }


@router.post("/cycles/{cycle_id}/prioritize", dependencies=[Depends(_verify_api_key)])
def prioritize_exposures(cycle_id: str) -> Dict[str, Any]:
    """Stage 3 — risk-rank all exposures in this cycle."""
    engine = _get_engine()
    try:
        prioritized = engine.prioritize_exposures(cycle_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "cycle_id": cycle_id,
        "prioritized": [e.model_dump(mode="json") for e in prioritized],
        "count": len(prioritized),
    }


# ---------------------------------------------------------------------------
# Exposure endpoints
# ---------------------------------------------------------------------------


@router.post("/exposures", dependencies=[Depends(_verify_api_key)])
def add_exposure(request: AddExposureRequest) -> Dict[str, Any]:
    """Add a new exposure and auto-link it to the latest active cycle."""
    engine = _get_engine()
    try:
        exp = Exposure(
            title=request.title,
            description=request.description,
            assets=request.assets,
            findings=request.findings,
            risk_score=request.risk_score,
            business_impact=request.business_impact,
            org_id=request.org_id,
        )
        saved = engine.add_exposure(exp)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return saved.model_dump(mode="json")


@router.put("/exposures/{exposure_id}", dependencies=[Depends(_verify_api_key)])
def update_exposure(exposure_id: str, request: UpdateExposureRequest) -> Dict[str, Any]:
    """Apply partial updates to an exposure."""
    engine = _get_engine()
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No update fields provided")
    try:
        updated = engine.update_exposure(exposure_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return updated.model_dump(mode="json")


@router.post("/exposures/{exposure_id}/validate", dependencies=[Depends(_verify_api_key)])
def validate_exposure(exposure_id: str, request: ValidateExposureRequest) -> Dict[str, Any]:
    """Stage 4 — confirm or reject exploitability of an exposure."""
    engine = _get_engine()
    try:
        updated = engine.validate_exposure(exposure_id, validated=request.validated)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return updated.model_dump(mode="json")


@router.post("/exposures/{exposure_id}/mobilize", dependencies=[Depends(_verify_api_key)])
def mobilize_remediation(exposure_id: str, request: MobilizeRequest) -> Dict[str, Any]:
    """Stage 5 — assign ownership and remediation plan to an exposure."""
    engine = _get_engine()
    try:
        updated = engine.mobilize_remediation(
            exposure_id, owner=request.owner, plan=request.plan
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return updated.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Dashboard and stats
# ---------------------------------------------------------------------------


@router.get("/dashboard", dependencies=[Depends(_verify_api_key)])
def get_dashboard(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return cycle progress and exposure statistics for the org dashboard."""
    engine = _get_engine()
    return engine.get_ctem_dashboard(org_id=org_id)


@router.get("/stats", dependencies=[Depends(_verify_api_key)])
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate CTEM statistics for the org."""
    engine = _get_engine()
    return engine.get_ctem_stats(org_id=org_id)


@router.get("/", dependencies=[Depends(_verify_api_key)])
def get_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """5-state CTEM domain summary — delegates to dashboard + stats."""
    try:
        engine = _get_engine()
        dashboard = engine.get_ctem_dashboard(org_id=org_id)
        stats = engine.get_ctem_stats(org_id=org_id)
    except HTTPException:
        raise
    except Exception as exc:
        _logger.error("ctem.summary error: %s", exc)
        return {"status": "error", "domain": "ctem", "error": str(exc)}

    active_cycles = stats.get("active_cycles", 0)
    total_exposures = stats.get("total_exposures", 0)
    open_high = stats.get("exposures_by_risk", {}).get("high", 0)

    if total_exposures == 0 and active_cycles == 0:
        status = "empty"
    elif open_high > 0:
        status = "degraded"
    else:
        status = "healthy"

    return {
        "status": status,
        "domain": "ctem",
        "org_id": org_id,
        "dashboard": dashboard,
        "stats": stats,
    }
