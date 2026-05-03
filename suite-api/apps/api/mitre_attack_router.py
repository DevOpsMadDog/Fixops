"""MITRE ATT&CK Coverage API Router.

Endpoints:
    GET  /api/v1/mitre-attack/coverage          -- overall coverage % + tactic breakdown
    GET  /api/v1/mitre-attack/heatmap           -- heatmap data for ATT&CK Navigator
    GET  /api/v1/mitre-attack/gaps              -- undetected techniques (coverage gaps)
    GET  /api/v1/mitre-attack/techniques        -- list all registered techniques
    GET  /api/v1/mitre-attack/detections        -- list detection events
    POST /api/v1/mitre-attack/techniques        -- add a custom technique
    POST /api/v1/mitre-attack/detections        -- log a detection event
    POST /api/v1/mitre-attack/seed              -- seed the 14 tactics + 28+ techniques

Security:
    All endpoints require API key authentication via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mitre-attack",
    tags=["mitre-attack"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine factory
# ---------------------------------------------------------------------------

def _get_engine():
    from core.mitre_attack_coverage_engine import get_mitre_coverage_engine
    return get_mitre_coverage_engine()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AddTechniqueRequest(BaseModel):
    technique_id: str = Field(..., min_length=2, max_length=20, description="e.g. T1190")
    name: str = Field(..., min_length=1, max_length=200)
    tactic_id: str = Field(..., min_length=4, max_length=10, description="e.g. TA0001")
    description: str = Field("", max_length=1000)
    severity: str = Field("medium", description="critical|high|medium|low")


class LogDetectionRequest(BaseModel):
    technique_id: str = Field(..., min_length=2, max_length=20)
    source: str = Field(..., min_length=1, max_length=100, description="e.g. 'ids', 'siem', 'edr'")
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    metadata: Optional[Dict[str, Any]] = Field(None)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/seed")
async def seed_techniques(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Seed the 14 MITRE ATT&CK tactics and 28+ key Enterprise techniques."""
    try:
        engine = _get_engine()
        count = engine.seed_att_ck_techniques(org_id)
        return {"org_id": org_id, "seeded": count, "status": "ok"}
    except Exception as exc:
        logger.exception("mitre_attack.seed failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/coverage")
async def get_coverage(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get overall ATT&CK coverage percentage and per-tactic breakdown."""
    try:
        engine = _get_engine()
        return engine.get_coverage(org_id)
    except Exception as exc:
        logger.exception("mitre_attack.coverage failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/heatmap")
async def get_heatmap(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Get heatmap data: technique → detection count per tactic (ATT&CK Navigator format)."""
    try:
        engine = _get_engine()
        return engine.get_heatmap(org_id)
    except Exception as exc:
        logger.exception("mitre_attack.heatmap failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/gaps")
async def get_gaps(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Get undetected techniques — the critical coverage gaps."""
    try:
        engine = _get_engine()
        return engine.get_gaps(org_id)
    except Exception as exc:
        logger.exception("mitre_attack.gaps failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques")
async def list_techniques(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all ATT&CK techniques registered for the org."""
    try:
        engine = _get_engine()
        return engine.get_techniques(org_id)
    except Exception as exc:
        logger.exception("mitre_attack.techniques.list failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/techniques/{technique_id}")
async def get_technique_by_id(
    technique_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Look up a single MITRE ATT&CK technique by ID (e.g. T1190)."""
    try:
        engine = _get_engine()
        result = engine.get_technique_by_id(org_id, technique_id)
        if result is None:
            raise HTTPException(status_code=404, detail=f"Technique {technique_id.upper()} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("mitre_attack.technique.lookup failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/techniques")
async def add_technique(
    body: AddTechniqueRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register a custom MITRE ATT&CK technique."""
    try:
        engine = _get_engine()
        return engine.add_technique(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("mitre_attack.techniques.add failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/detections")
async def list_detections(
    org_id: str = Depends(get_org_id),
    technique_id: Optional[str] = Query(None, description="Filter by technique ID"),
    limit: int = Query(100, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    """List detection events for the org."""
    try:
        engine = _get_engine()
        return engine.get_detections(org_id, technique_id=technique_id, limit=limit)
    except Exception as exc:
        logger.exception("mitre_attack.detections.list failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/detections")
async def log_detection(
    body: LogDetectionRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Log a detection event for a MITRE ATT&CK technique."""
    try:
        engine = _get_engine()
        return engine.log_detection(
            org_id=org_id,
            technique_id=body.technique_id,
            source=body.source,
            confidence=body.confidence,
            metadata=body.metadata,
        )
    except Exception as exc:
        logger.exception("mitre_attack.detections.log failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats")
async def get_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregated MITRE ATT&CK statistics: technique count, detection count, coverage %."""
    try:
        engine = _get_engine()
        coverage = engine.get_coverage(org_id)
        detections = engine.get_detections(org_id, limit=1000)
        techniques = engine.get_techniques(org_id)
        return {
            "org_id": org_id,
            "total_techniques": len(techniques),
            "total_detections": len(detections),
            "coverage_pct": coverage.get("coverage_pct", 0.0),
            "tactics_covered": coverage.get("tactics_covered", 0),
            "tactics_total": coverage.get("tactics_total", 0),
        }
    except Exception as exc:
        logger.exception("mitre_attack.stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
