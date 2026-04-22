"""Stage Matrix Router — GAP-004 (CTEM stage-aware policy enforcement).

Exposes per-stage policy opt-in and evaluation. A policy's stage matrix is a
dict of boolean flags keyed by the 5 CTEM stages: {ide, pr, build, deploy,
runtime}. Evaluation at a given stage filters to policies that opted into it.

Endpoints (all under /api/v1/stage-matrix):

  POST /api/v1/stage-matrix/policy     — set stage matrix on a policy
  POST /api/v1/stage-matrix/evaluate   — evaluate context at a stage
  GET  /api/v1/stage-matrix/policies   — list policies for a stage

Auth: `api_key_auth` via `dependencies=[Depends(api_key_auth)]`.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/stage-matrix", tags=["stage-matrix"])

_VALID_STAGES = {"ide", "pr", "build", "deploy", "runtime"}


# ---------------------------------------------------------------------------
# Engine loader
# ---------------------------------------------------------------------------


def _get_enforcement_engine(org_id: str):
    from core.policy_enforcement_engine import get_engine  # type: ignore

    return get_engine(org_id)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class StageMatrixRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    policy_id: str = Field(..., min_length=1, max_length=128)
    stage_matrix: Dict[str, bool] = Field(...)

    @field_validator("stage_matrix")
    @classmethod
    def _validate_stages(cls, v: Dict[str, bool]) -> Dict[str, bool]:
        unknown = set(v.keys()) - _VALID_STAGES
        if unknown:
            raise ValueError(
                f"Invalid stage keys {sorted(unknown)}. Valid: {sorted(_VALID_STAGES)}"
            )
        return v


class EvaluateRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=128)
    stage: str = Field(..., min_length=1, max_length=32)
    context: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: str) -> str:
        if v not in _VALID_STAGES:
            raise ValueError(f"Invalid stage '{v}'. Valid: {sorted(_VALID_STAGES)}")
        return v


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/policy")
def set_stage_matrix(req: StageMatrixRequest) -> Dict[str, Any]:
    """Assign a CTEM stage opt-in matrix to an existing policy."""
    try:
        engine = _get_enforcement_engine(req.org_id)
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"engine unavailable: {exc}")
    try:
        updated = engine.set_stage_matrix(req.org_id, req.policy_id, req.stage_matrix)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail=f"policy not found: {req.policy_id}")
    return updated


@router.post("/evaluate")
def evaluate_stage(req: EvaluateRequest) -> Dict[str, Any]:
    """Evaluate context at a CTEM stage, returning matched policies + decision."""
    try:
        engine = _get_enforcement_engine(req.org_id)
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"engine unavailable: {exc}")
    try:
        return engine.evaluate(req.org_id, req.stage, req.context)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/policies")
def list_policies_for_stage(
    org_id: str = Query(default="default", min_length=1, max_length=128),
    stage: str = Query(..., min_length=1, max_length=32),
) -> Dict[str, Any]:
    """List policies whose stage_matrix[stage]=True for an org."""
    if stage not in _VALID_STAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid stage '{stage}'. Valid: {sorted(_VALID_STAGES)}",
        )
    try:
        engine = _get_enforcement_engine(org_id)
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=503, detail=f"engine unavailable: {exc}")
    try:
        policies: List[Dict[str, Any]] = engine.list_policies_for_stage(org_id, stage)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "org_id": org_id,
        "stage": stage,
        "policy_count": len(policies),
        "policies": policies,
    }
