"""Security OKR Router — ALDECI.

Endpoints for the Security OKR engine.

Prefix: /api/v1/security-okrs
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/security-okrs/objectives                              create_objective
  GET   /api/v1/security-okrs/objectives                              list_objectives
  GET   /api/v1/security-okrs/objectives/{id}                         get_objective
  POST  /api/v1/security-okrs/objectives/{id}/key-results             add_key_result
  POST  /api/v1/security-okrs/objectives/{id}/key-results/{kr_id}/update  update_key_result
  GET   /api/v1/security-okrs/summary/{period}                        get_period_summary
  GET   /api/v1/security-okrs/team/{owner}                            get_team_okrs
  POST  /api/v1/security-okrs/objectives/{id}/close                   close_objective
  GET   /api/v1/security-okrs/velocity                                get_okr_velocity
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-okrs",
    tags=["Security OKR"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_okr_engine import SecurityOKREngine
        _engine = SecurityOKREngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ObjectiveCreate(BaseModel):
    title: str
    description: str = ""
    owner: str = ""
    period: str = "Q1-2026"
    due_date: Optional[str] = None


class KeyResultCreate(BaseModel):
    title: str
    target_value: float
    unit: str = "count"


class KeyResultUpdate(BaseModel):
    new_value: float
    notes: str = ""
    updated_by: str = ""


class ObjectiveClose(BaseModel):
    final_status: str


# ---------------------------------------------------------------------------
# Objectives
# ---------------------------------------------------------------------------

@router.post("/objectives", dependencies=[Depends(api_key_auth)], status_code=201)
def create_objective(body: ObjectiveCreate, org_id: str = Query(default="default")):
    """Create a new security objective."""
    try:
        return _get_engine().create_objective(
            org_id=org_id,
            title=body.title,
            description=body.description,
            owner=body.owner,
            period=body.period,
            due_date=body.due_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/objectives", dependencies=[Depends(api_key_auth)])
def list_objectives(
     org_id: str = Query(default="default"),
    period: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List objectives with optional filters."""
    return _get_engine().list_objectives(org_id, period=period, status=status)


@router.get("/objectives/{objective_id}", dependencies=[Depends(api_key_auth)])
def get_objective(objective_id: str, org_id: str = Query(default="default")):
    """Get an objective with its key results."""
    result = _get_engine().get_objective(objective_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail="Objective not found")
    return result


@router.post("/objectives/{objective_id}/close", dependencies=[Depends(api_key_auth)])
def close_objective(
    objective_id: str,
    body: ObjectiveClose,
     org_id: str = Query(default="default"),
):
    """Close an objective with a final status."""
    try:
        return _get_engine().close_objective(objective_id, org_id, body.final_status)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Key Results
# ---------------------------------------------------------------------------

@router.post(
    "/objectives/{objective_id}/key-results",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_key_result(
    objective_id: str,
    body: KeyResultCreate,
     org_id: str = Query(default="default"),
):
    """Add a key result to an objective."""
    try:
        return _get_engine().add_key_result(
            objective_id=objective_id,
            org_id=org_id,
            title=body.title,
            target_value=body.target_value,
            unit=body.unit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post(
    "/objectives/{objective_id}/key-results/{kr_id}/update",
    dependencies=[Depends(api_key_auth)],
)
def update_key_result(
    objective_id: str,
    kr_id: str,
    body: KeyResultUpdate,
     org_id: str = Query(default="default"),
):
    """Update a key result value and recompute progress."""
    try:
        return _get_engine().update_key_result(
            key_result_id=kr_id,
            objective_id=objective_id,
            org_id=org_id,
            new_value=body.new_value,
            notes=body.notes,
            updated_by=body.updated_by,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Summary & Team
# ---------------------------------------------------------------------------

@router.get("/summary/{period}", dependencies=[Depends(api_key_auth)])
def get_period_summary(period: str, org_id: str = Query(default="default")):
    """Get OKR summary for a period."""
    return _get_engine().get_period_summary(org_id, period)


@router.get("/team/{owner}", dependencies=[Depends(api_key_auth)])
def get_team_okrs(owner: str, org_id: str = Query(default="default")):
    """Get objectives filtered by owner."""
    return _get_engine().get_team_okrs(org_id, owner)


# ---------------------------------------------------------------------------
# Velocity
# ---------------------------------------------------------------------------

@router.get("/velocity", dependencies=[Depends(api_key_auth)])
def get_okr_velocity(org_id: str = Query(default="default")):
    """Get per-objective update history showing progress over time."""
    return _get_engine().get_okr_velocity(org_id)
