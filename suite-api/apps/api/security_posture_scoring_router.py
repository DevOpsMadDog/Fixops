"""Security Posture Scoring Router — ALDECI.

Control registration, weighted posture score calculation, history, and gap stats.

Prefix: /api/v1/posture-scoring
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/posture-scoring/controls                register_control
  GET    /api/v1/posture-scoring/controls                list_controls
  GET    /api/v1/posture-scoring/controls/{id}           get_control
  PATCH  /api/v1/posture-scoring/controls/{id}/status    update_control_status
  POST   /api/v1/posture-scoring/score                   calculate_posture_score
  GET    /api/v1/posture-scoring/history                 get_posture_history
  GET    /api/v1/posture-scoring/stats                   get_posture_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/posture-scoring",
    tags=["Security Posture Scoring"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_posture_scoring_engine import SecurityPostureScoringEngine
        _engine = SecurityPostureScoringEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterControlRequest(BaseModel):
    name: str = Field(..., description="Control name")
    domain: str = Field(
        default="governance",
        description="identity | network | endpoint | cloud | application | data | governance",
    )
    description: str = Field(default="")
    weight: float = Field(default=1.0, gt=0.0, description="Relative importance weight")
    control_status: str = Field(
        default="not_implemented",
        description="implemented | partial | not_implemented | compensating",
    )
    evidence_url: str = Field(default="")
    last_assessed: Optional[str] = Field(default=None)


class UpdateControlStatusRequest(BaseModel):
    control_status: str = Field(
        ...,
        description="implemented | partial | not_implemented | compensating",
    )
    evidence_url: str = Field(default="")


class CalculateScoreRequest(BaseModel):
    domain: Optional[str] = Field(
        default=None,
        description="Limit score to a specific domain; omit for all-domain score",
    )


# ---------------------------------------------------------------------------
# Routes — Controls
# ---------------------------------------------------------------------------

@router.post("/controls", dependencies=[Depends(api_key_auth)], status_code=201)
def register_control(
    body: RegisterControlRequest,
    org_id: str = Query(default="default"),
):
    """Register a new security control."""
    try:
        return _get_engine().register_control(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering control")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/controls", dependencies=[Depends(api_key_auth)])
def list_controls(
    org_id: str = Query(default="default"),
    domain: Optional[str] = Query(default=None),
    control_status: Optional[str] = Query(default=None),
):
    """List controls with optional domain/status filters."""
    return _get_engine().list_controls(
        org_id, domain=domain, control_status=control_status
    )


@router.get("/controls/{control_id}", dependencies=[Depends(api_key_auth)])
def get_control(
    control_id: str,
    org_id: str = Query(default="default"),
):
    """Retrieve a single control by ID."""
    ctrl = _get_engine().get_control(org_id, control_id)
    if ctrl is None:
        raise HTTPException(status_code=404, detail=f"Control {control_id} not found")
    return ctrl


@router.patch("/controls/{control_id}/status", dependencies=[Depends(api_key_auth)])
def update_control_status(
    control_id: str,
    body: UpdateControlStatusRequest,
    org_id: str = Query(default="default"),
):
    """Update a control's status and optional evidence URL."""
    try:
        return _get_engine().update_control_status(
            org_id, control_id, body.control_status, body.evidence_url
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error updating control status")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Routes — Score & History
# ---------------------------------------------------------------------------

@router.post("/score", dependencies=[Depends(api_key_auth)])
def calculate_posture_score(
    body: CalculateScoreRequest,
    org_id: str = Query(default="default"),
):
    """Compute weighted posture score and persist a snapshot."""
    try:
        return _get_engine().calculate_posture_score(org_id, domain=body.domain)
    except Exception as exc:
        _logger.exception("Error calculating posture score")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/history", dependencies=[Depends(api_key_auth)])
def get_posture_history(
    org_id: str = Query(default="default"),
    domain: Optional[str] = Query(default=None),
    limit: int = Query(default=30, ge=1, le=500),
):
    """Retrieve posture score history snapshots."""
    return _get_engine().get_posture_history(org_id, domain=domain, limit=limit)


# ---------------------------------------------------------------------------
# Routes — Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_posture_stats(org_id: str = Query(default="default")):
    """Return overall posture score, per-domain scores, and control gap counts."""
    return _get_engine().get_posture_stats(org_id)


@router.get("/context/{entity_id}", dependencies=[Depends(api_key_auth)])
def get_trustgraph_context(
    entity_id: str,
    org_id: str = Query(default="default"),
):
    """Return TrustGraph cross-domain context for a posture entity (related assets, findings, incidents)."""
    return _get_engine().get_trustgraph_context(org_id, entity_id)
