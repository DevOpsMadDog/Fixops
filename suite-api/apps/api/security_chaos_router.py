"""Security Chaos Router — ALDECI.

Endpoints for the Security Chaos Engineering engine.

Prefix: /api/v1/security-chaos
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/security-chaos/experiments                        create_experiment
  GET  /api/v1/security-chaos/experiments                        list_experiments
  GET  /api/v1/security-chaos/experiments/{id}                   get_experiment
  PUT  /api/v1/security-chaos/experiments/{id}/start             start_experiment
  PUT  /api/v1/security-chaos/experiments/{id}/complete          complete_experiment
  POST /api/v1/security-chaos/experiments/{id}/observations      add_observation
  GET  /api/v1/security-chaos/experiments/{id}/observations      list_observations
  POST /api/v1/security-chaos/experiments/{id}/remediations      add_remediation
  PUT  /api/v1/security-chaos/remediations/{id}/status           update_remediation_status
  GET  /api/v1/security-chaos/stats                              get_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-chaos",
    tags=["Security Chaos"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_chaos_engine import SecurityChaosEngine
        _engine = SecurityChaosEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ExperimentCreate(BaseModel):
    experiment_name: str
    experiment_type: str
    target_system: str
    hypothesis: str = ""
    expected_outcome: str = ""
    scheduled_at: Optional[str] = None


class CompleteExperiment(BaseModel):
    actual_outcome: str = ""
    resilience_score: int = 0


class ObservationCreate(BaseModel):
    observation_type: str
    severity: str = "info"
    description: str = ""
    observed_at: Optional[str] = None


class RemediationCreate(BaseModel):
    finding: str
    remediation_action: str
    priority: str = "medium"


class RemediationStatusUpdate(BaseModel):
    new_status: str


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------

@router.post("/experiments", dependencies=[Depends(api_key_auth)], status_code=201)
def create_experiment(body: ExperimentCreate, org_id: str = Query(default="default")):
    """Create a new chaos experiment."""
    try:
        return _get_engine().create_experiment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/experiments", dependencies=[Depends(api_key_auth)])
def list_experiments(
    org_id: str = Query(default="default"),
    experiment_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List chaos experiments (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — security chaos
    experiments are manually designed by SREs/security engineers (think
    Gremlin/ChaosMonkey-style game-day playbooks), not auto-derivable from
    any public source. Always returns full envelope with pagination context
    + filters echo + actionable hint when empty.
    """
    rows = _get_engine().list_experiments(
        org_id, experiment_type=experiment_type, status=status
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "experiments": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "experiment_type": experiment_type,
            "status": status,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Design and run chaos experiments via POST /api/v1/security-chaos/experiments "
            "(manual experiment design). Empty IS the correct response for a fresh "
            "tenant — no public source exists."
        )
    return envelope


@router.get("/experiments/{experiment_id}", dependencies=[Depends(api_key_auth)])
def get_experiment(experiment_id: str, org_id: str = Query(default="default")):
    """Get a single chaos experiment by ID."""
    exp = _get_engine().get_experiment(org_id, experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail="Experiment not found")
    return exp


@router.put("/experiments/{experiment_id}/start", dependencies=[Depends(api_key_auth)])
def start_experiment(experiment_id: str, org_id: str = Query(default="default")):
    """Start a planned chaos experiment."""
    try:
        return _get_engine().start_experiment(org_id, experiment_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/experiments/{experiment_id}/complete", dependencies=[Depends(api_key_auth)])
def complete_experiment(
    experiment_id: str, body: CompleteExperiment, org_id: str = Query(default="default")
):
    """Complete a chaos experiment with outcome and resilience score."""
    try:
        return _get_engine().complete_experiment(org_id, experiment_id, body.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

@router.post(
    "/experiments/{experiment_id}/observations",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_observation(
    experiment_id: str, body: ObservationCreate, org_id: str = Query(default="default")
):
    """Add an observation to a chaos experiment."""
    try:
        return _get_engine().add_observation(org_id, experiment_id, body.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/experiments/{experiment_id}/observations",
    dependencies=[Depends(api_key_auth)],
)
def list_observations(experiment_id: str, org_id: str = Query(default="default")):
    """List observations for a chaos experiment."""
    return _get_engine().list_observations(org_id, experiment_id)


# ---------------------------------------------------------------------------
# Remediations
# ---------------------------------------------------------------------------

@router.post(
    "/experiments/{experiment_id}/remediations",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_remediation(
    experiment_id: str, body: RemediationCreate, org_id: str = Query(default="default")
):
    """Add a remediation item for a chaos experiment finding."""
    try:
        return _get_engine().add_remediation(org_id, experiment_id, body.model_dump())
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/remediations/{remediation_id}/status", dependencies=[Depends(api_key_auth)])
def update_remediation_status(
    remediation_id: str, body: RemediationStatusUpdate, org_id: str = Query(default="default")
):
    """Update the status of a remediation item."""
    try:
        return _get_engine().update_remediation_status(
            org_id, remediation_id, body.new_status
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(org_id: str = Query(default="default")):
    """Return aggregated chaos engineering statistics."""
    return _get_engine().get_chaos_stats(org_id)
