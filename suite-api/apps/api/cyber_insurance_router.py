"""Cyber Insurance API Router — ALDECI.

Endpoints (all under /api/v1/cyber-insurance):

  Policies:
    GET  /policies              — list insurance policies
    POST /policies              — add a new policy

  Assessments:
    GET  /assessments           — list coverage assessments
    POST /assessments           — create a coverage assessment

  Claims:
    GET  /claims                — list claims (filter: status)
    POST /claims                — file a new claim
    PATCH /claims/{id}          — update claim status / settlement amount

  Stats:
    GET  /stats                 — insurance portfolio statistics

Auth: Depends(_verify_api_key) injected at app.include_router() level.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.cyber_insurance_engine import CyberInsuranceEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cyber-insurance", tags=["cyber-insurance"])

_engine = None  # lazy-initialised on first request


def _get_engine():
    global _engine
    if _engine is None:
        _engine = CyberInsuranceEngine()
    return _engine

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class PolicyIn(BaseModel):
    carrier: str = ""
    policy_number: str = ""
    coverage_type: str = "both"
    coverage_limit: float = 0.0
    deductible: float = 0.0
    premium_annual: float = 0.0
    effective_date: str = ""
    expiry_date: str = ""
    status: str = "active"
    covered_events: List[str] = Field(default_factory=list)


class AssessmentIn(BaseModel):
    policy_id: str
    mfa_score: int = 0
    backup_score: int = 0
    incident_response_score: int = 0
    patch_score: int = 0
    training_score: int = 0
    recommendations: List[str] = Field(default_factory=list)
    assessed_at: Optional[str] = None


class ClaimIn(BaseModel):
    policy_id: str
    incident_type: str = ""
    incident_date: str = ""
    estimated_loss: float = 0.0
    adjuster: str = ""


class ClaimUpdateIn(BaseModel):
    status: str
    settlement_amount: Optional[float] = None


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/policies")
def list_policies(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all cyber insurance policies for an org."""
    try:
        return _get_engine().list_policies(org_id)
    except Exception as exc:
        logger.exception("list_policies failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/policies", status_code=201)
def add_policy(
    payload: PolicyIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a new cyber insurance policy."""
    try:
        return _get_engine().add_policy(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("add_policy failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------


@router.get("/assessments")
def list_assessments(
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """List all coverage assessments for an org."""
    try:
        return _get_engine().list_assessments(org_id)
    except Exception as exc:
        logger.exception("list_assessments failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/assessments", status_code=201)
def create_assessment(
    payload: AssessmentIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a coverage assessment for a policy."""
    try:
        data = payload.model_dump()
        policy_id = data.pop("policy_id")
        return _get_engine().create_assessment(org_id, policy_id, data)
    except Exception as exc:
        logger.exception("create_assessment failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------


@router.get("/claims")
def list_claims(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List insurance claims, optionally filtered by status."""
    try:
        return _get_engine().list_claims(org_id, status=status)
    except Exception as exc:
        logger.exception("list_claims failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/claims", status_code=201)
def file_claim(
    payload: ClaimIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """File a new cyber insurance claim."""
    try:
        return _get_engine().file_claim(org_id, payload.model_dump())
    except Exception as exc:
        logger.exception("file_claim failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.patch("/claims/{claim_id}")
def update_claim(
    claim_id: str,
    payload: ClaimUpdateIn,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Update claim status and optionally set settlement amount."""
    try:
        updated = _get_engine().update_claim(
            org_id,
            claim_id,
            payload.status,
            settlement_amount=payload.settlement_amount,
        )
        if not updated:
            raise HTTPException(
                status_code=404,
                detail=f"Claim {claim_id} not found or invalid status '{payload.status}'",
            )
        return {"claim_id": claim_id, "status": payload.status, "updated": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("update_claim failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return cyber insurance portfolio statistics for an org."""
    try:
        return _get_engine().get_insurance_stats(org_id)
    except Exception as exc:
        logger.exception("get_insurance_stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
