"""Identity Risk Router — ALDECI.

Endpoints for the Identity Risk engine.

Prefix: /api/v1/identity-risk
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/identity-risk/identities                         register_identity
  GET  /api/v1/identity-risk/identities                         list_identities
  GET  /api/v1/identity-risk/identities/{identity_id}           get_identity
  PUT  /api/v1/identity-risk/identities/{identity_id}/risk-score update_risk_score
  POST /api/v1/identity-risk/risk-factors                       record_risk_factor
  GET  /api/v1/identity-risk/risk-factors                       list_risk_factors
  PUT  /api/v1/identity-risk/risk-factors/{factor_id}/mitigate  mitigate_factor
  POST /api/v1/identity-risk/access-reviews                     record_access_review
  GET  /api/v1/identity-risk/access-reviews                     list_access_reviews
  GET  /api/v1/identity-risk/stats                              get_identity_risk_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/identity-risk",
    tags=["Identity Risk"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.identity_risk_engine import IdentityRiskEngine
        _engine = IdentityRiskEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class IdentityCreate(BaseModel):
    username: str = ""
    email: str = ""
    identity_type: str = "human"
    department: str = ""
    risk_score: float = 0.0
    mfa_enabled: bool = False
    last_activity: Optional[str] = None
    status: str = "active"


class RiskScoreUpdate(BaseModel):
    risk_score: float


class RiskFactorCreate(BaseModel):
    identity_id: str
    factor_type: str
    severity: str = "medium"
    score_impact: float = 0.0
    description: str = ""
    detected_at: Optional[str] = None
    status: str = "active"


class AccessReviewCreate(BaseModel):
    identity_id: str
    reviewer: str
    decision: str = "deferred"
    resource: str = ""
    access_level: str = ""
    review_reason: str = ""
    reviewed_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------

@router.post("/identities", dependencies=[Depends(api_key_auth)], status_code=201)
def register_identity(body: IdentityCreate, org_id: str = Query(default="default")):
    """Register a new identity."""
    try:
        return _get_engine().register_identity(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/identities", dependencies=[Depends(api_key_auth)])
def list_identities(
     org_id: str = Query(default="default"),
    identity_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List identities with optional filters."""
    return _get_engine().list_identities(
        org_id,
        identity_type=identity_type,
        risk_level=risk_level,
        status=status,
    )


@router.get("/identities/{identity_id}", dependencies=[Depends(api_key_auth)])
def get_identity(identity_id: str, org_id: str = Query(default="default")):
    """Get a single identity by ID."""
    result = _get_engine().get_identity(org_id, identity_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return result


@router.put("/identities/{identity_id}/risk-score", dependencies=[Depends(api_key_auth)])
def update_risk_score(identity_id: str, body: RiskScoreUpdate, org_id: str = Query(default="default")):
    """Update identity risk score (auto-computes risk_level)."""
    try:
        return _get_engine().update_risk_score(org_id, identity_id, body.risk_score)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Risk Factors
# ---------------------------------------------------------------------------

@router.post("/risk-factors", dependencies=[Depends(api_key_auth)], status_code=201)
def record_risk_factor(body: RiskFactorCreate, org_id: str = Query(default="default")):
    """Record a risk factor for an identity."""
    try:
        return _get_engine().record_risk_factor(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/risk-factors", dependencies=[Depends(api_key_auth)])
def list_risk_factors(
     org_id: str = Query(default="default"),
    identity_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List risk factors with optional filters."""
    return _get_engine().list_risk_factors(
        org_id,
        identity_id=identity_id,
        severity=severity,
        status=status,
    )


@router.put("/risk-factors/{factor_id}/mitigate", dependencies=[Depends(api_key_auth)])
def mitigate_factor(factor_id: str, org_id: str = Query(default="default")):
    """Mark a risk factor as mitigated."""
    try:
        return _get_engine().mitigate_factor(org_id, factor_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Access Reviews
# ---------------------------------------------------------------------------

@router.post("/access-reviews", dependencies=[Depends(api_key_auth)], status_code=201)
def record_access_review(body: AccessReviewCreate, org_id: str = Query(default="default")):
    """Record an access review decision."""
    try:
        return _get_engine().record_access_review(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/access-reviews", dependencies=[Depends(api_key_auth)])
def list_access_reviews(
     org_id: str = Query(default="default"),
    identity_id: Optional[str] = Query(None),
    decision: Optional[str] = Query(None),
):
    """List access reviews with optional filters."""
    return _get_engine().list_access_reviews(
        org_id,
        identity_id=identity_id,
        decision=decision,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_identity_risk_stats(org_id: str = Query(default="default")):
    """Return aggregated identity risk statistics."""
    return _get_engine().get_identity_risk_stats(org_id)
