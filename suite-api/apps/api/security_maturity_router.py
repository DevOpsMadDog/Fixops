"""Security Maturity Router — ALDECI.

Endpoints for CMMI-based security maturity assessments.
Prefix: /api/v1/security-maturity
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-maturity",
    tags=["security-maturity"],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from pathlib import Path

        from core.security_maturity_engine import SecurityMaturityEngine
        db_path = str(Path(__file__).resolve().parents[4] / ".fixops_data" / "security_maturity.db")
        _engine = SecurityMaturityEngine(db_path)
    return _engine


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

try:
    from apps.api.auth_deps import api_key_auth
except ImportError:
    def api_key_auth():
        return "anon"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AssessmentCreate(BaseModel):
    name: str
    framework: str = "nist_csf"
    assessor_id: str = ""
    start_date: str = ""


class DomainScoreUpdate(BaseModel):
    score: float = Field(ge=0.0, le=100.0)
    evidence: str = ""
    gaps: str = ""
    recommendations: str = ""


class ControlCreate(BaseModel):
    control_id: str = ""
    control_name: str
    implementation_status: str = "not_implemented"
    evidence: str = ""
    score: Optional[float] = None
    weight: float = 1.0


class TargetCreate(BaseModel):
    domain_name: str
    current_level: int = Field(ge=1, le=5, default=1)
    target_level: int = Field(ge=1, le=5, default=3)
    target_date: str = ""
    effort_estimate: str = "medium"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/assessments")
def create_assessment(
    body: AssessmentCreate,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Create a new maturity assessment."""
    try:
        return _get_engine().create_assessment(org_id, body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/assessments")
def list_assessments(
    org_id: str = Query(default="default"),
    status: Optional[str] = Query(default=None),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List assessments, optionally filtered by status."""
    return {"assessments": _get_engine().list_assessments(org_id, status=status)}


@router.get("/assessments/{assessment_id}")
def get_assessment(
    assessment_id: str,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get assessment with all domains."""
    result = _get_engine().get_assessment(org_id, assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return result


@router.post("/assessments/{assessment_id}/complete")
def complete_assessment(
    assessment_id: str,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Complete an assessment — computes overall score and level."""
    result = _get_engine().complete_assessment(org_id, assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail="Assessment not found.")
    return result


@router.put("/domains/{domain_id}/score")
def score_domain(
    domain_id: str,
    body: DomainScoreUpdate,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Score a domain within an assessment."""
    result = _get_engine().add_domain_score(org_id, domain_id, body.model_dump())
    if not result:
        raise HTTPException(status_code=404, detail="Domain not found.")
    return result


@router.post("/domains/{domain_id}/controls")
def add_control(
    domain_id: str,
    body: ControlCreate,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Add a control to a domain."""
    try:
        return _get_engine().add_control(org_id, domain_id, body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/domains/{domain_id}/controls")
def list_controls(
    domain_id: str,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List controls for a domain."""
    return {"controls": _get_engine().list_controls(org_id, domain_id)}


@router.post("/targets")
def set_target(
    body: TargetCreate,
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Set a maturity target for a domain."""
    try:
        return _get_engine().set_target(org_id, body.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


@router.get("/targets")
def list_targets(
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """List all maturity targets with gap analysis."""
    return {"targets": _get_engine().list_targets(org_id)}


@router.get("/stats")
def get_stats(
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get maturity statistics for an org."""
    return _get_engine().get_maturity_stats(org_id)


@router.get("/roadmap")
def get_roadmap(
    org_id: str = Query(default="default"),
    _: Any = Depends(api_key_auth),
) -> Dict[str, Any]:
    """Get maturity roadmap ordered by gap size."""
    return {"roadmap": _get_engine().get_roadmap(org_id)}
