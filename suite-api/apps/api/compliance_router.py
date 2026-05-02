"""Compliance Router — ALDECI.

Endpoints for the ComplianceAutomationEngine (7-framework, SQLite-backed).
This is distinct from compliance_scanner_router.py (compliance_scanner_engine.py).

Prefix: /api/v1/compliance
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/compliance/status                          get_overall_status
  GET    /api/v1/compliance/status/{framework}              get_framework_status
  POST   /api/v1/compliance/{framework}/collect-evidence    collect_evidence
  GET    /api/v1/compliance/evidence                        get_evidence
  GET    /api/v1/compliance/gaps                            get_gaps
  GET    /api/v1/compliance/cross-map                       get_cross_map
  POST   /api/v1/compliance/poam                            create_poam
  PATCH  /api/v1/compliance/poam/{poam_id}/status           update_poam_status
  GET    /api/v1/compliance/poam                            get_poam_list
  POST   /api/v1/compliance/{framework}/record-score        record_score
  GET    /api/v1/compliance/{framework}/score-trend         get_score_trend
  GET    /api/v1/compliance/{framework}/report              generate_report
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from apps.api.auth_deps import api_key_auth
from core.cache_layer import TTL_COMPLIANCE, cache_endpoint
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/compliance",
    tags=["Compliance Automation"],
)

_engine = None

_DB_PATH = os.environ.get(
    "COMPLIANCE_DB_PATH",
    "/tmp/aldeci_compliance.db",  # nosec B108
)


def _get_engine():
    global _engine
    if _engine is None:
        from core.compliance_engine import ComplianceAutomationEngine
        _engine = ComplianceAutomationEngine(db_path=_DB_PATH)
    return _engine


# Valid frameworks exposed by the engine
_FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001", "NIST-800-53", "CMMC"]

# Valid POA&M statuses
_POAM_STATUSES = ["open", "in_progress", "completed", "risk_accepted", "delayed"]


def _validate_framework(framework: str) -> None:
    if framework not in _FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{framework}'. Supported: {_FRAMEWORKS}",
        )


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CollectEvidenceRequest(BaseModel):
    control_id: Optional[str] = Field(
        default=None,
        description="If provided, collect evidence only for this control ID.",
    )
    org_id: Optional[str] = None


class POAMCreate(BaseModel):
    control_id: str
    framework: str
    title: str
    description: str
    responsible_party: str = "Security Team"
    risk_level: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    target_date: Optional[str] = None


class POAMStatusUpdate(BaseModel):
    status: str = Field(description="open | in_progress | completed | risk_accepted | delayed")
    risk_accepted: bool = False


# ---------------------------------------------------------------------------
# Overall / framework status
# ---------------------------------------------------------------------------

@router.get("/status", dependencies=[Depends(api_key_auth)])
@cache_endpoint(ttl=TTL_COMPLIANCE)
async def get_overall_status():
    """Return compliance status across all 7 frameworks."""
    return _get_engine().get_overall_status()


@router.get("/status/{framework}", dependencies=[Depends(api_key_auth)])
def get_framework_status(framework: str):
    """Return detailed control-level status for a single framework."""
    _validate_framework(framework)
    try:
        return _get_engine().get_framework_status(framework)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------

@router.post("/{framework}/collect-evidence", dependencies=[Depends(api_key_auth)], status_code=201)
def collect_evidence(framework: str, body: CollectEvidenceRequest):
    """
    Auto-collect evidence from ALDECI modules for a framework.
    Optionally scope to a single control_id.
    Returns list of collected evidence items.
    """
    _validate_framework(framework)
    try:
        items = _get_engine().collect_evidence(
            framework=framework,
            control_id=body.control_id,
            org_id=body.org_id,
        )
        return [item.model_dump() for item in items]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/evidence", dependencies=[Depends(api_key_auth)])
def get_evidence(
    framework: Optional[str] = Query(None),
    control_id: Optional[str] = Query(None),
):
    """Return evidence items, optionally filtered by framework and/or control_id."""
    return _get_engine().get_evidence(framework=framework, control_id=control_id)


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

@router.get("/gaps", dependencies=[Depends(api_key_auth)])
def get_gaps(framework: Optional[str] = Query(None)):
    """
    Return a priority-ranked gap analysis.
    Optionally filter to a single framework.
    """
    try:
        gaps = _get_engine().get_gaps(framework=framework)
        return [g.model_dump() for g in gaps]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Cross-framework mapping
# ---------------------------------------------------------------------------

@router.get("/cross-map", dependencies=[Depends(api_key_auth)])
def get_cross_map():
    """Return all cross-framework control mappings."""
    entries = _get_engine().get_cross_map()
    return [e.model_dump() for e in entries]


# ---------------------------------------------------------------------------
# POA&M
# ---------------------------------------------------------------------------

@router.post("/poam", dependencies=[Depends(api_key_auth)], status_code=201)
def create_poam(body: POAMCreate):
    """Create a Plan of Action & Milestones item for a failing control."""
    _validate_framework(body.framework)
    try:
        from core.compliance_engine import RemediationPriority
        risk_level = RemediationPriority(body.risk_level)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid risk_level '{body.risk_level}'. Use: critical | high | medium | low",
        )
    try:
        item = _get_engine().create_poam(
            control_id=body.control_id,
            framework=body.framework,
            title=body.title,
            description=body.description,
            responsible_party=body.responsible_party,
            risk_level=risk_level,
            target_date=body.target_date,
        )
        return item.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch("/poam/{poam_id}/status", dependencies=[Depends(api_key_auth)])
def update_poam_status(poam_id: str, body: POAMStatusUpdate):
    """Update the status of a POA&M item."""
    if body.status not in _POAM_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{body.status}'. Use: {_POAM_STATUSES}",
        )
    try:
        from core.compliance_engine import POAMStatus
        item = _get_engine().update_poam_status(
            poam_id=poam_id,
            status=POAMStatus(body.status),
            risk_accepted=body.risk_accepted,
        )
        return item.model_dump()
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/poam", dependencies=[Depends(api_key_auth)])
def get_poam_list(framework: Optional[str] = Query(None)):
    """Return all POA&M items, optionally filtered by framework."""
    items = _get_engine().get_poam_list(framework=framework)
    return [i.model_dump() for i in items]


# ---------------------------------------------------------------------------
# Score tracking
# ---------------------------------------------------------------------------

@router.post("/{framework}/record-score", dependencies=[Depends(api_key_auth)], status_code=201)
def record_score(framework: str):
    """Record the current compliance score snapshot for a framework (for trend tracking)."""
    _validate_framework(framework)
    try:
        score = _get_engine().record_score(framework)
        return score.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{framework}/score-trend", dependencies=[Depends(api_key_auth)])
def get_score_trend(
    framework: str,
    limit: int = Query(default=30, ge=1, le=365),
):
    """Return historical compliance score snapshots for a framework."""
    _validate_framework(framework)
    return _get_engine().get_score_trend(framework, limit=limit)


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@router.get("/{framework}/report", dependencies=[Depends(api_key_auth)])
def generate_report(
    framework: str,
    org_id: Optional[str] = Query(None),
):
    """Generate an audit-ready compliance report for a framework."""
    _validate_framework(framework)
    try:
        report = _get_engine().generate_report(framework=framework, org_id=org_id)
        return report.model_dump()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
