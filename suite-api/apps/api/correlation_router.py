"""
Correlation Router — Finding Correlation Engine API.

Exposes the FindingCorrelator to REST consumers for analyzing findings,
retrieving Exposure Cases, and tracking investigation status.

Endpoints:
  POST /api/v1/correlations/analyze                     -- correlate findings
  GET  /api/v1/correlations/exposure-cases              -- list cases
  GET  /api/v1/correlations/exposure-cases/{id}         -- case detail
  PUT  /api/v1/correlations/exposure-cases/{id}/status  -- update status
  GET  /api/v1/correlations/stats                       -- stats

Security: All endpoints require api_key_auth.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/correlations",
    tags=["correlations"],
    dependencies=[Depends(api_key_auth)],
)

# Lazy-import correlator to avoid hard dependency at import time
def _get_correlator():
    from core.finding_correlator import FindingCorrelator
    return FindingCorrelator()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    findings: List[Dict[str, Any]] = Field(
        ..., description="List of finding dicts to correlate"
    )
    org_id: str = Field(default="", description="Tenant / org identifier")
    build_cases: bool = Field(
        default=True, description="Also build and persist Exposure Cases"
    )


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., description="New status: open | investigating | resolved")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/analyze", summary="Run correlation on provided findings")
def analyze_findings(body: AnalyzeRequest) -> Dict[str, Any]:
    """Run all correlation strategies on the supplied findings list.

    Optionally also builds and persists Exposure Cases from the correlations.
    """
    correlator = _get_correlator()
    correlations = correlator.correlate_findings(body.findings)
    corr_dicts = [c.model_dump() for c in correlations]

    result: Dict[str, Any] = {
        "finding_count": len(body.findings),
        "correlation_count": len(correlations),
        "correlations": corr_dicts,
    }

    if body.build_cases:
        cases = correlator.build_exposure_cases(body.findings, org_id=body.org_id)
        result["case_count"] = len(cases)
        result["exposure_cases"] = [c.model_dump() for c in cases]
        logger.info(
            "analyze: org=%s findings=%d correlations=%d cases=%d",
            body.org_id,
            len(body.findings),
            len(correlations),
            len(cases),
        )

    return result


@router.get("/exposure-cases", summary="List Exposure Cases")
def list_exposure_cases(
    org_id: Optional[str] = Query(default=None, description="Filter by org"),
    status: Optional[str] = Query(
        default=None, description="Filter by status: open | investigating | resolved"
    ),
) -> Dict[str, Any]:
    """List persisted Exposure Cases with optional filters."""
    correlator = _get_correlator()
    cases = correlator.list_exposure_cases(org_id=org_id, status=status)
    return {
        "count": len(cases),
        "exposure_cases": [c.model_dump() for c in cases],
    }


@router.get("/exposure-cases/{case_id}", summary="Get Exposure Case detail")
def get_exposure_case(case_id: str) -> Dict[str, Any]:
    """Retrieve a single Exposure Case by ID."""
    correlator = _get_correlator()
    case = correlator.get_exposure_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail=f"Exposure case '{case_id}' not found")
    return case.model_dump()


@router.put(
    "/exposure-cases/{case_id}/status",
    summary="Update Exposure Case investigation status",
)
def update_case_status(case_id: str, body: StatusUpdateRequest) -> Dict[str, Any]:
    """Change the investigation status of an Exposure Case."""
    correlator = _get_correlator()
    try:
        updated = correlator.update_case_status(case_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not updated:
        raise HTTPException(status_code=404, detail=f"Exposure case '{case_id}' not found")

    return {"case_id": case_id, "status": body.status, "updated": True}


@router.get("/stats", summary="Correlation statistics")
def get_stats(
    org_id: Optional[str] = Query(default=None, description="Filter by org")
) -> Dict[str, Any]:
    """Return correlation statistics: reduction ratio, avg findings per case, etc."""
    correlator = _get_correlator()
    return correlator.get_correlation_stats(org_id=org_id)
