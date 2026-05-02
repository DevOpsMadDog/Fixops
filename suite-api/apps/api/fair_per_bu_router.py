"""FAIR per-Business-Unit Router — ALDECI (GAP-028 + GAP-051).

Merges onto RiskQuantificationEngineV2:
  - FAIR per-BU ALE computation
  - ROI-of-fixes weekly trend

Prefix: /api/v1/fair
Auth: api_key_auth on ALL endpoints
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/fair",
    tags=["FAIR per-BU + ROI Trend"],
    dependencies=[Depends(api_key_auth)],
)


_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.risk_quantification_engine_v2 import RiskQuantificationEngineV2
            _engine = RiskQuantificationEngineV2()
        except Exception as exc:
            _logger.error("Failed to init RiskQuantificationEngineV2: %s", exc)
            raise HTTPException(status_code=503, detail="FAIR engine unavailable")
    return _engine


class PerBuRiskRequest(BaseModel):
    bu_id: str = Field(..., description="Business unit ID")
    findings: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Optional list of findings. If omitted, pulled from security_findings by BU tag.",
    )


class FixCostRequest(BaseModel):
    finding_id: str = Field(..., description="Finding ID being fixed")
    cost: float = Field(..., ge=0.0, description="Cost of the fix in $")
    fixed_at: str = Field(..., description="ISO datetime when fix was deployed")
    ale_reduced: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Optional explicit ALE reduction $. If omitted, inferred from severity.",
    )


@router.get("/business-units")
def list_business_units(org_id: str = Query("default")) -> Dict[str, Any]:
    """List business units for an org. Seeds 5 defaults on first call."""
    try:
        bus = _get_engine().business_units(org_id)
        return {"org_id": org_id, "business_units": bus, "count": len(bus)}
    except Exception as exc:
        _logger.exception("Error listing business units")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/per-bu-risk")
def compute_per_bu_risk(
    payload: PerBuRiskRequest,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Compute FAIR per-BU risk (SLE × ARO × probability)."""
    try:
        return _get_engine().compute_per_bu_risk(
            org_id=org_id,
            bu_id=payload.bu_id,
            findings=payload.findings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("Error computing per-BU risk")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/fix-cost", status_code=201)
def record_fix_cost(
    payload: FixCostRequest,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Record the cost and ALE reduction of a fix."""
    try:
        return _get_engine().record_fix_cost(
            org_id=org_id,
            finding_id=payload.finding_id,
            cost=payload.cost,
            fixed_at=payload.fixed_at,
            ale_reduced=payload.ale_reduced,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("Error recording fix cost")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/roi-trend")
def roi_trend(
    org_id: str = Query("default"),
    window_days: int = Query(90, ge=7, le=730),
) -> Dict[str, Any]:
    """Weekly cumulative ALE-reduced ÷ cumulative fix cost trend."""
    try:
        return _get_engine().roi_of_fixes_trend(org_id, window_days)
    except Exception as exc:
        _logger.exception("Error computing ROI trend")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats")
def stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Combined stats: BU count + latest ROI snapshot."""
    try:
        eng = _get_engine()
        bus = eng.business_units(org_id)
        trend = eng.roi_of_fixes_trend(org_id, 90)
        latest_cum_ale = trend["cumulative_ale_reduced"][-1] if trend["cumulative_ale_reduced"] else 0.0
        latest_cum_cost = trend["cumulative_cost"][-1] if trend["cumulative_cost"] else 0.0
        latest_roi = trend["roi_trend"][-1] if trend["roi_trend"] else 0.0
        return {
            "org_id": org_id,
            "business_unit_count": len(bus),
            "cumulative_ale_reduced_90d": latest_cum_ale,
            "cumulative_fix_cost_90d": latest_cum_cost,
            "roi_pct_90d": latest_roi,
            "weekly_points": len(trend["weeks"]),
        }
    except Exception as exc:
        _logger.exception("Error computing FAIR stats")
        raise HTTPException(status_code=500, detail=str(exc))
