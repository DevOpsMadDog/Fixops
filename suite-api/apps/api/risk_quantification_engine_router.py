"""Risk Quantification Engine v2 Router — ALDECI.

FAIR methodology: SLE, ARO, ALE calculations with control ROI.

Prefix: /api/v1/risk-quant
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
    prefix="/api/v1/risk-quant",
    tags=["Risk Quantification v2"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.risk_quantification_engine_v2 import RiskQuantificationEngineV2
            _engine = RiskQuantificationEngineV2()
        except Exception as exc:
            _logger.error("Failed to init RiskQuantificationEngineV2: %s", exc)
            raise HTTPException(status_code=503, detail="Risk quantification engine unavailable")
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScenarioCreate(BaseModel):
    scenario_name: str = Field(..., description="Scenario name")
    asset_name: str = Field(..., description="Asset under threat")
    threat_actor: str = Field(..., description="Threat actor description")
    threat_type: str = Field("malware", description="malware/ransomware/insider/ddos/phishing/supply_chain/physical/natural_disaster/system_failure")
    asset_value: float = Field(0.0, ge=0.0, description="Asset value in $")
    exposure_factor: float = Field(0.5, ge=0.0, le=1.0, description="Exposure factor 0.0-1.0")
    annual_rate_occurrence: float = Field(1.0, ge=0.0, description="Expected occurrences per year")


class ControlCreate(BaseModel):
    control_name: str = Field(..., description="Control name")
    control_type: str = Field("preventive", description="preventive/detective/corrective/deterrent/recovery")
    implementation_cost: float = Field(0.0, ge=0.0, description="One-time implementation cost $")
    annual_cost: float = Field(0.0, ge=0.0, description="Annual recurring cost $")
    effectiveness_pct: float = Field(0.0, ge=0.0, le=100.0, description="Effectiveness percentage 0-100")


class RatesUpdate(BaseModel):
    asset_value: Optional[float] = Field(None, ge=0.0)
    exposure_factor: Optional[float] = Field(None, ge=0.0, le=1.0)
    annual_rate_occurrence: Optional[float] = Field(None, ge=0.0)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scenarios", status_code=201)
def create_scenario(
    payload: ScenarioCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Create a FAIR risk scenario with computed SLE and ALE."""
    try:
        return _get_engine().create_scenario(
            org_id=org_id,
            scenario_name=payload.scenario_name,
            asset_name=payload.asset_name,
            threat_actor=payload.threat_actor,
            threat_type=payload.threat_type,
            asset_value=payload.asset_value,
            exposure_factor=payload.exposure_factor,
            annual_rate_occurrence=payload.annual_rate_occurrence,
        )
    except Exception as exc:
        _logger.exception("Error creating scenario")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/scenarios/{scenario_id}/controls", status_code=201)
def add_control(
    scenario_id: str,
    payload: ControlCreate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Add a control to a scenario with ROI computation."""
    try:
        return _get_engine().add_control(
            scenario_id=scenario_id,
            org_id=org_id,
            control_name=payload.control_name,
            control_type=payload.control_type,
            implementation_cost=payload.implementation_cost,
            annual_cost=payload.annual_cost,
            effectiveness_pct=payload.effectiveness_pct,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        _logger.exception("Error adding control")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/scenarios/{scenario_id}/rates")
def update_rates(
    scenario_id: str,
    payload: RatesUpdate,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Update scenario rate fields and recompute FAIR metrics."""
    result = _get_engine().update_rates(
        scenario_id=scenario_id,
        org_id=org_id,
        asset_value=payload.asset_value,
        exposure_factor=payload.exposure_factor,
        annual_rate_occurrence=payload.annual_rate_occurrence,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


@router.post("/snapshots", status_code=201)
def take_snapshot(org_id: str = Query("default")) -> Dict[str, Any]:
    """Take a portfolio risk snapshot for the org."""
    return _get_engine().take_snapshot(org_id)


@router.get("/summary")
def get_portfolio_summary(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate portfolio summary."""
    return _get_engine().get_portfolio_summary(org_id)


@router.get("/scenarios/{scenario_id}")
def get_scenario_detail(
    scenario_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Return scenario with controls and recommended controls."""
    result = _get_engine().get_scenario_detail(scenario_id, org_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return result


@router.get("/history")
def get_snapshot_history(
    org_id: str = Query("default"),
    days: int = Query(90, ge=1, le=365),
) -> List[Dict[str, Any]]:
    """Return portfolio snapshot history."""
    return _get_engine().get_snapshot_history(org_id, days)


@router.get("/roi-analysis")
def get_roi_analysis(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """Return all positive-ROI controls ordered by ROI DESC."""
    return _get_engine().get_roi_analysis(org_id)
