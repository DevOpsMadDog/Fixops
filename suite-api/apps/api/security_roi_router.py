"""
Security Investment ROI REST API — ALDECI ASPM Platform.

Endpoints:
    POST /api/v1/security-roi/investments            - Record a security investment
    GET  /api/v1/security-roi/investments            - List investments for org
    GET  /api/v1/security-roi/investments/{id}/roi   - Compute ROI for investment
    GET  /api/v1/security-roi/portfolio              - Portfolio ROI across all investments
    GET  /api/v1/security-roi/breach-estimate        - IBM breach cost model estimate
    GET  /api/v1/security-roi/risk-reduction         - Risk reduction from investments
    GET  /api/v1/security-roi/recommendations        - Where to invest next
    GET  /api/v1/security-roi/budget                 - Budget utilization
    GET  /api/v1/security-roi/trend                  - ROI over time
    GET  /api/v1/security-roi/health                 - Service health check

Compliance: SOC2 CC9.1 (Risk Mitigation), CC3.2 (Risk Assessment)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/security-roi", tags=["Security ROI"])


# ---------------------------------------------------------------------------
# Lazy engine accessor
# ---------------------------------------------------------------------------


def _get_engine():
    """Return the SecurityROI singleton."""
    from core.security_roi import get_security_roi

    db_path = os.environ.get("SECURITY_ROI_DB", "security_roi.db")
    return get_security_roi(db_path=db_path)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddInvestmentRequest(BaseModel):
    """Request body for adding a security investment."""

    name: str = Field(..., min_length=1, description="Investment name")
    category: str = Field(
        ...,
        description="Category: TOOLS | PERSONNEL | TRAINING | CONSULTING | INSURANCE | INFRASTRUCTURE",
    )
    amount_usd: float = Field(0.0, ge=0.0, description="One-time or initial cost (USD)")
    annual_cost: float = Field(0.0, ge=0.0, description="Recurring annual cost (USD)")
    start_date: Optional[str] = Field(None, description="Start date YYYY-MM-DD")
    description: str = Field("", description="Investment description")
    investment_id: Optional[str] = Field(None, description="Optional explicit ID")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/investments", summary="Record a security investment")
def add_investment(
    body: AddInvestmentRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Record a new security investment for the organization.

    The investment is immediately persisted and available for ROI computation.
    """
    try:
        from core.security_roi import Investment, InvestmentCategory

        category = InvestmentCategory(body.category.upper())

        inv = Investment(
            name=body.name,
            category=category,
            amount_usd=body.amount_usd,
            annual_cost=body.annual_cost,
            description=body.description,
            org_id=org_id,
        )
        if body.investment_id:
            inv.id = body.investment_id
        if body.start_date:
            inv.start_date = body.start_date

        engine = _get_engine()
        stored = engine.add_investment(inv)

        return {
            "status": "created",
            "investment": stored.model_dump(),
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to add investment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/investments", summary="List investments for org")
def list_investments(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List all recorded investments for the organization."""
    try:
        import os

        os.environ.get("SECURITY_ROI_DB", "security_roi.db")
        engine = _get_engine()

        with engine._lock:
            conn = engine._connect()
            try:
                rows = conn.execute(
                    "SELECT id, name, category, amount_usd, annual_cost, start_date, description "
                    "FROM investments WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            finally:
                engine._close(conn)

        investments = [
            {
                "id": r[0],
                "name": r[1],
                "category": r[2],
                "amount_usd": r[3],
                "annual_cost": r[4],
                "start_date": r[5],
                "description": r[6],
                "org_id": org_id,
            }
            for r in rows
        ]

        return {
            "org_id": org_id,
            "count": len(investments),
            "investments": investments,
        }
    except Exception as exc:
        logger.exception("Failed to list investments")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/investments/{investment_id}/roi", summary="Compute ROI for investment")
def get_investment_roi(
    investment_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compute ROI metrics for a specific investment using Ponemon benchmarks.

    Returns risk reduction %, incidents prevented, cost avoidance, and ROI ratio.
    """
    try:
        engine = _get_engine()
        metric = engine.calculate_roi(investment_id)
        return {
            "status": "ok",
            "roi": metric.model_dump(),
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to compute ROI for %s", investment_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/portfolio", summary="Portfolio ROI across all investments")
def get_portfolio_roi(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Aggregate ROI across all investments for the organization.

    Returns total cost, cost avoidance, blended ROI, and per-investment breakdown
    sorted by ROI ratio descending.
    """
    try:
        engine = _get_engine()
        return engine.get_portfolio_roi(org_id)
    except Exception as exc:
        logger.exception("Failed to compute portfolio ROI for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/breach-estimate", summary="IBM breach cost model estimate")
def get_breach_estimate(
    org_size: str = Query("medium", description="small | medium | large | enterprise"),
    industry: str = Query("default", description="healthcare | financial | technology | etc."),
    records_at_risk: int = Query(17200, ge=1, description="Number of records at risk"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Estimate breach cost using the IBM Cost of a Data Breach 2023 model.

    Applies organization size and industry multipliers to the $4.45M baseline.
    """
    try:
        engine = _get_engine()
        return engine.get_cost_of_breach_estimate(
            org_id=org_id,
            org_size=org_size,
            industry=industry,
            records_at_risk=records_at_risk,
        )
    except Exception as exc:
        logger.exception("Failed to compute breach estimate for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/risk-reduction", summary="Risk reduction from investments")
def get_risk_reduction(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Calculate total risk reduction achieved by the org's security investments.

    Uses Ponemon category-weighted benchmarks. Overall reduction is capped at 85%
    (no security program eliminates all risk).
    """
    try:
        engine = _get_engine()
        return engine.get_risk_reduction(org_id)
    except Exception as exc:
        logger.exception("Failed to compute risk reduction for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/recommendations", summary="Where to invest next")
def get_investment_recommendations(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return prioritized investment recommendations based on coverage gaps.

    Identifies under-funded categories relative to Ponemon importance weights
    and scores by gap × ROI potential.
    """
    try:
        engine = _get_engine()
        return engine.get_investment_recommendations(org_id)
    except Exception as exc:
        logger.exception("Failed to compute recommendations for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/budget", summary="Budget utilization")
def get_budget_utilization(
    annual_budget_usd: float = Query(0.0, ge=0.0, description="Total annual security budget (0=unset)"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Compute spending vs budget and category allocation breakdown.

    Pass annual_budget_usd=0 to get spend-only summary without utilization %.
    """
    try:
        engine = _get_engine()
        return engine.get_budget_utilization(org_id, annual_budget_usd=annual_budget_usd)
    except Exception as exc:
        logger.exception("Failed to compute budget utilization for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/trend", summary="ROI over time")
def get_roi_trend(
    months: int = Query(12, ge=1, le=60, description="Months of history to return"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """
    Return monthly ROI trend data for the last N months.

    Aggregates roi_ratio, cost_avoidance, incidents_prevented by calendar month.
    """
    try:
        engine = _get_engine()
        return engine.get_roi_trend(org_id, months=months)
    except Exception as exc:
        logger.exception("Failed to compute ROI trend for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/health", summary="Service health check")
def health_check() -> Dict[str, Any]:
    """Return service health status."""
    try:
        engine = _get_engine()
        # Minimal smoke-test: can we connect?
        with engine._lock:
            conn = engine._connect()
            try:
                conn.execute("SELECT 1").fetchone()
            finally:
                engine._close(conn)
        return {"status": "ok", "service": "security-roi"}
    except Exception as exc:
        logger.exception("Health check failed")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
