"""Security Investment Router — ALDECI.

Tracks security budget investments, ROI, and business value.

Prefix: /api/v1/security-investment
Auth: _verify_api_key

Routes:
  POST /investments                     create_investment
  POST /investments/{id}/outcomes       record_outcome
  POST /investments/{id}/activate       activate_investment
  POST /investments/{id}/complete       complete_investment
  POST /budgets                         set_budget
  POST /budgets/spend                   record_spend
  GET  /portfolio                       get_portfolio_summary
  GET  /budgets/{year}                  get_budget_utilization
  GET  /investments                     list_investments
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-investment",
    tags=["Security Investment"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_investment_engine import SecurityInvestmentEngine
        _engine = SecurityInvestmentEngine()
    return _engine


def _verify_api_key():
    """Stub auth dependency — real implementation in auth_deps."""
    try:
        from apps.api.auth_deps import api_key_auth
        return api_key_auth
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateInvestmentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    investment_name: str = Field(..., description="Name of the investment")
    investment_category: str = Field(
        ...,
        description="tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D",
    )
    vendor: str = Field(default="", description="Vendor or supplier name")
    amount: float = Field(default=0.0, ge=0, description="Investment amount")
    currency: str = Field(default="USD", description="USD|EUR|GBP|AUD|CAD")
    start_date: str = Field(default="", description="ISO start date")
    end_date: str = Field(default="", description="ISO end date")


class RecordOutcomeRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    outcome_type: str = Field(
        ...,
        description=(
            "cost-avoidance|incident-reduction|efficiency|"
            "compliance|risk-reduction|revenue-protection"
        ),
    )
    description: str = Field(default="", description="Outcome description")
    quantified_value: float = Field(default=0.0, description="Quantified monetary value")
    measurement_date: str = Field(default="", description="ISO measurement date")
    verified: bool = Field(default=False, description="Whether outcome is verified")


class OrgRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")


class SetBudgetRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    fiscal_year: str = Field(..., description="Fiscal year (e.g. '2025')")
    category: str = Field(
        ...,
        description="tools|personnel|training|compliance|infrastructure|consulting|insurance|R&D",
    )
    allocated: float = Field(..., ge=0, description="Allocated budget amount")
    currency: str = Field(default="USD", description="USD|EUR|GBP|AUD|CAD")


class RecordSpendRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    fiscal_year: str = Field(..., description="Fiscal year (e.g. '2025')")
    category: str = Field(..., description="Budget category")
    amount: float = Field(..., gt=0, description="Amount to record as spent")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/investments", summary="Create a security investment")
def create_investment(req: CreateInvestmentRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_investment(
            org_id=req.org_id,
            investment_name=req.investment_name,
            investment_category=req.investment_category,
            vendor=req.vendor,
            amount=req.amount,
            currency=req.currency,
            start_date=req.start_date,
            end_date=req.end_date,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/investments/{investment_id}/outcomes", summary="Record an investment outcome")
def record_outcome(investment_id: str, req: RecordOutcomeRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_outcome(
            investment_id=investment_id,
            org_id=req.org_id,
            outcome_type=req.outcome_type,
            description=req.description,
            quantified_value=req.quantified_value,
            measurement_date=req.measurement_date,
            verified=req.verified,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/investments/{investment_id}/activate", summary="Activate an investment")
def activate_investment(investment_id: str, req: OrgRequest) -> Dict[str, Any]:
    try:
        return _get_engine().activate_investment(
            investment_id=investment_id,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/investments/{investment_id}/complete", summary="Complete an investment")
def complete_investment(investment_id: str, req: OrgRequest) -> Dict[str, Any]:
    try:
        return _get_engine().complete_investment(
            investment_id=investment_id,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/budgets", summary="Set a budget allocation")
def set_budget(req: SetBudgetRequest) -> Dict[str, Any]:
    try:
        return _get_engine().set_budget(
            org_id=req.org_id,
            fiscal_year=req.fiscal_year,
            category=req.category,
            allocated=req.allocated,
            currency=req.currency,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/budgets/spend", summary="Record budget spend")
def record_spend(req: RecordSpendRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_spend(
            org_id=req.org_id,
            fiscal_year=req.fiscal_year,
            category=req.category,
            amount=req.amount,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/portfolio", summary="Get portfolio summary")
def get_portfolio_summary(org_id: str = Query(..., description="Organisation ID")) -> Dict[str, Any]:
    return _get_engine().get_portfolio_summary(org_id=org_id)


@router.get("/budgets/{fiscal_year}", summary="Get budget utilization for a fiscal year")
def get_budget_utilization(
    fiscal_year: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> List[Dict[str, Any]]:
    return _get_engine().get_budget_utilization(org_id=org_id, fiscal_year=fiscal_year)


@router.get("/investments", summary="List investments")
def list_investments(
    org_id: str = Query(..., description="Organisation ID"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    investment_category: Optional[str] = Query(default=None, description="Filter by category"),
) -> List[Dict[str, Any]]:
    return _get_engine().list_investments(
        org_id=org_id,
        status=status,
        investment_category=investment_category,
    )
