"""Security Budget Router — ALDECI.

Budget allocation, spend transaction, and ROI assessment endpoints.

Prefix: /api/v1/security-budget
Auth: api_key_auth dependency

Routes:
  POST /api/v1/security-budget/allocations               create_allocation
  GET  /api/v1/security-budget/allocations               list_allocations
  GET  /api/v1/security-budget/allocations/{id}          get_allocation
  POST /api/v1/security-budget/transactions              record_spend
  PUT  /api/v1/security-budget/transactions/{id}/approve approve_spend
  GET  /api/v1/security-budget/transactions              list_transactions
  POST /api/v1/security-budget/roi-assessments           record_roi_assessment
  GET  /api/v1/security-budget/roi-assessments           list_roi_assessments
  GET  /api/v1/security-budget/stats                     get_budget_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-budget",
    tags=["Security Budget"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_budget_engine import SecurityBudgetEngine
        _engine = SecurityBudgetEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateAllocationRequest(BaseModel):
    fiscal_year: int = Field(..., description="Fiscal year (positive integer)")
    category: str = Field(
        ...,
        description="tools|personnel|training|consulting|infrastructure|compliance|incident_response",
    )
    allocated_amount: float = Field(..., gt=0, description="Budget amount in currency")
    currency: str = Field(default="USD", description="Currency code")
    notes: str = Field(default="", description="Optional notes")


class RecordSpendRequest(BaseModel):
    allocation_id: str = Field(..., description="ID of the budget allocation")
    vendor_name: str = Field(..., description="Vendor or payee name")
    description: str = Field(default="", description="Spend description")
    amount: float = Field(..., gt=0, description="Transaction amount")
    transaction_date: Optional[str] = Field(
        default=None, description="ISO date of transaction"
    )


class ApproveSpendRequest(BaseModel):
    approver: str = Field(..., description="Approver username or ID")


class RecordROIRequest(BaseModel):
    category: str = Field(default="", description="Budget category")
    initiative_name: str = Field(..., description="Name of the security initiative")
    investment_amount: float = Field(..., gt=0, description="Total investment amount")
    estimated_risk_reduction: float = Field(
        ..., ge=0, le=100, description="Estimated risk reduction % (0-100)"
    )
    assessment_date: Optional[str] = Field(
        default=None, description="ISO assessment date"
    )
    notes: str = Field(default="", description="Optional notes")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/allocations", dependencies=[Depends(api_key_auth)], status_code=201)
def create_allocation(
    body: CreateAllocationRequest,
    org_id: str = Query(default="default"),
):
    """Create a new budget allocation."""
    try:
        return _get_engine().create_allocation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error creating allocation")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/allocations", dependencies=[Depends(api_key_auth)])
def list_allocations(
    org_id: str = Query(default="default"),
    fiscal_year: Optional[int] = Query(default=None),
    category: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List budget allocations (canonical envelope, batch-6).

    Class-c contract: empty IS correct for fresh tenants — security budget is
    a manual finance/CFO entry, not auto-derivable from any public source.
    Always returns full envelope with pagination context + filters echo +
    actionable hint when empty.
    """
    rows = _get_engine().list_allocations(
        org_id, fiscal_year=fiscal_year, category=category
    ) or []
    paged = rows[offset : offset + limit] if offset else rows[:limit]
    envelope = {
        "items": paged,
        "allocations": paged,  # legacy key preserved
        "total": len(rows),
        "org_id": org_id,
        "limit": limit,
        "offset": offset,
        "filters_applied": {
            "fiscal_year": fiscal_year,
            "category": category,
        },
    }
    if not rows:
        envelope["hint"] = (
            "Create a budget allocation via POST /api/v1/security-budget/allocations "
            "(manual finance entry). No public source exists for this — empty IS "
            "the correct response for a fresh tenant."
        )
    return envelope


@router.get("/allocations/{allocation_id}", dependencies=[Depends(api_key_auth)])
def get_allocation(
    allocation_id: str,
    org_id: str = Query(default="default"),
):
    """Get a specific budget allocation."""
    result = _get_engine().get_allocation(org_id, allocation_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Allocation not found")
    return result


@router.post("/transactions", dependencies=[Depends(api_key_auth)], status_code=201)
def record_spend(
    body: RecordSpendRequest,
    org_id: str = Query(default="default"),
):
    """Record a spend transaction against an allocation."""
    try:
        data = body.model_dump()
        allocation_id = data.pop("allocation_id")
        return _get_engine().record_spend(org_id, allocation_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording spend")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put(
    "/transactions/{transaction_id}/approve",
    dependencies=[Depends(api_key_auth)],
)
def approve_spend(
    transaction_id: str,
    body: ApproveSpendRequest,
    org_id: str = Query(default="default"),
):
    """Approve a spend transaction."""
    try:
        return _get_engine().approve_spend(org_id, transaction_id, body.approver)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error approving spend")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/transactions", dependencies=[Depends(api_key_auth)])
def list_transactions(
    org_id: str = Query(default="default"),
    allocation_id: Optional[str] = Query(default=None),
    approval_status: Optional[str] = Query(default=None),
):
    """List spend transactions with optional filters."""
    return _get_engine().list_transactions(
        org_id, allocation_id=allocation_id, approval_status=approval_status
    )


@router.post(
    "/roi-assessments", dependencies=[Depends(api_key_auth)], status_code=201
)
def record_roi_assessment(
    body: RecordROIRequest,
    org_id: str = Query(default="default"),
):
    """Record an ROI assessment for a security initiative."""
    try:
        return _get_engine().record_roi_assessment(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error recording ROI assessment")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/roi-assessments", dependencies=[Depends(api_key_auth)])
def list_roi_assessments(
    org_id: str = Query(default="default"),
):
    """List all ROI assessments."""
    return _get_engine().list_roi_assessments(org_id)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_budget_stats(
    org_id: str = Query(default="default"),
    fiscal_year: Optional[int] = Query(default=None),
):
    """Get budget statistics: totals, by_category, utilization, pending count."""
    return _get_engine().get_budget_stats(org_id, fiscal_year=fiscal_year)
