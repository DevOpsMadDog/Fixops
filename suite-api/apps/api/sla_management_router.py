"""
SLA Management Router for ALDECI — Advanced Vulnerability Remediation SLA Tracking.

Endpoints (8 under /api/v1/sla-management):
  POST /policies                    — create/update SLA policy (org/team/tier scoped)
  GET  /policies                    — list all policies for org
  POST /assign                      — assign SLA to a finding
  GET  /status/{finding_id}         — get current SLA status (with breach detection)
  POST /exceptions                  — request an SLA exception
  PATCH /exceptions/{id}/approve    — approve an exception
  GET  /teams/leaderboard           — per-team performance leaderboard
  GET  /report                      — full SLA compliance report (JSON export)

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, PCI-DSS Req 6.3
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.sla_management import (
    EscalationRule,
    ExceptionStatus,
    ExceptionType,
    SLAAssignment,
    SLAException,
    SLAManagement,
    SLAPolicyV2,
    SLAReport,
    TeamMetrics,
)
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla-management", tags=["SLA Management"])

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> SLAManagement:
    global _engine
    if _engine is None:
        _engine = SLAManagement()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreatePolicyRequest(BaseModel):
    """Request to create or update a scoped SLA policy."""

    name: str = Field(..., min_length=1, description="Human-readable policy name")
    team_id: Optional[str] = Field(None, description="Scope to a specific team")
    asset_tier: Optional[str] = Field(
        None,
        description="Scope to asset tier: tier1–tier5",
    )
    severity_deadlines: Dict[str, int] = Field(
        default_factory=lambda: {
            "critical": 24,
            "high": 168,
            "medium": 720,
            "low": 2160,
        },
        description="SLA deadline in hours per severity level",
    )
    framework_overrides: Dict[str, Dict[str, int]] = Field(
        default_factory=dict,
        description="Per-framework deadline overrides (pci-dss, hipaa, soc2, etc.)",
    )
    business_hours_only: bool = Field(
        False,
        description="Count only business hours (Mon–Fri 09:00–17:00) against SLA",
    )
    tz_name: str = Field("UTC", description="Timezone for business hours calculation")
    escalation_rules: List[EscalationRule] = Field(
        default_factory=list,
        description="Escalation contacts per severity",
    )
    enabled: bool = True


class AssignSLARequest(BaseModel):
    """Request to assign an SLA to a finding."""

    finding_id: str = Field(..., min_length=1)
    severity: str = Field(..., description="critical | high | medium | low")
    discovered_at: Optional[datetime] = Field(
        None, description="Discovery timestamp (UTC); defaults to now"
    )
    team_id: Optional[str] = None
    asset_tier: str = Field("tier3", description="tier1–tier5")
    frameworks: List[str] = Field(
        default_factory=list,
        description="Active compliance frameworks (e.g. pci-dss, hipaa)",
    )


class ExceptionRequest(BaseModel):
    """Request to submit an SLA exception."""

    finding_id: str = Field(..., min_length=1)
    exception_type: ExceptionType
    justification: str = Field(..., min_length=10)
    requested_by: str = Field(..., min_length=1)
    expiry_date: Optional[datetime] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    new_deadline: Optional[datetime] = Field(
        None, description="Required for extended_deadline exceptions"
    )


class ApproveExceptionRequest(BaseModel):
    """Approve or supply approver info for an exception."""

    approved_by: str = Field(..., min_length=1)


class SLAStatusResponse(BaseModel):
    """SLA status response for a single finding."""

    finding_id: str
    status: str
    severity: str
    asset_tier: str
    deadline: str
    discovered_at: str
    pct_elapsed: float
    escalation_level: str
    breached_at: Optional[str]
    resolved_at: Optional[str]
    frameworks: List[str]
    business_hours: bool


# ---------------------------------------------------------------------------
# 1. Policy management
# ---------------------------------------------------------------------------


@router.post(
    "/policies",
    response_model=SLAPolicyV2,
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a scoped SLA policy",
)
async def create_policy(
    payload: CreatePolicyRequest,
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAPolicyV2:
    """Create or replace an SLA policy scoped to org / team / asset-tier.

    - If no team_id/asset_tier: org-wide default policy.
    - If team_id given: applies only to that team.
    - If asset_tier given: applies only to that tier.
    - Most-specific scope wins at assignment time.
    """
    policy = SLAPolicyV2(
        org_id=org_id,
        team_id=payload.team_id,
        asset_tier=payload.asset_tier,
        name=payload.name,
        severity_deadlines=payload.severity_deadlines,
        framework_overrides=payload.framework_overrides,
        business_hours_only=payload.business_hours_only,
        tz_name=payload.tz_name,
        escalation_rules=payload.escalation_rules,
        enabled=payload.enabled,
    )
    try:
        return engine.create_policy(policy)
    except Exception as exc:
        logger.error("sla_management_router: create_policy failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/policies",
    response_model=List[SLAPolicyV2],
    summary="List all SLA policies for the org",
)
async def list_policies(
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> List[SLAPolicyV2]:
    """Return all SLA policies configured for the current org."""
    return engine.list_policies(org_id)


# ---------------------------------------------------------------------------
# 2. SLA Assignment
# ---------------------------------------------------------------------------


@router.post(
    "/assign",
    response_model=SLAAssignment,
    status_code=status.HTTP_201_CREATED,
    summary="Auto-assign SLA to a finding",
)
async def assign_sla(
    payload: AssignSLARequest,
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAAssignment:
    """Assign an SLA deadline to a finding.

    Deadline is computed from:
    1. Applicable SLA policy (org → team → tier scope)
    2. Active compliance frameworks (strictest wins)
    3. Asset tier multiplier (tier1 = 0.5x, tier5 = 2x)
    4. Business-hours-only mode (if policy enables it)
    """
    disc = payload.discovered_at or datetime.now(timezone.utc)
    try:
        return engine.assign_sla(
            finding_id=payload.finding_id,
            severity=payload.severity,
            discovered_at=disc,
            org_id=org_id,
            team_id=payload.team_id,
            asset_tier=payload.asset_tier,
            frameworks=payload.frameworks,
        )
    except Exception as exc:
        logger.error("sla_management_router: assign_sla failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# 3. Breach Detection — status check
# ---------------------------------------------------------------------------


@router.get(
    "/status/{finding_id}",
    response_model=SLAStatusResponse,
    summary="Get real-time SLA status for a finding",
)
async def get_status(
    finding_id: str,
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAStatusResponse:
    """Compute and return current SLA status.

    Status values:
    - ``within_sla``       — deadline not yet reached
    - ``approaching``      — ≥80% of time elapsed
    - ``breached``         — deadline passed
    - ``severely_breached`` — 2× deadline elapsed
    - ``resolved``         — finding was remediated
    - ``exempt``           — exception approved / risk accepted
    """
    try:
        assignment = engine.check_and_update_status(finding_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return SLAStatusResponse(
        finding_id=assignment.finding_id,
        status=assignment.status if isinstance(assignment.status, str)
        else assignment.status.value,
        severity=assignment.severity,
        asset_tier=assignment.asset_tier,
        deadline=assignment.deadline.isoformat(),
        discovered_at=assignment.discovered_at.isoformat(),
        pct_elapsed=round(assignment.pct_elapsed, 4),
        escalation_level=assignment.escalation_level
        if isinstance(assignment.escalation_level, str)
        else assignment.escalation_level.value,
        breached_at=assignment.breached_at.isoformat() if assignment.breached_at else None,
        resolved_at=assignment.resolved_at.isoformat() if assignment.resolved_at else None,
        frameworks=assignment.frameworks,
        business_hours=assignment.business_hours,
    )


# ---------------------------------------------------------------------------
# 4. Exception Management
# ---------------------------------------------------------------------------


@router.post(
    "/exceptions",
    response_model=SLAException,
    status_code=status.HTTP_201_CREATED,
    summary="Request an SLA exception",
)
async def request_exception(
    payload: ExceptionRequest,
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAException:
    """Submit an SLA exception request.

    Types:
    - ``risk_acceptance``      — accept the risk with justification + expiry
    - ``extended_deadline``    — request more time (supply new_deadline)
    - ``false_positive``       — mark finding as false positive (with evidence)
    - ``compensating_control`` — document a compensating control
    """
    if (
        payload.exception_type == ExceptionType.EXTENDED_DEADLINE
        and payload.new_deadline is None
    ):
        raise HTTPException(
            status_code=422,
            detail="new_deadline is required for extended_deadline exceptions",
        )
    try:
        return engine.request_exception(
            finding_id=payload.finding_id,
            org_id=org_id,
            exception_type=payload.exception_type,
            justification=payload.justification,
            requested_by=payload.requested_by,
            expiry_date=payload.expiry_date,
            evidence=payload.evidence,
            new_deadline=payload.new_deadline,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.patch(
    "/exceptions/{exception_id}/approve",
    response_model=SLAException,
    summary="Approve an SLA exception",
)
async def approve_exception(
    exception_id: str,
    payload: ApproveExceptionRequest,
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAException:
    """Approve a pending SLA exception.

    Effect depends on type:
    - ``false_positive`` / ``risk_acceptance`` → finding marked exempt
    - ``extended_deadline`` → finding deadline extended to new_deadline
    """
    try:
        return engine.approve_exception(exception_id, approved_by=payload.approved_by)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get(
    "/exceptions",
    response_model=List[SLAException],
    summary="List SLA exceptions for the org",
)
async def list_exceptions(
    status_filter: Optional[str] = Query(None, alias="status"),
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> List[SLAException]:
    """List all exception requests for the org, optionally filtered by status."""
    exc_status: Optional[ExceptionStatus] = None
    if status_filter:
        try:
            exc_status = ExceptionStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status '{status_filter}'. Must be one of: "
                f"{[s.value for s in ExceptionStatus]}",
            )
    return engine.list_exceptions(org_id, status=exc_status)


# ---------------------------------------------------------------------------
# 5. Team Performance — leaderboard
# ---------------------------------------------------------------------------


@router.get(
    "/teams/leaderboard",
    response_model=List[Dict[str, Any]],
    summary="Per-team SLA performance leaderboard",
)
async def get_leaderboard(
    period_days: int = Query(30, ge=1, le=365, description="Reporting period in days"),
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """Return teams ranked by SLA compliance rate (highest first).

    Each entry includes: rank, team_id, compliance_rate, total_assigned,
    breached, avg_resolution_hours, trend (improving/stable/degrading).
    """
    return engine.get_team_leaderboard(org_id, period_days=period_days)


@router.get(
    "/teams/{team_id}/metrics",
    response_model=TeamMetrics,
    summary="Per-team SLA metrics for a specific team",
)
async def get_team_metrics(
    team_id: str,
    period_days: int = Query(30, ge=1, le=365),
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> TeamMetrics:
    """Compute SLA metrics for a specific team over a time period."""
    return engine.compute_team_metrics(org_id, team_id=team_id, period_days=period_days)


# ---------------------------------------------------------------------------
# 6. Escalation check
# ---------------------------------------------------------------------------


@router.post(
    "/escalate",
    response_model=Dict[str, Any],
    summary="Run escalation check for all open SLA assignments",
)
async def run_escalation(
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> Dict[str, Any]:
    """Scan all open assignments and fire escalation notifications:

    - ≥80% elapsed → team lead
    - ≥100% elapsed (breached) → director
    - ≥200% elapsed (severely breached) → CISO

    Returns count of escalations fired per level.
    """
    summary = engine.run_escalation_check(org_id)
    return {"org_id": org_id, "escalations": summary}


# ---------------------------------------------------------------------------
# 7. Reporting
# ---------------------------------------------------------------------------


@router.get(
    "/report",
    response_model=SLAReport,
    summary="Full SLA compliance report (JSON export)",
)
async def get_report(
    period_days: int = Query(30, ge=1, le=365, description="Reporting period in days"),
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> SLAReport:
    """Generate a full SLA compliance report.

    Includes breakdowns by:
    - Severity (critical / high / medium / low)
    - Team (with compliance rate)
    - Compliance framework (pci-dss, hipaa, soc2, etc.)
    - Asset tier (tier1–tier5)
    - Escalation summary
    - Exception summary
    - Team leaderboard
    """
    return engine.generate_report(org_id, period_days=period_days)


# ---------------------------------------------------------------------------
# 8. Bulk operations
# ---------------------------------------------------------------------------


@router.post(
    "/assign/bulk",
    response_model=Dict[str, Any],
    summary="Bulk-assign SLAs to multiple findings",
)
async def bulk_assign(
    findings: List[AssignSLARequest],
    org_id: str = Depends(get_org_id),
    engine: SLAManagement = Depends(_get_engine),
) -> Dict[str, Any]:
    """Assign SLAs to multiple findings in a single call.

    Returns count of newly assigned findings (skips already-tracked).
    """
    assigned = 0
    skipped = 0
    errors: List[str] = []

    for f in findings:
        disc = f.discovered_at or datetime.now(timezone.utc)
        try:
            existing = engine.get_assignment(f.finding_id)
            if existing is not None:
                skipped += 1
                continue
            engine.assign_sla(
                finding_id=f.finding_id,
                severity=f.severity,
                discovered_at=disc,
                org_id=org_id,
                team_id=f.team_id,
                asset_tier=f.asset_tier,
                frameworks=f.frameworks,
            )
            assigned += 1
        except Exception as exc:
            errors.append(f"{f.finding_id}: {exc}")

    return {
        "org_id": org_id,
        "assigned": assigned,
        "skipped": skipped,
        "errors": errors,
    }


__all__ = ["router"]
