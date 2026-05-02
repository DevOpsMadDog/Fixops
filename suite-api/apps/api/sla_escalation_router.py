"""
SLA Escalation Router — Auto-escalation for breached SLA findings.

Endpoints:
  GET  /api/v1/sla-escalation/check    — run breach check, return findings list
  POST /api/v1/sla-escalation/cycle    — run full escalation cycle for org
  GET  /api/v1/sla-escalation/history  — escalation history (query param: finding_id)
  PUT  /api/v1/sla-escalation/policy   — set escalation policy
  GET  /api/v1/sla-escalation/policy   — get current policy

Compliance: SOC2 CC7.2, ISO27001 A.12.6.1, NIST SP 800-137
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.sla_escalation_engine import EscalationAction, SLAEscalationEngine
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sla-escalation",
    tags=["SLA Escalation"],
    dependencies=[Depends(api_key_auth)],
)

# Module-level singleton
_engine = None  # lazy-initialised on first request


def _get_engine() -> SLAEscalationEngine:
    global _engine
    if _engine is None:
        _engine = SLAEscalationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class EscalationPolicyRequest(BaseModel):
    breach_threshold_hours: int = Field(
        default=24,
        ge=1,
        description="Hours past SLA deadline before auto-escalation fires",
    )
    auto_action: str = Field(
        default=EscalationAction.NOTIFY,
        description="Default escalation action",
    )
    severity_bump: bool = Field(
        default=False,
        description="Whether to bump severity on escalation",
    )


class EscalationPolicyResponse(BaseModel):
    org_id: str
    breach_threshold_hours: int
    auto_action: str
    severity_bump: bool
    updated_at: Optional[str] = None


class BreachItem(BaseModel):
    finding_id: str
    severity: str
    deadline: str
    hours_past_deadline: float
    recommended_actions: List[str]


class CycleSummary(BaseModel):
    breaches_found: int
    escalations_triggered: int
    actions: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/check",
    response_model=List[BreachItem],
    summary="Check for SLA breaches",
    description="Scan all tracked findings for SLA deadline breaches. Returns list of breached findings.",
)
async def check_breaches(
    org_id: str = Query(default="default", description="Organisation ID"),
    engine: SLAEscalationEngine = Depends(_get_engine),
) -> List[BreachItem]:
    try:
        breaches = engine.check_sla_breaches(org_id=org_id)
        return [BreachItem(**b) for b in breaches]
    except Exception as exc:
        logger.error("check_breaches_error", exc_info=exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/cycle",
    response_model=CycleSummary,
    summary="Run full escalation cycle",
    description="Check all SLA breaches and auto-escalate per configured policy.",
)
async def run_cycle(
    org_id: str = Query(default="default", description="Organisation ID"),
    engine: SLAEscalationEngine = Depends(_get_engine),
) -> CycleSummary:
    try:
        summary = engine.run_escalation_cycle(org_id=org_id)
        return CycleSummary(**summary)
    except Exception as exc:
        logger.error("run_cycle_error", exc_info=exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/history",
    summary="Get escalation history",
    description="List escalation events. Pass `finding_id` query param to filter.",
)
async def get_history(
    finding_id: Optional[str] = Query(default=None, description="Filter by finding ID"),
    org_id: str = Query(default="default", description="Organisation ID"),
    engine: SLAEscalationEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    try:
        return engine.get_escalation_history(finding_id=finding_id, org_id=org_id)
    except Exception as exc:
        logger.error("get_history_error", exc_info=exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.put(
    "/policy",
    response_model=EscalationPolicyResponse,
    summary="Set escalation policy",
    description="Configure escalation policy for an org.",
)
async def set_policy(
    payload: EscalationPolicyRequest,
    org_id: str = Query(default="default", description="Organisation ID"),
    engine: SLAEscalationEngine = Depends(_get_engine),
) -> EscalationPolicyResponse:
    try:
        stored = engine.set_escalation_policy(payload.model_dump(), org_id=org_id)
        return EscalationPolicyResponse(**stored)
    except Exception as exc:
        logger.error("set_policy_error", exc_info=exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/policy",
    response_model=EscalationPolicyResponse,
    summary="Get escalation policy",
    description="Return the current escalation policy for an org.",
)
async def get_policy(
    org_id: str = Query(default="default", description="Organisation ID"),
    engine: SLAEscalationEngine = Depends(_get_engine),
) -> EscalationPolicyResponse:
    try:
        policy = engine.get_escalation_policy(org_id=org_id)
        return EscalationPolicyResponse(**policy)
    except Exception as exc:
        logger.error("get_policy_error", exc_info=exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
