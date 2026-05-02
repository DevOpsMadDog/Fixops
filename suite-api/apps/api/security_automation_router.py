"""Security Automation Router — ALDECI.

Endpoints for the Security Automation engine.

Prefix: /api/v1/security-automation
Auth:   api_key_auth dependency

Routes:
  POST   /api/v1/security-automation/rules                      create_automation_rule
  GET    /api/v1/security-automation/rules                      list_automation_rules
  GET    /api/v1/security-automation/rules/{rule_id}            get_rule
  PATCH  /api/v1/security-automation/rules/{rule_id}/enable     enable_rule
  PATCH  /api/v1/security-automation/rules/{rule_id}/disable    disable_rule
  POST   /api/v1/security-automation/rules/{rule_id}/execute    execute_rule
  GET    /api/v1/security-automation/executions                 list_executions
  GET    /api/v1/security-automation/stats                      get_automation_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/security-automation",
    tags=["Security Automation"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_automation_engine import SecurityAutomationEngine
        _engine = SecurityAutomationEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RuleCreate(BaseModel):
    name: str
    trigger_type: str = "alert"
    trigger_condition: str = ""
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True


class ExecuteRuleRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

@router.post("/rules", dependencies=[Depends(api_key_auth)], status_code=201)
def create_automation_rule(body: RuleCreate, org_id: str = Query(default="default")):
    """Create a new automation rule for the org."""
    try:
        return _get_engine().create_automation_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_automation_rules(
     org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(None),
):
    """List automation rules, optionally filtered by enabled state."""
    return _get_engine().list_automation_rules(org_id, enabled=enabled)


@router.get("/rules/{rule_id}", dependencies=[Depends(api_key_auth)])
def get_rule(rule_id: str, org_id: str = Query(default="default")):
    """Get a single automation rule by ID."""
    rule = _get_engine().get_rule(org_id, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/rules/{rule_id}/enable", dependencies=[Depends(api_key_auth)])
def enable_rule(rule_id: str, org_id: str = Query(default="default")):
    """Enable an automation rule."""
    rule = _get_engine().enable_rule(org_id, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.patch("/rules/{rule_id}/disable", dependencies=[Depends(api_key_auth)])
def disable_rule(rule_id: str, org_id: str = Query(default="default")):
    """Disable an automation rule."""
    rule = _get_engine().disable_rule(org_id, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

@router.post("/rules/{rule_id}/execute", dependencies=[Depends(api_key_auth)], status_code=201)
def execute_rule(rule_id: str, body: ExecuteRuleRequest, org_id: str = Query(default="default")):
    """Execute an automation rule against a given context."""
    result = _get_engine().execute_rule(org_id, rule_id, body.context)
    if not result:
        raise HTTPException(status_code=404, detail="Rule not found")
    return result


@router.get("/executions", dependencies=[Depends(api_key_auth)])
def list_executions(
     org_id: str = Query(default="default"),
    rule_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List execution history for the org."""
    return _get_engine().list_executions(org_id, rule_id=rule_id, status=status, limit=limit)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_automation_stats(org_id: str = Query(default="default")):
    """Return aggregated automation statistics for the org."""
    return _get_engine().get_automation_stats(org_id)
