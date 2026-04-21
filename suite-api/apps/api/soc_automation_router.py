"""SOC Automation Engine API endpoints.

Provides 8 endpoints to manage automation rules and trigger SOC workflows:
- POST   /api/v1/soc-automation/rules          — create rule
- GET    /api/v1/soc-automation/rules           — list rules
- GET    /api/v1/soc-automation/rules/{rule_id} — get rule
- PUT    /api/v1/soc-automation/rules/{rule_id} — update rule
- DELETE /api/v1/soc-automation/rules/{rule_id} — delete rule
- POST   /api/v1/soc-automation/evaluate        — evaluate finding against rules
- GET    /api/v1/soc-automation/stats           — automation statistics
- POST   /api/v1/soc-automation/actions/{action} — run a single action on a finding
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

try:
    from core.soc_automation import (
        AutomationRule,
        AutomationStats,
        SOCAction,
        SOCAutomation,
    )

    _engine: Optional[SOCAutomation] = None

    def _get_engine() -> SOCAutomation:
        global _engine
        if _engine is None:
            _engine = SOCAutomation()
        return _engine

    _HAS_SOC = True
except ImportError as _exc:
    _logger.warning("soc_automation_router: soc_automation unavailable: %s", _exc)
    _HAS_SOC = False

router = APIRouter(prefix="/api/v1/soc-automation", tags=["soc-automation"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CreateRuleRequest(BaseModel):
    name: str
    trigger_condition: Dict[str, Any] = {}
    action: str
    config: Dict[str, Any] = {}
    enabled: bool = True
    org_id: str = "default"


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = None
    trigger_condition: Optional[Dict[str, Any]] = None
    action: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class EvaluateFindingRequest(BaseModel):
    finding: Dict[str, Any]
    org_id: str = "default"


class RunActionRequest(BaseModel):
    finding: Dict[str, Any]
    org_id: str = "default"


class RuleResponse(BaseModel):
    id: str
    name: str
    trigger_condition: Dict[str, Any]
    action: str
    config: Dict[str, Any]
    enabled: bool
    execution_count: int
    last_triggered: Optional[str]
    org_id: str


def _rule_to_response(rule: "AutomationRule") -> RuleResponse:
    return RuleResponse(
        id=rule.id,
        name=rule.name,
        trigger_condition=rule.trigger_condition,
        action=rule.action.value,
        config=rule.config,
        enabled=rule.enabled,
        execution_count=rule.execution_count,
        last_triggered=rule.last_triggered.isoformat() if rule.last_triggered else None,
        org_id=rule.org_id,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/rules", response_model=RuleResponse, status_code=201)
def create_rule(req: CreateRuleRequest) -> RuleResponse:
    """Create a new automation rule."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    try:
        action = SOCAction(req.action)
    except ValueError:
        valid = [a.value for a in SOCAction]
        raise HTTPException(status_code=422, detail=f"Invalid action '{req.action}'. Valid: {valid}")
    rule = AutomationRule(
        name=req.name,
        trigger_condition=req.trigger_condition,
        action=action,
        config=req.config,
        enabled=req.enabled,
        org_id=req.org_id,
    )
    created = _get_engine().create_rule(rule)
    return _rule_to_response(created)


@router.get("/rules", response_model=List[RuleResponse])
def list_rules(org_id: str = Query(default="default")) -> List[RuleResponse]:
    """List all automation rules for an org."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    rules = _get_engine().list_rules(org_id=org_id)
    return [_rule_to_response(r) for r in rules]


@router.get("/rules/{rule_id}", response_model=RuleResponse)
def get_rule(rule_id: str) -> RuleResponse:
    """Get a single automation rule by ID."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    rule = _get_engine().get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    return _rule_to_response(rule)


@router.put("/rules/{rule_id}", response_model=RuleResponse)
def update_rule(rule_id: str, req: UpdateRuleRequest) -> RuleResponse:
    """Update an existing automation rule."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    engine = _get_engine()
    rule = engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")
    if req.name is not None:
        rule.name = req.name
    if req.trigger_condition is not None:
        rule.trigger_condition = req.trigger_condition
    if req.action is not None:
        try:
            rule.action = SOCAction(req.action)
        except ValueError:
            valid = [a.value for a in SOCAction]
            raise HTTPException(status_code=422, detail=f"Invalid action '{req.action}'. Valid: {valid}")
    if req.config is not None:
        rule.config = req.config
    if req.enabled is not None:
        rule.enabled = req.enabled
    updated = engine.update_rule(rule)
    return _rule_to_response(updated)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str) -> None:
    """Delete an automation rule."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    deleted = _get_engine().delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.post("/evaluate")
def evaluate_finding(req: EvaluateFindingRequest) -> Dict[str, Any]:
    """Evaluate a finding against all enabled rules; execute matching ones."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    results = _get_engine().evaluate_finding(finding=req.finding, org_id=req.org_id)
    return {
        "finding_id": req.finding.get("id", "unknown"),
        "org_id": req.org_id,
        "rules_fired": len(results),
        "results": results,
    }


@router.get("/stats", response_model=AutomationStats)
def get_stats(org_id: str = Query(default="default")) -> AutomationStats:
    """Return automation statistics for the org."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    return _get_engine().get_automation_stats(org_id=org_id)


@router.post("/actions/{action}")
def run_action(action: str, req: RunActionRequest) -> Dict[str, Any]:
    """Run a single SOC action against a finding directly."""
    if not _HAS_SOC:
        raise HTTPException(status_code=503, detail="SOC automation engine not available")
    try:
        soc_action = SOCAction(action)
    except ValueError:
        valid = [a.value for a in SOCAction]
        raise HTTPException(status_code=422, detail=f"Invalid action '{action}'. Valid: {valid}")

    engine = _get_engine()
    finding = req.finding

    action_map = {
        SOCAction.AUTO_TRIAGE: lambda: engine.auto_triage(finding).model_dump(),
        SOCAction.AUTO_ENRICH: lambda: engine.auto_enrich(finding).model_dump(),
        SOCAction.AUTO_ESCALATE: lambda: engine.auto_escalate(finding).model_dump(),
        SOCAction.AUTO_CLOSE: lambda: engine.auto_close(finding),
        SOCAction.AUTO_ASSIGN: lambda: engine.auto_assign(finding, req.org_id).model_dump(),
        SOCAction.AUTO_INVESTIGATE: lambda: engine._auto_investigate(finding),
    }

    handler = action_map.get(soc_action)
    result = handler()
    return {"action": action, "finding_id": finding.get("id", "unknown"), "result": result}
