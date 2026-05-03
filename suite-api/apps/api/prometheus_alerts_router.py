"""
ALDECI Prometheus Alerts Capability Router.

Exposes the in-memory Prometheus alert rule catalog and a SAFE PromQL-subset
evaluator over REST.

Endpoints:
  GET  /api/v1/prometheus/                 — capability summary
  GET  /api/v1/prometheus/groups           — rule groups + counts
  GET  /api/v1/prometheus/rules            — full alert-rule catalog (group filter optional)
  GET  /api/v1/prometheus/rules/{rule_id}  — single rule detail
  POST /api/v1/prometheus/alerts/test      — evaluate a rule against sample metrics

Vision Pillars: V3 (Decision Intelligence), V8 (Observability)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/prometheus",
    tags=["prometheus-alerts"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test override via monkeypatch)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.prometheus_alerts_engine import get_prometheus_alerts_engine

    return get_prometheus_alerts_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    rule_groups: List[str]
    evaluation_engine: str
    status: str
    rule_count: int


class RuleDetail(BaseModel):
    rule_id: str
    group: str
    name: str
    expr: str
    for_duration: str
    severity: str
    summary: str
    runbook_url: str


class RulesListResponse(BaseModel):
    rules: List[RuleDetail]
    count: int


class GroupSummary(BaseModel):
    group: str
    rule_count: int


class GroupsResponse(BaseModel):
    groups: List[GroupSummary]
    count: int


class AlertTestRequest(BaseModel):
    rule_id: str = Field(..., description="rule_id from /rules catalog")
    sample_metrics: Dict[str, float] = Field(
        default_factory=dict,
        description="Mapping of metric_name -> numeric value used to evaluate expr",
    )


class AlertTestResponse(BaseModel):
    rule_id: str
    evaluation_result: str
    evaluated_expr: str
    sample_metrics: Dict[str, float]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
def capability_summary() -> CapabilityResponse:
    eng = _get_engine()
    rules = eng.list_rules()
    return CapabilityResponse(
        service="Prometheus",
        rule_groups=["security", "availability", "performance", "compliance"],
        evaluation_engine="PromQL-subset",
        status="ok" if rules else "empty",
        rule_count=len(rules),
    )


@router.get("/groups", response_model=GroupsResponse)
def list_groups() -> GroupsResponse:
    eng = _get_engine()
    groups = [GroupSummary(**g) for g in eng.list_groups()]
    return GroupsResponse(groups=groups, count=len(groups))


@router.get("/rules", response_model=RulesListResponse)
def list_rules(
    group: Optional[str] = Query(default=None, description="Optional group filter"),
) -> RulesListResponse:
    eng = _get_engine()
    if group is not None:
        from core.prometheus_alerts_engine import RULE_GROUPS

        if group not in RULE_GROUPS:
            raise HTTPException(status_code=400, detail=f"unknown group: {group}")
    rules = [RuleDetail(**r.to_dict()) for r in eng.list_rules(group=group)]
    return RulesListResponse(rules=rules, count=len(rules))


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str) -> RuleDetail:
    eng = _get_engine()
    rule = eng.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail=f"rule_id not found: {rule_id}")
    return RuleDetail(**rule.to_dict())


@router.post("/alerts/test", response_model=AlertTestResponse, status_code=200)
def test_alert(payload: AlertTestRequest) -> AlertTestResponse:
    eng = _get_engine()
    try:
        result = eng.evaluate(payload.rule_id, payload.sample_metrics or {})
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"rule_id not found: {exc.args[0]}") from exc
    return AlertTestResponse(**result)


__all__ = ["router"]
