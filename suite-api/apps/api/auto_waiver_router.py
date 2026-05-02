"""Auto-Waiver Router — ALDECI (GAP-006).

Prefix: /api/v1/auto-waiver
Auth: api_key_auth dependency

Endpoints:
  POST   /api/v1/auto-waiver/rule             register (upsert) rule
  GET    /api/v1/auto-waiver/rules             list rules (filter by enabled)
  POST   /api/v1/auto-waiver/apply             evaluate finding, apply first matching rule
  GET    /api/v1/auto-waiver/stats             rule + auto-waived finding stats
  DELETE /api/v1/auto-waiver/rule/{rule_key}   delete rule
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/auto-waiver",
    tags=["Auto-Waiver"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.vuln_exception_engine import VulnExceptionEngine
        _engine = VulnExceptionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterRuleRequest(BaseModel):
    rule_key: str
    conditions: Dict[str, Any] = Field(default_factory=dict)
    max_active_count: int = 100
    approvers: List[str] = Field(default_factory=list)
    expires_days: int = 30


class ApplyRequest(BaseModel):
    finding: Dict[str, Any]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/rule", dependencies=[Depends(api_key_auth)], status_code=201)
def register_rule(body: RegisterRuleRequest, org_id: str = Query(default="default")):
    """Register (or replace) an auto-waiver rule."""
    try:
        return _get_engine().register_auto_waiver_rule(
            org_id=org_id,
            rule_key=body.rule_key,
            conditions=body.conditions,
            max_active_count=body.max_active_count,
            approvers=body.approvers,
            expires_days=body.expires_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_rules(
    org_id: str = Query(default="default"),
    enabled: Optional[bool] = Query(default=None),
):
    """List auto-waiver rules, optionally filtered by enabled flag."""
    return _get_engine().list_auto_waiver_rules(org_id, enabled=enabled)


@router.post("/apply", dependencies=[Depends(api_key_auth)])
def apply_waivers(body: ApplyRequest, org_id: str = Query(default="default")):
    """Apply auto-waiver rules against a finding. Returns matched exception or {matched: False}."""
    try:
        result = _get_engine().apply_auto_waivers(org_id, body.finding)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if result is None:
        return {"matched": False, "exception": None}
    return {"matched": True, "exception": result}


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def stats(org_id: str = Query(default="default")):
    """Return auto-waiver rule and exception stats for the org."""
    return _get_engine().auto_waiver_stats(org_id)


@router.delete("/rule/{rule_key}", dependencies=[Depends(api_key_auth)])
def delete_rule(rule_key: str, org_id: str = Query(default="default")):
    """Delete an auto-waiver rule by rule_key."""
    return _get_engine().delete_auto_waiver_rule(org_id, rule_key)
