"""WAF Engine Router — REST endpoints for WAF management.

Endpoints under /api/v1/waf-engine:
  GET    /rules                  — List WAF rules (filter: rule_type, enabled)
  POST   /rules                  — Create a WAF rule
  PUT    /rules/{rule_id}        — Update a WAF rule
  DELETE /rules/{rule_id}        — Delete a WAF rule
  GET    /blocked-requests       — List blocked requests (filter: attack_type, severity, hours)
  POST   /blocked-requests       — Record a blocked request
  GET    /virtual-patches        — List virtual patches
  POST   /virtual-patches        — Add a virtual patch
  GET    /rate-limits            — List rate limit rules
  POST   /rate-limits            — Create a rate limit rule
  GET    /stats                  — WAF statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/waf-engine",
    tags=["WAF Engine"],
    dependencies=[Depends(api_key_auth)],
)


def _get_engine():
    try:
        from core.waf_engine import WAFEngine
        return WAFEngine()
    except Exception as exc:
        _logger.error("WAFEngine unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=f"WAF engine unavailable: {exc}")


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRuleRequest(BaseModel):
    rule_name: str
    rule_type: str = "block"
    pattern: str = ""
    target: str = "uri"
    action: str = "block"
    severity: str = "high"
    enabled: bool = True
    description: str = ""


class UpdateRuleRequest(BaseModel):
    rule_name: Optional[str] = None
    rule_type: Optional[str] = None
    pattern: Optional[str] = None
    target: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None
    description: Optional[str] = None


class BlockedRequestBody(BaseModel):
    rule_id: str = ""
    source_ip: str = ""
    uri: str = ""
    method: str = "GET"
    user_agent: str = ""
    attack_type: str = "xss"
    severity: str = "high"
    request_headers: Dict[str, str] = Field(default_factory=dict)
    blocked_at: Optional[str] = None


class VirtualPatchBody(BaseModel):
    cve_id: str
    title: str
    rule_pattern: str = ""
    expires_at: Optional[str] = None


class RateLimitBody(BaseModel):
    endpoint_pattern: str = "/*"
    requests_per_minute: int = 60
    burst_size: int = 10
    action: str = "block"


# ---------------------------------------------------------------------------
# Rules endpoints
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=Dict[str, Any])
def list_rules(
    org_id: str = Query("default"),
    rule_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
):
    eng = _get_engine()
    try:
        rules = eng.list_rules(org_id, rule_type=rule_type, enabled=enabled)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"total": len(rules), "rules": rules}


@router.post("/rules", response_model=Dict[str, Any])
def create_rule(body: CreateRuleRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        rule = eng.create_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return rule


@router.put("/rules/{rule_id}", response_model=Dict[str, Any])
def update_rule(rule_id: str, body: UpdateRuleRequest, org_id: str = Query("default")):
    eng = _get_engine()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        rule = eng.update_rule(org_id, rule_id, updates)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if rule is None:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    return rule


@router.delete("/rules/{rule_id}", response_model=Dict[str, Any])
def delete_rule(rule_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    deleted = eng.delete_rule(org_id, rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id!r} not found")
    return {"deleted": True, "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Blocked requests endpoints
# ---------------------------------------------------------------------------

@router.get("/blocked-requests", response_model=Dict[str, Any])
def list_blocked_requests(
    org_id: str = Query("default"),
    attack_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100),
    hours: int = Query(24),
):
    eng = _get_engine()
    try:
        items = eng.list_blocked_requests(
            org_id, attack_type=attack_type, severity=severity, limit=limit, hours=hours
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"total": len(items), "blocked_requests": items}


@router.post("/blocked-requests", response_model=Dict[str, Any])
def record_blocked_request(body: BlockedRequestBody, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("blocked_at") is None:
        data.pop("blocked_at", None)
    try:
        item = eng.record_blocked_request(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return item


# ---------------------------------------------------------------------------
# Virtual patches endpoints
# ---------------------------------------------------------------------------

@router.get("/virtual-patches", response_model=Dict[str, Any])
def list_virtual_patches(
    org_id: str = Query("default"),
    active_only: bool = Query(True),
):
    eng = _get_engine()
    patches = eng.list_virtual_patches(org_id, active_only=active_only)
    return {"total": len(patches), "virtual_patches": patches}


@router.post("/virtual-patches", response_model=Dict[str, Any])
def add_virtual_patch(body: VirtualPatchBody, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("expires_at") is None:
        data.pop("expires_at", None)
    patch = eng.add_virtual_patch(org_id, data)
    return patch


# ---------------------------------------------------------------------------
# Rate limit rules endpoints
# ---------------------------------------------------------------------------

@router.get("/rate-limits", response_model=Dict[str, Any])
def list_rate_limits(org_id: str = Query("default")):
    eng = _get_engine()
    rules = eng.list_rate_limit_rules(org_id)
    return {"total": len(rules), "rate_limit_rules": rules}


@router.post("/rate-limits", response_model=Dict[str, Any])
def create_rate_limit(body: RateLimitBody, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        rule = eng.create_rate_limit_rule(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return rule


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_waf_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_waf_stats(org_id)
