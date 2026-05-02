"""Firewall Management Router — ALDECI.

Endpoints for the Firewall Management engine.

Prefix: /api/v1/firewall-mgmt
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/firewall-mgmt/firewalls                              add_firewall
  GET    /api/v1/firewall-mgmt/firewalls                              list_firewalls
  GET    /api/v1/firewall-mgmt/firewalls/{firewall_id}                get_firewall
  POST   /api/v1/firewall-mgmt/firewalls/{firewall_id}/rules          add_rule
  GET    /api/v1/firewall-mgmt/rules                                  list_rules
  POST   /api/v1/firewall-mgmt/rules/{rule_id}/disable                disable_rule
  POST   /api/v1/firewall-mgmt/firewalls/{firewall_id}/detect-shadows detect_shadowed_rules
  POST   /api/v1/firewall-mgmt/change-requests                        create_change_request
  GET    /api/v1/firewall-mgmt/change-requests                        list_change_requests
  POST   /api/v1/firewall-mgmt/change-requests/{request_id}/approve   approve_change_request
  POST   /api/v1/firewall-mgmt/change-requests/{request_id}/reject    reject_change_request
  POST   /api/v1/firewall-mgmt/change-requests/{request_id}/implement implement_change_request
  POST   /api/v1/firewall-mgmt/firewalls/{firewall_id}/scan           run_compliance_scan
  GET    /api/v1/firewall-mgmt/violations                             list_violations
  POST   /api/v1/firewall-mgmt/violations/{violation_id}/resolve      resolve_violation
  GET    /api/v1/firewall-mgmt/stats                                  get_firewall_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/firewall-mgmt",
    tags=["firewall-mgmt"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.firewall_management_engine import FirewallManagementEngine
        _engine = FirewallManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class FirewallCreate(BaseModel):
    name: str
    vendor: str = "generic"
    model: str = ""
    fw_type: str = "perimeter"
    ip_address: str = ""


class RuleCreate(BaseModel):
    rule_name: str = ""
    src_zone: str = ""
    dst_zone: str = ""
    src_address: str = "any"
    dst_address: str = "any"
    service: List[str] = Field(default_factory=list)
    action: str = "deny"
    expires_at: Optional[str] = None


class ChangeRequestCreate(BaseModel):
    firewall_id: str
    change_type: str = "add"
    requester: str = ""
    business_justification: str = ""
    rules_json: List[Dict[str, Any]] = Field(default_factory=list)
    expiry_date: Optional[str] = None
    risk_assessment: str = ""


class ApproveRequest(BaseModel):
    approver: str


class RejectRequest(BaseModel):
    approver: str


# ---------------------------------------------------------------------------
# Firewall routes
# ---------------------------------------------------------------------------

@router.post("/firewalls", dependencies=[Depends(api_key_auth)], status_code=201)
def add_firewall(body: FirewallCreate, org_id: str = Query(default="default")):
    """Register a new firewall device."""
    try:
        return _get_engine().add_firewall(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/firewalls", dependencies=[Depends(api_key_auth)])
def list_firewalls(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List registered firewalls, optionally filtered by status."""
    return _get_engine().list_firewalls(org_id, status=status)


@router.get("/firewalls/{firewall_id}", dependencies=[Depends(api_key_auth)])
def get_firewall(firewall_id: str, org_id: str = Query(default="default")):
    """Get a single firewall by ID."""
    fw = _get_engine().get_firewall(org_id, firewall_id)
    if not fw:
        raise HTTPException(status_code=404, detail="Firewall not found")
    return fw


# ---------------------------------------------------------------------------
# Rule routes
# ---------------------------------------------------------------------------

@router.post(
    "/firewalls/{firewall_id}/rules",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_rule(firewall_id: str, body: RuleCreate, org_id: str = Query(default="default")):
    """Add a firewall rule. Risk level is automatically assessed."""
    data = body.model_dump()
    data["firewall_id"] = firewall_id
    try:
        return _get_engine().add_rule(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_rules(
     org_id: str = Query(default="default"),
    firewall_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List firewall rules with optional filters."""
    return _get_engine().list_rules(
        org_id, firewall_id=firewall_id, status=status, risk_level=risk_level
    )


@router.post("/rules/{rule_id}/disable", dependencies=[Depends(api_key_auth)])
def disable_rule(rule_id: str, org_id: str = Query(default="default")):
    """Disable a firewall rule."""
    updated = _get_engine().disable_rule(org_id, rule_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"disabled": True, "rule_id": rule_id}


@router.post(
    "/firewalls/{firewall_id}/detect-shadows",
    dependencies=[Depends(api_key_auth)],
)
def detect_shadowed_rules(firewall_id: str, org_id: str = Query(default="default")):
    """Detect and mark shadowed rules for a firewall."""
    shadowed = _get_engine().detect_shadowed_rules(org_id, firewall_id)
    return {"shadowed_rule_ids": shadowed, "count": len(shadowed)}


# ---------------------------------------------------------------------------
# Change request routes
# ---------------------------------------------------------------------------

@router.post(
    "/change-requests", dependencies=[Depends(api_key_auth)], status_code=201
)
def create_change_request(body: ChangeRequestCreate, org_id: str = Query(default="default")):
    """Create a firewall rule change request."""
    try:
        return _get_engine().create_change_request(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/change-requests", dependencies=[Depends(api_key_auth)])
def list_change_requests(
     org_id: str = Query(default="default"),
    status: Optional[str] = Query(None),
):
    """List change requests with optional status filter."""
    return _get_engine().list_change_requests(org_id, status=status)


@router.post(
    "/change-requests/{request_id}/approve", dependencies=[Depends(api_key_auth)]
)
def approve_change_request(
    request_id: str, body: ApproveRequest, org_id: str = Query(default="default")
):
    """Approve a pending change request."""
    updated = _get_engine().approve_change_request(org_id, request_id, body.approver)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Change request not found or not in pending status",
        )
    return {"approved": True, "request_id": request_id, "approver": body.approver}


@router.post(
    "/change-requests/{request_id}/reject", dependencies=[Depends(api_key_auth)]
)
def reject_change_request(
    request_id: str, body: RejectRequest, org_id: str = Query(default="default")
):
    """Reject a pending change request."""
    updated = _get_engine().reject_change_request(org_id, request_id, body.approver)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Change request not found or not in pending status",
        )
    return {"rejected": True, "request_id": request_id}


@router.post(
    "/change-requests/{request_id}/implement", dependencies=[Depends(api_key_auth)]
)
def implement_change_request(request_id: str, org_id: str = Query(default="default")):
    """Mark an approved change request as implemented."""
    updated = _get_engine().implement_change_request(org_id, request_id)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Change request not found or not in approved status",
        )
    return {"implemented": True, "request_id": request_id}


# ---------------------------------------------------------------------------
# Compliance scan routes
# ---------------------------------------------------------------------------

@router.post(
    "/firewalls/{firewall_id}/scan", dependencies=[Depends(api_key_auth)]
)
def run_compliance_scan(firewall_id: str, org_id: str = Query(default="default")):
    """Run a compliance scan on all rules for a firewall. Creates violation records."""
    violations = _get_engine().run_compliance_scan(org_id, firewall_id)
    return {"violations_found": len(violations), "violations": violations}


@router.get("/violations", dependencies=[Depends(api_key_auth)])
def list_violations(
     org_id: str = Query(default="default"),
    firewall_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List compliance violations with optional filters."""
    return _get_engine().list_violations(
        org_id, firewall_id=firewall_id, severity=severity, status=status
    )


@router.post(
    "/violations/{violation_id}/resolve", dependencies=[Depends(api_key_auth)]
)
def resolve_violation(violation_id: str, org_id: str = Query(default="default")):
    """Mark a compliance violation as resolved."""
    updated = _get_engine().resolve_violation(org_id, violation_id)
    if not updated:
        raise HTTPException(status_code=404, detail="Violation not found")
    return {"resolved": True, "violation_id": violation_id}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_firewall_stats(org_id: str = Query(default="default")):
    """Return aggregated firewall management stats for org."""
    return _get_engine().get_firewall_stats(org_id)
