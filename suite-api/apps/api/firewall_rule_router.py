"""Firewall Rule Analysis Router — ALDECI.

Endpoints under /api/v1/firewall:
  POST   /firewalls                          add a firewall
  GET    /firewalls                          list firewalls (org scoped)
  GET    /firewalls/{firewall_id}            get a single firewall
  GET    /rules                              list rules (all or per firewall)
  POST   /rules                              add a rule
  POST   /firewalls/{firewall_id}/analyze    run rule analysis
  GET    /findings                           list findings
  POST   /findings                           create a finding manually
  POST   /findings/{finding_id}/resolve      resolve a finding
  GET    /stats                              aggregate statistics
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "firewall_rule_router: auth_deps not available, relying on app-level auth"
    )
    _AUTH_DEP = []

from core.firewall_rule_engine import FirewallRuleEngine

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/firewall",
    tags=["firewall"],
    dependencies=_AUTH_DEP,
)

_engine: Optional[FirewallRuleEngine] = None


def _get_engine() -> FirewallRuleEngine:
    global _engine
    if _engine is None:
        _engine = FirewallRuleEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================

_VALID_VENDORS = {
    "palo_alto", "cisco", "fortinet", "checkpoint",
    "aws_sg", "azure_nsg", "unknown",
}
_VALID_STATUSES = {"active", "inactive"}
_VALID_ACTIONS = {"allow", "deny", "drop"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class AddFirewallRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    name: str = Field(..., description="Friendly name for the firewall")
    vendor: str = Field("unknown", description="Vendor: palo_alto/cisco/fortinet/checkpoint/aws_sg/azure_nsg")
    ip_address: str = Field("", description="Management IP address")
    status: str = Field("active", description="active or inactive")
    rule_count: int = Field(0, description="Known rule count (metadata only)")
    last_audited: Optional[str] = Field(None, description="ISO-8601 timestamp of last audit")


class AddRuleRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    firewall_id: str = Field(..., description="Parent firewall ID")
    rule_number: int = Field(0, description="Rule sequence number (lower = higher priority)")
    src_zone: str = Field("", description="Source security zone")
    dst_zone: str = Field("", description="Destination security zone")
    src_ip: str = Field("any", description="Source IP / CIDR / 'any'")
    dst_ip: str = Field("any", description="Destination IP / CIDR / 'any'")
    port: str = Field("any", description="Port or range, e.g. '443', '1024-65535', 'any'")
    protocol: str = Field("any", description="Protocol: tcp/udp/icmp/any")
    action: str = Field("allow", description="allow / deny / drop")
    enabled: bool = Field(True, description="Whether the rule is active")
    hit_count: int = Field(0, description="Hit counter (imported from device)")
    last_hit: Optional[str] = Field(None, description="ISO-8601 timestamp of last match")


class CreateFindingRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    firewall_id: str = Field(..., description="Associated firewall ID")
    rule_id: Optional[str] = Field(None, description="Associated rule ID")
    finding_type: str = Field(..., description="Type label, e.g. overly_permissive")
    severity: str = Field("medium", description="critical/high/medium/low/info")
    description: str = Field("", description="Human-readable description")


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/firewalls", response_model=Dict[str, Any], summary="Add a firewall")
def add_firewall(
    body: AddFirewallRequest,
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    if body.vendor not in _VALID_VENDORS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid vendor '{body.vendor}'. Choose from: {sorted(_VALID_VENDORS)}",
        )
    if body.status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status '{body.status}'. Choose: active or inactive",
        )
    return engine.add_firewall(body.org_id, body.model_dump(exclude={"org_id"}))


@router.get("/firewalls", response_model=List[Dict[str, Any]], summary="List firewalls")
def list_firewalls(
    org_id: str = Query("default"),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    return engine.list_firewalls(org_id)


@router.get("/firewalls/{firewall_id}", response_model=Dict[str, Any], summary="Get a firewall")
def get_firewall(
    firewall_id: str,
    org_id: str = Query("default"),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    fw = engine.get_firewall(org_id, firewall_id)
    if fw is None:
        raise HTTPException(status_code=404, detail="Firewall not found")
    return fw


@router.post(
    "/firewalls/{firewall_id}/analyze",
    response_model=Dict[str, Any],
    summary="Analyze all rules for a firewall",
)
def analyze_rules(
    firewall_id: str,
    org_id: str = Query("default"),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    fw = engine.get_firewall(org_id, firewall_id)
    if fw is None:
        raise HTTPException(status_code=404, detail="Firewall not found")
    return engine.analyze_rules(org_id, firewall_id)


@router.get("/rules", response_model=List[Dict[str, Any]], summary="List firewall rules")
def list_rules(
    org_id: str = Query("default"),
    firewall_id: Optional[str] = Query(None),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    return engine.list_rules(org_id, firewall_id=firewall_id)


@router.post("/rules", response_model=Dict[str, Any], summary="Add a firewall rule")
def add_rule(
    body: AddRuleRequest,
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    if body.action not in _VALID_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid action '{body.action}'. Choose from: allow, deny, drop",
        )
    fw = engine.get_firewall(body.org_id, body.firewall_id)
    if fw is None:
        raise HTTPException(status_code=404, detail="Firewall not found")
    data = body.model_dump(exclude={"org_id", "firewall_id"})
    return engine.add_rule(body.org_id, body.firewall_id, data)


@router.get("/findings", response_model=List[Dict[str, Any]], summary="List rule findings")
def list_findings(
    org_id: str = Query("default"),
    firewall_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    if severity and severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity '{severity}'. Choose from: {sorted(_VALID_SEVERITIES)}",
        )
    return engine.list_findings(org_id, firewall_id=firewall_id, severity=severity)


@router.post("/findings", response_model=Dict[str, Any], summary="Create a finding manually")
def create_finding(
    body: CreateFindingRequest,
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    if body.severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity '{body.severity}'. Choose from: {sorted(_VALID_SEVERITIES)}",
        )
    return engine.create_finding(
        body.org_id,
        body.firewall_id,
        body.rule_id,
        body.finding_type,
        body.severity,
        body.description,
    )


@router.post(
    "/findings/{finding_id}/resolve",
    response_model=Dict[str, Any],
    summary="Resolve a finding",
)
def resolve_finding(
    finding_id: str,
    org_id: str = Query("default"),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    resolved = engine.resolve_finding(org_id, finding_id)
    if not resolved:
        raise HTTPException(
            status_code=404,
            detail="Finding not found, already resolved, or belongs to a different org",
        )
    return {"finding_id": finding_id, "status": "resolved", "message": "Finding resolved"}


@router.get("/stats", response_model=Dict[str, Any], summary="Firewall aggregate statistics")
def get_firewall_stats(
    org_id: str = Query("default"),
    engine: FirewallRuleEngine = Depends(_get_engine),
):
    return engine.get_firewall_stats(org_id)
