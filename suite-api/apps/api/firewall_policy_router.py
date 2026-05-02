"""Firewall Policy Router — ALDECI.

Prefix: /api/v1/firewall-policy
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/firewall-policy/firewalls                          register_firewall
  GET    /api/v1/firewall-policy/firewalls                          list_firewalls
  POST   /api/v1/firewall-policy/firewalls/{firewall_id}/rules      add_rule
  GET    /api/v1/firewall-policy/firewalls/{firewall_id}/rules      list_rules
  GET    /api/v1/firewall-policy/firewalls/{firewall_id}/conflicts  find_conflicting_rules
  GET    /api/v1/firewall-policy/firewalls/{firewall_id}/unused     find_unused_rules
  GET    /api/v1/firewall-policy/firewalls/{firewall_id}/gaps       analyze_coverage_gaps
  GET    /api/v1/firewall-policy/stats                              get_firewall_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/firewall-policy",
    tags=["Firewall Policy"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.firewall_policy_engine import FirewallPolicyEngine
        _engine = FirewallPolicyEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class FirewallCreate(BaseModel):
    name: str
    fw_type: str
    management_ip: str = ""
    description: str = ""


class RuleCreate(BaseModel):
    name: str
    action: str
    src_zones: List[str] = []
    dst_zones: List[str] = []
    src_ips: List[str] = []
    dst_ips: List[str] = []
    ports: List[str] = []
    protocol: str = "any"
    enabled: bool = True
    order_num: int = 0
    hit_count: int = 0
    last_hit_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Firewall routes
# ---------------------------------------------------------------------------

@router.post("/firewalls", dependencies=[Depends(api_key_auth)], status_code=201)
def register_firewall(body: FirewallCreate, org_id: str = Query(default="default")):
    """Register a new firewall device."""
    try:
        return _get_engine().register_firewall(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/firewalls", dependencies=[Depends(api_key_auth)])
def list_firewalls(org_id: str = Query(default="default")):
    """List all firewalls for the org."""
    return _get_engine().list_firewalls(org_id)


# ---------------------------------------------------------------------------
# Rule routes
# ---------------------------------------------------------------------------

@router.post("/firewalls/{firewall_id}/rules", dependencies=[Depends(api_key_auth)], status_code=201)
def add_rule(firewall_id: str, body: RuleCreate, org_id: str = Query(default="default")):
    """Add a rule to a firewall."""
    try:
        return _get_engine().add_rule(org_id, firewall_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/firewalls/{firewall_id}/rules", dependencies=[Depends(api_key_auth)])
def list_rules(
    firewall_id: str,
     org_id: str = Query(default="default"),
    action: Optional[str] = Query(None),
):
    """List rules for a firewall with optional action filter."""
    return _get_engine().list_rules(org_id, firewall_id, action=action)


# ---------------------------------------------------------------------------
# Analysis routes
# ---------------------------------------------------------------------------

@router.get("/firewalls/{firewall_id}/conflicts", dependencies=[Depends(api_key_auth)])
def find_conflicting_rules(firewall_id: str, org_id: str = Query(default="default")):
    """Find rules that shadow or conflict with each other."""
    return _get_engine().find_conflicting_rules(org_id, firewall_id)


@router.get("/firewalls/{firewall_id}/unused", dependencies=[Depends(api_key_auth)])
def find_unused_rules(
    firewall_id: str,
     org_id: str = Query(default="default"),
    days_threshold: int = Query(default=90, ge=1),
):
    """Find rules with zero hits or no recent hits."""
    return _get_engine().find_unused_rules(org_id, firewall_id, days_threshold=days_threshold)


@router.get("/firewalls/{firewall_id}/gaps", dependencies=[Depends(api_key_auth)])
def analyze_coverage_gaps(firewall_id: str, org_id: str = Query(default="default")):
    """Analyze coverage gaps and risky configurations."""
    return _get_engine().analyze_coverage_gaps(org_id, firewall_id)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_firewall_stats(org_id: str = Query(default="default")):
    """Return aggregated firewall statistics for the org."""
    return _get_engine().get_firewall_stats(org_id)
