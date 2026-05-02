"""DDoS Protection Router — ALDECI.

Endpoints for managing DDoS-protected resources, recording attack events,
managing mitigation rules, and querying DDoS statistics.

Prefix: /api/v1/ddos-protection
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/ddos-protection/resources                     register_protected_resource
  GET    /api/v1/ddos-protection/resources                     list_protected_resources
  POST   /api/v1/ddos-protection/attacks                       record_attack_event
  GET    /api/v1/ddos-protection/attacks                       list_attack_events
  PATCH  /api/v1/ddos-protection/attacks/{attack_id}/status    update_attack_status
  POST   /api/v1/ddos-protection/rules                         create_mitigation_rule
  GET    /api/v1/ddos-protection/rules                         list_mitigation_rules
  GET    /api/v1/ddos-protection/stats                         get_ddos_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ddos-protection",
    tags=["DDoS Protection"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ddos_protection_engine import DDoSProtectionEngine
        _engine = DDoSProtectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterResourceRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    name: str = Field(..., description="Friendly name for the resource")
    ip_or_fqdn: str = Field(..., description="IP address or fully-qualified domain name")
    resource_type: str = Field(..., description="web | api | dns | network")
    protection_tier: str = Field("basic", description="basic | standard | premium")


class RecordAttackRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    resource_id: str = Field(..., description="Protected resource UUID")
    attack_type: str = Field(..., description="volumetric | protocol | application | slowloris | amplification")
    source_ips: List[str] = Field(default_factory=list, description="List of attacking source IPs")
    peak_gbps: float = Field(0.0, description="Peak attack volume in Gbps")
    duration_seconds: int = Field(0, description="Attack duration in seconds")
    status: str = Field("detected", description="detected | mitigating | mitigated")


class UpdateAttackStatusRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    status: str = Field(..., description="detected | mitigating | mitigated")


class CreateMitigationRuleRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    name: str = Field(..., description="Rule name")
    rule_type: str = Field(..., description="rate_limit | geo_block | ip_block | challenge")
    threshold: Any = Field(..., description="Rule threshold value")
    action: str = Field(..., description="Action to take when rule triggers")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/",
    dependencies=[Depends(api_key_auth)],
    summary="DDoS protection summary (5-state envelope)",
)
def get_ddos_summary(org_id: str = Query("default", description="Organisation identifier")) -> Dict[str, Any]:
    """Return a 5-state envelope summarising DDoS protection posture for the org.

    States: ok | warning | critical | empty | error
    Always calls the real engine — no mocks, no stubs.
    """
    try:
        stats = _get_engine().get_ddos_stats(org_id)
        resources = stats.get("resources", 0)
        attacks_24h = stats.get("attacks_24h", 0)
        mitigated_pct = stats.get("mitigated_pct", 100.0)

        if resources == 0:
            state = "empty"
            message = "No protected resources registered. Add resources via POST /resources."
        elif attacks_24h > 0 and mitigated_pct < 80:
            state = "critical"
            message = f"{attacks_24h} attack(s) in the last 24 h; only {mitigated_pct:.0f}% mitigated."
        elif attacks_24h > 0:
            state = "warning"
            message = f"{attacks_24h} attack(s) in the last 24 h; {mitigated_pct:.0f}% mitigated."
        else:
            state = "ok"
            message = f"{resources} resource(s) protected, no attacks in the last 24 h."

        return {
            "state": state,
            "message": message,
            "org_id": org_id,
            "stats": stats,
            "links": {
                "resources": "/api/v1/ddos-protection/resources",
                "attacks": "/api/v1/ddos-protection/attacks",
                "rules": "/api/v1/ddos-protection/rules",
                "stats": "/api/v1/ddos-protection/stats",
            },
        }
    except Exception as exc:
        _logger.exception("ddos_summary_failed")
        return {
            "state": "error",
            "message": str(exc),
            "org_id": org_id,
            "stats": {},
            "links": {},
        }


@router.post(
    "/resources",
    dependencies=[Depends(api_key_auth)],
    summary="Register a protected resource",
)
def register_protected_resource(req: RegisterResourceRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_protected_resource(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("register_protected_resource_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/resources",
    dependencies=[Depends(api_key_auth)],
    summary="List protected resources",
)
def list_protected_resources(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_protected_resources(org_id)
    except Exception as exc:
        _logger.exception("list_protected_resources_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/attacks",
    dependencies=[Depends(api_key_auth)],
    summary="Record a DDoS attack event",
)
def record_attack_event(req: RecordAttackRequest) -> Dict[str, Any]:
    try:
        return _get_engine().record_attack_event(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_attack_event_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/attacks",
    dependencies=[Depends(api_key_auth)],
    summary="List attack events",
)
def list_attack_events(
    org_id: str = Query(..., description="Organisation identifier"),
    resource_id: Optional[str] = Query(None, description="Filter by resource UUID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Maximum records to return"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_attack_events(org_id, resource_id=resource_id, status=status, limit=limit)
    except Exception as exc:
        _logger.exception("list_attack_events_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.patch(
    "/attacks/{attack_id}/status",
    dependencies=[Depends(api_key_auth)],
    summary="Update attack event status",
)
def update_attack_status(attack_id: str, req: UpdateAttackStatusRequest) -> Dict[str, Any]:
    try:
        return _get_engine().update_attack_status(req.org_id, attack_id, req.status)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_attack_status_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/rules",
    dependencies=[Depends(api_key_auth)],
    summary="Create a mitigation rule",
)
def create_mitigation_rule(req: CreateMitigationRuleRequest) -> Dict[str, Any]:
    try:
        return _get_engine().create_mitigation_rule(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_mitigation_rule_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/rules",
    dependencies=[Depends(api_key_auth)],
    summary="List mitigation rules",
)
def list_mitigation_rules(org_id: str = Query(..., description="Organisation identifier")) -> List[Dict[str, Any]]:
    try:
        return _get_engine().list_mitigation_rules(org_id)
    except Exception as exc:
        _logger.exception("list_mitigation_rules_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/stats",
    dependencies=[Depends(api_key_auth)],
    summary="Get DDoS stats for an org",
)
def get_ddos_stats(org_id: str = Query(..., description="Organisation identifier")) -> Dict[str, Any]:
    try:
        return _get_engine().get_ddos_stats(org_id)
    except Exception as exc:
        _logger.exception("get_ddos_stats_failed")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
