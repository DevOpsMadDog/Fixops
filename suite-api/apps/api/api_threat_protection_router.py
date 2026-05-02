"""API Threat Protection Router — ALDECI.

API threat detection rules and event management endpoints.

Prefix: /api/v1/api-threat-protection
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/api-threat-protection/rules              create_protection_rule
  GET    /api/v1/api-threat-protection/rules              list_rules
  GET    /api/v1/api-threat-protection/rules/{id}         get_rule
  POST   /api/v1/api-threat-protection/events             record_threat_event
  GET    /api/v1/api-threat-protection/events             list_threat_events
  PATCH  /api/v1/api-threat-protection/rules/{id}/status  update_rule_status
  GET    /api/v1/api-threat-protection/stats              get_protection_stats
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/api-threat-protection",
    tags=["API Threat Protection"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.api_threat_protection_engine import APIThreatProtectionEngine
        _engine = APIThreatProtectionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateRuleRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    name: str = Field(..., description="Rule name")
    threat_type: str = Field(
        default="injection",
        description="Threat type: injection, auth_bypass, rate_abuse, data_scraping, "
                    "bot_attack, credential_stuffing, parameter_tampering, mass_assignment",
    )
    pattern: str = Field(default="", description="Detection pattern (regex or keyword)")
    action: str = Field(
        default="block",
        description="Action: block, rate_limit, challenge, monitor, allow",
    )
    threshold: int = Field(default=10, ge=1, description="Trigger threshold count")
    window_seconds: int = Field(default=60, ge=1, description="Time window in seconds")


class RecordEventRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    rule_id: str = Field(default="", description="Associated rule id (optional)")
    threat_type: str = Field(
        default="injection",
        description="Threat type that was detected",
    )
    source_ip: str = Field(default="", description="Attacker source IP address")
    endpoint: str = Field(default="", description="Targeted API endpoint")
    method: str = Field(default="GET", description="HTTP method")
    payload_hash: str = Field(default="", description="SHA-256 hash of request payload")
    action_taken: str = Field(default="monitor", description="Action taken by the system")
    severity: str = Field(default="medium", description="Event severity")


class UpdateRuleStatusRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    status: str = Field(..., description="New status: active, disabled, testing")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/rules", dependencies=[Depends(api_key_auth)])
def create_protection_rule(req: CreateRuleRequest) -> Dict[str, Any]:
    """Create a new API threat protection rule."""
    try:
        return _get_engine().create_protection_rule(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("create_protection_rule failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/rules", dependencies=[Depends(api_key_auth)])
def list_rules(
    org_id: str = Query(default="default"),
    threat_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List API threat protection rules."""
    try:
        return _get_engine().list_rules(org_id, threat_type=threat_type, status=status)
    except Exception as exc:
        _logger.exception("list_rules failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/rules/{rule_id}", dependencies=[Depends(api_key_auth)])
def get_rule(
    rule_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get a single protection rule by id."""
    try:
        result = _get_engine().get_rule(org_id, rule_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("get_rule failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/events", dependencies=[Depends(api_key_auth)])
def record_threat_event(req: RecordEventRequest) -> Dict[str, Any]:
    """Record a detected threat event."""
    try:
        return _get_engine().record_threat_event(req.org_id, req.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("record_threat_event failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/events", dependencies=[Depends(api_key_auth)])
def list_threat_events(
    org_id: str = Query(default="default"),
    threat_type: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    rule_id: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List threat events with optional filters."""
    try:
        return _get_engine().list_threat_events(
            org_id,
            threat_type=threat_type,
            source_ip=source_ip,
            rule_id=rule_id,
        )
    except Exception as exc:
        _logger.exception("list_threat_events failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.patch("/rules/{rule_id}/status", dependencies=[Depends(api_key_auth)])
def update_rule_status(
    rule_id: str,
    req: UpdateRuleStatusRequest,
) -> Dict[str, Any]:
    """Update the status of a protection rule."""
    try:
        return _get_engine().update_rule_status(req.org_id, rule_id, req.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("update_rule_status failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_protection_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Return aggregate API threat protection statistics for the org."""
    try:
        return _get_engine().get_protection_stats(org_id)
    except Exception as exc:
        _logger.exception("get_protection_stats failed")
        raise HTTPException(status_code=500, detail=str(exc))
