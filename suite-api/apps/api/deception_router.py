"""
Deception Technology Router — ALDECI.

6 endpoints for the deception engine (honeypots + canary tokens):
  POST   /api/v1/deception/canaries          create_canary
  GET    /api/v1/deception/canaries          list_canaries
  DELETE /api/v1/deception/canaries/{id}     deactivate_canary
  POST   /api/v1/deception/check             check_canary (called by other engines)
  GET    /api/v1/deception/alerts            list canary trigger alerts
  GET    /api/v1/deception/stats             canary statistics
  POST   /api/v1/deception/honeypots         deploy_honeypot_endpoint
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
        "deception_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.deception_engine import (
    CanaryAlert,
    CanaryToken,
    CanaryType,
    DeceptionEngine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/deception",
    tags=["deception"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance (file-backed, shared across requests)
_engine: Optional[DeceptionEngine] = None


def _get_engine() -> DeceptionEngine:
    global _engine
    if _engine is None:
        _engine = DeceptionEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class CreateCanaryRequest(BaseModel):
    type: CanaryType = Field(..., description="Type of canary token to create")
    description: str = Field(..., description="Human-readable description")
    org_id: str = Field("default", description="Organisation ID")


class CheckCanaryRequest(BaseModel):
    token_value: str = Field(..., description="Value to check against known canaries")
    source_ip: str = Field(..., description="IP address of the accessor")
    context: Dict[str, Any] = Field(
        default_factory=dict, description="Optional context (user_agent, headers, etc.)"
    )


class DeployHoneypotRequest(BaseModel):
    path: str = Field(..., description="URL path for the honeypot endpoint")
    org_id: str = Field("default", description="Organisation ID")


class DeactivateResponse(BaseModel):
    success: bool
    message: str


class CheckCanaryResponse(BaseModel):
    matched: bool
    alert: Optional[CanaryAlert] = None
    message: str


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/canaries", response_model=CanaryToken, status_code=201)
def create_canary(
    body: CreateCanaryRequest,
    engine: DeceptionEngine = Depends(_get_engine),
) -> CanaryToken:
    """Create a new canary token / honeypot credential."""
    try:
        return engine.create_canary(
            type=body.type,
            description=body.description,
            org_id=body.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to create canary: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/canaries", response_model=List[CanaryToken])
def list_canaries(
    org_id: str = Query("default", description="Organisation ID"),
    engine: DeceptionEngine = Depends(_get_engine),
) -> List[CanaryToken]:
    """List all canary tokens for an organisation."""
    try:
        return engine.list_canaries(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to list canaries: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/canaries/{canary_id}", response_model=DeactivateResponse)
def deactivate_canary(
    canary_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    engine: DeceptionEngine = Depends(_get_engine),
) -> DeactivateResponse:
    """Deactivate (soft-delete) a canary token."""
    try:
        found = engine.deactivate_canary(canary_id=canary_id, org_id=org_id)
        if not found:
            raise HTTPException(
                status_code=404, detail=f"Canary {canary_id} not found for org {org_id}"
            )
        return DeactivateResponse(success=True, message="Canary deactivated")
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to deactivate canary: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/check", response_model=CheckCanaryResponse)
def check_canary(
    body: CheckCanaryRequest,
    engine: DeceptionEngine = Depends(_get_engine),
) -> CheckCanaryResponse:
    """
    Check whether a value matches any active canary token.

    Called by other engines (connectors, scanners) to detect credential theft.
    Returns matched=True and alert details if a canary was triggered.
    """
    try:
        alert = engine.check_canary(
            token_value=body.token_value,
            source_ip=body.source_ip,
            context=body.context,
        )
        if alert:
            return CheckCanaryResponse(
                matched=True,
                alert=alert,
                message="CANARY TRIGGERED — potential attacker/insider detected",
            )
        return CheckCanaryResponse(matched=False, message="No canary matched")
    except Exception as exc:
        logger.exception("Failed to check canary: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/alerts", response_model=List[CanaryAlert])
def get_alerts(
    org_id: str = Query("default", description="Organisation ID"),
    hours: int = Query(24, ge=1, le=8760, description="Look-back window in hours"),
    engine: DeceptionEngine = Depends(_get_engine),
) -> List[CanaryAlert]:
    """List canary trigger alerts within the last N hours."""
    try:
        return engine.get_alerts(org_id=org_id, hours=hours)
    except Exception as exc:
        logger.exception("Failed to get alerts: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", response_model=Dict[str, Any])
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
    engine: DeceptionEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Return aggregate deception statistics for an organisation."""
    try:
        return engine.get_stats(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to get stats: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/honeypots", response_model=List[Dict[str, Any]])
def list_honeypots(
    org_id: str = Query("default", description="Organisation ID"),
    active_only: bool = Query(True, description="Return only active honeypot endpoints"),
    engine: DeceptionEngine = Depends(_get_engine),
) -> List[Dict[str, Any]]:
    """List registered honeypot endpoints for an organisation."""
    try:
        return engine.list_honeypot_endpoints(org_id=org_id, active_only=active_only)
    except Exception as exc:
        logger.exception("Failed to list honeypots: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/honeypots", response_model=Dict[str, Any], status_code=201)
def deploy_honeypot(
    body: DeployHoneypotRequest,
    engine: DeceptionEngine = Depends(_get_engine),
) -> Dict[str, Any]:
    """Register a honeypot endpoint path."""
    try:
        return engine.deploy_honeypot_endpoint(path=body.path, org_id=body.org_id)
    except Exception as exc:
        logger.exception("Failed to deploy honeypot: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
