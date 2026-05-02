"""Integration Health Dashboard API Router.

Endpoints:
    POST   /api/v1/integrations              -- Register a new integration
    GET    /api/v1/integrations              -- List integrations (with optional status filter)
    GET    /api/v1/integrations/dashboard    -- Health dashboard for org
    GET    /api/v1/integrations/alerts       -- Active alerts
    GET    /api/v1/integrations/stats        -- Health statistics
    GET    /api/v1/integrations/{id}         -- Get integration details
    DELETE /api/v1/integrations/{id}         -- Delete integration
    POST   /api/v1/integrations/{id}/check   -- Run health check
    POST   /api/v1/integrations/check-all    -- Check all integrations
    GET    /api/v1/integrations/{id}/history -- Check history
    POST   /api/v1/integrations/{id}/enable  -- Re-enable disabled integration

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations", tags=["integration-health"])

# ---------------------------------------------------------------------------
# Lazy monitor singleton
# ---------------------------------------------------------------------------

_monitor: Optional[Any] = None


def _get_monitor():
    """Return a module-level IntegrationHealthMonitor singleton."""
    global _monitor
    if _monitor is None:
        from core.integration_health import IntegrationHealthMonitor
        _monitor = IntegrationHealthMonitor()
    return _monitor


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Human-readable integration name")
    type: str = Field(..., min_length=1, max_length=100, description="Integration type (e.g. jira, github)")
    endpoint_url: str = Field(..., min_length=1, max_length=2048, description="Service endpoint URL")


# ---------------------------------------------------------------------------
# Endpoints — order matters: specific paths before parameterised ones
# ---------------------------------------------------------------------------


@router.post("", summary="Register a new integration")
async def register_integration(
    body: RegisterRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Register an integration for health monitoring."""
    monitor = _get_monitor()
    info = monitor.register_integration(
        name=body.name,
        type=body.type,
        endpoint_url=body.endpoint_url,
        org_id=org_id,
    )
    return info.model_dump()


@router.get("", summary="List integrations")
async def list_integrations(
    status: Optional[str] = Query(None, description="Filter by status"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List all integrations for the org, optionally filtered by status."""
    monitor = _get_monitor()
    integrations = monitor.list_integrations(org_id=org_id, status_filter=status)
    return [i.model_dump() for i in integrations]


@router.get("/dashboard", summary="Integration health dashboard")
async def get_dashboard(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return a full health dashboard for all integrations in the org."""
    monitor = _get_monitor()
    return monitor.get_dashboard(org_id=org_id)


@router.get("/alerts", summary="Active integration alerts")
async def get_alerts(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return integrations that require attention (down, degraded, or disabled)."""
    monitor = _get_monitor()
    return monitor.get_alerts(org_id=org_id)


@router.get("/stats", summary="Integration health statistics")
async def get_health_stats(
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate health statistics for the org."""
    monitor = _get_monitor()
    return monitor.get_health_stats(org_id=org_id)


@router.post("/check-all", summary="Check all integrations")
async def check_all(
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Run health checks against all non-disabled integrations in the org."""
    monitor = _get_monitor()
    results = monitor.check_all(org_id=org_id)
    return [r.model_dump() for r in results]


@router.get("/{integration_id}", summary="Get integration details")
async def get_integration(
    integration_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return details for a specific integration."""
    monitor = _get_monitor()
    try:
        info = monitor.get_integration(integration_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    if info.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    return info.model_dump()


@router.delete("/{integration_id}", summary="Delete integration")
async def delete_integration(
    integration_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Delete an integration and its full check history."""
    monitor = _get_monitor()
    try:
        info = monitor.get_integration(integration_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    if info.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    monitor.delete_integration(integration_id)
    return {"status": "deleted", "integration_id": integration_id}


@router.post("/{integration_id}/check", summary="Run health check")
async def check_integration(
    integration_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Run a health check for a specific integration."""
    monitor = _get_monitor()
    try:
        info = monitor.get_integration(integration_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    if info.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    result = monitor.check_health(integration_id)
    return result.model_dump()


@router.get("/{integration_id}/history", summary="Check history")
async def get_check_history(
    integration_id: str,
    limit: int = Query(50, ge=1, le=500, description="Max results to return"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Return recent health check history for an integration."""
    monitor = _get_monitor()
    try:
        info = monitor.get_integration(integration_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    if info.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    history = monitor.get_check_history(integration_id, limit=limit)
    return [r.model_dump() for r in history]


@router.post("/{integration_id}/enable", summary="Re-enable disabled integration")
async def enable_integration(
    integration_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Re-enable a disabled integration and reset failure counters."""
    monitor = _get_monitor()
    try:
        info = monitor.get_integration(integration_id)
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    if info.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Integration not found: {integration_id}")
    monitor.enable_integration(integration_id)
    return {"status": "enabled", "integration_id": integration_id}
