"""Azure Sentinel Router — ALDECI.

Prefix: /api/v1/azure-sentinel
Scope:  read:scans (mounted via platform_app)

Routes:
  GET  /                         capability summary
  GET  /incidents                list Sentinel incidents (OData filter, $top)
  GET  /alertRules               list scheduled / NRT / Fusion alert rules
  GET  /bookmarks                list investigation bookmarks
  GET  /watchlists               list watchlists
  POST /entities/expand          expand an entity via Sentinel expansion id

NO MOCKS — engine raises RuntimeError when env unset → mapped to HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/azure-sentinel", tags=["Azure Sentinel"])


def _engine():
    from core.azure_sentinel_engine import get_azure_sentinel_engine
    return get_azure_sentinel_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class EntityRef(BaseModel):
    kind: str = Field(..., min_length=1, max_length=128, description="Entity kind (Account, Host, Ip, etc)")
    id: str = Field(..., min_length=1, max_length=512, description="Entity resource id")


class ExpandEntityRequest(BaseModel):
    entity: EntityRef
    expansionId: str = Field(..., min_length=1, max_length=128, description="Expansion identifier (uuid)")
    subscriptionId: str = Field(..., min_length=1, max_length=128)
    resourceGroupName: str = Field(..., min_length=1, max_length=128)
    workspaceName: str = Field(..., min_length=1, max_length=128)
    startTime: Optional[str] = Field(default=None, max_length=64)
    endTime: Optional[str] = Field(default=None, max_length=64)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — env not set / token fetch failed.
        raise HTTPException(
            status_code=503, detail=f"azure sentinel unavailable: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(
            status_code=status, detail=f"azure sentinel error: {exc}"
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"azure sentinel transport error: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Azure Sentinel integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/incidents")
def list_incidents(
    subscriptionId: str = Query(..., min_length=1, max_length=128),
    resourceGroupName: str = Query(..., min_length=1, max_length=128),
    workspaceName: str = Query(..., min_length=1, max_length=128),
    filter_: Optional[str] = Query(default=None, alias="$filter", max_length=2048),
    top: Optional[int] = Query(default=None, alias="$top", ge=1, le=1000),
) -> Dict[str, Any]:
    """List Sentinel incidents (Azure REST GET /incidents)."""
    eng = _engine()
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="azure sentinel unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )
    return _handle_engine_call(
        lambda: eng.list_incidents(
            subscription_id=subscriptionId,
            resource_group_name=resourceGroupName,
            workspace_name=workspaceName,
            odata_filter=filter_,
            top=top,
        )
    )


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


@router.get("/alertRules")
def list_alert_rules(
    subscriptionId: str = Query(..., min_length=1, max_length=128),
    resourceGroupName: str = Query(..., min_length=1, max_length=128),
    workspaceName: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    """List Sentinel alert rules (Scheduled / NRT / Fusion / MicrosoftSecurity)."""
    eng = _engine()
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="azure sentinel unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )
    return _handle_engine_call(
        lambda: eng.list_alert_rules(
            subscription_id=subscriptionId,
            resource_group_name=resourceGroupName,
            workspace_name=workspaceName,
        )
    )


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------


@router.get("/bookmarks")
def list_bookmarks(
    subscriptionId: str = Query(..., min_length=1, max_length=128),
    resourceGroupName: str = Query(..., min_length=1, max_length=128),
    workspaceName: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    """List Sentinel investigation bookmarks."""
    eng = _engine()
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="azure sentinel unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )
    return _handle_engine_call(
        lambda: eng.list_bookmarks(
            subscription_id=subscriptionId,
            resource_group_name=resourceGroupName,
            workspace_name=workspaceName,
        )
    )


# ---------------------------------------------------------------------------
# Watchlists
# ---------------------------------------------------------------------------


@router.get("/watchlists")
def list_watchlists(
    subscriptionId: str = Query(..., min_length=1, max_length=128),
    resourceGroupName: str = Query(..., min_length=1, max_length=128),
    workspaceName: str = Query(..., min_length=1, max_length=128),
) -> Dict[str, Any]:
    """List Sentinel watchlists."""
    eng = _engine()
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="azure sentinel unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )
    return _handle_engine_call(
        lambda: eng.list_watchlists(
            subscription_id=subscriptionId,
            resource_group_name=resourceGroupName,
            workspace_name=workspaceName,
        )
    )


# ---------------------------------------------------------------------------
# Entity expansion
# ---------------------------------------------------------------------------


@router.post("/entities/expand")
def expand_entity(req: ExpandEntityRequest) -> Dict[str, Any]:
    """Expand an entity via Sentinel expansion id (POST /entities/{id}/expand)."""
    eng = _engine()
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail="azure sentinel unavailable: AZURE_TENANT_ID, AZURE_CLIENT_ID, "
            "AZURE_CLIENT_SECRET must be set",
        )
    return _handle_engine_call(
        lambda: eng.expand_entity(
            subscription_id=req.subscriptionId,
            resource_group_name=req.resourceGroupName,
            workspace_name=req.workspaceName,
            entity_id=req.entity.id,
            expansion_id=req.expansionId,
            start_time=req.startTime,
            end_time=req.endTime,
        )
    )


__all__ = ["router"]
