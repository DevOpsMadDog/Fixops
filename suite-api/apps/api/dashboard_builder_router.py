"""
Dashboard Builder API Router — custom dashboard layouts, sharing, and templates.

Endpoints:
  POST   /api/v1/dashboards                    create dashboard
  GET    /api/v1/dashboards                    list dashboards
  GET    /api/v1/dashboards/templates          list built-in templates
  GET    /api/v1/dashboards/widget-library     widget type catalog
  POST   /api/v1/dashboards/from-template      create from template
  GET    /api/v1/dashboards/{id}               get dashboard
  PUT    /api/v1/dashboards/{id}               update dashboard
  DELETE /api/v1/dashboards/{id}               delete dashboard
  POST   /api/v1/dashboards/{id}/widgets       add widget
  PUT    /api/v1/dashboards/{id}/widgets/{wid} update widget
  DELETE /api/v1/dashboards/{id}/widgets/{wid} remove widget
  POST   /api/v1/dashboards/{id}/share         share dashboard
  POST   /api/v1/dashboards/{id}/clone         clone dashboard

All endpoints are protected with API key authentication.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Auth dependency — mirrors pattern used across all ALDECI routers
# ---------------------------------------------------------------------------

from apps.api.auth_deps import api_key_auth as _verify_api_key
from apps.api.dependencies import get_org_id

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_builder = None


def _get_builder():
    global _builder
    if _builder is None:
        from core.dashboard_builder import DashboardBuilder
        _builder = DashboardBuilder()
    return _builder


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CreateDashboardRequest(BaseModel):
    name: str
    description: str = ""
    owner_email: str = "unknown"
    org_id: str = "default"


class UpdateDashboardRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    visibility: Optional[str] = None
    layout: Optional[Dict[str, Any]] = None


class AddWidgetRequest(BaseModel):
    type: str
    title: str
    data_source: str
    config: Dict[str, Any] = Field(default_factory=dict)
    order: int = 0


class UpdateWidgetRequest(BaseModel):
    type: Optional[str] = None
    title: Optional[str] = None
    data_source: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    order: Optional[int] = None


class ShareRequest(BaseModel):
    emails: List[str]
    visibility: Optional[str] = None


class CloneRequest(BaseModel):
    new_name: str
    new_owner: str


class ReorderRequest(BaseModel):
    widget_ids: List[str]


class FromTemplateRequest(BaseModel):
    template_id: str
    name: str
    owner_email: str = "unknown"
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/dashboards",
    tags=["dashboard-builder"],
)


# Static sub-routes MUST come before parameterised /{id} routes
# so FastAPI does not swallow them as path parameters.

@router.get("/templates", dependencies=[Depends(_verify_api_key)])
async def list_templates() -> List[Dict[str, Any]]:
    """Return all built-in dashboard templates."""
    builder = _get_builder()
    return [t.model_dump() for t in builder.get_templates()]


@router.get("/widget-library", dependencies=[Depends(_verify_api_key)])
async def get_widget_library() -> List[Dict[str, Any]]:
    """Return the available widget type catalog with config schemas."""
    builder = _get_builder()
    return builder.get_widget_library()


@router.post("/from-template", dependencies=[Depends(_verify_api_key)])
async def create_from_template(
    req: FromTemplateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new dashboard from a built-in template (org_id sourced from auth token)."""
    builder = _get_builder()
    try:
        dash = builder.create_from_template(
            template_id=req.template_id,
            name=req.name,
            owner=req.owner_email,
            org_id=org_id,  # always from auth, never from request body
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return dash.model_dump()


@router.post("", dependencies=[Depends(_verify_api_key)])
async def create_dashboard(
    req: CreateDashboardRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new empty dashboard (org_id sourced from auth token)."""
    builder = _get_builder()
    dash = builder.create_dashboard(
        name=req.name,
        description=req.description,
        owner=req.owner_email,
        org_id=org_id,  # always from auth, never from request body
    )
    return dash.model_dump()


@router.get("", dependencies=[Depends(_verify_api_key)])
async def list_dashboards(
    org_id: str = Depends(get_org_id),
    owner: Optional[str] = Query(None, description="Filter by owner email"),
) -> List[Dict[str, Any]]:
    """List dashboards for the caller's org only."""
    builder = _get_builder()
    # org_id always comes from auth — the query-param org_id is intentionally
    # removed to prevent callers from scoping to a different org.
    dashboards = builder.list_dashboards(org_id=org_id, owner=owner)
    return [d.model_dump() for d in dashboards]


def _get_dashboard_owned(builder: Any, dashboard_id: str, org_id: str):
    """Fetch a dashboard and raise 404 if it doesn't exist or belongs to another org."""
    try:
        dash = builder.get_dashboard(dashboard_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if dash.org_id != org_id:
        raise HTTPException(status_code=404, detail=f"Dashboard not found: {dashboard_id}")
    return dash


@router.get("/{dashboard_id}", dependencies=[Depends(_verify_api_key)])
async def get_dashboard(
    dashboard_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Retrieve a single dashboard by ID (must belong to the caller's org)."""
    builder = _get_builder()
    dash = _get_dashboard_owned(builder, dashboard_id, org_id)
    return dash.model_dump()


@router.put("/{dashboard_id}", dependencies=[Depends(_verify_api_key)])
async def update_dashboard(
    dashboard_id: str,
    req: UpdateDashboardRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update dashboard metadata (must belong to the caller's org)."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        dash = builder.update_dashboard(dashboard_id, updates)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return dash.model_dump()


@router.delete("/{dashboard_id}", dependencies=[Depends(_verify_api_key)])
async def delete_dashboard(
    dashboard_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Delete a dashboard and all its widgets (must belong to the caller's org)."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    try:
        builder.delete_dashboard(dashboard_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "deleted", "id": dashboard_id}


# ------------------------------------------------------------------
# Widget endpoints
# ------------------------------------------------------------------

@router.post("/{dashboard_id}/widgets", dependencies=[Depends(_verify_api_key)])
async def add_widget(
    dashboard_id: str,
    req: AddWidgetRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Add a new widget to a dashboard (must belong to the caller's org)."""
    from core.dashboard_builder import Widget, WidgetType
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    try:
        widget = Widget(
            type=WidgetType(req.type),
            title=req.title,
            data_source=req.data_source,
            config=req.config,
            order=req.order,
        )
        added = builder.add_widget(dashboard_id, widget)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return added.model_dump()


@router.put("/{dashboard_id}/widgets/{widget_id}", dependencies=[Depends(_verify_api_key)])
async def update_widget(
    dashboard_id: str,
    widget_id: str,
    req: UpdateWidgetRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Update an existing widget's properties (dashboard must belong to the caller's org)."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    try:
        widget = builder.update_widget(dashboard_id, widget_id, updates)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return widget.model_dump()


@router.delete("/{dashboard_id}/widgets/{widget_id}", dependencies=[Depends(_verify_api_key)])
async def remove_widget(
    dashboard_id: str,
    widget_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Remove a widget from a dashboard (must belong to the caller's org)."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    try:
        builder.remove_widget(dashboard_id, widget_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "removed", "widget_id": widget_id}


@router.post("/{dashboard_id}/reorder", dependencies=[Depends(_verify_api_key)])
async def reorder_widgets(
    dashboard_id: str,
    req: ReorderRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, str]:
    """Reorder widgets by providing a new ordered list of widget IDs."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    try:
        builder.reorder_widgets(dashboard_id, req.widget_ids)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"status": "reordered", "dashboard_id": dashboard_id}


# ------------------------------------------------------------------
# Sharing & cloning
# ------------------------------------------------------------------

@router.post("/{dashboard_id}/share", dependencies=[Depends(_verify_api_key)])
async def share_dashboard(
    dashboard_id: str,
    req: ShareRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Share a dashboard with a list of email addresses and/or change visibility."""
    from core.dashboard_builder import DashboardVisibility
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    visibility = DashboardVisibility(req.visibility) if req.visibility else None
    try:
        dash = builder.share_dashboard(dashboard_id, req.emails, visibility)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return dash.model_dump()


@router.post("/{dashboard_id}/clone", dependencies=[Depends(_verify_api_key)])
async def clone_dashboard(
    dashboard_id: str,
    req: CloneRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Clone a dashboard for a new owner (source must belong to the caller's org)."""
    builder = _get_builder()
    _get_dashboard_owned(builder, dashboard_id, org_id)  # ownership check
    try:
        dash = builder.clone_dashboard(dashboard_id, req.new_name, req.new_owner)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return dash.model_dump()


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

@router.get("/{dashboard_id}/stats", dependencies=[Depends(_verify_api_key)])
async def get_stats(
    dashboard_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return aggregate dashboard statistics for the caller's org."""
    builder = _get_builder()
    # Verify the dashboard belongs to this org (prevents stats oracle via ID enumeration)
    _get_dashboard_owned(builder, dashboard_id, org_id)
    return builder.get_dashboard_stats(org_id=org_id)
