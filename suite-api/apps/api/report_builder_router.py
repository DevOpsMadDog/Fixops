"""
Report Builder API Router — custom configurable reports with drag-and-drop sections.

Endpoints:
  POST   /api/v1/report-builder/templates              create template
  GET    /api/v1/report-builder/templates              list templates
  GET    /api/v1/report-builder/templates/{id}         get template
  PUT    /api/v1/report-builder/templates/{id}         update template
  DELETE /api/v1/report-builder/templates/{id}         delete template
  POST   /api/v1/report-builder/templates/{id}/clone   clone template
  POST   /api/v1/report-builder/templates/{id}/generate generate report
  GET    /api/v1/report-builder/reports                list generated reports
  GET    /api/v1/report-builder/reports/{id}           get generated report
  GET    /api/v1/report-builder/reports/{id}/export    export report (JSON/HTML)
  GET    /api/v1/report-builder/meta/section-types     available section types
  GET    /api/v1/report-builder/meta/data-sources      available data sources
  GET    /api/v1/report-builder/stats                  builder statistics

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

# ---------------------------------------------------------------------------
# Lazy singleton
# ---------------------------------------------------------------------------

_builder = None


def _get_builder():
    global _builder
    if _builder is None:
        from core.report_builder import ReportBuilder
        _builder = ReportBuilder()
    return _builder


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateTemplateRequest(BaseModel):
    name: str
    description: str = ""
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    schedule: Optional[str] = None
    recipients: List[str] = Field(default_factory=list)
    org_id: str = "default"
    created_by: str = "system"


class UpdateTemplateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    sections: Optional[List[Dict[str, Any]]] = None
    schedule: Optional[str] = None
    recipients: Optional[List[str]] = None


class CloneTemplateRequest(BaseModel):
    new_name: str


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/report-builder",
    tags=["report-builder"],
)


# Static sub-routes MUST come before parameterised routes
# so FastAPI does not swallow them as path parameters.

@router.get("/meta/section-types", dependencies=[Depends(_verify_api_key)])
async def get_section_types() -> List[Dict[str, Any]]:
    """Return all available section types with labels and descriptions."""
    return _get_builder().get_section_types()


@router.get("/meta/data-sources", dependencies=[Depends(_verify_api_key)])
async def get_data_sources() -> List[Dict[str, Any]]:
    """Return all available data sources."""
    return _get_builder().get_available_data_sources()


@router.get("/stats", dependencies=[Depends(_verify_api_key)])
async def get_stats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """Return aggregate statistics for the report builder."""
    return _get_builder().get_builder_stats(org_id=org_id)


@router.get("/reports", dependencies=[Depends(_verify_api_key)])
async def list_reports(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Dict[str, Any]]:
    """List generated reports for an organisation, newest first."""
    reports = _get_builder().list_reports(org_id=org_id)
    return [r.model_dump() for r in reports]


@router.get("/reports/{report_id}/export", dependencies=[Depends(_verify_api_key)])
async def export_report(
    report_id: str,
    format: str = Query("json", description="Export format: json or html"),
) -> Any:
    """Export a generated report as JSON object or HTML string."""
    builder = _get_builder()
    result = builder.export_report(report_id, format=format)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
    if format.lower() == "html":
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=result)
    import json
    return json.loads(result)


@router.get("/reports/{report_id}", dependencies=[Depends(_verify_api_key)])
async def get_report(report_id: str) -> Dict[str, Any]:
    """Retrieve a single generated report by ID."""
    report = _get_builder().get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
    return report.model_dump()


# ---------------------------------------------------------------------------
# Template endpoints
# ---------------------------------------------------------------------------

@router.post("/templates", dependencies=[Depends(_verify_api_key)], status_code=201)
async def create_template(req: CreateTemplateRequest) -> Dict[str, Any]:
    """Create a new report template."""
    from core.report_builder import ReportSection, ReportTemplate
    sections = [ReportSection.model_validate(s) for s in req.sections]
    template = ReportTemplate(
        name=req.name,
        description=req.description,
        sections=sections,
        schedule=req.schedule,
        recipients=req.recipients,
        org_id=req.org_id,
        created_by=req.created_by,
    )
    result = _get_builder().create_template(template)
    return result.model_dump()


@router.get("/templates", dependencies=[Depends(_verify_api_key)])
async def list_templates(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[Dict[str, Any]]:
    """List all report templates for an organisation."""
    templates = _get_builder().list_templates(org_id=org_id)
    return [t.model_dump() for t in templates]


@router.get("/templates/{template_id}", dependencies=[Depends(_verify_api_key)])
async def get_template(template_id: str) -> Dict[str, Any]:
    """Retrieve a report template by ID."""
    template = _get_builder().get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return template.model_dump()


@router.put("/templates/{template_id}", dependencies=[Depends(_verify_api_key)])
async def update_template(template_id: str, req: UpdateTemplateRequest) -> Dict[str, Any]:
    """Partially update a report template."""
    updates = req.model_dump(exclude_none=True)
    result = _get_builder().update_template(template_id, updates)
    if not result:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return result.model_dump()


@router.delete("/templates/{template_id}", dependencies=[Depends(_verify_api_key)], status_code=204)
async def delete_template(template_id: str) -> None:
    """Delete a report template by ID."""
    deleted = _get_builder().delete_template(template_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")


@router.post("/templates/{template_id}/clone", dependencies=[Depends(_verify_api_key)], status_code=201)
async def clone_template(template_id: str, req: CloneTemplateRequest) -> Dict[str, Any]:
    """Clone a report template under a new name."""
    result = _get_builder().clone_template(template_id, new_name=req.new_name)
    if not result:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return result.model_dump()


@router.post("/templates/{template_id}/generate", dependencies=[Depends(_verify_api_key)], status_code=201)
async def generate_report(template_id: str) -> Dict[str, Any]:
    """Generate a report from a template, populating all sections with live data."""
    report = _get_builder().generate_report(template_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return report.model_dump()
