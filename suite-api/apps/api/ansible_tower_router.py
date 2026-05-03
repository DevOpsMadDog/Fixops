"""ALDECI Ansible Tower / AWX API Router.

Direct pass-through to the Ansible Tower (AWX) REST API v2 — covers the
read-mostly automation surface (inventories, job templates, jobs, projects,
credentials) plus a single mutating launch endpoint.

Endpoints (mounted at ``/api/v1/ansible-tower``)
-----------------------------------------------
GET    /                                                — capability summary
GET    /api/v2/inventories                              — list inventories
GET    /api/v2/job_templates                            — list job templates
POST   /api/v2/job_templates/{id}/launch                — launch job template
GET    /api/v2/jobs/{id}                                — fetch job by id
GET    /api/v2/jobs/{id}/job_events                     — stream job events
GET    /api/v2/projects                                 — list projects
GET    /api/v2/credentials                              — list credentials

When ``TOWER_HOST`` / ``TOWER_OAUTH_TOKEN`` are unset the capability summary
reports ``status="unavailable"`` and lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ansible-tower",
    tags=["ansible-tower"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.ansible_tower_engine import get_ansible_tower_engine
    return get_ansible_tower_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    tower_host_present: bool
    tower_oauth_token_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class JobTemplateLaunchRequest(BaseModel):
    """Mirrors Tower's POST /api/v2/job_templates/{id}/launch body shape."""

    extra_vars: Optional[Union[str, Dict[str, Any]]] = Field(
        None,
        description="Override extra_vars — JSON object or YAML/JSON string.",
    )
    limit: Optional[str] = Field(None, description="Inventory limit pattern.")
    job_tags: Optional[str] = Field(None, description="Comma-separated tags to run.")
    skip_tags: Optional[str] = Field(None, description="Comma-separated tags to skip.")
    inventory: Optional[int] = Field(None, description="Override inventory id.")
    credentials: Optional[List[int]] = Field(
        None, description="Credential id list (when prompt_on_launch enabled)."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "ansible_tower_unavailable",
            "message": "TOWER_HOST and TOWER_OAUTH_TOKEN environment variables are not configured",
        },
    )


def _map_tower_error(exc: Exception) -> HTTPException:
    """Translate AnsibleTowerHTTPError / Unavailable into an HTTPException."""
    from core.ansible_tower_engine import AnsibleTowerHTTPError, AnsibleTowerUnavailable

    if isinstance(exc, AnsibleTowerUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "ansible_tower_unavailable", "message": str(exc)},
        )
    if isinstance(exc, AnsibleTowerHTTPError):
        # Pass auth/perm/not-found/conflict/rate-limit through; otherwise 502.
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "tower_upstream_error",
                "upstream_status": exc.status_code,
                "message": str(exc),
                "payload": exc.payload,
            },
        )
    return HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=CapabilitySummary,
    summary="Ansible Tower / AWX capability summary",
)
def capability_summary() -> CapabilitySummary:
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.get(
    "/api/v2/inventories",
    summary="List inventories",
)
def list_inventories(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = Query(None, description="Tower search term"),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_inventories(page=page, page_size=page_size, search=search)
    except Exception as exc:
        raise _map_tower_error(exc) from exc


@router.get(
    "/api/v2/job_templates",
    summary="List job templates",
)
def list_job_templates(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_job_templates(page=page, page_size=page_size, search=search)
    except Exception as exc:
        raise _map_tower_error(exc) from exc


@router.post(
    "/api/v2/job_templates/{template_id}/launch",
    summary="Launch a job template",
)
def launch_job_template(
    template_id: int,
    req: JobTemplateLaunchRequest,
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        # Tower returns the created job inline. Wrap in {"job": ...} envelope so
        # callers have a stable response shape distinct from list endpoints.
        body = engine.launch_job_template(template_id, req.model_dump(exclude_none=True))
    except Exception as exc:
        raise _map_tower_error(exc) from exc
    if isinstance(body, dict) and ("id" in body or "job" in body):
        # Some Tower deployments return the job at top-level, others wrap it.
        return {"job": body.get("job", body)}
    return {"job": body or {}}


@router.get(
    "/api/v2/jobs/{job_id}",
    summary="Fetch job by id",
)
def get_job(job_id: int) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_job(job_id)
    except Exception as exc:
        raise _map_tower_error(exc) from exc


@router.get(
    "/api/v2/jobs/{job_id}/job_events",
    summary="List job events for a job",
)
def list_job_events(
    job_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_job_events(job_id, page=page, page_size=page_size)
    except Exception as exc:
        raise _map_tower_error(exc) from exc


@router.get(
    "/api/v2/projects",
    summary="List projects",
)
def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = Query(None),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_projects(page=page, page_size=page_size, search=search)
    except Exception as exc:
        raise _map_tower_error(exc) from exc


@router.get(
    "/api/v2/credentials",
    summary="List credentials",
)
def list_credentials(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_credentials(page=page, page_size=page_size)
    except Exception as exc:
        raise _map_tower_error(exc) from exc
