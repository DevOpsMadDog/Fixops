"""ALDECI Jira Cloud API Router.

Direct pass-through to the Jira Cloud REST API v3 — distinct from the
bidirectional finding-sync layer in ``jira_sync_router.py``.

Endpoints (mounted at ``/api/v1/jira-cloud``)
---------------------------------------------
GET    /                                               — capability summary
POST   /rest/api/3/issue                               — create an issue
GET    /rest/api/3/issue/{key}                         — fetch an issue
POST   /rest/api/3/search                              — JQL search
GET    /rest/api/3/issue/{key}/transitions             — list transitions
POST   /rest/api/3/issue/{key}/transitions             — transition an issue
GET    /rest/api/3/project                             — list projects

When ``JIRA_URL`` / ``JIRA_AUTH`` are unset the capability summary reports
``status="unavailable"`` and the lookup endpoints respond with HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/jira-cloud",
    tags=["jira-cloud"],
)


# ---------------------------------------------------------------------------
# Lazy engine accessor (test seam)
# ---------------------------------------------------------------------------


def _get_engine():
    from core.jira_cloud_engine import get_jira_cloud_engine
    return get_jira_cloud_engine()


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CapabilitySummary(BaseModel):
    service: str
    endpoints: List[str]
    jira_url_present: bool
    jira_auth_present: bool
    status: str = Field(..., description="ok | empty | unavailable")


class IssueCreateRequest(BaseModel):
    """Mirrors Jira's POST /rest/api/3/issue body shape."""

    fields: Dict[str, Any] = Field(
        ...,
        description="Issue fields. Must include project.key, summary, issuetype.name; may include description, priority, assignee, labels.",
    )


class IssueCreateResponse(BaseModel):
    id: str
    key: str
    self: Optional[str] = None


class SearchRequest(BaseModel):
    jql: str = Field(..., description="JQL query string")
    startAt: int = Field(0, ge=0, description="Pagination offset")
    maxResults: int = Field(50, ge=1, le=1000, description="Max results to return")
    fields: Optional[List[str]] = Field(None, description="Field selector — None = all")


class TransitionRef(BaseModel):
    id: str


class TransitionRequest(BaseModel):
    transition: TransitionRef


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _raise_unavailable() -> None:
    raise HTTPException(
        status_code=503,
        detail={
            "error": "jira_cloud_unavailable",
            "message": "JIRA_URL and JIRA_AUTH environment variables are not configured",
        },
    )


def _map_jira_error(exc: Exception) -> HTTPException:
    """Translate a JiraCloudHTTPError (or unavailable) into an HTTPException."""
    from core.jira_cloud_engine import JiraCloudHTTPError, JiraCloudUnavailable

    if isinstance(exc, JiraCloudUnavailable):
        return HTTPException(
            status_code=503,
            detail={"error": "jira_cloud_unavailable", "message": str(exc)},
        )
    if isinstance(exc, JiraCloudHTTPError):
        # Pass auth/perm/not-found/conflict/rate-limit through; otherwise 502.
        passthrough = {400, 401, 403, 404, 409, 422, 429}
        status = exc.status_code if exc.status_code in passthrough else 502
        return HTTPException(
            status_code=status,
            detail={
                "error": "jira_upstream_error",
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
    summary="Jira Cloud capability summary",
)
def capability_summary() -> CapabilitySummary:
    """Return service identity, exposed endpoints, and configuration status."""
    engine = _get_engine()
    return CapabilitySummary(**engine.capability_summary())


@router.post(
    "/rest/api/3/issue",
    response_model=IssueCreateResponse,
    summary="Create a Jira issue",
)
def create_issue(req: IssueCreateRequest) -> IssueCreateResponse:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        body = engine.create_issue(req.fields)
    except Exception as exc:
        raise _map_jira_error(exc) from exc
    return IssueCreateResponse(
        id=str(body.get("id", "")),
        key=str(body.get("key", "")),
        self=body.get("self"),
    )


@router.get(
    "/rest/api/3/issue/{key}",
    summary="Fetch a Jira issue by key",
)
def get_issue(
    key: str,
    fields: Optional[str] = Query(None, description="Comma-separated field list"),
    expand: Optional[str] = Query(None, description="Comma-separated expand list"),
) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_issue(
            key,
            fields=[f.strip() for f in fields.split(",")] if fields else None,
            expand=[e.strip() for e in expand.split(",")] if expand else None,
        )
    except Exception as exc:
        raise _map_jira_error(exc) from exc


@router.post(
    "/rest/api/3/search",
    summary="JQL search",
)
def search_issues(req: SearchRequest) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.search(
            jql=req.jql,
            start_at=req.startAt,
            max_results=req.maxResults,
            fields=req.fields,
        )
    except Exception as exc:
        raise _map_jira_error(exc) from exc


@router.get(
    "/rest/api/3/issue/{key}/transitions",
    summary="List available transitions for an issue",
)
def list_transitions(key: str) -> Dict[str, Any]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.get_transitions(key)
    except Exception as exc:
        raise _map_jira_error(exc) from exc


@router.post(
    "/rest/api/3/issue/{key}/transitions",
    status_code=204,
    summary="Transition an issue",
)
def transition_issue(key: str, req: TransitionRequest) -> None:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        engine.transition_issue(key, req.transition.id)
    except Exception as exc:
        raise _map_jira_error(exc) from exc
    return None


@router.get(
    "/rest/api/3/project",
    summary="List projects",
)
def list_projects() -> List[Dict[str, Any]]:
    engine = _get_engine()
    if not engine.configured:
        _raise_unavailable()
    try:
        return engine.list_projects()
    except Exception as exc:
        raise _map_jira_error(exc) from exc
