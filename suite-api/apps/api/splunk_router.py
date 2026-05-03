"""Splunk SIEM Router — ALDECI.

Prefix: /api/v1/splunk
Scope:  read:scans (mounted via platform_app)

Routes:
  GET    /                                          capability summary
  POST   /services/search/jobs                      create a search job
  GET    /services/search/jobs/{sid}                fetch job metadata
  GET    /services/search/jobs/{sid}/results        fetch results page
  DELETE /services/search/jobs/{sid}                cancel a job
  GET    /services/saved/searches                   list saved searches
  POST   /services/saved/searches/{name}/dispatch   dispatch saved search

Returns 503 on lookup endpoints when SPLUNK_URL/SPLUNK_TOKEN unset.
NO MOCKS — engine raises RuntimeError → mapped to 503 unavailable.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/splunk", tags=["Splunk SIEM"])


def _engine():
    from core.splunk_siem_engine import get_splunk_siem_engine
    return get_splunk_siem_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SearchJobRequest(BaseModel):
    search: str = Field(..., min_length=1, max_length=8192, description="SPL search string")
    earliest_time: Optional[str] = Field(default=None, max_length=64)
    latest_time: Optional[str] = Field(default=None, max_length=64)
    exec_mode: str = Field(default="normal", pattern="^(normal|blocking|oneshot)$")
    output_mode: str = Field(default="json", pattern="^(json|csv|xml)$")


class DispatchSavedSearchRequest(BaseModel):
    trigger_actions: int = Field(default=1, ge=0, le=1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"splunk unavailable: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"splunk error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"splunk transport error: {exc}") from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Splunk integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Search jobs
# ---------------------------------------------------------------------------


@router.post("/services/search/jobs")
def create_search_job(req: SearchJobRequest) -> Dict[str, Any]:
    """Create a Splunk search job."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.create_search_job(
            search=req.search,
            earliest_time=req.earliest_time,
            latest_time=req.latest_time,
            exec_mode=req.exec_mode,
            output_mode=req.output_mode,
        )
    )


@router.get("/services/search/jobs/{sid}")
def get_search_job(sid: str) -> Dict[str, Any]:
    """Fetch job metadata (isDone, dispatchState, eventCount, etc)."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_search_job(sid))


@router.get("/services/search/jobs/{sid}/results")
def get_search_job_results(
    sid: str,
    output_mode: str = Query(default="json", pattern="^(json|csv|xml)$"),
    offset: int = Query(default=0, ge=0),
    count: int = Query(default=100, ge=0, le=50000),
) -> Dict[str, Any]:
    """Fetch a page of search results."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.get_search_job_results(
            sid=sid,
            output_mode=output_mode,
            offset=offset,
            count=count,
        )
    )


@router.delete("/services/search/jobs/{sid}")
def delete_search_job(sid: str) -> Dict[str, Any]:
    """Cancel/delete a search job."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.delete_search_job(sid))


# ---------------------------------------------------------------------------
# Saved searches
# ---------------------------------------------------------------------------


@router.get("/services/saved/searches")
def list_saved_searches(count: int = Query(default=30, ge=1, le=1000)) -> Dict[str, Any]:
    """List saved searches."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.list_saved_searches(count=count))


@router.post("/services/saved/searches/{name}/dispatch")
def dispatch_saved_search(name: str, req: DispatchSavedSearchRequest) -> Dict[str, Any]:
    """Dispatch a saved search (returns sid)."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.dispatch_saved_search(name=name, trigger_actions=req.trigger_actions)
    )


__all__ = ["router"]
