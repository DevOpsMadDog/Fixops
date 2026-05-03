"""Sumo Logic Cloud SIEM Router — ALDECI.

Prefix: /api/v1/sumologic
Scope:  read:scans (mounted via platform_app)

Routes:
  GET    /                                              capability summary
  POST   /api/v1/search/jobs                            create search job
  GET    /api/v1/search/jobs/{job_id}                   job state + counts
  GET    /api/v1/search/jobs/{job_id}/messages          message page
  GET    /api/v1/search/jobs/{job_id}/records           aggregate records
  DELETE /api/v1/search/jobs/{job_id}                   cancel job
  GET    /api/v1/dashboards                             list dashboards
  GET    /api/v1/collectors                             list collectors
  GET    /api/v1/collectors/{cid}/sources               nested sources
  GET    /api/sec/v1/insights                           Cloud SIEM insights
  GET    /api/v1/health-events                          cluster health events

Returns 503 on lookup endpoints when SUMO_ACCESS_ID/SUMO_ACCESS_KEY unset.
NO MOCKS — engine raises RuntimeError → mapped to 503 unavailable.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sumologic", tags=["Sumo Logic Cloud SIEM"])


def _engine():
    from core.sumologic_siem_engine import get_sumologic_siem_engine
    return get_sumologic_siem_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SearchJobRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=8192, description="Sumo query")
    from_: str = Field(..., alias="from", min_length=1, max_length=64,
                       description="ISO-8601 start time")
    to: str = Field(..., min_length=1, max_length=64,
                    description="ISO-8601 end time")
    timeZone: str = Field(default="UTC", min_length=1, max_length=64)
    byReceiptTime: Optional[bool] = Field(default=None)
    autoParsingMode: Optional[str] = Field(
        default=None, pattern="^(intelligent|performance)$"
    )

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(
            status_code=503, detail=f"sumologic unavailable: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(
            status_code=status, detail=f"sumologic error: {exc}"
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"sumologic transport error: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Sumo Logic integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Search Job API
# ---------------------------------------------------------------------------


@router.post("/api/v1/search/jobs")
def create_search_job(req: SearchJobRequest) -> Dict[str, Any]:
    """Create a Sumo Logic search job."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.create_search_job(
            query=req.query,
            from_ts=req.from_,
            to_ts=req.to,
            time_zone=req.timeZone,
            by_receipt_time=req.byReceiptTime,
            auto_parsing_mode=req.autoParsingMode,
        )
    )


@router.get("/api/v1/search/jobs/{job_id}")
def get_search_job(job_id: str) -> Dict[str, Any]:
    """Fetch search job state, message/record counts, and pending warnings."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_search_job(job_id))


@router.get("/api/v1/search/jobs/{job_id}/messages")
def get_search_job_messages(
    job_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=10000),
) -> Dict[str, Any]:
    """Fetch a page of raw messages for a search job."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.get_search_job_messages(
            job_id=job_id, offset=offset, limit=limit
        )
    )


@router.get("/api/v1/search/jobs/{job_id}/records")
def get_search_job_records(
    job_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=10000),
) -> Dict[str, Any]:
    """Fetch a page of aggregate records for a search job (when query aggregates)."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.get_search_job_records(
            job_id=job_id, offset=offset, limit=limit
        )
    )


@router.delete("/api/v1/search/jobs/{job_id}")
def delete_search_job(job_id: str) -> Dict[str, Any]:
    """Cancel/delete a search job."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.delete_search_job(job_id))


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------


@router.get("/api/v1/dashboards")
def list_dashboards(
    limit: int = Query(default=100, ge=1, le=1000),
    token: Optional[str] = Query(default=None, max_length=512),
) -> Dict[str, Any]:
    """List dashboards (paginated via opaque cursor token)."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_dashboards(limit=limit, token=token)
    )


# ---------------------------------------------------------------------------
# Collectors + sources
# ---------------------------------------------------------------------------


@router.get("/api/v1/collectors")
def list_collectors(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List collectors (alive, ephemeral, version, etc)."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_collectors(limit=limit, offset=offset)
    )


@router.get("/api/v1/collectors/{collector_id}/sources")
def list_collector_sources(collector_id: str) -> Dict[str, Any]:
    """List sources nested under a collector."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_collector_sources(collector_id)
    )


# ---------------------------------------------------------------------------
# Cloud SIEM insights
# ---------------------------------------------------------------------------


@router.get("/api/sec/v1/insights")
def list_insights(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    q: Optional[str] = Query(default=None, max_length=2048),
) -> Dict[str, Any]:
    """List Cloud SIEM detection insights."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_insights(limit=limit, offset=offset, q=q)
    )


# ---------------------------------------------------------------------------
# Health events
# ---------------------------------------------------------------------------


@router.get("/api/v1/health-events")
def list_health_events(
    limit: int = Query(default=100, ge=1, le=1000),
    token: Optional[str] = Query(default=None, max_length=512),
) -> Dict[str, Any]:
    """List cluster/source health events."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_health_events(limit=limit, token=token)
    )


__all__ = ["router"]
