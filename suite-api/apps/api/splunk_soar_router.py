"""Splunk SOAR (Phantom) REST Router — ALDECI.

Prefix: /api/v1/splunk-soar-rest
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                                    capability summary
  GET   /rest/playbook                       list playbooks
  GET   /rest/container                      list containers (incidents)
  GET   /rest/container/{container_id}       single container detail
  POST  /rest/playbook_run                   trigger playbook on container
  GET   /rest/playbook_run/{run_id}          playbook run status
  GET   /rest/action_run                     list action runs
  GET   /rest/asset                          list configured assets

Returns 503 on lookup endpoints when SPLUNK_SOAR_URL/SPLUNK_SOAR_TOKEN
unset. NO MOCKS — engine raises RuntimeError → mapped to 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/splunk-soar-rest",
    tags=["Splunk SOAR (Phantom)"],
)


def _engine():
    from core.splunk_soar_engine import get_splunk_soar_engine
    return get_splunk_soar_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class PlaybookRunRequest(BaseModel):
    playbook_id: int = Field(..., ge=1, description="Splunk SOAR playbook id")
    container_id: int = Field(..., ge=1, description="Container id to act on")
    scope: str = Field(default="new", pattern=r"^(all|new)$")
    run: bool = Field(default=True)


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
            status_code=503, detail=f"splunk-soar unavailable: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(
            status_code=status, detail=f"splunk-soar error: {exc}"
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"splunk-soar transport error: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Splunk SOAR integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


@router.get("/rest/playbook")
def list_playbooks(
    _filter_active: Optional[bool] = Query(default=True, alias="_filter_active"),
    page_size: int = Query(default=100, ge=1, le=1000),
    page: int = Query(default=0, ge=0),
    include_expensive: bool = Query(default=False),
) -> Dict[str, Any]:
    """List Splunk SOAR playbooks, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_playbooks(
            active=_filter_active,
            page=page,
            page_size=page_size,
            include_expensive=include_expensive,
        )
    )


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------


@router.get("/rest/container")
def list_containers(
    _filter_status: Optional[str] = Query(
        default=None,
        alias="_filter_status",
        max_length=64,
        description="new|open|closed|in_progress",
    ),
    _filter_severity: Optional[str] = Query(
        default=None,
        alias="_filter_severity",
        max_length=64,
        description="high|medium|low",
    ),
    page_size: int = Query(default=100, ge=1, le=1000),
    page: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List Splunk SOAR containers (incidents), paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_containers(
            status=_filter_status,
            severity=_filter_severity,
            page=page,
            page_size=page_size,
        )
    )


@router.get("/rest/container/{container_id}")
def get_container(
    container_id: str = Path(..., min_length=1, max_length=64),
) -> Dict[str, Any]:
    """Return single Splunk SOAR container detail."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_container(container_id))


# ---------------------------------------------------------------------------
# Playbook runs
# ---------------------------------------------------------------------------


@router.post("/rest/playbook_run")
def trigger_playbook_run(req: PlaybookRunRequest) -> Dict[str, Any]:
    """Trigger a playbook on a container; returns ``{playbook_run_id}``."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.trigger_playbook_run(
            playbook_id=req.playbook_id,
            container_id=req.container_id,
            scope=req.scope,
            run=req.run,
        )
    )


@router.get("/rest/playbook_run/{run_id}")
def get_playbook_run(
    run_id: str = Path(..., min_length=1, max_length=64),
) -> Dict[str, Any]:
    """Return playbook run status/result."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_playbook_run(run_id))


# ---------------------------------------------------------------------------
# Action runs
# ---------------------------------------------------------------------------


@router.get("/rest/action_run")
def list_action_runs(
    _filter_status: Optional[str] = Query(
        default=None,
        alias="_filter_status",
        max_length=64,
        description="running|success|failed|pending|cancelled",
    ),
    _filter_container_id: Optional[int] = Query(
        default=None,
        alias="_filter_container_id",
        ge=1,
    ),
    page_size: int = Query(default=100, ge=1, le=1000),
    page: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List Splunk SOAR action runs, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_action_runs(
            status=_filter_status,
            container_id=_filter_container_id,
            page=page,
            page_size=page_size,
        )
    )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@router.get("/rest/asset")
def list_assets(
    _filter_active: Optional[bool] = Query(default=True, alias="_filter_active"),
    page_size: int = Query(default=100, ge=1, le=1000),
    page: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List Splunk SOAR configured assets, paginated."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_assets(
            active=_filter_active,
            page=page,
            page_size=page_size,
        )
    )
