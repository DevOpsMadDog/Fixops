"""Harness CD Platform Router — ALDECI.

Wraps ``core.harness_cd_engine.HarnessCDEngine`` with REST endpoints that
mirror the Harness CD (NextGen) v1 surface.

Prefix: /api/v1/harness
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/harness/                                       capability summary
  GET  /api/v1/harness/pipeline/api/pipelines                 list pipelines
  POST /api/v1/harness/pipeline/api/pipelines/execute/{id}    execute pipeline
  GET  /api/v1/harness/pipeline/api/pipelines/execution/{id}  fetch execution
  GET  /api/v1/harness/ng/api/services                        list services
  GET  /api/v1/harness/ng/api/environments                    list environments
  POST /api/v1/harness/ng/api/connectors                      create connector

NO MOCKS rule: when ``HARNESS_API_KEY`` and/or ``HARNESS_ACCOUNT_ID`` are
unset, capability summary returns ``status="unavailable"`` and every live
call returns HTTP 503.  We never fabricate pipelines or executions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/harness",
    tags=["Harness CD"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.harness_cd_engine import get_harness_cd_engine

    return get_harness_cd_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    api_key_present: bool
    account_id_present: bool
    base_url: str
    status: str  # ok | empty | unavailable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    HarnessUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError              -> 422 (input validation)
    """
    from core.harness_cd_engine import HarnessUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HarnessUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without Harness credentials."""
    eng = _engine()
    api_key = eng.api_key_present()
    account = eng.account_id_present()
    if not (api_key and account):
        status = "unavailable"
    else:
        status = "empty"  # no in-process cache; live calls populate
    return CapabilityResponse(
        service="Harness CD",
        endpoints=[
            "/pipeline/api/pipelines",
            "/pipeline/api/pipelines/execute",
            "/ng/api/services",
            "/ng/api/environments",
            "/pipeline/api/pipelines/execution",
        ],
        api_key_present=api_key,
        account_id_present=account,
        base_url=eng.base_url(),
        status=status,
    )


@router.get("/pipeline/api/pipelines")
async def list_pipelines(
    accountIdentifier: str = Query("", description="Harness account ID (overrides env)"),
    projectIdentifier: str = Query(..., description="Harness project identifier"),
    orgIdentifier: str = Query(..., description="Harness org identifier"),
    size: Optional[int] = Query(None, ge=1, le=1000),
    page: Optional[int] = Query(None, ge=0),
) -> Dict[str, Any]:
    """List pipelines for a Harness project."""
    eng = _engine()
    return _serve(
        lambda: eng.list_pipelines(
            account_identifier=accountIdentifier or None,
            project_identifier=projectIdentifier,
            org_identifier=orgIdentifier,
            size=size,
            page=page,
        )
    )


@router.post("/pipeline/api/pipelines/execute/{pipeline_id}")
async def execute_pipeline(
    request: Request,
    pipeline_id: str = Path(..., description="Pipeline identifier"),
    accountIdentifier: str = Query("", description="Harness account ID"),
    projectIdentifier: str = Query(..., description="Harness project identifier"),
    orgIdentifier: str = Query(..., description="Harness org identifier"),
) -> Dict[str, Any]:
    """Trigger pipeline execution.

    Body is the runtime variables YAML (Content-Type: application/yaml is
    forwarded to Harness verbatim).
    """
    raw = await request.body()
    runtime_yaml = raw.decode("utf-8", errors="replace") if raw else ""
    eng = _engine()
    return _serve(
        lambda: eng.execute_pipeline(
            pipeline_id=pipeline_id,
            account_identifier=accountIdentifier or None,
            project_identifier=projectIdentifier,
            org_identifier=orgIdentifier,
            runtime_yaml=runtime_yaml,
        )
    )


@router.get("/pipeline/api/pipelines/execution/{exec_id}")
async def get_execution(
    exec_id: str = Path(..., description="Execution UUID (planExecutionId)"),
    accountIdentifier: str = Query("", description="Harness account ID"),
    projectIdentifier: str = Query("", description="Harness project identifier"),
    orgIdentifier: str = Query("", description="Harness org identifier"),
) -> Dict[str, Any]:
    """Fetch pipeline execution summary."""
    eng = _engine()
    return _serve(
        lambda: eng.get_execution(
            exec_id=exec_id,
            account_identifier=accountIdentifier or None,
            project_identifier=projectIdentifier or None,
            org_identifier=orgIdentifier or None,
        )
    )


@router.get("/ng/api/services")
async def list_services(
    accountIdentifier: str = Query("", description="Harness account ID"),
    orgIdentifier: str = Query(..., description="Harness org identifier"),
    projectIdentifier: str = Query(..., description="Harness project identifier"),
) -> Dict[str, Any]:
    """List Harness services (deployable units)."""
    eng = _engine()
    return _serve(
        lambda: eng.list_services(
            account_identifier=accountIdentifier or None,
            project_identifier=projectIdentifier,
            org_identifier=orgIdentifier,
        )
    )


@router.get("/ng/api/environments")
async def list_environments(
    accountIdentifier: str = Query("", description="Harness account ID"),
    orgIdentifier: str = Query(..., description="Harness org identifier"),
    projectIdentifier: str = Query(..., description="Harness project identifier"),
) -> Dict[str, Any]:
    """List Harness environments (Production / PreProduction)."""
    eng = _engine()
    return _serve(
        lambda: eng.list_environments(
            account_identifier=accountIdentifier or None,
            project_identifier=projectIdentifier,
            org_identifier=orgIdentifier,
        )
    )


@router.post("/ng/api/connectors")
async def create_connector(
    body: Dict[str, Any] = Body(..., description="Harness connector config"),
    accountIdentifier: str = Query("", description="Harness account ID"),
) -> Dict[str, Any]:
    """Create a Harness connector (Git, Cloud, Secret-Manager, …)."""
    eng = _engine()
    return _serve(
        lambda: eng.create_connector(
            connector=body, account_identifier=accountIdentifier or None
        )
    )
