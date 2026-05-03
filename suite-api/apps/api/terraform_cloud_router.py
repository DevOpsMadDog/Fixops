"""ALDECI Terraform Cloud router - REAL httpx only, NO MOCKS.

Mounted at ``/api/v1/terraform-cloud`` under the ``read:scans`` scope.

Endpoints
---------
GET  /                                                                  - capability summary
GET  /api/v2/organizations/{org}/workspaces                             - list workspaces
GET  /api/v2/workspaces/{ws_id}/runs                                    - list workspace runs
POST /api/v2/runs                                                       - create run
POST /api/v2/runs/{run_id}/actions/apply                                - apply run
POST /api/v2/runs/{run_id}/actions/cancel                               - cancel run
POST /api/v2/runs/{run_id}/actions/discard                              - discard run
GET  /api/v2/workspaces/{ws_id}/current-state-version                   - current state version
GET  /api/v2/policies                                                   - list sentinel/OPA policies

When TFC_TOKEN is not set, every lookup endpoint returns HTTP 503 and the
capability summary still responds 200 with ``status="unavailable"``.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.terraform_cloud_engine import (
    TerraformCloudUnavailableError,
    get_terraform_cloud_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/terraform-cloud",
    tags=["terraform-cloud"],
    dependencies=[Depends(api_key_auth)],
)


# --------------------------------------------------------------- Pydantic


class _RunWorkspaceRef(BaseModel):
    type: str = "workspaces"
    id: str


class _RunRelationships(BaseModel):
    workspace: Dict[str, _RunWorkspaceRef]


class _RunAttributes(BaseModel):
    message: Optional[str] = None
    is_destroy: Optional[bool] = Field(default=None, alias="is-destroy")
    refresh_only: Optional[bool] = Field(default=None, alias="refresh-only")
    plan_only: Optional[bool] = Field(default=None, alias="plan-only")
    target_addrs: Optional[list] = Field(default=None, alias="target-addrs")

    model_config = {"populate_by_name": True}


class _RunData(BaseModel):
    type: str = "runs"
    attributes: Optional[_RunAttributes] = None
    relationships: _RunRelationships


class RunCreateRequest(BaseModel):
    data: _RunData


class RunActionRequest(BaseModel):
    comment: Optional[str] = None


# ------------------------------------------------------------------ helpers


def _to_503(exc: TerraformCloudUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("/", summary="Terraform Cloud capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    return eng.capability_summary()


@router.get(
    "/api/v2/organizations/{org}/workspaces",
    summary="List Terraform Cloud workspaces in an organization",
)
def list_workspaces(
    org: str,
    page_number: Optional[int] = Query(None, alias="page[number]", ge=1),
    page_size: Optional[int] = Query(None, alias="page[size]", ge=1, le=100),
    search_name: Optional[str] = Query(None, alias="search[name]"),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    try:
        return eng.list_workspaces(
            org=org,
            page_number=page_number,
            page_size=page_size,
            search_name=search_name,
        )
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/workspaces/{ws_id}/runs",
    summary="List runs for a Terraform Cloud workspace",
)
def list_workspace_runs(
    ws_id: str,
    page_size: Optional[int] = Query(None, alias="page[size]", ge=1, le=100),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    try:
        return eng.list_workspace_runs(ws_id=ws_id, page_size=page_size)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/v2/runs",
    summary="Create a Terraform Cloud run",
)
def create_run(body: RunCreateRequest = Body(...)) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    payload = body.dict(by_alias=True, exclude_none=True)
    try:
        return eng.create_run(payload)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/v2/runs/{run_id}/actions/apply",
    summary="Apply a confirmed Terraform Cloud run",
)
def apply_run(
    run_id: str,
    body: Optional[RunActionRequest] = Body(default=None),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    comment = body.comment if body else None
    try:
        return eng.apply_run(run_id=run_id, comment=comment)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/v2/runs/{run_id}/actions/cancel",
    summary="Cancel a Terraform Cloud run",
)
def cancel_run(
    run_id: str,
    body: Optional[RunActionRequest] = Body(default=None),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    comment = body.comment if body else None
    try:
        return eng.cancel_run(run_id=run_id, comment=comment)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.post(
    "/api/v2/runs/{run_id}/actions/discard",
    summary="Discard a Terraform Cloud run",
)
def discard_run(
    run_id: str,
    body: Optional[RunActionRequest] = Body(default=None),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    comment = body.comment if body else None
    try:
        return eng.discard_run(run_id=run_id, comment=comment)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/workspaces/{ws_id}/current-state-version",
    summary="Get the current state version for a Terraform Cloud workspace",
)
def current_state_version(ws_id: str) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    try:
        return eng.current_state_version(ws_id=ws_id)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


@router.get(
    "/api/v2/policies",
    summary="List Terraform Cloud sentinel/OPA policies",
)
def list_policies(
    filter_org: Optional[str] = Query(None, alias="filter[organization][name]"),
) -> Dict[str, Any]:
    eng = get_terraform_cloud_engine()
    try:
        return eng.list_policies(org=filter_org)
    except TerraformCloudUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
