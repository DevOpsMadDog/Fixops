"""Databricks REST Connector Router — ALDECI (2026-05-31).

Wraps the Databricks REST API 2.0/2.1 with live httpx calls for cluster
management, job orchestration, workspace browsing, and SQL warehouse
inspection against a real Databricks workspace.

Prefix: /api/v1/databricks
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/databricks/                         connector info / configured-status
  GET  /api/v1/databricks/clusters                 GET /api/2.0/clusters/list
  GET  /api/v1/databricks/jobs                     GET /api/2.1/jobs/list
  GET  /api/v1/databricks/runs/{run_id}            GET /api/2.1/jobs/runs/get
  GET  /api/v1/databricks/workspace/list           GET /api/2.0/workspace/list
  GET  /api/v1/databricks/warehouses               GET /api/2.0/sql/warehouses

NO MOCKS rule: when DATABRICKS_HOST or DATABRICKS_TOKEN are missing every
live endpoint returns HTTP 503 with ``{"error":"databricks_not_configured",
"needed":["DATABRICKS_HOST","DATABRICKS_TOKEN"]}``. We do not fabricate
cluster lists, job runs, workspace trees, or warehouse data ever.

Credentials
-----------
  DATABRICKS_HOST   — workspace hostname, e.g. ``adb-1234567890.azuredatabricks.net``
                      (scheme is optional; https:// is prepended if absent)
  DATABRICKS_TOKEN  — personal access token (PAT) or service-principal OAuth token
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_TIMEOUT = 10.0  # seconds — matches platform convention
_NOT_CONFIGURED_ERROR = "databricks_not_configured"
_NEEDED_VARS = ["DATABRICKS_HOST", "DATABRICKS_TOKEN"]

router = APIRouter(
    prefix="/api/v1/databricks",
    tags=["Databricks"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_creds() -> tuple[str, str] | tuple[None, None]:
    """Return (host_url, token) or (None, None) if either is missing."""
    host = os.environ.get("DATABRICKS_HOST", "").strip()
    token = os.environ.get("DATABRICKS_TOKEN", "").strip()
    if not host or not token:
        return None, None
    # Normalise: ensure https:// prefix, strip trailing slash
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    host = host.rstrip("/")
    return host, token


def _require_creds() -> tuple[str, str]:
    """Return (host_url, token) or raise HTTP 503 not_configured."""
    host, token = _get_creds()
    if host is None or token is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": _NEEDED_VARS,
            },
        )
    return host, token  # type: ignore[return-value]


def _auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _get(host: str, token: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Issue an authenticated GET against the Databricks workspace.

    Raises HTTPException on upstream HTTP errors or timeouts.
    Returns the parsed JSON body on success.
    """
    url = f"{host}{path}"
    headers = _auth_headers(token)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params or {})
    except httpx.TimeoutException as exc:
        _logger.warning("databricks_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "databricks_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("databricks_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "databricks_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "databricks_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        # Pass the upstream error body through honestly
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "databricks_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ConnectorInfoResponse(BaseModel):
    service: str = "Databricks REST API"
    version: str = "2.0/2.1"
    endpoints: List[str]
    databricks_host_present: bool
    databricks_token_present: bool
    status: str  # ok | partial | unavailable


class ClustersResponse(BaseModel):
    clusters: List[Dict[str, Any]] = Field(default_factory=list)


class JobsResponse(BaseModel):
    jobs: List[Dict[str, Any]] = Field(default_factory=list)
    has_more: bool = False
    next_page_token: Optional[str] = None


class RunResponse(BaseModel):
    model_config = {"extra": "allow"}


class WorkspaceListResponse(BaseModel):
    objects: List[Dict[str, Any]] = Field(default_factory=list)


class WarehousesResponse(BaseModel):
    warehouses: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# GET / — connector info (always returns 200, no creds required)
# ---------------------------------------------------------------------------


@router.get("/", response_model=ConnectorInfoResponse)
async def connector_info() -> ConnectorInfoResponse:
    """Connector capability summary — safe to call without credentials.

    Returns configured-status so the UI can surface actionable setup guidance
    without requiring a live Databricks workspace.
    """
    host_raw = os.environ.get("DATABRICKS_HOST", "").strip()
    token_raw = os.environ.get("DATABRICKS_TOKEN", "").strip()
    host_present = bool(host_raw)
    token_present = bool(token_raw)

    if host_present and token_present:
        status = "ok"
    elif host_present or token_present:
        status = "partial"
    else:
        status = "unavailable"

    _logger.info(
        "databricks_connector_info host_present=%s token_present=%s status=%s",
        host_present, token_present, status,
    )
    return ConnectorInfoResponse(
        endpoints=[
            "/clusters",
            "/jobs",
            "/runs/{run_id}",
            "/workspace/list",
            "/warehouses",
        ],
        databricks_host_present=host_present,
        databricks_token_present=token_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /clusters — Databricks REST 2.0 clusters/list
# ---------------------------------------------------------------------------


@router.get("/clusters", response_model=ClustersResponse)
async def list_clusters() -> ClustersResponse:
    """List all clusters in the Databricks workspace.

    Upstream: GET /api/2.0/clusters/list
    Returns 503 when DATABRICKS_HOST or DATABRICKS_TOKEN are unset.
    """
    host, token = _require_creds()
    data = await _get(host, token, "/api/2.0/clusters/list")
    clusters = data.get("clusters", [])
    _logger.info("databricks_list_clusters count=%d", len(clusters))
    return ClustersResponse(clusters=clusters)


# ---------------------------------------------------------------------------
# GET /jobs — Databricks REST 2.1 jobs/list
# ---------------------------------------------------------------------------


@router.get("/jobs", response_model=JobsResponse)
async def list_jobs(
    limit: int = Query(25, ge=1, le=100, description="Max jobs to return (1-100)"),
    page_token: Optional[str] = Query(None, max_length=2048, description="Pagination cursor"),
    expand_tasks: bool = Query(False, description="Include task details in response"),
) -> JobsResponse:
    """List jobs defined in the Databricks workspace.

    Upstream: GET /api/2.1/jobs/list
    Returns 503 when DATABRICKS_HOST or DATABRICKS_TOKEN are unset.
    """
    host, token = _require_creds()
    params: Dict[str, Any] = {"limit": limit, "expand_tasks": str(expand_tasks).lower()}
    if page_token:
        params["page_token"] = page_token

    data = await _get(host, token, "/api/2.1/jobs/list", params=params)
    jobs = data.get("jobs", [])
    _logger.info("databricks_list_jobs count=%d has_more=%s", len(jobs), data.get("has_more", False))
    return JobsResponse(
        jobs=jobs,
        has_more=data.get("has_more", False),
        next_page_token=data.get("next_page_token"),
    )


# ---------------------------------------------------------------------------
# GET /runs/{run_id} — Databricks REST 2.1 jobs/runs/get
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}", response_model=RunResponse)
async def get_run(
    run_id: int = Path(..., ge=1, description="Databricks job run ID"),
    include_history: bool = Query(False, description="Include repair history"),
) -> RunResponse:
    """Fetch details of a specific job run.

    Upstream: GET /api/2.1/jobs/runs/get?run_id=<id>
    Returns 503 when DATABRICKS_HOST or DATABRICKS_TOKEN are unset.
    """
    host, token = _require_creds()
    params: Dict[str, Any] = {
        "run_id": run_id,
        "include_history": str(include_history).lower(),
    }
    data = await _get(host, token, "/api/2.1/jobs/runs/get", params=params)
    _logger.info(
        "databricks_get_run run_id=%d state=%s",
        run_id, data.get("state", {}).get("life_cycle_state", "unknown"),
    )
    return RunResponse(**data)


# ---------------------------------------------------------------------------
# GET /workspace/list — Databricks REST 2.0 workspace/list
# ---------------------------------------------------------------------------


@router.get("/workspace/list", response_model=WorkspaceListResponse)
async def workspace_list(
    path: str = Query("/", max_length=1024, description="Absolute workspace path to list"),
) -> WorkspaceListResponse:
    """List objects at a workspace path (notebooks, directories, files, repos).

    Upstream: GET /api/2.0/workspace/list?path=<path>
    Returns 503 when DATABRICKS_HOST or DATABRICKS_TOKEN are unset.
    """
    host, token = _require_creds()
    data = await _get(host, token, "/api/2.0/workspace/list", params={"path": path})
    objects = data.get("objects", [])
    _logger.info("databricks_workspace_list path=%r count=%d", path, len(objects))
    return WorkspaceListResponse(objects=objects)


# ---------------------------------------------------------------------------
# GET /warehouses — Databricks REST 2.0 sql/warehouses
# ---------------------------------------------------------------------------


@router.get("/warehouses", response_model=WarehousesResponse)
async def list_warehouses() -> WarehousesResponse:
    """List SQL warehouses (formerly SQL endpoints) in the workspace.

    Upstream: GET /api/2.0/sql/warehouses
    Returns 503 when DATABRICKS_HOST or DATABRICKS_TOKEN are unset.
    """
    host, token = _require_creds()
    data = await _get(host, token, "/api/2.0/sql/warehouses")
    warehouses = data.get("warehouses", [])
    _logger.info("databricks_list_warehouses count=%d", len(warehouses))
    return WarehousesResponse(warehouses=warehouses)


__all__ = ["router"]
