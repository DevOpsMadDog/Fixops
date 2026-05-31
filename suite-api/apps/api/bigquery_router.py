"""GCP BigQuery Data Plane Connector Router — ALDECI (2026-05-31).

Wraps the BigQuery REST API v2 with live httpx calls for dataset discovery,
table enumeration, job inspection, and query execution against a real GCP
project.

Prefix: /api/v1/bigquery
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/bigquery/                             connector info / configured-status
  GET  /api/v1/bigquery/datasets                     GET /projects/{project}/datasets
  GET  /api/v1/bigquery/datasets/{dataset_id}/tables GET /projects/{project}/datasets/{dataset_id}/tables
  GET  /api/v1/bigquery/jobs                         GET /projects/{project}/jobs
  POST /api/v1/bigquery/queries                      POST /projects/{project}/queries

NO MOCKS rule: when GCP_BIGQUERY_ACCESS_TOKEN or GCP_PROJECT_ID are missing
every live endpoint returns HTTP 503 with ``{"error":"bigquery_not_configured",
"needed":["GCP_BIGQUERY_ACCESS_TOKEN","GCP_PROJECT_ID"]}``. We do not fabricate
dataset lists, table schemas, job records, or query results ever.

Credentials
-----------
  GCP_BIGQUERY_ACCESS_TOKEN — OAuth 2.0 Bearer token for the BigQuery API
  GCP_PROJECT_ID            — GCP project ID used to scope all requests
  GCP_BIGQUERY_LOCATION     — optional dataset location (default: US)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx
from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_TIMEOUT = 10.0  # seconds — matches platform convention
_NOT_CONFIGURED_ERROR = "bigquery_not_configured"
_NEEDED_VARS = ["GCP_BIGQUERY_ACCESS_TOKEN", "GCP_PROJECT_ID"]
_BQ_BASE = "https://bigquery.googleapis.com/bigquery/v2"

router = APIRouter(
    prefix="/api/v1/bigquery",
    tags=["BigQuery"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_creds() -> tuple[str, str, str] | tuple[None, None, None]:
    """Return (access_token, project_id, location) or (None, None, None) if missing."""
    token = os.environ.get("GCP_BIGQUERY_ACCESS_TOKEN", "").strip()
    project = os.environ.get("GCP_PROJECT_ID", "").strip()
    if not token or not project:
        return None, None, None
    location = os.environ.get("GCP_BIGQUERY_LOCATION", "US").strip() or "US"
    return token, project, location


def _require_creds() -> tuple[str, str, str]:
    """Return (access_token, project_id, location) or raise HTTP 503."""
    token, project, location = _get_creds()
    if token is None or project is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": _NEEDED_VARS,
            },
        )
    return token, project, location  # type: ignore[return-value]


def _auth_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


async def _get(token: str, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Issue an authenticated GET against the BigQuery REST API.

    Raises HTTPException on upstream HTTP errors or timeouts.
    Returns the parsed JSON body on success.
    """
    url = f"{_BQ_BASE}{path}"
    headers = _auth_headers(token)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params or {})
    except httpx.TimeoutException as exc:
        _logger.warning("bigquery_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "bigquery_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("bigquery_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "bigquery_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "bigquery_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "bigquery_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


async def _post(token: str, path: str, body: Dict[str, Any]) -> Any:
    """Issue an authenticated POST against the BigQuery REST API."""
    url = f"{_BQ_BASE}{path}"
    headers = _auth_headers(token)
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        _logger.warning("bigquery_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "bigquery_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("bigquery_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "bigquery_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "bigquery_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "bigquery_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ConnectorInfoResponse(BaseModel):
    service: str = "GCP BigQuery REST API v2"
    version: str = "v2"
    endpoints: List[str]
    access_token_present: bool
    project_id_present: bool
    location: str
    status: str  # ok | partial | unavailable


class DatasetsResponse(BaseModel):
    datasets: List[Dict[str, Any]] = Field(default_factory=list)
    next_page_token: Optional[str] = None


class TablesResponse(BaseModel):
    tables: List[Dict[str, Any]] = Field(default_factory=list)
    next_page_token: Optional[str] = None


class JobsResponse(BaseModel):
    jobs: List[Dict[str, Any]] = Field(default_factory=list)
    next_page_token: Optional[str] = None


class QueryResponse(BaseModel):
    model_config = {"extra": "allow"}


# ---------------------------------------------------------------------------
# GET / — connector info (always returns 200, no creds required)
# ---------------------------------------------------------------------------


@router.get("/", response_model=ConnectorInfoResponse)
async def connector_info() -> ConnectorInfoResponse:
    """Connector capability summary — safe to call without credentials.

    Returns configured-status so the UI can surface actionable setup guidance
    without requiring a live GCP project.
    """
    token_raw = os.environ.get("GCP_BIGQUERY_ACCESS_TOKEN", "").strip()
    project_raw = os.environ.get("GCP_PROJECT_ID", "").strip()
    location = os.environ.get("GCP_BIGQUERY_LOCATION", "US").strip() or "US"

    token_present = bool(token_raw)
    project_present = bool(project_raw)

    if token_present and project_present:
        status = "ok"
    elif token_present or project_present:
        status = "partial"
    else:
        status = "unavailable"

    _logger.info(
        "bigquery_connector_info token_present=%s project_present=%s status=%s",
        token_present, project_present, status,
    )
    return ConnectorInfoResponse(
        endpoints=[
            "/datasets",
            "/datasets/{dataset_id}/tables",
            "/jobs",
            "/queries",
        ],
        access_token_present=token_present,
        project_id_present=project_present,
        location=location,
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /datasets — BigQuery v2 projects/{project}/datasets
# ---------------------------------------------------------------------------


@router.get("/datasets", response_model=DatasetsResponse)
async def list_datasets() -> DatasetsResponse:
    """List all datasets in the configured GCP project.

    Upstream: GET /projects/{project}/datasets
    Returns 503 when GCP_BIGQUERY_ACCESS_TOKEN or GCP_PROJECT_ID are unset.
    """
    token, project, _location = _require_creds()
    data = await _get(token, f"/projects/{project}/datasets")
    datasets = data.get("datasets", [])
    _logger.info("bigquery_list_datasets project=%s count=%d", project, len(datasets))
    return DatasetsResponse(
        datasets=datasets,
        next_page_token=data.get("nextPageToken"),
    )


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}/tables — BigQuery v2 tables list
# ---------------------------------------------------------------------------


@router.get("/datasets/{dataset_id}/tables", response_model=TablesResponse)
async def list_tables(
    dataset_id: str = Path(..., min_length=1, max_length=1024, description="BigQuery dataset ID"),
) -> TablesResponse:
    """List all tables in a dataset.

    Upstream: GET /projects/{project}/datasets/{dataset_id}/tables
    Returns 503 when GCP_BIGQUERY_ACCESS_TOKEN or GCP_PROJECT_ID are unset.
    """
    token, project, _location = _require_creds()
    data = await _get(token, f"/projects/{project}/datasets/{dataset_id}/tables")
    tables = data.get("tables", [])
    _logger.info(
        "bigquery_list_tables project=%s dataset=%s count=%d",
        project, dataset_id, len(tables),
    )
    return TablesResponse(
        tables=tables,
        next_page_token=data.get("nextPageToken"),
    )


# ---------------------------------------------------------------------------
# GET /jobs — BigQuery v2 projects/{project}/jobs
# ---------------------------------------------------------------------------


@router.get("/jobs", response_model=JobsResponse)
async def list_jobs() -> JobsResponse:
    """List recent jobs in the configured GCP project.

    Upstream: GET /projects/{project}/jobs
    Returns 503 when GCP_BIGQUERY_ACCESS_TOKEN or GCP_PROJECT_ID are unset.
    """
    token, project, _location = _require_creds()
    data = await _get(token, f"/projects/{project}/jobs")
    jobs = data.get("jobs", [])
    _logger.info("bigquery_list_jobs project=%s count=%d", project, len(jobs))
    return JobsResponse(
        jobs=jobs,
        next_page_token=data.get("nextPageToken"),
    )


# ---------------------------------------------------------------------------
# POST /queries — BigQuery v2 projects/{project}/queries
# ---------------------------------------------------------------------------


@router.post("/queries", response_model=QueryResponse)
async def run_query(
    body: Dict[str, Any] = Body(
        ...,
        examples=[
            {
                "query": "SELECT * FROM `project.dataset.table` LIMIT 10",
                "useLegacySql": False,
                "maxResults": 100,
            }
        ],
    ),
) -> QueryResponse:
    """Execute a synchronous BigQuery query.

    Forwards the JSON body to: POST /projects/{project}/queries
    Expected body fields: query (required), useLegacySql (bool), maxResults (int).
    Returns 503 when GCP_BIGQUERY_ACCESS_TOKEN or GCP_PROJECT_ID are unset.
    """
    token, project, location = _require_creds()

    # Build upstream payload — only forward recognised fields, merge location
    upstream_body: Dict[str, Any] = {
        "query": body.get("query", ""),
        "useLegacySql": body.get("useLegacySql", False),
        "location": body.get("location", location),
    }
    if "maxResults" in body:
        upstream_body["maxResults"] = body["maxResults"]

    _logger.info(
        "bigquery_run_query project=%s query_len=%d use_legacy=%s",
        project, len(str(upstream_body.get("query", ""))), upstream_body["useLegacySql"],
    )
    data = await _post(token, f"/projects/{project}/queries", upstream_body)
    return QueryResponse(**data)


__all__ = ["router"]
