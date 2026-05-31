"""MongoDB Atlas Admin API Connector Router — ALDECI (2026-05-31).

Wraps the MongoDB Atlas Administration API v2 with live httpx calls using
HTTP Digest authentication (public/private key pair). Provides project
listing, cluster inspection, database user enumeration, audit log retrieval,
and IP allowlist access for security-relevant posture data.

Prefix: /api/v1/mongodb-atlas
Auth:   api_key_auth dependency (read:scans scope at registration)

Routes:
  GET  /api/v1/mongodb-atlas/                                  connector info / configured-status
  GET  /api/v1/mongodb-atlas/orgs/{org_id}/projects            list Atlas projects in an org
  GET  /api/v1/mongodb-atlas/groups/{group_id}/clusters        list clusters in a project
  GET  /api/v1/mongodb-atlas/groups/{group_id}/databaseUsers   list database users
  GET  /api/v1/mongodb-atlas/groups/{group_id}/auditLog        audit log entries (security findings source)
  GET  /api/v1/mongodb-atlas/groups/{group_id}/accessList      IP allowlist entries

NO MOCKS rule: when MONGODB_ATLAS_PUBLIC_KEY or MONGODB_ATLAS_PRIVATE_KEY are
missing every live endpoint returns HTTP 503 with
``{"error":"mongodb_atlas_not_configured","needed":[...]}}``. We never
fabricate project lists, cluster data, user records, or audit events.

Credentials
-----------
  MONGODB_ATLAS_PUBLIC_KEY   — Atlas API public key (username for Digest auth)
  MONGODB_ATLAS_PRIVATE_KEY  — Atlas API private key (password for Digest auth)
  MONGODB_ATLAS_ORG_ID       — optional default org ID (informational only)
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

_TIMEOUT = 10.0
_NOT_CONFIGURED_ERROR = "mongodb_atlas_not_configured"
_NEEDED_VARS = ["MONGODB_ATLAS_PUBLIC_KEY", "MONGODB_ATLAS_PRIVATE_KEY"]
_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"
_ACCEPT_HEADER = "application/vnd.atlas.2023-01-01+json"

router = APIRouter(
    prefix="/api/v1/mongodb-atlas",
    tags=["MongoDB Atlas"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_creds() -> tuple[str, str] | tuple[None, None]:
    """Return (public_key, private_key) or (None, None) if either is missing."""
    pub = os.environ.get("MONGODB_ATLAS_PUBLIC_KEY", "").strip()
    priv = os.environ.get("MONGODB_ATLAS_PRIVATE_KEY", "").strip()
    if not pub or not priv:
        return None, None
    return pub, priv


def _require_creds() -> tuple[str, str]:
    """Return (public_key, private_key) or raise HTTP 503 not_configured."""
    pub, priv = _get_creds()
    if pub is None or priv is None:
        raise HTTPException(
            status_code=503,
            detail={
                "error": _NOT_CONFIGURED_ERROR,
                "needed": _NEEDED_VARS,
            },
        )
    return pub, priv  # type: ignore[return-value]


async def _get(
    pub: str,
    priv: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
) -> Any:
    """Issue an authenticated GET against the Atlas Admin API.

    Uses HTTP Digest auth (public_key:private_key). Atlas requires the
    ``Accept: application/vnd.atlas.2023-01-01+json`` header on every call.

    Raises HTTPException on upstream HTTP errors or timeouts.
    Returns the parsed JSON body on success.
    """
    url = f"{_BASE_URL}{path}"
    headers = {"Accept": _ACCEPT_HEADER}
    try:
        async with httpx.AsyncClient(
            timeout=_TIMEOUT,
            auth=httpx.DigestAuth(pub, priv),
        ) as client:
            resp = await client.get(url, headers=headers, params=params or {})
    except httpx.TimeoutException as exc:
        _logger.warning("mongodb_atlas_timeout path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=504,
            detail={"error": "mongodb_atlas_timeout", "path": path},
        ) from exc
    except httpx.HTTPError as exc:
        _logger.warning("mongodb_atlas_http_error path=%s exc=%s", path, exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "mongodb_atlas_upstream_error", "path": path},
        ) from exc

    if resp.status_code >= 400:
        _logger.warning(
            "mongodb_atlas_upstream_error path=%s status=%d body=%.200s",
            path, resp.status_code, resp.text,
        )
        try:
            detail = resp.json()
        except Exception:
            detail = {"error": "mongodb_atlas_upstream_error", "status": resp.status_code}
        raise HTTPException(status_code=resp.status_code, detail=detail)

    return resp.json()


# ---------------------------------------------------------------------------
# Pydantic response schemas
# ---------------------------------------------------------------------------


class ConnectorInfoResponse(BaseModel):
    service: str = "MongoDB Atlas Admin API"
    version: str = "v2"
    endpoints: List[str]
    public_key_present: bool
    private_key_present: bool
    org_id_present: bool
    status: str  # ok | partial | unavailable


class ProjectsResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0


class ClustersResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0


class DatabaseUsersResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0


class AuditLogResponse(BaseModel):
    auditLog: Dict[str, Any] = Field(default_factory=dict)


class AccessListResponse(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_count: int = 0


# ---------------------------------------------------------------------------
# GET / — connector info (always returns 200, no creds required)
# ---------------------------------------------------------------------------


@router.get("/", response_model=ConnectorInfoResponse)
async def connector_info() -> ConnectorInfoResponse:
    """Connector capability summary — safe to call without credentials.

    Returns configured-status so the UI can surface actionable setup guidance
    without requiring a live Atlas workspace.
    """
    pub_raw = os.environ.get("MONGODB_ATLAS_PUBLIC_KEY", "").strip()
    priv_raw = os.environ.get("MONGODB_ATLAS_PRIVATE_KEY", "").strip()
    org_raw = os.environ.get("MONGODB_ATLAS_ORG_ID", "").strip()

    pub_present = bool(pub_raw)
    priv_present = bool(priv_raw)
    org_present = bool(org_raw)

    if pub_present and priv_present:
        status = "ok"
    elif pub_present or priv_present:
        status = "partial"
    else:
        status = "unavailable"

    _logger.info(
        "mongodb_atlas_connector_info pub_present=%s priv_present=%s status=%s",
        pub_present, priv_present, status,
    )
    return ConnectorInfoResponse(
        endpoints=[
            "/orgs/{org_id}/projects",
            "/groups/{group_id}/clusters",
            "/groups/{group_id}/databaseUsers",
            "/groups/{group_id}/auditLog",
            "/groups/{group_id}/accessList",
        ],
        public_key_present=pub_present,
        private_key_present=priv_present,
        org_id_present=org_present,
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /orgs/{org_id}/projects — list projects in an organization
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}/projects", response_model=ProjectsResponse)
async def list_projects(
    org_id: str = Path(..., min_length=1, max_length=256, description="Atlas organization ID"),
    items_per_page: int = Query(100, ge=1, le=500, description="Results per page"),
    page_num: int = Query(1, ge=1, description="Page number (1-indexed)"),
) -> ProjectsResponse:
    """List Atlas projects (groups) belonging to the given organization.

    Upstream: GET /orgs/{org_id}/groups
    Returns 503 when public or private key are unset.
    """
    pub, priv = _require_creds()
    params: Dict[str, Any] = {"itemsPerPage": items_per_page, "pageNum": page_num}
    data = await _get(pub, priv, f"/orgs/{org_id}/groups", params=params)
    results = data.get("results", [])
    _logger.info("mongodb_atlas_list_projects org_id=%s count=%d", org_id, len(results))
    return ProjectsResponse(
        results=results,
        total_count=data.get("totalCount", len(results)),
    )


# ---------------------------------------------------------------------------
# GET /groups/{group_id}/clusters — list clusters in a project
# ---------------------------------------------------------------------------


@router.get("/groups/{group_id}/clusters", response_model=ClustersResponse)
async def list_clusters(
    group_id: str = Path(..., min_length=1, max_length=256, description="Atlas project (group) ID"),
) -> ClustersResponse:
    """List all clusters in the specified Atlas project.

    Upstream: GET /groups/{group_id}/clusters
    Returns 503 when public or private key are unset.
    """
    pub, priv = _require_creds()
    data = await _get(pub, priv, f"/groups/{group_id}/clusters")
    results = data.get("results", [])
    _logger.info("mongodb_atlas_list_clusters group_id=%s count=%d", group_id, len(results))
    return ClustersResponse(
        results=results,
        total_count=data.get("totalCount", len(results)),
    )


# ---------------------------------------------------------------------------
# GET /groups/{group_id}/databaseUsers — list database users
# ---------------------------------------------------------------------------


@router.get("/groups/{group_id}/databaseUsers", response_model=DatabaseUsersResponse)
async def list_database_users(
    group_id: str = Path(..., min_length=1, max_length=256, description="Atlas project (group) ID"),
    items_per_page: int = Query(100, ge=1, le=500, description="Results per page"),
    page_num: int = Query(1, ge=1, description="Page number (1-indexed)"),
) -> DatabaseUsersResponse:
    """List database users defined in the specified Atlas project.

    Upstream: GET /groups/{group_id}/databaseUsers
    Returns 503 when public or private key are unset.
    """
    pub, priv = _require_creds()
    params: Dict[str, Any] = {"itemsPerPage": items_per_page, "pageNum": page_num}
    data = await _get(pub, priv, f"/groups/{group_id}/databaseUsers", params=params)
    results = data.get("results", [])
    _logger.info("mongodb_atlas_list_db_users group_id=%s count=%d", group_id, len(results))
    return DatabaseUsersResponse(
        results=results,
        total_count=data.get("totalCount", len(results)),
    )


# ---------------------------------------------------------------------------
# GET /groups/{group_id}/auditLog — security audit log (findings source)
# ---------------------------------------------------------------------------


@router.get("/groups/{group_id}/auditLog", response_model=AuditLogResponse)
async def get_audit_log(
    group_id: str = Path(..., min_length=1, max_length=256, description="Atlas project (group) ID"),
    start_date: Optional[str] = Query(
        None,
        alias="startDate",
        description="ISO-8601 start timestamp, e.g. 2026-01-01T00:00:00Z",
    ),
    end_date: Optional[str] = Query(
        None,
        alias="endDate",
        description="ISO-8601 end timestamp",
    ),
) -> AuditLogResponse:
    """Retrieve audit logging configuration and recent entries for a project.

    Upstream: GET /groups/{group_id}/auditLog
    Returns 503 when public or private key are unset.
    """
    pub, priv = _require_creds()
    params: Dict[str, Any] = {}
    if start_date:
        params["startDate"] = start_date
    if end_date:
        params["endDate"] = end_date
    data = await _get(pub, priv, f"/groups/{group_id}/auditLog", params=params)
    _logger.info("mongodb_atlas_audit_log group_id=%s", group_id)
    return AuditLogResponse(auditLog=data)


# ---------------------------------------------------------------------------
# GET /groups/{group_id}/accessList — IP allowlist
# ---------------------------------------------------------------------------


@router.get("/groups/{group_id}/accessList", response_model=AccessListResponse)
async def list_access_list(
    group_id: str = Path(..., min_length=1, max_length=256, description="Atlas project (group) ID"),
    items_per_page: int = Query(100, ge=1, le=500, description="Results per page"),
    page_num: int = Query(1, ge=1, description="Page number (1-indexed)"),
) -> AccessListResponse:
    """List IP allowlist entries for the specified Atlas project.

    Upstream: GET /groups/{group_id}/accessList
    Returns 503 when public or private key are unset.
    """
    pub, priv = _require_creds()
    params: Dict[str, Any] = {"itemsPerPage": items_per_page, "pageNum": page_num}
    data = await _get(pub, priv, f"/groups/{group_id}/accessList", params=params)
    results = data.get("results", [])
    _logger.info("mongodb_atlas_access_list group_id=%s count=%d", group_id, len(results))
    return AccessListResponse(
        results=results,
        total_count=data.get("totalCount", len(results)),
    )


__all__ = ["router"]
