"""Checkmarx One Router — ALDECI.

Wraps the Checkmarx One REST surfaces under prefix ``/api/v1/checkmarx``:

  - GET  /                                                                     capability summary
  - POST /api/iam/auth/realms/{tenant}/protocol/openid-connect/token           OAuth2 client_credentials
  - GET  /api/projects                                                         list projects
  - GET  /api/projects/{project_id}                                            project detail
  - GET  /api/scans                                                            list scans
  - POST /api/scans                                                            create scan
  - GET  /api/scan-results                                                     list scan results
  - GET  /api/scan-results/{result_id}                                         result detail
  - POST /api/scan-results                                                     triage update
  - GET  /api/cx-policy-management/policies                                    list policies

NO MOCKS rule
-------------
* When CHECKMARX_BASE_URL / CHECKMARX_CLIENT_ID / CHECKMARX_CLIENT_SECRET /
  CHECKMARX_TENANT env unset, every live endpoint returns HTTP 503 and the
  capability summary surfaces ``status="unavailable"``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/checkmarx",
    tags=["Checkmarx"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.checkmarx_engine import get_checkmarx_engine

    return get_checkmarx_engine()


def _serve(callable_):
    """Run a Checkmarx call, translating engine errors to HTTP responses.

    CheckmarxUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError                -> 422 (input validation)
    """
    from core.checkmarx_engine import CheckmarxUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except CheckmarxUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class TokenRequest(BaseModel):
    grant_type: str = Field(default="client_credentials")
    client_id: Optional[str] = Field(default=None)
    client_secret: Optional[str] = Field(default=None)


class ScanProject(BaseModel):
    id: str = Field(..., min_length=1, description="Checkmarx project id")


class ScanRequest(BaseModel):
    project: ScanProject = Field(...)
    branch: Optional[str] = Field(default=None)
    sourceType: Optional[str] = Field(default=None, alias="sourceType")
    handler: Optional[Dict[str, Any]] = Field(default=None)
    config: Optional[Any] = Field(default=None)

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class ScanResultUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")

    scanId: str = Field(..., min_length=1)
    projectId: str = Field(..., min_length=1)
    similarityId: str = Field(..., min_length=1)
    severity: Optional[str] = Field(default=None)
    state: Optional[str] = Field(default=None)
    status: Optional[str] = Field(default=None)
    comment: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Checkmarx capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    cid_ok = eng.client_id_present()
    sec_ok = eng.client_secret_present()
    ten_ok = eng.tenant_present()
    return {
        "service": "Checkmarx One",
        "endpoints": [
            "/api/iam/auth/realms/{tenant}/protocol/openid-connect/token",
            "/api/projects",
            "/api/projects/{project_id}",
            "/api/scans",
            "/api/scan-results",
            "/api/scan-results/{result_id}",
            "/api/cx-policy-management/policies",
        ],
        "checkmarx_base_url_present": base_ok,
        "checkmarx_client_id_present": cid_ok,
        "checkmarx_client_secret_present": sec_ok,
        "checkmarx_tenant_present": ten_ok,
        "status": "ok" if (base_ok and cid_ok and sec_ok and ten_ok) else "unavailable",
    }


# ---------------------------------------------------------------------------
# OAuth2
# ---------------------------------------------------------------------------


@router.post(
    "/api/iam/auth/realms/{tenant}/protocol/openid-connect/token",
    summary="Checkmarx OAuth2 client_credentials token",
)
def issue_token(
    tenant: str = Path(..., min_length=1),
    body: TokenRequest = Body(default_factory=TokenRequest),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().request_token(
            grant_type=body.grant_type,
            client_id=body.client_id,
            client_secret=body.client_secret,
            tenant=tenant,
        )
    )


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------


@router.get("/api/projects", summary="List Checkmarx projects")
def list_projects(
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    offset: Optional[int] = Query(default=None, ge=0),
    name: Optional[str] = Query(default=None),
    groups: Optional[str] = Query(default=None),
    tags_keys: Optional[str] = Query(default=None, alias="tags-keys"),
    tags_values: Optional[str] = Query(default=None, alias="tags-values"),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_projects(
            limit=limit,
            offset=offset,
            name=name,
            groups=groups,
            tags_keys=tags_keys,
            tags_values=tags_values,
        )
    )


@router.get("/api/projects/{project_id}", summary="Get Checkmarx project")
def get_project(project_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_project(project_id))


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@router.get("/api/scans", summary="List Checkmarx scans")
def list_scans(
    project_id: Optional[str] = Query(default=None, alias="project-id"),
    statuses: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    offset: Optional[int] = Query(default=None, ge=0),
    from_date: Optional[str] = Query(default=None, alias="from-date"),
    to_date: Optional[str] = Query(default=None, alias="to-date"),
    branch: Optional[str] = Query(default=None),
    tags_keys: Optional[str] = Query(default=None, alias="tags-keys"),
    tags_values: Optional[str] = Query(default=None, alias="tags-values"),
    engine: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_scans(
            project_id=project_id,
            statuses=statuses,
            limit=limit,
            offset=offset,
            from_date=from_date,
            to_date=to_date,
            branch=branch,
            tags_keys=tags_keys,
            tags_values=tags_values,
            engine=engine,
        )
    )


@router.post("/api/scans", summary="Create a Checkmarx scan")
def create_scan(body: ScanRequest = Body(...)) -> Dict[str, Any]:
    payload = body.model_dump(by_alias=True, exclude_none=True)
    return _serve(lambda: _engine().create_scan(payload))


# ---------------------------------------------------------------------------
# Scan results
# ---------------------------------------------------------------------------


@router.get("/api/scan-results", summary="List Checkmarx scan results")
def list_scan_results(
    scan_id: str = Query(..., alias="scan-id", min_length=1),
    severity: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    offset: Optional[int] = Query(default=None, ge=0),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_scan_results(
            scan_id=scan_id,
            severity=severity,
            state=state,
            status=status,
            limit=limit,
            offset=offset,
        )
    )


@router.get("/api/scan-results/{result_id}", summary="Get Checkmarx scan result")
def get_scan_result(result_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_scan_result(result_id))


@router.post("/api/scan-results", summary="Update Checkmarx scan result triage")
def update_scan_result(body: ScanResultUpdate = Body(...)) -> Dict[str, Any]:
    payload = body.model_dump(exclude_none=True)
    return _serve(lambda: _engine().update_scan_result(payload))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get(
    "/api/cx-policy-management/policies",
    summary="List Checkmarx policies",
)
def list_policies(
    tenantId: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().list_policies(tenant_id=tenantId))


__all__ = ["router"]
