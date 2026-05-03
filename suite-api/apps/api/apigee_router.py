"""Apigee Edge X Router — ALDECI.

Wraps the Google Apigee X management API under prefix ``/api/v1/apigee``:

  - GET  /                                                                          — capability summary
  - GET  /v1/organizations/{org}/apis                                                — list API proxies
  - GET  /v1/organizations/{org}/apis/{api_name}                                     — proxy detail
  - GET  /v1/organizations/{org}/apis/{api_name}/revisions                           — revision list
  - GET  /v1/organizations/{org}/apis/{api_name}/revisions/{revision}                — revision detail
  - GET  /v1/organizations/{org}/apis/{api_name}/revisions/{revision}/policies       — policy list
  - GET  /v1/organizations/{org}/environments                                        — environment list
  - GET  /v1/organizations/{org}/environments/{env}/apis/{api}/revisions/{r}/deployments
  - GET  /v1/organizations/{org}/apiproducts                                         — API product list
  - GET  /v1/organizations/{org}/developers                                          — developer list
  - GET  /v1/organizations/{org}/developers/{email}/apps                             — apps for one developer
  - GET  /v1/organizations/{org}/apps                                                — global app list

NO MOCKS rule
-------------
* When ``GOOGLE_APPLICATION_CREDENTIALS`` or ``APIGEE_ORG`` is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/apigee",
    tags=["Apigee"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.apigee_engine import get_apigee_engine

    return get_apigee_engine()


def _serve(callable_):
    """Run an Apigee call, translating engine errors to HTTP responses."""
    from core.apigee_engine import ApigeeUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ApigeeUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Apigee Edge X capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    creds_ok = eng.google_app_creds_present()
    org_ok = eng.apigee_org_present()
    creds = creds_ok and org_ok
    return {
        "service": "Apigee Edge X",
        "endpoints": [
            "/v1/organizations/{org}/apis",
            "/v1/organizations/{org}/environments",
            "/v1/organizations/{org}/apiproducts",
            "/v1/organizations/{org}/developers",
            "/v1/organizations/{org}/apps",
        ],
        "google_app_creds_present": creds_ok,
        "apigee_org_present": org_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# API proxies
# ---------------------------------------------------------------------------


@router.get(
    "/v1/organizations/{org}/apis",
    summary="List API proxies for an organization",
)
def list_apis(
    org: str = Path(..., description="Apigee organization name"),
    includeRevisions: bool = Query(False),
    includeMetaData: bool = Query(False),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_apis(
            org,
            include_revisions=includeRevisions,
            include_meta_data=includeMetaData,
        )
    )


@router.get(
    "/v1/organizations/{org}/apis/{api_name}",
    summary="Get API proxy detail",
)
def get_api(
    org: str = Path(...),
    api_name: str = Path(..., description="API proxy name"),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_api(org, api_name))


@router.get(
    "/v1/organizations/{org}/apis/{api_name}/revisions",
    summary="List API proxy revisions",
)
def list_api_revisions(
    org: str = Path(...),
    api_name: str = Path(...),
) -> List[str]:
    return _serve(lambda: _engine().list_api_revisions(org, api_name))


@router.get(
    "/v1/organizations/{org}/apis/{api_name}/revisions/{revision}",
    summary="Get API proxy revision detail",
)
def get_api_revision(
    org: str = Path(...),
    api_name: str = Path(...),
    revision: str = Path(...),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().get_api_revision(org, api_name, revision))


@router.get(
    "/v1/organizations/{org}/apis/{api_name}/revisions/{revision}/policies",
    summary="List policies in an API proxy revision",
)
def list_api_revision_policies(
    org: str = Path(...),
    api_name: str = Path(...),
    revision: str = Path(...),
) -> List[str]:
    return _serve(
        lambda: _engine().list_api_revision_policies(org, api_name, revision)
    )


# ---------------------------------------------------------------------------
# Environments
# ---------------------------------------------------------------------------


@router.get(
    "/v1/organizations/{org}/environments",
    summary="List environments for an organization",
)
def list_environments(
    org: str = Path(...),
) -> List[str]:
    return _serve(lambda: _engine().list_environments(org))


@router.get(
    "/v1/organizations/{org}/environments/{env}/apis/{api_name}/revisions/{revision}/deployments",
    summary="Get deployment status for an API revision in an environment",
)
def get_environment_deployments(
    org: str = Path(...),
    env: str = Path(...),
    api_name: str = Path(...),
    revision: str = Path(...),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().get_environment_deployments(
            org, env, api_name, revision
        )
    )


# ---------------------------------------------------------------------------
# API products
# ---------------------------------------------------------------------------


@router.get(
    "/v1/organizations/{org}/apiproducts",
    summary="List API products",
)
def list_api_products(
    org: str = Path(...),
    expand: bool = Query(False),
    count: int = Query(None, ge=1, le=1000),
    startKey: str = Query(None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_api_products(
            org,
            expand=expand,
            count=count,
            start_key=startKey,
        )
    )


# ---------------------------------------------------------------------------
# Developers
# ---------------------------------------------------------------------------


@router.get(
    "/v1/organizations/{org}/developers",
    summary="List developers",
)
def list_developers(
    org: str = Path(...),
    expand: bool = Query(False),
    count: int = Query(None, ge=1, le=1000),
    startKey: str = Query(None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_developers(
            org,
            expand=expand,
            count=count,
            start_key=startKey,
        )
    )


@router.get(
    "/v1/organizations/{org}/developers/{email}/apps",
    summary="List apps belonging to a developer",
)
def list_developer_apps(
    org: str = Path(...),
    email: str = Path(...),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().list_developer_apps(org, email))


# ---------------------------------------------------------------------------
# Apps
# ---------------------------------------------------------------------------


@router.get(
    "/v1/organizations/{org}/apps",
    summary="List apps across all developers",
)
def list_apps(
    org: str = Path(...),
    expand: bool = Query(False),
    count: int = Query(None, ge=1, le=1000),
    startKey: str = Query(None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().list_apps(
            org,
            expand=expand,
            count=count,
            start_key=startKey,
        )
    )


__all__ = ["router"]
