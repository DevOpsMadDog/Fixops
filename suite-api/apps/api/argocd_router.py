"""ALDECI ArgoCD GitOps router — REAL API only, NO MOCKS.

Mounted at ``/api/v1/argocd`` under the ``read:scans`` scope.

Endpoints
---------
GET    /                                 — capability summary
GET    /api/v1/applications              — list applications (projects, selector filters)
GET    /api/v1/applications/{name}       — fetch one application (refresh=normal|hard)
POST   /api/v1/applications/{name}/sync  — trigger sync for one application
GET    /api/v1/projects                  — list projects
GET    /api/v1/clusters                  — list clusters
GET    /api/v1/repositories              — list repositories
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from core.argocd_engine import (
    ArgoCDUnavailableError,
    get_argocd_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/argocd",
    tags=["argocd"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------- Pydantic


class _SyncStrategy(BaseModel):
    hook: Optional[Dict[str, Any]] = None
    apply: Optional[Dict[str, Any]] = None


class SyncRequest(BaseModel):
    revision: Optional[str] = None
    prune: Optional[bool] = None
    dryRun: Optional[bool] = None
    strategy: Optional[_SyncStrategy] = None
    syncOptions: Optional[List[str]] = Field(
        default=None,
        description="ArgoCD sync options (e.g. CreateNamespace=true)",
    )


# ----------------------------------------------------------------- helpers


def _to_503(exc: ArgoCDUnavailableError) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ----------------------------------------------------------------- endpoints


@router.get("", summary="ArgoCD capability summary")
@router.get("/", summary="ArgoCD capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = get_argocd_engine()
    return eng.capability_summary()


@router.get("/api/v1/applications", summary="List ArgoCD applications")
def list_applications(
    projects: Optional[List[str]] = Query(
        None, description="Filter by ArgoCD project names"
    ),
    selector: Optional[str] = Query(
        None, description="Kubernetes label selector (e.g. env=prod)"
    ),
) -> Dict[str, Any]:
    eng = get_argocd_engine()
    try:
        return eng.list_applications(projects=projects, selector=selector)
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/api/v1/applications/{name}", summary="Get ArgoCD application")
def get_application(
    name: str,
    refresh: Optional[str] = Query(
        None,
        pattern="^(normal|hard)$",
        description="Trigger a refresh: normal | hard",
    ),
) -> Dict[str, Any]:
    eng = get_argocd_engine()
    try:
        return eng.get_application(name, refresh=refresh)
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/api/v1/applications/{name}/sync",
    summary="Trigger sync of an ArgoCD application",
)
def sync_application(
    name: str,
    body: Optional[SyncRequest] = Body(default=None),
) -> Dict[str, Any]:
    eng = get_argocd_engine()
    payload = body.dict(exclude_none=True) if body is not None else {}
    try:
        return eng.sync_application(name, body=payload)
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/api/v1/projects", summary="List ArgoCD projects")
def list_projects() -> Dict[str, Any]:
    eng = get_argocd_engine()
    try:
        return eng.list_projects()
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)


@router.get("/api/v1/clusters", summary="List ArgoCD clusters")
def list_clusters() -> Dict[str, Any]:
    eng = get_argocd_engine()
    try:
        return eng.list_clusters()
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)


@router.get("/api/v1/repositories", summary="List ArgoCD repositories")
def list_repositories() -> Dict[str, Any]:
    eng = get_argocd_engine()
    try:
        return eng.list_repositories()
    except ArgoCDUnavailableError as exc:
        raise _to_503(exc)


__all__ = ["router"]
