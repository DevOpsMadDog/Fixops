"""GCP GKE (Google Kubernetes Engine) Router — ALDECI.

Wraps ``core.gcp_gke_engine.GCPGKEEngine`` with REST endpoints mirroring
the GCP Container/GKE v1 surface.

Prefix: /api/v1/gcp-gke
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/gcp-gke/                                                                                      capability summary
  GET  /api/v1/gcp-gke/v1/projects/{project}/locations/{location}/clusters                                   list clusters
  GET  /api/v1/gcp-gke/v1/projects/{project}/locations/{location}/clusters/{cluster_id}                      single cluster
  GET  /api/v1/gcp-gke/v1/projects/{project}/locations/{location}/clusters/{cluster_id}/nodePools            list node pools
  POST /api/v1/gcp-gke/v1/projects/{project}/locations/{location}/clusters/{cluster_id}:getJwks              cluster JWKs
  GET  /api/v1/gcp-gke/v1/projects/{project}/locations/{location}/operations                                 list operations

NO MOCKS rule: when ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file
is missing the capability summary returns ``status="unavailable"`` and every
live GKE call returns HTTP 503. We never fabricate cluster data.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gcp-gke",
    tags=["GCP GKE"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.gcp_gke_engine import get_gcp_gke_engine

    return get_gcp_gke_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    google_app_creds_present: bool
    status: str  # ok | empty | unavailable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    GCPGKEUnavailableError -> 503  (creds missing, network, upstream error)
    ValueError             -> 422  (input validation)
    """
    from core.gcp_gke_engine import GCPGKEUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GCPGKEUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without GCP credentials."""
    eng = _engine()
    creds = eng.google_app_creds_present()
    if not creds:
        status = "unavailable"
    else:
        status = "empty"  # no in-process cache; live calls populate
    return CapabilityResponse(
        service="GCP GKE",
        endpoints=[
            "/v1/projects/{p}/locations/{loc}/clusters",
            "/v1/projects/{p}/locations/{loc}/clusters/{c}/nodePools",
            "/v1/projects/{p}/locations/{loc}/operations",
        ],
        google_app_creds_present=creds,
        status=status,
    )


@router.get("/v1/projects/{project}/locations/{location}/clusters")
async def list_clusters(
    project: str = Path(..., description="GCP project ID"),
    location: str = Path(..., description="GKE location (zone or region)"),
    parent: Optional[str] = Query(None, description="Parent resource path"),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List GKE clusters under a location."""
    eng = _engine()
    return _serve(
        lambda: eng.list_clusters(
            project=project,
            location=location,
            parent=parent,
            page_token=pageToken,
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/clusters/{cluster_id}"
)
async def get_cluster(
    project: str = Path(...),
    location: str = Path(...),
    cluster_id: str = Path(...),
) -> Dict[str, Any]:
    """Get a single GKE cluster."""
    eng = _engine()
    return _serve(
        lambda: eng.get_cluster(
            project=project, location=location, cluster_id=cluster_id
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/clusters/{cluster_id}/nodePools"
)
async def list_node_pools(
    project: str = Path(...),
    location: str = Path(...),
    cluster_id: str = Path(...),
) -> Dict[str, Any]:
    """List node pools in a GKE cluster."""
    eng = _engine()
    return _serve(
        lambda: eng.list_node_pools(
            project=project, location=location, cluster_id=cluster_id
        )
    )


@router.post(
    "/v1/projects/{project}/locations/{location}/clusters/{cluster_id}:getJwks"
)
async def get_jwks(
    project: str = Path(...),
    location: str = Path(...),
    cluster_id: str = Path(...),
) -> Dict[str, Any]:
    """Fetch the cluster's OIDC JWKs document."""
    eng = _engine()
    return _serve(
        lambda: eng.get_jwks(
            project=project, location=location, cluster_id=cluster_id
        )
    )


@router.get("/v1/projects/{project}/locations/{location}/operations")
async def list_operations(
    project: str = Path(...),
    location: str = Path(...),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List GKE operations under a location."""
    eng = _engine()
    return _serve(
        lambda: eng.list_operations(
            project=project, location=location, page_token=pageToken
        )
    )
