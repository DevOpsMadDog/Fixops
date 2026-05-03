"""GCP Cloud KMS Router — ALDECI.

Wraps ``core.gcp_cloudkms_engine.GCPCloudKMSEngine`` with REST endpoints
mirroring the GCP Cloud KMS v1 surface.

Prefix: /api/v1/gcp-cloudkms
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/gcp-cloudkms/                                                                        capability summary
  GET  /api/v1/gcp-cloudkms/v1/projects/{project}/locations                                         list locations
  GET  /api/v1/gcp-cloudkms/v1/projects/{project}/locations/{location}/keyRings                     list keyRings
  GET  /api/v1/gcp-cloudkms/v1/projects/{project}/locations/{location}/keyRings/{key_ring}          get keyRing
  GET  .../keyRings/{key_ring}/cryptoKeys                                                           list cryptoKeys
  GET  .../keyRings/{key_ring}/cryptoKeys/{crypto_key}                                              get cryptoKey
  GET  .../cryptoKeys/{crypto_key}/cryptoKeyVersions                                                list versions
  GET  .../cryptoKeys/{crypto_key}/cryptoKeyVersions/{version}                                      get version
  POST .../cryptoKeys/{crypto_key}:getIamPolicy                                                     IAM policy

NO MOCKS rule: when ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file
is missing the capability summary returns ``status="unavailable"`` and every
live KMS call returns HTTP 503. We never fabricate key material.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gcp-cloudkms",
    tags=["GCP Cloud KMS"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.gcp_cloudkms_engine import get_gcp_cloudkms_engine

    return get_gcp_cloudkms_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    google_app_creds_present: bool
    status: str  # ok | empty | unavailable


class IamPolicyOptions(BaseModel):
    requestedPolicyVersion: Optional[int] = None


class GetIamPolicyRequest(BaseModel):
    options: Optional[IamPolicyOptions] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    GCPCloudKMSUnavailableError -> 503  (creds missing, network, upstream error)
    ValueError                  -> 422  (input validation)
    """
    from core.gcp_cloudkms_engine import GCPCloudKMSUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GCPCloudKMSUnavailableError as exc:
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
        service="GCP Cloud KMS",
        endpoints=[
            "/v1/projects/{p}/locations",
            "/v1/projects/{p}/locations/{loc}/keyRings",
            "/v1/projects/{p}/locations/{loc}/keyRings/{kr}/cryptoKeys",
            "/v1/projects/{p}/locations/{loc}/keyRings/{kr}/cryptoKeys/{ck}/cryptoKeyVersions",
            "IAM policy endpoints",
        ],
        google_app_creds_present=creds,
        status=status,
    )


@router.get("/v1/projects/{project}/locations")
async def list_locations(
    project: str = Path(..., description="GCP project ID"),
) -> Dict[str, Any]:
    """List Cloud KMS locations available to the project."""
    eng = _engine()
    return _serve(lambda: eng.list_locations(project=project))


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings"
)
async def list_key_rings(
    project: str = Path(..., description="GCP project ID"),
    location: str = Path(..., description="KMS location"),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List keyRings under a location."""
    eng = _engine()
    return _serve(
        lambda: eng.list_key_rings(
            project=project,
            location=location,
            page_size=pageSize,
            page_token=pageToken,
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}"
)
async def get_key_ring(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
) -> Dict[str, Any]:
    """Get a single keyRing."""
    eng = _engine()
    return _serve(
        lambda: eng.get_key_ring(
            project=project, location=location, key_ring=key_ring
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys"
)
async def list_crypto_keys(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    versionView: Optional[str] = Query(None, description="BASIC | FULL"),
) -> Dict[str, Any]:
    """List cryptoKeys in a keyRing."""
    eng = _engine()
    return _serve(
        lambda: eng.list_crypto_keys(
            project=project,
            location=location,
            key_ring=key_ring,
            page_size=pageSize,
            page_token=pageToken,
            version_view=versionView,
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}"
    "/cryptoKeys/{crypto_key}"
)
async def get_crypto_key(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
    crypto_key: str = Path(...),
) -> Dict[str, Any]:
    """Get a single cryptoKey."""
    eng = _engine()
    return _serve(
        lambda: eng.get_crypto_key(
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}"
    "/cryptoKeys/{crypto_key}/cryptoKeyVersions"
)
async def list_crypto_key_versions(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
    crypto_key: str = Path(...),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
    pageToken: Optional[str] = Query(None),
    filter: Optional[str] = Query(None, description="CEL filter"),
    orderBy: Optional[str] = Query(None),
    view: Optional[str] = Query(None, description="BASIC | FULL"),
) -> Dict[str, Any]:
    """List cryptoKeyVersions for a cryptoKey."""
    eng = _engine()
    return _serve(
        lambda: eng.list_crypto_key_versions(
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
            page_size=pageSize,
            page_token=pageToken,
            filter_=filter,
            order_by=orderBy,
            view=view,
        )
    )


@router.get(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}"
    "/cryptoKeys/{crypto_key}/cryptoKeyVersions/{version}"
)
async def get_crypto_key_version(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
    crypto_key: str = Path(...),
    version: str = Path(...),
) -> Dict[str, Any]:
    """Get a single cryptoKeyVersion."""
    eng = _engine()
    return _serve(
        lambda: eng.get_crypto_key_version(
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
            version=version,
        )
    )


@router.post(
    "/v1/projects/{project}/locations/{location}/keyRings/{key_ring}"
    "/cryptoKeys/{crypto_key}:getIamPolicy"
)
async def get_iam_policy(
    project: str = Path(...),
    location: str = Path(...),
    key_ring: str = Path(...),
    crypto_key: str = Path(...),
    body: GetIamPolicyRequest = Body(default_factory=GetIamPolicyRequest),
) -> Dict[str, Any]:
    """Fetch IAM policy attached to a cryptoKey."""
    eng = _engine()
    rpv: Optional[int] = None
    if body.options is not None:
        rpv = body.options.requestedPolicyVersion
    return _serve(
        lambda: eng.get_iam_policy(
            project=project,
            location=location,
            key_ring=key_ring,
            crypto_key=crypto_key,
            requested_policy_version=rpv,
        )
    )
