"""GCP Security Command Center Router — ALDECI.

Wraps ``core.gcp_scc_engine.GCPSCCEngine`` with REST endpoints mirroring the
GCP Security Command Center v1 surface.

Prefix: /api/v1/gcp-scc
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

Routes:
  GET  /api/v1/gcp-scc/                         capability summary
  GET  /api/v1/gcp-scc/findings                 list findings under an org
  GET  /api/v1/gcp-scc/sources                  list SCC sources for an org
  GET  /api/v1/gcp-scc/assets                   list assets under an org
  GET  /api/v1/gcp-scc/findings/group           groupBy aggregate
  POST /api/v1/gcp-scc/findings/{name}:setMute  toggle mute on a finding

NO MOCKS rule: when ``GOOGLE_APPLICATION_CREDENTIALS`` is unset OR the file
is missing the capability summary returns ``status="unavailable"`` and every
live SCC call returns HTTP 503. We never fabricate findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/gcp-scc",
    tags=["GCP Security Command Center"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.gcp_scc_engine import get_gcp_scc_engine

    return get_gcp_scc_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    google_app_creds_present: bool
    org_id_present: bool
    status: str  # ok | empty | unavailable


class SetMuteRequest(BaseModel):
    mute: str  # MUTED | UNMUTED | UNDEFINED


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    GCPSCCUnavailableError -> 503  (creds missing, network, upstream error)
    ValueError             -> 422  (input validation)
    """
    from core.gcp_scc_engine import GCPSCCUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except GCPSCCUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without GCP credentials."""
    eng = _engine()
    creds = eng.google_app_creds_present()
    org = eng.org_id_present()
    if not (creds and org):
        status = "unavailable"
    else:
        status = "empty"  # no in-process cache; live calls populate
    return CapabilityResponse(
        service="GCP Security Command Center",
        endpoints=[
            "/findings",
            "/sources",
            "/assets",
            "/findings/group",
            "/findings/list",
        ],
        google_app_creds_present=creds,
        org_id_present=org,
        status=status,
    )


@router.get("/findings")
async def list_findings(
    orgId: str = Query("", description="GCP organization ID (overrides GCP_ORG_ID env)"),
    filter: Optional[str] = Query(None, description="SCC CEL filter expression"),
    pageToken: Optional[str] = Query(None),
    pageSize: Optional[int] = Query(None, ge=1, le=1000),
) -> Dict[str, Any]:
    """List findings across all sources of the org."""
    eng = _engine()
    return _serve(
        lambda: eng.list_findings(
            org_id=orgId or None,
            filter_=filter,
            page_token=pageToken,
            page_size=pageSize,
        )
    )


@router.get("/sources")
async def list_sources(
    orgId: str = Query("", description="GCP organization ID"),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List SCC sources for the org."""
    eng = _engine()
    return _serve(
        lambda: eng.list_sources(
            org_id=orgId or None, page_token=pageToken
        )
    )


@router.get("/assets")
async def list_assets(
    orgId: str = Query("", description="GCP organization ID"),
    filter: Optional[str] = Query(None, description="SCC CEL filter expression"),
    pageToken: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List assets tracked by SCC."""
    eng = _engine()
    return _serve(
        lambda: eng.list_assets(
            org_id=orgId or None, filter_=filter, page_token=pageToken
        )
    )


@router.get("/findings/group")
async def group_findings(
    orgId: str = Query("", description="GCP organization ID"),
    groupBy: str = Query("category", description="Field to group by"),
    filter: Optional[str] = Query(None, description="SCC CEL filter expression"),
) -> Dict[str, Any]:
    """Aggregate findings by an arbitrary property (category, severity, state, ...)."""
    eng = _engine()
    return _serve(
        lambda: eng.group_findings(
            org_id=orgId or None, group_by=groupBy, filter_=filter
        )
    )


@router.post("/findings/{name:path}:setMute")
async def set_finding_mute(
    name: str = Path(
        ...,
        description=(
            "Fully qualified finding resource name "
            "(organizations/{org}/sources/{src}/findings/{id})"
        ),
    ),
    body: SetMuteRequest = Body(...),
) -> Dict[str, Any]:
    """Mute / unmute / clear-mute on an existing SCC finding."""
    eng = _engine()
    return _serve(lambda: eng.set_mute(finding_name=name, mute=body.mute))
