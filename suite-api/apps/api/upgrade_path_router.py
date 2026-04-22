"""Upgrade Path Resolver Router — ALDECI (GAP-007).

Given a pURL + list of CVEs, return the lowest safe version-bump that
resolves all the CVEs, per ecosystem (npm, pypi, maven v0 static catalog).

Prefix: /api/v1/upgrade-path
Auth:   api_key_auth dependency on ALL endpoints.

Routes:
  POST /api/v1/upgrade-path/resolve        resolve a single pURL+CVE set
  POST /api/v1/upgrade-path/bulk           batch resolve (findings page)
  POST /api/v1/upgrade-path/ingest-vuln    admin: add/upsert a catalog entry
  GET  /api/v1/upgrade-path/stats          counters + supported ecosystems
  GET  /api/v1/upgrade-path/queries        recent resolve history (org-scoped)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth


_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/upgrade-path",
    tags=["Upgrade Path Resolver"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.upgrade_path_resolver_engine import UpgradePathResolverEngine

        _engine = UpgradePathResolverEngine()
    return _engine


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------


class ResolveRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation ID")
    purl: str = Field(..., description="Package URL, e.g. pkg:npm/lodash@4.17.19")
    cve_ids: List[str] = Field(..., description="CVE identifiers to resolve")


class FindingItem(BaseModel):
    purl: str = Field(..., description="Package URL")
    cve_ids: List[str] = Field(..., description="CVE identifiers")


class BulkResolveRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation ID")
    findings: List[FindingItem] = Field(..., description="Batch of findings")


class IngestVulnRequest(BaseModel):
    ecosystem: str = Field(..., description="npm|pypi|maven")
    package_name: str = Field(..., description="Package name (maven uses group/artifact)")
    version: str = Field(..., description="Affected version")
    cve_id: str = Field(..., description="CVE identifier")
    fixed_in: str = Field(..., description="Version where fix is available")


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


@router.post("/resolve", dependencies=[Depends(api_key_auth)])
def resolve_upgrade(req: ResolveRequest) -> Dict[str, Any]:
    """Resolve the lowest safe version that fixes all the provided CVEs."""
    try:
        return _get_engine().resolve_upgrade(
            org_id=req.org_id,
            purl=req.purl,
            cve_ids=req.cve_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/bulk", dependencies=[Depends(api_key_auth)])
def bulk_resolve(req: BulkResolveRequest) -> Dict[str, Any]:
    """Batch resolve for a findings page (many pURL+CVE tuples)."""
    try:
        findings = [f.model_dump() for f in req.findings]
        return _get_engine().bulk_resolve(org_id=req.org_id, findings=findings)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post(
    "/ingest-vuln",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def ingest_vuln(req: IngestVulnRequest) -> Dict[str, Any]:
    """Admin endpoint: upsert a vuln catalog entry."""
    try:
        return _get_engine().ingest_vuln(
            ecosystem=req.ecosystem,
            package_name=req.package_name,
            version=req.version,
            cve_id=req.cve_id,
            fixed_in=req.fixed_in,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats(
    org_id: Optional[str] = Query(
        default=None, description="Scope resolve-query counters to org_id"
    ),
) -> Dict[str, Any]:
    """Return counters + supported ecosystems."""
    return _get_engine().stats(org_id=org_id)


@router.get("/queries", dependencies=[Depends(api_key_auth)])
def list_queries(
    org_id: str = Query(..., description="Organisation ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List recent resolve queries for an org (audit trail)."""
    return _get_engine().list_queries(org_id=org_id, limit=limit)
