"""Upgrade Path Resolver API Router — ALDECI.

Resolves lowest-safe package upgrade versions that fix CVEs.
Backed by UpgradePathResolverEngine (suite-core).

Prefix: /api/v1/upgrade-path
Auth:   api_key_auth

Routes:
  POST /resolve       — resolve upgrade path for a single purl + CVE list
  POST /bulk-resolve  — resolve upgrade paths for a batch of findings
  GET  /stats         — query/vuln counts and resolution rates
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/upgrade-path",
    tags=["Upgrade Path Resolver"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.upgrade_path_resolver_engine import UpgradePathResolverEngine
        _engine = UpgradePathResolverEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ResolveRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    purl: str = Field(..., description="Package URL (purl) e.g. pkg:pypi/django@3.2.0")
    cve_ids: List[str] = Field(..., min_length=1, description="List of CVE IDs to fix")


class BulkFinding(BaseModel):
    purl: str
    cve_ids: List[str]


class BulkResolveRequest(BaseModel):
    org_id: str = Field("default", description="Organisation ID")
    findings: List[BulkFinding] = Field(..., min_length=1, description="List of purl+CVE pairs")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/resolve", summary="Resolve upgrade path for a single package")
def resolve_upgrade(payload: ResolveRequest) -> Dict[str, Any]:
    """Return the lowest safe version that fixes all given CVEs for a package."""
    try:
        return _get_engine().resolve_upgrade(
            org_id=payload.org_id,
            purl=payload.purl,
            cve_ids=payload.cve_ids,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("resolve_upgrade failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/bulk-resolve", summary="Bulk-resolve upgrade paths for multiple findings")
def bulk_resolve(payload: BulkResolveRequest) -> Dict[str, Any]:
    """Resolve upgrade paths for a batch of purl+CVE findings."""
    try:
        findings = [f.model_dump() for f in payload.findings]
        return _get_engine().bulk_resolve(
            org_id=payload.org_id,
            findings=findings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("bulk_resolve failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", summary="Upgrade path resolver statistics")
def stats(org_id: Optional[str] = Query(None, description="Filter stats by org")) -> Dict[str, Any]:
    """Return aggregated statistics: vuln count, query count, resolution rate."""
    try:
        return _get_engine().stats(org_id=org_id)
    except Exception as exc:
        _logger.exception("stats failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
