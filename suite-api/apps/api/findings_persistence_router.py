"""Findings Persistence API Router — ALDECI.

Three endpoints backed by FindingsStore (real SQLite, no mocks):

  GET  /api/v1/findings/v2          — list with filters + pagination
  GET  /api/v1/findings/v2/stats    — severity breakdown counts
  GET  /api/v1/findings/v2/{id}     — single finding detail

The prefix /v2 disambiguates from the legacy findings_routes.py at /api/v1/findings
which is still mounted for lifecycle operations (status, assign, comment, export).
These endpoints surface data from the real persistence store rather than the
in-memory dict.

Auth: inherits _verify_api_key + read:findings scope from app.py include_router().
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/findings/v2", tags=["findings-persistence"])


def _get_store():
    from core.findings_persistence import get_findings_store  # noqa: PLC0415
    return get_findings_store()


# ---------------------------------------------------------------------------
# GET /api/v1/findings/v2
# ---------------------------------------------------------------------------

@router.get("", response_model=Dict[str, Any])
async def list_findings_real(
    severity: Optional[str] = Query(None, description="Filter: critical|high|medium|low|informational"),
    source: Optional[str] = Query(None, description="Filter by scanner source (e.g. Semgrep, Trivy)"),
    file_path: Optional[str] = Query(None, description="Substring match on file_path"),
    asset_id: Optional[str] = Query(None, description="Filter by asset_id"),
    status: Optional[str] = Query(None, description="Filter by status (open|in_progress|resolved|suppressed|false_positive)"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE identifier"),
    date_from: Optional[str] = Query(None, description="ISO-8601 lower bound on created_at"),
    date_to: Optional[str] = Query(None, description="ISO-8601 upper bound on created_at"),
    limit: int = Query(200, ge=1, le=1000, description="Max results (default 200)"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """List persisted findings with filtering and pagination.

    All data is read from the tenant-isolated SQLite database.
    Returns paginated findings sorted by created_at DESC.
    """
    filters: Dict[str, Any] = {}
    if severity:
        filters["severity"] = severity.lower()
    if source:
        filters["source"] = source
    if file_path:
        filters["file_path"] = file_path
    if asset_id:
        filters["asset_id"] = asset_id
    if status:
        filters["status"] = status
    if cve_id:
        filters["cve_id"] = cve_id
    if date_from:
        filters["date_from"] = date_from
    if date_to:
        filters["date_to"] = date_to

    store = _get_store()
    findings = await store.list_findings(
        tenant_id=org_id,
        filters=filters,
        limit=limit,
        offset=offset,
    )
    finding_dicts = [f.to_dict() for f in findings]

    # Count total (re-query without limit for accurate total)
    total_counts = await store.count_findings(tenant_id=org_id, filters=filters)
    total = total_counts.get("total", len(finding_dicts))

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "findings": finding_dicts,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/findings/v2/stats
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
async def findings_stats(
    source: Optional[str] = Query(None),
    asset_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return severity-keyed finding counts from real persistence store.

    Response shape:
        {
          "tenant_id": "...",
          "counts": {
            "critical": int,
            "high": int,
            "medium": int,
            "low": int,
            "informational": int,
            "total": int
          }
        }
    """
    filters: Dict[str, Any] = {}
    if source:
        filters["source"] = source
    if asset_id:
        filters["asset_id"] = asset_id
    if status:
        filters["status"] = status
    if date_from:
        filters["date_from"] = date_from
    if date_to:
        filters["date_to"] = date_to

    store = _get_store()
    counts = await store.count_findings(tenant_id=org_id, filters=filters)

    return {
        "tenant_id": org_id,
        "counts": counts,
    }


# ---------------------------------------------------------------------------
# GET /api/v1/findings/v2/{finding_id}
# ---------------------------------------------------------------------------

@router.get("/{finding_id}", response_model=Dict[str, Any])
async def get_finding_real(
    finding_id: str,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Return a single finding detail from real persistence store.

    Returns 404 if not found or tenant mismatch (no enumeration leak).
    """
    store = _get_store()
    finding = await store.get_finding(tenant_id=org_id, finding_id=finding_id)
    if finding is None:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {finding_id} not found",
        )
    return finding.to_dict()
