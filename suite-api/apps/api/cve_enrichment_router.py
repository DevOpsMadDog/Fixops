"""CVE enrichment API endpoints — NVD + EPSS + KEV unified records."""
from __future__ import annotations

from typing import List, Optional

from core.cve_enrichment import CVEEnrichmentService
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/cve", tags=["cve-enrichment"])
_svc = CVEEnrichmentService()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class BatchRequest(BaseModel):
    cve_ids: List[str] = Field(..., description="List of CVE IDs to enrich")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats", summary="CVE enrichment statistics")
def get_stats() -> dict:
    """Return CVE enrichment statistics including cache hit rate and record count."""
    return _svc.get_cache_stats()


@router.get("/{cve_id}", summary="Get enriched CVE record")
def get_cve(cve_id: str) -> dict:
    """Retrieve enriched CVE data combining NVD, EPSS, and KEV sources."""
    record = _svc.enrich_cve(cve_id)
    return record


@router.post("/batch", summary="Enrich multiple CVEs")
def batch_enrich(body: BatchRequest) -> List[dict]:
    """Enrich a list of CVE IDs in a single request."""
    if len(body.cve_ids) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 CVEs per batch request")
    return _svc.enrich_batch(body.cve_ids)


@router.get("/search", summary="Search cached CVEs")
def search_cves(
    keyword: Optional[str] = Query(None, description="Keyword to search in CVE ID, description, or products"),
    min_cvss: float = Query(0.0, ge=0.0, le=10.0, description="Minimum CVSS score filter"),
    is_kev: Optional[bool] = Query(None, description="Filter to KEV entries only"),
    limit: int = Query(20, ge=1, le=200, description="Maximum results to return"),
) -> List[dict]:
    """Search cached CVEs by keyword, CVSS score, and KEV status."""
    return _svc.search_cves(keyword=keyword, min_cvss=min_cvss, is_kev=is_kev, limit=limit)


@router.get("/top-epss", summary="Top CVEs by EPSS score")
def top_epss(limit: int = Query(10, ge=1, le=100)) -> List[dict]:
    """Return CVEs with the highest EPSS exploitation probability scores."""
    return _svc.get_top_epss(limit=limit)


@router.get("/cache/stats", summary="Cache statistics")
def cache_stats() -> dict:
    """Return CVE cache statistics including hit rate and record count."""
    return _svc.get_cache_stats()


@router.delete("/cache", summary="Invalidate all cached CVEs")
def invalidate_all_cache() -> dict:
    """Clear the entire CVE enrichment cache."""
    count = _svc.invalidate_cache()
    return {"invalidated": count}


@router.delete("/cache/{cve_id}", summary="Invalidate cached CVE")
def invalidate_cve_cache(cve_id: str) -> dict:
    """Invalidate the cache entry for a specific CVE."""
    count = _svc.invalidate_cache(cve_id)
    return {"invalidated": count, "cve_id": cve_id.upper()}
