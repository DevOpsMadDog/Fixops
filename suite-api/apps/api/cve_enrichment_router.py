"""CVE enrichment API endpoints — NVD + EPSS + KEV + CIRCL unified records."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import List, Optional

from core.cve_enrichment import CVEEnrichmentService
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/cve", tags=["cve-enrichment"])
_svc = CVEEnrichmentService()

_CIRCL_BASE = "https://cve.circl.lu/api/cve"
_CIRCL_TIMEOUT = 8


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


# ---------------------------------------------------------------------------
# CIRCL CVE lookup — https://cve.circl.lu/api/cve/{id}
# ---------------------------------------------------------------------------


@router.get("/circl/{cve_id}", summary="CIRCL CVE lookup")
def circl_lookup(cve_id: str) -> dict:
    """Fetch CVE details from the CIRCL CVE Search API (cve.circl.lu).

    Returns a normalized record with CVSS score, severity, description,
    CWE, affected products, references, and CIRCL-specific fields.
    Returns HTTP 404 when CIRCL has no record for the requested CVE ID.
    Returns HTTP 502 when the upstream CIRCL service is unreachable.
    """
    cve_id = cve_id.upper().strip()
    url = f"{_CIRCL_BASE}/{cve_id}"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "ALDECI-CVE-CIRCL/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_CIRCL_TIMEOUT) as resp:  # nosec
            raw = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(status_code=404, detail=f"{cve_id} not found in CIRCL") from exc
        raise HTTPException(status_code=502, detail=f"CIRCL upstream error: {exc.code}") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"CIRCL unreachable: {exc}") from exc

    if not raw:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found in CIRCL")

    # Normalize CVSS
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_severity: str = "none"

    # CIRCL returns cvss (v2 float), cvss-time, cvss-vector; may also have cvssV3
    raw_cvss = raw.get("cvss")
    if raw_cvss is not None:
        try:
            cvss_score = float(raw_cvss)
        except (TypeError, ValueError):
            pass
    # Prefer CVSSv3 when present
    for v3_key in ("cvssV3", "cvss3"):
        v3 = raw.get(v3_key)
        if v3 and isinstance(v3, dict):
            try:
                cvss_score = float(v3.get("baseScore", cvss_score))
                cvss_vector = v3.get("vectorString", "")
            except (TypeError, ValueError):
                pass
            break
    if not cvss_vector:
        cvss_vector = raw.get("cvss-vector", "")
    cvss_severity = _svc.get_severity(cvss_score)

    # Description — CIRCL uses "summary"
    description = raw.get("summary", raw.get("description", ""))

    # CWE
    cwe = raw.get("cwe", "")

    # Published date (trim to YYYY-MM-DD)
    published = (raw.get("Published") or raw.get("published") or "")[:10]

    # Modified date
    modified = (raw.get("Modified") or raw.get("modified") or "")[:10]

    # Affected products / CPE entries
    affected: list = raw.get("vulnerable_product", raw.get("affectedProducts", []))
    if not isinstance(affected, list):
        affected = []

    # References
    references: list = raw.get("references", [])
    if not isinstance(references, list):
        references = []

    # Access complexity / authentication (CVSS v2 metadata)
    access_vector = raw.get("access", {}).get("vector", "") if isinstance(raw.get("access"), dict) else ""

    return {
        "cve_id": cve_id,
        "source": "circl",
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_severity": cvss_severity,
        "description": description,
        "cwe": cwe,
        "published": published,
        "modified": modified,
        "affected_products": affected,
        "references": references[:20],  # cap to 20 to keep payload manageable
        "access_vector": access_vector,
        "fetched_at": datetime.utcnow().isoformat(),
        "raw_circl": {
            k: raw[k]
            for k in ("id", "cvss-time", "capec", "map_cwe_capec")
            if k in raw
        },
    }
