"""NIST NVD CVE Router — ALDECI.

Endpoints to import and query NVD 2.0 CVE records.

Prefix: /api/v1/nvd
Auth:   api_key_auth dependency

Routes:
    GET  /api/v1/nvd          nvd_summary         (severity breakdown + totals)
    POST /api/v1/nvd/import   trigger_import
    GET  /api/v1/nvd/cves     list_cves
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/nvd",
    tags=["NVD CVE"],
)


def _get_importer():
    from feeds.nvd_cve.importer import NvdCveImporter
    return NvdCveImporter()


@router.get("/", dependencies=[Depends(api_key_auth)])
def nvd_summary() -> Dict[str, Any]:
    """Return NVD CVE severity breakdown and total count from the local DB."""
    try:
        importer = _get_importer()
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        breakdown: Dict[str, int] = {}
        total = 0
        for sev in severities:
            result = importer.list_cves(severity=sev, page=1, page_size=1)
            count = result.get("total", 0)
            breakdown[sev.lower()] = count
            total += count
        return {
            "router": "nvd-cve",
            "total_cves": total,
            "severity_breakdown": breakdown,
        }
    except Exception as exc:
        logger.exception("NVD summary failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    days: int = Query(default=7, ge=1, le=120,
                      description="Trailing days to pull (default 7)"),
    full_history: bool = Query(default=False,
                               description="Backfill from 1999-01-01 in 120-day windows"),
) -> Dict[str, Any]:
    """Pull CVEs from the NIST NVD 2.0 API and upsert into the local DB.

    Honors the NVD_API_KEY env var when set (50 req/30s vs 5 req/30s).
    """
    try:
        importer = _get_importer()
        return importer.run(days=days, full_history=full_history)
    except Exception as exc:
        logger.exception("NVD CVE import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/cves", dependencies=[Depends(api_key_auth)])
def list_cves(
    cve_id: Optional[str] = Query(default=None, description="Exact CVE id (e.g. CVE-2023-23397)"),
    severity: Optional[str] = Query(default=None,
                                    description="CVSS baseSeverity: LOW | MEDIUM | HIGH | CRITICAL"),
    published_since: Optional[str] = Query(
        default=None,
        description="ISO-8601 timestamp; return CVEs published at or after this time",
    ),
    cvss_min: Optional[float] = Query(default=None, ge=0.0, le=10.0,
                                      description="Minimum CVSS base score"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """List NVD CVEs from the local DB with optional filters."""
    try:
        importer = _get_importer()
        return importer.list_cves(
            cve_id=cve_id,
            severity=severity,
            published_since=published_since,
            cvss_min=cvss_min,
            page=page,
            page_size=page_size,
        )
    except Exception as exc:
        logger.exception("Failed to list NVD CVEs")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
