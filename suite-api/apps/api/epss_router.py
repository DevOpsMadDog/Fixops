"""EPSS (Exploit Prediction Scoring System) Router — ALDECI.

Endpoints to import and query FIRST.org EPSS daily scores.

Prefix: /api/v1/epss
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/epss/import           trigger_import
  GET  /api/v1/epss/scores           list_scores
  GET  /api/v1/epss/scores/{cve_id}  get_score_by_cve
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/epss",
    tags=["EPSS"],
)


def _get_importer():
    from feeds.epss.importer import EpssImporter
    return EpssImporter


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Download and import the FIRST.org EPSS daily CSV feed.

    Pulls https://epss.cyentia.com/epss_scores-current.csv.gz, decompresses,
    REPLACES all rows in the local epss.db table, and returns:
        {"scores_imported": N, "high_risk_count": <epss > 0.5>,
         "source_url": "..."}
    """
    try:
        EpssImporter = _get_importer()
        return EpssImporter().run()
    except Exception as exc:
        logger.exception("EPSS import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/scores", dependencies=[Depends(api_key_auth)])
def list_epss_scores(
    cve_id: Optional[str] = Query(
        default=None,
        description="Exact-match filter on CVE ID (e.g. CVE-2021-44228)",
    ),
    epss_min: Optional[float] = Query(
        default=None,
        ge=0.0,
        le=1.0,
        description="Minimum EPSS score (0..1, inclusive)",
    ),
    percentile_min: Optional[float] = Query(
        default=None,
        ge=0.0,
        le=1.0,
        description="Minimum EPSS percentile (0..1, inclusive)",
    ),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
) -> Dict[str, Any]:
    """List EPSS scores ordered by epss_score DESC, with optional filters."""
    try:
        EpssImporter = _get_importer()
        return EpssImporter().list_scores(
            page=page,
            page_size=page_size,
            cve_id=cve_id,
            epss_min=epss_min,
            percentile_min=percentile_min,
        )
    except Exception as exc:
        logger.exception("Failed to list EPSS scores")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scores/{cve_id}", dependencies=[Depends(api_key_auth)])
def get_score_by_cve(cve_id: str) -> Dict[str, Any]:
    """Return the EPSS score for a single CVE, or 404 if unknown."""
    try:
        EpssImporter = _get_importer()
        row = EpssImporter().get_by_cve(cve_id)
    except Exception as exc:
        logger.exception("Failed to get EPSS score for %s", cve_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"No EPSS score found for {cve_id}",
        )
    return row
