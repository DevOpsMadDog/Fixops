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
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/epss",
    tags=["EPSS"],
)

# EPSS data lives in two places for historical reasons: the feed sync that the
# rest of the product uses writes `data/feeds/feeds.db`, while this router's
# own importer writes a standalone `data/epss.db` with a different schema
# (`epss` vs `epss_score`, `date` vs `imported_at`).
#
# Only the feed sync is ever run in practice, so reads here returned an empty
# list while the platform held 360,142 scores — measured 2026-08-16, when
# GET /api/v1/feeds/epss?cve_ids=CVE-2021-44228 returned 0.99999 and
# GET /api/v1/epss/scores for the same CVE returned nothing at all.
#
# Reads now serve the canonical store, falling back to the standalone one when
# the canonical store is absent (a deployment that only ever ran /epss/import).
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _canonical_epss_db() -> Path:
    """Path to the feed-sync store that the rest of the product reads."""
    override = os.environ.get("FIXOPS_FEEDS_DB")
    if override:
        return Path(override)
    return _REPO_ROOT / "data" / "feeds" / "feeds.db"


def _canonical_available() -> bool:
    db = _canonical_epss_db()
    if not db.exists():
        return False
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master "
                "WHERE type='table' AND name='epss_scores'"
            ).fetchone()
            return bool(row and row[0])
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def _canonical_query(
    *,
    cve_id: Optional[str],
    epss_min: Optional[float],
    percentile_min: Optional[float],
    page: int,
    page_size: int,
) -> Dict[str, Any]:
    """Query the canonical feeds store, shaped like the importer's response."""
    conn = sqlite3.connect(f"file:{_canonical_epss_db()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conditions: List[str] = []
        params: List[Any] = []
        if cve_id:
            conditions.append("cve_id = ?")
            params.append(cve_id.strip().upper())
        if epss_min is not None:
            conditions.append("epss >= ?")
            params.append(epss_min)
        if percentile_min is not None:
            conditions.append("percentile >= ?")
            params.append(percentile_min)
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM epss_scores{where}", params
        ).fetchone()[0]

        rows = conn.execute(
            "SELECT cve_id, epss AS epss_score, percentile, date AS imported_at "
            f"FROM epss_scores{where} ORDER BY epss DESC LIMIT ? OFFSET ?",
            [*params, page_size, (page - 1) * page_size],
        ).fetchall()

        return {
            "scores": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
        }
    finally:
        conn.close()


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
    """List EPSS scores ordered by score DESC, with optional filters."""
    if _canonical_available():
        try:
            return _canonical_query(
                cve_id=cve_id,
                epss_min=epss_min,
                percentile_min=percentile_min,
                page=page,
                page_size=page_size,
            )
        except sqlite3.Error as exc:
            logger.warning("Canonical EPSS store unreadable, falling back: %s", exc)

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
    if _canonical_available():
        try:
            result = _canonical_query(
                cve_id=cve_id,
                epss_min=None,
                percentile_min=None,
                page=1,
                page_size=1,
            )
            scores = result["scores"]
            if scores:
                return scores[0]
            raise HTTPException(
                status_code=404, detail=f"No EPSS score found for {cve_id}"
            )
        except sqlite3.Error as exc:
            logger.warning("Canonical EPSS store unreadable, falling back: %s", exc)

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
