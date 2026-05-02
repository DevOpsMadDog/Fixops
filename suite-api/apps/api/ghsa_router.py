"""GitHub Advisory Database (GHSA) Router — ALDECI.

Endpoints to import and query GHSA advisories.

Prefix: /api/v1/ghsa
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/ghsa/import       trigger_import
  GET  /api/v1/ghsa/advisories   list_ghsa_advisories
  GET  /api/v1/ghsa/stats        get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ghsa",
    tags=["GHSA"],
)


def _get_importer():
    from feeds.ghsa.importer import get_store_stats, list_advisories, run_import
    return run_import, list_advisories, get_store_stats


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    local_path: Optional[str] = Query(
        default=None,
        description=(
            "Optional path to an already-cloned advisory-database checkout. "
            "When set, the importer skips the network fetch and walks the "
            "directory directly (operator-friendly air-gapped mode)."
        ),
    ),
) -> Dict[str, Any]:
    """Pull github/advisory-database and import every reviewed advisory.

    Network: ``git clone --depth 1`` is preferred; falls back to a master
    tarball when the git binary is unavailable.

    Returns counts keyed by ``advisories_imported``, ``by_ecosystem``,
    ``by_severity``, and ``with_cve_alias``.
    """
    try:
        run_import, _l, _s = _get_importer()
        return run_import(local_path=local_path)
    except Exception as exc:
        logger.exception("GHSA import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/advisories", dependencies=[Depends(api_key_auth)])
def list_ghsa_advisories(
    id: Optional[str] = Query(default=None, description="Filter by GHSA id (exact match)."),
    cve_id: Optional[str] = Query(default=None, description="Filter by CVE alias (e.g. CVE-2024-12345)."),
    ecosystem: Optional[str] = Query(
        default=None,
        description="Filter by ecosystem: PyPI | npm | Maven | RubyGems | Go | NuGet | composer | crates.io | …",
    ),
    package: Optional[str] = Query(default=None, description="Filter by affected package name."),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity. Accepts 'low', 'moderate', 'high', 'critical', "
                    "a comma-separated list, or the alias 'high+critical'.",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List GHSA advisories from the local DB with optional filters."""
    try:
        _r, list_advisories, _s = _get_importer()
        advisories = list_advisories(
            id=id,
            cve_id=cve_id,
            ecosystem=ecosystem,
            package=package,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {
            "advisories": advisories,
            "total": len(advisories),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list GHSA advisories")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total GHSA advisory count and breakdowns."""
    try:
        _r, _l, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get GHSA stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
