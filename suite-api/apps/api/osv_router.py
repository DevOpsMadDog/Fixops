"""OSV (Open Source Vulnerabilities) Router — ALDECI.

Endpoints to import and query vulnerability records from OSV.dev.

Prefix: /api/v1/osv
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/osv/import   trigger_import (per-ecosystem zip backfill)
  GET  /api/v1/osv/vulns    list_vulns    (filters: id, ecosystem, package, severity)
  GET  /api/v1/osv/stats    get_stats     (totals + breakdowns)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/osv",
    tags=["OSV"],
)


def _get_importer():
    from feeds.osv.importer import (
        DEFAULT_ECOSYSTEM,
        SUPPORTED_ECOSYSTEMS,
        get_store_stats,
        list_vulns,
        poll_feed_status,
        run_import,
    )
    return run_import, list_vulns, get_store_stats, SUPPORTED_ECOSYSTEMS, DEFAULT_ECOSYSTEM, poll_feed_status


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import(
    ecosystem: Optional[str] = Query(
        default=None,
        description=(
            "Ecosystem to import (e.g. PyPI, npm, Maven, Go, RubyGems, NuGet, "
            "crates.io, Packagist, Hex). Default: PyPI."
        ),
    ),
    ecosystems: Optional[List[str]] = Query(
        default=None,
        description="Multiple ecosystems (repeated query param) — overrides `ecosystem`.",
    ),
) -> Dict[str, Any]:
    """Download the OSV per-ecosystem zip(s) and import every vulnerability.

    Pulls https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip,
    stream-parses each JSON entry, normalises into the OSV schema shape ALDECI
    uses, and upserts into data/osv.db keyed by vuln id (idempotent).
    """
    try:
        run_import, _l, _s, supported, default_eco, _p = _get_importer()
        if ecosystems:
            return run_import(ecosystems=ecosystems)
        return run_import(ecosystem=ecosystem or default_eco)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("OSV import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/vulns", dependencies=[Depends(api_key_auth)])
def list_osv_vulns(
    id: Optional[str] = Query(
        default=None,
        description="Filter by OSV id or alias (e.g. CVE-2024-1234, GHSA-xxxx-xxxx).",
    ),
    ecosystem: Optional[str] = Query(
        default=None,
        description="Filter by ecosystem (PyPI, npm, Maven, Go, …).",
    ),
    package: Optional[str] = Query(
        default=None,
        description="Filter by package name (case-insensitive exact match).",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity bucket: critical | high | medium | low | none | unknown",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List OSV vulns from the local DB with optional filters."""
    try:
        _r, list_vulns, _s, _e, _d, _p = _get_importer()
        vulns = list_vulns(
            id=id,
            ecosystem=ecosystem,
            package=package,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {
            "vulns": vulns,
            "total": len(vulns),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list OSV vulns")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total OSV vuln count + per-ecosystem and per-severity breakdowns."""
    try:
        _r, _l, get_store_stats, _e, _d, _p = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get OSV stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/poll", dependencies=[Depends(api_key_auth)])
def poll_feed(
    ecosystem: Optional[List[str]] = Query(
        default=None,
        description=(
            "Ecosystem(s) to HEAD-check (repeatable). "
            "Omit to check all supported ecosystems. "
            "Supported: PyPI, npm, Maven, Go, RubyGems, NuGet, crates.io, Packagist, Hex."
        ),
    ),
    timeout: float = Query(
        default=15.0,
        ge=1.0,
        le=60.0,
        description="Per-request HTTP timeout in seconds (1–60).",
    ),
) -> Dict[str, Any]:
    """HEAD-check OSV feed zips and report whether any ecosystem needs a re-import.

    Sends a lightweight HTTP HEAD request to the Google OSV bucket for each
    requested ecosystem, reads Content-Length and Last-Modified headers, and
    compares against the cached size from the previous poll.  No data is
    downloaded.  ``needs_update: true`` in a result row means the remote zip
    has changed size since the last poll and a fresh ``POST /import`` is
    advisable for that ecosystem.
    """
    try:
        _r, _l, _s, _e, _d, poll_feed_status = _get_importer()
        return poll_feed_status(ecosystems=ecosystem, timeout=timeout)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("OSV feed poll failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
