"""Nuclei Templates Router — ALDECI.

Provides endpoints to import and query ProjectDiscovery Nuclei detection templates.

Prefix: /api/v1/nuclei
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/nuclei/import          trigger_import
  GET  /api/v1/nuclei/templates       list_templates
  GET  /api/v1/nuclei/stats           get_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/nuclei",
    tags=["Nuclei Templates"],
)


def _get_importer():
    """Lazy import to avoid heavy deps at process start."""
    from feeds.nuclei_templates.importer import (
        get_store_stats,
        list_templates,
        run_import,
    )
    return run_import, list_templates, get_store_stats


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Download and import all ProjectDiscovery Nuclei templates from main branch.

    Downloads https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.tar.gz,
    walks every YAML file, and upserts all templates into the local
    nuclei_templates.db.  Skips .github/, helpers/, and workflows/ directories.

    Returns a summary with total template count broken down by severity and
    category, plus the number of templates with a CVE classification.
    """
    try:
        run_import, _list, _stats = _get_importer()
        result = run_import()
        return result
    except Exception as exc:
        logger.exception("Nuclei templates import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/templates", dependencies=[Depends(api_key_auth)])
def list_nuclei_templates(
    severity: Optional[str] = Query(
        default=None,
        description="Filter by severity: info | low | medium | high | critical",
    ),
    tag: Optional[str] = Query(
        default=None,
        description="Filter by tag substring, e.g. 'rce' or 'sqli'",
    ),
    cve_id: Optional[str] = Query(
        default=None,
        description="Filter by exact CVE ID, e.g. CVE-2021-44228",
    ),
    category: Optional[str] = Query(
        default=None,
        description="Filter by top-level category directory, e.g. cves | vulnerabilities | misconfiguration",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List Nuclei templates from the local DB with optional filters."""
    try:
        _run, list_templates, _stats = _get_importer()
        templates = list_templates(
            severity=severity,
            tag=tag,
            cve_id=cve_id,
            category=category,
            limit=limit,
            offset=offset,
        )
        return {
            "templates": templates,
            "total": len(templates),
            "offset": offset,
            "limit": limit,
        }
    except Exception as exc:
        logger.exception("Failed to list Nuclei templates")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Return total Nuclei template count and breakdowns by severity and category."""
    try:
        _run, _list, get_store_stats = _get_importer()
        return get_store_stats()
    except Exception as exc:
        logger.exception("Failed to get Nuclei template stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
