"""Nuclei DAST + Templates Router — ALDECI.

Combines the original ProjectDiscovery Nuclei templates importer surface
with a DAST scan-orchestration surface backed by NucleiScanEngine
(``suite-core/core/nuclei_scan_engine.py``).

Prefix: ``/api/v1/nuclei``
Auth scope (mounted in platform_app.py): ``read:scans``

Routes
------
DAST (NucleiScanEngine)
  GET  /api/v1/nuclei/                  capability_summary
  GET  /api/v1/nuclei/templates         template catalog (categories + counts)
  POST /api/v1/nuclei/scan              queue a Nuclei scan against target_url
  GET  /api/v1/nuclei/scan/{scan_id}    fetch a scan record (status + findings)

Templates importer (legacy)
  POST /api/v1/nuclei/import            trigger_import
  GET  /api/v1/nuclei/templates/import-stats
                                        global importer stats

The router degrades gracefully:
- If the ``nuclei`` binary is absent, the engine reports
  ``status=unavailable`` and queued scans are persisted as such (NO MOCKS).
- If the templates importer module is absent, ``GET /templates`` still
  returns the canonical category list with zero counts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth
from core.nuclei_scan_engine import (
    SEVERITY_LEVELS,
    TEMPLATE_CATEGORIES,
    get_nuclei_scan_engine,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/nuclei",
    tags=["Nuclei", "DAST"],
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class NucleiCapabilityResponse(BaseModel):
    service: str
    engine: str
    status: str
    nuclei_binary_available: bool
    template_categories: List[str]
    severity_levels: List[str]
    scan_count: int
    db_path: str


class NucleiCategoryEntry(BaseModel):
    name: str
    template_count: int


class NucleiTemplatesCatalogResponse(BaseModel):
    categories: List[NucleiCategoryEntry]
    total_templates: int
    category_counts: Dict[str, int]


class NucleiScanRequest(BaseModel):
    target_url: str = Field(..., min_length=1, max_length=2048)
    template_categories: Optional[List[str]] = Field(default=None)
    severity_threshold: Optional[str] = Field(default="medium")
    follow_redirects: Optional[bool] = Field(default=False)
    rate_limit: Optional[int] = Field(default=None, ge=1, le=10000)


class NucleiScanQueuedResponse(BaseModel):
    scan_id: str
    target_url: str
    template_categories: List[str]
    severity_threshold: str
    follow_redirects: bool
    rate_limit: Optional[int] = None
    status: str
    queued_at: str


class NucleiFinding(BaseModel):
    template_id: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    matched_url: Optional[str] = None
    extracted_results: Optional[List[Any]] = None


class NucleiScanRecordResponse(BaseModel):
    scan_id: str
    target_url: str
    template_categories: List[str]
    status: str
    severity_counts: Dict[str, int]
    category_counts: Dict[str, int]
    findings: List[NucleiFinding] = Field(default_factory=list)
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    exit_code: Optional[int] = None


# ---------------------------------------------------------------------------
# Templates importer lazy hook
# ---------------------------------------------------------------------------

def _get_importer():
    """Lazy import of the templates importer; may raise ImportError."""
    from feeds.nuclei_templates.importer import (  # noqa: PLC0415
        get_store_stats,
        list_templates,
        run_import,
    )
    return run_import, list_templates, get_store_stats


# ---------------------------------------------------------------------------
# DAST endpoints (NucleiScanEngine)
# ---------------------------------------------------------------------------


@router.get(
    "/",
    response_model=NucleiCapabilityResponse,
    summary="Nuclei capability summary",
    dependencies=[Depends(api_key_auth)],
)
def capability_summary() -> Dict[str, Any]:
    """Return Nuclei capability descriptor — template categories, severity
    levels, and overall status envelope (``ok``/``empty``/``unavailable``)."""
    engine = get_nuclei_scan_engine()
    return engine.capability_summary()


@router.get(
    "/templates",
    response_model=NucleiTemplatesCatalogResponse,
    summary="List Nuclei template categories with counts",
    dependencies=[Depends(api_key_auth)],
)
def list_template_catalog() -> Dict[str, Any]:
    """Return the canonical Nuclei template-category catalog with per-category
    template counts sourced from the local templates store when present."""
    engine = get_nuclei_scan_engine()
    return engine.template_catalog()


@router.post(
    "/scan",
    response_model=NucleiScanQueuedResponse,
    status_code=202,
    summary="Queue a Nuclei DAST scan",
)
def queue_nuclei_scan(body: NucleiScanRequest) -> Dict[str, Any]:
    """Queue a Nuclei DAST scan against ``target_url``.

    Body fields:
    - ``target_url`` (required, http/https only — SSRF blocked)
    - ``template_categories`` (optional list — defaults to all categories)
    - ``severity_threshold`` (optional — info|low|medium|high|critical, default medium)
    - ``follow_redirects`` (optional bool, default False)
    - ``rate_limit`` (optional int — requests/second, [1,10000])

    When the ``nuclei`` binary is not present, the scan is recorded with
    ``status=unavailable`` rather than fabricating findings (NO MOCKS rule)."""
    engine = get_nuclei_scan_engine()
    try:
        return engine.queue_scan(
            target_url=body.target_url,
            template_categories=body.template_categories,
            severity_threshold=body.severity_threshold,
            follow_redirects=body.follow_redirects,
            rate_limit=body.rate_limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to queue Nuclei scan")
        raise HTTPException(status_code=500, detail=f"queue_nuclei_scan failed: {exc!s}")


@router.get(
    "/scan/{scan_id}",
    response_model=NucleiScanRecordResponse,
    summary="Fetch Nuclei scan status + finding counts",
)
def get_nuclei_scan(scan_id: str) -> Dict[str, Any]:
    """Fetch a Nuclei scan record by ``scan_id`` — includes status, severity
    counts, category counts, and individual findings."""
    engine = get_nuclei_scan_engine()
    try:
        record = engine.get_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {scan_id}")
    return record


# ---------------------------------------------------------------------------
# Templates importer endpoints (preserved from prior router)
# ---------------------------------------------------------------------------


@router.post("/import", dependencies=[Depends(api_key_auth)])
def trigger_import() -> Dict[str, Any]:
    """Download and import all ProjectDiscovery Nuclei templates from main
    branch. Walks every YAML file and upserts into nuclei_templates.db.
    Skips ``.github/``, ``helpers/``, and ``workflows/`` directories.

    Returns a summary with template count broken down by severity and
    category, plus the number of templates with a CVE classification."""
    try:
        run_import, _list, _stats = _get_importer()
        result = run_import()
        return result
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Nuclei templates importer unavailable: {exc}",
        )
    except Exception as exc:
        logger.exception("Nuclei templates import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get(
    "/templates/import-stats",
    dependencies=[Depends(api_key_auth)],
    summary="Importer-side template counts (severity/category breakdown)",
)
def get_import_stats() -> Dict[str, Any]:
    """Return total Nuclei template count plus severity/category breakdowns
    from the local templates importer. Returns 503 when importer absent."""
    try:
        _run, _list, get_store_stats = _get_importer()
        return get_store_stats()
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Nuclei templates importer unavailable: {exc}",
        )
    except Exception as exc:
        logger.exception("Failed to get Nuclei template stats")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/templates/list",
    dependencies=[Depends(api_key_auth)],
    summary="List individual Nuclei templates from local importer DB",
)
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
        description="Filter by top-level category dir, e.g. cves|vulnerabilities|misconfiguration",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List Nuclei templates from the local importer DB with optional filters."""
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
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Nuclei templates importer unavailable: {exc}",
        )
    except Exception as exc:
        logger.exception("Failed to list Nuclei templates")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
