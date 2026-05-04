"""Dependency-Track integration router — primary SBOM engine for FixOps.

OWASP Dependency-Track is the single source of truth for:
  - SBOM lifecycle (upload CycloneDX/SPDX, track components, export)
  - Vulnerability monitoring (NVD, OSS Index, GitHub Advisories, Snyk, OSV)
  - License compliance (policy engine with SPDX license detection)
  - Portfolio-wide impact analysis ("which apps use log4j?")
  - VEX (Vulnerability Exploitability eXchange) for analysis decisions

All endpoints proxy to DependencyTrackConnector which handles retries,
circuit breaking, and rate limiting.

Prefix: /api/v1/dtrack
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.security_connectors import DependencyTrackConnector
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dtrack", tags=["dependency-track"])

# Lazy singleton — created on first request so env vars are read at runtime
_connector: Optional[DependencyTrackConnector] = None


def _get_connector() -> DependencyTrackConnector:
    global _connector
    if _connector is None:
        _connector = DependencyTrackConnector()
    return _connector


def _require_configured() -> DependencyTrackConnector:
    """Return connector or raise 503 if not configured."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Dependency-Track not configured",
                "hint": "Set DTRACK_URL and DTRACK_API_KEY environment variables",
                "docs": "https://docs.dependencytrack.org/",
            },
        )
    return conn


# ── Health ──────────────────────────────────────────────────────────────────


@router.get("/health")
async def dtrack_health() -> Dict[str, Any]:
    """Check Dependency-Track connectivity and version."""
    conn = _get_connector()
    if not conn.configured:
        return {
            "status": "not_configured",
            "message": "Set DTRACK_URL and DTRACK_API_KEY to enable SBOM analysis",
        }
    health = conn.health_check()
    return health.to_dict()


# ── Projects ────────────────────────────────────────────────────────────────


@router.get("/projects")
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List all Dependency-Track projects (applications with SBOMs)."""
    conn = _require_configured()
    return conn.list_projects(page_size=page_size, page=page)


@router.get("/projects/lookup")
async def lookup_project(
    name: str = Query(...),
    version: str = Query("latest"),
) -> Dict[str, Any]:
    """Lookup or create a Dependency-Track project by name + version."""
    conn = _require_configured()
    return conn.get_or_create_project(name=name, version=version)


# ── SBOM Upload ─────────────────────────────────────────────────────────────


class SBOMUploadRequest(BaseModel):
    """Upload SBOM via JSON body (alternative to file upload)."""

    project_name: str = Field(..., description="Target project name in Dependency-Track", max_length=512)
    project_version: str = Field("latest", description="Project version tag", max_length=128)
    sbom: str = Field(..., description="Raw CycloneDX/SPDX JSON or XML as string", max_length=10_000_000)
    auto_create: bool = Field(True, description="Auto-create project if it doesn't exist")


@router.post("/sbom/upload")
async def upload_sbom_json(req: SBOMUploadRequest) -> Dict[str, Any]:
    """Upload a CycloneDX or SPDX SBOM (JSON body). DTrack auto-detects format."""
    conn = _require_configured()
    outcome = conn.upload_sbom(
        project_name=req.project_name,
        sbom_content=req.sbom,
        project_version=req.project_version,
        auto_create=req.auto_create,
    )
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details)
    return {
        "status": "uploaded",
        "message": "SBOM submitted to Dependency-Track for analysis",
        **outcome.details,
    }


@router.post("/sbom/upload-file")
async def upload_sbom_file(
    file: UploadFile = File(..., description="CycloneDX or SPDX SBOM file"),
    project_name: str = Query(..., description="Target project name"),
    project_version: str = Query("latest"),
) -> Dict[str, Any]:
    """Upload a CycloneDX or SPDX SBOM file. DTrack auto-detects format."""
    conn = _require_configured()
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=413, detail="SBOM file exceeds 50MB limit")
    outcome = conn.upload_sbom(
        project_name=project_name,
        sbom_content=content,
        project_version=project_version,
    )
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details)
    return {
        "status": "uploaded",
        "filename": file.filename,
        **outcome.details,
    }


@router.get("/sbom/status/{token}")
async def sbom_processing_status(token: str) -> Dict[str, Any]:
    """Check whether a previously uploaded SBOM has been fully processed."""
    conn = _require_configured()
    return conn.get_bom_processing_status(token)


@router.get("/sbom/export/{project_uuid}")
async def export_sbom(
    project_uuid: str,
    fmt: str = Query("json", pattern="^(json|xml)$"),
) -> Dict[str, Any]:
    """Export the current SBOM for a project in CycloneDX format."""
    conn = _require_configured()
    outcome = conn.export_sbom(project_uuid, fmt=fmt)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Export failed"))
    return outcome.details


# ── Components ──────────────────────────────────────────────────────────────


@router.get("/components/{project_uuid}")
async def get_project_components(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch all components (dependencies) for a project."""
    conn = _require_configured()
    outcome = conn.fetch_project_components(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


@router.get("/components/search")
async def search_components(
    query: str = Query(..., min_length=2, description="Component name to search (e.g. 'log4j')"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Search components across entire portfolio. Use for impact analysis
    (e.g., 'which applications use log4j?')."""
    conn = _require_configured()
    outcome = conn.search_components(query, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Findings (vulnerabilities) ──────────────────────────────────────────────


@router.get("/findings/{project_uuid}")
async def get_findings(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch vulnerability findings for a project from Dependency-Track."""
    conn = _require_configured()
    outcome = conn.fetch_findings(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Licenses ────────────────────────────────────────────────────────────────


@router.get("/licenses/{project_uuid}")
async def get_licenses(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch component license data for a project."""
    conn = _require_configured()
    outcome = conn.fetch_licenses(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Policy violations ───────────────────────────────────────────────────────


@router.get("/violations/{project_uuid}")
async def get_policy_violations(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch policy violations for a project."""
    conn = _require_configured()
    outcome = conn.fetch_policy_violations(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── VEX (Vulnerability Exploitability eXchange) ────────────────────────────


class VEXUploadRequest(BaseModel):
    """Upload VEX document to apply analysis decisions in bulk."""

    project_name: str = Field(..., description="Target project name")
    project_version: str = Field("latest")
    vex: str = Field(..., description="CycloneDX VEX JSON document as string")


@router.post("/vex/upload")
async def upload_vex(req: VEXUploadRequest) -> Dict[str, Any]:
    """Upload a CycloneDX VEX document to apply analysis decisions
    (e.g., mark findings as not_affected, false_positive, in_triage)."""
    conn = _require_configured()
    outcome = conn.upload_vex(
        project_name=req.project_name,
        vex_content=req.vex,
        project_version=req.project_version,
    )
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details)
    return {"status": "applied", **outcome.details}


# ── Project tags ────────────────────────────────────────────────────────────


class TagRequest(BaseModel):
    """Add tags to a project for FixOps categorization."""

    tags: List[str] = Field(..., description="Tags to add (e.g., ['production', 'pci-dss'])")


@router.post("/projects/{project_uuid}/tags")
async def tag_project(project_uuid: str, req: TagRequest) -> Dict[str, Any]:
    """Add tags to a project for FixOps categorization and filtering."""
    conn = _require_configured()
    outcome = conn.tag_project(project_uuid, tags=req.tags)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details)
    return {"status": "tagged", **outcome.details}


# ── Metrics ─────────────────────────────────────────────────────────────────


@router.get("/metrics/portfolio")
async def portfolio_metrics() -> Dict[str, Any]:
    """Fetch portfolio-wide vulnerability metrics from Dependency-Track."""
    conn = _require_configured()
    outcome = conn.fetch_portfolio_metrics()
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


@router.get("/metrics/project/{project_uuid}")
async def project_metrics(project_uuid: str) -> Dict[str, Any]:
    """Fetch project-level vulnerability metrics from Dependency-Track."""
    conn = _require_configured()
    outcome = conn.fetch_project_metrics(project_uuid)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details

