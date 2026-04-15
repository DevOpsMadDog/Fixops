"""
SBOM lifecycle management API router for ALDECI.

Provides endpoints for importing, exporting, querying, and diffing
Software Bills of Materials (SBOMs) in CycloneDX and SPDX formats.

Routes:
- POST   /api/v1/sbom/import        — import SBOM
- GET    /api/v1/sbom               — list SBOMs
- GET    /api/v1/sbom/diff          — diff two SBOMs
- GET    /api/v1/sbom/{id}          — get SBOM details
- GET    /api/v1/sbom/{id}/export   — export SBOM
- GET    /api/v1/sbom/{id}/components  — list components
- GET    /api/v1/sbom/{id}/vulnerabilities  — vulnerable components
- GET    /api/v1/sbom/{id}/licenses — license compliance report
- DELETE /api/v1/sbom/{id}          — delete SBOM

Protected by api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sbom",
    tags=["sbom"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy singletons (avoids import-time SQLite init during tests)
# ---------------------------------------------------------------------------

_manager = None
_generator = None


def _get_manager():
    global _manager
    if _manager is None:
        from core.sbom_manager import SBOMManager
        _manager = SBOMManager()
    return _manager


def _get_generator():
    global _generator
    if _generator is None:
        from core.sbom_generator import SBOMGenerator
        _generator = SBOMGenerator()
    return _generator


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ImportRequest(BaseModel):
    content: str = Field(..., description="Raw SBOM JSON content")
    format: str = Field(..., description="cyclonedx, spdx, or custom")
    project_name: str = Field(..., description="Name of the project")
    org_id: str = Field(default="default", description="Organisation ID")


class GenerateRequest(BaseModel):
    content: str = Field(..., description="Raw dependency file content")
    file_type: str = Field(
        ...,
        description="requirements.txt, package.json, or go.mod",
    )
    format: str = Field(default="cyclonedx", description="cyclonedx or spdx")
    target: str = Field(default="", description="Target project / repo name")
    org_id: str = Field(default="default", description="Organisation ID")


class ScanDirectoryRequest(BaseModel):
    directory: str = Field(..., description="Absolute path to scan for dependency files")
    format: str = Field(default="cyclonedx", description="cyclonedx or spdx")
    org_id: str = Field(default="default", description="Organisation ID")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/import", summary="Import SBOM")
async def import_sbom(req: ImportRequest) -> Dict[str, Any]:
    """Parse and store a CycloneDX or SPDX SBOM."""
    from core.sbom_manager import SBOMFormat

    try:
        fmt = SBOMFormat(req.format.lower())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown format {req.format!r}. Use cyclonedx, spdx, or custom.",
        )

    try:
        sbom = _get_manager().import_sbom(
            content=req.content,
            format=fmt,
            project_name=req.project_name,
            org_id=req.org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "id": sbom.id,
        "format": sbom.format.value,
        "spec_version": sbom.spec_version,
        "project_name": sbom.project_name,
        "project_version": sbom.project_version,
        "component_count": len(sbom.components),
        "created_at": sbom.created_at,
        "org_id": sbom.org_id,
    }


@router.get("", summary="List SBOMs")
async def list_sboms(
    org_id: Optional[str] = Query(default=None),
    project_name: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """List stored SBOMs, optionally filtered by org or project."""
    sboms = _get_manager().list_sboms(org_id=org_id, project_name=project_name)
    return {
        "sboms": [
            {
                "id": s.id,
                "format": s.format.value,
                "project_name": s.project_name,
                "project_version": s.project_version,
                "component_count": len(s.components),
                "created_at": s.created_at,
                "org_id": s.org_id,
            }
            for s in sboms
        ],
        "total": len(sboms),
    }


@router.get("/diff", summary="Diff two SBOMs")
async def diff_sboms(
    a: str = Query(..., description="First SBOM ID"),
    b: str = Query(..., description="Second SBOM ID"),
) -> Dict[str, Any]:
    """Compare two SBOM versions: returns added, removed, updated components."""
    try:
        return _get_manager().diff_sboms(a, b)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/{sbom_id}", summary="Get SBOM details")
async def get_sbom(sbom_id: str) -> Dict[str, Any]:
    """Return full SBOM including all components."""
    try:
        sbom = _get_manager().get_sbom(sbom_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return sbom.model_dump()


@router.get("/{sbom_id}/export", summary="Export SBOM")
async def export_sbom(
    sbom_id: str,
    format: str = Query(default="cyclonedx", description="cyclonedx or spdx"),
) -> Dict[str, Any]:
    """Export SBOM in the specified format (CycloneDX or SPDX JSON)."""
    from core.sbom_manager import SBOMFormat

    try:
        fmt = SBOMFormat(format.lower())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown format {format!r}")

    try:
        content = _get_manager().export_sbom(sbom_id, fmt)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {"sbom_id": sbom_id, "format": fmt.value, "content": content}


@router.get("/{sbom_id}/components", summary="List components")
async def get_components(sbom_id: str) -> Dict[str, Any]:
    """Return all components for a given SBOM."""
    try:
        components = _get_manager().get_components(sbom_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "sbom_id": sbom_id,
        "components": [c.model_dump() for c in components],
        "total": len(components),
    }


@router.get("/{sbom_id}/vulnerabilities", summary="Vulnerable components")
async def get_vulnerabilities(sbom_id: str) -> Dict[str, Any]:
    """Map SBOM components to known CVEs and return vulnerable entries."""
    try:
        vulns = _get_manager().map_vulnerabilities(sbom_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "sbom_id": sbom_id,
        "vulnerable_components": [v.model_dump() for v in vulns],
        "total": len(vulns),
    }


@router.get("/{sbom_id}/licenses", summary="License compliance check")
async def check_licenses(sbom_id: str) -> Dict[str, Any]:
    """Run license compliance check and flag copyleft/unknown licenses."""
    try:
        report = _get_manager().check_licenses(sbom_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    flagged = [item for item in report if item["flagged"]]
    return {
        "sbom_id": sbom_id,
        "report": report,
        "flagged_count": len(flagged),
        "total": len(report),
    }


@router.delete("/{sbom_id}", summary="Delete SBOM")
async def delete_sbom(sbom_id: str) -> Dict[str, Any]:
    """Delete an SBOM and all associated components."""
    try:
        _get_manager().delete_sbom(sbom_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"deleted": True, "sbom_id": sbom_id}


# ---------------------------------------------------------------------------
# Generation endpoints (use SBOMGenerator)
# ---------------------------------------------------------------------------


@router.post("/generate", summary="Generate SBOM from dependency file content")
async def generate_sbom(req: GenerateRequest) -> Dict[str, Any]:
    """Parse dependency file content and return a CycloneDX or SPDX SBOM."""
    gen = _get_generator()
    file_type = req.file_type.lower().strip()

    if file_type == "requirements.txt":
        components = gen.parse_requirements_txt(req.content)
    elif file_type == "package.json":
        components = gen.parse_package_json(req.content)
    elif file_type == "go.mod":
        components = gen.parse_go_mod(req.content)
    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file_type {req.file_type!r}. Use requirements.txt, package.json, or go.mod.",
        )

    fmt = req.format.lower()
    if fmt == "cyclonedx":
        sbom = gen.generate_cyclonedx(components)
    elif fmt == "spdx":
        sbom = gen.generate_spdx(components)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown format {req.format!r}. Use cyclonedx or spdx.")

    target = req.target or file_type
    sbom_id = gen.store_sbom(sbom, fmt, target, req.org_id)
    return {"sbom_id": sbom_id, "format": fmt, "component_count": len(components), "sbom": sbom}


@router.post("/scan-directory", summary="Scan directory for dependency files and generate SBOM")
async def scan_directory(req: ScanDirectoryRequest) -> Dict[str, Any]:
    """Scan a directory for requirements.txt / package.json / go.mod and produce a unified SBOM."""
    from pathlib import Path as _Path

    if not _Path(req.directory).is_dir():
        raise HTTPException(status_code=400, detail=f"Directory not found or not accessible: {req.directory}")

    gen = _get_generator()
    components = gen.scan_directory(req.directory)

    fmt = req.format.lower()
    if fmt == "cyclonedx":
        sbom = gen.generate_cyclonedx(components)
    elif fmt == "spdx":
        sbom = gen.generate_spdx(components)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown format {fmt!r}. Use cyclonedx or spdx.")

    sbom_id = gen.store_sbom(sbom, fmt, req.directory, req.org_id)
    return {
        "sbom_id": sbom_id,
        "format": fmt,
        "directory": req.directory,
        "component_count": len(components),
        "sbom": sbom,
    }


# ---------------------------------------------------------------------------
# High-level scan endpoints (read from project filesystem)
# ---------------------------------------------------------------------------


@router.get("/cyclonedx", summary="Generate CycloneDX SBOM from project deps")
async def generate_cyclonedx_from_project(
    org_id: str = Query(default="default", description="Organisation ID"),
    include_python: bool = Query(default=True, description="Include Python deps from requirements.txt"),
    include_js: bool = Query(default=True, description="Include JS deps from package.json"),
) -> Dict[str, Any]:
    """Scan project manifests and return a CycloneDX 1.4 SBOM."""
    gen = _get_generator()
    components: list = []
    if include_python:
        components.extend(gen.scan_python_deps(org_id))
    if include_js:
        components.extend(gen.scan_js_deps(org_id))
    sbom = gen.generate_cyclonedx(components)
    return {"format": "cyclonedx", "component_count": len(components), "sbom": sbom}


@router.get("/spdx", summary="Generate SPDX SBOM from project deps")
async def generate_spdx_from_project(
    org_id: str = Query(default="default", description="Organisation ID"),
    include_python: bool = Query(default=True, description="Include Python deps from requirements.txt"),
    include_js: bool = Query(default=True, description="Include JS deps from package.json"),
) -> Dict[str, Any]:
    """Scan project manifests and return an SPDX 2.3 SBOM."""
    gen = _get_generator()
    components: list = []
    if include_python:
        components.extend(gen.scan_python_deps(org_id))
    if include_js:
        components.extend(gen.scan_js_deps(org_id))
    sbom = gen.generate_spdx(components)
    return {"format": "spdx", "component_count": len(components), "sbom": sbom}


@router.get("/stats", summary="SBOM dependency statistics")
async def get_sbom_stats(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return dependency counts (python_deps, js_deps, total_deps, generated_at)."""
    gen = _get_generator()
    return gen.get_sbom_stats(org_id)


@router.get("/{sbom_id}/diff/{other_id}", summary="Diff two generated SBOMs")
async def diff_generated_sboms(sbom_id: str, other_id: str) -> Dict[str, Any]:
    """Compare two SBOMs stored via the generate endpoint."""
    gen = _get_generator()
    try:
        result = gen.diff_sboms(sbom_id, other_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"sbom_id_a": sbom_id, "sbom_id_b": other_id, **result}
