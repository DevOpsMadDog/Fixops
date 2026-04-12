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
# Lazy manager singleton (avoids import-time SQLite init during tests)
# ---------------------------------------------------------------------------

_manager = None


def _get_manager():
    global _manager
    if _manager is None:
        from core.sbom_manager import SBOMManager
        _manager = SBOMManager()
    return _manager


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ImportRequest(BaseModel):
    content: str = Field(..., description="Raw SBOM JSON content")
    format: str = Field(..., description="cyclonedx, spdx, or custom")
    project_name: str = Field(..., description="Name of the project")
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
