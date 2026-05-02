"""SBOM Export Router — ALDECI.

CycloneDX 1.4 and SPDX 2.3 SBOM generation endpoints.

Prefix: /api/v1/sbom-export
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/sbom-export/components                        register_component
  POST /api/v1/sbom-export/components/{id}/vulns             add_vuln
  POST /api/v1/sbom-export/generate/cyclonedx               generate_cyclonedx
  POST /api/v1/sbom-export/generate/spdx                    generate_spdx
  GET  /api/v1/sbom-export/projects                         list_projects
  GET  /api/v1/sbom-export/projects/{project_name}/summary  get_project_summary
  GET  /api/v1/sbom-export/projects/{project_name}/history  get_export_history
  GET  /api/v1/sbom-export/search                           search_component
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sbom-export",
    tags=["SBOM Export"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.sbom_export_engine import SBOMExportEngine
        _engine = SBOMExportEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class RegisterComponentRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    project_name: str = Field(..., description="Project name")
    component_name: str = Field(..., description="Component name")
    component_version: str = Field(..., description="Component version")
    component_type: str = Field(..., description="library|framework|application|container|device|firmware|file|operating-system")
    ecosystem: str = Field(default="", description="npm|pypi|maven|nuget|cargo|go|gem|composer")
    license: str = Field(default="", description="SPDX license identifier")
    purl: str = Field(default="", description="Package URL")
    cpe: str = Field(default="", description="CPE identifier")
    supplier: str = Field(default="", description="Supplier/vendor name")
    hash_sha256: str = Field(default="", description="SHA-256 hash of component")


class AddVulnRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    cve_id: str = Field(..., description="CVE identifier")
    severity: str = Field(..., description="critical|high|medium|low|informational")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0, description="CVSS score")
    affects_version: str = Field(default="", description="Affected version string")
    fixed_in: str = Field(default="", description="Version where fix is available")


class GenerateRequest(BaseModel):
    org_id: str = Field(..., description="Organisation ID")
    project_name: str = Field(..., description="Project name")
    version_tag: str = Field(default="1.0", description="SBOM version tag")
    exported_by: str = Field(default="", description="Exporting user/system")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_sbom_exports(org_id: str = Query("default")) -> Dict[str, Any]:
    """List SBOM projects for the org."""
    projects = _get_engine().list_projects(org_id=org_id)
    return {"org_id": org_id, "projects": projects, "total": len(projects)}


@router.post("/components", dependencies=[Depends(api_key_auth)], status_code=201)
def register_component(req: RegisterComponentRequest) -> Dict[str, Any]:
    """Register a software component (deduped by org+project+name+version)."""
    try:
        return _get_engine().register_component(
            org_id=req.org_id,
            project_name=req.project_name,
            component_name=req.component_name,
            component_version=req.component_version,
            component_type=req.component_type,
            ecosystem=req.ecosystem,
            license=req.license,
            purl=req.purl,
            cpe=req.cpe,
            supplier=req.supplier,
            hash_sha256=req.hash_sha256,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/components/{component_id}/vulns", dependencies=[Depends(api_key_auth)], status_code=201)
def add_vuln(component_id: str, req: AddVulnRequest) -> Dict[str, Any]:
    """Add a vulnerability to a component."""
    try:
        return _get_engine().add_vuln(
            component_id=component_id,
            org_id=req.org_id,
            cve_id=req.cve_id,
            severity=req.severity,
            cvss_score=req.cvss_score,
            affects_version=req.affects_version,
            fixed_in=req.fixed_in,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/generate/cyclonedx", dependencies=[Depends(api_key_auth)])
def generate_cyclonedx(req: GenerateRequest) -> Dict[str, Any]:
    """Generate a CycloneDX 1.4 SBOM for a project."""
    try:
        return _get_engine().generate_cyclonedx(
            org_id=req.org_id,
            project_name=req.project_name,
            version_tag=req.version_tag,
            exported_by=req.exported_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/generate/spdx", dependencies=[Depends(api_key_auth)])
def generate_spdx(req: GenerateRequest) -> Dict[str, Any]:
    """Generate an SPDX 2.3 SBOM for a project."""
    try:
        return _get_engine().generate_spdx(
            org_id=req.org_id,
            project_name=req.project_name,
            version_tag=req.version_tag,
            exported_by=req.exported_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/projects", dependencies=[Depends(api_key_auth)])
def list_projects(org_id: str = Query(..., description="Organisation ID")) -> list:
    """List all projects with component counts."""
    return _get_engine().list_projects(org_id=org_id)


@router.get("/projects/{project_name}/summary", dependencies=[Depends(api_key_auth)])
def get_project_summary(
    project_name: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> Dict[str, Any]:
    """Return component count, vuln counts, ecosystem/license breakdown, latest export."""
    return _get_engine().get_project_summary(org_id=org_id, project_name=project_name)


@router.get("/projects/{project_name}/history", dependencies=[Depends(api_key_auth)])
def get_export_history(
    project_name: str,
    org_id: str = Query(..., description="Organisation ID"),
) -> list:
    """Return SBOM export history for a project."""
    return _get_engine().get_export_history(org_id=org_id, project_name=project_name)


@router.get("/search", dependencies=[Depends(api_key_auth)])
def search_component(
    org_id: str = Query(..., description="Organisation ID"),
    q: str = Query(..., description="Search query (name or purl)"),
) -> list:
    """Search components by name or purl."""
    return _get_engine().search_component(org_id=org_id, query=q)


@router.get("/formats", dependencies=[Depends(api_key_auth)])
def list_formats() -> Dict[str, Any]:
    """Return supported SBOM formats and their specifications."""
    return {
        "formats": [
            {
                "id": "cyclonedx",
                "name": "CycloneDX",
                "version": "1.4",
                "description": "CycloneDX 1.4 SBOM standard — EO 14028 compliant",
                "mime_type": "application/vnd.cyclonedx+json",
                "spec_url": "https://cyclonedx.org/specification/overview/",
            },
            {
                "id": "spdx",
                "name": "SPDX",
                "version": "2.3",
                "description": "SPDX 2.3 SBOM standard — NTIA Minimum Elements compliant",
                "mime_type": "application/spdx+json",
                "spec_url": "https://spdx.github.io/spdx-spec/v2.3/",
            },
        ],
        "default": "cyclonedx",
    }


@router.get("/cyclonedx", dependencies=[Depends(api_key_auth)])
def export_cyclonedx_get(
    org_id: str = Query(..., description="Organisation ID"),
    project_name: str = Query(..., description="Project name"),
    version_tag: str = Query(default="1.0", description="SBOM version tag"),
    exported_by: str = Query(default="", description="Exporting user/system"),
) -> Dict[str, Any]:
    """Generate a CycloneDX 1.4 SBOM for a project (GET variant)."""
    try:
        return _get_engine().generate_cyclonedx(
            org_id=org_id,
            project_name=project_name,
            version_tag=version_tag,
            exported_by=exported_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/spdx", dependencies=[Depends(api_key_auth)])
def export_spdx_get(
    org_id: str = Query(..., description="Organisation ID"),
    project_name: str = Query(..., description="Project name"),
    version_tag: str = Query(default="1.0", description="SBOM version tag"),
    exported_by: str = Query(default="", description="Exporting user/system"),
) -> Dict[str, Any]:
    """Generate an SPDX 2.3 SBOM for a project (GET variant)."""
    try:
        return _get_engine().generate_spdx(
            org_id=org_id,
            project_name=project_name,
            version_tag=version_tag,
            exported_by=exported_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
