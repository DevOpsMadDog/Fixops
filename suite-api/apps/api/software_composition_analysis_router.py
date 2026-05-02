"""Software Composition Analysis (SCA) Router — ALDECI.

Open-source dependency tracking, vulnerability detection, and license compliance.

Prefix: /api/v1/sca
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/sca/projects                      register_project
  GET    /api/v1/sca/projects                      list_projects
  GET    /api/v1/sca/projects/{id}                 get_project
  POST   /api/v1/sca/projects/{id}/scans           submit_scan
  GET    /api/v1/sca/scans                         list_scans
  GET    /api/v1/sca/scans/{id}                    get_scan
  GET    /api/v1/sca/scans/{id}/vulnerable-deps    get_vulnerable_dependencies
  GET    /api/v1/sca/scans/{id}/license-report     get_license_report
  GET    /api/v1/sca/stats                         get_sca_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/sca",
    tags=["Software Composition Analysis"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.software_composition_analysis_engine import (
            SoftwareCompositionAnalysisEngine,
        )
        _engine = SoftwareCompositionAnalysisEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterProjectRequest(BaseModel):
    name: str = Field(..., description="Project name")
    language: str = Field("python", description="Primary language: python, java, js, go, rust")
    repo_url: str = Field("", description="Source repository URL")


class SubmitScanRequest(BaseModel):
    dependencies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of {name, version, license} dependency objects",
    )
    direct_count: int = Field(0, ge=0, description="Number of direct dependencies")
    transitive_count: int = Field(0, ge=0, description="Number of transitive dependencies")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/projects", dependencies=[Depends(api_key_auth)], status_code=201)
def register_project(
    body: RegisterProjectRequest,
    org_id: str = Query(default="default"),
):
    """Register a new project for SCA dependency tracking."""
    try:
        return _get_engine().register_project(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error registering project")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/projects", dependencies=[Depends(api_key_auth)])
def list_projects(org_id: str = Query(default="default")):
    """List all SCA-tracked projects for an org."""
    return _get_engine().list_projects(org_id)


@router.get("/projects/{project_id}", dependencies=[Depends(api_key_auth)])
def get_project(project_id: str, org_id: str = Query(default="default")):
    """Retrieve a single project by ID."""
    result = _get_engine().get_project(org_id, project_id)
    if not result:
        raise HTTPException(status_code=404, detail="Project not found")
    return result


@router.post("/projects/{project_id}/scans", dependencies=[Depends(api_key_auth)], status_code=201)
def submit_scan(
    project_id: str,
    body: SubmitScanRequest,
    org_id: str = Query(default="default"),
):
    """Submit a dependency scan result for a project."""
    try:
        return _get_engine().submit_scan(org_id, project_id, body.model_dump())
    except Exception as exc:
        _logger.exception("Error submitting scan")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scans", dependencies=[Depends(api_key_auth)])
def list_scans(
    org_id: str = Query(default="default"),
    project_id: Optional[str] = Query(default=None),
):
    """List scans, optionally filtered by project."""
    return _get_engine().list_scans(org_id, project_id=project_id)


@router.get("/scans/{scan_id}", dependencies=[Depends(api_key_auth)])
def get_scan(scan_id: str, org_id: str = Query(default="default")):
    """Retrieve a single scan by ID."""
    result = _get_engine().get_scan(org_id, scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/scans/{scan_id}/vulnerable-deps", dependencies=[Depends(api_key_auth)])
def get_vulnerable_dependencies(scan_id: str, org_id: str = Query(default="default")):
    """Return only vulnerable dependencies (with known CVEs) from a scan."""
    try:
        return _get_engine().get_vulnerable_dependencies(org_id, scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error fetching vulnerable deps")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/scans/{scan_id}/license-report", dependencies=[Depends(api_key_auth)])
def get_license_report(scan_id: str, org_id: str = Query(default="default")):
    """Return license distribution and risky license list for a scan."""
    try:
        return _get_engine().get_license_report(org_id, scan_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error generating license report")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_sca_stats(org_id: str = Query(default="default")):
    """Return aggregated SCA statistics for the org."""
    return _get_engine().get_sca_stats(org_id)


# ---------------------------------------------------------------------------
# Snyk-parity: test a specific package version for vulnerabilities
# ---------------------------------------------------------------------------

@router.get("/test/{ecosystem}/{package}/{version:path}", dependencies=[Depends(api_key_auth)])
def test_package_version(
    ecosystem: str,
    package: str,
    version: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Check whether a specific package version is vulnerable.

    Returns safe/vulnerable status, CVE list, and a recommended upgrade version.

    Example: GET /api/v1/sca/test/npm/lodash/4.17.20
    """
    return _get_engine().test_package_version(org_id, ecosystem, package, version)
