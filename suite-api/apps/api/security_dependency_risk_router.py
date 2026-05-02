"""Security Dependency Risk Router — ALDECI.

Software dependency risk tracking: transitive vulnerabilities, license conflicts.

Prefix: /api/v1/dependency-risk
Auth: api_key_auth dependency on all endpoints

Routes:
  POST   /api/v1/dependency-risk/dependencies                      register_dependency
  POST   /api/v1/dependency-risk/dependencies/{id}/vulns           add_vuln
  PUT    /api/v1/dependency-risk/vulns/{id}/patch                  patch_vuln
  POST   /api/v1/dependency-risk/license-risks                     flag_license_risk
  GET    /api/v1/dependency-risk/summary                           get_dependency_summary
  GET    /api/v1/dependency-risk/risky                             get_risky_dependencies
  GET    /api/v1/dependency-risk/license-conflicts                 get_license_conflicts
  GET    /api/v1/dependency-risk/vulns                             get_vuln_list
  GET    /api/v1/dependency-risk/graph/{package_name}              get_transitive_graph
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dependency-risk",
    tags=["Security Dependency Risk"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.security_dependency_risk_engine import SecurityDependencyRiskEngine
        _engine = SecurityDependencyRiskEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class RegisterDependencyRequest(BaseModel):
    org_id: str = Field(default="default")
    package_name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    ecosystem: str = Field(
        default="npm",
        description="Ecosystem: npm/pypi/maven/nuget/cargo/go/gem/composer/hex",
    )
    license: str = Field(default="", description="SPDX license identifier")
    direct: bool = Field(default=True, description="True=direct dep, False=transitive")
    depth: int = Field(default=0, ge=0, description="Dependency depth (0=direct)")
    parent_package: str = Field(default="", description="Parent package name if transitive")


class AddVulnRequest(BaseModel):
    org_id: str = Field(default="default")
    cve_id: str = Field(..., description="CVE identifier")
    severity: str = Field(
        default="medium",
        description="Severity: critical/high/medium/low",
    )
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS base score")
    fixed_version: str = Field(default="", description="Version that fixes the vuln")


class PatchVulnRequest(BaseModel):
    org_id: str = Field(default="default")


class LicenseRiskRequest(BaseModel):
    org_id: str = Field(default="default")
    license_name: str = Field(..., description="SPDX license name")
    risk_level: str = Field(
        default="low",
        description="Risk level: low/medium/high/critical",
    )
    copyleft: bool = Field(default=False, description="Is this a copyleft license?")
    commercial_use_allowed: bool = Field(
        default=True, description="Is commercial use allowed?"
    )
    notes: str = Field(default="", description="Additional notes")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/")
def list_dependency_risk(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get security dependency risk summary for the org."""
    try:
        return _get_engine().get_dependency_summary(org_id=org_id)
    except Exception as exc:
        _logger.exception("list_dependency_risk failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/dependencies", summary="Register a dependency")
def register_dependency(req: RegisterDependencyRequest) -> Dict[str, Any]:
    try:
        return _get_engine().register_dependency(
            org_id=req.org_id,
            package_name=req.package_name,
            version=req.version,
            ecosystem=req.ecosystem,
            license=req.license,
            direct=req.direct,
            depth=req.depth,
            parent_package=req.parent_package,
        )
    except Exception as exc:
        _logger.exception("register_dependency failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/dependencies/{dep_id}/vulns", summary="Add a vulnerability to a dependency")
def add_vuln(dep_id: str, req: AddVulnRequest) -> Dict[str, Any]:
    try:
        return _get_engine().add_vuln(
            dependency_id=dep_id,
            org_id=req.org_id,
            cve_id=req.cve_id,
            severity=req.severity,
            cvss_score=req.cvss_score,
            fixed_version=req.fixed_version,
        )
    except Exception as exc:
        _logger.exception("add_vuln failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/vulns/{vuln_id}/patch", summary="Mark a vulnerability as patched")
def patch_vuln(vuln_id: str, req: PatchVulnRequest) -> Dict[str, Any]:
    try:
        result = _get_engine().patch_vuln(vuln_id=vuln_id, org_id=req.org_id)
        if result.get("error") == "not_found":
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("patch_vuln failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/license-risks", summary="Flag a license as risky")
def flag_license_risk(req: LicenseRiskRequest) -> Dict[str, Any]:
    try:
        return _get_engine().flag_license_risk(
            org_id=req.org_id,
            license_name=req.license_name,
            risk_level=req.risk_level,
            copyleft=req.copyleft,
            commercial_use_allowed=req.commercial_use_allowed,
            notes=req.notes,
        )
    except Exception as exc:
        _logger.exception("flag_license_risk failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/summary", summary="Dependency risk summary")
def get_dependency_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_dependency_summary(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_dependency_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/risky", summary="Dependencies above risk threshold")
def get_risky_dependencies(
    org_id: str = Query(default="default"),
    min_risk: float = Query(default=5.0, ge=0.0, le=10.0),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_risky_dependencies(org_id=org_id, min_risk=min_risk)
    except Exception as exc:
        _logger.exception("get_risky_dependencies failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/license-conflicts", summary="Dependencies with license conflicts")
def get_license_conflicts(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_license_conflicts(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_license_conflicts failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/vulns", summary="List vulnerabilities (optionally filtered by patched status)")
def get_vuln_list(
    org_id: str = Query(default="default"),
    patched: Optional[bool] = Query(default=None, description="Filter by patched status"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_vuln_list(org_id=org_id, patched=patched)
    except Exception as exc:
        _logger.exception("get_vuln_list failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/graph/{package_name}", summary="Transitive dependency graph (1-level children)")
def get_transitive_graph(
    package_name: str,
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    try:
        return _get_engine().get_transitive_graph(org_id=org_id, package_name=package_name)
    except Exception as exc:
        _logger.exception("get_transitive_graph failed")
        raise HTTPException(status_code=500, detail=str(exc))
