"""Supply Chain Intel Router — ALDECI.

Endpoints for the Supply Chain Intelligence engine.

Prefix: /api/v1/supply-chain-intel
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/supply-chain-intel/packages                 track_package
  GET    /api/v1/supply-chain-intel/packages                 list_packages
  POST   /api/v1/supply-chain-intel/packages/{pkg_id}/vulns  add_vulnerability
  GET    /api/v1/supply-chain-intel/vulns                    list_vulnerabilities
  POST   /api/v1/supply-chain-intel/malicious                flag_malicious
  GET    /api/v1/supply-chain-intel/malicious                list_malicious
  GET    /api/v1/supply-chain-intel/check                    check_package
  POST   /api/v1/supply-chain-intel/sbom/snapshots           create_sbom_snapshot
  GET    /api/v1/supply-chain-intel/sbom/snapshots           list_snapshots
  GET    /api/v1/supply-chain-intel/stats                    get_supply_chain_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/supply-chain-intel",
    tags=["Supply Chain Intelligence"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.supply_chain_intel_engine import SupplyChainIntelEngine
        _engine = SupplyChainIntelEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class PackageCreate(BaseModel):
    name: str
    ecosystem: str = "pypi"
    version: str = ""
    license: str = ""
    is_direct: bool = True
    risk_level: str = "safe"


class VulnerabilityCreate(BaseModel):
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    fixed_in_version: str = ""
    published_at: Optional[str] = None
    patched: bool = False


class MaliciousPackageCreate(BaseModel):
    name: str
    ecosystem: str = "pypi"
    version: str = ""
    malware_type: str = "backdoor"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    reported_at: Optional[str] = None
    source: str = ""


class CVERef(BaseModel):
    cve_id: str = ""
    severity: str = "low"


class SBOMPackageEntry(BaseModel):
    name: str
    ecosystem: str = "pypi"
    version: str = ""
    is_direct: bool = True
    license_ok: bool = True
    cve_ids: List[CVERef] = Field(default_factory=list)


class SBOMSnapshotCreate(BaseModel):
    project_name: str
    packages: List[SBOMPackageEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Package routes
# ---------------------------------------------------------------------------

@router.post("/packages", dependencies=[Depends(api_key_auth)], status_code=201)
def track_package(body: PackageCreate, org_id: str = Query(default="default")):
    """Register a package for tracking."""
    try:
        return _get_engine().track_package(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/packages", dependencies=[Depends(api_key_auth)])
def list_packages(
     org_id: str = Query(default="default"),
    ecosystem: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List tracked packages with optional ecosystem/risk_level filters."""
    return _get_engine().list_packages(org_id, ecosystem=ecosystem, risk_level=risk_level)


# ---------------------------------------------------------------------------
# Vulnerability routes
# ---------------------------------------------------------------------------

@router.post(
    "/packages/{pkg_id}/vulns",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def add_vulnerability(pkg_id: str, body: VulnerabilityCreate, org_id: str = Query(default="default")):
    """Add a vulnerability record to a tracked package."""
    try:
        return _get_engine().add_vulnerability(org_id, pkg_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vulns", dependencies=[Depends(api_key_auth)])
def list_vulnerabilities(
     org_id: str = Query(default="default"),
    pkg_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    patched: bool = Query(default=False),
):
    """List package vulnerabilities. By default returns only unpatched."""
    return _get_engine().list_vulnerabilities(
        org_id, pkg_id=pkg_id, severity=severity, patched=patched
    )


# ---------------------------------------------------------------------------
# Malicious package routes
# ---------------------------------------------------------------------------

@router.post("/malicious", dependencies=[Depends(api_key_auth)], status_code=201)
def flag_malicious(body: MaliciousPackageCreate, org_id: str = Query(default="default")):
    """Flag a package as malicious (typosquat, backdoor, etc.)."""
    try:
        return _get_engine().flag_malicious(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/malicious", dependencies=[Depends(api_key_auth)])
def list_malicious(
     org_id: str = Query(default="default"),
    ecosystem: Optional[str] = Query(None),
):
    """List malicious packages, optionally filtered by ecosystem."""
    return _get_engine().list_malicious(org_id, ecosystem=ecosystem)


# ---------------------------------------------------------------------------
# Package gate check
# ---------------------------------------------------------------------------

@router.get("/check", dependencies=[Depends(api_key_auth)])
def check_package(
     org_id: str = Query(default="default"),
    name: str = Query(...),
    ecosystem: str = Query(...),
):
    """Fast-path package check for CI/CD gate. Returns risk summary + recommendation."""
    return _get_engine().check_package(org_id, name, ecosystem)


# ---------------------------------------------------------------------------
# SBOM snapshot routes
# ---------------------------------------------------------------------------

@router.post("/sbom/snapshots", dependencies=[Depends(api_key_auth)], status_code=201)
def create_sbom_snapshot(body: SBOMSnapshotCreate, org_id: str = Query(default="default")):
    """Create an SBOM snapshot from a package list. Computes risk score."""
    packages_data = [
        {
            "name": p.name,
            "ecosystem": p.ecosystem,
            "version": p.version,
            "is_direct": p.is_direct,
            "license_ok": p.license_ok,
            "cve_ids": [c.model_dump() for c in p.cve_ids],
        }
        for p in body.packages
    ]
    return _get_engine().create_sbom_snapshot(org_id, body.project_name, packages_data)


@router.get("/sbom/snapshots", dependencies=[Depends(api_key_auth)])
def list_snapshots(
     org_id: str = Query(default="default"),
    project_name: Optional[str] = Query(None),
):
    """List SBOM snapshots, optionally filtered by project name."""
    return _get_engine().list_snapshots(org_id, project_name=project_name)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_supply_chain_stats(org_id: str = Query(default="default")):
    """Return aggregated supply chain intelligence statistics for the org."""
    return _get_engine().get_supply_chain_stats(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def supply_chain_intel_overview(org_id: str = Query(default="default")):
    """Top-level supply chain intelligence overview: package, vuln, and malicious signal counts."""
    return {
        "status": "ok",
        "org_id": org_id,
        "stats": _get_engine().get_supply_chain_stats(org_id),
    }
