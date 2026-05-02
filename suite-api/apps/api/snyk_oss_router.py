"""ALDECI Snyk-OSS Connector API Router.

Exposes the real Snyk-family scanner (Trivy + OSV-Scanner + Semgrep CE)
via a REST endpoint, replacing the previously stubbed Snyk integration.

Prefix: /api/v1/connectors/snyk-oss
Auth:   api_key_auth dependency

Routes:
  GET   /api/v1/connectors/snyk-oss/status
  GET   /api/v1/connectors/snyk-oss/tenants
  POST  /api/v1/connectors/snyk-oss/scan          — scan one tenant
  POST  /api/v1/connectors/snyk-oss/scan-fleet    — scan all tenants
"""
from __future__ import annotations

import logging
import shutil
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/snyk-oss",
    tags=["connectors", "snyk-oss"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy connector accessor — keeps app startup fast.
# ---------------------------------------------------------------------------

def _connector():
    from connectors.snyk_oss_connector import get_default_connector
    return get_default_connector()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanTenantRequest(BaseModel):
    tenant: str = Field(..., description="Tenant directory name under fleet root")
    org_id: str = Field("default", description="Organization id for ingestion")
    build_image: bool = Field(True, description="Build+scan Dockerfile if present")


class ScanFleetRequest(BaseModel):
    org_id: str = Field("default", description="Organization id for ingestion")
    build_images: bool = Field(True, description="Build+scan Dockerfiles where present")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status")
def status() -> Dict[str, Any]:
    """Report tool availability + fleet readiness."""
    c = _connector()
    return {
        "connector": "snyk-oss",
        "replaces": ["Snyk Open Source", "Snyk Container", "Snyk Code"],
        "tools": {
            "trivy": bool(shutil.which("trivy")),
            "osv-scanner": bool(shutil.which("osv-scanner")),
            "semgrep": bool(shutil.which("semgrep")),
            "docker": bool(shutil.which("docker")),
            "brew": bool(shutil.which("brew")),
        },
        "fleet_root": str(c.fleet_root),
        "fleet_exists": c.fleet_root.exists(),
        "tenant_count": len(c.list_tenants()),
    }


@router.get("/tenants")
def tenants() -> Dict[str, Any]:
    c = _connector()
    items = []
    for p in c.list_tenants():
        items.append({
            "tenant": p.name,
            "path": str(p),
            "has_dockerfile": (p / "Dockerfile").exists(),
        })
    return {"fleet_root": str(c.fleet_root), "tenants": items, "total": len(items)}


@router.post("/scan")
def scan_tenant(body: ScanTenantRequest) -> Dict[str, Any]:
    c = _connector()
    tenant_path = c.fleet_root / body.tenant
    if not tenant_path.exists() or not tenant_path.is_dir():
        raise HTTPException(status_code=404, detail=f"tenant not found: {body.tenant}")
    # Allow per-call override of image building
    original = c.build_images
    c.build_images = bool(body.build_image)
    try:
        result = c.scan_tenant(tenant_path, org_id=body.org_id)
    finally:
        c.build_images = original
    return result.to_dict()


@router.post("/scan-fleet")
def scan_fleet(body: ScanFleetRequest) -> Dict[str, Any]:
    c = _connector()
    original = c.build_images
    c.build_images = bool(body.build_images)
    try:
        report = c.scan_fleet(org_id=body.org_id)
    finally:
        c.build_images = original
    return report
