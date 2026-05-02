"""Attack Surface Discovery API — /api/v1/attack-surface

External attack surface discovery: subdomain enumeration, port scanning,
certificate monitoring, technology fingerprinting, exposed service detection.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict

from core.attack_surface_discovery import (
    AssetType,
    RiskLevel,
    get_attack_surface_engine,
)
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/attack-surface", tags=["Attack Surface Discovery"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DiscoverRequest(BaseModel):
    domain: str = Field(..., description="Target domain to discover")
    scan_ports: bool = Field(default=True, description="Scan for open ports")
    check_certs: bool = Field(default=True, description="Check TLS certificates")
    enumerate_subdomains: bool = Field(default=True, description="Enumerate subdomains")
    port_timeout: float = Field(default=0.5, description="Port scan timeout in seconds")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/discover")
async def discover(req: DiscoverRequest) -> Dict[str, Any]:
    """Run full attack surface discovery for a domain."""
    engine = get_attack_surface_engine()
    result = engine.discover(
        domain=req.domain,
        scan_ports=req.scan_ports,
        check_certs=req.check_certs,
        enumerate_subdomains=req.enumerate_subdomains,
        port_timeout=req.port_timeout,
    )
    return {
        "report_id": result.report_id,
        "domain": result.domain,
        "discovered_at": result.discovered_at,
        "scan_duration_ms": result.scan_duration_ms,
        "asset_count": result.asset_count,
        "subdomains": [asdict(s) for s in result.subdomains],
        "open_ports": [asdict(p) for p in result.open_ports],
        "certificates": [asdict(c) for c in result.certificates],
        "technologies": [asdict(t) for t in result.technologies],
        "exposed_services": result.exposed_services,
        "risk_summary": result.risk_summary,
        "recommendations": result.recommendations,
    }


@router.get("/{domain}/report")
async def get_domain_report(domain: str) -> Dict[str, Any]:
    """Get the latest attack surface report for a domain."""
    engine = get_attack_surface_engine()
    # Find the most recent report for this domain
    reports = engine.list_reports()
    domain_reports = [r for r in reports if r["domain"] == domain]
    if not domain_reports:
        raise HTTPException(status_code=404, detail=f"No reports found for domain {domain}")
    latest = domain_reports[-1]
    full_report = engine.get_report(latest["report_id"])
    if full_report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "report_id": full_report.report_id,
        "domain": full_report.domain,
        "discovered_at": full_report.discovered_at,
        "scan_duration_ms": full_report.scan_duration_ms,
        "asset_count": full_report.asset_count,
        "subdomains": [asdict(s) for s in full_report.subdomains],
        "open_ports": [asdict(p) for p in full_report.open_ports],
        "certificates": [asdict(c) for c in full_report.certificates],
        "technologies": [asdict(t) for t in full_report.technologies],
        "exposed_services": full_report.exposed_services,
        "risk_summary": full_report.risk_summary,
        "recommendations": full_report.recommendations,
    }


@router.get("/reports")
async def list_reports() -> Dict[str, Any]:
    """List all attack surface discovery reports."""
    engine = get_attack_surface_engine()
    reports = engine.list_reports()
    return {"reports": reports, "count": len(reports)}


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """Get attack surface scanning statistics."""
    engine = get_attack_surface_engine()
    return engine.get_stats()


@router.get("/asset-types")
async def list_asset_types() -> Dict[str, Any]:
    """List all discoverable asset types."""
    return {"asset_types": [t.value for t in AssetType]}


@router.get("/risk-levels")
async def list_risk_levels() -> Dict[str, Any]:
    """List all risk levels."""
    return {"risk_levels": [r.value for r in RiskLevel]}


@router.get("/status")
async def status() -> Dict[str, Any]:
    """Attack surface engine health/status."""
    engine = get_attack_surface_engine()
    stats = engine.get_stats()
    return {
        "status": "operational",
        "engine": "AttackSurfaceEngine",
        "version": "1.0.0",
        "capabilities": [
            "subdomain_enumeration",
            "port_scanning",
            "certificate_monitoring",
            "technology_fingerprinting",
            "exposed_service_detection",
        ],
        **stats,
    }

