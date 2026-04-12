"""
Supply Chain Intelligence API router for ALDECI.

Provides endpoints for analyzing package supply chain risks, detecting
typosquatting, maintainer trust, abandoned packages, and dependency confusion.

Routes:
- POST   /api/v1/supply-chain/analyze          — analyze a single package
- POST   /api/v1/supply-chain/analyze-sbom     — analyze all SBOM components
- GET    /api/v1/supply-chain/alerts           — list alerts
- POST   /api/v1/supply-chain/alerts/{id}/resolve — resolve alert
- GET    /api/v1/supply-chain/high-risk        — high-risk packages
- GET    /api/v1/supply-chain/stats            — supply chain stats
- GET    /api/v1/supply-chain/risk-summary     — risk summary by ecosystem/category
- POST   /api/v1/supply-chain/typosquat        — typosquat detection
- POST   /api/v1/supply-chain/maintainer-trust — maintainer trust check
- GET    /api/v1/supply-chain/malicious-db     — list known-malicious packages

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
    prefix="/api/v1/supply-chain",
    tags=["supply-chain"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Lazy singleton — avoids import-time SQLite init during tests
# ---------------------------------------------------------------------------

_intel = None


def _get_intel():
    global _intel
    if _intel is None:
        from core.supply_chain_intel import SupplyChainIntel
        _intel = SupplyChainIntel()
    return _intel


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AnalyzePackageRequest(BaseModel):
    package_name: str = Field(..., description="Package name to analyze")
    ecosystem: str = Field(..., description="pip, npm, or maven")
    version: str = Field(default="", description="Package version (optional)")
    org_id: str = Field(default="default", description="Organisation ID")


class AnalyzeSBOMRequest(BaseModel):
    sbom_id: str = Field(..., description="SBOM ID to analyze all components of")
    org_id: str = Field(default="default", description="Organisation ID")


class TyposquatRequest(BaseModel):
    package_name: str = Field(..., description="Package name to check")
    ecosystem: str = Field(..., description="pip, npm, or maven")


class MaintainerTrustRequest(BaseModel):
    package_name: str = Field(..., description="Package name to check")
    ecosystem: str = Field(..., description="pip, npm, or maven")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/analyze", summary="Analyze a single package for supply chain risk")
async def analyze_package(req: AnalyzePackageRequest) -> Dict[str, Any]:
    """Score a package for typosquatting, abandonment, malicious code, and more."""
    intel = _get_intel()
    result = intel.analyze_package(
        name=req.package_name,
        ecosystem=req.ecosystem,
        version=req.version,
        org_id=req.org_id,
    )
    return {
        "package_name": result.package_name,
        "ecosystem": result.ecosystem,
        "version": result.version,
        "risk_score": result.risk_score,
        "risk_level": _score_to_level(result.risk_score),
        "risks": result.risks,
        "maintainer_count": result.maintainer_count,
        "last_updated_days": result.last_updated_days,
        "download_count": result.download_count,
        "dependencies_count": result.dependencies_count,
        "org_id": result.org_id,
    }


@router.post("/analyze-sbom", summary="Analyze all components of an SBOM")
async def analyze_sbom(req: AnalyzeSBOMRequest) -> Dict[str, Any]:
    """Run supply chain analysis across every component in the given SBOM."""
    intel = _get_intel()
    results = intel.analyze_sbom(sbom_id=req.sbom_id, org_id=req.org_id)
    high_risk = [r for r in results if r.risk_score >= 70]
    return {
        "sbom_id": req.sbom_id,
        "org_id": req.org_id,
        "total_components": len(results),
        "high_risk_count": len(high_risk),
        "packages": [
            {
                "package_name": r.package_name,
                "ecosystem": r.ecosystem,
                "version": r.version,
                "risk_score": r.risk_score,
                "risk_level": _score_to_level(r.risk_score),
                "risks": r.risks,
            }
            for r in results
        ],
    }


@router.get("/alerts", summary="List supply chain alerts")
async def get_alerts(
    org_id: str = Query(default="default", description="Organisation ID"),
    unresolved_only: bool = Query(default=False, description="Only return unresolved alerts"),
) -> Dict[str, Any]:
    """Return supply chain alerts, optionally filtered to unresolved."""
    intel = _get_intel()
    alerts = intel.get_alerts(org_id=org_id)
    if unresolved_only:
        alerts = [a for a in alerts if not a.resolved]
    return {
        "org_id": org_id,
        "total": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "package_name": a.package_name,
                "category": a.category.value,
                "severity": a.severity,
                "description": a.description,
                "detected_at": a.detected_at,
                "resolved": a.resolved,
            }
            for a in alerts
        ],
    }


@router.post("/alerts/{alert_id}/resolve", summary="Resolve a supply chain alert")
async def resolve_alert(alert_id: str) -> Dict[str, Any]:
    """Mark a supply chain alert as resolved."""
    intel = _get_intel()
    found = intel.resolve_alert(alert_id)
    if not found:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id!r} not found")
    return {"alert_id": alert_id, "resolved": True}


@router.get("/high-risk", summary="List high-risk packages")
async def get_high_risk_packages(
    org_id: str = Query(default="default", description="Organisation ID"),
    threshold: float = Query(default=70.0, ge=0, le=100, description="Risk score threshold"),
) -> Dict[str, Any]:
    """Return packages whose risk score meets or exceeds the threshold."""
    intel = _get_intel()
    packages = intel.get_high_risk_packages(org_id=org_id, threshold=threshold)
    return {
        "org_id": org_id,
        "threshold": threshold,
        "count": len(packages),
        "packages": [
            {
                "package_name": p.package_name,
                "ecosystem": p.ecosystem,
                "version": p.version,
                "risk_score": p.risk_score,
                "risk_level": _score_to_level(p.risk_score),
                "risks": p.risks,
            }
            for p in packages
        ],
    }


@router.get("/stats", summary="Supply chain statistics")
async def get_stats(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregate supply chain statistics for an organisation."""
    intel = _get_intel()
    return intel.get_supply_chain_stats(org_id=org_id)


@router.get("/risk-summary", summary="Risk summary by ecosystem and category")
async def get_risk_summary(
    org_id: str = Query(default="default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return risk breakdown by ecosystem, category, and severity."""
    intel = _get_intel()
    return intel.get_risk_summary(org_id=org_id)


@router.post("/typosquat", summary="Detect typosquatting candidates")
async def detect_typosquat(req: TyposquatRequest) -> Dict[str, Any]:
    """Check whether a package name is a known or likely typosquat."""
    intel = _get_intel()
    hits = intel.detect_typosquat(req.package_name, req.ecosystem)
    return {
        "package_name": req.package_name,
        "ecosystem": req.ecosystem,
        "is_typosquat": len(hits) > 0,
        "candidates": hits,
    }


@router.post("/maintainer-trust", summary="Check maintainer trust for a package")
async def check_maintainer_trust(req: MaintainerTrustRequest) -> Dict[str, Any]:
    """Return maintainer trust analysis including account age and change history."""
    intel = _get_intel()
    return intel.check_maintainer_trust(req.package_name, req.ecosystem)


@router.get("/malicious-db", summary="List known-malicious package database")
async def get_malicious_db(
    ecosystem: Optional[str] = Query(
        default=None, description="Filter by ecosystem (pip, npm, maven)"
    ),
) -> Dict[str, Any]:
    """Return the built-in known-malicious package database, optionally filtered."""
    from core.supply_chain_intel import _KNOWN_MALICIOUS

    entries = [
        {
            "package_name": name,
            "ecosystem": info["ecosystem"],
            "reason": info["reason"],
            "severity": info["severity"],
        }
        for name, info in _KNOWN_MALICIOUS.items()
        if ecosystem is None or info["ecosystem"] == ecosystem
    ]
    return {
        "total": len(entries),
        "ecosystem_filter": ecosystem,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_to_level(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"
