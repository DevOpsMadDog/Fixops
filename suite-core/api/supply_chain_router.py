"""ALdeci Supply Chain Security Router.

Endpoints for supply-chain risk analysis: typosquatting, provenance,
health scoring, and maintainer analysis.

POST /api/v1/supply-chain/analyze  — Analyze packages for supply chain risks
POST /api/v1/supply-chain/analyze/sbom — Analyze an SBOM for supply chain risks
GET  /api/v1/supply-chain/health   — Engine health check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.supply_chain_engine import (
    SupplyChainEngine,
    get_supply_chain_engine,
)
from fastapi import APIRouter
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/supply-chain", tags=["Supply Chain Security"])


# ── Request / Response Models ──────────────────────────────────────


class PackageInput(BaseModel):
    name: str = Field(..., description="Package name")
    version: str = Field(default="unknown", description="Package version")
    package_manager: str = Field(default="unknown", description="Package manager (npm, pypi, maven)")
    age_days: Optional[int] = Field(default=None, description="Days since first publish")
    download_count: Optional[int] = Field(default=None, description="Total downloads")
    maintainer_count: Optional[int] = Field(default=None, description="Number of maintainers")
    has_provenance: Optional[bool] = Field(default=None, description="Has build provenance attestation")
    ownership_changed: Optional[bool] = Field(default=None, description="Recent ownership transfer")
    last_update_days: Optional[int] = Field(default=None, description="Days since last update")


class AnalyzePackagesRequest(BaseModel):
    packages: List[PackageInput] = Field(..., min_length=1, max_length=5000)
    typosquat_threshold: int = Field(default=2, ge=1, le=5)
    min_age_days: int = Field(default=30, ge=1)
    min_downloads: int = Field(default=100, ge=0)


class AnalyzeSBOMRequest(BaseModel):
    sbom: Dict[str, Any] = Field(..., description="CycloneDX or SPDX SBOM document")
    typosquat_threshold: int = Field(default=2, ge=1, le=5)
    min_age_days: int = Field(default=30, ge=1)
    min_downloads: int = Field(default=100, ge=0)


# ── Endpoints ──────────────────────────────────────────────────────


@router.post("/analyze")
async def analyze_packages(request: AnalyzePackagesRequest):
    """Analyze packages for supply chain risks.

    Checks each package for:
    - Typosquatting (Levenshtein distance to known packages)
    - Known malicious patterns
    - Missing provenance attestation
    - Package health (age, popularity, maintenance)
    - Maintainer risk signals
    """
    engine = SupplyChainEngine(
        typosquat_threshold=request.typosquat_threshold,
        min_age_days=request.min_age_days,
        min_downloads=request.min_downloads,
    )

    packages = [p.model_dump(exclude_none=True) for p in request.packages]
    result = engine.analyze_packages(packages)
    return result.to_dict()


@router.post("/analyze/sbom")
async def analyze_sbom(request: AnalyzeSBOMRequest):
    """Analyze an SBOM (CycloneDX or SPDX) for supply chain risks.

    Extracts components from the SBOM and runs full supply chain analysis.
    """
    engine = SupplyChainEngine(
        typosquat_threshold=request.typosquat_threshold,
        min_age_days=request.min_age_days,
        min_downloads=request.min_downloads,
    )

    result = engine.analyze_sbom(request.sbom)
    return result.to_dict()


@router.get("/health")
async def supply_chain_health():
    """Health check for supply chain engine."""
    get_supply_chain_engine()
    return {
        "status": "healthy",
        "engine": "SupplyChainEngine",
        "version": "1.0.0",
        "capabilities": [
            "typosquatting_detection",
            "provenance_verification",
            "health_scoring",
            "maintainer_analysis",
            "known_malicious_detection",
            "sbom_analysis",
        ],
    }

