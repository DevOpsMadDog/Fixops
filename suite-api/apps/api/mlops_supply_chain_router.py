"""
MLOps / Model Supply Chain Security API Router.

Exposes SupplyChainAnalyzer for model-supply-chain and training-data-poisoning
risk detection: typosquat scanning, known-malicious package checks, dependency
manifest analysis, and per-org risk summaries.

Prefix: /api/v1/mlops/supply-chain

Endpoints:
  POST   /analyze/package        Analyze a single package for supply chain risks
  POST   /analyze/requirements   Analyze a requirements.txt or package.json manifest
  POST   /analyze/typosquats     Detect typosquat candidates for a package name
  GET    /check/malicious        Check if a package+version is known malicious
  GET    /analyses               List stored analyses for an org
  GET    /risk-summary           Aggregated risk summary for an org
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    _AUTH_DEP = []

from core.supply_chain_analyzer import SupplyChainAnalyzer, get_supply_chain_analyzer

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/mlops/supply-chain",
    tags=["MLOps Supply Chain Security"],
    dependencies=_AUTH_DEP,
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class PackageAnalyzeRequest(BaseModel):
    """Analyze a single package for MLOps / model supply chain risks."""

    name: str = Field(..., description="Package name (e.g. 'torch', 'transformers')")
    version: Optional[str] = Field(None, description="Package version string")
    ecosystem: str = Field(
        "pypi",
        description="Package ecosystem: pypi, npm, conda",
    )
    org_id: str = Field("default", description="Organisation ID")
    store_result: bool = Field(
        True,
        description="Persist the analysis result for historical tracking",
    )


class RequirementsAnalyzeRequest(BaseModel):
    """Analyze a dependency manifest for supply chain risks."""

    content: str = Field(
        ...,
        description=(
            "Raw requirements.txt content (pypi) or package.json content (npm). "
            "For conda, pass requirements.txt-style pinned packages."
        ),
    )
    ecosystem: str = Field(
        "pypi",
        description="Package ecosystem: pypi or npm",
    )
    org_id: str = Field("default", description="Organisation ID")
    store_result: bool = Field(
        True,
        description="Persist the aggregate analysis for historical tracking",
    )


class TyposquatRequest(BaseModel):
    """Detect typosquat candidates for a package name."""

    package_name: str = Field(..., description="Package name to check")
    ecosystem: str = Field("pypi", description="Ecosystem: pypi or npm")


class PackageAnalyzeResponse(BaseModel):
    """Single-package analysis result."""

    analysis_id: Optional[str] = None
    package: str
    version: Optional[str]
    ecosystem: str
    risk_score: float
    overall_risk: str
    is_known_malicious: bool
    is_typosquat: bool
    is_abandoned: bool
    similar_packages: List[str]
    days_since_last_release: int
    risks: List[Dict[str, Any]]


class RequirementsAnalyzeResponse(BaseModel):
    """Batch manifest analysis result."""

    analysis_id: Optional[str] = None
    total_packages: int
    high_risk_count: int
    overall_risk: str
    packages: List[Dict[str, Any]]


class TyposquatResponse(BaseModel):
    """Typosquat detection result."""

    package_name: str
    ecosystem: str
    typosquat_candidates: List[str]
    is_typosquat: bool


class MaliciousCheckResponse(BaseModel):
    """Result of a known-malicious check."""

    package: str
    version: Optional[str]
    is_known_malicious: bool


class RiskSummaryResponse(BaseModel):
    """Aggregated risk summary for an org."""

    org_id: str
    total_analyzed: int
    high_risk_packages: int
    known_malicious_detected: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/analyze/package",
    response_model=PackageAnalyzeResponse,
    status_code=200,
    summary="Analyze a single package for MLOps supply chain risks",
)
def analyze_package(body: PackageAnalyzeRequest) -> PackageAnalyzeResponse:
    """
    Analyze a single Python/npm package for model supply chain risks.

    Checks:
    - Known malicious package database (typosquats, backdoors, RATs)
    - Typosquat detection against popular ML packages (torch, transformers, etc.)
    - Compromised version flags
    - Maintenance status (abandoned packages = supply chain risk)
    - Suspicious naming heuristics

    Relevant for: ML model registries, training pipeline dependencies,
    inference server packages, data-poisoning attack surface.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        result = analyzer.analyze_package(
            name=body.name,
            version=body.version,
            ecosystem=body.ecosystem,
        )

        analysis_id: Optional[str] = None
        if body.store_result:
            try:
                analysis_id = analyzer.store_analysis(result, org_id=body.org_id)
            except Exception as store_exc:
                _logger.warning("mlops_sc: store_analysis failed: %s", store_exc)

        risk_score = result["risk_score"]
        if risk_score >= 90:
            overall_risk = "critical"
        elif risk_score >= 70:
            overall_risk = "high"
        elif risk_score >= 40:
            overall_risk = "medium"
        else:
            overall_risk = "low"

        return PackageAnalyzeResponse(
            analysis_id=analysis_id,
            package=result["package"],
            version=result["version"],
            ecosystem=result["ecosystem"],
            risk_score=risk_score,
            overall_risk=overall_risk,
            is_known_malicious=result["is_known_malicious"],
            is_typosquat=result["is_typosquat"],
            is_abandoned=result["is_abandoned"],
            similar_packages=result["similar_packages"],
            days_since_last_release=result["days_since_last_release"],
            risks=result["risks"],
        )
    except Exception as exc:
        _logger.exception("mlops_sc: analyze_package failed name=%s", body.name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/analyze/requirements",
    response_model=RequirementsAnalyzeResponse,
    status_code=200,
    summary="Analyze a dependency manifest for MLOps supply chain risks",
)
def analyze_requirements(body: RequirementsAnalyzeRequest) -> RequirementsAnalyzeResponse:
    """
    Analyze an entire requirements.txt or package.json for supply chain risks.

    Parses all declared packages and runs per-package risk analysis.
    Returns an aggregated view: overall risk level, high-risk count,
    and per-package breakdown.

    Use this to gate model training pipeline runs or CI/CD stages where
    a poisoned transitive dependency could corrupt model weights.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        result = analyzer.analyze_requirements(
            content=body.content,
            ecosystem=body.ecosystem,
        )

        analysis_id: Optional[str] = None
        if body.store_result:
            try:
                analysis_id = analyzer.store_analysis(result, org_id=body.org_id)
            except Exception as store_exc:
                _logger.warning("mlops_sc: store_analysis(requirements) failed: %s", store_exc)

        return RequirementsAnalyzeResponse(
            analysis_id=analysis_id,
            total_packages=result["total_packages"],
            high_risk_count=result["high_risk_count"],
            overall_risk=result["overall_risk"],
            packages=result["packages"],
        )
    except Exception as exc:
        _logger.exception("mlops_sc: analyze_requirements failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/analyze/typosquats",
    response_model=TyposquatResponse,
    status_code=200,
    summary="Detect typosquat candidates for a package name",
)
def detect_typosquats(body: TyposquatRequest) -> TyposquatResponse:
    """
    Return a list of popular packages that the given name may be typosquatting.

    Uses Levenshtein edit-distance thresholds against curated lists of
    high-value ML/data-science packages. A non-empty result means the package
    name is suspiciously similar to a popular legitimate package — a common
    training-data-poisoning delivery vector.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        candidates = analyzer.detect_typosquats(
            package_name=body.package_name,
            ecosystem=body.ecosystem,
        )
        return TyposquatResponse(
            package_name=body.package_name,
            ecosystem=body.ecosystem,
            typosquat_candidates=candidates,
            is_typosquat=len(candidates) > 0,
        )
    except Exception as exc:
        _logger.exception(
            "mlops_sc: detect_typosquats failed package=%s", body.package_name
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/check/malicious",
    response_model=MaliciousCheckResponse,
    status_code=200,
    summary="Check if a package+version is in the known-malicious database",
)
def check_malicious(
    package: str = Query(..., description="Package name"),
    version: Optional[str] = Query(None, description="Package version (optional)"),
) -> MaliciousCheckResponse:
    """
    Point-check whether a specific package (and optional version) is in the
    ALDECI known-malicious package database.

    The database includes real-world incidents: event-stream, ctx, node-ipc,
    loglib-modules, and others. Version-specific checks are supported for
    packages where only specific releases were compromised.

    Returns immediately — no network calls required.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        is_malicious = analyzer.check_known_malicious(name=package, version=version)
        return MaliciousCheckResponse(
            package=package,
            version=version,
            is_known_malicious=is_malicious,
        )
    except Exception as exc:
        _logger.exception("mlops_sc: check_malicious failed package=%s", package)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/analyses",
    status_code=200,
    summary="List stored supply chain analyses for an org",
)
def list_analyses(
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(50, ge=1, le=500, description="Maximum results"),
) -> List[Dict[str, Any]]:
    """
    Return historical supply chain analyses for the organisation,
    ordered by most-recent first.

    Each entry includes analysis_id, package_name, ecosystem, risk_score,
    overall_risk, is_known_malicious, and created_at timestamp.

    Use this to audit which ML dependencies were scanned and when,
    supporting compliance with model supply chain attestation requirements.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        return analyzer.list_analyses(org_id=org_id, limit=limit)
    except Exception as exc:
        _logger.exception("mlops_sc: list_analyses failed org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/risk-summary",
    response_model=RiskSummaryResponse,
    status_code=200,
    summary="Aggregated supply chain risk summary for an org",
)
def get_risk_summary(
    org_id: str = Query("default", description="Organisation ID"),
) -> RiskSummaryResponse:
    """
    Return aggregated supply chain risk metrics for the organisation:
    - Total packages analyzed
    - High-risk package count (risk_score >= 70)
    - Known-malicious packages detected

    Use this for the MLOps security dashboard and model release gate checks.
    """
    analyzer = get_supply_chain_analyzer()
    try:
        summary = analyzer.get_risk_summary(org_id=org_id)
        return RiskSummaryResponse(
            org_id=org_id,
            total_analyzed=summary["total_analyzed"],
            high_risk_packages=summary["high_risk_packages"],
            known_malicious_detected=summary["known_malicious_detected"],
        )
    except Exception as exc:
        _logger.exception("mlops_sc: get_risk_summary failed org=%s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
