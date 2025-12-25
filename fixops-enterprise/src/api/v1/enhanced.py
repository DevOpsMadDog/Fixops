"""Enhanced decision API endpoints for the enterprise deployment."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, MutableMapping, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from src.api.dependencies import authenticate, authenticated_payload
from src.services.correlation_engine import get_correlation_engine
from src.services.enhanced_decision_engine import (
    EnhancedDecisionService,
    enhanced_decision_service,
)

router = APIRouter(tags=["enhanced"])


class CorrelationRequest(BaseModel):
    """Request body for correlation analysis."""

    findings: List[Dict[str, Any]] = Field(..., min_length=1)
    stage: Optional[str] = Field(
        default=None,
        description="SDLC stage: design, build, deploy, runtime",
    )
    window_hours: int = Field(default=24, ge=1, le=720)
    strategies: Optional[List[str]] = Field(
        default=None,
        description="Correlation strategies: fingerprint, location, pattern, root_cause, vulnerability",
    )
    deduplicate: bool = Field(default=True)


class CrossStageCorrelationRequest(BaseModel):
    """Request body for cross-stage correlation."""

    design: List[Dict[str, Any]] = Field(default_factory=list)
    build: List[Dict[str, Any]] = Field(default_factory=list)
    deploy: List[Dict[str, Any]] = Field(default_factory=list)
    runtime: List[Dict[str, Any]] = Field(default_factory=list)
    link_attributes: Optional[List[str]] = Field(
        default=None,
        description="Attributes for cross-stage linking: cve_id, component, asset_id, repo_path",
    )


def _get_service(_: None = Depends(authenticate)) -> EnhancedDecisionService:
    service = enhanced_decision_service
    if service is None:  # pragma: no cover - defensive guard
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enhanced decision service unavailable",
        )
    return service


@router.post("/analysis", response_model=dict)
def run_enhanced_analysis(
    payload: Dict[str, Any] = Depends(authenticated_payload),
    service: EnhancedDecisionService = Depends(_get_service),
) -> MutableMapping[str, Any]:
    """Return consensus telemetry for the supplied findings payload."""

    return service.analyse_payload(payload)


@router.post("/pipeline", response_model=dict)
def run_pipeline_enhanced(
    payload: Dict[str, Any] = Depends(authenticated_payload),
    service: EnhancedDecisionService = Depends(_get_service),
) -> MutableMapping[str, Any]:
    """Evaluate a canonical pipeline response with the enhanced engine."""

    return service.evaluate_pipeline(payload)


@router.get("/capabilities", response_model=dict)
def enhanced_capabilities(
    service: EnhancedDecisionService = Depends(_get_service),
) -> MutableMapping[str, Any]:
    """Expose engine status, supported models, and latest signals."""

    capabilities = service.capabilities()
    capabilities["signals"] = service.signals()
    return capabilities


@router.get("/signals", response_model=dict)
def enhanced_signals(
    verdict: str = Query("allow", min_length=3),
    confidence: float = Query(0.9, ge=0.0, le=1.0),
    service: EnhancedDecisionService = Depends(_get_service),
) -> Mapping[str, Any]:
    """Return the SSVC label and telemetry for the provided decision context."""

    return service.signals(verdict=verdict, confidence=confidence)


@router.post("/correlation", response_model=dict)
async def run_correlation(
    request: CorrelationRequest,
    _: None = Depends(authenticate),
) -> MutableMapping[str, Any]:
    """
    Correlate and deduplicate findings.

    Applies correlation strategies to identify related findings and reduce noise.
    Preserves raw findings for auditability.
    """
    engine = get_correlation_engine(enabled=True)

    # Deduplicate first if requested
    dedup_result: Dict[str, Any] = {"duplicates_removed": 0, "dedup_ratio": 0.0}
    findings = request.findings

    if request.deduplicate:
        dedup_result = await engine.deduplicate_findings(
            findings, window_hours=request.window_hours
        )
        findings = dedup_result.get("unique", findings)

    # Run batch correlation
    correlation_results = await engine.batch_correlate_findings(findings)

    # Group correlated findings
    correlated_groups = []
    for result in correlation_results:
        correlated_groups.append({
            "finding_id": result.finding_id,
            "correlated_findings": result.correlated_findings,
            "correlation_type": result.correlation_type,
            "confidence_score": result.confidence_score,
            "noise_reduction_factor": result.noise_reduction_factor,
            "root_cause": result.root_cause,
        })

    noise_reduction_pct = (
        dedup_result["dedup_ratio"] * 100
        + (len(correlated_groups) / len(findings) * 35 if findings else 0)
    )

    return {
        "correlated_groups": correlated_groups,
        "dedup_count": dedup_result["duplicates_removed"],
        "noise_reduction_pct": min(noise_reduction_pct, 100.0),
        "raw_preserved": True,
        "total_findings": len(request.findings),
        "unique_findings": len(findings),
        "stage": request.stage,
    }


@router.post("/correlation/cross-stage", response_model=dict)
async def run_cross_stage_correlation(
    request: CrossStageCorrelationRequest,
    _: None = Depends(authenticate),
) -> MutableMapping[str, Any]:
    """
    Correlate findings across SDLC stages.

    Links findings from design, build, deploy, and runtime stages
    using shared attributes like CVE ID, component, and asset.
    """
    engine = get_correlation_engine(enabled=True)

    findings_by_stage = {
        "design": request.design,
        "build": request.build,
        "deploy": request.deploy,
        "runtime": request.runtime,
    }

    # Filter empty stages
    findings_by_stage = {k: v for k, v in findings_by_stage.items() if v}

    if not findings_by_stage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one stage must have findings",
        )

    correlated_groups = await engine.correlate_cross_stage(
        findings_by_stage,
        link_attributes=request.link_attributes,
    )

    total_findings = sum(len(v) for v in findings_by_stage.values())

    return {
        "correlated_groups": correlated_groups,
        "total_findings": total_findings,
        "stages_analyzed": list(findings_by_stage.keys()),
        "groups_found": len(correlated_groups),
        "cross_stage_links": sum(g.get("total_related", 0) for g in correlated_groups),
    }


@router.get("/correlation/stats", response_model=dict)
async def get_correlation_stats(
    _: None = Depends(authenticate),
) -> MutableMapping[str, Any]:
    """Get correlation engine statistics and configuration."""
    engine = get_correlation_engine(enabled=True)
    stats = engine.get_stats()
    stats["cross_stage_enabled"] = True
    stats["supported_stages"] = ["design", "build", "deploy", "runtime"]
    stats["link_attributes"] = ["cve_id", "component", "asset_id", "repo_path", "rule_id"]
    return stats


__all__ = ["router"]
