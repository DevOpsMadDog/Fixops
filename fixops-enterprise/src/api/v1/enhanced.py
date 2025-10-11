"""Enhanced decision API endpoints for the enterprise deployment."""
from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from fastapi import APIRouter, Depends, HTTPException, Query, status

from src.api.dependencies import authenticate, authenticated_payload
from src.services.enhanced_decision_engine import enhanced_decision_service, EnhancedDecisionService

router = APIRouter(tags=["enhanced"])


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


__all__ = ["router"]
