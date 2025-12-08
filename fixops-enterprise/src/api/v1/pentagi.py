"""PentAGI integration API endpoints for receiving penetration test findings."""

from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping

from fastapi import APIRouter, Depends, HTTPException, Query, status
from src.api.dependencies import authenticate, authenticated_payload
from src.services.enhanced_decision_engine import (
    EnhancedDecisionService,
    enhanced_decision_service,
)

router = APIRouter(tags=["pentagi"])


def _get_service(_: None = Depends(authenticate)) -> EnhancedDecisionService:
    service = enhanced_decision_service
    if service is None:  # pragma: no cover - defensive guard
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enhanced decision service unavailable",
        )
    return service


@router.post("/findings", response_model=dict)
def ingest_pentest_findings(
    payload: Dict[str, Any] = Depends(authenticated_payload),
    service: EnhancedDecisionService = Depends(_get_service),
) -> MutableMapping[str, Any]:
    """Ingest penetration test findings from PentAGI and return enhanced analysis."""

    # Extract findings from payload
    findings = payload.get("findings", [])
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No findings provided in payload",
        )

    # Prepare context and metadata
    context = payload.get("context", {})
    metadata = payload.get("metadata", {})
    metadata["source"] = "pentagi"
    metadata["integration_type"] = "penetration_test"

    # Use enhanced decision engine to analyze findings
    analysis_result = service.analyse_payload({
        "findings": findings,
        "context": context,
        "metadata": metadata,
    })

    return {
        "status": "success",
        "analysis": analysis_result,
        "findings_count": len(findings),
    }


@router.post("/report", response_model=dict)
def ingest_pentest_report(
    payload: Dict[str, Any] = Depends(authenticated_payload),
    service: EnhancedDecisionService = Depends(_get_service),
) -> MutableMapping[str, Any]:
    """Ingest a complete penetration test report from PentAGI."""

    # Extract report data
    findings = payload.get("findings", [])
    target = payload.get("target", "")
    flow_id = payload.get("flow_id")
    task_id = payload.get("task_id")
    subtask_id = payload.get("subtask_id")

    if not findings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No findings provided in report",
        )

    # Prepare context with report metadata
    context = {
        "target": target,
        "flow_id": flow_id,
        "task_id": task_id,
        "subtask_id": subtask_id,
        **payload.get("context", {}),
    }

    metadata = {
        "source": "pentagi",
        "integration_type": "penetration_test_report",
        "report_type": payload.get("report_type", "penetration_test"),
        "summary": payload.get("summary", {}),
        "risk_score": payload.get("risk_score"),
    }

    # Analyze findings through enhanced decision engine
    analysis_result = service.analyse_payload({
        "findings": findings,
        "context": context,
        "metadata": metadata,
    })

    # Calculate aggregate metrics
    severity_counts = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "status": "success",
        "analysis": analysis_result,
        "report_summary": {
            "findings_count": len(findings),
            "severity_breakdown": severity_counts,
            "target": target,
            "flow_id": flow_id,
        },
    }


@router.get("/health", response_model=dict)
def pentagi_health_check() -> MutableMapping[str, Any]:
    """Health check endpoint for PentAGI integration."""

    return {
        "status": "healthy",
        "integration": "pentagi",
        "version": "1.0.0",
    }


__all__ = ["router"]
