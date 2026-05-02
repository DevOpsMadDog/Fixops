"""
Configuration Drift Detection API router.

Endpoints for checking infrastructure resources against CIS baseline rules,
listing active drifts, resolving findings, and viewing trend data.

Auth is applied centrally by app.py (Depends(_verify_api_key)).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.config_drift import (
    BaselineRule,
    CloudProvider,
    ConfigDriftDetector,
    DriftResult,
    DriftSeverity,
    DriftSummary,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/drift", tags=["drift"])

_detector = ConfigDriftDetector()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class CheckResourceRequest(BaseModel):
    resource_id: str = Field(..., description="Unique identifier of the resource")
    resource_type: str = Field(..., description="Resource type (e.g. s3_bucket, iam_user)")
    actual_config: Dict[str, Any] = Field(..., description="Current resource configuration")
    provider: CloudProvider = Field(..., description="Cloud provider")
    org_id: str = Field("default", description="Organisation identifier")


class BatchResource(BaseModel):
    resource_id: str
    resource_type: str
    actual_config: Dict[str, Any]
    provider: CloudProvider


class CheckBatchRequest(BaseModel):
    resources: List[BatchResource] = Field(..., description="Resources to check")
    org_id: str = Field("default", description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/check", response_model=List[DriftResult], summary="Check resource against baselines")
def check_resource(req: CheckResourceRequest) -> List[DriftResult]:
    """Compare a resource's actual config against all matching baseline rules."""
    try:
        return _detector.check_resource(
            resource_id=req.resource_id,
            resource_type=req.resource_type,
            actual_config=req.actual_config,
            provider=req.provider,
            org_id=req.org_id,
        )
    except Exception as exc:
        logger.exception("Failed to check resource %s: %s", req.resource_id, exc)
        raise HTTPException(status_code=500, detail=f"Drift check failed: {exc}") from exc


@router.post("/check/batch", response_model=List[DriftResult], summary="Batch check resources")
def check_batch(req: CheckBatchRequest) -> List[DriftResult]:
    """Check multiple resources against baselines in a single call."""
    try:
        resources = [
            {
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "actual_config": r.actual_config,
                "provider": r.provider.value,
            }
            for r in req.resources
        ]
        return _detector.check_batch(resources=resources, org_id=req.org_id)
    except Exception as exc:
        logger.exception("Batch drift check failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Batch check failed: {exc}") from exc


@router.get("/active", response_model=List[DriftResult], summary="List active drifts")
def get_active_drifts(
    org_id: str = Query("default", description="Organisation identifier"),
    severity: Optional[DriftSeverity] = Query(None, description="Filter by severity"),
) -> List[DriftResult]:
    """Return all unresolved drift findings for the organisation."""
    try:
        return _detector.get_active_drifts(org_id=org_id, severity_filter=severity)
    except Exception as exc:
        logger.exception("Failed to fetch active drifts: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch active drifts: {exc}") from exc


@router.get("/summary", response_model=DriftSummary, summary="Drift summary")
def get_drift_summary(
    org_id: str = Query("default", description="Organisation identifier"),
) -> DriftSummary:
    """Return aggregated drift statistics for the organisation."""
    try:
        return _detector.get_drift_summary(org_id=org_id)
    except Exception as exc:
        logger.exception("Failed to compute drift summary: %s", exc)
        raise HTTPException(status_code=500, detail=f"Summary failed: {exc}") from exc


@router.get("/trend", response_model=List[Dict[str, Any]], summary="Drift trend over time")
def get_drift_trend(
    org_id: str = Query("default", description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
) -> List[Dict[str, Any]]:
    """Return daily drift counts over the last N days."""
    try:
        return _detector.get_drift_trend(org_id=org_id, days=days)
    except Exception as exc:
        logger.exception("Failed to compute drift trend: %s", exc)
        raise HTTPException(status_code=500, detail=f"Trend failed: {exc}") from exc


@router.get("/baselines", response_model=List[BaselineRule], summary="List baseline rules")
def list_baselines(
    provider: Optional[CloudProvider] = Query(None, description="Filter by provider"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
) -> List[BaselineRule]:
    """List all configured baseline rules."""
    try:
        return _detector.list_baseline_rules(provider=provider, resource_type=resource_type)
    except Exception as exc:
        logger.exception("Failed to list baselines: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to list baselines: {exc}") from exc


@router.post("/baselines", response_model=BaselineRule, summary="Add baseline rule")
def add_baseline(rule: BaselineRule) -> BaselineRule:
    """Add a custom baseline rule."""
    try:
        return _detector.add_baseline_rule(rule)
    except Exception as exc:
        logger.exception("Failed to add baseline rule: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to add baseline: {exc}") from exc


@router.delete("/baselines/{rule_id}", summary="Delete baseline rule")
def delete_baseline(rule_id: str) -> Dict[str, str]:
    """Delete a baseline rule by ID."""
    try:
        _detector.delete_baseline_rule(rule_id)
        return {"status": "deleted", "rule_id": rule_id}
    except Exception as exc:
        logger.exception("Failed to delete baseline rule %s: %s", rule_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to delete baseline: {exc}") from exc


@router.get("/defaults", response_model=List[BaselineRule], summary="Built-in CIS baselines")
def get_default_baselines() -> List[BaselineRule]:
    """Return the built-in CIS baseline rules (not yet persisted)."""
    return _detector.get_default_baselines()


@router.post("/defaults/load", response_model=Dict[str, Any], summary="Load built-in CIS baselines")
def load_default_baselines() -> Dict[str, Any]:
    """Persist all built-in CIS baseline rules into the database."""
    try:
        defaults = _detector.get_default_baselines()
        loaded = []
        for rule in defaults:
            _detector.add_baseline_rule(rule)
            loaded.append(rule.id)
        return {"loaded": len(loaded), "rule_ids": loaded}
    except Exception as exc:
        logger.exception("Failed to load default baselines: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to load defaults: {exc}") from exc


@router.get("/history", response_model=List[DriftResult], summary="Drift history")
def get_drift_history(
    org_id: str = Query("default", description="Organisation identifier"),
    resource_id: Optional[str] = Query(None, description="Filter by resource ID"),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
) -> List[DriftResult]:
    """Return drift history for an organisation."""
    try:
        return _detector.get_drift_history(org_id=org_id, resource_id=resource_id, days=days)
    except Exception as exc:
        logger.exception("Failed to fetch drift history: %s", exc)
        raise HTTPException(status_code=500, detail=f"History failed: {exc}") from exc


@router.post("/resolve/{drift_id}", summary="Resolve a drift finding")
def resolve_drift(drift_id: str) -> Dict[str, str]:
    """Mark a drift finding as resolved."""
    try:
        _detector.resolve_drift(drift_id)
        return {"status": "resolved", "drift_id": drift_id}
    except Exception as exc:
        logger.exception("Failed to resolve drift %s: %s", drift_id, exc)
        raise HTTPException(status_code=500, detail=f"Failed to resolve drift: {exc}") from exc


@router.get("/remediation/{drift_id}", summary="Get remediation steps")
def get_remediation(drift_id: str) -> Dict[str, str]:
    """Return remediation steps for a specific drift finding."""
    try:
        text = _detector.get_remediation(drift_id)
        return {"drift_id": drift_id, "remediation": text}
    except Exception as exc:
        logger.exception("Failed to fetch remediation for %s: %s", drift_id, exc)
        raise HTTPException(status_code=500, detail=f"Remediation lookup failed: {exc}") from exc
