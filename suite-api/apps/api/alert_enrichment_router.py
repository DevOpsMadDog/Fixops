"""Alert Enrichment Router — ALDECI.

Enriches security alerts with threat context, asset data, and IOC correlation.

Prefix: /api/v1/alert-enrichment
Auth: api_key_auth dependency on ALL endpoints

Routes:
  POST   /api/v1/alert-enrichment/alerts                     submit_alert
  POST   /api/v1/alert-enrichment/alerts/{id}/enrich         enrich_alert
  POST   /api/v1/alert-enrichment/alerts/{id}/fail           mark_failed
  PUT    /api/v1/alert-enrichment/alerts/{id}/context        add_context
  POST   /api/v1/alert-enrichment/sources                    register_source
  PUT    /api/v1/alert-enrichment/sources/{id}/toggle        toggle_source
  GET    /api/v1/alert-enrichment/queue                      get_enrichment_queue
  GET    /api/v1/alert-enrichment/alerts/{id}                get_alert_detail
  GET    /api/v1/alert-enrichment/summary                    get_enrichment_summary
  GET    /api/v1/alert-enrichment/high-risk                  get_high_risk_alerts
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/alert-enrichment",
    tags=["Alert Enrichment"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.alert_enrichment_engine import AlertEnrichmentEngine
        _engine = AlertEnrichmentEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SubmitAlertRequest(BaseModel):
    alert_id: str = Field(..., description="Unique alert identifier from source system")
    alert_source: str = Field(..., description="Source system name (e.g. SIEM, EDR)")
    severity: str = Field(
        default="medium",
        description="critical | high | medium | low",
    )
    raw_indicator: str = Field(..., description="Raw indicator value to enrich")
    indicator_type: str = Field(
        default="ip",
        description="ip | domain | url | hash | email | user | process | registry",
    )


class EnrichAlertRequest(BaseModel):
    source_name: str = Field(..., description="Enrichment source name")
    result_type: str = Field(
        ...,
        description="ioc_match | geolocation | asset_info | vuln_info | reputation | error",
    )
    result_data: str = Field(default="", description="Enrichment result payload")
    ioc_matches: int = Field(default=0, ge=0, description="Number of IOC matches found")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")


class MarkFailedRequest(BaseModel):
    source_name: str = Field(..., description="Enrichment source that failed")
    error_msg: str = Field(..., description="Error description")


class AddContextRequest(BaseModel):
    threat_context: str = Field(default="", description="Threat intelligence context")
    asset_context: str = Field(default="", description="Asset metadata context")


class RegisterSourceRequest(BaseModel):
    source_name: str = Field(..., description="Unique source name")
    source_type: str = Field(
        ...,
        description="threat_intel | asset_db | vuln_db | geolocation | reputation",
    )
    priority: int = Field(default=1, ge=1, description="Priority (lower = higher priority)")
    api_key: str = Field(default="", description="API key (stored as SHA-256 hash)")


class ToggleSourceRequest(BaseModel):
    enabled: bool = Field(..., description="Enable or disable the source")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/", dependencies=[Depends(api_key_auth)])
def list_alert_enrichment(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get alert enrichment summary for the org."""
    return _get_engine().get_enrichment_summary(org_id=org_id)


@router.post("/alerts", dependencies=[Depends(api_key_auth)], status_code=201)
def submit_alert(
    req: SubmitAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Submit an alert for enrichment. Deduplicates on alert_id per org."""
    try:
        return _get_engine().submit_alert(
            org_id=org_id,
            alert_id=req.alert_id,
            alert_source=req.alert_source,
            severity=req.severity,
            raw_indicator=req.raw_indicator,
            indicator_type=req.indicator_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/enrich", dependencies=[Depends(api_key_auth)])
def enrich_alert(
    alert_id: str,
    req: EnrichAlertRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Record an enrichment result for an alert."""
    try:
        return _get_engine().enrich_alert(
            alert_id=alert_id,
            org_id=org_id,
            source_name=req.source_name,
            result_type=req.result_type,
            result_data=req.result_data,
            ioc_matches=req.ioc_matches,
            confidence_score=req.confidence_score,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/alerts/{alert_id}/fail", dependencies=[Depends(api_key_auth)])
def mark_failed(
    alert_id: str,
    req: MarkFailedRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Mark enrichment as failed for an alert from a specific source."""
    try:
        return _get_engine().mark_failed(
            alert_id=alert_id,
            org_id=org_id,
            source_name=req.source_name,
            error_msg=req.error_msg,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put("/alerts/{alert_id}/context", dependencies=[Depends(api_key_auth)])
def add_context(
    alert_id: str,
    req: AddContextRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Update threat and asset context for an alert."""
    try:
        return _get_engine().add_context(
            alert_id=alert_id,
            org_id=org_id,
            threat_context=req.threat_context,
            asset_context=req.asset_context,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/sources", dependencies=[Depends(api_key_auth)], status_code=201)
def register_source(
    req: RegisterSourceRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Register an enrichment source. API key stored as SHA-256 hash."""
    try:
        return _get_engine().register_source(
            org_id=org_id,
            source_name=req.source_name,
            source_type=req.source_type,
            priority=req.priority,
            api_key=req.api_key,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.put("/sources/{source_id}/toggle", dependencies=[Depends(api_key_auth)])
def toggle_source(
    source_id: str,
    req: ToggleSourceRequest,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Enable or disable an enrichment source."""
    try:
        return _get_engine().toggle_source(
            source_id=source_id,
            org_id=org_id,
            enabled=req.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/queue", dependencies=[Depends(api_key_auth)])
def get_enrichment_queue(
    org_id: str = Query(..., description="Organization ID"),
) -> List[Dict[str, Any]]:
    """Return pending alerts ordered by severity (critical first), then created_at."""
    return _get_engine().get_enrichment_queue(org_id)


@router.get("/alerts/{alert_id}", dependencies=[Depends(api_key_auth)])
def get_alert_detail(
    alert_id: str,
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return enriched alert record plus enrichment history."""
    detail = _get_engine().get_alert_detail(alert_id, org_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return detail


@router.get("/summary", dependencies=[Depends(api_key_auth)])
def get_enrichment_summary(
    org_id: str = Query(..., description="Organization ID"),
) -> Dict[str, Any]:
    """Return enrichment summary statistics."""
    return _get_engine().get_enrichment_summary(org_id)


@router.get("/high-risk", dependencies=[Depends(api_key_auth)])
def get_high_risk_alerts(
    org_id: str = Query(..., description="Organization ID"),
    min_risk: float = Query(default=7.0, ge=0.0, description="Minimum risk score threshold"),
) -> List[Dict[str, Any]]:
    """Return enriched alerts with risk_score >= min_risk."""
    return _get_engine().get_high_risk_alerts(org_id, min_risk=min_risk)
