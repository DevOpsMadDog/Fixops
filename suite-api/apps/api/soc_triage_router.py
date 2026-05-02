"""SOC Alert Triage Router — ALDECI.

ML-powered SOC alert classification API.

Prefix: /api/v1/soc-triage
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/soc-triage/alerts                        ingest_alert
  GET    /api/v1/soc-triage/alerts                        list_alerts
  GET    /api/v1/soc-triage/alerts/{alert_id}             get_alert
  POST   /api/v1/soc-triage/alerts/{alert_id}/verdict     update_verdict
  GET    /api/v1/soc-triage/stats                         get_triage_stats
  GET    /api/v1/soc-triage/metrics                       get_daily_metrics
  POST   /api/v1/soc-triage/rules                         create_rule
  GET    /api/v1/soc-triage/rules                         list_rules
  POST   /api/v1/soc-triage/sessions                      start_session
  POST   /api/v1/soc-triage/sessions/{session_id}/close   close_session
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/soc-triage",
    tags=["soc-triage"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.soc_triage_engine import SOCTriageEngine
        # Use a default singleton; org_id is passed per-request
        _engine = SOCTriageEngine
    return _engine


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class IngestAlertRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    alert_source: str = Field("siem", description="siem | edr | ndr | xdr | manual")
    alert_type: str = Field("", description="Short type label e.g. 'brute_force'")
    title: str = Field(..., description="Alert title — used for ML keyword scoring")
    raw_description: str = Field("", description="Full alert body / raw log")
    severity_original: str = Field("medium", description="critical | high | medium | low | info")
    analyst_id: str = Field("", description="Analyst who ingested the alert (optional)")


class VerdictRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    analyst_id: str = Field(..., description="Analyst ID issuing the verdict")
    verdict: str = Field(..., description="confirmed | disputed | closed")
    notes: str = Field("", description="Optional analyst notes")


class CreateRuleRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    rule_name: str = Field(..., description="Unique rule name")
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Field→value map that must match for rule to fire",
    )
    action: str = Field("monitor", description="escalate | investigate | monitor | close | block")
    override_severity: str = Field("", description="Override severity when rule fires")
    tag: str = Field("", description="Optional tag")
    enabled: bool = Field(True)


class StartSessionRequest(BaseModel):
    org_id: str = Field(..., description="Organisation identifier")
    analyst_id: str = Field(..., description="Analyst starting the triage session")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine_for(org_id: str):
    """Return the SOCTriageEngine singleton for the given org."""
    EngineClass = _get_engine()
    return EngineClass.for_org(org_id)


def _not_found(resource: str, id_val: str):
    raise HTTPException(status_code=404, detail=f"{resource} '{id_val}' not found.")


# ---------------------------------------------------------------------------
# Alert routes
# ---------------------------------------------------------------------------

@router.post("/alerts", summary="Ingest and AI-triage an alert")
def ingest_alert(
    req: IngestAlertRequest,
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        engine = _engine_for(req.org_id)
        return engine.ingest_alert(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        _logger.exception("ingest_alert failed: %s", exc)
        raise HTTPException(status_code=500, detail="Internal error during alert ingestion.")


@router.get("/alerts", summary="List alerts with optional filters")
def list_alerts(
    org_id: str = Query(..., description="Organisation identifier"),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    classification: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _auth: None = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    engine = _engine_for(org_id)
    return engine.list_alerts(org_id, status=status, severity=severity,
                               classification=classification, limit=limit)


@router.get("/alerts/{alert_id}", summary="Retrieve a single alert")
def get_alert(
    alert_id: str,
    org_id: str = Query(..., description="Organisation identifier"),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    engine = _engine_for(org_id)
    alert = engine.get_alert(org_id, alert_id)
    if not alert:
        _not_found("Alert", alert_id)
    return alert


@router.post("/alerts/{alert_id}/verdict", summary="Submit analyst verdict")
def update_verdict(
    alert_id: str,
    req: VerdictRequest,
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        engine = _engine_for(req.org_id)
        result = engine.update_verdict(
            req.org_id, alert_id, req.analyst_id, req.verdict, req.notes
        )
        if not result:
            _not_found("Alert", alert_id)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


# ---------------------------------------------------------------------------
# Stats + Metrics routes
# ---------------------------------------------------------------------------

@router.get("/stats", summary="Get triage statistics for an org")
def get_triage_stats(
    org_id: str = Query(..., description="Organisation identifier"),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    engine = _engine_for(org_id)
    return engine.get_triage_stats(org_id)


@router.get("/metrics", summary="Get daily triage metrics")
def get_daily_metrics(
    org_id: str = Query(..., description="Organisation identifier"),
    days: int = Query(30, ge=1, le=365),
    _auth: None = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    engine = _engine_for(org_id)
    return engine.get_daily_metrics(org_id, days=days)


# ---------------------------------------------------------------------------
# Rules routes
# ---------------------------------------------------------------------------

@router.post("/rules", summary="Create a triage rule")
def create_rule(
    req: CreateRuleRequest,
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        engine = _engine_for(req.org_id)
        return engine.create_rule(req.org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.get("/rules", summary="List triage rules for an org")
def list_rules(
    org_id: str = Query(..., description="Organisation identifier"),
    _auth: None = Depends(api_key_auth),
) -> List[Dict[str, Any]]:
    engine = _engine_for(org_id)
    return engine.list_rules(org_id)


# ---------------------------------------------------------------------------
# Session routes
# ---------------------------------------------------------------------------

@router.post("/sessions", summary="Start a triage session")
def start_session(
    req: StartSessionRequest,
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    try:
        engine = _engine_for(req.org_id)
        return engine.start_session(req.org_id, req.analyst_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@router.post("/sessions/{session_id}/close", summary="Close a triage session")
def close_session(
    session_id: str,
    org_id: str = Query(..., description="Organisation identifier"),
    _auth: None = Depends(api_key_auth),
) -> Dict[str, Any]:
    engine = _engine_for(org_id)
    result = engine.close_session(org_id, session_id)
    if not result:
        _not_found("Session", session_id)
    return result
