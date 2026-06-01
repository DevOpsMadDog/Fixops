"""ML Anomaly Detection Router — ALDECI.

Prefix: /api/v1/ml/anomaly
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/ml/anomaly/detect    detect_anomalies  — wired to real AnomalyDetector
  GET   /api/v1/ml/anomaly/list      list_anomalies    — wired to real AnomalyDetector
  POST  /api/v1/ml/anomaly/record    record_metric     — wired to real AnomalyDetector
  GET   /api/v1/ml/anomaly/models    list_models       — honest registry (no fake accuracy)

The anomaly detection engine is the real statistical AnomalyDetector
(suite-core/core/anomaly_detector.py): SQLite-backed, multi-tenant,
uses rolling mean / std-dev / drift / 3-sigma threshold methods.

There is NO trained ML model file (.pkl / .joblib / sklearn / torch).
The /models endpoint returns an honest empty registry until a model is
trained and loaded — it never returns fabricated accuracy numbers.
Confidence values come from real statistical deviation — never from random number
generation or hardcoded literals.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ml/anomaly",
    tags=["ML Anomaly Detection"],
)

# ---------------------------------------------------------------------------
# Lazy engine singleton
# ---------------------------------------------------------------------------

_detector = None


def _get_detector():
    global _detector
    if _detector is None:
        from core.anomaly_detector import AnomalyDetector
        _detector = AnomalyDetector()
    return _detector


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class MetricPoint(BaseModel):
    """A single time-series data point to feed into the detector."""

    metric_name: str = Field(..., description="Name of the metric (e.g. 'findings_count')")
    value: float = Field(..., description="Numeric value of the metric")
    org_id: str = Field(default="default", description="Tenant / org identifier")


class DetectRequest(BaseModel):
    """Request body for the /detect endpoint."""

    org_id: str = Field(default="default", description="Tenant / org identifier")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/detect", dependencies=[Depends(api_key_auth)])
def detect_anomalies(body: DetectRequest):
    """Run anomaly detection across all recorded metrics for an org.

    Returns a list of detected anomalies from the real AnomalyDetector engine.
    Confidence values are derived from actual statistical deviation.
    If no metrics have been recorded yet, returns an empty list.
    """
    try:
        detector = _get_detector()
        anomalies = detector.detect_anomalies(org_id=body.org_id)
        return {
            "org_id": body.org_id,
            "anomalies_detected": len(anomalies),
            "anomalies": [a.model_dump() for a in anomalies],
            "engine": "AnomalyDetector",
            "engine_path": "core.anomaly_detector.AnomalyDetector",
        }
    except Exception as exc:
        _logger.exception("Anomaly detection failed: %s", exc)
        raise HTTPException(status_code=503, detail={
            "detail": "Anomaly detection engine encountered an error",
            "error": str(exc),
        }) from exc


@router.get("/list", dependencies=[Depends(api_key_auth)])
def list_anomalies(
    org_id: str = Depends(get_org_id),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List stored anomalies for an org, ordered by detection time (newest first)."""
    try:
        from core.anomaly_detector import AnomalySeverity
        detector = _get_detector()
        sev_filter = AnomalySeverity(severity) if severity else None
        anomalies = detector.get_anomalies(
            org_id=org_id,
            severity_filter=sev_filter,
            limit=limit,
        )
        return {
            "org_id": org_id,
            "count": len(anomalies),
            "anomalies": [a.model_dump() for a in anomalies],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("List anomalies failed: %s", exc)
        raise HTTPException(status_code=503, detail={
            "detail": "Anomaly detection engine encountered an error",
            "error": str(exc),
        }) from exc


@router.post("/record", dependencies=[Depends(api_key_auth)], status_code=201)
def record_metric(body: MetricPoint):
    """Record a metric data point for later anomaly detection."""
    try:
        detector = _get_detector()
        row_id = detector.record_metric(
            name=body.metric_name,
            value=body.value,
            org_id=body.org_id,
        )
        return {"recorded": True, "row_id": row_id, "metric_name": body.metric_name}
    except Exception as exc:
        _logger.exception("Record metric failed: %s", exc)
        raise HTTPException(status_code=503, detail={
            "detail": "Anomaly detection engine encountered an error",
            "error": str(exc),
        }) from exc


@router.get("/models", dependencies=[Depends(api_key_auth)])
def list_models():
    """Return the registry of loaded anomaly-detection models.

    The current engine is a statistical detector (rolling mean / std-dev /
    3-sigma), NOT a trained ML model file.  No sklearn/torch model has been
    trained or serialised.  This endpoint returns an honest registry — an
    empty ``trained_models`` list — rather than fabricated accuracy numbers.

    When a real trained model is available, it should be registered here with
    its actual evaluated metrics from a hold-out test set.
    """
    return {
        "engine": "AnomalyDetector",
        "engine_type": "statistical",
        "description": (
            "Rolling-mean / std-dev / drift / 3-sigma threshold detector. "
            "No trained ML model file is currently loaded."
        ),
        "trained_models": [],
        "note": (
            "trained_models is empty because no sklearn/torch model has been "
            "trained and serialised yet.  Accuracy figures will appear here "
            "once a model is trained against real labelled data."
        ),
    }
