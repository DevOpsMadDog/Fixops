"""
Anomaly Detection Router — ALDECI.

8 endpoints for the anomaly detection engine:
  POST   /api/v1/anomalies/metrics             record_metric
  POST   /api/v1/anomalies/detect              detect_anomalies (full scan)
  GET    /api/v1/anomalies                     list anomalies (with optional severity filter)
  GET    /api/v1/anomalies/stats               summary statistics
  GET    /api/v1/anomalies/baseline/{metric}   statistical baseline for a metric
  POST   /api/v1/anomalies/detect/spike        detect spike on named metric
  POST   /api/v1/anomalies/detect/drop         detect drop on named metric
  POST   /api/v1/anomalies/{anomaly_id}/ack    acknowledge anomaly
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "anomaly_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.anomaly_detector import (
    Anomaly,
    AnomalyDetector,
    AnomalySeverity,
    AnomalyStats,
    BaselineStats,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/anomalies",
    tags=["anomaly-detection"],
    dependencies=_AUTH_DEP,
)

# Shared detector instance (file-backed, shared across requests)
_detector: Optional[AnomalyDetector] = None


def _get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class RecordMetricRequest(BaseModel):
    """Body for recording a metric data point."""

    name: str = Field(..., description="Metric name, e.g. 'cpu_usage'")
    value: float = Field(..., description="Numeric metric value")
    org_id: str = Field("default", description="Organisation ID")


class RecordMetricResponse(BaseModel):
    row_id: int
    message: str = "Metric recorded"


class DetectRequest(BaseModel):
    """Body for triggering a full anomaly scan."""

    org_id: str = Field("default", description="Organisation ID to scan")


class SpikeDropRequest(BaseModel):
    """Body for targeted spike / drop detection."""

    metric_name: str = Field(..., description="Metric to analyse")
    threshold_pct: float = Field(
        ..., description="Percentage deviation that triggers the anomaly"
    )
    org_id: str = Field("default", description="Organisation ID")


class DetectResponse(BaseModel):
    anomalies_found: int
    anomalies: List[Anomaly]


class AckResponse(BaseModel):
    acknowledged: bool
    anomaly_id: str


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post("/metrics", response_model=RecordMetricResponse, summary="Record a metric data point")
def record_metric(body: RecordMetricRequest) -> RecordMetricResponse:
    """
    Store a time-series data point for the named metric.

    Returns the SQLite row ID of the inserted record.
    """
    detector = _get_detector()
    try:
        row_id = detector.record_metric(
            name=body.name,
            value=body.value,
            org_id=body.org_id,
        )
        return RecordMetricResponse(row_id=row_id)
    except Exception as exc:
        logger.exception("Failed to record metric %s", body.name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/detect", response_model=DetectResponse, summary="Run full anomaly scan")
def detect_anomalies(body: DetectRequest) -> DetectResponse:
    """
    Scan all metrics for the given org and return detected anomalies.

    Runs spike, drop, drift, threshold-breach, and unusual-timing detection
    for every distinct metric name recorded for the org.
    """
    detector = _get_detector()
    try:
        anomalies = detector.detect_anomalies(org_id=body.org_id)
        return DetectResponse(anomalies_found=len(anomalies), anomalies=anomalies)
    except Exception as exc:
        logger.exception("Anomaly scan failed for org %s", body.org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("", response_model=List[Anomaly], summary="List detected anomalies")
def list_anomalies(
    org_id: str = Query("default", description="Organisation ID"),
    severity: Optional[str] = Query(None, description="Filter by severity (low/medium/high/critical)"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
) -> List[Anomaly]:
    """
    Retrieve persisted anomalies for the given org, optionally filtered by severity.
    """
    detector = _get_detector()
    sev_filter: Optional[AnomalySeverity] = None
    if severity:
        try:
            sev_filter = AnomalySeverity(severity.lower())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid severity '{severity}'. Valid: low, medium, high, critical",
            )
    return detector.get_anomalies(org_id=org_id, severity_filter=sev_filter, limit=limit)


@router.get("/stats", response_model=AnomalyStats, summary="Anomaly summary statistics")
def get_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> AnomalyStats:
    """
    Return aggregate statistics: totals, breakdown by type/severity,
    unacknowledged count, oldest/newest timestamps.
    """
    detector = _get_detector()
    return detector.get_anomaly_stats(org_id=org_id)


@router.get(
    "/baseline/{metric_name}",
    response_model=BaselineStats,
    summary="Statistical baseline for a metric",
)
def get_baseline(
    metric_name: str,
    org_id: str = Query("default", description="Organisation ID"),
    window_days: int = Query(30, ge=1, le=365, description="Lookback window in days"),
) -> BaselineStats:
    """
    Compute mean, std-dev, min, max over the lookback window for the metric.

    Returns 404 if there are fewer than 2 data points in the window.
    """
    detector = _get_detector()
    baseline = detector.get_baseline(metric_name, org_id=org_id, window_days=window_days)
    if baseline is None:
        raise HTTPException(
            status_code=404,
            detail=f"Insufficient data for metric '{metric_name}' in org '{org_id}'",
        )
    return baseline


@router.post("/detect/spike", response_model=DetectResponse, summary="Detect spike anomaly")
def detect_spike(body: SpikeDropRequest) -> DetectResponse:
    """
    Run spike detection on a single metric.

    A spike is flagged when the latest value exceeds the rolling mean
    by more than threshold_pct percent.
    """
    detector = _get_detector()
    try:
        anomalies = detector.detect_spike(
            metric_name=body.metric_name,
            threshold_pct=body.threshold_pct,
            org_id=body.org_id,
        )
        return DetectResponse(anomalies_found=len(anomalies), anomalies=anomalies)
    except Exception as exc:
        logger.exception("Spike detection failed for %s", body.metric_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/detect/drop", response_model=DetectResponse, summary="Detect drop anomaly")
def detect_drop(body: SpikeDropRequest) -> DetectResponse:
    """
    Run drop detection on a single metric.

    A drop is flagged when the latest value is below the rolling mean
    by more than threshold_pct percent.
    """
    detector = _get_detector()
    try:
        anomalies = detector.detect_drop(
            metric_name=body.metric_name,
            threshold_pct=body.threshold_pct,
            org_id=body.org_id,
        )
        return DetectResponse(anomalies_found=len(anomalies), anomalies=anomalies)
    except Exception as exc:
        logger.exception("Drop detection failed for %s", body.metric_name)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{anomaly_id}/ack", response_model=AckResponse, summary="Acknowledge an anomaly")
def acknowledge_anomaly(anomaly_id: str) -> AckResponse:
    """
    Mark an anomaly as reviewed.

    Returns 404 if the anomaly does not exist or was already acknowledged.
    """
    detector = _get_detector()
    updated = detector.acknowledge_anomaly(anomaly_id)
    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Anomaly '{anomaly_id}' not found or already acknowledged",
        )
    return AckResponse(acknowledged=True, anomaly_id=anomaly_id)
