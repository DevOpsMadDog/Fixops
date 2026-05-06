"""
Anomaly ML Router — ALDECI.

8 endpoints under /api/v1/anomaly-ml:

  POST   /api/v1/anomaly-ml/events                  record_event
  POST   /api/v1/anomaly-ml/detect/zscore            detect_zscore
  POST   /api/v1/anomaly-ml/detect/isolation         score_isolation
  POST   /api/v1/anomaly-ml/detect/timeseries        analyze_timeseries
  GET    /api/v1/anomaly-ml/ueba/{user_id}           get_user_risk
  GET    /api/v1/anomaly-ml/groups                   list_alert_groups
  GET    /api/v1/anomaly-ml/anomalies                list_anomalies
  POST   /api/v1/anomaly-ml/feedback                 submit_feedback
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "anomaly_ml_router: auth_deps not available, relying on app.py mount-level auth"
    )
    _AUTH_DEP = []

from core.anomaly_ml_engine import (
    AlertGroup,
    AnomalyMLEngine,
    FeedbackRequest,
    MLAnomaly,
    RiskLevel,
    UserRiskScore,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/anomaly-ml",
    tags=["anomaly-ml"],
    dependencies=_AUTH_DEP,
)

# Shared engine instance
_engine: Optional[AnomalyMLEngine] = None


def _get_engine() -> AnomalyMLEngine:
    global _engine
    if _engine is None:
        _engine = AnomalyMLEngine()
    return _engine


# ============================================================================
# REQUEST / RESPONSE MODELS
# ============================================================================


class RecordEventRequest(BaseModel):
    entity_id: str = Field(..., description="User or service ID")
    metric_name: str = Field(..., description="Metric name, e.g. 'login_count'")
    value: float = Field(..., description="Numeric metric value")
    entity_type: str = Field("user", description="'user' or 'service'")
    org_id: str = Field("default", description="Organisation ID")


class RecordEventResponse(BaseModel):
    row_id: int
    message: str = "Event recorded"


class ZScoreRequest(BaseModel):
    entity_id: str = Field(..., description="User or service ID")
    metric_name: str = Field(..., description="Metric to evaluate")
    value: float = Field(..., description="Observed value to test")
    window_days: int = Field(30, ge=1, le=365, description="Baseline window in days")
    z_threshold: float = Field(3.0, ge=1.0, le=10.0, description="Sigma threshold")
    entity_type: str = Field("user", description="Entity type")
    org_id: str = Field("default", description="Organisation ID")


class ZScoreResponse(BaseModel):
    anomaly_detected: bool
    anomaly: Optional[MLAnomaly] = None
    message: str


class IsolationRequest(BaseModel):
    entity_id: str = Field(..., description="Entity to score")
    metric_names: List[str] = Field(..., min_length=1, description="Feature metric names")
    current_values: List[float] = Field(..., min_length=1, description="Current feature vector")
    window_days: int = Field(14, ge=1, le=90, description="Training window in days")
    org_id: str = Field("default", description="Organisation ID")


class IsolationResponse(BaseModel):
    anomaly_detected: bool
    isolation_score: Optional[float] = None
    anomaly: Optional[MLAnomaly] = None
    message: str


class TimeSeriesRequest(BaseModel):
    entity_id: str = Field(..., description="User or service ID")
    metric_name: str = Field(..., description="Metric to analyse")
    window_hours: int = Field(24, ge=1, le=720, description="Analysis window in hours")
    entity_type: str = Field("service", description="Entity type")
    org_id: str = Field("default", description="Organisation ID")


class TimeSeriesResponse(BaseModel):
    anomalies_found: int
    anomalies: List[MLAnomaly]


class UEBARiskResponse(BaseModel):
    user_risk: UserRiskScore


class AlertGroupResponse(BaseModel):
    group_count: int
    groups: List[AlertGroup]


class AnomalyListResponse(BaseModel):
    count: int
    anomalies: List[MLAnomaly]


class FeedbackResponse(BaseModel):
    success: bool
    anomaly_id: str
    label: str
    message: str


class FeedbackStatsResponse(BaseModel):
    stats: Dict[str, Any]


# ============================================================================
# ENDPOINTS
# ============================================================================


@router.post(
    "/events",
    response_model=RecordEventResponse,
    summary="Record a behavioral event for an entity",
)
def record_event(body: RecordEventRequest) -> RecordEventResponse:
    """
    Store a time-series observation (login count, API calls, data bytes, etc.)
    for a user or service entity.
    """
    engine = _get_engine()
    try:
        row_id = engine.record_event(
            entity_id=body.entity_id,
            metric_name=body.metric_name,
            value=body.value,
            entity_type=body.entity_type,
            org_id=body.org_id,
        )
        return RecordEventResponse(row_id=row_id)
    except Exception as exc:
        logger.exception("Failed to record event for entity %s", body.entity_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/detect/zscore",
    response_model=ZScoreResponse,
    summary="Z-score anomaly detection against behavioral baseline",
)
def detect_zscore(body: ZScoreRequest) -> ZScoreResponse:
    """
    Compute z-score for an observed value against the entity's historical baseline.

    Returns an anomaly if |z| > z_threshold (default 3.0 sigma).
    The baseline is computed from events in the lookback window.
    """
    engine = _get_engine()
    try:
        anomaly = engine.detect_zscore(
            entity_id=body.entity_id,
            metric_name=body.metric_name,
            value=body.value,
            window_days=body.window_days,
            z_threshold=body.z_threshold,
            entity_type=body.entity_type,
            org_id=body.org_id,
        )
        if anomaly is None:
            return ZScoreResponse(
                anomaly_detected=False,
                message="No anomaly detected — value within normal range",
            )
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED
            from core.trustgraph_event_bus import get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"anomaly-zscore-{body.entity_id}-{body.metric_name}",
                    "type": "ml_anomaly", "severity": anomaly.risk_level.value if hasattr(anomaly.risk_level, "value") else "medium",
                    "source": "anomaly_ml_router", "data": {"entity_id": body.entity_id, "metric": body.metric_name},
                }))
        except Exception:
            pass
        return ZScoreResponse(
            anomaly_detected=True,
            anomaly=anomaly,
            message=f"Anomaly detected: z-score {anomaly.z_score:.2f}",
        )
    except Exception as exc:
        logger.exception("Z-score detection failed for entity %s", body.entity_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/detect/isolation",
    response_model=IsolationResponse,
    summary="Isolation Forest multi-dimensional anomaly scoring",
)
def score_isolation(body: IsolationRequest) -> IsolationResponse:
    """
    Score a multi-metric feature vector using a lightweight Isolation Forest.

    Trains on historical data (window_days) and scores the current observation.
    Score > 0.6 is flagged as anomalous. No sklearn required.
    """
    if len(body.metric_names) != len(body.current_values):
        raise HTTPException(
            status_code=422,
            detail="metric_names and current_values must have the same length",
        )
    engine = _get_engine()
    try:
        anomaly = engine.score_isolation(
            entity_id=body.entity_id,
            metric_names=body.metric_names,
            current_values=body.current_values,
            window_days=body.window_days,
            org_id=body.org_id,
        )
        if anomaly is None:
            return IsolationResponse(
                anomaly_detected=False,
                message="Isolation score within normal range (<=0.6)",
            )
        # TrustGraph explicit indexing (fire-and-forget)
        try:
            from core.trustgraph_event_bus import EVENT_FINDING_CREATED
            from core.trustgraph_event_bus import get_event_bus as _get_eb
            _bus = _get_eb()
            if _bus and _bus.enabled:
                import asyncio as _asyncio
                _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                    "finding_id": f"anomaly-isolation-{body.entity_id}",
                    "type": "ml_anomaly", "severity": "high",
                    "source": "anomaly_ml_router", "data": {"entity_id": body.entity_id, "score": anomaly.isolation_score},
                }))
        except Exception:
            pass
        return IsolationResponse(
            anomaly_detected=True,
            isolation_score=anomaly.isolation_score,
            anomaly=anomaly,
            message=f"Anomaly detected: isolation score {anomaly.isolation_score:.3f}",
        )
    except Exception as exc:
        logger.exception("Isolation scoring failed for entity %s", body.entity_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/detect/timeseries",
    response_model=TimeSeriesResponse,
    summary="Time-series anomaly detection (spike/drop/trend/seasonality)",
)
def analyze_timeseries(body: TimeSeriesRequest) -> TimeSeriesResponse:
    """
    Analyse time-series data for a metric, detecting:
    - SPIKE: sudden increase > 3x baseline mean
    - DROP: sudden decrease to < 0.2x baseline mean
    - TREND_UP/DOWN: sustained directional change > 20% over recent window
    - SEASONALITY_VIOLATION: z-score > 4.0 vs historical distribution
    """
    engine = _get_engine()
    try:
        anomalies = engine.analyze_timeseries(
            entity_id=body.entity_id,
            metric_name=body.metric_name,
            window_hours=body.window_hours,
            entity_type=body.entity_type,
            org_id=body.org_id,
        )
        # TrustGraph explicit indexing (fire-and-forget)
        if anomalies:
            try:
                from core.trustgraph_event_bus import EVENT_FINDING_CREATED
                from core.trustgraph_event_bus import get_event_bus as _get_eb
                _bus = _get_eb()
                if _bus and _bus.enabled:
                    import asyncio as _asyncio
                    _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                        "finding_id": f"anomaly-ts-{body.entity_id}-{body.metric_name}",
                        "type": "ml_anomaly", "severity": "medium",
                        "source": "anomaly_ml_router", "data": {"entity_id": body.entity_id, "anomaly_count": len(anomalies)},
                    }))
            except Exception:
                pass
        return TimeSeriesResponse(
            anomalies_found=len(anomalies),
            anomalies=anomalies,
        )
    except Exception as exc:
        logger.exception(
            "Time-series analysis failed for entity %s metric %s",
            body.entity_id,
            body.metric_name,
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/ueba/{user_id}",
    response_model=UEBARiskResponse,
    summary="UEBA composite risk score for a user",
)
def get_user_risk(
    user_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    window_days: int = Query(7, ge=1, le=90, description="Lookback window"),
) -> UEBARiskResponse:
    """
    Compute User Entity Behavior Analytics (UEBA) composite risk score (0-100).

    Sub-scores:
    - login_anomaly_score (0-25): login frequency vs baseline
    - access_pattern_score (0-25): API call patterns vs baseline
    - data_volume_score (0-25): data egress vs baseline
    - travel_anomaly_score (0-25): distinct geo_region count (impossible travel)
    """
    engine = _get_engine()
    try:
        risk = engine.compute_user_risk(
            user_id=user_id,
            org_id=org_id,
            window_days=window_days,
        )
        return UEBARiskResponse(user_risk=risk)
    except Exception as exc:
        logger.exception("UEBA risk computation failed for user %s", user_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/groups",
    response_model=AlertGroupResponse,
    summary="Get grouped anomaly alerts (alert fatigue reduction)",
)
def list_alert_groups(
    org_id: str = Query("default", description="Organisation ID"),
    window_hours: int = Query(4, ge=1, le=72, description="Grouping time window"),
) -> AlertGroupResponse:
    """
    Cluster recent anomalies into alert groups to reduce alert fatigue.

    Groups by: same entity, same metric across entities, temporal proximity.
    """
    engine = _get_engine()
    try:
        groups = engine.group_anomalies(org_id=org_id, window_hours=window_hours)
        return AlertGroupResponse(group_count=len(groups), groups=groups)
    except Exception as exc:
        logger.exception("Alert grouping failed for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/anomalies",
    response_model=AnomalyListResponse,
    summary="List detected ML anomalies",
)
def list_anomalies(
    org_id: str = Query("default", description="Organisation ID"),
    entity_id: Optional[str] = Query(None, description="Filter by entity ID"),
    risk_level: Optional[str] = Query(
        None, description="Filter by risk level: low/medium/high/critical"
    ),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
) -> AnomalyListResponse:
    """
    Retrieve persisted ML anomalies with optional filters.
    """
    engine = _get_engine()
    risk_filter: Optional[RiskLevel] = None
    if risk_level:
        try:
            risk_filter = RiskLevel(risk_level.lower())
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid risk_level '{risk_level}'. Valid: low, medium, high, critical",
            )
    try:
        anomalies = engine.list_anomalies(
            org_id=org_id,
            entity_id=entity_id,
            risk_level=risk_filter,
            limit=limit,
        )
        return AnomalyListResponse(count=len(anomalies), anomalies=anomalies)
    except Exception as exc:
        logger.exception("Failed to list anomalies for org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    summary="Submit analyst feedback on a detected anomaly",
)
def submit_feedback(body: FeedbackRequest) -> FeedbackResponse:
    """
    Record analyst verdict for an anomaly: true_positive, false_positive,
    or needs_investigation.

    Feedback is stored and used to compute per-metric false-positive rates
    and threshold adjustment recommendations.
    """
    engine = _get_engine()
    try:
        success = engine.submit_feedback(
            anomaly_id=body.anomaly_id,
            label=body.label,
            analyst_id=body.analyst_id,
            notes=body.notes,
        )
        if not success:
            raise HTTPException(
                status_code=404,
                detail=f"Anomaly '{body.anomaly_id}' not found",
            )
        return FeedbackResponse(
            success=True,
            anomaly_id=body.anomaly_id,
            label=body.label.value,
            message=f"Feedback '{body.label.value}' recorded for anomaly {body.anomaly_id}",
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Feedback submission failed for anomaly %s", body.anomaly_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get(
    "/",
    summary="Anomaly ML summary — counts and feedback stats",
    tags=["anomaly-ml"],
)
def anomaly_ml_index(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate anomaly counts and feedback stats from the real engine."""
    engine = _get_engine()
    try:
        anomalies: List[Any] = engine.list_anomalies(org_id=org_id)
        feedback_stats: Dict[str, Any] = engine.get_feedback_stats(org_id=org_id)
    except Exception as exc:
        logger.warning("anomaly_ml_index: engine error — %s", exc)
        anomalies = []
        feedback_stats = {}
    return {
        "router": "anomaly-ml",
        "org_id": org_id,
        "count": len(anomalies),
        "items": anomalies,
        "feedback_stats": feedback_stats,
        "status": "ok",
    }
