"""MindsDB / ML Learning Layer API Router.

Exposes the local API Learning Store through REST endpoints for:
- Model status and health
- On-demand model training
- Real-time predictions (anomaly detection, threat assessment, response time)
- Traffic analytics and API health scoring
- Threat indicator management

Replaces the stub MindsDB endpoints in intelligent_engine_routes.py with
real, locally-trained ML models.

Phase 6 of FixOps Transformation Plan (R1).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ml", tags=["ML Learning Layer"])


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------


class ModelStatusResponse(BaseModel):
    """Status of a single ML model."""

    name: str
    type: str
    status: str
    samples_trained: int = 0
    accuracy: float = 0.0
    last_trained: Optional[str] = None
    feature_names: List[str] = Field(default_factory=list)


class AllModelsStatusResponse(BaseModel):
    """Status of all ML models."""

    models: Dict[str, ModelStatusResponse]
    store_stats: Dict[str, Any] = Field(default_factory=dict)


class AnomalyPredictionRequest(BaseModel):
    """Input for anomaly detection."""

    method: str = "GET"
    path: str = "/"
    status_code: int = 200
    duration_ms: float = 100.0
    request_size: int = 0
    response_size: int = 0


class AnomalyPredictionResponse(BaseModel):
    """Anomaly detection result."""

    is_anomaly: bool
    score: float
    confidence: float
    reason: str = ""


class ThreatAssessmentRequest(BaseModel):
    """Input for threat assessment."""

    method: str = "GET"
    path: str = "/"
    client_ip: str = ""
    status_code: int = 200
    duration_ms: float = 100.0
    user_agent: str = ""


class ThreatAssessmentResponse(BaseModel):
    """Threat assessment result."""

    threat_score: float
    risk_level: str
    indicators: List[str] = Field(default_factory=list)
    recommended_action: str = ""


class ResponseTimePrediction(BaseModel):
    """Predicted response time."""

    predicted_ms: float
    historical_avg_ms: Optional[float] = None
    confidence: float
    method: str = "default"


class TrainResult(BaseModel):
    """Training result for a model."""

    name: str
    status: str
    samples_trained: int = 0
    accuracy: float = 0.0


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _get_store():
    """Get the singleton learning store."""
    try:
        from core.api_learning_store import get_learning_store

        return get_learning_store()
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail=f"Learning store unavailable: {exc}"
        )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=AllModelsStatusResponse)
async def get_ml_status():
    """Get status of all ML models and overall store statistics."""
    store = _get_store()
    stats = store.get_stats()
    models = {}
    for name, info in store._model_info.items():
        models[name] = ModelStatusResponse(
            name=info.name,
            type=info.type,
            status=info.status.value,
            samples_trained=info.samples_trained,
            accuracy=round(info.accuracy, 4),
            last_trained=info.last_trained,
            feature_names=info.feature_names,
        )
    return AllModelsStatusResponse(models=models, store_stats=stats)


@router.get("/models")
async def get_ml_models():
    """Get all ML models as a list (frontend-friendly format).

    Returns models as a list with ``model_id`` field for the ML Dashboard UI.
    """
    store = _get_store()
    models_list = []
    for name, info in store._model_info.items():
        models_list.append(
            {
                "model_id": name,
                "name": info.name,
                "type": info.type,
                "status": "trained"
                if info.status.value == "trained"
                else info.status.value,
                "accuracy": round(info.accuracy, 4),
                "last_trained": info.last_trained,
                "predictions_count": info.samples_trained,
                "feature_names": info.feature_names,
            }
        )
    return {"models": models_list}


@router.post("/train", response_model=Dict[str, TrainResult])
async def train_all_models(background_tasks: BackgroundTasks):
    """Trigger training of all ML models on collected traffic data."""
    store = _get_store()
    results = store.train_all_models()
    return {
        name: TrainResult(
            name=name,
            status=info.status.value,
            samples_trained=info.samples_trained,
            accuracy=round(info.accuracy, 4),
        )
        for name, info in results.items()
    }


@router.post("/models/{model_id}/train")
async def train_single_model(model_id: str):
    """Train a specific ML model by its model_id.

    Falls back to training all models if individual training is not supported.
    """
    store = _get_store()
    if model_id not in store._model_info:
        raise HTTPException(status_code=404, detail=f"Model '{model_id}' not found")
    results = store.train_all_models()
    info = results.get(model_id)
    if info:
        return {
            "model_id": model_id,
            "name": info.name,
            "status": info.status.value,
            "samples_trained": info.samples_trained,
            "accuracy": round(info.accuracy, 4),
        }
    return {"model_id": model_id, "status": "training_triggered"}


@router.post("/predict/anomaly", response_model=AnomalyPredictionResponse)
async def predict_anomaly(req: AnomalyPredictionRequest):
    """Detect if a request pattern is anomalous using trained ML model."""
    store = _get_store()
    result = store.detect_anomaly(
        method=req.method,
        path=req.path,
        status_code=req.status_code,
        duration_ms=req.duration_ms,
        request_size=req.request_size,
        response_size=req.response_size,
    )
    return AnomalyPredictionResponse(
        is_anomaly=result.is_anomaly,
        score=round(result.score, 4),
        confidence=round(result.confidence, 4),
        reason=result.reason,
    )


@router.post("/predict/threat", response_model=ThreatAssessmentResponse)
async def predict_threat(req: ThreatAssessmentRequest):
    """Assess threat level for a request pattern."""
    store = _get_store()
    result = store.assess_threat(
        method=req.method,
        path=req.path,
        client_ip=req.client_ip,
        status_code=req.status_code,
        duration_ms=req.duration_ms,
        user_agent=req.user_agent,
    )
    return ThreatAssessmentResponse(
        threat_score=round(result.threat_score, 4),
        risk_level=result.risk_level,
        indicators=result.indicators,
        recommended_action=result.recommended_action,
    )


@router.get("/predict/response-time", response_model=ResponseTimePrediction)
async def predict_response_time(
    method: str = Query("GET"),
    path: str = Query("/"),
    request_size: int = Query(0),
):
    """Predict expected response time for a given endpoint."""
    store = _get_store()
    result = store.predict_response_time(
        method=method, path=path, request_size=request_size
    )
    return ResponseTimePrediction(**result)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_stats_alias():
    """Alias for /analytics/stats — keeps frontend happy."""
    store = _get_store()
    return store.get_stats()


@router.get("/analytics/stats")
async def get_traffic_stats():
    """Get overall API traffic statistics."""
    store = _get_store()
    return store.get_stats()


@router.get("/analytics/health")
async def get_api_health():
    """Get per-endpoint API health scores based on learned patterns."""
    store = _get_store()
    return store.get_api_health()


@router.get("/analytics/anomalies")
async def get_recent_anomalies(limit: int = Query(20, ge=1, le=100)):
    """Get recent anomalous requests detected by the ML layer."""
    store = _get_store()
    return store.get_recent_anomalies(limit=limit)


@router.get("/analytics/threats")
async def get_threat_indicators(
    limit: int = Query(20, ge=1, le=100),
    acknowledged: bool = Query(False),
):
    """Get recent threat indicators."""
    store = _get_store()
    return store.get_threat_indicators(limit=limit, acknowledged=acknowledged)


@router.post("/analytics/threats/{indicator_id}/acknowledge")
async def acknowledge_threat(indicator_id: int):
    """Acknowledge a threat indicator."""
    _get_store()
    try:
        from core.api_learning_store import get_learning_store

        s = get_learning_store()
        with s._get_conn() as conn:
            conn.execute(
                "UPDATE threat_indicators SET acknowledged = 1 WHERE id = ?",
                (indicator_id,),
            )
        return {"acknowledged": True, "id": indicator_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/flush")
async def flush_traffic():
    """Force-flush any pending traffic records to the database."""
    store = _get_store()
    store.flush()
    return {"flushed": True}
