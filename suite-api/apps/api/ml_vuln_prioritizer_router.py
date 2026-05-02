"""
ML Vulnerability Prioritizer Router — ALDECI.

Endpoints:
  POST /api/v1/ml/vuln-prioritizer/predict     Predict P(exploit) for a CVE
  GET  /api/v1/ml/vuln-prioritizer/model-info  Model metadata + metrics
  GET  /api/v1/ml/vuln-prioritizer/health      Liveness check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    from fastapi import Depends
    _AUTH_DEP: list = [Depends(_api_key_auth)]
except ImportError:
    _AUTH_DEP = []

router = APIRouter(
    prefix="/api/v1/ml/vuln-prioritizer",
    tags=["ML — Vulnerability Prioritizer"],
    dependencies=_AUTH_DEP,
)

# ---------------------------------------------------------------------------
# Lazy-load inference engine (avoids import-time joblib overhead)
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.ml.vuln_prioritizer import VulnPrioritizerML
            _engine = VulnPrioritizerML.get_instance()
        except Exception as exc:
            logger.error("ml_vuln_prioritizer_router: engine load failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={"error": "ML engine unavailable", "reason": str(exc)},
            )
    return _engine


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class PredictRequest(BaseModel):
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2024-12345")
    features: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Optional: pre-built feature dict (bypasses DB lookup). "
            "If omitted, features are joined from NVD + EPSS + KEV + ExploitDB."
        ),
    )


class PredictResponse(BaseModel):
    cve_id: str
    exploit_probability: float = Field(..., ge=0.0, le=1.0)
    risk_tier: str = Field(..., description="CRITICAL / HIGH / MEDIUM / LOW")
    model_version: str
    sources: List[str]
    feature_values: Dict[str, Any]
    error: Optional[str] = None


class ModelInfoResponse(BaseModel):
    version: str
    trained_at: str
    roc_auc: float
    f1: float
    precision: float
    recall: float
    total_training_rows: int
    model_path: str
    feature_count: int


# ---------------------------------------------------------------------------
# POST /predict
# ---------------------------------------------------------------------------

@router.post(
    "/predict",
    response_model=PredictResponse,
    summary="Predict exploit probability for a CVE",
    description=(
        "Returns calibrated P(exploit) in [0,1] from the gradient-boosted classifier. "
        "Features are joined from NVD + EPSS + CISA KEV + ExploitDB unless provided inline. "
        "risk_tier: CRITICAL (>=0.75), HIGH (>=0.50), MEDIUM (>=0.25), LOW (<0.25)."
    ),
)
def predict(body: PredictRequest) -> PredictResponse:
    cve_id = body.cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_cve_id",
                "message": f"CVE ID must start with 'CVE-', got: {body.cve_id!r}",
            },
        )

    engine = _get_engine()

    try:
        if body.features is not None:
            result = engine.predict_features(cve_id, body.features)
        else:
            result = engine.predict(cve_id)
    except Exception as exc:
        logger.error("predict error cve=%s: %s", cve_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail={"error": str(exc)}) from exc

    # Emit TrustGraph event (fire-and-forget)
    try:
        import asyncio as _asyncio

        from core.trustgraph_event_bus import get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled:
            _asyncio.ensure_future(_bus.emit("ml.vuln_prioritizer.predict", {
                "cve_id": cve_id,
                "exploit_probability": result.exploit_probability,
                "risk_tier": result.risk_tier,
                "model_version": result.model_version,
            }))
    except Exception:
        pass

    return PredictResponse(
        cve_id=result.cve_id,
        exploit_probability=result.exploit_probability,
        risk_tier=result.risk_tier,
        model_version=result.model_version,
        sources=result.sources,
        feature_values=result.feature_values,
        error=result.error,
    )


# ---------------------------------------------------------------------------
# GET /model-info
# ---------------------------------------------------------------------------

@router.get(
    "/model-info",
    response_model=ModelInfoResponse,
    summary="ML model metadata and training metrics",
)
def model_info() -> ModelInfoResponse:
    engine = _get_engine()
    artifact = getattr(engine, "_artifact", None)
    if artifact is None:
        raise HTTPException(status_code=503, detail={"error": "Model artifact not loaded"})

    metrics = artifact.get("metrics", {})
    feat_cols = artifact.get("feature_cols", [])

    model_path = str(engine._path) if hasattr(engine, "_path") else "unknown"

    return ModelInfoResponse(
        version=artifact.get("version", "v1"),
        trained_at=artifact.get("trained_at", "unknown"),
        roc_auc=metrics.get("roc_auc", 0.0),
        f1=metrics.get("f1", 0.0),
        precision=metrics.get("precision", 0.0),
        recall=metrics.get("recall", 0.0),
        total_training_rows=metrics.get("total_rows", 0),
        model_path=model_path,
        feature_count=len(feat_cols),
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

@router.get("/health", summary="ML router liveness")
def health() -> dict:
    try:
        engine = _get_engine()
        loaded = engine._artifact is not None
        return {
            "status": "ok" if loaded else "degraded",
            "model_version": engine.model_version,
            "model_loaded": loaded,
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc), "model_loaded": False}
