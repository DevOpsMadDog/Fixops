"""Behavioral Analytics Router — ALDECI.

UEBA behavioral analytics via REST endpoints.

Prefix: /api/v1/behavioral-analytics

Endpoints:
  POST   /baselines                    — Establish or update a user baseline
  GET    /baselines                    — List baselines (user_id, baseline_type)
  POST   /anomalies                    — Detect/record an anomaly
  GET    /anomalies                    — List anomalies (user_id, behavior_type, severity, status)
  PATCH  /anomalies/{id}/status        — Update anomaly status
  GET    /users/{user_id}/profile      — Get user risk profile
  GET    /stats                        — Org-level behavioral stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/behavioral-analytics",
    tags=["behavioral-analytics"],
)

# ---------------------------------------------------------------------------
# Lazy engine loader
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from core.behavioral_analytics_engine import BehavioralAnalyticsEngine
            _engine = BehavioralAnalyticsEngine()
        except ImportError as exc:
            logger.error("behavioral_analytics_engine import failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail=f"behavioral_analytics unavailable: {exc}",
            )
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class EstablishBaselineRequest(BaseModel):
    org_id: str = "default"
    user_id: str
    baseline_type: str = "login_hours"
    normal_value: float = 0.0
    std_deviation: float = 0.0
    samples_count: int = 0


class DetectAnomalyRequest(BaseModel):
    org_id: str = "default"
    user_id: str
    behavior_type: str = "login_anomaly"
    severity: str = "medium"
    observed_value: float = 0.0
    baseline_value: float = 0.0
    deviation_score: float = 0.0
    description: str = ""
    detected_at: Optional[str] = None


class UpdateAnomalyStatusRequest(BaseModel):
    status: str
    notes: str = ""


# ---------------------------------------------------------------------------
# Endpoints — Baselines
# ---------------------------------------------------------------------------


@router.post("/baselines", status_code=201)
def establish_baseline(body: EstablishBaselineRequest) -> Dict[str, Any]:
    """Establish or update a user behavioral baseline."""
    engine = _get_engine()
    try:
        return engine.establish_baseline(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/baselines")
def list_baselines(
    org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(default=None),
    baseline_type: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List baselines with optional filters."""
    engine = _get_engine()
    return engine.list_baselines(
        org_id,
        user_id=user_id,
        baseline_type=baseline_type,
    )


# ---------------------------------------------------------------------------
# Endpoints — Anomalies
# ---------------------------------------------------------------------------


@router.post("/anomalies", status_code=201)
def detect_anomaly(body: DetectAnomalyRequest) -> Dict[str, Any]:
    """Record a detected behavioral anomaly."""
    engine = _get_engine()
    try:
        return engine.detect_anomaly(body.org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/anomalies")
def list_anomalies(
    org_id: str = Query(default="default"),
    user_id: Optional[str] = Query(default=None),
    behavior_type: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
) -> List[Dict[str, Any]]:
    """List anomalies with optional filters."""
    engine = _get_engine()
    return engine.list_anomalies(
        org_id,
        user_id=user_id,
        behavior_type=behavior_type,
        severity=severity,
        status=status,
    )


@router.patch("/anomalies/{anomaly_id}/status")
def update_anomaly_status(
    anomaly_id: str,
    body: UpdateAnomalyStatusRequest,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Update the status of a behavioral anomaly."""
    engine = _get_engine()
    try:
        result = engine.update_anomaly_status(
            org_id, anomaly_id, body.status, notes=body.notes
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail=f"Anomaly {anomaly_id!r} not found.")
    return result


# ---------------------------------------------------------------------------
# Endpoints — User Profile & Stats
# ---------------------------------------------------------------------------


@router.get("/users/{user_id}/profile")
def get_user_risk_profile(
    user_id: str,
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Get the behavioral risk profile for a specific user."""
    engine = _get_engine()
    return engine.get_user_risk_profile(org_id, user_id)


@router.get("/stats")
def get_behavioral_stats(
    org_id: str = Query(default="default"),
) -> Dict[str, Any]:
    """Return org-level behavioral analytics statistics."""
    engine = _get_engine()
    return engine.get_behavioral_stats(org_id)
