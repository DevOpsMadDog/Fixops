"""Threat Score Router — ALDECI.

Endpoints for the Threat Score engine.

Prefix: /api/v1/threat-scores
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/threat-scores/signals                          ingest_signal
  POST  /api/v1/threat-scores/scores/{asset_id}/calculate      calculate_score
  GET   /api/v1/threat-scores/scores                           list_scores
  GET   /api/v1/threat-scores/scores/{asset_id}                get_score
  GET   /api/v1/threat-scores/scores/{asset_id}/history        get_score_history
  GET   /api/v1/threat-scores/top-threats                      get_top_threats
  GET   /api/v1/threat-scores/stats                            get_threat_stats
"""

from __future__ import annotations

import logging
from typing import Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/threat-scores",
    tags=["Threat Scores"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_score_engine import ThreatScoreEngine
        _engine = ThreatScoreEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SignalIngest(BaseModel):
    asset_id: str
    signal_source: str
    signal_type: str = ""
    signal_value: float
    signal_weight: float = 1.0


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------

@router.post("/signals", dependencies=[Depends(api_key_auth)], status_code=201)
def ingest_signal(body: SignalIngest, org_id: str = Query(default="default")):
    """Ingest a security signal for an asset."""
    try:
        return _get_engine().ingest_signal(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------

@router.post("/scores/{asset_id}/calculate", dependencies=[Depends(api_key_auth)])
def calculate_score(asset_id: str, org_id: str = Query(default="default")):
    """Calculate composite threat score for an asset from ingested signals."""
    return _get_engine().calculate_score(org_id, asset_id)


# ---------------------------------------------------------------------------
# Score queries
# ---------------------------------------------------------------------------

@router.get("/scores", dependencies=[Depends(api_key_auth)])
def list_scores(
     org_id: str = Query(default="default"),
    asset_type: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
):
    """List all threat scores with optional filters."""
    return _get_engine().list_scores(org_id, asset_type=asset_type, risk_level=risk_level)


@router.get("/scores/{asset_id}", dependencies=[Depends(api_key_auth)])
def get_score(asset_id: str, org_id: str = Query(default="default")):
    """Get the latest threat score for an asset."""
    result = _get_engine().get_score(org_id, asset_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Score not found for asset")
    return result


@router.get("/scores/{asset_id}/history", dependencies=[Depends(api_key_auth)])
def get_score_history(
    asset_id: str,
     org_id: str = Query(default="default"),
    limit: int = Query(30),
):
    """Get score history for an asset, most recent first."""
    return _get_engine().get_score_history(org_id, asset_id, limit=limit)


# ---------------------------------------------------------------------------
# Top threats + stats
# ---------------------------------------------------------------------------

@router.get("/top-threats", dependencies=[Depends(api_key_auth)])
def get_top_threats(org_id: str = Query(default="default"), limit: int = Query(10)):
    """Return top-scoring assets ordered by threat score descending."""
    return _get_engine().get_top_threats(org_id, limit=limit)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_threat_stats(org_id: str = Query(default="default")):
    """Return aggregated threat score statistics."""
    return _get_engine().get_threat_stats(org_id)
