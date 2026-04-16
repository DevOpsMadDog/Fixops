"""Threat Intel Fusion API Router — ALDECI.

Endpoints (all under /api/v1/threat-intel-fusion):

  Sources:
    POST   /sources                 — add intel source
    GET    /sources                 — list intel sources

  Indicators:
    POST   /indicators              — ingest indicator
    GET    /indicators/search       — search indicators by value
    GET    /indicators/high-confidence — get high-confidence indicators
    POST   /indicators/expire       — expire old indicators

  Fusion:
    GET    /fuse/{indicator_value}  — fuse indicator from all sources

  Stats:
    GET    /stats                   — fusion statistics

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-intel-fusion", tags=["threat-intel-fusion"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intel_fusion_engine import ThreatIntelFusionEngine
        _engine = ThreatIntelFusionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AddSourceRequest(BaseModel):
    name: str = Field(..., min_length=1)
    source_type: str = Field(default="osint")
    reliability: int = Field(default=5, ge=1, le=10)
    tlp_level: str = Field(default="white")


class IngestIndicatorRequest(BaseModel):
    source_id: str = Field(default="")
    indicator_type: str = Field(default="ip")
    value: str = Field(..., min_length=1)
    confidence: int = Field(default=50, ge=0, le=100)
    tags: List[str] = Field(default_factory=list)
    expiry_days: int = Field(default=30, ge=1)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


@router.post("/sources", summary="Add an intel source")
def add_source(req: AddSourceRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().add_intel_source(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/sources", summary="List intel sources")
def list_sources(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    return _get_engine().list_intel_sources(org_id)


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------


@router.post("/indicators", summary="Ingest a threat indicator")
def ingest_indicator(req: IngestIndicatorRequest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().ingest_indicator(org_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/indicators/search", summary="Search indicators by value")
def search_indicators(
    q: str = Query(..., min_length=1),
    indicator_type: Optional[str] = Query(None),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().search_indicators(org_id, query=q, indicator_type=indicator_type)


@router.get("/indicators/high-confidence", summary="Get high-confidence indicators")
def get_high_confidence(
    min_confidence: int = Query(80, ge=0, le=100),
    limit: int = Query(50, ge=1, le=500),
    org_id: str = Query(default="default"),
) -> List[Dict[str, Any]]:
    return _get_engine().get_high_confidence_indicators(
        org_id, min_confidence=min_confidence, limit=limit
    )


@router.post("/indicators/expire", summary="Expire old indicators past expiry date")
def expire_indicators(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().expire_old_indicators(org_id)


# ---------------------------------------------------------------------------
# Fusion
# ---------------------------------------------------------------------------


@router.get("/fuse/{indicator_value}", summary="Fuse indicator from all sources")
def fuse_indicator(indicator_value: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().fuse_indicator(org_id, indicator_value)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats", summary="Get fusion statistics")
def get_stats(org_id: str = Query(default="default")) -> Dict[str, Any]:
    return _get_engine().get_fusion_stats(org_id)
