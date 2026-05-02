"""Threat Intelligence Confidence Router — ALDECI.

IOC confidence scoring and source reliability tracking.

Prefix: /api/v1/ti-confidence
Auth: api_key_auth dependency on all endpoints

Routes:
  POST   /api/v1/ti-confidence/iocs/score              score_ioc
  PUT    /api/v1/ti-confidence/iocs/{id}/confirm        confirm_ioc
  PUT    /api/v1/ti-confidence/iocs/{id}/false-positive report_false_positive
  POST   /api/v1/ti-confidence/expire                  expire_stale_iocs
  GET    /api/v1/ti-confidence/summary                 get_ioc_summary
  GET    /api/v1/ti-confidence/sources                 get_source_rankings
  GET    /api/v1/ti-confidence/high-confidence         get_high_confidence_iocs
  GET    /api/v1/ti-confidence/search                  search_ioc
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ti-confidence",
    tags=["Threat Intelligence Confidence"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.threat_intelligence_confidence_engine import (
            ThreatIntelligenceConfidenceEngine,
        )
        _engine = ThreatIntelligenceConfidenceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScoreIOCRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")
    ioc_value: str = Field(..., description="The IOC value (IP, domain, hash, etc.)")
    ioc_type: str = Field(
        default="ip",
        description="Type: ip/domain/url/hash/email/asn/cidr/user_agent",
    )
    source_name: str = Field(..., description="Name of the contributing source")
    source_confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Source confidence for this IOC (0.0–1.0)"
    )


class ConfirmIOCRequest(BaseModel):
    org_id: str = Field(default="default")
    source_name: str = Field(..., description="Source confirming the IOC")


class FalsePositiveRequest(BaseModel):
    org_id: str = Field(default="default")
    source_name: str = Field(..., description="Source reporting the false positive")


class ExpireRequest(BaseModel):
    org_id: str = Field(default="default", description="Organisation identifier")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/iocs/score", summary="Score or re-score an IOC")
def score_ioc(req: ScoreIOCRequest) -> Dict[str, Any]:
    try:
        return _get_engine().score_ioc(
            org_id=req.org_id,
            ioc_value=req.ioc_value,
            ioc_type=req.ioc_type,
            source_name=req.source_name,
            source_confidence=req.source_confidence,
        )
    except Exception as exc:
        _logger.exception("score_ioc failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/iocs/{ioc_id}/confirm", summary="Confirm an IOC (boosts source reliability)")
def confirm_ioc(ioc_id: str, req: ConfirmIOCRequest) -> Dict[str, Any]:
    try:
        result = _get_engine().confirm_ioc(
            ioc_id=ioc_id,
            org_id=req.org_id,
            source_name=req.source_name,
        )
        if result.get("error") == "not_found":
            raise HTTPException(status_code=404, detail="IOC not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("confirm_ioc failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.put("/iocs/{ioc_id}/false-positive", summary="Report an IOC as false positive")
def report_false_positive(ioc_id: str, req: FalsePositiveRequest) -> Dict[str, Any]:
    try:
        result = _get_engine().report_false_positive(
            ioc_id=ioc_id,
            org_id=req.org_id,
            source_name=req.source_name,
        )
        if result.get("error") == "not_found":
            raise HTTPException(status_code=404, detail="IOC not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("report_false_positive failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/expire", summary="Expire stale IOCs past their expires_at date")
def expire_stale_iocs(req: ExpireRequest) -> Dict[str, Any]:
    try:
        count = _get_engine().expire_stale_iocs(org_id=req.org_id)
        return {"expired_count": count}
    except Exception as exc:
        _logger.exception("expire_stale_iocs failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/summary", summary="IOC summary stats")
def get_ioc_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    try:
        return _get_engine().get_ioc_summary(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_ioc_summary failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/sources", summary="Source reliability rankings")
def get_source_rankings(org_id: str = Query(default="default")):
    try:
        return _get_engine().get_source_rankings(org_id=org_id)
    except Exception as exc:
        _logger.exception("get_source_rankings failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/high-confidence", summary="High confidence active IOCs")
def get_high_confidence_iocs(
    org_id: str = Query(default="default"),
    min_confidence: float = Query(default=0.7, ge=0.0, le=1.0),
):
    try:
        return _get_engine().get_high_confidence_iocs(
            org_id=org_id, min_confidence=min_confidence
        )
    except Exception as exc:
        _logger.exception("get_high_confidence_iocs failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/search", summary="Search IOC by exact value")
def search_ioc(
    org_id: str = Query(default="default"),
    ioc_value: str = Query(..., description="Exact IOC value to look up"),
) -> Dict[str, Any]:
    try:
        result = _get_engine().search_ioc(org_id=org_id, ioc_value=ioc_value)
        if result is None:
            raise HTTPException(status_code=404, detail="IOC not found")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("search_ioc failed")
        raise HTTPException(status_code=500, detail=str(exc))
