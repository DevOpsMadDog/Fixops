"""Anti-Phishing Router — REST endpoints for anti-phishing management.

Endpoints under /api/v1/anti-phishing:
  POST   /urls                        — Submit a URL for analysis
  GET    /urls                        — List submitted URLs (filter: verdict, status)
  GET    /urls/{url_id}               — Get a single URL submission
  POST   /urls/{url_id}/analyze       — Record analysis verdict for a URL
  POST   /simulations                 — Create a phishing simulation campaign
  PUT    /simulations/{sim_id}/results — Update simulation results
  GET    /simulations                 — List simulations (filter: status)
  GET    /stats                       — Anti-phishing statistics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/anti-phishing",
    tags=["Anti-Phishing"],
    dependencies=[Depends(api_key_auth)],
)

_engine_instance = None


def _get_engine():
    global _engine_instance
    if _engine_instance is None:
        try:
            from core.anti_phishing_engine import AntiPhishingEngine
            _engine_instance = AntiPhishingEngine()
        except Exception as exc:
            _logger.error("AntiPhishingEngine unavailable: %s", exc)
            raise HTTPException(status_code=503, detail=f"Anti-phishing engine unavailable: {exc}")
    return _engine_instance


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SubmitUrlRequest(BaseModel):
    url: str
    submission_source: str = "automated"
    submitted_at: Optional[str] = None


class AnalyzeUrlRequest(BaseModel):
    verdict: str
    confidence: int = 0
    indicators: List[str] = []


class RecordSimulationRequest(BaseModel):
    campaign_name: str
    target_department: str = ""
    simulation_type: str
    sent_count: int
    opened: int = 0
    clicked: int = 0
    reported: int = 0
    started_at: Optional[str] = None


class UpdateSimulationResultsRequest(BaseModel):
    opened: int
    clicked: int
    reported: int


# ---------------------------------------------------------------------------
# URL endpoints
# ---------------------------------------------------------------------------

@router.post("/urls", response_model=Dict[str, Any])
def submit_url(body: SubmitUrlRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("submitted_at") is None:
        data.pop("submitted_at", None)
    try:
        url_obj = eng.submit_url(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return url_obj


@router.get("/urls", response_model=Dict[str, Any])
def list_urls(
    org_id: str = Query("default"),
    verdict: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    urls = eng.list_urls(org_id, verdict=verdict, status=status)
    return {"total": len(urls), "urls": urls}


@router.get("/urls/{url_id}", response_model=Dict[str, Any])
def get_url(url_id: str, org_id: str = Query("default")):
    eng = _get_engine()
    url_obj = eng.get_url(org_id, url_id)
    if url_obj is None:
        raise HTTPException(status_code=404, detail=f"URL {url_id!r} not found")
    return url_obj


@router.post("/urls/{url_id}/analyze", response_model=Dict[str, Any])
def analyze_url(url_id: str, body: AnalyzeUrlRequest, org_id: str = Query("default")):
    eng = _get_engine()
    try:
        result = eng.analyze_url(org_id, url_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if result is None:
        raise HTTPException(status_code=404, detail=f"URL {url_id!r} not found")
    return result


# ---------------------------------------------------------------------------
# Simulation endpoints
# ---------------------------------------------------------------------------

@router.post("/simulations", response_model=Dict[str, Any])
def record_simulation(body: RecordSimulationRequest, org_id: str = Query("default")):
    eng = _get_engine()
    data = body.model_dump()
    if data.get("started_at") is None:
        data.pop("started_at", None)
    try:
        sim = eng.record_simulation(org_id, data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return sim


@router.put("/simulations/{sim_id}/results", response_model=Dict[str, Any])
def update_simulation_results(
    sim_id: str,
    body: UpdateSimulationResultsRequest,
    org_id: str = Query("default"),
):
    eng = _get_engine()
    result = eng.update_simulation_results(
        org_id, sim_id, body.opened, body.clicked, body.reported
    )
    if result is None:
        raise HTTPException(status_code=404, detail=f"Simulation {sim_id!r} not found")
    return result


@router.get("/simulations", response_model=Dict[str, Any])
def list_simulations(
    org_id: str = Query("default"),
    status: Optional[str] = Query(None),
):
    eng = _get_engine()
    sims = eng.list_simulations(org_id, status=status)
    return {"total": len(sims), "simulations": sims}


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=Dict[str, Any])
def get_anti_phishing_stats(org_id: str = Query("default")):
    eng = _get_engine()
    return eng.get_anti_phishing_stats(org_id)
