"""
Threat Intelligence Correlation API endpoints — ALDECI.

Exposes threat actor profiles, campaign data, and finding correlation
via the ThreatIntelCorrelator engine.

Protected with API key authentication via ``_verify_api_key`` (injected
via ``app.include_router`` dependencies — see app.py).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.threat_intel_correlator import (
    Campaign,
    ThreatActor,
    ThreatCorrelation,
    ThreatIntelCorrelator,
)

router = APIRouter(
    prefix="/api/v1/threat-intel",
    tags=["threat-intel"],
)

_correlator = ThreatIntelCorrelator()


# ---------------------------------------------------------------------------
# Request / Response shapes
# ---------------------------------------------------------------------------


class CorrelateRequest(BaseModel):
    """Request body for finding correlation."""

    finding: Dict[str, Any]


class BatchCorrelateRequest(BaseModel):
    """Request body for batch correlation."""

    findings: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/correlate", response_model=ThreatCorrelation)
async def correlate_finding(body: CorrelateRequest) -> ThreatCorrelation:
    """
    Correlate a single security finding against all known threat actors
    and campaigns. Returns the best-matching ThreatCorrelation.
    """
    if not body.finding:
        raise HTTPException(status_code=422, detail="finding must not be empty")
    return _correlator.correlate_finding(body.finding)


@router.post("/correlate/batch", response_model=List[ThreatCorrelation])
async def correlate_batch(body: BatchCorrelateRequest) -> List[ThreatCorrelation]:
    """
    Correlate a batch of security findings. Returns a correlation result
    for each finding in the same order as the input list.
    """
    if not body.findings:
        raise HTTPException(status_code=422, detail="findings list must not be empty")
    return _correlator.correlate_batch(body.findings)


@router.get("/actors", response_model=List[ThreatActor])
async def list_threat_actors(
    active_only: bool = Query(False, description="Return only active actors"),
) -> List[ThreatActor]:
    """
    List all registered threat actor profiles. Optionally filter to
    active actors only.
    """
    actors = _correlator._load_all_actors()
    if active_only:
        actors = [a for a in actors if a.active]
    return actors


@router.post("/actors", response_model=ThreatActor)
async def add_threat_actor(actor: ThreatActor) -> ThreatActor:
    """
    Register a new threat actor profile. If an actor with the same ID
    already exists it will be replaced (upsert).
    """
    _correlator.add_threat_actor(actor)
    return actor


@router.get("/actors/{actor_id}", response_model=Dict[str, Any])
async def get_actor_profile(actor_id: str) -> Dict[str, Any]:
    """
    Return full actor dossier: profile, associated campaigns, and
    recent finding correlations.
    """
    profile = _correlator.get_actor_profile(actor_id)
    if profile is None:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found")
    return profile


@router.post("/campaigns", response_model=Campaign)
async def add_campaign(campaign: Campaign) -> Campaign:
    """
    Register a new threat campaign. Upserts on duplicate ID.
    """
    _correlator.add_campaign(campaign)
    return campaign


@router.get("/campaigns/{campaign_id}/timeline", response_model=Dict[str, Any])
async def get_campaign_timeline(campaign_id: str) -> Dict[str, Any]:
    """
    Return campaign details and all correlated finding events as a
    chronological timeline.
    """
    timeline = _correlator.get_campaign_timeline(campaign_id)
    if timeline is None:
        raise HTTPException(
            status_code=404, detail=f"Campaign '{campaign_id}' not found"
        )
    return timeline


@router.get("/landscape", response_model=Dict[str, Any])
async def get_threat_landscape(
    org_id: str = Query("default", description="Organisation identifier"),
) -> Dict[str, Any]:
    """
    Return a high-level threat landscape overview for the organisation:
    active actor count, active campaigns, and top correlated threat actors.
    """
    return _correlator.get_threat_landscape(org_id)


@router.get("/active-threats", response_model=List[ThreatActor])
async def get_active_threats(
    org_id: str = Query("default", description="Organisation identifier"),
) -> List[ThreatActor]:
    """
    Return all currently active threat actors relevant to the organisation.
    """
    return _correlator.get_active_threats(org_id)


# ---------------------------------------------------------------------------
# CVE / EPSS / KEV aggregation endpoints (ThreatIntelAggregator)
# ---------------------------------------------------------------------------

import logging as _logging  # noqa: E402

from threat_intel_aggregator import ThreatIntelAggregator  # noqa: E402

_agg_logger = _logging.getLogger(__name__)
_aggregator = ThreatIntelAggregator()


@router.get("/cves/recent", response_model=List[Dict[str, Any]])
async def get_recent_cves(
    limit: int = Query(100, ge=1, le=500, description="Max CVEs to return"),
) -> List[Dict[str, Any]]:
    """
    Return the most recently cached CVEs enriched with EPSS scores.

    CVEs are served from the local SQLite cache. Call ``/refresh`` to
    pull the latest data from NVD / EPSS / CISA KEV.
    """
    records = _aggregator.get_cached_cves(limit=limit)
    if not records:
        raise HTTPException(
            status_code=404,
            detail="No CVE data cached yet — call POST /api/v1/threat-intel/refresh first",
        )
    # Enrich with latest EPSS if missing
    missing_epss = [r.cve_id for r in records if r.epss_score == 0.0]
    if missing_epss:
        try:
            epss_map = _aggregator.enrich_with_epss(missing_epss[:50])
            for rec in records:
                if rec.cve_id in epss_map:
                    rec.epss_score = epss_map[rec.cve_id]
        except Exception as exc:  # noqa: BLE001
            _agg_logger.warning("EPSS enrichment failed: %s", exc)

    return [r.to_dict() for r in records]


@router.get("/kev", response_model=Dict[str, Any])
async def get_kev_catalog() -> Dict[str, Any]:
    """
    Return the current CISA Known Exploited Vulnerabilities catalog from cache.

    The catalog is refreshed on each call to ``/refresh``.
    """
    kev_map = _aggregator._load_kev_from_cache()
    if not kev_map:
        raise HTTPException(
            status_code=404,
            detail="KEV catalog not yet cached — call POST /api/v1/threat-intel/refresh",
        )
    return {
        "count": len(kev_map),
        "entries": [
            {"cve_id": cve_id, "due_date": due_date}
            for cve_id, due_date in sorted(kev_map.items())
        ],
    }


@router.post("/refresh", response_model=Dict[str, Any])
async def trigger_refresh() -> Dict[str, Any]:
    """
    Trigger a fresh pull from NVD, EPSS, and CISA KEV.

    This is a synchronous operation — it blocks until all feeds
    are fetched and cached. For large date ranges this may take
    up to 60 seconds due to NVD rate limits.
    """
    try:
        report = _aggregator.aggregate_daily()
        return {
            "status": "ok",
            "generated_at": report.generated_at,
            "total_cves": report.total_cves,
            "kev_count": report.kev_count,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "avg_epss": report.avg_epss,
            "osv_count": report.osv_count,
            "otx_pulses": report.otx_pulses,
        }
    except Exception as exc:  # noqa: BLE001
        _agg_logger.error("Threat intel refresh failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Refresh failed: {exc}") from exc
