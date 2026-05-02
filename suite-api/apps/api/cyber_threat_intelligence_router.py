"""Cyber Threat Intelligence Router — ALDECI.

Endpoints for the Cyber Threat Intelligence engine.

Prefix: /api/v1/cyber-threat-intel
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/cyber-threat-intel/reports                    create_intel_report
  GET   /api/v1/cyber-threat-intel/reports                    list_reports
  GET   /api/v1/cyber-threat-intel/reports/{id}               get_report
  POST  /api/v1/cyber-threat-intel/reports/{id}/publish       publish_report
  POST  /api/v1/cyber-threat-intel/reports/{id}/iocs          add_ioc_to_report
  GET   /api/v1/cyber-threat-intel/iocs                       list_iocs
  GET   /api/v1/cyber-threat-intel/stats                      get_intel_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/cyber-threat-intel",
    tags=["Cyber Threat Intelligence"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.cyber_threat_intelligence_engine import CyberThreatIntelligenceEngine
        _engine = CyberThreatIntelligenceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ReportCreate(BaseModel):
    title: str
    intel_type: str = "tactical"
    tlp: str = "amber"
    source_type: str = "osint"
    summary: str = ""
    content: str = ""
    tags_json: List[str] = []
    confidence_score: float = 0.5


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    context: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    confidence: float = 0.5


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.post("/reports", dependencies=[Depends(api_key_auth)], status_code=201)
def create_intel_report(body: ReportCreate, org_id: str = Query(default="default")):
    """Create a new CTI report in draft status."""
    try:
        return _get_engine().create_intel_report(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/reports", dependencies=[Depends(api_key_auth)])
def list_reports(
     org_id: str = Query(default="default"),
    intel_type: Optional[str] = Query(None),
    tlp: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List CTI reports with optional filters."""
    return _get_engine().list_reports(
        org_id,
        intel_type=intel_type,
        tlp=tlp,
        status=status,
    )


@router.get("/reports/{report_id}", dependencies=[Depends(api_key_auth)])
def get_report(report_id: str, org_id: str = Query(default="default")):
    """Get a single CTI report by ID."""
    report = _get_engine().get_report(org_id, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.post("/reports/{report_id}/publish", dependencies=[Depends(api_key_auth)])
def publish_report(report_id: str, org_id: str = Query(default="default")):
    """Publish a CTI report."""
    try:
        return _get_engine().publish_report(org_id, report_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------

@router.post("/reports/{report_id}/iocs", dependencies=[Depends(api_key_auth)], status_code=201)
def add_ioc_to_report(report_id: str, body: IOCCreate, org_id: str = Query(default="default")):
    """Add an IOC to a CTI report."""
    try:
        return _get_engine().add_ioc_to_report(org_id, report_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/iocs", dependencies=[Depends(api_key_auth)])
def list_iocs(
     org_id: str = Query(default="default"),
    report_id: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None),
):
    """List IOCs with optional filters."""
    return _get_engine().list_iocs(
        org_id,
        report_id=report_id,
        ioc_type=ioc_type,
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_intel_stats(org_id: str = Query(default="default")):
    """Return aggregated CTI statistics."""
    return _get_engine().get_intel_stats(org_id)
