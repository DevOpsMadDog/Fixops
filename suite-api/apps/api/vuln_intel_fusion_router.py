"""Vulnerability Intelligence Fusion Router — ALDECI.

Endpoints for the Vulnerability Intelligence Fusion engine.

Prefix: /api/v1/vuln-intel-fusion
Auth:   api_key_auth dependency on ALL endpoints

Routes:
  POST /api/v1/vuln-intel-fusion/ingest                 ingest_from_source
  PUT  /api/v1/vuln-intel-fusion/vulns/{cve_id}/patch   mark_patch_available
  POST /api/v1/vuln-intel-fusion/asset-impacts          add_asset_impact
  GET  /api/v1/vuln-intel-fusion/summary                get_fusion_summary
  GET  /api/v1/vuln-intel-fusion/priority-queue         get_priority_queue
  GET  /api/v1/vuln-intel-fusion/vulns/{cve_id}         get_vuln_detail
  GET  /api/v1/vuln-intel-fusion/kev                    get_kev_vulns
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/vuln-intel-fusion",
    tags=["Vulnerability Intelligence Fusion"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.vuln_intel_fusion_engine import VulnIntelFusionEngine
        _engine = VulnIntelFusionEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SourceIngest(BaseModel):
    cve_id: str
    source_name: str
    source_severity: str = "medium"
    cvss_score: float = 0.0
    epss_score: float = 0.0
    kev_listed: int = 0
    title: str = ""
    additional_data: Dict[str, Any] = Field(default_factory=dict)


class AssetImpactCreate(BaseModel):
    cve_id: str
    asset_id: str
    asset_name: str = ""
    asset_criticality: str = "medium"
    exposure: str = "unknown"
    remediation_priority: int = 3


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/ingest", status_code=201)
def ingest_from_source(body: SourceIngest, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Ingest CVE intelligence from a source feed and fuse into consensus view."""
    try:
        return _get_engine().ingest_from_source(
            org_id=org_id,
            cve_id=body.cve_id,
            source_name=body.source_name,
            source_severity=body.source_severity,
            cvss_score=body.cvss_score,
            epss_score=body.epss_score,
            kev_listed=body.kev_listed,
            title=body.title,
            additional_data=body.additional_data,
        )
    except Exception as exc:
        _logger.exception("ingest_from_source failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/vulns/{cve_id}/patch")
def mark_patch_available(cve_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Mark a CVE as having a patch available."""
    try:
        return _get_engine().mark_patch_available(cve_id, org_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("mark_patch_available failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/asset-impacts", status_code=201)
def add_asset_impact(body: AssetImpactCreate, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Record that a CVE impacts an asset (idempotent by org/cve/asset)."""
    try:
        return _get_engine().add_asset_impact(
            org_id=org_id,
            cve_id=body.cve_id,
            asset_id=body.asset_id,
            asset_name=body.asset_name,
            asset_criticality=body.asset_criticality,
            exposure=body.exposure,
            remediation_priority=body.remediation_priority,
        )
    except Exception as exc:
        _logger.exception("add_asset_impact failed")
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/summary")
def get_fusion_summary(org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get org-level vulnerability intelligence fusion summary."""
    return _get_engine().get_fusion_summary(org_id)


@router.get("/priority-queue")
def get_priority_queue(
     org_id: str = Query(default="default"),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Get prioritized vulnerability queue (consensus_priority ASC, fusion_score DESC)."""
    return _get_engine().get_priority_queue(org_id, limit)


@router.get("/kev")
def get_kev_vulns(org_id: str = Query(default="default")) -> List[Dict[str, Any]]:
    """Get all CISA KEV-listed vulnerabilities ordered by fusion_score DESC."""
    return _get_engine().get_kev_vulns(org_id)


@router.get("/vulns/{cve_id}")
def get_vuln_detail(cve_id: str, org_id: str = Query(default="default")) -> Dict[str, Any]:
    """Get full vulnerability detail including source feeds and asset impacts."""
    result = _get_engine().get_vuln_detail(cve_id, org_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id!r} not found for org {org_id!r}.")
    return result
