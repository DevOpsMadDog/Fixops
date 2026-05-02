"""Zero Day Intelligence Router — ALDECI.

Endpoints for the Zero Day Intelligence engine.

Prefix: /api/v1/zero-day
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/zero-day/vulns                          register_vulnerability
  GET  /api/v1/zero-day/vulns                          list_vulnerabilities
  GET  /api/v1/zero-day/vulns/{vuln_id}                get_vulnerability
  PUT  /api/v1/zero-day/vulns/{vuln_id}/patch-status   update_patch_status
  POST /api/v1/zero-day/threat-actors                  record_threat_actor
  GET  /api/v1/zero-day/threat-actors                  list_threat_actors
  POST /api/v1/zero-day/mitigations                    record_mitigation
  GET  /api/v1/zero-day/mitigations                    list_mitigations
  GET  /api/v1/zero-day/stats                          get_zero_day_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/zero-day",
    tags=["Zero Day Intelligence"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.zero_day_intelligence_engine import ZeroDayIntelligenceEngine
        _engine = ZeroDayIntelligenceEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class VulnerabilityCreate(BaseModel):
    cve_id: str
    title: str = ""
    description: str = ""
    cvss_score: float = 0.0
    exploitability_score: float = 0.0
    affected_products: List[str] = []
    disclosure_type: str = "coordinated"
    patch_status: str = "unpatched"
    exploitation_status: str = "unconfirmed"
    severity: str = "medium"
    discovered_at: Optional[str] = None
    disclosed_at: Optional[str] = None
    patched_at: Optional[str] = None


class PatchStatusUpdate(BaseModel):
    patch_status: str
    patched_at: Optional[str] = None


class ThreatActorCreate(BaseModel):
    vulnerability_id: str
    actor_name: str
    actor_type: str = "unknown"
    confidence_score: float = 50.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class MitigationCreate(BaseModel):
    vulnerability_id: str
    mitigation_type: str = "workaround"
    description: str = ""
    status: str = "proposed"
    applied_by: str = ""
    applied_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------

@router.post("/vulns", dependencies=[Depends(api_key_auth)], status_code=201)
def register_vulnerability(body: VulnerabilityCreate, org_id: str = Query(default="default")):
    """Register a new zero-day vulnerability."""
    try:
        return _get_engine().register_vulnerability(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/vulns", dependencies=[Depends(api_key_auth)])
def list_vulnerabilities(
     org_id: str = Query(default="default"),
    severity: Optional[str] = Query(None),
    patch_status: Optional[str] = Query(None),
    exploitation_status: Optional[str] = Query(None),
):
    """List vulnerabilities with optional filters."""
    return _get_engine().list_vulnerabilities(
        org_id,
        severity=severity,
        patch_status=patch_status,
        exploitation_status=exploitation_status,
    )


@router.get("/vulns/{vuln_id}", dependencies=[Depends(api_key_auth)])
def get_vulnerability(vuln_id: str, org_id: str = Query(default="default")):
    """Get a single vulnerability by ID."""
    vuln = _get_engine().get_vulnerability(org_id, vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.put("/vulns/{vuln_id}/patch-status", dependencies=[Depends(api_key_auth)])
def update_patch_status(vuln_id: str, body: PatchStatusUpdate, org_id: str = Query(default="default")):
    """Update the patch status of a vulnerability."""
    try:
        return _get_engine().update_patch_status(
            org_id, vuln_id, body.patch_status, patched_at=body.patched_at
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Threat Actors
# ---------------------------------------------------------------------------

@router.post("/threat-actors", dependencies=[Depends(api_key_auth)], status_code=201)
def record_threat_actor(body: ThreatActorCreate, org_id: str = Query(default="default")):
    """Record a threat actor associated with a vulnerability."""
    try:
        return _get_engine().record_threat_actor(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/threat-actors", dependencies=[Depends(api_key_auth)])
def list_threat_actors(
     org_id: str = Query(default="default"),
    vulnerability_id: Optional[str] = Query(None),
):
    """List threat actors with optional vulnerability filter."""
    return _get_engine().list_threat_actors(org_id, vulnerability_id=vulnerability_id)


# ---------------------------------------------------------------------------
# Mitigations
# ---------------------------------------------------------------------------

@router.post("/mitigations", dependencies=[Depends(api_key_auth)], status_code=201)
def record_mitigation(body: MitigationCreate, org_id: str = Query(default="default")):
    """Record a mitigation for a vulnerability."""
    try:
        return _get_engine().record_mitigation(org_id, body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/mitigations", dependencies=[Depends(api_key_auth)])
def list_mitigations(
     org_id: str = Query(default="default"),
    vulnerability_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    """List mitigations with optional filters."""
    return _get_engine().list_mitigations(
        org_id, vulnerability_id=vulnerability_id, status=status
    )


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_zero_day_stats(org_id: str = Query(default="default")):
    """Return aggregated zero-day intelligence statistics."""
    return _get_engine().get_zero_day_stats(org_id)
