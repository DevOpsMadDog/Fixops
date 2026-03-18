"""Dependency-Track integration router.

Exposes OWASP Dependency-Track SBOM analysis data through the FixOps API.
All endpoints proxy to the DTrack connector, which handles retries, circuit
breaking, and rate limiting via _BaseConnector.

Prefix: /api/v1/dtrack
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from core.security_connectors import DependencyTrackConnector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/dtrack", tags=["dependency-track"])

# Lazy singleton — created on first request so env vars are read at runtime
_connector: Optional[DependencyTrackConnector] = None


def _get_connector() -> DependencyTrackConnector:
    global _connector
    if _connector is None:
        _connector = DependencyTrackConnector()
    return _connector


# ── Health ──────────────────────────────────────────────────────────────────


@router.get("/health")
async def dtrack_health() -> Dict[str, Any]:
    """Check Dependency-Track connectivity and version."""
    conn = _get_connector()
    if not conn.configured:
        return {"status": "not_configured", "message": "DTRACK_API_KEY not set"}
    health = conn.health_check()
    return health.to_dict()


# ── Projects ────────────────────────────────────────────────────────────────


@router.get("/projects")
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """List all Dependency-Track projects."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    return conn.list_projects(page_size=page_size, page=page)


@router.get("/projects/lookup")
async def lookup_project(
    name: str = Query(...),
    version: str = Query("latest"),
) -> Dict[str, Any]:
    """Lookup or create a Dependency-Track project by name + version."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    return conn.get_or_create_project(name=name, version=version)


# ── Findings (vulnerabilities) ──────────────────────────────────────────────


@router.get("/findings/{project_uuid}")
async def get_findings(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch vulnerability findings for a project from Dependency-Track."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    outcome = conn.fetch_findings(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Licenses ────────────────────────────────────────────────────────────────


@router.get("/licenses/{project_uuid}")
async def get_licenses(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch component license data for a project."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    outcome = conn.fetch_licenses(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Policy violations ───────────────────────────────────────────────────────


@router.get("/violations/{project_uuid}")
async def get_policy_violations(
    project_uuid: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    """Fetch policy violations for a project."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    outcome = conn.fetch_policy_violations(project_uuid, page_size=page_size, page=page)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


# ── Metrics ─────────────────────────────────────────────────────────────────


@router.get("/metrics/portfolio")
async def portfolio_metrics() -> Dict[str, Any]:
    """Fetch portfolio-wide vulnerability metrics from Dependency-Track."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    outcome = conn.fetch_portfolio_metrics()
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details


@router.get("/metrics/project/{project_uuid}")
async def project_metrics(project_uuid: str) -> Dict[str, Any]:
    """Fetch project-level vulnerability metrics from Dependency-Track."""
    conn = _get_connector()
    if not conn.configured:
        raise HTTPException(status_code=503, detail="Dependency-Track not configured")
    outcome = conn.fetch_project_metrics(project_uuid)
    if not outcome.success:
        raise HTTPException(status_code=502, detail=outcome.details.get("error", "Unknown error"))
    return outcome.details

