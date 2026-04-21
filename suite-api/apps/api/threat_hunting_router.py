"""Threat Hunting API Router — hunt query management, session lifecycle, and IOC correlation.

Endpoints:
    GET    /api/v1/hunting/queries              -- List all queries (built-in + custom)
    POST   /api/v1/hunting/queries              -- Create a custom query
    POST   /api/v1/hunting/sessions             -- Start a new hunt session
    GET    /api/v1/hunting/sessions             -- List sessions for the org
    GET    /api/v1/hunting/sessions/{id}        -- Get session details
    POST   /api/v1/hunting/sessions/{id}/run    -- Run a query against findings
    POST   /api/v1/hunting/sessions/{id}/end    -- End a session
    GET    /api/v1/hunting/sessions/{id}/results -- Get all results for a session
    POST   /api/v1/hunting/ioc-correlate        -- Cross-correlate IOC values
    GET    /api/v1/hunting/stats                -- Hunt statistics for the org

Security:
    All endpoints require API key authentication via api_key_auth dependency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth, require_role
from apps.api.dependencies import get_org_id

logger = logging.getLogger(__name__)

_ANALYST_ROLES = ("admin", "super_admin", "org_admin", "security_engineer", "analyst")

router = APIRouter(
    prefix="/api/v1/hunting",
    tags=["threat-hunting"],
    dependencies=[require_role(*_ANALYST_ROLES)],
)


# ---------------------------------------------------------------------------
# Lazy engine factory to avoid circular imports
# ---------------------------------------------------------------------------

def _get_engine():
    from core.threat_hunting import ThreatHuntingEngine
    return ThreatHuntingEngine()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateQueryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(..., description="HuntCategory value")
    query_logic: Dict[str, Any] = Field(..., description="Matching logic (any/all conditions)")
    severity: str = Field("medium", description="critical|high|medium|low|info")
    description: str = Field("", max_length=2000)
    mitre_tactic: str = Field("", max_length=20)


class StartSessionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    hunter_email: str = Field(..., min_length=1, max_length=254)


class RunHuntRequest(BaseModel):
    query_id: str = Field(..., description="Built-in or custom query ID")
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    iocs: Optional[List[Dict[str, Any]]] = Field(None, description="IOC list for correlation")


class EndSessionRequest(BaseModel):
    notes: str = Field("", max_length=4000)


class IOCCorrelateRequest(BaseModel):
    ioc_values: List[str] = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Static routes
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_hunt_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return aggregate hunt statistics for the org."""
    engine = _get_engine()
    return engine.get_hunt_stats(org_id=org_id)


@router.post("/ioc-correlate")
async def ioc_correlate(
    body: IOCCorrelateRequest,
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Cross-reference IOC values against all persisted hunt results for the org."""
    engine = _get_engine()
    return engine.correlate_iocs(body.ioc_values, org_id=org_id)


# ---------------------------------------------------------------------------
# Query routes
# ---------------------------------------------------------------------------


@router.get("/queries")
async def list_queries(
    built_in_only: bool = Query(False, description="Return only built-in queries"),
) -> List[Dict[str, Any]]:
    """List all hunt queries (built-in + custom), or built-in only."""
    try:
        engine = _get_engine()
        queries = (
            engine.get_predefined_queries() if built_in_only else engine.get_all_queries()
        )
        return [q.model_dump() for q in queries]
    except Exception:
        return []


@router.post("/queries")
async def create_query(body: CreateQueryRequest) -> Dict[str, Any]:
    """Create a custom hunt query."""
    from core.threat_hunting import HuntCategory

    try:
        category = HuntCategory(body.category)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid category: {body.category}")

    engine = _get_engine()
    query = engine.create_custom_query(
        name=body.name,
        category=category,
        query_logic=body.query_logic,
        severity=body.severity,
        description=body.description,
        mitre_tactic=body.mitre_tactic,
    )
    return query.model_dump()


# ---------------------------------------------------------------------------
# Session routes
# ---------------------------------------------------------------------------


@router.post("/sessions")
async def start_session(
    body: StartSessionRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Start a new hunt session."""
    engine = _get_engine()
    session = engine.start_session(
        name=body.name,
        hunter_email=body.hunter_email,
        org_id=org_id,
    )
    return session.model_dump()


@router.get("/sessions")
async def list_sessions(
    status: Optional[str] = Query(None, description="HuntStatus filter"),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List hunt sessions for the org, optionally filtered by status."""
    from core.threat_hunting import HuntStatus

    parsed_status: Optional[HuntStatus] = None
    if status:
        try:
            parsed_status = HuntStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    engine = _get_engine()
    sessions = engine.list_sessions(org_id=org_id, status_filter=parsed_status)
    return [s.model_dump() for s in sessions]


@router.get("/sessions/{session_id}")
async def get_session(session_id: str) -> Dict[str, Any]:
    """Get hunt session details by ID."""
    engine = _get_engine()
    session = engine.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return session.model_dump()


@router.post("/sessions/{session_id}/run")
async def run_hunt(
    session_id: str,
    body: RunHuntRequest,
) -> List[Dict[str, Any]]:
    """Execute a hunt query against a list of findings, persist results."""
    engine = _get_engine()

    # Verify session exists
    session = engine.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

    try:
        results = engine.run_hunt(
            session_id=session_id,
            query_id=body.query_id,
            findings=body.findings,
            iocs=body.iocs,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # TrustGraph explicit indexing (fire-and-forget)
    try:
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED, get_event_bus as _get_eb
        _bus = _get_eb()
        if _bus and _bus.enabled and results:
            import asyncio as _asyncio
            _asyncio.ensure_future(_bus.emit(EVENT_FINDING_CREATED, {
                "finding_id": f"hunt-{session_id}-{body.query_id}",
                "type": "hunt_finding", "severity": "medium",
                "source": "threat_hunting_router",
                "data": {"session_id": session_id, "query_id": body.query_id, "hits": len(results)},
            }))
    except Exception:
        pass
    return [r.model_dump() for r in results]


@router.post("/sessions/{session_id}/end")
async def end_session(
    session_id: str,
    body: EndSessionRequest,
) -> Dict[str, Any]:
    """End a hunt session and mark it completed."""
    engine = _get_engine()
    try:
        session = engine.end_session(session_id, notes=body.notes)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return session.model_dump()


@router.get("/sessions/{session_id}/results")
async def get_session_results(session_id: str) -> List[Dict[str, Any]]:
    """Retrieve all hunt results for a session."""
    engine = _get_engine()
    session = engine.get_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    results = engine.get_results(session_id)
    return [r.model_dump() for r in results]
