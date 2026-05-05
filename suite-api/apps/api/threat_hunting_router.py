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

from apps.api.auth_deps import require_role
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

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
        from core.trustgraph_event_bus import EVENT_FINDING_CREATED
        from core.trustgraph_event_bus import get_event_bus as _get_eb
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


# ---------------------------------------------------------------------------
# Saved-hunt engine factory (ThreatHuntingEngine from threat_hunting_engine.py)
# ---------------------------------------------------------------------------


def _get_hunt_engine():
    from core.threat_hunting_engine import ThreatHuntingEngine
    return ThreatHuntingEngine()


# ---------------------------------------------------------------------------
# Root overview
# ---------------------------------------------------------------------------


@router.get("")
async def hunting_overview(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Return capabilities overview and saved-hunt summary for the org."""
    engine = _get_hunt_engine()
    hunts = engine.list_hunts(org_id=org_id)
    stats = engine.get_hunt_stats(org_id=org_id)
    return {
        "capabilities": {
            "hunt_types": [
                "ioc_match",
                "behavior_pattern",
                "anomaly_correlation",
                "lateral_movement",
                "persistence",
                "exfiltration",
                "custom",
            ],
            "session_lifecycle": True,
            "ioc_correlation": True,
            "scheduling": True,
        },
        "saved_hunts": {
            "total": len(hunts),
            "stats": stats,
        },
    }


# ---------------------------------------------------------------------------
# Saved-hunt CRUD
# ---------------------------------------------------------------------------


class CreateHuntRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    hunt_type: str = Field(..., description="ioc_match|behavior_pattern|anomaly_correlation|lateral_movement|persistence|exfiltration|custom")
    query: Dict[str, Any] = Field(default_factory=dict)
    description: str = Field("", max_length=2000)
    org_id: str = Field("default", max_length=200)


class ScheduleHuntRequest(BaseModel):
    interval_hours: int = Field(24, ge=1, le=8760)


@router.post("/hunts", status_code=201)
async def create_hunt(
    body: CreateHuntRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a saved hunt definition."""
    engine = _get_hunt_engine()
    try:
        hunt = engine.create_hunt(
            name=body.name,
            hunt_type=body.hunt_type,
            query=body.query,
            description=body.description,
            org_id=org_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return hunt


@router.get("/hunts")
async def list_hunts(
    hunt_type: Optional[str] = Query(None),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """List saved hunts for the org, optionally filtered by type."""
    engine = _get_hunt_engine()
    return engine.list_hunts(org_id=org_id, hunt_type=hunt_type)


@router.get("/hunts/{hunt_id}")
async def get_hunt(hunt_id: str) -> Dict[str, Any]:
    """Get a saved hunt by ID."""
    engine = _get_hunt_engine()
    hunt = engine.get_hunt(hunt_id)
    if hunt is None:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} not found")
    return hunt


@router.post("/hunts/{hunt_id}/run")
async def run_saved_hunt(hunt_id: str) -> Dict[str, Any]:
    """Execute a saved hunt immediately."""
    engine = _get_hunt_engine()
    try:
        result = engine.run_hunt(hunt_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return result


@router.get("/hunts/{hunt_id}/results")
async def get_hunt_results(hunt_id: str) -> List[Dict[str, Any]]:
    """Retrieve execution history for a saved hunt."""
    engine = _get_hunt_engine()
    if engine.get_hunt(hunt_id) is None:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} not found")
    return engine.get_results(hunt_id)


@router.post("/hunts/{hunt_id}/schedule", status_code=201)
async def schedule_hunt(
    hunt_id: str,
    body: ScheduleHuntRequest,
) -> Dict[str, Any]:
    """Schedule a saved hunt to run on a recurring interval."""
    engine = _get_hunt_engine()
    try:
        record = engine.schedule_hunt(hunt_id, interval_hours=body.interval_hours)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return record


@router.delete("/hunts/{hunt_id}", status_code=204)
async def delete_hunt(hunt_id: str) -> None:
    """Delete a saved hunt by ID."""
    engine = _get_hunt_engine()
    deleted = engine.delete_hunt(hunt_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Hunt {hunt_id} not found")


# ---------------------------------------------------------------------------
# Alias router: /api/v1/threat-hunting  (UI calls this prefix)
# The canonical router above uses /api/v1/hunting; this alias exposes the
# two endpoints consumed by ThreatHuntingDashboard.tsx without duplicating
# any business logic.
# ---------------------------------------------------------------------------

threat_hunting_alias = APIRouter(
    prefix="/api/v1/threat-hunting",
    tags=["threat-hunting"],
    dependencies=[require_role(*_ANALYST_ROLES)],
)


@threat_hunting_alias.get("/stats")
async def alias_hunt_stats(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    """Alias: GET /api/v1/threat-hunting/stats — delegates to ThreatHuntingEngine."""
    engine = _get_engine()
    return engine.get_hunt_stats(org_id=org_id)


@threat_hunting_alias.get("/hunts")
async def alias_list_hunts(
    limit: int = Query(20, ge=1, le=200),
    org_id: str = Depends(get_org_id),
) -> List[Dict[str, Any]]:
    """Alias: GET /api/v1/threat-hunting/hunts — returns saved hunt definitions."""
    engine = _get_hunt_engine()
    hunts = engine.list_hunts(org_id=org_id)
    return [h if isinstance(h, dict) else h.model_dump() for h in hunts[:limit]]
