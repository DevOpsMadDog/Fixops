"""Code-to-Runtime Matcher Router — ALDECI (GAP-013).

Endpoints for the CodeToRuntimeMatcherEngine.

Prefix: /api/v1/code-to-runtime
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/code-to-runtime/service-mapping      register_service_mapping
  POST  /api/v1/code-to-runtime/event                ingest_runtime_event
  POST  /api/v1/code-to-runtime/match/{event_id}     match_event_to_code
  POST  /api/v1/code-to-runtime/bulk-match           bulk_match
  GET   /api/v1/code-to-runtime/events               list_events
  GET   /api/v1/code-to-runtime/matches              list_matches
  GET   /api/v1/code-to-runtime/stats                stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/code-to-runtime",
    tags=["Code-to-Runtime"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.code_to_runtime_matcher_engine import CodeToRuntimeMatcherEngine
        _engine = CodeToRuntimeMatcherEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ServiceMappingCreate(BaseModel):
    org_id: str
    service_name: str
    repo_ref: str
    deploy_ref: str = ""


class RuntimeEventCreate(BaseModel):
    org_id: str
    event_ref: str
    event_type: str
    service_name: str = ""
    path: str = ""
    method: str = ""
    status_code: int = 0
    error_message: str = ""
    stack_trace: str = ""


class BulkMatchRequest(BaseModel):
    org_id: str
    since_minutes: int = 60


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/service-mapping")
async def register_service_mapping(req: ServiceMappingCreate) -> Dict[str, Any]:
    try:
        return _get_engine().register_service_mapping(
            org_id=req.org_id,
            service_name=req.service_name,
            repo_ref=req.repo_ref,
            deploy_ref=req.deploy_ref,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/event")
async def ingest_runtime_event(req: RuntimeEventCreate) -> Dict[str, Any]:
    try:
        return _get_engine().ingest_runtime_event(
            org_id=req.org_id,
            event_ref=req.event_ref,
            event_type=req.event_type,
            service_name=req.service_name,
            path=req.path,
            method=req.method,
            status_code=req.status_code,
            error_message=req.error_message,
            stack_trace=req.stack_trace,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/match/{event_id}")
async def match_event(event_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().match_event_to_code(event_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/bulk-match")
async def bulk_match(req: BulkMatchRequest) -> Dict[str, Any]:
    return _get_engine().bulk_match(
        org_id=req.org_id, since_minutes=req.since_minutes
    )


@router.get("/events")
async def list_events(
    org_id: str = Query(...),
    service_name: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    return _get_engine().list_events(
        org_id=org_id, service_name=service_name, limit=limit
    )


@router.get("/matches")
async def list_matches(
    org_id: str = Query(...),
    event_id: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    return _get_engine().list_matches(
        org_id=org_id, runtime_event_id=event_id, limit=limit
    )


@router.get("/stats")
async def stats(org_id: str = Query(...)) -> Dict[str, Any]:
    return _get_engine().stats(org_id)
