"""Log Management API Router — ALDECI.

Endpoints (all under /api/v1/log-management):

  Sources:
    POST /sources                          — create a log source
    GET  /sources                          — list sources (filter: log_type)

  Entries:
    POST /entries                          — store a log entry
    GET  /entries                          — query logs (filters: source_id, level, search, limit)

  Retention Policies:
    POST /retention-policies               — create a retention policy
    GET  /retention-policies               — list all policies
    POST /retention-policies/{policy_id}/apply — apply policy (delete expired logs)

  Stats:
    GET  /stats                            — log management statistics

Auth: api_key_auth injected via Depends.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.log_management_engine import LogManagementEngine
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/log-management", tags=["log-management"])

# Lazy singleton
_engine: Optional[LogManagementEngine] = None


def _get_engine() -> LogManagementEngine:
    global _engine
    if _engine is None:
        _engine = LogManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class LogSourceCreate(BaseModel):
    org_id: str = "default"
    name: str
    log_type: str
    format: str = "json"
    retention_days: int = 90
    status: str = "active"


class LogEntryStore(BaseModel):
    org_id: str = "default"
    source_id: str
    level: str = "info"
    message: str
    metadata: Optional[Dict[str, Any]] = None


class RetentionPolicyCreate(BaseModel):
    org_id: str = "default"
    name: str
    log_type: str
    retention_days: int = 90
    action: str = "archive"


# ---------------------------------------------------------------------------
# Source endpoints
# ---------------------------------------------------------------------------


@router.post("/sources")
def create_source(body: LogSourceCreate) -> Dict[str, Any]:
    """Create a new log source."""
    try:
        result = _get_engine().create_log_source(body.org_id, body.model_dump())
        return {"status": "created", "source": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create log source")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/sources")
def list_sources(
    org_id: str = Query("default"),
    log_type: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List log sources for an org."""
    sources = _get_engine().list_log_sources(org_id, log_type=log_type)
    return {"org_id": org_id, "sources": sources, "total": len(sources)}


# ---------------------------------------------------------------------------
# Entry endpoints
# ---------------------------------------------------------------------------


@router.post("/entries")
def store_entry(body: LogEntryStore) -> Dict[str, Any]:
    """Store a log entry."""
    try:
        result = _get_engine().store_log_entry(body.org_id, body.model_dump())
        return {"status": "stored", "entry": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to store log entry")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/entries")
def query_entries(
    org_id: str = Query("default"),
    source_id: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
) -> Dict[str, Any]:
    """Query log entries with optional filters."""
    entries = _get_engine().query_logs(
        org_id, source_id=source_id, level=level, search=search, limit=limit
    )
    return {"org_id": org_id, "entries": entries, "total": len(entries)}


# ---------------------------------------------------------------------------
# Retention policy endpoints
# ---------------------------------------------------------------------------


@router.post("/retention-policies")
def create_retention_policy(body: RetentionPolicyCreate) -> Dict[str, Any]:
    """Create a log retention policy."""
    try:
        result = _get_engine().create_retention_policy(body.org_id, body.model_dump())
        return {"status": "created", "policy": result}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to create retention policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/retention-policies")
def list_retention_policies(org_id: str = Query("default")) -> Dict[str, Any]:
    """List all retention policies for an org."""
    policies = _get_engine().list_retention_policies(org_id)
    return {"org_id": org_id, "policies": policies, "total": len(policies)}


@router.post("/retention-policies/{policy_id}/apply")
def apply_retention_policy(
    policy_id: str, org_id: str = Query("default")
) -> Dict[str, Any]:
    """Apply a retention policy — deletes expired log entries."""
    try:
        result = _get_engine().apply_retention_policy(org_id, policy_id)
        return {"status": "applied", **result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to apply retention policy")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Get log management statistics for an org."""
    return _get_engine().get_log_stats(org_id)
