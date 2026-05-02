"""Runtime Protection API — /api/v1/runtime

Exposes the RuntimeProtectionEngine for configuration, event inspection,
real-time request scanning, and statistics.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.runtime_protection import (
    EngineMode,
    get_runtime_protection_engine,
)
from fastapi import APIRouter, Body, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/runtime", tags=["Runtime Protection"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class InspectRequest(BaseModel):
    source_ip: str = Field(..., description="Client IP address")
    path: str = Field(..., description="Request path")
    method: str = Field("GET", description="HTTP method")
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    user_id: Optional[str] = None


class ConfigUpdate(BaseModel):
    mode: Optional[str] = None
    block_sqli: Optional[bool] = None
    block_xss: Optional[bool] = None
    block_cmdi: Optional[bool] = None
    block_path_traversal: Optional[bool] = None
    block_ssrf: Optional[bool] = None
    block_prototype_pollution: Optional[bool] = None
    block_deserialization: Optional[bool] = None
    block_bots: Optional[bool] = None
    block_zero_day_patterns: Optional[bool] = None
    rate_limit_rpm: Optional[int] = None
    bot_score_threshold: Optional[float] = None
    ip_allowlist: Optional[List[str]] = None
    ip_denylist: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/inspect")
async def inspect_request(req: InspectRequest) -> Dict[str, Any]:
    """Inspect a single HTTP request for threats."""
    engine = get_runtime_protection_engine()
    return engine.inspect_request(
        source_ip=req.source_ip,
        path=req.path,
        method=req.method,
        headers=req.headers,
        body=req.body,
        user_id=req.user_id,
    )


@router.get("/events")
async def get_events(
    limit: int = Query(100, ge=1, le=1000),
    category: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Get recent protection events."""
    engine = get_runtime_protection_engine()
    events = engine.get_events(limit=limit, category=category)
    return {"events": events, "count": len(events)}


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """Get aggregate protection statistics."""
    engine = get_runtime_protection_engine()
    return engine.get_stats()


@router.put("/configure")
async def configure(update: ConfigUpdate) -> Dict[str, Any]:
    """Update runtime protection configuration."""
    engine = get_runtime_protection_engine()
    changes = {k: v for k, v in update.model_dump().items() if v is not None}
    if "mode" in changes:
        changes["mode"] = EngineMode(changes["mode"])
    engine.update_config(**changes)
    return {"status": "updated", "config": engine.get_stats()["config"]}


@router.get("/status")
async def status() -> Dict[str, Any]:
    """Health / readiness check for the runtime protection engine."""
    engine = get_runtime_protection_engine()
    stats = engine.get_stats()
    return {
        "status": "active",
        "mode": stats["mode"],
        "uptime_seconds": stats["uptime_seconds"],
        "total_events": stats["total_events"],
        "blocked_events": stats["blocked_events"],
    }


@router.post("/ip/block")
async def block_ip(ip: str = Body(..., embed=True)) -> Dict[str, Any]:
    """Add an IP to the denylist."""
    engine = get_runtime_protection_engine()
    if ip not in engine.config.ip_denylist:
        engine.config.ip_denylist.append(ip)
    return {"status": "blocked", "ip": ip}


@router.post("/ip/allow")
async def allow_ip(ip: str = Body(..., embed=True)) -> Dict[str, Any]:
    """Add an IP to the allowlist."""
    engine = get_runtime_protection_engine()
    if ip not in engine.config.ip_allowlist:
        engine.config.ip_allowlist.append(ip)
    return {"status": "allowed", "ip": ip}


@router.get("/categories")
async def list_categories() -> Dict[str, Any]:
    """List all threat categories the engine can detect."""
    from core.runtime_protection import ThreatCategory
    return {"categories": [c.value for c in ThreatCategory]}

