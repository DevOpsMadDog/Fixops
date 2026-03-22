"""ALdeci SIEM Integration Router.

Endpoints for configuring SIEM forwarding targets and sending events:
POST /api/v1/siem/targets          — Add a SIEM target
GET  /api/v1/siem/targets          — List all targets
GET  /api/v1/siem/targets/{id}     — Get target details
DELETE /api/v1/siem/targets/{id}   — Remove a target
POST /api/v1/siem/targets/{id}/test — Test target connectivity
POST /api/v1/siem/forward          — Forward an event to all targets
GET  /api/v1/siem/stats            — Forwarding statistics
GET  /api/v1/siem/events           — Recent forwarded events
POST /api/v1/siem/format/preview   — Preview event in CEF/LEEF/JSON
GET  /api/v1/siem/health           — Health check
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/siem", tags=["SIEM Integration"])


# ── Lazy engine import ───────────────────────────────────────────────

def _get_engine():
    from integrations.siem_engine import get_siem_engine
    return get_siem_engine()


# ── Request / Response Models ────────────────────────────────────────


class AddTargetRequest(BaseModel):
    name: str = Field(..., description="Human-readable target name")
    transport: str = Field(..., description="syslog_tcp, syslog_udp, splunk_hec, webhook")
    output_format: str = Field(default="cef", description="cef, leef, json")
    host: str = Field(default="localhost", description="Target host (syslog)")
    port: int = Field(default=514, description="Target port (syslog)")
    url: str = Field(default="", description="URL (Splunk HEC / webhook)")
    token: str = Field(default="", description="Auth token (Splunk HEC / webhook)")
    index: str = Field(default="fixops", description="Splunk index")
    source: str = Field(default="aldeci-ctem", description="Source identifier")
    sourcetype: str = Field(default="aldeci:security", description="Sourcetype")
    enabled: bool = Field(default=True)
    event_filters: List[str] = Field(default_factory=list, description="Event types to forward (empty=all)")


class ForwardEventRequest(BaseModel):
    event_type: str = Field(..., description="Event type identifier")
    severity: str = Field(default="info", description="critical, high, medium, low, info")
    action: str = Field(default="", description="Action taken")
    outcome: str = Field(default="", description="Outcome of the action")
    message: str = Field(default="", description="Human-readable message")
    src_ip: str = Field(default="")
    dst_ip: str = Field(default="")
    user_id: str = Field(default="")
    app_id: str = Field(default="")
    finding_id: str = Field(default="")
    cve_id: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FormatPreviewRequest(BaseModel):
    event_type: str = Field(default="scan.completed")
    severity: str = Field(default="medium")
    message: str = Field(default="Vulnerability scan completed with 5 findings")
    format: str = Field(default="cef", description="cef, leef, json")


# ── Endpoints ────────────────────────────────────────────────────────


@router.post("/targets")
async def add_target(request: AddTargetRequest):
    """Add a new SIEM forwarding target."""
    from integrations.siem_engine import SIEMTarget, SIEMTransport, SIEMOutputFormat

    try:
        transport = SIEMTransport(request.transport)
    except ValueError:
        raise HTTPException(400, f"Invalid transport: {request.transport}. Use: syslog_tcp, syslog_udp, splunk_hec, webhook")

    try:
        output_format = SIEMOutputFormat(request.output_format)
    except ValueError:
        raise HTTPException(400, f"Invalid format: {request.output_format}. Use: cef, leef, json")

    target = SIEMTarget(
        name=request.name,
        transport=transport,
        output_format=output_format,
        host=request.host,
        port=request.port,
        url=request.url,
        token=request.token,
        index=request.index,
        source=request.source,
        sourcetype=request.sourcetype,
        enabled=request.enabled,
        event_filters=request.event_filters,
    )

    engine = _get_engine()
    result = engine.add_target(target)
    return {"status": "created", "target": result.to_dict()}


@router.get("/targets")
async def list_targets():
    """List all configured SIEM targets."""
    engine = _get_engine()
    targets = engine.list_targets()
    return {"targets": [t.to_dict() for t in targets], "count": len(targets)}


@router.get("/targets/{target_id}")
async def get_target(target_id: str):
    """Get details of a specific SIEM target."""
    engine = _get_engine()
    target = engine.get_target(target_id)
    if not target:
        raise HTTPException(404, f"Target not found: {target_id}")
    return target.to_dict()


@router.delete("/targets/{target_id}")
async def remove_target(target_id: str):
    """Remove a SIEM forwarding target."""
    engine = _get_engine()
    if not engine.remove_target(target_id):
        raise HTTPException(404, f"Target not found: {target_id}")
    return {"status": "deleted", "target_id": target_id}


@router.post("/targets/{target_id}/test")
async def test_target(target_id: str):
    """Test connectivity to a SIEM target by sending a test event."""
    engine = _get_engine()
    if not engine.get_target(target_id):
        raise HTTPException(404, f"Target not found: {target_id}")
    result = engine.test_target(target_id)
    return {
        "status": "success" if result.success else "failed",
        "result": result.to_dict(),
    }


@router.post("/forward")
async def forward_event(request: ForwardEventRequest):
    """Forward a security event to all enabled SIEM targets."""
    from integrations.siem_engine import SIEMEvent, SIEMSeverity

    try:
        severity = SIEMSeverity(request.severity)
    except ValueError:
        severity = SIEMSeverity.INFO

    event = SIEMEvent(
        event_type=request.event_type,
        severity=severity,
        action=request.action,
        outcome=request.outcome,
        message=request.message,
        src_ip=request.src_ip,
        dst_ip=request.dst_ip,
        user_id=request.user_id,
        app_id=request.app_id,
        finding_id=request.finding_id,
        cve_id=request.cve_id,
        metadata=request.metadata,
    )

    engine = _get_engine()
    results = engine.forward_event(event)
    return {
        "event_id": event.event_id,
        "targets_attempted": len(results),
        "targets_succeeded": sum(1 for r in results if r.success),
        "results": [r.to_dict() for r in results],
    }


@router.get("/stats")
async def siem_stats():
    """Get SIEM forwarding statistics."""
    engine = _get_engine()
    return engine.get_stats()


@router.get("/events")
async def recent_events(limit: int = Query(default=50, ge=1, le=500)):
    """Get recently forwarded events."""
    engine = _get_engine()
    events = engine.get_recent_events(limit)
    return {"events": events, "count": len(events)}


@router.post("/format/preview")
async def format_preview(request: FormatPreviewRequest):
    """Preview how an event would look in different SIEM formats."""
    from integrations.siem_engine import (
        SIEMEvent, SIEMSeverity, SIEMOutputFormat,
        format_cef, format_leef, format_json,
    )

    try:
        severity = SIEMSeverity(request.severity)
    except ValueError:
        severity = SIEMSeverity.INFO

    event = SIEMEvent(
        event_type=request.event_type,
        severity=severity,
        message=request.message,
        action=request.event_type,
    )

    if request.format == "all":
        return {
            "cef": format_cef(event),
            "leef": format_leef(event),
            "json": format_json(event),
        }

    formatters = {"cef": format_cef, "leef": format_leef, "json": format_json}
    formatter = formatters.get(request.format, format_json)
    return {"format": request.format, "output": formatter(event)}


@router.get("/health")
async def siem_health():
    """Health check for SIEM integration engine."""
    engine = _get_engine()
    stats = engine.get_stats()
    return {
        "status": "healthy",
        "engine": "SIEMEngine",
        "version": "1.0.0",
        "active_targets": stats["active_targets"],
        "total_targets": stats["total_targets"],
        "capabilities": [
            "syslog_tcp", "syslog_udp", "splunk_hec", "webhook",
            "cef_format", "leef_format", "json_format",
            "event_filtering", "connectivity_testing",
        ],
    }

