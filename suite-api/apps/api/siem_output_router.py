"""SIEM Output Router — ALDECI.

Endpoints (all under /api/v1/siem-output):

  POST /configure              — configure a SIEM output target (Splunk HEC / Sentinel)
  GET  /targets                — list configured SIEM targets
  GET  /targets/{target_id}    — get a single target
  PUT  /targets/{target_id}/status — update target status (active/inactive)
  DELETE /targets/{target_id}  — delete a target
  GET  /status                 — connection health for all targets
  GET  /status/{target_id}     — connection health for one target
  POST /test                   — send test event to a target
  POST /test/{target_id}       — send test event to specific target
  GET  /stats                  — delivery statistics (all targets)
  GET  /stats/{target_id}      — delivery statistics for one target
  GET  /history/{target_id}    — delivery history for one target

Auth: api_key_auth injected via Depends.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, Optional

from core.siem_output_engine import SIEMOutputEngine
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/siem-output", tags=["siem-output"])

# Lazy singleton
_engine: Optional[SIEMOutputEngine] = None


def _get_engine() -> SIEMOutputEngine:
    global _engine
    if _engine is None:
        _engine = SIEMOutputEngine()
    return _engine


def _api_key_auth() -> None:  # noqa: D401
    """Placeholder — replaced by app-level dependency injection."""


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SIEMTargetConfigure(BaseModel):
    org_id: str = "default"
    name: str
    siem_type: str = Field(
        ..., description="splunk_hec | sentinel | generic"
    )
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Connector-specific config (url, token, tenant_id, etc.)",
    )


class SIEMTargetStatusUpdate(BaseModel):
    status: str = Field(..., description="active | inactive | error")


class SIEMTestRequest(BaseModel):
    org_id: str = "default"
    target_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/configure")
def configure_siem_target(body: SIEMTargetConfigure):
    """Configure a new SIEM output target (Splunk HEC or Microsoft Sentinel)."""
    engine = _get_engine()
    try:
        result = engine.configure_target(
            org_id=body.org_id,
            name=body.name,
            siem_type=body.siem_type,
            config=body.config,
        )
        return {"status": "configured", "target": result}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/targets")
def list_targets(org_id: str = Query("default")):
    """List all configured SIEM output targets."""
    engine = _get_engine()
    targets = engine.get_targets(org_id)
    return {"targets": targets, "count": len(targets)}


@router.get("/targets/{target_id}")
def get_target(target_id: str, org_id: str = Query("default")):
    """Get a single SIEM output target by ID."""
    engine = _get_engine()
    target = engine.get_target(org_id, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.put("/targets/{target_id}/status")
def update_target_status(
    target_id: str,
    body: SIEMTargetStatusUpdate,
    org_id: str = Query("default"),
):
    """Update a SIEM target's status (active/inactive/error)."""
    engine = _get_engine()
    try:
        result = engine.update_target_status(org_id, target_id, body.status)
        if not result:
            raise HTTPException(status_code=404, detail="Target not found")
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/targets/{target_id}")
def delete_target(target_id: str, org_id: str = Query("default")):
    """Delete a SIEM output target."""
    engine = _get_engine()
    deleted = engine.delete_target(org_id, target_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"status": "deleted", "target_id": target_id}


@router.get("/status")
def get_all_status(org_id: str = Query("default")):
    """Get connection health for all SIEM targets."""
    engine = _get_engine()
    targets = engine.get_targets(org_id)

    statuses = []
    for t in targets:
        health = _check_connector_health(t)
        statuses.append({
            "target_id": t["target_id"],
            "name": t["name"],
            "siem_type": t["siem_type"],
            "status": t["status"],
            "health": health,
        })

    return {"targets": statuses, "count": len(statuses)}


@router.get("/status/{target_id}")
def get_target_status(target_id: str, org_id: str = Query("default")):
    """Get connection health for a specific SIEM target."""
    engine = _get_engine()
    target = engine.get_target(org_id, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    health = _check_connector_health(target)
    return {
        "target_id": target["target_id"],
        "name": target["name"],
        "siem_type": target["siem_type"],
        "status": target["status"],
        "health": health,
    }


@router.post("/test")
def send_test_event(body: SIEMTestRequest):
    """Send a test event to a SIEM target to verify connectivity."""
    engine = _get_engine()

    if body.target_id:
        target = engine.get_target(body.org_id, body.target_id)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        targets = [target]
    else:
        targets = engine.get_targets(body.org_id)
        targets = [t for t in targets if t["status"] == "active"]

    if not targets:
        raise HTTPException(status_code=404, detail="No active SIEM targets configured")

    results = []
    for t in targets:
        result = _send_test_to_connector(t)
        # Record the delivery attempt
        engine.record_delivery(
            org_id=body.org_id,
            target_id=t["target_id"],
            batch_size=1,
            events_sent=1 if result.get("success") else 0,
            events_failed=0 if result.get("success") else 1,
            success=result.get("success", False),
            status_code=result.get("status_code", 0),
            error=result.get("error", ""),
            duration_ms=result.get("duration_ms", 0.0),
        )
        results.append({
            "target_id": t["target_id"],
            "name": t["name"],
            "siem_type": t["siem_type"],
            **result,
        })

    return {"test_results": results}


@router.post("/test/{target_id}")
def send_test_event_to_target(target_id: str, org_id: str = Query("default")):
    """Send a test event to a specific SIEM target."""
    engine = _get_engine()
    target = engine.get_target(org_id, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    result = _send_test_to_connector(target)
    engine.record_delivery(
        org_id=org_id,
        target_id=target_id,
        batch_size=1,
        events_sent=1 if result.get("success") else 0,
        events_failed=0 if result.get("success") else 1,
        success=result.get("success", False),
        status_code=result.get("status_code", 0),
        error=result.get("error", ""),
        duration_ms=result.get("duration_ms", 0.0),
    )

    return {
        "target_id": target_id,
        "name": target["name"],
        "siem_type": target["siem_type"],
        **result,
    }


@router.get("/stats")
def get_delivery_stats(
    org_id: str = Query("default"),
    target_id: Optional[str] = Query(None),
):
    """Get delivery statistics for SIEM output targets."""
    engine = _get_engine()
    stats = engine.get_stats(org_id, target_id)
    return stats


@router.get("/stats/{target_id}")
def get_target_delivery_stats(target_id: str, org_id: str = Query("default")):
    """Get delivery statistics for a specific SIEM target."""
    engine = _get_engine()
    stats = engine.get_stats(org_id, target_id)
    return stats


@router.get("/history/{target_id}")
def get_delivery_history(
    target_id: str,
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
):
    """Get delivery history for a specific SIEM target."""
    engine = _get_engine()
    history = engine.get_delivery_history(org_id, target_id, limit)
    return {"history": history, "count": len(history)}


@router.get(
    "/stream",
    summary="SSE stream of SIEM delivery audit log",
    response_class=StreamingResponse,
)
async def stream_audit_log(
    org_id: str = Query("default"),
    target_id: Optional[str] = Query(None, description="Filter to one target"),
    poll_interval: float = Query(5.0, ge=1.0, le=60.0, description="Polling interval in seconds"),
    last_seen_id: Optional[str] = Query(None, description="Resume: only emit deliveries newer than this delivery_id"),
) -> StreamingResponse:
    """Stream SIEM delivery audit events as Server-Sent Events.

    Emits one SSE ``delivery`` event per new row in siem_deliveries.
    Heartbeat comment (`: ping`) every poll_interval seconds when idle.
    Connect with ``Accept: text/event-stream``.

    SSE format::

        id: <delivery_id>
        event: delivery
        data: {"delivery_id": "...", "target_id": "...", "success": true, ...}

    """
    engine = _get_engine()

    async def _generator() -> AsyncGenerator[str, None]:
        seen_id = last_seen_id
        while True:
            rows = engine.get_delivery_history(
                org_id=org_id,
                target_id=target_id or "",
                limit=50,
                after_id=seen_id,
            )
            if rows:
                for row in reversed(rows):  # chronological order
                    delivery_id = row.get("delivery_id", "")
                    payload = json.dumps(row, default=str)
                    yield f"id: {delivery_id}\nevent: delivery\ndata: {payload}\n\n"
                    seen_id = delivery_id
            else:
                yield ": ping\n\n"
            await asyncio.sleep(poll_interval)

    return StreamingResponse(
        _generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Connector helpers (instantiate connectors from stored config)
# ---------------------------------------------------------------------------


def _check_connector_health(target: Dict[str, Any]) -> Dict[str, Any]:
    """Check health for a SIEM connector based on its type."""
    siem_type = target.get("siem_type", "")
    config = target.get("config", {})

    try:
        if siem_type == "splunk_hec":
            from siem_connectors.splunk_hec_connector import (
                SplunkHECConfig,
                SplunkHECConnector,
            )

            hec_config = SplunkHECConfig(
                url=config.get("url", ""),
                token=config.get("token", ""),
                index=config.get("index", "aldeci"),
                verify_ssl=config.get("verify_ssl", True),
            )
            connector = SplunkHECConnector(hec_config)
            return connector.check_health()

        elif siem_type == "sentinel":
            from siem_connectors.sentinel_connector import (
                SentinelConfig,
                SentinelConnector,
            )

            sentinel_config = SentinelConfig(
                tenant_id=config.get("tenant_id", ""),
                client_id=config.get("client_id", ""),
                client_secret=config.get("client_secret", ""),
                dcr_endpoint=config.get("dcr_endpoint", ""),
                dcr_rule_id=config.get("dcr_rule_id", ""),
                stream_name=config.get("stream_name", "Custom-ALDECISecurityEvents_CL"),
            )
            connector = SentinelConnector(sentinel_config)
            return connector.check_health()

        else:
            return {"healthy": False, "error": f"Unknown siem_type: {siem_type}"}

    except ImportError as exc:
        return {"healthy": False, "error": f"Connector not available: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"healthy": False, "error": str(exc)}


def _send_test_to_connector(target: Dict[str, Any]) -> Dict[str, Any]:
    """Send a test event via the appropriate connector."""
    siem_type = target.get("siem_type", "")
    config = target.get("config", {})

    try:
        if siem_type == "splunk_hec":
            from siem_connectors.splunk_hec_connector import (
                SplunkHECConfig,
                SplunkHECConnector,
            )

            hec_config = SplunkHECConfig(
                url=config.get("url", ""),
                token=config.get("token", ""),
                index=config.get("index", "aldeci"),
                verify_ssl=config.get("verify_ssl", True),
            )
            connector = SplunkHECConnector(hec_config)
            result = connector.send_test_event()
            return result.to_dict()

        elif siem_type == "sentinel":
            from siem_connectors.sentinel_connector import (
                SentinelConfig,
                SentinelConnector,
            )

            sentinel_config = SentinelConfig(
                tenant_id=config.get("tenant_id", ""),
                client_id=config.get("client_id", ""),
                client_secret=config.get("client_secret", ""),
                dcr_endpoint=config.get("dcr_endpoint", ""),
                dcr_rule_id=config.get("dcr_rule_id", ""),
                stream_name=config.get("stream_name", "Custom-ALDECISecurityEvents_CL"),
            )
            connector = SentinelConnector(sentinel_config)
            result = connector.send_test_event()
            return result.to_dict()

        else:
            return {"success": False, "error": f"Unknown siem_type: {siem_type}"}

    except ImportError as exc:
        return {"success": False, "error": f"Connector not available: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}
