"""SSE (Server-Sent Events) streaming endpoints.

Provides real-time streaming for:
    - Pipeline progress
    - Scan status
    - Copilot responses
    - Live notifications / event bus

All endpoints use ``text/event-stream`` media type.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/stream", tags=["SSE Streaming"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _sse_encode(data: dict, event: str | None = None) -> str:
    """Format a dict as an SSE message."""
    lines = []
    if event:
        lines.append(f"event: {event}")
    lines.append(f"data: {json.dumps(data)}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Pipeline progress stream
# ---------------------------------------------------------------------------


@router.get("/pipeline/{run_id}")
async def stream_pipeline_progress(run_id: str):
    """Stream pipeline run progress as SSE events."""

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            from core.brain_pipeline import get_brain_pipeline

            pipeline = get_brain_pipeline()
        except ImportError:
            yield await _sse_encode({"error": "Pipeline not available"}, "error")
            return

        start = time.time()
        timeout = 300  # 5 min max

        while time.time() - start < timeout:
            try:
                status = (
                    pipeline.get_run_status(run_id)
                    if hasattr(pipeline, "get_run_status")
                    else None
                )
            except Exception:
                status = None

            if status is None:
                yield await _sse_encode(
                    {
                        "run_id": run_id,
                        "status": "unknown",
                        "message": "Run not found or pipeline unavailable",
                    },
                    "status",
                )
                return

            yield await _sse_encode(
                {
                    "run_id": run_id,
                    "status": status.get("status", "running"),
                    "current_stage": status.get("current_stage"),
                    "progress": status.get("progress", 0),
                    "stages_completed": status.get("stages_completed", 0),
                    "total_stages": status.get("total_stages", 12),
                    "elapsed_seconds": round(time.time() - start, 1),
                },
                "progress",
            )

            if status.get("status") in ("completed", "failed"):
                yield await _sse_encode(
                    {
                        "run_id": run_id,
                        "status": status["status"],
                        "result": status.get("result"),
                    },
                    "complete",
                )
                return

            await asyncio.sleep(0.5)

        yield await _sse_encode({"run_id": run_id, "status": "timeout"}, "error")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Event bus live stream
# ---------------------------------------------------------------------------


@router.get("/events")
async def stream_events(
    types: Optional[str] = Query(
        None, description="Comma-separated event types to filter"
    ),
):
    """Stream EventBus events in real-time via SSE."""

    async def event_generator() -> AsyncGenerator[str, None]:
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=256)
        filter_types = set(types.split(",")) if types else None

        async def _relay(event):
            etype = (
                event.event_type.value
                if hasattr(event.event_type, "value")
                else str(event.event_type)
            )
            if filter_types and etype not in filter_types:
                return
            try:
                queue.put_nowait(
                    {
                        "event_type": etype,
                        "source": event.source,
                        "data": event.data,
                        "org_id": getattr(event, "org_id", None),
                        "timestamp": getattr(event, "timestamp", None),
                    }
                )
            except asyncio.QueueFull:
                pass  # drop oldest-style: client too slow

        try:
            from core.event_bus import get_event_bus

            bus = get_event_bus()
            bus.subscribe_all(_relay)
        except ImportError:
            yield await _sse_encode({"error": "EventBus not available"}, "error")
            return

        # Keep-alive heartbeat interleaved with real events
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=15)
                yield await _sse_encode(msg, "event")
            except asyncio.TimeoutError:
                yield await _sse_encode({"type": "heartbeat"}, "heartbeat")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
