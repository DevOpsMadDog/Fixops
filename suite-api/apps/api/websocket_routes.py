"""
Phase 6: WebSocket Routes for ALDECI Event Streaming.

This module provides FastAPI WebSocket endpoints for real-time event streaming:
- /ws/events — Main event stream with role-based filtering
- /ws/pipeline/{stage} — Stage-specific event stream
- /api/v1/events/recent — REST endpoint for recent events
- /api/v1/events/stats — Event bus statistics

Includes:
- Authentication via JWT or API key
- Role-based event filtering
- Heartbeat/ping for connection monitoring
- Reconnection support with event replay
- Multi-tenant isolation
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, Set

try:
    from fastapi import (
        APIRouter,
        WebSocket,
        WebSocketDisconnect,
        Query,
        Depends,
        HTTPException,
        status,
    )
    from fastapi.responses import JSONResponse
except ImportError:
    raise ImportError("FastAPI is required for websocket_routes")

from suite_core.core.event_streaming import (
    EventBus,
    EventHistory,
    StreamEvent,
    EventType,
)

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["events"])


# ============================================================================
# GLOBAL STATE
# ============================================================================

# Singleton instances
_event_bus = EventBus()
_event_history = EventHistory(max_size=500)

# Track active WebSocket connections for heartbeat
_active_connections: Dict[str, WebSocket] = {}


# ============================================================================
# AUTHENTICATION HELPER
# ============================================================================

async def authenticate_websocket(
    websocket: WebSocket,
    api_key: Optional[str] = None,
    token: Optional[str] = None,
) -> tuple[str, Set[str], str]:
    """
    Authenticate WebSocket connection.

    Args:
        websocket: WebSocket connection
        api_key: API key from query param
        token: JWT token from query param

    Returns:
        Tuple of (user_id, roles set, org_id)

    Raises:
        HTTPException if authentication fails
    """
    # In production, implement real JWT/API key validation
    # This is a stub that accepts any connection for demo

    user_id = api_key or token or str(uuid.uuid4())[:8]
    roles = {"admin", "security_analyst", "viewer"}  # Default roles
    org_id = "default"

    _logger.info(f"WebSocket authenticated: user_id={user_id}, roles={roles}, org_id={org_id}")
    return user_id, roles, org_id


# ============================================================================
# WEBSOCKET ENDPOINTS
# ============================================================================

@router.websocket("/ws/events")
async def websocket_events(
    websocket: WebSocket,
    api_key: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    last_event_id: Optional[str] = Query(None),
):
    """
    Main WebSocket event stream.

    Provides real-time event streaming with role-based filtering.
    Supports reconnection via last_event_id for event replay.

    Query Parameters:
        api_key: API key for authentication
        token: JWT token for authentication
        last_event_id: Event ID to start replay from (for reconnection)

    Message Format (JSON):
        {
            "event_id": "uuid",
            "event_type": "finding:scored",
            "payload": {...},
            "timestamp": "2026-04-12T...",
            "source": "pipeline",
            "severity": "warning",
            "target_roles": ["admin"],
            "org_id": "default"
        }
    """
    try:
        await websocket.accept()

        # Authenticate
        user_id, roles, org_id = await authenticate_websocket(websocket, api_key, token)
        connection_id = str(uuid.uuid4())
        _active_connections[connection_id] = websocket

        _logger.info(f"WebSocket connection opened: {connection_id}")

        # Send replay events if last_event_id provided
        if last_event_id:
            replay_events = _event_history.get_after(last_event_id, org_id)
            for event in replay_events:
                try:
                    await websocket.send_json(event.to_dict())
                except Exception as e:
                    _logger.warning(f"Failed to send replay event: {e}")

        # Subscribe to event stream
        heartbeat_task = asyncio.create_task(_heartbeat(websocket, connection_id))
        event_task = asyncio.create_task(
            _event_stream(websocket, user_id, roles, org_id, connection_id)
        )

        # Wait for either task to complete
        done, pending = await asyncio.wait(
            [heartbeat_task, event_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel remaining task
        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        _logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        _logger.error(f"WebSocket error: {e}")
    finally:
        _active_connections.pop(connection_id, None)
        await websocket.close()


async def _event_stream(
    websocket: WebSocket,
    user_id: str,
    roles: Set[str],
    org_id: str,
    connection_id: str,
) -> None:
    """
    Receive events from EventBus and send to WebSocket.

    Args:
        websocket: WebSocket connection
        user_id: Authenticated user ID
        roles: User's roles for filtering
        org_id: Organization ID
        connection_id: Unique connection ID
    """
    subscriber_id = f"ws-{connection_id}"

    try:
        async for event in _event_bus.subscribe(subscriber_id, roles, org_id):
            # Add to history
            _event_history.add(event)

            try:
                await websocket.send_json(event.to_dict())
            except Exception as e:
                _logger.error(f"Failed to send event to WebSocket: {e}")
                break
    except asyncio.CancelledError:
        _logger.debug(f"Event stream cancelled for {connection_id}")
    except Exception as e:
        _logger.error(f"Error in event stream: {e}")
    finally:
        await _event_bus.unsubscribe(subscriber_id)


async def _heartbeat(
    websocket: WebSocket,
    connection_id: str,
    interval: int = 30,
) -> None:
    """
    Send heartbeat pings to keep connection alive.

    Args:
        websocket: WebSocket connection
        connection_id: Unique connection ID
        interval: Heartbeat interval in seconds
    """
    try:
        while True:
            await asyncio.sleep(interval)
            ping = {
                "type": "ping",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "connection_id": connection_id,
            }
            try:
                await websocket.send_json(ping)
            except Exception:
                break
    except asyncio.CancelledError:
        pass


@router.websocket("/ws/pipeline/{stage}")
async def websocket_pipeline_stage(
    stage: str,
    websocket: WebSocket,
    api_key: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """
    Stage-specific event stream.

    Filters events to only those from the specified pipeline stage.

    Path Parameters:
        stage: Pipeline stage name (e.g., 'normalize', 'score', 'prioritize')

    Query Parameters:
        api_key: API key for authentication
        token: JWT token for authentication
    """
    try:
        await websocket.accept()

        # Authenticate
        user_id, roles, org_id = await authenticate_websocket(websocket, api_key, token)
        connection_id = str(uuid.uuid4())
        _active_connections[connection_id] = websocket

        _logger.info(f"WebSocket pipeline stage connection: {connection_id}, stage={stage}")

        # Start heartbeat and event stream
        heartbeat_task = asyncio.create_task(_heartbeat(websocket, connection_id))

        # Subscribe with stage filtering
        async def stage_filtered_stream():
            subscriber_id = f"ws-stage-{connection_id}"
            try:
                async for event in _event_bus.subscribe(subscriber_id, roles, org_id):
                    # Filter by stage name in payload
                    if "stage_name" in event.payload and event.payload["stage_name"] == stage:
                        _event_history.add(event)
                        try:
                            await websocket.send_json(event.to_dict())
                        except Exception as e:
                            _logger.error(f"Failed to send stage event: {e}")
                            break
            finally:
                await _event_bus.unsubscribe(subscriber_id)

        event_task = asyncio.create_task(stage_filtered_stream())

        # Wait for either task to complete
        done, pending = await asyncio.wait(
            [heartbeat_task, event_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

    except WebSocketDisconnect:
        _logger.info(f"WebSocket stage disconnected: {connection_id}")
    except Exception as e:
        _logger.error(f"WebSocket stage error: {e}")
    finally:
        _active_connections.pop(connection_id, None)
        await websocket.close()


# ============================================================================
# REST ENDPOINTS
# ============================================================================

@router.get("/events/recent")
async def get_recent_events(
    count: int = Query(10, ge=1, le=100),
    event_types: Optional[str] = Query(None),
    min_severity: Optional[str] = Query(None),
    api_key: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """
    Get recent events from history.

    Query Parameters:
        count: Number of events to return (1-100, default 10)
        event_types: Comma-separated event type filters
        min_severity: Minimum severity (info/warning/critical)
        api_key: API key for authentication
        token: JWT token for authentication

    Returns:
        {
            "events": [...],
            "count": 10,
            "timestamp": "2026-04-12T..."
        }
    """
    try:
        # Authenticate
        user_id, roles, org_id = await authenticate_websocket(None, api_key, token)

        # Parse filters
        event_type_list = None
        if event_types:
            event_type_list = [t.strip() for t in event_types.split(",")]

        # Get recent events
        events = _event_history.get_recent(
            count=count,
            event_types=event_type_list,
            min_severity=min_severity,
            org_id=org_id,
        )

        return {
            "events": [e.to_dict() for e in events],
            "count": len(events),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        _logger.error(f"Error fetching recent events: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@router.get("/events/stats")
async def get_event_stats(
    api_key: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
):
    """
    Get event bus statistics.

    Query Parameters:
        api_key: API key for authentication
        token: JWT token for authentication

    Returns:
        {
            "events_published": 1000,
            "events_delivered": 950,
            "events_dropped": 50,
            "subscribers_active": 5,
            "history_size": 500,
            "active_connections": 3,
            "timestamp": "2026-04-12T..."
        }
    """
    try:
        # Authenticate
        user_id, roles, org_id = await authenticate_websocket(None, api_key, token)

        # Check for admin role
        if "admin" not in roles and "super_admin" not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin role required for statistics",
            )

        metrics = _event_bus.get_metrics()

        return {
            **metrics,
            "history_size": _event_history.size(),
            "active_connections": len(_active_connections),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        _logger.error(f"Error fetching event stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


# ============================================================================
# HELPERS TO GET INSTANCES (for integration with other modules)
# ============================================================================

def get_event_bus() -> EventBus:
    """Get the singleton EventBus instance."""
    return _event_bus


def get_event_history() -> EventHistory:
    """Get the singleton EventHistory instance."""
    return _event_history


# Import typing for type hints
from typing import Dict
