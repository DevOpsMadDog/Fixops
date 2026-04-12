"""
ALdeci Queue Status REST API.

Exposes read-only visibility into the Redis task queue used for
horizontal pipeline scaling.

Endpoints:
    GET /api/v1/queue/status   — queue depths + worker count + rates
    GET /api/v1/queue/workers  — list active workers with last heartbeat
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/queue",
    tags=["Queue"],
    dependencies=[Depends(api_key_auth)],
)

_DEFAULT_QUEUE = "aldeci:pipeline:default"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_qm():
    """Lazy-import to avoid circular imports at module load time."""
    from core.queue_manager import get_queue_manager

    return get_queue_manager()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", summary="Queue depths, worker count, and processing rates")
async def get_queue_status() -> Dict[str, Any]:
    """Return current queue depth and worker count.

    Returns:
        JSON object with:
        - ``queue_depth``: number of items waiting in the default pipeline queue.
        - ``worker_count``: number of workers with a live heartbeat.
        - ``queue_name``: the queue being monitored.
        - ``backend``: ``"redis"`` or ``"local"`` — which backend is active.
        - ``timestamp``: Unix epoch of the snapshot.
    """
    qm = _get_qm()
    from core.queue_manager import RedisQueueManager

    backend = "redis" if isinstance(qm, RedisQueueManager) else "local"
    depth = qm.get_queue_depth(_DEFAULT_QUEUE)
    worker_count = qm.get_worker_count()

    return {
        "queue_name": _DEFAULT_QUEUE,
        "queue_depth": depth,
        "worker_count": worker_count,
        "backend": backend,
        "timestamp": time.time(),
    }


@router.get("/workers", summary="List active workers with last heartbeat")
async def get_workers() -> Dict[str, Any]:
    """Return a list of currently active pipeline workers.

    Workers are identified by their heartbeat keys in Redis (or in-process
    registry when using the local fallback).

    Returns:
        JSON object with:
        - ``workers``: list of worker dicts (``worker_id``, ``registered_at``,
          ``last_heartbeat``).
        - ``count``: total number of active workers.
        - ``timestamp``: Unix epoch of the snapshot.
    """
    qm = _get_qm()
    workers: List[Dict[str, Any]] = qm.list_workers()

    return {
        "workers": workers,
        "count": len(workers),
        "timestamp": time.time(),
    }
