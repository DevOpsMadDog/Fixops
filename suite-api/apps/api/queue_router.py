"""Queue management API endpoints.

Exposes the RedisQueue (with in-memory fallback) via REST so operators
can monitor depth, enqueue tasks programmatically, and drain/clear the
queue without direct Redis access.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth
from core.redis_queue import RedisQueue

router = APIRouter(
    prefix="/api/v1/queue",
    tags=["Queue"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Singleton queue instance (shared across all requests in one worker process)
# ---------------------------------------------------------------------------
_queue = RedisQueue()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class EnqueueRequest(BaseModel):
    task_type: str = Field(..., description="Category / type of task (e.g. 'scan', 'alert')")
    payload: dict = Field(default_factory=dict, description="Arbitrary task payload")
    priority: int = Field(default=5, ge=1, le=10, description="Priority 1=highest, 10=lowest")


class EnqueueResponse(BaseModel):
    task_id: str
    priority: int
    backend: str


class QueueStatus(BaseModel):
    backend: str
    depth: int
    workers: int


class PeekResponse(BaseModel):
    tasks: list[dict]


class ClearResponse(BaseModel):
    cleared: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=QueueStatus, summary="Queue depth and backend info")
async def queue_status() -> QueueStatus:
    """Return current backend type, queue depth, and connected worker count."""
    return QueueStatus(
        backend=_queue.backend,
        depth=_queue.depth(),
        workers=_queue.workers(),
    )


@router.post("/enqueue", response_model=EnqueueResponse, summary="Add a task to the queue")
async def enqueue_task(body: EnqueueRequest) -> EnqueueResponse:
    """Push a task onto the queue at the given priority level."""
    task = {"task_type": body.task_type, **body.payload}
    task_id = _queue.enqueue(task, priority=body.priority)
    return EnqueueResponse(task_id=task_id, priority=body.priority, backend=_queue.backend)


@router.get("/peek", response_model=PeekResponse, summary="Preview next tasks without removing")
async def peek_queue(limit: int = 10) -> PeekResponse:
    """Return up to *limit* next tasks without dequeuing them."""
    limit = max(1, min(100, limit))
    return PeekResponse(tasks=_queue.peek(limit=limit))


@router.delete("/clear", response_model=ClearResponse, summary="Clear all queued tasks")
async def clear_queue() -> ClearResponse:
    """Drain the entire queue. Returns count of tasks removed."""
    count = _queue.clear()
    return ClearResponse(cleared=count)
