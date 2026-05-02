"""Queue management API — monitor depth, enqueue tasks, and drain the queue."""
from __future__ import annotations

from apps.api.auth_deps import api_key_auth
from core.redis_queue import RedisQueue
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/api/v1/queue",
    tags=["Queue"],
    dependencies=[Depends(api_key_auth)],
)

_queue: "RedisQueue | None" = None  # lazy-initialised on first request


def _get_queue() -> "RedisQueue":
    global _queue
    if _queue is None:
        _queue = RedisQueue()
    return _queue


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


@router.get("/status", response_model=QueueStatus, summary="Queue depth and backend info")
async def queue_status() -> QueueStatus:
    q = _get_queue()
    return QueueStatus(
        backend=q.backend,
        depth=q.depth(),
        workers=q.workers(),
    )


@router.post("/enqueue", response_model=EnqueueResponse, summary="Add a task to the queue")
async def enqueue_task(body: EnqueueRequest) -> EnqueueResponse:
    task = {"task_type": body.task_type, **body.payload}
    q = _get_queue()
    task_id = q.enqueue(task, priority=body.priority)
    return EnqueueResponse(task_id=task_id, priority=body.priority, backend=q.backend)


@router.get("/peek", response_model=PeekResponse, summary="Preview next tasks without removing")
async def peek_queue(limit: int = 10) -> PeekResponse:
    limit = max(1, min(100, limit))
    return PeekResponse(tasks=_get_queue().peek(limit=limit))


@router.delete("/clear", response_model=ClearResponse, summary="Clear all queued tasks")
async def clear_queue() -> ClearResponse:
    count = _get_queue().clear()
    return ClearResponse(cleared=count)
