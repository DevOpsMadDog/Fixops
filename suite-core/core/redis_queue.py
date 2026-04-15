"""Redis-backed task queue with in-memory fallback for horizontal scaling."""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import deque
from typing import Optional

import structlog

_logger = structlog.get_logger()

try:
    import redis as _redis_lib

    _REDIS_AVAILABLE = True
except ImportError:
    _redis_lib = None  # type: ignore[assignment]
    _REDIS_AVAILABLE = False


class RedisQueue:
    """Task queue backed by Redis when available, in-memory deque otherwise.

    Priority range: 1 (highest) to 10 (lowest).
    Each task is stored as a JSON blob with injected metadata fields:
      - task_id   : UUID string
      - priority  : int 1-10
      - enqueued_at : Unix timestamp (float)

    All queue keys are scoped by org_id to enforce multi-tenant isolation.
    Key pattern: {prefix}:{org_id}:{priority}
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        prefix: str = "aldeci:queue",
        org_id: str = "default",
    ) -> None:
        self._prefix = prefix
        self._org_id = org_id
        self._redis: Optional[object] = None  # redis.Redis instance or None
        # In-memory fallback: keyed by org_id to maintain isolation
        self._memory_queues: dict[str, deque[dict]] = {}
        self._lock = threading.Lock()

        if _REDIS_AVAILABLE:
            try:
                client = _redis_lib.Redis(  # type: ignore[union-attr]
                    host=host, port=port, db=db, socket_connect_timeout=1
                )
                client.ping()
                self._redis = client
                _logger.info("redis_queue.connected", host=host, port=port, db=db)
            except Exception as exc:
                _logger.warning(
                    "redis_queue.fallback_memory",
                    reason=str(exc),
                )
                self._redis = None
        else:
            _logger.info("redis_queue.redis_not_installed", backend="memory")

    def _queue_key(self, org_id: str, priority: int) -> str:
        """Build a tenant-scoped Redis key."""
        return f"{self._prefix}:{org_id}:{priority}"

    def _get_memory_queue(self, org_id: str) -> deque[dict]:
        """Return (creating if necessary) the in-memory deque for an org."""
        if org_id not in self._memory_queues:
            self._memory_queues[org_id] = deque()
        return self._memory_queues[org_id]

    @property
    def backend(self) -> str:
        """Return 'redis' or 'memory' depending on availability."""
        return "redis" if self._redis is not None else "memory"

    def enqueue(self, task: dict, priority: int = 5) -> str:
        """Add task to queue. Returns task_id. Priority 1=highest, 10=lowest.

        The org_id is read from the task dict if present; otherwise falls back
        to the org_id this queue was constructed with.
        """
        priority = max(1, min(10, priority))
        task_id = str(uuid.uuid4())
        # Resolve org_id: task payload wins, then queue-level default
        org_id = str(task.get("org_id") or self._org_id)
        payload = {
            **task,
            "task_id": task_id,
            "priority": priority,
            "enqueued_at": time.time(),
            "org_id": org_id,
        }
        serialized = json.dumps(payload)

        if self._redis is not None:
            key = self._queue_key(org_id, priority)
            self._redis.lpush(key, serialized)  # type: ignore[union-attr]
        else:
            with self._lock:
                q = self._get_memory_queue(org_id)
                q.append(payload)
                # Keep deque sorted: lowest priority number (highest urgency) first
                sorted_items = sorted(q, key=lambda t: t["priority"])
                q.clear()
                q.extend(sorted_items)

        _logger.debug(
            "redis_queue.enqueued", task_id=task_id, priority=priority, org_id=org_id
        )
        return task_id

    def dequeue(self) -> Optional[dict]:
        """Pop next highest-priority task for this queue's org_id. Returns None if empty."""
        org_id = self._org_id
        if self._redis is not None:
            for p in range(1, 11):
                key = self._queue_key(org_id, p)
                raw = self._redis.rpop(key)  # type: ignore[union-attr]
                if raw is not None:
                    return json.loads(raw)
            return None
        else:
            with self._lock:
                q = self._get_memory_queue(org_id)
                if not q:
                    return None
                return q.popleft()

    def depth(self) -> int:
        """Total tasks across all priority levels for this queue's org_id."""
        org_id = self._org_id
        if self._redis is not None:
            total = 0
            for p in range(1, 11):
                key = self._queue_key(org_id, p)
                total += self._redis.llen(key)  # type: ignore[union-attr]
            return total
        else:
            with self._lock:
                return len(self._get_memory_queue(org_id))

    def workers(self) -> int:
        """Number of active worker connections (Redis INFO clients, or 1 for memory)."""
        if self._redis is not None:
            try:
                info = self._redis.info("clients")  # type: ignore[union-attr]
                return int(info.get("connected_clients", 1))
            except Exception:
                return 1
        return 1

    def clear(self) -> int:
        """Clear all tasks for this queue's org_id. Returns count cleared."""
        org_id = self._org_id
        if self._redis is not None:
            count = 0
            for p in range(1, 11):
                key = self._queue_key(org_id, p)
                count += self._redis.llen(key)  # type: ignore[union-attr]
                self._redis.delete(key)  # type: ignore[union-attr]
            return count
        else:
            with self._lock:
                q = self._get_memory_queue(org_id)
                count = len(q)
                q.clear()
                return count

    def peek(self, limit: int = 10) -> list[dict]:
        """Preview next N tasks for this queue's org_id without removing them."""
        org_id = self._org_id
        if self._redis is not None:
            results: list[dict] = []
            for p in range(1, 11):
                if len(results) >= limit:
                    break
                key = self._queue_key(org_id, p)
                # LRANGE reads from right (oldest/next-to-pop) to left
                needed = limit - len(results)
                raw_items = self._redis.lrange(key, -needed, -1)  # type: ignore[union-attr]
                for raw in reversed(raw_items):
                    results.append(json.loads(raw))
                    if len(results) >= limit:
                        break
            return results
        else:
            with self._lock:
                q = self._get_memory_queue(org_id)
                return list(q)[:limit]
