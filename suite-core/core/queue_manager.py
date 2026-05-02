"""
ALdeci Queue Manager — Redis-backed task queue with local fallback.

Provides a uniform API for enqueueing pipeline steps, dequeuing work,
publishing results via pub/sub, and monitoring worker health.

Usage:
    from core.queue_manager import get_queue_manager

    qm = get_queue_manager()
    qm.enqueue_step("run-123", "enrich_threats", {"findings": [...]})
    item = qm.dequeue_step("default", timeout=5)
    qm.publish_result("run-123", "enrich_threats", {"status": "ok"})

Graceful fallback:
    When Redis is unavailable, ``get_queue_manager()`` returns a
    ``LocalQueueManager`` that uses in-process ``queue.Queue`` objects.
    The API is identical — callers never need to check which backend is active.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import json
import logging
import queue
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_DEFAULT_QUEUE = "aldeci:pipeline:default"
_RESULT_CHANNEL_PREFIX = "aldeci:pipeline:results:"
_WORKER_HEARTBEAT_PREFIX = "aldeci:pipeline:worker:"
_WORKER_HEARTBEAT_TTL = 30  # seconds
_STEP_KEY_PREFIX = "aldeci:pipeline:step:"


# ---------------------------------------------------------------------------
# Abstract base — defines the shared API
# ---------------------------------------------------------------------------
class BaseQueueManager(ABC):
    """Abstract queue manager interface."""

    @abstractmethod
    def enqueue_step(self, run_id: str, step_name: str, payload: Dict[str, Any]) -> str:
        """Push a pipeline step onto the queue.

        Args:
            run_id: Unique pipeline run identifier.
            step_name: Name of the pipeline step (e.g. ``"enrich_threats"``).
            payload: Serialisable dict passed to the worker.

        Returns:
            A unique task ID for the enqueued item.
        """

    @abstractmethod
    def dequeue_step(
        self, queue_name: str = _DEFAULT_QUEUE, timeout: int = 5
    ) -> Optional[Dict[str, Any]]:
        """Blocking pop a step from the queue.

        Args:
            queue_name: Queue to read from (defaults to the global pipeline queue).
            timeout: Seconds to block waiting for an item.  0 = non-blocking.

        Returns:
            The task dict, or ``None`` if the queue was empty within *timeout*.
        """

    @abstractmethod
    def publish_result(self, run_id: str, step_name: str, result: Dict[str, Any]) -> None:
        """Publish a step result so subscribers can react.

        Args:
            run_id: Pipeline run identifier (must match the one used in
                ``enqueue_step``).
            step_name: Name of the completed step.
            result: Serialisable result payload.
        """

    @abstractmethod
    def subscribe_results(self, run_id: str) -> "ResultSubscription":
        """Return a subscription object that yields results for *run_id*.

        The returned object implements an iterator that yields ``Dict[str, Any]``
        result payloads until closed.
        """

    @abstractmethod
    def get_queue_depth(self, queue_name: str = _DEFAULT_QUEUE) -> int:
        """Return the number of items currently waiting in *queue_name*."""

    @abstractmethod
    def get_worker_count(self) -> int:
        """Return the number of workers with a live heartbeat key."""

    @abstractmethod
    def register_worker(self, worker_id: str) -> None:
        """Upsert the heartbeat key for *worker_id* (call periodically)."""

    @abstractmethod
    def deregister_worker(self, worker_id: str) -> None:
        """Remove the heartbeat key for *worker_id*."""

    @abstractmethod
    def list_workers(self) -> List[Dict[str, Any]]:
        """Return metadata for all active workers."""


# ---------------------------------------------------------------------------
# Subscription helpers
# ---------------------------------------------------------------------------
class ResultSubscription(ABC):
    """Iterable subscription that yields step results for a single run."""

    @abstractmethod
    def __iter__(self):
        ...

    @abstractmethod
    def close(self) -> None:
        """Unsubscribe and release resources."""


# ---------------------------------------------------------------------------
# Redis implementation
# ---------------------------------------------------------------------------
class RedisQueueManager(BaseQueueManager):
    """Redis-backed queue manager using connection pooling."""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0) -> None:
        import redis as _redis  # type: ignore[import]

        self._pool = _redis.ConnectionPool(host=host, port=port, db=db, decode_responses=True)
        self._redis = _redis.Redis(connection_pool=self._pool)
        self._pubsub_clients: List[Any] = []
        logger.info("RedisQueueManager connected to %s:%d db=%d", host, port, db)

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _make_task(run_id: str, step_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": str(uuid.uuid4()),
            "run_id": run_id,
            "step_name": step_name,
            "payload": payload,
            "enqueued_at": time.time(),
        }

    @staticmethod
    def _channel(run_id: str) -> str:
        return f"{_RESULT_CHANNEL_PREFIX}{run_id}"

    @staticmethod
    def _worker_key(worker_id: str) -> str:
        return f"{_WORKER_HEARTBEAT_PREFIX}{worker_id}"

    # -- BaseQueueManager implementation ------------------------------------

    def enqueue_step(self, run_id: str, step_name: str, payload: Dict[str, Any]) -> str:
        task = self._make_task(run_id, step_name, payload)
        serialised = json.dumps(task)
        self._redis.rpush(_DEFAULT_QUEUE, serialised)
        logger.debug("enqueue_step run=%s step=%s task=%s", run_id, step_name, task["task_id"])
        return task["task_id"]

    def dequeue_step(
        self, queue_name: str = _DEFAULT_QUEUE, timeout: int = 5
    ) -> Optional[Dict[str, Any]]:
        result = self._redis.blpop(queue_name, timeout=timeout)
        if result is None:
            return None
        _, raw = result
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("dequeue_step: failed to deserialise item: %s", exc)
            return None

    def publish_result(self, run_id: str, step_name: str, result: Dict[str, Any]) -> None:
        message = json.dumps(
            {
                "run_id": run_id,
                "step_name": step_name,
                "result": result,
                "published_at": time.time(),
            }
        )
        self._redis.publish(self._channel(run_id), message)
        logger.debug("publish_result run=%s step=%s", run_id, step_name)

    def subscribe_results(self, run_id: str) -> "RedisResultSubscription":

        ps = self._redis.pubsub()
        ps.subscribe(self._channel(run_id))
        sub = RedisResultSubscription(ps, run_id)
        self._pubsub_clients.append(sub)
        return sub

    def get_queue_depth(self, queue_name: str = _DEFAULT_QUEUE) -> int:
        try:
            return int(self._redis.llen(queue_name))
        except Exception:
            return 0

    def get_worker_count(self) -> int:
        pattern = f"{_WORKER_HEARTBEAT_PREFIX}*"
        return len(self._redis.keys(pattern))

    def register_worker(self, worker_id: str) -> None:
        key = self._worker_key(worker_id)
        self._redis.setex(key, _WORKER_HEARTBEAT_TTL, json.dumps({
            "worker_id": worker_id,
            "registered_at": time.time(),
            "last_heartbeat": time.time(),
        }))
        logger.debug("register_worker worker_id=%s", worker_id)

    def deregister_worker(self, worker_id: str) -> None:
        self._redis.delete(self._worker_key(worker_id))
        logger.debug("deregister_worker worker_id=%s", worker_id)

    def list_workers(self) -> List[Dict[str, Any]]:
        pattern = f"{_WORKER_HEARTBEAT_PREFIX}*"
        workers = []
        for key in self._redis.keys(pattern):
            raw = self._redis.get(key)
            if raw:
                try:
                    workers.append(json.loads(raw))
                except (json.JSONDecodeError, TypeError):
                    pass
        return workers


class RedisResultSubscription(ResultSubscription):
    """Wraps a Redis PubSub channel for a single pipeline run."""

    def __init__(self, pubsub: Any, run_id: str) -> None:
        self._pubsub = pubsub
        self._run_id = run_id
        self._closed = False

    def __iter__(self):
        while not self._closed:
            msg = self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg.get("type") == "message":
                try:
                    yield json.loads(msg["data"])
                except (json.JSONDecodeError, TypeError):
                    pass

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._pubsub.unsubscribe()
                self._pubsub.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Local (in-process) fallback implementation
# ---------------------------------------------------------------------------
class LocalQueueManager(BaseQueueManager):
    """In-process queue manager using ``queue.Queue``.

    Identical API to ``RedisQueueManager`` but runs entirely in memory.
    No horizontal scaling — suitable for development or when Redis is absent.
    """

    def __init__(self) -> None:
        self._queues: Dict[str, queue.Queue] = {}
        self._result_queues: Dict[str, queue.Queue] = {}  # run_id -> Queue
        self._workers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        logger.info("LocalQueueManager started (no Redis — in-process only)")

    # -- Internal helpers ---------------------------------------------------

    def _get_queue(self, queue_name: str) -> queue.Queue:
        with self._lock:
            if queue_name not in self._queues:
                self._queues[queue_name] = queue.Queue()
            return self._queues[queue_name]

    def _get_result_queue(self, run_id: str) -> queue.Queue:
        with self._lock:
            if run_id not in self._result_queues:
                self._result_queues[run_id] = queue.Queue()
            return self._result_queues[run_id]

    @staticmethod
    def _make_task(run_id: str, step_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "task_id": str(uuid.uuid4()),
            "run_id": run_id,
            "step_name": step_name,
            "payload": payload,
            "enqueued_at": time.time(),
        }

    # -- BaseQueueManager implementation ------------------------------------

    def enqueue_step(self, run_id: str, step_name: str, payload: Dict[str, Any]) -> str:
        task = self._make_task(run_id, step_name, payload)
        self._get_queue(_DEFAULT_QUEUE).put(task)
        logger.debug("local enqueue_step run=%s step=%s task=%s", run_id, step_name, task["task_id"])
        return task["task_id"]

    def dequeue_step(
        self, queue_name: str = _DEFAULT_QUEUE, timeout: int = 5
    ) -> Optional[Dict[str, Any]]:
        q = self._get_queue(queue_name)
        try:
            return q.get(block=timeout > 0, timeout=timeout if timeout > 0 else None)
        except queue.Empty:
            return None

    def publish_result(self, run_id: str, step_name: str, result: Dict[str, Any]) -> None:
        message = {
            "run_id": run_id,
            "step_name": step_name,
            "result": result,
            "published_at": time.time(),
        }
        self._get_result_queue(run_id).put(message)
        logger.debug("local publish_result run=%s step=%s", run_id, step_name)

    def subscribe_results(self, run_id: str) -> "LocalResultSubscription":
        q = self._get_result_queue(run_id)
        return LocalResultSubscription(q, run_id)

    def get_queue_depth(self, queue_name: str = _DEFAULT_QUEUE) -> int:
        return self._get_queue(queue_name).qsize()

    def get_worker_count(self) -> int:
        now = time.time()
        with self._lock:
            # Expire workers whose heartbeat is older than TTL
            expired = [
                wid
                for wid, info in self._workers.items()
                if now - info.get("last_heartbeat", 0) > _WORKER_HEARTBEAT_TTL
            ]
            for wid in expired:
                del self._workers[wid]
            return len(self._workers)

    def register_worker(self, worker_id: str) -> None:
        is_new = False
        with self._lock:
            now = time.time()
            if worker_id not in self._workers:
                self._workers[worker_id] = {
                    "worker_id": worker_id,
                    "registered_at": now,
                }
                is_new = True
            self._workers[worker_id]["last_heartbeat"] = now
        logger.debug("local register_worker worker_id=%s", worker_id)
        if is_new:
            _emit_event("queue_manager.worker_registered", {
                "worker_id": worker_id,
                "backend": "local",
            })

    def deregister_worker(self, worker_id: str) -> None:
        with self._lock:
            removed = self._workers.pop(worker_id, None)
        logger.debug("local deregister_worker worker_id=%s", worker_id)
        if removed is not None:
            _emit_event("queue_manager.worker_deregistered", {
                "worker_id": worker_id,
                "backend": "local",
            })

    def list_workers(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._workers.values())


class LocalResultSubscription(ResultSubscription):
    """Iterates over a local result queue for a single pipeline run."""

    def __init__(self, q: queue.Queue, run_id: str) -> None:
        self._queue = q
        self._run_id = run_id
        self._closed = False

    def __iter__(self):
        while not self._closed:
            try:
                yield self._queue.get(block=True, timeout=1.0)
            except queue.Empty:
                pass

    def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Factory / singleton
# ---------------------------------------------------------------------------
_queue_manager_instance: Optional[BaseQueueManager] = None
_queue_manager_lock = threading.Lock()


def get_queue_manager(
    *,
    host: str = "localhost",
    port: int = 6379,
    db: int = 0,
    force_local: bool = False,
) -> BaseQueueManager:
    """Return the singleton QueueManager, creating it on first call.

    Tries Redis first.  Falls back to ``LocalQueueManager`` automatically
    if Redis is unavailable or if *force_local* is ``True``.

    Args:
        host: Redis host (default ``localhost``).
        port: Redis port (default ``6379``).
        db: Redis database index (default ``0``).
        force_local: Skip Redis and always return the in-process backend.

    Returns:
        A ``BaseQueueManager`` instance (either Redis or local).
    """
    global _queue_manager_instance

    with _queue_manager_lock:
        if _queue_manager_instance is not None:
            return _queue_manager_instance

        if not force_local:
            try:
                import redis as _redis  # type: ignore[import]

                mgr = RedisQueueManager(host=host, port=port, db=db)
                # Verify connectivity with a lightweight ping
                mgr._redis.ping()
                _queue_manager_instance = mgr
                logger.info("QueueManager: using Redis backend")
                return _queue_manager_instance
            except ImportError:
                logger.warning("QueueManager: redis package not installed — falling back to local")
            except Exception as exc:
                logger.warning(
                    "QueueManager: Redis unavailable (%s) — falling back to local", exc
                )

        _queue_manager_instance = LocalQueueManager()
        return _queue_manager_instance


def reset_queue_manager() -> None:
    """Reset the singleton (for testing only)."""
    global _queue_manager_instance
    with _queue_manager_lock:
        _queue_manager_instance = None


# Public alias used in tests
QueueManager = RedisQueueManager
