"""Tests for RedisQueue — always exercises the in-memory backend.

Redis is not expected to be running in CI/test environments;
the memory fallback is the primary tested code path.
"""
import sys
import time

sys.path.insert(0, "suite-core")

import pytest
from core.redis_queue import RedisQueue


# ---------------------------------------------------------------------------
# Fixture: fresh queue per test
# ---------------------------------------------------------------------------


@pytest.fixture()
def q() -> RedisQueue:
    """Return a fresh in-memory RedisQueue with Redis patched out entirely."""
    import core.redis_queue as rq_module

    # Patch _REDIS_AVAILABLE so no connection is attempted
    original = rq_module._REDIS_AVAILABLE
    rq_module._REDIS_AVAILABLE = False
    queue = RedisQueue(prefix="test:queue", org_id="test-org")
    queue.clear()
    yield queue
    rq_module._REDIS_AVAILABLE = original


@pytest.fixture()
def q_org_a() -> RedisQueue:
    """RedisQueue scoped to org_a."""
    import core.redis_queue as rq_module

    original = rq_module._REDIS_AVAILABLE
    rq_module._REDIS_AVAILABLE = False
    queue = RedisQueue(prefix="test:queue", org_id="org_a")
    queue.clear()
    yield queue
    rq_module._REDIS_AVAILABLE = original


@pytest.fixture()
def q_org_b() -> RedisQueue:
    """RedisQueue scoped to org_b."""
    import core.redis_queue as rq_module

    original = rq_module._REDIS_AVAILABLE
    rq_module._REDIS_AVAILABLE = False
    queue = RedisQueue(prefix="test:queue", org_id="org_b")
    queue.clear()
    yield queue
    rq_module._REDIS_AVAILABLE = original


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


def test_backend_is_memory_when_redis_unavailable(q: RedisQueue) -> None:
    assert q.backend == "memory"


# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------


def test_enqueue_returns_string_task_id(q: RedisQueue) -> None:
    task_id = q.enqueue({"job": "scan"})
    assert isinstance(task_id, str)
    assert len(task_id) > 0


def test_enqueue_task_id_is_uuid_format(q: RedisQueue) -> None:
    import uuid
    task_id = q.enqueue({"job": "test"})
    # Should not raise
    uuid.UUID(task_id)


def test_enqueue_task_ids_are_unique(q: RedisQueue) -> None:
    ids = {q.enqueue({"job": "scan"}) for _ in range(50)}
    assert len(ids) == 50


def test_enqueue_dict_payload_preserved_in_dequeue(q: RedisQueue) -> None:
    q.enqueue({"job": "scan", "target": "192.168.1.1", "depth": 3})
    task = q.dequeue()
    assert task is not None
    assert task["job"] == "scan"
    assert task["target"] == "192.168.1.1"
    assert task["depth"] == 3


def test_enqueue_injects_task_id_into_payload(q: RedisQueue) -> None:
    task_id = q.enqueue({"job": "enrich"})
    task = q.dequeue()
    assert task is not None
    assert task["task_id"] == task_id


def test_enqueue_injects_priority_into_payload(q: RedisQueue) -> None:
    q.enqueue({"job": "enrich"}, priority=3)
    task = q.dequeue()
    assert task is not None
    assert task["priority"] == 3


def test_enqueue_injects_enqueued_at_timestamp(q: RedisQueue) -> None:
    before = time.time()
    q.enqueue({"job": "scan"})
    after = time.time()
    task = q.dequeue()
    assert task is not None
    assert before <= task["enqueued_at"] <= after


# ---------------------------------------------------------------------------
# dequeue
# ---------------------------------------------------------------------------


def test_dequeue_after_enqueue_returns_task(q: RedisQueue) -> None:
    q.enqueue({"job": "scan"})
    task = q.dequeue()
    assert task is not None


def test_dequeue_on_empty_queue_returns_none(q: RedisQueue) -> None:
    assert q.dequeue() is None


def test_dequeue_returns_none_after_all_tasks_consumed(q: RedisQueue) -> None:
    q.enqueue({"job": "a"})
    q.dequeue()
    assert q.dequeue() is None


def test_dequeue_fifo_within_same_priority(q: RedisQueue) -> None:
    q.enqueue({"job": "first"}, priority=5)
    q.enqueue({"job": "second"}, priority=5)
    t1 = q.dequeue()
    t2 = q.dequeue()
    assert t1 is not None and t2 is not None
    assert t1["job"] == "first"
    assert t2["job"] == "second"


# ---------------------------------------------------------------------------
# Priority ordering
# ---------------------------------------------------------------------------


def test_priority_1_dequeued_before_priority_9(q: RedisQueue) -> None:
    q.enqueue({"job": "low"}, priority=9)
    q.enqueue({"job": "high"}, priority=1)
    first = q.dequeue()
    assert first is not None
    assert first["job"] == "high"


def test_priority_ordering_across_multiple_levels(q: RedisQueue) -> None:
    q.enqueue({"job": "p5"}, priority=5)
    q.enqueue({"job": "p2"}, priority=2)
    q.enqueue({"job": "p8"}, priority=8)
    q.enqueue({"job": "p1"}, priority=1)

    results = [q.dequeue()["job"] for _ in range(4)]
    assert results[0] == "p1"
    assert results[1] == "p2"
    assert results[2] == "p5"
    assert results[3] == "p8"


# ---------------------------------------------------------------------------
# depth
# ---------------------------------------------------------------------------


def test_depth_increases_on_enqueue(q: RedisQueue) -> None:
    assert q.depth() == 0
    q.enqueue({"job": "a"})
    assert q.depth() == 1
    q.enqueue({"job": "b"})
    assert q.depth() == 2


def test_depth_decreases_on_dequeue(q: RedisQueue) -> None:
    q.enqueue({"job": "a"})
    q.enqueue({"job": "b"})
    q.dequeue()
    assert q.depth() == 1
    q.dequeue()
    assert q.depth() == 0


def test_depth_zero_on_empty_queue(q: RedisQueue) -> None:
    assert q.depth() == 0


# ---------------------------------------------------------------------------
# clear
# ---------------------------------------------------------------------------


def test_clear_returns_correct_count(q: RedisQueue) -> None:
    for _ in range(5):
        q.enqueue({"job": "scan"})
    cleared = q.clear()
    assert cleared == 5


def test_clear_empties_queue(q: RedisQueue) -> None:
    for _ in range(3):
        q.enqueue({"job": "x"})
    q.clear()
    assert q.depth() == 0
    assert q.dequeue() is None


def test_clear_on_empty_returns_zero(q: RedisQueue) -> None:
    assert q.clear() == 0


# ---------------------------------------------------------------------------
# peek
# ---------------------------------------------------------------------------


def test_peek_does_not_remove_items(q: RedisQueue) -> None:
    q.enqueue({"job": "scan"})
    q.enqueue({"job": "alert"})
    peeked = q.peek(limit=10)
    assert len(peeked) == 2
    assert q.depth() == 2


def test_peek_respects_limit(q: RedisQueue) -> None:
    for i in range(10):
        q.enqueue({"job": f"task_{i}"})
    peeked = q.peek(limit=3)
    assert len(peeked) == 3


def test_peek_on_empty_queue_returns_empty_list(q: RedisQueue) -> None:
    assert q.peek() == []


def test_peek_returns_highest_priority_first(q: RedisQueue) -> None:
    q.enqueue({"job": "low"}, priority=9)
    q.enqueue({"job": "high"}, priority=1)
    peeked = q.peek(limit=2)
    assert peeked[0]["job"] == "high"


# ---------------------------------------------------------------------------
# workers
# ---------------------------------------------------------------------------


def test_workers_returns_int_gte_1(q: RedisQueue) -> None:
    w = q.workers()
    assert isinstance(w, int)
    assert w >= 1


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


def test_org_isolation_enqueue_dequeue(q_org_a: RedisQueue, q_org_b: RedisQueue) -> None:
    """Tasks enqueued for org_a must not be visible to org_b and vice versa."""
    q_org_a.enqueue({"job": "scan_a", "org_id": "org_a"})
    q_org_b.enqueue({"job": "scan_b", "org_id": "org_b"})

    task_a = q_org_a.dequeue()
    task_b = q_org_b.dequeue()

    assert task_a is not None
    assert task_a["job"] == "scan_a"
    assert task_a["org_id"] == "org_a"

    assert task_b is not None
    assert task_b["job"] == "scan_b"
    assert task_b["org_id"] == "org_b"

    # Both queues should now be empty — no cross-contamination
    assert q_org_a.dequeue() is None
    assert q_org_b.dequeue() is None


def test_org_isolation_depth_is_independent(q_org_a: RedisQueue, q_org_b: RedisQueue) -> None:
    """depth() for each org reflects only that org's tasks."""
    for _ in range(3):
        q_org_a.enqueue({"job": "task"})
    for _ in range(7):
        q_org_b.enqueue({"job": "task"})

    assert q_org_a.depth() == 3
    assert q_org_b.depth() == 7

    # Draining org_a does not affect org_b
    q_org_a.clear()
    assert q_org_a.depth() == 0
    assert q_org_b.depth() == 7


def test_org_isolation_clear_does_not_affect_other_org(
    q_org_a: RedisQueue, q_org_b: RedisQueue
) -> None:
    """clear() on one org must not remove tasks belonging to another org."""
    q_org_a.enqueue({"job": "important"})
    q_org_b.enqueue({"job": "keep_me"})

    cleared = q_org_a.clear()
    assert cleared == 1
    assert q_org_a.depth() == 0

    # org_b task must still be present
    task = q_org_b.dequeue()
    assert task is not None
    assert task["job"] == "keep_me"


def test_task_org_id_in_payload_overrides_queue_org_id(q_org_a: RedisQueue) -> None:
    """When a task dict carries its own org_id, that value is used for routing."""
    task_id = q_org_a.enqueue({"job": "routed", "org_id": "org_a"})
    task = q_org_a.dequeue()
    assert task is not None
    assert task["task_id"] == task_id
    assert task["org_id"] == "org_a"


def test_default_org_id_used_when_task_has_none(q: RedisQueue) -> None:
    """When a task dict has no org_id, the queue's own org_id is injected."""
    q.enqueue({"job": "no_org"})
    task = q.dequeue()
    assert task is not None
    assert task["org_id"] == "test-org"
