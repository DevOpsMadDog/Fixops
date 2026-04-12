"""Tests for the ALdeci Queue Manager.

All tests run without an actual Redis instance — Redis is mocked via
``unittest.mock``.  The LocalQueueManager tests use real in-process queues.

Coverage:
- QueueManager (Redis-backed) — enqueue, dequeue, pub/sub, workers
- LocalQueueManager fallback — full API without Redis
- Graceful fallback when Redis is unavailable
- Worker registration and heartbeat expiry
"""

from __future__ import annotations

import json
import queue
import time
import threading
import unittest
from unittest.mock import MagicMock, patch, call
from typing import Any, Dict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_redis_mock(ping_ok: bool = True, blpop_return=None):
    """Return a mock Redis client."""
    mock = MagicMock()
    if ping_ok:
        mock.ping.return_value = True
    else:
        mock.ping.side_effect = Exception("Connection refused")
    if blpop_return is not None:
        mock.blpop.return_value = blpop_return
    else:
        mock.blpop.return_value = None
    mock.llen.return_value = 0
    mock.keys.return_value = []
    return mock


# ---------------------------------------------------------------------------
# LocalQueueManager tests
# ---------------------------------------------------------------------------

class TestLocalQueueManager(unittest.TestCase):
    """Test the in-process fallback queue manager."""

    def setUp(self):
        from core.queue_manager import LocalQueueManager, reset_queue_manager
        reset_queue_manager()
        self.qm = LocalQueueManager()

    def test_enqueue_returns_task_id(self):
        task_id = self.qm.enqueue_step("run-1", "enrich_threats", {"data": 1})
        self.assertIsInstance(task_id, str)
        self.assertTrue(len(task_id) > 0)

    def test_enqueue_dequeue_roundtrip(self):
        self.qm.enqueue_step("run-2", "score_risk", {"findings": [1, 2]})
        item = self.qm.dequeue_step(timeout=1)
        self.assertIsNotNone(item)
        self.assertEqual(item["run_id"], "run-2")
        self.assertEqual(item["step_name"], "score_risk")
        self.assertEqual(item["payload"]["findings"], [1, 2])

    def test_dequeue_empty_returns_none(self):
        item = self.qm.dequeue_step(timeout=0)
        self.assertIsNone(item)

    def test_queue_depth(self):
        self.assertEqual(self.qm.get_queue_depth(), 0)
        self.qm.enqueue_step("run-3", "enrich_threats", {})
        self.qm.enqueue_step("run-3", "score_risk", {})
        self.assertEqual(self.qm.get_queue_depth(), 2)

    def test_worker_registration(self):
        self.assertEqual(self.qm.get_worker_count(), 0)
        self.qm.register_worker("worker-1")
        self.assertEqual(self.qm.get_worker_count(), 1)

    def test_worker_deregistration(self):
        self.qm.register_worker("worker-a")
        self.qm.register_worker("worker-b")
        self.assertEqual(self.qm.get_worker_count(), 2)
        self.qm.deregister_worker("worker-a")
        self.assertEqual(self.qm.get_worker_count(), 1)

    def test_worker_heartbeat_refresh(self):
        self.qm.register_worker("worker-hb")
        self.qm.register_worker("worker-hb")  # refresh
        self.assertEqual(self.qm.get_worker_count(), 1)

    def test_list_workers(self):
        self.qm.register_worker("w1")
        self.qm.register_worker("w2")
        workers = self.qm.list_workers()
        ids = {w["worker_id"] for w in workers}
        self.assertIn("w1", ids)
        self.assertIn("w2", ids)

    def test_worker_heartbeat_expiry(self):
        """Workers whose heartbeat is older than TTL should not appear."""
        from core.queue_manager import _WORKER_HEARTBEAT_TTL

        self.qm.register_worker("stale-worker")
        # Manually backdate the last_heartbeat
        with self.qm._lock:
            self.qm._workers["stale-worker"]["last_heartbeat"] = (
                time.time() - _WORKER_HEARTBEAT_TTL - 1
            )
        # get_worker_count() evicts stale entries
        count = self.qm.get_worker_count()
        self.assertEqual(count, 0)

    def test_publish_subscribe_result(self):
        sub = self.qm.subscribe_results("run-99")
        self.qm.publish_result("run-99", "score_risk", {"verdict": "high"})

        received = []
        def consume():
            for msg in sub:
                received.append(msg)
                sub.close()
                break

        t = threading.Thread(target=consume, daemon=True)
        t.start()
        t.join(timeout=3)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["step_name"], "score_risk")
        self.assertEqual(received[0]["result"]["verdict"], "high")

    def test_task_has_required_fields(self):
        task_id = self.qm.enqueue_step("run-fields", "llm_consensus", {"k": "v"})
        item = self.qm.dequeue_step(timeout=1)
        self.assertIn("task_id", item)
        self.assertIn("run_id", item)
        self.assertIn("step_name", item)
        self.assertIn("payload", item)
        self.assertIn("enqueued_at", item)
        self.assertEqual(item["task_id"], task_id)

    def test_multiple_queues_are_isolated(self):
        from core.queue_manager import _DEFAULT_QUEUE

        self.qm.enqueue_step("r1", "step_a", {})
        # Dequeue from a different queue name — should be empty
        item = self.qm.dequeue_step(queue_name="aldeci:pipeline:other", timeout=0)
        self.assertIsNone(item)
        # Original queue still has the item
        item2 = self.qm.dequeue_step(queue_name=_DEFAULT_QUEUE, timeout=0)
        self.assertIsNotNone(item2)


# ---------------------------------------------------------------------------
# RedisQueueManager tests (Redis mocked)
# ---------------------------------------------------------------------------

class TestRedisQueueManager(unittest.TestCase):
    """Test the Redis-backed queue manager with mocked Redis."""

    def _make_manager(self, redis_client=None):
        """Create a RedisQueueManager with an injected mock Redis client."""
        import sys
        # We patch redis.Redis and redis.ConnectionPool
        redis_mock_module = MagicMock()
        mock_client = redis_client or _make_redis_mock()
        redis_mock_module.Redis.return_value = mock_client
        redis_mock_module.ConnectionPool.return_value = MagicMock()

        with patch.dict("sys.modules", {"redis": redis_mock_module}):
            from importlib import reload
            import core.queue_manager as qm_module
            # Directly instantiate with the mock already in sys.modules
            manager = qm_module.RedisQueueManager.__new__(qm_module.RedisQueueManager)
            manager._redis = mock_client
            manager._pool = MagicMock()
            manager._pubsub_clients = []
        return manager, mock_client

    def test_enqueue_pushes_to_redis(self):
        mgr, redis_mock = self._make_manager()
        task_id = mgr.enqueue_step("run-A", "enrich_threats", {"x": 1})
        self.assertTrue(redis_mock.rpush.called)
        call_args = redis_mock.rpush.call_args
        key, payload_str = call_args[0]
        self.assertIn("aldeci:pipeline", key)
        payload = json.loads(payload_str)
        self.assertEqual(payload["run_id"], "run-A")
        self.assertEqual(payload["step_name"], "enrich_threats")

    def test_dequeue_returns_none_on_timeout(self):
        mgr, redis_mock = self._make_manager()
        redis_mock.blpop.return_value = None
        result = mgr.dequeue_step(timeout=1)
        self.assertIsNone(result)

    def test_dequeue_deserialises_item(self):
        task = {"task_id": "abc", "run_id": "r1", "step_name": "score_risk",
                "payload": {}, "enqueued_at": time.time()}
        mgr, redis_mock = self._make_manager()
        redis_mock.blpop.return_value = ("key", json.dumps(task))
        result = mgr.dequeue_step(timeout=1)
        self.assertIsNotNone(result)
        self.assertEqual(result["task_id"], "abc")
        self.assertEqual(result["step_name"], "score_risk")

    def test_dequeue_handles_corrupt_json(self):
        mgr, redis_mock = self._make_manager()
        redis_mock.blpop.return_value = ("key", "NOT_JSON{{{")
        result = mgr.dequeue_step(timeout=1)
        self.assertIsNone(result)

    def test_publish_result_calls_publish(self):
        mgr, redis_mock = self._make_manager()
        mgr.publish_result("run-B", "llm_consensus", {"verdict": "low"})
        self.assertTrue(redis_mock.publish.called)
        channel, message_str = redis_mock.publish.call_args[0]
        self.assertIn("run-B", channel)
        msg = json.loads(message_str)
        self.assertEqual(msg["step_name"], "llm_consensus")
        self.assertEqual(msg["result"]["verdict"], "low")

    def test_get_queue_depth_calls_llen(self):
        mgr, redis_mock = self._make_manager()
        redis_mock.llen.return_value = 7
        depth = mgr.get_queue_depth()
        self.assertEqual(depth, 7)

    def test_get_worker_count_counts_keys(self):
        mgr, redis_mock = self._make_manager()
        redis_mock.keys.return_value = ["w1", "w2", "w3"]
        count = mgr.get_worker_count()
        self.assertEqual(count, 3)

    def test_register_worker_calls_setex(self):
        mgr, redis_mock = self._make_manager()
        mgr.register_worker("worker-X")
        self.assertTrue(redis_mock.setex.called)
        key_arg = redis_mock.setex.call_args[0][0]
        self.assertIn("worker-X", key_arg)

    def test_deregister_worker_calls_delete(self):
        mgr, redis_mock = self._make_manager()
        mgr.deregister_worker("worker-X")
        self.assertTrue(redis_mock.delete.called)

    def test_list_workers_parses_json(self):
        mgr, redis_mock = self._make_manager()
        worker_data = json.dumps({"worker_id": "wZ", "registered_at": 0, "last_heartbeat": 0})
        redis_mock.keys.return_value = ["aldeci:pipeline:worker:wZ"]
        redis_mock.get.return_value = worker_data
        workers = mgr.list_workers()
        self.assertEqual(len(workers), 1)
        self.assertEqual(workers[0]["worker_id"], "wZ")

    def test_list_workers_skips_corrupt_entries(self):
        mgr, redis_mock = self._make_manager()
        redis_mock.keys.return_value = ["key1"]
        redis_mock.get.return_value = "INVALID_JSON{{{"
        workers = mgr.list_workers()
        self.assertEqual(workers, [])


# ---------------------------------------------------------------------------
# Fallback / factory tests
# ---------------------------------------------------------------------------

class TestGetQueueManagerFallback(unittest.TestCase):
    """Test that get_queue_manager() returns LocalQueueManager when Redis fails."""

    def setUp(self):
        from core.queue_manager import reset_queue_manager
        reset_queue_manager()

    def tearDown(self):
        from core.queue_manager import reset_queue_manager
        reset_queue_manager()

    def test_force_local_returns_local_manager(self):
        from core.queue_manager import get_queue_manager, LocalQueueManager

        mgr = get_queue_manager(force_local=True)
        self.assertIsInstance(mgr, LocalQueueManager)

    def test_redis_import_error_falls_back_to_local(self):
        """When redis package is not installed, fall back to LocalQueueManager."""
        import sys
        from core.queue_manager import get_queue_manager, LocalQueueManager, reset_queue_manager
        reset_queue_manager()

        # Hide redis from imports
        original = sys.modules.get("redis")
        sys.modules["redis"] = None  # type: ignore[assignment]
        try:
            mgr = get_queue_manager()
            self.assertIsInstance(mgr, LocalQueueManager)
        finally:
            if original is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = original
            reset_queue_manager()

    def test_redis_connection_error_falls_back_to_local(self):
        """When Redis is installed but unreachable, fall back to LocalQueueManager."""
        from core.queue_manager import get_queue_manager, LocalQueueManager, reset_queue_manager
        reset_queue_manager()

        redis_mock_module = MagicMock()
        mock_client = MagicMock()
        mock_client.ping.side_effect = Exception("Connection refused")
        redis_mock_module.Redis.return_value = mock_client
        redis_mock_module.ConnectionPool.return_value = MagicMock()

        import sys
        with patch.dict("sys.modules", {"redis": redis_mock_module}):
            mgr = get_queue_manager()
            self.assertIsInstance(mgr, LocalQueueManager)

    def test_singleton_returns_same_instance(self):
        from core.queue_manager import get_queue_manager

        mgr1 = get_queue_manager(force_local=True)
        mgr2 = get_queue_manager(force_local=True)
        self.assertIs(mgr1, mgr2)

    def test_reset_allows_new_instance(self):
        from core.queue_manager import get_queue_manager, reset_queue_manager, LocalQueueManager

        mgr1 = get_queue_manager(force_local=True)
        reset_queue_manager()
        mgr2 = get_queue_manager(force_local=True)
        self.assertIsNot(mgr1, mgr2)


# ---------------------------------------------------------------------------
# ResultSubscription tests
# ---------------------------------------------------------------------------

class TestLocalResultSubscription(unittest.TestCase):
    """Test the local pub/sub subscription."""

    def setUp(self):
        from core.queue_manager import LocalQueueManager, reset_queue_manager
        reset_queue_manager()
        self.qm = LocalQueueManager()

    def test_subscription_receives_published_result(self):
        sub = self.qm.subscribe_results("run-sub")

        received = []

        def consumer():
            for msg in sub:
                received.append(msg)
                sub.close()
                break

        t = threading.Thread(target=consumer, daemon=True)
        t.start()
        time.sleep(0.05)
        self.qm.publish_result("run-sub", "enrich_threats", {"ok": True})
        t.join(timeout=3)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["run_id"], "run-sub")
        self.assertEqual(received[0]["step_name"], "enrich_threats")
        self.assertTrue(received[0]["result"]["ok"])

    def test_subscription_close_stops_iteration(self):
        sub = self.qm.subscribe_results("run-close")
        sub.close()
        # Iterating a closed subscription should yield nothing (breaks immediately)
        items = []
        # We do a bounded iteration — closed sub returns nothing on next get
        # because _closed=True prevents further blocking gets
        for msg in sub:
            items.append(msg)
            break
        # No message published, so nothing consumed even if iteration tried
        self.assertEqual(items, [])

    def test_multiple_subscribers_same_run(self):
        """Each subscriber gets its own queue; they don't compete for messages."""
        sub1 = self.qm.subscribe_results("shared-run")
        sub2 = self.qm.subscribe_results("shared-run")

        self.qm.publish_result("shared-run", "score_risk", {"score": 9.0})

        # sub1 should receive the message
        item = None
        try:
            item = sub1._queue.get(timeout=1)
        except Exception:
            pass
        self.assertIsNotNone(item)


if __name__ == "__main__":
    unittest.main()
