"""Tests for WebhookDLQ — dead letter queue for failed webhook deliveries.

Covers: enqueue, retry with backoff, dead letter after max retries, replay,
bulk replay, purge, failure analytics, DLQ stats, and list/filter operations.
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict
from unittest.mock import patch

import pytest

from core.webhook_dlq import (
    DeliveryStatus,
    RetryPolicy,
    WebhookDelivery,
    WebhookDLQ,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_dlq(tmp_path):
    """WebhookDLQ backed by a temporary SQLite file, default RetryPolicy."""
    db_path = str(tmp_path / "test_dlq.db")
    return WebhookDLQ(db_path=db_path)


@pytest.fixture
def strict_dlq(tmp_path):
    """WebhookDLQ with max_retries=2 for dead-letter tests."""
    db_path = str(tmp_path / "strict_dlq.db")
    policy = RetryPolicy(max_retries=2, initial_delay_seconds=1, backoff_multiplier=2.0, max_delay_seconds=60)
    return WebhookDLQ(db_path=db_path, policy=policy)


def _sample_payload() -> Dict[str, Any]:
    return {"finding_id": "F-001", "severity": "critical", "source": "trivy"}


# ---------------------------------------------------------------------------
# RetryPolicy model
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    def test_default_values(self):
        policy = RetryPolicy()
        assert policy.max_retries == 5
        assert policy.initial_delay_seconds == 30
        assert policy.backoff_multiplier == 2.0
        assert policy.max_delay_seconds == 3600

    def test_custom_values(self):
        policy = RetryPolicy(max_retries=3, initial_delay_seconds=10, backoff_multiplier=1.5, max_delay_seconds=300)
        assert policy.max_retries == 3
        assert policy.initial_delay_seconds == 10
        assert policy.backoff_multiplier == 1.5
        assert policy.max_delay_seconds == 300

    def test_max_retries_zero_allowed(self):
        policy = RetryPolicy(max_retries=0)
        assert policy.max_retries == 0


# ---------------------------------------------------------------------------
# DeliveryStatus enum
# ---------------------------------------------------------------------------


class TestDeliveryStatus:
    def test_all_statuses_present(self):
        statuses = {s.value for s in DeliveryStatus}
        assert "pending" in statuses
        assert "retrying" in statuses
        assert "delivered" in statuses
        assert "failed" in statuses
        assert "dead_letter" in statuses

    def test_string_enum(self):
        assert DeliveryStatus.PENDING == "pending"
        assert DeliveryStatus.DEAD_LETTER == "dead_letter"


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


class TestEnqueue:
    def test_enqueue_returns_delivery(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", _sample_payload(), "https://example.com/hook", "org-1")
        assert isinstance(d, WebhookDelivery)
        assert d.webhook_id == "wh-1"
        assert d.event_id == "evt-1"
        assert d.org_id == "org-1"
        assert d.url == "https://example.com/hook"
        assert d.payload == _sample_payload()

    def test_enqueue_status_is_pending(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        assert d.status == DeliveryStatus.PENDING

    def test_enqueue_attempts_zero(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        assert d.attempts == 0

    def test_enqueue_sets_next_retry_at(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        assert d.next_retry_at is not None

    def test_enqueue_sets_created_at(self, tmp_dlq):
        before = datetime.now(timezone.utc)
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        after = datetime.now(timezone.utc)
        assert isinstance(d.created_at, datetime)

    def test_enqueue_persists(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", _sample_payload(), "https://example.com/hook", "org-1")
        fetched = tmp_dlq.get_delivery(d.id)
        assert fetched.id == d.id
        assert fetched.payload == _sample_payload()

    def test_enqueue_multiple_deliveries(self, tmp_dlq):
        for i in range(5):
            tmp_dlq.enqueue(f"wh-{i}", f"evt-{i}", {}, "https://example.com/hook", "org-1")
        deliveries = tmp_dlq.list_deliveries("org-1")
        assert len(deliveries) == 5


# ---------------------------------------------------------------------------
# record_attempt — success path
# ---------------------------------------------------------------------------


class TestRecordAttemptSuccess:
    def test_success_sets_delivered(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.record_attempt(d.id, success=True)
        updated = tmp_dlq.get_delivery(d.id)
        assert updated.status == DeliveryStatus.DELIVERED

    def test_success_increments_attempts(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.record_attempt(d.id, success=True)
        updated = tmp_dlq.get_delivery(d.id)
        assert updated.attempts == 1

    def test_success_sets_completed_at(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.record_attempt(d.id, success=True)
        updated = tmp_dlq.get_delivery(d.id)
        assert updated.completed_at is not None

    def test_success_clears_last_error(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.record_attempt(d.id, success=True)
        updated = tmp_dlq.get_delivery(d.id)
        assert updated.last_error is None


# ---------------------------------------------------------------------------
# record_attempt — failure path with backoff
# ---------------------------------------------------------------------------


class TestRecordAttemptFailure:
    def test_first_failure_sets_retrying(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        updated = strict_dlq.get_delivery(d.id)
        assert updated.status == DeliveryStatus.RETRYING

    def test_failure_records_error(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="ConnectionError")
        updated = strict_dlq.get_delivery(d.id)
        assert updated.last_error == "ConnectionError"

    def test_failure_increments_attempts(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        updated = strict_dlq.get_delivery(d.id)
        assert updated.attempts == 1

    def test_max_retries_exceeded_sets_dead_letter(self, strict_dlq):
        # strict_dlq has max_retries=2
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        updated = strict_dlq.get_delivery(d.id)
        assert updated.status == DeliveryStatus.DEAD_LETTER

    def test_dead_letter_clears_next_retry_at(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        updated = strict_dlq.get_delivery(d.id)
        assert updated.next_retry_at is None

    def test_nonexistent_delivery_no_error(self, tmp_dlq):
        # Should not raise; just log a warning
        tmp_dlq.record_attempt("nonexistent-id", success=False, error="Timeout")


# ---------------------------------------------------------------------------
# Exponential backoff calculation
# ---------------------------------------------------------------------------


class TestCalculateNextRetry:
    def test_attempt_zero_uses_initial_delay(self, tmp_dlq):
        policy = RetryPolicy(initial_delay_seconds=30, backoff_multiplier=2.0, max_delay_seconds=3600)
        before = datetime.now(timezone.utc)
        next_retry = tmp_dlq.calculate_next_retry(0, policy)
        # Should be ~30 seconds from now
        delta = (next_retry - before).total_seconds()
        assert 29 <= delta <= 32

    def test_backoff_doubles_per_attempt(self, tmp_dlq):
        policy = RetryPolicy(initial_delay_seconds=10, backoff_multiplier=2.0, max_delay_seconds=3600)
        t0 = tmp_dlq.calculate_next_retry(0, policy)
        t1 = tmp_dlq.calculate_next_retry(1, policy)
        delta0 = (t0 - datetime.now(timezone.utc)).total_seconds()
        delta1 = (t1 - datetime.now(timezone.utc)).total_seconds()
        assert abs(delta1 - delta0 * 2) < 2  # allow 2s tolerance

    def test_max_delay_capped(self, tmp_dlq):
        policy = RetryPolicy(initial_delay_seconds=100, backoff_multiplier=10.0, max_delay_seconds=300)
        next_retry = tmp_dlq.calculate_next_retry(5, policy)
        delta = (next_retry - datetime.now(timezone.utc)).total_seconds()
        assert delta <= 301  # at most max_delay + 1s tolerance

    def test_returns_datetime(self, tmp_dlq):
        policy = RetryPolicy()
        result = tmp_dlq.calculate_next_retry(0, policy)
        assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# get_pending
# ---------------------------------------------------------------------------


class TestGetPending:
    def test_pending_returned_immediately(self, tmp_path):
        # Use policy with 0 initial delay effectively (very small)
        db_path = str(tmp_path / "pending.db")
        policy = RetryPolicy(initial_delay_seconds=1, max_retries=5)
        dlq = WebhookDLQ(db_path=db_path, policy=policy)
        d = dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        # Manually set next_retry_at to the past
        import sqlite3, json
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE webhook_deliveries SET next_retry_at=? WHERE id=?",
                     ("2000-01-01T00:00:00+00:00", d.id))
        conn.commit()
        conn.close()
        pending = dlq.get_pending(limit=10)
        assert any(p.id == d.id for p in pending)

    def test_future_retry_not_returned(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        # next_retry_at is in the future (default 30s)
        pending = tmp_dlq.get_pending(limit=10)
        assert not any(p.id == d.id for p in pending)

    def test_delivered_not_in_pending(self, tmp_path):
        db_path = str(tmp_path / "pending2.db")
        dlq = WebhookDLQ(db_path=db_path)
        d = dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        dlq.record_attempt(d.id, success=True)
        pending = dlq.get_pending(limit=100)
        assert not any(p.id == d.id for p in pending)

    def test_limit_respected(self, tmp_path):
        db_path = str(tmp_path / "pending3.db")
        dlq = WebhookDLQ(db_path=db_path)
        import sqlite3
        for i in range(5):
            d = dlq.enqueue(f"wh-{i}", f"evt-{i}", {}, "https://example.com/hook", "org-1")
            conn = sqlite3.connect(db_path)
            conn.execute("UPDATE webhook_deliveries SET next_retry_at=? WHERE id=?",
                         ("2000-01-01T00:00:00+00:00", d.id))
            conn.commit()
            conn.close()
        pending = dlq.get_pending(limit=3)
        assert len(pending) <= 3


# ---------------------------------------------------------------------------
# get_dead_letters
# ---------------------------------------------------------------------------


class TestGetDeadLetters:
    def test_dead_letter_appears(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        dead = strict_dlq.get_dead_letters("org-1")
        assert any(dl.id == d.id for dl in dead)

    def test_org_isolation(self, strict_dlq):
        d1 = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d1.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d1.id, success=False, error="Timeout")
        dead_org2 = strict_dlq.get_dead_letters("org-2")
        assert not any(dl.id == d1.id for dl in dead_org2)

    def test_pending_not_in_dead_letters(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        dead = strict_dlq.get_dead_letters("org-1")
        assert not any(dl.id == d.id for dl in dead)


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


class TestReplay:
    def test_replay_resets_status_to_pending(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        replayed = strict_dlq.replay(d.id)
        assert replayed.status == DeliveryStatus.PENDING

    def test_replay_resets_attempts_to_zero(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        replayed = strict_dlq.replay(d.id)
        assert replayed.attempts == 0

    def test_replay_clears_last_error(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="ConnectionError")
        strict_dlq.record_attempt(d.id, success=False, error="ConnectionError")
        replayed = strict_dlq.replay(d.id)
        assert replayed.last_error is None

    def test_replay_nonexistent_raises(self, tmp_dlq):
        with pytest.raises(RuntimeError):
            tmp_dlq.replay("nonexistent-delivery-id")

    def test_replay_returns_delivery(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        result = strict_dlq.replay(d.id)
        assert isinstance(result, WebhookDelivery)
        assert result.id == d.id


# ---------------------------------------------------------------------------
# replay_batch
# ---------------------------------------------------------------------------


class TestReplayBatch:
    def test_batch_returns_count(self, strict_dlq):
        ids = []
        for i in range(3):
            d = strict_dlq.enqueue(f"wh-{i}", f"evt-{i}", {}, "https://example.com/hook", "org-1")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
            ids.append(d.id)
        count = strict_dlq.replay_batch(ids)
        assert count == 3

    def test_batch_empty_list_returns_zero(self, tmp_dlq):
        count = tmp_dlq.replay_batch([])
        assert count == 0

    def test_batch_resets_status(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.replay_batch([d.id])
        updated = strict_dlq.get_delivery(d.id)
        assert updated.status == DeliveryStatus.PENDING

    def test_batch_skips_nonexistent_gracefully(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        count = tmp_dlq.replay_batch([d.id, "fake-id-xyz"])
        # Should update the real one, ignore the fake
        assert count >= 1


# ---------------------------------------------------------------------------
# purge_delivered
# ---------------------------------------------------------------------------


class TestPurgeDelivered:
    def test_purge_old_delivered(self, tmp_path):
        db_path = str(tmp_path / "purge.db")
        dlq = WebhookDLQ(db_path=db_path)
        d = dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        dlq.record_attempt(d.id, success=True)
        # Force completed_at into the past
        import sqlite3
        old_date = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE webhook_deliveries SET completed_at=? WHERE id=?", (old_date, d.id))
        conn.commit()
        conn.close()
        count = dlq.purge_delivered(days=30)
        assert count == 1

    def test_purge_recent_delivered_not_removed(self, tmp_path):
        db_path = str(tmp_path / "purge2.db")
        dlq = WebhookDLQ(db_path=db_path)
        d = dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        dlq.record_attempt(d.id, success=True)
        count = dlq.purge_delivered(days=30)
        assert count == 0

    def test_purge_returns_count(self, tmp_dlq):
        count = tmp_dlq.purge_delivered(days=30)
        assert isinstance(count, int)


# ---------------------------------------------------------------------------
# purge_dead_letters
# ---------------------------------------------------------------------------


class TestPurgeDeadLetters:
    def test_purge_dead_letters_for_org(self, strict_dlq):
        for i in range(3):
            d = strict_dlq.enqueue(f"wh-{i}", f"evt-{i}", {}, "https://example.com/hook", "org-1")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        count = strict_dlq.purge_dead_letters("org-1")
        assert count == 3

    def test_purge_only_affects_target_org(self, strict_dlq):
        d1 = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d1.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d1.id, success=False, error="Timeout")
        d2 = strict_dlq.enqueue("wh-2", "evt-2", {}, "https://example.com/hook", "org-2")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")
        strict_dlq.purge_dead_letters("org-1")
        # org-2's dead letter should still exist
        dead_org2 = strict_dlq.get_dead_letters("org-2")
        assert any(dl.id == d2.id for dl in dead_org2)


# ---------------------------------------------------------------------------
# get_delivery
# ---------------------------------------------------------------------------


class TestGetDelivery:
    def test_get_existing_delivery(self, tmp_dlq):
        d = tmp_dlq.enqueue("wh-1", "evt-1", _sample_payload(), "https://example.com/hook", "org-1")
        fetched = tmp_dlq.get_delivery(d.id)
        assert fetched.id == d.id
        assert fetched.payload == _sample_payload()

    def test_get_nonexistent_raises_value_error(self, tmp_dlq):
        with pytest.raises(ValueError):
            tmp_dlq.get_delivery("nonexistent-id")


# ---------------------------------------------------------------------------
# list_deliveries
# ---------------------------------------------------------------------------


class TestListDeliveries:
    def test_list_all_for_org(self, tmp_dlq):
        tmp_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.enqueue("wh-2", "evt-2", {}, "https://example.com/hook", "org-1")
        tmp_dlq.enqueue("wh-3", "evt-3", {}, "https://example.com/hook", "org-2")
        result = tmp_dlq.list_deliveries("org-1")
        assert len(result) == 2

    def test_filter_by_status(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        dead = strict_dlq.list_deliveries("org-1", status_filter="dead_letter")
        assert len(dead) == 1
        assert dead[0].id == d.id

    def test_filter_by_webhook_id(self, tmp_dlq):
        tmp_dlq.enqueue("wh-A", "evt-1", {}, "https://example.com/hook", "org-1")
        tmp_dlq.enqueue("wh-B", "evt-2", {}, "https://example.com/hook", "org-1")
        result = tmp_dlq.list_deliveries("org-1", webhook_id="wh-A")
        assert len(result) == 1
        assert result[0].webhook_id == "wh-A"

    def test_empty_org_returns_empty(self, tmp_dlq):
        result = tmp_dlq.list_deliveries("org-nonexistent")
        assert result == []


# ---------------------------------------------------------------------------
# Failure analytics
# ---------------------------------------------------------------------------


class TestFailureAnalytics:
    def test_analytics_structure(self, tmp_dlq):
        analytics = tmp_dlq.get_failure_analytics("org-1")
        assert "failure_rate_by_webhook" in analytics
        assert "top_errors" in analytics
        assert "avg_retries" in analytics
        assert "total_deliveries" in analytics
        assert "total_failed" in analytics

    def test_analytics_failure_rate(self, strict_dlq):
        # 1 success, 2 failures → max_retries exceeded → dead_letter
        d1 = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d1.id, success=True)

        d2 = strict_dlq.enqueue("wh-1", "evt-2", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")

        analytics = strict_dlq.get_failure_analytics("org-1")
        rate = analytics["failure_rate_by_webhook"].get("wh-1", 0.0)
        # 1 dead_letter out of 2 total = 0.5
        assert rate == pytest.approx(0.5, abs=0.01)

    def test_analytics_top_errors(self, strict_dlq):
        for i in range(3):
            d = strict_dlq.enqueue(f"wh-{i}", f"evt-{i}", {}, "https://example.com/hook", "org-1")
            strict_dlq.record_attempt(d.id, success=False, error="ConnectionError")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
        analytics = strict_dlq.get_failure_analytics("org-1")
        assert len(analytics["top_errors"]) > 0
        # Most frequent error should appear
        error_names = [e["error"] for e in analytics["top_errors"]]
        assert "Timeout" in error_names or "ConnectionError" in error_names

    def test_analytics_empty_org(self, tmp_dlq):
        analytics = tmp_dlq.get_failure_analytics("org-empty")
        assert analytics["total_deliveries"] == 0
        assert analytics["total_failed"] == 0
        assert analytics["avg_retries"] == 0.0


# ---------------------------------------------------------------------------
# DLQ stats
# ---------------------------------------------------------------------------


class TestDLQStats:
    def test_stats_structure(self, tmp_dlq):
        stats = tmp_dlq.get_dlq_stats("org-1")
        assert "pending" in stats
        assert "retrying" in stats
        assert "delivered" in stats
        assert "dead" in stats
        assert "by_webhook" in stats

    def test_stats_counts(self, strict_dlq):
        # Enqueue 2, deliver 1, dead-letter 1
        d1 = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d1.id, success=True)

        d2 = strict_dlq.enqueue("wh-1", "evt-2", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")
        strict_dlq.record_attempt(d2.id, success=False, error="Timeout")

        stats = strict_dlq.get_dlq_stats("org-1")
        assert stats["delivered"] == 1
        assert stats["dead"] == 1

    def test_stats_by_webhook(self, strict_dlq):
        d = strict_dlq.enqueue("wh-X", "evt-1", {}, "https://example.com/hook", "org-1")
        strict_dlq.record_attempt(d.id, success=True)

        stats = strict_dlq.get_dlq_stats("org-1")
        assert "wh-X" in stats["by_webhook"]

    def test_stats_org_isolation(self, strict_dlq):
        d = strict_dlq.enqueue("wh-1", "evt-1", {}, "https://example.com/hook", "org-A")
        strict_dlq.record_attempt(d.id, success=True)

        stats_b = strict_dlq.get_dlq_stats("org-B")
        assert stats_b["delivered"] == 0
