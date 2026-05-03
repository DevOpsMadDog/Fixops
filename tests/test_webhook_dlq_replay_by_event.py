"""Tests for webhook-replay-by-event: engine replay_by_event_id + router endpoints.

Covers:
- WebhookDLQ.replay_by_event_id resets all matching deliveries to PENDING
- replay_by_event_id is org-scoped (cross-org isolation)
- replay_by_event_id returns 0 for unknown event_id
- GET /api/v1/webhooks/dlq/{delivery_id} happy path
- GET /api/v1/webhooks/dlq/{delivery_id} 404 for missing delivery
- POST /api/v1/webhooks/dlq/replay-by-event resets deliveries and returns count
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from core.webhook_dlq import DeliveryStatus, RetryPolicy, WebhookDLQ


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_dlq(tmp_path):
    """WebhookDLQ with max_retries=2 so dead-letter is easy to trigger."""
    db_path = str(tmp_path / "replay_event.db")
    policy = RetryPolicy(max_retries=2, initial_delay_seconds=1, backoff_multiplier=2.0, max_delay_seconds=60)
    return WebhookDLQ(db_path=db_path, policy=policy)


@pytest.fixture
def tmp_dlq(tmp_path):
    db_path = str(tmp_path / "tmp.db")
    return WebhookDLQ(db_path=db_path)


@pytest.fixture
def test_app(tmp_path):
    """Minimal FastAPI app wiring the DLQ router against a temp DB."""
    from apps.api.webhook_dlq_router import router, _dlq
    import apps.api.webhook_dlq_router as dlq_mod

    # Swap the module-level _dlq singleton to a temp-DB instance
    policy = RetryPolicy(max_retries=2, initial_delay_seconds=1, backoff_multiplier=2.0, max_delay_seconds=60)
    temp_dlq = WebhookDLQ(db_path=str(tmp_path / "router.db"), policy=policy)
    dlq_mod._dlq = temp_dlq

    app = FastAPI()
    app.include_router(router)

    # Override get_org_id to return a fixed org
    from apps.api.dependencies import get_org_id
    app.dependency_overrides[get_org_id] = lambda: "org-test"

    yield TestClient(app), temp_dlq

    # Restore singleton to avoid cross-test pollution
    dlq_mod._dlq = _dlq
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Engine: replay_by_event_id
# ---------------------------------------------------------------------------


class TestReplayByEventId:
    def test_resets_all_deliveries_for_event(self, strict_dlq):
        """All deliveries for a given event_id within the org are reset to PENDING."""
        # Enqueue 3 deliveries for same event, same org
        ids = []
        for i in range(3):
            d = strict_dlq.enqueue(f"wh-{i}", "evt-shared", {}, "https://h.example.com/hook", "org-1")
            # Drive to dead_letter
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
            strict_dlq.record_attempt(d.id, success=False, error="Timeout")
            ids.append(d.id)

        count = strict_dlq.replay_by_event_id("evt-shared", "org-1")
        assert count == 3

        for did in ids:
            refreshed = strict_dlq.get_delivery(did)
            assert refreshed.status == DeliveryStatus.PENDING
            assert refreshed.attempts == 0
            assert refreshed.last_error is None

    def test_org_isolation(self, strict_dlq):
        """replay_by_event_id only touches deliveries belonging to the specified org."""
        d1 = strict_dlq.enqueue("wh-1", "evt-X", {}, "https://h.example.com/hook", "org-A")
        strict_dlq.record_attempt(d1.id, success=False, error="Err")
        strict_dlq.record_attempt(d1.id, success=False, error="Err")

        d2 = strict_dlq.enqueue("wh-2", "evt-X", {}, "https://h.example.com/hook", "org-B")
        strict_dlq.record_attempt(d2.id, success=False, error="Err")
        strict_dlq.record_attempt(d2.id, success=False, error="Err")

        # Replay only for org-A
        count = strict_dlq.replay_by_event_id("evt-X", "org-A")
        assert count == 1

        # org-B delivery must remain dead_letter
        d2_refreshed = strict_dlq.get_delivery(d2.id)
        assert d2_refreshed.status == DeliveryStatus.DEAD_LETTER

    def test_unknown_event_id_returns_zero(self, tmp_dlq):
        """Returns 0 when no deliveries match the event_id."""
        count = tmp_dlq.replay_by_event_id("evt-nonexistent", "org-1")
        assert count == 0


# ---------------------------------------------------------------------------
# Router: GET /{delivery_id}
# ---------------------------------------------------------------------------


class TestGetDeliveryEndpoint:
    def test_get_existing_delivery(self, test_app):
        client, dlq = test_app
        d = dlq.enqueue("wh-1", "evt-1", {"k": "v"}, "https://h.example.com/hook", "org-test")

        resp = client.get(f"/api/v1/webhooks/dlq/{d.id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == d.id
        assert body["event_id"] == "evt-1"
        assert body["webhook_id"] == "wh-1"
        assert body["org_id"] == "org-test"

    def test_get_missing_delivery_returns_404(self, test_app):
        client, _ = test_app
        resp = client.get("/api/v1/webhooks/dlq/nonexistent-delivery-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Router: POST /replay-by-event
# ---------------------------------------------------------------------------


class TestReplayByEventEndpoint:
    def test_replay_by_event_resets_deliveries(self, test_app):
        client, dlq = test_app
        ids = []
        for i in range(2):
            d = dlq.enqueue(f"wh-{i}", "evt-router", {}, "https://h.example.com/hook", "org-test")
            dlq.record_attempt(d.id, success=False, error="Timeout")
            dlq.record_attempt(d.id, success=False, error="Timeout")
            ids.append(d.id)

        resp = client.post("/api/v1/webhooks/dlq/replay-by-event", json={"event_id": "evt-router"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["event_id"] == "evt-router"
        assert body["replayed"] == 2

        for did in ids:
            refreshed = dlq.get_delivery(did)
            assert refreshed.status == DeliveryStatus.PENDING
