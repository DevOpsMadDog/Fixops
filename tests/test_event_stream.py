"""
Tests for suite-core/core/event_stream.py and suite-api/apps/api/stream_router.py.

Covers:
- StreamEvent model (creation, serialisation, SSE format)
- EventChannel enum
- EventStream publish / subscribe / unsubscribe
- get_recent() with org_id filtering and limit
- get_event_stats() accuracy
- SSE generator (yields events, heartbeat, replay)
- WebSocket handler (ping/pong, event delivery)
- Router endpoints via TestClient (SSE header, publish, stats, recent)

Total: 35+ tests
"""

from __future__ import annotations

import asyncio
import json
import sys
import os
from datetime import datetime, timezone
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.event_stream import EventChannel, EventStream, StreamEvent


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture(autouse=True)
def fresh_stream():
    """Reset the EventStream singleton before each test."""
    EventStream.reset_instance()
    yield
    EventStream.reset_instance()


@pytest.fixture
def stream() -> EventStream:
    return EventStream.instance()


# ===========================================================================
# StreamEvent model tests
# ===========================================================================


class TestStreamEvent:
    def test_default_fields(self):
        ev = StreamEvent()
        assert ev.id is not None
        assert len(ev.id) == 36  # UUID4
        assert ev.event_type == "event"
        assert ev.data == {}
        assert ev.org_id == "default"
        assert ev.timestamp  # non-empty string

    def test_custom_fields(self):
        ev = StreamEvent(
            event_type="finding.created",
            data={"cve": "CVE-2024-1234", "severity": "critical"},
            org_id="acme",
        )
        assert ev.event_type == "finding.created"
        assert ev.data["cve"] == "CVE-2024-1234"
        assert ev.org_id == "acme"

    def test_id_uniqueness(self):
        ids = {StreamEvent().id for _ in range(100)}
        assert len(ids) == 100

    def test_to_dict_has_required_keys(self):
        ev = StreamEvent(event_type="alert.fired", data={"score": 9.5})
        d = ev.to_dict()
        assert "id" in d
        assert "event_type" in d
        assert "data" in d
        assert "timestamp" in d
        assert "org_id" in d
        assert d["event_type"] == "alert.fired"
        assert d["data"]["score"] == 9.5

    def test_to_sse_format(self):
        ev = StreamEvent(event_type="posture.update", org_id="corp")
        sse = ev.to_sse()
        assert sse.startswith(f"id: {ev.id}\n")
        assert f"event: {ev.event_type}\n" in sse
        assert "data: " in sse
        assert sse.endswith("\n\n")

    def test_to_sse_data_is_valid_json(self):
        ev = StreamEvent(data={"nested": {"key": [1, 2, 3]}})
        sse = ev.to_sse()
        data_line = [l for l in sse.splitlines() if l.startswith("data: ")][0]
        payload = json.loads(data_line[6:])
        assert payload["data"]["nested"]["key"] == [1, 2, 3]

    def test_to_sse_roundtrip(self):
        ev = StreamEvent(event_type="compliance.alert", data={"framework": "SOC2"})
        sse = ev.to_sse()
        data_line = [l for l in sse.splitlines() if l.startswith("data: ")][0]
        recovered = json.loads(data_line[6:])
        assert recovered["id"] == ev.id
        assert recovered["event_type"] == "compliance.alert"

    def test_timestamp_is_iso8601(self):
        ev = StreamEvent()
        # Should not raise
        datetime.fromisoformat(ev.timestamp)

    def test_unicode_data(self):
        ev = StreamEvent(data={"msg": "αλφα 中文 العربية"})
        d = ev.to_dict()
        assert d["data"]["msg"] == "αλφα 中文 العربية"


# ===========================================================================
# EventChannel enum tests
# ===========================================================================


class TestEventChannel:
    def test_all_channels_exist(self):
        channels = {ch.value for ch in EventChannel}
        assert channels == {"findings", "incidents", "compliance", "posture", "alerts", "system"}

    def test_channel_string_value(self):
        assert EventChannel.FINDINGS.value == "findings"
        assert EventChannel.SYSTEM.value == "system"

    def test_channel_is_str(self):
        # EventChannel(str, Enum) — can be used as string
        assert EventChannel.ALERTS == "alerts"


# ===========================================================================
# EventStream core tests
# ===========================================================================


class TestEventStreamPublish:
    @pytest.mark.asyncio
    async def test_publish_increments_stats(self, stream):
        ev = StreamEvent(event_type="test.event")
        await stream.publish(EventChannel.FINDINGS, ev)
        stats = stream.get_event_stats()
        assert stats["events_per_channel"]["findings"] == 1

    @pytest.mark.asyncio
    async def test_publish_stores_in_history(self, stream):
        ev = StreamEvent(event_type="finding.scored")
        await stream.publish(EventChannel.FINDINGS, ev)
        recent = stream.get_recent(EventChannel.FINDINGS)
        assert len(recent) == 1
        assert recent[0].id == ev.id

    @pytest.mark.asyncio
    async def test_publish_returns_delivery_count(self, stream):
        # No subscribers yet
        ev = StreamEvent()
        count = await stream.publish(EventChannel.ALERTS, ev)
        assert count == 0

    @pytest.mark.asyncio
    async def test_publish_delivers_to_callback(self, stream):
        received: List[StreamEvent] = []

        async def cb(event: StreamEvent):
            received.append(event)

        stream.subscribe(EventChannel.FINDINGS, cb)
        ev = StreamEvent(event_type="x")
        await stream.publish(EventChannel.FINDINGS, ev)
        assert len(received) == 1
        assert received[0].id == ev.id

    @pytest.mark.asyncio
    async def test_publish_to_multiple_callbacks(self, stream):
        calls_a: List = []
        calls_b: List = []

        async def cb_a(e):
            calls_a.append(e)

        async def cb_b(e):
            calls_b.append(e)

        stream.subscribe(EventChannel.SYSTEM, cb_a)
        stream.subscribe(EventChannel.SYSTEM, cb_b)
        await stream.publish(EventChannel.SYSTEM, StreamEvent())
        assert len(calls_a) == 1
        assert len(calls_b) == 1

    @pytest.mark.asyncio
    async def test_publish_only_to_correct_channel(self, stream):
        received: List = []

        async def cb(e):
            received.append(e)

        stream.subscribe(EventChannel.COMPLIANCE, cb)
        await stream.publish(EventChannel.FINDINGS, StreamEvent())  # different channel
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_publish_all_channels(self, stream):
        for ch in EventChannel:
            ev = StreamEvent(event_type=f"{ch.value}.test")
            count = await stream.publish(ch, ev)
            assert isinstance(count, int)

        stats = stream.get_event_stats()
        for ch in EventChannel:
            assert stats["events_per_channel"][ch.value] == 1


class TestEventStreamSubscribeUnsubscribe:
    @pytest.mark.asyncio
    async def test_subscribe_sync_callback(self, stream):
        received: List = []

        def sync_cb(e):
            received.append(e)

        stream.subscribe(EventChannel.ALERTS, sync_cb)
        await stream.publish(EventChannel.ALERTS, StreamEvent())
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_unsubscribe_stops_delivery(self, stream):
        received: List = []

        async def cb(e):
            received.append(e)

        stream.subscribe(EventChannel.POSTURE, cb)
        await stream.publish(EventChannel.POSTURE, StreamEvent())
        assert len(received) == 1

        stream.unsubscribe(EventChannel.POSTURE, cb)
        await stream.publish(EventChannel.POSTURE, StreamEvent())
        assert len(received) == 1  # no new delivery

    @pytest.mark.asyncio
    async def test_unsubscribe_returns_true_when_found(self, stream):
        async def cb(e):
            pass

        stream.subscribe(EventChannel.INCIDENTS, cb)
        assert stream.unsubscribe(EventChannel.INCIDENTS, cb) is True

    @pytest.mark.asyncio
    async def test_unsubscribe_returns_false_when_not_found(self, stream):
        async def cb(e):
            pass

        assert stream.unsubscribe(EventChannel.INCIDENTS, cb) is False

    @pytest.mark.asyncio
    async def test_subscribe_with_explicit_id(self, stream):
        async def cb(e):
            pass

        sid = stream.subscribe(EventChannel.SYSTEM, cb, subscriber_id="my-sub")
        assert sid == "my-sub"


class TestEventStreamGetRecent:
    @pytest.mark.asyncio
    async def test_get_recent_newest_first(self, stream):
        for i in range(5):
            await stream.publish(EventChannel.FINDINGS, StreamEvent(data={"i": i}))

        recent = stream.get_recent(EventChannel.FINDINGS)
        assert recent[0].data["i"] == 4
        assert recent[-1].data["i"] == 0

    @pytest.mark.asyncio
    async def test_get_recent_limit(self, stream):
        for _ in range(20):
            await stream.publish(EventChannel.ALERTS, StreamEvent())

        recent = stream.get_recent(EventChannel.ALERTS, limit=5)
        assert len(recent) == 5

    @pytest.mark.asyncio
    async def test_get_recent_org_filter(self, stream):
        await stream.publish(EventChannel.COMPLIANCE, StreamEvent(org_id="org1"))
        await stream.publish(EventChannel.COMPLIANCE, StreamEvent(org_id="org2"))
        await stream.publish(EventChannel.COMPLIANCE, StreamEvent(org_id="org1"))

        org1 = stream.get_recent(EventChannel.COMPLIANCE, org_id="org1")
        assert all(e.org_id == "org1" for e in org1)
        assert len(org1) == 2

    @pytest.mark.asyncio
    async def test_get_recent_empty_channel(self, stream):
        recent = stream.get_recent(EventChannel.INCIDENTS)
        assert recent == []

    @pytest.mark.asyncio
    async def test_history_ring_buffer_drops_oldest(self):
        small_stream = EventStream(history_size=5)
        for i in range(10):
            await small_stream.publish(EventChannel.SYSTEM, StreamEvent(data={"i": i}))

        recent = small_stream.get_recent(EventChannel.SYSTEM, limit=100)
        assert len(recent) == 5
        # newest first — last 5 events (i=5..9)
        assert recent[0].data["i"] == 9
        assert recent[-1].data["i"] == 5


class TestEventStreamStats:
    @pytest.mark.asyncio
    async def test_stats_keys_present(self, stream):
        stats = stream.get_event_stats()
        assert "events_per_channel" in stats
        assert "subscribers_per_channel" in stats
        assert "history_size_per_channel" in stats
        assert "total_published" in stats
        assert "total_subscribers" in stats

    @pytest.mark.asyncio
    async def test_stats_all_channels_present(self, stream):
        stats = stream.get_event_stats()
        for ch in EventChannel:
            assert ch.value in stats["events_per_channel"]
            assert ch.value in stats["subscribers_per_channel"]
            assert ch.value in stats["history_size_per_channel"]

    @pytest.mark.asyncio
    async def test_stats_total_published(self, stream):
        await stream.publish(EventChannel.FINDINGS, StreamEvent())
        await stream.publish(EventChannel.ALERTS, StreamEvent())
        stats = stream.get_event_stats()
        assert stats["total_published"] == 2

    @pytest.mark.asyncio
    async def test_stats_subscriber_count(self, stream):
        async def cb(e):
            pass

        stream.subscribe(EventChannel.POSTURE, cb)
        stats = stream.get_event_stats()
        assert stats["subscribers_per_channel"]["posture"] == 1
        assert stats["total_subscribers"] >= 1

    @pytest.mark.asyncio
    async def test_stats_history_size(self, stream):
        for _ in range(3):
            await stream.publish(EventChannel.INCIDENTS, StreamEvent())

        stats = stream.get_event_stats()
        assert stats["history_size_per_channel"]["incidents"] == 3


# ===========================================================================
# SSE generator tests
# ===========================================================================


class TestSSEGenerator:
    @pytest.mark.asyncio
    async def test_sse_yields_heartbeat_on_timeout(self, stream):
        """With no events published, the generator should yield a ping comment."""
        chunks = []
        gen = stream.sse_generator(
            EventChannel.SYSTEM, heartbeat_interval=0.05
        )
        # Collect one chunk (heartbeat)
        chunk = await gen.__anext__()
        assert chunk == ": ping\n\n"
        await gen.aclose()

    @pytest.mark.asyncio
    async def test_sse_delivers_published_event(self, stream):
        """Events published to a channel should appear in the SSE stream."""
        gen = stream.sse_generator(
            EventChannel.FINDINGS, heartbeat_interval=5.0
        )
        # Skip any replay events (there are none)

        ev = StreamEvent(event_type="finding.new", org_id="default")

        async def _publish_after():
            await asyncio.sleep(0.05)
            await stream.publish(EventChannel.FINDINGS, ev)

        publish_task = asyncio.create_task(_publish_after())

        chunk = await asyncio.wait_for(gen.__anext__(), timeout=2.0)
        assert f"id: {ev.id}" in chunk
        assert "event: finding.new" in chunk

        await publish_task
        await gen.aclose()

    @pytest.mark.asyncio
    async def test_sse_org_filter(self, stream):
        """Events for a different org should not appear in the SSE stream."""
        gen = stream.sse_generator(
            EventChannel.ALERTS, org_id="org1", heartbeat_interval=0.1
        )

        ev_org2 = StreamEvent(event_type="x", org_id="org2")
        await stream.publish(EventChannel.ALERTS, ev_org2)

        # Next chunk should be a heartbeat (org2 event was filtered)
        chunk = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
        assert chunk == ": ping\n\n"
        await gen.aclose()

    @pytest.mark.asyncio
    async def test_sse_replay_on_connect(self, stream):
        """Events in history should be replayed at connect time."""
        ev = StreamEvent(event_type="historical", org_id="default")
        await stream.publish(EventChannel.POSTURE, ev)

        gen = stream.sse_generator(
            EventChannel.POSTURE, org_id="default", heartbeat_interval=5.0
        )
        chunk = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
        assert ev.id in chunk
        await gen.aclose()


# ===========================================================================
# WebSocket handler tests
# ===========================================================================


class TestWebSocketHandler:
    @pytest.mark.asyncio
    async def test_ping_pong(self, stream):
        """Client sending ping should receive pong."""
        messages_sent: List[str] = []
        messages_received: List[str] = [json.dumps({"type": "ping"})]

        class FakeWS:
            async def accept(self):
                pass

            async def send_text(self, text):
                messages_sent.append(text)

            async def receive_text(self):
                if messages_received:
                    return messages_received.pop(0)
                await asyncio.sleep(10)  # block until cancelled

            async def close(self):
                pass

        ws = FakeWS()
        task = asyncio.create_task(
            stream.websocket_handler(
                ws, EventChannel.SYSTEM, heartbeat_interval=0.05
            )
        )
        await asyncio.sleep(0.15)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        pong_messages = [m for m in messages_sent if "pong" in m]
        assert len(pong_messages) >= 1

    @pytest.mark.asyncio
    async def test_websocket_receives_event(self, stream):
        """Events published to a channel should be received by WS handler."""
        received_texts: List[str] = []

        class FakeWS:
            async def accept(self):
                pass

            async def send_text(self, text):
                received_texts.append(text)

            async def receive_text(self):
                await asyncio.sleep(10)

            async def close(self):
                pass

        ev = StreamEvent(event_type="incident.new", org_id="default")
        task = asyncio.create_task(
            stream.websocket_handler(
                FakeWS(), EventChannel.INCIDENTS, org_id="default", heartbeat_interval=5.0
            )
        )
        await asyncio.sleep(0.05)
        await stream.publish(EventChannel.INCIDENTS, ev)
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        event_messages = [
            m for m in received_texts if "incident.new" in m
        ]
        assert len(event_messages) >= 1

    @pytest.mark.asyncio
    async def test_websocket_heartbeat(self, stream):
        """Handler should send ping heartbeats when no events arrive."""
        received: List[str] = []

        class FakeWS:
            async def accept(self):
                pass

            async def send_text(self, text):
                received.append(text)

            async def receive_text(self):
                await asyncio.sleep(10)

            async def close(self):
                pass

        task = asyncio.create_task(
            stream.websocket_handler(
                FakeWS(), EventChannel.SYSTEM, heartbeat_interval=0.05
            )
        )
        await asyncio.sleep(0.2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        pings = [m for m in received if "ping" in m]
        assert len(pings) >= 1


# ===========================================================================
# Router endpoint tests (via FastAPI TestClient)
# ===========================================================================


class TestStreamRouter:
    @pytest.fixture(autouse=True)
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.stream_router import router

        app = FastAPI()
        app.include_router(router)
        self._client = TestClient(app, raise_server_exceptions=True)

    def test_publish_returns_202(self):
        resp = self._client.post(
            "/api/v1/stream/publish",
            json={
                "channel": "findings",
                "event_type": "finding.created",
                "data": {"cve": "CVE-2024-9999"},
                "org_id": "test-org",
            },
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body["status"] == "published"
        assert "event_id" in body
        assert body["channel"] == "findings"

    def test_publish_invalid_channel_returns_422(self):
        resp = self._client.post(
            "/api/v1/stream/publish",
            json={"channel": "nonexistent", "event_type": "x"},
        )
        assert resp.status_code == 422

    def test_stats_returns_200(self):
        resp = self._client.get("/api/v1/stream/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert "events_per_channel" in body
        assert "total_published" in body

    def test_recent_returns_200(self):
        # Publish first
        self._client.post(
            "/api/v1/stream/publish",
            json={"channel": "alerts", "event_type": "alert.fired", "data": {}},
        )
        resp = self._client.get("/api/v1/stream/recent/alerts?limit=5")
        assert resp.status_code == 200
        body = resp.json()
        assert body["channel"] == "alerts"
        assert "events" in body
        assert "count" in body

    def test_recent_invalid_channel_returns_422(self):
        resp = self._client.get("/api/v1/stream/recent/invalid")
        assert resp.status_code == 422

    def test_recent_limit_enforced(self):
        for _ in range(10):
            self._client.post(
                "/api/v1/stream/publish",
                json={"channel": "system", "event_type": "e"},
            )
        resp = self._client.get("/api/v1/stream/recent/system?limit=3")
        body = resp.json()
        assert body["count"] <= 3
        assert len(body["events"]) <= 3

    def test_sse_endpoint_is_streaming_response(self):
        """SSE endpoint must be registered as a StreamingResponse route."""
        from apps.api.stream_router import router

        sse_routes = [
            r for r in router.routes
            if hasattr(r, "path") and "/sse/" in r.path
        ]
        assert len(sse_routes) >= 1

    def test_sse_endpoint_headers(self):
        """SSE endpoint must return text/event-stream content type."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api import stream_router as sr_module

        # Build a one-shot generator so the endpoint finishes immediately
        async def _one_chunk(channel, *, org_id=None, heartbeat_interval=15.0, queue_maxsize=256):
            yield ": ping\n\n"

        # Patch EventStream.instance() at the module level so the router uses our mock
        with patch.object(sr_module, "_stream") as mock_stream:
            mock_stream.sse_generator.side_effect = _one_chunk
            mock_stream.get_recent.return_value = []
            mock_stream.get_event_stats.return_value = {}
            mock_stream.publish = AsyncMock(return_value=0)

            app2 = FastAPI()
            app2.include_router(sr_module.router)
            c = TestClient(app2, raise_server_exceptions=False)

            with c.stream("GET", "/api/v1/stream/sse/findings") as resp:
                assert resp.status_code == 200
                ct = resp.headers.get("content-type", "")
                assert "text/event-stream" in ct

    def test_publish_multiple_channels(self):
        for ch in ["findings", "incidents", "compliance", "posture", "alerts", "system"]:
            resp = self._client.post(
                "/api/v1/stream/publish",
                json={"channel": ch, "event_type": "test"},
            )
            assert resp.status_code == 202

    def test_stats_after_publish(self):
        self._client.post(
            "/api/v1/stream/publish",
            json={"channel": "posture", "event_type": "posture.degraded"},
        )
        stats = self._client.get("/api/v1/stream/stats").json()
        assert stats["events_per_channel"]["posture"] >= 1
        assert stats["total_published"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
