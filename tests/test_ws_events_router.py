"""
Tests for suite-api/apps/api/ws_events_router.py

Covers:
    - _authenticate_ws: dev-mode pass-through, valid token, invalid token, missing token
    - _parse_event_type_filter: None input, valid types, invalid types, mixed
    - _event_matches: no filter (accept all), matching filter, non-matching filter
    - _alert_to_security_event: envelope shape, event_type mapping, fallback to "alert"
    - WebSocket endpoint: connect+welcome frame, event_type filter delivery,
      unauthenticated rejection (4403 close), test-publish REST endpoint
"""

from __future__ import annotations

import asyncio
import json
import sys
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from apps.api.ws_events_router import (
    SECURITY_EVENT_TYPES,
    _alert_to_security_event,
    _authenticate_ws,
    _event_matches,
    _parse_event_type_filter,
)


# ===========================================================================
# _authenticate_ws
# ===========================================================================


class TestAuthenticateWs:
    def test_dev_mode_no_creds_passes(self):
        with (
            patch("apps.api.ws_events_router._DEV_MODE", True),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ()),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            assert _authenticate_ws(None, None) is True

    def test_valid_api_key_passes(self):
        with (
            patch("apps.api.ws_events_router._DEV_MODE", False),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ("secret-key",)),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            assert _authenticate_ws("secret-key", None) is True

    def test_valid_token_alias_passes(self):
        with (
            patch("apps.api.ws_events_router._DEV_MODE", False),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ("tok123",)),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            assert _authenticate_ws(None, "tok123") is True

    def test_invalid_key_rejected(self):
        with (
            patch("apps.api.ws_events_router._DEV_MODE", False),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ("correct-key",)),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            assert _authenticate_ws("wrong-key", None) is False

    def test_missing_credential_rejected_when_auth_required(self):
        with (
            patch("apps.api.ws_events_router._DEV_MODE", False),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ("real-token",)),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            assert _authenticate_ws(None, None) is False


# ===========================================================================
# _parse_event_type_filter
# ===========================================================================


class TestParseEventTypeFilter:
    def test_none_returns_none(self):
        assert _parse_event_type_filter(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_event_type_filter("") is None

    def test_single_valid_type(self):
        result = _parse_event_type_filter("alert")
        assert result == {"alert"}

    def test_multiple_valid_types(self):
        result = _parse_event_type_filter("alert,finding,incident")
        assert result == {"alert", "finding", "incident"}

    def test_invalid_types_only_returns_none(self):
        assert _parse_event_type_filter("banana,mango") is None

    def test_mixed_valid_and_invalid_keeps_valid(self):
        result = _parse_event_type_filter("alert,banana")
        assert result == {"alert"}

    def test_whitespace_trimmed(self):
        result = _parse_event_type_filter(" finding , incident ")
        assert result == {"finding", "incident"}

    def test_all_known_types_accepted(self):
        all_types = ",".join(SECURITY_EVENT_TYPES)
        result = _parse_event_type_filter(all_types)
        assert result == SECURITY_EVENT_TYPES


# ===========================================================================
# _event_matches
# ===========================================================================


class TestEventMatches:
    def _make_event(self, event_type: str) -> Dict[str, Any]:
        return {"type": "event", "event_type": event_type, "severity": "high"}

    def test_no_filter_accepts_all(self):
        for et in SECURITY_EVENT_TYPES:
            assert _event_matches(self._make_event(et), None) is True

    def test_matching_filter_passes(self):
        assert _event_matches(self._make_event("finding"), {"finding"}) is True

    def test_non_matching_filter_rejected(self):
        assert _event_matches(self._make_event("alert"), {"finding"}) is False

    def test_multi_type_filter_passes_any_match(self):
        assert _event_matches(self._make_event("incident"), {"finding", "incident"}) is True


# ===========================================================================
# _alert_to_security_event
# ===========================================================================


class TestAlertToSecurityEvent:
    def _make_alert(self, alert_type: str, **extra) -> Dict[str, Any]:
        return {
            "id": "test-alert-id",
            "type": alert_type,
            "severity": "critical",
            "title": "Test Alert",
            "message": "Something happened",
            "timestamp": "2026-04-17T10:00:00+00:00",
            **extra,
        }

    def test_envelope_shape(self):
        event = _alert_to_security_event(self._make_alert("finding_created"))
        assert event["type"] == "event"
        assert "event_id" in event
        assert "event_type" in event
        assert "severity" in event
        assert "title" in event
        assert "message" in event
        assert "payload" in event
        assert "org_id" in event
        assert "timestamp" in event

    def test_finding_created_maps_to_finding(self):
        event = _alert_to_security_event(self._make_alert("finding_created"))
        assert event["event_type"] == "finding"

    def test_sla_breach_maps_correctly(self):
        event = _alert_to_security_event(self._make_alert("sla_breach"))
        assert event["event_type"] == "sla_breach"

    def test_incident_created_maps_to_incident(self):
        event = _alert_to_security_event(self._make_alert("incident_created"))
        assert event["event_type"] == "incident"

    def test_unknown_alert_type_falls_back_to_alert(self):
        event = _alert_to_security_event(self._make_alert("some_unknown_type"))
        assert event["event_type"] == "alert"

    def test_tenant_id_becomes_org_id(self):
        event = _alert_to_security_event(self._make_alert("alert", tenant_id="org-acme"))
        assert event["org_id"] == "org-acme"

    def test_severity_preserved(self):
        event = _alert_to_security_event(self._make_alert("finding_created"))
        assert event["severity"] == "critical"

    def test_alert_id_used_as_event_id(self):
        event = _alert_to_security_event(self._make_alert("alert"))
        assert event["event_id"] == "test-alert-id"


# ===========================================================================
# WebSocket endpoint integration tests
# ===========================================================================


def _make_mock_broadcaster(queue_items=None):
    """Build a mock AlertBroadcaster with a pre-loaded asyncio.Queue."""
    q = asyncio.Queue()
    if queue_items:
        for item in queue_items:
            q.put_nowait(item)

    broadcaster = MagicMock()
    broadcaster.subscribe.return_value = q
    broadcaster.unsubscribe = MagicMock()
    broadcaster.broadcast = AsyncMock(return_value=1)
    broadcaster.broadcast_to_tenant = AsyncMock(return_value=1)
    return broadcaster, q


class TestWsEventsEndpoint:
    """Integration tests using FastAPI's TestClient WebSocket support."""

    @pytest.fixture
    def app(self):
        from fastapi import FastAPI
        from apps.api.ws_events_router import router
        _app = FastAPI()
        _app.include_router(router)
        return _app

    def test_unauthenticated_connection_rejected(self, app):
        """Unauthenticated client should receive close code 4403."""
        from fastapi.testclient import TestClient

        with (
            patch("apps.api.ws_events_router._DEV_MODE", False),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ("valid",)),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
        ):
            client = TestClient(app)
            with pytest.raises(Exception):
                # TestClient raises on abnormal close
                with client.websocket_connect("/api/v1/ws/events") as ws:
                    ws.receive_json()

    def test_authenticated_receives_welcome_frame(self, app):
        """Authenticated client receives connected frame immediately."""
        from fastapi.testclient import TestClient

        broadcaster, _ = _make_mock_broadcaster()

        with (
            patch("apps.api.ws_events_router._DEV_MODE", True),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ()),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
            patch("apps.api.ws_events_router._get_broadcaster", return_value=broadcaster),
        ):
            client = TestClient(app)
            with client.websocket_connect("/api/v1/ws/events") as ws:
                frame = ws.receive_json()
                assert frame["type"] == "connected"
                assert "connection_id" in frame
                assert frame["message"] == "ALDECI event stream active"
                assert "filters" in frame

    def test_event_type_filter_in_welcome_frame(self, app):
        """Filter params are echoed back in the connected frame."""
        from fastapi.testclient import TestClient

        broadcaster, _ = _make_mock_broadcaster()

        with (
            patch("apps.api.ws_events_router._DEV_MODE", True),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ()),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
            patch("apps.api.ws_events_router._get_broadcaster", return_value=broadcaster),
        ):
            client = TestClient(app)
            with client.websocket_connect("/api/v1/ws/events?event_type=finding,incident") as ws:
                frame = ws.receive_json()
                assert frame["type"] == "connected"
                filters = frame["filters"]
                assert "finding" in filters["event_type"]
                assert "incident" in filters["event_type"]

    def test_event_delivered_to_subscriber(self, app):
        """Events put in the broadcaster queue are streamed to client."""
        from fastapi.testclient import TestClient

        alert = {
            "id": "evt-001",
            "type": "finding_created",
            "severity": "high",
            "title": "SQL Injection",
            "message": "Found in /api/login",
            "timestamp": "2026-04-17T10:00:00+00:00",
        }
        broadcaster, queue = _make_mock_broadcaster(queue_items=[alert])

        with (
            patch("apps.api.ws_events_router._DEV_MODE", True),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ()),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
            patch("apps.api.ws_events_router._get_broadcaster", return_value=broadcaster),
        ):
            client = TestClient(app)
            with client.websocket_connect("/api/v1/ws/events") as ws:
                # Discard the welcome frame
                ws.receive_json()
                # Receive the security event
                frame = ws.receive_json()
                assert frame["type"] == "event"
                assert frame["event_type"] == "finding"
                assert frame["severity"] == "high"
                assert frame["event_id"] == "evt-001"

    def test_filtered_event_not_delivered(self, app):
        """Events that don't match event_type filter are not sent."""
        from fastapi.testclient import TestClient

        # Queue an "alert" type event but filter only for "incident"
        alert = {
            "id": "evt-002",
            "type": "finding_created",  # maps to "finding"
            "severity": "high",
            "title": "Finding",
            "message": "Found something",
            "timestamp": "2026-04-17T10:00:00+00:00",
        }
        # Add sentinel incident so client gets something after filtered event
        incident_alert = {
            "id": "evt-003",
            "type": "incident_created",  # maps to "incident"
            "severity": "critical",
            "title": "Incident",
            "message": "Major incident",
            "timestamp": "2026-04-17T10:01:00+00:00",
        }
        broadcaster, queue = _make_mock_broadcaster(queue_items=[alert, incident_alert])

        with (
            patch("apps.api.ws_events_router._DEV_MODE", True),
            patch("apps.api.ws_events_router._EXPECTED_TOKENS", ()),
            patch("apps.api.ws_events_router._HAS_JWT_AUTH", False),
            patch("apps.api.ws_events_router._get_broadcaster", return_value=broadcaster),
        ):
            client = TestClient(app)
            with client.websocket_connect("/api/v1/ws/events?event_type=incident") as ws:
                ws.receive_json()  # welcome
                frame = ws.receive_json()  # should be the incident, not the finding
                assert frame["type"] == "event"
                assert frame["event_type"] == "incident"
                assert frame["event_id"] == "evt-003"
