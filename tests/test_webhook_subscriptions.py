"""
Tests for webhook subscriptions router.

Covers: CRUD, SSRF protection, HMAC signing, event validation,
org_id scoping, failure tracking, delivery engine, input validation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite paths are available
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk", "suite-integrations"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
from apps.api.webhook_subscriptions_router import (
    ALLOWED_EVENT_TYPES,
    CreateSubscriptionRequest,
    UpdateSubscriptionRequest,
    _get_db,
    _is_private_ip,
    _row_to_dict,
    _sign_payload,
    _validate_sub_id,
    _validate_webhook_url,
    dispatch_event,
    router,
)
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Pydantic Model Tests
# ---------------------------------------------------------------------------

class TestCreateSubscriptionRequest:
    def test_valid_request(self):
        req = CreateSubscriptionRequest(
            url="https://example.com/webhook",
            events=["finding.created", "sla.breach"],
        )
        assert req.url == "https://example.com/webhook"
        assert set(req.events) <= ALLOWED_EVENT_TYPES
        assert req.max_retries == 3

    def test_http_rejected(self):
        with pytest.raises(Exception):  # Pydantic ValidationError
            CreateSubscriptionRequest(url="http://example.com/hook", events=["finding.created"])

    def test_invalid_event_type(self):
        with pytest.raises(Exception):
            CreateSubscriptionRequest(url="https://example.com/hook", events=["bogus.event"])

    def test_empty_events_rejected(self):
        with pytest.raises(Exception):
            CreateSubscriptionRequest(url="https://example.com/hook", events=[])

    def test_deduplicates_events(self):
        req = CreateSubscriptionRequest(
            url="https://example.com/hook",
            events=["finding.created", "finding.created", "sla.breach"],
        )
        assert len(req.events) == 2

    def test_max_retries_range(self):
        req = CreateSubscriptionRequest(url="https://example.com/hook", events=["finding.created"], max_retries=0)
        assert req.max_retries == 0
        with pytest.raises(Exception):
            CreateSubscriptionRequest(url="https://example.com/hook", events=["finding.created"], max_retries=11)

    def test_no_hostname_rejected(self):
        with pytest.raises(Exception):
            CreateSubscriptionRequest(url="https:///path", events=["finding.created"])

    def test_url_stripped(self):
        req = CreateSubscriptionRequest(url="  https://example.com/hook  ", events=["finding.created"])
        assert req.url == "https://example.com/hook"


class TestUpdateSubscriptionRequest:
    def test_all_none_is_valid(self):
        # The model itself allows all-None; endpoint logic checks for no-op
        req = UpdateSubscriptionRequest()
        assert req.url is None
        assert req.events is None

    def test_http_rejected(self):
        with pytest.raises(Exception):
            UpdateSubscriptionRequest(url="http://bad.com")

    def test_valid_partial_update(self):
        req = UpdateSubscriptionRequest(active=False, max_retries=5)
        assert req.active is False
        assert req.max_retries == 5


# ---------------------------------------------------------------------------
# SSRF Protection Tests
# ---------------------------------------------------------------------------

class TestSSRFProtection:
    def test_http_blocked(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_webhook_url("http://example.com/hook")
        assert exc_info.value.status_code == 422

    def test_localhost_blocked(self):
        for host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            with pytest.raises(HTTPException) as exc_info:
                _validate_webhook_url(f"https://{host}/hook")
            assert exc_info.value.status_code == 422

    def test_private_ip_10x_blocked(self):
        with pytest.raises(HTTPException):
            _validate_webhook_url("https://10.0.0.1/hook")

    def test_private_ip_172_blocked(self):
        with pytest.raises(HTTPException):
            _validate_webhook_url("https://172.16.0.1/hook")

    def test_private_ip_192_blocked(self):
        with pytest.raises(HTTPException):
            _validate_webhook_url("https://192.168.1.1/hook")

    def test_metadata_ip_blocked(self):
        with pytest.raises(HTTPException):
            _validate_webhook_url("https://169.254.169.254/latest/meta-data")

    def test_no_hostname_blocked(self):
        with pytest.raises(HTTPException):
            _validate_webhook_url("https:///path")

    def test_is_private_ip_unresolvable(self):
        # Unresolvable hostnames should be treated as private (blocked)
        assert _is_private_ip("this-host-does-not-exist-xyzzy.invalid") is True

    def test_is_private_ip_loopback(self):
        assert _is_private_ip("127.0.0.1") is True


# ---------------------------------------------------------------------------
# HMAC Signing Tests
# ---------------------------------------------------------------------------

class TestHMACSigning:
    def test_sign_payload_deterministic(self):
        secret = "test-secret-key"
        body = b'{"event": "test"}'
        sig1 = _sign_payload(secret, body)
        sig2 = _sign_payload(secret, body)
        assert sig1 == sig2
        assert len(sig1) == 64  # SHA256 hex digest

    def test_sign_payload_matches_stdlib(self):
        secret = "my-secret"
        body = b'{"hello": "world"}'
        expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        assert _sign_payload(secret, body) == expected

    def test_different_secrets_different_sigs(self):
        body = b"same-body"
        sig1 = _sign_payload("secret-a", body)
        sig2 = _sign_payload("secret-b", body)
        assert sig1 != sig2

    def test_different_bodies_different_sigs(self):
        secret = "same-secret"
        sig1 = _sign_payload(secret, b"body-a")
        sig2 = _sign_payload(secret, b"body-b")
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# Subscription ID Validation Tests
# ---------------------------------------------------------------------------

class TestSubIdValidation:
    def test_valid_uuid(self):
        uid = str(uuid.uuid4())
        assert _validate_sub_id(uid) == uid.lower()

    def test_invalid_format_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _validate_sub_id("not-a-uuid")
        assert exc_info.value.status_code == 422

    def test_sql_injection_rejected(self):
        with pytest.raises(HTTPException):
            _validate_sub_id("'; DROP TABLE subscriptions; --")

    def test_path_traversal_rejected(self):
        with pytest.raises(HTTPException):
            _validate_sub_id("../../etc/passwd")

    def test_strips_whitespace(self):
        uid = str(uuid.uuid4())
        assert _validate_sub_id(f"  {uid}  ") == uid.lower()


# ---------------------------------------------------------------------------
# Database Tests
# ---------------------------------------------------------------------------

class TestDatabase:
    def test_schema_creation(self):
        """Verify DB creates tables correctly."""
        with patch("apps.api.webhook_subscriptions_router._DB_PATH") as mock_path:
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
                mock_path.__str__ = lambda s: f.name
            try:
                conn = _get_db()
                # Check tables exist
                tables = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                table_names = {t[0] for t in tables}
                assert "subscriptions" in table_names
                assert "delivery_log" in table_names
                conn.close()
            finally:
                os.unlink(f.name)

    def test_row_to_dict_events_parsed(self):
        """Verify _row_to_dict parses JSON events field."""
        # Create a mock row
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE t (events TEXT, active INTEGER)")
        conn.execute("INSERT INTO t VALUES (?, ?)", (json.dumps(["finding.created"]), 1))
        row = conn.execute("SELECT * FROM t").fetchone()
        result = _row_to_dict(row)
        assert result["events"] == ["finding.created"]
        assert result["active"] is True
        conn.close()

    def test_row_to_dict_inactive(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE t (events TEXT, active INTEGER)")
        conn.execute("INSERT INTO t VALUES (?, ?)", ("[]", 0))
        row = conn.execute("SELECT * FROM t").fetchone()
        result = _row_to_dict(row)
        assert result["active"] is False
        conn.close()


# ---------------------------------------------------------------------------
# Event Types Tests
# ---------------------------------------------------------------------------

class TestEventTypes:
    def test_all_expected_events_present(self):
        expected = {
            "finding.created", "finding.critical", "finding.resolved",
            "sla.breach", "pipeline.completed", "autofix.applied",
            "compliance.violation", "attack_path.discovered",
        }
        assert ALLOWED_EVENT_TYPES == expected

    def test_event_types_is_frozenset(self):
        assert isinstance(ALLOWED_EVENT_TYPES, frozenset)


# ---------------------------------------------------------------------------
# Dispatch Tests (with mocked delivery)
# ---------------------------------------------------------------------------

class TestDispatchEvent:
    def test_unknown_event_returns_empty(self):
        results = dispatch_event("bogus.event", {"data": 1}, "org-1")
        assert results == []

    def test_no_subscriptions_returns_empty(self):
        # Use a unique org_id that has no subscriptions
        results = dispatch_event("finding.created", {"data": 1}, f"nonexistent-{uuid.uuid4()}")
        assert results == []


# ---------------------------------------------------------------------------
# Router Structure Tests
# ---------------------------------------------------------------------------

class TestRouterStructure:
    def test_router_prefix(self):
        assert router.prefix == "/api/v1/webhook-subscriptions"

    def test_router_has_health_endpoint(self):
        paths = [r.path for r in router.routes if hasattr(r, "path")]
        assert any("/health" in p for p in paths)

    def test_router_has_status_endpoint(self):
        paths = [r.path for r in router.routes if hasattr(r, "path")]
        assert any("/status" in p for p in paths)

    def test_router_has_crud_endpoints(self):
        paths = [r.path for r in router.routes if hasattr(r, "path")]
        assert any(p.endswith("/") for p in paths)
        assert any("{sub_id}" in p for p in paths)
        assert any("/test" in p for p in paths)

    def test_router_endpoint_count(self):
        # health, status, create, list, get, update, delete, test = 8 routes
        paths = [r.path for r in router.routes if hasattr(r, "path")]
        assert len(paths) >= 8

    def test_router_tags(self):
        assert "webhook-subscriptions" in router.tags


# ---------------------------------------------------------------------------
# Delivery Engine Tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestDeliverWebhook:
    def test_successful_delivery(self):
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "test-secret"}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            result = _deliver_webhook(sub, "finding.created", {"title": "CVE-2024-1234"})
        assert result["status"] == "success"
        assert result["response_code"] == 200
        assert result["delivery_id"]  # UUID present
        assert result["error"] is None

    def test_failed_delivery_4xx(self):
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "s"}
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        with patch("requests.post", return_value=mock_resp):
            result = _deliver_webhook(sub, "finding.created", {"data": 1})
        assert result["status"] == "failed"
        assert result["response_code"] == 403
        assert result["error"] == "HTTP 403"

    def test_timeout_delivery(self):
        import requests
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "s"}
        with patch("requests.post", side_effect=requests.Timeout("timed out")):
            result = _deliver_webhook(sub, "finding.created", {"data": 1})
        assert result["status"] == "failed"
        assert result["error"] == "Timeout"

    def test_connection_error_delivery(self):
        import requests
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "s"}
        with patch("requests.post", side_effect=requests.ConnectionError("refused")):
            result = _deliver_webhook(sub, "finding.created", {"data": 1})
        assert result["status"] == "failed"
        assert result["error"] == "ConnectionError"

    def test_hmac_signature_in_headers(self):
        """Verify the HMAC signature sent matches what we compute independently."""
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "verify-me"}
        captured_headers = {}

        def capture_post(url, data=None, headers=None, **kwargs):
            captured_headers.update(headers or {})
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("requests.post", side_effect=capture_post):
            _deliver_webhook(sub, "finding.created", {"test": True})

        assert "X-ALdeci-Signature" in captured_headers
        assert captured_headers["X-ALdeci-Signature"].startswith("sha256=")
        assert "X-ALdeci-Event" in captured_headers
        assert captured_headers["X-ALdeci-Event"] == "finding.created"
        assert "X-ALdeci-Delivery-ID" in captured_headers

        # Verify the signature is correct
        sig_hex = captured_headers["X-ALdeci-Signature"].removeprefix("sha256=")
        body = json.dumps({"test": True}, default=str).encode("utf-8")
        expected = hmac.new(b"verify-me", body, hashlib.sha256).hexdigest()
        assert sig_hex == expected

    def test_no_redirects_followed(self):
        """Verify allow_redirects=False to prevent SSRF via redirect."""
        from apps.api.webhook_subscriptions_router import _deliver_webhook
        sub = {"id": str(uuid.uuid4()), "url": "https://example.com/hook", "secret": "s"}
        captured_kwargs: Dict[str, Any] = {}

        def capture_post(*args, **kwargs):
            captured_kwargs.update(kwargs)
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("requests.post", side_effect=capture_post):
            _deliver_webhook(sub, "test", {"data": 1})
        assert captured_kwargs.get("allow_redirects") is False
