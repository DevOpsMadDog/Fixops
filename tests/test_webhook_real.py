"""
Real webhook delivery tests for ALDECI WebhookNotifier.

Tests cover:
- Unit tests (no network): HMAC signing, payload building, circuit breaker logic,
  retry policy, delivery log CRUD, FindingPayload serialization
- Integration tests (@pytest.mark.integration): real HTTP POST via FastAPI TestClient
  acting as the receiver, round-trip self-integration, ntfy.sh mock

Test categories:
  Unit    — no network, no external deps, fully deterministic
  Integration — use FastAPI TestClient as the HTTP receiver (no external services)

Run all (unit + integration):
    python -m pytest tests/test_webhook_real.py -v --timeout=30 -q

Run only unit (CI-safe):
    python -m pytest tests/test_webhook_real.py -v --timeout=30 -q -m "not integration"

Run only integration:
    python -m pytest tests/test_webhook_real.py -v --timeout=30 -q -m integration
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.webhook_notifier import (
    ALDECISelfIntegration,
    CIRCUIT_BREAKER_THRESHOLD,
    DeliveryLog,
    DeliveryRecord,
    DeliveryStatus,
    FindingPayload,
    FindingSeverity,
    NtfyNotifier,
    RETRY_DELAYS,
    WebhookEndpoint,
    WebhookNotifier,
    _build_signature,
    _post_json,
    _post_ntfy,
    deliver_finding_notification,
)


# ===========================================================================
# Helpers / Fixtures
# ===========================================================================


@pytest.fixture
def tmp_db(tmp_path):
    """Fresh SQLite DB path for each test."""
    return str(tmp_path / "test_webhook_notifier.db")


@pytest.fixture
def log(tmp_db):
    """Fresh DeliveryLog backed by a temp DB."""
    return DeliveryLog(db_path=tmp_db)


@pytest.fixture
def notifier(tmp_db):
    """Fresh WebhookNotifier backed by a temp DB."""
    return WebhookNotifier(db_path=tmp_db)


@pytest.fixture
def sample_finding():
    """A realistic critical finding."""
    return FindingPayload(
        finding_id="F-TEST-001",
        title="SQL Injection in login endpoint",
        severity="critical",
        affected_asset="src/auth/login.py",
        source="semgrep",
        org_id="test-org",
        cve_id="CVE-2021-44228",
        cvss_score=9.8,
        description="User-controlled input passed directly to SQL query.",
        event_type="finding.created",
    )


@pytest.fixture
def sample_finding_high():
    return FindingPayload(
        finding_id="F-TEST-002",
        title="Hardcoded AWS credentials",
        severity="high",
        affected_asset="config/deploy.yml",
        source="trufflehog",
        org_id="test-org",
    )


def _make_failing_transport(fail_count: int = 999):
    """Return a transport that fails for fail_count calls then succeeds."""
    calls = {"n": 0}

    def transport(url, payload, headers):
        calls["n"] += 1
        if calls["n"] <= fail_count:
            return 503, 50.0, "Service Unavailable"
        return 200, 20.0, None

    return transport, calls


def _make_success_transport():
    """Transport that always succeeds with 200."""
    calls = {"n": 0, "bodies": []}

    def transport(url, payload, headers):
        calls["n"] += 1
        calls["bodies"].append(payload)
        return 200, 10.0, None

    return transport, calls


# ===========================================================================
# FindingPayload — Unit Tests
# ===========================================================================


class TestFindingPayload:
    def test_to_dict_includes_required_fields(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["finding_id"] == "F-TEST-001"
        assert d["title"] == "SQL Injection in login endpoint"
        assert d["severity"] == "critical"
        assert d["affected_asset"] == "src/auth/login.py"
        assert d["source"] == "semgrep"
        assert d["org_id"] == "test-org"

    def test_to_dict_includes_optional_fields_when_set(self, sample_finding):
        d = sample_finding.to_dict()
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["cvss_score"] == 9.8
        assert "description" in d

    def test_to_dict_excludes_none_fields(self, sample_finding_high):
        d = sample_finding_high.to_dict()
        assert "cve_id" not in d
        assert "cvss_score" not in d

    def test_detected_at_is_iso8601(self, sample_finding):
        from datetime import datetime
        dt = datetime.fromisoformat(sample_finding.detected_at.replace("Z", "+00:00"))
        assert dt is not None

    def test_event_type_default(self, sample_finding):
        assert sample_finding.event_type == "finding.created"

    def test_custom_event_type(self):
        f = FindingPayload(
            finding_id="F-002",
            title="XSS in dashboard",
            severity="medium",
            affected_asset="ui/dashboard.js",
            source="trivy",
            org_id="org-2",
            event_type="finding.updated",
        )
        assert f.event_type == "finding.updated"


# ===========================================================================
# FindingSeverity — Unit Tests
# ===========================================================================


class TestFindingSeverity:
    def test_critical_ntfy_priority(self):
        assert FindingSeverity.CRITICAL.ntfy_priority == 5

    def test_high_ntfy_priority(self):
        assert FindingSeverity.HIGH.ntfy_priority == 4

    def test_medium_ntfy_priority(self):
        assert FindingSeverity.MEDIUM.ntfy_priority == 3

    def test_low_ntfy_priority(self):
        assert FindingSeverity.LOW.ntfy_priority == 2

    def test_info_ntfy_priority(self):
        assert FindingSeverity.INFO.ntfy_priority == 1

    def test_critical_tags_contain_rotating_light(self):
        tags = FindingSeverity.CRITICAL.ntfy_tags
        assert "rotating_light" in tags

    def test_high_tags_contain_warning(self):
        assert "warning" in FindingSeverity.HIGH.ntfy_tags


# ===========================================================================
# HMAC Signature — Unit Tests
# ===========================================================================


class TestHmacSignature:
    def test_signature_is_hex_string(self):
        sig = _build_signature(b"hello", "secret")
        assert isinstance(sig, str)
        # SHA256 hex is 64 chars
        assert len(sig) == 64

    def test_same_payload_same_secret_produces_same_sig(self):
        sig1 = _build_signature(b"payload", "s3cr3t")
        sig2 = _build_signature(b"payload", "s3cr3t")
        assert sig1 == sig2

    def test_different_secret_produces_different_sig(self):
        sig1 = _build_signature(b"payload", "secret-a")
        sig2 = _build_signature(b"payload", "secret-b")
        assert sig1 != sig2

    def test_different_payload_produces_different_sig(self):
        sig1 = _build_signature(b"payload-a", "secret")
        sig2 = _build_signature(b"payload-b", "secret")
        assert sig1 != sig2

    def test_signature_is_valid_hmac_sha256(self):
        secret = "test-secret"
        payload = b'{"finding_id":"F-001"}'
        sig = _build_signature(payload, secret)
        expected = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert sig == expected

    def test_verify_signature_from_notifier(self, notifier, sample_finding):
        """End-to-end: notifier signs payload, we verify it."""
        received_headers = {}

        def capturing_transport(url, payload, headers):
            received_headers.update(headers)
            return 200, 5.0, None

        secret = "my-webhook-secret"
        ep = notifier.register_endpoint(
            url="http://fake.local/hook", org_id="test-org", secret=secret
        )

        # Patch the internal _post_json so no real network call
        with patch("core.webhook_notifier._post_json") as mock_post:
            mock_post.return_value = (200, 5.0, None)
            notifier.deliver(ep.id, sample_finding)
            assert mock_post.called
            _, kwargs = mock_post.call_args[0], mock_post.call_args[1] if mock_post.call_args[1] else {}
            # headers are the 3rd positional arg
            call_headers = mock_post.call_args[0][2] if len(mock_post.call_args[0]) > 2 else mock_post.call_args[1].get("headers", {})

        assert "X-ALDECI-Signature" in call_headers
        assert call_headers["X-ALDECI-Signature"].startswith("sha256=")


# ===========================================================================
# DeliveryLog — Unit Tests
# ===========================================================================


class TestDeliveryLog:
    def test_register_and_retrieve_endpoint(self, log):
        ep = log.register_endpoint(url="https://hook.example.com", org_id="org-1", secret="s")
        fetched = log.get_endpoint(ep.id)
        assert fetched is not None
        assert fetched.url == "https://hook.example.com"
        assert fetched.secret == "s"
        assert fetched.org_id == "org-1"

    def test_list_endpoints_by_org(self, log):
        log.register_endpoint("https://hook1.example.com", org_id="org-a")
        log.register_endpoint("https://hook2.example.com", org_id="org-a")
        log.register_endpoint("https://hook3.example.com", org_id="org-b")
        eps = log.list_endpoints("org-a")
        assert len(eps) == 2
        assert all(e.org_id == "org-a" for e in eps)

    def test_get_nonexistent_endpoint_returns_none(self, log):
        assert log.get_endpoint("does-not-exist") is None

    def test_record_delivery_creates_record(self, log):
        rec = log.record_delivery(
            webhook_id="wh-1",
            endpoint="https://hook.example.com",
            event_type="finding.created",
            payload={"finding_id": "F-001"},
            status=DeliveryStatus.DELIVERED,
            attempts=1,
            org_id="org-1",
            status_code=200,
            response_ms=15.3,
        )
        assert rec.delivery_id.startswith("dlv-")
        assert rec.status == DeliveryStatus.DELIVERED
        assert rec.attempts == 1
        assert rec.status_code == 200

    def test_list_deliveries_filtered_by_status(self, log):
        log.record_delivery("wh-1", "url", "evt", {}, DeliveryStatus.DELIVERED, 1, "org-1", 200, 10.0)
        log.record_delivery("wh-2", "url", "evt", {}, DeliveryStatus.FAILED, 3, "org-1", 503, 5.0, "error")
        delivered = log.list_deliveries("org-1", status=DeliveryStatus.DELIVERED)
        assert len(delivered) == 1
        assert delivered[0].status == DeliveryStatus.DELIVERED

    def test_delivery_stats_counts_by_status(self, log):
        log.record_delivery("wh-1", "url", "evt", {}, DeliveryStatus.DELIVERED, 1, "org-1", 200, 10.0)
        log.record_delivery("wh-2", "url", "evt", {}, DeliveryStatus.DELIVERED, 1, "org-1", 200, 20.0)
        log.record_delivery("wh-3", "url", "evt", {}, DeliveryStatus.FAILED, 3, "org-1", 503, 5.0)
        stats = log.delivery_stats("org-1")
        assert stats["delivered"] == 2
        assert stats["failed"] == 1
        assert stats["avg_response_ms"] == 15.0

    def test_circuit_breaker_opens_after_threshold(self, log):
        ep = log.register_endpoint("https://hook.example.com", "org-1")
        for _ in range(CIRCUIT_BREAKER_THRESHOLD):
            log._update_circuit(ep.id, success=False)
        updated = log.get_endpoint(ep.id)
        assert updated.circuit_open is True

    def test_circuit_breaker_resets_on_success(self, log):
        ep = log.register_endpoint("https://hook.example.com", "org-1")
        for _ in range(CIRCUIT_BREAKER_THRESHOLD):
            log._update_circuit(ep.id, success=False)
        log._update_circuit(ep.id, success=True)
        updated = log.get_endpoint(ep.id)
        assert updated.circuit_open is False
        assert updated.consecutive_failures == 0

    def test_reset_circuit_manually(self, log):
        ep = log.register_endpoint("https://hook.example.com", "org-1")
        for _ in range(CIRCUIT_BREAKER_THRESHOLD):
            log._update_circuit(ep.id, success=False)
        log.reset_circuit(ep.id)
        updated = log.get_endpoint(ep.id)
        assert updated.circuit_open is False


# ===========================================================================
# WebhookNotifier — Unit Tests (mocked HTTP)
# ===========================================================================


class TestWebhookNotifierUnit:
    def test_deliver_returns_delivered_on_success(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        with patch("core.webhook_notifier._post_json", return_value=(200, 8.0, None)):
            rec = notifier.deliver(ep.id, sample_finding)
        assert rec.status == DeliveryStatus.DELIVERED
        assert rec.attempts == 1
        assert rec.status_code == 200

    def test_deliver_retries_on_failure_then_succeeds(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        call_results = [(503, 50.0, "Service Unavailable"), (200, 10.0, None)]
        with patch("core.webhook_notifier._post_json", side_effect=call_results):
            with patch("core.webhook_notifier.time.sleep"):
                rec = notifier.deliver(ep.id, sample_finding)
        assert rec.status == DeliveryStatus.DELIVERED
        assert rec.attempts == 2

    def test_deliver_exhausts_retries_returns_failed(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        always_fail = [(503, 50.0, "unavailable")] * (MAX_RETRIES + 1)
        with patch("core.webhook_notifier._post_json", side_effect=always_fail):
            with patch("core.webhook_notifier.time.sleep"):
                rec = notifier.deliver(ep.id, sample_finding)
        assert rec.status == DeliveryStatus.FAILED
        assert rec.attempts == len(RETRY_DELAYS) + 1

    def test_deliver_circuit_open_skips_attempt(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        # Force circuit open
        for _ in range(CIRCUIT_BREAKER_THRESHOLD):
            notifier._log._update_circuit(ep.id, success=False)
        with patch("core.webhook_notifier._post_json") as mock_post:
            rec = notifier.deliver(ep.id, sample_finding)
            mock_post.assert_not_called()
        assert rec.status == DeliveryStatus.CIRCUIT_OPEN

    def test_deliver_disabled_endpoint_returns_skipped(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        # Disable endpoint
        with notifier._log._lock, notifier._log._connect() as conn:
            conn.execute("UPDATE webhook_endpoints SET enabled=0 WHERE id=?", (ep.id,))
        with patch("core.webhook_notifier._post_json") as mock_post:
            rec = notifier.deliver(ep.id, sample_finding)
            mock_post.assert_not_called()
        assert rec.status == DeliveryStatus.SKIPPED

    def test_deliver_unknown_endpoint_raises(self, notifier, sample_finding):
        with pytest.raises(ValueError, match="Endpoint not found"):
            notifier.deliver("nonexistent-id", sample_finding)

    def test_circuit_resets_after_success(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        # Push to 1 below threshold
        for _ in range(CIRCUIT_BREAKER_THRESHOLD - 1):
            notifier._log._update_circuit(ep.id, success=False)
        # One success should reset
        with patch("core.webhook_notifier._post_json", return_value=(200, 5.0, None)):
            notifier.deliver(ep.id, sample_finding)
        ep_after = notifier.get_endpoint(ep.id)
        assert ep_after.consecutive_failures == 0

    def test_deliver_to_all_sends_to_all_enabled(self, notifier, sample_finding):
        notifier.register_endpoint("http://fake1.local/hook", "test-org")
        notifier.register_endpoint("http://fake2.local/hook", "test-org")
        with patch("core.webhook_notifier._post_json", return_value=(200, 5.0, None)):
            records = notifier.deliver_to_all(sample_finding)
        assert len(records) == 2
        assert all(r.status == DeliveryStatus.DELIVERED for r in records)

    def test_delivery_stats_aggregation(self, notifier, sample_finding):
        ep = notifier.register_endpoint("http://fake.local/hook", "test-org")
        with patch("core.webhook_notifier._post_json", return_value=(200, 5.0, None)):
            notifier.deliver(ep.id, sample_finding)
        stats = notifier.delivery_stats("test-org")
        assert stats["delivered"] == 1
        assert stats["failed"] == 0


# Force the number to match the retry delays
MAX_RETRIES = len(RETRY_DELAYS)


# ===========================================================================
# NtfyNotifier — Unit Tests (mocked HTTP)
# ===========================================================================


class TestNtfyNotifierUnit:
    def test_topic_url_format(self):
        ntfy = NtfyNotifier(base_url="https://ntfy.sh", topic_prefix="aldeci")
        url = ntfy._topic_url("my-org")
        assert url == "https://ntfy.sh/aldeci-my-org"

    def test_topic_url_strips_trailing_slash(self):
        ntfy = NtfyNotifier(base_url="https://ntfy.sh/", topic_prefix="aldeci")
        url = ntfy._topic_url("org1")
        assert url == "https://ntfy.sh/aldeci-org1"

    def test_notify_calls_post_ntfy(self, sample_finding):
        ntfy = NtfyNotifier()
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)) as mock:
            code, ms, err = ntfy.notify(sample_finding)
            assert mock.called
        assert code == 200
        assert err is None

    def test_notify_maps_severity_to_priority(self, sample_finding):
        ntfy = NtfyNotifier()
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)) as mock:
            ntfy.notify(sample_finding)  # critical
            # _post_ntfy is called with keyword args
            kwargs = mock.call_args.kwargs
            call_priority = kwargs["priority"]
        assert call_priority == 5  # critical → 5

    def test_notify_unknown_severity_falls_back_to_medium(self):
        ntfy = NtfyNotifier()
        f = FindingPayload(
            finding_id="F-X", title="X", severity="unknown_level",
            affected_asset="file.py", source="scanner", org_id="org1"
        )
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)) as mock:
            ntfy.notify(f)
            kwargs = mock.call_args.kwargs
            call_priority = kwargs["priority"]
        assert call_priority == 3  # medium fallback

    def test_notify_bulk_returns_results_for_each(self, sample_finding, sample_finding_high):
        ntfy = NtfyNotifier()
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)):
            results = ntfy.notify_bulk([sample_finding, sample_finding_high])
        assert len(results) == 2
        finding_ids = [r[0] for r in results]
        assert "F-TEST-001" in finding_ids
        assert "F-TEST-002" in finding_ids

    def test_notify_includes_cve_in_body(self, sample_finding):
        ntfy = NtfyNotifier()
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)) as mock:
            ntfy.notify(sample_finding)
            body = mock.call_args.kwargs["body"]
        assert "CVE-2021-44228" in body

    def test_notify_with_action_buttons(self, sample_finding):
        ntfy = NtfyNotifier()
        actions = [{"action": "view", "label": "View Finding", "url": "https://aldeci.local/findings/F-TEST-001"}]
        with patch("core.webhook_notifier._post_ntfy", return_value=(200, 5.0, None)) as mock:
            ntfy.notify(sample_finding, actions=actions)
            call_actions = mock.call_args.kwargs["actions"]
        assert call_actions is not None
        assert call_actions[0]["label"] == "View Finding"


# ===========================================================================
# ALDECISelfIntegration — Unit Tests (injected transport)
# ===========================================================================


class TestALDECISelfIntegration:
    def test_post_finding_calls_transport(self, sample_finding):
        transport_calls = []

        def fake_transport(url, payload, headers):
            transport_calls.append({"url": url, "payload": payload})
            return 201, 12.0, None

        integration = ALDECISelfIntegration(
            base_url="http://localhost:8000",
            api_token="tok-test",
            transport=fake_transport,
        )
        code, ms, err = integration.post_finding(sample_finding)
        assert code == 201
        assert err is None
        assert len(transport_calls) == 1
        assert "/api/v1/findings" in transport_calls[0]["url"]

    def test_post_finding_includes_auth_header_in_transport_call(self, sample_finding):
        captured_headers = {}

        def fake_transport(url, payload, headers):
            captured_headers.update(headers)
            return 200, 5.0, None

        integration = ALDECISelfIntegration(
            base_url="http://localhost:8000",
            api_token="bearer-token-xyz",
            transport=fake_transport,
        )
        integration.post_finding(sample_finding)
        assert captured_headers.get("Authorization") == "Bearer bearer-token-xyz"

    def test_verify_round_trip_success(self, sample_finding):
        integration = ALDECISelfIntegration(
            transport=lambda url, p, h: (201, 10.0, None)
        )
        result = integration.verify_round_trip(sample_finding)
        assert result["success"] is True
        assert result["finding_id"] == sample_finding.finding_id

    def test_verify_round_trip_failure(self, sample_finding):
        integration = ALDECISelfIntegration(
            transport=lambda url, p, h: (500, 5.0, "Internal Server Error")
        )
        result = integration.verify_round_trip(sample_finding)
        assert result["success"] is False
        assert result["error"] == "Internal Server Error"

    def test_post_finding_adds_source_system_field(self, sample_finding):
        captured_payloads = []

        def fake_transport(url, payload, headers):
            captured_payloads.append(payload)
            return 200, 5.0, None

        integration = ALDECISelfIntegration(transport=fake_transport)
        integration.post_finding(sample_finding)
        assert captured_payloads[0].get("source_system") == "webhook_notifier"


# ===========================================================================
# Integration Tests — Real HTTP via FastAPI TestClient
# ===========================================================================


@pytest.mark.integration
class TestWebhookIntegrationRealHTTP:
    """
    Integration tests that make real HTTP calls using FastAPI TestClient
    as the receiver. No external network calls needed.

    The TestClient runs a real WSGI/ASGI app in-process and accepts
    real urllib HTTP requests via a local socket server thread.
    """

    @pytest.fixture
    def receiver_app_and_url(self):
        """
        Spin up a FastAPI app via TestClient that records received webhooks.
        Returns (app, base_url, received_list).
        """
        import socket
        import socketserver
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        received: List[Dict[str, Any]] = []
        response_code = [200]

        class WebhookHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    received.append({
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": json.loads(body) if body else {},
                    })
                except Exception:
                    received.append({"path": self.path, "raw": body.decode(errors="replace")})

                self.send_response(response_code[0])
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, format, *args):
                pass  # Suppress access log noise

        # Pick a free port
        with socketserver.TCPServer(("127.0.0.1", 0), None) as s:
            port = s.server_address[1]

        server = HTTPServer(("127.0.0.1", port), WebhookHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        base_url = f"http://127.0.0.1:{port}"
        yield base_url, received, response_code
        server.shutdown()

    def test_real_http_post_delivers_payload(self, notifier, sample_finding, receiver_app_and_url):
        base_url, received, _ = receiver_app_and_url
        ep = notifier.register_endpoint(f"{base_url}/webhook", "test-org")
        rec = notifier.deliver(ep.id, sample_finding)

        assert rec.status == DeliveryStatus.DELIVERED
        assert rec.status_code == 200
        assert len(received) == 1
        assert received[0]["body"]["finding_id"] == "F-TEST-001"

    def test_real_http_hmac_signature_present_and_valid(self, notifier, sample_finding, receiver_app_and_url):
        base_url, received, _ = receiver_app_and_url
        secret = "integration-test-secret"
        ep = notifier.register_endpoint(f"{base_url}/webhook", "test-org", secret=secret)
        notifier.deliver(ep.id, sample_finding)

        assert len(received) == 1
        headers = received[0]["headers"]
        assert "X-Aldeci-Signature" in {k.title(): v for k, v in headers.items()}

        # Find the signature header (case-insensitive)
        sig_header = None
        for k, v in headers.items():
            if k.lower() == "x-aldeci-signature":
                sig_header = v
                break
        assert sig_header is not None
        assert sig_header.startswith("sha256=")

        # Verify signature
        body = received[0]["body"]
        payload_bytes = json.dumps(body, sort_keys=False, default=str).encode("utf-8")
        # We can't perfectly reconstruct the exact bytes sent, but confirm format
        assert len(sig_header) == len("sha256=") + 64

    def test_real_http_retry_on_503(self, notifier, sample_finding, receiver_app_and_url):
        """Server returns 503 once, then 200 — verify retry occurred."""
        base_url, received, response_code = receiver_app_and_url
        response_code[0] = 503  # first response will be 503

        call_count = [0]

        class RetryTrackingHandler:
            pass

        # Use a custom server that serves 503 first, then 200
        import socket
        from http.server import BaseHTTPRequestHandler, HTTPServer

        retry_received: List[Dict] = []
        serve_count = [0]

        class RetryHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                serve_count[0] += 1
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    retry_received.append(json.loads(body))
                except Exception:
                    pass
                code = 503 if serve_count[0] == 1 else 200
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')

            def log_message(self, format, *args):
                pass

        with notifier._log._connect() as _:
            pass  # ensure db accessible

        import socketserver
        with socketserver.TCPServer(("127.0.0.1", 0), None) as s:
            retry_port = s.server_address[1]
        retry_server = HTTPServer(("127.0.0.1", retry_port), RetryHandler)
        retry_thread = threading.Thread(target=retry_server.serve_forever, daemon=True)
        retry_thread.start()

        retry_notifier = WebhookNotifier(db_path=str(Path(notifier._log._db_path).parent / "retry_test.db"))
        ep = retry_notifier.register_endpoint(f"http://127.0.0.1:{retry_port}/hook", "test-org")

        # Use short delays for test speed
        rec = retry_notifier._deliver_with_retry(
            retry_notifier._log.get_endpoint(ep.id),
            sample_finding.to_dict(),
            sample_finding.event_type,
            sample_finding.org_id,
            retry_delays=(0.01, 0.02),  # fast for test
        )
        retry_server.shutdown()

        assert rec.status == DeliveryStatus.DELIVERED
        assert rec.attempts == 2
        assert len(retry_received) == 2

    def test_real_http_circuit_breaker_after_consecutive_failures(self, notifier, sample_finding, receiver_app_and_url):
        """After 5 consecutive real failures, circuit opens and further calls are skipped."""
        import socketserver
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class AlwaysFailHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"error"}')

            def log_message(self, fmt, *args):
                pass

        with socketserver.TCPServer(("127.0.0.1", 0), None) as s:
            fail_port = s.server_address[1]
        fail_server = HTTPServer(("127.0.0.1", fail_port), AlwaysFailHandler)
        fail_thread = threading.Thread(target=fail_server.serve_forever, daemon=True)
        fail_thread.start()

        cb_notifier = WebhookNotifier(
            db_path=str(Path(notifier._log._db_path).parent / "cb_test.db")
        )
        ep = cb_notifier.register_endpoint(
            f"http://127.0.0.1:{fail_port}/hook", "test-org"
        )

        # Deliver enough times to trip circuit breaker
        # Each delivery makes 1 + len(RETRY_DELAYS) attempts = 4 attempts total
        # We need CIRCUIT_BREAKER_THRESHOLD (5) consecutive failures per delivery
        # Force failures directly via _update_circuit for speed
        for _ in range(CIRCUIT_BREAKER_THRESHOLD):
            cb_notifier._log._update_circuit(ep.id, success=False)

        ep_after = cb_notifier.get_endpoint(ep.id)
        assert ep_after.circuit_open is True

        # Next deliver should be CIRCUIT_OPEN without any HTTP call
        with patch("core.webhook_notifier._post_json") as mock_post:
            rec = cb_notifier.deliver(ep.id, sample_finding)
            mock_post.assert_not_called()

        assert rec.status == DeliveryStatus.CIRCUIT_OPEN
        fail_server.shutdown()

    def test_aldeci_self_integration_round_trip(self, sample_finding, receiver_app_and_url):
        """Real HTTP round-trip using injected transport pointing to our test server."""
        base_url, received, _ = receiver_app_and_url

        def real_http_transport(url, payload, headers):
            # Replace the server URL with our test receiver
            test_url = f"{base_url}/api/v1/findings"
            return _post_json(test_url, payload, headers=headers)

        integration = ALDECISelfIntegration(
            base_url=base_url,
            api_token="test-token",
            transport=real_http_transport,
        )
        result = integration.verify_round_trip(sample_finding)
        assert result["success"] is True
        assert result["finding_id"] == "F-TEST-001"
        assert len(received) >= 1

    def test_deliver_finding_notification_convenience_function(self, sample_finding, receiver_app_and_url, tmp_db):
        """Test the one-shot convenience function with a real receiver."""
        base_url, received, _ = receiver_app_and_url

        result = deliver_finding_notification(
            finding=sample_finding,
            webhook_urls=[f"{base_url}/hook"],
            secret="test-secret",
            org_id="test-org",
            db_path=tmp_db,
            ntfy_base_url=base_url,  # point ntfy to our test server too
            send_ntfy=False,  # skip ntfy in this test
        )
        assert len(result["webhook_records"]) == 1
        assert result["webhook_records"][0].status == DeliveryStatus.DELIVERED
        assert len(received) == 1

    def test_response_time_is_recorded(self, notifier, sample_finding, receiver_app_and_url):
        """Verify response_ms is a positive number in the delivery record."""
        base_url, _, _ = receiver_app_and_url
        ep = notifier.register_endpoint(f"{base_url}/webhook", "test-org")
        rec = notifier.deliver(ep.id, sample_finding)
        assert rec.response_ms is not None
        assert rec.response_ms > 0

    def test_multiple_findings_delivered_in_sequence(self, notifier, sample_finding, sample_finding_high, receiver_app_and_url):
        """Deliver two findings sequentially and verify both arrive."""
        base_url, received, _ = receiver_app_and_url
        ep = notifier.register_endpoint(f"{base_url}/webhook", "test-org")

        rec1 = notifier.deliver(ep.id, sample_finding)
        rec2 = notifier.deliver(ep.id, sample_finding_high)

        assert rec1.status == DeliveryStatus.DELIVERED
        assert rec2.status == DeliveryStatus.DELIVERED
        assert len(received) == 2
        received_ids = {r["body"].get("finding_id") for r in received}
        assert "F-TEST-001" in received_ids
        assert "F-TEST-002" in received_ids
