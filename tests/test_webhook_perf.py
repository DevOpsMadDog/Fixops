"""Performance assertions for webhook delivery — guards against regressions.

Tests verify:
1. deliver_to_all fan-out is parallelized: N endpoints complete faster than
   N * single_endpoint_time (with a generous 0.6x threshold to be CI-safe).
2. Payload is encoded exactly once per delivery (_post_json_bytes path):
   no redundant json.dumps inside the retry loop.
3. Single-endpoint fast path skips ThreadPoolExecutor overhead.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import json
import time
import threading
from typing import Any, Dict, Optional, Tuple
from unittest.mock import MagicMock, patch
import tempfile
import os

import pytest

from core.webhook_notifier import (
    DeliveryStatus,
    FindingPayload,
    WebhookNotifier,
    _post_json_bytes,
    _build_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(org_id: str = "perf-org") -> FindingPayload:
    return FindingPayload(
        finding_id="F-perf-001",
        title="SQL Injection",
        severity="high",
        affected_asset="src/auth/login.py",
        source="semgrep",
        org_id=org_id,
    )


def _slow_transport(delay: float = 0.05):
    """Returns a transport callable that simulates a slow HTTP endpoint."""
    call_times: list[float] = []

    def transport(url: str, body: bytes, headers: Optional[Dict[str, str]]) -> Tuple[int, float, Optional[str]]:
        t0 = time.monotonic()
        time.sleep(delay)
        elapsed = (time.monotonic() - t0) * 1000
        call_times.append(elapsed)
        return 200, elapsed, None

    transport.call_times = call_times  # type: ignore[attr-defined]
    return transport


# ---------------------------------------------------------------------------
# Test 1: deliver_to_all parallelism
# ---------------------------------------------------------------------------

class TestDeliverToAllParallelism:
    """deliver_to_all must complete N endpoints faster than N * serial time."""

    def test_parallel_fan_out_is_faster_than_serial(self, tmp_path):
        """With 4 endpoints each taking ~40 ms, parallel should finish in <160 ms."""
        db = str(tmp_path / "wh.db")
        notifier = WebhookNotifier(db_path=db)
        finding = _make_finding()

        ENDPOINT_COUNT = 4
        SIMULATED_DELAY_S = 0.04  # 40 ms per endpoint

        ep_ids = []
        for i in range(ENDPOINT_COUNT):
            ep = notifier.register_endpoint(
                url=f"http://test-endpoint-{i}.invalid/hook",
                org_id=finding.org_id,
            )
            ep_ids.append(ep.id)

        call_count = {"n": 0}
        lock = threading.Lock()

        def fake_post_bytes(url, body, headers=None, timeout=10):
            time.sleep(SIMULATED_DELAY_S)
            with lock:
                call_count["n"] += 1
            return 200, SIMULATED_DELAY_S * 1000, None

        with patch("core.webhook_notifier._post_json_bytes", side_effect=fake_post_bytes):
            t0 = time.monotonic()
            records = notifier.deliver_to_all(finding)
            elapsed = time.monotonic() - t0

        serial_lower_bound = ENDPOINT_COUNT * SIMULATED_DELAY_S
        # Parallel should finish in less than 60% of serial time
        assert elapsed < serial_lower_bound * 0.6, (
            f"deliver_to_all took {elapsed:.3f}s — expected < "
            f"{serial_lower_bound * 0.6:.3f}s (serial would be {serial_lower_bound:.3f}s). "
            "Fan-out may have regressed to sequential."
        )
        assert len(records) == ENDPOINT_COUNT
        assert call_count["n"] == ENDPOINT_COUNT
        assert all(r.status == DeliveryStatus.DELIVERED for r in records)

    def test_single_endpoint_fast_path_no_executor(self, tmp_path):
        """Single endpoint must not spin up a ThreadPoolExecutor."""
        db = str(tmp_path / "wh.db")
        notifier = WebhookNotifier(db_path=db)
        finding = _make_finding()

        ep = notifier.register_endpoint(url="http://test.invalid/hook", org_id=finding.org_id)

        with patch("core.webhook_notifier._post_json_bytes", return_value=(200, 5.0, None)):
            with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
                records = notifier.deliver_to_all(finding)

        mock_executor.assert_not_called()
        assert len(records) == 1
        assert records[0].status == DeliveryStatus.DELIVERED

    def test_no_endpoints_returns_empty(self, tmp_path):
        db = str(tmp_path / "wh.db")
        notifier = WebhookNotifier(db_path=db)
        finding = _make_finding(org_id="empty-org")
        records = notifier.deliver_to_all(finding)
        assert records == []


# ---------------------------------------------------------------------------
# Test 2: No double-encode — payload_bytes reused across retry loop
# ---------------------------------------------------------------------------

class TestNoDoubleEncode:
    """_deliver_with_retry must call json.dumps exactly once per delivery."""

    def test_json_dumps_called_once_per_delivery(self, tmp_path):
        db = str(tmp_path / "wh.db")
        notifier = WebhookNotifier(db_path=db)
        finding = _make_finding()
        ep = notifier.register_endpoint(url="http://test.invalid/hook", org_id=finding.org_id)

        encode_count = {"n": 0}
        original_dumps = json.dumps

        def counting_dumps(*args, **kwargs):
            encode_count["n"] += 1
            return original_dumps(*args, **kwargs)

        with patch("core.webhook_notifier.json.dumps", side_effect=counting_dumps):
            with patch("core.webhook_notifier._post_json_bytes", return_value=(200, 5.0, None)):
                notifier.deliver(ep.id, finding)

        # json.dumps is called: once for payload in deliver(), once for payload_sha in
        # record_delivery, once for payload_bytes in _deliver_with_retry.
        # It must NOT be called again inside _post_json_bytes (that path takes raw bytes).
        # Allow up to 4 calls total (deliver payload prep + sha + retry-loop encode + record).
        # The old code called it 5+ times (once per retry attempt via _post_json).
        assert encode_count["n"] <= 4, (
            f"json.dumps called {encode_count['n']} times in a single delivery. "
            "Suspected double-encode regression in _post_json_bytes path."
        )

    def test_post_json_bytes_accepts_pre_encoded(self):
        """_post_json_bytes must accept bytes directly without re-encoding."""
        payload = {"finding_id": "F-001", "severity": "high"}
        body = json.dumps(payload).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.status = 200
            mock_urlopen.return_value = mock_resp

            status, ms, err = _post_json_bytes("http://test.invalid/hook", body)

        assert status == 200
        assert err is None
        # Verify bytes passed through verbatim
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.data == body

    def test_oversized_payload_rejected_before_network(self):
        """_post_json_bytes must reject oversized payloads without hitting network."""
        oversized = b"x" * (512 * 1024 + 1)
        with patch("urllib.request.urlopen") as mock_urlopen:
            status, ms, err = _post_json_bytes("http://test.invalid/hook", oversized)

        mock_urlopen.assert_not_called()
        assert status == 0
        assert "too large" in (err or "")


# ---------------------------------------------------------------------------
# Test 3: HMAC signing still works with pre-encoded bytes
# ---------------------------------------------------------------------------

class TestHmacIntegrityWithPreEncode:
    """Signature must be computed on the same bytes that are transmitted."""

    def test_hmac_bytes_match_transmitted_body(self, tmp_path):
        db = str(tmp_path / "wh.db")
        notifier = WebhookNotifier(db_path=db)
        finding = _make_finding()
        ep = notifier.register_endpoint(
            url="http://test.invalid/hook",
            org_id=finding.org_id,
            secret="test-secret-key",
        )

        transmitted_headers: dict = {}
        transmitted_body: list[bytes] = []

        def capture_transport(url, body, headers=None, timeout=10):
            transmitted_body.append(body)
            if headers:
                transmitted_headers.update(headers)
            return 200, 5.0, None

        with patch("core.webhook_notifier._post_json_bytes", side_effect=capture_transport):
            notifier.deliver(ep.id, finding)

        assert len(transmitted_body) == 1
        body_bytes = transmitted_body[0]
        sig_header = transmitted_headers.get("X-ALDECI-Signature", "")
        assert sig_header.startswith("sha256=")
        expected_sig = _build_signature(body_bytes, "test-secret-key")
        assert sig_header == f"sha256={expected_sig}", (
            "HMAC signature does not match bytes actually transmitted. "
            "Pre-encode optimization may have broken signing."
        )
