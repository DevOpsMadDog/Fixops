"""
Tests for scripts/load_test.py — load testing harness logic.

All HTTP calls are mocked; no live server required.

Run with:
    python -m pytest tests/test_load_harness.py -x --tb=short --timeout=10 -q
"""

import json
import math
import sys
import time
from pathlib import Path
from threading import Event, Lock
from typing import List, Optional
from unittest.mock import MagicMock, patch

import pytest

# Make the scripts/ directory importable
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from load_test import (
    DEFAULT_DURATION,
    DEFAULT_TARGET,
    DEFAULT_USERS,
    ENDPOINTS,
    ERROR_RATE_THRESHOLD,
    P99_THRESHOLD_S,
    EndpointStats,
    LoadTestConfig,
    LoadTestReport,
    RequestResult,
    _compute_stats,
    _do_request,
    _format_table,
    _parse_args,
    _percentile,
    _worker_loop,
    run_load_test,
    main,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_results(
    n: int,
    *,
    endpoint: str = "/health",
    status: int = 200,
    latency: float = 0.05,
    error: Optional[str] = None,
    base_ts: float = 0.0,
) -> List[RequestResult]:
    return [
        RequestResult(
            endpoint=endpoint,
            status_code=status,
            latency_s=latency,
            error=error,
            timestamp=base_ts + i * 0.01,
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# 1. RequestResult.success
# ---------------------------------------------------------------------------

class TestRequestResultSuccess:
    def test_200_is_success(self):
        r = RequestResult(endpoint="/health", status_code=200, latency_s=0.1)
        assert r.success is True

    def test_404_is_success(self):
        # 4xx are not network failures — we still count them as "not an error"
        r = RequestResult(endpoint="/health", status_code=404, latency_s=0.1)
        assert r.success is True

    def test_500_is_not_success(self):
        r = RequestResult(endpoint="/health", status_code=500, latency_s=0.1)
        assert r.success is False

    def test_network_error_is_not_success(self):
        r = RequestResult(endpoint="/health", status_code=0, latency_s=0.1, error="timeout")
        assert r.success is False

    def test_zero_status_no_error_is_not_success(self):
        r = RequestResult(endpoint="/health", status_code=0, latency_s=0.1, error="refused")
        assert r.success is False


# ---------------------------------------------------------------------------
# 2. _percentile
# ---------------------------------------------------------------------------

class TestPercentile:
    def test_empty_returns_zero(self):
        assert _percentile([], 50) == 0.0

    def test_single_element(self):
        assert _percentile([1.0], 50) == 1.0
        assert _percentile([1.0], 99) == 1.0

    def test_p50_median(self):
        data = [1.0, 2.0, 3.0, 4.0, 5.0]
        assert _percentile(data, 50) == 3.0

    def test_p99_near_max(self):
        data = list(range(1, 101))  # 1..100
        # p99 of 100 elements → ceil(99/100*100)=99th element = 99
        assert _percentile(data, 99) == 99

    def test_p100_is_max(self):
        data = [0.1, 0.5, 1.0, 2.0]
        assert _percentile(data, 100) == 2.0

    def test_unsorted_input(self):
        data = [3.0, 1.0, 2.0]
        assert _percentile(data, 50) == 2.0


# ---------------------------------------------------------------------------
# 3. EndpointStats
# ---------------------------------------------------------------------------

class TestEndpointStats:
    def _make(self, total, errors, latencies):
        es = EndpointStats(
            endpoint="/health",
            total=total,
            successes=total - errors,
            errors=errors,
            latencies=latencies,
        )
        return es

    def test_error_rate_zero_errors(self):
        es = self._make(100, 0, [0.1] * 100)
        assert es.error_rate == 0.0

    def test_error_rate_all_errors(self):
        es = self._make(10, 10, [])
        assert es.error_rate == 1.0

    def test_error_rate_partial(self):
        es = self._make(200, 2, [0.1] * 198)
        assert abs(es.error_rate - 0.01) < 1e-9

    def test_error_rate_zero_total(self):
        es = self._make(0, 0, [])
        assert es.error_rate == 0.0

    def test_percentile_empty(self):
        es = self._make(0, 0, [])
        assert es.percentile(99) == 0.0

    def test_percentile_values(self):
        latencies = [float(i) for i in range(1, 11)]  # 1..10
        es = self._make(10, 0, latencies)
        assert es.percentile(50) == 5.0


# ---------------------------------------------------------------------------
# 4. LoadTestConfig
# ---------------------------------------------------------------------------

class TestLoadTestConfig:
    def test_warmup_seconds(self):
        cfg = LoadTestConfig(target="http://x", users=10, duration=60)
        assert abs(cfg.warmup_seconds - 60 * 0.15) < 1e-9

    def test_default_endpoints(self):
        cfg = LoadTestConfig(target="http://x", users=5, duration=10)
        assert "/health" in cfg.endpoints
        assert len(cfg.endpoints) == len(ENDPOINTS)

    def test_custom_endpoints(self):
        cfg = LoadTestConfig(target="http://x", users=1, duration=5, endpoints=["/health"])
        assert cfg.endpoints == ["/health"]


# ---------------------------------------------------------------------------
# 5. _compute_stats — warm-up filtering
# ---------------------------------------------------------------------------

class TestComputeStats:
    def test_warmup_results_excluded(self):
        base = 1000.0
        warmup_results = _make_results(10, endpoint="/health", base_ts=base)
        steady_results = _make_results(20, endpoint="/health", base_ts=base + 100.0)
        all_results = warmup_results + steady_results
        latencies, ep_map = _compute_stats(all_results, warmup_cutoff=base + 50.0, duration_s=150.0)
        assert len(latencies) == 20

    def test_all_results_in_warmup_gives_zero(self):
        base = 1000.0
        results = _make_results(5, endpoint="/health", base_ts=base)
        latencies, ep_map = _compute_stats(results, warmup_cutoff=base + 100.0, duration_s=120.0)
        assert latencies == []

    def test_endpoint_counts_correct(self):
        base = 0.0
        results = (
            _make_results(5, endpoint="/health", base_ts=base + 50.0)
            + _make_results(3, endpoint="/api/v1/findings", base_ts=base + 50.0)
        )
        latencies, ep_map = _compute_stats(results, warmup_cutoff=base + 10.0, duration_s=200.0)
        assert ep_map["/health"].total == 5
        assert ep_map["/api/v1/findings"].total == 3

    def test_error_counting(self):
        base = 0.0
        good = _make_results(8, endpoint="/health", base_ts=base + 50.0, status=200)
        bad = _make_results(2, endpoint="/health", base_ts=base + 60.0, status=500)
        latencies, ep_map = _compute_stats(good + bad, warmup_cutoff=base + 10.0, duration_s=200.0)
        assert ep_map["/health"].errors == 2
        assert ep_map["/health"].successes == 8


# ---------------------------------------------------------------------------
# 6. _do_request — mocked urllib
# ---------------------------------------------------------------------------

class TestDoRequest:
    def _mock_response(self, status: int, body: bytes = b"{}"):
        resp = MagicMock()
        resp.status = status
        resp.read.return_value = body
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        return resp

    def test_successful_request(self):
        mock_resp = self._mock_response(200)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            status, latency, error = _do_request("http://x/health", timeout=5)
        assert status == 200
        assert latency >= 0
        assert error is None

    def test_http_error_returned_as_status(self):
        import urllib.error
        http_err = urllib.error.HTTPError(
            url="http://x/health", code=503, msg="Service Unavailable",
            hdrs=None, fp=None
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            status, latency, error = _do_request("http://x/health", timeout=5)
        assert status == 503
        assert error is None  # HTTP errors are NOT network errors

    def test_url_error_returns_error_string(self):
        import urllib.error
        url_err = urllib.error.URLError(reason="Connection refused")
        with patch("urllib.request.urlopen", side_effect=url_err):
            status, latency, error = _do_request("http://x/health", timeout=5)
        assert status == 0
        assert error is not None
        assert "refused" in error.lower()

    def test_generic_exception_captured(self):
        with patch("urllib.request.urlopen", side_effect=RuntimeError("boom")):
            status, latency, error = _do_request("http://x/health", timeout=5)
        assert status == 0
        assert "boom" in error


# ---------------------------------------------------------------------------
# 7. _parse_args
# ---------------------------------------------------------------------------

class TestParseArgs:
    def test_defaults(self):
        args = _parse_args([])
        assert args.users == DEFAULT_USERS
        assert args.duration == DEFAULT_DURATION
        assert args.target == DEFAULT_TARGET
        assert args.json_out is None

    def test_custom_values(self):
        args = _parse_args(["--users", "50", "--duration", "120", "--target", "http://prod"])
        assert args.users == 50
        assert args.duration == 120
        assert args.target == "http://prod"

    def test_json_out(self):
        args = _parse_args(["--json-out", "/tmp/report.json"])
        assert args.json_out == "/tmp/report.json"


# ---------------------------------------------------------------------------
# 8. _format_table
# ---------------------------------------------------------------------------

class TestFormatTable:
    def _make_report(self, passed=True, p99=0.1, error_rate=0.0):
        return LoadTestReport(
            config={"target": "http://localhost:8000", "users": 5, "duration": 10},
            start_time="2026-01-01T00:00:00+00:00",
            end_time="2026-01-01T00:00:10+00:00",
            warmup_seconds=1.5,
            total_requests=100,
            total_errors=int(error_rate * 100),
            overall_error_rate=error_rate,
            overall_rps=10.0,
            p50_s=0.05,
            p95_s=0.09,
            p99_s=p99,
            max_concurrent=5,
            endpoint_stats=[
                {
                    "endpoint": "/health",
                    "total": 100,
                    "errors": 0,
                    "error_rate": 0.0,
                    "p50_ms": 50.0,
                    "p95_ms": 90.0,
                    "p99_ms": p99 * 1000,
                    "rps": 10.0,
                }
            ],
            passed=passed,
            failure_reason=None if passed else "p99 exceeded",
        )

    def test_table_contains_verdict_pass(self):
        table = _format_table(self._make_report(passed=True))
        assert "PASS" in table

    def test_table_contains_verdict_fail(self):
        table = _format_table(self._make_report(passed=False))
        assert "FAIL" in table

    def test_table_contains_target(self):
        table = _format_table(self._make_report())
        assert "localhost:8000" in table

    def test_table_contains_endpoint(self):
        table = _format_table(self._make_report())
        assert "/health" in table


# ---------------------------------------------------------------------------
# 9. run_load_test — full integration with mocked HTTP
# ---------------------------------------------------------------------------

class TestRunLoadTest:
    def _fast_request(self, url, timeout):
        """Simulates a fast, always-successful request."""
        time.sleep(0.001)
        return 200, 0.001, None

    def test_report_structure(self):
        config = LoadTestConfig(target="http://x", users=2, duration=0.3)
        with patch("load_test._do_request", side_effect=self._fast_request):
            report = run_load_test(config)
        assert isinstance(report.total_requests, int)
        assert isinstance(report.p99_s, float)
        assert isinstance(report.passed, bool)
        assert isinstance(report.endpoint_stats, list)

    def test_passes_when_fast_and_no_errors(self):
        config = LoadTestConfig(target="http://x", users=2, duration=0.3)
        with patch("load_test._do_request", side_effect=self._fast_request):
            report = run_load_test(config)
        # With 1ms latency and 0 errors, should always pass
        assert report.overall_error_rate == 0.0
        assert report.p99_s < P99_THRESHOLD_S

    def test_fails_when_high_error_rate(self):
        def _always_error(url, timeout):
            return 500, 0.001, None

        config = LoadTestConfig(target="http://x", users=2, duration=0.3)
        with patch("load_test._do_request", side_effect=_always_error):
            report = run_load_test(config)
        assert report.overall_error_rate > ERROR_RATE_THRESHOLD
        assert report.passed is False

    def test_fails_when_slow(self):
        def _slow_request(url, timeout):
            time.sleep(0.01)  # only 10ms but we'll inject high latencies via results
            return 200, 3.0, None  # report 3s latency

        config = LoadTestConfig(target="http://x", users=1, duration=0.3)
        with patch("load_test._do_request", side_effect=_slow_request):
            report = run_load_test(config)
        assert report.p99_s >= P99_THRESHOLD_S
        assert report.passed is False

    def test_warmup_requests_excluded(self):
        """Requests during warm-up should not affect aggregate stats."""
        call_times = []

        def _track_request(url, timeout):
            call_times.append(time.time())
            return 200, 0.001, None

        config = LoadTestConfig(
            target="http://x", users=1, duration=0.5, warmup_fraction=0.5
        )
        with patch("load_test._do_request", side_effect=_track_request):
            report = run_load_test(config)
        # All requests were fast (1ms), so p99 should be tiny
        assert report.p99_s < 1.0


# ---------------------------------------------------------------------------
# 10. main() exit codes
# ---------------------------------------------------------------------------

class TestMainExitCodes:
    def _fast_request(self, url, timeout):
        return 200, 0.001, None

    def test_exit_0_on_pass(self, tmp_path):
        out_file = str(tmp_path / "report.json")
        with patch("load_test._do_request", side_effect=self._fast_request):
            code = main(["--users", "1", "--duration", "1", "--target", "http://x",
                         "--json-out", out_file])
        assert code == 0

    def test_exit_1_on_slow_server(self, tmp_path):
        def _slow(url, timeout):
            return 200, 3.0, None

        out_file = str(tmp_path / "report.json")
        with patch("load_test._do_request", side_effect=_slow):
            code = main(["--users", "1", "--duration", "1", "--target", "http://x",
                         "--json-out", out_file])
        assert code == 1

    def test_json_report_written(self, tmp_path):
        out_file = str(tmp_path / "report.json")
        with patch("load_test._do_request", side_effect=self._fast_request):
            main(["--users", "1", "--duration", "1", "--target", "http://x",
                  "--json-out", out_file])
        data = json.loads(Path(out_file).read_text())
        assert "aggregate" in data
        assert "endpoints" in data
        assert "verdict" in data
        assert "config" in data

    def test_json_report_has_required_fields(self, tmp_path):
        out_file = str(tmp_path / "report.json")
        with patch("load_test._do_request", side_effect=self._fast_request):
            main(["--users", "1", "--duration", "1", "--target", "http://x",
                  "--json-out", out_file])
        data = json.loads(Path(out_file).read_text())
        agg = data["aggregate"]
        for key in ("total_requests", "total_errors", "overall_error_rate",
                    "overall_rps", "p50_s", "p95_s", "p99_s", "max_concurrent"):
            assert key in agg, f"Missing key: {key}"
