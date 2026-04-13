#!/usr/bin/env python3
"""ALDECI Load Testing Harness

Measures API performance under concurrent load using only stdlib.
No external dependencies (no locust, no aiohttp).

Usage:
    python scripts/load_test.py --users 10 --duration 30 --target http://localhost:8000

Exit codes:
    0  p99 latency < 2s AND error_rate < 1%
    1  thresholds exceeded
"""

import argparse
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import Event, Lock
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TARGET = "http://localhost:8000"
DEFAULT_USERS = 10
DEFAULT_DURATION = 30  # seconds
WARMUP_FRACTION = 0.15  # first 15% of duration is warm-up
REQUEST_TIMEOUT = 10  # seconds per request

ENDPOINTS = [
    "/health",
    "/api/v1/findings",
    "/api/v1/posture/current",
    "/api/v1/compliance",
    "/api/v1/analytics/executive-summary",
]

P99_THRESHOLD_S = 2.0   # 2 seconds
ERROR_RATE_THRESHOLD = 0.01  # 1%


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RequestResult:
    endpoint: str
    status_code: int
    latency_s: float
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @property
    def success(self) -> bool:
        return self.error is None and 200 <= self.status_code < 500


@dataclass
class LoadTestConfig:
    target: str
    users: int
    duration: int
    endpoints: List[str] = field(default_factory=lambda: list(ENDPOINTS))
    warmup_fraction: float = WARMUP_FRACTION
    request_timeout: int = REQUEST_TIMEOUT

    @property
    def warmup_seconds(self) -> float:
        return self.duration * self.warmup_fraction


@dataclass
class EndpointStats:
    endpoint: str
    total: int
    successes: int
    errors: int
    latencies: List[float]

    @property
    def error_rate(self) -> float:
        return self.errors / self.total if self.total else 0.0

    @property
    def rps(self) -> float:
        return 0.0  # set externally after duration is known

    def percentile(self, pct: float) -> float:
        """Return the Nth percentile latency (0-100). Returns 0 if no data."""
        if not self.latencies:
            return 0.0
        sorted_lat = sorted(self.latencies)
        idx = int(math.ceil(pct / 100.0 * len(sorted_lat))) - 1
        return sorted_lat[max(0, idx)]


@dataclass
class LoadTestReport:
    config: Dict
    start_time: str
    end_time: str
    warmup_seconds: float
    total_requests: int
    total_errors: int
    overall_error_rate: float
    overall_rps: float
    p50_s: float
    p95_s: float
    p99_s: float
    max_concurrent: int
    endpoint_stats: List[Dict]
    passed: bool
    failure_reason: Optional[str]


# ---------------------------------------------------------------------------
# HTTP worker
# ---------------------------------------------------------------------------

def _do_request(url: str, timeout: int) -> Tuple[int, float, Optional[str]]:
    """Issue a single GET request. Returns (status_code, latency_s, error)."""
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            _ = resp.read()  # drain body
            elapsed = time.perf_counter() - start
            return resp.status, elapsed, None
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - start
        return exc.code, elapsed, None  # HTTP errors are not network errors
    except urllib.error.URLError as exc:
        elapsed = time.perf_counter() - start
        return 0, elapsed, str(exc.reason)
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - start
        return 0, elapsed, str(exc)


# ---------------------------------------------------------------------------
# Worker loop (runs in each thread)
# ---------------------------------------------------------------------------

def _worker_loop(
    config: LoadTestConfig,
    stop_event: Event,
    results: List[RequestResult],
    results_lock: Lock,
    endpoint_cycle_lock: Lock,
    endpoint_index_ref: List[int],
) -> None:
    """Continuously issue requests until stop_event is set."""
    while not stop_event.is_set():
        # Round-robin across endpoints (thread-safe)
        with endpoint_cycle_lock:
            idx = endpoint_index_ref[0] % len(config.endpoints)
            endpoint_index_ref[0] += 1

        endpoint = config.endpoints[idx]
        url = f"{config.target.rstrip('/')}{endpoint}"

        status, latency, error = _do_request(url, config.request_timeout)
        result = RequestResult(
            endpoint=endpoint,
            status_code=status,
            latency_s=latency,
            error=error,
        )

        with results_lock:
            results.append(result)


# ---------------------------------------------------------------------------
# Ramp-up scheduler
# ---------------------------------------------------------------------------

def _ramp_users(
    executor: ThreadPoolExecutor,
    config: LoadTestConfig,
    stop_event: Event,
    results: List[RequestResult],
    results_lock: Lock,
) -> None:
    """Submit workers gradually over the warm-up period."""
    warmup_s = config.warmup_seconds
    endpoint_index_ref = [0]
    endpoint_cycle_lock = Lock()

    step_s = warmup_s / config.users if config.users > 0 else 0

    for i in range(config.users):
        if stop_event.is_set():
            break
        executor.submit(
            _worker_loop,
            config,
            stop_event,
            results,
            results_lock,
            endpoint_cycle_lock,
            endpoint_index_ref,
        )
        if step_s > 0 and i < config.users - 1:
            # Sleep between user spawns — but respect stop_event
            stop_event.wait(timeout=step_s)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _compute_stats(
    results: List[RequestResult],
    warmup_cutoff: float,
    duration_s: float,
) -> Tuple[List[float], Dict[str, EndpointStats]]:
    """
    Filter out warm-up results, then compute per-endpoint and aggregate stats.
    Returns (all_latencies, endpoint_stats_map).
    """
    # Exclude warm-up window
    steady_results = [r for r in results if r.timestamp >= warmup_cutoff]

    # Group by endpoint
    ep_map: Dict[str, EndpointStats] = {}
    for ep in ENDPOINTS:
        ep_map[ep] = EndpointStats(
            endpoint=ep, total=0, successes=0, errors=0, latencies=[]
        )

    all_latencies: List[float] = []
    for r in steady_results:
        if r.endpoint not in ep_map:
            ep_map[r.endpoint] = EndpointStats(
                endpoint=r.endpoint, total=0, successes=0, errors=0, latencies=[]
            )
        ep = ep_map[r.endpoint]
        ep.total += 1
        ep.latencies.append(r.latency_s)
        all_latencies.append(r.latency_s)
        if r.success:
            ep.successes += 1
        else:
            ep.errors += 1

    return all_latencies, ep_map


def _percentile(data: List[float], pct: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int(math.ceil(pct / 100.0 * len(sorted_data))) - 1
    return sorted_data[max(0, idx)]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _format_table(report: LoadTestReport) -> str:
    lines = []
    lines.append("")
    lines.append("=" * 72)
    lines.append("  ALDECI LOAD TEST RESULTS")
    lines.append("=" * 72)
    lines.append(f"  Target   : {report.config['target']}")
    lines.append(f"  Users    : {report.config['users']}")
    lines.append(f"  Duration : {report.config['duration']}s  (warm-up: {report.warmup_seconds:.1f}s)")
    lines.append(f"  Window   : {report.start_time} → {report.end_time}")
    lines.append("")
    lines.append("  AGGREGATE")
    lines.append(f"    Total requests : {report.total_requests}")
    lines.append(f"    Errors        : {report.total_errors} ({report.overall_error_rate*100:.2f}%)")
    lines.append(f"    Throughput    : {report.overall_rps:.1f} req/s")
    lines.append(f"    Latency p50   : {report.p50_s*1000:.1f} ms")
    lines.append(f"    Latency p95   : {report.p95_s*1000:.1f} ms")
    lines.append(f"    Latency p99   : {report.p99_s*1000:.1f} ms")
    lines.append(f"    Max concurrent: {report.max_concurrent}")
    lines.append("")
    lines.append("  PER-ENDPOINT")
    header = f"  {'Endpoint':<45} {'Req':>6} {'Err%':>6} {'p50ms':>7} {'p95ms':>7} {'p99ms':>7} {'RPS':>6}"
    lines.append(header)
    lines.append("  " + "-" * 70)
    for es in report.endpoint_stats:
        lines.append(
            f"  {es['endpoint']:<45} "
            f"{es['total']:>6} "
            f"{es['error_rate']*100:>5.1f}% "
            f"{es['p50_ms']:>7.1f} "
            f"{es['p95_ms']:>7.1f} "
            f"{es['p99_ms']:>7.1f} "
            f"{es['rps']:>6.1f}"
        )
    lines.append("")
    status = "PASS" if report.passed else "FAIL"
    lines.append(f"  VERDICT: {status}")
    if report.failure_reason:
        lines.append(f"  REASON : {report.failure_reason}")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------

def run_load_test(config: LoadTestConfig) -> LoadTestReport:
    """Execute the load test and return the report."""
    results: List[RequestResult] = []
    results_lock = Lock()
    stop_event = Event()

    start_ts = time.time()
    start_str = datetime.fromtimestamp(start_ts, tz=timezone.utc).isoformat()

    with ThreadPoolExecutor(max_workers=config.users + 2) as executor:
        # Ramp workers in a dedicated thread so main thread can sleep
        ramp_future = executor.submit(
            _ramp_users, executor, config, stop_event, results, results_lock
        )

        # Run for the full duration
        time.sleep(config.duration)
        stop_event.set()

        # Wait for ramp thread to finish (already done since stop_event is set)
        ramp_future.result(timeout=5)

    end_ts = time.time()
    end_str = datetime.fromtimestamp(end_ts, tz=timezone.utc).isoformat()
    actual_duration = end_ts - start_ts
    warmup_cutoff = start_ts + config.warmup_seconds

    all_latencies, ep_map = _compute_stats(results, warmup_cutoff, actual_duration)

    steady_duration = actual_duration - config.warmup_seconds
    total = len(all_latencies)
    total_errors = sum(1 for r in results if r.timestamp >= warmup_cutoff and not r.success)
    overall_error_rate = total_errors / total if total else 0.0
    overall_rps = total / steady_duration if steady_duration > 0 else 0.0

    p50 = _percentile(all_latencies, 50)
    p95 = _percentile(all_latencies, 95)
    p99 = _percentile(all_latencies, 99)

    # Build per-endpoint dicts for JSON serialization
    ep_stats_list = []
    for ep_key, ep_stat in ep_map.items():
        ep_rps = ep_stat.total / steady_duration if steady_duration > 0 else 0.0
        ep_stats_list.append({
            "endpoint": ep_stat.endpoint,
            "total": ep_stat.total,
            "errors": ep_stat.errors,
            "error_rate": ep_stat.error_rate,
            "p50_ms": ep_stat.percentile(50) * 1000,
            "p95_ms": ep_stat.percentile(95) * 1000,
            "p99_ms": ep_stat.percentile(99) * 1000,
            "rps": ep_rps,
        })

    # Verdict
    failure_reason: Optional[str] = None
    if p99 >= P99_THRESHOLD_S:
        failure_reason = f"p99 latency {p99*1000:.0f}ms >= {P99_THRESHOLD_S*1000:.0f}ms threshold"
    if overall_error_rate >= ERROR_RATE_THRESHOLD:
        err_msg = f"error_rate {overall_error_rate*100:.2f}% >= {ERROR_RATE_THRESHOLD*100:.0f}% threshold"
        failure_reason = f"{failure_reason}; {err_msg}" if failure_reason else err_msg

    report = LoadTestReport(
        config={"target": config.target, "users": config.users, "duration": config.duration},
        start_time=start_str,
        end_time=end_str,
        warmup_seconds=config.warmup_seconds,
        total_requests=total,
        total_errors=total_errors,
        overall_error_rate=overall_error_rate,
        overall_rps=overall_rps,
        p50_s=p50,
        p95_s=p95,
        p99_s=p99,
        max_concurrent=config.users,
        endpoint_stats=ep_stats_list,
        passed=failure_reason is None,
        failure_reason=failure_reason,
    )
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ALDECI load testing harness (stdlib only)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--users", type=int, default=DEFAULT_USERS, help="Number of concurrent users")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION, help="Test duration in seconds")
    parser.add_argument("--target", type=str, default=DEFAULT_TARGET, help="Base URL of the target API")
    parser.add_argument("--json-out", type=str, default=None, help="Write JSON report to this file path")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    config = LoadTestConfig(
        target=args.target,
        users=args.users,
        duration=args.duration,
    )

    print(f"Starting load test: {config.users} users, {config.duration}s, target={config.target}")
    print(f"Warm-up period: {config.warmup_seconds:.1f}s — results excluded from stats")
    print(f"Endpoints under test: {', '.join(config.endpoints)}")

    report = run_load_test(config)

    print(_format_table(report))

    json_payload = json.dumps(
        {
            "config": report.config,
            "start_time": report.start_time,
            "end_time": report.end_time,
            "warmup_seconds": report.warmup_seconds,
            "aggregate": {
                "total_requests": report.total_requests,
                "total_errors": report.total_errors,
                "overall_error_rate": report.overall_error_rate,
                "overall_rps": report.overall_rps,
                "p50_s": report.p50_s,
                "p95_s": report.p95_s,
                "p99_s": report.p99_s,
                "max_concurrent": report.max_concurrent,
            },
            "endpoints": report.endpoint_stats,
            "verdict": {
                "passed": report.passed,
                "failure_reason": report.failure_reason,
            },
        },
        indent=2,
    )

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(json_payload)
        print(f"JSON report written to: {args.json_out}")
    else:
        print("--- JSON REPORT ---")
        print(json_payload)

    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
