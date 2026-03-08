#!/usr/bin/env python3
"""FixOps Enterprise Stress Test — 50+ concurrent requests across critical endpoints."""

import asyncio
import aiohttp
import time
import sys
from collections import defaultdict

API = "http://localhost:8000/api/v1"
KEY = "fixops_sk_WIjum9WxuQv8s6vzJeU2gYKximI5WSdMDtshH1U_p0U"
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}

# Critical endpoints to stress test
ENDPOINTS = [
    ("GET", "/health", None),
    ("GET", "/brain/status", None),
    ("GET", "/brain/status/full", None),
    ("GET", "/brain/findings", None),
    ("GET", "/brain/findings/stats", None),
    ("GET", "/brain/remediation/plans", None),
    ("GET", "/inventory/assets", None),
    ("GET", "/inventory/sbom/components", None),
    ("GET", "/scanner-ingest/health", None),
    ("GET", "/scanner-ingest/supported", None),
    ("GET", "/scanner-ingest/stats", None),
    ("GET", "/compliance/frameworks", None),
    ("GET", "/compliance/status", None),
    ("GET", "/sast/scan/results", None),
    ("GET", "/container/scan/results", None),
    ("GET", "/secrets/scan/results", None),
    ("GET", "/cspm/scan/results", None),
    ("GET", "/dast/scan/results", None),
    ("GET", "/knowledge-graph/nodes", None),
    ("GET", "/knowledge-graph/stats", None),
    ("GET", "/risk/scores", None),
    ("GET", "/risk/trends", None),
    ("GET", "/evidence/chain", None),
    ("GET", "/self-learning/metrics", None),
    ("GET", "/self-learning/model/status", None),
    ("POST", "/brain/ingest/finding", {
        "title": "Stress Test Finding",
        "severity": "medium",
        "source_tool": "stress-test",
        "description": "Concurrent stress test finding"
    }),
    ("POST", "/compliance/assess", {
        "app_id": "stress-test-app",
        "framework": "soc2",
        "scope": "full"
    }),
    ("POST", "/sast/scan/code", {
        "code": "import os; os.system(input())",
        "language": "python",
        "app_id": "stress-test"
    }),
    ("POST", "/secrets/scan/content", {
        "content": "AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE password=hunter2",
        "source": "stress-test"
    }),
    ("POST", "/risk/calculate", {
        "app_id": "stress-test-app",
        "findings_count": 15,
        "critical_count": 2
    }),
]

CONCURRENCY = 50  # 50 concurrent requests
TOTAL_REQUESTS = 200  # Total requests to send

results = defaultdict(lambda: {"success": 0, "fail": 0, "errors": [], "latencies": []})


async def make_request(session, method, path, body=None, req_id=0):
    """Make a single API request and record metrics."""
    url = f"{API}{path}"
    start = time.monotonic()
    try:
        if method == "GET":
            async with session.get(url, headers=HEADERS, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                status = resp.status
                await resp.read()
        else:
            async with session.post(url, headers=HEADERS, json=body, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                status = resp.status
                await resp.read()
        
        elapsed = (time.monotonic() - start) * 1000  # ms
        key = f"{method} {path}"
        
        if status < 500:
            results[key]["success"] += 1
        else:
            results[key]["fail"] += 1
            results[key]["errors"].append(f"HTTP {status}")
        
        results[key]["latencies"].append(elapsed)
        return status, elapsed
        
    except Exception as e:
        elapsed = (time.monotonic() - start) * 1000
        key = f"{method} {path}"
        results[key]["fail"] += 1
        results[key]["errors"].append(str(e)[:80])
        results[key]["latencies"].append(elapsed)
        return 0, elapsed


async def run_stress_test():
    """Execute the stress test with concurrent requests."""
    print("=" * 70)
    print("FIXOPS ENTERPRISE STRESS TEST")
    print(f"Concurrency: {CONCURRENCY} | Total Requests: {TOTAL_REQUESTS}")
    print("=" * 70)
    
    connector = aiohttp.TCPConnector(limit=CONCURRENCY, force_close=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Phase 1: Warm-up (5 sequential requests)
        print("\n[Phase 1] Warm-up...")
        for method, path, body in ENDPOINTS[:5]:
            await make_request(session, method, path, body)
        print("  Warm-up complete")
        
        # Phase 2: Burst test (50 concurrent to single endpoint)
        print(f"\n[Phase 2] Burst test — {CONCURRENCY} concurrent to /health...")
        start = time.monotonic()
        tasks = [make_request(session, "GET", "/health", None, i) for i in range(CONCURRENCY)]
        burst_results = await asyncio.gather(*tasks)
        burst_time = (time.monotonic() - start) * 1000
        successes = sum(1 for s, _ in burst_results if s and s < 500)
        print(f"  {successes}/{CONCURRENCY} succeeded in {burst_time:.0f}ms")
        print(f"  Throughput: {CONCURRENCY / (burst_time / 1000):.0f} req/sec")
        
        # Phase 3: Mixed workload (all endpoints, concurrent)
        print(f"\n[Phase 3] Mixed workload — {TOTAL_REQUESTS} requests across {len(ENDPOINTS)} endpoints...")
        start = time.monotonic()
        tasks = []
        for i in range(TOTAL_REQUESTS):
            method, path, body = ENDPOINTS[i % len(ENDPOINTS)]
            # Add unique identifier for POST bodies
            if body:
                body = {**body}
                if "title" in body:
                    body["title"] = f"Stress Test Finding #{i}"
            tasks.append(make_request(session, method, path, body, i))
        
        # Run with semaphore for controlled concurrency
        sem = asyncio.Semaphore(CONCURRENCY)
        async def bounded_request(task_coro):
            async with sem:
                return await task_coro
        
        mixed_results = await asyncio.gather(*[bounded_request(t) for t in tasks])
        mixed_time = (time.monotonic() - start) * 1000
        
        total_success = sum(1 for s, _ in mixed_results if s and s < 500)
        total_fail = TOTAL_REQUESTS - total_success
        avg_latency = sum(lat for _, lat in mixed_results) / len(mixed_results)
        
        print(f"  Total: {total_success} success, {total_fail} fail")
        print(f"  Duration: {mixed_time:.0f}ms")
        print(f"  Throughput: {TOTAL_REQUESTS / (mixed_time / 1000):.0f} req/sec")
        print(f"  Avg latency: {avg_latency:.1f}ms")
        
        # Phase 4: Scanner ingestion under load
        print("\n[Phase 4] Scanner ingestion burst — 20 concurrent uploads...")
        trivy_data = open("/tmp/trivy_scan.json", "rb").read()
        
        async def upload_scan(i):
            url = f"{API}/scanner-ingest/upload"
            form = aiohttp.FormData()
            form.add_field("file", trivy_data, filename=f"trivy_scan_{i}.json", content_type="application/json")
            form.add_field("scanner_type", "trivy")
            form.add_field("app_id", f"stress-app-{i}")
            
            start = time.monotonic()
            try:
                async with session.post(url, headers={"X-API-Key": KEY}, data=form, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    status = resp.status
                    body = await resp.json()
                    elapsed = (time.monotonic() - start) * 1000
                    return status, elapsed, body.get("findings_count", 0)
            except Exception as e:
                return 0, (time.monotonic() - start) * 1000, str(e)[:50]
        
        start = time.monotonic()
        scan_tasks = [upload_scan(i) for i in range(20)]
        scan_results = await asyncio.gather(*scan_tasks)
        scan_time = (time.monotonic() - start) * 1000
        
        scan_success = sum(1 for s, _, _ in scan_results if s == 200)
        scan_findings = sum(fc for s, _, fc in scan_results if isinstance(fc, int))
        print(f"  {scan_success}/20 uploads succeeded in {scan_time:.0f}ms")
        print(f"  Total findings ingested: {scan_findings}")
        print(f"  Throughput: {20 / (scan_time / 1000):.0f} uploads/sec")
    
    # Summary
    print("\n" + "=" * 70)
    print("ENDPOINT PERFORMANCE SUMMARY")
    print("=" * 70)
    print(f"{'Endpoint':<50} {'OK':>4} {'Fail':>4} {'P50':>7} {'P99':>7}")
    print("-" * 70)
    
    total_ok = 0
    total_fail = 0
    all_latencies = []
    
    for endpoint in sorted(results.keys()):
        r = results[endpoint]
        lats = sorted(r["latencies"])
        p50 = lats[len(lats)//2] if lats else 0
        p99 = lats[int(len(lats)*0.99)] if lats else 0
        total_ok += r["success"]
        total_fail += r["fail"]
        all_latencies.extend(lats)
        
        status_icon = "✓" if r["fail"] == 0 else "✗"
        print(f"  {status_icon} {endpoint:<48} {r['success']:>4} {r['fail']:>4} {p50:>6.0f}ms {p99:>6.0f}ms")
    
    all_lats = sorted(all_latencies)
    overall_p50 = all_lats[len(all_lats)//2] if all_lats else 0
    overall_p99 = all_lats[int(len(all_lats)*0.99)] if all_lats else 0
    
    print("-" * 70)
    print(f"  TOTAL: {total_ok} success, {total_fail} fail | P50: {overall_p50:.0f}ms | P99: {overall_p99:.0f}ms")
    
    # Final verdict
    success_rate = total_ok / max(total_ok + total_fail, 1) * 100
    print(f"\n{'='*70}")
    if success_rate >= 95 and overall_p99 < 5000:
        print(f"  ✅ STRESS TEST PASSED — {success_rate:.1f}% success rate, P99 {overall_p99:.0f}ms")
    elif success_rate >= 80:
        print(f"  ⚠️  STRESS TEST WARNING — {success_rate:.1f}% success rate, P99 {overall_p99:.0f}ms")
    else:
        print(f"  ❌ STRESS TEST FAILED — {success_rate:.1f}% success rate, P99 {overall_p99:.0f}ms")
    print(f"{'='*70}")
    
    return success_rate >= 95


if __name__ == "__main__":
    passed = asyncio.run(run_stress_test())
    sys.exit(0 if passed else 1)
