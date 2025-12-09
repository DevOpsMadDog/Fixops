#!/usr/bin/env python3
"""FixOps Performance Benchmarking Script

Measures and reports performance metrics for Gartner Magic Quadrant positioning.
Target: 10M LOC analyzed in <5 minutes, <100ms API latency (p99).
"""

import asyncio
import logging
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import aiohttp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for benchmarking."""

    total_lines_of_code: int
    analysis_duration_seconds: float
    lines_per_second: float
    api_latency_p50_ms: float
    api_latency_p95_ms: float
    api_latency_p99_ms: float
    throughput_requests_per_second: float
    error_rate: float
    memory_usage_mb: float
    cpu_usage_percent: float


class FixOpsBenchmark:
    """FixOps performance benchmarking suite."""

    def __init__(self, api_base_url: str = "http://localhost:8000"):
        """Initialize benchmark suite."""
        self.api_base_url = api_base_url
        self.results: List[Dict[str, Any]] = []

    async def benchmark_reachability_analysis(
        self, repository_url: str, cve_id: str, iterations: int = 10
    ) -> PerformanceMetrics:
        """Benchmark reachability analysis performance."""
        logger.info(f"Benchmarking reachability analysis: {repository_url}")

        latencies = []
        errors = 0
        total_lines = 0

        async with aiohttp.ClientSession() as session:
            for i in range(iterations):
                start_time = time.time()

                try:
                    # Simulate reachability analysis API call
                    async with session.post(
                        f"{self.api_base_url}/api/v1/reachability/analyze",
                        json={
                            "repository": {"url": repository_url},
                            "cve_id": cve_id,
                            "component_name": "test-component",
                            "component_version": "1.0.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=300),
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            latency_ms = (time.time() - start_time) * 1000
                            latencies.append(latency_ms)

                            # Extract LOC from metadata if available
                            metadata = result.get("metadata", {})
                            total_lines += metadata.get("lines_of_code", 0)
                        else:
                            errors += 1
                            logger.warning(f"Request failed: {response.status}")

                except Exception as e:
                    errors += 1
                    logger.error(f"Request error: {e}")

        if not latencies:
            raise ValueError("No successful requests")

        # Calculate metrics
        total_duration = sum(latencies) / 1000  # Convert to seconds
        lines_per_second = total_lines / total_duration if total_duration > 0 else 0

        return PerformanceMetrics(
            total_lines_of_code=total_lines,
            analysis_duration_seconds=total_duration,
            lines_per_second=lines_per_second,
            api_latency_p50_ms=statistics.median(latencies),
            api_latency_p95_ms=self._percentile(latencies, 95),
            api_latency_p99_ms=self._percentile(latencies, 99),
            throughput_requests_per_second=len(latencies) / total_duration,
            error_rate=errors / iterations,
            memory_usage_mb=0.0,  # Would need system monitoring
            cpu_usage_percent=0.0,  # Would need system monitoring
        )

    async def benchmark_bulk_analysis(
        self, repositories: List[Dict[str, str]], concurrent: int = 10
    ) -> PerformanceMetrics:
        """Benchmark bulk analysis with concurrency."""
        logger.info(f"Benchmarking bulk analysis: {len(repositories)} repositories")

        start_time = time.time()
        latencies = []
        errors = 0
        total_lines = 0

        async def analyze_repo(repo: Dict[str, str]) -> None:
            nonlocal latencies, errors, total_lines

            req_start = time.time()
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.api_base_url}/api/v1/reachability/analyze",
                        json={
                            "repository": {"url": repo["url"]},
                            "cve_id": repo.get("cve_id", "CVE-2024-0001"),
                            "component_name": repo.get("component", "test"),
                            "component_version": "1.0.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=300),
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            latency_ms = (time.time() - req_start) * 1000
                            latencies.append(latency_ms)

                            metadata = result.get("metadata", {})
                            total_lines += metadata.get("lines_of_code", 0)
                        else:
                            errors += 1
            except Exception as e:
                errors += 1
                logger.error(f"Bulk analysis error: {e}")

        # Run concurrent analyses
        semaphore = asyncio.Semaphore(concurrent)

        async def bounded_analyze(repo: Dict[str, str]) -> None:
            async with semaphore:
                await analyze_repo(repo)

        await asyncio.gather(*[bounded_analyze(repo) for repo in repositories])

        total_duration = time.time() - start_time
        lines_per_second = total_lines / total_duration if total_duration > 0 else 0

        return PerformanceMetrics(
            total_lines_of_code=total_lines,
            analysis_duration_seconds=total_duration,
            lines_per_second=lines_per_second,
            api_latency_p50_ms=statistics.median(latencies) if latencies else 0,
            api_latency_p95_ms=self._percentile(latencies, 95) if latencies else 0,
            api_latency_p99_ms=self._percentile(latencies, 99) if latencies else 0,
            throughput_requests_per_second=len(repositories) / total_duration,
            error_rate=errors / len(repositories) if repositories else 0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0,
        )

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]

    def generate_report(self, metrics: PerformanceMetrics) -> Dict[str, Any]:
        """Generate performance report for Gartner submission."""
        # Gartner targets
        target_loc_per_5min = 10_000_000  # 10M LOC in 5 minutes
        target_api_latency_p99_ms = 100  # <100ms p99

        # Calculate if targets are met
        loc_in_5min = metrics.lines_per_second * 300  # 5 minutes = 300 seconds
        meets_loc_target = loc_in_5min >= target_loc_per_5min
        meets_latency_target = metrics.api_latency_p99_ms <= target_api_latency_p99_ms

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": {
                "total_lines_of_code": metrics.total_lines_of_code,
                "analysis_duration_seconds": round(
                    metrics.analysis_duration_seconds, 2
                ),
                "lines_per_second": round(metrics.lines_per_second, 2),
                "lines_in_5_minutes": round(loc_in_5min, 0),
                "api_latency": {
                    "p50_ms": round(metrics.api_latency_p50_ms, 2),
                    "p95_ms": round(metrics.api_latency_p95_ms, 2),
                    "p99_ms": round(metrics.api_latency_p99_ms, 2),
                },
                "throughput_requests_per_second": round(
                    metrics.throughput_requests_per_second, 2
                ),
                "error_rate": round(metrics.error_rate * 100, 2),
            },
            "gartner_targets": {
                "target_lines_in_5min": target_loc_per_5min,
                "target_api_latency_p99_ms": target_api_latency_p99_ms,
                "meets_loc_target": meets_loc_target,
                "meets_latency_target": meets_latency_target,
                "overall_status": "PASS"
                if (meets_loc_target and meets_latency_target)
                else "FAIL",
            },
            "recommendations": [],
        }

        if not meets_loc_target:
            report["recommendations"].append(
                f"Need to improve analysis speed: {loc_in_5min:,.0f} LOC/5min < {target_loc_per_5min:,.0f} target"
            )

        if not meets_latency_target:
            report["recommendations"].append(
                f"Need to improve API latency: {metrics.api_latency_p99_ms:.2f}ms p99 > {target_api_latency_p99_ms}ms target"
            )

        return report


async def main():
    """Run performance benchmarks."""
    benchmark = FixOpsBenchmark()

    # Test repositories (would be real repos in production)
    test_repos = [
        {"url": "https://github.com/test/repo1", "cve_id": "CVE-2024-0001"},
        {"url": "https://github.com/test/repo2", "cve_id": "CVE-2024-0002"},
    ]

    logger.info("Running reachability analysis benchmark...")
    metrics = await benchmark.benchmark_reachability_analysis(
        "https://github.com/test/repo", "CVE-2024-0001", iterations=10
    )

    report = benchmark.generate_report(metrics)

    print("\n" + "=" * 80)
    print("FIXOPS PERFORMANCE BENCHMARK REPORT")
    print("=" * 80)
    print(f"\nTimestamp: {report['timestamp']}")
    print(f"\nMetrics:")
    print(f"  Total LOC Analyzed: {report['metrics']['total_lines_of_code']:,}")
    print(f"  Analysis Duration: {report['metrics']['analysis_duration_seconds']:.2f}s")
    print(f"  Lines/Second: {report['metrics']['lines_per_second']:,.0f}")
    print(f"  Lines in 5 Minutes: {report['metrics']['lines_in_5_minutes']:,.0f}")
    print(f"\nAPI Latency:")
    print(f"  p50: {report['metrics']['api_latency']['p50_ms']:.2f}ms")
    print(f"  p95: {report['metrics']['api_latency']['p95_ms']:.2f}ms")
    print(f"  p99: {report['metrics']['api_latency']['p99_ms']:.2f}ms")
    print(f"\nGartner Targets:")
    print(
        f"  LOC Target (10M in 5min): {'✅ PASS' if report['gartner_targets']['meets_loc_target'] else '❌ FAIL'}"
    )
    print(
        f"  Latency Target (<100ms p99): {'✅ PASS' if report['gartner_targets']['meets_latency_target'] else '❌ FAIL'}"
    )
    print(f"  Overall Status: {report['gartner_targets']['overall_status']}")

    if report["recommendations"]:
        print(f"\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")

    print("\n" + "=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
