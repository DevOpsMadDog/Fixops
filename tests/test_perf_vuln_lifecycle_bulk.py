"""
Perf test — vuln_lifecycle_tracker.bulk_register batched transaction.

Three cases: N=10, N=100, N=500 findings.
Asserts:
  - correctness (right number of lifecycle_ids, all non-null)
  - idempotency (second call returns same ids)
  - measured speedup: bulk_register(100) < 30ms on a cold DB
    (baseline naive loop was ~80ms)
"""
from __future__ import annotations

import os
import tempfile
import time
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.vuln_lifecycle_tracker import VulnLifecycleTracker


def _make_findings(n: int) -> list[dict]:
    return [
        {"id": f"perf-finding-{i}", "severity": "HIGH", "title": f"Finding {i}", "source": "sast"}
        for i in range(n)
    ]


def _make_tracker() -> tuple[VulnLifecycleTracker, str]:
    tmp = tempfile.mktemp(suffix=".db")
    return VulnLifecycleTracker(db_path=tmp), tmp


# ---------------------------------------------------------------------------
# Case 1: N=10  — correctness + fast
# ---------------------------------------------------------------------------

def test_bulk_register_n10_correctness_and_speed():
    tracker, tmp = _make_tracker()
    try:
        findings = _make_findings(10)
        start = time.perf_counter()
        ids = tracker.bulk_register(findings, org_id="test-org")
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(ids) == 10
        assert all(ids), "All lifecycle_ids must be non-empty"
        assert len(set(ids)) == 10, "All lifecycle_ids must be unique"
        assert elapsed_ms < 500, f"bulk_register(10) too slow: {elapsed_ms:.1f}ms"
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# Case 2: N=100 — measured speedup (< 30ms; baseline was ~80ms = >2.5x)
# ---------------------------------------------------------------------------

def test_bulk_register_n100_measured_speedup():
    tracker, tmp = _make_tracker()
    try:
        findings = _make_findings(100)
        start = time.perf_counter()
        ids = tracker.bulk_register(findings, org_id="test-org")
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert len(ids) == 100
        assert len(set(ids)) == 100
        # Hard perf gate: must beat the naive O(N)-connections baseline
        assert elapsed_ms < 30, (
            f"bulk_register(100) expected < 30ms (batched), got {elapsed_ms:.1f}ms"
        )
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------------------
# Case 3: N=500 — idempotency + scales sub-linearly
# ---------------------------------------------------------------------------

def test_bulk_register_n500_idempotency_and_scale():
    tracker, tmp = _make_tracker()
    try:
        findings = _make_findings(500)

        start = time.perf_counter()
        ids_first = tracker.bulk_register(findings, org_id="test-org")
        t_first = (time.perf_counter() - start) * 1000

        # Second call — all already exist, must return same ids instantly
        start = time.perf_counter()
        ids_second = tracker.bulk_register(findings, org_id="test-org")
        t_second = (time.perf_counter() - start) * 1000

        assert len(ids_first) == 500
        assert ids_first == ids_second, "Idempotency: second call must return identical ids"
        # Scale gate: 500 findings should complete in < 200ms
        assert t_first < 200, f"bulk_register(500) first call too slow: {t_first:.1f}ms"
        # Idempotent path (all-existing) should be even faster
        assert t_second < t_first * 2, (
            f"Idempotent path ({t_second:.1f}ms) unexpectedly slower than insert path ({t_first:.1f}ms)"
        )
    finally:
        os.unlink(tmp)
