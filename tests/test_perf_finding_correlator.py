"""
Perf test: finding_correlator._finding_tags / _extract_cve_ids regex hot-path.

Three cases: small (10), medium (100), large (1000) findings.
Each case is timed; we assert a sensible upper bound so the test is
MEASURED not just a smoke-check.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List

import pytest

from core.finding_correlator import _extract_cve_ids, _finding_tags


def _make_findings(n: int) -> List[Dict[str, Any]]:
    findings = []
    for i in range(n):
        findings.append(
            {
                "id": f"finding-{i}",
                "title": f"CVE-2024-{1000 + i} remote-code-execution vulnerability",
                "description": f"A critical flaw in package-{i} allows auth bypass",
                "tags": ["critical", "authentication", "remote"],
                "rule_id": f"RULE-{i}",
                "type": "vulnerability",
            }
        )
    return findings


def _run_batch(findings: List[Dict[str, Any]]) -> None:
    for f in findings:
        _finding_tags(f)
        _extract_cve_ids(f)


@pytest.mark.perf
def test_perf_finding_correlator_small():
    """10 findings — baseline: must complete in <50 ms."""
    findings = _make_findings(10)
    start = time.perf_counter()
    _run_batch(findings)
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"\n[perf] 10 findings: {elapsed_ms:.2f} ms")
    assert elapsed_ms < 50, f"Too slow for 10 findings: {elapsed_ms:.2f} ms"


@pytest.mark.perf
def test_perf_finding_correlator_medium():
    """100 findings — must complete in <200 ms."""
    findings = _make_findings(100)
    start = time.perf_counter()
    _run_batch(findings)
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"\n[perf] 100 findings: {elapsed_ms:.2f} ms")
    assert elapsed_ms < 200, f"Too slow for 100 findings: {elapsed_ms:.2f} ms"


@pytest.mark.perf
def test_perf_finding_correlator_large():
    """1000 findings — must complete in <1500 ms."""
    findings = _make_findings(1000)
    start = time.perf_counter()
    _run_batch(findings)
    elapsed_ms = (time.perf_counter() - start) * 1000
    print(f"\n[perf] 1000 findings: {elapsed_ms:.2f} ms")
    assert elapsed_ms < 1500, f"Too slow for 1000 findings: {elapsed_ms:.2f} ms"
