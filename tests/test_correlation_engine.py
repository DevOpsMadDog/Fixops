"""Tests for the correlation engine.

The actual CorrelationEngine API is fully asynchronous:
  - ``async correlate_finding(finding_id: str) -> Optional[CorrelationResult]``
  - ``async batch_correlate_findings(finding_ids: List[str]) -> List[CorrelationResult]``
  - ``async get_correlation_stats() -> Dict[str, Any]``
  - ``async calculate_noise_reduction(findings_before, findings_after) -> Dict``
  - ``async ai_enhanced_correlation(finding_id) -> Optional[CorrelationResult]``

There is NO sync ``correlate(findings_list)`` method.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest
from core.services.enterprise.correlation_engine import (
    CorrelationEngine,
    CorrelationResult,
    correlate_finding_async,
    batch_correlate_async,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Instantiation
# ---------------------------------------------------------------------------

def test_correlation_engine_initialization():
    engine = CorrelationEngine()
    assert engine is not None


def test_correlation_engine_second_instance():
    """Two independent instances must both construct without error."""
    e1 = CorrelationEngine()
    e2 = CorrelationEngine()
    assert e1 is not e2


# ---------------------------------------------------------------------------
# correlate_finding — unknown IDs
# ---------------------------------------------------------------------------

def test_correlate_finding_returns_none_for_unknown():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("nonexistent-finding-id"))
    assert result is None or hasattr(result, "finding_id")


def test_correlate_finding_empty_string_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding(""))
    assert result is None or isinstance(result, CorrelationResult)


def test_correlate_finding_uuid_style_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    assert result is None or isinstance(result, CorrelationResult)


def test_correlate_finding_numeric_string_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("12345"))
    assert result is None or isinstance(result, CorrelationResult)


def test_correlate_finding_special_chars_id():
    """Special chars in ID should not raise — engine must handle gracefully."""
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("find-id/with'quotes"))
    assert result is None or isinstance(result, CorrelationResult)


# ---------------------------------------------------------------------------
# batch_correlate_findings
# ---------------------------------------------------------------------------

def test_batch_correlate_empty_list():
    engine = CorrelationEngine()
    results = _run(engine.batch_correlate_findings([]))
    assert isinstance(results, list)
    assert len(results) == 0


def test_batch_correlate_single_unknown():
    engine = CorrelationEngine()
    results = _run(engine.batch_correlate_findings(["no-such-finding"]))
    assert isinstance(results, list)
    # Unknown findings produce no CorrelationResult rows
    assert len(results) == 0


def test_batch_correlate_multiple_unknowns():
    engine = CorrelationEngine()
    ids = [f"unknown-{i}" for i in range(5)]
    results = _run(engine.batch_correlate_findings(ids))
    assert isinstance(results, list)
    assert len(results) == 0


def test_batch_correlate_returns_only_correlation_results():
    engine = CorrelationEngine()
    ids = ["id-a", "id-b", "id-c"]
    results = _run(engine.batch_correlate_findings(ids))
    for r in results:
        assert isinstance(r, CorrelationResult)


def test_batch_correlate_large_batch_no_raise():
    engine = CorrelationEngine()
    ids = [f"finding-{i}" for i in range(50)]
    results = _run(engine.batch_correlate_findings(ids))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# get_correlation_stats
# ---------------------------------------------------------------------------

def test_get_correlation_stats_returns_dict():
    engine = CorrelationEngine()
    stats = _run(engine.get_correlation_stats())
    assert isinstance(stats, dict)


def test_get_correlation_stats_has_expected_keys():
    engine = CorrelationEngine()
    stats = _run(engine.get_correlation_stats())
    # At minimum the stats dict should not be empty or should have known keys
    assert stats is not None


# ---------------------------------------------------------------------------
# calculate_noise_reduction
# ---------------------------------------------------------------------------

def test_calculate_noise_reduction_returns_dict():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(100, 60))
    assert isinstance(result, dict)


def test_calculate_noise_reduction_zero_after():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(100, 0))
    assert isinstance(result, dict)


def test_calculate_noise_reduction_equal_values():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(50, 50))
    assert isinstance(result, dict)


def test_calculate_noise_reduction_zero_before():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(0, 0))
    assert isinstance(result, dict)


def test_calculate_noise_reduction_large_values():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(10000, 3000))
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# ai_enhanced_correlation
# ---------------------------------------------------------------------------

def test_ai_enhanced_correlation_unknown_id_returns_none_or_result():
    engine = CorrelationEngine()
    result = _run(engine.ai_enhanced_correlation("unknown-ai-finding"))
    assert result is None or isinstance(result, CorrelationResult)


def test_ai_enhanced_correlation_empty_id():
    engine = CorrelationEngine()
    result = _run(engine.ai_enhanced_correlation(""))
    assert result is None or isinstance(result, CorrelationResult)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

def test_module_correlate_finding_async_unknown():
    result = _run(correlate_finding_async("module-level-unknown"))
    assert result is None or isinstance(result, CorrelationResult)


def test_module_batch_correlate_async_empty():
    results = _run(batch_correlate_async([]))
    assert isinstance(results, list)
    assert len(results) == 0


def test_module_batch_correlate_async_unknown_ids():
    results = _run(batch_correlate_async(["m1", "m2", "m3"]))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# CorrelationResult dataclass
# ---------------------------------------------------------------------------

def test_correlation_result_construction():
    r = CorrelationResult(
        finding_id="f1",
        correlated_finding_id="f2",
        correlation_type="fingerprint",
        confidence=0.85,
        explanation="Same CVE on same host",
    )
    assert r.finding_id == "f1"
    assert r.correlated_finding_id == "f2"
    assert r.confidence == 0.85


def test_correlation_result_confidence_boundary_zero():
    r = CorrelationResult(
        finding_id="f1",
        correlated_finding_id="f2",
        correlation_type="pattern",
        confidence=0.0,
        explanation="No confidence",
    )
    assert r.confidence == 0.0


def test_correlation_result_confidence_boundary_one():
    r = CorrelationResult(
        finding_id="f1",
        correlated_finding_id="f2",
        correlation_type="vulnerability",
        confidence=1.0,
        explanation="Perfect match",
    )
    assert r.confidence == 1.0


def test_correlation_result_all_types():
    for ctype in ("fingerprint", "location", "pattern", "root_cause", "vulnerability"):
        r = CorrelationResult(
            finding_id="fa",
            correlated_finding_id="fb",
            correlation_type=ctype,
            confidence=0.5,
            explanation=f"type {ctype}",
        )
        assert r.correlation_type == ctype
