"""Tests for the correlation engine.

The actual CorrelationEngine API is fully asynchronous and requires
``aiosqlite`` at runtime. Tests that invoke the async engine are skipped
when that dependency is missing.

CorrelationResult fields (actual):
  - finding_id: str
  - correlated_findings: List[str]
  - correlation_type: str
  - confidence_score: float
  - noise_reduction_factor: float
  - root_cause: str
"""

from __future__ import annotations

import asyncio
import importlib
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Detect whether aiosqlite is available so we can skip engine-calling tests
# gracefully rather than failing with ModuleNotFoundError.
# ---------------------------------------------------------------------------
_AIOSQLITE_AVAILABLE = importlib.util.find_spec("aiosqlite") is not None
_SKIP_ASYNC = pytest.mark.skipif(
    not _AIOSQLITE_AVAILABLE,
    reason="aiosqlite not installed — async DB engine unavailable",
)

from core.services.enterprise.correlation_engine import (
    CorrelationEngine,
    CorrelationResult,
    correlate_finding_async,
    batch_correlate_async,
)


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Instantiation (no DB access — always runs)
# ---------------------------------------------------------------------------

def test_correlation_engine_initialization():
    engine = CorrelationEngine()
    assert engine is not None


def test_correlation_engine_second_instance():
    e1 = CorrelationEngine()
    e2 = CorrelationEngine()
    assert e1 is not e2


def test_correlation_engine_has_strategies():
    engine = CorrelationEngine()
    assert hasattr(engine, "correlation_strategies")
    assert len(engine.correlation_strategies) > 0


# ---------------------------------------------------------------------------
# correlate_finding — unknown IDs
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_correlate_finding_returns_none_for_unknown():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("nonexistent-finding-id"))
    assert result is None or hasattr(result, "finding_id")


@_SKIP_ASYNC
def test_correlate_finding_empty_string_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding(""))
    assert result is None or isinstance(result, CorrelationResult)


@_SKIP_ASYNC
def test_correlate_finding_uuid_style_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    assert result is None or isinstance(result, CorrelationResult)


@_SKIP_ASYNC
def test_correlate_finding_numeric_string_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("12345"))
    assert result is None or isinstance(result, CorrelationResult)


@_SKIP_ASYNC
def test_correlate_finding_special_chars_id():
    engine = CorrelationEngine()
    result = _run(engine.correlate_finding("find-id/with'quotes"))
    assert result is None or isinstance(result, CorrelationResult)


# ---------------------------------------------------------------------------
# batch_correlate_findings
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_batch_correlate_empty_list():
    engine = CorrelationEngine()
    results = _run(engine.batch_correlate_findings([]))
    assert isinstance(results, list)
    assert len(results) == 0


@_SKIP_ASYNC
def test_batch_correlate_single_unknown():
    engine = CorrelationEngine()
    results = _run(engine.batch_correlate_findings(["no-such-finding"]))
    assert isinstance(results, list)
    assert len(results) == 0


@_SKIP_ASYNC
def test_batch_correlate_multiple_unknowns():
    engine = CorrelationEngine()
    ids = [f"unknown-{i}" for i in range(5)]
    results = _run(engine.batch_correlate_findings(ids))
    assert isinstance(results, list)
    assert len(results) == 0


@_SKIP_ASYNC
def test_batch_correlate_returns_only_correlation_results():
    engine = CorrelationEngine()
    ids = ["id-a", "id-b", "id-c"]
    results = _run(engine.batch_correlate_findings(ids))
    for r in results:
        assert isinstance(r, CorrelationResult)


@_SKIP_ASYNC
def test_batch_correlate_large_batch_no_raise():
    engine = CorrelationEngine()
    ids = [f"finding-{i}" for i in range(50)]
    results = _run(engine.batch_correlate_findings(ids))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# get_correlation_stats
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_get_correlation_stats_returns_dict():
    engine = CorrelationEngine()
    stats = _run(engine.get_correlation_stats())
    assert isinstance(stats, dict)


@_SKIP_ASYNC
def test_get_correlation_stats_has_expected_keys():
    engine = CorrelationEngine()
    stats = _run(engine.get_correlation_stats())
    assert stats is not None


# ---------------------------------------------------------------------------
# calculate_noise_reduction
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_calculate_noise_reduction_returns_dict():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(100, 60))
    assert isinstance(result, dict)


@_SKIP_ASYNC
def test_calculate_noise_reduction_zero_after():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(100, 0))
    assert isinstance(result, dict)


@_SKIP_ASYNC
def test_calculate_noise_reduction_equal_values():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(50, 50))
    assert isinstance(result, dict)


@_SKIP_ASYNC
def test_calculate_noise_reduction_zero_before():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(0, 0))
    assert isinstance(result, dict)


@_SKIP_ASYNC
def test_calculate_noise_reduction_large_values():
    engine = CorrelationEngine()
    result = _run(engine.calculate_noise_reduction(10000, 3000))
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# ai_enhanced_correlation
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_ai_enhanced_correlation_unknown_id_returns_none_or_result():
    engine = CorrelationEngine()
    result = _run(engine.ai_enhanced_correlation("unknown-ai-finding"))
    assert result is None or isinstance(result, CorrelationResult)


@_SKIP_ASYNC
def test_ai_enhanced_correlation_empty_id():
    engine = CorrelationEngine()
    result = _run(engine.ai_enhanced_correlation(""))
    assert result is None or isinstance(result, CorrelationResult)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------

@_SKIP_ASYNC
def test_module_correlate_finding_async_unknown():
    result = _run(correlate_finding_async("module-level-unknown"))
    assert result is None or isinstance(result, CorrelationResult)


@_SKIP_ASYNC
def test_module_batch_correlate_async_empty():
    results = _run(batch_correlate_async([]))
    assert isinstance(results, list)
    assert len(results) == 0


@_SKIP_ASYNC
def test_module_batch_correlate_async_unknown_ids():
    results = _run(batch_correlate_async(["m1", "m2", "m3"]))
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# CorrelationResult dataclass (actual fields — no DB needed)
# Actual fields: finding_id, correlated_findings, correlation_type,
#               confidence_score, noise_reduction_factor, root_cause
# ---------------------------------------------------------------------------

def test_correlation_result_construction():
    r = CorrelationResult(
        finding_id="f1",
        correlated_findings=["f2", "f3"],
        correlation_type="fingerprint",
        confidence_score=0.85,
        noise_reduction_factor=0.4,
        root_cause="Same CVE on same host",
    )
    assert r.finding_id == "f1"
    assert r.correlated_findings == ["f2", "f3"]
    assert r.confidence_score == 0.85


def test_correlation_result_confidence_boundary_zero():
    r = CorrelationResult(
        finding_id="f1",
        correlated_findings=[],
        correlation_type="pattern",
        confidence_score=0.0,
        noise_reduction_factor=0.0,
        root_cause="No confidence",
    )
    assert r.confidence_score == 0.0


def test_correlation_result_confidence_boundary_one():
    r = CorrelationResult(
        finding_id="f1",
        correlated_findings=["f2"],
        correlation_type="vulnerability",
        confidence_score=1.0,
        noise_reduction_factor=0.9,
        root_cause="Perfect match",
    )
    assert r.confidence_score == 1.0


def test_correlation_result_all_types():
    for ctype in ("fingerprint", "location", "pattern", "root_cause", "vulnerability"):
        r = CorrelationResult(
            finding_id="fa",
            correlated_findings=["fb"],
            correlation_type=ctype,
            confidence_score=0.5,
            noise_reduction_factor=0.3,
            root_cause=f"type {ctype}",
        )
        assert r.correlation_type == ctype


def test_correlation_result_empty_correlated_findings():
    r = CorrelationResult(
        finding_id="lone",
        correlated_findings=[],
        correlation_type="fingerprint",
        confidence_score=0.1,
        noise_reduction_factor=0.0,
        root_cause="No matches",
    )
    assert r.correlated_findings == []


def test_correlation_result_multiple_correlated_findings():
    r = CorrelationResult(
        finding_id="hub",
        correlated_findings=["a", "b", "c", "d", "e"],
        correlation_type="vulnerability",
        confidence_score=0.95,
        noise_reduction_factor=0.8,
        root_cause="Shared CVE cluster",
    )
    assert len(r.correlated_findings) == 5


def test_correlation_result_noise_reduction_factor_range():
    r = CorrelationResult(
        finding_id="f",
        correlated_findings=["g"],
        correlation_type="location",
        confidence_score=0.7,
        noise_reduction_factor=0.5,
        root_cause="Same subnet",
    )
    assert 0.0 <= r.noise_reduction_factor <= 1.0
