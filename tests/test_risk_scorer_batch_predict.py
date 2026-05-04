"""Tests for batched risk scoring (perf fix #2 — risk_scorer.py:507).

Validates that ``RiskScoringModel.predict_batch`` is:
  1. Length-correct: produces N PredictionResults for N findings.
  2. Numerically equivalent: per-finding values match the prior loop output
     (same risk_score, CI bounds, priority, and feature contributions).
  3. Fast: 50 findings < 50 ms wall time (was ~527 ms in the per-finding loop).

Reference: docs/perf/brain_pipeline_profile_2026-04-27.md (Bottleneck #2).
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import math
import time
from typing import Any, Dict, List

import pytest

# Force the test to use the source-of-truth module (sitecustomize wires sys.path)
from core.ml.risk_scorer import (  # type: ignore  # noqa: E402
    FEATURE_NAMES,
    PredictionResult,
    RiskScoringModel,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Representative CVE mix — covers the feature space used by the GBT model.
_VULN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2024-3094",
        "cvss_score": 9.8,
        "epss_score": 0.95,
        "in_kev": True,
        "asset_criticality": 1.0,
        "network_exposure": "internet",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "reachable": True,
    },
    {
        "cve_id": "CVE-2023-0001",
        "cvss_score": 7.5,
        "epss_score": 0.4,
        "in_kev": False,
        "asset_criticality": 0.7,
        "network_exposure": "partner",
        "exploit_available": True,
        "exploit_maturity": "active",
        "reachable": True,
    },
    {
        "cve_id": "CVE-2022-99999",
        "cvss_score": 5.0,
        "epss_score": 0.05,
        "in_kev": False,
        "asset_criticality": 0.5,
        "network_exposure": "internal",
        "exploit_available": False,
        "exploit_maturity": "none",
        "reachable": False,
    },
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.97,
        "in_kev": True,
        "asset_criticality": 0.9,
        "network_exposure": "internet",
        "exploit_available": True,
        "exploit_maturity": "weaponized",
        "reachable": True,
        "chain_cves": ["CVE-2021-45046"],
    },
    {
        "cve_id": "CVE-2020-1472",
        "cvss_score": 8.1,
        "epss_score": 0.6,
        "in_kev": True,
        "asset_criticality": 0.8,
        "network_exposure": "controlled",
        "exploit_available": True,
        "exploit_maturity": "proof_of_concept",
        "reachable": True,
    },
]


def _build_findings(n: int) -> List[Dict[str, Any]]:
    """Build n findings by cycling templates with deterministic per-index jitter."""
    findings: List[Dict[str, Any]] = []
    for i in range(n):
        tpl = dict(_VULN_TEMPLATES[i % len(_VULN_TEMPLATES)])
        # Light jitter so we don't end up with fully duplicated rows
        tpl["asset_criticality"] = round(
            min(max(tpl["asset_criticality"] - (i % 7) * 0.03, 0.0), 1.0), 3
        )
        tpl["epss_score"] = round(
            min(max(tpl["epss_score"] - (i % 5) * 0.02, 0.0), 1.0), 3
        )
        findings.append(tpl)
    return findings


@pytest.fixture(scope="module")
def trained_model() -> RiskScoringModel:
    """Train a fresh model from the golden dataset for this test module.

    We deliberately train rather than load a cached pickle — this keeps the
    test self-contained and immune to "stale model on disk" surprises.
    """
    from pathlib import Path

    golden = Path("data/golden_regression_cases.json")
    if not golden.exists():
        pytest.skip("golden_regression_cases.json not present in this checkout")

    model = RiskScoringModel(random_seed=42)
    model.train_from_golden_dataset(golden_path=golden, n_bootstrap=5)
    assert model.is_trained
    return model


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_predict_batch_returns_correct_length(trained_model: RiskScoringModel) -> None:
    findings = _build_findings(50)
    preds = trained_model.predict_batch(findings)

    assert isinstance(preds, list)
    assert len(preds) == 50
    assert all(isinstance(p, PredictionResult) for p in preds)


def test_predict_batch_empty_input(trained_model: RiskScoringModel) -> None:
    assert trained_model.predict_batch([]) == []


def test_predict_batch_numerical_equivalence_to_per_finding(
    trained_model: RiskScoringModel,
) -> None:
    """Per-finding values from predict_batch must match predict() called per item."""
    findings = _build_findings(50)

    batch_preds = trained_model.predict_batch(findings)
    loop_preds = [trained_model.predict(v) for v in findings]

    assert len(batch_preds) == len(loop_preds) == 50

    for i, (b, l) in enumerate(zip(batch_preds, loop_preds)):
        # risk score (0-100) — sklearn predict is deterministic given fixed seed
        assert math.isclose(b.risk_score, l.risk_score, abs_tol=1e-6), (
            f"finding {i}: batch risk_score={b.risk_score} vs loop={l.risk_score}"
        )

        # CI bounds — driven by bootstrap models; same X → same percentiles
        assert math.isclose(
            b.confidence_interval[0], l.confidence_interval[0], abs_tol=1e-6
        ), f"finding {i}: ci_low mismatch"
        assert math.isclose(
            b.confidence_interval[1], l.confidence_interval[1], abs_tol=1e-6
        ), f"finding {i}: ci_high mismatch"

        # Priority is derived from risk_score → must match
        assert b.priority == l.priority, (
            f"finding {i}: priority {b.priority} vs {l.priority}"
        )

        # Feature contributions — interventional approach is the same;
        # batched version reshapes a (F*N, F) matrix predict, scalar version
        # iterates per feature. Values must match within float precision.
        assert set(b.feature_contributions.keys()) == set(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            assert math.isclose(
                b.feature_contributions[name],
                l.feature_contributions[name],
                abs_tol=1e-6,
            ), (
                f"finding {i}: contribution[{name}] "
                f"batch={b.feature_contributions[name]} vs loop={l.feature_contributions[name]}"
            )


def test_predict_batch_wall_time_under_50ms_for_50_findings(
    trained_model: RiskScoringModel,
) -> None:
    """50 findings must batch-predict in < 50 ms on developer hardware.

    Baseline (per-finding loop) was 527 ms in the cProfile snapshot
    (docs/perf/brain_pipeline_profile_2026-04-27.md). Target is ~30 ms;
    we assert < 50 ms to leave headroom for slower CI runners.
    """
    findings = _build_findings(50)

    # Warm-up — first call after model fit can pay one-time JIT/validation costs.
    trained_model.predict_batch(findings)

    n_iters = 5
    timings_ms: List[float] = []
    for _ in range(n_iters):
        t0 = time.monotonic()
        preds = trained_model.predict_batch(findings)
        timings_ms.append((time.monotonic() - t0) * 1000.0)
        assert len(preds) == 50

    best_ms = min(timings_ms)
    assert best_ms < 50.0, (
        f"predict_batch(50 findings) took {best_ms:.1f} ms; "
        f"expected < 50 ms (per-finding baseline was 527 ms). "
        f"All timings: {[round(t, 1) for t in timings_ms]}"
    )


def test_predict_batch_single_finding(trained_model: RiskScoringModel) -> None:
    """Single-finding input must return a list of length 1, not crash."""
    finding = [_VULN_TEMPLATES[0]]
    preds = trained_model.predict_batch(finding)
    assert isinstance(preds, list)
    assert len(preds) == 1
    assert isinstance(preds[0], PredictionResult)
    assert 0.0 <= preds[0].risk_score <= 100.0
    # Must match the scalar predict() path within float tolerance
    scalar = trained_model.predict(_VULN_TEMPLATES[0])
    assert math.isclose(preds[0].risk_score, scalar.risk_score, abs_tol=1e-6), (
        f"single-finding: batch={preds[0].risk_score} vs scalar={scalar.risk_score}"
    )


def test_predict_batch_speedup_vs_per_finding_loop(
    trained_model: RiskScoringModel,
) -> None:
    """predict_batch should be substantially faster than the per-finding loop.

    Conservative gate: at least 5x faster. Target speedup is ~17x but CI noise
    makes a hard 10x assertion flaky on shared runners.
    """
    findings = _build_findings(50)

    # Warm sklearn paths.
    trained_model.predict_batch(findings)
    [trained_model.predict(v) for v in findings]

    t0 = time.monotonic()
    trained_model.predict_batch(findings)
    batch_ms = (time.monotonic() - t0) * 1000.0

    t0 = time.monotonic()
    [trained_model.predict(v) for v in findings]
    loop_ms = (time.monotonic() - t0) * 1000.0

    speedup = loop_ms / max(batch_ms, 0.01)
    assert speedup >= 5.0, (
        f"batch_ms={batch_ms:.1f} ms, loop_ms={loop_ms:.1f} ms, "
        f"speedup={speedup:.1f}x (expected >= 5x)"
    )


def test_predict_batch_n100_under_100ms(trained_model: RiskScoringModel) -> None:
    """N=100 findings must complete via predict_batch in < 100 ms.

    Perf fix #2 target: single vectorized sklearn predict() over (100, 9)
    matrix instead of 100 individual calls. Baseline per-finding loop was
    ~527 ms for 50 findings (~1054 ms projected for 100). Target < 100 ms.
    """
    findings = _build_findings(100)

    # Warm-up to avoid one-time sklearn/numpy JIT costs.
    trained_model.predict_batch(findings)

    n_iters = 5
    timings_ms: List[float] = []
    for _ in range(n_iters):
        t0 = time.monotonic()
        preds = trained_model.predict_batch(findings)
        timings_ms.append((time.monotonic() - t0) * 1000.0)
        assert len(preds) == 100

    best_ms = min(timings_ms)
    assert best_ms < 100.0, (
        f"predict_batch(100 findings) took {best_ms:.1f} ms best of {n_iters}; "
        f"expected < 100 ms (per-finding baseline was ~1054 ms projected). "
        f"All timings: {[round(t, 1) for t in timings_ms]}"
    )

    # Sanity: all results are valid PredictionResults with scores in [0, 100].
    assert all(isinstance(p, PredictionResult) for p in preds)
    assert all(0.0 <= p.risk_score <= 100.0 for p in preds)
