"""
Performance lockdown benchmarks for ALDECI.

Three regressions locked in from session 2026-05-04:
  - RSA singleton   : commit 1276b4df  (2111 ms → <50 ms)
  - risk_scorer     : commit 4bbd12ad  (527 ms  → <50 ms)
  - brain_pipeline  : commit ee340f83  (~2 s saved on feed reload)

Run with:
    python -m pytest tests/benchmarks/ -m benchmark -x --tb=short --timeout=15 -q -o "addopts="

Thresholds (enforced as hard assertions):
  RSA p95 (singleton, calls 2-100)  : < 5 ms
  risk_scorer predict_batch (100)   : < 100 ms  (best of 5 runs)
  brain_pipeline warm feed reload   : < 10 ms
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Ensure suite-core is importable regardless of working directory
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SUITE_CORE = _REPO_ROOT / "suite-core"
for _p in [str(_REPO_ROOT), str(_SUITE_CORE)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _perf_counter_ms() -> float:
    return time.perf_counter() * 1_000


def _best_of(fn, *, runs: int = 5) -> float:
    """Return the minimum wall-time (ms) across *runs* executions of *fn*."""
    times: List[float] = []
    for _ in range(runs):
        t0 = _perf_counter_ms()
        fn()
        times.append(_perf_counter_ms() - t0)
    return min(times)


def _percentile(data: List[float], p: int) -> float:
    """Return the p-th percentile of *data* (sorted copy, nearest-rank)."""
    if not data:
        raise ValueError("empty data")
    sd = sorted(data)
    idx = max(0, int(len(sd) * p / 100) - 1)
    return sd[idx]


# ===========================================================================
# 1. RSA singleton benchmark
# ===========================================================================

@pytest.mark.benchmark
def test_rsa_singleton_p95_under_5ms():
    """
    After the first call (key load), get_crypto_manager() must return the
    cached singleton in < 5 ms at p95 across calls 2-100.

    Threshold: p95 < 5 ms
    Locked in: commit 1276b4df (was ~2 111 ms cold → <50 ms warm)
    """
    from core.crypto import get_crypto_manager, reset_crypto_manager

    # Reset so we control the cold call
    reset_crypto_manager()

    # Cold call — not measured (key load / keygen allowed to be slow)
    get_crypto_manager()

    # Warm calls — these must be O(1) singleton lookups
    latencies: List[float] = []
    for _ in range(99):          # calls 2-100
        t0 = _perf_counter_ms()
        mgr = get_crypto_manager()
        latencies.append(_perf_counter_ms() - t0)
        assert mgr is not None

    p95 = _percentile(latencies, 95)
    avg = mean(latencies)

    print(
        f"\n[RSA singleton] p95={p95:.3f} ms  avg={avg:.3f} ms  "
        f"(threshold: p95 < 5 ms)"
    )

    assert p95 < 5.0, (
        f"RSA singleton p95 regression: {p95:.3f} ms >= 5 ms threshold. "
        f"Commit 1276b4df broke — check CryptoManager singleton path."
    )


# ===========================================================================
# 2. risk_scorer batch benchmark
# ===========================================================================

def _make_vuln(i: int) -> Dict[str, Any]:
    """Build a realistic vulnerability dict for the risk scorer."""
    return {
        "cve_id": f"CVE-2024-{10000 + i}",
        "cvss_score": 5.0 + (i % 5),           # 5.0-9.0 range
        "epss_score": 0.01 * (i % 10),          # 0.0-0.09
        "in_kev": (i % 7 == 0),
        "asset_criticality": 0.3 + 0.04 * (i % 10),
        "network_exposure": ["internet", "internal", "isolated"][i % 3],
        "exploit_available": (i % 4 == 0),
        "exploit_maturity": ["none", "poc", "weaponized"][i % 3],
        "reachable": (i % 5 != 0),
        "has_chain": (i % 11 == 0),
    }


@pytest.mark.benchmark
def test_risk_scorer_batch_under_100ms():
    """
    predict_batch() on 100 findings must complete in < 100 ms (best of 5).
    Uses the deterministic fallback path — no trained model required.

    Threshold: best-of-5 wall time < 100 ms
    Locked in: commit 4bbd12ad (was ~527 ms → <50 ms)
    """
    from core.ml.risk_scorer import RiskScoringModel

    model = RiskScoringModel()
    vulns = [_make_vuln(i) for i in range(100)]

    # Warm-up: one un-timed call so any lazy init is done
    model.predict_batch(vulns[:5])

    best_ms = _best_of(lambda: model.predict_batch(vulns), runs=5)

    print(
        f"\n[risk_scorer batch 100] best={best_ms:.1f} ms  "
        f"(threshold: < 100 ms)"
    )

    assert best_ms < 100.0, (
        f"risk_scorer batch regression: {best_ms:.1f} ms >= 100 ms threshold. "
        f"Commit 4bbd12ad broke — check predict_batch() or extract_features()."
    )


# ===========================================================================
# 3. brain_pipeline warm feed reload benchmark
# ===========================================================================

@pytest.mark.benchmark
def test_brain_pipeline_warm_feed_reload_under_10ms():
    """
    The second call to BrainPipeline._load_local_feeds() within the 5-min TTL
    must return from cache in < 10 ms.

    Threshold: warm call < 10 ms
    Locked in: commit ee340f83 (~2 s saved per pipeline run)
    """
    from core.brain_pipeline import BrainPipeline

    # Force-prime the cache (cold call — not measured)
    BrainPipeline._feeds_cache = None
    BrainPipeline._feeds_cache_ts = 0.0
    BrainPipeline._load_local_feeds()

    # Verify cache is now populated
    assert BrainPipeline._feeds_cache is not None, (
        "Cache not populated after first call — check _load_local_feeds logic"
    )

    # Warm call — must hit TTL cache
    t0 = _perf_counter_ms()
    result = BrainPipeline._load_local_feeds()
    warm_ms = _perf_counter_ms() - t0

    print(
        f"\n[brain_pipeline warm feeds] warm={warm_ms:.3f} ms  "
        f"(threshold: < 10 ms)"
    )

    assert isinstance(result, tuple) and len(result) == 3, (
        "_load_local_feeds must return a 3-tuple (epss, kev, nvd)"
    )
    assert warm_ms < 10.0, (
        f"brain_pipeline warm feed reload regression: {warm_ms:.3f} ms >= 10 ms. "
        f"Commit ee340f83 broke — check _feeds_cache TTL path."
    )
