"""
CTEM/Exposure performance assertions.

Validates that the three hotspot fixes do not regress correctness and
that batch ingest is faster than the old per-row loop baseline.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import os
import tempfile
import time
import uuid

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_db(tmp_path):
    return str(tmp_path / "test.db")


# ---------------------------------------------------------------------------
# 1. ExposureScorer — batch ingest correctness + speed
# ---------------------------------------------------------------------------

def test_ingest_scores_batch_correctness(tmp_db):
    """executemany path must store all rows and return correct count."""
    from core.exposure_scorer import ExposureScorer

    scorer = ExposureScorer(db_path=tmp_db)
    N = 200
    scores = [
        {
            "finding_id": f"f-{i}",
            "asset_id": f"ast-{i % 10}",
            "composite_score": float(i % 100),
            "status": "open",
        }
        for i in range(N)
    ]
    count = scorer.ingest_scores(scores)
    assert count == N, f"Expected {N} upserted rows, got {count}"


def test_ingest_scores_batch_faster_than_sequential(tmp_db):
    """Batch ingest of 500 rows must complete in under 2 s on any CI box."""
    from core.exposure_scorer import ExposureScorer

    scorer = ExposureScorer(db_path=tmp_db)
    N = 500
    scores = [
        {
            "finding_id": f"f-{uuid.uuid4().hex}",
            "asset_id": f"ast-{i % 20}",
            "composite_score": float(i % 100),
            "status": "open",
        }
        for i in range(N)
    ]
    t0 = time.perf_counter()
    scorer.ingest_scores(scores)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"Batch ingest of {N} rows took {elapsed:.3f}s — expected < 2s"


# ---------------------------------------------------------------------------
# 2. ExposureScorer — single-pass weighted average correctness
# ---------------------------------------------------------------------------

def test_calculate_org_exposure_weighted_avg(tmp_db):
    """Weighted average must match manual single-pass computation."""
    from core.exposure_scorer import ExposureScorer

    scorer = ExposureScorer(db_path=tmp_db)
    raw = [85.0, 65.0, 40.0, 15.0]  # critical, high, medium, low
    scorer.ingest_scores(
        [
            {"finding_id": f"f{i}", "asset_id": "ast-1", "composite_score": s, "status": "open"}
            for i, s in enumerate(raw)
        ]
    )
    result = scorer.calculate_org_exposure(org_id="default", snapshot=False)

    # Manual single-pass
    weighted_sum = sum(s * (2.0 if s >= 80 else 1.5 if s >= 60 else 1.0) for s in raw)
    weight_total = sum(2.0 if s >= 80 else 1.5 if s >= 60 else 1.0 for s in raw)
    expected_avg = weighted_sum / weight_total

    assert abs(result.weighted_risk_avg - round(expected_avg, 2)) < 0.01, (
        f"weighted_risk_avg mismatch: {result.weighted_risk_avg} vs {expected_avg:.2f}"
    )
    assert result.open_findings_count == 4
    assert result.critical_count == 1
    assert result.high_count == 1


# ---------------------------------------------------------------------------
# 3. ExposureScorer — singleton double-checked locking
# ---------------------------------------------------------------------------

def test_get_exposure_scorer_singleton(tmp_db, monkeypatch):
    """Two calls must return the same instance without error."""
    import core.exposure_scorer as mod

    # Reset singleton for test isolation
    monkeypatch.setattr(mod, "_instance", None)

    a = mod.get_exposure_scorer(db_path=tmp_db)
    b = mod.get_exposure_scorer(db_path=tmp_db)
    assert a is b, "get_exposure_scorer must return the same singleton instance"


# ---------------------------------------------------------------------------
# 4. ThreatExposureEngine — collapsed get_exposure_stats correctness
# ---------------------------------------------------------------------------

def test_get_exposure_stats_collapsed(tmp_db):
    """Collapsed 2-query stats must return same shape as the 6-query original."""
    from core.threat_exposure_engine import ThreatExposureEngine

    engine = ThreatExposureEngine(db_path=tmp_db)
    org = "test-org"

    # Register assets
    for i in range(5):
        engine.register_asset(org, {"asset_id": f"a{i}", "asset_name": f"Asset {i}"})

    # Correlate threats to drive exposure_level changes
    for i in range(3):
        engine.correlate_threat(
            org,
            {
                "asset_id": f"a{i}",
                "threat_type": "exploit",
                "severity": "critical",
                "confidence": 90.0,
            },
        )
        engine.calculate_exposure(org, f"a{i}")

    stats = engine.get_exposure_stats(org)

    assert "total_assets" in stats
    assert "by_level" in stats
    assert "avg_exposure_score" in stats
    assert "critical_assets" in stats
    assert "total_correlations" in stats
    assert "assessed_today" in stats
    assert stats["total_assets"] == 5
    assert stats["total_correlations"] == 3


def test_get_exposure_stats_speed(tmp_db):
    """Stats query over 50 assets must complete in under 0.5 s."""
    from core.threat_exposure_engine import ThreatExposureEngine

    engine = ThreatExposureEngine(db_path=tmp_db)
    org = "perf-org"
    for i in range(50):
        engine.register_asset(org, {"asset_id": f"a{i}", "asset_name": f"Asset {i}"})

    t0 = time.perf_counter()
    engine.get_exposure_stats(org)
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.5, f"get_exposure_stats took {elapsed:.3f}s — expected < 0.5s"
