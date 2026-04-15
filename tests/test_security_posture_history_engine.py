"""Tests for SecurityPostureHistoryEngine — 35+ tests covering all methods."""
from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.security_posture_history_engine import SecurityPostureHistoryEngine

ORG = "test-org"
ORG2 = "other-org"


@pytest.fixture
def engine(tmp_path):
    return SecurityPostureHistoryEngine(db_path=str(tmp_path / "test_sph.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snap(engine, org=ORG, domain="network", score=75.0, **kwargs):
    return engine.record_snapshot(
        org_id=org, domain=domain, score=score,
        findings_count=kwargs.get("findings_count", 5),
        critical_count=kwargs.get("critical_count", 1),
        high_count=kwargs.get("high_count", 2),
        source=kwargs.get("source", "scanner"),
    )


# ---------------------------------------------------------------------------
# record_snapshot
# ---------------------------------------------------------------------------

def test_record_snapshot_returns_dict(engine):
    s = _snap(engine)
    assert isinstance(s, dict)
    assert s["domain"] == "network"
    assert s["score"] == 75.0
    assert s["org_id"] == ORG


def test_record_snapshot_overall_score_set(engine):
    s = _snap(engine)
    assert s["overall_score"] is not None
    assert 0.0 <= s["overall_score"] <= 100.0


def test_record_snapshot_clamps_score_max(engine):
    s = _snap(engine, score=150.0)
    assert s["score"] == 100.0


def test_record_snapshot_clamps_score_min(engine):
    s = _snap(engine, score=-10.0)
    assert s["score"] == 0.0


def test_record_snapshot_invalid_domain_raises(engine):
    with pytest.raises(ValueError, match="domain"):
        engine.record_snapshot(ORG, "mars", 50.0)


def test_record_snapshot_all_valid_domains(engine):
    for d in ["network", "endpoint", "cloud", "identity",
              "application", "data", "compliance", "physical"]:
        s = _snap(engine, domain=d)
        assert s["domain"] == d


def test_record_snapshot_stores_counts(engine):
    s = engine.record_snapshot(ORG, "cloud", 80.0, findings_count=10,
                               critical_count=3, high_count=4, source="cis")
    assert s["findings_count"] == 10
    assert s["critical_count"] == 3
    assert s["high_count"] == 4
    assert s["source"] == "cis"


# ---------------------------------------------------------------------------
# get_snapshots
# ---------------------------------------------------------------------------

def test_get_snapshots_returns_list(engine):
    _snap(engine)
    _snap(engine, domain="cloud")
    result = engine.get_snapshots(ORG)
    assert len(result) == 2


def test_get_snapshots_filter_by_domain(engine):
    _snap(engine, domain="network")
    _snap(engine, domain="cloud")
    result = engine.get_snapshots(ORG, domain="network")
    assert all(r["domain"] == "network" for r in result)
    assert len(result) == 1


def test_get_snapshots_org_isolation(engine):
    _snap(engine, org=ORG)
    _snap(engine, org=ORG2)
    assert len(engine.get_snapshots(ORG)) == 1
    assert len(engine.get_snapshots(ORG2)) == 1


def test_get_snapshots_empty_for_new_org(engine):
    assert engine.get_snapshots("brand-new-org") == []


def test_get_snapshots_days_filter(engine):
    _snap(engine)
    # days=0 means cutoff is now — unlikely to catch very recent records
    # days=1 should still catch a just-created record
    result = engine.get_snapshots(ORG, days=1)
    assert len(result) == 1


# ---------------------------------------------------------------------------
# compute_trend
# ---------------------------------------------------------------------------

def test_compute_trend_returns_dict(engine):
    _snap(engine, score=70.0)
    _snap(engine, score=80.0)
    t = engine.compute_trend(ORG, "network", "monthly")
    assert isinstance(t, dict)
    assert t["domain"] == "network"
    assert t["period"] == "monthly"
    assert t["trend_direction"] in {"improving", "declining", "stable"}


def test_compute_trend_stable_single_snapshot(engine):
    _snap(engine, score=75.0)
    t = engine.compute_trend(ORG, "network", "weekly")
    assert t["trend_direction"] == "stable"


def test_compute_trend_improving(engine):
    # Create enough snapshots with growing scores to force improving
    for score in [50.0, 50.0, 50.0, 90.0, 90.0, 90.0]:
        _snap(engine, score=score)
    t = engine.compute_trend(ORG, "network", "monthly")
    assert t["trend_direction"] == "improving"


def test_compute_trend_declining(engine):
    for score in [90.0, 90.0, 90.0, 50.0, 50.0, 50.0]:
        _snap(engine, score=score)
    t = engine.compute_trend(ORG, "network", "monthly")
    assert t["trend_direction"] == "declining"


def test_compute_trend_invalid_period_raises(engine):
    with pytest.raises(ValueError, match="period"):
        engine.compute_trend(ORG, "network", "yearly")


def test_compute_trend_invalid_domain_raises(engine):
    with pytest.raises(ValueError, match="domain"):
        engine.compute_trend(ORG, "mars", "monthly")


def test_compute_trend_all_valid_periods(engine):
    _snap(engine)
    for p in ["weekly", "monthly", "quarterly"]:
        t = engine.compute_trend(ORG, "network", p)
        assert t["period"] == p


def test_compute_trend_stores_avg_min_max(engine):
    _snap(engine, score=60.0)
    _snap(engine, score=80.0)
    t = engine.compute_trend(ORG, "network", "monthly")
    assert t["min_score"] <= t["avg_score"] <= t["max_score"]


def test_compute_trend_no_snapshots_returns_zeros(engine):
    t = engine.compute_trend(ORG, "cloud", "monthly")
    assert t["avg_score"] == 0.0
    assert t["min_score"] == 0.0
    assert t["max_score"] == 0.0


# ---------------------------------------------------------------------------
# get_trends
# ---------------------------------------------------------------------------

def test_get_trends_returns_list(engine):
    _snap(engine)
    engine.compute_trend(ORG, "network", "monthly")
    trends = engine.get_trends(ORG)
    assert len(trends) >= 1


def test_get_trends_filter_by_domain(engine):
    _snap(engine, domain="network")
    _snap(engine, domain="cloud")
    engine.compute_trend(ORG, "network", "monthly")
    engine.compute_trend(ORG, "cloud", "monthly")
    trends = engine.get_trends(ORG, domain="network")
    assert all(t["domain"] == "network" for t in trends)


def test_get_trends_org_isolation(engine):
    _snap(engine, org=ORG)
    _snap(engine, org=ORG2)
    engine.compute_trend(ORG, "network", "monthly")
    engine.compute_trend(ORG2, "network", "monthly")
    assert len(engine.get_trends(ORG)) == 1
    assert len(engine.get_trends(ORG2)) == 1


# ---------------------------------------------------------------------------
# set_baseline & get_baseline
# ---------------------------------------------------------------------------

def test_set_baseline_returns_dict(engine):
    b = engine.set_baseline(ORG, "network", 70.0, 90.0, "admin")
    assert isinstance(b, dict)
    assert b["domain"] == "network"
    assert b["baseline_score"] == 70.0
    assert b["target_score"] == 90.0
    assert b["set_by"] == "admin"


def test_set_baseline_upserts(engine):
    engine.set_baseline(ORG, "network", 70.0, 90.0, "admin")
    b2 = engine.set_baseline(ORG, "network", 75.0, 95.0, "admin2")
    assert b2["baseline_score"] == 75.0
    assert b2["target_score"] == 95.0


def test_set_baseline_invalid_domain_raises(engine):
    with pytest.raises(ValueError, match="domain"):
        engine.set_baseline(ORG, "mars", 50.0, 80.0)


def test_get_baseline_returns_dict(engine):
    engine.set_baseline(ORG, "cloud", 65.0, 85.0, "sre")
    b = engine.get_baseline(ORG, "cloud")
    assert b is not None
    assert b["domain"] == "cloud"
    assert b["baseline_score"] == 65.0


def test_get_baseline_not_found_returns_none(engine):
    result = engine.get_baseline(ORG, "network")
    assert result is None


def test_get_baseline_org_isolation(engine):
    engine.set_baseline(ORG, "network", 70.0, 90.0)
    result = engine.get_baseline(ORG2, "network")
    assert result is None


# ---------------------------------------------------------------------------
# get_posture_delta
# ---------------------------------------------------------------------------

def test_get_posture_delta_no_snapshots(engine):
    delta = engine.get_posture_delta(ORG, "network", days=30)
    assert delta["delta"] is None
    assert delta["oldest_score"] is None
    assert delta["newest_score"] is None


def test_get_posture_delta_single_snapshot(engine):
    _snap(engine, score=70.0)
    delta = engine.get_posture_delta(ORG, "network", days=30)
    assert delta["oldest_score"] == 70.0
    assert delta["newest_score"] == 70.0
    assert delta["delta"] == 0.0


def test_get_posture_delta_positive(engine):
    _snap(engine, score=60.0)
    _snap(engine, score=80.0)
    delta = engine.get_posture_delta(ORG, "network", days=30)
    assert delta["delta"] == pytest.approx(20.0, abs=0.1)


def test_get_posture_delta_negative(engine):
    _snap(engine, score=80.0)
    _snap(engine, score=60.0)
    delta = engine.get_posture_delta(ORG, "network", days=30)
    assert delta["delta"] == pytest.approx(-20.0, abs=0.1)


def test_get_posture_delta_domain_filter(engine):
    _snap(engine, domain="network", score=60.0)
    _snap(engine, domain="cloud", score=90.0)
    delta = engine.get_posture_delta(ORG, "cloud", days=30)
    assert delta["oldest_score"] == 90.0


# ---------------------------------------------------------------------------
# get_domain_summary
# ---------------------------------------------------------------------------

def test_get_domain_summary_empty(engine):
    result = engine.get_domain_summary(ORG)
    assert result == []


def test_get_domain_summary_returns_domains(engine):
    _snap(engine, domain="network", score=75.0)
    _snap(engine, domain="cloud", score=85.0)
    result = engine.get_domain_summary(ORG)
    domains = {r["domain"] for r in result}
    assert "network" in domains
    assert "cloud" in domains


def test_get_domain_summary_includes_gap_when_baseline_set(engine):
    _snap(engine, domain="network", score=75.0)
    engine.set_baseline(ORG, "network", 70.0, 90.0)
    result = engine.get_domain_summary(ORG)
    net = next(r for r in result if r["domain"] == "network")
    assert net["gap_from_baseline"] is not None
    assert net["gap_from_target"] is not None


def test_get_domain_summary_gap_none_without_baseline(engine):
    _snap(engine, domain="endpoint", score=60.0)
    result = engine.get_domain_summary(ORG)
    ep = next(r for r in result if r["domain"] == "endpoint")
    assert ep["gap_from_baseline"] is None
    assert ep["gap_from_target"] is None


def test_get_domain_summary_org_isolation(engine):
    _snap(engine, org=ORG, domain="network")
    _snap(engine, org=ORG2, domain="cloud")
    summary_org1 = engine.get_domain_summary(ORG)
    assert all(r["domain"] == "network" for r in summary_org1)
    summary_org2 = engine.get_domain_summary(ORG2)
    assert all(r["domain"] == "cloud" for r in summary_org2)
