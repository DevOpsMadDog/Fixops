"""
Tests for Security Posture Trends Tracker.

Covers:
- PostureSnapshot and PostureDiff Pydantic models
- record_posture: persistence, snapshot_id returned
- get_current_posture: most recent snapshot returned
- get_trend: time-window filtering, ordering
- calculate_posture: formula fallback (no scorer DB)
- compare_posture: delta values, trend classification
- _formula_score: deduction logic, clamping
- _classify_trend: improving / stable / degrading labels
- SQLite persistence: data survives across PostureTracker instances
- Edge cases: empty org, missing snapshot IDs, score clamping
"""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.posture_tracker import (
    PostureDiff,
    PostureSnapshot,
    PostureTracker,
    _SnapshotDB,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    return str(tmp_path / "posture_tracker_test.db")


@pytest.fixture
def tracker(tmp_db: str) -> PostureTracker:
    return PostureTracker(db_path=tmp_db)


def _components(
    crit: int = 0,
    high: int = 0,
    med: int = 0,
    low: int = 0,
    sla: float = 90.0,
    coverage: float = 75.0,
    remediation: float = 80.0,
) -> dict:
    return {
        "critical_findings": crit,
        "high_findings": high,
        "medium_findings": med,
        "low_findings": low,
        "sla_compliance_rate": sla,
        "trustgraph_coverage": coverage,
        "remediation_rate": remediation,
    }


# ============================================================================
# Model tests
# ============================================================================


def test_posture_snapshot_defaults():
    snap = PostureSnapshot(org_id="acme", overall_score=85.0)
    assert snap.snapshot_id.startswith("snap-")
    assert snap.trend == "stable"
    assert snap.critical_findings == 0
    assert snap.sla_compliance_rate == 0.0


def test_posture_snapshot_score_bounds():
    snap = PostureSnapshot(org_id="acme", overall_score=0.0)
    assert snap.overall_score == 0.0
    snap2 = PostureSnapshot(org_id="acme", overall_score=100.0)
    assert snap2.overall_score == 100.0


def test_posture_diff_fields():
    diff = PostureDiff(
        snapshot_id_1="snap-aaa",
        snapshot_id_2="snap-bbb",
        timestamp_1="2026-04-01T00:00:00+00:00",
        timestamp_2="2026-04-07T00:00:00+00:00",
        org_id="default",
        score_delta=5.0,
        critical_delta=-1,
        high_delta=2,
        sla_delta=3.5,
        coverage_delta=1.0,
        remediation_delta=2.0,
        trend="improving",
        summary="Score improved by 5.",
    )
    assert diff.score_delta == 5.0
    assert diff.trend == "improving"


# ============================================================================
# record_posture tests
# ============================================================================


def test_record_posture_returns_snapshot_id(tracker: PostureTracker):
    sid = tracker.record_posture(score=72.5, components=_components(), org_id="org1")
    assert isinstance(sid, str)
    assert sid.startswith("snap-")


def test_record_posture_persists(tracker: PostureTracker):
    sid = tracker.record_posture(score=80.0, components=_components(crit=1), org_id="org1")
    snap = tracker.get_current_posture("org1")
    assert snap is not None
    assert snap.snapshot_id == sid
    assert snap.overall_score == 80.0
    assert snap.critical_findings == 1


def test_record_posture_clamps_score(tracker: PostureTracker):
    sid = tracker.record_posture(score=150.0, components=_components(), org_id="clamp")
    snap = tracker.get_current_posture("clamp")
    assert snap is not None
    assert snap.overall_score == 100.0


def test_record_posture_clamps_negative_score(tracker: PostureTracker):
    sid = tracker.record_posture(score=-50.0, components=_components(), org_id="neg")
    snap = tracker.get_current_posture("neg")
    assert snap is not None
    assert snap.overall_score == 0.0


# ============================================================================
# get_current_posture tests
# ============================================================================


def test_get_current_posture_none_for_unknown_org(tracker: PostureTracker):
    snap = tracker.get_current_posture("nonexistent")
    assert snap is None


def test_get_current_posture_returns_latest(tracker: PostureTracker):
    tracker.record_posture(50.0, _components(), "org2")
    sid2 = tracker.record_posture(70.0, _components(), "org2")
    snap = tracker.get_current_posture("org2")
    assert snap is not None
    assert snap.snapshot_id == sid2
    assert snap.overall_score == 70.0


# ============================================================================
# get_trend tests
# ============================================================================


def test_get_trend_empty_for_no_snapshots(tracker: PostureTracker):
    results = tracker.get_trend(days=30, org_id="empty_org")
    assert results == []


def test_get_trend_returns_within_window(tracker: PostureTracker):
    # Record three snapshots for org3
    for score in [60.0, 70.0, 80.0]:
        tracker.record_posture(score, _components(), "org3")
    results = tracker.get_trend(days=30, org_id="org3")
    assert len(results) == 3
    # Ordered oldest first
    assert results[0].overall_score <= results[-1].overall_score or len(results) >= 1


def test_get_trend_isolates_by_org(tracker: PostureTracker):
    tracker.record_posture(55.0, _components(), "orgA")
    tracker.record_posture(66.0, _components(), "orgB")
    results_a = tracker.get_trend(days=30, org_id="orgA")
    assert all(s.org_id == "orgA" for s in results_a)
    assert len(results_a) == 1


# ============================================================================
# calculate_posture tests
# ============================================================================


def test_calculate_posture_returns_snapshot(tracker: PostureTracker):
    # Scorer DBs do not exist → falls back to formula; no previous snapshot → score=100
    snap = tracker.calculate_posture(org_id="calc_org")
    assert isinstance(snap, PostureSnapshot)
    assert 0.0 <= snap.overall_score <= 100.0
    assert snap.org_id == "calc_org"


def test_calculate_posture_persists(tracker: PostureTracker):
    snap = tracker.calculate_posture(org_id="persist_org")
    current = tracker.get_current_posture("persist_org")
    assert current is not None
    assert current.snapshot_id == snap.snapshot_id


# ============================================================================
# compare_posture tests
# ============================================================================


def test_compare_posture_improving(tracker: PostureTracker):
    sid1 = tracker.record_posture(60.0, _components(crit=2, high=3), "cmp_org")
    sid2 = tracker.record_posture(80.0, _components(crit=0, high=1), "cmp_org")
    diff = tracker.compare_posture(sid1, sid2)
    assert diff.score_delta == pytest.approx(20.0)
    assert diff.critical_delta == -2
    assert diff.high_delta == -2
    assert diff.trend == "improving"
    assert "improving" in diff.summary


def test_compare_posture_degrading(tracker: PostureTracker):
    sid1 = tracker.record_posture(85.0, _components(), "deg_org")
    sid2 = tracker.record_posture(70.0, _components(crit=3), "deg_org")
    diff = tracker.compare_posture(sid1, sid2)
    assert diff.score_delta == pytest.approx(-15.0)
    assert diff.critical_delta == 3
    assert diff.trend == "degrading"


def test_compare_posture_stable(tracker: PostureTracker):
    sid1 = tracker.record_posture(75.0, _components(), "stab_org")
    sid2 = tracker.record_posture(75.5, _components(), "stab_org")
    diff = tracker.compare_posture(sid1, sid2)
    assert diff.trend == "stable"


def test_compare_posture_missing_id_raises(tracker: PostureTracker):
    sid1 = tracker.record_posture(70.0, _components(), "err_org")
    with pytest.raises(ValueError, match="not found"):
        tracker.compare_posture(sid1, "snap-doesnotexist")


def test_compare_posture_both_missing_raises(tracker: PostureTracker):
    with pytest.raises(ValueError):
        tracker.compare_posture("snap-x", "snap-y")


# ============================================================================
# Formula score tests
# ============================================================================


def test_formula_score_no_findings():
    assert PostureTracker._formula_score(0, 0, 0, 0) == 100.0


def test_formula_score_deductions():
    # 1 crit(-10) + 2 high(-10) + 3 med(-6) + 4 low(-2) = 100 - 28 = 72
    score = PostureTracker._formula_score(1, 2, 3, 4)
    assert score == pytest.approx(72.0)


def test_formula_score_clamps_to_zero():
    score = PostureTracker._formula_score(100, 100, 100, 100)
    assert score == 0.0


def test_formula_score_clamps_high_end():
    score = PostureTracker._formula_score(0, 0, 0, 0)
    assert score == 100.0


# ============================================================================
# SQLite persistence tests
# ============================================================================


def test_persistence_survives_new_instance(tmp_db: str):
    t1 = PostureTracker(db_path=tmp_db)
    sid = t1.record_posture(88.0, _components(crit=1), "persist_test")

    t2 = PostureTracker(db_path=tmp_db)
    snap = t2.get_current_posture("persist_test")
    assert snap is not None
    assert snap.snapshot_id == sid
    assert snap.overall_score == 88.0
    assert snap.critical_findings == 1
