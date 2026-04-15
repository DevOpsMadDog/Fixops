"""Tests for SecurityBaselineEngine.

Covers: control_count increment, compliance_pct formula (pass/(pass+fail)*100),
skip excluded from compliance calc, drift report improved/degraded detection,
publish sets published_at, org isolation, list_baselines filtering.

Total: 40 tests.
"""

from __future__ import annotations

import os
import pytest

from core.security_baseline_engine import SecurityBaselineEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path):
    return SecurityBaselineEngine(db_path=str(tmp_path / "sb_test.db"))


@pytest.fixture()
def baseline(engine):
    return engine.create_baseline(
        org_id="org1",
        baseline_name="CIS Ubuntu 22.04",
        target_type="server",
        framework="CIS",
        version="1.0",
        created_by="admin",
    )


@pytest.fixture()
def baseline_with_controls(engine, baseline):
    bl_id = baseline["id"]
    for i in range(3):
        engine.add_control(
            baseline_id=bl_id,
            org_id="org1",
            control_id=f"CIS-{i+1}",
            control_name=f"Control {i+1}",
            category="Access",
            description="desc",
            expected_value="enabled",
            severity="high",
        )
    return baseline["id"]


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "sb_init.db")
    SecurityBaselineEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "sb_idem.db")
    SecurityBaselineEngine(db_path=db)
    SecurityBaselineEngine(db_path=db)


# ===========================================================================
# 2. create_baseline
# ===========================================================================

def test_create_baseline_returns_record(baseline):
    assert baseline["status"] == "draft"
    assert baseline["control_count"] == 0
    assert baseline["published_at"] is None


def test_create_baseline_invalid_target_type(engine):
    with pytest.raises(ValueError, match="target_type"):
        engine.create_baseline("org1", "Bad", "spaceship", "CIS", "1.0", "admin")


def test_create_baseline_invalid_framework(engine):
    with pytest.raises(ValueError, match="framework"):
        engine.create_baseline("org1", "Bad", "server", "UNKNOWN", "1.0", "admin")


def test_create_baseline_org_id_stored(baseline):
    assert baseline["org_id"] == "org1"


# ===========================================================================
# 3. add_control — control_count
# ===========================================================================

def test_add_control_increments_count(engine, baseline_with_controls):
    detail = engine.get_baseline_detail(baseline_with_controls, "org1")
    assert detail["control_count"] == 3


def test_add_control_each_increment(engine, baseline):
    bl_id = baseline["id"]
    engine.add_control(bl_id, "org1", "C1", "Control 1", "cat", "desc", "val", "high")
    detail = engine.get_baseline_detail(bl_id, "org1")
    assert detail["control_count"] == 1
    engine.add_control(bl_id, "org1", "C2", "Control 2", "cat", "desc", "val", "medium")
    detail = engine.get_baseline_detail(bl_id, "org1")
    assert detail["control_count"] == 2


def test_add_control_invalid_severity(engine, baseline):
    with pytest.raises(ValueError, match="severity"):
        engine.add_control(baseline["id"], "org1", "C1", "N", "cat", "d", "v", "supercritical")


def test_add_control_wrong_baseline_raises(engine):
    with pytest.raises(KeyError):
        engine.add_control("GHOST-ID", "org1", "C1", "N", "cat", "d", "v", "high")


def test_add_control_wrong_org_raises(engine, baseline):
    with pytest.raises(KeyError):
        engine.add_control(baseline["id"], "org_evil", "C1", "N", "cat", "d", "v", "high")


def test_add_control_automated_check_stored(engine, baseline):
    ctrl = engine.add_control(baseline["id"], "org1", "C1", "N", "cat", "d", "v", "high", automated_check=True)
    assert ctrl["automated_check"] == 1


# ===========================================================================
# 4. publish_baseline
# ===========================================================================

def test_publish_sets_active(engine, baseline):
    result = engine.publish_baseline(baseline["id"], "org1")
    assert result["status"] == "active"


def test_publish_sets_published_at(engine, baseline):
    result = engine.publish_baseline(baseline["id"], "org1")
    assert result["published_at"] is not None


def test_publish_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.publish_baseline("GHOST", "org1")


def test_publish_wrong_org_raises(engine, baseline):
    with pytest.raises(KeyError):
        engine.publish_baseline(baseline["id"], "org_evil")


# ===========================================================================
# 5. run_assessment — compliance_pct formula
# ===========================================================================

def _make_results(pass_n, fail_n, skip_n):
    results = []
    for i in range(pass_n):
        results.append({"control_id": f"P{i}", "control_name": f"P{i}", "status": "pass",
                        "actual_value": "ok", "deviation": "", "severity": "medium"})
    for i in range(fail_n):
        results.append({"control_id": f"F{i}", "control_name": f"F{i}", "status": "fail",
                        "actual_value": "bad", "deviation": "diff", "severity": "high"})
    for i in range(skip_n):
        results.append({"control_id": f"S{i}", "control_name": f"S{i}", "status": "skip",
                        "actual_value": "", "deviation": "", "severity": "low"})
    return results


def test_compliance_pct_all_pass(engine, baseline):
    results = _make_results(5, 0, 0)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["compliance_pct"] == pytest.approx(100.0)


def test_compliance_pct_half(engine, baseline):
    results = _make_results(5, 5, 0)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["compliance_pct"] == pytest.approx(50.0)


def test_compliance_pct_skips_excluded(engine, baseline):
    """5 pass, 5 fail, 10 skip → compliance = 5/(5+5)*100 = 50%, skips don't count"""
    results = _make_results(5, 5, 10)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["compliance_pct"] == pytest.approx(50.0)


def test_compliance_pct_all_skip_is_zero(engine, baseline):
    """All skips → no pass or fail → compliance_pct = 0"""
    results = _make_results(0, 0, 5)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["compliance_pct"] == pytest.approx(0.0)


def test_compliance_pct_all_fail(engine, baseline):
    results = _make_results(0, 4, 0)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["compliance_pct"] == pytest.approx(0.0)


def test_assessment_counts_stored(engine, baseline):
    results = _make_results(3, 2, 1)
    assessment = engine.run_assessment(baseline["id"], "org1", "host1", results, "admin")
    assert assessment["pass_count"] == 3
    assert assessment["fail_count"] == 2
    assert assessment["skip_count"] == 1


def test_assessment_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.run_assessment("GHOST", "org1", "host1", [], "admin")


# ===========================================================================
# 6. get_baseline_detail
# ===========================================================================

def test_detail_includes_controls(engine, baseline_with_controls):
    detail = engine.get_baseline_detail(baseline_with_controls, "org1")
    assert len(detail["controls"]) == 3


def test_detail_includes_assessments(engine, baseline):
    engine.run_assessment(baseline["id"], "org1", "host1", _make_results(2, 1, 0), "admin")
    detail = engine.get_baseline_detail(baseline["id"], "org1")
    assert len(detail["recent_assessments"]) == 1


def test_detail_limits_assessments_to_5(engine, baseline):
    for i in range(7):
        engine.run_assessment(baseline["id"], "org1", f"host{i}", _make_results(1, 0, 0), "admin")
    detail = engine.get_baseline_detail(baseline["id"], "org1")
    assert len(detail["recent_assessments"]) == 5


def test_detail_not_found_returns_none(engine):
    assert engine.get_baseline_detail("GHOST", "org1") is None


# ===========================================================================
# 7. get_drift_report
# ===========================================================================

def test_drift_insufficient_data(engine, baseline):
    report = engine.get_drift_report(baseline["id"], "org1")
    assert report.get("insufficient_data") is True


def test_drift_no_change(engine, baseline):
    results = _make_results(3, 2, 0)
    engine.run_assessment(baseline["id"], "org1", "h1", results, "admin")
    engine.run_assessment(baseline["id"], "org1", "h2", results, "admin")
    report = engine.get_drift_report(baseline["id"], "org1")
    assert report["improved"] == []
    assert report["degraded"] == []


def test_drift_detects_degraded(engine, baseline):
    # First: P0 passes
    r1 = [{"control_id": "P0", "control_name": "P0", "status": "pass",
            "actual_value": "ok", "deviation": "", "severity": "high"}]
    # Second: P0 fails
    r2 = [{"control_id": "P0", "control_name": "P0", "status": "fail",
            "actual_value": "bad", "deviation": "diff", "severity": "high"}]
    engine.run_assessment(baseline["id"], "org1", "h1", r1, "admin")
    engine.run_assessment(baseline["id"], "org1", "h2", r2, "admin")
    report = engine.get_drift_report(baseline["id"], "org1")
    assert len(report["degraded"]) == 1
    assert report["degraded"][0]["control_id"] == "P0"


def test_drift_detects_improved(engine, baseline):
    r1 = [{"control_id": "F0", "control_name": "F0", "status": "fail",
            "actual_value": "bad", "deviation": "d", "severity": "high"}]
    r2 = [{"control_id": "F0", "control_name": "F0", "status": "pass",
            "actual_value": "ok", "deviation": "", "severity": "high"}]
    engine.run_assessment(baseline["id"], "org1", "h1", r1, "admin")
    engine.run_assessment(baseline["id"], "org1", "h2", r2, "admin")
    report = engine.get_drift_report(baseline["id"], "org1")
    assert len(report["improved"]) == 1
    assert report["improved"][0]["control_id"] == "F0"


# ===========================================================================
# 8. get_compliance_trend
# ===========================================================================

def test_compliance_trend_ordered_by_date(engine, baseline):
    engine.run_assessment(baseline["id"], "org1", "h1", _make_results(5, 5, 0), "admin")
    engine.run_assessment(baseline["id"], "org1", "h2", _make_results(8, 2, 0), "admin")
    trend = engine.get_compliance_trend(baseline["id"], "org1")
    pcts = [t["compliance_pct"] for t in trend]
    assert pcts[0] == pytest.approx(50.0)
    assert pcts[1] == pytest.approx(80.0)


def test_compliance_trend_empty_for_new_baseline(engine, baseline):
    trend = engine.get_compliance_trend(baseline["id"], "org1")
    assert trend == []


# ===========================================================================
# 9. list_baselines
# ===========================================================================

def test_list_baselines_all(engine, baseline):
    engine.create_baseline("org1", "B2", "workstation", "NIST", "1.0", "user2")
    baselines = engine.list_baselines("org1")
    assert len(baselines) == 2


def test_list_baselines_filter_by_status(engine, baseline):
    engine.publish_baseline(baseline["id"], "org1")
    b2 = engine.create_baseline("org1", "B2", "server", "CIS", "2.0", "user2")
    active = engine.list_baselines("org1", status="active")
    draft = engine.list_baselines("org1", status="draft")
    assert len(active) == 1
    assert len(draft) == 1


def test_list_baselines_invalid_status(engine):
    with pytest.raises(ValueError, match="status"):
        engine.list_baselines("org1", status="bogus")


def test_list_baselines_org_isolation(engine, baseline):
    engine.create_baseline("org2", "OtherBaseline", "server", "CIS", "1.0", "admin2")
    org1_list = engine.list_baselines("org1")
    org2_list = engine.list_baselines("org2")
    assert all(b["org_id"] == "org1" for b in org1_list)
    assert all(b["org_id"] == "org2" for b in org2_list)
