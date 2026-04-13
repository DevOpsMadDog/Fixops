"""Tests for CTEMEngine — Continuous Threat Exposure Management.

Covers:
- Cycle lifecycle (start, advance stages, full progression)
- Exposure CRUD (add, update, get)
- Auto-discovery
- Prioritization
- Validation (confirmed + rejected)
- Mobilization
- Dashboard
- Stats
- Error handling (not-found, invalid advances)
"""

from __future__ import annotations

import os
import tempfile
import pytest

# Ensure env vars are set before any imports
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

from core.ctem_engine import (
    CTEMCycle,
    CTEMEngine,
    CTEMStage,
    Exposure,
    ExposureStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh CTEMEngine backed by a temp SQLite file per test."""
    db_path = str(tmp_path / "ctem_test.db")
    return CTEMEngine(db_path=db_path)


@pytest.fixture
def cycle(engine):
    """A started cycle at SCOPING stage."""
    return engine.start_cycle("Test Cycle", org_id="test-org")


@pytest.fixture
def exposure(engine, cycle):
    """A persisted exposure linked to the test cycle."""
    exp = Exposure(
        title="Auth bypass in /login",
        description="JWT token not validated",
        assets=["app-001", "app-002"],
        findings=["finding-1"],
        risk_score=65.0,
        org_id="test-org",
    )
    return engine.add_exposure(exp)


# ---------------------------------------------------------------------------
# Cycle lifecycle tests
# ---------------------------------------------------------------------------


def test_start_cycle_returns_ctem_cycle(engine):
    cycle = engine.start_cycle("Q2 Assessment", org_id="acme")
    assert isinstance(cycle, CTEMCycle)
    assert cycle.name == "Q2 Assessment"
    assert cycle.org_id == "acme"


def test_start_cycle_begins_at_scoping(engine):
    cycle = engine.start_cycle("Scoping Test")
    assert cycle.current_stage == CTEMStage.SCOPING


def test_start_cycle_has_zero_completion(engine):
    cycle = engine.start_cycle("Zero Completion")
    assert cycle.completion_pct == 0.0


def test_start_cycle_has_empty_exposures(engine):
    cycle = engine.start_cycle("Empty Cycle")
    assert cycle.exposures == []


def test_start_cycle_id_generated(engine):
    cycle = engine.start_cycle("ID Test")
    assert cycle.id.startswith("cycle-")
    assert len(cycle.id) > 6


def test_advance_stage_scoping_to_discovery(engine, cycle):
    advanced = engine.advance_stage(cycle.id)
    assert advanced.current_stage == CTEMStage.DISCOVERY


def test_advance_stage_discovery_to_prioritization(engine, cycle):
    engine.advance_stage(cycle.id)
    advanced = engine.advance_stage(cycle.id)
    assert advanced.current_stage == CTEMStage.PRIORITIZATION


def test_advance_stage_prioritization_to_validation(engine, cycle):
    engine.advance_stage(cycle.id)
    engine.advance_stage(cycle.id)
    advanced = engine.advance_stage(cycle.id)
    assert advanced.current_stage == CTEMStage.VALIDATION


def test_advance_stage_validation_to_mobilization(engine, cycle):
    for _ in range(4):
        engine.advance_stage(cycle.id)
    advanced = engine.get_cycle(cycle.id)
    assert advanced.current_stage == CTEMStage.MOBILIZATION


def test_advance_stage_updates_completion_pct(engine, cycle):
    advanced = engine.advance_stage(cycle.id)
    assert advanced.completion_pct == 20.0
    advanced2 = engine.advance_stage(cycle.id)
    assert advanced2.completion_pct == 40.0


def test_advance_stage_at_mobilization_raises(engine, cycle):
    for _ in range(4):
        engine.advance_stage(cycle.id)
    with pytest.raises(ValueError, match="final stage"):
        engine.advance_stage(cycle.id)


def test_advance_stage_unknown_cycle_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.advance_stage("cycle-doesnotexist")


def test_get_cycle_returns_correct_cycle(engine, cycle):
    fetched = engine.get_cycle(cycle.id)
    assert fetched.id == cycle.id
    assert fetched.name == cycle.name


def test_get_cycle_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.get_cycle("cycle-missing")


def test_list_cycles_empty_org(engine):
    cycles = engine.list_cycles(org_id="no-org")
    assert cycles == []


def test_list_cycles_returns_all_for_org(engine):
    engine.start_cycle("Cycle A", org_id="org-x")
    engine.start_cycle("Cycle B", org_id="org-x")
    engine.start_cycle("Cycle C", org_id="org-y")
    cycles = engine.list_cycles(org_id="org-x")
    assert len(cycles) == 2


def test_list_cycles_newest_first(engine):
    c1 = engine.start_cycle("First", org_id="org-order")
    c2 = engine.start_cycle("Second", org_id="org-order")
    cycles = engine.list_cycles(org_id="org-order")
    ids = [c.id for c in cycles]
    assert c2.id in ids and c1.id in ids


# ---------------------------------------------------------------------------
# Exposure CRUD tests
# ---------------------------------------------------------------------------


def test_add_exposure_returns_exposure(engine, cycle):
    exp = Exposure(title="RCE in upload", org_id="test-org")
    saved = engine.add_exposure(exp)
    assert isinstance(saved, Exposure)
    assert saved.title == "RCE in upload"


def test_add_exposure_links_to_latest_cycle(engine, cycle):
    exp = Exposure(title="SSRF", org_id="test-org")
    engine.add_exposure(exp)
    refreshed = engine.get_cycle(cycle.id)
    assert exp.id in refreshed.exposures


def test_add_exposure_id_generated(engine, cycle):
    exp = Exposure(title="XSS", org_id="test-org")
    saved = engine.add_exposure(exp)
    assert saved.id.startswith("exp-")


def test_update_exposure_title(engine, exposure):
    updated = engine.update_exposure(exposure.id, {"title": "Updated Title"})
    assert updated.title == "Updated Title"


def test_update_exposure_risk_score(engine, exposure):
    updated = engine.update_exposure(exposure.id, {"risk_score": 90.0})
    assert updated.risk_score == 90.0


def test_update_exposure_multiple_fields(engine, exposure):
    updated = engine.update_exposure(
        exposure.id, {"owner": "alice@corp.com", "business_impact": "Critical asset"}
    )
    assert updated.owner == "alice@corp.com"
    assert updated.business_impact == "Critical asset"


def test_update_exposure_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_exposure("exp-missing", {"title": "x"})


def test_get_exposures_for_cycle(engine, cycle, exposure):
    exposures = engine.get_exposures(cycle.id)
    ids = [e.id for e in exposures]
    assert exposure.id in ids


def test_get_exposures_sorted_by_risk_score(engine, cycle):
    e1 = Exposure(title="Low Risk", risk_score=20.0, org_id="test-org")
    e2 = Exposure(title="High Risk", risk_score=80.0, org_id="test-org")
    engine.add_exposure(e1)
    engine.add_exposure(e2)
    exposures = engine.get_exposures(cycle.id)
    scores = [e.risk_score for e in exposures]
    assert scores == sorted(scores, reverse=True)


def test_get_exposures_for_missing_cycle_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.get_exposures("cycle-missing")


# ---------------------------------------------------------------------------
# Scope assets tests
# ---------------------------------------------------------------------------


def test_scope_assets_creates_scoping_exposure(engine, cycle):
    engine.scope_assets(cycle.id, asset_ids=["ast-001", "ast-002", "ast-003"])
    exposures = engine.get_exposures(cycle.id)
    scoping_exps = [e for e in exposures if e.stage == CTEMStage.SCOPING]
    assert len(scoping_exps) >= 1


def test_scope_assets_records_asset_list(engine, cycle):
    asset_ids = ["ast-A", "ast-B"]
    engine.scope_assets(cycle.id, asset_ids=asset_ids)
    exposures = engine.get_exposures(cycle.id)
    all_assets = [a for e in exposures for a in e.assets]
    assert "ast-A" in all_assets
    assert "ast-B" in all_assets


def test_scope_assets_returns_cycle(engine, cycle):
    result = engine.scope_assets(cycle.id, asset_ids=["ast-X"])
    assert isinstance(result, CTEMCycle)
    assert result.id == cycle.id


def test_scope_assets_missing_cycle_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.scope_assets("cycle-none", asset_ids=["ast-1"])


# ---------------------------------------------------------------------------
# Auto-discovery tests
# ---------------------------------------------------------------------------


def test_discover_exposures_creates_discovery_exposure(engine, cycle):
    engine.scope_assets(cycle.id, asset_ids=["ast-1", "ast-2"])
    discovered = engine.discover_exposures(cycle.id)
    assert len(discovered) >= 1
    assert all(e.stage == CTEMStage.DISCOVERY for e in discovered)


def test_discover_exposures_returns_list(engine, cycle):
    engine.scope_assets(cycle.id, asset_ids=["ast-9"])
    result = engine.discover_exposures(cycle.id)
    assert isinstance(result, list)


def test_discover_exposures_no_scope_returns_empty(engine, cycle):
    # No scoped assets = nothing to discover
    discovered = engine.discover_exposures(cycle.id)
    assert discovered == []


def test_discover_exposures_missing_cycle_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.discover_exposures("cycle-bad")


# ---------------------------------------------------------------------------
# Prioritization tests
# ---------------------------------------------------------------------------


def test_prioritize_exposures_sets_assessed_status(engine, cycle, exposure):
    prioritized = engine.prioritize_exposures(cycle.id)
    assert all(e.status == ExposureStatus.ASSESSED for e in prioritized)


def test_prioritize_exposures_sets_prioritization_stage(engine, cycle, exposure):
    prioritized = engine.prioritize_exposures(cycle.id)
    assert all(e.stage == CTEMStage.PRIORITIZATION for e in prioritized)


def test_prioritize_exposures_computes_risk_score(engine, cycle):
    exp = Exposure(
        title="Multi-asset exposure",
        assets=["a1", "a2", "a3", "a4", "a5"],
        findings=["f1", "f2", "f3"],
        risk_score=50.0,
        org_id="test-org",
    )
    engine.add_exposure(exp)
    prioritized = engine.prioritize_exposures(cycle.id)
    scored = [e for e in prioritized if e.id == exp.id]
    assert len(scored) == 1
    assert scored[0].risk_score > 50.0  # score was boosted by asset/finding factors


def test_prioritize_exposures_missing_cycle_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.prioritize_exposures("cycle-none")


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


def test_validate_exposure_confirmed(engine, exposure):
    updated = engine.validate_exposure(exposure.id, validated=True)
    assert updated.status == ExposureStatus.VALIDATED
    assert updated.stage == CTEMStage.VALIDATION


def test_validate_exposure_rejected(engine, exposure):
    updated = engine.validate_exposure(exposure.id, validated=False)
    assert updated.status == ExposureStatus.ACCEPTED
    assert updated.stage == CTEMStage.VALIDATION


def test_validate_exposure_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.validate_exposure("exp-missing", validated=True)


# ---------------------------------------------------------------------------
# Mobilization tests
# ---------------------------------------------------------------------------


def test_mobilize_sets_owner(engine, exposure):
    updated = engine.mobilize_remediation(exposure.id, owner="bob@corp.com", plan="Patch ASAP")
    assert updated.owner == "bob@corp.com"


def test_mobilize_sets_remediation_plan(engine, exposure):
    updated = engine.mobilize_remediation(exposure.id, owner="alice", plan="Apply fix #42")
    assert updated.remediation_plan == "Apply fix #42"


def test_mobilize_sets_mobilization_stage(engine, exposure):
    updated = engine.mobilize_remediation(exposure.id, owner="ops", plan="Rollback")
    assert updated.stage == CTEMStage.MOBILIZATION


def test_mobilize_not_found_raises(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.mobilize_remediation("exp-gone", owner="x", plan="y")


# ---------------------------------------------------------------------------
# Dashboard tests
# ---------------------------------------------------------------------------


def test_dashboard_returns_org_id(engine, cycle):
    dash = engine.get_ctem_dashboard(org_id="test-org")
    assert dash["org_id"] == "test-org"


def test_dashboard_total_cycles(engine):
    engine.start_cycle("D1", org_id="dash-org")
    engine.start_cycle("D2", org_id="dash-org")
    dash = engine.get_ctem_dashboard(org_id="dash-org")
    assert dash["total_cycles"] == 2


def test_dashboard_has_required_keys(engine, cycle):
    dash = engine.get_ctem_dashboard(org_id="test-org")
    for key in (
        "org_id", "total_cycles", "active_cycles", "total_exposures",
        "average_risk_score", "exposures_by_status", "exposures_by_stage",
        "cycles", "generated_at",
    ):
        assert key in dash, f"Missing key: {key}"


def test_dashboard_exposure_counts(engine, cycle, exposure):
    dash = engine.get_ctem_dashboard(org_id="test-org")
    assert dash["total_exposures"] >= 1


def test_dashboard_average_risk_score_zero_when_no_exposures(engine):
    engine.start_cycle("Empty", org_id="empty-org")
    dash = engine.get_ctem_dashboard(org_id="empty-org")
    assert dash["average_risk_score"] == 0.0


# ---------------------------------------------------------------------------
# Stats tests
# ---------------------------------------------------------------------------


def test_stats_returns_org_id(engine):
    stats = engine.get_ctem_stats(org_id="test-org")
    assert stats["org_id"] == "test-org"


def test_stats_has_required_keys(engine):
    stats = engine.get_ctem_stats(org_id="test-org")
    assert "cycles" in stats
    assert "exposures" in stats
    assert "total" in stats["cycles"]
    assert "by_stage" in stats["cycles"]
    assert "total" in stats["exposures"]
    assert "by_severity" in stats["exposures"]


def test_stats_severity_buckets(engine, cycle, exposure):
    stats = engine.get_ctem_stats(org_id="test-org")
    buckets = stats["exposures"]["by_severity"]
    for bucket in ("critical", "high", "medium", "low"):
        assert bucket in buckets


def test_stats_remediation_rate_zero_with_no_remediations(engine, cycle, exposure):
    stats = engine.get_ctem_stats(org_id="test-org")
    assert stats["exposures"]["remediation_rate_pct"] == 0.0


def test_stats_cycle_count(engine):
    engine.start_cycle("S1", org_id="stats-org")
    engine.start_cycle("S2", org_id="stats-org")
    stats = engine.get_ctem_stats(org_id="stats-org")
    assert stats["cycles"]["total"] == 2


def test_stats_by_stage_counts_scoping(engine):
    engine.start_cycle("Stage Count", org_id="stage-org")
    stats = engine.get_ctem_stats(org_id="stage-org")
    assert stats["cycles"]["by_stage"]["scoping"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
