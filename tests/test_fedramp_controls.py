"""
Tests for FedRAMP Compliance Controls module.

Covers:
- FedRAMPManager CRUD operations
- Compliance scoring
- Gap analysis
- SSP generation
- ALDECI feature mapping
- POA&M generation
- Statistics
- FedRAMP router endpoints (via FastAPI TestClient)
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

# Ensure suite-core is importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

_suite_api = str(Path(__file__).parent.parent / "suite-api")
if _suite_api not in sys.path:
    sys.path.insert(0, _suite_api)

from core.fedramp_controls import (
    ControlFamily,
    ControlStatus,
    FedRAMPBaseline,
    FedRAMPControl,
    FedRAMPManager,
    POAMItem,
    ComplianceScore,
    GapAnalysis,
    SSPData,
    FedRAMPStats,
    _ALDECI_FEATURE_CONTROL_MAP,
    _CONTROL_CATALOGUE,
    _readiness_level,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a fresh temporary database path."""
    return str(tmp_path / "fedramp_test.db")


@pytest.fixture
def manager(tmp_db):
    """Create a FedRAMPManager with a temporary DB (seeded with catalogue)."""
    return FedRAMPManager(db_path=tmp_db)


@pytest.fixture
def empty_manager(tmp_path):
    """Manager whose catalogue has been cleared for controlled tests."""
    mgr = FedRAMPManager(db_path=str(tmp_path / "empty.db"))
    return mgr


@pytest.fixture
def sample_control():
    return FedRAMPControl(
        id="AC-99",
        family=ControlFamily.AC,
        title="Custom Control",
        description="A custom access control for testing.",
        baseline=[FedRAMPBaseline.MODERATE, FedRAMPBaseline.HIGH],
        status=ControlStatus.PLANNED,
        evidence_ids=[],
        implementation_notes="",
    )


# ---------------------------------------------------------------------------
# Enum sanity checks
# ---------------------------------------------------------------------------


class TestEnums:
    def test_baseline_values(self):
        assert FedRAMPBaseline.LOW == "LOW"
        assert FedRAMPBaseline.MODERATE == "MODERATE"
        assert FedRAMPBaseline.HIGH == "HIGH"

    def test_all_control_families_present(self):
        families = {f.value for f in ControlFamily}
        expected = {"AC", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI"}
        assert expected == families

    def test_control_status_values(self):
        assert ControlStatus.IMPLEMENTED == "implemented"
        assert ControlStatus.PARTIAL == "partial"
        assert ControlStatus.PLANNED == "planned"
        assert ControlStatus.NOT_APPLICABLE == "not_applicable"

    def test_readiness_levels(self):
        assert _readiness_level(95) == "Authorization Ready"
        assert _readiness_level(80) == "Significant Progress"
        assert _readiness_level(60) == "Moderate Progress"
        assert _readiness_level(30) == "Early Stage"
        assert _readiness_level(10) == "Initial"


# ---------------------------------------------------------------------------
# Catalogue checks
# ---------------------------------------------------------------------------


class TestCatalogue:
    def test_catalogue_not_empty(self):
        assert len(_CONTROL_CATALOGUE) >= 50

    def test_all_catalogue_families_are_valid(self):
        valid = {f.value for f in ControlFamily}
        for ctrl in _CONTROL_CATALOGUE:
            assert ctrl["family"] in valid, f"Invalid family for {ctrl['id']}"

    def test_all_catalogue_baselines_are_valid(self):
        valid = {b.value for b in FedRAMPBaseline}
        for ctrl in _CONTROL_CATALOGUE:
            for b in ctrl["baseline"]:
                assert b in valid, f"Invalid baseline {b} for {ctrl['id']}"

    def test_catalogue_ids_unique(self):
        ids = [c["id"] for c in _CONTROL_CATALOGUE]
        assert len(ids) == len(set(ids)), "Duplicate control IDs in catalogue"

    def test_catalogue_covers_all_families(self):
        families_in_catalogue = {c["family"] for c in _CONTROL_CATALOGUE}
        all_families = {f.value for f in ControlFamily}
        assert all_families == families_in_catalogue


# ---------------------------------------------------------------------------
# FedRAMPManager — seeding & DB
# ---------------------------------------------------------------------------


class TestManagerSeeding:
    def test_catalogue_seeded_on_init(self, manager):
        controls = manager.list_controls()
        assert len(controls) >= 50

    def test_no_duplicate_seeding(self, tmp_db):
        mgr1 = FedRAMPManager(db_path=tmp_db)
        count1 = len(mgr1.list_controls())
        mgr2 = FedRAMPManager(db_path=tmp_db)
        count2 = len(mgr2.list_controls())
        assert count1 == count2


# ---------------------------------------------------------------------------
# FedRAMPManager — CRUD
# ---------------------------------------------------------------------------


class TestManagerCRUD:
    def test_add_control(self, manager, sample_control):
        added = manager.add_control(sample_control)
        assert added.id == "AC-99"
        assert added.family == ControlFamily.AC

    def test_add_control_persisted(self, manager, sample_control):
        manager.add_control(sample_control)
        fetched = manager.get_control("AC-99")
        assert fetched is not None
        assert fetched.title == "Custom Control"

    def test_get_control_not_found(self, manager):
        assert manager.get_control("ZZ-999") is None

    def test_get_existing_catalogue_control(self, manager):
        ctrl = manager.get_control("AC-1")
        assert ctrl is not None
        assert ctrl.family == ControlFamily.AC

    def test_add_control_overwrites(self, manager, sample_control):
        manager.add_control(sample_control)
        sample_control.title = "Updated Title"
        manager.add_control(sample_control)
        fetched = manager.get_control("AC-99")
        assert fetched.title == "Updated Title"

    def test_update_status_implemented(self, manager):
        updated = manager.update_status("AC-1", ControlStatus.IMPLEMENTED, "Fully implemented via RBAC")
        assert updated is not None
        assert updated.status == ControlStatus.IMPLEMENTED
        assert updated.implementation_notes == "Fully implemented via RBAC"

    def test_update_status_partial(self, manager):
        updated = manager.update_status("AU-2", ControlStatus.PARTIAL)
        assert updated.status == ControlStatus.PARTIAL

    def test_update_status_not_found(self, manager):
        result = manager.update_status("ZZ-999", ControlStatus.IMPLEMENTED)
        assert result is None

    def test_update_status_with_evidence(self, manager):
        evidence = ["ev-001", "ev-002"]
        updated = manager.update_status("IA-2", ControlStatus.IMPLEMENTED, evidence_ids=evidence)
        assert updated.evidence_ids == evidence

    def test_update_status_preserves_existing_notes(self, manager):
        manager.update_status("CM-2", ControlStatus.PARTIAL, "initial notes")
        updated = manager.update_status("CM-2", ControlStatus.IMPLEMENTED)
        assert updated.implementation_notes == "initial notes"


# ---------------------------------------------------------------------------
# FedRAMPManager — list_controls filtering
# ---------------------------------------------------------------------------


class TestListControls:
    def test_list_all(self, manager):
        all_controls = manager.list_controls()
        assert len(all_controls) >= 50

    def test_filter_by_family(self, manager):
        ac_controls = manager.list_controls(family=ControlFamily.AC)
        assert all(c.family == ControlFamily.AC for c in ac_controls)
        assert len(ac_controls) >= 4

    def test_filter_by_baseline_low(self, manager):
        low = manager.list_controls(baseline=FedRAMPBaseline.LOW)
        assert all(FedRAMPBaseline.LOW in c.baseline for c in low)

    def test_filter_by_baseline_high(self, manager):
        high = manager.list_controls(baseline=FedRAMPBaseline.HIGH)
        assert len(high) > 0

    def test_filter_by_status(self, manager):
        manager.update_status("AC-1", ControlStatus.IMPLEMENTED)
        implemented = manager.list_controls(status=ControlStatus.IMPLEMENTED)
        assert any(c.id == "AC-1" for c in implemented)

    def test_filter_family_and_baseline(self, manager):
        controls = manager.list_controls(family=ControlFamily.SC, baseline=FedRAMPBaseline.HIGH)
        assert all(c.family == ControlFamily.SC for c in controls)
        assert all(FedRAMPBaseline.HIGH in c.baseline for c in controls)


# ---------------------------------------------------------------------------
# FedRAMPManager — compliance score
# ---------------------------------------------------------------------------


class TestComplianceScore:
    def test_score_returns_compliance_score(self, manager):
        score = manager.get_compliance_score(FedRAMPBaseline.LOW)
        assert isinstance(score, ComplianceScore)
        assert score.baseline == FedRAMPBaseline.LOW

    def test_score_zero_when_all_planned(self, manager):
        score = manager.get_compliance_score(FedRAMPBaseline.LOW)
        assert score.score_percent == 0.0

    def test_score_increases_after_implementation(self, manager):
        low_controls = manager.list_controls(baseline=FedRAMPBaseline.LOW)
        for ctrl in low_controls:
            manager.update_status(ctrl.id, ControlStatus.IMPLEMENTED)
        score = manager.get_compliance_score(FedRAMPBaseline.LOW)
        assert score.score_percent == 100.0

    def test_score_partial_counts_half(self, manager):
        low_controls = manager.list_controls(baseline=FedRAMPBaseline.LOW)
        total = len(low_controls)
        for ctrl in low_controls:
            manager.update_status(ctrl.id, ControlStatus.PARTIAL)
        score = manager.get_compliance_score(FedRAMPBaseline.LOW)
        assert score.score_percent == 50.0

    def test_score_readiness_level_present(self, manager):
        score = manager.get_compliance_score(FedRAMPBaseline.MODERATE)
        assert score.readiness_level in [
            "Authorization Ready", "Significant Progress", "Moderate Progress", "Early Stage", "Initial"
        ]

    def test_score_totals_add_up(self, manager):
        score = manager.get_compliance_score(FedRAMPBaseline.HIGH)
        assert score.implemented + score.partial + score.planned + score.not_applicable == score.total_controls


# ---------------------------------------------------------------------------
# FedRAMPManager — gap analysis
# ---------------------------------------------------------------------------


class TestGapAnalysis:
    def test_gap_analysis_returns_type(self, manager):
        gap = manager.get_gap_analysis(FedRAMPBaseline.LOW)
        assert isinstance(gap, GapAnalysis)

    def test_all_planned_are_gaps(self, manager):
        gap = manager.get_gap_analysis(FedRAMPBaseline.LOW)
        assert gap.gap_count > 0

    def test_implemented_not_in_gaps(self, manager):
        manager.update_status("AC-1", ControlStatus.IMPLEMENTED)
        gap = manager.get_gap_analysis(FedRAMPBaseline.LOW)
        gap_ids = [g["control_id"] for g in gap.gaps]
        assert "AC-1" not in gap_ids

    def test_critical_gaps_from_key_families(self, manager):
        gap = manager.get_gap_analysis(FedRAMPBaseline.HIGH)
        assert isinstance(gap.critical_gaps, list)

    def test_gap_analysis_gap_count_matches_list(self, manager):
        gap = manager.get_gap_analysis(FedRAMPBaseline.MODERATE)
        assert gap.gap_count == len(gap.gaps)


# ---------------------------------------------------------------------------
# FedRAMPManager — SSP generation
# ---------------------------------------------------------------------------


class TestSSPGeneration:
    def test_ssp_returns_ssp_data(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.LOW)
        assert isinstance(ssp, SSPData)

    def test_ssp_system_name(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.LOW, system_name="TestSystem")
        assert ssp.system_name == "TestSystem"

    def test_ssp_contains_controls(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.LOW)
        assert len(ssp.controls) > 0

    def test_ssp_summary_keys(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.MODERATE)
        assert "total" in ssp.summary
        assert "implemented" in ssp.summary
        assert "planned" in ssp.summary

    def test_ssp_feature_coverage_present(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.LOW)
        assert isinstance(ssp.feature_coverage, dict)
        assert "RBAC" in ssp.feature_coverage

    def test_ssp_baseline_field(self, manager):
        ssp = manager.generate_ssp_data(FedRAMPBaseline.HIGH)
        assert ssp.baseline == FedRAMPBaseline.HIGH


# ---------------------------------------------------------------------------
# FedRAMPManager — feature mapping
# ---------------------------------------------------------------------------


class TestFeatureMapping:
    def test_map_returns_dict(self, manager):
        mapping = manager.map_aldeci_features_to_controls()
        assert isinstance(mapping, dict)

    def test_map_has_rbac_key(self, manager):
        mapping = manager.map_aldeci_features_to_controls()
        assert "RBAC" in mapping
        assert "AC-1" in mapping["RBAC"] or "AC-2" in mapping["RBAC"]

    def test_map_has_encryption_keys(self, manager):
        mapping = manager.map_aldeci_features_to_controls()
        assert "Encryption_In_Transit" in mapping
        assert "Encryption_At_Rest" in mapping

    def test_get_controls_for_valid_feature(self, manager):
        controls = manager.get_controls_for_feature("RBAC")
        assert len(controls) > 0
        assert all(isinstance(c, FedRAMPControl) for c in controls)

    def test_get_controls_for_invalid_feature(self, manager):
        controls = manager.get_controls_for_feature("NONEXISTENT_FEATURE")
        assert controls == []

    def test_all_feature_control_ids_exist(self, manager):
        mapping = manager.map_aldeci_features_to_controls()
        for feature, ids in mapping.items():
            for cid in ids:
                ctrl = manager.get_control(cid)
                assert ctrl is not None, f"Control {cid} for feature {feature} not found in DB"


# ---------------------------------------------------------------------------
# FedRAMPManager — POA&M
# ---------------------------------------------------------------------------


class TestPOAM:
    def test_poam_returns_list(self, manager):
        items = manager.get_poam()
        assert isinstance(items, list)

    def test_poam_all_planned_creates_items(self, manager):
        items = manager.get_poam(baseline=FedRAMPBaseline.LOW)
        assert len(items) > 0

    def test_poam_item_fields(self, manager):
        items = manager.get_poam(baseline=FedRAMPBaseline.LOW)
        item = items[0]
        assert isinstance(item, POAMItem)
        assert item.control_id
        assert item.weakness
        assert len(item.milestones) == 4

    def test_poam_implemented_not_in_list(self, manager):
        manager.update_status("AC-1", ControlStatus.IMPLEMENTED)
        items = manager.get_poam()
        control_ids = [i.control_id for i in items]
        assert "AC-1" not in control_ids

    def test_poam_with_baseline_filter(self, manager):
        low_items = manager.get_poam(baseline=FedRAMPBaseline.LOW)
        high_items = manager.get_poam(baseline=FedRAMPBaseline.HIGH)
        # HIGH has more controls than LOW, so its POA&M should be at least as large
        assert len(high_items) >= len(low_items)

    def test_poam_status_open_for_planned(self, manager):
        items = manager.get_poam(baseline=FedRAMPBaseline.LOW)
        open_items = [i for i in items if i.status == "open"]
        assert len(open_items) > 0


# ---------------------------------------------------------------------------
# FedRAMPManager — stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_returns_type(self, manager):
        stats = manager.get_fedramp_stats()
        assert isinstance(stats, FedRAMPStats)

    def test_stats_total_controls(self, manager):
        stats = manager.get_fedramp_stats()
        assert stats.total_controls >= 50

    def test_stats_by_status_has_planned(self, manager):
        stats = manager.get_fedramp_stats()
        assert "planned" in stats.by_status

    def test_stats_by_family_covers_all(self, manager):
        stats = manager.get_fedramp_stats()
        assert "AC" in stats.by_family
        assert "AU" in stats.by_family

    def test_stats_scores_all_baselines(self, manager):
        stats = manager.get_fedramp_stats()
        assert "LOW" in stats.scores
        assert "MODERATE" in stats.scores
        assert "HIGH" in stats.scores

    def test_stats_scores_between_0_and_100(self, manager):
        stats = manager.get_fedramp_stats()
        for bl, score in stats.scores.items():
            assert 0.0 <= score <= 100.0, f"Score for {bl} out of range: {score}"


# ---------------------------------------------------------------------------
# Router endpoint tests (via FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_db):
    """Create a TestClient with isolated FedRAMPManager."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import apps.api.fedramp_router as fedramp_router_module

    # Patch the module-level manager with our test manager
    test_mgr = FedRAMPManager(db_path=tmp_db)
    with patch.object(fedramp_router_module, "_manager", test_mgr):
        app = FastAPI()
        app.include_router(fedramp_router_module.router)
        yield TestClient(app), test_mgr


class TestRouterEndpoints:
    def test_list_controls_200(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 50

    def test_list_controls_filter_family(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls?family=AC")
        assert resp.status_code == 200
        data = resp.json()
        assert all(c["family"] == "AC" for c in data)

    def test_list_controls_invalid_family(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls?family=ZZ")
        assert resp.status_code == 400

    def test_list_controls_filter_baseline(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls?baseline=LOW")
        assert resp.status_code == 200

    def test_get_control_found(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls/AC-1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "AC-1"

    def test_get_control_not_found(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/controls/ZZ-999")
        assert resp.status_code == 404

    def test_add_control_201(self, client):
        tc, _ = client
        payload = {
            "id": "AC-99",
            "family": "AC",
            "title": "Custom Control",
            "description": "Test control",
            "baseline": ["LOW"],
            "status": "planned",
        }
        resp = tc.post("/api/v1/fedramp/controls", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] == "AC-99"

    def test_update_status_200(self, client):
        tc, _ = client
        resp = tc.patch(
            "/api/v1/fedramp/controls/AC-1/status",
            json={"status": "implemented", "implementation_notes": "Done via RBAC"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "implemented"

    def test_update_status_not_found(self, client):
        tc, _ = client
        resp = tc.patch(
            "/api/v1/fedramp/controls/ZZ-999/status",
            json={"status": "implemented"},
        )
        assert resp.status_code == 404

    def test_get_score(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/score/MODERATE")
        assert resp.status_code == 200
        data = resp.json()
        assert "score_percent" in data
        assert "readiness_level" in data

    def test_get_score_invalid_baseline(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/score/INVALID")
        assert resp.status_code == 400

    def test_gap_analysis(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/gap-analysis/HIGH")
        assert resp.status_code == 200
        data = resp.json()
        assert "gap_count" in data
        assert "gaps" in data

    def test_ssp_generation(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/ssp/MODERATE?system_name=TestSystem")
        assert resp.status_code == 200
        data = resp.json()
        assert data["system_name"] == "TestSystem"
        assert "controls" in data
        assert "summary" in data

    def test_feature_mapping(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/feature-mapping")
        assert resp.status_code == 200
        data = resp.json()
        assert "RBAC" in data

    def test_feature_mapping_specific(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/feature-mapping/RBAC")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_feature_mapping_not_found(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/feature-mapping/NONEXISTENT")
        assert resp.status_code == 404

    def test_poam(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/poam")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_poam_with_baseline(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/poam?baseline=LOW")
        assert resp.status_code == 200

    def test_stats(self, client):
        tc, _ = client
        resp = tc.get("/api/v1/fedramp/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_controls" in data
        assert "by_status" in data
        assert "scores" in data
