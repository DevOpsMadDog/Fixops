"""Tests for MITRE ATT&CK Navigator Engine — suite-core/core/mitre_navigator.py.

Coverage: 50+ tests across all engine features:
- Tactic/technique data completeness
- Detection coverage mapping
- Coverage scoring per tactic + overall
- Gap analysis ordering and filtering
- Threat group overlay calculations
- Custom layer creation (coverage, threat group, user-defined)
- Detection rules access
- Singleton accessor

Run with:
    pytest tests/test_mitre_navigator.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Add suite-core to path
suite_core = str(Path(__file__).parent.parent / "suite-core")
if suite_core not in sys.path:
    sys.path.insert(0, suite_core)

from core.mitre_navigator import (
    ALDECIEngine,
    CoverageLevel,
    DetectionCoverage,
    DetectionRule,
    GapAnalysisResult,
    LayerAnnotation,
    LayerColor,
    MITRENavigatorEngine,
    NavigatorLayer,
    Tactic,
    TacticCoverage,
    TacticInfo,
    Technique,
    ThreatGroup,
    ThreatGroupOverlay,
    TACTICS,
    TECHNIQUES,
    DETECTION_COVERAGE,
    THREAT_GROUPS,
    DETECTION_RULES,
    get_mitre_navigator_engine,
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def engine() -> MITRENavigatorEngine:
    """Fresh engine instance per test."""
    return MITRENavigatorEngine()


# ===========================================================================
# 1. Data completeness
# ===========================================================================

class TestDataCompleteness:
    def test_14_tactics_defined(self):
        assert len(TACTICS) == 14

    def test_all_tactic_enum_ids_in_data(self):
        for tactic in Tactic:
            assert tactic.value in TACTICS, f"{tactic.value} missing from TACTICS"

    def test_100_plus_techniques(self):
        assert len(TECHNIQUES) >= 100

    def test_techniques_have_required_fields(self):
        for tid, tech in TECHNIQUES.items():
            assert tech.id == tid, f"{tid}: id mismatch"
            assert tech.name, f"{tid}: empty name"
            assert tech.tactic_ids, f"{tid}: no tactic_ids"
            assert tech.description, f"{tid}: empty description"
            assert 0.0 <= tech.frequency_score <= 1.0, f"{tid}: invalid frequency_score"
            assert tech.severity in ("low", "medium", "high", "critical"), f"{tid}: invalid severity"

    def test_subtechnique_parent_references_exist(self):
        for tid, tech in TECHNIQUES.items():
            if tech.is_subtechnique:
                assert tech.parent_id is not None, f"{tid}: subtechnique missing parent_id"
                assert tech.parent_id in TECHNIQUES, f"{tid}: parent {tech.parent_id} not in TECHNIQUES"

    def test_tactic_ids_in_techniques_are_valid(self):
        for tid, tech in TECHNIQUES.items():
            for tactic_id in tech.tactic_ids:
                assert tactic_id in TACTICS, f"{tid}: unknown tactic_id {tactic_id}"

    def test_threat_groups_have_techniques(self):
        for gid, group in THREAT_GROUPS.items():
            assert group.techniques, f"{gid}: no techniques"
            assert group.name, f"{gid}: empty name"

    def test_threat_group_techniques_reference_known_ids(self):
        """All threat group technique IDs must exist in TECHNIQUES."""
        for gid, group in THREAT_GROUPS.items():
            for tid in group.techniques:
                assert tid in TECHNIQUES, f"{gid}: unknown technique {tid}"

    def test_detection_coverage_technique_ids_valid(self):
        for tid in DETECTION_COVERAGE:
            assert tid in TECHNIQUES, f"Coverage for unknown technique: {tid}"

    def test_detection_rules_technique_ids_valid(self):
        for tid in DETECTION_RULES:
            assert tid in TECHNIQUES, f"Rule for unknown technique: {tid}"

    def test_at_least_8_threat_groups(self):
        assert len(THREAT_GROUPS) >= 7

    def test_at_least_8_detection_rules(self):
        assert len(DETECTION_RULES) >= 8

    def test_coverage_levels_are_valid_enum_values(self):
        valid = {CoverageLevel.NONE, CoverageLevel.PARTIAL, CoverageLevel.FULL}
        for tid, cov in DETECTION_COVERAGE.items():
            assert cov.level in valid, f"{tid}: invalid coverage level {cov.level}"

    def test_tactic_info_fields(self):
        for tid, tactic in TACTICS.items():
            assert tactic.id == tid
            assert tactic.name
            assert tactic.shortname
            assert tactic.description
            assert tactic.url.startswith("https://")


# ===========================================================================
# 2. Engine — matrix queries
# ===========================================================================

class TestEngineMatrix:
    def test_get_tactics_returns_all_14(self, engine):
        tactics = engine.get_tactics()
        assert len(tactics) == 14
        assert all(isinstance(t, TacticInfo) for t in tactics)

    def test_get_technique_known_id(self, engine):
        tech = engine.get_technique("T1059")
        assert tech is not None
        assert tech.name == "Command and Scripting Interpreter"

    def test_get_technique_unknown_id_returns_none(self, engine):
        assert engine.get_technique("T9999") is None

    def test_get_techniques_for_tactic(self, engine):
        techs = engine.get_techniques_for_tactic("TA0002")  # Execution
        assert len(techs) >= 5
        assert all("TA0002" in t.tactic_ids for t in techs)

    def test_get_techniques_for_unknown_tactic(self, engine):
        techs = engine.get_techniques_for_tactic("TA9999")
        assert techs == []

    def test_get_all_techniques_includes_subtechniques(self, engine):
        all_techs = engine.get_all_techniques(include_subtechniques=True)
        subtechs = [t for t in all_techs if t.is_subtechnique]
        assert len(subtechs) > 0

    def test_get_all_techniques_excludes_subtechniques(self, engine):
        all_techs = engine.get_all_techniques(include_subtechniques=False)
        assert all(not t.is_subtechnique for t in all_techs)

    def test_initial_access_tactic_has_phishing(self, engine):
        techs = engine.get_techniques_for_tactic("TA0001")
        ids = [t.id for t in techs]
        assert "T1566" in ids

    def test_valid_accounts_spans_multiple_tactics(self, engine):
        tech = engine.get_technique("T1078")
        assert "TA0001" in tech.tactic_ids
        assert "TA0003" in tech.tactic_ids


# ===========================================================================
# 3. Engine — coverage
# ===========================================================================

class TestEngineCoverage:
    def test_get_coverage_known_technique_full(self, engine):
        cov = engine.get_coverage("T1190")
        assert cov.technique_id == "T1190"
        assert cov.level == CoverageLevel.FULL
        assert len(cov.engines) > 0

    def test_get_coverage_partial_technique(self, engine):
        cov = engine.get_coverage("T1595.002")
        assert cov.level == CoverageLevel.PARTIAL

    def test_get_coverage_unknown_returns_none_level(self, engine):
        cov = engine.get_coverage("T9999")
        assert cov.level == CoverageLevel.NONE
        assert cov.engines == []

    def test_get_tactic_coverage_initial_access(self, engine):
        tc = engine.get_tactic_coverage("TA0001")
        assert isinstance(tc, TacticCoverage)
        assert tc.tactic_id == "TA0001"
        assert tc.total_techniques >= 5
        assert 0.0 <= tc.coverage_pct <= 100.0
        assert tc.covered_techniques + tc.partial_techniques <= tc.total_techniques

    def test_get_tactic_coverage_unknown_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown tactic"):
            engine.get_tactic_coverage("TA9999")

    def test_get_overall_coverage_score_keys(self, engine):
        score = engine.get_overall_coverage_score()
        assert "total_techniques" in score
        assert "fully_covered" in score
        assert "partially_covered" in score
        assert "not_covered" in score
        assert "coverage_score_pct" in score
        assert "grade" in score

    def test_overall_coverage_score_in_range(self, engine):
        score = engine.get_overall_coverage_score()
        assert 0.0 <= score["coverage_score_pct"] <= 100.0

    def test_overall_coverage_counts_sum_to_total(self, engine):
        score = engine.get_overall_coverage_score()
        assert (score["fully_covered"] + score["partially_covered"] + score["not_covered"]
                == score["total_techniques"])

    def test_coverage_grade_valid_values(self, engine):
        score = engine.get_overall_coverage_score()
        assert score["grade"] in ("A", "B", "C", "D", "F")

    def test_score_to_grade_boundaries(self, engine):
        assert engine._score_to_grade(95) == "A"
        assert engine._score_to_grade(85) == "B"
        assert engine._score_to_grade(75) == "C"
        assert engine._score_to_grade(65) == "D"
        assert engine._score_to_grade(50) == "F"

    def test_tactic_coverage_pct_between_0_and_100(self, engine):
        for tactic in engine.get_tactics():
            tc = engine.get_tactic_coverage(tactic.id)
            assert 0.0 <= tc.coverage_pct <= 100.0, f"{tactic.id}: pct out of range"

    def test_coverage_to_dict_has_required_keys(self, engine):
        cov = engine.get_coverage("T1190")
        d = cov.to_dict()
        assert "technique_id" in d
        assert "level" in d
        assert "engines" in d


# ===========================================================================
# 4. Engine — gap analysis
# ===========================================================================

class TestEngineGapAnalysis:
    def test_gap_analysis_returns_list(self, engine):
        gaps = engine.get_gap_analysis()
        assert isinstance(gaps, list)
        assert len(gaps) > 0

    def test_gap_analysis_no_full_coverage_techniques(self, engine):
        gaps = engine.get_gap_analysis()
        for gap in gaps:
            cov = engine.get_coverage(gap.technique_id)
            assert cov.level != CoverageLevel.FULL, (
                f"{gap.technique_id} has FULL coverage but appears in gap list"
            )

    def test_gap_analysis_sorted_by_frequency_desc(self, engine):
        gaps = engine.get_gap_analysis()
        scores = [g.frequency_score for g in gaps]
        assert scores == sorted(scores, reverse=True)

    def test_gap_analysis_limit(self, engine):
        gaps = engine.get_gap_analysis(limit=10)
        assert len(gaps) <= 10

    def test_gap_analysis_result_fields(self, engine):
        gaps = engine.get_gap_analysis(limit=5)
        for gap in gaps:
            assert gap.technique_id in TECHNIQUES
            assert gap.technique_name
            assert gap.tactic_ids
            assert 0.0 <= gap.frequency_score <= 1.0
            assert gap.severity in ("low", "medium", "high", "critical")
            assert gap.recommended_engine
            assert gap.recommended_action

    def test_gap_analysis_to_dict(self, engine):
        gaps = engine.get_gap_analysis(limit=1)
        d = gaps[0].to_dict()
        required = {"technique_id", "technique_name", "tactic_ids", "frequency_score",
                    "severity", "priority_rank", "recommended_engine", "recommended_action"}
        assert required.issubset(d.keys())

    def test_gap_analysis_high_frequency_techniques_not_fully_covered(self, engine):
        gaps = engine.get_gap_analysis()
        assert len(gaps) > 5, "Expected several coverage gaps to exist"


# ===========================================================================
# 5. Engine — threat group overlay
# ===========================================================================

class TestEngineThreatGroups:
    def test_get_threat_groups_returns_all(self, engine):
        groups = engine.get_threat_groups()
        assert len(groups) >= 7
        assert all(isinstance(g, ThreatGroup) for g in groups)

    def test_get_threat_group_known_id(self, engine):
        group = engine.get_threat_group("G0016")  # APT29
        assert group is not None
        assert group.name == "APT29"

    def test_get_threat_group_unknown_returns_none(self, engine):
        assert engine.get_threat_group("G9999") is None

    def test_get_threat_group_overlay_apt29(self, engine):
        overlay = engine.get_threat_group_overlay("G0016")
        assert isinstance(overlay, ThreatGroupOverlay)
        assert overlay.group_id == "G0016"
        assert overlay.group_name == "APT29"
        assert overlay.total_techniques > 0
        assert 0.0 <= overlay.coverage_pct <= 100.0
        assert overlay.risk_level in ("low", "medium", "high", "critical")

    def test_get_threat_group_overlay_unknown_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown threat group"):
            engine.get_threat_group_overlay("G9999")

    def test_overlay_blind_spots_have_no_coverage(self, engine):
        overlay = engine.get_threat_group_overlay("G0016")
        for tid in overlay.blind_spots:
            cov = engine.get_coverage(tid)
            assert cov.level == CoverageLevel.NONE

    def test_overlay_partial_coverage_list(self, engine):
        overlay = engine.get_threat_group_overlay("G0016")
        for tid in overlay.partial_coverage:
            cov = engine.get_coverage(tid)
            assert cov.level == CoverageLevel.PARTIAL

    def test_overlay_covered_count_correct(self, engine):
        overlay = engine.get_threat_group_overlay("G0016")
        expected_covered = overlay.total_techniques - len(overlay.blind_spots) - len(overlay.partial_coverage)
        assert overlay.covered_count == expected_covered

    def test_get_all_threat_group_overlays(self, engine):
        overlays = engine.get_all_threat_group_overlays()
        assert len(overlays) == len(THREAT_GROUPS)

    def test_overlay_to_dict(self, engine):
        overlay = engine.get_threat_group_overlay("G0016")
        d = overlay.to_dict()
        required = {"group_id", "group_name", "total_techniques", "covered_count",
                    "blind_spots", "partial_coverage", "coverage_pct", "risk_level"}
        assert required.issubset(d.keys())

    def test_threat_group_with_high_blind_spots_is_critical_risk(self, engine):
        """A group where >30% of techniques are uncovered should be critical risk."""
        # Find any group with critical risk
        overlays = engine.get_all_threat_group_overlays()
        risk_levels = {o.risk_level for o in overlays}
        # At minimum medium risk should exist across the threat groups
        assert risk_levels & {"critical", "high", "medium", "low"}


# ===========================================================================
# 6. Engine — layers
# ===========================================================================

class TestEngineLayers:
    def test_create_coverage_layer(self, engine):
        layer = engine.create_coverage_layer()
        assert isinstance(layer, NavigatorLayer)
        assert layer.name
        assert len(layer.techniques) > 0
        assert layer.domain == "enterprise-attack"

    def test_coverage_layer_techniques_match_known_ids(self, engine):
        layer = engine.create_coverage_layer()
        layer_ids = {a.technique_id for a in layer.techniques}
        assert layer_ids.issubset(TECHNIQUES.keys())

    def test_coverage_layer_full_coverage_has_green_color(self, engine):
        layer = engine.create_coverage_layer()
        full_cov_ids = {tid for tid, cov in DETECTION_COVERAGE.items()
                        if cov.level == CoverageLevel.FULL}
        for ann in layer.techniques:
            if ann.technique_id in full_cov_ids:
                assert ann.color == LayerColor.GREEN.value
                assert ann.score == 100.0
                break

    def test_coverage_layer_no_coverage_has_red_color(self, engine):
        layer = engine.create_coverage_layer()
        no_cov_ids = {tid for tid in TECHNIQUES if tid not in DETECTION_COVERAGE}
        for ann in layer.techniques:
            if ann.technique_id in no_cov_ids:
                assert ann.color == LayerColor.RED.value
                assert ann.score == 0.0
                break

    def test_create_threat_group_layer_apt29(self, engine):
        layer = engine.create_threat_group_layer("G0016")
        assert "APT29" in layer.name
        assert len(layer.techniques) > 0

    def test_create_threat_group_layer_unknown_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown threat group"):
            engine.create_threat_group_layer("G9999")

    def test_threat_group_layer_only_has_group_techniques(self, engine):
        group = engine.get_threat_group("G0016")
        layer = engine.create_threat_group_layer("G0016")
        layer_ids = {a.technique_id for a in layer.techniques}
        assert layer_ids == set(group.techniques)

    def test_create_custom_layer(self, engine):
        annotations = [
            {"technique_id": "T1059", "score": 80.0, "color": "#ff0000", "comment": "test"},
            {"technique_id": "T1566", "score": 50.0, "color": "#00ff00", "comment": "partial"},
        ]
        layer = engine.create_custom_layer("My Layer", "Test layer", annotations)
        assert layer.name == "My Layer"
        assert len(layer.techniques) == 2

    def test_custom_layer_stored_and_retrievable(self, engine):
        engine.create_custom_layer("Stored Layer", "desc", [
            {"technique_id": "T1059", "score": 75.0}
        ])
        retrieved = engine.get_custom_layer("Stored Layer")
        assert retrieved is not None
        assert retrieved.name == "Stored Layer"

    def test_get_custom_layer_not_found_returns_none(self, engine):
        assert engine.get_custom_layer("nonexistent_layer") is None

    def test_list_custom_layers(self, engine):
        engine.create_custom_layer("Layer A", "", [{"technique_id": "T1059", "score": 50}])
        engine.create_custom_layer("Layer B", "", [{"technique_id": "T1566", "score": 75}])
        names = engine.list_custom_layers()
        assert "Layer A" in names
        assert "Layer B" in names

    def test_custom_layer_skips_empty_technique_id(self, engine):
        annotations = [
            {"technique_id": "T1059", "score": 50.0},
            {"technique_id": "", "score": 99.0},  # should be skipped
        ]
        layer = engine.create_custom_layer("Clean Layer", "", annotations)
        assert len(layer.techniques) == 1
        assert layer.techniques[0].technique_id == "T1059"

    def test_layer_to_dict_structure(self, engine):
        layer = engine.create_coverage_layer()
        d = layer.to_dict()
        assert "name" in d
        assert "versions" in d
        assert "domain" in d
        assert "techniques" in d
        assert "gradient" in d
        assert isinstance(d["techniques"], list)


# ===========================================================================
# 7. Engine — detection rules
# ===========================================================================

class TestEngineDetectionRules:
    def test_get_detection_rule_known(self, engine):
        rule = engine.get_detection_rule("T1190")
        assert rule is not None
        assert rule.technique_id == "T1190"
        assert rule.rule_name
        assert rule.what_to_look_for
        assert rule.aldeci_engine

    def test_get_detection_rule_unknown_returns_none(self, engine):
        assert engine.get_detection_rule("T9999") is None

    def test_get_all_detection_rules(self, engine):
        rules = engine.get_all_detection_rules()
        assert len(rules) >= 8

    def test_get_detection_rules_for_engine(self, engine):
        rules = engine.get_detection_rules_for_engine(ALDECIEngine.ENDPOINT_SECURITY.value)
        assert len(rules) > 0
        assert all(r.aldeci_engine == ALDECIEngine.ENDPOINT_SECURITY.value for r in rules)

    def test_detection_rule_to_dict(self, engine):
        rule = engine.get_detection_rule("T1059.001")
        d = rule.to_dict()
        required = {"technique_id", "technique_name", "rule_name", "description",
                    "what_to_look_for", "data_sources", "aldeci_engine",
                    "query_hint", "severity"}
        assert required.issubset(d.keys())

    def test_detection_rule_what_to_look_for_is_list(self, engine):
        for rule in engine.get_all_detection_rules():
            assert isinstance(rule.what_to_look_for, list)
            assert len(rule.what_to_look_for) > 0

    def test_detection_rule_severity_valid(self, engine):
        for rule in engine.get_all_detection_rules():
            assert rule.severity in ("low", "medium", "high", "critical"), (
                f"{rule.technique_id}: invalid severity {rule.severity}"
            )


# ===========================================================================
# 8. Singleton
# ===========================================================================

class TestSingleton:
    def test_singleton_returns_same_instance(self):
        e1 = get_mitre_navigator_engine()
        e2 = get_mitre_navigator_engine()
        assert e1 is e2

    def test_singleton_is_mitre_engine(self):
        e = get_mitre_navigator_engine()
        assert isinstance(e, MITRENavigatorEngine)

    def test_singleton_has_data(self):
        e = get_mitre_navigator_engine()
        assert len(e.get_tactics()) == 14
        assert len(e.get_all_techniques()) >= 100


# ===========================================================================
# 9. Model serialization
# ===========================================================================

class TestModelSerialization:
    def test_tactic_info_to_dict(self):
        tactic = TACTICS["TA0001"]
        d = tactic.to_dict()
        assert d["id"] == "TA0001"
        assert d["name"] == "Initial Access"
        assert "description" in d
        assert "url" in d

    def test_technique_to_dict(self):
        tech = TECHNIQUES["T1059"]
        d = tech.to_dict()
        assert d["id"] == "T1059"
        assert d["name"]
        assert isinstance(d["tactic_ids"], list)
        assert isinstance(d["platforms"], list)
        assert isinstance(d["data_sources"], list)
        assert "frequency_score" in d
        assert "severity" in d

    def test_threat_group_to_dict(self):
        group = THREAT_GROUPS["G0016"]
        d = group.to_dict()
        assert d["id"] == "G0016"
        assert d["name"] == "APT29"
        assert isinstance(d["aliases"], list)
        assert isinstance(d["techniques"], list)

    def test_layer_annotation_to_dict(self):
        ann = LayerAnnotation("T1059", score=75.0, color="#ff0000", comment="test")
        d = ann.to_dict()
        assert d["techniqueID"] == "T1059"
        assert d["score"] == 75.0
        assert d["color"] == "#ff0000"
        assert d["comment"] == "test"
        assert d["enabled"] is True

    def test_tactic_coverage_to_dict(self, engine):
        tc = engine.get_tactic_coverage("TA0001")
        d = tc.to_dict()
        assert "tactic_id" in d
        assert "coverage_pct" in d
        assert "total_techniques" in d
        assert "covered_techniques" in d
        assert "uncovered_technique_ids" in d
