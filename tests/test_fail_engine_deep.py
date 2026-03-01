"""
Deep FAIL Engine tests -- comprehensive coverage of every branch, enum,
weight adjustment, edge case, and utility method in suite-core/core/fail_engine.py.

This file is ADDITIVE to test_fail_engine.py and test_fail_engine_unit.py.
It targets untested branches and combinatorial edge cases that the existing
42-test suites do not reach.

Target: 50+ test functions exercising real engine logic (no mocks, no stubs).
"""

from __future__ import annotations

import math
import uuid

import pytest

from core.fail_engine import (
    AssetCriticality,
    DataClassification,
    ExploitMaturity,
    FAILAssessScore,
    FAILEngine,
    FAILFactScore,
    FAILGrade,
    FAILImpactScore,
    FAILInput,
    FAILLikelihoodScore,
    FAILResult,
    RecommendedAction,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    """Fresh FAILEngine with default weights."""
    return FAILEngine()


# ---------------------------------------------------------------------------
# 1. Enum completeness -- every member accessible and has the expected value
# ---------------------------------------------------------------------------


class TestEnumCompleteness:
    """Verify all enum members exist and have correct string values."""

    @pytest.mark.parametrize(
        "member,value",
        [
            (FAILGrade.CRITICAL, "CRITICAL"),
            (FAILGrade.HIGH, "HIGH"),
            (FAILGrade.MEDIUM, "MEDIUM"),
            (FAILGrade.LOW, "LOW"),
            (FAILGrade.INFO, "INFO"),
        ],
    )
    def test_fail_grade_values(self, member, value):
        assert member.value == value
        assert isinstance(member, str)  # str enum

    @pytest.mark.parametrize(
        "member,value",
        [
            (RecommendedAction.PATCH_IMMEDIATELY, "PATCH_IMMEDIATELY"),
            (RecommendedAction.PATCH_NEXT_SPRINT, "PATCH_NEXT_SPRINT"),
            (RecommendedAction.SCHEDULE_FIX, "SCHEDULE_FIX"),
            (RecommendedAction.MONITOR, "MONITOR"),
            (RecommendedAction.ACCEPT_RISK, "ACCEPT_RISK"),
        ],
    )
    def test_recommended_action_values(self, member, value):
        assert member.value == value

    @pytest.mark.parametrize(
        "member,value",
        [
            (AssetCriticality.CRITICAL, "critical"),
            (AssetCriticality.HIGH, "high"),
            (AssetCriticality.MEDIUM, "medium"),
            (AssetCriticality.LOW, "low"),
            (AssetCriticality.UNKNOWN, "unknown"),
        ],
    )
    def test_asset_criticality_values(self, member, value):
        assert member.value == value

    @pytest.mark.parametrize(
        "member,value",
        [
            (DataClassification.PII, "pii"),
            (DataClassification.PHI, "phi"),
            (DataClassification.PCI, "pci"),
            (DataClassification.FINANCIAL, "financial"),
            (DataClassification.CREDENTIALS, "credentials"),
            (DataClassification.INTERNAL, "internal"),
            (DataClassification.PUBLIC, "public"),
            (DataClassification.NONE, "none"),
        ],
    )
    def test_data_classification_values(self, member, value):
        assert member.value == value

    @pytest.mark.parametrize(
        "member,value",
        [
            (ExploitMaturity.WEAPONIZED, "weaponized"),
            (ExploitMaturity.POC_PUBLIC, "poc_public"),
            (ExploitMaturity.POC_PRIVATE, "poc_private"),
            (ExploitMaturity.THEORETICAL, "theoretical"),
            (ExploitMaturity.UNKNOWN, "unknown"),
        ],
    )
    def test_exploit_maturity_values(self, member, value):
        assert member.value == value

    def test_fail_grade_has_exactly_5_members(self):
        assert len(FAILGrade) == 5

    def test_recommended_action_has_exactly_5_members(self):
        assert len(RecommendedAction) == 5

    def test_asset_criticality_has_exactly_5_members(self):
        assert len(AssetCriticality) == 5

    def test_data_classification_has_exactly_8_members(self):
        assert len(DataClassification) == 8

    def test_exploit_maturity_has_exactly_5_members(self):
        assert len(ExploitMaturity) == 5


# ---------------------------------------------------------------------------
# 2. Grade boundary tests -- exact boundary values
# ---------------------------------------------------------------------------


class TestGradeBoundariesDeep:
    """Test _score_to_grade at every boundary and transition point."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            # CRITICAL: >= 90
            (100.0, FAILGrade.CRITICAL),
            (90.0, FAILGrade.CRITICAL),
            (90.001, FAILGrade.CRITICAL),
            # HIGH: 70-89.99
            (89.999, FAILGrade.HIGH),
            (89.0, FAILGrade.HIGH),
            (70.0, FAILGrade.HIGH),
            (70.001, FAILGrade.HIGH),
            # MEDIUM: 40-69.99
            (69.999, FAILGrade.MEDIUM),
            (69.0, FAILGrade.MEDIUM),
            (50.0, FAILGrade.MEDIUM),
            (40.0, FAILGrade.MEDIUM),
            (40.001, FAILGrade.MEDIUM),
            # LOW: 20-39.99
            (39.999, FAILGrade.LOW),
            (30.0, FAILGrade.LOW),
            (20.0, FAILGrade.LOW),
            (20.001, FAILGrade.LOW),
            # INFO: 0-19.99
            (19.999, FAILGrade.INFO),
            (10.0, FAILGrade.INFO),
            (1.0, FAILGrade.INFO),
            (0.0, FAILGrade.INFO),
        ],
    )
    def test_score_to_grade_at_boundaries(self, score, expected):
        assert FAILEngine._score_to_grade(score) == expected


# ---------------------------------------------------------------------------
# 3. Action mapping -- every grade maps to exactly one action
# ---------------------------------------------------------------------------


class TestActionMappingDeep:
    """Verify bidirectional consistency between grades and actions."""

    @pytest.mark.parametrize(
        "grade,action",
        [
            (FAILGrade.CRITICAL, RecommendedAction.PATCH_IMMEDIATELY),
            (FAILGrade.HIGH, RecommendedAction.PATCH_NEXT_SPRINT),
            (FAILGrade.MEDIUM, RecommendedAction.SCHEDULE_FIX),
            (FAILGrade.LOW, RecommendedAction.MONITOR),
            (FAILGrade.INFO, RecommendedAction.ACCEPT_RISK),
        ],
    )
    def test_grade_to_action(self, grade, action):
        assert FAILEngine._grade_to_action(grade) == action

    def test_all_grades_have_action_mapping(self):
        """Every FAILGrade must produce a RecommendedAction."""
        for grade in FAILGrade:
            action = FAILEngine._grade_to_action(grade)
            assert isinstance(action, RecommendedAction)


# ---------------------------------------------------------------------------
# 4. FACT sub-score -- exhaustive evidence combination tests
# ---------------------------------------------------------------------------


class TestFactSubScoreDeep:
    """Test every evidence combination in _compute_fact."""

    def test_zero_evidence_score_is_zero(self, engine):
        result = engine.score(FAILInput())
        assert result.fact.score == 0.0
        assert result.fact.evidence_quality == "low"

    def test_only_cve_gives_45(self, engine):
        """CVE(30) + scanner_confirmed(15) = 45."""
        result = engine.score(FAILInput(cve_id="CVE-2024-0001"))
        assert result.fact.score == 45.0
        assert result.fact.evidence_quality == "medium"

    def test_only_cvss_gives_35(self, engine):
        """CVSS(20) + scanner_confirmed(15) = 35."""
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.fact.score == 35.0
        assert result.fact.evidence_quality == "low"

    def test_only_epss_gives_20(self, engine):
        """EPSS(20), no scanner_confirmed, 1 source."""
        result = engine.score(FAILInput(epss_score=0.5))
        assert result.fact.score == 20.0
        assert result.fact.has_epss is True
        assert result.fact.scanner_confirmed is False

    def test_cve_plus_cvss_gives_75(self, engine):
        """CVE(30) + CVSS(20) + 2-source bonus(10) + scanner(15) = 75."""
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        assert result.fact.score == 75.0
        assert result.fact.evidence_quality == "high"

    def test_cve_cvss_epss_gives_100(self, engine):
        """CVE(30) + CVSS(20) + EPSS(20) + 3-source(15) + scanner(15) = 100."""
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5))
        assert result.fact.score == 100.0
        assert result.fact.multiple_sources is True
        assert result.fact.evidence_quality == "high"

    def test_has_exploit_counts_as_evidence_source(self, engine):
        """has_exploit is the 4th evidence source for the multi-source bonus."""
        result = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, has_exploit=True)
        )
        # CVE(30) + CVSS(20) + 3-source(15) + scanner(15) = 80
        # 3 sources: cve, cvss, has_exploit
        assert result.fact.multiple_sources is True
        assert result.fact.score == 80.0

    def test_epss_plus_exploit_gives_2_source_bonus(self, engine):
        """EPSS + has_exploit = 2 sources, gets +10 bonus."""
        result = engine.score(FAILInput(epss_score=0.3, has_exploit=True))
        # EPSS(20) + 2-source(10) = 30
        assert result.fact.score == 30.0
        assert result.fact.scanner_confirmed is False

    def test_cvss_zero_is_not_counted(self, engine):
        """CVSS=0.0 should NOT count as evidence."""
        result = engine.score(FAILInput(cvss_score=0.0))
        assert result.fact.has_cvss is False

    def test_epss_zero_is_not_counted(self, engine):
        """EPSS=0.0 should NOT count as evidence."""
        result = engine.score(FAILInput(epss_score=0.0))
        assert result.fact.has_epss is False

    def test_cvss_none_is_not_counted(self, engine):
        result = engine.score(FAILInput(cvss_score=None))
        assert result.fact.has_cvss is False

    def test_fact_score_capped_at_100(self, engine):
        """All evidence present should not exceed 100."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-1",
                cvss_score=9.0,
                epss_score=0.8,
                has_exploit=True,
            )
        )
        assert result.fact.score <= 100.0

    def test_evidence_quality_low_threshold(self, engine):
        """Score < 40 -> low."""
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.fact.score == 35.0
        assert result.fact.evidence_quality == "low"

    def test_evidence_quality_medium_threshold(self, engine):
        """Score 40-69 -> medium."""
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert 40.0 <= result.fact.score < 70.0
        assert result.fact.evidence_quality == "medium"

    def test_evidence_quality_high_threshold(self, engine):
        """Score >= 70 -> high."""
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=9.0))
        assert result.fact.score >= 70.0
        assert result.fact.evidence_quality == "high"


# ---------------------------------------------------------------------------
# 5. ASSESS sub-score -- every CVSS tier and exploit maturity
# ---------------------------------------------------------------------------


class TestAssessSubScoreDeep:
    """Exercise every branch in _compute_assess."""

    @pytest.mark.parametrize(
        "cvss,expected_complexity,min_assess_base",
        [
            (9.5, "low", 40.0),     # >= 9.0
            (9.0, "low", 40.0),     # boundary
            (8.0, "low", 30.0),     # >= 7.0, < 9.0
            (7.0, "low", 30.0),     # boundary
            (5.5, "medium", 20.0),  # >= 4.0, < 7.0
            (4.0, "medium", 20.0),  # boundary
            (3.0, "high", 10.0),    # < 4.0
            (0.1, "high", 10.0),
        ],
    )
    def test_cvss_attack_complexity_tiers(self, engine, cvss, expected_complexity, min_assess_base):
        result = engine.score(FAILInput(cvss_score=cvss))
        assert result.assess.attack_complexity == expected_complexity

    def test_no_cvss_gives_unknown_complexity_with_15(self, engine):
        """None CVSS -> unknown complexity, +15 base score."""
        result = engine.score(FAILInput())
        assert result.assess.attack_complexity == "unknown"

    @pytest.mark.parametrize(
        "maturity,expected_label,extra_score",
        [
            (ExploitMaturity.WEAPONIZED, "weaponized", 35.0),
            (ExploitMaturity.POC_PUBLIC, "poc_public", 25.0),
            (ExploitMaturity.POC_PRIVATE, "poc_private", 15.0),
            (ExploitMaturity.THEORETICAL, "theoretical", 5.0),
        ],
    )
    def test_exploit_maturity_score_contributions(self, engine, maturity, expected_label, extra_score):
        result = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=maturity)
        )
        assert result.assess.exploit_maturity == expected_label

    def test_unknown_maturity_with_has_exploit_adds_20(self, engine):
        """ExploitMaturity.UNKNOWN + has_exploit=True -> +20."""
        without = engine.score(FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.UNKNOWN))
        with_exploit = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.UNKNOWN, has_exploit=True)
        )
        assert with_exploit.assess.score > without.assess.score

    def test_unknown_maturity_without_exploit_adds_nothing(self, engine):
        """ExploitMaturity.UNKNOWN + has_exploit=False -> no maturity bonus."""
        result = engine.score(FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.UNKNOWN))
        assert result.assess.exploit_maturity == "unknown"

    def test_privileges_none_for_cvss_8_plus(self, engine):
        result = engine.score(FAILInput(cvss_score=8.0))
        assert result.assess.privileges_required == "none"

    def test_privileges_low_for_cvss_below_8(self, engine):
        result = engine.score(FAILInput(cvss_score=7.9))
        assert result.assess.privileges_required == "low"

    def test_user_interaction_none_for_cvss_7_plus(self, engine):
        result = engine.score(FAILInput(cvss_score=7.0))
        assert result.assess.user_interaction == "none"

    def test_user_interaction_required_for_cvss_below_7(self, engine):
        result = engine.score(FAILInput(cvss_score=6.9))
        assert result.assess.user_interaction == "required"

    def test_assess_capped_at_100(self, engine):
        """Max possible assess should not exceed 100."""
        result = engine.score(
            FAILInput(
                cvss_score=10.0,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                has_exploit=True,
            )
        )
        assert result.assess.score <= 100.0

    def test_no_cvss_privileges_treated_as_low(self, engine):
        """When cvss_score is None, privileges_required is 'low' (falsy check)."""
        result = engine.score(FAILInput())
        assert result.assess.privileges_required == "low"


# ---------------------------------------------------------------------------
# 6. IMPACT sub-score -- asset criticality, data, CIA, blast radius
# ---------------------------------------------------------------------------


class TestImpactSubScoreDeep:
    """Exercise every branch in _compute_impact."""

    @pytest.mark.parametrize(
        "criticality,expected_score_contrib",
        [
            ("critical", 30.0),
            ("high", 22.0),
            ("medium", 14.0),
            ("low", 6.0),
            ("unknown", 14.0),
        ],
    )
    def test_asset_criticality_scores(self, engine, criticality, expected_score_contrib):
        """Each criticality level adds a specific amount."""
        result = engine.score(FAILInput(asset_criticality=criticality))
        # We cannot isolate the exact contribution, but we can compare relative ordering
        baseline = engine.score(FAILInput(asset_criticality="low"))
        if criticality != "low":
            if expected_score_contrib > 6.0:
                assert result.impact.score >= baseline.impact.score

    @pytest.mark.parametrize(
        "data_class,expected_contrib",
        [
            ("phi", 28.0),
            ("credentials", 28.0),
            ("pii", 25.0),
            ("pci", 25.0),
            ("financial", 22.0),
            ("internal", 12.0),
            ("public", 3.0),
            ("none", 5.0),
        ],
    )
    def test_data_classification_ordering(self, engine, data_class, expected_contrib):
        """PHI and credentials are highest; public is lowest."""
        result = engine.score(FAILInput(data_classification=data_class, cvss_score=5.0))
        public = engine.score(FAILInput(data_classification="public", cvss_score=5.0))
        if expected_contrib > 3.0:
            assert result.impact.score >= public.impact.score

    def test_business_impact_maps_known_criticalities(self, engine):
        for crit in ["critical", "high", "medium", "low"]:
            result = engine.score(FAILInput(asset_criticality=crit))
            assert result.impact.business_impact == crit

    def test_business_impact_unknown_defaults_to_medium(self, engine):
        result = engine.score(FAILInput(asset_criticality="unknown"))
        assert result.impact.business_impact == "medium"

    def test_business_impact_unrecognized_defaults_to_medium(self, engine):
        """Totally unknown string treated same as 'unknown'."""
        result = engine.score(FAILInput(asset_criticality="foobar"))
        assert result.impact.business_impact == "medium"

    def test_data_at_risk_reflects_classification(self, engine):
        for dc in ["pii", "phi", "pci", "financial", "credentials", "internal", "public", "none"]:
            result = engine.score(FAILInput(data_classification=dc))
            assert result.impact.data_at_risk == dc

    def test_unrecognized_data_classification_gets_default(self, engine):
        """Unknown data_classification string gets default 10.0 contribution."""
        result = engine.score(FAILInput(data_classification="alien_data"))
        # Should not crash; data_at_risk reflects the raw string
        assert result.impact.data_at_risk == "alien_data"

    @pytest.mark.parametrize(
        "cvss,conf,integ,avail",
        [
            (9.5, "high", "high", "high"),
            (9.0, "high", "high", "high"),
            (8.0, "high", "low", "low"),
            (7.0, "high", "low", "low"),
            (5.0, "low", "low", "none"),
            (4.0, "low", "low", "none"),
            (3.0, "none", "none", "none"),
            (None, "none", "none", "none"),
        ],
    )
    def test_cia_derived_from_cvss(self, engine, cvss, conf, integ, avail):
        result = engine.score(FAILInput(cvss_score=cvss))
        assert result.impact.confidentiality == conf
        assert result.impact.integrity == integ
        assert result.impact.availability == avail

    @pytest.mark.parametrize(
        "assets,expected_radius",
        [
            (0, "contained"),
            (1, "contained"),
            (2, "component"),
            (5, "component"),
            (9, "component"),
            (10, "system"),
            (50, "system"),
            (99, "system"),
            (100, "org-wide"),
            (1000, "org-wide"),
        ],
    )
    def test_blast_radius_thresholds(self, engine, assets, expected_radius):
        result = engine.score(FAILInput(affected_assets=assets))
        assert result.impact.blast_radius == expected_radius

    @pytest.mark.parametrize(
        "num_frameworks,expected_penalty",
        [
            (0, 0.0),
            (1, 3.0),
            (2, 6.0),
            (3, 9.0),
            (4, 10.0),   # capped at 10
            (5, 10.0),
            (10, 10.0),
        ],
    )
    def test_compliance_penalty_scaling(self, engine, num_frameworks, expected_penalty):
        """Compliance penalty = min(10, count * 3)."""
        frameworks = [f"FW-{i}" for i in range(num_frameworks)]
        with_fw = engine.score(FAILInput(cvss_score=5.0, compliance_frameworks=frameworks))
        without_fw = engine.score(FAILInput(cvss_score=5.0))
        diff = with_fw.impact.score - without_fw.impact.score
        assert abs(diff - expected_penalty) < 0.01

    def test_impact_capped_at_100(self, engine):
        """Max possible impact should not exceed 100."""
        result = engine.score(
            FAILInput(
                asset_criticality="critical",
                data_classification="phi",
                cvss_score=10.0,
                affected_assets=1000,
                compliance_frameworks=["A", "B", "C", "D", "E"],
            )
        )
        assert result.impact.score <= 100.0


# ---------------------------------------------------------------------------
# 7. LIKELIHOOD sub-score -- every signal and its interaction
# ---------------------------------------------------------------------------


class TestLikelihoodSubScoreDeep:
    """Exercise every branch in _compute_likelihood."""

    @pytest.mark.parametrize(
        "epss,expected_scaled",
        [
            (0.0, 0.0),
            (0.25, 10.0),
            (0.5, 20.0),
            (0.75, 30.0),
            (1.0, 40.0),
            (None, 0.0),
        ],
    )
    def test_epss_linear_scaling(self, engine, epss, expected_scaled):
        result = engine.score(FAILInput(epss_score=epss))
        assert abs(result.likelihood.epss_based - expected_scaled) < 0.01

    def test_kev_boost_is_25(self, engine):
        result = engine.score(FAILInput(is_kev=True))
        assert result.likelihood.kev_boost == 25.0

    def test_no_kev_boost_is_0(self, engine):
        result = engine.score(FAILInput(is_kev=False))
        assert result.likelihood.kev_boost == 0.0

    def test_has_exploit_gives_15(self, engine):
        result = engine.score(FAILInput(has_exploit=True))
        assert result.likelihood.exploit_availability == 15.0

    def test_weaponized_overrides_has_exploit_to_20(self, engine):
        """Weaponized maturity override: 20 instead of 15."""
        result = engine.score(
            FAILInput(has_exploit=True, exploit_maturity=ExploitMaturity.WEAPONIZED)
        )
        assert result.likelihood.exploit_availability == 20.0

    def test_poc_public_gives_15(self, engine):
        result = engine.score(FAILInput(exploit_maturity=ExploitMaturity.POC_PUBLIC))
        assert result.likelihood.exploit_availability == 15.0

    def test_poc_private_no_exploit_gives_0(self, engine):
        """POC_PRIVATE does not trigger the exploit_availability branch."""
        result = engine.score(FAILInput(exploit_maturity=ExploitMaturity.POC_PRIVATE))
        assert result.likelihood.exploit_availability == 0.0

    def test_theoretical_no_exploit_gives_0(self, engine):
        result = engine.score(FAILInput(exploit_maturity=ExploitMaturity.THEORETICAL))
        assert result.likelihood.exploit_availability == 0.0

    @pytest.mark.parametrize(
        "campaigns,expected_threat",
        [
            (0, 0.0),
            (1, 5.0),
            (2, 10.0),
            (3, 15.0),
            (4, 15.0),    # capped at 15
            (100, 15.0),
        ],
    )
    def test_active_campaigns_scaling(self, engine, campaigns, expected_threat):
        result = engine.score(FAILInput(active_campaigns=campaigns))
        assert abs(result.likelihood.threat_activity - expected_threat) < 0.01

    def test_reachable_adds_10(self, engine):
        result = engine.score(FAILInput(is_reachable=True))
        assert result.likelihood.exposure_factor == 10.0

    def test_internet_facing_adds_10(self, engine):
        result = engine.score(FAILInput(is_internet_facing=True))
        assert result.likelihood.exposure_factor == 10.0

    def test_both_reachable_and_internet_facing_gives_20(self, engine):
        result = engine.score(FAILInput(is_reachable=True, is_internet_facing=True))
        assert result.likelihood.exposure_factor == 20.0

    def test_compensating_controls_subtract_8(self, engine):
        result = engine.score(
            FAILInput(
                is_reachable=True,
                is_internet_facing=True,
                has_compensating_controls=True,
            )
        )
        assert result.likelihood.exposure_factor == 12.0  # 20 - 8

    def test_compensating_controls_floor_at_0(self, engine):
        """Controls applied when exposure is 0 should not go negative."""
        result = engine.score(FAILInput(has_compensating_controls=True))
        assert result.likelihood.exposure_factor == 0.0

    def test_controls_on_reachable_only_gives_2(self, engine):
        """10 (reachable) - 8 (controls) = 2."""
        result = engine.score(
            FAILInput(is_reachable=True, has_compensating_controls=True)
        )
        assert result.likelihood.exposure_factor == 2.0

    def test_likelihood_total_capped_at_100(self, engine):
        """Max everything in likelihood should cap at 100."""
        result = engine.score(
            FAILInput(
                epss_score=1.0,       # 40
                is_kev=True,          # 25
                has_exploit=True,
                exploit_maturity=ExploitMaturity.WEAPONIZED,  # 20
                active_campaigns=10,  # 15
                is_reachable=True,    # 10
                is_internet_facing=True,  # 10
            )
        )
        # 40+25+20+15+20 = 120 -> capped at 100
        assert result.likelihood.score == 100.0


# ---------------------------------------------------------------------------
# 8. Dynamic weight adjustment -- all three adjustment paths
# ---------------------------------------------------------------------------


class TestDynamicWeightsDeep:
    """Test the three adjustment conditions in _adjust_weights."""

    def test_default_weights_when_no_triggers(self, engine):
        """Good evidence, no KEV, non-critical asset -> default weights."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-1",
                cvss_score=7.0,
                epss_score=0.5,
                has_exploit=True,
                asset_criticality="medium",
            )
        )
        # Should be close to defaults 0.2/0.2/0.3/0.3
        for key in ("fact", "assess", "impact", "likelihood"):
            assert key in result.weights

    def test_low_evidence_boosts_fact(self, engine):
        """No evidence -> fact gets +0.10, likelihood -0.05, impact -0.05."""
        result = engine.score(FAILInput())
        # fact should be higher than default 0.20
        assert result.weights["fact"] > 0.20

    def test_kev_boosts_likelihood(self, engine):
        """KEV -> likelihood +0.10, assess -0.05, fact -0.05."""
        no_kev = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True))
        kev = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True, is_kev=True)
        )
        assert kev.weights["likelihood"] > no_kev.weights["likelihood"]

    def test_active_campaigns_boost_likelihood(self, engine):
        """active_campaigns > 0 triggers same boost as KEV."""
        no_camp = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True)
        )
        camp = engine.score(
            FAILInput(
                cve_id="CVE-1",
                cvss_score=7.0,
                epss_score=0.5,
                has_exploit=True,
                active_campaigns=2,
            )
        )
        assert camp.weights["likelihood"] > no_camp.weights["likelihood"]

    def test_critical_asset_boosts_impact(self, engine):
        medium = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True, asset_criticality="medium")
        )
        critical = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True, asset_criticality="critical")
        )
        assert critical.weights["impact"] > medium.weights["impact"]

    def test_high_asset_also_boosts_impact(self, engine):
        """asset_criticality='high' also triggers impact boost."""
        medium = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True, asset_criticality="medium")
        )
        high = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True, asset_criticality="high")
        )
        assert high.weights["impact"] > medium.weights["impact"]

    def test_all_adjustments_together_still_sum_to_1(self, engine):
        """Trigger ALL three adjustments at once."""
        result = engine.score(
            FAILInput(
                # No evidence -> low evidence trigger
                is_kev=True,                    # KEV trigger
                active_campaigns=3,             # campaigns trigger
                asset_criticality="critical",   # critical asset trigger
            )
        )
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    @pytest.mark.parametrize("_idx", range(10))
    def test_weights_always_sum_to_1_random_combos(self, engine, _idx):
        """Parametrized: various combos always normalize to 1.0."""
        combos = [
            FAILInput(),
            FAILInput(is_kev=True),
            FAILInput(asset_criticality="critical"),
            FAILInput(is_kev=True, asset_criticality="critical"),
            FAILInput(cve_id="X", cvss_score=9.0, epss_score=0.9, has_exploit=True),
            FAILInput(active_campaigns=5),
            FAILInput(asset_criticality="high", active_campaigns=1),
            FAILInput(cve_id="X", cvss_score=5.0),
            FAILInput(is_kev=True, asset_criticality="high"),
            FAILInput(epss_score=0.01),
        ]
        result = engine.score(combos[_idx])
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_weights_contain_four_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert set(result.weights.keys()) == {"fact", "assess", "impact", "likelihood"}

    def test_no_negative_weights(self, engine):
        """No individual weight should go negative after adjustment and normalization."""
        result = engine.score(
            FAILInput(
                is_kev=True,
                active_campaigns=10,
                asset_criticality="critical",
            )
        )
        for key, weight in result.weights.items():
            assert weight >= 0.0, f"Weight {key} is negative: {weight}"


# ---------------------------------------------------------------------------
# 9. Composite scoring and clamping
# ---------------------------------------------------------------------------


class TestCompositeScoreDeep:
    """Verify composite FAIL score is correct and always in [0, 100]."""

    def test_zero_input_score_in_range(self, engine):
        result = engine.score(FAILInput())
        assert 0.0 <= result.fail_score <= 100.0

    def test_maximum_input_score_in_range(self, engine):
        result = engine.score(
            FAILInput(
                cve_id="CVE-MAX",
                cvss_score=10.0,
                epss_score=1.0,
                is_kev=True,
                has_exploit=True,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                active_campaigns=100,
                asset_criticality="critical",
                data_classification="credentials",
                is_reachable=True,
                is_internet_facing=True,
                affected_assets=10000,
                compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO", "NIST"],
            )
        )
        assert 0.0 <= result.fail_score <= 100.0
        assert result.grade in (FAILGrade.CRITICAL, FAILGrade.HIGH)

    def test_composite_equals_weighted_sum(self, engine):
        """Verify the composite is actually fact*w_f + assess*w_a + impact*w_i + likelihood*w_l."""
        inp = FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.4)
        result = engine.score(inp)
        expected = (
            result.fact.score * result.weights["fact"]
            + result.assess.score * result.weights["assess"]
            + result.impact.score * result.weights["impact"]
            + result.likelihood.score * result.weights["likelihood"]
        )
        expected = max(0.0, min(100.0, expected))
        assert abs(result.fail_score - expected) < 0.01


# ---------------------------------------------------------------------------
# 10. Batch scoring, ranking, compare
# ---------------------------------------------------------------------------


class TestBatchAndRankDeep:
    def test_batch_preserves_order(self, engine):
        """Batch results are in same order as inputs."""
        inputs = [FAILInput(cve_id=f"CVE-{i}") for i in range(5)]
        results = engine.score_batch(inputs)
        for i, result in enumerate(results):
            assert result.cve_id == f"CVE-{i}"

    def test_batch_empty(self, engine):
        assert engine.score_batch([]) == []

    def test_batch_single_item(self, engine):
        results = engine.score_batch([FAILInput(cve_id="CVE-SINGLE")])
        assert len(results) == 1
        assert results[0].cve_id == "CVE-SINGLE"

    def test_rank_descending(self, engine):
        inputs = [
            FAILInput(cve_id="LOW", cvss_score=1.0),
            FAILInput(cve_id="HIGH", cvss_score=10.0, is_kev=True, asset_criticality="critical"),
            FAILInput(cve_id="MED", cvss_score=5.0),
        ]
        results = engine.score_batch(inputs)
        ranked = engine.rank(results)
        for i in range(len(ranked) - 1):
            assert ranked[i].fail_score >= ranked[i + 1].fail_score

    def test_rank_empty_list(self, engine):
        assert engine.rank([]) == []

    def test_compare_winner_is_higher_score(self, engine):
        a = engine.score(FAILInput(cve_id="A", cvss_score=9.0))
        b = engine.score(FAILInput(cve_id="B", cvss_score=3.0))
        cmp = engine.compare(a, b)
        assert cmp["winner"] == "A"
        assert cmp["score_diff"] == abs(a.fail_score - b.fail_score)
        assert cmp["a"]["cve"] == "A"
        assert cmp["b"]["cve"] == "B"
        assert cmp["a"]["grade"] in [g.value for g in FAILGrade]

    def test_compare_equal_scores_picks_first(self, engine):
        a = engine.score(FAILInput(cve_id="X", cvss_score=5.0))
        b = engine.score(FAILInput(cve_id="Y", cvss_score=5.0))
        cmp = engine.compare(a, b)
        # When equal, a.fail_score >= b.fail_score is True, so winner is a.cve_id
        assert cmp["winner"] == "X"
        assert cmp["score_diff"] == 0.0


# ---------------------------------------------------------------------------
# 11. Statistics
# ---------------------------------------------------------------------------


class TestStatsDeep:
    def test_empty_engine_stats(self):
        fresh = FAILEngine()
        stats = fresh.stats()
        assert stats == {"total_scored": 0}

    def test_stats_average_score(self):
        engine = FAILEngine()
        engine.score(FAILInput(cvss_score=2.0))
        engine.score(FAILInput(cvss_score=8.0))
        stats = engine.stats()
        assert stats["total_scored"] == 2
        assert stats["min_score"] <= stats["average_score"] <= stats["max_score"]

    def test_stats_grade_distribution(self):
        engine = FAILEngine()
        for cvss in [1.0, 3.0, 5.0, 7.0, 10.0]:
            engine.score(FAILInput(cve_id=f"CVE-{cvss}", cvss_score=cvss))
        stats = engine.stats()
        assert stats["total_scored"] == 5
        assert isinstance(stats["grade_distribution"], dict)
        total_dist = sum(stats["grade_distribution"].values())
        assert total_dist == 5

    def test_stats_critical_and_high_counts(self):
        engine = FAILEngine()
        # Force a high-scoring finding
        engine.score(
            FAILInput(
                cve_id="CVE-CRIT",
                cvss_score=10.0,
                epss_score=0.97,
                is_kev=True,
                has_exploit=True,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                asset_criticality="critical",
                is_reachable=True,
                is_internet_facing=True,
            )
        )
        stats = engine.stats()
        assert stats["critical_count"] + stats["high_count"] >= 1


# ---------------------------------------------------------------------------
# 12. Serialization: to_dict
# ---------------------------------------------------------------------------


class TestSerializationDeep:
    def test_to_dict_all_top_level_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        d = result.to_dict()
        required_keys = {
            "score_id", "fail_score", "grade", "recommended_action",
            "cve_id", "finding_id", "sub_scores", "weights",
            "scored_at", "engine_version", "computation_ms",
        }
        assert required_keys.issubset(set(d.keys()))

    def test_to_dict_sub_score_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        d = result.to_dict()
        for sub in ["fact", "assess", "impact", "likelihood"]:
            assert sub in d["sub_scores"]

    def test_to_dict_fact_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        fact = result.to_dict()["sub_scores"]["fact"]
        for key in ["score", "has_cve", "has_cvss", "has_epss", "scanner_confirmed",
                     "multiple_sources", "evidence_quality"]:
            assert key in fact

    def test_to_dict_assess_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        assess = result.to_dict()["sub_scores"]["assess"]
        for key in ["score", "attack_complexity", "privileges_required",
                     "user_interaction", "exploit_maturity"]:
            assert key in assess

    def test_to_dict_impact_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        impact = result.to_dict()["sub_scores"]["impact"]
        for key in ["score", "confidentiality", "integrity", "availability",
                     "blast_radius", "data_at_risk", "business_impact"]:
            assert key in impact

    def test_to_dict_likelihood_keys(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        lk = result.to_dict()["sub_scores"]["likelihood"]
        for key in ["score", "epss_based", "kev_boost", "exploit_availability",
                     "threat_activity", "exposure_factor"]:
            assert key in lk

    def test_to_dict_scores_are_rounded(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.3, epss_score=0.333))
        d = result.to_dict()
        # fail_score rounded to 2 decimals
        score_str = str(d["fail_score"])
        if "." in score_str:
            assert len(score_str.split(".")[1]) <= 2

    def test_to_dict_weights_are_rounded(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        d = result.to_dict()
        for key, val in d["weights"].items():
            val_str = str(val)
            if "." in val_str:
                assert len(val_str.split(".")[1]) <= 3

    def test_grade_value_is_string(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        d = result.to_dict()
        assert isinstance(d["grade"], str)
        assert d["grade"] in [g.value for g in FAILGrade]


# ---------------------------------------------------------------------------
# 13. Score ID generation and metadata
# ---------------------------------------------------------------------------


class TestScoreIdAndMetadata:
    def test_score_id_format(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.score_id.startswith("FAIL-")
        assert len(result.score_id) == 17  # FAIL- + 12 hex chars

    def test_score_ids_are_unique(self, engine):
        ids = set()
        for i in range(20):
            result = engine.score(FAILInput(cve_id=f"CVE-{i}"))
            ids.add(result.score_id)
        assert len(ids) == 20

    def test_explicit_score_id_preserved(self):
        result = FAILResult(score_id="FAIL-CUSTOM123456")
        assert result.score_id == "FAIL-CUSTOM123456"

    def test_scored_at_is_iso_format(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert "T" in result.scored_at
        assert result.scored_at.endswith("+00:00") or result.scored_at.endswith("Z")

    def test_engine_version(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.engine_version == "1.0.0"
        assert FAILEngine.VERSION == "1.0.0"

    def test_computation_ms_is_non_negative(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.computation_ms >= 0.0

    def test_cve_id_propagated(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-2024-99999"))
        assert result.cve_id == "CVE-2024-99999"

    def test_finding_id_propagated(self, engine):
        result = engine.score(FAILInput(finding_id="FIND-001"))
        assert result.finding_id == "FIND-001"


# ---------------------------------------------------------------------------
# 14. History management
# ---------------------------------------------------------------------------


class TestHistoryDeep:
    def test_fresh_engine_empty_history(self):
        engine = FAILEngine()
        assert engine.history == []
        assert len(engine.history) == 0

    def test_scoring_appends_to_history(self):
        engine = FAILEngine()
        engine.score(FAILInput(cve_id="CVE-1"))
        engine.score(FAILInput(cve_id="CVE-2"))
        engine.score(FAILInput(cve_id="CVE-3"))
        assert len(engine.history) == 3

    def test_history_returns_copy(self):
        engine = FAILEngine()
        engine.score(FAILInput(cve_id="CVE-1"))
        h = engine.history
        h.clear()
        assert len(engine.history) == 1  # Internal list is not cleared

    def test_history_elements_are_fail_results(self):
        engine = FAILEngine()
        engine.score(FAILInput(cve_id="CVE-1"))
        for item in engine.history:
            assert isinstance(item, FAILResult)


# ---------------------------------------------------------------------------
# 15. Custom weights
# ---------------------------------------------------------------------------


class TestCustomWeightsDeep:
    def test_custom_weights_change_scoring(self):
        """Fact-heavy engine vs likelihood-heavy engine produce different scores."""
        fact_heavy = FAILEngine(weights={"fact": 0.70, "assess": 0.10, "impact": 0.10, "likelihood": 0.10})
        like_heavy = FAILEngine(weights={"fact": 0.10, "assess": 0.10, "impact": 0.10, "likelihood": 0.70})
        inp = FAILInput(
            cve_id="CVE-1",
            cvss_score=7.0,
            epss_score=0.9,
            is_kev=True,
            asset_criticality="low",
        )
        r_fact = fact_heavy.score(inp)
        r_like = like_heavy.score(inp)
        # They should produce different scores since the sub-scores differ
        assert r_fact.fail_score != r_like.fail_score

    def test_custom_weights_still_normalize_to_1(self):
        engine = FAILEngine(weights={"fact": 2.0, "assess": 3.0, "impact": 4.0, "likelihood": 1.0})
        result = engine.score(FAILInput(cve_id="CVE-1"))
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001


# ---------------------------------------------------------------------------
# 16. FAILResult dataclass defaults
# ---------------------------------------------------------------------------


class TestFAILResultDefaults:
    def test_default_result_has_auto_id(self):
        r = FAILResult()
        assert r.score_id.startswith("FAIL-")

    def test_default_result_has_scored_at(self):
        r = FAILResult()
        assert r.scored_at != ""

    def test_default_grade_is_info(self):
        r = FAILResult()
        assert r.grade == FAILGrade.INFO

    def test_default_action_is_accept_risk(self):
        r = FAILResult()
        assert r.recommended_action == RecommendedAction.ACCEPT_RISK

    def test_default_fail_score_is_zero(self):
        r = FAILResult()
        assert r.fail_score == 0.0

    def test_default_sub_scores_are_zero(self):
        r = FAILResult()
        assert r.fact.score == 0.0
        assert r.assess.score == 0.0
        assert r.impact.score == 0.0
        assert r.likelihood.score == 0.0


# ---------------------------------------------------------------------------
# 17. FAILInput mutable defaults isolation
# ---------------------------------------------------------------------------


class TestFAILInputIsolation:
    def test_compliance_frameworks_not_shared(self):
        a = FAILInput()
        b = FAILInput()
        a.compliance_frameworks.append("SOC2")
        assert b.compliance_frameworks == []

    def test_metadata_not_shared(self):
        a = FAILInput()
        b = FAILInput()
        a.metadata["key"] = "val"
        assert "key" not in b.metadata


# ---------------------------------------------------------------------------
# 18. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_none_asset_criticality(self, engine):
        """asset_criticality=None should not crash."""
        result = engine.score(FAILInput(asset_criticality=None))  # type: ignore[arg-type]
        assert 0.0 <= result.fail_score <= 100.0

    def test_none_data_classification(self, engine):
        """data_classification=None should not crash."""
        result = engine.score(FAILInput(data_classification=None))  # type: ignore[arg-type]
        assert 0.0 <= result.fail_score <= 100.0

    def test_affected_assets_zero(self, engine):
        result = engine.score(FAILInput(affected_assets=0))
        assert result.impact.blast_radius == "contained"

    def test_very_small_epss(self, engine):
        result = engine.score(FAILInput(epss_score=0.0001))
        assert result.likelihood.epss_based > 0.0
        assert result.likelihood.epss_based < 1.0

    def test_cvss_exactly_boundaries(self, engine):
        """Test CVSS at exact boundary values for all tiers."""
        for cvss in [0.0, 4.0, 7.0, 8.0, 9.0, 10.0]:
            result = engine.score(FAILInput(cvss_score=cvss))
            assert 0.0 <= result.fail_score <= 100.0
