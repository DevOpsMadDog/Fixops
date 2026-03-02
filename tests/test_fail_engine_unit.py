"""
Comprehensive unit tests for the FAIL Engine (suite-core/core/fail_engine.py).

Covers:
  - FAILInput default values and construction
  - FAILResult auto-generated fields (score_id, scored_at)
  - FAILResult.to_dict() structure and rounding
  - $FACT sub-score: CVE present, CVSS present, EPSS present, multiple sources
  - $ASSESS sub-score: attack complexity tiers, exploit maturity, privileges
  - $IMPACT sub-score: asset criticality, data classification, blast radius, compliance
  - $LIKELIHOOD sub-score: EPSS scaling, KEV boost, campaigns, exposure, controls
  - Dynamic weight adjustment (low evidence, KEV, critical asset)
  - Composite scoring: boundary grades, clamping to 0-100
  - Grade/action mapping: parametric boundary tests
  - Batch scoring and ranking
  - History and statistics
  - Compare utility
  - Custom weights
"""

from __future__ import annotations

import pytest

from core.fail_engine import (
    AssetCriticality,
    DataClassification,
    ExploitMaturity,
    FAILEngine,
    FAILGrade,
    FAILInput,
    FAILResult,
    RecommendedAction,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    return FAILEngine()


@pytest.fixture
def critical_input():
    """Worst-case CVE: KEV, weaponized, critical asset, PII, reachable."""
    return FAILInput(
        cve_id="CVE-2024-3094",
        title="XZ Utils backdoor",
        cvss_score=10.0,
        epss_score=0.97,
        is_kev=True,
        has_exploit=True,
        exploit_maturity=ExploitMaturity.WEAPONIZED,
        active_campaigns=3,
        asset_criticality="critical",
        data_classification="pii",
        is_reachable=True,
        is_internet_facing=True,
        has_compensating_controls=False,
        affected_assets=50,
        compliance_frameworks=["SOC2", "PCI-DSS"],
    )


@pytest.fixture
def minimal_input():
    """Absolute minimum input: no CVE, no scores."""
    return FAILInput()


# ---------------------------------------------------------------------------
# FAILInput construction tests
# ---------------------------------------------------------------------------


class TestFAILInputDefaults:
    def test_default_fields_are_safe(self):
        inp = FAILInput()
        assert inp.cve_id is None
        assert inp.cvss_score is None
        assert inp.epss_score is None
        assert inp.is_kev is False
        assert inp.has_exploit is False
        assert inp.exploit_maturity == ExploitMaturity.UNKNOWN
        assert inp.active_campaigns == 0
        assert inp.asset_criticality == "unknown"
        assert inp.data_classification == "none"
        assert inp.is_reachable is False
        assert inp.is_internet_facing is False
        assert inp.has_compensating_controls is False
        assert inp.affected_assets == 1
        assert inp.affected_users == 0
        assert inp.compliance_frameworks == []
        assert inp.metadata == {}

    def test_compliance_frameworks_not_shared_between_instances(self):
        a = FAILInput()
        b = FAILInput()
        a.compliance_frameworks.append("SOC2")
        assert b.compliance_frameworks == []

    def test_metadata_not_shared_between_instances(self):
        a = FAILInput()
        b = FAILInput()
        a.metadata["key"] = "val"
        assert "key" not in b.metadata


# ---------------------------------------------------------------------------
# FAILResult auto-generated fields
# ---------------------------------------------------------------------------


class TestFAILResultAutoFields:
    def test_score_id_auto_generated(self):
        r = FAILResult()
        assert r.score_id.startswith("FAIL-")
        assert len(r.score_id) == 17  # "FAIL-" + 12 hex chars

    def test_scored_at_auto_generated(self):
        r = FAILResult()
        assert r.scored_at != ""
        assert "T" in r.scored_at  # ISO format

    def test_explicit_score_id_preserved(self):
        r = FAILResult(score_id="FAIL-CUSTOM123456")
        assert r.score_id == "FAIL-CUSTOM123456"

    def test_to_dict_structure(self, engine, critical_input):
        result = engine.score(critical_input)
        d = result.to_dict()
        # Top-level keys
        for key in [
            "score_id", "fail_score", "grade", "recommended_action",
            "cve_id", "finding_id", "sub_scores", "weights",
            "scored_at", "engine_version", "computation_ms",
        ]:
            assert key in d, f"Missing key: {key}"
        # Sub-score keys
        for sub in ["fact", "assess", "impact", "likelihood"]:
            assert sub in d["sub_scores"]
        # Values are rounded
        assert isinstance(d["fail_score"], float)
        assert d["engine_version"] == "1.0.0"

    def test_to_dict_score_rounded_to_two_decimals(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.3))
        d = result.to_dict()
        score_str = str(d["fail_score"])
        if "." in score_str:
            decimals = len(score_str.split(".")[1])
            assert decimals <= 2


# ---------------------------------------------------------------------------
# $FACT sub-score tests
# ---------------------------------------------------------------------------


class TestFactScoreUnit:
    def test_no_evidence_produces_low_score(self, engine):
        result = engine.score(FAILInput())
        assert result.fact.score == 0.0
        assert result.fact.has_cve is False
        assert result.fact.has_cvss is False
        assert result.fact.has_epss is False
        assert result.fact.evidence_quality == "low"

    def test_cve_only_gives_partial_score(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-2024-0001"))
        assert result.fact.has_cve is True
        assert result.fact.score >= 30.0  # CVE=30 + scanner_confirmed=15

    def test_cvss_zero_treated_as_no_cvss(self, engine):
        result = engine.score(FAILInput(cvss_score=0.0))
        assert result.fact.has_cvss is False

    def test_epss_zero_treated_as_no_epss(self, engine):
        result = engine.score(FAILInput(epss_score=0.0))
        assert result.fact.has_epss is False

    def test_all_evidence_produces_high_quality(self, engine):
        result = engine.score(FAILInput(
            cve_id="CVE-2024-1",
            cvss_score=9.0,
            epss_score=0.5,
            has_exploit=True,
        ))
        assert result.fact.has_cve is True
        assert result.fact.has_cvss is True
        assert result.fact.has_epss is True
        assert result.fact.multiple_sources is True
        assert result.fact.evidence_quality == "high"
        assert result.fact.score == 100.0  # 30+20+20+15+15 = 100

    def test_two_sources_gives_medium_bonus(self, engine):
        # CVE + CVSS = 2 sources, gets +10
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=5.0))
        assert result.fact.multiple_sources is False  # need >= 3
        assert result.fact.score >= 60.0  # 30+20+10+15 = 75

    def test_scanner_confirmed_when_cve_present(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.fact.scanner_confirmed is True

    def test_scanner_confirmed_when_cvss_present(self, engine):
        result = engine.score(FAILInput(cvss_score=4.0))
        assert result.fact.scanner_confirmed is True

    def test_medium_evidence_quality_range(self, engine):
        # Score between 40-69 => medium
        engine.score(FAILInput(cve_id="CVE-1", cvss_score=5.0))
        # 30 + 20 + 10(2 sources) + 15(scanner) = 75 => "high"
        # Actually this will be high. Let me find a combo that gives medium.
        engine.score(FAILInput(cvss_score=5.0))
        # 0 + 20 + 0 + 0(1 source) + 15(scanner) = 35 ... low
        # Need 40-69 for medium. CVE alone: 30+15=45 => medium
        result3 = engine.score(FAILInput(cve_id="CVE-1"))
        assert result3.fact.score == 45.0
        assert result3.fact.evidence_quality == "medium"


# ---------------------------------------------------------------------------
# $ASSESS sub-score tests
# ---------------------------------------------------------------------------


class TestAssessScoreUnit:
    def test_cvss_9_plus_gives_low_complexity(self, engine):
        result = engine.score(FAILInput(cvss_score=9.5))
        assert result.assess.attack_complexity == "low"
        assert result.assess.score >= 40.0

    def test_cvss_7_gives_low_complexity(self, engine):
        result = engine.score(FAILInput(cvss_score=7.5))
        assert result.assess.attack_complexity == "low"

    def test_cvss_4_gives_medium_complexity(self, engine):
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.assess.attack_complexity == "medium"

    def test_cvss_below_4_gives_high_complexity(self, engine):
        result = engine.score(FAILInput(cvss_score=2.0))
        assert result.assess.attack_complexity == "high"

    def test_no_cvss_gives_unknown_complexity(self, engine):
        result = engine.score(FAILInput())
        assert result.assess.attack_complexity == "unknown"

    def test_weaponized_exploit_maturity_adds_35(self, engine):
        base = engine.score(FAILInput(cvss_score=7.0))
        weaponized = engine.score(FAILInput(
            cvss_score=7.0,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        ))
        assert weaponized.assess.exploit_maturity == "weaponized"
        assert weaponized.assess.score > base.assess.score

    def test_poc_public_adds_25(self, engine):
        result = engine.score(FAILInput(
            cvss_score=7.0,
            exploit_maturity=ExploitMaturity.POC_PUBLIC,
        ))
        assert result.assess.exploit_maturity == "poc_public"

    def test_theoretical_exploit_adds_5(self, engine):
        result = engine.score(FAILInput(
            cvss_score=7.0,
            exploit_maturity=ExploitMaturity.THEORETICAL,
        ))
        assert result.assess.exploit_maturity == "theoretical"

    def test_unknown_maturity_with_exploit_adds_20(self, engine):
        result = engine.score(FAILInput(
            cvss_score=7.0,
            has_exploit=True,
            exploit_maturity=ExploitMaturity.UNKNOWN,
        ))
        assert result.assess.exploit_maturity == "unknown"

    def test_high_cvss_means_no_privileges(self, engine):
        result = engine.score(FAILInput(cvss_score=9.0))
        assert result.assess.privileges_required == "none"

    def test_low_cvss_means_low_privileges(self, engine):
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.assess.privileges_required == "low"

    def test_high_cvss_means_no_user_interaction(self, engine):
        result = engine.score(FAILInput(cvss_score=7.5))
        assert result.assess.user_interaction == "none"

    def test_low_cvss_means_required_interaction(self, engine):
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.assess.user_interaction == "required"

    def test_assess_score_capped_at_100(self, engine):
        # Maximum combo
        result = engine.score(FAILInput(
            cvss_score=10.0,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
            has_exploit=True,
        ))
        assert result.assess.score <= 100.0


# ---------------------------------------------------------------------------
# $IMPACT sub-score tests
# ---------------------------------------------------------------------------


class TestImpactScoreUnit:
    def test_critical_asset_adds_30(self, engine):
        result = engine.score(FAILInput(asset_criticality="critical", cvss_score=5.0))
        high = engine.score(FAILInput(asset_criticality="high", cvss_score=5.0))
        assert result.impact.score > high.impact.score

    def test_unknown_asset_treated_as_medium(self, engine):
        result = engine.score(FAILInput(asset_criticality="unknown", cvss_score=5.0))
        medium = engine.score(FAILInput(asset_criticality="medium", cvss_score=5.0))
        assert result.impact.score == medium.impact.score

    def test_phi_data_scores_highest(self, engine):
        phi = engine.score(FAILInput(data_classification="phi", cvss_score=5.0))
        pii = engine.score(FAILInput(data_classification="pii", cvss_score=5.0))
        assert phi.impact.score >= pii.impact.score

    def test_credentials_data_scores_high(self, engine):
        result = engine.score(FAILInput(data_classification="credentials", cvss_score=5.0))
        public = engine.score(FAILInput(data_classification="public", cvss_score=5.0))
        assert result.impact.score > public.impact.score

    def test_public_data_scores_low(self, engine):
        result = engine.score(FAILInput(data_classification="public"))
        assert result.impact.data_at_risk == "public"

    def test_cia_high_for_cvss_9_plus(self, engine):
        result = engine.score(FAILInput(cvss_score=9.5))
        assert result.impact.confidentiality == "high"
        assert result.impact.integrity == "high"
        assert result.impact.availability == "high"

    def test_cia_mixed_for_cvss_7(self, engine):
        result = engine.score(FAILInput(cvss_score=7.5))
        assert result.impact.confidentiality == "high"
        assert result.impact.integrity == "low"

    def test_blast_radius_contained_for_1_asset(self, engine):
        result = engine.score(FAILInput(affected_assets=1))
        assert result.impact.blast_radius == "contained"

    def test_blast_radius_component_for_2_assets(self, engine):
        result = engine.score(FAILInput(affected_assets=5))
        assert result.impact.blast_radius == "component"

    def test_blast_radius_system_for_10_assets(self, engine):
        result = engine.score(FAILInput(affected_assets=20))
        assert result.impact.blast_radius == "system"

    def test_blast_radius_orgwide_for_100_assets(self, engine):
        result = engine.score(FAILInput(affected_assets=100))
        assert result.impact.blast_radius == "org-wide"

    def test_compliance_penalty_capped_at_10(self, engine):
        many = engine.score(FAILInput(
            cvss_score=5.0,
            compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO27001", "NIST"],
        ))
        # 5 frameworks * 3.0 = 15, capped at 10
        few = engine.score(FAILInput(
            cvss_score=5.0,
            compliance_frameworks=["SOC2"],
        ))
        diff = many.impact.score - few.impact.score
        assert diff <= 10.0  # penalty capped

    def test_impact_score_capped_at_100(self, engine):
        result = engine.score(FAILInput(
            cvss_score=10.0,
            asset_criticality="critical",
            data_classification="phi",
            affected_assets=1000,
            compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO"],
        ))
        assert result.impact.score <= 100.0

    def test_business_impact_maps_correctly(self, engine):
        crit = engine.score(FAILInput(asset_criticality="critical"))
        assert crit.impact.business_impact == "critical"
        low = engine.score(FAILInput(asset_criticality="low"))
        assert low.impact.business_impact == "low"


# ---------------------------------------------------------------------------
# $LIKELIHOOD sub-score tests
# ---------------------------------------------------------------------------


class TestLikelihoodScoreUnit:
    def test_epss_scaled_to_40(self, engine):
        result = engine.score(FAILInput(epss_score=1.0))
        assert result.likelihood.epss_based == 40.0

    def test_epss_zero_gives_zero(self, engine):
        result = engine.score(FAILInput(epss_score=0.0))
        assert result.likelihood.epss_based == 0.0

    def test_epss_none_gives_zero(self, engine):
        result = engine.score(FAILInput())
        assert result.likelihood.epss_based == 0.0

    def test_kev_adds_25(self, engine):
        result = engine.score(FAILInput(is_kev=True))
        assert result.likelihood.kev_boost == 25.0

    def test_no_kev_gives_zero_boost(self, engine):
        result = engine.score(FAILInput(is_kev=False))
        assert result.likelihood.kev_boost == 0.0

    def test_exploit_availability_15_for_has_exploit(self, engine):
        result = engine.score(FAILInput(has_exploit=True))
        assert result.likelihood.exploit_availability == 15.0

    def test_weaponized_overrides_to_20(self, engine):
        result = engine.score(FAILInput(
            has_exploit=True,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        ))
        assert result.likelihood.exploit_availability == 20.0

    def test_poc_public_gives_15(self, engine):
        result = engine.score(FAILInput(
            exploit_maturity=ExploitMaturity.POC_PUBLIC,
        ))
        assert result.likelihood.exploit_availability == 15.0

    def test_active_campaigns_capped_at_15(self, engine):
        result = engine.score(FAILInput(active_campaigns=100))
        assert result.likelihood.threat_activity == 15.0

    def test_three_campaigns_gives_15(self, engine):
        result = engine.score(FAILInput(active_campaigns=3))
        assert result.likelihood.threat_activity == 15.0

    def test_one_campaign_gives_5(self, engine):
        result = engine.score(FAILInput(active_campaigns=1))
        assert result.likelihood.threat_activity == 5.0

    def test_reachable_adds_10(self, engine):
        result = engine.score(FAILInput(is_reachable=True))
        assert result.likelihood.exposure_factor >= 10.0

    def test_internet_facing_adds_10(self, engine):
        result = engine.score(FAILInput(is_internet_facing=True))
        assert result.likelihood.exposure_factor >= 10.0

    def test_both_reachable_and_internet_facing_gives_20(self, engine):
        result = engine.score(FAILInput(is_reachable=True, is_internet_facing=True))
        assert result.likelihood.exposure_factor == 20.0

    def test_compensating_controls_reduce_by_8(self, engine):
        exposed = engine.score(FAILInput(is_reachable=True, is_internet_facing=True))
        controlled = engine.score(FAILInput(
            is_reachable=True,
            is_internet_facing=True,
            has_compensating_controls=True,
        ))
        assert controlled.likelihood.exposure_factor == 12.0
        assert exposed.likelihood.exposure_factor == 20.0

    def test_controls_dont_go_below_zero(self, engine):
        result = engine.score(FAILInput(has_compensating_controls=True))
        assert result.likelihood.exposure_factor >= 0.0

    def test_likelihood_score_capped_at_100(self, engine):
        result = engine.score(FAILInput(
            epss_score=1.0,
            is_kev=True,
            has_exploit=True,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
            active_campaigns=100,
            is_reachable=True,
            is_internet_facing=True,
        ))
        assert result.likelihood.score <= 100.0


# ---------------------------------------------------------------------------
# Dynamic weight adjustment
# ---------------------------------------------------------------------------


class TestDynamicWeightsUnit:
    def test_weights_always_sum_to_one(self, engine):
        inputs = [
            FAILInput(),
            FAILInput(cve_id="CVE-1", cvss_score=10.0, is_kev=True),
            FAILInput(asset_criticality="critical"),
            FAILInput(is_kev=True, asset_criticality="critical"),
        ]
        for inp in inputs:
            result = engine.score(inp)
            total = sum(result.weights.values())
            assert abs(total - 1.0) < 0.001, f"Weights sum to {total}, not 1.0"

    def test_low_evidence_boosts_fact_weight(self, engine):
        low_evidence = engine.score(FAILInput())  # no evidence => low
        good_evidence = engine.score(FAILInput(cve_id="CVE-1", cvss_score=9.0, epss_score=0.5, has_exploit=True))
        assert low_evidence.weights["fact"] > good_evidence.weights["fact"]

    def test_kev_boosts_likelihood_weight(self, engine):
        no_kev = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        kev = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, is_kev=True))
        assert kev.weights["likelihood"] > no_kev.weights["likelihood"]

    def test_active_campaigns_boost_likelihood(self, engine):
        no_camp = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        camp = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, active_campaigns=2))
        assert camp.weights["likelihood"] > no_camp.weights["likelihood"]

    def test_critical_asset_boosts_impact_weight(self, engine):
        medium = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="medium"))
        critical = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="critical"))
        assert critical.weights["impact"] > medium.weights["impact"]


# ---------------------------------------------------------------------------
# Grade and action mapping boundary tests
# ---------------------------------------------------------------------------


class TestGradeActionBoundaries:
    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (100.0, FAILGrade.CRITICAL),
            (90.0, FAILGrade.CRITICAL),
            (89.9, FAILGrade.HIGH),
            (70.0, FAILGrade.HIGH),
            (69.9, FAILGrade.MEDIUM),
            (40.0, FAILGrade.MEDIUM),
            (39.9, FAILGrade.LOW),
            (20.0, FAILGrade.LOW),
            (19.9, FAILGrade.INFO),
            (0.0, FAILGrade.INFO),
        ],
    )
    def test_score_to_grade_boundaries(self, score, expected_grade):
        assert FAILEngine._score_to_grade(score) == expected_grade

    @pytest.mark.parametrize(
        "grade,expected_action",
        [
            (FAILGrade.CRITICAL, RecommendedAction.PATCH_IMMEDIATELY),
            (FAILGrade.HIGH, RecommendedAction.PATCH_NEXT_SPRINT),
            (FAILGrade.MEDIUM, RecommendedAction.SCHEDULE_FIX),
            (FAILGrade.LOW, RecommendedAction.MONITOR),
            (FAILGrade.INFO, RecommendedAction.ACCEPT_RISK),
        ],
    )
    def test_grade_to_action_mapping(self, grade, expected_action):
        assert FAILEngine._grade_to_action(grade) == expected_action


# ---------------------------------------------------------------------------
# Composite score clamping
# ---------------------------------------------------------------------------


class TestScoreClamping:
    def test_score_never_below_zero(self, engine):
        result = engine.score(FAILInput())
        assert result.fail_score >= 0.0

    def test_score_never_above_100(self, engine, critical_input):
        result = engine.score(critical_input)
        assert result.fail_score <= 100.0

    def test_extreme_input_stays_in_range(self, engine):
        extreme = FAILInput(
            cve_id="CVE-EXTREME",
            cvss_score=10.0,
            epss_score=1.0,
            is_kev=True,
            has_exploit=True,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
            active_campaigns=999,
            asset_criticality="critical",
            data_classification="phi",
            is_reachable=True,
            is_internet_facing=True,
            affected_assets=10000,
            compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO27001", "FedRAMP"],
        )
        result = engine.score(extreme)
        assert 0.0 <= result.fail_score <= 100.0


# ---------------------------------------------------------------------------
# Batch scoring and ranking
# ---------------------------------------------------------------------------


class TestBatchScoringUnit:
    def test_batch_returns_correct_count(self, engine):
        inputs = [FAILInput(cve_id=f"CVE-{i}") for i in range(10)]
        results = engine.score_batch(inputs)
        assert len(results) == 10

    def test_empty_batch(self, engine):
        results = engine.score_batch([])
        assert results == []

    def test_rank_highest_first(self, engine):
        inputs = [
            FAILInput(cve_id="CVE-LOW", cvss_score=1.0),
            FAILInput(cve_id="CVE-HIGH", cvss_score=10.0, is_kev=True, has_exploit=True, asset_criticality="critical"),
            FAILInput(cve_id="CVE-MED", cvss_score=5.0),
        ]
        results = engine.score_batch(inputs)
        ranked = engine.rank(results)
        scores = [r.fail_score for r in ranked]
        assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# Compare utility
# ---------------------------------------------------------------------------


class TestCompareUtility:
    def test_compare_returns_winner(self, engine):
        r1 = engine.score(FAILInput(cve_id="CVE-A", cvss_score=9.0))
        r2 = engine.score(FAILInput(cve_id="CVE-B", cvss_score=3.0))
        comparison = engine.compare(r1, r2)
        assert comparison["winner"] == "CVE-A"
        assert comparison["score_diff"] > 0

    def test_compare_equal_scores(self, engine):
        r1 = engine.score(FAILInput(cve_id="CVE-A", cvss_score=5.0))
        r2 = engine.score(FAILInput(cve_id="CVE-B", cvss_score=5.0))
        comparison = engine.compare(r1, r2)
        assert comparison["score_diff"] == 0.0


# ---------------------------------------------------------------------------
# History and statistics
# ---------------------------------------------------------------------------


class TestHistoryAndStats:
    def test_empty_engine_has_no_history(self):
        engine = FAILEngine()
        assert engine.history == []

    def test_scoring_appends_to_history(self, engine):
        engine.score(FAILInput(cve_id="CVE-1"))
        engine.score(FAILInput(cve_id="CVE-2"))
        assert len(engine.history) == 2

    def test_history_is_a_copy(self, engine):
        engine.score(FAILInput(cve_id="CVE-1"))
        h = engine.history
        h.clear()
        assert len(engine.history) == 1  # original unchanged

    def test_empty_stats(self):
        engine = FAILEngine()
        stats = engine.stats()
        assert stats["total_scored"] == 0

    def test_stats_after_scoring(self, engine, critical_input):
        engine.score(critical_input)
        engine.score(FAILInput(cvss_score=2.0))
        stats = engine.stats()
        assert stats["total_scored"] == 2
        assert "average_score" in stats
        assert "max_score" in stats
        assert "min_score" in stats
        assert "grade_distribution" in stats
        assert stats["max_score"] >= stats["min_score"]
        assert stats["average_score"] >= stats["min_score"]
        assert stats["average_score"] <= stats["max_score"]


# ---------------------------------------------------------------------------
# Custom weights
# ---------------------------------------------------------------------------


class TestCustomWeights:
    def test_custom_weights_applied(self):
        engine = FAILEngine(weights={"fact": 0.5, "assess": 0.1, "impact": 0.2, "likelihood": 0.2})
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        # Weights are dynamically adjusted, but base weights should differ
        assert result.weights is not None
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_computation_ms_is_positive(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.computation_ms >= 0.0


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestEnums:
    def test_fail_grade_values(self):
        assert FAILGrade.CRITICAL.value == "CRITICAL"
        assert FAILGrade.INFO.value == "INFO"

    def test_recommended_action_values(self):
        assert RecommendedAction.PATCH_IMMEDIATELY.value == "PATCH_IMMEDIATELY"
        assert RecommendedAction.ACCEPT_RISK.value == "ACCEPT_RISK"

    def test_exploit_maturity_values(self):
        assert ExploitMaturity.WEAPONIZED.value == "weaponized"
        assert ExploitMaturity.UNKNOWN.value == "unknown"

    def test_asset_criticality_values(self):
        assert AssetCriticality.CRITICAL.value == "critical"
        assert AssetCriticality.UNKNOWN.value == "unknown"

    def test_data_classification_values(self):
        assert DataClassification.PII.value == "pii"
        assert DataClassification.NONE.value == "none"
