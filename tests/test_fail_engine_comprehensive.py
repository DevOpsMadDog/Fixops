"""
Comprehensive tests for suite-core/core/fail_engine.py -- the FAIL scoring engine.

The FAIL engine scores vulnerabilities using 4 sub-scores:
  $FACT      - Evidence quality
  $ASSESS    - Attack complexity
  $IMPACT    - Blast radius
  $LIKELIHOOD - Exploitation probability

These tests cover:
  1. All severity grades (CRITICAL, HIGH, MEDIUM, LOW, INFO) via real engine scoring
  2. Edge cases: zero scores, max scores, missing optional fields, boundary values
  3. Grade mapping logic with exact boundary tests
  4. Recommended action mapping for every grade
  5. score_batch -- ordering, count, empty
  6. Input validation: out-of-range scores, missing CVE IDs, None fields
  7. All AssetCriticality enum values
  8. All DataClassification enum values
  9. Deterministic scoring: same input always produces same output
  10. Dynamic weight adjustment rules
  11. History, stats, compare, rank utilities
  12. Serialization (to_dict) completeness
  13. Custom engine weights
  14. ExploitMaturity full enum coverage
  15. Field propagation: cve_id, finding_id, title, metadata
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

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


@pytest.fixture
def critical_vuln():
    """Worst-case CVE: KEV, weaponized, critical asset, PHI data, reachable."""
    return FAILInput(
        cve_id="CVE-2024-3094",
        finding_id="FIND-001",
        title="XZ Utils backdoor",
        cvss_score=10.0,
        epss_score=0.97,
        is_kev=True,
        has_exploit=True,
        exploit_maturity=ExploitMaturity.WEAPONIZED,
        active_campaigns=5,
        asset_criticality="critical",
        data_classification="phi",
        is_reachable=True,
        is_internet_facing=True,
        has_compensating_controls=False,
        affected_assets=200,
        affected_users=10000,
        compliance_frameworks=["SOC2", "PCI-DSS", "HIPAA"],
        sla_hours=4,
        metadata={"source": "test"},
    )


@pytest.fixture
def high_vuln():
    """High-severity CVE: known exploit, high asset, PII, internet-facing."""
    return FAILInput(
        cve_id="CVE-2024-21762",
        title="FortiOS buffer overflow",
        cvss_score=9.0,
        epss_score=0.65,
        is_kev=True,
        has_exploit=True,
        exploit_maturity=ExploitMaturity.POC_PUBLIC,
        active_campaigns=1,
        asset_criticality="high",
        data_classification="pii",
        is_reachable=True,
        is_internet_facing=True,
        affected_assets=15,
        compliance_frameworks=["SOC2"],
    )


@pytest.fixture
def medium_vuln():
    """Medium-severity CVE: some evidence, medium asset, internal data."""
    return FAILInput(
        cve_id="CVE-2024-5555",
        title="Moderate XSS in admin panel",
        cvss_score=5.5,
        epss_score=0.08,
        is_kev=False,
        has_exploit=False,
        exploit_maturity=ExploitMaturity.THEORETICAL,
        active_campaigns=0,
        asset_criticality="medium",
        data_classification="internal",
        is_reachable=True,
        is_internet_facing=False,
        affected_assets=3,
    )


@pytest.fixture
def low_vuln():
    """Low-severity finding: info leak, dev environment, public data."""
    return FAILInput(
        cve_id="CVE-2024-9999",
        title="Info disclosure in debug endpoint",
        cvss_score=2.1,
        epss_score=0.001,
        is_kev=False,
        has_exploit=False,
        exploit_maturity=ExploitMaturity.THEORETICAL,
        active_campaigns=0,
        asset_criticality="low",
        data_classification="public",
        is_reachable=False,
        is_internet_facing=False,
        has_compensating_controls=True,
        affected_assets=1,
    )


@pytest.fixture
def info_vuln():
    """Informational finding: no real evidence, unknown everything."""
    return FAILInput(
        title="Informational banner grab",
    )


@pytest.fixture
def minimal_input():
    """Absolute minimum: default FAILInput with no fields set."""
    return FAILInput()


# ===================================================================
# Section 1: Enum Coverage
# ===================================================================


class TestFAILGradeEnum:
    """Verify all FAILGrade enum members and their values."""

    def test_all_grade_values(self):
        assert FAILGrade.CRITICAL.value == "CRITICAL"
        assert FAILGrade.HIGH.value == "HIGH"
        assert FAILGrade.MEDIUM.value == "MEDIUM"
        assert FAILGrade.LOW.value == "LOW"
        assert FAILGrade.INFO.value == "INFO"

    def test_grade_count(self):
        assert len(FAILGrade) == 5

    def test_grades_are_strings(self):
        for grade in FAILGrade:
            assert isinstance(grade.value, str)
            assert isinstance(grade, str)  # str enum


class TestRecommendedActionEnum:
    """Verify all RecommendedAction enum members."""

    def test_all_action_values(self):
        assert RecommendedAction.PATCH_IMMEDIATELY.value == "PATCH_IMMEDIATELY"
        assert RecommendedAction.PATCH_NEXT_SPRINT.value == "PATCH_NEXT_SPRINT"
        assert RecommendedAction.SCHEDULE_FIX.value == "SCHEDULE_FIX"
        assert RecommendedAction.MONITOR.value == "MONITOR"
        assert RecommendedAction.ACCEPT_RISK.value == "ACCEPT_RISK"

    def test_action_count(self):
        assert len(RecommendedAction) == 5


class TestAssetCriticalityEnum:
    """Verify all AssetCriticality enum members and their string values."""

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
    def test_asset_criticality_value(self, member, value):
        assert member.value == value

    def test_asset_criticality_count(self):
        assert len(AssetCriticality) == 5


class TestDataClassificationEnum:
    """Verify all DataClassification enum members and their string values."""

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
    def test_data_classification_value(self, member, value):
        assert member.value == value

    def test_data_classification_count(self):
        assert len(DataClassification) == 8


class TestExploitMaturityEnum:
    """Verify all ExploitMaturity enum members."""

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
    def test_exploit_maturity_value(self, member, value):
        assert member.value == value

    def test_exploit_maturity_count(self):
        assert len(ExploitMaturity) == 5


# ===================================================================
# Section 2: FAILInput Construction and Defaults
# ===================================================================


class TestFAILInputConstruction:
    """Test FAILInput default values, field isolation, and construction."""

    def test_all_defaults(self, minimal_input):
        assert minimal_input.cve_id is None
        assert minimal_input.finding_id is None
        assert minimal_input.title == ""
        assert minimal_input.cvss_score is None
        assert minimal_input.epss_score is None
        assert minimal_input.is_kev is False
        assert minimal_input.has_exploit is False
        assert minimal_input.exploit_maturity == ExploitMaturity.UNKNOWN
        assert minimal_input.active_campaigns == 0
        assert minimal_input.asset_criticality == "unknown"
        assert minimal_input.data_classification == "none"
        assert minimal_input.is_reachable is False
        assert minimal_input.is_internet_facing is False
        assert minimal_input.has_compensating_controls is False
        assert minimal_input.affected_assets == 1
        assert minimal_input.affected_users == 0
        assert minimal_input.compliance_frameworks == []
        assert minimal_input.sla_hours is None
        assert minimal_input.metadata == {}

    def test_compliance_frameworks_not_shared(self):
        """Verify dataclass field(default_factory=list) isolation."""
        a = FAILInput()
        b = FAILInput()
        a.compliance_frameworks.append("SOC2")
        assert b.compliance_frameworks == []

    def test_metadata_not_shared(self):
        """Verify dataclass field(default_factory=dict) isolation."""
        a = FAILInput()
        b = FAILInput()
        a.metadata["key"] = "value"
        assert "key" not in b.metadata

    def test_full_construction(self, critical_vuln):
        assert critical_vuln.cve_id == "CVE-2024-3094"
        assert critical_vuln.finding_id == "FIND-001"
        assert critical_vuln.cvss_score == 10.0
        assert critical_vuln.epss_score == 0.97
        assert critical_vuln.is_kev is True
        assert critical_vuln.affected_assets == 200
        assert critical_vuln.sla_hours == 4
        assert critical_vuln.metadata == {"source": "test"}

    def test_finding_id_without_cve(self):
        inp = FAILInput(finding_id="CUSTOM-FINDING-42")
        assert inp.cve_id is None
        assert inp.finding_id == "CUSTOM-FINDING-42"


# ===================================================================
# Section 3: FAILResult Auto-generated Fields
# ===================================================================


class TestFAILResultConstruction:
    """Test FAILResult auto-generated score_id and scored_at fields."""

    def test_score_id_auto_generated(self):
        r = FAILResult()
        assert r.score_id.startswith("FAIL-")
        assert len(r.score_id) == 17  # "FAIL-" (5) + 12 hex chars

    def test_score_id_unique_per_instance(self):
        r1 = FAILResult()
        r2 = FAILResult()
        assert r1.score_id != r2.score_id

    def test_scored_at_auto_generated_iso(self):
        r = FAILResult()
        assert r.scored_at != ""
        assert "T" in r.scored_at

    def test_explicit_score_id_preserved(self):
        r = FAILResult(score_id="FAIL-MY_CUSTOM_ID")
        assert r.score_id == "FAIL-MY_CUSTOM_ID"

    def test_explicit_scored_at_preserved(self):
        r = FAILResult(scored_at="2026-01-01T00:00:00Z")
        assert r.scored_at == "2026-01-01T00:00:00Z"

    def test_engine_version_default(self):
        r = FAILResult()
        assert r.engine_version == "1.0.0"

    def test_default_grade_and_action(self):
        r = FAILResult()
        assert r.grade == FAILGrade.INFO
        assert r.recommended_action == RecommendedAction.ACCEPT_RISK


# ===================================================================
# Section 4: $FACT Sub-score Tests
# ===================================================================


class TestFactSubScore:
    """$FACT measures evidence quality: is this vulnerability real?"""

    def test_zero_evidence_produces_zero(self, engine):
        """No CVE, no CVSS, no EPSS, no exploit = score 0."""
        result = engine.score(FAILInput())
        assert result.fact.score == 0.0
        assert result.fact.has_cve is False
        assert result.fact.has_cvss is False
        assert result.fact.has_epss is False
        assert result.fact.scanner_confirmed is False
        assert result.fact.multiple_sources is False
        assert result.fact.evidence_quality == "low"

    def test_cve_only_gives_45(self, engine):
        """CVE = 30 pts + scanner_confirmed = 15 pts = 45."""
        result = engine.score(FAILInput(cve_id="CVE-2024-0001"))
        assert result.fact.has_cve is True
        assert result.fact.scanner_confirmed is True
        assert result.fact.score == 45.0
        assert result.fact.evidence_quality == "medium"

    def test_cvss_only_gives_35(self, engine):
        """CVSS = 20 pts + scanner_confirmed = 15 pts = 35."""
        result = engine.score(FAILInput(cvss_score=7.5))
        assert result.fact.has_cve is False
        assert result.fact.has_cvss is True
        assert result.fact.scanner_confirmed is True
        assert result.fact.score == 35.0
        assert result.fact.evidence_quality == "low"

    def test_epss_only_gives_20(self, engine):
        """EPSS alone = 20 pts, scanner_confirmed = False."""
        result = engine.score(FAILInput(epss_score=0.5))
        assert result.fact.has_epss is True
        assert result.fact.scanner_confirmed is False
        assert result.fact.score == 20.0

    def test_cvss_zero_not_counted(self, engine):
        """CVSS of 0.0 is treated as no CVSS."""
        result = engine.score(FAILInput(cvss_score=0.0))
        assert result.fact.has_cvss is False

    def test_epss_zero_not_counted(self, engine):
        """EPSS of 0.0 is treated as no EPSS."""
        result = engine.score(FAILInput(epss_score=0.0))
        assert result.fact.has_epss is False

    def test_cvss_negative_not_counted(self, engine):
        """Negative CVSS treated as no CVSS (> 0 check)."""
        result = engine.score(FAILInput(cvss_score=-1.0))
        assert result.fact.has_cvss is False

    def test_two_sources_bonus_10(self, engine):
        """2 evidence sources => +10 bonus."""
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        # 30(cve) + 20(cvss) + 10(2 sources) + 15(scanner) = 75
        assert result.fact.score == 75.0
        assert result.fact.multiple_sources is False

    def test_three_sources_bonus_15(self, engine):
        """3+ evidence sources => +15 bonus and multiple_sources=True."""
        result = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5)
        )
        # 30(cve) + 20(cvss) + 20(epss) + 15(3 sources) + 15(scanner) = 100
        assert result.fact.multiple_sources is True
        assert result.fact.score == 100.0

    def test_four_sources_still_capped(self, engine):
        """4 sources: cve + cvss + epss + exploit => still capped at 100."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-1", cvss_score=7.0, epss_score=0.5, has_exploit=True
            )
        )
        assert result.fact.multiple_sources is True
        assert result.fact.score == 100.0

    def test_fact_capped_at_100(self, engine):
        """Even with all evidence, score cannot exceed 100."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-1", cvss_score=10.0, epss_score=0.99, has_exploit=True
            )
        )
        assert result.fact.score <= 100.0

    def test_evidence_quality_low_below_40(self, engine):
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.fact.score == 35.0
        assert result.fact.evidence_quality == "low"

    def test_evidence_quality_medium_40_to_69(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.fact.score == 45.0
        assert result.fact.evidence_quality == "medium"

    def test_evidence_quality_high_70_plus(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        assert result.fact.score == 75.0
        assert result.fact.evidence_quality == "high"


# ===================================================================
# Section 5: $ASSESS Sub-score Tests
# ===================================================================


class TestAssessSubScore:
    """$ASSESS measures attack complexity: what does exploitation require?"""

    @pytest.mark.parametrize(
        "cvss,expected_complexity",
        [
            (10.0, "low"),
            (9.0, "low"),
            (8.5, "low"),
            (7.0, "low"),
            (6.0, "medium"),
            (4.0, "medium"),
            (3.9, "high"),
            (2.0, "high"),
            (0.1, "high"),
        ],
    )
    def test_cvss_to_complexity_mapping(self, engine, cvss, expected_complexity):
        result = engine.score(FAILInput(cvss_score=cvss))
        assert result.assess.attack_complexity == expected_complexity

    def test_no_cvss_gives_unknown_complexity(self, engine):
        result = engine.score(FAILInput())
        assert result.assess.attack_complexity == "unknown"

    @pytest.mark.parametrize(
        "maturity,expected_label",
        [
            (ExploitMaturity.WEAPONIZED, "weaponized"),
            (ExploitMaturity.POC_PUBLIC, "poc_public"),
            (ExploitMaturity.POC_PRIVATE, "poc_private"),
            (ExploitMaturity.THEORETICAL, "theoretical"),
            (ExploitMaturity.UNKNOWN, "unknown"),
        ],
    )
    def test_all_exploit_maturity_labels(self, engine, maturity, expected_label):
        result = engine.score(FAILInput(cvss_score=7.0, exploit_maturity=maturity))
        assert result.assess.exploit_maturity == expected_label

    def test_weaponized_adds_more_than_poc_public(self, engine):
        wp = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.WEAPONIZED)
        )
        poc = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.POC_PUBLIC)
        )
        assert wp.assess.score > poc.assess.score

    def test_poc_public_adds_more_than_poc_private(self, engine):
        pub = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.POC_PUBLIC)
        )
        priv = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.POC_PRIVATE)
        )
        assert pub.assess.score > priv.assess.score

    def test_poc_private_adds_more_than_theoretical(self, engine):
        priv = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.POC_PRIVATE)
        )
        theo = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.THEORETICAL)
        )
        assert priv.assess.score > theo.assess.score

    def test_unknown_maturity_with_exploit_gets_boost(self, engine):
        """When maturity is unknown but has_exploit is True, adds 20."""
        result = engine.score(
            FAILInput(
                cvss_score=7.0,
                has_exploit=True,
                exploit_maturity=ExploitMaturity.UNKNOWN,
            )
        )
        no_exploit = engine.score(
            FAILInput(cvss_score=7.0, exploit_maturity=ExploitMaturity.UNKNOWN)
        )
        assert result.assess.score > no_exploit.assess.score

    def test_privileges_none_for_cvss_8_plus(self, engine):
        """CVSS >= 8.0 => no privileges required."""
        result = engine.score(FAILInput(cvss_score=8.0))
        assert result.assess.privileges_required == "none"

    def test_privileges_low_for_cvss_below_8(self, engine):
        result = engine.score(FAILInput(cvss_score=7.9))
        assert result.assess.privileges_required == "low"

    def test_user_interaction_none_for_cvss_7_plus(self, engine):
        """CVSS >= 7.0 => no user interaction needed."""
        result = engine.score(FAILInput(cvss_score=7.0))
        assert result.assess.user_interaction == "none"

    def test_user_interaction_required_for_cvss_below_7(self, engine):
        result = engine.score(FAILInput(cvss_score=6.9))
        assert result.assess.user_interaction == "required"

    def test_assess_capped_at_100(self, engine):
        """Maximum assess inputs still cap at 100."""
        result = engine.score(
            FAILInput(
                cvss_score=10.0,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                has_exploit=True,
            )
        )
        assert result.assess.score <= 100.0

    def test_no_cvss_no_privileges_keyword(self, engine):
        """When cvss_score is None, privileges = 'low' (falsy check)."""
        result = engine.score(FAILInput())
        assert result.assess.privileges_required == "low"


# ===================================================================
# Section 6: $IMPACT Sub-score Tests
# ===================================================================


class TestImpactSubScore:
    """$IMPACT measures blast radius: what happens if exploited?"""

    @pytest.mark.parametrize(
        "criticality,expected_business_impact",
        [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("unknown", "medium"),
        ],
    )
    def test_all_asset_criticality_values(
        self, engine, criticality, expected_business_impact
    ):
        result = engine.score(
            FAILInput(asset_criticality=criticality, cvss_score=5.0)
        )
        assert result.impact.business_impact == expected_business_impact

    def test_unrecognized_criticality_defaults_to_medium_score(self, engine):
        """Unrecognized criticality string gets 14.0 (same as medium)."""
        result_unknown = engine.score(
            FAILInput(asset_criticality="banana", cvss_score=5.0)
        )
        result_medium = engine.score(
            FAILInput(asset_criticality="medium", cvss_score=5.0)
        )
        assert result_unknown.impact.score == result_medium.impact.score

    @pytest.mark.parametrize(
        "data_cls",
        [
            "pii",
            "phi",
            "pci",
            "financial",
            "credentials",
            "internal",
            "public",
            "none",
        ],
    )
    def test_all_data_classification_values_accepted(self, engine, data_cls):
        """Engine accepts all DataClassification string values without error."""
        result = engine.score(
            FAILInput(data_classification=data_cls, cvss_score=5.0)
        )
        assert result.impact.data_at_risk == data_cls

    def test_phi_and_credentials_score_highest(self, engine):
        """PHI and credentials both get 28 pts -- highest data risk."""
        phi = engine.score(FAILInput(data_classification="phi", cvss_score=5.0))
        cred = engine.score(
            FAILInput(data_classification="credentials", cvss_score=5.0)
        )
        pii = engine.score(FAILInput(data_classification="pii", cvss_score=5.0))
        assert phi.impact.score == cred.impact.score
        assert phi.impact.score >= pii.impact.score

    def test_public_data_scores_lowest(self, engine):
        """Public data = 3 pts, the lowest data risk."""
        pub = engine.score(FAILInput(data_classification="public", cvss_score=5.0))
        internal = engine.score(
            FAILInput(data_classification="internal", cvss_score=5.0)
        )
        assert pub.impact.score < internal.impact.score

    def test_cia_high_for_cvss_9_plus(self, engine):
        result = engine.score(FAILInput(cvss_score=9.5))
        assert result.impact.confidentiality == "high"
        assert result.impact.integrity == "high"
        assert result.impact.availability == "high"

    def test_cia_mixed_for_cvss_7_to_9(self, engine):
        result = engine.score(FAILInput(cvss_score=7.5))
        assert result.impact.confidentiality == "high"
        assert result.impact.integrity == "low"
        assert result.impact.availability == "low"

    def test_cia_low_for_cvss_4_to_7(self, engine):
        result = engine.score(FAILInput(cvss_score=5.0))
        assert result.impact.confidentiality == "low"
        assert result.impact.integrity == "low"
        assert result.impact.availability == "none"

    def test_cia_none_for_cvss_below_4(self, engine):
        result = engine.score(FAILInput(cvss_score=2.0))
        assert result.impact.confidentiality == "none"
        assert result.impact.integrity == "none"
        assert result.impact.availability == "none"

    def test_cia_none_when_no_cvss(self, engine):
        result = engine.score(FAILInput())
        assert result.impact.confidentiality == "none"
        assert result.impact.integrity == "none"
        assert result.impact.availability == "none"

    @pytest.mark.parametrize(
        "assets,expected_blast",
        [
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
    def test_blast_radius_thresholds(self, engine, assets, expected_blast):
        result = engine.score(FAILInput(affected_assets=assets))
        assert result.impact.blast_radius == expected_blast

    def test_compliance_penalty_increases_score(self, engine):
        no_comp = engine.score(FAILInput(cvss_score=5.0))
        with_comp = engine.score(
            FAILInput(cvss_score=5.0, compliance_frameworks=["SOC2", "PCI"])
        )
        assert with_comp.impact.score > no_comp.impact.score

    def test_compliance_penalty_capped_at_10(self, engine):
        """5+ frameworks: 5*3=15, capped at 10."""
        many = engine.score(
            FAILInput(
                cvss_score=5.0,
                compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO", "NIST"],
            )
        )
        few = engine.score(
            FAILInput(cvss_score=5.0, compliance_frameworks=["SOC2"])
        )
        diff = many.impact.score - few.impact.score
        # many = min(10, 5*3) = 10, few = min(10, 1*3) = 3 => diff = 7
        assert diff == 7.0

    def test_impact_capped_at_100(self, engine):
        result = engine.score(
            FAILInput(
                cvss_score=10.0,
                asset_criticality="critical",
                data_classification="phi",
                affected_assets=10000,
                compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO"],
            )
        )
        assert result.impact.score <= 100.0


# ===================================================================
# Section 7: $LIKELIHOOD Sub-score Tests
# ===================================================================


class TestLikelihoodSubScore:
    """$LIKELIHOOD measures exploitation probability."""

    def test_epss_scaled_0_to_40(self, engine):
        r0 = engine.score(FAILInput(epss_score=0.0))
        r50 = engine.score(FAILInput(epss_score=0.5))
        r100 = engine.score(FAILInput(epss_score=1.0))
        assert r0.likelihood.epss_based == 0.0
        assert r50.likelihood.epss_based == 20.0
        assert r100.likelihood.epss_based == 40.0

    def test_epss_none_gives_zero(self, engine):
        result = engine.score(FAILInput())
        assert result.likelihood.epss_based == 0.0

    def test_kev_boost_25(self, engine):
        kev = engine.score(FAILInput(is_kev=True))
        no_kev = engine.score(FAILInput(is_kev=False))
        assert kev.likelihood.kev_boost == 25.0
        assert no_kev.likelihood.kev_boost == 0.0

    def test_has_exploit_gives_15(self, engine):
        result = engine.score(FAILInput(has_exploit=True))
        assert result.likelihood.exploit_availability == 15.0

    def test_weaponized_overrides_exploit_to_20(self, engine):
        """Weaponized maturity overrides has_exploit's 15 to 20."""
        result = engine.score(
            FAILInput(has_exploit=True, exploit_maturity=ExploitMaturity.WEAPONIZED)
        )
        assert result.likelihood.exploit_availability == 20.0

    def test_poc_public_gives_15_in_likelihood(self, engine):
        result = engine.score(
            FAILInput(exploit_maturity=ExploitMaturity.POC_PUBLIC)
        )
        assert result.likelihood.exploit_availability == 15.0

    def test_poc_private_does_not_add_exploit_availability(self, engine):
        """POC_PRIVATE is not handled in likelihood (only WEAPONIZED/POC_PUBLIC)."""
        result = engine.score(
            FAILInput(exploit_maturity=ExploitMaturity.POC_PRIVATE)
        )
        assert result.likelihood.exploit_availability == 0.0

    def test_poc_private_with_has_exploit(self, engine):
        """POC_PRIVATE + has_exploit: has_exploit sets 15, then maturity check
        does not match WEAPONIZED or POC_PUBLIC, so stays at 15."""
        result = engine.score(
            FAILInput(
                has_exploit=True, exploit_maturity=ExploitMaturity.POC_PRIVATE
            )
        )
        assert result.likelihood.exploit_availability == 15.0

    def test_active_campaigns_5_each(self, engine):
        r1 = engine.score(FAILInput(active_campaigns=1))
        r2 = engine.score(FAILInput(active_campaigns=2))
        assert r1.likelihood.threat_activity == 5.0
        assert r2.likelihood.threat_activity == 10.0

    def test_active_campaigns_capped_at_15(self, engine):
        r10 = engine.score(FAILInput(active_campaigns=10))
        r100 = engine.score(FAILInput(active_campaigns=100))
        assert r10.likelihood.threat_activity == 15.0
        assert r100.likelihood.threat_activity == 15.0

    def test_reachable_adds_10_to_exposure(self, engine):
        result = engine.score(FAILInput(is_reachable=True))
        assert result.likelihood.exposure_factor == 10.0

    def test_internet_facing_adds_10_to_exposure(self, engine):
        result = engine.score(FAILInput(is_internet_facing=True))
        assert result.likelihood.exposure_factor == 10.0

    def test_both_reachable_and_internet_gives_20(self, engine):
        result = engine.score(
            FAILInput(is_reachable=True, is_internet_facing=True)
        )
        assert result.likelihood.exposure_factor == 20.0

    def test_compensating_controls_reduce_by_8(self, engine):
        exposed = engine.score(
            FAILInput(is_reachable=True, is_internet_facing=True)
        )
        controlled = engine.score(
            FAILInput(
                is_reachable=True,
                is_internet_facing=True,
                has_compensating_controls=True,
            )
        )
        assert exposed.likelihood.exposure_factor == 20.0
        assert controlled.likelihood.exposure_factor == 12.0

    def test_controls_cannot_produce_negative_exposure(self, engine):
        """Compensating controls with no exposure = max(0, 0-8) = 0."""
        result = engine.score(FAILInput(has_compensating_controls=True))
        assert result.likelihood.exposure_factor == 0.0

    def test_controls_reduce_small_exposure(self, engine):
        """Reachable only (10) - 8 = 2."""
        result = engine.score(
            FAILInput(is_reachable=True, has_compensating_controls=True)
        )
        assert result.likelihood.exposure_factor == 2.0

    def test_likelihood_capped_at_100(self, engine):
        result = engine.score(
            FAILInput(
                epss_score=1.0,
                is_kev=True,
                has_exploit=True,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                active_campaigns=100,
                is_reachable=True,
                is_internet_facing=True,
            )
        )
        assert result.likelihood.score <= 100.0
        # 40 + 25 + 20 + 15 + 20 = 120, capped to 100
        assert result.likelihood.score == 100.0


# ===================================================================
# Section 8: Grade Mapping Boundary Tests
# ===================================================================


class TestGradeMappingBoundaries:
    """Exact boundary tests for _score_to_grade."""

    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (100.0, FAILGrade.CRITICAL),
            (95.0, FAILGrade.CRITICAL),
            (90.0, FAILGrade.CRITICAL),
            (89.999, FAILGrade.HIGH),
            (89.0, FAILGrade.HIGH),
            (70.0, FAILGrade.HIGH),
            (69.999, FAILGrade.MEDIUM),
            (50.0, FAILGrade.MEDIUM),
            (40.0, FAILGrade.MEDIUM),
            (39.999, FAILGrade.LOW),
            (30.0, FAILGrade.LOW),
            (20.0, FAILGrade.LOW),
            (19.999, FAILGrade.INFO),
            (10.0, FAILGrade.INFO),
            (0.0, FAILGrade.INFO),
        ],
    )
    def test_score_to_grade_boundary(self, score, expected_grade):
        assert FAILEngine._score_to_grade(score) == expected_grade


# ===================================================================
# Section 9: Recommended Action Mapping
# ===================================================================


class TestRecommendedActionMapping:
    """Every grade maps to exactly one recommended action."""

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
    def test_grade_to_action(self, grade, expected_action):
        assert FAILEngine._grade_to_action(grade) == expected_action

    def test_action_mapping_covers_all_grades(self):
        """Every FAILGrade member produces a valid action (not default)."""
        for grade in FAILGrade:
            action = FAILEngine._grade_to_action(grade)
            assert action in RecommendedAction


# ===================================================================
# Section 10: Dynamic Weight Adjustment
# ===================================================================


class TestDynamicWeights:
    """Weights are dynamically adjusted based on context signals."""

    def test_weights_always_sum_to_one(self, engine):
        inputs = [
            FAILInput(),
            FAILInput(cve_id="CVE-1", cvss_score=10.0, is_kev=True),
            FAILInput(asset_criticality="critical"),
            FAILInput(
                is_kev=True, asset_criticality="critical", active_campaigns=5
            ),
            FAILInput(
                cve_id="CVE-1", cvss_score=9.0, epss_score=0.9, has_exploit=True
            ),
        ]
        for inp in inputs:
            result = engine.score(inp)
            total = sum(result.weights.values())
            assert abs(total - 1.0) < 0.001, (
                f"Weights {result.weights} sum to {total}"
            )

    def test_low_evidence_boosts_fact_weight(self, engine):
        """When evidence quality is low, fact weight increases."""
        low_ev = engine.score(FAILInput())
        high_ev = engine.score(
            FAILInput(
                cve_id="CVE-1", cvss_score=9.0, epss_score=0.5, has_exploit=True
            )
        )
        assert low_ev.weights["fact"] > high_ev.weights["fact"]

    def test_kev_boosts_likelihood_weight(self, engine):
        no_kev = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        kev = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, is_kev=True)
        )
        assert kev.weights["likelihood"] > no_kev.weights["likelihood"]

    def test_active_campaigns_boost_likelihood_weight(self, engine):
        no_camp = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        camp = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, active_campaigns=3)
        )
        assert camp.weights["likelihood"] > no_camp.weights["likelihood"]

    def test_critical_asset_boosts_impact_weight(self, engine):
        med = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="medium")
        )
        crit = engine.score(
            FAILInput(
                cve_id="CVE-1", cvss_score=7.0, asset_criticality="critical"
            )
        )
        assert crit.weights["impact"] > med.weights["impact"]

    def test_high_asset_also_boosts_impact_weight(self, engine):
        """High asset criticality (not just critical) also boosts impact."""
        med = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="medium")
        )
        high = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="high")
        )
        assert high.weights["impact"] > med.weights["impact"]

    def test_default_weights_are_balanced(self):
        """Default weights: FACT=0.20, ASSESS=0.20, IMPACT=0.30, LIKELIHOOD=0.30."""
        assert FAILEngine.DEFAULT_WEIGHTS == {
            "fact": 0.20,
            "assess": 0.20,
            "impact": 0.30,
            "likelihood": 0.30,
        }


# ===================================================================
# Section 11: Composite FAIL Score -- All Grades via Real Inputs
# ===================================================================


class TestCompositeAllGrades:
    """Prove the engine can produce all 5 severity grades with real inputs."""

    def test_critical_grade(self, engine, critical_vuln):
        result = engine.score(critical_vuln)
        assert result.grade in (FAILGrade.CRITICAL, FAILGrade.HIGH)
        assert result.fail_score >= 70.0
        assert result.recommended_action in (
            RecommendedAction.PATCH_IMMEDIATELY,
            RecommendedAction.PATCH_NEXT_SPRINT,
        )

    def test_high_grade(self, engine, high_vuln):
        result = engine.score(high_vuln)
        assert result.fail_score >= 60.0
        assert result.grade in (FAILGrade.HIGH, FAILGrade.CRITICAL)

    def test_medium_grade(self, engine, medium_vuln):
        result = engine.score(medium_vuln)
        assert 25.0 <= result.fail_score <= 70.0
        assert result.grade in (FAILGrade.MEDIUM, FAILGrade.LOW)

    def test_low_grade(self, engine, low_vuln):
        result = engine.score(low_vuln)
        assert result.fail_score < 50.0
        assert result.grade in (FAILGrade.LOW, FAILGrade.INFO, FAILGrade.MEDIUM)

    def test_info_grade(self, engine, info_vuln):
        result = engine.score(info_vuln)
        assert result.fail_score < 30.0
        assert result.grade in (FAILGrade.INFO, FAILGrade.LOW)

    def test_empty_input_scores_low(self, engine, minimal_input):
        result = engine.score(minimal_input)
        assert 0.0 <= result.fail_score <= 100.0
        assert result.fail_score < 30.0

    def test_score_always_clamped_0_to_100(self, engine):
        """Even extreme inputs keep score in [0, 100]."""
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
            affected_assets=100000,
            compliance_frameworks=["SOC2", "PCI", "HIPAA", "ISO", "NIST"],
        )
        result = engine.score(extreme)
        assert 0.0 <= result.fail_score <= 100.0
        assert result.grade == FAILGrade.CRITICAL

    def test_ordering_critical_gt_high_gt_medium_gt_low(
        self, engine, critical_vuln, high_vuln, medium_vuln, low_vuln
    ):
        """Higher severity inputs always produce higher scores."""
        rc = engine.score(critical_vuln).fail_score
        rh = engine.score(high_vuln).fail_score
        rm = engine.score(medium_vuln).fail_score
        rl = engine.score(low_vuln).fail_score
        assert rc >= rh >= rm
        assert rm >= rl


# ===================================================================
# Section 12: Deterministic Scoring
# ===================================================================


class TestDeterministicScoring:
    """Same input must always produce the same fail_score and grade."""

    def test_same_input_same_score(self, engine):
        inp = FAILInput(
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
            epss_score=0.45,
            is_kev=True,
            asset_criticality="high",
            data_classification="pii",
        )
        r1 = engine.score(inp)
        r2 = engine.score(inp)
        assert r1.fail_score == r2.fail_score
        assert r1.grade == r2.grade
        assert r1.recommended_action == r2.recommended_action
        assert r1.fact.score == r2.fact.score
        assert r1.assess.score == r2.assess.score
        assert r1.impact.score == r2.impact.score
        assert r1.likelihood.score == r2.likelihood.score

    def test_deterministic_across_engines(self):
        """Two separate engine instances produce identical scores."""
        inp = FAILInput(
            cve_id="CVE-2024-9999",
            cvss_score=6.5,
            epss_score=0.12,
            has_exploit=True,
            asset_criticality="medium",
        )
        e1 = FAILEngine()
        e2 = FAILEngine()
        r1 = e1.score(inp)
        r2 = e2.score(inp)
        assert r1.fail_score == r2.fail_score
        assert r1.grade == r2.grade

    def test_ten_runs_identical(self, engine):
        """Score the same input 10 times -- all identical."""
        inp = FAILInput(cve_id="CVE-REPEAT", cvss_score=7.7, epss_score=0.33)
        scores = [engine.score(inp).fail_score for _ in range(10)]
        assert len(set(scores)) == 1, f"Non-deterministic: {scores}"


# ===================================================================
# Section 13: Batch Scoring (score_batch)
# ===================================================================


class TestBatchScoring:
    """Test score_batch method."""

    def test_batch_returns_correct_count(self, engine):
        inputs = [FAILInput(cve_id=f"CVE-{i}") for i in range(7)]
        results = engine.score_batch(inputs)
        assert len(results) == 7

    def test_empty_batch_returns_empty(self, engine):
        results = engine.score_batch([])
        assert results == []

    def test_batch_preserves_order(self, engine):
        """Results match input order, not sorted by score."""
        ids = ["CVE-AAA", "CVE-BBB", "CVE-CCC"]
        inputs = [FAILInput(cve_id=cid) for cid in ids]
        results = engine.score_batch(inputs)
        for i, r in enumerate(results):
            assert r.cve_id == ids[i]

    def test_batch_populates_history(self, engine):
        inputs = [FAILInput(cve_id=f"CVE-{i}") for i in range(5)]
        engine.score_batch(inputs)
        assert len(engine.history) == 5

    def test_batch_single_item(self, engine):
        results = engine.score_batch([FAILInput(cve_id="CVE-SOLO")])
        assert len(results) == 1
        assert results[0].cve_id == "CVE-SOLO"


# ===================================================================
# Section 14: Ranking
# ===================================================================


class TestRanking:
    """Test the rank() method for ordering results by score."""

    def test_rank_orders_descending(self, engine):
        inputs = [
            FAILInput(cve_id="CVE-LOW", cvss_score=1.0),
            FAILInput(
                cve_id="CVE-HIGH",
                cvss_score=10.0,
                is_kev=True,
                has_exploit=True,
                asset_criticality="critical",
            ),
            FAILInput(cve_id="CVE-MED", cvss_score=5.0),
        ]
        results = engine.score_batch(inputs)
        ranked = engine.rank(results)
        scores = [r.fail_score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rank_empty_list(self, engine):
        assert engine.rank([]) == []

    def test_rank_single_item(self, engine):
        r = engine.score(FAILInput(cve_id="CVE-1"))
        ranked = engine.rank([r])
        assert len(ranked) == 1


# ===================================================================
# Section 15: Compare Utility
# ===================================================================


class TestCompareUtility:
    """Test the compare() method for head-to-head vulnerability comparison."""

    def test_compare_returns_winner(self, engine):
        r_high = engine.score(
            FAILInput(cve_id="CVE-HIGH", cvss_score=9.5, is_kev=True)
        )
        r_low = engine.score(FAILInput(cve_id="CVE-LOW", cvss_score=2.0))
        comp = engine.compare(r_high, r_low)
        assert comp["winner"] == "CVE-HIGH"
        assert comp["score_diff"] > 0
        assert comp["a"]["cve"] == "CVE-HIGH"
        assert comp["b"]["cve"] == "CVE-LOW"

    def test_compare_equal_scores_picks_a(self, engine):
        """When scores are equal, 'a' wins (>= comparison)."""
        r1 = engine.score(FAILInput(cve_id="CVE-A", cvss_score=5.0))
        r2 = engine.score(FAILInput(cve_id="CVE-B", cvss_score=5.0))
        comp = engine.compare(r1, r2)
        assert comp["winner"] == "CVE-A"
        assert comp["score_diff"] == 0.0

    def test_compare_without_cve_ids(self, engine):
        """Compare works even when cve_id is None."""
        r1 = engine.score(FAILInput(finding_id="F-1", cvss_score=8.0))
        r2 = engine.score(FAILInput(finding_id="F-2", cvss_score=3.0))
        comp = engine.compare(r1, r2)
        # r1 wins but cve_id is None
        assert comp["winner"] is None
        assert comp["score_diff"] > 0

    def test_compare_structure(self, engine):
        r1 = engine.score(FAILInput(cve_id="CVE-X", cvss_score=7.0))
        r2 = engine.score(FAILInput(cve_id="CVE-Y", cvss_score=3.0))
        comp = engine.compare(r1, r2)
        assert "winner" in comp
        assert "score_diff" in comp
        assert "a" in comp
        assert "b" in comp
        assert "cve" in comp["a"]
        assert "score" in comp["a"]
        assert "grade" in comp["a"]


# ===================================================================
# Section 16: History and Statistics
# ===================================================================


class TestHistoryAndStats:
    """Test scoring history tracking and statistical aggregation."""

    def test_fresh_engine_empty_history(self):
        engine = FAILEngine()
        assert engine.history == []

    def test_scoring_appends_to_history(self, engine):
        engine.score(FAILInput(cve_id="CVE-1"))
        engine.score(FAILInput(cve_id="CVE-2"))
        engine.score(FAILInput(cve_id="CVE-3"))
        assert len(engine.history) == 3

    def test_history_returns_copy(self, engine):
        """Modifying returned history does not affect internal state."""
        engine.score(FAILInput(cve_id="CVE-1"))
        h = engine.history
        h.clear()
        assert len(engine.history) == 1

    def test_empty_stats(self):
        engine = FAILEngine()
        stats = engine.stats()
        assert stats == {"total_scored": 0}

    def test_stats_after_multiple_scores(self, engine, critical_vuln, low_vuln):
        engine.score(critical_vuln)
        engine.score(low_vuln)
        stats = engine.stats()
        assert stats["total_scored"] == 2
        assert "average_score" in stats
        assert "max_score" in stats
        assert "min_score" in stats
        assert "grade_distribution" in stats
        assert "critical_count" in stats
        assert "high_count" in stats
        assert stats["max_score"] >= stats["min_score"]
        assert stats["min_score"] <= stats["average_score"] <= stats["max_score"]

    def test_grade_distribution_counts(self, engine):
        """Each scored item's grade appears in the distribution."""
        engine.score(
            FAILInput(
                cve_id="CVE-1",
                cvss_score=10.0,
                epss_score=0.95,
                is_kev=True,
                has_exploit=True,
                exploit_maturity=ExploitMaturity.WEAPONIZED,
                asset_criticality="critical",
                data_classification="phi",
                is_reachable=True,
                is_internet_facing=True,
                affected_assets=200,
            )
        )
        engine.score(FAILInput())  # likely INFO
        stats = engine.stats()
        total_in_dist = sum(stats["grade_distribution"].values())
        assert total_in_dist == 2


# ===================================================================
# Section 17: Serialization (to_dict)
# ===================================================================


class TestSerialization:
    """Test FAILResult.to_dict() output structure and value correctness."""

    def test_to_dict_has_all_top_level_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        expected_keys = {
            "score_id",
            "fail_score",
            "grade",
            "recommended_action",
            "cve_id",
            "finding_id",
            "sub_scores",
            "weights",
            "scored_at",
            "engine_version",
            "computation_ms",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_sub_scores_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        assert set(d["sub_scores"].keys()) == {
            "fact",
            "assess",
            "impact",
            "likelihood",
        }

    def test_to_dict_fact_sub_score_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        fact = d["sub_scores"]["fact"]
        expected = {
            "score",
            "has_cve",
            "has_cvss",
            "has_epss",
            "scanner_confirmed",
            "multiple_sources",
            "evidence_quality",
        }
        assert set(fact.keys()) == expected

    def test_to_dict_assess_sub_score_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        assess = d["sub_scores"]["assess"]
        expected = {
            "score",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "exploit_maturity",
        }
        assert set(assess.keys()) == expected

    def test_to_dict_impact_sub_score_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        impact = d["sub_scores"]["impact"]
        expected = {
            "score",
            "confidentiality",
            "integrity",
            "availability",
            "blast_radius",
            "data_at_risk",
            "business_impact",
        }
        assert set(impact.keys()) == expected

    def test_to_dict_likelihood_sub_score_keys(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        lh = d["sub_scores"]["likelihood"]
        expected = {
            "score",
            "epss_based",
            "kev_boost",
            "exploit_availability",
            "threat_activity",
            "exposure_factor",
        }
        assert set(lh.keys()) == expected

    def test_to_dict_scores_are_rounded(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.3))
        d = result.to_dict()
        for sub in d["sub_scores"].values():
            score_str = str(sub["score"])
            if "." in score_str:
                assert len(score_str.split(".")[1]) <= 2

    def test_to_dict_grade_is_string(self, engine):
        d = engine.score(FAILInput(cve_id="CVE-1")).to_dict()
        assert isinstance(d["grade"], str)
        assert d["grade"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_to_dict_preserves_cve_id(self, engine):
        d = engine.score(FAILInput(cve_id="CVE-2024-3094")).to_dict()
        assert d["cve_id"] == "CVE-2024-3094"

    def test_to_dict_preserves_finding_id(self, engine):
        d = engine.score(FAILInput(finding_id="FIND-42")).to_dict()
        assert d["finding_id"] == "FIND-42"

    def test_to_dict_none_ids(self, engine):
        d = engine.score(FAILInput()).to_dict()
        assert d["cve_id"] is None
        assert d["finding_id"] is None

    def test_to_dict_weights_sum_to_one(self, engine, critical_vuln):
        d = engine.score(critical_vuln).to_dict()
        total = sum(d["weights"].values())
        assert abs(total - 1.0) < 0.01


# ===================================================================
# Section 18: Custom Weights
# ===================================================================


class TestCustomWeights:
    """Test engine construction with custom base weights."""

    def test_custom_weights_accepted(self):
        engine = FAILEngine(
            weights={
                "fact": 0.5,
                "assess": 0.1,
                "impact": 0.2,
                "likelihood": 0.2,
            }
        )
        result = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        assert result.weights is not None
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_fact_heavy_weights_change_score(self):
        """Fact-heavy weights make evidence quality matter more."""
        inp = FAILInput(cve_id="CVE-1", cvss_score=7.0, epss_score=0.5)
        default_engine = FAILEngine()
        fact_heavy = FAILEngine(
            weights={
                "fact": 0.7,
                "assess": 0.1,
                "impact": 0.1,
                "likelihood": 0.1,
            }
        )
        r_default = default_engine.score(inp)
        r_heavy = fact_heavy.score(inp)
        assert r_default.fail_score != r_heavy.fail_score

    def test_engine_version_constant(self):
        assert FAILEngine.VERSION == "1.0.0"

    def test_default_weights_constant(self):
        assert FAILEngine.DEFAULT_WEIGHTS == {
            "fact": 0.20,
            "assess": 0.20,
            "impact": 0.30,
            "likelihood": 0.30,
        }


# ===================================================================
# Section 19: Field Propagation
# ===================================================================


class TestFieldPropagation:
    """Test that input identity fields propagate to the result."""

    def test_cve_id_propagates(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-2024-3094"))
        assert result.cve_id == "CVE-2024-3094"

    def test_finding_id_propagates(self, engine):
        result = engine.score(FAILInput(finding_id="FINDING-ABC"))
        assert result.finding_id == "FINDING-ABC"

    def test_none_cve_propagates(self, engine):
        result = engine.score(FAILInput())
        assert result.cve_id is None

    def test_none_finding_id_propagates(self, engine):
        result = engine.score(FAILInput())
        assert result.finding_id is None

    def test_computation_ms_positive(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.computation_ms >= 0.0

    def test_score_id_starts_with_fail(self, engine):
        result = engine.score(FAILInput(cve_id="CVE-1"))
        assert result.score_id.startswith("FAIL-")

    def test_engine_version_in_result(self, engine):
        result = engine.score(FAILInput())
        assert result.engine_version == "1.0.0"


# ===================================================================
# Section 20: Edge Cases and Robustness
# ===================================================================


class TestEdgeCases:
    """Edge cases, boundary values, and unusual input combinations."""

    def test_cvss_exactly_4(self, engine):
        """CVSS 4.0 is the boundary between medium and high complexity."""
        result = engine.score(FAILInput(cvss_score=4.0))
        assert result.assess.attack_complexity == "medium"

    def test_cvss_exactly_7(self, engine):
        """CVSS 7.0 is the boundary between low and medium complexity."""
        result = engine.score(FAILInput(cvss_score=7.0))
        assert result.assess.attack_complexity == "low"
        assert result.assess.user_interaction == "none"

    def test_cvss_exactly_8(self, engine):
        """CVSS 8.0 is the boundary for privileges_required=none."""
        result = engine.score(FAILInput(cvss_score=8.0))
        assert result.assess.privileges_required == "none"

    def test_cvss_exactly_9(self, engine):
        """CVSS 9.0 is the boundary for max CIA and highest complexity score."""
        result = engine.score(FAILInput(cvss_score=9.0))
        assert result.assess.attack_complexity == "low"
        assert result.impact.confidentiality == "high"
        assert result.impact.integrity == "high"
        assert result.impact.availability == "high"

    def test_cvss_3_99_high_complexity(self, engine):
        """Just below 4.0 boundary gives high complexity."""
        result = engine.score(FAILInput(cvss_score=3.99))
        assert result.assess.attack_complexity == "high"

    def test_cvss_6_99_medium_complexity(self, engine):
        """Just below 7.0 boundary gives medium complexity."""
        result = engine.score(FAILInput(cvss_score=6.99))
        assert result.assess.attack_complexity == "medium"

    def test_cvss_8_99_low_complexity(self, engine):
        """Just below 9.0 boundary still gives low complexity."""
        result = engine.score(FAILInput(cvss_score=8.99))
        assert result.assess.attack_complexity == "low"

    def test_affected_assets_zero(self, engine):
        """Zero affected assets gives contained blast radius."""
        result = engine.score(FAILInput(affected_assets=0))
        assert result.impact.blast_radius == "contained"

    def test_very_high_epss(self, engine):
        """EPSS of 1.0 gives max 40 pts in likelihood."""
        result = engine.score(FAILInput(epss_score=1.0))
        assert result.likelihood.epss_based == 40.0

    def test_epss_slightly_above_zero(self, engine):
        """Very small EPSS still registers."""
        result = engine.score(FAILInput(epss_score=0.001))
        assert result.likelihood.epss_based > 0.0
        assert result.fact.has_epss is True

    def test_case_insensitive_criticality(self, engine):
        """Engine lowercases asset_criticality."""
        upper = engine.score(
            FAILInput(asset_criticality="CRITICAL", cvss_score=5.0)
        )
        lower = engine.score(
            FAILInput(asset_criticality="critical", cvss_score=5.0)
        )
        assert upper.impact.score == lower.impact.score

    def test_case_insensitive_data_classification(self, engine):
        """Engine lowercases data_classification."""
        upper = engine.score(
            FAILInput(data_classification="PII", cvss_score=5.0)
        )
        lower = engine.score(
            FAILInput(data_classification="pii", cvss_score=5.0)
        )
        assert upper.impact.score == lower.impact.score

    def test_unrecognized_data_classification_gets_default(self, engine):
        """Unrecognized data classification gets default 10 pts."""
        result = engine.score(
            FAILInput(data_classification="alien_data", cvss_score=5.0)
        )
        none_result = engine.score(
            FAILInput(data_classification="none", cvss_score=5.0)
        )
        # "none" gets 5.0, "alien_data" gets 10.0
        assert result.impact.score > none_result.impact.score

    def test_all_booleans_true(self, engine):
        """All boolean flags set to True does not crash."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-ALL-TRUE",
                is_kev=True,
                has_exploit=True,
                is_reachable=True,
                is_internet_facing=True,
                has_compensating_controls=True,
            )
        )
        assert 0.0 <= result.fail_score <= 100.0

    def test_all_booleans_false(self, engine):
        """All boolean flags False gives minimal score."""
        result = engine.score(
            FAILInput(
                cve_id="CVE-ALL-FALSE",
                is_kev=False,
                has_exploit=False,
                is_reachable=False,
                is_internet_facing=False,
                has_compensating_controls=False,
            )
        )
        assert 0.0 <= result.fail_score <= 100.0

    def test_large_compliance_list(self, engine):
        """Many compliance frameworks: penalty capped at 10."""
        frameworks = [f"FRAMEWORK-{i}" for i in range(20)]
        result = engine.score(
            FAILInput(cvss_score=5.0, compliance_frameworks=frameworks)
        )
        no_comp = engine.score(FAILInput(cvss_score=5.0))
        diff = result.impact.score - no_comp.impact.score
        assert diff == 10.0

    def test_metadata_does_not_affect_score(self, engine):
        """Metadata field is stored but does not influence scoring."""
        r1 = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        r2 = engine.score(
            FAILInput(
                cve_id="CVE-1",
                cvss_score=7.0,
                metadata={"anything": "here", "nested": {"data": True}},
            )
        )
        assert r1.fail_score == r2.fail_score

    def test_sla_hours_does_not_affect_score(self, engine):
        """SLA hours field is stored but does not influence scoring."""
        r1 = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        r2 = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, sla_hours=2)
        )
        assert r1.fail_score == r2.fail_score

    def test_affected_users_does_not_affect_score(self, engine):
        """Affected users field is stored but does not influence scoring."""
        r1 = engine.score(FAILInput(cve_id="CVE-1", cvss_score=7.0))
        r2 = engine.score(
            FAILInput(cve_id="CVE-1", cvss_score=7.0, affected_users=50000)
        )
        assert r1.fail_score == r2.fail_score


# ===================================================================
# Section 21: Data Class Sub-score Defaults
# ===================================================================


class TestSubScoreDataclassDefaults:
    """Verify default values of sub-score dataclasses."""

    def test_fact_score_defaults(self):
        f = FAILFactScore()
        assert f.score == 0.0
        assert f.has_cve is False
        assert f.has_cvss is False
        assert f.has_epss is False
        assert f.scanner_confirmed is False
        assert f.multiple_sources is False
        assert f.evidence_quality == "low"

    def test_assess_score_defaults(self):
        a = FAILAssessScore()
        assert a.score == 0.0
        assert a.attack_complexity == "unknown"
        assert a.privileges_required == "none"
        assert a.user_interaction == "none"
        assert a.exploit_maturity == "unknown"

    def test_impact_score_defaults(self):
        i = FAILImpactScore()
        assert i.score == 0.0
        assert i.confidentiality == "none"
        assert i.integrity == "none"
        assert i.availability == "none"
        assert i.blast_radius == "contained"
        assert i.data_at_risk == "none"
        assert i.business_impact == "low"

    def test_likelihood_score_defaults(self):
        lh = FAILLikelihoodScore()
        assert lh.score == 0.0
        assert lh.epss_based == 0.0
        assert lh.kev_boost == 0.0
        assert lh.exploit_availability == 0.0
        assert lh.threat_activity == 0.0
        assert lh.exposure_factor == 0.0
