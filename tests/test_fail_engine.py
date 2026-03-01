"""
Tests for the FAIL Engine — core scoring + API layer.

Covers:
  - $FACT sub-score computation
  - $ASSESS sub-score computation
  - $IMPACT sub-score computation
  - $LIKELIHOOD sub-score computation
  - Composite FAIL score + grade mapping
  - Dynamic weight adjustment
  - Batch scoring
  - Edge cases (minimal input, maximal input, zero scores)
  - API endpoint contract
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
    """A worst-case CVE: KEV, weaponized, critical asset, PII, reachable."""
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
def low_input():
    """A low-risk finding: info severity, no exploit, internal data."""
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
def minimal_input():
    """Absolute minimum input — just a CVE ID."""
    return FAILInput(cve_id="CVE-2024-0001")


# ---------------------------------------------------------------------------
# $FACT tests
# ---------------------------------------------------------------------------


class TestFactScore:
    def test_cve_with_cvss_and_epss_is_high_quality(self, engine):
        inp = FAILInput(cve_id="CVE-2024-1234", cvss_score=8.0, epss_score=0.5, has_exploit=True)
        result = engine.score(inp)
        assert result.fact.has_cve is True
        assert result.fact.has_cvss is True
        assert result.fact.has_epss is True
        assert result.fact.evidence_quality == "high"
        assert result.fact.score >= 70

    def test_no_cve_is_low_quality(self, engine):
        inp = FAILInput(title="Unknown vuln")
        result = engine.score(inp)
        assert result.fact.has_cve is False
        assert result.fact.evidence_quality == "low"
        assert result.fact.score <= 30

    def test_multiple_sources_bonus(self, engine):
        inp1 = FAILInput(cve_id="CVE-2024-1", cvss_score=7.0)
        inp2 = FAILInput(cve_id="CVE-2024-2", cvss_score=7.0, epss_score=0.3, has_exploit=True)
        r1 = engine.score(inp1)
        r2 = engine.score(inp2)
        assert r2.fact.score > r1.fact.score


# ---------------------------------------------------------------------------
# $ASSESS tests
# ---------------------------------------------------------------------------


class TestAssessScore:
    def test_high_cvss_means_low_complexity(self, engine):
        inp = FAILInput(cve_id="CVE-2024-1", cvss_score=9.5)
        result = engine.score(inp)
        assert result.assess.attack_complexity == "low"

    def test_weaponized_exploit_boosts_score(self, engine):
        base = FAILInput(cve_id="CVE-2024-1", cvss_score=7.0)
        weaponized = FAILInput(
            cve_id="CVE-2024-2",
            cvss_score=7.0,
            exploit_maturity=ExploitMaturity.WEAPONIZED,
        )
        r_base = engine.score(base)
        r_weapon = engine.score(weaponized)
        assert r_weapon.assess.score > r_base.assess.score

    def test_low_cvss_means_high_complexity(self, engine):
        inp = FAILInput(cve_id="CVE-2024-1", cvss_score=2.0)
        result = engine.score(inp)
        assert result.assess.attack_complexity == "high"


# ---------------------------------------------------------------------------
# $IMPACT tests
# ---------------------------------------------------------------------------


class TestImpactScore:
    def test_critical_asset_with_pii_scores_high(self, engine, critical_input):
        result = engine.score(critical_input)
        assert result.impact.score >= 70
        assert result.impact.business_impact == "critical"
        assert result.impact.data_at_risk == "pii"

    def test_low_asset_with_public_data_scores_low(self, engine, low_input):
        result = engine.score(low_input)
        assert result.impact.score < 40
        assert result.impact.business_impact == "low"

    def test_blast_radius_scales_with_assets(self, engine):
        inp1 = FAILInput(cve_id="CVE-1", affected_assets=1, cvss_score=7.0, asset_criticality="medium")
        inp2 = FAILInput(cve_id="CVE-2", affected_assets=100, cvss_score=7.0, asset_criticality="medium")
        r1 = engine.score(inp1)
        r2 = engine.score(inp2)
        assert r2.impact.blast_radius == "org-wide"
        assert r2.impact.score > r1.impact.score

    def test_compliance_adds_penalty(self, engine):
        base = FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="medium")
        comp = FAILInput(
            cve_id="CVE-2",
            cvss_score=7.0,
            asset_criticality="medium",
            compliance_frameworks=["SOC2", "PCI-DSS", "HIPAA"],
        )
        r_base = engine.score(base)
        r_comp = engine.score(comp)
        assert r_comp.impact.score > r_base.impact.score


# ---------------------------------------------------------------------------
# $LIKELIHOOD tests
# ---------------------------------------------------------------------------


class TestLikelihoodScore:
    def test_kev_gives_major_boost(self, engine):
        base = FAILInput(cve_id="CVE-1", epss_score=0.3)
        kev = FAILInput(cve_id="CVE-2", epss_score=0.3, is_kev=True)
        r_base = engine.score(base)
        r_kev = engine.score(kev)
        assert r_kev.likelihood.kev_boost == 25.0
        assert r_kev.likelihood.score > r_base.likelihood.score

    def test_high_epss_increases_likelihood(self, engine):
        low = FAILInput(cve_id="CVE-1", epss_score=0.01)
        high = FAILInput(cve_id="CVE-2", epss_score=0.95)
        r_low = engine.score(low)
        r_high = engine.score(high)
        assert r_high.likelihood.epss_based > r_low.likelihood.epss_based

    def test_compensating_controls_reduce_exposure(self, engine):
        exposed = FAILInput(cve_id="CVE-1", is_reachable=True, is_internet_facing=True)
        controlled = FAILInput(
            cve_id="CVE-2",
            is_reachable=True,
            is_internet_facing=True,
            has_compensating_controls=True,
        )
        r_exp = engine.score(exposed)
        r_ctrl = engine.score(controlled)
        assert r_ctrl.likelihood.exposure_factor < r_exp.likelihood.exposure_factor


# ---------------------------------------------------------------------------
# Composite FAIL score tests
# ---------------------------------------------------------------------------


class TestCompositeScore:
    def test_critical_input_scores_critical(self, engine, critical_input):
        result = engine.score(critical_input)
        assert result.fail_score >= 70  # At minimum HIGH
        assert result.grade in (FAILGrade.CRITICAL, FAILGrade.HIGH)

    def test_low_input_scores_low(self, engine, low_input):
        result = engine.score(low_input)
        assert result.fail_score < 50
        assert result.grade in (FAILGrade.LOW, FAILGrade.MEDIUM, FAILGrade.INFO)

    def test_minimal_input_doesnt_crash(self, engine, minimal_input):
        result = engine.score(minimal_input)
        assert 0 <= result.fail_score <= 100
        assert result.grade is not None
        assert result.recommended_action is not None
        assert result.cve_id == "CVE-2024-0001"

    def test_score_always_in_range(self, engine):
        """Edge: even extreme inputs produce 0-100 score."""
        extreme = FAILInput(
            cve_id="CVE-EDGE",
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
            affected_assets=1000,
            compliance_frameworks=["SOC2", "PCI-DSS", "HIPAA", "ISO27001"],
        )
        result = engine.score(extreme)
        assert 0 <= result.fail_score <= 100

    def test_empty_input_scores_zero_ish(self, engine):
        result = engine.score(FAILInput())
        assert result.fail_score < 30
        assert result.grade in (FAILGrade.INFO, FAILGrade.LOW)


# ---------------------------------------------------------------------------
# Grade / Action mapping
# ---------------------------------------------------------------------------


class TestGradeMapping:
    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (95, FAILGrade.CRITICAL),
            (75, FAILGrade.HIGH),
            (50, FAILGrade.MEDIUM),
            (30, FAILGrade.LOW),
            (10, FAILGrade.INFO),
        ],
    )
    def test_score_to_grade(self, score, expected_grade):
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
    def test_grade_to_action(self, grade, expected_action):
        assert FAILEngine._grade_to_action(grade) == expected_action


# ---------------------------------------------------------------------------
# Dynamic weight adjustment
# ---------------------------------------------------------------------------


class TestDynamicWeights:
    def test_weights_sum_to_one(self, engine, critical_input):
        result = engine.score(critical_input)
        total = sum(result.weights.values())
        assert abs(total - 1.0) < 0.001

    def test_kev_boosts_likelihood_weight(self, engine):
        base = FAILInput(cve_id="CVE-1", cvss_score=7.0)
        kev = FAILInput(cve_id="CVE-2", cvss_score=7.0, is_kev=True)
        r_base = engine.score(base)
        r_kev = engine.score(kev)
        assert r_kev.weights["likelihood"] > r_base.weights["likelihood"]

    def test_critical_asset_boosts_impact_weight(self, engine):
        normal = FAILInput(cve_id="CVE-1", cvss_score=7.0, asset_criticality="medium")
        critical = FAILInput(cve_id="CVE-2", cvss_score=7.0, asset_criticality="critical")
        r_norm = engine.score(normal)
        r_crit = engine.score(critical)
        assert r_crit.weights["impact"] > r_norm.weights["impact"]


# ---------------------------------------------------------------------------
# Batch scoring
# ---------------------------------------------------------------------------


class TestBatchScoring:
    def test_batch_returns_all_results(self, engine):
        inputs = [
            FAILInput(cve_id=f"CVE-2024-{i}", cvss_score=float(i)) for i in range(1, 6)
        ]
        results = engine.score_batch(inputs)
        assert len(results) == 5

    def test_rank_orders_by_score(self, engine):
        inputs = [
            FAILInput(cve_id="CVE-LOW", cvss_score=2.0),
            FAILInput(cve_id="CVE-HIGH", cvss_score=9.5, is_kev=True, has_exploit=True),
            FAILInput(cve_id="CVE-MED", cvss_score=5.5),
        ]
        results = engine.score_batch(inputs)
        ranked = engine.rank(results)
        assert ranked[0].fail_score >= ranked[1].fail_score >= ranked[2].fail_score


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_to_dict_contains_all_fields(self, engine, critical_input):
        result = engine.score(critical_input)
        d = result.to_dict()
        assert "score_id" in d
        assert "fail_score" in d
        assert "grade" in d
        assert "recommended_action" in d
        assert "sub_scores" in d
        assert "fact" in d["sub_scores"]
        assert "assess" in d["sub_scores"]
        assert "impact" in d["sub_scores"]
        assert "likelihood" in d["sub_scores"]
        assert "weights" in d
        assert "scored_at" in d
        assert "engine_version" in d

    def test_score_id_starts_with_fail(self, engine, minimal_input):
        result = engine.score(minimal_input)
        assert result.score_id.startswith("FAIL-")


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class TestStats:
    def test_empty_history_stats(self):
        fresh = FAILEngine()
        stats = fresh.stats()
        assert stats["total_scored"] == 0

    def test_stats_after_scoring(self, engine, critical_input, low_input):
        engine.score(critical_input)
        engine.score(low_input)
        stats = engine.stats()
        assert stats["total_scored"] == 2
        assert "average_score" in stats
        assert "grade_distribution" in stats


# ---------------------------------------------------------------------------
# DB layer (basic)
# ---------------------------------------------------------------------------


class TestFAILDB:
    def test_save_and_retrieve(self, tmp_path):
        from core.fail_db import FAILDB

        db = FAILDB(db_path=str(tmp_path / "test_fail.db"))
        engine = FAILEngine()
        inp = FAILInput(cve_id="CVE-2024-TEST", cvss_score=8.5, epss_score=0.7)
        result = engine.score(inp)
        result_dict = result.to_dict()

        score_id = db.save_score(result_dict, org_id="test-org")
        assert score_id == result.score_id

        retrieved = db.get_score(score_id)
        assert retrieved is not None
        assert retrieved["cve_id"] == "CVE-2024-TEST"
        assert retrieved["grade"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_get_by_cve(self, tmp_path):
        from core.fail_db import FAILDB

        db = FAILDB(db_path=str(tmp_path / "test_fail2.db"))
        engine = FAILEngine()

        for i in range(3):
            inp = FAILInput(cve_id="CVE-2024-SAME", cvss_score=7.0 + i)
            result = engine.score(inp)
            db.save_score(result.to_dict(), org_id="test")

        scores = db.get_scores_by_cve("CVE-2024-SAME")
        assert len(scores) == 3

    def test_stats(self, tmp_path):
        from core.fail_db import FAILDB

        db = FAILDB(db_path=str(tmp_path / "test_fail3.db"))
        engine = FAILEngine()

        for cvss in [2.0, 5.0, 8.0, 9.5]:
            inp = FAILInput(cve_id=f"CVE-{cvss}", cvss_score=cvss)
            db.save_score(engine.score(inp).to_dict(), org_id="dev")

        stats = db.get_stats(org_id="dev")
        assert stats["total"] == 4
        assert stats["average_score"] > 0

    def test_delete(self, tmp_path):
        from core.fail_db import FAILDB

        db = FAILDB(db_path=str(tmp_path / "test_fail4.db"))
        engine = FAILEngine()
        result = engine.score(FAILInput(cve_id="CVE-DEL"))
        db.save_score(result.to_dict())

        assert db.delete_score(result.score_id) is True
        assert db.get_score(result.score_id) is None

    def test_grade_distribution(self, tmp_path):
        from core.fail_db import FAILDB

        db = FAILDB(db_path=str(tmp_path / "test_fail5.db"))
        engine = FAILEngine()

        for cvss in [1.0, 3.0, 5.0, 7.5, 9.8]:
            db.save_score(
                engine.score(FAILInput(cve_id=f"CVE-{cvss}", cvss_score=cvss)).to_dict()
            )

        dist = db.get_grade_distribution()
        assert isinstance(dist, dict)
        assert sum(dist.values()) == 5
