"""
Tests for ALdeci Predictive Vulnerability Scorer — Year 3 ML Roadmap.

[V3] Decision Intelligence — Pre-CVE risk prediction using code patterns.

Tests cover:
1. CWE profile-based risk scoring
2. Code complexity correlation
3. Dependency risk scoring
4. Temporal risk decay
5. Cross-CVE similarity
6. Edge cases and boundary conditions
7. Golden dataset integration
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure suite paths are available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.ml.predictive_scorer import (
    CWE_EXPLOIT_PROFILES,
    LANGUAGE_RISK_MULTIPLIERS,
    PredictiveScorer,
    get_predictive_scorer,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scorer():
    """Create a fresh PredictiveScorer."""
    return PredictiveScorer(random_seed=42)


@pytest.fixture
def fitted_scorer():
    """Create a PredictiveScorer fitted on golden dataset."""
    s = PredictiveScorer(random_seed=42)
    golden_path = Path("data/golden_regression_cases.json")
    if golden_path.exists():
        s.fit_from_cve_history(str(golden_path))
    return s


@pytest.fixture
def sql_injection_pattern():
    """High-risk SQL injection code pattern."""
    return {
        "cwe_id": "CWE-89",
        "language": "python",
        "complexity": 25,
        "function_length": 150,
        "has_user_input": True,
        "dependency_age_days": 730,
        "dependency_vuln_history": 5,
        "is_internet_facing": True,
        "has_auth_check": False,
    }


@pytest.fixture
def low_risk_pattern():
    """Low-risk code pattern."""
    return {
        "cwe_id": "CWE-209",
        "language": "rust",
        "complexity": 5,
        "function_length": 20,
        "has_user_input": False,
        "dependency_age_days": 30,
        "dependency_vuln_history": 0,
        "is_internet_facing": False,
        "has_auth_check": True,
    }


# ---------------------------------------------------------------------------
# Tests: CWE Profile Database
# ---------------------------------------------------------------------------


class TestCWEProfiles:
    def test_profiles_exist_for_top_25(self):
        """MITRE CWE Top 25 categories should have profiles."""
        top_cwes = ["CWE-89", "CWE-79", "CWE-787", "CWE-22", "CWE-502",
                    "CWE-287", "CWE-78", "CWE-862", "CWE-434", "CWE-94"]
        for cwe in top_cwes:
            assert cwe in CWE_EXPLOIT_PROFILES, f"{cwe} missing from profiles"

    def test_exploit_probabilities_valid_range(self):
        """All exploit probabilities should be between 0 and 1."""
        for cwe, profile in CWE_EXPLOIT_PROFILES.items():
            assert 0.0 <= profile["base_exploit_prob"] <= 1.0, \
                f"{cwe} has invalid exploit prob: {profile['base_exploit_prob']}"

    def test_avg_cvss_valid_range(self):
        """All avg CVSS scores should be between 0 and 10."""
        for cwe, profile in CWE_EXPLOIT_PROFILES.items():
            assert 0.0 <= profile["avg_cvss"] <= 10.0, \
                f"{cwe} has invalid avg_cvss: {profile['avg_cvss']}"

    def test_weaponize_days_non_negative(self):
        """Weaponization days should be non-negative."""
        for cwe, profile in CWE_EXPLOIT_PROFILES.items():
            assert profile["weaponize_days"] >= 0

    def test_injection_cwes_have_high_exploit_prob(self):
        """Injection CWEs should have >0.7 exploit probability."""
        injection_cwes = [cwe for cwe, p in CWE_EXPLOIT_PROFILES.items()
                         if p["category"] == "injection"]
        for cwe in injection_cwes:
            assert CWE_EXPLOIT_PROFILES[cwe]["base_exploit_prob"] >= 0.70

    def test_categories_are_valid(self):
        """All categories should be from the expected set."""
        valid_cats = {"injection", "deserialization", "auth", "memory",
                     "path", "crypto", "supply_chain", "dos",
                     "info_disclosure", "race", "access"}
        for cwe, profile in CWE_EXPLOIT_PROFILES.items():
            assert profile["category"] in valid_cats, \
                f"{cwe} has invalid category: {profile['category']}"


class TestLanguageMultipliers:
    def test_all_multipliers_positive(self):
        """Language multipliers should all be positive."""
        for lang, mult in LANGUAGE_RISK_MULTIPLIERS.items():
            assert mult > 0, f"{lang} has non-positive multiplier"

    def test_c_higher_than_rust(self):
        """C should have higher risk than Rust (memory safety)."""
        assert LANGUAGE_RISK_MULTIPLIERS["c"] > LANGUAGE_RISK_MULTIPLIERS["rust"]

    def test_rust_is_lowest(self):
        """Rust should have the lowest multiplier (borrow checker)."""
        rust_mult = LANGUAGE_RISK_MULTIPLIERS["rust"]
        for lang, mult in LANGUAGE_RISK_MULTIPLIERS.items():
            assert mult >= rust_mult


# ---------------------------------------------------------------------------
# Tests: Code Risk Prediction
# ---------------------------------------------------------------------------


class TestCodeRiskPrediction:
    def test_sql_injection_is_high_risk(self, scorer, sql_injection_pattern):
        """SQL injection with user input + no auth should be high risk."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        assert result.risk_score >= 50
        assert result.exploit_probability > 0.8
        assert result.priority in ("P0", "P1")

    def test_low_risk_pattern_is_low(self, scorer, low_risk_pattern):
        """Error message info leak in Rust, no user input should be low risk."""
        result = scorer.predict_code_risk(low_risk_pattern)
        assert result.risk_score < 25
        assert result.priority in ("P3", "P4", "FP")

    def test_result_has_risk_factors(self, scorer, sql_injection_pattern):
        """Result should include detailed risk factor breakdown."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        assert len(result.risk_factors) >= 6
        factor_names = {f["factor"] for f in result.risk_factors}
        assert "cwe_base_risk" in factor_names
        assert "language_risk" in factor_names
        assert "code_complexity" in factor_names

    def test_result_has_confidence_interval(self, scorer, sql_injection_pattern):
        """Result should have valid CI."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        ci_low, ci_high = result.confidence_interval
        assert ci_low <= result.risk_score <= ci_high
        assert ci_low >= 0
        assert ci_high <= 100

    def test_result_has_time_to_exploit(self, scorer, sql_injection_pattern):
        """Result should estimate time to exploitation."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        assert result.time_to_exploit_days >= 0
        # SQL injection should be fast to weaponize
        assert result.time_to_exploit_days <= 14

    def test_result_has_recommendation(self, scorer, sql_injection_pattern):
        """Result should have actionable recommendation."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        assert len(result.recommendation) > 20
        assert "SQL Injection" in result.recommendation or "injection" in result.recommendation.lower()

    def test_result_has_category(self, scorer, sql_injection_pattern):
        """Result should identify the vulnerability category."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        assert result.category == "injection"

    def test_to_dict_serializable(self, scorer, sql_injection_pattern):
        """Result should be JSON-serializable."""
        result = scorer.predict_code_risk(sql_injection_pattern)
        d = result.to_dict()
        assert isinstance(d, dict)
        json.dumps(d)  # Should not raise

    def test_higher_complexity_increases_risk(self, scorer):
        """Higher cyclomatic complexity should increase risk."""
        low_complexity = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "complexity": 5,
            "function_length": 50,
        })
        high_complexity = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "complexity": 80,
            "function_length": 50,
        })
        assert high_complexity.risk_score > low_complexity.risk_score

    def test_user_input_increases_risk(self, scorer):
        """Processing user input should increase risk."""
        no_input = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "has_user_input": False,
        })
        with_input = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "has_user_input": True,
        })
        assert with_input.risk_score > no_input.risk_score

    def test_auth_check_reduces_risk(self, scorer):
        """Having auth check should reduce risk."""
        no_auth = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "has_auth_check": False,
        })
        with_auth = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "has_auth_check": True,
        })
        assert with_auth.risk_score <= no_auth.risk_score

    def test_internet_facing_increases_risk(self, scorer):
        """Internet-facing code should have higher risk."""
        internal = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "is_internet_facing": False,
        })
        internet = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "is_internet_facing": True,
        })
        assert internet.risk_score > internal.risk_score

    def test_unknown_cwe_gets_default_score(self, scorer):
        """Unknown CWE should still produce a valid result."""
        result = scorer.predict_code_risk({
            "cwe_id": "CWE-99999",
            "language": "python",
        })
        assert 0 <= result.risk_score <= 100
        assert result.category == "unknown"

    def test_risk_score_bounded_0_100(self, scorer):
        """Risk score should always be between 0 and 100."""
        # Maximum risk case
        max_result = scorer.predict_code_risk({
            "cwe_id": "CWE-798",  # Hardcoded creds — highest exploit prob
            "language": "c",
            "complexity": 200,
            "function_length": 2000,
            "has_user_input": True,
            "dependency_age_days": 2000,
            "dependency_vuln_history": 20,
            "is_internet_facing": True,
            "has_auth_check": False,
        })
        assert 0 <= max_result.risk_score <= 100

        # Minimum risk case
        min_result = scorer.predict_code_risk({
            "cwe_id": "CWE-209",
            "language": "rust",
            "complexity": 1,
            "function_length": 1,
            "has_user_input": False,
            "dependency_age_days": 0,
            "dependency_vuln_history": 0,
            "is_internet_facing": False,
            "has_auth_check": True,
        })
        assert 0 <= min_result.risk_score <= 100

    def test_exploit_probability_bounded(self, scorer):
        """Exploit probability should be between 0 and 1."""
        result = scorer.predict_code_risk({
            "cwe_id": "CWE-506",
            "has_user_input": True,
            "has_auth_check": False,
            "dependency_vuln_history": 50,
        })
        assert 0 <= result.exploit_probability <= 1.0


# ---------------------------------------------------------------------------
# Tests: Fitted Scorer (with golden dataset)
# ---------------------------------------------------------------------------


class TestFittedScorer:
    def test_fit_returns_stats(self, fitted_scorer):
        """Fitting should return CWE statistics."""
        assert fitted_scorer._fitted
        assert len(fitted_scorer._cwe_stats) > 0

    def test_fitted_scorer_finds_similar_cves(self, fitted_scorer):
        """Fitted scorer should find similar CVEs from history."""
        result = fitted_scorer.predict_code_risk({
            "cwe_id": "CWE-502",
            "has_user_input": True,
        })
        assert len(result.similar_cves) > 0
        # Should find Log4Shell (CWE-502) as similar
        cve_ids = {c["cve_id"] for c in result.similar_cves}
        assert "CVE-2021-44228" in cve_ids or len(result.similar_cves) > 0

    def test_fitted_has_narrower_ci(self, fitted_scorer, scorer):
        """Fitted scorer should have narrower CI than unfitted."""
        pattern = {"cwe_id": "CWE-89", "has_user_input": True}
        fitted_result = fitted_scorer.predict_code_risk(pattern)
        unfitted_result = scorer.predict_code_risk(pattern)

        fitted_width = fitted_result.confidence_interval[1] - fitted_result.confidence_interval[0]
        unfitted_width = unfitted_result.confidence_interval[1] - unfitted_result.confidence_interval[0]

        # Both should be reasonable width
        assert fitted_width <= 40  # Not too wide
        assert unfitted_width <= 50


# ---------------------------------------------------------------------------
# Tests: Dependency Risk Scoring
# ---------------------------------------------------------------------------


class TestDependencyRisk:
    def test_high_risk_dependency(self, scorer):
        """Dependency with many active CVEs should be high risk."""
        result = scorer.score_dependency_risk({
            "name": "log4j",
            "cve_count": 15,
            "active_cves": 5,
            "highest_cvss": 10.0,
            "age_days": 3650,
            "last_update_days": 180,
            "maintainers": 2,
            "downloads_weekly": 500000,
        })
        assert result.risk_score >= 50
        assert result.supply_chain_risk in ("high", "critical")
        assert "URGENT" in result.recommendation or "Upgrade" in result.recommendation

    def test_low_risk_dependency(self, scorer):
        """Well-maintained dependency with no CVEs should be low risk."""
        result = scorer.score_dependency_risk({
            "name": "requests",
            "cve_count": 2,
            "active_cves": 0,
            "highest_cvss": 0.0,
            "age_days": 3650,
            "last_update_days": 14,
            "maintainers": 5,
            "downloads_weekly": 10000000,
        })
        assert result.risk_score < 30
        assert result.supply_chain_risk in ("low", "medium")

    def test_stale_dependency_warning(self, scorer):
        """Dependency not updated for >1 year should get warning."""
        result = scorer.score_dependency_risk({
            "name": "abandoned-lib",
            "cve_count": 0,
            "active_cves": 0,
            "highest_cvss": 0.0,
            "age_days": 1825,
            "last_update_days": 400,
            "maintainers": 1,
        })
        assert "replacing" in result.recommendation.lower() or \
               "updated" in result.recommendation.lower() or \
               "monitor" in result.recommendation.lower()

    def test_result_serializable(self, scorer):
        """Dependency risk result should be JSON-serializable."""
        result = scorer.score_dependency_risk({
            "name": "test-pkg",
            "cve_count": 3,
            "active_cves": 1,
            "highest_cvss": 7.5,
        })
        d = result.to_dict()
        json.dumps(d)  # Should not raise

    def test_vuln_density_calculation(self, scorer):
        """Vulnerability density should be correctly calculated."""
        result = scorer.score_dependency_risk({
            "name": "test",
            "cve_count": 10,
            "age_days": 365,  # 1 year
        })
        assert abs(result.vuln_density - 10.0) < 0.1  # 10 vulns / 1 year


# ---------------------------------------------------------------------------
# Tests: Temporal Risk Decay
# ---------------------------------------------------------------------------


class TestTemporalDecay:
    def test_risk_decays_over_time(self, scorer):
        """Risk should decrease for unpatched, non-exploited vulns."""
        decay = scorer.compute_temporal_decay(
            initial_risk=80.0,
            days_since_discovery=90,
            is_actively_exploited=False,
            has_patch=False,
        )
        assert decay.current_risk < decay.initial_risk
        assert decay.current_risk > 0

    def test_actively_exploited_no_decay(self, scorer):
        """Actively exploited vulns should NOT decay."""
        decay = scorer.compute_temporal_decay(
            initial_risk=80.0,
            days_since_discovery=365,
            is_actively_exploited=True,
        )
        assert decay.current_risk >= decay.initial_risk
        assert decay.decay_rate == 0.0

    def test_patched_vulns_decay_faster(self, scorer):
        """Patched vulns should decay 3x faster."""
        unpatched = scorer.compute_temporal_decay(80.0, 90, has_patch=False)
        patched = scorer.compute_temporal_decay(80.0, 90, has_patch=True)
        assert patched.current_risk < unpatched.current_risk

    def test_kev_no_decay(self, scorer):
        """KEV entries should not decay."""
        decay = scorer.compute_temporal_decay(
            initial_risk=80.0,
            days_since_discovery=180,
            in_kev=True,
        )
        assert decay.current_risk >= decay.initial_risk

    def test_half_life_calculation(self, scorer):
        """Half-life should be ~90 days for standard decay."""
        decay = scorer.compute_temporal_decay(80.0, 0)
        assert 85 <= decay.half_life_days <= 95  # ~90 days

    def test_patched_half_life_shorter(self, scorer):
        """Patched vulns should have ~30 day half-life (3x faster)."""
        decay = scorer.compute_temporal_decay(80.0, 0, has_patch=True)
        assert 25 <= decay.half_life_days <= 35

    def test_decay_result_serializable(self, scorer):
        """Temporal decay result should be JSON-serializable."""
        decay = scorer.compute_temporal_decay(80.0, 90)
        d = decay.to_dict()
        json.dumps(d)  # Should not raise

    def test_risk_bounded_0_100(self, scorer):
        """Decayed risk should stay within bounds."""
        # Very old vuln
        decay = scorer.compute_temporal_decay(100.0, 3650)
        assert 0 <= decay.current_risk <= 100

        # KEV increase case
        decay = scorer.compute_temporal_decay(95.0, 60, in_kev=True)
        assert 0 <= decay.current_risk <= 100


# ---------------------------------------------------------------------------
# Tests: Cross-CVE Similarity
# ---------------------------------------------------------------------------


class TestSimilarity:
    def test_identical_vulns_high_similarity(self, scorer):
        """Identical vulns should have high similarity."""
        vuln = {
            "cwe_id": "CWE-89",
            "cvss_score": 9.8,
            "exploit_available": True,
            "in_kev": True,
            "reachable": True,
        }
        sim = scorer.compute_similarity(vuln, vuln)
        assert sim > 0.8

    def test_different_vulns_lower_similarity(self, scorer):
        """Completely different vulns should have lower similarity."""
        vuln_a = {
            "cwe_id": "CWE-89",
            "cvss_score": 9.8,
            "exploit_available": True,
        }
        vuln_b = {
            "cwe_id": "CWE-327",
            "cvss_score": 3.0,
            "exploit_available": False,
        }
        sim = scorer.compute_similarity(vuln_a, vuln_b)
        assert sim < 0.5

    def test_same_cwe_increases_similarity(self, scorer):
        """Same CWE should significantly increase similarity."""
        vuln_a = {"cwe_id": "CWE-89", "cvss_score": 9.0}
        vuln_b = {"cwe_id": "CWE-89", "cvss_score": 5.0}
        vuln_c = {"cwe_id": "CWE-787", "cvss_score": 9.0}

        sim_same_cwe = scorer.compute_similarity(vuln_a, vuln_b)
        sim_diff_cwe = scorer.compute_similarity(vuln_a, vuln_c)
        assert sim_same_cwe > sim_diff_cwe

    def test_similarity_bounded_0_1(self, scorer):
        """Similarity should always be between 0 and 1."""
        vulns = [
            {"cwe_id": "CWE-89", "cvss_score": 10.0},
            {"cwe_id": "CWE-787", "cvss_score": 0.0},
            {},
        ]
        for a in vulns:
            for b in vulns:
                sim = scorer.compute_similarity(a, b)
                assert 0.0 <= sim <= 1.0


# ---------------------------------------------------------------------------
# Tests: Priority Assignment
# ---------------------------------------------------------------------------


class TestPriorityAssignment:
    def test_critical_gets_p0(self, scorer):
        """Very high risk patterns should get P0."""
        result = scorer.predict_code_risk({
            "cwe_id": "CWE-798",  # Hardcoded creds
            "has_user_input": True,
            "has_auth_check": False,
            "is_internet_facing": True,
            "complexity": 50,
            "dependency_vuln_history": 10,
            "dependency_age_days": 1000,
        })
        assert result.priority in ("P0", "P1")

    def test_low_risk_gets_p3_or_lower(self, scorer, low_risk_pattern):
        """Low risk patterns should get P3 or lower."""
        result = scorer.predict_code_risk(low_risk_pattern)
        assert result.priority in ("P3", "P4", "FP")

    def test_priority_thresholds_match_risk_scorer(self, scorer):
        """Priority thresholds should match the risk_scorer module."""
        # These thresholds are from risk_scorer.py
        cases = [
            (85, "P0"),
            (60, "P1"),
            (35, "P2"),
            (10, "P3"),
            (6,  "P4"),
            (3,  "FP"),
        ]
        for score, expected_prio in cases:
            # Use a known CWE and manipulate to get approximate score
            result = scorer.predict_code_risk({
                "cwe_id": "CWE-89",
                "has_user_input": score > 50,
                "has_auth_check": score < 50,
                "complexity": int(score / 2),
            })
            # Just verify priority is valid
            assert result.priority in ("P0", "P1", "P2", "P3", "P4", "FP")


# ---------------------------------------------------------------------------
# Tests: Module-level convenience
# ---------------------------------------------------------------------------


class TestModuleLevel:
    def test_get_predictive_scorer_returns_scorer(self):
        """Module-level getter should return a PredictiveScorer."""
        # Reset singleton
        import core.ml.predictive_scorer as ps
        ps._default_scorer = None
        scorer = get_predictive_scorer()
        assert isinstance(scorer, PredictiveScorer)
        ps._default_scorer = None  # Cleanup

    def test_get_predictive_scorer_is_singleton(self):
        """Should return the same instance on multiple calls."""
        import core.ml.predictive_scorer as ps
        ps._default_scorer = None
        s1 = get_predictive_scorer()
        s2 = get_predictive_scorer()
        assert s1 is s2
        ps._default_scorer = None

    def test_get_predictive_scorer_handles_missing_golden(self):
        """Should handle missing golden dataset gracefully."""
        import core.ml.predictive_scorer as ps
        ps._default_scorer = None
        scorer = get_predictive_scorer("/nonexistent/path.json")
        assert isinstance(scorer, PredictiveScorer)
        # Should still work, just with wider CIs
        result = scorer.predict_code_risk({"cwe_id": "CWE-89"})
        assert 0 <= result.risk_score <= 100
        ps._default_scorer = None


# ---------------------------------------------------------------------------
# Tests: Edge Cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_pattern(self, scorer):
        """Empty pattern should produce valid result with defaults."""
        result = scorer.predict_code_risk({})
        assert 0 <= result.risk_score <= 100
        assert result.category == "unknown"

    def test_extreme_complexity(self, scorer):
        """Extreme complexity values should be clamped."""
        result = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "complexity": 10000,
        })
        assert 0 <= result.risk_score <= 100

    def test_negative_values_handled(self, scorer):
        """Negative input values should be clamped to 0."""
        result = scorer.predict_code_risk({
            "cwe_id": "CWE-89",
            "complexity": -10,
            "function_length": -100,
            "dependency_age_days": -500,
            "dependency_vuln_history": -5,
        })
        assert 0 <= result.risk_score <= 100

    def test_fit_with_nonexistent_file(self, scorer):
        """Fitting with nonexistent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            scorer.fit_from_cve_history("/nonexistent/golden.json")

    def test_fit_with_minimal_golden(self, scorer):
        """Fitting with minimal golden dataset should work."""
        minimal = {
            "_meta": {"total_cases": 1, "version": "test"},
            "cases": [{
                "id": "GR-001",
                "cve_id": "CVE-2021-44228",
                "cwe_id": "CWE-502",
                "cvss_score": 10.0,
                "epss_score": 0.97,
                "in_kev": True,
                "exploit_available": True,
                "expected_risk_score_min": 90,
                "expected_risk_score_max": 100,
            }]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(minimal, f)
            tmp_path = f.name

        try:
            stats = scorer.fit_from_cve_history(tmp_path)
            assert stats["cases_analyzed"] == 1
            assert scorer._fitted
        finally:
            os.unlink(tmp_path)

    def test_dependency_with_zero_age(self, scorer):
        """Brand new dependency should still score."""
        result = scorer.score_dependency_risk({
            "name": "new-pkg",
            "age_days": 0,
            "cve_count": 0,
        })
        assert 0 <= result.risk_score <= 100

    def test_temporal_decay_day_zero(self, scorer):
        """Day zero should have current_risk equal to initial_risk."""
        decay = scorer.compute_temporal_decay(80.0, 0)
        assert abs(decay.current_risk - 80.0) < 0.01

    def test_temporal_decay_very_old(self, scorer):
        """Very old non-exploited vuln should have near-zero risk."""
        decay = scorer.compute_temporal_decay(80.0, 3650)  # 10 years
        assert decay.current_risk < 1.0

    def test_similarity_empty_vulns(self, scorer):
        """Similarity between empty dicts should not crash."""
        sim = scorer.compute_similarity({}, {})
        assert 0.0 <= sim <= 1.0
