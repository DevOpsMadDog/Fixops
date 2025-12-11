"""Tests for risk/reachability/proprietary_scoring.py module."""

from datetime import datetime, timedelta, timezone

from risk.reachability.proprietary_scoring import (
    ProprietaryRiskFactors,
    ProprietaryScoringEngine,
)


class TestProprietaryRiskFactors:
    """Tests for ProprietaryRiskFactors dataclass."""

    def test_factors_creation(self):
        """Test creating risk factors."""
        factors = ProprietaryRiskFactors(
            exploitability=0.8,
            impact=0.7,
            exposure=0.6,
            reachability=0.5,
            temporal=0.4,
            environmental=0.3,
        )
        assert factors.exploitability == 0.8
        assert factors.impact == 0.7
        assert factors.exposure == 0.6
        assert factors.reachability == 0.5
        assert factors.temporal == 0.4
        assert factors.environmental == 0.3


class TestProprietaryScoringEngine:
    """Tests for ProprietaryScoringEngine class."""

    def test_initialization_default_config(self):
        """Test engine initialization with default config."""
        engine = ProprietaryScoringEngine()
        assert engine.config == {}
        assert "exploitability" in engine.weights
        assert "impact" in engine.weights
        assert "exposure" in engine.weights
        assert "reachability" in engine.weights
        assert "temporal" in engine.weights
        assert "environmental" in engine.weights

    def test_initialization_custom_config(self):
        """Test engine initialization with custom config."""
        config = {"custom_key": "custom_value"}
        engine = ProprietaryScoringEngine(config)
        assert engine.config == config

    def test_build_decay_functions(self):
        """Test decay functions are built correctly."""
        engine = ProprietaryScoringEngine()
        assert "exponential" in engine.decay_functions
        assert "linear" in engine.decay_functions
        assert "logarithmic" in engine.decay_functions

    def test_exponential_decay_function(self):
        """Test exponential decay function."""
        engine = ProprietaryScoringEngine()
        decay = engine.decay_functions["exponential"]
        # At x=0, decay should be 1.0
        assert abs(decay(0, 0.1) - 1.0) < 0.001
        # At x>0, decay should be less than 1.0
        assert decay(10, 0.1) < 1.0

    def test_linear_decay_function(self):
        """Test linear decay function."""
        engine = ProprietaryScoringEngine()
        decay = engine.decay_functions["linear"]
        # At x=0, decay should be 1.0
        assert abs(decay(0, 100) - 1.0) < 0.001
        # At x=max_val, decay should be 0.0
        assert abs(decay(100, 100) - 0.0) < 0.001

    def test_logarithmic_decay_function(self):
        """Test logarithmic decay function."""
        engine = ProprietaryScoringEngine()
        decay = engine.decay_functions["logarithmic"]
        # At x=0, decay should be 1.0
        assert abs(decay(0, 10) - 1.0) < 0.001
        # At x>0, decay should be less than 1.0
        assert decay(10, 10) < 1.0

    def test_calculate_proprietary_score_basic(self):
        """Test basic proprietary score calculation."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 7.5, "severity": "high"}
        component_data = {"criticality": "high"}

        result = engine.calculate_proprietary_score(cve_data, component_data)

        assert "fixops_proprietary_score" in result
        assert "base_score" in result
        assert "confidence" in result
        assert "factors" in result
        assert "weights" in result
        assert "metadata" in result
        assert 0 <= result["fixops_proprietary_score"] <= 100

    def test_calculate_proprietary_score_with_epss(self):
        """Test proprietary score with EPSS score."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 7.5}
        component_data = {}

        result = engine.calculate_proprietary_score(
            cve_data, component_data, epss_score=0.8
        )

        assert result["factors"]["exploitability"] > 0.5

    def test_calculate_proprietary_score_with_kev(self):
        """Test proprietary score with KEV listing."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 7.5}
        component_data = {}

        result = engine.calculate_proprietary_score(
            cve_data, component_data, kev_listed=True
        )

        # KEV should boost exploitability
        assert result["factors"]["exploitability"] > 0.1

    def test_calculate_proprietary_score_with_reachability(self):
        """Test proprietary score with reachability data."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 7.5}
        component_data = {}
        reachability_data = {"is_reachable": True, "confidence_score": 0.9}

        result = engine.calculate_proprietary_score(
            cve_data, component_data, reachability_data
        )

        assert result["metadata"]["has_reachability"] is True
        assert result["factors"]["reachability"] > 0.5

    def test_calculate_exploitability_with_epss(self):
        """Test exploitability calculation with EPSS."""
        engine = ProprietaryScoringEngine()
        cve_data = {}

        result = engine._calculate_exploitability(cve_data, 0.7, False)
        assert abs(result - 0.7) < 0.001

    def test_calculate_exploitability_with_kev_boost(self):
        """Test exploitability calculation with KEV boost."""
        engine = ProprietaryScoringEngine()
        cve_data = {}

        result = engine._calculate_exploitability(cve_data, 0.5, True)
        # KEV should boost by 50%
        assert abs(result - 0.75) < 0.001

    def test_calculate_exploitability_with_sql_injection_cwe(self):
        """Test exploitability calculation with SQL injection CWE."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cwe_ids": ["CWE-89"]}

        result = engine._calculate_exploitability(cve_data, 0.5, False)
        # SQL injection should boost by 20%
        assert result > 0.5

    def test_calculate_exploitability_with_command_injection_cwe(self):
        """Test exploitability calculation with command injection CWE."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cwe_ids": ["CWE-78"]}

        result = engine._calculate_exploitability(cve_data, 0.5, False)
        # Command injection should boost by 30%
        assert result > 0.5

    def test_calculate_exploitability_with_xss_cwe(self):
        """Test exploitability calculation with XSS CWE."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cwe_ids": ["CWE-79"]}

        result = engine._calculate_exploitability(cve_data, 0.5, False)
        # XSS should boost by 10%
        assert result > 0.5

    def test_calculate_exploitability_fallback(self):
        """Test exploitability calculation fallback when no EPSS."""
        engine = ProprietaryScoringEngine()
        cve_data = {}

        result = engine._calculate_exploitability(cve_data, None, False)
        assert abs(result - 0.1) < 0.001

    def test_calculate_impact_with_cvss(self):
        """Test impact calculation with CVSS score."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 8.0}
        component_data = {}

        result = engine._calculate_impact(cve_data, component_data)
        assert abs(result - 0.8) < 0.001

    def test_calculate_impact_with_severity_critical(self):
        """Test impact calculation with critical severity."""
        engine = ProprietaryScoringEngine()
        cve_data = {"severity": "critical"}
        component_data = {}

        result = engine._calculate_impact(cve_data, component_data)
        assert abs(result - 0.9) < 0.001

    def test_calculate_impact_with_severity_high(self):
        """Test impact calculation with high severity."""
        engine = ProprietaryScoringEngine()
        cve_data = {"severity": "high"}
        component_data = {}

        result = engine._calculate_impact(cve_data, component_data)
        assert abs(result - 0.7) < 0.001

    def test_calculate_impact_with_severity_medium(self):
        """Test impact calculation with medium severity."""
        engine = ProprietaryScoringEngine()
        cve_data = {"severity": "medium"}
        component_data = {}

        result = engine._calculate_impact(cve_data, component_data)
        assert abs(result - 0.5) < 0.001

    def test_calculate_impact_with_severity_low(self):
        """Test impact calculation with low severity."""
        engine = ProprietaryScoringEngine()
        cve_data = {"severity": "low"}
        component_data = {}

        result = engine._calculate_impact(cve_data, component_data)
        assert abs(result - 0.3) < 0.001

    def test_calculate_impact_with_mission_critical_component(self):
        """Test impact calculation with mission critical component."""
        engine = ProprietaryScoringEngine()
        cve_data = {"cvss_score": 5.0}
        component_data = {"criticality": "mission_critical"}

        result = engine._calculate_impact(cve_data, component_data)
        # 0.5 * 1.2 = 0.6
        assert abs(result - 0.6) < 0.001

    def test_calculate_exposure_with_internet(self):
        """Test exposure calculation with internet exposure."""
        engine = ProprietaryScoringEngine()
        component_data = {"exposure_flags": ["internet"]}

        result = engine._calculate_exposure(component_data)
        assert abs(result - 1.0) < 0.001

    def test_calculate_exposure_with_public(self):
        """Test exposure calculation with public exposure."""
        engine = ProprietaryScoringEngine()
        component_data = {"exposure_flags": ["public"]}

        result = engine._calculate_exposure(component_data)
        assert abs(result - 0.9) < 0.001

    def test_calculate_exposure_with_internal(self):
        """Test exposure calculation with internal exposure."""
        engine = ProprietaryScoringEngine()
        component_data = {"exposure_flags": ["internal"]}

        result = engine._calculate_exposure(component_data)
        assert abs(result - 0.5) < 0.001

    def test_calculate_exposure_default(self):
        """Test exposure calculation with no flags."""
        engine = ProprietaryScoringEngine()
        component_data = {}

        result = engine._calculate_exposure(component_data)
        assert abs(result - 0.3) < 0.001

    def test_calculate_exposure_multiple_flags(self):
        """Test exposure calculation with multiple flags takes highest."""
        engine = ProprietaryScoringEngine()
        component_data = {"exposure_flags": ["internal", "internet"]}

        result = engine._calculate_exposure(component_data)
        # Should take highest (internet = 1.0)
        assert abs(result - 1.0) < 0.001

    def test_calculate_reachability_none(self):
        """Test reachability calculation with no data."""
        engine = ProprietaryScoringEngine()

        result = engine._calculate_reachability(None)
        assert abs(result - 0.5) < 0.001

    def test_calculate_reachability_reachable_high_confidence(self):
        """Test reachability calculation when reachable with high confidence."""
        engine = ProprietaryScoringEngine()
        reachability_data = {"is_reachable": True, "confidence_score": 1.0}

        result = engine._calculate_reachability(reachability_data)
        # 0.5 + (1.0 * 0.5) = 1.0
        assert abs(result - 1.0) < 0.001

    def test_calculate_reachability_not_reachable_high_confidence(self):
        """Test reachability calculation when not reachable with high confidence."""
        engine = ProprietaryScoringEngine()
        reachability_data = {"is_reachable": False, "confidence_score": 1.0}

        result = engine._calculate_reachability(reachability_data)
        # (1.0 - 1.0) * 0.5 = 0.0
        assert abs(result - 0.0) < 0.001

    def test_calculate_temporal_with_recent_date(self):
        """Test temporal calculation with recent published date."""
        engine = ProprietaryScoringEngine()
        recent_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        cve_data = {"published_date": recent_date}

        result = engine._calculate_temporal(cve_data)
        # Recent date should have high temporal score
        assert result > 0.9

    def test_calculate_temporal_with_old_date(self):
        """Test temporal calculation with old published date."""
        engine = ProprietaryScoringEngine()
        old_date = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        cve_data = {"published_date": old_date}

        result = engine._calculate_temporal(cve_data)
        # Old date should have lower temporal score
        assert result < 0.9

    def test_calculate_temporal_default(self):
        """Test temporal calculation with no date."""
        engine = ProprietaryScoringEngine()
        cve_data = {}

        result = engine._calculate_temporal(cve_data)
        assert abs(result - 0.8) < 0.001

    def test_calculate_environmental_with_pii(self):
        """Test environmental calculation with PII data."""
        engine = ProprietaryScoringEngine()
        component_data = {"data_classification": ["pii"]}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 1.0) < 0.001

    def test_calculate_environmental_with_phi(self):
        """Test environmental calculation with PHI data."""
        engine = ProprietaryScoringEngine()
        component_data = {"data_classification": ["phi"]}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 1.0) < 0.001

    def test_calculate_environmental_with_pci(self):
        """Test environmental calculation with PCI data."""
        engine = ProprietaryScoringEngine()
        component_data = {"data_classification": ["pci"]}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 0.9) < 0.001

    def test_calculate_environmental_with_public(self):
        """Test environmental calculation with public data."""
        engine = ProprietaryScoringEngine()
        component_data = {"data_classification": ["public"]}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 0.4) < 0.001

    def test_calculate_environmental_string_classification(self):
        """Test environmental calculation with string classification."""
        engine = ProprietaryScoringEngine()
        component_data = {"data_classification": "pii"}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 1.0) < 0.001

    def test_calculate_environmental_default(self):
        """Test environmental calculation with no classification."""
        engine = ProprietaryScoringEngine()
        component_data = {}

        result = engine._calculate_environmental(component_data)
        assert abs(result - 0.5) < 0.001

    def test_proprietary_formula(self):
        """Test proprietary scoring formula."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.5,
            impact=0.5,
            exposure=0.5,
            reachability=0.5,
            temporal=0.5,
            environmental=0.5,
        )

        result = engine._proprietary_formula(factors)
        # With all factors at 0.5, weighted sum is 0.5, sigmoid at 0.5 = 50
        assert abs(result - 50.0) < 1.0

    def test_proprietary_formula_high_factors(self):
        """Test proprietary formula with high factors."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=1.0,
            impact=1.0,
            exposure=1.0,
            reachability=1.0,
            temporal=1.0,
            environmental=1.0,
        )

        result = engine._proprietary_formula(factors)
        # High factors should give high score
        assert result > 90

    def test_proprietary_formula_low_factors(self):
        """Test proprietary formula with low factors."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.0,
            impact=0.0,
            exposure=0.0,
            reachability=0.0,
            temporal=0.0,
            environmental=0.0,
        )

        result = engine._proprietary_formula(factors)
        # Low factors should give low score
        assert result < 10

    def test_apply_proprietary_adjustments_high_exploit_reach(self):
        """Test adjustments for high exploitability and reachability."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.8,
            impact=0.5,
            exposure=0.5,
            reachability=0.8,
            temporal=0.5,
            environmental=0.5,
        )
        cve_data = {}
        component_data = {}

        result = engine._apply_proprietary_adjustments(
            50.0, factors, cve_data, component_data
        )
        # Should be boosted by 1.3
        assert result > 50.0

    def test_apply_proprietary_adjustments_high_impact_exposure(self):
        """Test adjustments for high impact and exposure."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.5,
            impact=0.9,
            exposure=0.9,
            reachability=0.5,
            temporal=0.5,
            environmental=0.5,
        )
        cve_data = {}
        component_data = {}

        result = engine._apply_proprietary_adjustments(
            50.0, factors, cve_data, component_data
        )
        # Should be boosted by 1.2
        assert result > 50.0

    def test_apply_proprietary_adjustments_exploited(self):
        """Test adjustments for exploited vulnerability."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.5,
            impact=0.5,
            exposure=0.5,
            reachability=0.5,
            temporal=0.5,
            environmental=0.5,
        )
        cve_data = {"exploited": True}
        component_data = {}

        result = engine._apply_proprietary_adjustments(
            50.0, factors, cve_data, component_data
        )
        # Should add 10 points
        assert abs(result - 60.0) < 0.001

    def test_apply_proprietary_adjustments_clamped(self):
        """Test adjustments are clamped to 0-100."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=1.0,
            impact=1.0,
            exposure=1.0,
            reachability=1.0,
            temporal=1.0,
            environmental=1.0,
        )
        cve_data = {"exploited": True}
        component_data = {}

        result = engine._apply_proprietary_adjustments(
            95.0, factors, cve_data, component_data
        )
        # Should be clamped to 100
        assert result <= 100.0

    def test_calculate_confidence_base(self):
        """Test confidence calculation base."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.0,
            impact=0.0,
            exposure=0.0,
            reachability=0.0,
            temporal=0.0,
            environmental=0.0,
        )

        result = engine._calculate_confidence(factors, None)
        # Base confidence is 0.5
        assert result >= 0.5

    def test_calculate_confidence_with_reachability_data(self):
        """Test confidence calculation with reachability data."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=0.5,
            impact=0.5,
            exposure=0.5,
            reachability=0.5,
            temporal=0.5,
            environmental=0.5,
        )
        reachability_data = {"is_reachable": True}

        result = engine._calculate_confidence(factors, reachability_data)
        # Should be higher with reachability data
        assert result > 0.5

    def test_calculate_confidence_clamped(self):
        """Test confidence is clamped to 0-1."""
        engine = ProprietaryScoringEngine()
        factors = ProprietaryRiskFactors(
            exploitability=1.0,
            impact=1.0,
            exposure=1.0,
            reachability=1.0,
            temporal=1.0,
            environmental=1.0,
        )
        reachability_data = {"is_reachable": True}

        result = engine._calculate_confidence(factors, reachability_data)
        assert result <= 1.0

    def test_full_scoring_pipeline(self):
        """Test full scoring pipeline end-to-end."""
        engine = ProprietaryScoringEngine()
        cve_data = {
            "cvss_score": 9.0,
            "severity": "critical",
            "cwe_ids": ["CWE-89"],
            "published_date": datetime.now(timezone.utc).isoformat(),
            "exploited": True,
        }
        component_data = {
            "criticality": "mission_critical",
            "exposure_flags": ["internet"],
            "data_classification": ["pii"],
        }
        reachability_data = {"is_reachable": True, "confidence_score": 0.95}

        result = engine.calculate_proprietary_score(
            cve_data, component_data, reachability_data, epss_score=0.9, kev_listed=True
        )

        # High risk scenario should have high score
        assert result["fixops_proprietary_score"] > 80
        assert result["confidence"] > 0.7
        assert result["metadata"]["algorithm_version"] == "2.0"
        assert result["metadata"]["has_reachability"] is True
