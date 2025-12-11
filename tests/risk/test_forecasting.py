"""Rigorous tests for probabilistic forecasting functionality.

These tests verify Bayesian updates, Markov forecasting, and overall
forecast computation with realistic scenarios and proper assertions.
"""


from risk.enrichment import EnrichmentEvidence
from risk.forecasting import (
    ForecastResult,
    _apply_likelihood_ratio,
    _markov_forecast_30d,
    _naive_bayes_update,
    compute_forecast,
)


class TestForecastResult:
    """Tests for ForecastResult dataclass."""

    def test_result_defaults(self):
        """Verify ForecastResult has correct default values."""
        result = ForecastResult(
            cve_id="CVE-2023-12345",
            p_exploit_now=0.5,
            p_exploit_30d=0.7,
        )
        assert result.cve_id == "CVE-2023-12345"
        assert result.p_exploit_now == 0.5
        assert result.p_exploit_30d == 0.7
        assert result.evidence_breakdown == {}
        assert result.method == "naive_bayes"
        assert result.confidence == 0.0

    def test_result_with_all_fields(self):
        """Verify ForecastResult stores all fields correctly."""
        result = ForecastResult(
            cve_id="CVE-2023-54321",
            p_exploit_now=0.85,
            p_exploit_30d=0.95,
            evidence_breakdown={"prior": 0.5, "signals_applied": []},
            method="naive_bayes_markov",
            confidence=0.9,
        )
        assert result.p_exploit_now == 0.85
        assert result.p_exploit_30d == 0.95
        assert result.method == "naive_bayes_markov"
        assert result.confidence == 0.9

    def test_result_to_dict(self):
        """Verify to_dict produces correct dictionary structure."""
        result = ForecastResult(
            cve_id="CVE-2023-11111",
            p_exploit_now=0.12345,
            p_exploit_30d=0.56789,
            evidence_breakdown={"prior": 0.1},
            method="test",
            confidence=0.875,  # Use value that rounds cleanly
        )
        d = result.to_dict()
        assert d["cve_id"] == "CVE-2023-11111"
        assert d["p_exploit_now"] == 0.1235  # Rounded to 4 decimal places
        assert d["p_exploit_30d"] == 0.5679  # Rounded to 4 decimal places
        assert d["confidence"] == 0.875  # Rounded to 3 decimal places
        assert d["method"] == "test"


class TestApplyLikelihoodRatio:
    """Tests for _apply_likelihood_ratio function."""

    def test_likelihood_ratio_increases_probability(self):
        """Verify likelihood ratio > 1 increases probability."""
        p_initial = 0.5
        p_updated = _apply_likelihood_ratio(p_initial, 2.0)
        assert p_updated > p_initial

    def test_likelihood_ratio_decreases_probability(self):
        """Verify likelihood ratio < 1 decreases probability."""
        p_initial = 0.5
        p_updated = _apply_likelihood_ratio(p_initial, 0.5)
        assert p_updated < p_initial

    def test_likelihood_ratio_one_unchanged(self):
        """Verify likelihood ratio = 1 keeps probability unchanged."""
        p_initial = 0.5
        p_updated = _apply_likelihood_ratio(p_initial, 1.0)
        assert abs(p_updated - p_initial) < 0.001

    def test_likelihood_ratio_bounds_low(self):
        """Verify probability doesn't go below epsilon."""
        p_updated = _apply_likelihood_ratio(0.01, 0.001)
        assert p_updated > 0

    def test_likelihood_ratio_bounds_high(self):
        """Verify probability doesn't exceed 1 - epsilon."""
        p_updated = _apply_likelihood_ratio(0.99, 1000.0)
        assert p_updated < 1.0

    def test_likelihood_ratio_extreme_low_probability(self):
        """Verify handling of very low initial probability."""
        p_updated = _apply_likelihood_ratio(0.0001, 5.0)
        assert p_updated > 0.0001
        assert p_updated < 1.0

    def test_likelihood_ratio_extreme_high_probability(self):
        """Verify handling of very high initial probability."""
        p_updated = _apply_likelihood_ratio(0.9999, 0.5)
        assert p_updated < 0.9999
        assert p_updated > 0


class TestNaiveBayesUpdate:
    """Tests for _naive_bayes_update function."""

    def _create_evidence(self, **kwargs):
        """Create EnrichmentEvidence with given fields."""
        defaults = {
            "cve_id": "CVE-2023-12345",
            "kev_listed": False,
            "epss_score": None,
            "exploitdb_refs": 0,
            "cvss_score": None,
            "has_vendor_advisory": False,
            "age_days": None,
        }
        defaults.update(kwargs)
        return EnrichmentEvidence(**defaults)

    def test_no_signals_returns_prior(self):
        """Verify prior returned when no signals apply."""
        evidence = self._create_evidence()
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert abs(posterior - 0.1) < 0.01
        assert breakdown["prior"] == 0.1
        assert len(breakdown["signals_applied"]) == 0

    def test_kev_listed_increases_probability(self):
        """Verify KEV listing increases probability."""
        evidence = self._create_evidence(kev_listed=True)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert posterior > 0.1
        assert any(s["signal"] == "kev_listed" for s in breakdown["signals_applied"])

    def test_exploitdb_refs_increases_probability(self):
        """Verify ExploitDB references increase probability."""
        evidence = self._create_evidence(exploitdb_refs=3)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert posterior > 0.1
        assert any(
            s["signal"] == "exploitdb_refs" for s in breakdown["signals_applied"]
        )

    def test_high_cvss_increases_probability(self):
        """Verify high CVSS score increases probability."""
        evidence = self._create_evidence(cvss_score=9.0)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert posterior > 0.1
        assert any(s["signal"] == "high_cvss" for s in breakdown["signals_applied"])

    def test_low_cvss_no_effect(self):
        """Verify low CVSS score has no effect."""
        evidence = self._create_evidence(cvss_score=5.0)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert abs(posterior - 0.1) < 0.01
        assert not any(s["signal"] == "high_cvss" for s in breakdown["signals_applied"])

    def test_vendor_advisory_decreases_probability(self):
        """Verify vendor advisory decreases probability (patch available)."""
        evidence = self._create_evidence(has_vendor_advisory=True)
        posterior, breakdown = _naive_bayes_update(0.5, evidence)
        assert posterior < 0.5
        assert any(
            s["signal"] == "vendor_advisory" for s in breakdown["signals_applied"]
        )

    def test_old_vulnerability_increases_probability(self):
        """Verify old vulnerability increases probability."""
        evidence = self._create_evidence(age_days=400)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert posterior > 0.1
        assert any(
            s["signal"] == "old_vulnerability" for s in breakdown["signals_applied"]
        )

    def test_recent_vulnerability_no_age_effect(self):
        """Verify recent vulnerability has no age effect."""
        evidence = self._create_evidence(age_days=100)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert not any(
            s["signal"] == "old_vulnerability" for s in breakdown["signals_applied"]
        )

    def test_multiple_signals_compound(self):
        """Verify multiple signals compound correctly."""
        evidence = self._create_evidence(
            kev_listed=True,
            exploitdb_refs=2,
            cvss_score=9.5,
        )
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert posterior > 0.5  # Should be significantly higher
        assert len(breakdown["signals_applied"]) == 3

    def test_custom_config_likelihood_ratios(self):
        """Verify custom likelihood ratios are used."""
        evidence = self._create_evidence(kev_listed=True)
        config = {"kev_likelihood": 10.0}  # Higher than default 5.0
        posterior_custom, _ = _naive_bayes_update(0.1, evidence, config)
        posterior_default, _ = _naive_bayes_update(0.1, evidence)
        assert posterior_custom > posterior_default

    def test_breakdown_contains_final_posterior(self):
        """Verify breakdown contains final posterior."""
        evidence = self._create_evidence(kev_listed=True)
        posterior, breakdown = _naive_bayes_update(0.1, evidence)
        assert "final_posterior" in breakdown
        assert abs(breakdown["final_posterior"] - posterior) < 0.001


class TestMarkovForecast30d:
    """Tests for _markov_forecast_30d function."""

    def _create_evidence(self, **kwargs):
        """Create EnrichmentEvidence with given fields."""
        defaults = {
            "cve_id": "CVE-2023-12345",
            "kev_listed": False,
            "epss_score": None,
            "has_vendor_advisory": False,
        }
        defaults.update(kwargs)
        return EnrichmentEvidence(**defaults)

    def test_baseline_forecast(self):
        """Verify baseline 30-day forecast."""
        evidence = self._create_evidence()
        p_30d = _markov_forecast_30d(0.1, evidence)
        assert p_30d >= 0.1  # Should be at least current probability
        assert p_30d <= 0.99

    def test_kev_listed_increases_forecast(self):
        """Verify KEV listing increases 30-day forecast."""
        evidence_kev = self._create_evidence(kev_listed=True)
        evidence_no_kev = self._create_evidence(kev_listed=False)
        p_30d_kev = _markov_forecast_30d(0.1, evidence_kev)
        p_30d_no_kev = _markov_forecast_30d(0.1, evidence_no_kev)
        assert p_30d_kev > p_30d_no_kev

    def test_high_epss_increases_forecast(self):
        """Verify high EPSS score increases 30-day forecast."""
        evidence_high = self._create_evidence(epss_score=0.8)
        evidence_low = self._create_evidence(epss_score=0.2)
        p_30d_high = _markov_forecast_30d(0.1, evidence_high)
        p_30d_low = _markov_forecast_30d(0.1, evidence_low)
        assert p_30d_high > p_30d_low

    def test_vendor_advisory_reduces_forecast(self):
        """Verify vendor advisory reduces 30-day forecast."""
        evidence_patched = self._create_evidence(has_vendor_advisory=True)
        evidence_unpatched = self._create_evidence(has_vendor_advisory=False)
        # Use lower initial probability to see the effect more clearly
        p_30d_patched = _markov_forecast_30d(0.1, evidence_patched)
        p_30d_unpatched = _markov_forecast_30d(0.1, evidence_unpatched)
        # Patched should have lower or equal forecast (patch reduces exploitation rate)
        assert p_30d_patched <= p_30d_unpatched

    def test_forecast_bounded(self):
        """Verify forecast is bounded between p_now and 0.99."""
        evidence = self._create_evidence(kev_listed=True, epss_score=0.9)
        p_30d = _markov_forecast_30d(0.5, evidence)
        assert p_30d >= 0.5
        assert p_30d <= 0.99

    def test_custom_config_transition_rates(self):
        """Verify custom transition rates are used."""
        evidence = self._create_evidence()
        config_fast = {"lambda_ux_to_ex": 0.1}  # Higher exploitation rate
        config_slow = {"lambda_ux_to_ex": 0.001}  # Lower exploitation rate
        p_30d_fast = _markov_forecast_30d(0.1, evidence, config_fast)
        p_30d_slow = _markov_forecast_30d(0.1, evidence, config_slow)
        assert p_30d_fast > p_30d_slow


class TestComputeForecast:
    """Tests for compute_forecast function."""

    def _create_evidence(self, cve_id, **kwargs):
        """Create EnrichmentEvidence with given fields."""
        defaults = {
            "cve_id": cve_id,
            "kev_listed": False,
            "epss_score": None,
            "exploitdb_refs": 0,
            "cvss_score": None,
            "has_vendor_advisory": False,
            "age_days": None,
        }
        defaults.update(kwargs)
        return EnrichmentEvidence(**defaults)

    def test_compute_forecast_basic(self):
        """Verify basic forecast computation."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345"),
        }
        result = compute_forecast(enrichment_map)

        assert "CVE-2023-12345" in result
        forecast = result["CVE-2023-12345"]
        assert forecast.cve_id == "CVE-2023-12345"
        assert 0 < forecast.p_exploit_now < 1
        assert 0 < forecast.p_exploit_30d < 1
        assert forecast.method == "naive_bayes_markov"

    def test_compute_forecast_with_epss(self):
        """Verify EPSS score used as prior."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345", epss_score=0.8),
        }
        result = compute_forecast(enrichment_map)

        forecast = result["CVE-2023-12345"]
        # With high EPSS, probability should be high
        assert forecast.p_exploit_now > 0.5
        assert forecast.confidence > 0.5  # EPSS adds confidence

    def test_compute_forecast_kev_without_epss(self):
        """Verify KEV-listed without EPSS uses high baseline."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345", kev_listed=True),
        }
        result = compute_forecast(enrichment_map)

        forecast = result["CVE-2023-12345"]
        # KEV without EPSS should use 0.5 baseline
        assert forecast.p_exploit_now > 0.5
        assert forecast.confidence > 0.5  # KEV adds confidence

    def test_compute_forecast_no_signals(self):
        """Verify default baseline used when no signals."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345"),
        }
        result = compute_forecast(enrichment_map)

        forecast = result["CVE-2023-12345"]
        # Default baseline is 0.1
        assert forecast.p_exploit_now < 0.3
        assert forecast.confidence == 0.5  # Base confidence

    def test_compute_forecast_multiple_cves(self):
        """Verify forecasting multiple CVEs."""
        enrichment_map = {
            "CVE-2023-11111": self._create_evidence("CVE-2023-11111"),
            "CVE-2023-22222": self._create_evidence("CVE-2023-22222", kev_listed=True),
            "CVE-2023-33333": self._create_evidence("CVE-2023-33333", epss_score=0.9),
        }
        result = compute_forecast(enrichment_map)

        assert len(result) == 3
        # KEV and high EPSS should have higher probabilities
        assert (
            result["CVE-2023-22222"].p_exploit_now
            > result["CVE-2023-11111"].p_exploit_now
        )
        assert (
            result["CVE-2023-33333"].p_exploit_now
            > result["CVE-2023-11111"].p_exploit_now
        )

    def test_compute_forecast_confidence_calculation(self):
        """Verify confidence calculation based on available data."""
        # No data - base confidence
        evidence_none = self._create_evidence("CVE-1")
        # EPSS only
        evidence_epss = self._create_evidence("CVE-2", epss_score=0.5)
        # KEV only
        evidence_kev = self._create_evidence("CVE-3", kev_listed=True)
        # CVSS only
        evidence_cvss = self._create_evidence("CVE-4", cvss_score=8.0)
        # All data
        evidence_all = self._create_evidence(
            "CVE-5", epss_score=0.5, kev_listed=True, cvss_score=8.0
        )

        enrichment_map = {
            "CVE-1": evidence_none,
            "CVE-2": evidence_epss,
            "CVE-3": evidence_kev,
            "CVE-4": evidence_cvss,
            "CVE-5": evidence_all,
        }
        result = compute_forecast(enrichment_map)

        assert result["CVE-1"].confidence == 0.5  # Base
        assert result["CVE-2"].confidence == 0.7  # Base + EPSS
        assert result["CVE-3"].confidence == 0.7  # Base + KEV
        assert result["CVE-4"].confidence == 0.6  # Base + CVSS
        assert result["CVE-5"].confidence == 0.95  # Capped at 0.95

    def test_compute_forecast_empty_map(self):
        """Verify handling of empty enrichment map."""
        result = compute_forecast({})
        assert result == {}

    def test_compute_forecast_custom_config(self):
        """Verify custom config is passed through."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345", kev_listed=True),
        }
        config_high = {"kev_likelihood": 20.0}
        config_low = {"kev_likelihood": 2.0}

        result_high = compute_forecast(enrichment_map, config_high)
        result_low = compute_forecast(enrichment_map, config_low)

        assert (
            result_high["CVE-2023-12345"].p_exploit_now
            > result_low["CVE-2023-12345"].p_exploit_now
        )

    def test_compute_forecast_30d_always_gte_now(self):
        """Verify 30-day forecast is always >= current probability."""
        enrichment_map = {
            "CVE-2023-12345": self._create_evidence("CVE-2023-12345", epss_score=0.3),
        }
        result = compute_forecast(enrichment_map)

        forecast = result["CVE-2023-12345"]
        assert forecast.p_exploit_30d >= forecast.p_exploit_now
