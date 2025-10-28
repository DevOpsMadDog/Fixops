"""Unit tests for risk forecasting module."""

from __future__ import annotations

from risk.enrichment import EnrichmentEvidence
from risk.forecasting import (
    ForecastResult,
    _markov_forecast_30d,
    _naive_bayes_update,
    compute_forecast,
)


class TestForecastResult:
    """Test ForecastResult dataclass."""

    def test_create_forecast(self):
        """Test creating forecast result."""
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.75,
            p_exploit_30d=0.85,
            evidence_breakdown={"kev": 5.0, "epss": 3.0},
            method="naive_bayes",
            confidence=0.80,
        )

        assert forecast.cve_id == "CVE-2023-1234"
        assert forecast.p_exploit_now == 0.75
        assert forecast.p_exploit_30d == 0.85
        assert forecast.method == "naive_bayes"
        assert forecast.confidence == 0.80

    def test_to_dict(self):
        """Test converting forecast to dictionary."""
        forecast = ForecastResult(
            cve_id="CVE-2023-1234",
            p_exploit_now=0.75,
            p_exploit_30d=0.85,
        )

        result = forecast.to_dict()

        assert isinstance(result, dict)
        assert result["cve_id"] == "CVE-2023-1234"
        assert result["p_exploit_now"] == 0.75
        assert result["p_exploit_30d"] == 0.85


class TestNaiveBayesUpdate:
    """Test Naive Bayes probability update."""

    def test_bayes_update_kev_listed(self):
        """Test Bayes update with KEV listing."""
        prior = 0.05
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert posterior > prior
        assert "signals_applied" in breakdown
        assert len(breakdown["signals_applied"]) > 0
        assert breakdown["signals_applied"][0]["signal"] == "kev_listed"
        assert breakdown["signals_applied"][0]["likelihood_ratio"] == 5.0

    def test_bayes_update_exploitdb(self):
        """Test Bayes update with ExploitDB references."""
        prior = 0.05
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            exploitdb_refs=3,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert posterior > prior
        assert "signals_applied" in breakdown
        assert len(breakdown["signals_applied"]) > 0
        assert breakdown["signals_applied"][0]["signal"] == "exploitdb_refs"

    def test_bayes_update_high_cvss(self):
        """Test Bayes update with high CVSS score."""
        prior = 0.05
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            cvss_score=9.8,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert posterior > prior
        assert "signals_applied" in breakdown
        assert len(breakdown["signals_applied"]) > 0
        assert breakdown["signals_applied"][0]["signal"] == "high_cvss"

    def test_bayes_update_vendor_advisory(self):
        """Test Bayes update with vendor advisory (reduces probability)."""
        prior = 0.50
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            has_vendor_advisory=True,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert posterior < prior
        assert "signals_applied" in breakdown
        assert len(breakdown["signals_applied"]) > 0
        assert breakdown["signals_applied"][0]["signal"] == "vendor_advisory"

    def test_bayes_update_old_vulnerability(self):
        """Test Bayes update with old vulnerability."""
        prior = 0.05
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            age_days=400,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert posterior > prior
        assert "signals_applied" in breakdown
        assert len(breakdown["signals_applied"]) > 0
        assert breakdown["signals_applied"][0]["signal"] == "old_vulnerability"

    def test_bayes_update_clamping(self):
        """Test that probability is clamped to valid range."""
        prior = 0.95
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
            exploitdb_refs=5,
            cvss_score=10.0,
        )
        config = {}

        posterior, breakdown = _naive_bayes_update(prior, evidence, config)

        assert 0.01 <= posterior <= 0.99


class TestMarkovForecast:
    """Test Markov forecasting."""

    def test_markov_forecast_kev_boost(self):
        """Test Markov forecast with KEV boost."""
        p_now = 0.20
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
        )
        config = {}

        p_30d = _markov_forecast_30d(p_now, evidence, config)

        assert p_30d > p_now

    def test_markov_forecast_patch_available(self):
        """Test Markov forecast with patch available."""
        p_now = 0.50
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            has_vendor_advisory=True,
        )
        config = {}

        p_30d = _markov_forecast_30d(p_now, evidence, config)

        assert p_30d < p_now

    def test_markov_forecast_no_evidence(self):
        """Test Markov forecast with no special evidence."""
        p_now = 0.30
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
        )
        config = {}

        p_30d = _markov_forecast_30d(p_now, evidence, config)

        assert p_30d >= p_now

    def test_markov_forecast_clamping(self):
        """Test that forecast is clamped to valid range."""
        p_now = 0.95
        evidence = EnrichmentEvidence(
            cve_id="CVE-2023-1234",
            kev_listed=True,
        )
        config = {}

        p_30d = _markov_forecast_30d(p_now, evidence, config)

        assert 0.0 <= p_30d <= 1.0


class TestComputeForecast:
    """Test compute_forecast function."""

    def test_compute_forecast_basic(self):
        """Test basic forecast computation."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                kev_listed=True,
                epss_score=0.85,
                cvss_score=9.8,
            )
        }
        config = {}

        result = compute_forecast(enrichment_map, config)

        assert len(result) == 1
        assert "CVE-2023-1234" in result

        forecast = result["CVE-2023-1234"]
        assert forecast.cve_id == "CVE-2023-1234"
        assert forecast.p_exploit_now > 0.05  # Higher than prior
        assert forecast.p_exploit_30d >= forecast.p_exploit_now

    def test_compute_forecast_multiple_cves(self):
        """Test forecast with multiple CVEs."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                kev_listed=True,
            ),
            "CVE-2023-5678": EnrichmentEvidence(
                cve_id="CVE-2023-5678",
                cvss_score=5.0,
            ),
        }
        config = {}

        result = compute_forecast(enrichment_map, config)

        assert len(result) == 2
        assert "CVE-2023-1234" in result
        assert "CVE-2023-5678" in result

        assert (
            result["CVE-2023-1234"].p_exploit_now
            > result["CVE-2023-5678"].p_exploit_now
        )

    def test_compute_forecast_custom_config(self):
        """Test forecast with custom configuration."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
            )
        }
        config = {
            "prior_exploit": 0.10,  # Higher prior
        }

        result = compute_forecast(enrichment_map, config)

        forecast = result["CVE-2023-1234"]
        assert forecast.p_exploit_now >= 0.10

    def test_compute_forecast_empty_map(self):
        """Test forecast with empty enrichment map."""
        result = compute_forecast({}, {})

        assert len(result) == 0

    def test_compute_forecast_confidence(self):
        """Test that confidence is calculated."""
        enrichment_map = {
            "CVE-2023-1234": EnrichmentEvidence(
                cve_id="CVE-2023-1234",
                kev_listed=True,
                epss_score=0.85,
            )
        }
        config = {}

        result = compute_forecast(enrichment_map, config)

        forecast = result["CVE-2023-1234"]
        assert 0.0 <= forecast.confidence <= 1.0
        assert forecast.confidence > 0.5
