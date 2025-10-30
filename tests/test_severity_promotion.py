"""Tests for severity promotion with evidence tracking."""

from __future__ import annotations

from core.severity_promotion import (
    DEFAULT_PROMOTION_RULES,
    PROMOTION_RULE_VERSION,
    PromotionRule,
    SeverityPromotionEngine,
    SeverityPromotionEvidence,
)


class TestSeverityPromotionEvidence:
    """Test SeverityPromotionEvidence dataclass."""

    def test_to_dict_promoted(self):
        """Test to_dict for promoted severity."""
        evidence = SeverityPromotionEvidence(
            cve_id="CVE-2024-1234",
            was_promoted=True,
            prior_severity="medium",
            new_severity="critical",
            first_seen_at="2024-01-15T10:00:00Z",
            first_exploit_report_at="2024-01-20T15:30:00Z",
            evidence_source="CISA KEV catalog (added: 2024-01-20) - https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            promotion_reason="KEV-listed: CISA KEV catalog - actively exploited in the wild",
            metadata={"signal_type": "kev"},
        )

        result = evidence.to_dict()

        assert result["cve_id"] == "CVE-2024-1234"
        assert result["was_promoted"] is True
        assert result["prior_severity"] == "medium"
        assert result["new_severity"] == "critical"
        assert result["first_seen_at"] == "2024-01-15T10:00:00Z"
        assert result["first_exploit_report_at"] == "2024-01-20T15:30:00Z"
        assert "CISA KEV catalog" in result["evidence_source"]
        assert result["promotion_rule_version"] == PROMOTION_RULE_VERSION
        assert "KEV-listed" in result["promotion_reason"]
        assert result["metadata"]["signal_type"] == "kev"

    def test_to_dict_not_promoted(self):
        """Test to_dict for non-promoted severity."""
        evidence = SeverityPromotionEvidence(
            cve_id="CVE-2024-5678",
            was_promoted=False,
            prior_severity="low",
            new_severity="low",
            first_seen_at="2024-01-15T10:00:00Z",
            promotion_reason="No promotion criteria met",
        )

        result = evidence.to_dict()

        assert result["cve_id"] == "CVE-2024-5678"
        assert result["was_promoted"] is False
        assert result["prior_severity"] == "low"
        assert result["new_severity"] == "low"
        assert result["first_exploit_report_at"] is None
        assert result["evidence_source"] is None


class TestPromotionRule:
    """Test PromotionRule class."""

    def test_applies_to_kev_signal(self):
        """Test KEV promotion rule application."""
        rule = PromotionRule(
            signal_type="kev",
            promote_from=["low", "medium", "high"],
            promote_to="critical",
        )

        assert rule.applies_to("medium", True)
        assert rule.applies_to("high", True)
        assert rule.applies_to("low", True)
        assert not rule.applies_to("critical", True)
        assert not rule.applies_to("medium", False)

    def test_applies_to_epss_threshold(self):
        """Test EPSS threshold-based promotion rule."""
        rule = PromotionRule(
            signal_type="epss_high",
            threshold=0.7,
            promote_from=["low", "medium"],
            promote_to="high",
        )

        assert rule.applies_to("medium", 0.75)
        assert rule.applies_to("low", 0.9)
        assert not rule.applies_to("medium", 0.5)
        assert not rule.applies_to("high", 0.8)
        assert not rule.applies_to("medium", "invalid")

    def test_applies_to_empty_promote_from(self):
        """Test rule with empty promote_from list applies to all severities."""
        rule = PromotionRule(
            signal_type="kev",
            promote_from=[],
            promote_to="critical",
        )

        assert rule.applies_to("low", True)
        assert rule.applies_to("medium", True)
        assert rule.applies_to("high", True)
        assert rule.applies_to("critical", True)


class TestSeverityPromotionEngine:
    """Test SeverityPromotionEngine class."""

    def test_init_default_rules(self):
        """Test initialization with default rules."""
        engine = SeverityPromotionEngine()

        assert engine.enabled is True
        assert len(engine.rules) == len(DEFAULT_PROMOTION_RULES)

    def test_init_custom_rules(self):
        """Test initialization with custom rules."""
        custom_rules = [
            PromotionRule(
                signal_type="custom",
                promote_from=["low"],
                promote_to="medium",
            )
        ]
        engine = SeverityPromotionEngine(rules=custom_rules)

        assert len(engine.rules) == 1
        assert engine.rules[0].signal_type == "custom"

    def test_init_disabled(self):
        """Test initialization with disabled engine."""
        engine = SeverityPromotionEngine(enabled=False)

        assert engine.enabled is False

    def test_evaluate_promotion_kev_medium_to_critical(self):
        """Test promotion from medium to critical for KEV-listed CVE."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "signals": {
                "kev": {
                    "matches": [
                        {
                            "cve_id": "CVE-2024-1234",
                            "value": True,
                        }
                    ]
                }
            },
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                        "dateAdded": "2024-01-20",
                    }
                ]
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-1234",
            current_severity="medium",
            exploit_signals=exploit_signals,
            first_seen_at="2024-01-15T10:00:00Z",
        )

        assert result is not None
        assert result.was_promoted is True
        assert result.prior_severity == "medium"
        assert result.new_severity == "critical"
        assert result.first_seen_at == "2024-01-15T10:00:00Z"
        assert result.first_exploit_report_at == "2024-01-20"
        assert "CISA KEV catalog" in result.evidence_source
        assert "2024-01-20" in result.evidence_source
        assert "KEV-listed" in result.promotion_reason
        assert result.metadata["signal_type"] == "kev"

    def test_evaluate_promotion_kev_high_to_critical(self):
        """Test promotion from high to critical for KEV-listed CVE."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-5678",
                        "dateAdded": "2024-02-01",
                    }
                ]
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-5678",
            current_severity="high",
            exploit_signals=exploit_signals,
        )

        assert result is not None
        assert result.was_promoted is True
        assert result.prior_severity == "high"
        assert result.new_severity == "critical"

    def test_evaluate_promotion_kev_critical_no_promotion(self):
        """Test no promotion for already critical KEV-listed CVE."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-9999",
                        "dateAdded": "2024-02-01",
                    }
                ]
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-9999",
            current_severity="critical",
            exploit_signals=exploit_signals,
        )

        assert result is not None
        assert result.was_promoted is False
        assert result.prior_severity == "critical"
        assert result.new_severity == "critical"

    def test_evaluate_promotion_epss_high_medium_to_high(self):
        """Test promotion from medium to high for high EPSS score."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "signals": {
                "epss": {
                    "matches": [
                        {
                            "cve_id": "CVE-2024-7777",
                            "value": 0.85,
                        }
                    ]
                }
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-7777",
            current_severity="medium",
            exploit_signals=exploit_signals,
        )

        assert result is not None
        assert result.was_promoted is True
        assert result.prior_severity == "medium"
        assert result.new_severity == "high"
        assert "EPSS score 0.8500" in result.evidence_source
        assert result.metadata["signal_type"] == "epss"
        assert result.metadata["epss_score"] == 0.85

    def test_evaluate_promotion_epss_low_threshold_no_promotion(self):
        """Test no promotion for EPSS score below threshold."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "signals": {
                "epss": {
                    "matches": [
                        {
                            "cve_id": "CVE-2024-8888",
                            "value": 0.5,
                        }
                    ]
                }
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-8888",
            current_severity="medium",
            exploit_signals=exploit_signals,
        )

        assert result is not None
        assert result.was_promoted is False
        assert result.prior_severity == "medium"
        assert result.new_severity == "medium"

    def test_evaluate_promotion_no_signals(self):
        """Test no promotion when no exploit signals present."""
        engine = SeverityPromotionEngine()
        exploit_signals = {}

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-0000",
            current_severity="medium",
            exploit_signals=exploit_signals,
        )

        assert result is not None
        assert result.was_promoted is False
        assert result.prior_severity == "medium"
        assert result.new_severity == "medium"
        assert "No promotion criteria met" in result.promotion_reason

    def test_evaluate_promotion_disabled_engine(self):
        """Test that disabled engine returns None."""
        engine = SeverityPromotionEngine(enabled=False)
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                        "dateAdded": "2024-01-20",
                    }
                ]
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-1234",
            current_severity="medium",
            exploit_signals=exploit_signals,
        )

        assert result is None

    def test_check_kev_signal_case_insensitive(self):
        """Test KEV signal check is case-insensitive."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "cve-2024-1234",
                    }
                ]
            },
        }

        result = engine._check_kev_signal("CVE-2024-1234", exploit_signals)
        assert result is True

    def test_extract_kev_date_missing(self):
        """Test KEV date extraction when date is missing."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                    }
                ]
            },
        }

        result = engine._extract_kev_date("CVE-2024-1234", exploit_signals)
        assert result is None

    def test_extract_epss_score_from_dict(self):
        """Test EPSS score extraction from dict format."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "epss": {
                "CVE-2024-1234": 0.75,
            }
        }

        result = engine._extract_epss_score("CVE-2024-1234", exploit_signals)
        assert result == 0.75

    def test_build_kev_evidence_source_with_date(self):
        """Test KEV evidence source building with date."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                        "dateAdded": "2024-01-20",
                    }
                ]
            },
        }

        result = engine._build_kev_evidence_source("CVE-2024-1234", exploit_signals)
        assert "2024-01-20" in result
        assert "CISA KEV catalog" in result
        assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in result

    def test_build_kev_evidence_source_without_date(self):
        """Test KEV evidence source building without date."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2024-1234",
                    }
                ]
            },
        }

        result = engine._build_kev_evidence_source("CVE-2024-1234", exploit_signals)
        assert "CISA KEV catalog" in result
        assert "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" in result
        assert "added:" not in result


class TestSeverityPromotionIntegration:
    """Integration tests for severity promotion."""

    def test_multiple_cves_with_mixed_promotions(self):
        """Test promotion evaluation for multiple CVEs with different outcomes."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "signals": {
                "kev": {
                    "matches": [
                        {"cve_id": "CVE-2024-0001", "value": True},
                    ]
                },
                "epss": {
                    "matches": [
                        {"cve_id": "CVE-2024-0002", "value": 0.8},
                        {"cve_id": "CVE-2024-0003", "value": 0.3},
                    ]
                },
            },
            "kev": {
                "vulnerabilities": [
                    {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-15"}
                ]
            },
        }

        cves = [
            ("CVE-2024-0001", "medium"),  # KEV -> critical
            ("CVE-2024-0002", "low"),  # EPSS high -> high
            ("CVE-2024-0003", "medium"),  # EPSS low -> no promotion
            ("CVE-2024-0004", "high"),  # No signals -> no promotion
        ]

        results = []
        for cve_id, severity in cves:
            result = engine.evaluate_promotion(
                cve_id=cve_id,
                current_severity=severity,
                exploit_signals=exploit_signals,
            )
            results.append(result)

        assert results[0].was_promoted is True
        assert results[0].new_severity == "critical"

        assert results[1].was_promoted is True
        assert results[1].new_severity == "high"

        assert results[2].was_promoted is False
        assert results[2].new_severity == "medium"

        assert results[3].was_promoted is False
        assert results[3].new_severity == "high"

    def test_promotion_rule_version_consistency(self):
        """Test that all promotions use consistent rule version."""
        engine = SeverityPromotionEngine()
        exploit_signals = {
            "kev": {
                "vulnerabilities": [
                    {"cveID": "CVE-2024-1234", "dateAdded": "2024-01-20"}
                ]
            },
        }

        result = engine.evaluate_promotion(
            cve_id="CVE-2024-1234",
            current_severity="medium",
            exploit_signals=exploit_signals,
        )

        assert result.promotion_rule_version == PROMOTION_RULE_VERSION
        assert result.promotion_rule_version == "1.0.0"
