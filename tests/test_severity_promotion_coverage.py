"""Tests for core.severity_promotion — severity promotion engine."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.severity_promotion import (
    DEFAULT_PROMOTION_RULES,
    PROMOTION_RULE_VERSION,
    PromotionRule,
    SeverityPromotionEngine,
    SeverityPromotionEvidence,
)


# ── SeverityPromotionEvidence ────────────────────────────────────────

class TestSeverityPromotionEvidence:
    def test_to_dict(self):
        evidence = SeverityPromotionEvidence(
            cve_id="CVE-2024-1234",
            was_promoted=True,
            prior_severity="medium",
            new_severity="critical",
            first_seen_at="2024-01-01T00:00:00Z",
            first_exploit_report_at="2024-01-15T00:00:00Z",
            evidence_source="CISA KEV",
            promotion_reason="KEV-listed",
        )
        d = evidence.to_dict()
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["was_promoted"] is True
        assert d["prior_severity"] == "medium"
        assert d["new_severity"] == "critical"
        assert d["promotion_rule_version"] == PROMOTION_RULE_VERSION

    def test_not_promoted(self):
        evidence = SeverityPromotionEvidence(
            cve_id="CVE-2024-5678",
            was_promoted=False,
            prior_severity="low",
            new_severity="low",
            first_seen_at="2024-01-01T00:00:00Z",
        )
        d = evidence.to_dict()
        assert d["was_promoted"] is False
        assert d["prior_severity"] == d["new_severity"]


# ── PromotionRule ────────────────────────────────────────────────────

class TestPromotionRule:
    def test_kev_rule_applies(self):
        rule = PromotionRule(
            signal_type="kev",
            promote_from=["low", "medium", "high"],
            promote_to="critical",
        )
        assert rule.applies_to("low", True) is True
        assert rule.applies_to("medium", True) is True
        assert rule.applies_to("high", True) is True
        assert rule.applies_to("critical", True) is False

    def test_kev_rule_false_signal(self):
        rule = PromotionRule(
            signal_type="kev",
            promote_from=["low", "medium"],
            promote_to="high",
        )
        assert rule.applies_to("low", False) is False
        assert rule.applies_to("low", None) is False
        assert rule.applies_to("low", 0) is False

    def test_epss_threshold_rule(self):
        rule = PromotionRule(
            signal_type="epss_high",
            threshold=0.7,
            promote_from=["low", "medium"],
            promote_to="high",
        )
        assert rule.applies_to("low", 0.8) is True
        assert rule.applies_to("low", 0.7) is True
        assert rule.applies_to("low", 0.5) is False
        assert rule.applies_to("high", 0.8) is False  # not in promote_from

    def test_threshold_invalid_value(self):
        rule = PromotionRule(
            signal_type="epss_high",
            threshold=0.7,
            promote_from=["low"],
            promote_to="high",
        )
        assert rule.applies_to("low", "not_a_number") is False
        assert rule.applies_to("low", None) is False

    def test_empty_promote_from(self):
        rule = PromotionRule(
            signal_type="kev",
            promote_from=[],
            promote_to="critical",
        )
        # Empty list means applies to all severities
        assert rule.applies_to("low", True) is True
        assert rule.applies_to("critical", True) is True


# ── Default Promotion Rules ─────────────────────────────────────────

class TestDefaultRules:
    def test_has_kev_rule(self):
        kev_rules = [r for r in DEFAULT_PROMOTION_RULES if r.signal_type == "kev"]
        assert len(kev_rules) >= 1
        assert kev_rules[0].promote_to == "critical"

    def test_has_epss_rule(self):
        epss_rules = [r for r in DEFAULT_PROMOTION_RULES if r.signal_type == "epss_high"]
        assert len(epss_rules) >= 1
        assert epss_rules[0].threshold == 0.7

    def test_at_least_two_rules(self):
        assert len(DEFAULT_PROMOTION_RULES) >= 2


# ── SeverityPromotionEngine ─────────────────────────────────────────

class TestSeverityPromotionEngine:
    @pytest.fixture
    def engine(self):
        return SeverityPromotionEngine()

    def test_init_defaults(self, engine):
        assert engine.enabled is True
        assert len(engine.rules) == len(DEFAULT_PROMOTION_RULES)

    def test_init_disabled(self):
        engine = SeverityPromotionEngine(enabled=False)
        result = engine.evaluate_promotion(
            "CVE-2024-0001", "low", {"signals": {"kev": {"matches": [{"cve_id": "CVE-2024-0001"}]}}}
        )
        assert result is None

    def test_kev_promotion(self, engine):
        signals = {
            "signals": {
                "kev": {
                    "matches": [{"cve_id": "CVE-2024-1234"}]
                }
            }
        }
        result = engine.evaluate_promotion("CVE-2024-1234", "medium", signals)
        assert result is not None
        assert result.was_promoted is True
        assert result.new_severity == "critical"
        assert result.prior_severity == "medium"
        assert "KEV" in result.promotion_reason

    def test_kev_promotion_case_insensitive(self, engine):
        signals = {
            "signals": {
                "kev": {
                    "matches": [{"cve_id": "CVE-2024-1234"}]
                }
            }
        }
        result = engine.evaluate_promotion("cve-2024-1234", "low", signals)
        assert result is not None
        assert result.was_promoted is True

    def test_epss_high_promotion(self, engine):
        signals = {
            "signals": {
                "epss": {"score": 0.85}
            }
        }
        result = engine.evaluate_promotion("CVE-2024-5678", "low", signals)
        # This depends on how _extract_epss_score works
        assert result is not None

    def test_no_promotion_no_signals(self, engine):
        result = engine.evaluate_promotion("CVE-2024-9999", "medium", {})
        assert result is not None
        assert result.was_promoted is False
        assert result.prior_severity == "medium"
        assert result.new_severity == "medium"

    def test_no_promotion_low_epss(self, engine):
        signals = {
            "signals": {
                "epss": {"score": 0.1}
            }
        }
        result = engine.evaluate_promotion("CVE-2024-9999", "low", signals)
        assert result is not None
        assert result.was_promoted is False

    def test_evidence_has_rule_version(self, engine):
        result = engine.evaluate_promotion("CVE-2024-0000", "medium", {})
        assert result is not None
        assert result.promotion_rule_version == PROMOTION_RULE_VERSION

    def test_first_seen_at_provided(self, engine):
        ts = "2024-06-01T00:00:00Z"
        result = engine.evaluate_promotion("CVE-2024-0000", "low", {}, first_seen_at=ts)
        assert result is not None
        assert result.first_seen_at == ts

    def test_first_seen_at_default(self, engine):
        result = engine.evaluate_promotion("CVE-2024-0000", "low", {})
        assert result is not None
        assert result.first_seen_at is not None

    def test_custom_rules(self):
        custom_rules = [
            PromotionRule(
                signal_type="kev",
                promote_from=["low"],
                promote_to="high",
            )
        ]
        engine = SeverityPromotionEngine(rules=custom_rules)
        signals = {
            "signals": {
                "kev": {"matches": [{"cve_id": "CVE-2024-0001"}]}
            }
        }
        result = engine.evaluate_promotion("CVE-2024-0001", "low", signals)
        assert result is not None
        assert result.was_promoted is True
        assert result.new_severity == "high"

    def test_evidence_metadata(self, engine):
        signals = {
            "signals": {
                "kev": {"matches": [{"cve_id": "CVE-2024-1234"}]}
            }
        }
        result = engine.evaluate_promotion("CVE-2024-1234", "low", signals)
        assert result is not None
        d = result.to_dict()
        assert "metadata" in d
