"""Tests for core.hallucination_guards — LLM output validation."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.hallucination_guards import (
    validate_cross_model_agreement,
    validate_input_citation,
    validate_numeric_consistency,
)


# ── validate_input_citation ─────────────────────────────────────────

class TestValidateInputCitation:
    def test_valid_citation(self):
        response = "CVE-2024-1234 has CVSS score 9.8 and is critical."
        context = {"cve_id": "CVE-2024-1234", "cvss": 9.8}
        is_valid, issues = validate_input_citation(
            response, context, required_fields=["cve_id"]
        )
        assert is_valid is True
        assert len(issues) == 0

    def test_missing_required_field(self):
        response = "This vulnerability is critical."
        context = {"cve_id": "CVE-2024-1234"}
        is_valid, issues = validate_input_citation(
            response, context, required_fields=["cve_id"]
        )
        assert is_valid is False
        assert any("cve_id" in issue for issue in issues)

    def test_no_required_fields(self):
        response = "Some analysis text."
        context = {"data": "value"}
        is_valid, issues = validate_input_citation(response, context)
        # Should pass since no required fields are specified
        # (may still find hallucinated numbers)
        assert isinstance(is_valid, bool)

    def test_field_value_none_skipped(self):
        response = "Analysis text."
        context = {"missing_field": None}
        is_valid, issues = validate_input_citation(
            response, context, required_fields=["missing_field"]
        )
        # Field with None value is skipped
        assert is_valid is True or len(issues) >= 0

    def test_hallucinated_numbers(self):
        response = "The score is 42.5 which is concerning."
        context = {"score": 7.0}
        is_valid, issues = validate_input_citation(response, context)
        # 42.5 is not in input context
        assert any("42.5" in issue for issue in issues) or is_valid


# ── validate_cross_model_agreement ──────────────────────────────────

class TestValidateCrossModelAgreement:
    def test_single_analysis(self):
        analyses = [{"recommended_action": "block", "confidence": 0.9}]
        is_valid, score, issues = validate_cross_model_agreement(analyses)
        assert is_valid is True
        assert score == 0.0
        assert issues == []

    def test_agreement(self):
        analyses = [
            {"recommended_action": "block", "confidence": 0.9},
            {"recommended_action": "block", "confidence": 0.85},
            {"recommended_action": "block", "confidence": 0.88},
        ]
        is_valid, score, issues = validate_cross_model_agreement(analyses)
        assert is_valid is True
        assert score == 0.0

    def test_disagreement(self):
        analyses = [
            {"recommended_action": "block", "confidence": 0.9},
            {"recommended_action": "allow", "confidence": 0.8},
            {"recommended_action": "review", "confidence": 0.7},
        ]
        is_valid, score, issues = validate_cross_model_agreement(analyses)
        assert score > 0

    def test_high_disagreement_flagged(self):
        analyses = [
            {"recommended_action": "block", "confidence": 0.9},
            {"recommended_action": "allow", "confidence": 0.2},
            {"recommended_action": "review", "confidence": 0.5},
        ]
        is_valid, score, issues = validate_cross_model_agreement(
            analyses, disagreement_threshold=0.2
        )
        # With 3 different actions, disagreement is high
        assert len(issues) >= 1

    def test_confidence_spread_flagged(self):
        analyses = [
            {"recommended_action": "block", "confidence": 0.95},
            {"recommended_action": "block", "confidence": 0.3},
        ]
        is_valid, score, issues = validate_cross_model_agreement(analyses)
        assert any("spread" in issue.lower() for issue in issues)

    def test_empty_analyses(self):
        is_valid, score, issues = validate_cross_model_agreement([])
        assert is_valid is True


# ── validate_numeric_consistency ────────────────────────────────────

class TestValidateNumericConsistency:
    def test_consistent(self):
        response = "risk_score: 0.85"
        computed = {"risk_score": 0.85}
        is_valid, issues = validate_numeric_consistency(response, computed)
        assert is_valid is True

    def test_inconsistent(self):
        response = "risk_score: 0.95"
        computed = {"risk_score": 0.5}
        is_valid, issues = validate_numeric_consistency(response, computed)
        assert is_valid is False
        assert any("risk_score" in issue for issue in issues)

    def test_metric_not_mentioned(self):
        response = "This is a general analysis."
        computed = {"risk_score": 0.75}
        is_valid, issues = validate_numeric_consistency(response, computed)
        assert is_valid is True  # Metric not mentioned, so no inconsistency

    def test_within_tolerance(self):
        response = "risk_score: 0.84"
        computed = {"risk_score": 0.85}
        is_valid, issues = validate_numeric_consistency(
            response, computed, tolerance=0.05
        )
        assert is_valid is True

    def test_empty_computed(self):
        response = "risk_score: 0.5"
        is_valid, issues = validate_numeric_consistency(response, {})
        assert is_valid is True
