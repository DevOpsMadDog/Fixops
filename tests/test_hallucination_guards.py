"""Unit tests for LLM hallucination guards."""

from __future__ import annotations

from core.hallucination_guards import (
    apply_hallucination_guards,
    validate_cross_model_agreement,
    validate_input_citation,
    validate_numeric_consistency,
)


class TestValidateInputCitation:
    """Test input citation validation."""

    def test_citation_valid(self):
        """Test validation passes when fields are cited."""
        llm_response = "The service web-server has high severity findings."
        input_context = {
            "service_name": "web-server",
            "highest_severity": "high",
        }
        required_fields = ["service_name", "highest_severity"]

        is_valid, issues = validate_input_citation(
            llm_response, input_context, required_fields
        )

        assert is_valid is True
        assert len(issues) == 0

    def test_citation_missing_field(self):
        """Test validation fails when required field not cited."""
        llm_response = "The service has high severity findings."
        input_context = {
            "service_name": "web-server",
            "highest_severity": "high",
        }
        required_fields = ["service_name", "highest_severity"]

        is_valid, issues = validate_input_citation(
            llm_response, input_context, required_fields
        )

        assert is_valid is False
        assert len(issues) > 0
        assert any("service_name" in issue for issue in issues)

    def test_citation_numeric_hallucination(self):
        """Test detection of numeric hallucinations."""
        llm_response = "Found 42 critical vulnerabilities."
        input_context = {
            "severity_counts": {"critical": 5, "high": 10},
        }

        is_valid, issues = validate_input_citation(llm_response, input_context, [])

        assert is_valid is False
        assert len(issues) > 0
        assert any("42" in issue for issue in issues)

    def test_citation_allows_common_numbers(self):
        """Test that common numbers like 0, 1, 100 are allowed."""
        llm_response = "Confidence is 100% with 0 errors."
        input_context = {
            "confidence": 0.95,
        }

        is_valid, issues = validate_input_citation(llm_response, input_context, [])

        assert is_valid is True

    def test_citation_no_required_fields(self):
        """Test validation with no required fields."""
        llm_response = "Analysis complete."
        input_context = {}

        is_valid, issues = validate_input_citation(llm_response, input_context, [])

        assert is_valid is True
        assert len(issues) == 0


class TestValidateCrossModelAgreement:
    """Test cross-model agreement validation."""

    def test_agreement_unanimous(self):
        """Test validation passes with unanimous agreement."""
        analyses = [
            {"recommended_action": "block", "confidence": 0.85},
            {"recommended_action": "block", "confidence": 0.82},
            {"recommended_action": "block", "confidence": 0.88},
        ]

        is_valid, disagreement, issues = validate_cross_model_agreement(analyses)

        assert is_valid is True
        assert disagreement == 0.0
        assert len(issues) == 0

    def test_agreement_high_disagreement(self):
        """Test validation fails with high disagreement."""
        analyses = [
            {"recommended_action": "block", "confidence": 0.85},
            {"recommended_action": "allow", "confidence": 0.80},
            {"recommended_action": "review", "confidence": 0.75},
        ]

        is_valid, disagreement, issues = validate_cross_model_agreement(
            analyses, disagreement_threshold=0.3
        )

        assert is_valid is False
        assert disagreement > 0.3
        assert len(issues) > 0

    def test_agreement_confidence_spread(self):
        """Test detection of high confidence spread."""
        analyses = [
            {"recommended_action": "block", "confidence": 0.95},
            {"recommended_action": "block", "confidence": 0.60},
        ]

        is_valid, disagreement, issues = validate_cross_model_agreement(analyses)

        assert is_valid is False
        assert len(issues) > 0
        assert any("confidence spread" in issue for issue in issues)

    def test_agreement_single_model(self):
        """Test validation with single model (always passes)."""
        analyses = [
            {"recommended_action": "block", "confidence": 0.85},
        ]

        is_valid, disagreement, issues = validate_cross_model_agreement(analyses)

        assert is_valid is True
        assert disagreement == 0.0

    def test_agreement_custom_threshold(self):
        """Test validation with custom disagreement threshold."""
        analyses = [
            {"recommended_action": "block", "confidence": 0.85},
            {"recommended_action": "allow", "confidence": 0.80},
        ]

        is_valid_strict, _, _ = validate_cross_model_agreement(
            analyses, disagreement_threshold=0.1
        )
        assert is_valid_strict is False

        is_valid_lenient, _, _ = validate_cross_model_agreement(
            analyses, disagreement_threshold=0.9
        )
        assert is_valid_lenient is True


class TestValidateNumericConsistency:
    """Test numeric consistency validation."""

    def test_consistency_exact_match(self):
        """Test validation passes with exact numeric match."""
        llm_response = "CVSS score: 9.8"
        computed_values = {"CVSS score": 9.8}

        is_valid, issues = validate_numeric_consistency(llm_response, computed_values)

        assert is_valid is True
        assert len(issues) == 0

    def test_consistency_within_tolerance(self):
        """Test validation passes within tolerance."""
        llm_response = "CVSS score: 9.75"
        computed_values = {"CVSS score": 9.8}

        is_valid, issues = validate_numeric_consistency(
            llm_response, computed_values, tolerance=0.05
        )

        assert is_valid is True

    def test_consistency_exceeds_tolerance(self):
        """Test validation fails when exceeding tolerance."""
        llm_response = "CVSS score: 8.5"
        computed_values = {"CVSS score": 9.8}

        is_valid, issues = validate_numeric_consistency(
            llm_response, computed_values, tolerance=0.05
        )

        assert is_valid is False
        assert len(issues) > 0
        assert any("CVSS score" in issue for issue in issues)

    def test_consistency_metric_not_in_response(self):
        """Test validation when metric not mentioned in response."""
        llm_response = "Analysis complete."
        computed_values = {"CVSS score": 9.8}

        is_valid, issues = validate_numeric_consistency(llm_response, computed_values)

        assert is_valid is True

    def test_consistency_multiple_metrics(self):
        """Test validation with multiple metrics."""
        llm_response = "CVSS score: 9.8, EPSS: 0.85"
        computed_values = {
            "CVSS score": 9.8,
            "EPSS": 0.85,
        }

        is_valid, issues = validate_numeric_consistency(llm_response, computed_values)

        assert is_valid is True


class TestApplyHallucinationGuards:
    """Test apply_hallucination_guards function."""

    def test_apply_guards_all_pass(self):
        """Test applying guards when all validations pass."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Service web-server has high severity findings.",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
                {"recommended_action": "block", "confidence": 0.82},
            ],
        }
        input_context = {
            "service_name": "web-server",
            "highest_severity": "high",
        }
        computed_metrics = {}

        result = apply_hallucination_guards(llm_result, input_context, computed_metrics)

        assert result["validation_passed"] is True
        assert result["adjusted_confidence"] == 0.85
        assert len(result["issues_found"]) == 0

    def test_apply_guards_citation_fails(self):
        """Test applying guards when citation validation fails."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Service has high severity findings.",  # Missing service name
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
            ],
        }
        input_context = {
            "service_name": "web-server",
            "highest_severity": "high",
        }

        result = apply_hallucination_guards(llm_result, input_context)

        assert result["validation_passed"] is False
        assert result["adjusted_confidence"] < result["original_confidence"]
        assert len(result["issues_found"]) > 0

    def test_apply_guards_agreement_fails(self):
        """Test applying guards when agreement validation fails."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Analysis complete.",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
                {"recommended_action": "allow", "confidence": 0.80},
                {"recommended_action": "review", "confidence": 0.75},
            ],
        }
        input_context = {}

        result = apply_hallucination_guards(llm_result, input_context)

        assert result["validation_passed"] is False
        assert result["adjusted_confidence"] < result["original_confidence"]
        assert "disagreement_score" in result

    def test_apply_guards_numeric_fails(self):
        """Test applying guards when numeric validation fails."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "CVSS score: 8.0",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
            ],
        }
        input_context = {}
        computed_metrics = {"CVSS score": 9.8}

        result = apply_hallucination_guards(llm_result, input_context, computed_metrics)

        assert result["validation_passed"] is False
        assert result["adjusted_confidence"] < result["original_confidence"]

    def test_apply_guards_custom_config(self):
        """Test applying guards with custom configuration."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Analysis complete.",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
                {"recommended_action": "allow", "confidence": 0.80},
            ],
        }
        input_context = {}
        config = {
            "disagreement_threshold": 0.1,  # Strict
            "confidence_penalty": 0.25,  # High penalty
        }

        result = apply_hallucination_guards(llm_result, input_context, None, config)

        assert result["validation_passed"] is False
        assert result["adjusted_confidence"] < 0.70

    def test_apply_guards_confidence_clamping(self):
        """Test that adjusted confidence is clamped to valid range."""
        llm_result = {
            "consensus_confidence": 0.50,
            "summary": "Service has findings.",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.95},
                {"recommended_action": "allow", "confidence": 0.60},
            ],
        }
        input_context = {
            "service_name": "web-server",
        }
        config = {
            "confidence_penalty": 0.50,  # Very high penalty
        }

        result = apply_hallucination_guards(llm_result, input_context, None, config)

        assert 0.0 <= result["adjusted_confidence"] <= 1.0

    def test_apply_guards_tracks_applied_guards(self):
        """Test that applied guards are tracked."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Analysis complete.",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.85},
            ],
        }
        input_context = {}
        computed_metrics = {"CVSS score": 9.8}

        result = apply_hallucination_guards(llm_result, input_context, computed_metrics)

        assert "guards_applied" in result
        assert "input_citation" in result["guards_applied"]
        assert "cross_model_agreement" in result["guards_applied"]
        assert "numeric_consistency" in result["guards_applied"]

    def test_apply_guards_multiple_failures(self):
        """Test applying guards with multiple validation failures."""
        llm_result = {
            "consensus_confidence": 0.85,
            "summary": "Found 42 vulnerabilities with CVSS score: 8.0",
            "individual_analyses": [
                {"recommended_action": "block", "confidence": 0.95},
                {"recommended_action": "allow", "confidence": 0.60},
            ],
        }
        input_context = {
            "service_name": "web-server",
            "severity_counts": {"critical": 5},
        }
        computed_metrics = {"CVSS score": 9.8}

        result = apply_hallucination_guards(llm_result, input_context, computed_metrics)

        assert result["validation_passed"] is False
        assert result["adjusted_confidence"] < 0.60
        assert len(result["issues_found"]) >= 2
