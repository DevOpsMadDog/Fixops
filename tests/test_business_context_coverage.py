"""Tests for core.business_context — data classification, criticality scoring, exposure analysis."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.business_context import (  # noqa: E402
    BusinessContextEngine,
    BusinessCriticality,
    BusinessCriticalityEngine,
    DataClassification,
    DataClassificationEngine,
    ExposureAnalyzer,
)


# ---------------------------------------------------------------------------
# DataClassification enum
# ---------------------------------------------------------------------------


class TestDataClassificationEnum:
    def test_all_levels(self):
        assert DataClassification.PUBLIC.value == "public"
        assert DataClassification.INTERNAL.value == "internal"
        assert DataClassification.CONFIDENTIAL.value == "confidential"
        assert DataClassification.RESTRICTED.value == "restricted"
        assert DataClassification.TOP_SECRET.value == "top_secret"
        assert len(DataClassification) == 5


class TestBusinessCriticalityEnum:
    def test_all_levels(self):
        assert BusinessCriticality.LOW.value == "low"
        assert BusinessCriticality.MISSION_CRITICAL.value == "mission_critical"
        assert len(BusinessCriticality) == 5


# ---------------------------------------------------------------------------
# DataClassificationEngine
# ---------------------------------------------------------------------------


class TestDataClassificationEngine:
    def setup_method(self):
        self.engine = DataClassificationEngine()

    def test_classify_public_content(self):
        result = self.engine.classify_data("This is public blog content for everyone.")
        assert result.classification == DataClassification.PUBLIC
        assert result.confidence > 0

    def test_classify_internal(self):
        result = self.engine.classify_data("Employee internal handbook for staff.")
        assert result.classification == DataClassification.INTERNAL
        assert "internal" in [i.lower().split(":")[0].strip() for i in result.indicators]

    def test_classify_confidential(self):
        result = self.engine.classify_data("Confidential private data that is sensitive.")
        assert result.classification in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED)

    def test_classify_restricted(self):
        result = self.engine.classify_data("This restricted proprietary credit card data has CVV codes.")
        assert result.classification == DataClassification.RESTRICTED

    def test_classify_top_secret(self):
        result = self.engine.classify_data("This is classified top secret TS//SCI material.")
        assert result.classification == DataClassification.TOP_SECRET
        assert result.confidence >= 0.45

    def test_classify_empty_defaults_to_internal(self):
        result = self.engine.classify_data("no matching keywords here xyz123")
        assert result.classification == DataClassification.INTERNAL
        assert result.confidence == 0.5

    def test_classify_with_patterns(self):
        result = self.engine.classify_data("SSN: 123-45-6789 from passport 123456789")
        assert result.classification == DataClassification.TOP_SECRET

    def test_result_has_reasoning(self):
        result = self.engine.classify_data("public data")
        assert "Classified as" in result.reasoning


# ---------------------------------------------------------------------------
# BusinessCriticalityEngine
# ---------------------------------------------------------------------------


class TestBusinessCriticalityEngine:
    def setup_method(self):
        self.engine = BusinessCriticalityEngine()

    def test_low_criticality(self):
        result = self.engine.calculate_criticality(
            {"user_count": "tens", "revenue_impact": "low"},
            DataClassification.PUBLIC,
        )
        assert result.criticality == BusinessCriticality.LOW
        assert result.score < 0.4

    def test_high_criticality(self):
        result = self.engine.calculate_criticality(
            {"user_count": "millions", "revenue_impact": "critical",
             "compliance_requirements": ["pci_dss"]},
            DataClassification.RESTRICTED,
        )
        assert result.criticality in (BusinessCriticality.HIGH, BusinessCriticality.CRITICAL, BusinessCriticality.MISSION_CRITICAL)
        assert result.score >= 0.6

    def test_numeric_user_count(self):
        result = self.engine.calculate_criticality(
            {"user_count": 5_000_000, "revenue_impact": "high"},
            DataClassification.CONFIDENTIAL,
        )
        assert result.factors["user_count"] == 1.0

    def test_small_numeric_user_count(self):
        result = self.engine.calculate_criticality(
            {"user_count": 50, "revenue_impact": "low"},
        )
        assert result.factors["user_count"] == 0.2

    def test_compliance_string(self):
        result = self.engine.calculate_criticality(
            {"compliance_requirements": "hipaa"},
        )
        assert result.factors["compliance"] == 0.9

    def test_no_classification(self):
        result = self.engine.calculate_criticality({"revenue_impact": "medium"})
        assert result.score > 0

    def test_result_has_factors(self):
        result = self.engine.calculate_criticality(
            {"user_count": "thousands", "revenue_impact": "medium"},
            DataClassification.INTERNAL,
        )
        assert "user_count" in result.factors
        assert "revenue_impact" in result.factors
        assert "compliance" in result.factors

    def test_result_has_reasoning(self):
        result = self.engine.calculate_criticality({"revenue_impact": "low"})
        assert "Criticality:" in result.reasoning


# ---------------------------------------------------------------------------
# ExposureAnalyzer
# ---------------------------------------------------------------------------


class TestExposureAnalyzer:
    def setup_method(self):
        self.analyzer = ExposureAnalyzer()

    def test_controlled_exposure(self):
        result = self.analyzer.analyze_exposure(
            {"requires_authentication": True},
        )
        assert result.exposure_level == "controlled"
        assert result.exposure_score == 0.0

    def test_internet_facing(self):
        result = self.analyzer.analyze_exposure(
            {"requires_authentication": False, "exposes_sensitive_data": True},
            {"public_ip": "1.2.3.4", "internet_facing": True, "open_ports": [80, 443]},
        )
        assert result.exposure_level in ("internet", "public")
        assert result.exposure_score >= 0.6
        assert len(result.exposure_vectors) >= 3
        assert len(result.recommendations) > 0

    def test_internal_exposure(self):
        result = self.analyzer.analyze_exposure(
            {"requires_authentication": False},
        )
        assert result.exposure_level == "internal"
        assert result.exposure_score >= 0.2

    def test_open_ports_add_exposure(self):
        result = self.analyzer.analyze_exposure(
            {},
            {"open_ports": [22, 80, 443, 8080]},
        )
        assert result.exposure_score > 0
        assert any("Open ports" in v for v in result.exposure_vectors)

    def test_no_network_config(self):
        result = self.analyzer.analyze_exposure({"requires_authentication": True})
        assert result.exposure_level == "controlled"

    def test_recommendations_for_high_exposure(self):
        result = self.analyzer.analyze_exposure(
            {"requires_authentication": False},
            {"public_ip": "1.2.3.4", "internet_facing": True},
        )
        assert "Restrict network access" in result.recommendations


# ---------------------------------------------------------------------------
# BusinessContextEngine (full integration)
# ---------------------------------------------------------------------------


class TestBusinessContextEngine:
    def setup_method(self):
        self.engine = BusinessContextEngine()

    def test_analyze_component_minimal(self):
        result = self.engine.analyze_component({"revenue_impact": "low"})
        assert "data_classification" in result
        assert "business_criticality" in result
        assert "exposure" in result
        assert "risk_adjustment" in result

    def test_analyze_component_with_code(self):
        result = self.engine.analyze_component(
            {"user_count": "thousands", "revenue_impact": "high"},
            code_content="Contains confidential private user data",
        )
        assert result["data_classification"]["level"] != "unknown"
        assert result["data_classification"]["confidence"] > 0

    def test_analyze_component_full(self):
        result = self.engine.analyze_component(
            {
                "user_count": 1_000_000,
                "revenue_impact": "critical",
                "compliance_requirements": ["pci_dss"],
                "requires_authentication": False,
                "exposes_sensitive_data": True,
            },
            code_content="This restricted credit card data has CVV",
            network_config={
                "public_ip": "1.2.3.4",
                "internet_facing": True,
                "open_ports": [443],
            },
        )
        assert result["business_criticality"]["score"] > 0.5
        assert result["exposure"]["score"] > 0.5
        assert result["risk_adjustment"] > 0

    def test_risk_adjustment_factor(self):
        result = self.engine.analyze_component(
            {"revenue_impact": "low"},
        )
        assert isinstance(result["risk_adjustment"], float)
        assert result["risk_adjustment"] >= 0
