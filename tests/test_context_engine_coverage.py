"""Tests for core.context_engine — business-aware context derivation."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.context_engine import ContextEngine  # noqa: E402


# ---------------------------------------------------------------------------
# ContextEngine initialisation
# ---------------------------------------------------------------------------


class TestContextEngineInit:
    def test_default_settings(self):
        engine = ContextEngine({})
        assert engine.criticality_field == "customer_impact"
        assert engine.data_field == "data_classification"
        assert engine.exposure_field == "exposure"
        assert "mission_critical" in engine.criticality_weights
        assert "pii" in engine.data_weights
        assert "internet" in engine.exposure_weights

    def test_custom_fields(self):
        engine = ContextEngine({
            "fields": {
                "criticality": "business_impact",
                "data": "data_type",
                "exposure": "network_zone",
            }
        })
        assert engine.criticality_field == "business_impact"
        assert engine.data_field == "data_type"
        assert engine.exposure_field == "network_zone"

    def test_custom_weights(self):
        engine = ContextEngine({
            "criticality_weights": {"tier1": 10, "tier2": 5},
        })
        assert engine.criticality_weights["tier1"] == 10
        assert engine.criticality_weights["tier2"] == 5

    def test_none_settings(self):
        engine = ContextEngine(None)
        assert engine.criticality_field == "customer_impact"

    def test_playbooks_parsing(self):
        engine = ContextEngine({
            "playbooks": [
                {"name": "Critical Response", "min_score": 8},
                {"name": "Standard Fix", "min_score": 3},
                {"name": "Monitor", "min_score": 0},
            ]
        })
        assert len(engine.playbooks) == 3
        # Sorted descending by min_score
        assert engine.playbooks[0]["name"] == "Critical Response"
        assert engine.playbooks[1]["name"] == "Standard Fix"


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


class TestSeverityHelpers:
    def setup_method(self):
        self.engine = ContextEngine({})

    def test_severity_index(self):
        assert self.engine._severity_index("low") == 0
        assert self.engine._severity_index("medium") == 1
        assert self.engine._severity_index("high") == 2
        assert self.engine._severity_index("critical") == 3

    def test_severity_index_unknown(self):
        # Unknown maps to medium index
        assert self.engine._severity_index("garbage") == 1

    def test_normalise_sarif_severity(self):
        assert self.engine._normalise_sarif_severity(None) == "low"
        assert self.engine._normalise_sarif_severity("") == "low"
        assert self.engine._normalise_sarif_severity("note") == "low"
        assert self.engine._normalise_sarif_severity("warning") == "medium"
        assert self.engine._normalise_sarif_severity("error") == "high"
        assert self.engine._normalise_sarif_severity("info") == "low"
        assert self.engine._normalise_sarif_severity("weird") == "medium"

    def test_normalise_cve_severity(self):
        assert self.engine._normalise_cve_severity(None) == "medium"
        assert self.engine._normalise_cve_severity("") == "medium"
        assert self.engine._normalise_cve_severity("critical") == "critical"
        assert self.engine._normalise_cve_severity("HIGH") == "high"
        assert self.engine._normalise_cve_severity("moderate") == "medium"
        assert self.engine._normalise_cve_severity("low") == "low"
        assert self.engine._normalise_cve_severity("unknown") == "medium"


# ---------------------------------------------------------------------------
# Weight normalisation
# ---------------------------------------------------------------------------


class TestWeightNormalisation:
    def test_normalise_weights_default(self):
        result = ContextEngine._normalise_weights(None, default={"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_normalise_weights_override(self):
        result = ContextEngine._normalise_weights(
            {"a": 10, "c": 5},
            default={"a": 1, "b": 2},
        )
        assert result["a"] == 10
        assert result["b"] == 2
        assert result["c"] == 5

    def test_normalise_weights_bad_values_skipped(self):
        result = ContextEngine._normalise_weights(
            {"a": "not_a_number"},
            default={"a": 1},
        )
        assert result["a"] == 1  # Default preserved

    def test_normalise_weights_case_insensitive(self):
        result = ContextEngine._normalise_weights(
            {"UPPER": 3},
            default={"lower": 1},
        )
        assert result["upper"] == 3


# ---------------------------------------------------------------------------
# Playbook parsing
# ---------------------------------------------------------------------------


class TestPlaybookParsing:
    def test_empty_list(self):
        result = ContextEngine._parse_playbooks([])
        assert result == []

    def test_non_mapping_items_skipped(self):
        result = ContextEngine._parse_playbooks(["string", 42, None])
        assert result == []

    def test_min_score_default(self):
        result = ContextEngine._parse_playbooks([{"name": "P1"}])
        assert result[0]["min_score"] == 0

    def test_sorted_descending(self):
        result = ContextEngine._parse_playbooks([
            {"name": "Low", "min_score": 1},
            {"name": "High", "min_score": 10},
            {"name": "Mid", "min_score": 5},
        ])
        assert result[0]["name"] == "High"
        assert result[1]["name"] == "Mid"
        assert result[2]["name"] == "Low"


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


class TestScoring:
    def setup_method(self):
        self.engine = ContextEngine({})

    def test_score_value_basic(self):
        assert self.engine._score_value("pii", self.engine.data_weights) == 4
        assert self.engine._score_value("internal", self.engine.data_weights) == 2
        assert self.engine._score_value("public", self.engine.data_weights) == 1
        assert self.engine._score_value(None, self.engine.data_weights) == 0
        assert self.engine._score_value("unknown", self.engine.data_weights) == 0

    def test_score_data_classification_list(self):
        assert self.engine._score_data_classification(["pii", "public"]) == 4
        assert self.engine._score_data_classification(["public"]) == 1

    def test_score_data_classification_single(self):
        assert self.engine._score_data_classification("pii") == 4
        assert self.engine._score_data_classification(None) == 0

    def test_evaluate_playbook(self):
        engine = ContextEngine({
            "playbooks": [
                {"name": "Critical", "min_score": 8},
                {"name": "Normal", "min_score": 3},
                {"name": "Monitor", "min_score": 0},
            ]
        })
        assert engine._evaluate_playbook(10)["name"] == "Critical"
        assert engine._evaluate_playbook(5)["name"] == "Normal"
        assert engine._evaluate_playbook(1)["name"] == "Monitor"

    def test_evaluate_playbook_no_match(self):
        engine = ContextEngine({})
        result = engine._evaluate_playbook(0)
        assert result["name"] == "Monitor"


# ---------------------------------------------------------------------------
# Component name extraction
# ---------------------------------------------------------------------------


class TestComponentNameExtraction:
    def setup_method(self):
        self.engine = ContextEngine({})

    def test_extract_component(self):
        assert self.engine._extract_component_name({"component": "api-gateway"}) == "api-gateway"

    def test_extract_service(self):
        assert self.engine._extract_component_name({"service": "auth-svc"}) == "auth-svc"

    def test_extract_name(self):
        assert self.engine._extract_component_name({"name": "db"}) == "db"

    def test_extract_unknown(self):
        assert self.engine._extract_component_name({}) == "unknown"

    def test_extract_strips_whitespace(self):
        assert self.engine._extract_component_name({"component": "  api  "}) == "api"


# ---------------------------------------------------------------------------
# Full evaluate
# ---------------------------------------------------------------------------


class TestEvaluate:
    def setup_method(self):
        self.engine = ContextEngine({
            "playbooks": [
                {"name": "Critical Response", "min_score": 8},
                {"name": "Fix", "min_score": 3},
                {"name": "Monitor", "min_score": 0},
            ]
        })

    def test_empty_input(self):
        result = self.engine.evaluate([], [])
        assert result["summary"]["components_evaluated"] == 0
        assert result["components"] == []

    def test_single_component_no_findings(self):
        design = [{"component": "my-api", "customer_impact": "internal", "exposure": "internal"}]
        crosswalk = [{"design_index": 0, "findings": [], "cves": []}]
        result = self.engine.evaluate(design, crosswalk)
        assert result["summary"]["components_evaluated"] == 1
        comp = result["components"][0]
        assert comp["name"] == "my-api"
        assert comp["severity"] == "low"

    def test_component_with_critical_cve(self):
        design = [
            {"component": "payment-svc", "customer_impact": "mission_critical",
             "data_classification": "pii", "exposure": "internet"},
        ]
        crosswalk = [
            {
                "design_index": 0,
                "findings": [{"level": "error"}],
                "cves": [{"severity": "critical", "exploited": True}],
            },
        ]
        result = self.engine.evaluate(design, crosswalk)
        comp = result["components"][0]
        assert comp["severity"] == "critical"
        assert comp["context_score"] > 8  # High score due to all risk factors
        assert comp["signals"]["exploited"] is True
        assert comp["signals"]["finding_count"] == 1
        assert comp["signals"]["cve_count"] == 1
        assert comp["playbook"]["name"] == "Critical Response"

    def test_multiple_components(self):
        design = [
            {"component": "api", "customer_impact": "internal", "exposure": "internal"},
            {"component": "db", "customer_impact": "mission_critical", "exposure": "internet"},
        ]
        crosswalk = [
            {"design_index": 0, "findings": [], "cves": []},
            {"design_index": 1, "findings": [{"level": "error"}], "cves": [{"severity": "high"}]},
        ]
        result = self.engine.evaluate(design, crosswalk)
        assert result["summary"]["components_evaluated"] == 2
        assert result["summary"]["highest_score"] > 0
        assert "average_score" in result["summary"]
        assert "signals" in result["summary"]

    def test_non_mapping_rows_skipped(self):
        design = [{"component": "valid"}, "invalid", None]
        crosswalk = []
        result = self.engine.evaluate(design, crosswalk)
        assert result["summary"]["components_evaluated"] == 1

    def test_signals_distribution(self):
        design = [
            {"component": "a", "customer_impact": "internal", "exposure": "internal"},
            {"component": "b", "customer_impact": "internal", "exposure": "internet"},
        ]
        crosswalk = []
        result = self.engine.evaluate(design, crosswalk)
        signals = result["summary"]["signals"]
        assert "criticality_distribution" in signals
        assert "exposure_distribution" in signals
        assert "playbook_usage" in signals
