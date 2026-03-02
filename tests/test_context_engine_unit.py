"""Unit tests for core.context_engine — V3 Decision Intelligence context derivation.

Tests the ContextEngine that derives business-aware context signals from
design/SBOM components, enabling the brain pipeline to make risk-informed decisions.
"""



class TestComponentContext:
    """Test ComponentContext dataclass."""

    def test_creation(self):
        from core.context_engine import ComponentContext
        ctx = ComponentContext(
            name="payment-service",
            severity="high",
            context_score=8,
            criticality="mission_critical",
            data_classification=["pii", "pci"],
            exposure="internet",
            signals={"exploited": True, "finding_count": 5, "cve_count": 2},
            playbook={"name": "Escalate", "min_score": 7},
        )
        assert ctx.name == "payment-service"
        assert ctx.severity == "high"
        assert ctx.context_score == 8
        assert ctx.criticality == "mission_critical"
        assert "pii" in ctx.data_classification
        assert ctx.exposure == "internet"
        assert ctx.signals["exploited"] is True
        assert ctx.playbook["name"] == "Escalate"


class TestContextEngineInit:
    """Test ContextEngine initialization."""

    def _engine(self, settings=None):
        from core.context_engine import ContextEngine
        return ContextEngine(settings or {})

    def test_default_settings(self):
        engine = self._engine()
        assert engine.criticality_field == "customer_impact"
        assert engine.data_field == "data_classification"
        assert engine.exposure_field == "exposure"

    def test_custom_field_names(self):
        engine = self._engine({
            "fields": {
                "criticality": "business_tier",
                "data": "data_type",
                "exposure": "network_zone",
            }
        })
        assert engine.criticality_field == "business_tier"
        assert engine.data_field == "data_type"
        assert engine.exposure_field == "network_zone"

    def test_default_criticality_weights(self):
        engine = self._engine()
        assert engine.criticality_weights["mission_critical"] == 4
        assert engine.criticality_weights["internal"] == 1

    def test_custom_criticality_weights(self):
        engine = self._engine({"criticality_weights": {"tier1": 10, "tier2": 5}})
        assert engine.criticality_weights["tier1"] == 10
        assert engine.criticality_weights["tier2"] == 5
        # Defaults still present
        assert engine.criticality_weights["mission_critical"] == 4

    def test_default_data_weights(self):
        engine = self._engine()
        assert engine.data_weights["pii"] == 4
        assert engine.data_weights["internal"] == 2
        assert engine.data_weights["public"] == 1

    def test_default_exposure_weights(self):
        engine = self._engine()
        assert engine.exposure_weights["internet"] == 3
        assert engine.exposure_weights["internal"] == 1


class TestNormaliseSeverity:
    """Test SARIF and CVE severity normalization."""

    def _engine(self):
        from core.context_engine import ContextEngine
        return ContextEngine({})

    def test_sarif_none_returns_low(self):
        assert self._engine()._normalise_sarif_severity(None) == "low"

    def test_sarif_empty_returns_low(self):
        assert self._engine()._normalise_sarif_severity("") == "low"

    def test_sarif_note_returns_low(self):
        assert self._engine()._normalise_sarif_severity("note") == "low"

    def test_sarif_warning_returns_medium(self):
        assert self._engine()._normalise_sarif_severity("warning") == "medium"

    def test_sarif_error_returns_high(self):
        assert self._engine()._normalise_sarif_severity("error") == "high"

    def test_sarif_info_returns_low(self):
        assert self._engine()._normalise_sarif_severity("info") == "low"

    def test_sarif_unknown_returns_medium(self):
        assert self._engine()._normalise_sarif_severity("unknown") == "medium"

    def test_cve_critical(self):
        assert self._engine()._normalise_cve_severity("critical") == "critical"

    def test_cve_high(self):
        assert self._engine()._normalise_cve_severity("high") == "high"

    def test_cve_moderate(self):
        assert self._engine()._normalise_cve_severity("moderate") == "medium"

    def test_cve_none(self):
        assert self._engine()._normalise_cve_severity(None) == "medium"

    def test_cve_empty(self):
        assert self._engine()._normalise_cve_severity("") == "medium"

    def test_cve_unknown(self):
        assert self._engine()._normalise_cve_severity("unknown") == "medium"


class TestSeverityIndex:
    """Test severity ordering."""

    def _engine(self):
        from core.context_engine import ContextEngine
        return ContextEngine({})

    def test_low_is_0(self):
        assert self._engine()._severity_index("low") == 0

    def test_medium_is_1(self):
        assert self._engine()._severity_index("medium") == 1

    def test_high_is_2(self):
        assert self._engine()._severity_index("high") == 2

    def test_critical_is_3(self):
        assert self._engine()._severity_index("critical") == 3

    def test_unknown_defaults_to_medium(self):
        assert self._engine()._severity_index("bogus") == 1


class TestPlaybookEvaluation:
    """Test playbook matching by score."""

    def _engine(self, playbooks=None):
        from core.context_engine import ContextEngine
        return ContextEngine({"playbooks": playbooks or []})

    def test_no_playbooks_returns_monitor(self):
        engine = self._engine()
        result = engine._evaluate_playbook(10)
        assert result["name"] == "Monitor"

    def test_playbook_matching(self):
        engine = self._engine([
            {"name": "Critical Response", "min_score": 8},
            {"name": "Standard Review", "min_score": 4},
            {"name": "Monitor", "min_score": 0},
        ])
        assert engine._evaluate_playbook(10)["name"] == "Critical Response"
        assert engine._evaluate_playbook(8)["name"] == "Critical Response"
        assert engine._evaluate_playbook(5)["name"] == "Standard Review"
        assert engine._evaluate_playbook(1)["name"] == "Monitor"
        assert engine._evaluate_playbook(0)["name"] == "Monitor"


class TestEvaluate:
    """Test full context evaluation."""

    def _engine(self, **kwargs):
        from core.context_engine import ContextEngine
        return ContextEngine(kwargs.get("settings", {}))

    def test_empty_inputs(self):
        engine = self._engine()
        result = engine.evaluate([], [])
        assert result["summary"]["components_evaluated"] == 0
        assert result["components"] == []

    def test_single_component_no_findings(self):
        engine = self._engine()
        design_rows = [{"component": "api-gateway", "customer_impact": "internal", "exposure": "internal"}]
        crosswalk = []
        result = engine.evaluate(design_rows, crosswalk)
        assert result["summary"]["components_evaluated"] == 1
        comp = result["components"][0]
        assert comp["name"] == "api-gateway"
        assert comp["severity"] == "low"

    def test_single_component_with_critical_finding(self):
        engine = self._engine()
        design_rows = [{"component": "payment-api", "customer_impact": "mission_critical", "exposure": "internet"}]
        crosswalk = [{
            "design_index": 0,
            "findings": [{"level": "error"}],
            "cves": [{"severity": "critical", "exploited": True}],
        }]
        result = engine.evaluate(design_rows, crosswalk)
        comp = result["components"][0]
        assert comp["severity"] == "critical"
        assert comp["signals"]["exploited"] is True
        assert comp["context_score"] > 5

    def test_multiple_components(self):
        engine = self._engine()
        design_rows = [
            {"component": "auth-svc", "customer_impact": "mission_critical", "exposure": "internet"},
            {"component": "logging", "customer_impact": "internal", "exposure": "internal"},
        ]
        crosswalk = [
            {"design_index": 0, "findings": [{"level": "error"}], "cves": []},
            {"design_index": 1, "findings": [], "cves": []},
        ]
        result = engine.evaluate(design_rows, crosswalk)
        assert result["summary"]["components_evaluated"] == 2
        assert result["summary"]["highest_component"]["name"] == "auth-svc"

    def test_summary_statistics(self):
        engine = self._engine()
        design_rows = [
            {"component": "a", "customer_impact": "mission_critical", "exposure": "internet"},
            {"component": "b", "customer_impact": "internal", "exposure": "internal"},
        ]
        result = engine.evaluate(design_rows, [])
        summary = result["summary"]
        assert "highest_score" in summary
        assert "average_score" in summary
        assert "signals" in summary

    def test_distribution_signals(self):
        engine = self._engine()
        design_rows = [
            {"component": "a", "customer_impact": "mission_critical", "exposure": "internet"},
            {"component": "b", "customer_impact": "internal", "exposure": "internal"},
            {"component": "c", "customer_impact": "internal", "exposure": "internet"},
        ]
        result = engine.evaluate(design_rows, [])
        signals = result["summary"]["signals"]
        assert "criticality_distribution" in signals
        assert "exposure_distribution" in signals
        assert "playbook_usage" in signals

    def test_extract_component_name_fallbacks(self):
        engine = self._engine()
        design_rows = [
            {"service": "my-service"},
            {"name": "my-name"},
            {},
        ]
        result = engine.evaluate(design_rows, [])
        names = [c["name"] for c in result["components"]]
        assert "my-service" in names
        assert "my-name" in names
        assert "unknown" in names

    def test_non_mapping_rows_skipped(self):
        engine = self._engine()
        design_rows = [{"component": "valid"}, "not-a-dict", None, 42]
        result = engine.evaluate(design_rows, [])
        assert result["summary"]["components_evaluated"] == 1

    def test_data_classification_list(self):
        engine = self._engine()
        design_rows = [{"component": "x", "data_classification": ["pii", "pci"]}]
        result = engine.evaluate(design_rows, [])
        comp = result["components"][0]
        assert "pii" in comp["data_classification"]
        assert "pci" in comp["data_classification"]

    def test_exploited_cve_boosts_score(self):
        engine = self._engine()
        design_rows = [{"component": "api"}]
        crosswalk_no_exploit = [{"design_index": 0, "findings": [], "cves": [{"severity": "high", "exploited": False}]}]
        crosswalk_exploit = [{"design_index": 0, "findings": [], "cves": [{"severity": "high", "exploited": True}]}]
        r1 = engine.evaluate(design_rows, crosswalk_no_exploit)
        r2 = engine.evaluate(design_rows, crosswalk_exploit)
        assert r2["components"][0]["context_score"] > r1["components"][0]["context_score"]


class TestNormaliseWeights:
    """Test weight normalization utility."""

    def test_default_weights(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._normalise_weights(None, default={"a": 1, "b": 2})
        assert result == {"a": 1, "b": 2}

    def test_custom_overrides(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._normalise_weights({"a": 10}, default={"a": 1, "b": 2})
        assert result["a"] == 10
        assert result["b"] == 2

    def test_invalid_values_skipped(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._normalise_weights({"c": "not-a-number"}, default={"a": 1})
        assert result == {"a": 1}  # Invalid entry skipped


class TestParsePlaybooks:
    """Test playbook parsing."""

    def test_empty_list(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._parse_playbooks([])
        assert result == []

    def test_valid_playbooks_sorted(self):
        from core.context_engine import ContextEngine
        raw = [
            {"name": "Low", "min_score": 0},
            {"name": "High", "min_score": 10},
            {"name": "Med", "min_score": 5},
        ]
        result = ContextEngine._parse_playbooks(raw)
        assert result[0]["name"] == "High"
        assert result[-1]["name"] == "Low"

    def test_non_mapping_items_skipped(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._parse_playbooks(["not-a-dict", 42])
        assert result == []

    def test_missing_min_score_defaults_to_0(self):
        from core.context_engine import ContextEngine
        result = ContextEngine._parse_playbooks([{"name": "X"}])
        assert result[0]["min_score"] == 0
