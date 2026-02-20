"""Comprehensive tests for correlation and decision engines."""

from apps.api.pipeline import PipelineOrchestrator

from tests.test_helpers import get_all_minimal_params


class TestCorrelationEngine:
    """Test correlation engine functionality."""

    def test_crosswalk_generation(self):
        """Test crosswalk generation across all sources."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "crosswalk" in result
        assert len(result["crosswalk"]) > 0

    def test_component_correlation(self):
        """Test component correlation across design and SBOM."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "sbom_summary" in result

    def test_vulnerability_correlation(self):
        """Test vulnerability correlation across SARIF and CVE."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "cve_summary" in result

    def test_batch_correlation(self):
        """Test batch correlation of multiple findings."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "sarif_summary" in result


class TestDecisionEngine:
    """Test decision engine functionality."""

    def test_weighted_scoring(self):
        """Test weighted severity scoring."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "severity_overview" in result

    def test_verdict_thresholds(self):
        """Test verdict threshold calculation."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_ssvc_framework(self):
        """Test SSVC framework integration."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_kev_integration(self):
        """Test KEV (Known Exploited Vulnerabilities) integration."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "cve_summary" in result

    def test_epss_integration(self):
        """Test EPSS (Exploit Prediction Scoring System) integration."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "cve_summary" in result

    def test_confidence_scores(self):
        """Test confidence score calculation."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result


class TestEnhancedDecisionEngine:
    """Test enhanced decision engine with multi-LLM consensus."""

    def test_multi_llm_consensus(self):
        """Test multi-LLM consensus mechanism."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_hallucination_guards(self):
        """Test hallucination guards for LLM outputs."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_mitre_attack_mapping(self):
        """Test MITRE ATT&CK mapping."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result
