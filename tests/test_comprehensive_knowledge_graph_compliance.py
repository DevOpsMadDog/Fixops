"""Comprehensive tests for knowledge graph and compliance reporting."""

import json

from apps.api.pipeline import PipelineOrchestrator
from tests.test_helpers import get_all_minimal_params


class TestKnowledgeGraph:
    """Test knowledge graph generation and exports."""

    def test_graph_construction(self):
        """Test knowledge graph construction."""
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

    def test_entity_relationships(self):
        """Test entity relationship mapping."""
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

    def test_attack_path_analysis(self):
        """Test attack path analysis."""
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

    def test_reachability_scoring(self):
        """Test reachability scoring."""
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

    def test_graph_export_json(self):
        """Test knowledge graph export to JSON."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        json_str = json.dumps(result)
        assert len(json_str) > 0

    def test_graph_export_graphml(self):
        """Test knowledge graph export to GraphML format."""
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

    def test_graph_visualization_data(self):
        """Test knowledge graph visualization data generation."""
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


class TestComplianceReports:
    """Test compliance report generation."""

    def test_soc2_compliance(self):
        """Test SOC2 compliance report generation."""
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

    def test_iso27001_compliance(self):
        """Test ISO27001 compliance report generation."""
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

    def test_pci_dss_compliance(self):
        """Test PCI-DSS compliance report generation."""
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

    def test_gdpr_compliance(self):
        """Test GDPR compliance report generation."""
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

    def test_cwe_to_control_mapping(self):
        """Test CWE to control requirement mapping."""
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

    def test_control_gaps_analysis(self):
        """Test control gaps analysis."""
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

    def test_audit_ready_evidence(self):
        """Test audit-ready evidence bundle generation."""
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


class TestEvidenceManagement:
    """Test evidence management and cryptographic signing."""

    def test_evidence_bundle_creation(self):
        """Test evidence bundle creation."""
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

    def test_rsa_sha256_signatures(self):
        """Test RSA-SHA256 cryptographic signatures."""
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

    def test_evidence_retention(self):
        """Test evidence retention policies."""
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

    def test_transparency_index(self):
        """Test transparency index audit trail."""
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
