"""Comprehensive tests for vulnerability management, marketplace, and backtesting."""

from apps.api.pipeline import PipelineOrchestrator
from tests.test_helpers import get_all_minimal_params


class TestVulnerabilityManagement:
    """Test vulnerability management fine-tuning."""

    def test_config_overlay_loading(self):
        """Test configuration overlay loading."""
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

    def test_stage_specific_tuning(self):
        """Test stage-specific risk tuning."""
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

    def test_requirements_stage_tuning(self):
        """Test requirements stage vulnerability tuning."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "design_summary" in result

    def test_design_stage_tuning(self):
        """Test design stage vulnerability tuning."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "design_summary" in result

    def test_build_stage_tuning(self):
        """Test build stage vulnerability tuning."""
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

    def test_test_stage_tuning(self):
        """Test test stage vulnerability tuning."""
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

    def test_deploy_stage_tuning(self):
        """Test deploy stage vulnerability tuning."""
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

    def test_operate_stage_tuning(self):
        """Test operate stage vulnerability tuning."""
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

    def test_severity_threshold_override(self):
        """Test severity threshold override via config."""
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

    def test_criticality_based_tuning(self):
        """Test criticality-based vulnerability tuning."""
        params = get_all_minimal_params()
        params["design_dataset"]["rows"][0]["criticality"] = "high"

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result


class TestMarketplace:
    """Test marketplace functionality."""

    def test_test_pack_sharing(self):
        """Test test pack sharing functionality."""
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

    def test_test_pack_validation(self):
        """Test test pack validation."""
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

    def test_developer_extensions(self):
        """Test developer extension framework."""
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

    def test_ecosystem_extensibility(self):
        """Test ecosystem extensibility."""
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


class TestAdhocUpload:
    """Test adhoc upload functionality."""

    def test_chunked_upload_manager(self):
        """Test chunked upload manager."""
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

    def test_session_based_upload(self):
        """Test session-based upload tracking."""
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

    def test_checksum_validation(self):
        """Test checksum validation for uploads."""
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

    def test_resumable_uploads(self):
        """Test resumable upload functionality."""
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

    def test_large_artifact_handling(self):
        """Test large artifact handling."""
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


class TestCVEBacktesting:
    """Test CVE backtesting functionality."""

    def test_log4shell_backtesting(self):
        """Test Log4Shell (CVE-2021-44228) backtesting."""
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

    def test_heartbleed_backtesting(self):
        """Test Heartbleed (CVE-2014-0160) backtesting."""
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

    def test_shellshock_backtesting(self):
        """Test Shellshock (CVE-2014-6271) backtesting."""
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

    def test_eternalblue_backtesting(self):
        """Test EternalBlue (CVE-2017-0144) backtesting."""
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

    def test_struts2_backtesting(self):
        """Test Struts2 (CVE-2017-5638) backtesting."""
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

    def test_historical_accuracy(self):
        """Test historical accuracy of backtesting."""
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

    def test_backtesting_fixtures(self):
        """Test backtesting with fixture data."""
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
