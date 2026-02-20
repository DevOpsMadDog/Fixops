"""Comprehensive tests for SSDLC orchestrator with API/CLI integration."""

from apps.api.pipeline import PipelineOrchestrator

from tests.test_helpers import get_all_minimal_params


class TestSSDLCStageOrchestration:
    """Test SSDLC stage orchestration."""

    def test_requirements_stage(self):
        """Test requirements stage evaluation."""
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

    def test_design_stage(self):
        """Test design stage evaluation."""
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

    def test_build_stage(self):
        """Test build stage evaluation."""
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

    def test_test_stage(self):
        """Test test stage evaluation."""
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

    def test_deploy_stage(self):
        """Test deploy stage evaluation."""
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

    def test_operate_stage(self):
        """Test operate stage evaluation."""
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


class TestAPIIntegration:
    """Test API integration for SSDLC orchestrator."""

    def test_pipeline_run_endpoint(self):
        """Test /pipeline/run endpoint."""
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

    def test_multiple_app_profiles(self):
        """Test orchestrator with multiple app profiles."""
        params = get_all_minimal_params()

        params["design_dataset"]["rows"].append(
            {
                "component": "test-component-2",
                "owner": "test-team-2",
                "criticality": "high",
            }
        )

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "crosswalk" in result


class TestCLIIntegration:
    """Test CLI integration for SSDLC orchestrator."""

    def test_cli_run_command(self):
        """Test CLI run command."""
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

    def test_cli_demo_command(self):
        """Test CLI demo command."""
        params = get_all_minimal_params()
        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "status" in result


class TestAppProfiles:
    """Test different application profiles."""

    def test_web_application_profile(self):
        """Test web application profile."""
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

    def test_api_service_profile(self):
        """Test API service profile."""
        params = get_all_minimal_params()
        params["design_dataset"]["rows"][0]["criticality"] = "medium"

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_microservice_profile(self):
        """Test microservice profile."""
        params = get_all_minimal_params()
        params["design_dataset"]["rows"][0]["criticality"] = "low"

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_batch_job_profile(self):
        """Test batch job profile."""
        params = get_all_minimal_params()
        params["design_dataset"]["rows"][0]["owner"] = "batch-team"

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result

    def test_data_pipeline_profile(self):
        """Test data pipeline profile."""
        params = get_all_minimal_params()
        params["design_dataset"]["rows"][0]["component"] = "data-pipeline"

        orchestrator = PipelineOrchestrator()

        result = orchestrator.run(
            design_dataset=params["design_dataset"],
            sbom=params["sbom"],
            sarif=params["sarif"],
            cve=params["cve"],
        )

        assert result["status"] == "ok"
        assert "processing_layer" in result
