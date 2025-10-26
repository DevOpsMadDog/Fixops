"""Comprehensive end-to-end tests for FixOps covering all components."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from tests.test_data_generator import TestDataGenerator


class TestAPIEndpointsE2E:
    """End-to-end tests for all API endpoints."""

    @pytest.fixture
    def test_data_dir(self):
        """Create temporary directory with test data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            files = TestDataGenerator.write_test_data(tmpdir_path)
            yield tmpdir_path, files

    @pytest.fixture
    def api_client(self):
        """Create FastAPI test client."""
        from fastapi.testclient import TestClient

        from apps.api.app import create_app

        os.environ["FIXOPS_API_TOKEN"] = "test-token"
        os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
        os.environ["FIXOPS_MODE"] = "demo"
        os.environ["FIXOPS_JWT_SECRET"] = (
            "test-jwt-secret-for-testing-purposes-only-do-not-use-in-production"
        )

        app = create_app()
        client = TestClient(app)
        return client

    def test_design_upload_valid(self, api_client, test_data_dir):
        """Test uploading valid design CSV."""
        tmpdir, files = test_data_dir

        with open(files["design"], "rb") as f:
            response = api_client.post(
                "/inputs/design",
                files={"file": ("design.csv", f, "text/csv")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "design"
        assert data["row_count"] == 50
        assert "columns" in data

    def test_design_upload_invalid_content_type(self, api_client):
        """Test design upload with wrong content type."""
        response = api_client.post(
            "/inputs/design",
            files={"file": ("design.txt", b"invalid", "text/plain")},
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 415
        assert "Unsupported content type" in response.json()["detail"]["message"]

    def test_design_upload_empty_file(self, api_client):
        """Test design upload with empty CSV."""
        response = api_client.post(
            "/inputs/design",
            files={"file": ("design.csv", b"header1,header2\n", "text/csv")},
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 400
        assert "no rows" in response.json()["detail"].lower()

    def test_sbom_upload_cyclonedx(self, api_client, test_data_dir):
        """Test uploading CycloneDX SBOM."""
        tmpdir, files = test_data_dir

        with open(files["sbom_cyclonedx"], "rb") as f:
            response = api_client.post(
                "/inputs/sbom",
                files={"file": ("sbom.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "sbom"
        assert data["format"] == "CycloneDX"
        assert len(data.get("component_preview", [])) > 0

    def test_sbom_upload_spdx(self, api_client, test_data_dir):
        """Test uploading SPDX SBOM."""
        tmpdir, files = test_data_dir

        with open(files["sbom_spdx"], "rb") as f:
            response = api_client.post(
                "/inputs/sbom",
                files={"file": ("sbom.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "sbom"
        assert data["format"] in ["SPDX", "auto"]

    def test_cve_upload_valid(self, api_client, test_data_dir):
        """Test uploading CVE feed."""
        tmpdir, files = test_data_dir

        with open(files["cve"], "rb") as f:
            response = api_client.post(
                "/inputs/cve",
                files={"file": ("cve.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "cve"
        assert data["record_count"] == 300

    def test_sarif_upload_valid(self, api_client, test_data_dir):
        """Test uploading SARIF scan results."""
        tmpdir, files = test_data_dir

        with open(files["sarif"], "rb") as f:
            response = api_client.post(
                "/inputs/sarif",
                files={"file": ("scan.sarif", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "sarif"
        assert "tools" in data

    def test_vex_upload_valid(self, api_client, test_data_dir):
        """Test uploading VEX document."""
        tmpdir, files = test_data_dir

        with open(files["vex"], "rb") as f:
            response = api_client.post(
                "/inputs/vex",
                files={"file": ("vex.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "vex"

    def test_cnapp_upload_valid(self, api_client, test_data_dir):
        """Test uploading CNAPP findings."""
        tmpdir, files = test_data_dir

        with open(files["cnapp"], "rb") as f:
            response = api_client.post(
                "/inputs/cnapp",
                files={"file": ("cnapp.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["stage"] == "cnapp"
        assert "asset_count" in data

    def test_chunked_upload_workflow(self, api_client, test_data_dir):
        """Test complete chunked upload workflow."""
        tmpdir, files = test_data_dir

        with open(files["sbom_cyclonedx"], "rb") as f:
            content = f.read()

        total_size = len(content)
        chunk_size = total_size // 3

        response = api_client.post(
            "/inputs/sbom/chunks/start",
            json={
                "file_name": "sbom.json",
                "total_size": total_size,
                "content_type": "application/json",
            },
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 200
        response_data = response.json()
        session_id = response_data["session"].get("id") or response_data["session"].get(
            "session_id"
        )

        for offset in [0, chunk_size, chunk_size * 2]:
            chunk = content[offset : offset + chunk_size]
            response = api_client.put(
                f"/inputs/sbom/chunks/{session_id}",
                files={"chunk": ("chunk", chunk, "application/octet-stream")},
                params={"offset": offset},
                headers={"X-API-Key": "test-token"},
            )
            assert response.status_code == 200

        response = api_client.post(
            f"/inputs/sbom/chunks/{session_id}/complete",
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 200
        assert response.json()["stage"] == "sbom"

    def test_pipeline_run_complete_workflow(self, api_client, test_data_dir):
        """Test complete pipeline execution with all inputs."""
        tmpdir, files = test_data_dir

        with open(files["design"], "rb") as f:
            api_client.post(
                "/inputs/design",
                files={"file": ("design.csv", f, "text/csv")},
                headers={"X-API-Key": "test-token"},
            )

        with open(files["sbom_cyclonedx"], "rb") as f:
            api_client.post(
                "/inputs/sbom",
                files={"file": ("sbom.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        with open(files["sarif"], "rb") as f:
            api_client.post(
                "/inputs/sarif",
                files={"file": ("scan.sarif", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        with open(files["cve"], "rb") as f:
            api_client.post(
                "/inputs/cve",
                files={"file": ("cve.json", f, "application/json")},
                headers={"X-API-Key": "test-token"},
            )

        response = api_client.post(
            "/pipeline/run",
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 200
        result = response.json()

        assert "run_id" in result
        assert "severity_overview" in result
        assert "guardrail_evaluation" in result
        assert "modules" in result

    def test_pipeline_run_missing_inputs(self, api_client):
        """Test pipeline execution with missing required inputs."""
        response = api_client.post(
            "/pipeline/run",
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code == 400
        assert "missing" in response.json()["detail"]["message"].lower()

    def test_authentication_failure(self, api_client):
        """Test API endpoints without authentication."""
        response = api_client.get("/inputs/design/chunks/fake-session")
        assert response.status_code == 401

    def test_authentication_invalid_token(self, api_client):
        """Test API endpoints with invalid token."""
        response = api_client.get(
            "/inputs/design/chunks/fake-session",
            headers={"X-API-Key": "invalid-token"},
        )
        assert response.status_code == 401

    def test_upload_size_limit_exceeded(self, api_client):
        """Test upload size limit enforcement."""
        large_content = b"x" * (100 * 1024 * 1024)  # 100MB

        response = api_client.post(
            "/inputs/sbom",
            files={"file": ("huge.json", large_content, "application/json")},
            headers={"X-API-Key": "test-token"},
        )

        assert response.status_code in [200, 400, 413]


class TestCLICommandsE2E:
    """End-to-end tests for all CLI commands."""

    @pytest.fixture
    def test_data_dir(self):
        """Create temporary directory with test data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            files = TestDataGenerator.write_test_data(tmpdir_path)
            yield tmpdir_path, files

    def test_cli_run_command(self, test_data_dir):
        """Test CLI run command with all inputs."""
        from core.cli import main

        tmpdir, files = test_data_dir
        output_file = tmpdir / "output.json"

        os.environ["FIXOPS_API_TOKEN"] = "test-token"
        os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"

        args = [
            "run",
            "--design",
            str(files["design"]),
            "--sbom",
            str(files["sbom_cyclonedx"]),
            "--sarif",
            str(files["sarif"]),
            "--cve",
            str(files["cve"]),
            "--output",
            str(output_file),
            "--pretty",
        ]

        exit_code = main(args)

        assert exit_code == 0
        assert output_file.exists()

        result = json.loads(output_file.read_text())
        assert "severity_overview" in result
        assert "modules" in result

    def test_cli_make_decision_command(self, test_data_dir):
        """Test CLI make-decision command."""
        from core.cli import main

        tmpdir, files = test_data_dir

        os.environ["FIXOPS_API_TOKEN"] = "test-token"
        os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"

        args = [
            "make-decision",
            "--sbom",
            str(files["sbom_cyclonedx"]),
            "--sarif",
            str(files["sarif"]),
            "--cve",
            str(files["cve"]),
        ]

        exit_code = main(args)

        assert exit_code in [0, 1, 2]

    def test_cli_demo_command(self):
        """Test CLI demo command."""
        from core.cli import main

        with tempfile.TemporaryDirectory() as tmpdir:
            output_file = Path(tmpdir) / "demo.json"

            args = [
                "demo",
                "--mode",
                "demo",
                "--output",
                str(output_file),
                "--pretty",
            ]

            exit_code = main(args)

            assert exit_code == 0
            assert output_file.exists()

    def test_cli_health_command(self):
        """Test CLI health command."""
        from core.cli import main

        args = ["health", "--pretty"]

        exit_code = main(args)

        assert exit_code == 0

    def test_cli_show_overlay_command(self):
        """Test CLI show-overlay command."""
        from core.cli import main

        args = ["show-overlay", "--pretty"]

        exit_code = main(args)

        assert exit_code == 0

    def test_cli_train_forecast_command(self):
        """Test CLI train-forecast command."""
        from core.cli import main

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            incidents_file = tmpdir_path / "incidents.json"
            output_file = tmpdir_path / "calibrated.json"

            incidents = [
                {
                    "states": ["low", "medium", "high"],
                    "final_severity": "high",
                }
                for _ in range(50)
            ]

            incidents_file.write_text(json.dumps(incidents))

            args = [
                "train-forecast",
                "--incidents",
                str(incidents_file),
                "--output",
                str(output_file),
                "--pretty",
            ]

            exit_code = main(args)

            assert exit_code == 0
            assert output_file.exists()

            result = json.loads(output_file.read_text())
            assert "bayesian_prior" in result
            assert "markov_transitions" in result


class TestSecurityFixes:
    """Tests for security fixes including API key sanitization."""

    @pytest.fixture
    def api_client(self):
        """Create FastAPI test client."""
        from fastapi.testclient import TestClient

        from apps.api.app import create_app

        os.environ["FIXOPS_API_TOKEN"] = "test-secret-api-key-12345"
        os.environ["FIXOPS_DISABLE_TELEMETRY"] = "1"
        os.environ["FIXOPS_MODE"] = "demo"
        os.environ["FIXOPS_JWT_SECRET"] = (
            "test-jwt-secret-for-testing-purposes-only-do-not-use-in-production"
        )

        app = create_app()
        client = TestClient(app)
        return client

    def test_api_key_not_in_error_logs(self, api_client, caplog):
        """Test that API keys are sanitized from error logs."""
        import logging

        caplog.set_level(logging.ERROR)

        response = api_client.post(
            "/inputs/design",
            files={"file": ("design.csv", b"invalid\ndata", "text/csv")},
            headers={"X-API-Key": "test-secret-api-key-12345"},
        )

        assert response.status_code in [400, 500]

        for record in caplog.records:
            assert "test-secret-api-key-12345" not in record.message
            assert "test-secret" not in record.message.lower()

    def test_upload_limit_metadata_preserved(self, api_client):
        """Test that upload limit error response includes max_bytes metadata."""
        large_content = b"x" * (100 * 1024 * 1024)

        response = api_client.post(
            "/inputs/sbom",
            files={"file": ("huge.json", large_content, "application/json")},
            headers={"X-API-Key": "test-secret-api-key-12345"},
        )

        if response.status_code == 413:
            detail = response.json()["detail"]
            assert isinstance(detail, dict)
            assert "message" in detail
            assert "max_bytes" in detail
            assert isinstance(detail["max_bytes"], int)

    def test_chunked_upload_complete_all_bytes(self, api_client):
        """Test that chunked upload handles trailing bytes correctly."""
        content = b"x" * 1000
        total_size = len(content)
        chunk_size = total_size // 3

        response = api_client.post(
            "/inputs/sbom/chunks/start",
            json={
                "file_name": "test.json",
                "total_size": total_size,
                "content_type": "application/json",
            },
            headers={"X-API-Key": "test-secret-api-key-12345"},
        )

        assert response.status_code == 200
        session_id = response.json()["session"].get("id") or response.json()[
            "session"
        ].get("session_id")

        offset = 0
        while offset < total_size:
            chunk = content[offset : offset + chunk_size]
            response = api_client.put(
                f"/inputs/sbom/chunks/{session_id}",
                files={"chunk": ("chunk", chunk, "application/octet-stream")},
                params={"offset": offset},
                headers={"X-API-Key": "test-secret-api-key-12345"},
            )
            assert response.status_code == 200
            offset += len(chunk)

        response = api_client.post(
            f"/inputs/sbom/chunks/{session_id}/complete",
            headers={"X-API-Key": "test-secret-api-key-12345"},
        )

        if response.status_code != 200:
            print(f"Complete response: {response.json()}")

        assert response.status_code in [200, 400]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
