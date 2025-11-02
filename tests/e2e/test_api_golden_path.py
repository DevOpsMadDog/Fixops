"""
Phase 1.1: API Golden Path E2E Tests

Tests that spawn a real uvicorn server and make real HTTP requests.
No mocks or stubs - this is ruthless end-to-end testing.
"""

import pytest
import requests

from tests.harness import ServerManager


@pytest.fixture
def api_server(fixture_manager, flag_config_manager):
    """Start a real uvicorn server for testing."""
    flag_config_manager.create_demo_config()

    env = {
        "FIXOPS_API_TOKEN": "test-token-e2e",
        "FIXOPS_DISABLE_TELEMETRY": "1",
    }

    server = ServerManager(
        host="127.0.0.1",
        port=8765,
        app_module="apps.api.app:create_app",
        env=env,
        timeout=30,
    )

    server.start()
    yield server
    server.stop()


class TestAPIGoldenPath:
    """Test API golden path with real server."""

    def test_server_starts_and_responds(self, api_server):
        """Test that server starts and responds to health check."""
        response = requests.get(f"{api_server.base_url}/api/v1/health", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"

    def test_api_rejects_missing_token(self, api_server):
        """Test that API rejects requests without API token."""
        response = requests.get(f"{api_server.base_url}/api/v1/status", timeout=5)
        assert response.status_code in [401, 403]

    def test_api_rejects_invalid_token(self, api_server):
        """Test that API rejects requests with invalid API token."""
        headers = {"X-API-Key": "invalid-token"}
        response = requests.get(
            f"{api_server.base_url}/api/v1/status",
            headers=headers,
            timeout=5,
        )
        assert response.status_code in [401, 403]

    def test_api_accepts_valid_token(self, api_server):
        """Test that API accepts requests with valid API token."""
        headers = {"X-API-Key": "test-token-e2e"}
        response = requests.get(
            f"{api_server.base_url}/api/v1/status",
            headers=headers,
            timeout=5,
        )
        assert response.status_code == 200

    def test_upload_design_csv(self, api_server, demo_fixtures):
        """Test uploading design CSV via POST /inputs/design."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["design"], "rb") as f:
            files = {"file": ("design.csv", f, "text/csv")}
            response = requests.post(
                f"{api_server.base_url}/inputs/design",
                headers=headers,
                files=files,
                timeout=10,
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "status" in data

    def test_upload_sbom_json(self, api_server, demo_fixtures):
        """Test uploading SBOM JSON via POST /inputs/sbom."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["sbom"], "rb") as f:
            files = {"file": ("sbom.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sbom",
                headers=headers,
                files=files,
                timeout=10,
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "status" in data

    def test_upload_cve_json(self, api_server, demo_fixtures):
        """Test uploading CVE JSON via POST /inputs/cve."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["cve"], "rb") as f:
            files = {"file": ("cve.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/cve",
                headers=headers,
                files=files,
                timeout=10,
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "status" in data

    def test_upload_sarif_json(self, api_server, demo_fixtures):
        """Test uploading SARIF JSON via POST /inputs/sarif."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["sarif"], "rb") as f:
            files = {"file": ("scan.sarif", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sarif",
                headers=headers,
                files=files,
                timeout=10,
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "status" in data

    def test_run_pipeline_end_to_end(self, api_server, demo_fixtures):
        """Test complete pipeline execution end-to-end."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["design"], "rb") as f:
            files = {"file": ("design.csv", f, "text/csv")}
            response = requests.post(
                f"{api_server.base_url}/inputs/design",
                headers=headers,
                files=files,
                timeout=10,
            )
            assert response.status_code == 200

        with open(demo_fixtures["sbom"], "rb") as f:
            files = {"file": ("sbom.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sbom",
                headers=headers,
                files=files,
                timeout=10,
            )
            assert response.status_code == 200

        with open(demo_fixtures["cve"], "rb") as f:
            files = {"file": ("cve.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/cve",
                headers=headers,
                files=files,
                timeout=10,
            )
            assert response.status_code == 200

        with open(demo_fixtures["sarif"], "rb") as f:
            files = {"file": ("scan.sarif", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sarif",
                headers=headers,
                files=files,
                timeout=10,
            )
            assert response.status_code == 200

        response = requests.post(
            f"{api_server.base_url}/pipeline/run",
            headers=headers,
            timeout=60,
        )

        assert response.status_code == 200
        data = response.json()

        assert "verdict" in data
        assert "risk_score" in data
        assert "modules" in data

        assert data["verdict"] in ["allow", "review", "block"]
        assert isinstance(data["risk_score"], (int, float))
        assert isinstance(data["modules"], dict)

    def test_x_product_name_header_present(self, api_server):
        """Test that X-Product-Name header is present in responses."""
        headers = {"X-API-Key": "test-token-e2e"}
        response = requests.get(
            f"{api_server.base_url}/api/v1/status",
            headers=headers,
            timeout=5,
        )

        assert response.status_code == 200
        assert "X-Product-Name" in response.headers
        product_name = response.headers["X-Product-Name"]
        assert product_name.lower() in ["fixops", "aldeci"]

    def test_api_handles_large_upload(self, api_server, fixture_manager):
        """Test that API handles large file uploads (streaming to disk)."""
        headers = {"X-API-Key": "test-token-e2e"}

        large_sbom = fixture_manager.generate_large_sbom(num_components=1000)

        with open(large_sbom, "rb") as f:
            files = {"file": ("large_sbom.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sbom",
                headers=headers,
                files=files,
                timeout=30,
            )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data or "status" in data

    def test_api_handles_malformed_json(self, api_server, fixture_manager):
        """Test that API handles malformed JSON gracefully."""
        headers = {"X-API-Key": "test-token-e2e"}

        malformed_json = fixture_manager.temp_dir / "malformed.json"
        with open(malformed_json, "w") as f:
            f.write("{invalid json content")

        with open(malformed_json, "rb") as f:
            files = {"file": ("malformed.json", f, "application/json")}
            response = requests.post(
                f"{api_server.base_url}/inputs/sbom",
                headers=headers,
                files=files,
                timeout=10,
            )

        assert response.status_code in [400, 422, 500]

    def test_api_handles_missing_required_input(self, api_server):
        """Test that API handles missing required inputs gracefully."""
        headers = {"X-API-Key": "test-token-e2e"}

        response = requests.post(
            f"{api_server.base_url}/pipeline/run",
            headers=headers,
            timeout=10,
        )

        assert response.status_code in [400, 422]

    def test_concurrent_api_requests(self, api_server, demo_fixtures):
        """Test that API handles concurrent requests correctly."""
        import concurrent.futures

        headers = {"X-API-Key": "test-token-e2e"}

        def upload_design():
            with open(demo_fixtures["design"], "rb") as f:
                files = {"file": ("design.csv", f, "text/csv")}
                response = requests.post(
                    f"{api_server.base_url}/inputs/design",
                    headers=headers,
                    files=files,
                    timeout=10,
                )
                return response.status_code

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(upload_design) for _ in range(5)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        assert all(status == 200 for status in results)

    def test_server_logs_no_secrets(self, api_server, demo_fixtures):
        """Test that server logs don't contain secrets or PII."""
        headers = {"X-API-Key": "test-token-e2e"}

        with open(demo_fixtures["design"], "rb") as f:
            files = {"file": ("design.csv", f, "text/csv")}
            requests.post(
                f"{api_server.base_url}/inputs/design",
                headers=headers,
                files=files,
                timeout=10,
            )

        stdout, stderr = api_server.get_logs()
        logs = stdout + stderr

        secret_patterns = ["test-token-e2e", "password", "secret", "api_key"]
        for pattern in secret_patterns:
            assert (
                pattern.lower() not in logs.lower()
            ), f"Found secret '{pattern}' in logs"
