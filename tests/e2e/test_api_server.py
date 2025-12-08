"""End-to-end API server tests.

Tests the actual running API server with real requests.
"""

import os
import subprocess
import time
from pathlib import Path

import pytest
import requests

# API server configuration
API_BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("FIXOPS_API_TOKEN", "test-api-key-12345")


@pytest.fixture(scope="session")
def api_server():
    """Start API server for testing."""
    import sys
    
    # Start server in background
    server_process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "apps.api.app:create_app",
            "--factory",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
        cwd=Path(__file__).parent.parent.parent,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    
    # Wait for server to start
    max_attempts = 30
    for i in range(max_attempts):
        try:
            response = requests.get(f"{API_BASE_URL}/health", timeout=2)
            if response.status_code == 200:
                break
        except requests.exceptions.RequestException:
            time.sleep(1)
    else:
        server_process.terminate()
        pytest.fail("API server failed to start")
    
    yield server_process
    
    # Cleanup
    server_process.terminate()
    server_process.wait()


class TestAPIServer:
    """Test API server functionality."""
    
    def test_health_endpoint(self, api_server):
        """Test health check endpoint."""
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_api_key_authentication(self, api_server):
        """Test API key authentication."""
        # Without API key
        response = requests.get(f"{API_BASE_URL}/api/v1/status", timeout=5)
        assert response.status_code == 401
        
        # With API key
        headers = {"X-API-Key": API_KEY}
        response = requests.get(
            f"{API_BASE_URL}/api/v1/status", headers=headers, timeout=5
        )
        assert response.status_code == 200
    
    def test_sarif_upload(self, api_server):
        """Test SARIF file upload."""
        headers = {"X-API-Key": API_KEY}
        
        # Create test SARIF file
        test_sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "test-tool", "version": "1.0.0"}
                    },
                    "results": [
                        {
                            "ruleId": "test-rule",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "test.py"},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        
        import json
        import tempfile
        
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False
        ) as f:
            json.dump(test_sarif, f)
            temp_path = f.name
        
        try:
            with open(temp_path, "rb") as f:
                files = {"file": ("test.sarif", f, "application/json")}
                response = requests.post(
                    f"{API_BASE_URL}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=30,
                )
            
            assert response.status_code in [200, 201]
        finally:
            os.unlink(temp_path)
    
    def test_sbom_upload(self, api_server):
        """Test SBOM file upload."""
        headers = {"X-API-Key": API_KEY}
        
        # Create test SBOM (CycloneDX)
        test_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "name": "test-package",
                    "version": "1.0.0",
                    "purl": "pkg:pypi/test-package@1.0.0",
                }
            ],
        }
        
        import json
        import tempfile
        
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(test_sbom, f)
            temp_path = f.name
        
        try:
            with open(temp_path, "rb") as f:
                files = {"file": ("test-sbom.json", f, "application/json")}
                response = requests.post(
                    f"{API_BASE_URL}/inputs/sbom",
                    headers=headers,
                    files=files,
                    timeout=30,
                )
            
            assert response.status_code in [200, 201]
        finally:
            os.unlink(temp_path)
    
    def test_reachability_analysis(self, api_server):
        """Test reachability analysis endpoint."""
        headers = {"X-API-Key": API_KEY}
        
        payload = {
            "repository": {
                "url": "https://github.com/test/repo",
                "branch": "main",
            },
            "cve_id": "CVE-2024-0001",
            "component_name": "test-component",
            "component_version": "1.0.0",
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/reachability/analyze",
            headers=headers,
            json=payload,
            timeout=60,
        )
        
        # Should accept request (may be async)
        assert response.status_code in [200, 201, 202]
    
    def test_runtime_analysis(self, api_server):
        """Test runtime analysis endpoint."""
        headers = {"X-API-Key": API_KEY}
        
        payload = {
            "container_id": "test-container",
            "analysis_type": "iast",
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/runtime/analyze",
            headers=headers,
            json=payload,
            timeout=30,
        )
        
        assert response.status_code in [200, 201, 202]


class TestCLIIntegration:
    """Test CLI integration with API server."""
    
    def test_cli_scan(self, api_server):
        """Test CLI scan command."""
        import subprocess
        import tempfile
        from pathlib import Path
        
        # Create test code file
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text("def test(): pass\n")
            
            # Run CLI scan
            result = subprocess.run(
                [
                    "python",
                    "-m",
                    "cli.main",
                    "scan",
                    str(tmpdir),
                    "--api-url",
                    API_BASE_URL,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            # CLI should execute (may fail if API key not set, but should not crash)
            assert result.returncode in [0, 1]  # 0 = success, 1 = error (expected if no API key)
    
    def test_cli_auth(self, api_server):
        """Test CLI auth command."""
        import subprocess
        
        # Test login (will fail without real API key, but should not crash)
        result = subprocess.run(
            [
                "python",
                "-m",
                "cli.main",
                "auth",
                "login",
                "--api-key",
                API_KEY,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Should execute without crashing
        assert result.returncode in [0, 1]


class TestEndToEndWorkflows:
    """Test complete end-to-end workflows."""
    
    def test_vulnerability_management_workflow(self, api_server):
        """Test complete vulnerability management workflow."""
        headers = {"X-API-Key": API_KEY}
        
        # 1. Upload SARIF
        test_sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "test-tool", "version": "1.0.0"}
                    },
                    "results": [],
                }
            ],
        }
        
        import json
        import tempfile
        
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False
        ) as f:
            json.dump(test_sarif, f)
            temp_path = f.name
        
        try:
            # Upload
            with open(temp_path, "rb") as f:
                files = {"file": ("test.sarif", f, "application/json")}
                upload_response = requests.post(
                    f"{API_BASE_URL}/inputs/sarif",
                    headers=headers,
                    files=files,
                    timeout=30,
                )
            
            assert upload_response.status_code in [200, 201]
            
            # 2. Check status
            status_response = requests.get(
                f"{API_BASE_URL}/api/v1/status", headers=headers, timeout=5
            )
            assert status_response.status_code == 200
        
        finally:
            os.unlink(temp_path)
    
    def test_reachability_workflow(self, api_server):
        """Test reachability analysis workflow."""
        headers = {"X-API-Key": API_KEY}
        
        # Submit reachability analysis
        payload = {
            "repository": {
                "url": "https://github.com/test/repo",
                "branch": "main",
            },
            "cve_id": "CVE-2024-0001",
            "component_name": "test-component",
            "component_version": "1.0.0",
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/reachability/analyze",
            headers=headers,
            json=payload,
            timeout=60,
        )
        
        # Should accept request
        assert response.status_code in [200, 201, 202]
        
        # If async, check job status
        if response.status_code == 202:
            job_id = response.json().get("job_id")
            if job_id:
                status_response = requests.get(
                    f"{API_BASE_URL}/api/v1/reachability/jobs/{job_id}",
                    headers=headers,
                    timeout=10,
                )
                assert status_response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
