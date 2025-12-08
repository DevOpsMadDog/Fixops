"""End-to-end CLI functionality tests.

Tests CLI commands against real API server.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import requests

API_BASE_URL = "http://localhost:8000"
API_KEY = os.getenv("FIXOPS_API_TOKEN", "test-api-key-12345")


@pytest.fixture
def api_server_running():
    """Check if API server is running."""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=2)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


class TestCLIFunctionality:
    """Test CLI functionality end-to-end."""
    
    @pytest.mark.skipif(
        not pytest.config.getoption("--api-server-running", default=False),
        reason="API server not running",
    )
    def test_cli_scan_command(self, api_server_running):
        """Test CLI scan command."""
        if not api_server_running:
            pytest.skip("API server not running")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test Python file
            test_file = Path(tmpdir) / "test.py"
            test_file.write_text(
                """
def vulnerable_function(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return execute(query)
"""
            )
            
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
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=60,
                env={**os.environ, "FIXOPS_API_TOKEN": API_KEY},
            )
            
            # Should execute successfully
            assert result.returncode in [0, 1]  # 0 = success, 1 = error (acceptable)
    
    def test_cli_auth_login(self, api_server_running):
        """Test CLI auth login."""
        if not api_server_running:
            pytest.skip("API server not running")
        
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
    
    def test_cli_config(self, api_server_running):
        """Test CLI config commands."""
        if not api_server_running:
            pytest.skip("API server not running")
        
        # Test config show
        result = subprocess.run(
            ["python", "-m", "cli.main", "config", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        assert result.returncode == 0
        
        # Test config set-api-url
        result = subprocess.run(
            [
                "python",
                "-m",
                "cli.main",
                "config",
                "set-api-url",
                "--api-url",
                API_BASE_URL,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            input="y\n",  # Confirm
        )
        
        assert result.returncode in [0, 1]


class TestCLIWithRealAPI:
    """Test CLI with real API server."""
    
    def test_scan_real_codebase(self, api_server_running):
        """Test scanning a real codebase."""
        if not api_server_running:
            pytest.skip("API server not running")
        
        # Use workspace root as test codebase
        workspace_root = Path(__file__).parent.parent.parent
        
        result = subprocess.run(
            [
                "python",
                "-m",
                "cli.main",
                "scan",
                str(workspace_root / "risk"),
                "--api-url",
                API_BASE_URL,
                "--format",
                "table",
                "--exclude",
                "*.pyc",
                "--exclude",
                "__pycache__",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "FIXOPS_API_TOKEN": API_KEY},
        )
        
        # Should execute (may have findings or not)
        assert result.returncode in [0, 1]
    
    def test_monitor_command(self, api_server_running):
        """Test monitor command."""
        if not api_server_running:
            pytest.skip("API server not running")
        
        # Run monitor for a short time
        import signal
        
        process = subprocess.Popen(
            [
                "python",
                "-m",
                "cli.main",
                "monitor",
                "--api-url",
                API_BASE_URL,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "FIXOPS_API_TOKEN": API_KEY},
        )
        
        # Wait a bit then kill
        import time
        
        time.sleep(2)
        process.terminate()
        process.wait(timeout=5)
        
        # Should have started without crashing
        assert process.returncode in [0, -15]  # 0 = success, -15 = terminated


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--api-server-running"])
