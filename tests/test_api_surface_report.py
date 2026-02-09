"""
PR2.2a API Surface Report Tests

Tests for scripts/api_surface_report.py:
- Runs the script via subprocess and asserts exit code 0
- Parses stdout/JSON output and validates structure
- Asserts total_operations >= 363
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Project root for running the script
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "api_surface_report.py"


class TestApiSurfaceReportScript:
    """Tests for the api_surface_report.py CLI script."""

    def test_script_exists(self):
        """Script file should exist."""
        assert SCRIPT_PATH.exists(), f"Script not found: {SCRIPT_PATH}"

    def test_script_runs_successfully(self):
        """Script should exit with code 0 when run."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 0, f"Script failed:\n{result.stderr}\n{result.stdout}"

    def test_script_stdout_contains_report(self):
        """Stdout should contain readable report elements."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 0
        
        # Check for expected report sections
        stdout = result.stdout
        assert "API SURFACE REPORT" in stdout
        assert "Total Operations" in stdout
        assert "Unique Paths" in stdout
        assert "By HTTP Method" in stdout
        assert "By Prefix Bucket" in stdout

    def test_stdout_shows_method_counts(self):
        """Stdout should show GET/POST method counts."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 0
        stdout = result.stdout
        
        # Should have GET and POST at minimum
        assert "GET" in stdout
        assert "POST" in stdout

    def test_stdout_shows_api_v1_prefix(self):
        """Stdout should show /api/v1 prefix bucket."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 0
        assert "/api/v1" in result.stdout


class TestApiSurfaceReportJson:
    """Tests for JSON output mode."""

    def test_json_output_flag(self):
        """--json flag should write valid JSON file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--json", json_path],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0, f"Script failed:\n{result.stderr}"
            
            # Parse JSON
            with open(json_path) as f:
                data = json.load(f)
            
            assert isinstance(data, dict)
        finally:
            os.unlink(json_path)

    def test_json_has_total_operations(self):
        """JSON output should have total_operations >= 363."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--json", json_path],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            with open(json_path) as f:
                data = json.load(f)
            
            assert "total_operations" in data
            assert data["total_operations"] >= 363, (
                f"Expected >= 363 operations, got {data['total_operations']}"
            )
        finally:
            os.unlink(json_path)

    def test_json_has_by_method(self):
        """JSON output should have by_method with GET/POST keys."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--json", json_path],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            with open(json_path) as f:
                data = json.load(f)
            
            assert "by_method" in data
            assert "GET" in data["by_method"]
            assert "POST" in data["by_method"]
        finally:
            os.unlink(json_path)

    def test_json_has_by_prefix(self):
        """JSON output should have by_prefix with /api/v1 bucket."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--json", json_path],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            with open(json_path) as f:
                data = json.load(f)
            
            assert "by_prefix" in data
            assert "/api/v1" in data["by_prefix"]
        finally:
            os.unlink(json_path)

    def test_json_has_aliases_field(self):
        """JSON output should have aliases field (may be empty list)."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [sys.executable, str(SCRIPT_PATH), "--json", json_path],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            with open(json_path) as f:
                data = json.load(f)
            
            assert "aliases" in data
            assert isinstance(data["aliases"], list)
        finally:
            os.unlink(json_path)


class TestApiSurfaceReportMinEndpoints:
    """Tests for --min-endpoints flag."""

    def test_min_endpoints_pass(self):
        """--min-endpoints should pass when threshold is met."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--min-endpoints", "10"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 0
        assert "PASS" in result.stdout

    def test_min_endpoints_fail(self):
        """--min-endpoints should fail when threshold is not met."""
        result = subprocess.run(
            [sys.executable, str(SCRIPT_PATH), "--min-endpoints", "99999"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
        )
        assert result.returncode == 1
        assert "FAIL" in result.stderr


class TestApiSurfaceReportOnlyPrefix:
    """Tests for --only-prefix flag."""

    def test_only_prefix_filter(self):
        """--only-prefix should filter results to matching paths."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT_PATH),
                    "--only-prefix", "/api/v1",
                    "--json", json_path,
                    "--min-endpoints", "1",  # Lower threshold for filtered results
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            with open(json_path) as f:
                data = json.load(f)
            
            # Should have filter_prefix set
            assert data.get("filter_prefix") == "/api/v1"
            
            # Should only have /api/v1 in by_prefix (if there are results)
            if data["total_operations"] > 0:
                # All prefixes should be /api/v1
                prefixes = set(data["by_prefix"].keys())
                assert prefixes == {"/api/v1"}, f"Unexpected prefixes: {prefixes}"
        finally:
            os.unlink(json_path)


class TestApiSurfaceReportQuietMode:
    """Tests for --quiet flag."""

    def test_quiet_mode_suppresses_stdout(self):
        """--quiet should suppress stdout report."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        
        try:
            result = subprocess.run(
                [
                    sys.executable, str(SCRIPT_PATH),
                    "--quiet",
                    "--json", json_path,
                ],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(PROJECT_ROOT)},
            )
            assert result.returncode == 0
            
            # stdout should be empty or nearly empty
            assert "API SURFACE REPORT" not in result.stdout
            
            # JSON should still be written
            with open(json_path) as f:
                data = json.load(f)
            assert "total_operations" in data
        finally:
            os.unlink(json_path)
