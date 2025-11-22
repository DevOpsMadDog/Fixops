"""
Tests for policy management CLI commands.
"""
import json
import os
import subprocess
import tempfile

import pytest


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    os.unlink(path)


def test_policies_list_empty(temp_db):
    """Test listing policies when empty."""
    result = subprocess.run(
        ["python", "-m", "core.cli", "policies", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env={**os.environ, "POLICY_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_policies_create(temp_db):
    """Test creating a policy via CLI."""
    result = subprocess.run(
        [
            "python",
            "-m",
            "core.cli",
            "policies",
            "create",
            "--name",
            "Test Policy",
            "--description",
            "A test policy",
            "--type",
            "guardrail",
            "--status",
            "draft",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "POLICY_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    assert "Created policy:" in result.stdout
