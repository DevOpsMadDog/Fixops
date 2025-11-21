"""
Tests for team management CLI commands.
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


def test_teams_list_empty(temp_db):
    """Test listing teams when empty."""
    result = subprocess.run(
        ["python", "-m", "core.cli", "teams", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env={**os.environ, "USER_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_teams_create(temp_db):
    """Test creating a team via CLI."""
    result = subprocess.run(
        [
            "python",
            "-m",
            "core.cli",
            "teams",
            "create",
            "--name",
            "Engineering",
            "--description",
            "Engineering team",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "USER_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    assert "Created team:" in result.stdout
