"""
Tests for user management CLI commands.
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


def test_users_list_empty(temp_db):
    """Test listing users when empty."""
    result = subprocess.run(
        ["python", "-m", "core.cli", "users", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env={**os.environ, "USER_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)


def test_users_create(temp_db):
    """Test creating a user via CLI."""
    result = subprocess.run(
        [
            "python",
            "-m",
            "core.cli",
            "users",
            "create",
            "--email",
            "test@example.com",
            "--password",
            "SecurePass123!",
            "--first-name",
            "Test",
            "--last-name",
            "User",
            "--role",
            "viewer",
        ],
        capture_output=True,
        text=True,
        env={**os.environ, "USER_DB_PATH": temp_db},
    )
    assert result.returncode == 0
    assert "Created user:" in result.stdout
