"""
Tests for team management CLI commands.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
_SUITE_PYTHONPATH = os.pathsep.join(
    str(Path(_PROJECT_ROOT) / d)
    for d in ["suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-integrations", "suite-evidence-risk", "."]
)


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    os.unlink(path)


def _cli_env(**extra):
    """Build subprocess env with PYTHONPATH for suite imports."""
    env = {**os.environ, **extra}
    env["PYTHONPATH"] = _SUITE_PYTHONPATH + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_teams_list_empty(temp_db):
    """Test listing teams when empty."""
    result = subprocess.run(
        ["python", "-m", "core.cli", "teams", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env=_cli_env(USER_DB_PATH=temp_db),
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
        env=_cli_env(USER_DB_PATH=temp_db),
    )
    assert result.returncode == 0
    assert "Created team:" in result.stdout
