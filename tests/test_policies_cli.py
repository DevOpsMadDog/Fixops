"""
Tests for policy management CLI commands.
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

# `python -m core.cli` runs in a fresh subprocess that does NOT inherit our
# in-process sys.path, so `core` (in suite-core) is unimportable unless we put
# the suite dirs on PYTHONPATH explicitly. Build that once from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SUITE_PYTHONPATH = os.pathsep.join(
    str(p) for p in sorted(_REPO_ROOT.glob("suite-*")) if p.is_dir()
)


def _cli_env(temp_db):
    """Subprocess env with suite dirs on PYTHONPATH + the temp policy DB."""
    existing = os.environ.get("PYTHONPATH", "")
    pythonpath = _SUITE_PYTHONPATH + (os.pathsep + existing if existing else "")
    return {**os.environ, "POLICY_DB_PATH": temp_db, "PYTHONPATH": pythonpath}


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
        env=_cli_env(temp_db),
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
        ],
        capture_output=True,
        text=True,
        env=_cli_env(temp_db),
    )
    assert result.returncode == 0
    assert "Created policy:" in result.stdout
