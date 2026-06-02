"""
Tests for inventory CLI commands.
"""
import json
import os
import shutil
import subprocess
import tempfile

import pytest


@pytest.fixture
def test_db_path():
    """Create temporary database path."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_inventory.db")
    yield db_path
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def setup_test_db(test_db_path, monkeypatch):
    """Isolate each test on its own DB.

    The CLI inventory handler resolves its store from FIXOPS_DB_PATH (the
    platform-wide convention), so the subprocess must inherit that var — using
    a non-existent FIXOPS_INVENTORY_DB silently leaked writes to the shared
    .fixops_data/fixops.db and broke isolation (duplicate-name UNIQUE errors).
    """
    monkeypatch.setenv("FIXOPS_DB_PATH", test_db_path)


class TestInventoryCLI:
    """Test inventory CLI commands."""

    def test_inventory_list_empty(self):
        """Test listing when inventory is empty (subcommand: apps)."""
        result = subprocess.run(
            ["python", "-m", "core.cli", "inventory", "apps", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        # stdout must be pure machine-readable JSON (logs go to stderr).
        data = json.loads(result.stdout)
        assert isinstance(data, list)

    def test_inventory_create(self):
        """Test creating application via CLI (subcommand: add)."""
        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "inventory",
                "add",
                "--name",
                "CLI Test App",
                "--description",
                "Created via CLI",
                "--criticality",
                "high",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Added application:" in result.stdout

    def test_inventory_search(self):
        """Test search command."""
        subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "inventory",
                "add",
                "--name",
                "Searchable App",
                "--description",
                "For search test",
                "--criticality",
                "medium",
            ],
            capture_output=True,
        )

        result = subprocess.run(
            ["python", "-m", "core.cli", "inventory", "search", "Searchable"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "applications" in data

    def test_inventory_help(self):
        """Test help command lists the real subcommands."""
        result = subprocess.run(
            ["python", "-m", "core.cli", "inventory", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "apps" in result.stdout
        assert "add" in result.stdout
        assert "search" in result.stdout
