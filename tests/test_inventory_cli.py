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
    """Setup test database for CLI tests."""
    monkeypatch.setenv("FIXOPS_INVENTORY_DB", test_db_path)


class TestInventoryCLI:
    """Test inventory CLI commands."""

    def test_inventory_list_empty(self):
        """Test listing when inventory is empty."""
        result = subprocess.run(
            ["python", "-m", "core.cli", "inventory", "list", "--format", "json"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)

    def test_inventory_create(self):
        """Test creating application via CLI."""
        result = subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "inventory",
                "create",
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
        assert "Created application:" in result.stdout

    def test_inventory_search(self):
        """Test search command."""
        subprocess.run(
            [
                "python",
                "-m",
                "core.cli",
                "inventory",
                "create",
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
        """Test help command."""
        result = subprocess.run(
            ["python", "-m", "core.cli", "inventory", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "list" in result.stdout
        assert "create" in result.stdout
        assert "search" in result.stdout
