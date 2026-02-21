"""
Tests for integrations CLI commands.

These tests are skipped because the 'integrations' CLI command is not yet implemented.
The CLI currently supports: stage-run, run, ingest, make-decision, analyze, health,
get-evidence, show-overlay, train-forecast, demo, train-bn-lr, predict-bn-lr,
backtest-bn-lr, teams, users, mpte
"""
import json
import subprocess
import sys
import tempfile

import pytest

pytestmark = pytest.mark.skip(reason="CLI 'integrations' command not yet implemented")

from core.integration_db import IntegrationDB
from core.integration_models import Integration, IntegrationStatus, IntegrationType


@pytest.fixture
def temp_db():
    """Create temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    import os

    os.close(fd)
    db = IntegrationDB(db_path=path)
    yield db, path
    os.unlink(path)


def test_integrations_list_empty(temp_db):
    """Test listing integrations when empty."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) == 0


def test_integrations_list_table(temp_db):
    """Test listing integrations in table format."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(integration)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "list", "--format", "table"],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Test Jira" in result.stdout
    assert "jira" in result.stdout


def test_integrations_list_json(temp_db):
    """Test listing integrations in JSON format."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(integration)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "list", "--format", "json"],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["name"] == "Test Jira"


def test_integrations_list_filter_type(temp_db):
    """Test filtering integrations by type."""
    db, db_path = temp_db

    jira_integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(jira_integration)

    slack_integration = Integration(
        id="",
        name="Test Slack",
        integration_type=IntegrationType.SLACK,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    db.create_integration(slack_integration)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "integrations",
            "list",
            "--type",
            "jira",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 1
    assert data[0]["integration_type"] == "jira"


def test_integrations_create(temp_db):
    """Test creating an integration."""
    db, db_path = temp_db

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "integrations",
            "create",
            "--name",
            "Test Jira",
            "--type",
            "jira",
        ],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Created integration" in result.stdout
    data = json.loads(result.stdout.split("\n")[1])
    assert data["name"] == "Test Jira"


def test_integrations_get(temp_db):
    """Test getting integration details."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={"token": "secret-token"},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "get", created.id],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["name"] == "Test Jira"
    assert data["config"]["token"] == "***REDACTED***"


def test_integrations_get_with_secrets(temp_db):
    """Test getting integration with secrets shown."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={"token": "secret-token"},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "integrations",
            "get",
            created.id,
            "--show-secrets",
        ],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["config"]["token"] == "secret-token"


def test_integrations_get_not_found(temp_db):
    """Test getting non-existent integration."""
    db, db_path = temp_db

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "get", "nonexistent-id"],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 1
    assert "not found" in result.stdout


def test_integrations_update(temp_db):
    """Test updating integration."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "integrations",
            "update",
            created.id,
            "--name",
            "Updated Jira",
            "--status",
            "inactive",
        ],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Updated integration" in result.stdout
    data = json.loads(result.stdout.split("\n")[1])
    assert data["name"] == "Updated Jira"
    assert data["status"] == "inactive"


def test_integrations_delete_without_confirm(temp_db):
    """Test deleting integration without confirmation."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "delete", created.id],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 1
    assert "use --confirm" in result.stdout


def test_integrations_delete_with_confirm(temp_db):
    """Test deleting integration with confirmation."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "core.cli",
            "integrations",
            "delete",
            created.id,
            "--confirm",
        ],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Deleted integration" in result.stdout


def test_integrations_test(temp_db):
    """Test testing integration connection."""
    db, db_path = temp_db

    integration = Integration(
        id="",
        name="Test Jira",
        integration_type=IntegrationType.JIRA,
        status=IntegrationStatus.ACTIVE,
        config={},
    )
    created = db.create_integration(integration)

    result = subprocess.run(
        [sys.executable, "-m", "core.cli", "integrations", "test", created.id],
        capture_output=True,
        text=True,
        env={"INTEGRATION_DB_PATH": db_path},
    )

    assert result.returncode == 0
    assert "Testing integration" in result.stdout
