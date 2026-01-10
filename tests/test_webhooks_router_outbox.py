"""
Tests for webhooks router outbox execution and connector settings.
"""
import json
import os
import sqlite3
import tempfile
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def client(authenticated_client):
    """Create test client using shared authenticated_client fixture."""
    return authenticated_client


@pytest.fixture
def outbox_db():
    """Create test database with outbox table."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox (
            outbox_id TEXT PRIMARY KEY,
            integration_type TEXT NOT NULL,
            operation TEXT NOT NULL,
            payload TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            retry_count INTEGER DEFAULT 0,
            max_retries INTEGER DEFAULT 3,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT
        )
    """
    )
    conn.commit()
    conn.close()

    yield path

    os.unlink(path)


def test_execute_outbox_item_success(client, outbox_db, monkeypatch):
    """Test executing outbox item successfully."""
    from core.connectors import ConnectorOutcome

    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    conn = sqlite3.connect(outbox_db)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-outbox-1",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue", "description": "Test"}),
            "pending",
            0,
            3,
        ),
    )
    conn.commit()
    conn.close()

    mock_outcome = ConnectorOutcome("sent", {"issue_key": "TEST-123"})
    mock_connectors = MagicMock()
    mock_connectors.deliver.return_value = mock_outcome

    with patch(
        "apps.api.webhooks_router.AutomationConnectors", return_value=mock_connectors
    ):
        response = client.post("/api/v1/webhooks/outbox/test-outbox-1/execute")

    assert response.status_code == 200
    data = response.json()
    assert data["outbox_id"] == "test-outbox-1"
    assert data["success"] is True
    assert data["status"] == "completed"


def test_execute_outbox_item_not_found(client, outbox_db, monkeypatch):
    """Test executing non-existent outbox item."""
    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    response = client.post("/api/v1/webhooks/outbox/nonexistent/execute")
    assert response.status_code == 404


def test_execute_outbox_item_wrong_status(client, outbox_db, monkeypatch):
    """Test executing outbox item with wrong status."""
    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    conn = sqlite3.connect(outbox_db)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-outbox-2",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue"}),
            "completed",
            0,
            3,
        ),
    )
    conn.commit()
    conn.close()

    response = client.post("/api/v1/webhooks/outbox/test-outbox-2/execute")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert "Cannot execute" in data["message"]


def test_execute_outbox_item_failure_with_retry(client, outbox_db, monkeypatch):
    """Test executing outbox item that fails and needs retry."""
    from core.connectors import ConnectorOutcome

    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    conn = sqlite3.connect(outbox_db)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-outbox-3",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue"}),
            "pending",
            0,
            3,
        ),
    )
    conn.commit()
    conn.close()

    mock_outcome = ConnectorOutcome("failed", {"reason": "Connection timeout"})
    mock_connectors = MagicMock()
    mock_connectors.deliver.return_value = mock_outcome

    with patch(
        "apps.api.webhooks_router.AutomationConnectors", return_value=mock_connectors
    ):
        response = client.post("/api/v1/webhooks/outbox/test-outbox-3/execute")

    assert response.status_code == 200
    data = response.json()
    assert data["outbox_id"] == "test-outbox-3"
    assert data["success"] is False
    assert data["status"] == "retrying"
    assert data["retry_count"] == 1


def test_execute_outbox_item_failure_max_retries(client, outbox_db, monkeypatch):
    """Test executing outbox item that fails after max retries."""
    from core.connectors import ConnectorOutcome

    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    conn = sqlite3.connect(outbox_db)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-outbox-4",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue"}),
            "retrying",
            2,
            3,
        ),
    )
    conn.commit()
    conn.close()

    mock_outcome = ConnectorOutcome("failed", {"reason": "Connection timeout"})
    mock_connectors = MagicMock()
    mock_connectors.deliver.return_value = mock_outcome

    with patch(
        "apps.api.webhooks_router.AutomationConnectors", return_value=mock_connectors
    ):
        response = client.post("/api/v1/webhooks/outbox/test-outbox-4/execute")

    assert response.status_code == 200
    data = response.json()
    assert data["outbox_id"] == "test-outbox-4"
    assert data["success"] is False
    assert data["status"] == "failed"
    assert data["retry_count"] == 3


def test_get_connector_settings_jira(monkeypatch):
    """Test _get_connector_settings with Jira env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_JIRA_URL", "https://test.atlassian.net")
    monkeypatch.setenv("FIXOPS_JIRA_USER", "test@example.com")
    monkeypatch.setenv("FIXOPS_JIRA_PROJECT_KEY", "TEST")

    settings = _get_connector_settings()

    assert "jira" in settings
    assert settings["jira"]["url"] == "https://test.atlassian.net"
    assert settings["jira"]["user"] == "test@example.com"
    assert settings["jira"]["project_key"] == "TEST"


def test_get_connector_settings_servicenow(monkeypatch):
    """Test _get_connector_settings with ServiceNow env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_SERVICENOW_URL", "https://test.service-now.com")
    monkeypatch.setenv("FIXOPS_SERVICENOW_USER", "admin")

    settings = _get_connector_settings()

    assert "servicenow" in settings
    assert settings["servicenow"]["instance_url"] == "https://test.service-now.com"
    assert settings["servicenow"]["user"] == "admin"


def test_get_connector_settings_gitlab(monkeypatch):
    """Test _get_connector_settings with GitLab env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_GITLAB_URL", "https://gitlab.com")
    monkeypatch.setenv("FIXOPS_GITLAB_PROJECT_ID", "12345")

    settings = _get_connector_settings()

    assert "gitlab" in settings
    assert settings["gitlab"]["base_url"] == "https://gitlab.com"
    assert settings["gitlab"]["project_id"] == "12345"


def test_get_connector_settings_github(monkeypatch):
    """Test _get_connector_settings with GitHub env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_GITHUB_OWNER", "test-owner")
    monkeypatch.setenv("FIXOPS_GITHUB_REPO", "test-repo")

    settings = _get_connector_settings()

    assert "github" in settings
    assert settings["github"]["owner"] == "test-owner"
    assert settings["github"]["repo"] == "test-repo"


def test_get_connector_settings_azure_devops(monkeypatch):
    """Test _get_connector_settings with Azure DevOps env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_AZURE_DEVOPS_ORG", "test-org")
    monkeypatch.setenv("FIXOPS_AZURE_DEVOPS_PROJECT", "test-project")

    settings = _get_connector_settings()

    assert "azure_devops" in settings
    assert settings["azure_devops"]["organization"] == "test-org"
    assert settings["azure_devops"]["project"] == "test-project"


def test_get_connector_settings_slack(monkeypatch):
    """Test _get_connector_settings with Slack env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv(
        "FIXOPS_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/xxx"
    )

    settings = _get_connector_settings()

    assert "policy_automation" in settings
    assert (
        settings["policy_automation"]["webhook_url"]
        == "https://hooks.slack.com/services/xxx"
    )


def test_get_connector_settings_confluence(monkeypatch):
    """Test _get_connector_settings with Confluence env vars."""
    from apps.api.webhooks_router import _get_connector_settings

    monkeypatch.setenv("FIXOPS_CONFLUENCE_URL", "https://test.atlassian.net/wiki")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_USER", "test@example.com")
    monkeypatch.setenv("FIXOPS_CONFLUENCE_SPACE_KEY", "TEST")

    settings = _get_connector_settings()

    assert "confluence" in settings
    assert settings["confluence"]["url"] == "https://test.atlassian.net/wiki"
    assert settings["confluence"]["user"] == "test@example.com"
    assert settings["confluence"]["space_key"] == "TEST"


def test_process_pending_outbox_items(client, outbox_db, monkeypatch):
    """Test processing pending outbox items."""
    from core.connectors import ConnectorOutcome

    monkeypatch.setattr("apps.api.webhooks_router._get_db_path", lambda: outbox_db)

    conn = sqlite3.connect(outbox_db)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-pending-1",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue 1"}),
            "pending",
            0,
            3,
        ),
    )
    cursor.execute(
        """
        INSERT INTO outbox (outbox_id, integration_type, operation, payload, status, retry_count, max_retries)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            "test-pending-2",
            "jira",
            "create_issue",
            json.dumps({"summary": "Test Issue 2"}),
            "pending",
            0,
            3,
        ),
    )
    conn.commit()
    conn.close()

    mock_outcome = ConnectorOutcome("sent", {"issue_key": "TEST-123"})
    mock_connectors = MagicMock()
    mock_connectors.deliver.return_value = mock_outcome

    with patch(
        "apps.api.webhooks_router.AutomationConnectors", return_value=mock_connectors
    ):
        response = client.post("/api/v1/webhooks/outbox/process-pending?limit=10")

    assert response.status_code == 200
    data = response.json()
    assert data["processed_count"] == 2
    assert len(data["results"]) == 2
